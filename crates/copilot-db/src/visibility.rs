//! Which alerts a user may see — port of
//! `app/incidents/services/db_operations.py:alert_visibility_filters_for_user`
//! (customer scoping AND tag RBAC) and of the reads behind
//! `TagAccessHandler`.
//!
//! This is the **single definition** of alert visibility: anything listing,
//! counting or opening alerts for a user goes through [`AlertVisibility`],
//! never a second copy of the rules. The decisions themselves are pure
//! (`copilot_auth::{access, tags}`); this module reads the rows they need and
//! renders the result as SQL on a `QueryBuilder`.

use std::collections::BTreeSet;

use sqlx::{MySql, QueryBuilder};

use copilot_auth::AccessScope;
use copilot_auth::tags::{self, TagAccessSettings, TagScope, TagSet};

use crate::{Db, DbError};

/// The first `incident_management_tag_access_settings` row (`.limit(1)`).
pub async fn tag_access_settings(db: &Db) -> Result<Option<TagAccessSettings>, DbError> {
    let row = sqlx::query_as::<_, (bool, String, Option<i32>)>(
        "SELECT enabled, untagged_alert_behavior, default_tag_id \
         FROM incident_management_tag_access_settings ORDER BY id LIMIT 1",
    )
    .fetch_optional(db.pool())
    .await?;
    Ok(row.map(
        |(enabled, untagged_alert_behavior, default_tag_id)| TagAccessSettings {
            enabled,
            untagged_alert_behavior,
            default_tag_id,
        },
    ))
}

/// `get_user_accessible_tags`: reads `user_tag_access` / `role_tag_access`
/// only when tag RBAC applies to this user.
pub async fn accessible_tags(
    db: &Db,
    settings: Option<&TagAccessSettings>,
    user_id: i32,
    role_id: Option<i32>,
) -> Result<TagSet, DbError> {
    if !settings.is_some_and(|s| s.enabled) || tags::is_unrestricted(role_id) {
        return Ok(TagSet::All);
    }
    let user_tags =
        sqlx::query_scalar::<_, i32>("SELECT tag_id FROM user_tag_access WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(db.pool())
            .await?;
    let role_ids = tags::tag_role_ids(role_id);
    let role_tags = if role_ids.is_empty() {
        Vec::new()
    } else {
        let mut qb =
            QueryBuilder::<MySql>::new("SELECT tag_id FROM role_tag_access WHERE role_id IN (");
        let mut sep = qb.separated(", ");
        for id in &role_ids {
            sep.push_bind(*id);
        }
        qb.push(")");
        qb.build_query_scalar::<i32>().fetch_all(db.pool()).await?
    };
    Ok(tags::accessible_tags(
        settings, role_id, &user_tags, &role_tags,
    ))
}

/// `TagAccessHandler.can_user_access_alert`.
pub async fn can_user_access_alert(
    db: &Db,
    user_id: i32,
    role_id: Option<i32>,
    alert_id: i64,
) -> Result<bool, DbError> {
    let settings = tag_access_settings(db).await?;
    if !settings.as_ref().is_some_and(|s| s.enabled) || tags::is_unrestricted(role_id) {
        return Ok(true);
    }
    let alert_tags = sqlx::query_scalar::<_, i32>(
        "SELECT tag_id FROM incident_management_alert_to_tag WHERE alert_id = ?",
    )
    .bind(alert_id)
    .fetch_all(db.pool())
    .await?;
    let user_tags = accessible_tags(db, settings.as_ref(), user_id, role_id).await?;
    Ok(tags::can_access_alert(
        settings.as_ref(),
        role_id,
        &alert_tags,
        &user_tags,
    ))
}

/// Visibility of `incident_management_alert` rows for one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertVisibility {
    /// `None` = every customer; otherwise these codes (never empty).
    pub customers: Option<Vec<String>>,
    /// Tag restriction.
    pub tags: TagScope,
}

impl AlertVisibility {
    /// `alert_visibility_filters_for_user`. `requested` narrows to a subset of
    /// customers (`resolve_effective_customers`). `None` means the user can
    /// see no alert at all — callers return an empty result and must never
    /// run an unfiltered query instead.
    pub async fn for_user(
        db: &Db,
        user_id: i32,
        role_id: Option<i32>,
        access: &AccessScope,
        requested: Option<&[String]>,
    ) -> Result<Option<Self>, DbError> {
        let customers = match access.resolve_effective(requested) {
            AccessScope::All => None,
            AccessScope::Customers(codes) if codes.is_empty() => return Ok(None),
            AccessScope::Customers(codes) => Some(codes),
        };
        let settings = tag_access_settings(db).await?;
        let user_tags = accessible_tags(db, settings.as_ref(), user_id, role_id).await?;
        let tags = TagScope::for_lists(settings.as_ref(), role_id, user_tags);
        if tags.sees_nothing() {
            return Ok(None);
        }
        Ok(Some(Self { customers, tags }))
    }

    /// Append ` AND <conditions>` for the alert table aliased `alias`.
    pub fn push_and(&self, qb: &mut QueryBuilder<'_, MySql>, alias: &str) {
        if let Some(codes) = &self.customers {
            qb.push(format!(" AND {alias}.customer_code IN ("));
            let mut sep = qb.separated(", ");
            for c in codes {
                sep.push_bind(c.clone());
            }
            qb.push(")");
        }
        if let TagScope::Restricted {
            tags,
            include_untagged,
        } = &self.tags
        {
            let mut conditions: Vec<String> = Vec::new();
            if !tags.is_empty() {
                conditions.push(format!(
                    "EXISTS (SELECT 1 FROM incident_management_alert_to_tag t \
                     WHERE t.alert_id = {alias}.id AND t.tag_id IN ({}))",
                    join_ids(tags)
                ));
            }
            if *include_untagged {
                conditions.push(format!(
                    "NOT EXISTS (SELECT 1 FROM incident_management_alert_to_tag t \
                     WHERE t.alert_id = {alias}.id)"
                ));
            }
            qb.push(format!(" AND ({})", conditions.join(" OR ")));
        }
    }
}

/// Tag ids are integers read from the database, so they are rendered inline.
fn join_ids(ids: &BTreeSet<i32>) -> String {
    ids.iter()
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sql(v: &AlertVisibility) -> String {
        let mut qb =
            QueryBuilder::<MySql>::new("SELECT a.id FROM incident_management_alert a WHERE 1=1");
        v.push_and(&mut qb, "a");
        qb.sql().to_string()
    }

    #[test]
    fn renders_customer_and_tag_conditions() {
        let v = AlertVisibility {
            customers: Some(vec!["acme".into(), "beta".into()]),
            tags: TagScope::Restricted {
                tags: [3, 1].into(),
                include_untagged: true,
            },
        };
        assert_eq!(
            sql(&v),
            "SELECT a.id FROM incident_management_alert a WHERE 1=1 AND a.customer_code IN (?, ?) \
             AND (EXISTS (SELECT 1 FROM incident_management_alert_to_tag t WHERE t.alert_id = a.id \
             AND t.tag_id IN (1, 3)) OR NOT EXISTS (SELECT 1 FROM incident_management_alert_to_tag t \
             WHERE t.alert_id = a.id))"
        );
        let all = AlertVisibility {
            customers: None,
            tags: TagScope::All,
        };
        assert_eq!(
            sql(&all),
            "SELECT a.id FROM incident_management_alert a WHERE 1=1"
        );
    }
}
