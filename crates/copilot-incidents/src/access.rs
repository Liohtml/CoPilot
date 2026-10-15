//! Per-object access checks of the incidents routes: `get_alert_by_id(...,
//! user=…)` (tag RBAC), `_ensure_alert_access`, `_ensure_case_access`,
//! `_ensure_customer_access` and the `check_customer_access` tests the
//! routes spell out inline.
//!
//! The single-alert tag rule here is `TagAccessHandler.check_alert_tag_access`
//! — the *list* rule (`build_alert_query_filters`) applied to one alert's
//! tags — not `can_user_access_alert`: the two differ for `default_tag` with
//! no tag configured (`copilot_auth::tags`), and `get_alert_by_id` uses the
//! former.

use copilot_auth::AccessScope;
use copilot_auth::tags::TagScope;
use copilot_db::visibility;
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::schema::CaseOut;
use crate::views::{self, LoadedAlert};

/// `build_alert_query_filters` for `user`, as a [`TagScope`].
pub async fn tag_scope(ctx: &AppContext, user: &CurrentUser) -> Result<TagScope, ApiError> {
    let settings = visibility::tag_access_settings(&ctx.db).await?;
    let tags =
        visibility::accessible_tags(&ctx.db, settings.as_ref(), user.id, user.role_id).await?;
    Ok(TagScope::for_lists(settings.as_ref(), user.role_id, tags))
}

/// `check_alert_tag_access` for an alert carrying `alert_tags`.
pub fn tag_allows(scope: &TagScope, alert_tags: &[i32]) -> bool {
    match scope {
        TagScope::All => true,
        TagScope::Restricted {
            tags,
            include_untagged,
        } => {
            if alert_tags.is_empty() {
                *include_untagged
            } else {
                alert_tags.iter().any(|t| tags.contains(t))
            }
        }
    }
}

/// `get_alert_by_id(alert_id, db, user=user)`: 404 `Alert not found`, then
/// 403 for an alert whose tags the user may not see.
pub async fn alert_for(
    ctx: &AppContext,
    user: &CurrentUser,
    alert_id: i64,
) -> Result<LoadedAlert, ApiError> {
    let alert = views::load_alert(&ctx.db, alert_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Alert not found"))?;
    let scope = tag_scope(ctx, user).await?;
    if !tag_allows(&scope, &alert.tag_ids()) {
        return Err(ApiError::forbidden(format!(
            "Access denied to alert {alert_id} - insufficient tag permissions"
        )));
    }
    Ok(alert)
}

/// `customer_access_handler.check_customer_access` (`None` — a case
/// without a customer — passes only for admins).
pub async fn can_access(
    ctx: &AppContext,
    user: &CurrentUser,
    code: Option<&str>,
) -> Result<bool, ApiError> {
    let access = user.access(ctx).await?;
    Ok(match (access, code) {
        (AccessScope::All, _) => true,
        (_, None) => false,
        (scope, Some(code)) => scope.can_access(code),
    })
}

/// `_ensure_alert_access`: [`alert_for`], the response model built (it can
/// fail, see [`views`]), then the customer check.
pub async fn ensure_alert(
    ctx: &AppContext,
    user: &CurrentUser,
    alert_id: i64,
) -> Result<LoadedAlert, ApiError> {
    ensure_alert_msg(ctx, user, alert_id, &format!("alert {alert_id}")).await
}

/// [`ensure_alert`] with the subject of the 403 (`Access denied to
/// <subject> - insufficient customer permissions`).
pub async fn ensure_alert_msg(
    ctx: &AppContext,
    user: &CurrentUser,
    alert_id: i64,
    subject: &str,
) -> Result<LoadedAlert, ApiError> {
    let alert = alert_for(ctx, user, alert_id).await?;
    alert.build()?;
    if !can_access(ctx, user, Some(&alert.row.customer_code)).await? {
        return Err(ApiError::forbidden(format!(
            "Access denied to {subject} - insufficient customer permissions"
        )));
    }
    Ok(alert)
}

/// `_ensure_case_access` (and the inline copies): `get_case_by_id` (404
/// `Case not found`), then the customer check.
pub async fn ensure_case(
    ctx: &AppContext,
    user: &CurrentUser,
    case_id: i64,
) -> Result<CaseOut, ApiError> {
    ensure_case_msg(ctx, user, case_id, &format!("case {case_id}")).await
}

/// [`ensure_case`] with the 403's subject.
pub async fn ensure_case_msg(
    ctx: &AppContext,
    user: &CurrentUser,
    case_id: i64,
    subject: &str,
) -> Result<CaseOut, ApiError> {
    let case = views::case_full(&ctx.db, case_id).await?;
    if !can_access(ctx, user, case.customer_code.as_deref()).await? {
        return Err(ApiError::forbidden(format!(
            "Access denied to {subject} - insufficient customer permissions"
        )));
    }
    Ok(case)
}

/// `_ensure_customer_access`: a body's `customer_code` must be the caller's.
pub async fn ensure_customer(
    ctx: &AppContext,
    user: &CurrentUser,
    code: Option<&str>,
) -> Result<(), ApiError> {
    if !can_access(ctx, user, code).await? {
        return Err(ApiError::forbidden(format!(
            "Access denied to customer {} - insufficient customer permissions",
            code.unwrap_or("None")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_alert_tag_rule_is_the_list_rule() {
        let all = TagScope::All;
        assert!(tag_allows(&all, &[]));
        let r = TagScope::Restricted {
            tags: [2].into(),
            include_untagged: false,
        };
        assert!(!tag_allows(&r, &[]));
        assert!(tag_allows(&r, &[1, 2]));
        assert!(!tag_allows(&r, &[3]));
        let u = TagScope::Restricted {
            tags: Default::default(),
            include_untagged: true,
        };
        assert!(tag_allows(&u, &[]));
    }
}
