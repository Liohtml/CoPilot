//! The Customer Portal's SLA page (#1187) — port of
//! `customer_portal/services/sla.py`.
//!
//! **Opt-in per customer**: a missing `customer_portal_sla_settings` row
//! reads as disabled, and every read narrows the caller's customers to the
//! enabled ones *before* a figure is computed. **The same numbers as the SOC
//! sees, never who produced them**: the dashboard's own snapshot, projected
//! through `schema::portal`, which has no field for a person.

use chrono::NaiveDateTime;
use copilot_auth::AccessScope;
use copilot_db::visibility::AlertVisibility;
use copilot_web::{ApiError, AppContext, CurrentUser};
use sqlx::{MySql, QueryBuilder};

use crate::domain::analytics::EntityHeadline;
use crate::domain::periods::Period;
use crate::schema::metrics::Viewer;
use crate::schema::portal::{
    PortalSlaClock, PortalSlaEntity, PortalSlaOpenNow, PortalSlaOverviewResponse, PortalSlaTarget,
    PortalSlaTrendPoint,
};
use crate::services::datasets::{FactFilters, Visibility};
use crate::services::internal;
use crate::services::metrics::{DashboardQuery, Snapshot, compute_snapshot};

/// One `customer_portal_sla_settings` row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SlaSettingsRow {
    /// Customer (as stored).
    pub customer_code: String,
    /// The page is on.
    pub enabled: bool,
    /// Last change.
    pub updated_at: Option<NaiveDateTime>,
    /// Who.
    pub updated_by: Option<i64>,
}

/// `get_sla_settings(customer_code)` (MySQL's collation decides the match).
pub async fn get_settings(
    ctx: &AppContext,
    customer_code: &str,
) -> Result<Option<SlaSettingsRow>, ApiError> {
    sqlx::query_as::<_, SlaSettingsRow>(
        "SELECT customer_portal_sla_settings.customer_code, customer_portal_sla_settings.enabled, \
         customer_portal_sla_settings.updated_at, customer_portal_sla_settings.updated_by \
         FROM customer_portal_sla_settings WHERE customer_portal_sla_settings.customer_code = ?",
    )
    .bind(customer_code)
    .fetch_optional(ctx.db.pool())
    .await
    .map_err(internal)
}

/// `upsert_sla_settings` + commit + refresh: the row as stored afterwards.
pub async fn upsert_settings(
    ctx: &AppContext,
    customer_code: &str,
    enabled: bool,
    user_id: i64,
    now: NaiveDateTime,
) -> Result<SlaSettingsRow, ApiError> {
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM customer_portal_sla_settings WHERE customer_code = ? LIMIT 1",
    )
    .bind(customer_code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let stored = copilot_core::time::mysql_datetime(now);
    let id = match existing {
        Some((id,)) => {
            sqlx::query(
                "UPDATE customer_portal_sla_settings SET enabled = ?, updated_at = ?, \
                 updated_by = ? WHERE id = ?",
            )
            .bind(enabled)
            .bind(stored)
            .bind(user_id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            id
        }
        None => {
            let done = sqlx::query(
                "INSERT INTO customer_portal_sla_settings (customer_code, enabled, updated_at, \
                 updated_by) VALUES (?, ?, ?, ?)",
            )
            .bind(customer_code)
            .bind(enabled)
            .bind(stored)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            i64::try_from(done.last_insert_id()).map_err(internal)?
        }
    };
    let row = sqlx::query_as::<_, SlaSettingsRow>(
        "SELECT customer_code, enabled, updated_at, updated_by FROM customer_portal_sla_settings \
         WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(row)
}

/// `enabled_customer_codes(user, session, requested)`: the customers the
/// caller may see whose SLA page is on, optionally narrowed, sorted.
pub async fn enabled_customer_codes(
    ctx: &AppContext,
    user: &CurrentUser,
    requested: Option<&[String]>,
) -> Result<Vec<String>, ApiError> {
    let access = user.access(ctx).await?;
    let mut qb: QueryBuilder<'_, MySql> = QueryBuilder::new(
        "SELECT customer_portal_sla_settings.customer_code FROM customer_portal_sla_settings \
         WHERE customer_portal_sla_settings.enabled IS true",
    );
    if let AccessScope::Customers(codes) = access {
        if codes.is_empty() {
            return Ok(Vec::new());
        }
        qb.push(" AND customer_portal_sla_settings.customer_code IN (");
        let mut sep = qb.separated(", ");
        for c in codes {
            sep.push_bind(c.clone());
        }
        qb.push(")");
    }
    if let Some(requested) = requested.filter(|r| !r.is_empty()) {
        qb.push(" AND customer_portal_sla_settings.customer_code IN (");
        let mut sep = qb.separated(", ");
        for c in requested {
            sep.push_bind(c.clone());
        }
        qb.push(")");
    }
    let mut codes: Vec<String> = qb
        .build_query_scalar()
        .fetch_all(ctx.db.pool())
        .await
        .map_err(internal)?;
    codes.sort();
    Ok(codes)
}

/// `availability(user, session, customer_code)`.
pub async fn availability(
    ctx: &AppContext,
    user: &CurrentUser,
    customer_code: Option<&str>,
) -> Result<(Option<String>, bool), ApiError> {
    if let Some(code) = customer_code.filter(|c| !c.is_empty()) {
        if !user.access(ctx).await?.can_access(code) {
            return Err(ApiError::forbidden(format!(
                "Access denied to customer {code}"
            )));
        }
        let settings = get_settings(ctx, code).await?;
        return Ok((Some(code.to_string()), settings.is_some_and(|s| s.enabled)));
    }
    Ok((
        None,
        !enabled_customer_codes(ctx, user, None).await?.is_empty(),
    ))
}

/// `sla_overview(user, session, period, requested)`.
pub async fn overview(
    ctx: &AppContext,
    user: &CurrentUser,
    period: Period,
    requested: Option<&[String]>,
) -> Result<PortalSlaOverviewResponse, ApiError> {
    let codes = enabled_customer_codes(ctx, user, requested).await?;
    if codes.is_empty() {
        return Ok(PortalSlaOverviewResponse::disabled());
    }
    let access = user.access(ctx).await?;
    let alerts =
        AlertVisibility::for_user(&ctx.db, user.id, user.role_id, access, Some(&codes)).await?;
    let v = Visibility {
        alert_codes: alerts.as_ref().map(|_| codes.clone()),
        alerts,
        case_codes: Some(codes.clone()),
    };
    let query = DashboardQuery {
        period,
        customer_codes: Some(codes.clone()),
        filters: FactFilters::default(),
        bucket: None,
    };
    let viewer = Viewer {
        username: user.username.clone(),
        is_admin: false,
        sees_all_analysts: false,
    };
    // Inside `internal_errors`, a `ValueError` (a stored calendar that does
    // not parse) is a generic 500 like any other exception.
    let snapshot = compute_snapshot(ctx, &query, viewer, &v, 0)
        .await
        .map_err(|e| match e {
            ApiError::Http { status, .. } if status == http::StatusCode::BAD_REQUEST => {
                ApiError::internal(e)
            }
            other => other,
        })?;
    Ok(project(&snapshot, codes))
}

fn clock(c: &copilot_sla::evaluate::Compliance) -> PortalSlaClock {
    PortalSlaClock {
        met: c.met,
        breached: c.breached,
        rate: c.rate(),
    }
}

fn entity(h: &EntityHeadline) -> PortalSlaEntity {
    PortalSlaEntity {
        opened: h.opened,
        resolved: h.resolved,
        acknowledge: clock(&h.sla.ack),
        resolve: clock(&h.sla.resolve),
        time_to_acknowledge: h.tta.median,
        time_to_resolve: h.ttr.median,
    }
}

/// `project(snapshot, codes)`: the portal's view of a snapshot.
pub fn project(s: &Snapshot, codes: Vec<String>) -> PortalSlaOverviewResponse {
    let load = &s.workload;
    let targets = s
        .policy
        .cells
        .iter()
        .filter(|c| c.ack_minutes.is_some() || c.resolve_minutes.is_some())
        .map(|c| {
            let row = s
                .severities
                .iter()
                .find(|r| r.entity.as_str() == c.entity && r.severity == c.severity);
            PortalSlaTarget {
                entity: c.entity,
                severity: c.severity,
                acknowledge_minutes: c.ack_minutes,
                resolve_minutes: c.resolve_minutes,
                business_hours: c.business_hours,
                opened: row.map_or(0, |r| r.opened),
                acknowledge_rate: row.and_then(|r| r.sla.ack.rate()),
                resolve_rate: row.and_then(|r| r.sla.resolve.rate()),
                time_to_resolve: row.and_then(|r| r.ttr.median),
            }
        })
        .collect();
    PortalSlaOverviewResponse {
        enabled: true,
        customer_codes: codes,
        date_from: Some(s.period.start),
        date_to: Some(s.period.end),
        bucket: Some(s.bucket.as_str()),
        tracking_since: s.tracking_since,
        alerts: Some(entity(&s.headline.alerts)),
        cases: Some(entity(&s.headline.cases)),
        previous_alerts: Some(entity(&s.previous_headline.alerts)),
        previous_cases: Some(entity(&s.previous_headline.cases)),
        targets,
        trend: s
            .trends
            .iter()
            .map(|p| PortalSlaTrendPoint {
                start: p.start,
                opened: p.alerts_opened + p.cases_opened,
                resolved: p.alerts_resolved + p.cases_resolved,
                rate: p.sla_rate,
            })
            .collect(),
        open_now: Some(PortalSlaOpenNow {
            alerts: load.open_alerts,
            cases: load.open_cases,
            breached: load.breached,
            at_risk: load.at_risk,
            waiting_on_you: load.waiting_on_customer,
        }),
        success: true,
        message: "SLA figures retrieved successfully".into(),
    }
}
