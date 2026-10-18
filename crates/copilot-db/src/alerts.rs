//! Read-only views of `incident_management_alert` / `_asset` used for tenancy
//! checks and notification context. The incidents module itself is still
//! served by the Python backend; nothing here writes.
//!
//! `incident_management_alert.customer_code` is a plain string, not an FK:
//! orphaned codes exist by design, so never assume a join to `customers`.

use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::{Db, DbError};

/// The alert fields the AI-analyst and Talon surfaces display.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AlertSummary {
    /// Primary key.
    pub id: i32,
    /// Title.
    pub alert_name: String,
    /// Tenant (string, no FK).
    pub customer_code: String,
    /// `OPEN` | `IN_PROGRESS` | `PENDING_CUSTOMER` | `CLOSED`.
    pub status: String,
    /// Ingest source.
    pub source: String,
    /// Assignee username.
    pub assigned_to: Option<String>,
    /// Last-seen time (ingest moves it while the alert stays open).
    pub alert_creation_time: NaiveDateTime,
}

/// Owner of an alert, for `verify_alert_access`.
pub async fn alert_customer_code(db: &Db, alert_id: i64) -> Result<Option<String>, DbError> {
    let code = sqlx::query_scalar::<_, String>(
        "SELECT customer_code FROM incident_management_alert WHERE id = ?",
    )
    .bind(alert_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(code)
}

/// One alert's summary.
pub async fn find_alert(db: &Db, alert_id: i64) -> Result<Option<AlertSummary>, DbError> {
    let row = sqlx::query_as::<_, AlertSummary>(
        "SELECT id, alert_name, customer_code, status, source, assigned_to, alert_creation_time \
         FROM incident_management_alert WHERE id = ?",
    )
    .bind(alert_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// First linked asset's name (`… WHERE alert_linked = ? LIMIT 1`).
pub async fn first_asset_name(db: &Db, alert_id: i64) -> Result<Option<String>, DbError> {
    let name = sqlx::query_scalar::<_, String>(
        "SELECT asset_name FROM incident_management_asset WHERE alert_linked = ? \
         ORDER BY id LIMIT 1",
    )
    .bind(alert_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(name)
}

/// Whether a customer row exists.
pub async fn customer_exists(db: &Db, customer_code: &str) -> Result<bool, DbError> {
    let found =
        sqlx::query_scalar::<_, i32>("SELECT id FROM customers WHERE customer_code = ? LIMIT 1")
            .bind(customer_code)
            .fetch_optional(db.pool())
            .await?;
    Ok(found.is_some())
}

/// `create_comment` (the incidents *service*, not the route): a plain
/// timeline entry. Deliberately no SLA side effects — those are recorded by
/// the incidents routes, and a portal request must neither acknowledge an
/// SLA nor hand a waiting alert back.
pub async fn insert_alert_comment(
    db: &Db,
    alert_id: i64,
    comment: &str,
    user_name: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO incident_management_comment (alert_id, comment, user_name, created_at) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(alert_id)
    .bind(comment)
    .bind(user_name)
    .bind(copilot_core::time::now_utc_naive())
    .execute(db.pool())
    .await?;
    Ok(())
}
