//! `customer_portal_ai_report_settings` and `customer_portal_ai_request` —
//! the per-customer switch that publishes AI findings to the Customer Portal
//! and the log of analyses portal users asked for (#1215).
//!
//! A missing settings row means **disabled**: AI-written findings never reach
//! an end customer without an operator decision.

use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::{FromRow, MySql, QueryBuilder};

use copilot_core::time::mysql_datetime;

use crate::schema::TableRequirement;
use crate::visibility::AlertVisibility;
use crate::{Db, DbError};

/// Columns this module needs.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customer_portal_ai_report_settings",
        columns: &[
            "id",
            "customer_code",
            "enabled",
            "allow_customer_requests",
            "daily_request_limit",
            "updated_at",
            "updated_by",
        ],
    },
    TableRequirement {
        table: "customer_portal_ai_request",
        columns: &[
            "id",
            "customer_code",
            "alert_id",
            "requested_by_user_id",
            "requested_by",
            "requested_at",
        ],
    },
    TableRequirement {
        table: "incident_management_comment",
        columns: &["id", "alert_id", "comment", "user_name", "created_at"],
    },
    TableRequirement {
        table: "incident_management_tag_access_settings",
        columns: &["id", "enabled", "untagged_alert_behavior", "default_tag_id"],
    },
    TableRequirement {
        table: "user_tag_access",
        columns: &["user_id", "tag_id"],
    },
    TableRequirement {
        table: "role_tag_access",
        columns: &["role_id", "tag_id"],
    },
    TableRequirement {
        table: "incident_management_alert_to_tag",
        columns: &["alert_id", "tag_id"],
    },
];

/// One customer's AI report settings.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize)]
pub struct AiReportSettingsRow {
    /// Primary key.
    pub id: i32,
    /// Customer (unique, hard FK).
    pub customer_code: String,
    /// Portal users may read AI findings.
    pub enabled: bool,
    /// Portal users may ask for an analysis (only effective with `enabled`).
    pub allow_customer_requests: bool,
    /// Requests allowed in any 24 hours; `None` = unlimited.
    pub daily_request_limit: Option<i32>,
    /// Last change.
    pub updated_at: NaiveDateTime,
    /// Who changed it.
    pub updated_by: Option<i32>,
}

impl AiReportSettingsRow {
    /// `requests_allowed`: both switches on.
    pub fn requests_allowed(&self) -> bool {
        self.enabled && self.allow_customer_requests
    }
}

/// One accepted portal request.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize)]
pub struct AiRequestRow {
    /// Primary key.
    pub id: i32,
    /// The alert's customer.
    pub customer_code: String,
    /// The alert (no FK).
    pub alert_id: i32,
    /// Requesting user's id.
    pub requested_by_user_id: Option<i32>,
    /// Requesting user's name.
    pub requested_by: String,
    /// When.
    pub requested_at: NaiveDateTime,
}

const SETTINGS_COLS: &str = "id, customer_code, enabled, allow_customer_requests, \
     daily_request_limit, updated_at, updated_by";
const REQUEST_COLS: &str =
    "id, customer_code, alert_id, requested_by_user_id, requested_by, requested_at";

/// `get_ai_report_settings`.
pub async fn settings(
    db: &Db,
    customer_code: &str,
) -> Result<Option<AiReportSettingsRow>, DbError> {
    Ok(sqlx::query_as::<_, AiReportSettingsRow>(&format!(
        "SELECT {SETTINGS_COLS} FROM customer_portal_ai_report_settings WHERE customer_code = ?"
    ))
    .bind(customer_code)
    .fetch_optional(db.pool())
    .await?)
}

/// `count_recent_requests`: requests at or after `since`.
pub async fn count_requests_since(
    db: &Db,
    customer_code: &str,
    since: NaiveDateTime,
) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM customer_portal_ai_request \
         WHERE customer_code = ? AND requested_at >= ?",
    )
    .bind(customer_code)
    .bind(since)
    .fetch_one(db.pool())
    .await?)
}

/// Whether any enabled settings row exists, optionally among `codes`
/// (`is_ai_reports_enabled_for_user` without a customer).
pub async fn any_enabled(db: &Db, codes: Option<&[String]>) -> Result<bool, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT COUNT(*) FROM customer_portal_ai_report_settings WHERE enabled = TRUE",
    );
    if let Some(codes) = codes {
        if codes.is_empty() {
            return Ok(false);
        }
        qb.push(" AND customer_code IN (");
        let mut sep = qb.separated(", ");
        for c in codes {
            sep.push_bind(c.clone());
        }
        qb.push(")");
    }
    let n: i64 = qb.build_query_scalar().fetch_one(db.pool()).await?;
    Ok(n > 0)
}

/// What `upsert_ai_report_settings` writes. `None` fields are left alone
/// (`daily_request_limit: Some(None)` means "unlimited").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsUpdate {
    /// Read switch.
    pub enabled: bool,
    /// Request switch, when sent.
    pub allow_customer_requests: Option<bool>,
    /// Limit, when sent.
    pub daily_request_limit: Option<Option<i32>>,
    /// Acting user.
    pub updated_by: Option<i32>,
    /// Clock (stored as MySQL rounds it).
    pub now: NaiveDateTime,
}

/// Create or update a customer's settings in one transaction; a lost
/// insert race is retried as an update.
pub async fn upsert_settings(
    db: &Db,
    customer_code: &str,
    update: &SettingsUpdate,
) -> Result<AiReportSettingsRow, DbError> {
    match upsert_settings_once(db, customer_code, update).await {
        Err(e) if e.is_unique_violation() => upsert_settings_once(db, customer_code, update).await,
        other => other,
    }
}

async fn upsert_settings_once(
    db: &Db,
    customer_code: &str,
    u: &SettingsUpdate,
) -> Result<AiReportSettingsRow, DbError> {
    let now = mysql_datetime(u.now);
    let mut tx = db.pool().begin().await?;
    let existing = sqlx::query_scalar::<_, i32>(
        "SELECT id FROM customer_portal_ai_report_settings WHERE customer_code = ? FOR UPDATE",
    )
    .bind(customer_code)
    .fetch_optional(&mut *tx)
    .await?;
    match existing {
        Some(id) => {
            let mut qb = QueryBuilder::<MySql>::new(
                "UPDATE customer_portal_ai_report_settings SET enabled = ",
            );
            qb.push_bind(u.enabled);
            if let Some(allow) = u.allow_customer_requests {
                qb.push(", allow_customer_requests = ").push_bind(allow);
            }
            if let Some(limit) = u.daily_request_limit {
                qb.push(", daily_request_limit = ").push_bind(limit);
            }
            qb.push(", updated_at = ").push_bind(now);
            qb.push(", updated_by = ").push_bind(u.updated_by);
            qb.push(" WHERE id = ").push_bind(id);
            qb.build().execute(&mut *tx).await?;
        }
        None => {
            sqlx::query(
                "INSERT INTO customer_portal_ai_report_settings (customer_code, enabled, \
                 allow_customer_requests, daily_request_limit, updated_at, updated_by) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(customer_code)
            .bind(u.enabled)
            .bind(u.allow_customer_requests.unwrap_or(false))
            .bind(u.daily_request_limit.flatten())
            .bind(now)
            .bind(u.updated_by)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    settings(db, customer_code)
        .await?
        .ok_or_else(|| DbError::Config(format!("settings for {customer_code} vanished")))
}

/// What the request checks look at, read under the settings lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSnapshot {
    /// The customer's settings (`None` = disabled).
    pub settings: Option<AiReportSettingsRow>,
    /// Latest job on the alert: `(status, created_at)`.
    pub latest_job: Option<(String, NaiveDateTime)>,
    /// Latest portal request on the alert.
    pub latest_request: Option<NaiveDateTime>,
    /// Requests in the last 24 h (read only when a limit is set; else 0).
    pub recent_requests: i64,
}

/// The new request to record.
#[derive(Debug, Clone)]
pub struct NewRequest<'a> {
    /// The alert's customer (from the alert, never a body).
    pub customer_code: &'a str,
    /// Alert.
    pub alert_id: i64,
    /// Requesting user.
    pub user_id: Option<i32>,
    /// Requesting user's name.
    pub username: &'a str,
    /// Clock (`requested_at`, stored as MySQL rounds it).
    pub now: NaiveDateTime,
    /// Start of the daily-limit window.
    pub window_start: NaiveDateTime,
}

/// `request_alert_analysis`'s locked section: lock the customer's settings
/// row (`SELECT … FOR UPDATE`), read the snapshot, let `decide` refuse, and
/// otherwise insert the request and commit — which releases the lock before
/// the caller talks to Talon. `Ok(Err(_))` is a refusal (rolled back).
pub async fn record_request<E>(
    db: &Db,
    req: &NewRequest<'_>,
    decide: impl FnOnce(&RequestSnapshot) -> Result<(), E>,
) -> Result<Result<AiRequestRow, E>, DbError> {
    let mut tx = db.pool().begin().await?;
    let settings = sqlx::query_as::<_, AiReportSettingsRow>(&format!(
        "SELECT {SETTINGS_COLS} FROM customer_portal_ai_report_settings \
         WHERE customer_code = ? FOR UPDATE"
    ))
    .bind(req.customer_code)
    .fetch_optional(&mut *tx)
    .await?;
    let latest_job = sqlx::query_as::<_, (String, NaiveDateTime)>(
        "SELECT status, created_at FROM ai_analyst_job WHERE alert_id = ? \
         ORDER BY created_at DESC, id ASC LIMIT 1",
    )
    .bind(req.alert_id)
    .fetch_optional(&mut *tx)
    .await?;
    let latest_request = sqlx::query_scalar::<_, NaiveDateTime>(
        "SELECT requested_at FROM customer_portal_ai_request WHERE alert_id = ? \
         ORDER BY requested_at DESC, id ASC LIMIT 1",
    )
    .bind(req.alert_id)
    .fetch_optional(&mut *tx)
    .await?;
    let recent_requests = match settings.as_ref().and_then(|s| s.daily_request_limit) {
        Some(_) => {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM customer_portal_ai_request \
                 WHERE customer_code = ? AND requested_at >= ?",
            )
            .bind(req.customer_code)
            .bind(req.window_start)
            .fetch_one(&mut *tx)
            .await?
        }
        None => 0,
    };
    let snapshot = RequestSnapshot {
        settings,
        latest_job,
        latest_request,
        recent_requests,
    };
    if let Err(refusal) = decide(&snapshot) {
        tx.rollback().await?;
        return Ok(Err(refusal));
    }
    let res = sqlx::query(
        "INSERT INTO customer_portal_ai_request (customer_code, alert_id, requested_by_user_id, \
         requested_by, requested_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(req.customer_code)
    .bind(req.alert_id)
    .bind(req.user_id)
    .bind(req.username)
    .bind(mysql_datetime(req.now))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let id = res.last_insert_id();
    let row = sqlx::query_as::<_, AiRequestRow>(&format!(
        "SELECT {REQUEST_COLS} FROM customer_portal_ai_request WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?
    .ok_or_else(|| DbError::Config(format!("request {id} vanished after insert")))?;
    Ok(Ok(row))
}

/// Give a request back (Talon refused it).
pub async fn delete_request(db: &Db, id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM customer_portal_ai_request WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// One row of the portal Overview's "recent AI reports" list.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct InsightRow {
    /// Alert.
    pub alert_id: i32,
    /// Alert title.
    pub alert_name: String,
    /// Alert's customer.
    pub customer_code: String,
    /// Latest report's severity.
    pub severity_assessment: Option<String>,
    /// Latest report's summary.
    pub summary: Option<String>,
    /// Latest report's creation time.
    pub report_created_at: NaiveDateTime,
}

/// Restrict to the latest report per alert (`MAX(id)`, which never ties —
/// two replays can share a `created_at` second) on an alert the caller may
/// see, of a customer whose AI report switch is on.
fn push_insight_filters(qb: &mut QueryBuilder<'_, MySql>, visibility: &AlertVisibility) {
    qb.push(
        " WHERE r.id IN (SELECT MAX(id) FROM ai_analyst_report GROUP BY alert_id) \
         AND a.customer_code IN (SELECT customer_code FROM customer_portal_ai_report_settings \
         WHERE enabled = TRUE)",
    );
    visibility.push_and(qb, "a");
}

/// `ai_insights_within`: `(severity, count)` per latest-report severity, in
/// the order MySQL groups them, and the `limit` most recent reports.
pub async fn ai_insights(
    db: &Db,
    visibility: &AlertVisibility,
    limit: i64,
) -> Result<(Vec<(Option<String>, i64)>, Vec<InsightRow>), DbError> {
    let mut counts = QueryBuilder::<MySql>::new(
        "SELECT r.severity_assessment, COUNT(r.id) FROM ai_analyst_report r \
         JOIN incident_management_alert a ON a.id = r.alert_id",
    );
    push_insight_filters(&mut counts, visibility);
    counts.push(" GROUP BY r.severity_assessment");
    let counts = counts
        .build_query_as::<(Option<String>, i64)>()
        .fetch_all(db.pool())
        .await?;

    let mut recent = QueryBuilder::<MySql>::new(
        "SELECT a.id AS alert_id, a.alert_name, a.customer_code, r.severity_assessment, \
         r.summary, r.created_at AS report_created_at FROM incident_management_alert a \
         JOIN ai_analyst_report r ON r.alert_id = a.id",
    );
    push_insight_filters(&mut recent, visibility);
    recent.push(" ORDER BY r.created_at DESC, r.id DESC LIMIT ");
    recent.push_bind(limit);
    let recent = recent
        .build_query_as::<InsightRow>()
        .fetch_all(db.pool())
        .await?;
    Ok((counts, recent))
}
