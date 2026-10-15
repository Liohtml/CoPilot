//! `audit_log` and `log_entries` writers, and the `audit_log` reads.
//!
//! - [`DbAuditSink`] — `record_audit_event`: its own short transaction, after
//!   the caller's commit, spawned so the request never waits on it; failures
//!   are logged and swallowed. An absent before/after value is JSON `null`,
//!   as SQLAlchemy writes it. Over-long fields are cut to the column widths
//!   (the Python helper loses the whole event instead).
//! - [`insert_error_log`] — the `log_entries` row the Python exception
//!   handlers write for every handled error (`Logger.log_error`): event type
//!   `Error`, status 500 regardless of the response, message ≤ 5024 chars.
//! - [`list_audit_logs`] / [`get_audit_log`] — `app/audit/services/query.py`.

use copilot_core::audit::{AuditRecord, AuditSink};
use copilot_core::time::now_utc_naive;

use crate::{Db, DbError};

fn cut(value: Option<String>, max_chars: usize) -> Option<String> {
    value.map(|v| {
        if v.chars().count() <= max_chars {
            v
        } else {
            v.chars().take(max_chars).collect()
        }
    })
}

/// Insert one audit row now.
pub async fn insert_audit_record(db: &Db, r: AuditRecord) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO audit_log (timestamp, actor_user_id, actor_username, customer_code, \
         action, entity_type, entity_id, result, old_value, new_value, source_ip, details) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(now_utc_naive())
    .bind(r.actor_user_id)
    .bind(cut(r.actor_username, 256))
    .bind(cut(r.customer_code, 50))
    .bind(cut(Some(r.action), 128))
    .bind(cut(r.entity_type, 128))
    .bind(cut(r.entity_id, 256))
    .bind(r.result.as_str())
    // SQLAlchemy's `JSON` column stores `None` as JSON `null`, not SQL NULL.
    .bind(sqlx::types::Json(
        r.old_value.unwrap_or(serde_json::Value::Null),
    ))
    .bind(sqlx::types::Json(
        r.new_value.unwrap_or(serde_json::Value::Null),
    ))
    .bind(cut(r.source_ip, 64))
    .bind(cut(r.details, 5024))
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Audit sink writing `audit_log` rows in the background.
#[derive(Debug, Clone)]
pub struct DbAuditSink {
    db: Db,
}

impl DbAuditSink {
    /// Sink over a pool.
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

impl AuditSink for DbAuditSink {
    fn record(&self, record: AuditRecord) {
        let db = self.db.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(action = %record.action, "audit write skipped: no runtime");
            return;
        };
        handle.spawn(async move {
            let action = record.action.clone();
            if let Err(e) = insert_audit_record(&db, record).await {
                tracing::error!(action = %action, err = %e, "failed to write audit event");
            }
        });
    }
}

/// One handled-error row for `log_entries`.
#[derive(Debug, Clone)]
pub struct ErrorLogEntry {
    /// User resolved from the bearer token, if any.
    pub user_id: Option<i32>,
    /// Full request URL (`str(request.url)`).
    pub route: String,
    /// HTTP method.
    pub method: String,
    /// The error's message.
    pub message: String,
}

/// Insert a `log_entries` error row.
pub async fn insert_error_log(db: &Db, e: ErrorLogEntry) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO log_entries (timestamp, event_type, user_id, route, method, status_code, \
         message, additional_info) VALUES (?, 'Error', ?, ?, ?, 500, ?, NULL)",
    )
    .bind(now_utc_naive())
    .bind(e.user_id)
    .bind(cut(Some(e.route), 256))
    .bind(cut(Some(e.method), 256))
    .bind(cut(Some(e.message), 5024))
    .execute(db.pool())
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_respects_char_boundaries() {
        assert_eq!(cut(Some("äöü".into()), 2).as_deref(), Some("äö"));
        assert_eq!(cut(Some("ok".into()), 5).as_deref(), Some("ok"));
        assert_eq!(cut(None, 5), None);
    }
}

/// A MySQL `JSON` column, read in the key order MySQL stores.
pub type JsonColumn = sqlx::types::Json<serde_json::Value>;

/// One `audit_log` row as the read API returns it.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct AuditLogRow {
    /// Primary key.
    pub id: i32,
    /// When (naive UTC).
    pub timestamp: chrono::NaiveDateTime,
    /// Acting user's id.
    pub actor_user_id: Option<i32>,
    /// Acting user's name.
    pub actor_username: Option<String>,
    /// Tenant.
    pub customer_code: Option<String>,
    /// `<domain>.<verb>`.
    pub action: String,
    /// Kind of object.
    pub entity_type: Option<String>,
    /// Object id.
    pub entity_id: Option<String>,
    /// `success` | `failure`.
    pub result: String,
    /// State before (MySQL JSON, its key order).
    pub old_value: Option<JsonColumn>,
    /// State after.
    pub new_value: Option<JsonColumn>,
    /// Source address.
    pub source_ip: Option<String>,
    /// Free text.
    pub details: Option<String>,
}

const AUDIT_COLS: &str = "id, timestamp, actor_user_id, actor_username, customer_code, action, \
     entity_type, entity_id, result, old_value, new_value, source_ip, details";

/// `list_audit_logs`'s filters; empty strings are "not given", as in Python.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditLogFilter {
    /// Acting user id (`0` filters too).
    pub actor_user_id: Option<i64>,
    /// Exact username.
    pub actor_username: Option<String>,
    /// Exact action.
    pub action: Option<String>,
    /// Exact entity type.
    pub entity_type: Option<String>,
    /// Exact entity id.
    pub entity_id: Option<String>,
    /// Any of these customers.
    pub customer_codes: Option<Vec<String>>,
    /// `success` | `failure`.
    pub result: Option<String>,
    /// At or after (wall clock).
    pub start_time: Option<chrono::NaiveDateTime>,
    /// At or before (wall clock).
    pub end_time: Option<chrono::NaiveDateTime>,
    /// Case-insensitive substring of details, username or entity id (`LIKE`
    /// wildcards in it keep their meaning).
    pub search: Option<String>,
}

fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

impl AuditLogFilter {
    fn push_where(&self, qb: &mut sqlx::QueryBuilder<'_, sqlx::MySql>) {
        let mut first = true;
        let mut and = |qb: &mut sqlx::QueryBuilder<'_, sqlx::MySql>| {
            qb.push(if first { " WHERE " } else { " AND " });
            first = false;
        };
        if let Some(id) = self.actor_user_id {
            and(qb);
            qb.push("audit_log.actor_user_id = ").push_bind(id);
        }
        for (col, value) in [
            ("actor_username", &self.actor_username),
            ("action", &self.action),
            ("entity_type", &self.entity_type),
            ("entity_id", &self.entity_id),
        ] {
            if let Some(v) = non_empty(value) {
                and(qb);
                qb.push(format!("audit_log.{col} = "))
                    .push_bind(v.to_string());
            }
        }
        if let Some(codes) = self.customer_codes.as_ref().filter(|c| !c.is_empty()) {
            and(qb);
            qb.push("audit_log.customer_code IN (");
            let mut sep = qb.separated(", ");
            for c in codes {
                sep.push_bind(c.clone());
            }
            qb.push(")");
        }
        if let Some(v) = non_empty(&self.result) {
            and(qb);
            qb.push("audit_log.result = ").push_bind(v.to_string());
        }
        if let Some(t) = self.start_time {
            and(qb);
            qb.push("audit_log.timestamp >= ").push_bind(t);
        }
        if let Some(t) = self.end_time {
            and(qb);
            qb.push("audit_log.timestamp <= ").push_bind(t);
        }
        if let Some(term) = non_empty(&self.search) {
            let like = format!("%{term}%");
            and(qb);
            qb.push("(lower(audit_log.details) LIKE lower(")
                .push_bind(like.clone())
                .push(") OR lower(audit_log.actor_username) LIKE lower(")
                .push_bind(like.clone())
                .push(") OR lower(audit_log.entity_id) LIKE lower(")
                .push_bind(like)
                .push("))");
        }
    }
}

/// `list_audit_logs`: `(rows, total)`, newest first (`timestamp DESC, id DESC`).
pub async fn list_audit_logs(
    db: &Db,
    filter: &AuditLogFilter,
    skip: i64,
    limit: i64,
) -> Result<(Vec<AuditLogRow>, i64), DbError> {
    let mut count = sqlx::QueryBuilder::<sqlx::MySql>::new("SELECT count(*) FROM audit_log");
    filter.push_where(&mut count);
    let total: i64 = count.build_query_scalar().fetch_one(db.pool()).await?;

    let mut rows =
        sqlx::QueryBuilder::<sqlx::MySql>::new(format!("SELECT {AUDIT_COLS} FROM audit_log"));
    filter.push_where(&mut rows);
    rows.push(" ORDER BY audit_log.timestamp DESC, audit_log.id DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(skip);
    let rows = rows
        .build_query_as::<AuditLogRow>()
        .fetch_all(db.pool())
        .await?;
    Ok((rows, total))
}

/// `get_audit_log_by_id`.
pub async fn get_audit_log(db: &Db, id: i64) -> Result<Option<AuditLogRow>, DbError> {
    Ok(sqlx::query_as::<_, AuditLogRow>(&format!(
        "SELECT {AUDIT_COLS} FROM audit_log WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}
