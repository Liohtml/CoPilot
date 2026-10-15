//! `audit_log` and `log_entries` writers.
//!
//! - [`DbAuditSink`] — `record_audit_event`: its own short transaction, after
//!   the caller's commit, spawned so the request never waits on it; failures
//!   are logged and swallowed. Over-long fields are cut to the column widths
//!   (the Python helper loses the whole event instead).
//! - [`insert_error_log`] — the `log_entries` row the Python exception
//!   handlers write for every handled error (`Logger.log_error`): event type
//!   `Error`, status 500 regardless of the response, message ≤ 5024 chars.

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
    .bind(r.old_value.map(sqlx::types::Json))
    .bind(r.new_value.map(sqlx::types::Json))
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
