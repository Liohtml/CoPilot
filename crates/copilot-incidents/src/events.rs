//! The case timeline's writes — port of `app/incidents/services/case_events.py`
//! (`emit_case_event` and the payload constructors).
//!
//! `incident_management_case_event` is append-only. An emit never fails the
//! mutation it records: a failed write is logged and swallowed.

use copilot_core::time::{mysql_datetime, now_utc_micros};
use copilot_db::Db;
use serde_json::{Map, Value, json};
use sqlx::MySqlConnection;

/// `CaseEventType.CASE_CREATED`.
pub const CASE_CREATED: &str = "case_created";
/// `CaseEventType.CASE_STATUS_CHANGED`.
pub const CASE_STATUS_CHANGED: &str = "case_status_changed";
/// `CaseEventType.CASE_ASSIGNED`.
pub const CASE_ASSIGNED: &str = "case_assigned";
/// `CaseEventType.CASE_ESCALATED`.
pub const CASE_ESCALATED: &str = "case_escalated";
/// `CaseEventType.CASE_SEVERITY_CHANGED`.
pub const CASE_SEVERITY_CHANGED: &str = "case_severity_changed";
/// `CaseEventType.ALERT_LINKED`.
pub const ALERT_LINKED: &str = "alert_linked";
/// `CaseEventType.ALERT_UNLINKED`.
pub const ALERT_UNLINKED: &str = "alert_unlinked";
/// `CaseEventType.COMMENT_ADDED`.
pub const COMMENT_ADDED: &str = "comment_added";
/// `CaseEventType.TEMPLATE_APPLIED`.
pub const TEMPLATE_APPLIED: &str = "template_applied";
/// `CaseEventType.TASK_ADDED`.
pub const TASK_ADDED: &str = "task_added";
/// `CaseEventType.TASK_STATUS_CHANGED`.
pub const TASK_STATUS_CHANGED: &str = "task_status_changed";
/// `CaseEventType.TASK_COMMENTED`.
pub const TASK_COMMENTED: &str = "task_commented";
/// `CaseEventType.TASK_ASSIGNED`.
pub const TASK_ASSIGNED: &str = "task_assigned";

/// One event to append.
#[derive(Debug, Clone)]
pub struct CaseEvent {
    /// Case.
    pub case_id: i64,
    /// `CaseEventType` value.
    pub event_type: &'static str,
    /// `actor or "system"`.
    pub actor: String,
    /// Payload (`payload or None`: an empty object is stored as NULL).
    pub payload: Option<Value>,
}

impl CaseEvent {
    /// An event by `actor`.
    pub fn new(case_id: i64, event_type: &'static str, actor: &str, payload: Value) -> Self {
        Self {
            case_id,
            event_type,
            actor: if actor.is_empty() {
                "system".into()
            } else {
                actor.to_string()
            },
            payload: Some(payload),
        }
    }
}

/// Insert within the caller's transaction (`commit=False`).
pub async fn insert(conn: &mut MySqlConnection, event: &CaseEvent) -> Result<(), sqlx::Error> {
    let payload = event
        .payload
        .clone()
        .filter(|p| !matches!(p, Value::Null) && p.as_object().is_none_or(|o| !o.is_empty()));
    sqlx::query(
        "INSERT INTO incident_management_case_event (case_id, event_type, actor, timestamp, payload) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(event.case_id)
    .bind(event.event_type)
    .bind(&event.actor)
    .bind(mysql_datetime(now_utc_micros()))
    .bind(payload.map(sqlx::types::Json))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `emit_case_event(..., commit=True)`: its own short transaction, failures
/// logged.
pub async fn emit(db: &Db, events: &[CaseEvent]) {
    let result = async {
        let mut tx = db.pool().begin().await?;
        for event in events {
            insert(&mut tx, event).await?;
        }
        tx.commit().await
    }
    .await;
    if let Err(e) = result {
        tracing::warn!(
            target: "copilot::incidents",
            "Failed to emit CaseEvent(s) {:?}: {e}",
            events.iter().map(|e| (e.case_id, e.event_type)).collect::<Vec<_>>()
        );
    }
}

/// `payload_status_change`.
pub fn status_change(from: Option<&str>, to: &str, forced: bool) -> Value {
    json!({"from": from, "to": to, "forced": forced})
}

/// `payload_assignment`.
pub fn assignment(from: Option<&str>, to: Option<&str>) -> Value {
    json!({"from": from, "to": to})
}

/// `payload_escalation`.
pub fn escalation(escalated: bool) -> Value {
    json!({ "escalated": escalated })
}

/// `payload_alert_link(alert_id, **extra)`.
pub fn alert_link(alert_id: i64, extra: &[(&str, Value)]) -> Value {
    let mut out = Map::new();
    out.insert("alert_id".into(), json!(alert_id));
    for (k, v) in extra {
        out.insert((*k).to_string(), v.clone());
    }
    Value::Object(out)
}

/// `payload_alert_links_bulk`.
pub fn alert_links_bulk(alert_ids: &[i64]) -> Value {
    json!({"alert_ids": alert_ids, "count": alert_ids.len()})
}

/// `payload_comment(comment_id, snippet)`: the first 140 characters.
pub fn comment(comment_id: i64, snippet: &str) -> Value {
    let mut out = Map::new();
    out.insert("comment_id".into(), json!(comment_id));
    if !snippet.is_empty() {
        out.insert(
            "snippet".into(),
            Value::String(snippet.chars().take(140).collect()),
        );
    }
    Value::Object(out)
}

/// `payload_template_applied`.
pub fn template_applied(template_id: i64, template_name: &str, tasks_added: usize) -> Value {
    json!({"template_id": template_id, "template_name": template_name, "tasks_added": tasks_added})
}

/// `payload_task(task_id, title, mandatory, **extra)`.
pub fn task(task_id: i64, title: &str, mandatory: bool, extra: &[(&str, Value)]) -> Value {
    let mut out = Map::new();
    out.insert("task_id".into(), json!(task_id));
    out.insert("title".into(), json!(title));
    out.insert("mandatory".into(), json!(mandatory));
    for (k, v) in extra {
        out.insert((*k).to_string(), v.clone());
    }
    Value::Object(out)
}
