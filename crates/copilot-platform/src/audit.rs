//! The audit log read API — port of `app/audit/schema/audit.py` and the
//! vocabularies of `app/audit/models/audit.py`.

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value};

use copilot_core::time::pydantic;
use copilot_db::audit::{AuditLogRow, JsonColumn};
use copilot_web::ApiError;

/// `AuditAction` values, in declaration order (a test keeps them equal to
/// the Python enum).
pub const AUDIT_ACTIONS: &[&str] = &[
    "auth.login",
    "auth.login_failed",
    "auth.logout",
    "user.create",
    "user.delete",
    "user.update",
    "user.role_change",
    "connector.create",
    "connector.update",
    "connector.delete",
    "agent.delete",
    "agent.criticality_change",
    "response.quarantine",
    "response.command_execute",
    "artifact.collect",
    "response.copilot_action_invoke",
    "response.sysmon_deploy",
    "case.create",
    "alert.verdict_set",
    "alert.verdict_clear",
    "ai_analysis.request",
    "ai_report.settings_update",
    "uba.mode_change",
    "uba.rollback",
    "datastore.file_create",
    "datastore.file_delete",
];

/// `AuditResult` values.
pub const AUDIT_RESULTS: &[&str] = &["success", "failure"];

/// `GET /audit` caps a page at this many rows (`MAX_LIMIT`).
pub const MAX_LIMIT: i64 = 1000;

/// `AuditLogEntry`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditLogEntry {
    /// Primary key.
    pub id: i32,
    /// When.
    #[serde(serialize_with = "pydantic::datetime")]
    pub timestamp: NaiveDateTime,
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
    /// State before.
    pub old_value: Option<Map<String, Value>>,
    /// State after.
    pub new_value: Option<Map<String, Value>>,
    /// Source address.
    pub source_ip: Option<String>,
    /// Free text.
    pub details: Option<String>,
}

/// `Optional[dict]`: a stored JSON value that is not an object fails the
/// response model — a bare 500 in Python.
fn dict(field: &str, v: Option<JsonColumn>) -> Result<Option<Map<String, Value>>, ApiError> {
    match v.map(|j| j.0) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(other) => Err(ApiError::internal(format!(
            "AuditLogEntry.{field}: not a dict: {other}"
        ))),
    }
}

impl AuditLogEntry {
    /// `AuditLogEntry.model_validate(row)`.
    pub fn from_row(r: AuditLogRow) -> Result<Self, ApiError> {
        Ok(Self {
            id: r.id,
            timestamp: r.timestamp,
            actor_user_id: r.actor_user_id,
            actor_username: r.actor_username,
            customer_code: r.customer_code,
            action: r.action,
            entity_type: r.entity_type,
            entity_id: r.entity_id,
            result: r.result,
            old_value: dict("old_value", r.old_value)?,
            new_value: dict("new_value", r.new_value)?,
            source_ip: r.source_ip,
            details: r.details,
        })
    }
}

/// `{"total", "skip", "limit"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Pagination {
    /// Rows matching the filters.
    pub total: i64,
    /// Offset.
    pub skip: i64,
    /// Page size.
    pub limit: i64,
}

/// `AuditLogResponse`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditLogResponse {
    /// The page.
    pub audit_logs: Vec<AuditLogEntry>,
    /// Paging.
    pub pagination: Pagination,
    /// Always `true`.
    pub success: bool,
    /// `Retrieved {n} of {total} audit log entries`.
    pub message: String,
}

/// `AuditLogDetailResponse`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditLogDetailResponse {
    /// The entry.
    pub audit_log: AuditLogEntry,
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
}

/// `GET /audit/actions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VocabulariesResponse {
    /// Every action.
    pub actions: &'static [&'static str],
    /// Every result.
    pub results: &'static [&'static str],
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: &'static str,
}

/// The vocabularies.
pub fn vocabularies() -> VocabulariesResponse {
    VocabulariesResponse {
        actions: AUDIT_ACTIONS,
        results: AUDIT_RESULTS,
        success: true,
        message: "Audit vocabularies retrieved successfully",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The string values of `class <name>(str, Enum)` in the Python source.
    fn enum_values(src: &str, class: &str) -> Vec<String> {
        let start = src.find(&format!("class {class}(")).unwrap();
        let body = &src[start..];
        let end = body[1..].find("\nclass ").map_or(body.len(), |i| i + 1);
        body[..end]
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let (_, v) = l.split_once(" = \"")?;
                v.strip_suffix('"').map(str::to_string)
            })
            .collect()
    }

    #[test]
    fn vocabularies_match_the_python_enums() {
        let src = include_str!("../../../backend/app/audit/models/audit.py");
        assert_eq!(enum_values(src, "AuditAction"), AUDIT_ACTIONS);
        assert_eq!(enum_values(src, "AuditResult"), AUDIT_RESULTS);
    }
}
