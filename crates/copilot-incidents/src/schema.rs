//! Response shapes — port of `app/incidents/schema/db_operations.py` and
//! `schema/case_templates.py` (the parts the ported routes return).
//!
//! Field order is the Pydantic models' order: serde serializes struct fields
//! in declaration order and the workspace's `serde_json` keeps it. Two
//! timestamp renderings exist and both are kept:
//!
//! - [`fmt_ms_z`]: the `strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"` that
//!   `AlertOut`, `CaseOut`, `CommentBase`, … apply in a `mode="before"`
//!   validator (`2026-01-02T03:04:05.000Z`);
//! - Pydantic's own `datetime` serializer (`2026-01-02T03:04:05`) for the
//!   SQLModel rows (`Alert`, `Comment`, …) and the task/timeline models.

use chrono::{NaiveDateTime, Timelike};
use serde::Serialize;
use serde_json::Value;

use copilot_core::time::pydantic;

use crate::store::{
    AlertRow, AssetRow, CaseCommentRow, CaseEventRow, CaseRow, CaseTaskRow, CommentRow,
    LinkedCaseRow, TagRow,
};

/// `v.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"`: milliseconds, truncated.
pub fn fmt_ms_z(t: NaiveDateTime) -> String {
    let millis = t.nanosecond() / 1_000_000;
    format!("{}.{millis:03}Z", t.format("%Y-%m-%dT%H:%M:%S"))
}

/// `CommentBase`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CommentOut {
    /// Author (stamped by the routes).
    pub user_name: String,
    /// Alert.
    pub alert_id: i32,
    /// Id.
    pub id: i32,
    /// Text.
    pub comment: String,
    /// [`fmt_ms_z`].
    pub created_at: String,
}

impl From<&CommentRow> for CommentOut {
    fn from(c: &CommentRow) -> Self {
        Self {
            user_name: c.user_name.clone(),
            alert_id: c.alert_id.unwrap_or_default(),
            id: c.id,
            comment: c.comment.clone(),
            created_at: fmt_ms_z(c.created_at),
        }
    }
}

/// `AssetBase`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AssetOut {
    /// Host name.
    pub asset_name: String,
    /// Wazuh agent id.
    pub agent_id: Option<String>,
    /// Tenant.
    pub customer_code: String,
    /// Document id in the index.
    pub index_id: String,
    /// Alert.
    pub alert_linked: i32,
    /// Id.
    pub id: i32,
    /// Context row.
    pub alert_context_id: i32,
    /// Velociraptor client id.
    pub velociraptor_id: Option<String>,
    /// Index.
    pub index_name: String,
}

impl From<&AssetRow> for AssetOut {
    fn from(a: &AssetRow) -> Self {
        Self {
            asset_name: a.asset_name.clone(),
            agent_id: a.agent_id.clone(),
            customer_code: a.customer_code.clone(),
            index_id: a.index_id.clone(),
            alert_linked: a.alert_linked.unwrap_or_default(),
            id: a.id,
            alert_context_id: a.alert_context_id,
            velociraptor_id: a.velociraptor_id.clone(),
            index_name: a.index_name.clone(),
        }
    }
}

/// `AlertTagBase`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TagOut {
    /// Tag text.
    pub tag: String,
    /// Tag id.
    pub id: i32,
}

impl From<&TagRow> for TagOut {
    fn from(t: &TagRow) -> Self {
        Self {
            tag: t.tag.clone(),
            id: t.tag_id,
        }
    }
}

/// `IoCBase`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct IocOut {
    /// Value.
    pub value: String,
    /// `AlertIocValue`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Description.
    pub description: Option<String>,
    /// Id.
    pub id: i32,
}

/// `AlertIocValue`.
pub const IOC_TYPES: &[&str] = &["IP", "DOMAIN", "HASH", "URL"];

/// `LinkedCaseCreate`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LinkedCaseOut {
    /// Name.
    pub case_name: String,
    /// Description.
    pub case_description: String,
    /// [`fmt_ms_z`].
    pub case_creation_time: String,
    /// Status.
    pub case_status: String,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Id.
    pub id: i32,
}

impl From<&LinkedCaseRow> for LinkedCaseOut {
    fn from(c: &LinkedCaseRow) -> Self {
        Self {
            case_name: c.case_name.clone(),
            case_description: c.case_description.clone(),
            case_creation_time: fmt_ms_z(c.case_creation_time),
            case_status: c.case_status.clone(),
            assigned_to: c.assigned_to.clone(),
            id: c.case_id,
        }
    }
}

/// `AlertOut`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AlertOut {
    /// Id.
    pub id: i32,
    /// [`fmt_ms_z`].
    pub alert_creation_time: String,
    /// [`fmt_ms_z`].
    pub time_closed: Option<String>,
    /// Title.
    pub alert_name: String,
    /// Description.
    pub alert_description: String,
    /// Status.
    pub status: String,
    /// Tenant.
    pub customer_code: String,
    /// Source.
    pub source: String,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Escalated.
    pub escalated: bool,
    /// Verdict.
    pub verdict: Option<String>,
    /// Reason.
    pub verdict_reason: Option<String>,
    /// Note.
    pub verdict_note: Option<String>,
    /// Who.
    pub verdict_by: Option<String>,
    /// When ([`fmt_ms_z`]).
    pub verdict_at: Option<String>,
    /// Comments.
    pub comments: Vec<CommentOut>,
    /// Assets.
    pub assets: Vec<AssetOut>,
    /// Tags.
    pub tags: Vec<TagOut>,
    /// Cases the alert is linked to.
    pub linked_cases: Vec<LinkedCaseOut>,
    /// IoCs.
    pub iocs: Vec<IocOut>,
}

impl AlertOut {
    /// `build_alert_out` without relationships.
    pub fn bare(a: &AlertRow) -> Self {
        Self {
            id: a.id,
            alert_creation_time: fmt_ms_z(a.alert_creation_time),
            time_closed: a.time_closed.map(fmt_ms_z),
            alert_name: a.alert_name.clone(),
            alert_description: a.alert_description.clone(),
            status: a.status.clone(),
            customer_code: a.customer_code.clone(),
            source: a.source.clone(),
            assigned_to: a.assigned_to.clone(),
            escalated: a.escalated,
            verdict: a.verdict.clone(),
            verdict_reason: a.verdict_reason.clone(),
            verdict_note: a.verdict_note.clone(),
            verdict_by: a.verdict_by.clone(),
            verdict_at: a.verdict_at.map(fmt_ms_z),
            comments: Vec::new(),
            assets: Vec::new(),
            tags: Vec::new(),
            linked_cases: Vec::new(),
            iocs: Vec::new(),
        }
    }
}

/// `AlertOutResponse`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AlertOutResponse {
    /// Page.
    pub alerts: Vec<AlertOut>,
    /// Total.
    pub total: Option<i64>,
    /// OPEN.
    pub open: Option<i64>,
    /// IN_PROGRESS.
    pub in_progress: Option<i64>,
    /// CLOSED.
    pub closed: Option<i64>,
    /// PENDING_CUSTOMER.
    pub pending_customer: Option<i64>,
    /// Filtered total.
    pub total_filtered: Option<i64>,
    /// Always true.
    pub success: bool,
    /// Message.
    pub message: String,
}

/// `CaseCommentBase`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CaseCommentOut {
    /// Author.
    pub user_name: String,
    /// Case.
    pub case_id: i32,
    /// Id.
    pub id: i32,
    /// Text.
    pub comment: String,
    /// [`fmt_ms_z`].
    pub created_at: String,
}

impl From<&CaseCommentRow> for CaseCommentOut {
    fn from(c: &CaseCommentRow) -> Self {
        Self {
            user_name: c.user_name.clone(),
            case_id: c.case_id.unwrap_or_default(),
            id: c.id,
            comment: c.comment.clone(),
            created_at: fmt_ms_z(c.created_at),
        }
    }
}

/// `CaseOut`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CaseOut {
    /// Id.
    pub id: i32,
    /// Name.
    pub case_name: String,
    /// Description.
    pub case_description: String,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Linked alerts.
    pub alerts: Vec<AlertOut>,
    /// Status.
    pub case_status: String,
    /// [`fmt_ms_z`].
    pub case_creation_time: String,
    /// Tenant.
    pub customer_code: Option<String>,
    /// `notification_invoked_number or 0`.
    pub notification_invoked_number: i32,
    /// Escalated.
    pub escalated: bool,
    /// The analyst's severity (`None` = derived from the alerts).
    pub severity: Option<String>,
    /// Comments.
    pub comments: Vec<CaseCommentOut>,
}

impl CaseOut {
    /// `CaseOut(...)` without relationships.
    pub fn bare(c: &CaseRow) -> Self {
        Self {
            id: c.id,
            case_name: c.case_name.clone(),
            case_description: c.case_description.clone(),
            assigned_to: c.assigned_to.clone(),
            alerts: Vec::new(),
            case_status: c.case_status.clone(),
            case_creation_time: fmt_ms_z(c.case_creation_time),
            customer_code: c.customer_code.clone(),
            notification_invoked_number: c.notification_invoked_number.unwrap_or(0),
            escalated: c.escalated,
            severity: c.severity.clone(),
            comments: Vec::new(),
        }
    }
}

/// `CaseOutResponse`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CaseOutResponse {
    /// Cases.
    pub cases: Vec<CaseOut>,
    /// Total.
    pub total: Option<i64>,
    /// OPEN.
    pub open: Option<i64>,
    /// IN_PROGRESS.
    pub in_progress: Option<i64>,
    /// CLOSED.
    pub closed: Option<i64>,
    /// PENDING_CUSTOMER.
    pub pending_customer: Option<i64>,
    /// Always true.
    pub success: bool,
    /// Message.
    pub message: String,
}

/// The SQLModel `Alert` row as a response field (`AlertResponse.alert`).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AlertRecord {
    /// Id.
    pub id: i32,
    /// Title.
    pub alert_name: String,
    /// Description.
    pub alert_description: String,
    /// Status.
    pub status: String,
    /// Creation / last-seen time.
    #[serde(serialize_with = "pydantic::datetime")]
    pub alert_creation_time: NaiveDateTime,
    /// Tenant.
    pub customer_code: String,
    /// Closed at.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub time_closed: Option<NaiveDateTime>,
    /// Source.
    pub source: String,
    /// Severity.
    pub severity: Option<String>,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Escalated.
    pub escalated: bool,
    /// Verdict.
    pub verdict: Option<String>,
    /// Reason.
    pub verdict_reason: Option<String>,
    /// Note.
    pub verdict_note: Option<String>,
    /// Who.
    pub verdict_by: Option<String>,
    /// When.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub verdict_at: Option<NaiveDateTime>,
}

impl From<&AlertRow> for AlertRecord {
    fn from(a: &AlertRow) -> Self {
        Self {
            id: a.id,
            alert_name: a.alert_name.clone(),
            alert_description: a.alert_description.clone(),
            status: a.status.clone(),
            alert_creation_time: a.alert_creation_time,
            customer_code: a.customer_code.clone(),
            time_closed: a.time_closed,
            source: a.source.clone(),
            severity: a.severity.clone(),
            assigned_to: a.assigned_to.clone(),
            escalated: a.escalated,
            verdict: a.verdict.clone(),
            verdict_reason: a.verdict_reason.clone(),
            verdict_note: a.verdict_note.clone(),
            verdict_by: a.verdict_by.clone(),
            verdict_at: a.verdict_at,
        }
    }
}

/// `CaseTaskResponse`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CaseTaskOut {
    /// Id.
    pub id: i32,
    /// Case.
    pub case_id: i32,
    /// Originating alert.
    pub alert_id: Option<i32>,
    /// Template task (soft link).
    pub template_task_id: Option<i32>,
    /// Title.
    pub title: String,
    /// Description.
    pub description: Option<String>,
    /// Guidelines.
    pub guidelines: Option<String>,
    /// Mandatory.
    pub mandatory: bool,
    /// Order.
    pub order_index: i32,
    /// `CaseTaskStatus`.
    pub status: String,
    /// Evidence.
    pub evidence_comment: Option<String>,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Completed by.
    pub completed_by: Option<String>,
    /// Completed at.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub completed_at: Option<NaiveDateTime>,
    /// Creator.
    pub created_by: String,
    /// Created.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
    /// Updated.
    #[serde(serialize_with = "pydantic::datetime")]
    pub updated_at: NaiveDateTime,
}

impl From<&CaseTaskRow> for CaseTaskOut {
    fn from(t: &CaseTaskRow) -> Self {
        Self {
            id: t.id,
            case_id: t.case_id,
            alert_id: t.alert_id,
            template_task_id: t.template_task_id,
            title: t.title.clone(),
            description: t.description.clone(),
            guidelines: t.guidelines.clone(),
            mandatory: t.mandatory,
            order_index: t.order_index,
            status: t.status.clone(),
            evidence_comment: t.evidence_comment.clone(),
            assigned_to: t.assigned_to.clone(),
            completed_by: t.completed_by.clone(),
            completed_at: t.completed_at,
            created_by: t.created_by.clone(),
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

/// `CaseTaskStatus`.
pub const TASK_STATUSES: &[&str] = &["TODO", "DONE", "NOT_NECESSARY"];

/// `CaseEventResponse`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CaseEventOut {
    /// Id.
    pub id: i32,
    /// Case.
    pub case_id: i32,
    /// `CaseEventType` value.
    pub event_type: String,
    /// Who.
    pub actor: String,
    /// When.
    #[serde(serialize_with = "pydantic::datetime")]
    pub timestamp: NaiveDateTime,
    /// Event-specific payload.
    pub payload: Option<Value>,
}

impl From<&CaseEventRow> for CaseEventOut {
    fn from(e: &CaseEventRow) -> Self {
        Self {
            id: e.id,
            case_id: e.case_id,
            event_type: e.event_type.clone(),
            actor: e.actor.clone(),
            timestamp: e.timestamp,
            payload: e.payload.clone(),
        }
    }
}

/// `AlertStatus` (also the case statuses).
pub const ALERT_STATUSES: &[&str] = &["OPEN", "CLOSED", "IN_PROGRESS", "PENDING_CUSTOMER"];

/// `AlertVerdict`.
pub const VERDICTS: &[&str] = &["TRUE_POSITIVE", "FALSE_POSITIVE"];

/// `VERDICT_FILTER_UNTRIAGED`.
pub const VERDICT_UNTRIAGED: &str = "UNTRIAGED";

/// `FalsePositiveReason`.
pub const FALSE_POSITIVE_REASONS: &[&str] = &[
    "EXPECTED_ACTIVITY",
    "KNOWN_APPLICATION",
    "AUTHORIZED_USER",
    "RULE_TOO_SENSITIVE",
    "OTHER",
];

/// `CaseSeverity` (= `alert_severity.SEVERITY_LEVELS`, most severe first).
pub const CASE_SEVERITIES: &[&str] = &["Critical", "High", "Medium", "Low", "Informational"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn milliseconds_are_truncated_like_strftime_slicing() {
        let t = NaiveDateTime::parse_from_str("2026-01-02 03:04:05.678999", "%Y-%m-%d %H:%M:%S%.f")
            .unwrap();
        assert_eq!(fmt_ms_z(t), "2026-01-02T03:04:05.678Z");
        let whole =
            NaiveDateTime::parse_from_str("2026-01-02 03:04:05", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(fmt_ms_z(whole), "2026-01-02T03:04:05.000Z");
    }
}
