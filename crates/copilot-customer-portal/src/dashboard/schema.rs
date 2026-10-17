//! Port of `app/customer_portal/schema/overview.py` and `schema/dashboard.py`.

use chrono::NaiveDateTime;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use copilot_incidents::lists::StatusCounts;

use crate::schema::PortalAiInsightAlert;

/// `_utc_timestamp`: the `AlertOut` / `CaseOut` wire format
/// (`%Y-%m-%dT%H:%M:%S.mmmZ`).
pub fn utc_timestamp(t: &NaiveDateTime) -> String {
    format!(
        "{}.{:03}Z",
        t.format("%Y-%m-%dT%H:%M:%S"),
        t.and_utc().timestamp_subsec_micros() / 1000
    )
}

fn timestamp<S: Serializer>(t: &NaiveDateTime, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&utc_timestamp(t))
}

/// `OverviewStatusCounts`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct OverviewStatusCounts {
    /// Every status.
    pub total: i64,
    /// OPEN.
    pub open: i64,
    /// IN_PROGRESS.
    pub in_progress: i64,
    /// CLOSED.
    pub closed: i64,
    /// PENDING_CUSTOMER.
    pub pending_customer: i64,
}

impl From<StatusCounts> for OverviewStatusCounts {
    fn from(c: StatusCounts) -> Self {
        Self {
            total: c.total,
            open: c.open,
            in_progress: c.in_progress,
            closed: c.closed,
            pending_customer: c.pending_customer,
        }
    }
}

/// `OverviewAlert`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverviewAlert {
    /// Alert id.
    pub id: i32,
    /// Title.
    pub alert_name: String,
    /// Description.
    pub alert_description: Option<String>,
    /// Status.
    pub status: String,
    /// Creation (last seen) time.
    #[serde(serialize_with = "timestamp")]
    pub alert_creation_time: NaiveDateTime,
    /// Source.
    pub source: String,
    /// Tenant.
    pub customer_code: String,
    /// Its assets' names, in asset id order.
    pub asset_names: Vec<String>,
}

/// `OverviewCase`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverviewCase {
    /// Case id.
    pub id: i32,
    /// Name.
    pub case_name: String,
    /// Description.
    pub case_description: Option<String>,
    /// Status.
    pub case_status: String,
    /// Creation time.
    #[serde(serialize_with = "timestamp")]
    pub case_creation_time: NaiveDateTime,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Tenant.
    pub customer_code: Option<String>,
    /// Linked alerts.
    pub alert_count: i64,
}

/// `OverviewAlertsSection`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OverviewAlertsSection {
    /// Per-status counts.
    pub counts: OverviewStatusCounts,
    /// The most recent alerts.
    pub recent: Vec<OverviewAlert>,
    /// `Failed to load …` when the section failed.
    pub error: Option<String>,
}

/// `OverviewCasesSection`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OverviewCasesSection {
    /// Per-status counts.
    pub counts: OverviewStatusCounts,
    /// The most recent cases.
    pub recent: Vec<OverviewCase>,
    /// `Failed to load …` when the section failed.
    pub error: Option<String>,
}

/// `OverviewAgentsSection`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OverviewAgentsSection {
    /// Agents in scope.
    pub total: i64,
    /// `active`.
    pub online: i64,
    /// The rest.
    pub offline: i64,
    /// Critical assets.
    pub critical: i64,
    /// `Failed to load …` when the section failed.
    pub error: Option<String>,
}

/// `OverviewAiSection`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct OverviewAiSection {
    /// Alerts with an AI report.
    pub total_reports: i64,
    /// Latest-report severities.
    pub severity_counts: Map<String, Value>,
    /// The most recent reports.
    pub recent: Vec<PortalAiInsightAlert>,
    /// `Failed to load …` when the section failed.
    pub error: Option<String>,
}

/// `CustomerPortalOverviewResponse`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CustomerPortalOverviewResponse {
    /// Alerts.
    pub alerts: OverviewAlertsSection,
    /// Cases.
    pub cases: OverviewCasesSection,
    /// Agents.
    pub agents: OverviewAgentsSection,
    /// AI findings.
    pub ai: OverviewAiSection,
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
}

/// `CustomerDashboardStatsResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerDashboardStatsResponse {
    /// Alerts the caller may see.
    pub total_alerts: i64,
    /// Cases.
    pub total_cases: i64,
    /// Agents.
    pub total_agents: i64,
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
}

/// `CustomerDashboardAlertStatsResponse` / `…CaseStatsResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusStatsResponse {
    /// Every status.
    pub total: i64,
    /// OPEN.
    pub open: i64,
    /// IN_PROGRESS.
    pub in_progress: i64,
    /// CLOSED.
    pub closed: i64,
    /// PENDING_CUSTOMER.
    pub pending_customer: i64,
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
}

impl StatusStatsResponse {
    /// The counts and the message.
    pub fn new(c: StatusCounts, message: &str) -> Self {
        Self {
            total: c.total,
            open: c.open,
            in_progress: c.in_progress,
            closed: c.closed,
            pending_customer: c.pending_customer,
            success: true,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn timestamps_have_milliseconds_and_z() {
        let t = chrono::NaiveDate::from_ymd_opt(2026, 9, 1)
            .and_then(|d| d.and_hms_micro_opt(12, 0, 0, 987_654))
            .expect("date");
        assert_eq!(utc_timestamp(&t), "2026-09-01T12:00:00.987Z");
        let whole = t.with_nanosecond(0).expect("valid");
        assert_eq!(utc_timestamp(&whole), "2026-09-01T12:00:00.000Z");
    }
}
