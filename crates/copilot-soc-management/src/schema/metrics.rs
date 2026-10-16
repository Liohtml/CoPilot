//! Response shapes of the SOC Management dashboard — port of
//! `soc_management/schema/metrics.py`, field for field.

use chrono::NaiveDateTime;
use copilot_core::time::pydantic;
use copilot_sla::evaluate::Compliance;
use serde::Serialize;

use crate::domain::analytics::{
    AnalystRow, AssigneeLoad, AttentionItem, CustomerRow, EntityHeadline, Headline, RuleRow,
    SeverityLoad, SeverityRow, SlaPair, TrendPoint, Workload,
};
use crate::domain::stats::DurationStats;
use crate::schema::policy::PolicyMatrix;
use crate::schema::{py_float, py_opt_float};

/// `DurationStatsOut`.
#[derive(Debug, Clone, Serialize)]
pub struct DurationStatsOut {
    /// Count.
    pub count: i64,
    /// Mean.
    #[serde(serialize_with = "py_opt_float")]
    pub mean: Option<f64>,
    /// Median.
    #[serde(serialize_with = "py_opt_float")]
    pub median: Option<f64>,
    /// 90th percentile.
    #[serde(serialize_with = "py_opt_float")]
    pub p90: Option<f64>,
}

impl From<&DurationStats> for DurationStatsOut {
    fn from(s: &DurationStats) -> Self {
        Self {
            count: s.count,
            mean: s.mean,
            median: s.median,
            p90: s.p90,
        }
    }
}

/// `ComplianceOut`.
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceOut {
    /// Met.
    pub met: i64,
    /// Breached.
    pub breached: i64,
    /// At risk.
    pub at_risk: i64,
    /// On track.
    pub on_track: i64,
    /// Paused.
    pub paused: i64,
    /// Not tracked.
    pub not_tracked: i64,
    /// Met + breached.
    pub decided: i64,
    /// Percentage met.
    #[serde(serialize_with = "py_opt_float")]
    pub rate: Option<f64>,
}

impl From<&Compliance> for ComplianceOut {
    fn from(c: &Compliance) -> Self {
        Self {
            met: c.met,
            breached: c.breached,
            at_risk: c.at_risk,
            on_track: c.on_track,
            paused: c.paused,
            not_tracked: c.not_tracked,
            decided: c.decided(),
            rate: c.rate(),
        }
    }
}

/// `SlaPairOut`.
#[derive(Debug, Clone, Serialize)]
pub struct SlaPairOut {
    /// Acknowledge.
    pub ack: ComplianceOut,
    /// Resolve.
    pub resolve: ComplianceOut,
}

impl From<&SlaPair> for SlaPairOut {
    fn from(p: &SlaPair) -> Self {
        Self {
            ack: (&p.ack).into(),
            resolve: (&p.resolve).into(),
        }
    }
}

/// `EntityHeadlineOut`.
#[derive(Debug, Clone, Serialize)]
pub struct EntityHeadlineOut {
    /// Opened.
    pub opened: i64,
    /// Resolved.
    pub resolved: i64,
    /// Resolved by a customer.
    pub resolved_by_customer: i64,
    /// TTA.
    pub tta: DurationStatsOut,
    /// TTR.
    pub ttr: DurationStatsOut,
    /// Compliance.
    pub sla: SlaPairOut,
    /// Reopened.
    pub reopened: i64,
}

impl From<&EntityHeadline> for EntityHeadlineOut {
    fn from(h: &EntityHeadline) -> Self {
        Self {
            opened: h.opened,
            resolved: h.resolved,
            resolved_by_customer: h.resolved_by_customer,
            tta: (&h.tta).into(),
            ttr: (&h.ttr).into(),
            sla: (&h.sla).into(),
            reopened: h.reopened,
        }
    }
}

/// `HeadlineOut`.
#[derive(Debug, Clone, Serialize)]
pub struct HeadlineOut {
    /// Alerts.
    pub alerts: EntityHeadlineOut,
    /// Cases.
    pub cases: EntityHeadlineOut,
    /// False-positive rate.
    #[serde(serialize_with = "py_opt_float")]
    pub false_positive_rate: Option<f64>,
    /// Reviewed alerts.
    pub reviewed_alerts: i64,
    /// Case conversion rate.
    #[serde(serialize_with = "py_opt_float")]
    pub case_conversion_rate: Option<f64>,
    /// Escalated alerts.
    pub escalated_alerts: i64,
}

impl From<&Headline> for HeadlineOut {
    fn from(h: &Headline) -> Self {
        Self {
            alerts: (&h.alerts).into(),
            cases: (&h.cases).into(),
            false_positive_rate: h.false_positive_rate,
            reviewed_alerts: h.reviewed_alerts,
            case_conversion_rate: h.case_conversion_rate,
            escalated_alerts: h.escalated_alerts,
        }
    }
}

/// `SeverityRowOut`.
#[derive(Debug, Clone, Serialize)]
pub struct SeverityRowOut {
    /// Entity.
    pub entity: &'static str,
    /// Severity.
    pub severity: &'static str,
    /// Opened.
    pub opened: i64,
    /// Resolved.
    pub resolved: i64,
    /// Open now.
    pub open_now: i64,
    /// Breached now.
    pub breached_now: i64,
    /// TTA.
    pub tta: DurationStatsOut,
    /// TTR.
    pub ttr: DurationStatsOut,
    /// Compliance.
    pub sla: SlaPairOut,
}

impl From<&SeverityRow> for SeverityRowOut {
    fn from(r: &SeverityRow) -> Self {
        Self {
            entity: r.entity.as_str(),
            severity: r.severity,
            opened: r.opened,
            resolved: r.resolved,
            open_now: r.open_now,
            breached_now: r.breached_now,
            tta: (&r.tta).into(),
            ttr: (&r.ttr).into(),
            sla: (&r.sla).into(),
        }
    }
}

/// `TrendPointOut`.
#[derive(Debug, Clone, Serialize)]
pub struct TrendPointOut {
    /// Bucket start.
    #[serde(serialize_with = "pydantic::datetime")]
    pub start: NaiveDateTime,
    /// Alerts opened.
    pub alerts_opened: i64,
    /// Alerts resolved.
    pub alerts_resolved: i64,
    /// Cases opened.
    pub cases_opened: i64,
    /// Cases resolved.
    pub cases_resolved: i64,
    /// SLA rate.
    #[serde(serialize_with = "py_opt_float")]
    pub sla_rate: Option<f64>,
    /// Alert TTR median.
    #[serde(serialize_with = "py_opt_float")]
    pub alert_ttr_median: Option<f64>,
}

impl From<&TrendPoint> for TrendPointOut {
    fn from(p: &TrendPoint) -> Self {
        Self {
            start: p.start,
            alerts_opened: p.alerts_opened,
            alerts_resolved: p.alerts_resolved,
            cases_opened: p.cases_opened,
            cases_resolved: p.cases_resolved,
            sla_rate: p.sla_rate,
            alert_ttr_median: p.alert_ttr_median,
        }
    }
}

/// `AnalystRowOut`.
#[derive(Debug, Clone, Serialize)]
pub struct AnalystRowOut {
    /// User.
    pub username: String,
    /// Alerts acknowledged.
    pub alerts_acknowledged: i64,
    /// Alerts resolved.
    pub alerts_resolved: i64,
    /// Cases acknowledged.
    pub cases_acknowledged: i64,
    /// Cases resolved.
    pub cases_resolved: i64,
    /// TTA.
    pub tta: DurationStatsOut,
    /// TTR.
    pub ttr: DurationStatsOut,
    /// Compliance.
    pub sla: ComplianceOut,
    /// Open alerts.
    pub open_alerts: i64,
    /// Open cases.
    pub open_cases: i64,
    /// At risk.
    pub at_risk: i64,
    /// Breached.
    pub breached: i64,
}

impl From<&AnalystRow> for AnalystRowOut {
    fn from(r: &AnalystRow) -> Self {
        Self {
            username: r.username.clone(),
            alerts_acknowledged: r.alerts_acknowledged,
            alerts_resolved: r.alerts_resolved,
            cases_acknowledged: r.cases_acknowledged,
            cases_resolved: r.cases_resolved,
            tta: (&r.tta).into(),
            ttr: (&r.ttr).into(),
            sla: (&r.sla).into(),
            open_alerts: r.open_alerts,
            open_cases: r.open_cases,
            at_risk: r.at_risk,
            breached: r.breached,
        }
    }
}

/// `RuleRowOut`.
#[derive(Debug, Clone, Serialize)]
pub struct RuleRowOut {
    /// Title.
    pub alert_name: String,
    /// Sources.
    pub sources: Vec<String>,
    /// Alerts.
    pub alerts: i64,
    /// In a case.
    pub in_case: i64,
    /// Reviewed.
    pub reviewed: i64,
    /// True positives.
    pub true_positives: i64,
    /// False positives.
    pub false_positives: i64,
    /// False-positive rate.
    #[serde(serialize_with = "py_opt_float")]
    pub false_positive_rate: Option<f64>,
    /// Noisy.
    pub noisy: bool,
    /// Open now.
    pub open_now: i64,
    /// TTR.
    pub ttr: DurationStatsOut,
    /// Compliance.
    pub sla: ComplianceOut,
    /// Series.
    pub series: Vec<i64>,
}

impl From<&RuleRow> for RuleRowOut {
    fn from(r: &RuleRow) -> Self {
        Self {
            alert_name: r.alert_name.clone(),
            sources: r.sources.clone(),
            alerts: r.alerts,
            in_case: r.in_case,
            reviewed: r.reviewed,
            true_positives: r.true_positives,
            false_positives: r.false_positives,
            false_positive_rate: r.false_positive_rate,
            noisy: r.noisy,
            open_now: r.open_now,
            ttr: (&r.ttr).into(),
            sla: (&r.sla).into(),
            series: r.series.clone(),
        }
    }
}

/// `CustomerRowOut`.
#[derive(Debug, Clone, Serialize)]
pub struct CustomerRowOut {
    /// Code.
    pub customer_code: String,
    /// Name.
    pub customer_name: Option<String>,
    /// Alerts.
    pub alerts: i64,
    /// Cases.
    pub cases: i64,
    /// Resolved.
    pub resolved: i64,
    /// Open now.
    pub open_now: i64,
    /// Breached now.
    pub breached_now: i64,
    /// Alert TTR.
    pub alert_ttr: DurationStatsOut,
    /// Case TTR.
    pub case_ttr: DurationStatsOut,
    /// Alert compliance.
    pub alert_sla: ComplianceOut,
    /// Case compliance.
    pub case_sla: ComplianceOut,
    /// Top rule.
    pub top_rule: Option<String>,
}

impl CustomerRowOut {
    /// From a row and the customer's name.
    pub fn new(r: &CustomerRow, customer_name: Option<String>) -> Self {
        Self {
            customer_code: r.customer_code.clone(),
            customer_name,
            alerts: r.alerts,
            cases: r.cases,
            resolved: r.resolved,
            open_now: r.open_now,
            breached_now: r.breached_now,
            alert_ttr: (&r.alert_ttr).into(),
            case_ttr: (&r.case_ttr).into(),
            alert_sla: (&r.alert_sla).into(),
            case_sla: (&r.case_sla).into(),
            top_rule: r.top_rule.clone(),
        }
    }
}

/// `SeverityLoadOut`.
#[derive(Debug, Clone, Serialize)]
pub struct SeverityLoadOut {
    /// Severity.
    pub severity: &'static str,
    /// Alerts.
    pub alerts: i64,
    /// Cases.
    pub cases: i64,
    /// Breached.
    pub breached: i64,
    /// At risk.
    pub at_risk: i64,
}

impl From<&SeverityLoad> for SeverityLoadOut {
    fn from(s: &SeverityLoad) -> Self {
        Self {
            severity: s.severity,
            alerts: s.alerts,
            cases: s.cases,
            breached: s.breached,
            at_risk: s.at_risk,
        }
    }
}

/// `AssigneeLoadOut`.
#[derive(Debug, Clone, Serialize)]
pub struct AssigneeLoadOut {
    /// User.
    pub username: String,
    /// Alerts.
    pub alerts: i64,
    /// Cases.
    pub cases: i64,
    /// Breached.
    pub breached: i64,
    /// At risk.
    pub at_risk: i64,
}

impl From<&AssigneeLoad> for AssigneeLoadOut {
    fn from(a: &AssigneeLoad) -> Self {
        Self {
            username: a.username.clone(),
            alerts: a.alerts,
            cases: a.cases,
            breached: a.breached,
            at_risk: a.at_risk,
        }
    }
}

/// `WorkloadOut` (Pydantic's field order: `waiting_on_customer` after
/// `at_risk`).
#[derive(Debug, Clone, Serialize)]
pub struct WorkloadOut {
    /// Open alerts.
    pub open_alerts: i64,
    /// Open cases.
    pub open_cases: i64,
    /// Unassigned alerts.
    pub unassigned_alerts: i64,
    /// Unassigned cases.
    pub unassigned_cases: i64,
    /// Oldest unassigned.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub oldest_unassigned_at: Option<NaiveDateTime>,
    /// Breached.
    pub breached: i64,
    /// At risk.
    pub at_risk: i64,
    /// Waiting on the customer.
    pub waiting_on_customer: i64,
    /// Per severity.
    pub by_severity: Vec<SeverityLoadOut>,
    /// Per assignee.
    pub by_assignee: Vec<AssigneeLoadOut>,
}

impl From<&Workload> for WorkloadOut {
    fn from(w: &Workload) -> Self {
        Self {
            open_alerts: w.open_alerts,
            open_cases: w.open_cases,
            unassigned_alerts: w.unassigned_alerts,
            unassigned_cases: w.unassigned_cases,
            oldest_unassigned_at: w.oldest_unassigned_at,
            breached: w.breached,
            at_risk: w.at_risk,
            waiting_on_customer: w.waiting_on_customer,
            by_severity: w.by_severity.iter().map(Into::into).collect(),
            by_assignee: w.by_assignee.iter().map(Into::into).collect(),
        }
    }
}

/// `AttentionItemOut`.
#[derive(Debug, Clone, Serialize)]
pub struct AttentionItemOut {
    /// Entity.
    pub entity: &'static str,
    /// Id.
    pub id: i64,
    /// Title.
    pub title: String,
    /// Tenant.
    pub customer_code: Option<String>,
    /// Severity.
    pub severity: String,
    /// Status.
    pub status: String,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Opening.
    #[serde(serialize_with = "pydantic::datetime")]
    pub opened_at: NaiveDateTime,
    /// State.
    pub state: &'static str,
    /// Clock.
    pub clock: &'static str,
    /// Due time.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub due_at: Option<NaiveDateTime>,
    /// Overdue seconds.
    #[serde(serialize_with = "py_float")]
    pub overdue_seconds: f64,
}

impl From<&AttentionItem> for AttentionItemOut {
    fn from(i: &AttentionItem) -> Self {
        Self {
            entity: i.entity.as_str(),
            id: i.id,
            title: i.title.clone(),
            customer_code: i.customer_code.clone(),
            severity: i.severity.clone(),
            status: i.status.clone(),
            assigned_to: i.assigned_to.clone(),
            opened_at: i.opened_at,
            state: i.state.as_str(),
            clock: i.clock,
            due_at: i.due_at,
            overdue_seconds: i.overdue_seconds,
        }
    }
}

/// `PeriodOut`.
#[derive(Debug, Clone, Serialize)]
pub struct PeriodOut {
    /// Start.
    #[serde(serialize_with = "pydantic::datetime")]
    pub date_from: NaiveDateTime,
    /// End.
    #[serde(serialize_with = "pydantic::datetime")]
    pub date_to: NaiveDateTime,
    /// Previous start.
    #[serde(serialize_with = "pydantic::datetime")]
    pub previous_from: NaiveDateTime,
    /// Previous end.
    #[serde(serialize_with = "pydantic::datetime")]
    pub previous_to: NaiveDateTime,
    /// Trend bucket.
    pub bucket: &'static str,
}

/// `Viewer`.
#[derive(Debug, Clone, Serialize)]
pub struct Viewer {
    /// User.
    pub username: String,
    /// Admin.
    pub is_admin: bool,
    /// Sees every analyst's row.
    pub sees_all_analysts: bool,
}

/// `DashboardResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardResponse {
    /// Always true.
    pub success: bool,
    /// Empty.
    pub message: String,
    /// When the states were evaluated.
    #[serde(serialize_with = "pydantic::datetime")]
    pub generated_at: NaiveDateTime,
    /// The period.
    pub period: PeriodOut,
    /// Who it was computed for.
    pub viewer: Viewer,
    /// The customers covered (`None`: every customer the caller sees).
    pub customer_codes: Option<Vec<String>>,
    /// When tracking began.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub tracking_since: Option<NaiveDateTime>,
    /// This period.
    pub headline: HeadlineOut,
    /// The previous one.
    pub previous: HeadlineOut,
    /// Per severity.
    pub severities: Vec<SeverityRowOut>,
    /// Trend.
    pub trends: Vec<TrendPointOut>,
    /// Analysts.
    pub analysts: Vec<AnalystRowOut>,
    /// Rules.
    pub rules: Vec<RuleRowOut>,
    /// Customers.
    pub customers: Vec<CustomerRowOut>,
    /// Workload.
    pub workload: WorkloadOut,
    /// Attention list.
    pub attention: Vec<AttentionItemOut>,
    /// The policy in force for the scope shown.
    pub policy: PolicyMatrix,
}

/// `AttentionResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct AttentionResponse {
    /// Always true.
    pub success: bool,
    /// Empty.
    pub message: String,
    /// The page.
    pub items: Vec<AttentionItemOut>,
    /// Matching items before the limit.
    pub total: i64,
}

/// `SlaClockOut`.
#[derive(Debug, Clone, Serialize)]
pub struct SlaClockOut {
    /// Due time.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub due_at: Option<NaiveDateTime>,
    /// When achieved.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub achieved_at: Option<NaiveDateTime>,
    /// State.
    pub state: &'static str,
    /// By whom.
    pub by: Option<String>,
    /// Through which action.
    pub action: Option<String>,
    /// Target in minutes.
    pub target_minutes: Option<i64>,
}

/// `ItemSlaResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct ItemSlaResponse {
    /// Always true.
    pub success: bool,
    /// Empty.
    pub message: String,
    /// Entity.
    pub entity: &'static str,
    /// Id.
    pub id: i64,
    /// Severity.
    pub severity: String,
    /// Opening.
    #[serde(serialize_with = "pydantic::datetime")]
    pub opened_at: NaiveDateTime,
    /// Tracked.
    pub tracked: bool,
    /// Acknowledge clock.
    pub ack: SlaClockOut,
    /// Resolve clock.
    pub resolve: SlaClockOut,
    /// First assignment.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub first_assigned_at: Option<NaiveDateTime>,
    /// Reopened.
    pub reopen_count: i64,
    /// Business hours.
    pub business_hours: bool,
    /// The calendar's zone.
    pub calendar_timezone: Option<String>,
    /// Waiting since.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub paused_at: Option<NaiveDateTime>,
    /// Waiting so far.
    pub paused_seconds: i64,
    /// When evaluated.
    #[serde(serialize_with = "pydantic::datetime")]
    pub generated_at: NaiveDateTime,
}

/// `SourceOption`.
#[derive(Debug, Clone, Serialize)]
pub struct SourceOption {
    /// Source.
    pub source: String,
    /// Alerts from it.
    pub alerts: i64,
}

/// `SourcesResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct SourcesResponse {
    /// Always true.
    pub success: bool,
    /// Empty.
    pub message: String,
    /// Sources.
    pub sources: Vec<SourceOption>,
}
