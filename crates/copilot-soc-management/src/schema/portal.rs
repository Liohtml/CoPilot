//! What an end customer sees of the SOC's SLA — port of
//! `customer_portal/schema/sla.py`.
//!
//! A deliberately narrow projection of the dashboard: no field here can
//! carry a person's name, another tenant's figures or the SOC's internal
//! workload. Widening these models is how SOC internals leak into the
//! portal.

use chrono::NaiveDateTime;
use copilot_core::time::pydantic;
use serde::Serialize;

use crate::schema::py_opt_float;

/// `PortalSlaSettings`.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSlaSettings {
    /// Customer.
    pub customer_code: String,
    /// The page is on.
    pub enabled: bool,
    /// `updated_at.isoformat()`.
    pub updated_at: Option<String>,
    /// User id of the last change.
    pub updated_by: Option<i64>,
}

/// `PortalSlaSettingsResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSlaSettingsResponse {
    /// The switch.
    pub settings: PortalSlaSettings,
    /// Always true.
    pub success: bool,
    /// What happened.
    pub message: String,
}

/// `PortalSlaAvailabilityResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSlaAvailabilityResponse {
    /// The customer asked about, if any.
    pub customer_code: Option<String>,
    /// Whether the page renders.
    pub enabled: bool,
    /// Always true.
    pub success: bool,
    /// Which.
    pub message: String,
}

/// `PortalSlaClock`.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSlaClock {
    /// Met.
    pub met: i64,
    /// Breached.
    pub breached: i64,
    /// Percentage met of those decided.
    #[serde(serialize_with = "py_opt_float")]
    pub rate: Option<f64>,
}

/// `PortalSlaEntity`.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSlaEntity {
    /// Opened.
    pub opened: i64,
    /// Resolved.
    pub resolved: i64,
    /// Acknowledge clock.
    pub acknowledge: PortalSlaClock,
    /// Resolve clock.
    pub resolve: PortalSlaClock,
    /// Median, seconds.
    #[serde(serialize_with = "py_opt_float")]
    pub time_to_acknowledge: Option<f64>,
    /// Median, seconds.
    #[serde(serialize_with = "py_opt_float")]
    pub time_to_resolve: Option<f64>,
}

/// `PortalSlaTarget`.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSlaTarget {
    /// Entity.
    pub entity: &'static str,
    /// Severity.
    pub severity: &'static str,
    /// Acknowledge target.
    pub acknowledge_minutes: Option<i64>,
    /// Resolve target.
    pub resolve_minutes: Option<i64>,
    /// Business hours.
    pub business_hours: bool,
    /// Opened in the period.
    pub opened: i64,
    /// Acknowledge compliance.
    #[serde(serialize_with = "py_opt_float")]
    pub acknowledge_rate: Option<f64>,
    /// Resolve compliance.
    #[serde(serialize_with = "py_opt_float")]
    pub resolve_rate: Option<f64>,
    /// Median TTR.
    #[serde(serialize_with = "py_opt_float")]
    pub time_to_resolve: Option<f64>,
}

/// `PortalSlaTrendPoint`.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSlaTrendPoint {
    /// Bucket start.
    #[serde(serialize_with = "pydantic::datetime")]
    pub start: NaiveDateTime,
    /// Opened.
    pub opened: i64,
    /// Resolved.
    pub resolved: i64,
    /// Resolve compliance.
    #[serde(serialize_with = "py_opt_float")]
    pub rate: Option<f64>,
}

/// `PortalSlaOpenNow`.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSlaOpenNow {
    /// Open alerts.
    pub alerts: i64,
    /// Open cases.
    pub cases: i64,
    /// Breached.
    pub breached: i64,
    /// At risk.
    pub at_risk: i64,
    /// Waiting on the customer.
    pub waiting_on_you: i64,
}

/// `PortalSlaOverviewResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSlaOverviewResponse {
    /// False when no customer in scope has the page on.
    pub enabled: bool,
    /// The customers covered.
    pub customer_codes: Vec<String>,
    /// Period start.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub date_from: Option<NaiveDateTime>,
    /// Period end.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub date_to: Option<NaiveDateTime>,
    /// Trend bucket.
    pub bucket: Option<&'static str>,
    /// When tracking began.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub tracking_since: Option<NaiveDateTime>,
    /// Alerts.
    pub alerts: Option<PortalSlaEntity>,
    /// Cases.
    pub cases: Option<PortalSlaEntity>,
    /// Alerts, previous period.
    pub previous_alerts: Option<PortalSlaEntity>,
    /// Cases, previous period.
    pub previous_cases: Option<PortalSlaEntity>,
    /// Targets.
    pub targets: Vec<PortalSlaTarget>,
    /// Trend.
    pub trend: Vec<PortalSlaTrendPoint>,
    /// Open now.
    pub open_now: Option<PortalSlaOpenNow>,
    /// Always true.
    pub success: bool,
    /// What happened.
    pub message: String,
}

impl PortalSlaOverviewResponse {
    /// `PortalSlaOverviewResponse(enabled=False, message=…)`: nothing read.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            customer_codes: Vec::new(),
            date_from: None,
            date_to: None,
            bucket: None,
            tracking_since: None,
            alerts: None,
            cases: None,
            previous_alerts: None,
            previous_cases: None,
            targets: Vec::new(),
            trend: Vec::new(),
            open_now: None,
            success: true,
            message: "The SLA page is not enabled for this customer".into(),
        }
    }
}
