//! Port of `app/customer_portal/schema/ai_reports.py`.
//!
//! Read-only projections of the `ai_analyst_*` tables for end customers.
//! They deliberately expose **less** than `copilot_ai_analyst::schema`: job
//! ids, template names and agent error messages are SOC/agent plumbing and
//! never reach the portal. Widening these structs is how investigation
//! internals would leak — `tests::projections_carry_no_internals` pins it.
//!
//! Field order is the Pydantic models' order (the frontends do not care, the
//! parity harness does).

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value};

use copilot_core::time::pydantic;
use copilot_db::ai_analyst::{IocRow, JobRow, ReportRow};
use copilot_db::customer_portal::{AiReportSettingsRow, InsightRow};
use copilot_web::validate::{IntRules, Loc, Validator};

/// `PortalAiIoc`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortalAiIoc {
    /// IOC id.
    pub id: i32,
    /// The indicator.
    pub ioc_value: String,
    /// Indicator type.
    pub ioc_type: String,
    /// VirusTotal verdict.
    pub vt_verdict: String,
    /// VirusTotal score text.
    pub vt_score: Option<String>,
    /// Free text.
    pub details: Option<String>,
    /// Created.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
}

impl From<IocRow> for PortalAiIoc {
    fn from(r: IocRow) -> Self {
        Self {
            id: r.id,
            ioc_value: r.ioc_value,
            ioc_type: r.ioc_type,
            vt_verdict: r.vt_verdict,
            vt_score: r.vt_score,
            details: r.details,
            created_at: r.created_at,
        }
    }
}

/// `PortalAiReport`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortalAiReport {
    /// Report id.
    pub id: i32,
    /// Alert.
    pub alert_id: i32,
    /// Tenant.
    pub customer_code: String,
    /// Severity the agent assessed.
    pub severity_assessment: Option<String>,
    /// Summary.
    pub summary: Option<String>,
    /// Full report.
    pub report_markdown: Option<String>,
    /// Recommended actions.
    pub recommended_actions: Option<String>,
    /// Created.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
}

impl From<ReportRow> for PortalAiReport {
    fn from(r: ReportRow) -> Self {
        Self {
            id: r.id,
            alert_id: r.alert_id,
            customer_code: r.customer_code,
            severity_assessment: r.severity_assessment,
            summary: r.summary,
            report_markdown: r.report_markdown,
            recommended_actions: r.recommended_actions,
            created_at: r.created_at,
        }
    }
}

/// `PortalAiInvestigation`: the lifecycle, without job id / template /
/// error.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortalAiInvestigation {
    /// `pending` | `running` | `completed` | `failed`.
    pub status: String,
    /// What started it.
    pub triggered_by: String,
    /// Created.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
    /// Started.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub started_at: Option<NaiveDateTime>,
    /// Finished.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub completed_at: Option<NaiveDateTime>,
}

impl From<JobRow> for PortalAiInvestigation {
    fn from(j: JobRow) -> Self {
        Self {
            status: j.status,
            triggered_by: j.triggered_by,
            created_at: j.created_at,
            started_at: j.started_at,
            completed_at: j.completed_at,
        }
    }
}

/// `PortalAiAlertAnalysisResponse`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AlertAnalysisResponse {
    /// The alert asked about.
    pub alert_id: i64,
    /// The customer's AI report switch (off = nothing else was read).
    pub enabled: bool,
    /// Whether the caller may ask for a new analysis.
    pub can_request: bool,
    /// Whether an investigation ever ran.
    pub has_analysis: bool,
    /// Latest investigation.
    pub investigation: Option<PortalAiInvestigation>,
    /// Its report.
    pub report: Option<PortalAiReport>,
    /// The report's IOCs.
    pub iocs: Vec<PortalAiIoc>,
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
}

/// `PortalAiInsightAlert`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortalAiInsightAlert {
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
    #[serde(serialize_with = "pydantic::datetime")]
    pub report_created_at: NaiveDateTime,
}

impl From<InsightRow> for PortalAiInsightAlert {
    fn from(r: InsightRow) -> Self {
        Self {
            alert_id: r.alert_id,
            alert_name: r.alert_name,
            customer_code: r.customer_code,
            severity_assessment: r.severity_assessment,
            summary: r.summary,
            report_created_at: r.report_created_at,
        }
    }
}

/// `PortalAiInsightsResponse`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InsightsResponse {
    /// Alerts with at least one AI report, within the caller's visibility.
    pub total_reports: i64,
    /// Latest-report severity breakdown (`Unknown` when unset).
    pub severity_counts: Map<String, Value>,
    /// Most recent reports.
    pub recent: Vec<PortalAiInsightAlert>,
    /// Always `true`.
    pub success: bool,
    /// `"{total} alerts with an AI report found"`.
    pub message: String,
}

/// `PortalAiReportAvailabilityResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AvailabilityResponse {
    /// The customer asked about, when one was.
    pub customer_code: Option<String>,
    /// Whether the AI surfaces should render.
    pub enabled: bool,
    /// Always `true`.
    pub success: bool,
    /// `AI reports are (not) enabled`.
    pub message: String,
}

/// `PortalAiReportSettings`: the operator view of one customer's switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortalAiReportSettings {
    /// Customer.
    pub customer_code: String,
    /// Read switch.
    pub enabled: bool,
    /// Request switch.
    pub allow_customer_requests: bool,
    /// Requests allowed in any 24 hours; `null` = unlimited.
    pub daily_request_limit: Option<i32>,
    /// Requests made in the last 24 hours.
    pub requests_last_24h: i64,
    /// `updated_at.isoformat()`.
    pub updated_at: Option<String>,
    /// Who changed it last.
    pub updated_by: Option<i32>,
}

impl PortalAiReportSettings {
    /// `_settings_schema`: a missing row reads as disabled.
    pub fn project(
        customer_code: &str,
        row: Option<&AiReportSettingsRow>,
        requests_last_24h: i64,
    ) -> Self {
        match row {
            None => Self {
                customer_code: customer_code.to_string(),
                enabled: false,
                allow_customer_requests: false,
                daily_request_limit: None,
                requests_last_24h: 0,
                updated_at: None,
                updated_by: None,
            },
            Some(r) => Self {
                customer_code: r.customer_code.clone(),
                enabled: r.enabled,
                allow_customer_requests: r.allow_customer_requests,
                daily_request_limit: r.daily_request_limit,
                requests_last_24h,
                updated_at: Some(copilot_core::time::to_pydantic_iso(r.updated_at)),
                updated_by: r.updated_by,
            },
        }
    }
}

/// `PortalAiReportSettingsResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsResponse {
    /// The settings.
    pub settings: PortalAiReportSettings,
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
}

/// `PortalAiAnalysisRequestResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisRequestResponse {
    /// The alert.
    pub alert_id: i64,
    /// When the request was recorded (as stored).
    #[serde(serialize_with = "pydantic::datetime")]
    pub requested_at: NaiveDateTime,
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
}

/// `UpdatePortalAiReportSettingsRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSettingsRequest {
    /// Read switch (required).
    pub enabled: bool,
    /// Request switch; `None` = keep (`null` and absent alike).
    pub allow_customer_requests: Option<bool>,
    /// Limit; `None` = keep (key absent), `Some(None)` = unlimited (explicit
    /// `null`). Pydantic's `model_fields_set` draws the same line.
    pub daily_request_limit: Option<Option<i32>>,
}

/// `daily_request_limit: Field(None, ge=1, le=10000)`.
pub const DAILY_LIMIT_RULES: IntRules = IntRules {
    ge: Some(1),
    le: Some(10_000),
};

impl UpdateSettingsRequest {
    /// Validate a JSON object.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let enabled = v.req_bool(obj, at, "enabled");
        let allow_customer_requests = v.opt_bool(obj, at, "allow_customer_requests");
        let daily_request_limit = obj.contains_key("daily_request_limit").then(|| {
            v.opt_int(obj, at, "daily_request_limit", DAILY_LIMIT_RULES)
                .and_then(|n| i32::try_from(n).ok())
        });
        Self {
            enabled,
            allow_customer_requests,
            daily_request_limit,
        }
    }
}

/// `_settings_values`: what the audit event compares and records.
pub fn settings_values(row: Option<&AiReportSettingsRow>) -> Value {
    let (enabled, allow, limit) = match row {
        None => (false, false, None),
        Some(r) => (r.enabled, r.allow_customer_requests, r.daily_request_limit),
    };
    serde_json::json!({
        "enabled": enabled,
        "allow_customer_requests": allow,
        "daily_request_limit": limit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_web::validate::body_loc;
    use serde_json::json;

    fn t(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    fn read(body: Value) -> (UpdateSettingsRequest, usize) {
        let mut v = Validator::new();
        let obj = body.as_object().unwrap().clone();
        let r = UpdateSettingsRequest::read(&mut v, &obj, &body_loc());
        (r, v.errors().len())
    }

    #[test]
    fn settings_request_tells_absent_from_null() {
        let (r, errs) = read(json!({"enabled": true}));
        assert_eq!(errs, 0);
        assert_eq!(r.daily_request_limit, None);
        assert_eq!(r.allow_customer_requests, None);

        let (r, _) = read(json!({"enabled": "yes", "daily_request_limit": null}));
        assert!(r.enabled);
        assert_eq!(r.daily_request_limit, Some(None));

        let (r, _) = read(json!({"enabled": false, "daily_request_limit": "12"}));
        assert_eq!(r.daily_request_limit, Some(Some(12)));

        let (_, errs) = read(json!({"daily_request_limit": 0}));
        assert_eq!(errs, 2, "missing enabled + ge=1");
        let (_, errs) = read(json!({"enabled": true, "daily_request_limit": 10_001}));
        assert_eq!(errs, 1);
    }

    #[test]
    fn missing_settings_row_reads_disabled() {
        let s = PortalAiReportSettings::project("acme", None, 7);
        assert!(!s.enabled);
        assert_eq!(s.requests_last_24h, 0, "only counted when a row exists");
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            json!({"customer_code": "acme", "enabled": false, "allow_customer_requests": false,
                   "daily_request_limit": null, "requests_last_24h": 0, "updated_at": null,
                   "updated_by": null})
        );
        assert_eq!(
            settings_values(None),
            json!({"enabled": false, "allow_customer_requests": false, "daily_request_limit": null})
        );
    }

    #[test]
    fn projections_carry_no_internals() {
        let job = JobRow {
            id: "copilot-inv-1-1".into(),
            alert_id: 1,
            customer_code: "acme".into(),
            status: "failed".into(),
            alert_type: Some("sigma".into()),
            triggered_by: "manual".into(),
            template_used: Some("internal-template".into()),
            created_at: t("2026-01-01 00:00:00"),
            started_at: None,
            completed_at: None,
            error_message: Some("agent stack trace".into()),
        };
        let json = serde_json::to_string(&PortalAiInvestigation::from(job)).unwrap();
        for leak in [
            "copilot-inv",
            "internal-template",
            "agent stack trace",
            "sigma",
        ] {
            assert!(!json.contains(leak), "{leak} leaked: {json}");
        }
        let report = ReportRow {
            id: 3,
            job_id: "copilot-inv-1-1".into(),
            alert_id: 1,
            customer_code: "acme".into(),
            severity_assessment: None,
            summary: None,
            report_markdown: None,
            recommended_actions: None,
            created_at: t("2026-01-01 00:00:00"),
        };
        let json = serde_json::to_string(&PortalAiReport::from(report)).unwrap();
        assert!(!json.contains("job_id"), "{json}");
    }
}
