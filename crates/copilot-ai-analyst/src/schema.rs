//! Request and response shapes — port of `app/ai_analyst/schema/ai_analyst.py`.
//!
//! Requests are read with `copilot_web::validate` (Pydantic-lax semantics,
//! same 422 texts); responses serialize in Pydantic's field order with
//! Pydantic's datetime rendering, every optional field present as `null`.

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value};

use copilot_core::time::pydantic;
use copilot_db::ai_analyst::{
    AlertWithReport, IocReviewRow, IocRow, JobRow, PalaceLessonRow, ReportRow, ReviewWithIocs,
};
use copilot_talon::contract::is_valid_template_name;
use copilot_web::validate::{IntRules, Loc, StrRules, Validator};

/// `JobStatus`.
pub const JOB_STATUSES: &[&str] = &["pending", "running", "completed", "failed"];
/// `TriggeredBy`.
pub const TRIGGERED_BY: &[&str] = &["scheduled", "manual", "webhook"];
/// `SeverityAssessment`.
pub const SEVERITIES: &[&str] = &["Critical", "High", "Medium", "Low", "Informational"];
/// `IocType`.
pub const IOC_TYPES: &[&str] = &["ip", "domain", "hash", "process", "url", "user", "command"];
/// `VtVerdict`.
pub const VT_VERDICTS: &[&str] = &["malicious", "suspicious", "clean", "unknown"];
/// `OverallVerdict`.
pub const OVERALL_VERDICTS: &[&str] = &["up", "down"];
/// `TemplateChoice`.
pub const TEMPLATE_CHOICES: &[&str] = &["correct", "wrong", "partial"];
/// `LessonType` (the MemPalace rooms).
pub const LESSON_TYPES: &[&str] = &[
    "environment",
    "false_positives",
    "assets",
    "threat_intel",
    "alerts",
];
/// `Durability`.
pub const DURABILITIES: &[&str] = &["one_off", "durable"];

const RATING: IntRules = IntRules {
    ge: Some(1),
    le: Some(5),
};

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// `CreateJobRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateJobRequest {
    /// Job id (≤ 64).
    pub id: String,
    /// Alert.
    pub alert_id: i64,
    /// Customer (≤ 64).
    pub customer_code: String,
    /// `TriggeredBy`.
    pub triggered_by: String,
    /// ≤ 64.
    pub alert_type: Option<String>,
    /// ≤ 128.
    pub template_used: Option<String>,
}

impl CreateJobRequest {
    /// Read from a body object.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            id: v.req_str(o, at, "id", StrRules::max(64)),
            alert_id: v.req_int(o, at, "alert_id", IntRules::default()),
            customer_code: v.req_str(o, at, "customer_code", StrRules::max(64)),
            triggered_by: v.req_enum(o, at, "triggered_by", TRIGGERED_BY),
            alert_type: v.opt_str(o, at, "alert_type", StrRules::max(64)),
            template_used: v.opt_str(o, at, "template_used", StrRules::max(128)),
        }
    }
}

/// `UpdateJobRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateJobRequest {
    /// `JobStatus`.
    pub status: String,
    /// ≤ 64.
    pub alert_type: Option<String>,
    /// ≤ 128.
    pub template_used: Option<String>,
    /// Failure text.
    pub error_message: Option<String>,
}

impl UpdateJobRequest {
    /// Read from a body object.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            status: v.req_enum(o, at, "status", JOB_STATUSES),
            alert_type: v.opt_str(o, at, "alert_type", StrRules::max(64)),
            template_used: v.opt_str(o, at, "template_used", StrRules::max(128)),
            error_message: v.opt_str(o, at, "error_message", StrRules::any()),
        }
    }
}

/// `SubmitReportRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitReportRequest {
    /// Job (≤ 64).
    pub job_id: String,
    /// Alert.
    pub alert_id: i64,
    /// Customer (≤ 64).
    pub customer_code: String,
    /// `SeverityAssessment`.
    pub severity_assessment: Option<String>,
    /// Summary (control characters stripped).
    pub summary: Option<String>,
    /// Report body (control characters stripped).
    pub report_markdown: Option<String>,
    /// Actions (control characters stripped).
    pub recommended_actions: Option<String>,
}

impl SubmitReportRequest {
    /// Read from a body object, including the `require_report_body` model
    /// validator (which runs only once every field is valid).
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        let r = Self {
            job_id: v.req_str(o, at, "job_id", StrRules::max(64)),
            alert_id: v.req_int(o, at, "alert_id", IntRules::default()),
            customer_code: v.req_str(o, at, "customer_code", StrRules::max(64)),
            severity_assessment: v.opt_enum(o, at, "severity_assessment", SEVERITIES),
            summary: v.opt_str(o, at, "summary", StrRules::any().stripped()),
            report_markdown: v.opt_str(o, at, "report_markdown", StrRules::any().stripped()),
            recommended_actions: v.opt_str(
                o,
                at,
                "recommended_actions",
                StrRules::any().stripped(),
            ),
        };
        if !v.has_errors() {
            let blank = |s: &Option<String>| s.as_deref().is_none_or(|t| t.trim().is_empty());
            let missing: Vec<&str> = [
                ("severity_assessment", blank(&r.severity_assessment)),
                ("summary", blank(&r.summary)),
                ("report_markdown", blank(&r.report_markdown)),
                ("recommended_actions", blank(&r.recommended_actions)),
            ]
            .iter()
            .filter(|(_, b)| *b)
            .map(|(n, _)| *n)
            .collect();
            if !missing.is_empty() {
                v.push(
                    "value_error",
                    at.clone(),
                    format!(
                        "Value error, Report body fields must be non-empty: {}. \
                         A report missing these persists a blank row in CoPilot.",
                        missing.join(", ")
                    ),
                );
            }
        }
        r
    }
}

/// `SubmitIocRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitIocRequest {
    /// ≤ 512.
    pub ioc_value: String,
    /// `IocType`.
    pub ioc_type: String,
    /// `VtVerdict`, default `unknown`.
    pub vt_verdict: String,
    /// ≤ 32.
    pub vt_score: Option<String>,
    /// Free text.
    pub details: Option<String>,
}

/// `SubmitIocsRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitIocsRequest {
    /// Report.
    pub report_id: i64,
    /// Alert.
    pub alert_id: i64,
    /// Customer (≤ 64).
    pub customer_code: String,
    /// The IOCs (may be empty).
    pub iocs: Vec<SubmitIocRequest>,
}

impl SubmitIocsRequest {
    /// Read from a body object.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        let report_id = v.req_int(o, at, "report_id", IntRules::default());
        let alert_id = v.req_int(o, at, "alert_id", IntRules::default());
        let customer_code = v.req_str(o, at, "customer_code", StrRules::max(64));
        let mut iocs = Vec::new();
        for (l, item) in v.list(o, at, "iocs", true) {
            if let Some(i) = v.nested(item, &l, "SubmitIocRequest") {
                iocs.push(SubmitIocRequest {
                    ioc_value: v.req_str(i, &l, "ioc_value", StrRules::max(512)),
                    ioc_type: v.req_enum(i, &l, "ioc_type", IOC_TYPES),
                    vt_verdict: v.enum_or(i, &l, "vt_verdict", VT_VERDICTS, "unknown"),
                    vt_score: v.opt_str(i, &l, "vt_score", StrRules::max(32)),
                    details: v.opt_str(i, &l, "details", StrRules::any()),
                });
            }
        }
        Self {
            report_id,
            alert_id,
            customer_code,
            iocs,
        }
    }
}

/// `IocVerdictCorrection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocVerdictCorrection {
    /// IOC.
    pub ioc_id: i64,
    /// Right or wrong.
    pub verdict_correct: bool,
    /// ≤ 2000 after stripping control characters.
    pub note: Option<String>,
}

/// `SubmitReviewRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubmitReviewRequest {
    /// `up` | `down`.
    pub overall_verdict: Option<String>,
    /// `correct` | `wrong` | `partial`.
    pub template_choice: Option<String>,
    /// ≤ 128.
    pub template_used: Option<String>,
    /// 1–5.
    pub rating_instructions: Option<i64>,
    /// 1–5.
    pub rating_artifacts: Option<i64>,
    /// 1–5.
    pub rating_severity: Option<i64>,
    /// Free text.
    pub missing_steps: Option<String>,
    /// Free text.
    pub suggested_edits: Option<String>,
    /// Per-IOC corrections.
    pub ioc_reviews: Vec<IocVerdictCorrection>,
}

impl SubmitReviewRequest {
    /// Read from a body object.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        let mut r = Self {
            overall_verdict: v.opt_enum(o, at, "overall_verdict", OVERALL_VERDICTS),
            template_choice: v.opt_enum(o, at, "template_choice", TEMPLATE_CHOICES),
            template_used: v.opt_str(o, at, "template_used", StrRules::max(128)),
            rating_instructions: v.opt_int(o, at, "rating_instructions", RATING),
            rating_artifacts: v.opt_int(o, at, "rating_artifacts", RATING),
            rating_severity: v.opt_int(o, at, "rating_severity", RATING),
            missing_steps: v.opt_str(o, at, "missing_steps", StrRules::any().stripped()),
            suggested_edits: v.opt_str(o, at, "suggested_edits", StrRules::any().stripped()),
            ioc_reviews: Vec::new(),
        };
        for (l, item) in v.list(o, at, "ioc_reviews", false) {
            if let Some(i) = v.nested(item, &l, "IocVerdictCorrection") {
                r.ioc_reviews.push(IocVerdictCorrection {
                    ioc_id: v.req_int(i, &l, "ioc_id", IntRules::default()),
                    verdict_correct: v.req_bool(i, &l, "verdict_correct"),
                    note: v.opt_str(i, &l, "note", StrRules::max(2000).stripped()),
                });
            }
        }
        r
    }
}

/// `QueuePalaceLessonRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuePalaceLessonRequest {
    /// Customer (≤ 64).
    pub customer_code: String,
    /// `LessonType`.
    pub lesson_type: String,
    /// ≥ 1 char after stripping control characters.
    pub lesson_text: String,
    /// `Durability`, default `durable`.
    pub durability: String,
    /// Source review.
    pub review_id: Option<i64>,
}

impl QueuePalaceLessonRequest {
    /// Read from a body object.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            customer_code: v.req_str(o, at, "customer_code", StrRules::max(64)),
            lesson_type: v.req_enum(o, at, "lesson_type", LESSON_TYPES),
            lesson_text: v.req_str(o, at, "lesson_text", StrRules::any().min(1).stripped()),
            durability: v.enum_or(o, at, "durability", DURABILITIES, "durable"),
            review_id: v.opt_int(o, at, "review_id", IntRules::default()),
        }
    }
}

/// `ReplayRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRequest {
    /// A plain `.txt` template filename (≤ 128).
    pub template_override: String,
    /// Customer (≤ 64).
    pub customer_code: String,
    /// ≤ 64, default `copilot-replay`.
    pub sender: String,
}

impl ReplayRequest {
    /// Read from a body object. The filename rule is Talon's (no `..`, not
    /// hidden) under Python's message, so a name Talon would refuse is a 422
    /// here instead of a 500 from the replay call.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        let before = v.errors().len();
        let template_override = v.req_str(o, at, "template_override", StrRules::max(128));
        if v.errors().len() == before && !is_valid_template_name(&template_override) {
            let mut l = at.clone();
            l.push(copilot_web::validate::LocPart::Key(
                "template_override".into(),
            ));
            v.push(
                "value_error",
                l,
                "Value error, template_override must be a filename matching ^[a-zA-Z0-9._-]+\\.txt$",
            );
        }
        Self {
            template_override,
            customer_code: v.req_str(o, at, "customer_code", StrRules::max(64)),
            sender: v.str_or(o, at, "sender", StrRules::max(64), "copilot-replay"),
        }
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// `JobResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobResponse {
    /// Job id.
    pub id: String,
    /// Alert.
    pub alert_id: i32,
    /// Customer.
    pub customer_code: String,
    /// Status.
    pub status: String,
    /// Alert type.
    pub alert_type: Option<String>,
    /// Trigger.
    pub triggered_by: String,
    /// Template.
    pub template_used: Option<String>,
    /// Created.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
    /// Started.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub started_at: Option<NaiveDateTime>,
    /// Completed.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub completed_at: Option<NaiveDateTime>,
    /// Error.
    pub error_message: Option<String>,
}

impl From<JobRow> for JobResponse {
    fn from(j: JobRow) -> Self {
        Self {
            id: j.id,
            alert_id: j.alert_id,
            customer_code: j.customer_code,
            status: j.status,
            alert_type: j.alert_type,
            triggered_by: j.triggered_by,
            template_used: j.template_used,
            created_at: j.created_at,
            started_at: j.started_at,
            completed_at: j.completed_at,
            error_message: j.error_message,
        }
    }
}

/// `ReportResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportResponse {
    /// Id.
    pub id: i32,
    /// Job.
    pub job_id: String,
    /// Alert.
    pub alert_id: i32,
    /// Customer.
    pub customer_code: String,
    /// Severity.
    pub severity_assessment: Option<String>,
    /// Summary.
    pub summary: Option<String>,
    /// Body.
    pub report_markdown: Option<String>,
    /// Actions.
    pub recommended_actions: Option<String>,
    /// Created.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
}

impl From<ReportRow> for ReportResponse {
    fn from(r: ReportRow) -> Self {
        Self {
            id: r.id,
            job_id: r.job_id,
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

/// `IocResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IocResponse {
    /// Id.
    pub id: i32,
    /// Report.
    pub report_id: i32,
    /// Alert.
    pub alert_id: i32,
    /// Customer.
    pub customer_code: String,
    /// Value.
    pub ioc_value: String,
    /// Type.
    pub ioc_type: String,
    /// Verdict.
    pub vt_verdict: String,
    /// Score.
    pub vt_score: Option<String>,
    /// Details.
    pub details: Option<String>,
    /// Created.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
}

impl From<IocRow> for IocResponse {
    fn from(i: IocRow) -> Self {
        Self {
            id: i.id,
            report_id: i.report_id,
            alert_id: i.alert_id,
            customer_code: i.customer_code,
            ioc_value: i.ioc_value,
            ioc_type: i.ioc_type,
            vt_verdict: i.vt_verdict,
            vt_score: i.vt_score,
            details: i.details,
            created_at: i.created_at,
        }
    }
}

/// `AlertWithReportResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AlertWithReportResponse {
    /// Alert id.
    pub alert_id: i32,
    /// Title.
    pub alert_name: String,
    /// Customer.
    pub customer_code: String,
    /// Status.
    pub status: String,
    /// Source.
    pub source: String,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Alert time.
    #[serde(serialize_with = "pydantic::datetime")]
    pub alert_creation_time: NaiveDateTime,
    /// The report.
    pub report: ReportResponse,
}

impl From<AlertWithReport> for AlertWithReportResponse {
    fn from(a: AlertWithReport) -> Self {
        Self {
            alert_id: a.alert_id,
            alert_name: a.alert_name,
            customer_code: a.customer_code,
            status: a.status,
            source: a.source,
            assigned_to: a.assigned_to,
            alert_creation_time: a.alert_creation_time,
            report: a.report.into(),
        }
    }
}

/// `IocReviewResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IocReviewResponse {
    /// Id.
    pub id: i32,
    /// Review.
    pub review_id: i32,
    /// IOC.
    pub ioc_id: i32,
    /// Correct?
    pub verdict_correct: bool,
    /// Note.
    pub note: Option<String>,
    /// Created.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
}

impl From<IocReviewRow> for IocReviewResponse {
    fn from(r: IocReviewRow) -> Self {
        Self {
            id: r.id,
            review_id: r.review_id,
            ioc_id: r.ioc_id,
            verdict_correct: r.verdict_correct,
            note: r.note,
            created_at: r.created_at,
        }
    }
}

/// `ReviewResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewResponse {
    /// Id.
    pub id: i32,
    /// Report.
    pub report_id: i32,
    /// Alert.
    pub alert_id: i32,
    /// Customer.
    pub customer_code: String,
    /// Reviewer.
    pub reviewer_user_id: i32,
    /// Thumbs.
    pub overall_verdict: Option<String>,
    /// Template verdict.
    pub template_choice: Option<String>,
    /// Template.
    pub template_used: Option<String>,
    /// Rating.
    pub rating_instructions: Option<i32>,
    /// Rating.
    pub rating_artifacts: Option<i32>,
    /// Rating.
    pub rating_severity: Option<i32>,
    /// Text.
    pub missing_steps: Option<String>,
    /// Text.
    pub suggested_edits: Option<String>,
    /// Created.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
    /// Edited.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub updated_at: Option<NaiveDateTime>,
    /// Per-IOC corrections.
    pub ioc_reviews: Vec<IocReviewResponse>,
}

impl From<ReviewWithIocs> for ReviewResponse {
    fn from(r: ReviewWithIocs) -> Self {
        let v = r.review;
        Self {
            id: v.id,
            report_id: v.report_id,
            alert_id: v.alert_id,
            customer_code: v.customer_code,
            reviewer_user_id: v.reviewer_user_id,
            overall_verdict: v.overall_verdict,
            template_choice: v.template_choice,
            template_used: v.template_used,
            rating_instructions: v.rating_instructions,
            rating_artifacts: v.rating_artifacts,
            rating_severity: v.rating_severity,
            missing_steps: v.missing_steps,
            suggested_edits: v.suggested_edits,
            created_at: v.created_at,
            updated_at: v.updated_at,
            ioc_reviews: r.ioc_reviews.into_iter().map(Into::into).collect(),
        }
    }
}

/// `PalaceLessonResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PalaceLessonResponse {
    /// Id.
    pub id: i32,
    /// Review.
    pub review_id: Option<i32>,
    /// Customer.
    pub customer_code: String,
    /// Room.
    pub lesson_type: String,
    /// Text.
    pub lesson_text: String,
    /// Durability.
    pub durability: String,
    /// Status.
    pub status: String,
    /// Ingested.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub ingested_at: Option<NaiveDateTime>,
    /// Queued.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
}

impl From<PalaceLessonRow> for PalaceLessonResponse {
    fn from(l: PalaceLessonRow) -> Self {
        Self {
            id: l.id,
            review_id: l.review_id,
            customer_code: l.customer_code,
            lesson_type: l.lesson_type,
            lesson_text: l.lesson_text.unwrap_or_default(),
            durability: l.durability,
            status: l.status,
            ingested_at: l.ingested_at,
            created_at: l.created_at,
        }
    }
}

/// `PalaceSearchHit`. Talon's extra keys are dropped; scalar ids/texts are
/// accepted as numbers too (Python would 400 on a numeric id).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PalaceSearchHit {
    /// Drawer id.
    pub id: Option<String>,
    /// Room.
    pub room: Option<String>,
    /// Wing.
    pub wing: Option<String>,
    /// Text.
    pub text: Option<String>,
    /// Source file.
    pub source_file: Option<String>,
    /// Similarity.
    pub score: Option<f64>,
    /// Metadata object.
    pub metadata: Option<Map<String, Value>>,
}

impl PalaceSearchHit {
    /// From one of Talon's hit objects.
    pub fn from_value(v: &Value) -> Self {
        let s = |k: &str| match v.get(k) {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            _ => None,
        };
        Self {
            id: s("id"),
            room: s("room"),
            wing: s("wing"),
            text: s("text"),
            source_file: s("source_file"),
            score: v.get("score").and_then(Value::as_f64),
            metadata: v.get("metadata").and_then(Value::as_object).cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_web::ApiError;
    use copilot_web::validate::parse_body_model;
    use serde_json::json;

    fn messages(err: ApiError) -> Vec<String> {
        match err {
            ApiError::Validation(items) => items.into_iter().filter_map(|i| i.message).collect(),
            other => panic!("{other:?}"),
        }
    }

    fn body(v: Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn report_body_guard() {
        let err = parse_body_model(
            &body(
                json!({"job_id": "j", "alert_id": 1, "customer_code": "acme",
                          "severity_assessment": "High", "summary": "\u{1}\u{2}",
                          "report_markdown": "ok"}),
            ),
            SubmitReportRequest::read,
        )
        .unwrap_err();
        assert_eq!(
            messages(err),
            vec![
                "Report body fields must be non-empty: summary, recommended_actions. \
                 A report missing these persists a blank row in CoPilot."
            ]
        );
    }

    #[test]
    fn field_errors_suppress_the_model_validator() {
        let err = parse_body_model(
            &body(json!({"job_id": "j", "alert_id": "x", "customer_code": "acme"})),
            SubmitReportRequest::read,
        )
        .unwrap_err();
        assert_eq!(messages(err), vec!["Input is not a valid integer."]);
    }

    #[test]
    fn iocs_default_verdict_and_nested_errors() {
        let ok = parse_body_model(
            &body(
                json!({"report_id": 1, "alert_id": 2, "customer_code": "acme",
                          "iocs": [{"ioc_value": "1.2.3.4", "ioc_type": "ip"}]}),
            ),
            SubmitIocsRequest::read,
        )
        .unwrap();
        assert_eq!(ok.iocs[0].vt_verdict, "unknown");
        let err = parse_body_model(
            &body(
                json!({"report_id": 1, "alert_id": 2, "customer_code": "acme",
                          "iocs": [{"ioc_value": "x", "ioc_type": "ipv9"}]}),
            ),
            SubmitIocsRequest::read,
        )
        .unwrap_err();
        assert_eq!(
            messages(err),
            vec!["Value is not a valid enumeration member."]
        );
    }

    #[test]
    fn replay_template_rule() {
        let err = parse_body_model(
            &body(json!({"template_override": "../x.txt", "customer_code": "acme"})),
            ReplayRequest::read,
        )
        .unwrap_err();
        assert_eq!(
            messages(err),
            vec![
                "template_override: template_override must be a filename matching ^[a-zA-Z0-9._-]+\\.txt$"
            ]
        );
        let ok = parse_body_model(
            &body(json!({"template_override": "sysmon_event_1.txt", "customer_code": "acme"})),
            ReplayRequest::read,
        )
        .unwrap();
        assert_eq!(ok.sender, "copilot-replay");
    }

    #[test]
    fn lesson_defaults_and_ratings() {
        let l = parse_body_model(
            &body(json!({"customer_code": "acme", "lesson_type": "assets", "lesson_text": "dc01"})),
            QueuePalaceLessonRequest::read,
        )
        .unwrap();
        assert_eq!(l.durability, "durable");
        let err = parse_body_model(
            &body(json!({"rating_severity": 6})),
            SubmitReviewRequest::read,
        )
        .unwrap_err();
        assert_eq!(messages(err), vec!["Value is too large."]);
    }

    #[test]
    fn response_field_order() {
        let job = JobResponse {
            id: "j".into(),
            alert_id: 1,
            customer_code: "acme".into(),
            status: "pending".into(),
            alert_type: None,
            triggered_by: "webhook".into(),
            template_used: None,
            created_at: NaiveDateTime::parse_from_str("2026-01-02 03:04:05", "%Y-%m-%d %H:%M:%S")
                .unwrap(),
            started_at: None,
            completed_at: None,
            error_message: None,
        };
        assert_eq!(
            serde_json::to_string(&job).unwrap(),
            r#"{"id":"j","alert_id":1,"customer_code":"acme","status":"pending","alert_type":null,"triggered_by":"webhook","template_used":null,"created_at":"2026-01-02T03:04:05","started_at":null,"completed_at":null,"error_message":null}"#
        );
    }
}
