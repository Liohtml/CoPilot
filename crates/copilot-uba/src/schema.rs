//! Request bodies and response models — port of `schema/uba.py` and
//! `schema/provision.py`.
//!
//! Responses are UBA's own passed through: [`UBA_RESPONSE`] keeps the
//! envelope typed (`success`, `message`) and lets every payload field
//! through (`extra="allow"`), as Python's `UbaResponse` does. The models are
//! `copilot_upstream::model` statics, so a UBA answer Python's models refuse
//! is refused with Pydantic's `ValidationError` text here too. Request bodies
//! are read field by field ([`crate::params`]) into what `model_dump()`
//! produces — defaults as Pydantic leaves them (`Field(1, …)` dumps `1`, not
//! `1.0`).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};
use copilot_web::validate::{Loc, Validator};
use serde_json::{Map, Value};

use crate::params::{self, NumSpec, StrSpec};

fn yes() -> PyValue {
    PyValue::Bool(true)
}
fn no() -> PyValue {
    PyValue::Bool(false)
}
fn empty() -> PyValue {
    PyValue::Str(String::new())
}
fn zero() -> PyValue {
    PyValue::Int("0".into())
}
fn list() -> PyValue {
    PyValue::List(Vec::new())
}
fn dict() -> PyValue {
    PyValue::Dict(Vec::new())
}
fn ok_text() -> PyValue {
    PyValue::Str("UBA rollbacks".into())
}
fn report_text() -> PyValue {
    PyValue::Str("UBA rollback".into())
}

/// `UbaResponse`: UBA's answer, payload fields passed through.
pub static UBA_RESPONSE: Model = Model::allowing_extra(
    "UbaResponse",
    &[
        Field::def("success", Ty::Bool, yes),
        Field::def("message", Ty::Str, empty),
    ],
);

/// `UbaTenantStatus`.
pub static TENANT_STATUS: Model = Model::allowing_extra(
    "UbaTenantStatus",
    &[
        Field::req("tenant", Ty::Str),
        Field::opt("processed_until", Ty::Nullable(&Ty::DateTime)),
        Field::opt("lag_seconds", Ty::Nullable(&Ty::Float)),
        Field::def("alerts_24h", Ty::Int, zero),
        Field::def("open_alerts", Ty::Int, zero),
        Field::def("signals_24h", Ty::Int, zero),
        Field::opt("onboarding", Ty::Nullable(&Ty::Str)),
    ],
);

/// `UbaCustomerStatusResponse`.
pub static CUSTOMER_STATUS: Model = Model::new(
    "UbaCustomerStatusResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("version", Ty::Str),
        Field::opt("status", Ty::Nullable(&Ty::Model(&TENANT_STATUS))),
    ],
);

/// `UbaIncidentVerdict`.
pub static INCIDENT_VERDICT: Model = Model::new(
    "UbaIncidentVerdict",
    &[
        Field::req("status", Ty::Str),
        Field::opt("incident_alert_id", Ty::Nullable(&Ty::Int)),
        Field::opt("verdict", Ty::Nullable(&Ty::Str)),
        Field::def("message", Ty::Str, empty),
    ],
);

/// `UbaProvisionStep`.
pub static PROVISION_STEP: Model = Model::new(
    "UbaProvisionStep",
    &[
        Field::req("step", Ty::Str),
        Field::req("status", Ty::Str),
        Field::def("detail", Ty::Str, empty),
    ],
);

/// `UbaProvisionResponse`.
pub static PROVISION_RESPONSE: Model = Model::new(
    "UbaProvisionResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("steps", Ty::List(&Ty::Model(&PROVISION_STEP))),
        Field::opt("onboarding", Ty::Nullable(&Ty::Dict(&Ty::Any))),
    ],
);

/// `UbaProvisionStatusResponse`.
pub static PROVISION_STATUS: Model = Model::new(
    "UbaProvisionStatusResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::def("sources", Ty::Dict(&Ty::Int), dict),
        Field::def("office365_tenants", Ty::List(&Ty::Str), list),
        Field::opt("problem", Ty::Nullable(&Ty::Str)),
        Field::opt("onboarding", Ty::Nullable(&Ty::Dict(&Ty::Any))),
    ],
);

/// `UbaModeResponse`.
pub static MODE_RESPONSE: Model = Model::new(
    "UbaModeResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::opt("onboarding", Ty::Nullable(&Ty::Dict(&Ty::Any))),
    ],
);

/// `UbaRollbackItem`.
pub static ROLLBACK_ITEM: Model = Model::new(
    "UbaRollbackItem",
    &[
        Field::req("kind", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("title", Ty::Str),
        Field::opt("source", Ty::Nullable(&Ty::Str)),
        Field::def("recorded", Ty::Bool, no),
        Field::def("detail", Ty::Str, empty),
    ],
);

/// `UbaRollbackPlan`.
pub static ROLLBACK_PLAN: Model = Model::new(
    "UbaRollbackPlan",
    &[
        Field::def("success", Ty::Bool, yes),
        Field::req("message", Ty::Str),
        Field::def("remove", Ty::List(&Ty::Model(&ROLLBACK_ITEM)), list),
        Field::def("keep", Ty::List(&Ty::Model(&ROLLBACK_ITEM)), list),
        Field::def("conflicts", Ty::List(&Ty::Model(&ROLLBACK_ITEM)), list),
        Field::def("source_streams", Ty::List(&Ty::Dict(&Ty::Any)), list),
        Field::opt("uba", Ty::Nullable(&Ty::Dict(&Ty::Any))),
        Field::opt("uba_problem", Ty::Nullable(&Ty::Str)),
    ],
);

/// `UbaRollbackCheck`.
pub static ROLLBACK_CHECK: Model = Model::new(
    "UbaRollbackCheck",
    &[
        Field::req("check", Ty::Str),
        Field::req("ok", Ty::Nullable(&Ty::Bool)),
        Field::def("detail", Ty::Str, empty),
    ],
);

/// `UbaRollbackSummary` (`from_attributes`).
pub static ROLLBACK_SUMMARY: Model = Model::new(
    "UbaRollbackSummary",
    &[
        Field::req("id", Ty::Int),
        Field::req("customer_code", Ty::Str),
        Field::req("status", Ty::Str),
        Field::req("started_at", Ty::DateTime),
        Field::opt("finished_at", Ty::Nullable(&Ty::DateTime)),
        Field::opt("actor_username", Ty::Nullable(&Ty::Str)),
        Field::opt("message", Ty::Nullable(&Ty::Str)),
    ],
);

/// `UbaRollbackReport`.
pub static ROLLBACK_REPORT: Model = Model::new(
    "UbaRollbackReport",
    &[
        Field::req("id", Ty::Int),
        Field::req("customer_code", Ty::Str),
        Field::req("status", Ty::Str),
        Field::req("started_at", Ty::DateTime),
        Field::opt("finished_at", Ty::Nullable(&Ty::DateTime)),
        Field::opt("actor_username", Ty::Nullable(&Ty::Str)),
        Field::opt("message", Ty::Nullable(&Ty::Str)),
        Field::def("steps", Ty::List(&Ty::Model(&PROVISION_STEP)), list),
        Field::def("verification", Ty::List(&Ty::Model(&ROLLBACK_CHECK)), list),
        Field::opt("snapshot", Ty::Nullable(&Ty::Dict(&Ty::Any))),
    ],
);

/// `UbaRollbackResponse`.
pub static ROLLBACK_RESPONSE: Model = Model::new(
    "UbaRollbackResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("report", Ty::Model(&ROLLBACK_REPORT)),
    ],
);

/// `UbaRollbackListResponse`.
pub static ROLLBACK_LIST: Model = Model::new(
    "UbaRollbackListResponse",
    &[
        Field::def("success", Ty::Bool, yes),
        Field::def("message", Ty::Str, ok_text),
        Field::def("rollbacks", Ty::List(&Ty::Model(&ROLLBACK_SUMMARY)), list),
    ],
);

/// `UbaRollbackReportResponse`.
pub static ROLLBACK_REPORT_RESPONSE: Model = Model::new(
    "UbaRollbackReportResponse",
    &[
        Field::def("success", Ty::Bool, yes),
        Field::def("message", Ty::Str, report_text),
        Field::req("report", Ty::Model(&ROLLBACK_REPORT)),
    ],
);

// --- request bodies -----------------------------------------------------------------------

fn pairs(items: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// `UbaFeedbackRequest`, as `model_dump()` gives it.
#[derive(Debug, Clone, PartialEq)]
pub struct Feedback {
    /// `TRUE_POSITIVE` or `FALSE_POSITIVE`.
    pub verdict: String,
    /// The reason (free text, ≤ 50).
    pub reason: Option<String>,
    /// The note (≤ 1024).
    pub note: Option<String>,
    /// Suppress the alert's rules for the entity.
    pub suppress: bool,
    /// The dump.
    pub dump: PyValue,
}

fn opt_text(v: &PyValue) -> Option<String> {
    v.as_str().map(str::to_string)
}

impl Feedback {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let verdict = params::b_req_str(
            v,
            obj,
            at,
            "verdict",
            StrSpec::pattern("^(TRUE_POSITIVE|FALSE_POSITIVE)$"),
        );
        let reason = params::b_opt_str(v, obj, at, "reason", StrSpec::max(50));
        let note = params::b_opt_str(v, obj, at, "note", StrSpec::max(1024));
        let suppress = params::b_bool_or(v, obj, at, "suppress", true);
        let days = params::b_int_or(v, obj, at, "suppress_days", NumSpec::range(1.0, 365.0), 30);
        Self {
            verdict: verdict.as_str().unwrap_or_default().to_string(),
            reason: opt_text(&reason),
            note: opt_text(&note),
            suppress: matches!(suppress, PyValue::Bool(true)),
            dump: pairs(vec![
                ("verdict", verdict),
                ("reason", reason),
                ("note", note),
                ("suppress", suppress),
                ("suppress_days", days),
            ]),
        }
    }
}

/// `UbaSuppressionRequest.model_dump()`.
pub fn suppression(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> PyValue {
    let entity_key = params::b_req_str(v, obj, at, "entity_key", StrSpec::len(1, 512));
    let rule_ids = params::b_req_str_list(v, obj, at, "rule_ids", Some(1));
    let days = params::b_int_or(v, obj, at, "days", NumSpec::range(1.0, 365.0), 30);
    let reason = params::b_opt_str(v, obj, at, "reason", StrSpec::max(500));
    pairs(vec![
        ("entity_key", entity_key),
        ("rule_ids", rule_ids),
        ("days", days),
        ("reason", reason),
    ])
}

/// `UbaBacktestRequest.model_dump(exclude_none=True)`.
pub fn backtest(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> PyValue {
    let days = params::b_float_or(
        v,
        obj,
        at,
        "days",
        NumSpec {
            ge: None,
            gt: Some(0.0),
            le: Some(7.0),
        },
        PyValue::Int("1".into()),
    );
    let warmup = params::b_float_or(
        v,
        obj,
        at,
        "warmup_days",
        NumSpec::range(0.0, 14.0),
        PyValue::Int("0".into()),
    );
    let rules = params::b_opt_str_list(v, obj, at, "rules");
    let filter = params::b_opt_str(v, obj, at, "filter", StrSpec::max(1000));
    let out: Vec<(&str, PyValue)> = vec![
        ("days", days),
        ("warmup_days", warmup),
        ("rules", rules),
        ("filter", filter),
    ]
    .into_iter()
    .filter(|(_, v)| !matches!(v, PyValue::None))
    .collect();
    pairs(out)
}

/// `UbaScoreRequest.model_dump()`.
pub fn score(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> PyValue {
    let score = params::b_req_float(v, obj, at, "score", NumSpec::range(0.0, 100.0));
    pairs(vec![("score", score)])
}

/// `UbaIdentityMergeRequest.model_dump()`.
pub fn merge(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> PyValue {
    let into = params::b_req_str(v, obj, at, "into", StrSpec::len(1, 64));
    pairs(vec![("into", into)])
}

/// `UbaRuleSettingRequest.model_dump(exclude_unset=True)`: only the fields
/// sent, a `null` included.
pub fn rule_setting(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> PyValue {
    let enabled = params::b_opt_bool(v, obj, at, "enabled");
    let score = params::b_opt_float(v, obj, at, "score", NumSpec::range(0.0, 100.0));
    let mut out = Vec::new();
    if obj.contains_key("enabled") {
        out.push(("enabled", enabled));
    }
    if obj.contains_key("score") {
        out.push(("score", score));
    }
    pairs(out)
}

/// `UbaAlertThresholdRequest.model_dump()`.
pub fn alert_threshold(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> PyValue {
    let threshold =
        params::b_req_float(v, obj, at, "alert_threshold", NumSpec::range(20.0, 1000.0));
    pairs(vec![("alert_threshold", threshold)])
}

/// `UbaModeRequest.mode`.
pub fn mode(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> String {
    params::b_req_literal(v, obj, at, "mode", &["active", "learning"])
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// `UbaProvisionRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProvisionRequest {
    /// `bootstrap_days` (0–30, 14 by default), as its decimal text.
    pub bootstrap_days: String,
    /// `deploy_wazuh_rules`.
    pub deploy_wazuh_rules: bool,
}

impl ProvisionRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let days = params::b_int_or(v, obj, at, "bootstrap_days", NumSpec::range(0.0, 30.0), 14);
        let deploy = params::b_bool_or(v, obj, at, "deploy_wazuh_rules", false);
        Self {
            bootstrap_days: match days {
                PyValue::Int(i) => i,
                _ => "14".into(),
            },
            deploy_wazuh_rules: matches!(deploy, PyValue::Bool(true)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_upstream::json::Dumps;
    use copilot_upstream::json::py_dumps;
    use copilot_web::validate::body_loc;
    use serde_json::json;

    fn read<T>(
        body: Value,
        f: impl FnOnce(&mut Validator, &Map<String, Value>, &Loc) -> T,
    ) -> (T, Vec<String>) {
        let mut v = Validator::new();
        let out = f(&mut v, body.as_object().unwrap(), &body_loc());
        (out, v.errors().iter().map(|e| e.kind.clone()).collect())
    }

    #[test]
    fn bodies_dump_like_pydantic() {
        let (fb, errs) = read(
            json!({"verdict": "FALSE_POSITIVE", "suppress": "no"}),
            Feedback::read,
        );
        assert!(errs.is_empty());
        assert_eq!(
            py_dumps(&fb.dump, Dumps::HTTPX).unwrap(),
            r#"{"verdict":"FALSE_POSITIVE","reason":null,"note":null,"suppress":false,"suppress_days":30}"#
        );
        let (bt, errs) = read(json!({"warmup_days": "2"}), backtest);
        assert!(errs.is_empty());
        assert_eq!(
            py_dumps(&bt, Dumps::HTTPX).unwrap(),
            r#"{"days":1,"warmup_days":2.0}"#
        );
        let (rs, _) = read(json!({"score": null}), rule_setting);
        assert_eq!(py_dumps(&rs, Dumps::HTTPX).unwrap(), r#"{"score":null}"#);
        let (_, errs) = read(
            json!({"verdict": "TRUE_POSITIVE\n", "suppress_days": 0}),
            Feedback::read,
        );
        assert_eq!(errs, ["string_pattern_mismatch", "greater_than_equal"]);
        let (_, errs) = read(json!({"entity_key": "", "rule_ids": []}), suppression);
        assert_eq!(errs, ["string_too_short", "too_short"]);
        let (m, errs) = read(json!({"mode": "LEARNING"}), mode);
        assert_eq!((m.as_str(), errs), ("", vec!["literal_error".to_string()]));
    }
}
