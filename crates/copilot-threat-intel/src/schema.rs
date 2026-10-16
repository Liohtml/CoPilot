//! `app/threat_intel/schema/{epss,socfortress,virustotal}.py` and the MCP
//! answer of `app/integrations/copilot_mcp/schema/copilot_mcp.py`: the
//! request readers (FastAPI's 422 texts) and the Pydantic models the
//! services build from upstream answers.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{
    Field as F, Invalid, Loc as MLoc, Model, PyError, Ty, format_validation_error, kwargs, validate,
};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_web::validate::{Loc, StrRules, Validator};
use serde_json::{Map, Value};

// --- requests ------------------------------------------------------------------------------

/// `EpssThreatIntelRequest`.
#[derive(Debug, Clone, Default)]
pub struct EpssRequest {
    /// `cve`.
    pub cve: String,
}

impl EpssRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            cve: v.req_str(o, at, "cve", StrRules::any()),
        }
    }
}

/// `SocfortressThreatIntelRequest`.
#[derive(Debug, Clone, Default)]
pub struct IntelRequest {
    /// `ioc_value`.
    pub ioc_value: String,
    /// `customer_code` (`"socfortress_copilot"` when absent, `None` when
    /// sent as `null`).
    pub customer_code: Option<String>,
}

impl IntelRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            ioc_value: v.req_str(o, at, "ioc_value", StrRules::any()),
            customer_code: match o.get("customer_code") {
                None => Some("socfortress_copilot".into()),
                Some(_) => v.opt_str(o, at, "customer_code", StrRules::any()),
            },
        }
    }
}

/// `VirusTotalThreatIntelRequest`.
#[derive(Debug, Clone, Default)]
pub struct VirusTotalRequest {
    /// `ioc_value`.
    pub ioc_value: String,
}

impl VirusTotalRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            ioc_value: v.req_str(o, at, "ioc_value", StrRules::any()),
        }
    }
}

/// `SocfortressProcessNameAnalysisRequest`: its `mode="before"` validator
/// keeps what follows the last `\` (`re.search(r"[^\\]+$", v)`); a value
/// that is not a string is that validator's `TypeError`, which no handler
/// catches.
#[derive(Debug, Clone, Default)]
pub struct ProcessNameRequest {
    /// `process_name`.
    pub process_name: String,
    /// The `TypeError` the validator raised.
    pub type_error: Option<String>,
}

impl ProcessNameRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, o: &Map<String, Value>, at: &Loc) -> Self {
        match o.get("process_name") {
            None => {
                let mut l = at.clone();
                l.push(copilot_web::validate::LocPart::Key("process_name".into()));
                v.missing(l);
                Self::default()
            }
            Some(Value::String(s)) => Self {
                process_name: last_segment(s).to_string(),
                type_error: None,
            },
            Some(other) => Self {
                process_name: String::new(),
                type_error: Some(format!(
                    "expected string or bytes-like object, got '{}'",
                    json_type(other)
                )),
            },
        }
    }
}

/// `type(x).__name__` of a JSON value.
pub fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `match.group() if (match := re.search(r"[^\\]+$", v)) else v`: the text
/// after the last backslash, unless the value ends with one (or is empty).
pub fn last_segment(s: &str) -> &str {
    match s.rfind('\\') {
        Some(i) if i + 1 < s.len() => &s[i + 1..],
        Some(_) => s,
        None => s,
    }
}

// --- models --------------------------------------------------------------------------------

const OPT_STR: Ty = Ty::Nullable(&Ty::Str);
const OPT_INT: Ty = Ty::Nullable(&Ty::Int);

/// `EpssData`.
pub static EPSS_DATA: Model = Model::new(
    "EpssData",
    &[
        F::req("cve", Ty::Str),
        F::req("epss", Ty::Str),
        F::req("percentile", Ty::Str),
        F::req("date", Ty::Str),
    ],
);

fn epss_model() -> PyValue {
    PyValue::Str("https://www.first.org/epss/model".into())
}

/// `EpssThreatIntelResponse`.
pub static EPSS_RESPONSE: Model = Model::new(
    "EpssThreatIntelResponse",
    &[
        F::opt("data", Ty::Nullable(&Ty::List(&Ty::Model(&EPSS_DATA)))),
        F::req("success", Ty::Bool),
        F::opt("message", Ty::Str),
        F::def("the_epss_model", Ty::Str, epss_model),
    ],
);

fn intel_source() -> PyValue {
    PyValue::Str("SOCFortress Threat Intel".into())
}

/// `IoCMapping` (its `score` validator is [`crate::services::socfortress::score`]).
pub static IOC_MAPPING: Model = Model::new(
    "IoCMapping",
    &[
        F::opt("comment", OPT_STR),
        F::def("ioc_source", Ty::Str, intel_source),
        F::opt("report_url", OPT_STR),
        F::opt("score", OPT_INT),
        F::opt("timestamp", OPT_STR),
        F::opt("type", OPT_STR),
        F::opt("value", OPT_STR),
        F::opt("virustotal_url", OPT_STR),
    ],
);

/// `IoCResponse`.
pub static IOC_RESPONSE: Model = Model::new(
    "IoCResponse",
    &[
        F::opt("data", Ty::Nullable(&Ty::Model(&IOC_MAPPING))),
        F::req("success", Ty::Bool),
        F::opt("message", OPT_STR),
    ],
);

/// `StructuredAgentResponse`.
pub static STRUCTURED: Model = Model::new(
    "StructuredAgentResponse",
    &[
        F::req("response", Ty::Str),
        F::opt("thinking_process", OPT_STR),
    ],
);

/// `MCPQueryResponse`.
pub static MCP_RESPONSE: Model = Model::new(
    "MCPQueryResponse",
    &[
        F::req("message", Ty::Str),
        F::req("success", Ty::Bool),
        F::opt("result", Ty::Any),
        F::opt("structured_result", Ty::Nullable(&Ty::Model(&STRUCTURED))),
        F::opt("execution_time", Ty::Nullable(&Ty::Float)),
    ],
);

/// `SocfortressAiAlertResponse` (`confidence_score` is checked against
/// `ge=0, le=1` by [`ai_alert_response`]).
pub static AI_ALERT_RESPONSE: Model = Model::new(
    "SocfortressAiAlertResponse",
    &[
        F::req("message", Ty::Str),
        F::req("success", Ty::Bool),
        F::req("analysis", Ty::Str),
        F::opt("base64_decoded", OPT_STR),
        F::req("confidence_score", Ty::Float),
        F::opt("threat_indicators", OPT_STR),
        F::opt("risk_evaluation", OPT_STR),
    ],
);

/// `SocfortressAiWazuhExclusionRuleResponse`.
pub static AI_EXCLUSION_RESPONSE: Model = Model::new(
    "SocfortressAiWazuhExclusionRuleResponse",
    &[
        F::req("message", Ty::Str),
        F::req("success", Ty::Bool),
        F::opt("wazuh_exclusion_rule", OPT_STR),
        F::opt("wazuh_exclusion_rule_justification", OPT_STR),
    ],
);

/// `SocfortressAiAlertResponse(**data)`, the `ge` / `le` of
/// `confidence_score` included (pydantic-core checks `le` first; the error
/// shows the input as given).
pub fn ai_alert_response(data: &PyValue) -> PyResult<PyValue> {
    let mut errors = match validate(&AI_ALERT_RESPONSE, data) {
        Ok(dump) => return bounded(dump, data, Vec::new()),
        Err(Invalid::Abort(status, detail)) => return Err(PyExc::Http(status, detail)),
        Err(Invalid::Errors(e)) => e,
    };
    let score_failed = errors
        .iter()
        .any(|e| e.loc.first() == Some(&MLoc::Key("confidence_score".into())));
    if !score_failed {
        if let Some(error) = bound_error(data) {
            let before = ["message", "success", "analysis", "base64_decoded"];
            let at = errors
                .iter()
                .position(|e| {
                    !matches!(e.loc.first(), Some(MLoc::Key(k)) if before.contains(&k.as_str()))
                })
                .unwrap_or(errors.len());
            errors.insert(at, error);
        }
    }
    Err(PyExc::Validation(format_validation_error(
        AI_ALERT_RESPONSE.name,
        &errors,
    )))
}

fn bounded(dump: PyValue, data: &PyValue, mut errors: Vec<PyError>) -> PyResult<PyValue> {
    if let Some(error) = bound_error(data) {
        errors.push(error);
        return Err(PyExc::Validation(format_validation_error(
            AI_ALERT_RESPONSE.name,
            &errors,
        )));
    }
    Ok(dump)
}

/// The `le=1` / `ge=0` error of an input that parsed as a float.
fn bound_error(data: &PyValue) -> Option<PyError> {
    let input = data.get("confidence_score")?.clone();
    let parsed = validate_float(&input)?;
    // NaN fails both bounds; `le` is checked first.
    let (kind, msg) = if parsed.is_nan() || parsed > 1.0 {
        ("less_than_equal", "Input should be less than or equal to 1")
    } else if parsed < 0.0 {
        (
            "greater_than_equal",
            "Input should be greater than or equal to 0",
        )
    } else {
        return None;
    };
    Some(PyError {
        loc: vec![MLoc::Key("confidence_score".into())],
        kind,
        msg: msg.into(),
        input,
    })
}

/// The float the lax `float` validator made of `v` (`None`: it refused).
fn validate_float(v: &PyValue) -> Option<f64> {
    static ONE: Model = Model::new("F", &[F::req("x", Ty::Float)]);
    match validate(&ONE, &kwargs(vec![("x", v.clone())])).ok()? {
        PyValue::Dict(d) => match d.into_iter().next()?.1 {
            PyValue::Float(f) => Some(f),
            PyValue::Int(i) => i.parse().ok(),
            _ => None,
        },
        _ => None,
    }
}

// --- VirusTotal ----------------------------------------------------------------------------

/// `AnalysisResult`.
pub static ANALYSIS_RESULT: Model = Model::allowing_extra(
    "AnalysisResult",
    &[
        F::req("method", Ty::Str),
        F::req("engine_name", Ty::Str),
        F::req("category", Ty::Str),
        F::opt("result", OPT_STR),
    ],
);

/// `TotalVotes`.
pub static TOTAL_VOTES: Model = Model::allowing_extra(
    "TotalVotes",
    &[F::req("harmless", Ty::Int), F::req("malicious", Ty::Int)],
);

/// `Attributes`.
pub static ATTRIBUTES: Model = Model::allowing_extra(
    "Attributes",
    &[
        F::req("total_votes", Ty::Model(&TOTAL_VOTES)),
        F::opt(
            "last_analysis_results",
            Ty::Nullable(&Ty::Dict(&Ty::Model(&ANALYSIS_RESULT))),
        ),
        F::opt("regional_internet_registry", OPT_STR),
        F::opt("continent", OPT_STR),
        F::opt("last_modification_date", OPT_INT),
        F::opt(
            "crowdsourced_context",
            Ty::Nullable(&Ty::List(&Ty::Dict(&Ty::Str))),
        ),
        F::opt("tags", Ty::Nullable(&Ty::List(&Ty::Str))),
        F::opt("asn", OPT_INT),
        F::opt("whois", OPT_STR),
        F::opt("whois_date", OPT_INT),
        F::opt("reputation", OPT_INT),
        F::opt("last_analysis_date", OPT_INT),
        F::opt("jarm", OPT_STR),
        F::opt("country", OPT_STR),
        F::opt("as_owner", OPT_STR),
        F::opt("last_analysis_stats", Ty::Nullable(&Ty::Dict(&Ty::Int))),
        F::opt("last_https_certificate_date", OPT_INT),
        F::opt("network", OPT_STR),
    ],
);

/// `Links`.
pub static LINKS: Model = Model::allowing_extra("Links", &[F::req("self", Ty::Str)]);

/// `Data`.
pub static DATA: Model = Model::allowing_extra(
    "Data",
    &[
        F::req("id", Ty::Str),
        F::req("type", Ty::Str),
        F::req("links", Ty::Model(&LINKS)),
        F::req("attributes", Ty::Model(&ATTRIBUTES)),
    ],
);

/// `VirusTotalResponse`.
pub static VT_RESPONSE: Model =
    Model::allowing_extra("VirusTotalResponse", &[F::req("data", Ty::Model(&DATA))]);

/// `VirusTotalRouteResponse`.
pub static VT_ROUTE_RESPONSE: Model = Model::new(
    "VirusTotalRouteResponse",
    &[
        F::req("data", Ty::Model(&VT_RESPONSE)),
        F::req("success", Ty::Bool),
        F::req("message", Ty::Str),
    ],
);

/// `FileSubmissionData`.
pub static SUBMISSION_DATA: Model = Model::allowing_extra(
    "FileSubmissionData",
    &[F::req("type", Ty::Str), F::req("id", Ty::Str)],
);

/// `FileSubmissionResponse`.
pub static SUBMISSION_RESPONSE: Model = Model::allowing_extra(
    "FileSubmissionResponse",
    &[
        F::req("data", Ty::Model(&SUBMISSION_DATA)),
        F::req("success", Ty::Bool),
        F::req("message", Ty::Str),
    ],
);

fn zero() -> PyValue {
    PyValue::Int("0".into())
}

/// `FileAnalysisStats`.
pub static ANALYSIS_STATS: Model = Model::allowing_extra(
    "FileAnalysisStats",
    &[
        F::def("harmless", Ty::Int, zero),
        F::def("malicious", Ty::Int, zero),
        F::def("suspicious", Ty::Int, zero),
        F::def("undetected", Ty::Int, zero),
        F::def("timeout", Ty::Int, zero),
        F::def("confirmed_timeout", Ty::Int, zero),
        F::def("failure", Ty::Int, zero),
        F::def("type_unsupported", Ty::Int, zero),
    ],
);

/// `FileAnalysisAttributes`.
pub static ANALYSIS_ATTRIBUTES: Model = Model::allowing_extra(
    "FileAnalysisAttributes",
    &[
        F::req("date", Ty::Int),
        F::req("status", Ty::Str),
        F::req("stats", Ty::Model(&ANALYSIS_STATS)),
    ],
);

/// `FileAnalysisData`.
pub static ANALYSIS_DATA: Model = Model::allowing_extra(
    "FileAnalysisData",
    &[
        F::req("type", Ty::Str),
        F::req("id", Ty::Str),
        F::req("attributes", Ty::Model(&ANALYSIS_ATTRIBUTES)),
    ],
);

/// `FileAnalysisResponse`.
pub static ANALYSIS_RESPONSE: Model = Model::allowing_extra(
    "FileAnalysisResponse",
    &[
        F::req("data", Ty::Model(&ANALYSIS_DATA)),
        F::req("success", Ty::Bool),
        F::req("message", Ty::Str),
    ],
);

/// `FileReportAttributes`.
pub static REPORT_ATTRIBUTES: Model = Model::allowing_extra(
    "FileReportAttributes",
    &[
        F::opt("md5", OPT_STR),
        F::opt("sha1", OPT_STR),
        F::opt("sha256", OPT_STR),
        F::opt("size", OPT_INT),
        F::opt("type_description", OPT_STR),
        F::opt("type_tag", OPT_STR),
        F::opt("creation_date", OPT_INT),
        F::opt("first_submission_date", OPT_INT),
        F::opt("last_submission_date", OPT_INT),
        F::opt("last_analysis_date", OPT_INT),
        F::opt(
            "last_analysis_stats",
            Ty::Nullable(&Ty::Model(&ANALYSIS_STATS)),
        ),
        F::opt(
            "last_analysis_results",
            Ty::Nullable(&Ty::Dict(&Ty::Model(&ANALYSIS_RESULT))),
        ),
        F::opt("reputation", OPT_INT),
        F::opt("times_submitted", OPT_INT),
        F::opt("total_votes", Ty::Nullable(&Ty::Model(&TOTAL_VOTES))),
    ],
);

/// `FileReportData`.
pub static REPORT_DATA: Model = Model::allowing_extra(
    "FileReportData",
    &[
        F::req("type", Ty::Str),
        F::req("id", Ty::Str),
        F::req("attributes", Ty::Model(&REPORT_ATTRIBUTES)),
    ],
);

/// `FileReportResponse`.
pub static REPORT_RESPONSE: Model = Model::allowing_extra(
    "FileReportResponse",
    &[
        F::req("data", Ty::Model(&REPORT_DATA)),
        F::req("success", Ty::Bool),
        F::req("message", Ty::Str),
    ],
);

/// `repr()` of a validated model instance: its declared fields in order,
/// nested models by their own `repr`, then the extra fields.
pub fn model_repr(model: &'static Model, dump: &PyValue) -> String {
    let PyValue::Dict(items) = dump else {
        return dump.py_repr();
    };
    let mut parts = Vec::new();
    for field in model.fields {
        let value = items
            .iter()
            .find(|(k, _)| k == field.key())
            .map(|(_, v)| v.clone())
            .unwrap_or(PyValue::None);
        let text = match (&field.ty, &value) {
            (Ty::Model(m), PyValue::Dict(_)) => model_repr(m, &value),
            (Ty::Nullable(Ty::Model(m)), PyValue::Dict(_)) => model_repr(m, &value),
            _ => value.py_repr(),
        };
        parts.push(format!("{}={text}", field.name));
    }
    if model.extra_allow {
        for (k, v) in items {
            if !model.fields.iter().any(|f| f.key() == k) {
                parts.push(format!("{k}={}", v.py_repr()));
            }
        }
    }
    format!("{}({})", model.name, parts.join(", "))
}

/// `input_value=` of a `repr` text (pydantic-core cuts it to 25 + 24
/// characters around `...` past 50).
pub fn cut_repr(repr: &str) -> String {
    let len = repr.len();
    if len <= 50 {
        return repr.to_string();
    }
    let mut head = 25;
    while !repr.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = len - 24;
    while !repr.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{}...{}", &repr[..head], &repr[tail..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn the_process_name_keeps_what_follows_the_last_backslash() {
        assert_eq!(last_segment("C:\\Windows\\cmd.exe"), "cmd.exe");
        assert_eq!(last_segment("cmd.exe"), "cmd.exe");
        assert_eq!(last_segment("dir\\"), "dir\\");
        assert_eq!(last_segment(""), "");
        assert_eq!(last_segment("a\\b\n"), "b\n");
    }

    #[test]
    fn confidence_bounds_are_pydantics() {
        let err = |text: &str| match ai_alert_response(&loads(text).unwrap()) {
            Err(PyExc::Validation(t)) => t,
            other => panic!("{other:?}"),
        };
        // Recorded with pydantic 2.13.
        assert_eq!(
            err(r#"{"message": "m", "success": true, "analysis": "a", "confidence_score": 1.5}"#),
            "1 validation error for SocfortressAiAlertResponse\nconfidence_score\n  Input should be \
             less than or equal to 1 [type=less_than_equal, input_value=1.5, input_type=float]\n    \
             For further information visit https://errors.pydantic.dev/2.13/v/less_than_equal"
        );
        let three = err(
            r#"{"message": 1, "success": true, "analysis": "a", "confidence_score": "-0.5", "risk_evaluation": 3}"#,
        );
        assert!(three.starts_with("3 validation errors for SocfortressAiAlertResponse\nmessage\n"));
        assert!(three.contains(
            "\nconfidence_score\n  Input should be greater than or equal to 0 \
             [type=greater_than_equal, input_value='-0.5', input_type=str]"
        ));
        assert!(three.contains("\nrisk_evaluation\n"));
        let at = |s: &str| three.find(s).unwrap();
        assert!(at("\nconfidence_score\n") < at("\nrisk_evaluation\n"));
    }
}
