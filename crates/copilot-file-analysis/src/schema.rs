//! `schema/analysis.py`: the Pydantic models — the stored job and result
//! (validated again whenever a route answers with them, which is what drops
//! a key the model does not declare), the request bodies and the answers.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{EnumTy, Field as F, Model, Ty};

use crate::py;

fn empty_str() -> PyValue {
    py::s("")
}

fn yes() -> PyValue {
    PyValue::Bool(true)
}

fn no() -> PyValue {
    PyValue::Bool(false)
}

fn zero() -> PyValue {
    py::int(0)
}

fn upload() -> PyValue {
    py::s("upload")
}

fn pending() -> PyValue {
    py::s("pending")
}

fn lookup() -> PyValue {
    py::s("lookup")
}

fn static_only() -> PyValue {
    PyValue::List(vec![py::s("static")])
}

fn empty_dict() -> PyValue {
    py::empty_dict()
}

fn empty_list() -> PyValue {
    py::empty_list()
}

/// `Tier`.
pub static TIER: EnumTy = EnumTy {
    name: "Tier",
    values: &["static", "dynamic"],
};

/// `Verdict`.
pub static VERDICT: EnumTy = EnumTy {
    name: "Verdict",
    values: &["clean", "suspicious", "malicious"],
};

/// `Status`.
pub static STATUS: EnumTy = EnumTy {
    name: "Status",
    values: &["pending", "queued", "running", "done", "failed"],
};

const OPT_STR: Ty = Ty::Nullable(&Ty::Str);
const OPT_INT: Ty = Ty::Nullable(&Ty::Int);

/// `AnalysisJob`.
pub static ANALYSIS_JOB: Model = Model::new(
    "AnalysisJob",
    &[
        F::req("job_id", Ty::Str),
        F::def("sha256", Ty::Str, empty_str),
        F::def("filename", Ty::Str, empty_str),
        F::req("customer_code", Ty::Str),
        F::def("source", Ty::Str, upload),
        F::def("status", Ty::Enum(&STATUS), pending),
        F::def("static_status", Ty::Enum(&STATUS), pending),
        F::opt("dynamic_status", Ty::Nullable(&Ty::Enum(&STATUS))),
        F::def("sandbox_enabled", Ty::Bool, no),
        F::def("hardened", Ty::Bool, yes),
        F::opt("verdict", Ty::Nullable(&Ty::Enum(&VERDICT))),
        F::def("created_at", Ty::Str, empty_str),
        F::def("updated_at", Ty::Str, empty_str),
        F::opt("error", OPT_STR),
    ],
);

/// `AnalysisResult`.
pub static ANALYSIS_RESULT: Model = Model::new(
    "AnalysisResult",
    &[
        F::req("job", Ty::Model(&ANALYSIS_JOB)),
        F::def("inspector", Ty::Dict(&Ty::Any), empty_dict),
        F::opt("sandbox", Ty::Nullable(&Ty::Dict(&Ty::Any))),
        F::opt("reputation", Ty::Nullable(&Ty::Dict(&Ty::Any))),
        F::def("preview_urls", Ty::List(&Ty::Str), empty_list),
        F::opt("engine_version", OPT_INT),
        F::opt("verdict_reason", OPT_STR),
    ],
);

/// `SubmitRequest`.
pub static SUBMIT_REQUEST: Model = Model::new(
    "SubmitRequest",
    &[
        F::req("source", Ty::Str),
        F::req("customer_code", Ty::Str),
        F::def("tiers", Ty::List(&Ty::Enum(&TIER)), static_only),
        F::def("reputation_mode", Ty::Str, lookup),
        F::opt("client_id", OPT_STR),
        F::opt("target_path", OPT_STR),
        F::opt("hostname", OPT_STR),
    ],
);

/// `EnumerateRequest`.
pub static ENUMERATE_REQUEST: Model = Model::new(
    "EnumerateRequest",
    &[
        F::req("customer_code", Ty::Str),
        F::req("client_id", Ty::Str),
        F::req("target_path", Ty::Str),
    ],
);

/// `AgentInfo`.
pub static AGENT_INFO: Model = Model::new(
    "AgentInfo",
    &[
        F::req("client_id", Ty::Str),
        F::def("hostname", Ty::Str, empty_str),
        F::def("os", Ty::Str, empty_str),
        F::def("online", Ty::Bool, no),
        F::opt("last_seen", OPT_INT),
        F::def("unassigned", Ty::Bool, no),
    ],
);

/// `MatchInfo`.
pub static MATCH_INFO: Model = Model::new(
    "MatchInfo",
    &[
        F::req("path", Ty::Str),
        F::def("name", Ty::Str, empty_str),
        F::def("size", Ty::Int, zero),
        F::def("sha256", Ty::Str, empty_str),
    ],
);

/// `HistoryItem`.
pub static HISTORY_ITEM: Model = Model::new(
    "HistoryItem",
    &[
        F::req("job_id", Ty::Str),
        F::def("filename", Ty::Str, empty_str),
        F::def("sha256", Ty::Str, empty_str),
        F::opt("verdict", Ty::Nullable(&Ty::Enum(&VERDICT))),
        F::def("source", Ty::Str, empty_str),
        F::def("status", Ty::Str, empty_str),
        F::def("hardened", Ty::Bool, yes),
        F::def("created_at", Ty::Str, empty_str),
        F::def("updated_at", Ty::Str, empty_str),
        F::opt("vt_malicious", OPT_INT),
        F::opt("vt_total", OPT_INT),
    ],
);

/// `SubmitResponse`.
pub static SUBMIT_RESPONSE: Model = Model::new(
    "SubmitResponse",
    &[
        F::def("success", Ty::Bool, yes),
        F::def("message", Ty::Str, empty_str),
        F::req("job_id", Ty::Str),
    ],
);

/// `SearchResponse` (its only validated field).
pub static SEARCH_RESPONSE: Model = Model::new(
    "SearchResponse",
    &[
        F::def("success", Ty::Bool, yes),
        F::def("message", Ty::Str, empty_str),
        F::opt("job_id", OPT_STR),
    ],
);

/// The `{"success": true, "message": …, <key>: <value>}` answer the routes
/// build.
pub fn answer(message: &str, key: &str, value: PyValue) -> PyValue {
    py::dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", py::s(message)),
        (key, value),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;
    use copilot_upstream::model::construct;

    #[test]
    fn a_stored_job_validates_like_pydantic() {
        let dump = construct(
            &ANALYSIS_JOB,
            &loads(r#"{"job_id": "j", "customer_code": "c", "status": "done", "extra": 1}"#)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            copilot_upstream::json::pydantic_json(&dump),
            r#"{"job_id":"j","sha256":"","filename":"","customer_code":"c","source":"upload","status":"done","static_status":"pending","dynamic_status":null,"sandbox_enabled":false,"hardened":true,"verdict":null,"created_at":"","updated_at":"","error":null}"#
        );
        let err = construct(
            &ANALYSIS_JOB,
            &loads(r#"{"job_id": "j", "customer_code": "c", "status": "x"}"#).unwrap(),
        )
        .unwrap_err()
        .text();
        assert!(err.starts_with("1 validation error for AnalysisJob\nstatus\n  Input should be 'pending', 'queued', 'running', 'done' or 'failed'"), "{err}");
    }
}
