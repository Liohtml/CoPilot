//! `app/agents/vulnerabilities/schema/vulnerabilities.py`: the response
//! models, as `copilot_upstream::model` statics where Python validates
//! values it did not produce itself (indexer and EPSS data, stored filters),
//! and the dumps the services answer with.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Field, Model, Ty};
use copilot_upstream::py::PyExc;

use crate::pyfmt::{dict, int, opt, s};

use super::db::{ReportRow, VulnRow};

fn none() -> PyValue {
    PyValue::None
}

fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

/// `VulnerabilitySearchItem` (its datetimes already rendered).
pub static SEARCH_ITEM: Model = Model::new(
    "VulnerabilitySearchItem",
    &[
        Field::req("cve_id", Ty::Str),
        Field::req("severity", Ty::Str),
        Field::req("title", Ty::Str),
        Field::req("agent_name", Ty::Str),
        Field::def("customer_code", Ty::Nullable(&Ty::Str), none),
        Field::def("references", Ty::Nullable(&Ty::Str), none),
        Field::req("detected_at", Ty::Any),
        Field::def("published_at", Ty::Any, none),
        Field::def("base_score", Ty::Nullable(&Ty::Float), none),
        Field::def("package_name", Ty::Nullable(&Ty::Str), none),
        Field::def("package_version", Ty::Nullable(&Ty::Str), none),
        Field::def("package_architecture", Ty::Nullable(&Ty::Str), none),
        Field::def("epss_score", Ty::Nullable(&Ty::Str), none),
        Field::def("epss_percentile", Ty::Nullable(&Ty::Str), none),
    ],
);

/// `VulnerabilitySearchResponse`.
pub static SEARCH_RESPONSE: Model = Model::new(
    "VulnerabilitySearchResponse",
    &[
        Field::req("vulnerabilities", Ty::List(&Ty::Model(&SEARCH_ITEM))),
        Field::req("total_count", Ty::Int),
        Field::req("critical_count", Ty::Int),
        Field::req("high_count", Ty::Int),
        Field::req("medium_count", Ty::Int),
        Field::req("low_count", Ty::Int),
        Field::req("page", Ty::Int),
        Field::req("page_size", Ty::Int),
        Field::req("total_pages", Ty::Int),
        Field::req("has_next", Ty::Bool),
        Field::req("has_previous", Ty::Bool),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::def("filters_applied", Ty::Dict(&Ty::Any), empty_dict),
    ],
);

/// `VulnerabilityReportResponse` (`generated_at` already rendered).
pub static REPORT_RESPONSE: Model = Model::new(
    "VulnerabilityReportResponse",
    &[
        Field::req("id", Ty::Int),
        Field::req("report_name", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("file_name", Ty::Str),
        Field::req("file_size", Ty::Int),
        Field::req("generated_at", Ty::Any),
        Field::req("generated_by", Ty::Int),
        Field::req("total_vulnerabilities", Ty::Int),
        Field::req("critical_count", Ty::Int),
        Field::req("high_count", Ty::Int),
        Field::req("medium_count", Ty::Int),
        Field::req("low_count", Ty::Int),
        Field::req("filters_applied", Ty::Dict(&Ty::Any)),
        Field::req("status", Ty::Str),
        Field::def("download_url", Ty::Nullable(&Ty::Str), none),
    ],
);

/// `VulnerabilitySyncResponse`.
pub fn sync_response(success: bool, message: String, synced: i64, errors: &[String]) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(success)),
        ("message", s(message)),
        ("synced_count", int(synced)),
        ("errors", crate::pyfmt::str_list(errors)),
    ])
}

/// `VulnerabilityDeleteResponse`.
pub fn delete_response(success: bool, message: String, deleted: u64, errors: &[String]) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(success)),
        ("message", s(message)),
        ("deleted_count", int(deleted)),
        ("errors", crate::pyfmt::str_list(errors)),
    ])
}

/// `AgentVulnerabilityOut` of a row.
pub fn vulnerability_out(r: &VulnRow) -> PyValue {
    let t = |t: chrono::NaiveDateTime| s(copilot_core::time::to_pydantic_iso(t));
    dict(vec![
        ("id", int(r.id)),
        ("cve_id", s(&r.cve_id)),
        ("severity", s(&r.severity)),
        ("title", s(&r.title)),
        ("references", opt(r.references.clone())),
        ("status", s(&r.status)),
        ("discovered_at", t(r.discovered_at)),
        ("remediated_at", r.remediated_at.map_or(PyValue::None, t)),
        ("epss_score", opt(r.epss_score.clone())),
        ("epss_percentile", opt(r.epss_percentile.clone())),
        ("package_name", opt(r.package_name.clone())),
        ("agent_id", s(&r.agent_id)),
        ("customer_code", opt(r.customer_code.clone())),
    ])
}

/// An empty `VulnerabilitySearchResponse` (the early answers).
pub fn empty_search(
    page: i64,
    page_size: i64,
    success: bool,
    message: String,
    filters: PyValue,
) -> PyValue {
    dict(vec![
        ("vulnerabilities", PyValue::List(Vec::new())),
        ("total_count", int(0)),
        ("critical_count", int(0)),
        ("high_count", int(0)),
        ("medium_count", int(0)),
        ("low_count", int(0)),
        ("page", int(page)),
        ("page_size", int(page_size)),
        ("total_pages", int(0)),
        ("has_next", PyValue::Bool(false)),
        ("has_previous", PyValue::Bool(false)),
        ("success", PyValue::Bool(success)),
        ("message", s(message)),
        ("filters_applied", filters),
    ])
}

/// `VulnerabilityReportResponse(...)` of a stored row: `filters_applied` is
/// `json.loads(filters_json or "{}")`, whose failures (and a value that is
/// not a dict) are what Python raises there.
pub fn report_response(r: &ReportRow) -> Result<PyValue, PyExc> {
    let text = r
        .filters_json
        .as_deref()
        .filter(|t| !t.is_empty())
        .unwrap_or("{}");
    let filters = crate::pyfmt::json_loads(text)?;
    model::construct(
        &REPORT_RESPONSE,
        &model::kwargs(vec![
            ("id", int(r.id)),
            ("report_name", s(&r.report_name)),
            ("customer_code", s(&r.customer_code)),
            ("file_name", s(&r.file_name)),
            ("file_size", int(r.file_size)),
            (
                "generated_at",
                s(copilot_core::time::to_pydantic_iso(r.generated_at)),
            ),
            ("generated_by", int(r.generated_by)),
            ("total_vulnerabilities", int(r.total_vulnerabilities)),
            ("critical_count", int(r.critical_count)),
            ("high_count", int(r.high_count)),
            ("medium_count", int(r.medium_count)),
            ("low_count", int(r.low_count)),
            ("filters_applied", filters),
            ("status", s(&r.status)),
            (
                "download_url",
                s(format!("/api/v1/vulnerabilities/reports/{}/download", r.id)),
            ),
        ]),
    )
}

/// `VulnerabilityReportGenerateResponse`.
pub fn generate_response(
    success: bool,
    message: impl Into<String>,
    report: Option<PyValue>,
    error: Option<String>,
) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(success)),
        ("message", s(message)),
        ("report", report.unwrap_or(PyValue::None)),
        ("error", opt(error)),
    ])
}

/// `VulnerabilityReportListResponse`.
pub fn list_response(reports: Vec<PyValue>, success: bool, message: String) -> PyValue {
    let n = reports.len();
    dict(vec![
        ("reports", PyValue::List(reports)),
        ("total_count", int(n)),
        ("success", PyValue::Bool(success)),
        ("message", s(message)),
    ])
}
