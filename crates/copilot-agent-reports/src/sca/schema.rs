//! `app/agents/sca/schema/sca.py`: the models whose validation Python runs
//! on upstream data (Wazuh's SCA results, the CoPilot-SCA index, indexer
//! package documents, stored filters), and the dumps the routes answer with
//! (by alias: an overview item's counts are `pass` / `fail` / `invalid`).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Field, Model, Ty};
use copilot_upstream::py::PyExc;

use crate::pyfmt::{dict, int, opt, s};

use super::db::ScaReportRow;

fn none() -> PyValue {
    PyValue::None
}

/// `AgentScaOverviewItem`.
pub static OVERVIEW_ITEM: Model = Model::new(
    "AgentScaOverviewItem",
    &[
        Field::req("agent_id", Ty::Str),
        Field::req("agent_name", Ty::Str),
        Field::def("customer_code", Ty::Nullable(&Ty::Str), none),
        Field::req("policy_id", Ty::Str),
        Field::req("policy_name", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("total_checks", Ty::Int),
        Field::req("pass_count", Ty::Int).alias("pass"),
        Field::req("fail_count", Ty::Int).alias("fail"),
        Field::req("invalid_count", Ty::Int).alias("invalid"),
        Field::req("score", Ty::Int),
        Field::req("start_scan", Ty::Str),
        Field::req("end_scan", Ty::Str),
        Field::def("references", Ty::Nullable(&Ty::Str), none),
        Field::def("hash_file", Ty::Nullable(&Ty::Str), none),
    ],
);

/// `ScaPolicyItem`.
pub static POLICY_ITEM: Model = Model::new(
    "ScaPolicyItem",
    &[
        Field::req("id", Ty::Str),
        Field::req("name", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("file", Ty::Str),
        Field::req("application", Ty::Str),
        Field::req("app_version", Ty::Str),
        Field::req("platform", Ty::Str),
        Field::req("cis_version", Ty::Str),
    ],
);

/// `ScaPoliciesIndexResponse`.
pub static POLICIES_INDEX: Model = Model::new(
    "ScaPoliciesIndexResponse",
    &[
        Field::req("version", Ty::Str),
        Field::req("last_updated", Ty::Str),
        Field::req("policies", Ty::List(&Ty::Model(&POLICY_ITEM))),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `AgentPackageMatch`.
pub static PACKAGE_MATCH: Model = Model::new(
    "AgentPackageMatch",
    &[
        Field::def("agent_id", Ty::Nullable(&Ty::Str), none),
        Field::def("agent_name", Ty::Nullable(&Ty::Str), none),
        Field::def("package_name", Ty::Nullable(&Ty::Str), none),
        Field::def("package_version", Ty::Nullable(&Ty::Str), none),
        Field::def("package_architecture", Ty::Nullable(&Ty::Str), none),
    ],
);

/// `SCAReportResponse` (`generated_at` already rendered).
pub static REPORT_RESPONSE: Model = Model::new(
    "SCAReportResponse",
    &[
        Field::req("id", Ty::Int),
        Field::req("report_name", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("file_name", Ty::Str),
        Field::req("file_size", Ty::Int),
        Field::req("generated_at", Ty::Any),
        Field::req("generated_by", Ty::Int),
        Field::req("total_policies", Ty::Int),
        Field::req("total_checks", Ty::Int),
        Field::req("passed_count", Ty::Int),
        Field::req("failed_count", Ty::Int),
        Field::req("invalid_count", Ty::Int),
        Field::req("filters_applied", Ty::Dict(&Ty::Any)),
        Field::req("status", Ty::Str),
        Field::def("error_message", Ty::Nullable(&Ty::Str), none),
        Field::def("download_url", Ty::Nullable(&Ty::Str), none),
    ],
);

/// One validated overview item, with the values the services compute on.
#[derive(Debug, Clone, PartialEq)]
pub struct ScaItem {
    /// The `AgentScaOverviewItem` dump (by alias).
    pub dump: PyValue,
    /// `agent_id`.
    pub agent_id: String,
    /// `agent_name`.
    pub agent_name: String,
    /// `customer_code`.
    pub customer_code: Option<String>,
    /// `policy_id`.
    pub policy_id: String,
    /// `policy_name`.
    pub policy_name: String,
    /// `description`.
    pub description: String,
    /// `total_checks`.
    pub total_checks: i64,
    /// `pass_count`.
    pub pass_count: i64,
    /// `fail_count`.
    pub fail_count: i64,
    /// `invalid_count`.
    pub invalid_count: i64,
    /// `score`.
    pub score: i64,
    /// `start_scan`.
    pub start_scan: String,
    /// `end_scan`.
    pub end_scan: String,
    /// `references`.
    pub references: Option<String>,
    /// `hash_file`.
    pub hash_file: Option<String>,
}

fn text(v: &PyValue) -> String {
    v.as_str().unwrap_or_default().to_string()
}

fn number(v: &PyValue) -> i64 {
    match v {
        PyValue::Int(i) => i.parse().unwrap_or_default(),
        _ => 0,
    }
}

impl ScaItem {
    /// `AgentScaOverviewItem(**kwargs)` (kwargs by alias).
    pub fn construct(kwargs: &PyValue) -> Result<Self, PyExc> {
        let dump = model::construct(&OVERVIEW_ITEM, kwargs)?;
        let f = |k: &str| model::field(&dump, k).clone();
        Ok(Self {
            agent_id: text(&f("agent_id")),
            agent_name: text(&f("agent_name")),
            customer_code: f("customer_code").as_str().map(str::to_string),
            policy_id: text(&f("policy_id")),
            policy_name: text(&f("policy_name")),
            description: text(&f("description")),
            total_checks: number(&f("total_checks")),
            pass_count: number(&f("pass")),
            fail_count: number(&f("fail")),
            invalid_count: number(&f("invalid")),
            score: number(&f("score")),
            start_scan: text(&f("start_scan")),
            end_scan: text(&f("end_scan")),
            references: f("references").as_str().map(str::to_string),
            hash_file: f("hash_file").as_str().map(str::to_string),
            dump,
        })
    }

    /// The policy as the stream's `agent_result` frame lists it.
    pub fn stream_policy(&self) -> PyValue {
        dict(vec![
            ("policy_id", s(&self.policy_id)),
            ("policy_name", s(&self.policy_name)),
            ("description", s(&self.description)),
            ("total_checks", int(self.total_checks)),
            ("pass_count", int(self.pass_count)),
            ("fail_count", int(self.fail_count)),
            ("invalid_count", int(self.invalid_count)),
            ("score", int(self.score)),
            ("start_scan", s(&self.start_scan)),
            ("end_scan", s(&self.end_scan)),
            ("references", opt(self.references.clone())),
            ("hash_file", opt(self.hash_file.clone())),
        ])
    }
}

/// Totals over a set of items.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Totals {
    /// Distinct agent ids.
    pub agents: usize,
    /// Distinct policy ids.
    pub policies: usize,
    /// `sum(score) / len` (`0.0` for none), not rounded.
    pub average: f64,
    /// Checks.
    pub checks: i64,
    /// Passes.
    pub passes: i64,
    /// Fails.
    pub fails: i64,
    /// Invalid.
    pub invalid: i64,
}

impl Totals {
    /// Over `items`.
    pub fn of(items: &[&ScaItem]) -> Self {
        let mut agents: Vec<&str> = Vec::new();
        let mut policies: Vec<&str> = Vec::new();
        for i in items {
            if !agents.contains(&i.agent_id.as_str()) {
                agents.push(&i.agent_id);
            }
            if !policies.contains(&i.policy_id.as_str()) {
                policies.push(&i.policy_id);
            }
        }
        let score: i64 = items.iter().map(|i| i.score).sum();
        Self {
            agents: agents.len(),
            policies: policies.len(),
            average: if items.is_empty() {
                0.0
            } else {
                score as f64 / items.len() as f64
            },
            checks: items.iter().map(|i| i.total_checks).sum(),
            passes: items.iter().map(|i| i.pass_count).sum(),
            fails: items.iter().map(|i| i.fail_count).sum(),
            invalid: items.iter().map(|i| i.invalid_count).sum(),
        }
    }
}

/// An `ScaOverviewResponse` without results (`total_count` 0 …).
pub fn empty_overview(page: i64, page_size: i64, message: &str) -> PyValue {
    dict(vec![
        ("sca_results", PyValue::List(Vec::new())),
        ("total_count", int(0)),
        ("total_agents", int(0)),
        ("total_policies", int(0)),
        ("average_score", PyValue::Float(0.0)),
        ("total_checks_all_agents", int(0)),
        ("total_passes_all_agents", int(0)),
        ("total_fails_all_agents", int(0)),
        ("total_invalid_all_agents", int(0)),
        ("page", int(page)),
        ("page_size", int(page_size)),
        ("total_pages", int(0)),
        ("has_next", PyValue::Bool(false)),
        ("has_previous", PyValue::Bool(false)),
        ("success", PyValue::Bool(true)),
        ("message", s(message)),
        ("filters_applied", PyValue::Dict(Vec::new())),
    ])
}

/// An `ScaStatsResponse` of zeros.
pub fn empty_stats(message: &str) -> PyValue {
    dict(vec![
        ("total_agents_with_sca", int(0)),
        ("total_policies", int(0)),
        ("average_score_across_all", PyValue::Float(0.0)),
        ("total_checks_all_agents", int(0)),
        ("total_passes_all_agents", int(0)),
        ("total_fails_all_agents", int(0)),
        ("total_invalid_all_agents", int(0)),
        ("by_customer", PyValue::Dict(Vec::new())),
        ("success", PyValue::Bool(true)),
        ("message", s(message)),
    ])
}

/// `SCAReportResponse(...)` of a stored row (`error_message` only where
/// the list passes it).
pub fn report_response(r: &ScaReportRow, with_error: bool) -> Result<PyValue, PyExc> {
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
            ("total_policies", int(r.total_policies)),
            ("total_checks", int(r.total_checks)),
            ("passed_count", int(r.passed_count)),
            ("failed_count", int(r.failed_count)),
            ("invalid_count", int(r.invalid_count)),
            ("filters_applied", filters),
            ("status", s(&r.status)),
            (
                "error_message",
                if with_error {
                    opt(r.error_message.clone())
                } else {
                    PyValue::None
                },
            ),
            (
                "download_url",
                s(format!("/api/v1/sca/reports/{}/download", r.id)),
            ),
        ]),
    )
}

/// `SCAReportGenerateResponse`.
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

/// `SCAReportListResponse`.
pub fn list_response(reports: Vec<PyValue>, success: bool, message: String) -> PyValue {
    let n = reports.len();
    dict(vec![
        ("reports", PyValue::List(reports)),
        ("total_count", int(n)),
        ("success", PyValue::Bool(success)),
        ("message", s(message)),
    ])
}
