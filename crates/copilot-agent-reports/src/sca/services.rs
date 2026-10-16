//! `app/agents/sca/services/sca.py` but the stream ([`super::stream`]) and
//! the policy catalog ([`super::policies`]): the per-agent collection from
//! the Wazuh manager (100 requests at a time, results in the agents'
//! order), the overview and its sort, the statistics, the CSV report in
//! MinIO, the report list, and the package registry's indexer lookup.

use std::sync::Arc;

use chrono::Utc;
use reqwest::Method;
use serde_json::json;
use tokio::sync::Semaphore;

use copilot_agents::schema::AgentRecord;
use copilot_agents::services::{csv, wazuh_err};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::model::{self, kwargs};
use copilot_upstream::py::{self, PyExc, PyResult};
use copilot_wazuh::es::make_path;
use copilot_wazuh::indexer::services::async_client;
use copilot_wazuh::pymodel::py as to_py;
use copilot_web::CurrentUser;

use crate::AgentReportsState;
use crate::agents::{self, On, accessible, may_see};
use crate::pyfmt::{dict, int, opt, s, str_list};
use crate::vulnerabilities::sync::db_text;

use super::db::{self, NewScaReport, ScaReportRow};
use super::registry::{self, Entry};
use super::schema::{
    PACKAGE_MATCH, ScaItem, Totals, empty_stats, generate_response, list_response, report_response,
};

/// `DEFAULT_MAX_CONCURRENT_REQUESTS`.
pub const MAX_CONCURRENT: usize = 100;

/// The reports' bucket.
pub const REPORTS_BUCKET: &str = "sca-reports";

/// The package index the registry lookup searches.
pub const PACKAGES_INDEX: &str = "wazuh-states-inventory-packages-*";

/// The per-policy filters of a collection.
#[derive(Debug, Clone, Default)]
pub struct Filters {
    /// `policy_id` (exact).
    pub policy_id: Option<String>,
    /// `policy_name` (case-insensitive substring).
    pub policy_name: Option<String>,
    /// `min_score`.
    pub min_score: Option<i64>,
    /// `max_score`.
    pub max_score: Option<i64>,
}

fn nonempty(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

/// `get_all_agents_from_db(db, customer_codes)`.
pub async fn agents_of(
    st: &AgentReportsState,
    codes: Option<&[String]>,
) -> PyResult<Vec<AgentRecord>> {
    let terms: Vec<On<'_>> = match codes.filter(|c| !c.is_empty()) {
        Some(c) => vec![On::CustomerIn(c)],
        None => Vec::new(),
    };
    let rows = agents::select(&st.ctx.db, &terms).await.map_err(|e| {
        tracing::error!("Error fetching agents from database: {e}");
        PyExc::http(500, format!("Failed to fetch agents: {e}"))
    })?;
    tracing::info!("Found {} agents", rows.len());
    Ok(rows)
}

/// The policies of one agent's `collect_agent_sca` answer that pass the
/// filters, as overview items; any failure is the agent's empty list.
async fn policies_of(st: &AgentReportsState, agent: &AgentRecord, f: &Filters) -> Vec<ScaItem> {
    let run = async {
        let answer =
            copilot_agents::services::sca::collect_agent_sca(&st.wazuh, &agent.agent_id, None)
                .await?;
        let listed = match model::field(&answer, "sca") {
            PyValue::List(items) => items.clone(),
            _ => Vec::new(),
        };
        if model::field(&answer, "success") != &PyValue::Bool(true) || listed.is_empty() {
            tracing::debug!("No SCA data for agent {}", agent.hostname);
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for r in &listed {
            let field = |k: &str| model::field(r, k).clone();
            let policy_id = field("policy_id");
            if let Some(want) = nonempty(&f.policy_id) {
                if policy_id.as_str() != Some(want) {
                    continue;
                }
            }
            let name = field("name");
            if let Some(want) = nonempty(&f.policy_name) {
                let Some(have) = name.as_str() else {
                    return Err(PyExc::AttributeError(
                        "'NoneType' object has no attribute 'lower'".into(),
                    ));
                };
                if !have.to_lowercase().contains(&want.to_lowercase()) {
                    continue;
                }
            }
            let score = match field("score") {
                PyValue::Int(i) => i.parse::<i64>().unwrap_or_default(),
                _ => 0,
            };
            if f.min_score.is_some_and(|m| score < m) || f.max_score.is_some_and(|m| score > m) {
                continue;
            }
            out.push(ScaItem::construct(&kwargs(vec![
                ("agent_id", s(&agent.agent_id)),
                ("agent_name", s(&agent.hostname)),
                ("customer_code", opt(agent.customer_code.clone())),
                ("policy_id", policy_id),
                ("policy_name", name),
                ("description", field("description")),
                ("total_checks", field("total_checks")),
                ("pass", field("pass")),
                ("fail", field("fail")),
                ("invalid", field("invalid")),
                ("score", field("score")),
                ("start_scan", field("start_scan")),
                ("end_scan", field("end_scan")),
                ("references", field("references")),
                ("hash_file", field("hash_file")),
            ]))?);
        }
        Ok::<_, PyExc>(out)
    };
    match run.await {
        Ok(items) => items,
        Err(e) => {
            tracing::error!(
                "Error collecting SCA for agent {}: {}",
                agent.hostname,
                e.display()
            );
            Vec::new()
        }
    }
}

/// `collect_sca_for_single_agent(agent, semaphore, …)`.
pub async fn collect_one(
    st: &AgentReportsState,
    agent: &AgentRecord,
    gate: &Semaphore,
    f: &Filters,
) -> Vec<ScaItem> {
    let _permit = gate.acquire().await;
    policies_of(st, agent, f).await
}

/// `agents = [a for a in agents if a.hostname == agent_name]` when one is
/// named.
pub fn named(agents: Vec<AgentRecord>, agent_name: Option<&str>) -> Vec<AgentRecord> {
    match agent_name.filter(|n| !n.is_empty()) {
        Some(n) => agents.into_iter().filter(|a| a.hostname == n).collect(),
        None => agents,
    }
}

/// `collect_sca_for_all_agents(...)`: every agent's items, in the agents'
/// order.
pub async fn collect_all(
    st: &AgentReportsState,
    codes: Option<&[String]>,
    agent_name: Option<&str>,
    f: &Filters,
) -> PyResult<Vec<ScaItem>> {
    let agents = agents_of(st, codes).await.map_err(|e| {
        tracing::error!("Error collecting SCA for all agents: {}", e.display());
        PyExc::http(
            500,
            format!("Failed to collect SCA results: {}", e.display()),
        )
    })?;
    let agents = named(agents, agent_name);
    if agents.is_empty() {
        return Ok(Vec::new());
    }
    tracing::info!(
        "Collecting SCA data for {} agents (max concurrent: {MAX_CONCURRENT})",
        agents.len()
    );
    let gate = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let results =
        futures::future::join_all(agents.iter().map(|a| collect_one(st, a, &gate, f))).await;
    Ok(results.into_iter().flatten().collect())
}

/// `round(x, 2)` as a float value.
fn round2(x: f64) -> PyValue {
    PyValue::Float(copilot_core::time::py_round(x, 2))
}

/// The overview query (`search_sca_overview`'s arguments).
#[derive(Debug, Clone, Default)]
pub struct OverviewParams {
    /// The scoped customer codes (`None`: every agent).
    pub codes: Option<Vec<String>>,
    /// `agent_name`.
    pub agent_name: Option<String>,
    /// The policy filters.
    pub filters: Filters,
    /// `page`.
    pub page: i64,
    /// `page_size`.
    pub page_size: i64,
}

/// The items sorted by their agent's lowest score, then each agent's by
/// score (both stable).
pub fn sort_by_agent_minimum(items: Vec<ScaItem>) -> Vec<ScaItem> {
    let mut groups: Vec<(String, i64, Vec<ScaItem>)> = Vec::new();
    for item in items {
        match groups.iter_mut().find(|(id, _, _)| *id == item.agent_id) {
            Some(g) => {
                g.1 = g.1.min(item.score);
                g.2.push(item);
            }
            None => groups.push((item.agent_id.clone(), item.score, vec![item])),
        }
    }
    groups.sort_by_key(|g| g.1);
    groups
        .into_iter()
        .flat_map(|(_, _, mut items)| {
            items.sort_by_key(|i| i.score);
            items
        })
        .collect()
}

/// `search_sca_overview(...)`: the `ScaOverviewResponse` dump.
pub async fn overview(st: &AgentReportsState, p: &OverviewParams) -> PyResult<PyValue> {
    let mut filters: Vec<(String, PyValue)> = Vec::new();
    if let Some(c) = p.codes.as_ref().filter(|c| !c.is_empty()) {
        filters.push(("customer_codes".into(), str_list(c)));
    }
    for (k, v) in [
        ("agent_name", &p.agent_name),
        ("policy_id", &p.filters.policy_id),
        ("policy_name", &p.filters.policy_name),
    ] {
        if let Some(v) = nonempty(v) {
            filters.push((k.into(), s(v)));
        }
    }
    for (k, v) in [
        ("min_score", p.filters.min_score),
        ("max_score", p.filters.max_score),
    ] {
        if let Some(v) = v {
            filters.push((k.into(), int(v)));
        }
    }
    let all = collect_all(st, p.codes.as_deref(), p.agent_name.as_deref(), &p.filters)
        .await
        .map_err(|e| {
            tracing::error!("Error in SCA overview search: {}", e.display());
            PyExc::http(
                500,
                format!("Failed to search SCA results: {}", e.display()),
            )
        })?;
    let all = sort_by_agent_minimum(all);
    let total = i64::try_from(all.len()).unwrap_or(i64::MAX);
    let total_pages = (total + p.page_size - 1) / p.page_size;
    let start = usize::try_from((p.page - 1).saturating_mul(p.page_size)).unwrap_or(usize::MAX);
    let page: Vec<PyValue> = all
        .iter()
        .skip(start)
        .take(usize::try_from(p.page_size).unwrap_or(0))
        .map(|i| i.dump.clone())
        .collect();
    let refs: Vec<&ScaItem> = all.iter().collect();
    let t = Totals::of(&refs);
    Ok(dict(vec![
        ("sca_results", PyValue::List(page)),
        ("total_count", int(total)),
        ("total_agents", int(t.agents)),
        ("total_policies", int(t.policies)),
        ("average_score", round2(t.average)),
        ("total_checks_all_agents", int(t.checks)),
        ("total_passes_all_agents", int(t.passes)),
        ("total_fails_all_agents", int(t.fails)),
        ("total_invalid_all_agents", int(t.invalid)),
        ("page", int(p.page)),
        ("page_size", int(p.page_size)),
        ("total_pages", int(total_pages)),
        ("has_next", PyValue::Bool(p.page < total_pages)),
        ("has_previous", PyValue::Bool(p.page > 1)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            s(format!(
                "Found {total} SCA results across {} agents (sorted by agent minimum score, \
                 lowest first)",
                t.agents
            )),
        ),
        ("filters_applied", PyValue::Dict(filters)),
    ]))
}

/// `get_sca_statistics(db, customer_codes)`: the `ScaStatsResponse` dump.
pub async fn statistics(st: &AgentReportsState, codes: Option<&[String]>) -> PyResult<PyValue> {
    let all = collect_all(st, codes, None, &Filters::default())
        .await
        .map_err(|e| {
            tracing::error!("Error getting SCA statistics: {}", e.display());
            PyExc::http(
                500,
                format!("Failed to get SCA statistics: {}", e.display()),
            )
        })?;
    if all.is_empty() {
        return Ok(empty_stats("No SCA results found"));
    }
    let refs: Vec<&ScaItem> = all.iter().collect();
    let t = Totals::of(&refs);
    let mut by_customer: Vec<(String, PyValue)> = Vec::new();
    if codes.map_or(0, <[String]>::len) != 1 {
        let mut groups: Vec<(String, Vec<&ScaItem>)> = Vec::new();
        for item in &all {
            let code = item
                .customer_code
                .clone()
                .filter(|c| !c.is_empty())
                .unwrap_or_else(|| "unknown".into());
            match groups.iter_mut().find(|(c, _)| *c == code) {
                Some(g) => g.1.push(item),
                None => groups.push((code, vec![item])),
            }
        }
        for (code, items) in groups {
            let c = Totals::of(&items);
            by_customer.push((
                code,
                dict(vec![
                    ("total_agents", int(c.agents)),
                    ("total_policies", int(c.policies)),
                    ("average_score", round2(c.average)),
                    ("total_checks", int(c.checks)),
                    ("total_passes", int(c.passes)),
                    ("total_fails", int(c.fails)),
                    ("total_invalid", int(c.invalid)),
                ]),
            ));
        }
    }
    Ok(dict(vec![
        ("total_agents_with_sca", int(t.agents)),
        ("total_policies", int(t.policies)),
        ("average_score_across_all", round2(t.average)),
        ("total_checks_all_agents", int(t.checks)),
        ("total_passes_all_agents", int(t.passes)),
        ("total_fails_all_agents", int(t.fails)),
        ("total_invalid_all_agents", int(t.invalid)),
        ("by_customer", PyValue::Dict(by_customer)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            s(format!("SCA statistics calculated for {} agents", t.agents)),
        ),
    ]))
}

/// The report request (`SCAReportGenerateRequest`).
#[derive(Debug, Clone, Default)]
pub struct ScaReportRequest {
    /// `customer_code`.
    pub customer_code: String,
    /// `report_name`.
    pub report_name: Option<String>,
    /// `agent_name`.
    pub agent_name: Option<String>,
    /// `policy_id`.
    pub policy_id: Option<String>,
    /// `min_score`.
    pub min_score: Option<i64>,
    /// `max_score`.
    pub max_score: Option<i64>,
}

impl ScaReportRequest {
    /// `json.dumps(filters)` of the stored row.
    pub fn filters_json(&self) -> String {
        let mut f: Vec<(String, PyValue)> = Vec::new();
        for (k, v) in [
            ("agent_name", &self.agent_name),
            ("policy_id", &self.policy_id),
        ] {
            if let Some(v) = nonempty(v) {
                f.push((k.into(), s(v)));
            }
        }
        for (k, v) in [("min_score", self.min_score), ("max_score", self.max_score)] {
            if let Some(v) = v {
                f.push((k.into(), int(v)));
            }
        }
        py_dumps(&PyValue::Dict(f), Dumps::DEFAULT).unwrap_or_default()
    }

    /// `request.model_dump(exclude_none=True)` as the route logs it.
    fn logged(&self) -> String {
        let mut parts = vec![format!("'customer_code': '{}'", self.customer_code)];
        for (k, v) in [
            ("report_name", &self.report_name),
            ("agent_name", &self.agent_name),
            ("policy_id", &self.policy_id),
        ] {
            if let Some(v) = v {
                parts.push(format!("'{k}': '{v}'"));
            }
        }
        for (k, v) in [("min_score", self.min_score), ("max_score", self.max_score)] {
            if let Some(v) = v {
                parts.push(format!("'{k}': {v}"));
            }
        }
        format!("{{{}}}", parts.join(", "))
    }
}

/// The CSV of the report.
fn report_csv(items: &[ScaItem]) -> String {
    let mut out = String::new();
    csv::row(
        &mut out,
        &[
            "Agent ID",
            "Agent Name",
            "Customer Code",
            "Policy ID",
            "Policy Name",
            "Description",
            "Total Checks",
            "Passed",
            "Failed",
            "Invalid",
            "Score",
            "Start Scan",
            "End Scan",
            "References",
            "Hash File",
        ]
        .map(String::from),
    );
    for r in items {
        csv::row(
            &mut out,
            &[
                r.agent_id.clone(),
                r.agent_name.clone(),
                r.customer_code.clone().unwrap_or_default(),
                r.policy_id.clone(),
                r.policy_name.clone(),
                r.description.clone(),
                r.total_checks.to_string(),
                r.pass_count.to_string(),
                r.fail_count.to_string(),
                r.invalid_count.to_string(),
                r.score.to_string(),
                r.start_scan.clone(),
                r.end_scan.clone(),
                r.references.clone().unwrap_or_default(),
                r.hash_file.clone().unwrap_or_default(),
            ],
        );
    }
    out
}

/// `generate_sca_csv_report(db, user, request)`: the
/// `SCAReportGenerateResponse` dump.
pub async fn generate(
    st: &AgentReportsState,
    user: &CurrentUser,
    req: &ScaReportRequest,
) -> PyValue {
    tracing::info!(
        "Generating SCA report for customer {} with filters: {}",
        req.customer_code,
        req.logged()
    );
    match generate_inner(st, user, req).await {
        Ok(dump) => dump,
        Err(text) => {
            tracing::error!("Error generating SCA report: {text}");
            generate_response(false, "Failed to generate SCA report", None, Some(text))
        }
    }
}

async fn generate_inner(
    st: &AgentReportsState,
    user: &CurrentUser,
    req: &ScaReportRequest,
) -> Result<PyValue, String> {
    let db = &st.ctx.db;
    let scope = accessible(user.access(&st.ctx).await.map_err(|e| e.to_string())?);
    if !may_see(&scope, &req.customer_code) {
        return Ok(generate_response(
            false,
            format!("Access denied to customer {}", req.customer_code),
            None,
            Some("Insufficient permissions".into()),
        ));
    }
    let report_name = match nonempty(&req.report_name) {
        Some(n) => n.to_string(),
        None => format!("sca_report_{}", Utc::now().format("%Y%m%d_%H%M%S")),
    };
    let file_name = format!("{report_name}.csv");
    let object_key = format!("{}/{file_name}", req.customer_code);
    tracing::info!("Generating new SCA report: {report_name}");
    let filters = Filters {
        policy_id: req.policy_id.clone(),
        policy_name: None,
        min_score: req.min_score,
        max_score: req.max_score,
    };
    let codes = [req.customer_code.clone()];
    let items = collect_all(st, Some(&codes), req.agent_name.as_deref(), &filters)
        .await
        .map_err(|e| e.display())?;
    tracing::info!(
        "Fetched {} SCA policy results from Wazuh Manager for report",
        items.len()
    );
    if items.is_empty() {
        return Ok(generate_response(
            false,
            "No SCA results found matching the specified criteria",
            None,
            Some("No data to export".into()),
        ));
    }
    let content = report_csv(&items).into_bytes();
    let stored = copilot_objectstore::ops::store_file_in_minio(
        &st.store,
        &content,
        REPORTS_BUCKET,
        &object_key,
        "text/csv",
    )
    .await
    .map_err(|e| e.text())?;
    let stored = match stored {
        Ok(s) => s,
        Err(error) => {
            return Ok(generate_response(
                false,
                "Failed to store report in MinIO",
                None,
                Some(error),
            ));
        }
    };
    let refs: Vec<&ScaItem> = items.iter().collect();
    let t = Totals::of(&refs);
    let total_policies = i64::try_from(items.len()).unwrap_or(i64::MAX);
    let new = NewScaReport {
        report_name: report_name.clone(),
        customer_code: req.customer_code.clone(),
        bucket_name: REPORTS_BUCKET.into(),
        object_key,
        file_name,
        file_size: stored.file_size,
        file_hash: stored.file_hash,
        generated_at: copilot_core::time::now_utc_micros(),
        generated_by: user.id,
        filters_json: req.filters_json(),
        counts: [total_policies, t.checks, t.passes, t.fails, t.invalid],
        status: "completed".into(),
    };
    let id = db::insert_report(db, &new)
        .await
        .map_err(|e| insert_report_error(&e, &new))?;
    tracing::info!("Successfully generated SCA report: {report_name}");
    let saved = db::report(db, id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Could not refresh instance".to_string())?;
    let report = report_response(&saved, false).map_err(|e| e.text())?;
    Ok(generate_response(
        true,
        format!("Successfully generated report with {total_policies} SCA policy results"),
        Some(report),
        None,
    ))
}

/// SQLAlchemy's text of a failed `SCAReport` insert.
fn insert_report_error(e: &sqlx::Error, r: &NewScaReport) -> String {
    use copilot_auth::pyvalue::str_repr;
    let params = format!(
        "({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, None)",
        str_repr(&r.report_name),
        str_repr(&r.customer_code),
        str_repr(&r.bucket_name),
        str_repr(&r.object_key),
        str_repr(&r.file_name),
        r.file_size,
        str_repr(&r.file_hash),
        crate::pyfmt::datetime_repr(r.generated_at),
        r.generated_by,
        str_repr(&r.filters_json),
        r.counts[0],
        r.counts[1],
        r.counts[2],
        r.counts[3],
        r.counts[4],
        str_repr(&r.status),
    );
    copilot_incidents::datastore::services::sqlalchemy_error(e, db::INSERT_REPORT_SQL, &params)
        .text()
}

/// `list_sca_reports(db, user, customer_codes)`.
pub async fn list(
    st: &AgentReportsState,
    user: &CurrentUser,
    requested: Option<&[String]>,
) -> PyValue {
    let run = async {
        let scope = accessible(user.access(&st.ctx).await.map_err(|e| e.to_string())?);
        let requested = requested.filter(|r| !r.is_empty());
        if let (Some(acc), Some(req)) = (&scope, requested) {
            let denied: Vec<&str> = req
                .iter()
                .filter(|c| !acc.contains(c))
                .map(String::as_str)
                .collect();
            if !denied.is_empty() {
                return Ok(list_response(
                    Vec::new(),
                    true,
                    format!("Access denied to customer {}", denied.join(", ")),
                ));
            }
        }
        let rows = db::reports(&st.ctx.db, scope.as_deref(), requested)
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(report_response(r, true).map_err(|e| e.text())?);
        }
        let n = out.len();
        Ok::<_, String>(list_response(out, true, format!("Found {n} SCA reports")))
    };
    run.await.unwrap_or_else(|e| {
        tracing::error!("Error listing SCA reports: {e}");
        list_response(Vec::new(), false, format!("Failed to list reports: {e}"))
    })
}

/// One report row.
pub async fn report_of(st: &AgentReportsState, id: i64) -> Result<Option<ScaReportRow>, String> {
    db::report(&st.ctx.db, id).await.map_err(|e| db_text(&e))
}

/// `list_sca_package_registry()`.
pub fn registry_response() -> PyValue {
    let entries: Vec<PyValue> = registry::REGISTRY
        .iter()
        .map(|e| {
            dict(vec![
                ("key", s(e.key)),
                ("display_name", s(e.display_name)),
                ("sca_application", s(e.sca_application)),
                (
                    "package_patterns",
                    PyValue::List(e.package_patterns.iter().map(|p| s(*p)).collect()),
                ),
            ])
        })
        .collect();
    let n = entries.len();
    dict(vec![
        ("entries", PyValue::List(entries)),
        ("total", int(n)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            s(format!("Found {n} tracked SCA package categories")),
        ),
    ])
}

/// The registry lookup's indexer query.
pub fn package_query(entry: &Entry) -> serde_json::Value {
    let should: Vec<serde_json::Value> = entry
        .package_patterns
        .iter()
        .map(|p| {
            json!({"wildcard": {"package.name": {"value": format!("*{p}*"), "case_insensitive": true}}})
        })
        .collect();
    json!({"query": {"bool": {"should": should, "minimum_should_match": 1}}})
}

/// The agents a registry lookup found, de-duplicated by agent id (the
/// `AgentPackageMatch` dumps), or `str()` of what the loop raised.
fn package_matches(response: &PyValue) -> PyResult<Vec<PyValue>> {
    let empty = || PyValue::Dict(Vec::new());
    let hits = py::get(response, "hits")?.cloned().unwrap_or_else(empty);
    let hits = py::get(&hits, "hits")?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    let mut seen: Vec<PyValue> = Vec::new();
    let mut out = Vec::new();
    for hit in py::iterate(&hits)? {
        let src = py::get(&hit, "_source")?.cloned().unwrap_or_else(empty);
        let agent = py::get(&src, "agent")?.cloned().unwrap_or_else(empty);
        let pkg = py::get(&src, "package")?.cloned().unwrap_or_else(empty);
        let agent_id = py::get(&agent, "id")?.cloned().unwrap_or(PyValue::None);
        if matches!(agent_id, PyValue::List(_) | PyValue::Dict(_)) {
            return Err(PyExc::TypeError(format!(
                "unhashable type: '{}'",
                py::type_name(&agent_id)
            )));
        }
        if seen.iter().any(|v| py::py_eq(v, &agent_id)) {
            continue;
        }
        seen.push(agent_id.clone());
        let pick = |v: &PyValue, k: &str| -> PyResult<PyValue> {
            Ok(py::get(v, k)?.cloned().unwrap_or(PyValue::None))
        };
        out.push(model::construct(
            &PACKAGE_MATCH,
            &kwargs(vec![
                ("agent_id", pick(&agent, "id")?),
                ("agent_name", pick(&agent, "name")?),
                ("package_name", pick(&pkg, "name")?),
                ("package_version", pick(&pkg, "version")?),
                ("package_architecture", pick(&pkg, "architecture")?),
            ]),
        )?);
    }
    Ok(out)
}

/// `detect_agents_for_sca_package(registry_key)`, then the route's narrowing
/// to the caller's agents: the `ScaPackageAgentsResponse` dump.
///
/// `accessible` is `None` for an admin.
pub async fn detect_agents(
    st: &AgentReportsState,
    key: &str,
    accessible: Option<&[String]>,
) -> PyResult<PyValue> {
    let Some(entry) = registry::get(key) else {
        let keys: Vec<&str> = registry::REGISTRY.iter().map(|e| e.key).collect();
        return Err(PyExc::http(
            404,
            format!(
                "Registry key '{key}' not found. Valid keys: {}",
                keys.join(", ")
            ),
        ));
    };
    let es = async_client(&st.wazuh).await.map_err(wazuh_err)?;
    let search = async {
        let path = format!("{}/_search", make_path(&[PACKAGES_INDEX]));
        let response = es
            .perform(
                Method::POST,
                &path,
                &[("size", "10000".to_string())],
                Some(&package_query(entry)),
            )
            .await
            .map_err(|e| PyExc::Other("Exception", e.to_string()))?;
        package_matches(&to_py(&response))
    };
    let mut matches = search.await.map_err(|e| {
        tracing::error!(
            "Error detecting agents for SCA package '{key}': {}",
            e.display()
        );
        PyExc::http(
            500,
            format!(
                "Failed to search packages in Wazuh Indexer: {}",
                e.display()
            ),
        )
    })?;
    let applicable: Vec<PyValue> = match st.sca_repo.index().await {
        Ok(index) => super::policies::policies(&index)
            .into_iter()
            .filter(|p| model::field(p, "application").as_str() == Some(entry.sca_application))
            .collect(),
        Err(e) => {
            tracing::warn!(
                "Could not fetch SCA policies index for cross-reference: {}",
                e.display()
            );
            Vec::new()
        }
    };
    // The indexer knows nothing about CoPilot tenancy: matches on agents the
    // caller may not see are dropped before the list leaves the route.
    if let Some(customers) = accessible {
        let owned = db::agent_ids_of(&st.ctx.db, customers)
            .await
            .map_err(|e| PyExc::Other("Exception", e.to_string()))?;
        matches.retain(|m| match model::field(m, "agent_id") {
            PyValue::Str(id) => !id.is_empty() && owned.contains(id),
            _ => false,
        });
    }
    let n = matches.len();
    Ok(dict(vec![
        ("registry_key", s(key)),
        ("display_name", s(entry.display_name)),
        ("sca_application", s(entry.sca_application)),
        ("matched_agents", PyValue::List(matches)),
        ("total", int(n)),
        ("applicable_policies", PyValue::List(applicable)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            s(format!(
                "Found {n} agent-package combinations for '{}'",
                entry.display_name
            )),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(agent: &str, policy: &str, score: i64) -> ScaItem {
        ScaItem::construct(&kwargs(vec![
            ("agent_id", s(agent)),
            ("agent_name", s(format!("host-{agent}"))),
            ("customer_code", PyValue::None),
            ("policy_id", s(policy)),
            ("policy_name", s(policy)),
            ("description", s("d")),
            ("total_checks", int(10)),
            ("pass", int(score / 10)),
            ("fail", int(1)),
            ("invalid", int(0)),
            ("score", int(score)),
            ("start_scan", s("a")),
            ("end_scan", s("b")),
            ("references", PyValue::None),
            ("hash_file", PyValue::None),
        ]))
        .expect("item")
    }

    #[test]
    fn agents_sort_by_their_lowest_score_then_policies_by_score() {
        let sorted = sort_by_agent_minimum(vec![
            item("001", "p1", 80),
            item("002", "p1", 50),
            item("001", "p2", 40),
            item("003", "p1", 40),
            item("002", "p2", 90),
        ]);
        let keys: Vec<(String, i64)> = sorted
            .iter()
            .map(|i| (i.agent_id.clone(), i.score))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("001".to_string(), 40),
                ("001".to_string(), 80),
                ("003".to_string(), 40),
                ("002".to_string(), 50),
                ("002".to_string(), 90),
            ]
        );
    }

    #[test]
    fn report_filters_are_stored_as_json_dumps_writes_them() {
        let req = ScaReportRequest {
            customer_code: "C".into(),
            agent_name: Some("h".into()),
            policy_id: Some(String::new()),
            min_score: Some(0),
            ..Default::default()
        };
        assert_eq!(req.filters_json(), r#"{"agent_name": "h", "min_score": 0}"#);
        assert_eq!(ScaReportRequest::default().filters_json(), "{}");
    }

    #[test]
    fn the_registry_query_ors_every_pattern() {
        let q = package_query(registry::get("iis").expect("iis"));
        assert_eq!(
            q,
            json!({"query": {"bool": {"should": [
                {"wildcard": {"package.name": {"value": "*iis*", "case_insensitive": true}}},
                {"wildcard": {"package.name": {"value": "*w3svc*", "case_insensitive": true}}}
            ], "minimum_should_match": 1}}})
        );
    }

    #[test]
    fn package_matches_dedupe_by_agent_and_fail_like_python() {
        let resp = copilot_auth::pyvalue::loads(
            r#"{"hits": {"hits": [
                {"_source": {"agent": {"id": "001", "name": "a"}, "package": {"name": "nginx"}}},
                {"_source": {"agent": {"id": "001", "name": "a"}, "package": {"name": "nginx-core"}}},
                {"_source": {"agent": {"name": "b"}, "package": {}}},
                {"_source": {}}
            ]}}"#,
        )
        .expect("json");
        let m = package_matches(&resp).expect("matches");
        assert_eq!(m.len(), 2);
        assert_eq!(model::field(&m[0], "package_name").as_str(), Some("nginx"));
        assert_eq!(model::field(&m[1], "agent_name").as_str(), Some("b"));
        let bad = copilot_auth::pyvalue::loads(
            r#"{"hits": {"hits": [{"_source": {"agent": {"id": 7}}}]}}"#,
        )
        .expect("json");
        let err = package_matches(&bad).expect_err("int id");
        assert!(
            err.text()
                .starts_with("1 validation error for AgentPackageMatch\nagent_id\n"),
            "{}",
            err.text()
        );
    }
}
