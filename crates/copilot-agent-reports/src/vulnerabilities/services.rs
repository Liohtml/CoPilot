//! `app/agents/vulnerabilities/services/vulnerabilities.py` but the sync
//! ([`super::sync`]): the statistics, the delete, the indexer search, the
//! CSV report (and its export scroll), the report list.

use chrono::Utc;
use serde_json::{Value, json};

use copilot_agents::services::csv;
use copilot_auth::pyvalue::{PyValue, float_repr};
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::model;
use copilot_wazuh::error::PyErr;
use copilot_wazuh::es::{Es, make_path};
use copilot_wazuh::indexer::services::async_client;
use copilot_wazuh::pymodel::py;
use copilot_wazuh::pyops;
use copilot_web::{ApiError, CurrentUser};
use reqwest::Method;

use crate::AgentReportsState;
use crate::agents::{self, On, accessible, may_see};
use crate::pyfmt::{dict, int, isoformat, opt, pydantic_iso, s};

use super::db::{self, DeleteScope, NewReport, ReportRow};
use super::indexer::{self, VulnData, filter_query, hit_agent};
use super::schema::{
    SEARCH_ITEM, SEARCH_RESPONSE, delete_response, empty_search, generate_response, list_response,
    report_response, vulnerability_out,
};
use super::sync::db_text;

/// The reports' bucket.
pub const REPORTS_BUCKET: &str = "vulnerability-reports";

/// `get_vulnerabilities_by_agent(agent_id, severity)`, narrowed (Rust) to
/// the rows of the caller's customers.
pub async fn by_agent(
    st: &AgentReportsState,
    agent_id: &str,
    severities: Option<&[String]>,
    customers: Option<&[String]>,
) -> Result<PyValue, ApiError> {
    let rows = db::of_agent(&st.ctx.db, agent_id, severities, customers)
        .await
        .map_err(|e| {
            ApiError::server_error(format!(
                "Failed to get vulnerabilities for agent {agent_id}: 500: Failed to get \
                 vulnerabilities for agent {agent_id}: {}",
                db_text(&e)
            ))
        })?;
    let out: Vec<PyValue> = rows.iter().map(vulnerability_out).collect();
    let n = out.len();
    Ok(dict(vec![
        ("vulnerabilities", PyValue::List(out)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            s(format!(
                "Retrieved {n} vulnerabilities for agent {agent_id}"
            )),
        ),
        ("total_count", int(n)),
    ]))
}

/// `get_vulnerability_statistics(customer_code, accessible_customers)`.
pub async fn statistics(
    st: &AgentReportsState,
    customer_code: Option<&str>,
    accessible: Option<&[String]>,
) -> Result<PyValue, ApiError> {
    let code = customer_code.filter(|c| !c.is_empty());
    let rows = db::for_stats(&st.ctx.db, code, accessible)
        .await
        .map_err(|e| {
            ApiError::server_error(format!(
                "Failed to get vulnerability statistics: 500: Failed to get vulnerability \
                 statistics: {}",
                db_text(&e)
            ))
        })?;
    let count = |name: &str| {
        rows.iter()
            .filter(|r| r.severity.to_lowercase() == name)
            .count()
    };
    let mut by_customer: Vec<(String, i64)> = Vec::new();
    if code.is_none() {
        for r in &rows {
            if let Some(c) = r.customer_code.as_deref().filter(|c| !c.is_empty()) {
                match by_customer.iter_mut().find(|(k, _)| k == c) {
                    Some(slot) => slot.1 += 1,
                    None => by_customer.push((c.to_string(), 1)),
                }
            }
        }
    }
    Ok(dict(vec![
        ("total_vulnerabilities", int(rows.len())),
        ("critical_count", int(count("critical"))),
        ("high_count", int(count("high"))),
        ("medium_count", int(count("medium"))),
        ("low_count", int(count("low"))),
        (
            "by_customer",
            PyValue::Dict(by_customer.into_iter().map(|(k, n)| (k, int(n))).collect()),
        ),
        ("success", PyValue::Bool(true)),
        (
            "message",
            s("Vulnerability statistics retrieved successfully"),
        ),
    ]))
}

/// `delete_vulnerabilities(agent_name, customer_code)`.
pub async fn delete(
    st: &AgentReportsState,
    agent_name: Option<&str>,
    customer_code: Option<&str>,
) -> PyValue {
    let db = &st.ctx.db;
    let run = async {
        if let Some(name) = agent_name {
            tracing::info!("Deleting vulnerabilities for agent: {name}");
            let Some(agent) = agents::first(db, &[On::Hostname(name)])
                .await
                .map_err(|e| db_text(&e))?
            else {
                return Ok(delete_response(
                    false,
                    format!("Agent {name} not found in database"),
                    0,
                    &[format!("Agent {name} not found")],
                ));
            };
            let n = db::delete(db, DeleteScope::Agent(&agent.agent_id))
                .await
                .map_err(|e| db_text(&e))?;
            return Ok(delete_response(
                true,
                format!("Successfully deleted {n} vulnerabilities for agent {name}"),
                n,
                &[],
            ));
        }
        if let Some(code) = customer_code {
            tracing::info!("Deleting vulnerabilities for customer: {code}");
            let n = db::delete(db, DeleteScope::Customer(code))
                .await
                .map_err(|e| db_text(&e))?;
            return Ok(delete_response(
                true,
                format!("Successfully deleted {n} vulnerabilities for customer {code}"),
                n,
                &[],
            ));
        }
        tracing::warn!("Deleting ALL vulnerabilities from database");
        let n = db::delete(db, DeleteScope::All)
            .await
            .map_err(|e| db_text(&e))?;
        Ok::<_, String>(delete_response(
            true,
            format!("Successfully deleted ALL {n} vulnerabilities from database"),
            n,
            &[],
        ))
    };
    run.await.unwrap_or_else(|e| {
        tracing::error!("Error deleting vulnerabilities: {e}");
        delete_response(
            false,
            format!("Failed to delete vulnerabilities: {e}"),
            0,
            &[e],
        )
    })
}

/// `get_epss_score_for_cve`, when asked for.
async fn epss(st: &AgentReportsState, include: bool, cve: &str) -> (PyValue, PyValue) {
    if !include {
        return (PyValue::None, PyValue::None);
    }
    let (score, percentile) = st.epss.score_for_cve(cve).await;
    (opt(score), opt(percentile))
}

/// A `VulnerabilitySearchItem`: its dump, and its two `datetime`s as the
/// CSV prints them (`isoformat()`).
#[derive(Debug, Clone)]
pub struct Item {
    /// The model dump.
    pub dump: PyValue,
    /// `detected_at`.
    pub detected_at: copilot_ingest::py::IsoDateTime,
    /// `published_at`.
    pub published_at: Option<copilot_ingest::py::IsoDateTime>,
}

/// One hit as the search and the export turn it into a
/// `VulnerabilitySearchItem`; `Err` is the exception their loop logs and
/// skips.
async fn search_item(
    st: &AgentReportsState,
    hit: &Value,
    hostnames: &[(String, Option<String>)],
    include_epss: bool,
) -> Result<Item, String> {
    let agent = hit_agent(hit)?;
    let customer = match &agent {
        Value::String(h) => agents::customer_of(hostnames, h).map(str::to_string),
        _ => None,
    };
    let v: VulnData = indexer::process_document(hit)?;
    let (epss_score, epss_percentile) = epss(st, include_epss, &v.cve_id).await;
    let item = model::construct(
        &SEARCH_ITEM,
        &model::kwargs(vec![
            ("cve_id", s(&v.cve_id)),
            ("severity", s(&v.severity)),
            ("title", s(&v.title)),
            ("agent_name", py(&agent)),
            ("customer_code", opt(customer)),
            ("references", opt(v.references.clone())),
            ("detected_at", s(pydantic_iso(&v.detected_at))),
            (
                "published_at",
                v.published_at
                    .as_ref()
                    .map_or(PyValue::None, |p| s(pydantic_iso(p))),
            ),
            (
                "base_score",
                v.base_score.map_or(PyValue::None, PyValue::Float),
            ),
            ("package_name", opt(v.package_name.clone())),
            ("package_version", opt(v.package_version.clone())),
            ("package_architecture", opt(v.package_architecture.clone())),
            ("epss_score", epss_score),
            ("epss_percentile", epss_percentile),
        ]),
    )
    .map_err(|e| e.text())?;
    Ok(Item {
        dump: item,
        detected_at: v.detected_at,
        published_at: v.published_at,
    })
}

/// The search's filters.
#[derive(Debug, Clone, Default)]
pub struct SearchParams {
    /// `customer_codes_query`.
    pub customer_codes: Option<Vec<String>>,
    /// `agent_name`.
    pub agent_name: Option<String>,
    /// `severity`.
    pub severity: Option<String>,
    /// `cve_id`.
    pub cve_id: Option<String>,
    /// `package_name`.
    pub package_name: Option<String>,
    /// `page`.
    pub page: i64,
    /// `page_size`.
    pub page_size: i64,
    /// `include_epss`.
    pub include_epss: bool,
}

fn nonempty(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

/// `float(epss_score)` of the sort key (`0.0` for `None` or a failure).
fn epss_float(v: &PyValue) -> f64 {
    let PyValue::Str(text) = v else {
        return 0.0;
    };
    let t = copilot_web::form::py_strip(text).replace('_', "");
    t.parse::<f64>().unwrap_or(0.0)
}

fn severity_rank(sev: &PyValue) -> i64 {
    match sev.as_str() {
        Some("Critical") => 0,
        Some("High") => 1,
        Some("Medium") => 2,
        Some("Low") => 3,
        _ => 4,
    }
}

/// An integer of an indexer answer (`count`) as Python's arithmetic sees it.
fn py_int_value(v: &Value) -> Result<i64, String> {
    match v {
        Value::Number(n) if n.is_i64() => Ok(n.as_i64().unwrap_or_default()),
        Value::Number(n) => Ok(n.as_f64().map_or(0, |f| f as i64)),
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::String(_) => Err("can only concatenate str (not \"int\") to str".into()),
        Value::Array(_) => Err("can only concatenate list (not \"int\") to list".into()),
        other => Err(format!(
            "unsupported operand type(s) for +: '{}' and 'int'",
            copilot_wazuh::indexer::services::py_type(other)
        )),
    }
}

/// `search_vulnerabilities_from_indexer(...)`: the `VulnerabilitySearchResponse`
/// dump.
pub async fn search(
    st: &AgentReportsState,
    user: &CurrentUser,
    p: &SearchParams,
) -> Result<PyValue, ApiError> {
    let scope = accessible(user.access(&st.ctx).await?);
    if let Some(acc) = &scope {
        let denied: Vec<String> = p
            .customer_codes
            .iter()
            .flatten()
            .filter(|c| !acc.contains(c))
            .cloned()
            .collect();
        if !denied.is_empty() {
            return Ok(empty_search(
                p.page,
                p.page_size,
                true,
                format!("Access denied to customer {}", denied.join(", ")),
                json_dict(),
            ));
        }
    }
    let mut filters: Vec<(String, PyValue)> = Vec::new();
    if let Some(c) = p.customer_codes.as_ref().filter(|c| !c.is_empty()) {
        filters.push(("customer_codes".into(), crate::pyfmt::str_list(c)));
    }
    for (k, v) in [
        ("agent_name", &p.agent_name),
        ("severity", &p.severity),
        ("cve_id", &p.cve_id),
        ("package_name", &p.package_name),
    ] {
        if let Some(v) = nonempty(v) {
            filters.push((k.into(), s(v)));
        }
    }
    let filters = PyValue::Dict(filters);
    Ok(
        match search_inner(st, p, scope.as_deref(), &filters).await {
            Ok(dump) => dump,
            Err(text) => {
                tracing::error!("Error searching vulnerabilities from indexer: {text}");
                empty_search(
                    p.page,
                    p.page_size,
                    false,
                    format!("Failed to search vulnerabilities: {text}"),
                    filters,
                )
            }
        },
    )
}

fn json_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

async fn search_inner(
    st: &AgentReportsState,
    p: &SearchParams,
    accessible: Option<&[String]>,
    filters: &PyValue,
) -> Result<PyValue, String> {
    let es = async_client(&st.wazuh).await.map_err(|e| e.py_str())?;
    let db = &st.ctx.db;
    let hostnames = agents::hostname_customers(db)
        .await
        .map_err(|e| db_text(&e))?;
    let requested = p.customer_codes.as_deref().filter(|c| !c.is_empty());
    let agent_name = nonempty(&p.agent_name);
    let mut terms: Vec<On<'_>> = Vec::new();
    if let Some(acc) = accessible {
        terms.push(On::CustomerIn(acc));
    }
    if let Some(req) = requested {
        terms.push(On::CustomerIn(req));
    }
    if let Some(h) = agent_name {
        terms.push(On::Hostname(h));
    }
    let found = agents::select(db, &terms).await.map_err(|e| db_text(&e))?;
    let narrowed = accessible.is_some() || requested.is_some() || agent_name.is_some();
    if found.is_empty() && narrowed {
        return Ok(empty_search(
            p.page,
            p.page_size,
            true,
            "No agents found matching the specified criteria or user access permissions".into(),
            filters.clone(),
        ));
    }
    let hosts: Vec<String> = if narrowed {
        found
            .iter()
            .filter(|a| !a.hostname.is_empty())
            .map(|a| a.hostname.clone())
            .collect()
    } else {
        Vec::new()
    };
    let indices = indexer::vulnerability_indices(&st.wazuh)
        .await
        .map_err(|e: PyErr| e.py_str())?;
    if indices.is_empty() {
        return Ok(empty_search(
            p.page,
            p.page_size,
            true,
            "No vulnerability indices found".into(),
            filters.clone(),
        ));
    }
    let query = filter_query(
        &hosts,
        nonempty(&p.severity),
        nonempty(&p.cve_id),
        nonempty(&p.package_name),
    );
    let joined = indices.join(",");
    let count = es
        .perform(
            Method::POST,
            &make_path(&[&joined, "_count"]),
            &[],
            Some(&json!({ "query": query })),
        )
        .await
        .map_err(|e| e.to_string())?;
    let total_raw = pyops::index(&count, "count")?;
    let agg = es
        .perform(
            Method::POST,
            &make_path(&[&joined, "_search"]),
            &[],
            Some(&json!({
                "query": query,
                "size": 0,
                "aggs": {"severity_counts": {"terms": {"field": "vulnerability.severity", "size": 10}}},
            })),
        )
        .await
        .map_err(|e| e.to_string())?;
    let mut counts: Vec<(&str, Value)> = ["Critical", "High", "Medium", "Low"]
        .into_iter()
        .map(|k| (k, json!(0)))
        .collect();
    if pyops::contains(&agg, "aggregations")?
        && pyops::contains(&pyops::index(&agg, "aggregations")?, "severity_counts")?
    {
        let buckets = pyops::index(&pyops::index(&agg, "aggregations")?, "severity_counts")?;
        let buckets = pyops::index(&buckets, "buckets")?;
        for bucket in pyops::iterate(&buckets)? {
            let key = pyops::index(&bucket, "key")?;
            let n = pyops::index(&bucket, "doc_count")?;
            if let Value::Array(_) | Value::Object(_) = key {
                return Err(format!(
                    "unhashable type: '{}'",
                    copilot_wazuh::indexer::services::py_type(&key)
                ));
            }
            if let Some(slot) = counts.iter_mut().find(|(k, _)| Some(*k) == key.as_str()) {
                slot.1 = n;
            }
        }
    }
    let total_count = py_int_value(&total_raw)?;
    let total_pages = (total_count + p.page_size - 1).div_euclid(p.page_size);
    let has_next = p.page < total_pages;
    let has_previous = p.page > 1;
    let count_of = |k: &str| {
        counts
            .iter()
            .find(|(n, _)| *n == k)
            .map_or(PyValue::None, |(_, v)| py(v))
    };
    let build = |vulns: Vec<PyValue>, success: bool, message: String| {
        model::construct(
            &SEARCH_RESPONSE,
            &model::kwargs(vec![
                ("vulnerabilities", PyValue::List(vulns)),
                ("total_count", py(&total_raw)),
                ("critical_count", count_of("Critical")),
                ("high_count", count_of("High")),
                ("medium_count", count_of("Medium")),
                ("low_count", count_of("Low")),
                ("page", int(p.page)),
                ("page_size", int(p.page_size)),
                ("total_pages", int(total_pages)),
                ("has_next", PyValue::Bool(has_next)),
                ("has_previous", PyValue::Bool(has_previous)),
                ("success", PyValue::Bool(success)),
                ("message", s(message)),
                ("filters_applied", filters.clone()),
            ]),
        )
        .map_err(|e| e.text())
    };
    if total_count == 0 {
        return Ok(empty_search(
            p.page,
            p.page_size,
            true,
            "No vulnerabilities found matching the specified criteria".into(),
            filters.clone(),
        ));
    }
    let start = (p.page - 1) * p.page_size;
    if start >= 10000 {
        tracing::warn!(
            "Deep pagination requested (page {}, start_index {start}). Elasticsearch limits \
             pagination to 10,000 results. Please use more specific filters or export to CSV report.",
            p.page
        );
        return build(
            Vec::new(),
            false,
            format!(
                "Deep pagination not supported beyond 10,000 results (requested page {}, \
                 position {start}). Please use more specific filters to narrow down results or \
                 use the CSV export feature for accessing all vulnerabilities. Maximum supported \
                 page: 200 (with page_size=50).",
                p.page
            ),
        );
    }
    let page = es
        .perform(
            Method::POST,
            &make_path(&[&joined, "_search"]),
            &[],
            Some(&json!({
                "query": query,
                "sort": [
                    {"vulnerability.detected_at": {"order": "desc"}},
                    {"vulnerability.severity": {"order": "asc"}},
                    {"_id": {"order": "asc"}},
                ],
                "from": start,
                "size": p.page_size,
            })),
        )
        .await
        .map_err(|e| e.to_string())?;
    let hits = pyops::index(&pyops::index(&page, "hits")?, "hits")?;
    let mut vulns = Vec::new();
    for hit in pyops::iterate(&hits)? {
        match search_item(st, &hit, &hostnames, p.include_epss).await {
            Ok(item) => vulns.push(item.dump),
            Err(e) => tracing::error!("Error processing vulnerability document: {e}"),
        }
    }
    if p.include_epss {
        vulns.sort_by(|a, b| {
            let ka = (
                -epss_float(model::field(a, "epss_score")),
                severity_rank(model::field(a, "severity")),
            );
            let kb = (
                -epss_float(model::field(b, "epss_score")),
                severity_rank(model::field(b, "severity")),
            );
            ka.0.partial_cmp(&kb.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(ka.1.cmp(&kb.1))
                .then_with(|| {
                    model::field(a, "cve_id")
                        .as_str()
                        .cmp(&model::field(b, "cve_id").as_str())
                })
        });
        tracing::info!(
            "Sorted {} vulnerabilities by EPSS score (highest to lowest)",
            vulns.len()
        );
    }
    let mut message = format!(
        "Found {} vulnerabilities on page {} of {total_pages}",
        vulns.len(),
        p.page
    );
    if filters.truthy() {
        message.push_str(&format!(" with filters: {}", filters.py_repr()));
    }
    if p.include_epss {
        message.push_str(" (sorted by EPSS score, highest to lowest)");
    } else {
        message.push_str(" (sorted by detection date and severity)");
    }
    if start + p.page_size > 9000 {
        message.push_str(
            ". Note: Approaching pagination limit (10,000 results). Consider using filters or CSV \
             export for complete data access.",
        );
    }
    build(vulns, true, message)
}

/// The report request (`VulnerabilityReportGenerateRequest`).
#[derive(Debug, Clone, Default)]
pub struct ReportRequest {
    /// `customer_code`.
    pub customer_code: String,
    /// `report_name`.
    pub report_name: Option<String>,
    /// `agent_name`.
    pub agent_name: Option<String>,
    /// `severity`.
    pub severity: Option<String>,
    /// `cve_id`.
    pub cve_id: Option<String>,
    /// `package_name`.
    pub package_name: Option<String>,
    /// `include_epss`.
    pub include_epss: bool,
}

impl ReportRequest {
    /// The filters JSON the report row stores (`json.dumps(filters)`).
    pub fn filters_json(&self) -> String {
        let mut f: Vec<(String, PyValue)> = Vec::new();
        for (k, v) in [
            ("agent_name", &self.agent_name),
            ("severity", &self.severity),
            ("cve_id", &self.cve_id),
            ("package_name", &self.package_name),
        ] {
            if let Some(v) = nonempty(v) {
                f.push((k.into(), s(v)));
            }
        }
        f.push(("include_epss".into(), PyValue::Bool(self.include_epss)));
        py_dumps(&PyValue::Dict(f), Dumps::DEFAULT).unwrap_or_default()
    }

    /// `request.report_name or f"vulnerability_report_{timestamp}"`.
    pub fn name_or_default(&self, prefix: &str) -> String {
        match nonempty(&self.report_name) {
            Some(n) => n.to_string(),
            None => format!("{prefix}_{}", Utc::now().format("%Y%m%d_%H%M%S")),
        }
    }
}

/// `fetch_all_vulnerabilities_for_export(...)`: every matching hit (the
/// scroll API), as `VulnerabilitySearchItem` dumps.
async fn export(
    st: &AgentReportsState,
    scope: &Option<Vec<String>>,
    req: &ReportRequest,
) -> Result<Vec<Item>, String> {
    if !may_see(scope, &req.customer_code) {
        tracing::warn!("User denied access to customer {}", req.customer_code);
        return Ok(Vec::new());
    }
    let es = async_client(&st.wazuh).await.map_err(|e| e.py_str())?;
    let mut scroll_id: Option<Value> = None;
    let out = export_scroll(st, &es, req, &mut scroll_id).await;
    if let Some(id) = scroll_id.filter(pyops::truthy) {
        match indexer::clear_scroll(&es, &id).await {
            Ok(_) => tracing::info!("Cleared scroll context"),
            Err(e) => tracing::warn!("Could not clear scroll context: {e}"),
        }
    }
    out
}

async fn export_scroll(
    st: &AgentReportsState,
    es: &Es,
    req: &ReportRequest,
    scroll_id: &mut Option<Value>,
) -> Result<Vec<Item>, String> {
    let db = &st.ctx.db;
    let hostnames = agents::hostname_customers(db)
        .await
        .map_err(|e| db_text(&e))?;
    let mut terms = vec![On::Customer(&req.customer_code)];
    if let Some(h) = nonempty(&req.agent_name) {
        terms.push(On::Hostname(h));
    }
    let found = agents::select(db, &terms).await.map_err(|e| db_text(&e))?;
    if found.is_empty() {
        tracing::warn!("No agents found for customer {}", req.customer_code);
        return Ok(Vec::new());
    }
    let hosts: Vec<String> = found
        .iter()
        .filter(|a| !a.hostname.is_empty())
        .map(|a| a.hostname.clone())
        .collect();
    let indices = indexer::vulnerability_indices(&st.wazuh)
        .await
        .map_err(|e| e.py_str())?;
    if indices.is_empty() {
        tracing::warn!("No vulnerability indices found");
        return Ok(Vec::new());
    }
    let query = filter_query(
        &hosts,
        nonempty(&req.severity),
        nonempty(&req.cve_id),
        nonempty(&req.package_name),
    );
    let body = json!({
        "query": query,
        "sort": [
            {"vulnerability.detected_at": {"order": "desc"}},
            {"vulnerability.severity": {"order": "asc"}},
            {"_id": {"order": "asc"}},
        ],
    });
    let first = indexer::search_scroll(es, &indices.join(","), &body, "5m", Some(1000))
        .await
        .map_err(|e| e.to_string())?;
    *scroll_id = Some(pyops::index(&first, "_scroll_id")?);
    let mut hits = pyops::index(&pyops::index(&first, "hits")?, "hits")?;
    let mut out = Vec::new();
    for hit in pyops::iterate(&hits)? {
        match search_item(st, &hit, &hostnames, req.include_epss).await {
            Ok(item) => out.push(item),
            Err(e) => tracing::error!("Error processing vulnerability document: {e}"),
        }
    }
    while pyops::len(&hits)? > 0 {
        let next = async {
            let id = scroll_id.clone().unwrap_or(Value::Null);
            let page = indexer::scroll(es, &id, "5m")
                .await
                .map_err(|e| e.to_string())?;
            *scroll_id = Some(pyops::index(&page, "_scroll_id")?);
            pyops::index(&pyops::index(&page, "hits")?, "hits")
        }
        .await;
        match next {
            Ok(h) => hits = h,
            Err(e) => {
                tracing::error!("Error during scroll: {e}");
                break;
            }
        }
        if !pyops::truthy(&hits) {
            break;
        }
        let items = match pyops::iterate(&hits) {
            Ok(items) => items,
            Err(e) => {
                tracing::error!("Error during scroll: {e}");
                break;
            }
        };
        for hit in items {
            match search_item(st, &hit, &hostnames, req.include_epss).await {
                Ok(item) => out.push(item),
                Err(e) => tracing::error!("Error processing vulnerability document: {e}"),
            }
        }
    }
    tracing::info!(
        "Successfully fetched {} total vulnerabilities using scroll API",
        out.len()
    );
    Ok(out)
}

/// The CSV of the report, as `csv.writer` writes it.
fn report_csv(vulns: &[Item], include_epss: bool) -> String {
    let mut header: Vec<String> = [
        "CVE ID",
        "Severity",
        "Title",
        "Agent Name",
        "Customer Code",
        "Package Name",
        "Package Version",
        "Package Architecture",
        "Detected At",
        "Published At",
        "Base Score",
    ]
    .map(String::from)
    .to_vec();
    if include_epss {
        header.extend(["EPSS Score".into(), "EPSS Percentile".into()]);
    }
    header.push("References".into());
    let mut out = String::new();
    csv::row(&mut out, &header);
    let text = |v: &PyValue| match v {
        PyValue::Str(s) => s.clone(),
        PyValue::None => String::new(),
        other => other.py_str(),
    };
    for item in vulns {
        let v = &item.dump;
        let f = |k: &str| model::field(v, k);
        let base = match f("base_score") {
            PyValue::Float(x) if *x != 0.0 => float_repr(*x),
            _ => String::new(),
        };
        let mut row = vec![
            text(f("cve_id")),
            text(f("severity")),
            text(f("title")),
            text(f("agent_name")),
            text(f("customer_code")),
            text(f("package_name")),
            text(f("package_version")),
            text(f("package_architecture")),
            isoformat(&item.detected_at),
            item.published_at
                .as_ref()
                .map(isoformat)
                .unwrap_or_default(),
            base,
        ];
        if include_epss {
            row.push(text(f("epss_score")));
            row.push(text(f("epss_percentile")));
        }
        row.push(text(f("references")));
        csv::row(&mut out, &row);
    }
    out
}

fn severity_counts(vulns: &[Item]) -> [i64; 5] {
    let n = |sev: &str| {
        vulns
            .iter()
            .filter(|v| model::field(&v.dump, "severity").as_str() == Some(sev))
            .count() as i64
    };
    [
        vulns.len() as i64,
        n("Critical"),
        n("High"),
        n("Medium"),
        n("Low"),
    ]
}

/// `generate_vulnerability_csv_report(user, request, report_id)`: the
/// `VulnerabilityReportGenerateResponse` dump.
pub async fn generate(
    st: &AgentReportsState,
    user: &CurrentUser,
    req: &ReportRequest,
    report_id: Option<i64>,
) -> PyValue {
    match generate_inner(st, user, req, report_id).await {
        Ok(dump) => dump,
        Err(text) => {
            tracing::error!("Error generating vulnerability report: {text}");
            if let Some(id) = report_id {
                if let Err(e) = db::mark_failed(&st.ctx.db, id, &text).await {
                    tracing::error!("Failed to update report status: {e}");
                }
            }
            generate_response(
                false,
                "Failed to generate vulnerability report",
                None,
                Some(text),
            )
        }
    }
}

async fn fail_report(st: &AgentReportsState, id: Option<i64>, reason: &str) -> Result<(), String> {
    if let Some(id) = id {
        db::mark_failed(&st.ctx.db, id, reason)
            .await
            .map_err(|e| db_text(&e))?;
    }
    Ok(())
}

async fn generate_inner(
    st: &AgentReportsState,
    user: &CurrentUser,
    req: &ReportRequest,
    report_id: Option<i64>,
) -> Result<PyValue, String> {
    let db = &st.ctx.db;
    let scope = accessible(user.access(&st.ctx).await.map_err(|e| e.to_string())?);
    if !may_see(&scope, &req.customer_code) {
        fail_report(st, report_id, "Insufficient permissions").await?;
        return Ok(generate_response(
            false,
            format!("Access denied to customer {}", req.customer_code),
            None,
            Some("Insufficient permissions".into()),
        ));
    }
    if !db::customer_exists(db, &req.customer_code)
        .await
        .map_err(|e| db_text(&e))?
    {
        fail_report(st, report_id, "Customer not found").await?;
        return Ok(generate_response(
            false,
            format!("Customer {} not found", req.customer_code),
            None,
            Some("Customer not found".into()),
        ));
    }
    let (report_name, file_name, object_key, bucket) = match report_id {
        Some(id) => {
            let Some(r) = db::report(db, id).await.map_err(|e| db_text(&e))? else {
                return Ok(generate_response(
                    false,
                    format!("Report ID {id} not found"),
                    None,
                    Some("Report not found".into()),
                ));
            };
            tracing::info!(
                "Generating vulnerability report for existing record: {} (ID: {id})",
                r.report_name
            );
            (r.report_name, r.file_name, r.object_key, r.bucket_name)
        }
        None => {
            let name = req.name_or_default("vulnerability_report");
            let file = format!("{name}.csv");
            tracing::info!("Generating new vulnerability report: {name}");
            let key = format!("{}/{file}", req.customer_code);
            (name, file, key, REPORTS_BUCKET.to_string())
        }
    };
    let vulns = export(st, &scope, req).await?;
    tracing::info!("Fetched {} vulnerabilities for report", vulns.len());
    if vulns.is_empty() {
        fail_report(st, report_id, "No vulnerabilities found matching criteria").await?;
        return Ok(generate_response(
            false,
            "No vulnerabilities found matching the specified criteria",
            None,
            Some("No data to export".into()),
        ));
    }
    let content = report_csv(&vulns, req.include_epss).into_bytes();
    let stored = copilot_objectstore::ops::store_file_in_minio(
        &st.store,
        &content,
        &bucket,
        &object_key,
        "text/csv",
    )
    .await
    .map_err(|e| e.text())?;
    let stored = match stored {
        Ok(s) => s,
        Err(error) => {
            fail_report(st, report_id, &error).await?;
            return Ok(generate_response(
                false,
                "Failed to store report in MinIO",
                None,
                Some(error),
            ));
        }
    };
    let counts = severity_counts(&vulns);
    let row = match report_id {
        Some(id) => {
            if db::report(db, id).await.map_err(|e| db_text(&e))?.is_none() {
                tracing::error!("Report ID {id} not found for update");
                return Ok(generate_response(
                    false,
                    format!("Report ID {id} not found"),
                    None,
                    Some("Report not found".into()),
                ));
            }
            db::complete(db, id, stored.file_size, &stored.file_hash, counts)
                .await
                .map_err(|e| db_text(&e))?;
            tracing::info!("Successfully updated vulnerability report: {report_name} (ID: {id})");
            id
        }
        None => {
            let new = NewReport {
                report_name: report_name.clone(),
                customer_code: req.customer_code.clone(),
                bucket_name: bucket,
                object_key,
                file_name,
                file_size: stored.file_size,
                file_hash: stored.file_hash,
                generated_at: copilot_core::time::now_utc_micros(),
                generated_by: user.id,
                filters_json: req.filters_json(),
                counts,
                status: "completed".into(),
            };
            let id = db::insert_report(db, &new)
                .await
                .map_err(|e| insert_report_error(&e, &new))?;
            tracing::info!("Successfully generated vulnerability report: {report_name}");
            id
        }
    };
    let saved = db::report(db, row)
        .await
        .map_err(|e| db_text(&e))?
        .ok_or_else(|| "Could not refresh instance".to_string())?;
    let report = report_response(&saved).map_err(|e| e.text())?;
    Ok(generate_response(
        true,
        format!(
            "Successfully generated report with {} vulnerabilities",
            vulns.len()
        ),
        Some(report),
        None,
    ))
}

/// `list_vulnerability_reports(user, customer_codes)`.
pub async fn list(
    st: &AgentReportsState,
    user: &CurrentUser,
    requested: Option<&[String]>,
) -> PyValue {
    let run = async {
        let scope = accessible(user.access(&st.ctx).await.map_err(|e| e.to_string())?);
        let requested = requested.filter(|r| !r.is_empty());
        if let (Some(acc), Some(req)) = (&scope, requested) {
            let denied: Vec<&String> = req.iter().filter(|c| !acc.contains(c)).collect();
            if !denied.is_empty() {
                let names: Vec<&str> = denied.iter().map(|c| c.as_str()).collect();
                return Ok(list_response(
                    Vec::new(),
                    true,
                    format!("Access denied to customer {}", names.join(", ")),
                ));
            }
        }
        let rows = db::reports(&st.ctx.db, scope.as_deref(), requested)
            .await
            .map_err(|e| db_text(&e))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(report_response(r).map_err(|e| e.text())?);
        }
        let n = out.len();
        Ok::<_, String>(list_response(
            out,
            true,
            format!("Found {n} vulnerability reports"),
        ))
    };
    run.await.unwrap_or_else(|e| {
        tracing::error!("Error listing vulnerability reports: {e}");
        list_response(Vec::new(), false, format!("Failed to list reports: {e}"))
    })
}

/// The report row and the caller's scope (download, delete).
pub async fn report_of(st: &AgentReportsState, id: i64) -> Result<Option<ReportRow>, String> {
    db::report(&st.ctx.db, id).await.map_err(|e| db_text(&e))
}

/// The placeholder row of a background report (`status="processing"`); the
/// SQLAlchemy error text of a failed insert.
pub async fn queue(
    st: &AgentReportsState,
    user: &CurrentUser,
    req: &ReportRequest,
    report_name: &str,
) -> Result<i64, String> {
    let generated_at = copilot_core::time::now_utc_micros();
    let new = NewReport {
        report_name: report_name.to_string(),
        customer_code: req.customer_code.clone(),
        bucket_name: REPORTS_BUCKET.into(),
        object_key: format!("{}/{report_name}.csv", req.customer_code),
        file_name: format!("{report_name}.csv"),
        file_size: 0,
        file_hash: "pending".into(),
        generated_at,
        generated_by: user.id,
        filters_json: req.filters_json(),
        counts: [0; 5],
        status: "processing".into(),
    };
    db::insert_report(&st.ctx.db, &new)
        .await
        .map_err(|e| insert_report_error(&e, &new))
}

/// SQLAlchemy's text of a failed `VulnerabilityReport` insert.
fn insert_report_error(e: &sqlx::Error, r: &NewReport) -> String {
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

/// The answer of a queued report.
pub fn queued_response(id: i64, name: &str, customer: &str) -> PyValue {
    dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", s("Report generation queued successfully")),
        ("report_id", int(id)),
        ("report_name", s(name)),
        ("customer_code", s(customer)),
        ("status", s("processing")),
        ("check_status_url", s("/api/v1/vulnerabilities/reports")),
        (
            "download_url",
            s(format!("/api/v1/vulnerabilities/reports/{id}/download")),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_are_json_dumps() {
        let req = ReportRequest {
            customer_code: "C".into(),
            agent_name: Some("h".into()),
            severity: Some(String::new()),
            include_epss: true,
            ..Default::default()
        };
        assert_eq!(
            req.filters_json(),
            r#"{"agent_name": "h", "include_epss": true}"#
        );
    }

    #[test]
    fn epss_sort_values_are_floats() {
        assert_eq!(epss_float(&s(" 0.5 ")), 0.5);
        assert_eq!(epss_float(&s("x")), 0.0);
        assert_eq!(epss_float(&PyValue::None), 0.0);
    }
}
