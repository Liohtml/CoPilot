//! `app/agents/wazuh/services/vulnerabilities.py`: an agent's
//! vulnerabilities from the manager API (before Wazuh 4.8) or the
//! `wazuh-states-vulnerabilities-*` indices (4.8 and later), one by CVE, and
//! the per-customer sync to the Event Shipper.

use reqwest::Method;
use serde_json::{Value, json};

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::model;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_upstream::respond::from_json;
use copilot_wazuh::WazuhState;
use copilot_wazuh::es::{Es, make_path};
use copilot_wazuh::indexer::services::{async_client, client, collect_indices};
use copilot_wazuh::manager::client::{self as manager, Param};
use copilot_wazuh::pyops;

use crate::schema::WAZUH_AGENT_VULNERABILITIES;
use crate::services::{attr, wazuh_err};

/// `VULNERABILITY_STATES_INDEX_PATTERN`.
pub const STATES_PATTERN: &str = "wazuh-states-vulnerabilities-*";
const QUALNAME: &str = "app.agents.wazuh.schema.agents.WazuhAgentVulnerabilities";

/// The validated vulnerabilities (`WazuhAgentVulnerabilities` dumps).
pub type Vulns = Vec<PyValue>;

/// `WazuhAgentVulnerabilitiesResponse(...)`'s dump.
pub fn response(vulns: Option<Vulns>, message: &str) -> PyValue {
    PyValue::Dict(vec![
        (
            "vulnerabilities".into(),
            vulns.map_or(PyValue::None, PyValue::List),
        ),
        ("success".into(), PyValue::Bool(true)),
        ("message".into(), PyValue::Str(message.into())),
    ])
}

/// `collect_agent_vulnerabilities(agent_id, severity)` (the manager API).
pub async fn collect_from_manager(
    st: &WazuhState,
    agent_id: &str,
    severity: &str,
) -> PyResult<Vulns> {
    tracing::info!("Collecting agent {agent_id} vulnerabilities from Wazuh Manager");
    let severities: Vec<&str> = if severity == "All" {
        vec!["Low", "Medium", "High", "Critical"]
    } else {
        vec![severity]
    };
    let mut items: Vec<Value> = Vec::new();
    for sev in severities {
        let params = [("severity".to_string(), Param::Str(sev.to_string()))];
        let response = manager::send_get(st, &format!("/vulnerability/{agent_id}"), Some(&params))
            .await
            .map_err(wazuh_err)?;
        let success = pyops::index(&response, "success").map_err(PyExc::KeyError)?;
        if success == Value::Bool(false) {
            let message = pyops::index(&response, "message").map_err(PyExc::KeyError)?;
            return Err(PyExc::http(500, pyops::py_str(&message)));
        }
        let data = pyops::get(&response, "data", json!({})).map_err(attr)?;
        let data = pyops::get(&data, "data", json!({})).map_err(attr)?;
        let affected = pyops::get(&data, "affected_items", json!([])).map_err(attr)?;
        items.extend(pyops::iterate(&affected).map_err(PyExc::TypeError)?);
    }
    let mut out = Vec::with_capacity(items.len());
    for v in &items {
        let dump = model::construct_star(&WAZUH_AGENT_VULNERABILITIES, QUALNAME, &from_json(v))
            .map_err(|e| {
                PyExc::http(
                    500,
                    format!("Failed to process agent vulnerabilities: {}", e.display()),
                )
            })?;
        out.push(dump);
    }
    Ok(out)
}

/// `x.get(key)` (`None` when absent), `AttributeError` unless `x` is a dict.
fn get(v: &Value, key: &str) -> PyResult<Value> {
    pyops::get(v, key, Value::Null).map_err(attr)
}

/// `process_single_vulnerability(vulnerability)`, accessing the source in
/// Python's order (the first non-dict decides the `AttributeError`).
pub fn process_single(v: &Value) -> PyResult<PyValue> {
    let vuln = || get(v, "vulnerability");
    let package = || get(v, "package");
    let reference = get(&vuln()?, "reference")?;
    let external = match reference {
        Value::Array(_) => reference,
        other => Value::Array(vec![other]),
    };
    let kwargs = model::kwargs(vec![
        ("severity", from_json(&get(&vuln()?, "severity")?)),
        ("version", from_json(&get(&package()?, "version")?)),
        ("type", from_json(&get(&package()?, "type")?)),
        ("name", from_json(&get(&package()?, "name")?)),
        ("external_references", from_json(&external)),
        ("detection_time", from_json(&get(&vuln()?, "detected_at")?)),
        (
            "cvss3_score",
            from_json(&get(&get(&vuln()?, "score")?, "base")?),
        ),
        ("published", from_json(&get(&vuln()?, "published_at")?)),
        (
            "architecture",
            from_json(&get(&package()?, "architecture")?),
        ),
        ("cve", from_json(&get(&vuln()?, "id")?)),
        ("status", from_json(&get(v, "status")?)),
        ("title", from_json(&get(&vuln()?, "description")?)),
    ]);
    model::construct(&WAZUH_AGENT_VULNERABILITIES, &kwargs)
}

/// `page["hits"]["hits"]`.
fn hits(page: &Value) -> PyResult<Vec<Value>> {
    let h = pyops::index(page, "hits").map_err(PyExc::KeyError)?;
    let h = pyops::index(&h, "hits").map_err(PyExc::KeyError)?;
    pyops::iterate(&h).map_err(PyExc::TypeError)
}

fn es_err(e: copilot_wazuh::es::EsError) -> PyExc {
    PyExc::Other("TransportError", e.to_string())
}

/// `collect_vulnerabilities(es, indices, agent_id, severity)` (`agent.id`)
/// and its `agent.name` twin of the sync: one scrolled search per index.
async fn scroll_sources(
    es: &Es,
    indices: &[String],
    field: &str,
    value: &str,
    severity: &str,
) -> PyResult<Vec<Value>> {
    let mut out = Vec::new();
    for index in indices {
        let query = if severity == "All" {
            json!({"query": {"bool": {"must": [
                {"match": {field: value}},
                {"terms": {"vulnerability.severity": ["Low", "Medium", "High", "Critical"]}},
            ]}}})
        } else {
            json!({"query": {"bool": {"must": [
                {"match": {field: value}},
                {"match": {"vulnerability.severity": severity}},
            ]}}})
        };
        let path = make_path(&[index, "_search"]);
        let mut page = es
            .perform(
                Method::POST,
                &path,
                &[("scroll", "2m".into())],
                Some(&query),
            )
            .await
            .map_err(es_err)?;
        let mut sid = pyops::index(&page, "_scroll_id").map_err(PyExc::KeyError)?;
        let mut batch = hits(&page)?;
        while !batch.is_empty() {
            for hit in &batch {
                out.push(pyops::index(hit, "_source").map_err(PyExc::KeyError)?);
            }
            page = es
                .perform(
                    Method::POST,
                    "/_search/scroll",
                    &[("scroll", "2m".into())],
                    Some(&json!({"scroll_id": sid})),
                )
                .await
                .map_err(es_err)?;
            sid = pyops::index(&page, "_scroll_id").map_err(PyExc::KeyError)?;
            batch = hits(&page)?;
        }
    }
    Ok(out)
}

fn index_failure(e: copilot_wazuh::error::PyErr) -> PyExc {
    wazuh_err(e)
}

/// `collect_agent_vulnerabilities_new(agent_id, severity)` (the indexer).
pub async fn collect_from_indexer(
    st: &WazuhState,
    agent_id: &str,
    severity: &str,
) -> PyResult<Vulns> {
    tracing::info!("Collecting agent {agent_id} vulnerabilities from Wazuh Indexer Index");
    let es = client(st).await.map_err(index_failure)?;
    let indices = collect_indices(st, true).await.map_err(index_failure)?;
    let states: Vec<String> = indices
        .into_iter()
        .filter(|i| i.starts_with("wazuh-states-vulnerabilities"))
        .collect();
    let sources = scroll_sources(&es, &states, "agent.id", agent_id, severity).await?;
    sources.iter().map(process_single).collect()
}

/// `collect_agent_vulnerability_by_cve(...)`.
pub async fn collect_by_cve(
    st: &WazuhState,
    agent_id: &str,
    cve: &str,
    package_name: Option<&str>,
    package_version: Option<&str>,
    wazuh_new: bool,
) -> PyResult<PyValue> {
    tracing::info!("Collecting agent {agent_id} vulnerability {cve}");
    let matches: Vulns = if !wazuh_new {
        collect_from_manager(st, agent_id, "All")
            .await?
            .into_iter()
            .filter(|v| model::field(v, "cve").as_str() == Some(cve))
            .collect()
    } else {
        let es = client(st).await.map_err(index_failure)?;
        let mut must = vec![
            json!({"match": {"agent.id": agent_id}}),
            json!({"match": {"vulnerability.id": cve}}),
        ];
        if let Some(p) = package_name.filter(|p| !p.is_empty()) {
            must.push(json!({"match": {"package.name": p}}));
        }
        if let Some(v) = package_version.filter(|v| !v.is_empty()) {
            must.push(json!({"match": {"package.version": v}}));
        }
        let query = json!({"query": {"bool": {"must": must}}});
        let path = make_path(&[STATES_PATTERN, "_search"]);
        let response = es
            .perform(
                Method::POST,
                &path,
                &[
                    ("allow_no_indices", "true".into()),
                    ("ignore_unavailable", "true".into()),
                    ("size", "10".into()),
                ],
                Some(&query),
            )
            .await
            .map_err(es_err)?;
        let mut sources = Vec::new();
        for hit in hits(&response)? {
            sources.push(pyops::index(&hit, "_source").map_err(PyExc::KeyError)?);
        }
        sources
            .iter()
            .map(process_single)
            .collect::<PyResult<_>>()?
    };
    if matches.is_empty() {
        return Err(PyExc::http(
            404,
            format!("Vulnerability {cve} not found for this agent"),
        ));
    }
    let exact = matches.iter().find(|v| {
        package_name.is_none_or(|p| p.is_empty() || model::field(v, "name").as_str() == Some(p))
            && package_version
                .is_none_or(|p| p.is_empty() || model::field(v, "version").as_str() == Some(p))
    });
    let pick = exact.unwrap_or(&matches[0]).clone();
    Ok(response_with(
        vec![pick],
        "Vulnerability collected successfully",
    ))
}

fn response_with(vulns: Vulns, message: &str) -> PyValue {
    response(Some(vulns), message)
}

/// `sync_agent_vulnerabilities(agent_name, customer_code)`: the agent's
/// vulnerabilities not yet in the customer's `wazuh-vulnerabilities-<code>`
/// indices (all of them when there is none), each shipped as a GELF event.
pub async fn sync_agent_vulnerabilities(
    st: &WazuhState,
    connectors: &ConnectorCache,
    agent_name: &str,
    customer_code: &str,
) -> PyResult<()> {
    tracing::info!("Syncing agent {agent_name} with customer code {customer_code} vulnerabilities");
    let es = async_client(st).await.map_err(index_failure)?;
    let indices = collect_indices(st, true).await.map_err(index_failure)?;
    let states: Vec<String> = indices
        .iter()
        .filter(|i| i.starts_with("wazuh-states-vulnerabilities"))
        .cloned()
        .collect();
    let sources = scroll_sources(&es, &states, "agent.name", agent_name, "All").await?;
    let processed: Vulns = sources
        .iter()
        .map(process_single)
        .collect::<PyResult<_>>()?;
    let prefix_lower = format!("wazuh-vulnerabilities-{}", customer_code.to_lowercase());
    let customer_indices = indices.iter().any(|i| i.starts_with(&prefix_lower));
    let ship = |v: &PyValue| {
        let mut items = vec![
            (
                "integration".to_string(),
                PyValue::Str("vulnerabilities".into()),
            ),
            (
                "customer_code".to_string(),
                PyValue::Str(customer_code.into()),
            ),
            ("agent_name".to_string(), PyValue::Str(agent_name.into())),
        ];
        if let PyValue::Dict(fields) = v {
            items.extend(fields.iter().cloned());
        }
        // `EventShipperPayload(...).to_dict()`: `exclude_none=True`.
        PyValue::Dict(
            items
                .into_iter()
                .filter(|(_, v)| !matches!(v, PyValue::None))
                .collect(),
        )
    };
    if !customer_indices {
        tracing::info!("Customer vulnerabilities index does not exist");
        for v in &processed {
            copilot_graylog::gelf::ship(connectors, &ship(v)).await?;
        }
        return Ok(());
    }
    tracing::info!("Customer vulnerabilities index already exists");
    let pattern = format!("wazuh-vulnerabilities-{customer_code}*");
    let checks = processed.iter().map(|v| {
        let es = es.clone();
        let pattern = pattern.clone();
        let cve = model::field(v, "cve").clone();
        async move {
            let query = json!({"query": {"bool": {"must": [
                {"match": {"agent_name": agent_name}},
                {"match": {"cve": crate::services::to_json(&cve)}},
            ]}}});
            let r = es
                .perform(
                    Method::POST,
                    &make_path(&[&pattern, "_search"]),
                    &[],
                    Some(&query),
                )
                .await
                .map_err(es_err)?;
            let total = pyops::index(&r, "hits")
                .and_then(|h| pyops::index(&h, "total"))
                .and_then(|t| pyops::index(&t, "value"))
                .map_err(PyExc::KeyError)?;
            Ok::<bool, PyExc>(total.as_f64().is_some_and(|n| n > 0.0))
        }
    });
    let exists = futures::future::join_all(checks).await;
    for (v, found) in processed.iter().zip(exists) {
        if !found? {
            tracing::info!(
                "Vulnerability {} does not exist in customer index for agent {agent_name}, sending to Graylog",
                model::field(v, "cve").py_str()
            );
            copilot_graylog::gelf::ship(connectors, &ship(v)).await?;
        }
    }
    Ok(())
}
