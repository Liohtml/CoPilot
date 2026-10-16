//! The Wazuh indexer side of `services/vulnerabilities.py`: reading one
//! `wazuh-states-vulnerabilities-*` document (`process_wazuh_document`), the
//! vulnerability indices, the scrolled fetch of the sync and the queries of
//! the search and the CSV export.
//!
//! The documents are read with Python's dict semantics (`.get` on something
//! that is not a dict is the `AttributeError` whose text ends up in the
//! sync's `errors`), the timestamps with CPython 3.11's
//! `datetime.fromisoformat`, and the result validated as
//! `WazuhVulnerabilityData` (its `ValidationError` text likewise).

use reqwest::Method;
use serde_json::{Value, json};

use copilot_auth::pyvalue::{PyValue, float_repr};
use copilot_ingest::py::{IsoDateTime, fromisoformat};
use copilot_upstream::model::{self, Field, Model, Ty};
use copilot_wazuh::WazuhState;
use copilot_wazuh::error::PyErr;
use copilot_wazuh::es::{Es, EsError, make_path};
use copilot_wazuh::indexer::services::{async_client, collect_indices, py_type};
use copilot_wazuh::pymodel::py;
use copilot_wazuh::pyops;
use copilot_web::form::py_strip;

/// The vulnerability state indices' prefix.
pub const STATES_PREFIX: &str = "wazuh-states-vulnerabilities";

fn none() -> PyValue {
    PyValue::None
}

/// `WazuhVulnerabilityData`, built by field name (`populate_by_name`), so
/// errors name the fields; the two datetimes are always `datetime`s there.
static WAZUH_VULNERABILITY_DATA: Model = Model::new(
    "WazuhVulnerabilityData",
    &[
        Field::req("cve_id", Ty::Str),
        Field::req("severity", Ty::Str),
        Field::req("title", Ty::Str),
        Field::def("references", Ty::Nullable(&Ty::Str), none),
        Field::req("detected_at", Ty::Any),
        Field::def("published_at", Ty::Any, none),
        Field::def("base_score", Ty::Nullable(&Ty::Float), none),
        Field::def("package_name", Ty::Nullable(&Ty::Str), none),
        Field::def("package_version", Ty::Nullable(&Ty::Str), none),
        Field::def("package_architecture", Ty::Nullable(&Ty::Str), none),
    ],
);

/// A processed document.
#[derive(Debug, Clone, PartialEq)]
pub struct VulnData {
    /// `vulnerability.id`.
    pub cve_id: String,
    /// `vulnerability.severity`.
    pub severity: String,
    /// The package name (`title`).
    pub title: String,
    /// The first five references.
    pub references: Option<String>,
    /// `vulnerability.detected_at` (`datetime.utcnow()` without one).
    pub detected_at: IsoDateTime,
    /// `vulnerability.published_at`.
    pub published_at: Option<IsoDateTime>,
    /// `vulnerability.score.base`.
    pub base_score: Option<f64>,
    /// `package.name`.
    pub package_name: Option<String>,
    /// `package.version`.
    pub package_version: Option<String>,
    /// `package.architecture`.
    pub package_architecture: Option<String>,
}

fn attr(e: String) -> String {
    e
}

/// `s.replace("Z", "+00:00")` of a value that must be a `str`.
fn replace_z(v: &Value) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.replace('Z', "+00:00")),
        other => Err(format!(
            "'{}' object has no attribute 'replace'",
            py_type(other)
        )),
    }
}

/// `doc.get('_id', 'unknown')` as the error messages print it.
pub fn doc_id(doc: &Value) -> String {
    match doc {
        Value::Object(map) => map
            .get("_id")
            .map_or_else(|| "unknown".to_string(), pyops::py_str),
        _ => "unknown".into(),
    }
}

fn opt_str(v: &PyValue) -> Option<String> {
    match v {
        PyValue::Str(s) => Some(s.clone()),
        _ => None,
    }
}

/// `process_wazuh_document(document)`; `Err` is `str()` of what it raised.
pub fn process_document(doc: &Value) -> Result<VulnData, String> {
    // The `logger.info(... document.get('_id') ...)` before the `try`.
    pyops::get(doc, "_id", Value::Null).map_err(attr)?;
    let source = pyops::get(doc, "_source", json!({})).map_err(attr)?;
    let vuln = pyops::get(&source, "vulnerability", json!({})).map_err(attr)?;
    let package = pyops::get(&source, "package", json!({})).map_err(attr)?;
    let score = pyops::get(&vuln, "score", json!({})).map_err(attr)?;

    let raw = pyops::get(&vuln, "detected_at", Value::Null).map_err(attr)?;
    let detected_at = if pyops::truthy(&raw) {
        fromisoformat(&replace_z(&raw)?)?
    } else {
        crate::pyfmt::naive(copilot_core::time::now_utc_micros())
    };
    let raw = pyops::get(&vuln, "published_at", Value::Null).map_err(attr)?;
    let published_at = if pyops::truthy(&raw) {
        let text = replace_z(&raw)?;
        match fromisoformat(&text) {
            Ok(t) => Some(t),
            Err(_) => {
                tracing::warn!("Could not parse published_at: {}", pyops::py_str(&raw));
                None
            }
        }
    } else {
        None
    };

    let raw = pyops::get(&vuln, "reference", Value::Null).map_err(attr)?;
    let references = if pyops::truthy(&raw) {
        let mut text = match &raw {
            Value::String(s) if s.contains(',') => s
                .split(',')
                .map(py_strip)
                .take(5)
                .collect::<Vec<_>>()
                .join(", "),
            other => pyops::py_str(other),
        };
        if text.chars().count() > 2048 {
            text = text.chars().take(2045).collect::<String>() + "...";
        }
        Some(text)
    } else {
        None
    };

    let cve = pyops::get(&vuln, "id", json!("UNKNOWN_CVE")).map_err(attr)?;
    let severity = pyops::get(&vuln, "severity", json!("UNKNOWN")).map_err(attr)?;
    let title = pyops::get(&package, "name", json!("Unknown Package")).map_err(attr)?;
    let base = pyops::get(&score, "base", Value::Null).map_err(attr)?;
    let name = pyops::get(&package, "name", Value::Null).map_err(attr)?;
    let version = pyops::get(&package, "version", Value::Null).map_err(attr)?;
    let arch = pyops::get(&package, "architecture", Value::Null).map_err(attr)?;
    let kwargs = model::kwargs(vec![
        ("cve_id", py(&cve)),
        ("severity", py(&severity)),
        ("title", py(&title)),
        (
            "references",
            references.clone().map_or(PyValue::None, PyValue::Str),
        ),
        ("detected_at", PyValue::Str(String::new())),
        ("published_at", PyValue::None),
        ("base_score", py(&base)),
        ("package_name", py(&name)),
        ("package_version", py(&version)),
        ("package_architecture", py(&arch)),
    ]);
    let dump = model::construct(&WAZUH_VULNERABILITY_DATA, &kwargs).map_err(|e| e.text())?;
    let f = |k: &str| model::field(&dump, k).clone();
    Ok(VulnData {
        cve_id: opt_str(&f("cve_id")).unwrap_or_default(),
        severity: opt_str(&f("severity")).unwrap_or_default(),
        title: opt_str(&f("title")).unwrap_or_default(),
        references,
        detected_at,
        published_at,
        base_score: match f("base_score") {
            PyValue::Float(x) => Some(x),
            _ => None,
        },
        package_name: opt_str(&f("package_name")),
        package_version: opt_str(&f("package_version")),
        package_architecture: opt_str(&f("package_architecture")),
    })
}

impl VulnData {
    /// `str(base_score)`.
    pub fn base_score_text(&self) -> Option<String> {
        self.base_score.map(float_repr)
    }

    /// `base_score` as Python tests it (`if vuln_data.base_score:`).
    pub fn base_score_truthy(&self) -> bool {
        self.base_score.is_some_and(|b| b != 0.0)
    }
}

/// `get_vulnerabilities_indices()`: the indices named `wazuh-states-
/// vulnerabilities*`, a failure the 500 `Failed to collect vulnerability
/// indices: …`.
pub async fn vulnerability_indices(st: &WazuhState) -> Result<Vec<String>, PyErr> {
    match collect_indices(st, true).await {
        Ok(all) => {
            let found: Vec<String> = all
                .into_iter()
                .filter(|i| i.starts_with(STATES_PREFIX))
                .collect();
            tracing::info!("Found {} vulnerability indices", found.len());
            Ok(found)
        }
        Err(e) => {
            tracing::error!("Error collecting vulnerability indices: {}", e.py_str());
            Err(PyErr::server(format!(
                "Failed to collect vulnerability indices: {}",
                e.py_str()
            )))
        }
    }
}

/// `es.search(index=…, body=…, scroll=…, size=…)` — `POST /{index}/_search`.
pub async fn search_scroll(
    es: &Es,
    index: &str,
    body: &Value,
    scroll: &str,
    size: Option<i64>,
) -> Result<Value, EsError> {
    let mut params = vec![("scroll", scroll.to_string())];
    if let Some(n) = size {
        params.push(("size", n.to_string()));
    }
    es.perform(
        Method::POST,
        &make_path(&[index, "_search"]),
        &params,
        Some(body),
    )
    .await
}

/// `es.scroll(scroll_id=…, scroll=…)` — `POST /_search/scroll`.
pub async fn scroll(es: &Es, scroll_id: &Value, keep: &str) -> Result<Value, EsError> {
    es.perform(
        Method::POST,
        "/_search/scroll",
        &[("scroll", keep.to_string())],
        Some(&json!({ "scroll_id": scroll_id })),
    )
    .await
}

/// `es.clear_scroll(scroll_id=…)` — `DELETE /_search/scroll`.
pub async fn clear_scroll(es: &Es, scroll_id: &Value) -> Result<Value, EsError> {
    es.perform(
        Method::DELETE,
        "/_search/scroll",
        &[],
        Some(&json!({ "scroll_id": [scroll_id] })),
    )
    .await
}

/// `page["hits"]["hits"]` as a list (and the `len()` the loops take).
pub fn page_hits(page: &Value) -> Result<Vec<Value>, String> {
    let hits = pyops::index(page, "hits")?;
    let hits = pyops::index(&hits, "hits")?;
    pyops::len(&hits)?;
    pyops::iterate(&hits)
}

/// `fetch_vulnerabilities_from_indexer(agent_name=…)` as the sync calls it
/// (no severity filter): every index scrolled 1000 at a time, a failure of
/// one index logged and skipped; a failure before the loop is the 500
/// `Failed to fetch vulnerabilities: …`.
pub async fn fetch_for_agent(st: &WazuhState, agent_name: &str) -> Result<Vec<Value>, PyErr> {
    let failed = |e: PyErr| {
        tracing::error!(
            "Error fetching vulnerabilities from Indexer: {}",
            e.py_str()
        );
        PyErr::server(format!("Failed to fetch vulnerabilities: {}", e.py_str()))
    };
    let es = async_client(st).await.map_err(failed)?;
    let indices = vulnerability_indices(st).await.map_err(failed)?;
    if indices.is_empty() {
        tracing::warn!("No vulnerability indices found");
        return Ok(Vec::new());
    }
    let query = if agent_name.is_empty() {
        json!({"query": {"match_all": {}}})
    } else {
        json!({"query": {"bool": {"must": [{"match": {"agent.name": agent_name}}]}}})
    };
    let mut out = Vec::new();
    for index in &indices {
        if let Err(e) = scroll_index(&es, index, &query, &mut out).await {
            tracing::error!("Error querying index {index}: {e}");
        }
    }
    tracing::info!("Fetched {} vulnerabilities from Indexer", out.len());
    Ok(out)
}

/// One index of [`fetch_for_agent`]: the hits it gathered stay in `out`
/// when a later page fails.
async fn scroll_index(
    es: &Es,
    index: &str,
    query: &Value,
    out: &mut Vec<Value>,
) -> Result<(), String> {
    let page = search_scroll(es, index, query, "2m", Some(1000))
        .await
        .map_err(|e| e.to_string())?;
    let mut scroll_id = pyops::index(&page, "_scroll_id")?;
    let mut batch = page_hits(&page)?;
    let mut size = batch.len();
    out.append(&mut batch);
    while size > 0 {
        let page = scroll(es, &scroll_id, "2m")
            .await
            .map_err(|e| e.to_string())?;
        scroll_id = pyops::index(&page, "_scroll_id")?;
        let mut batch = page_hits(&page)?;
        size = batch.len();
        out.append(&mut batch);
    }
    if let Err(e) = clear_scroll(es, &scroll_id).await {
        tracing::warn!("Could not clear scroll context: {e}");
    }
    Ok(())
}

/// The search's and the export's `{"bool": {"must": [...]}}`.
pub fn filter_query(
    hostnames: &[String],
    severity: Option<&str>,
    cve_id: Option<&str>,
    package_name: Option<&str>,
) -> Value {
    let mut must = Vec::new();
    if !hostnames.is_empty() {
        must.push(json!({"terms": {"agent.name": hostnames}}));
    }
    if let Some(s) = severity.filter(|s| !s.is_empty()) {
        must.push(json!({"term": {"vulnerability.severity": s}}));
    }
    if let Some(c) = cve_id.filter(|c| !c.is_empty()) {
        must.push(json!({"term": {"vulnerability.id": c}}));
    }
    if let Some(p) = package_name.filter(|p| !p.is_empty()) {
        must.push(json!({"wildcard": {"package.name": format!("*{p}*")}}));
    }
    json!({"bool": {"must": must}})
}

/// The hit's `_source.agent.name` (default `"unknown"`), and whether it can
/// be a dict key (`customer_agent_map.get(...)` of a list is a `TypeError`).
pub fn hit_agent(hit: &Value) -> Result<Value, String> {
    let source = pyops::index(hit, "_source")?;
    let agent = pyops::get(&source, "agent", json!({}))?;
    let name = pyops::get(&agent, "name", json!("unknown"))?;
    match &name {
        Value::Array(_) | Value::Object(_) => Err(format!("unhashable type: '{}'", py_type(&name))),
        _ => Ok(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_read_as_python_reads_them() {
        let doc = json!({"_id": "d1", "_source": {
            "vulnerability": {"id": "CVE-1", "severity": "High",
                "detected_at": "2026-01-02T03:04:05.123Z", "published_at": "nope",
                "reference": "a, b ,c,d,e,f,g", "score": {"base": 7}},
            "package": {"name": "openssl", "version": "1.1", "architecture": "amd64"}}});
        let v = process_document(&doc).unwrap();
        assert_eq!(v.cve_id, "CVE-1");
        assert_eq!(v.references.as_deref(), Some("a, b, c, d, e"));
        assert_eq!(v.detected_at.offset_us, Some(0));
        assert_eq!(v.published_at, None);
        assert_eq!(v.base_score, Some(7.0));
        assert_eq!(v.base_score_text().as_deref(), Some("7.0"));
        let bad = json!({"_source": {"vulnerability": {"id": null, "detected_at": 5}}});
        assert_eq!(
            process_document(&bad).unwrap_err(),
            "'int' object has no attribute 'replace'"
        );
        let bad = json!({"_source": {"vulnerability": {"id": null}, "package": {"name": "p"}}});
        assert!(
            process_document(&bad)
                .unwrap_err()
                .starts_with("1 validation error for WazuhVulnerabilityData\ncve_id\n")
        );
        let bad = json!({"_source": {"vulnerability": {"score": null}}});
        assert_eq!(
            process_document(&bad).unwrap_err(),
            "'NoneType' object has no attribute 'get'"
        );
        assert_eq!(
            process_document(&json!([1])).unwrap_err(),
            "'list' object has no attribute 'get'"
        );
    }

    #[test]
    fn queries_are_pythons() {
        assert_eq!(
            filter_query(&["h".into()], Some("High"), None, Some("ssl")).to_string(),
            r#"{"bool":{"must":[{"terms":{"agent.name":["h"]}},{"term":{"vulnerability.severity":"High"}},{"wildcard":{"package.name":"*ssl*"}}]}}"#
        );
        assert_eq!(
            filter_query(&[], None, None, None).to_string(),
            r#"{"bool":{"must":[]}}"#
        );
    }
}
