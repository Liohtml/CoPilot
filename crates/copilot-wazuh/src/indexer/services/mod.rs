//! `wazuh_indexer/services/*.py` and the helpers of `utils/universal.py`
//! and `utils/customer_index.py`.

pub mod alerts;
pub mod monitoring;
pub mod scheduled;
pub mod snapshots;

use reqwest::Method;
use serde_json::Value;

use copilot_db::Db;

use crate::WazuhState;
use crate::error::PyErr;
use crate::es::{Es, Flavor};

/// `IndexConfigModel.SKIP_INDEX_NAMES` (prefixes).
const SKIP_INDEX_PREFIXES: &[&str] = &[
    "wazuh-statistics",
    "wazuh-monitoring",
    ".opendistro",
    ".opensearch",
    ".kibana",
    "praeco",
    "filebeat",
    ".tasks",
    ".task",
    "wazuh-states-vulnerabilities",
    ".plugins",
    ".ql",
];

/// `IndexConfigModel().is_valid_index(name)`.
pub fn is_valid_index(name: &str) -> bool {
    !SKIP_INDEX_PREFIXES.iter().any(|p| name.starts_with(p)) && !name.contains("deflector")
}

/// The sync client (`create_wazuh_indexer_client`).
pub async fn client(st: &WazuhState) -> Result<Es, PyErr> {
    Ok(Es::connect(&st.es, &st.ctx.connectors, Flavor::Sync).await?)
}

/// The async client (`create_wazuh_indexer_client_async`).
pub async fn async_client(st: &WazuhState) -> Result<Es, PyErr> {
    Ok(Es::connect(&st.es, &st.ctx.connectors, Flavor::Async).await?)
}

/// `list(d.keys())` of a `json.loads` result (`AttributeError` otherwise).
pub fn keys(v: &Value) -> Result<Vec<String>, String> {
    match v {
        Value::Object(map) => Ok(map.keys().cloned().collect()),
        other => Err(format!(
            "'{}' object has no attribute 'keys'",
            py_type(other)
        )),
    }
}

/// `type(value).__name__`.
pub fn py_type(v: &Value) -> &'static str {
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

/// `collect_indices(all_indices)`: the open indices (`GET /*/_alias`),
/// filtered by [`is_valid_index`] unless `all`.
pub async fn collect_indices(st: &WazuhState, all: bool) -> Result<Vec<String>, PyErr> {
    let es = client(st).await?;
    let result = es
        .perform(
            Method::GET,
            "/*/_alias",
            &[("expand_wildcards", "open".into())],
            None,
        )
        .await
        .map_err(|e| e.to_string())
        .and_then(|v| keys(&v));
    match result {
        Ok(list) => Ok(if all {
            list
        } else {
            list.into_iter().filter(|i| is_valid_index(i)).collect()
        }),
        Err(e) => Err(PyErr::server(format!("Failed to collect indices: {e}"))),
    }
}

/// `build_customer_index_matchers`: each customer's code, and its name as
/// is, with `_` and with `-` for spaces, lower-cased.
pub async fn customer_matchers(db: &Db, codes: &[String]) -> Result<Vec<String>, PyErr> {
    if codes.is_empty() {
        return Ok(Vec::new());
    }
    let marks = vec!["?"; codes.len()].join(", ");
    let sql = format!(
        "SELECT customer_code, customer_name FROM customers WHERE customer_code IN ({marks})"
    );
    let mut q = sqlx::query_as::<_, (String, Option<String>)>(&sql);
    for c in codes {
        q = q.bind(c);
    }
    let rows = q.fetch_all(db.pool()).await?;
    let mut out: Vec<String> = Vec::new();
    let mut add = |s: String| {
        if !out.contains(&s) {
            out.push(s);
        }
    };
    for (code, name) in rows {
        add(code.to_lowercase());
        if let Some(name) = name.filter(|n| !n.is_empty()) {
            let n = name.to_lowercase();
            add(n.replace(' ', "_"));
            add(n.replace(' ', "-"));
            add(n);
        }
    }
    Ok(out)
}

/// `index_matches_customer`.
pub fn index_matches_customer(index: &str, matchers: &[String]) -> bool {
    if index.is_empty() || matchers.is_empty() {
        return false;
    }
    let lower = index.to_lowercase();
    matchers.iter().any(|m| lower.contains(m.as_str()))
}
