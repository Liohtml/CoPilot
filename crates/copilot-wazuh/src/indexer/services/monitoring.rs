//! `wazuh_indexer/services/monitoring.py`: cluster health, allocation,
//! indices (per customer too), shards, and the field-limit resize.

use std::sync::OnceLock;

use regex::Regex;
use reqwest::Method;
use serde_json::{Map, Value, json};

use copilot_auth::pyvalue::str_repr;

use crate::WazuhState;
use crate::error::{PyErr, key_error};
use crate::indexer::schema::{CLUSTER_HEALTH, INDICES_STATS, NODE_ALLOCATION, SHARDS};
use crate::indexer::services::{client, customer_matchers, index_matches_customer, py_type};
use crate::pymodel::{self, Model};

/// `Model(**data)`: a `TypeError` unless `data` is a mapping.
fn from_kwargs(model: &Model, data: &Value) -> Result<Value, String> {
    if !data.is_object() {
        return Err(format!(
            "{}() argument after ** must be a mapping, not {}",
            model.name,
            py_type(data)
        ));
    }
    pymodel::validate(model, data).map_err(|e| e.to_string())
}

/// `for x in value` over a `json.loads` value (a dict iterates its keys).
fn iterate(v: &Value) -> Result<Vec<Value>, String> {
    match v {
        Value::Array(a) => Ok(a.clone()),
        Value::Object(o) => Ok(o.keys().map(|k| json!(k)).collect()),
        Value::String(s) => Ok(s.chars().map(|c| json!(c.to_string())).collect()),
        other => Err(format!("'{}' object is not iterable", py_type(other))),
    }
}

/// `row[key]` on one listed row.
fn get(row: &Value, key: &str) -> Result<Value, String> {
    match row {
        Value::Object(m) => m.get(key).cloned().ok_or_else(|| key_error(key).py_str()),
        Value::String(_) => Err("string indices must be integers, not 'str'".into()),
        Value::Array(_) => Err("list indices must be integers or slices, not str".into()),
        other => Err(format!("'{}' object is not subscriptable", py_type(other))),
    }
}

/// `format_*`: pick and rename `(output, input)` keys, in order.
fn reshape(rows: &Value, keys: &[(&str, &str)]) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for row in iterate(rows)? {
        let mut m = Map::new();
        for (to, from) in keys {
            m.insert((*to).into(), get(&row, from)?);
        }
        out.push(Value::Object(m));
    }
    Ok(out)
}

async fn fetch(
    st: &WazuhState,
    path: &str,
    format_json: bool,
) -> Result<Result<Value, String>, PyErr> {
    let es = client(st).await?;
    let params: Vec<(&str, String)> = if format_json {
        vec![("format", "json".into())]
    } else {
        Vec::new()
    };
    Ok(es
        .perform(Method::GET, path, &params, None)
        .await
        .map_err(|e| e.to_string()))
}

/// `cluster_healthcheck()`.
pub async fn cluster_health(st: &WazuhState) -> Result<Value, PyErr> {
    let result = fetch(st, "/_cluster/health", false)
        .await?
        .and_then(|v| from_kwargs(&CLUSTER_HEALTH, &v));
    match result {
        Ok(health) => Ok(json!({
            "cluster_health": health,
            "message": "Successfully collected Wazuh Indexer cluster health",
            "success": true,
        })),
        Err(e) => Err(PyErr::Other(format!(
            "Cluster health check failed with error: {e}"
        ))),
    }
}

/// `output_shard_number_to_be_set_based_on_nodes()`.
pub async fn shard_number(st: &WazuhState) -> Result<Value, PyErr> {
    let result = fetch(st, "/_cluster/health", false)
        .await?
        .and_then(|v| from_kwargs(&CLUSTER_HEALTH, &v));
    match result {
        Ok(health) => Ok(health["number_of_nodes"].clone()),
        Err(e) => Err(PyErr::Other(format!("Shards check failed with error: {e}"))),
    }
}

fn validate_rows(model: &Model, rows: Vec<Value>) -> Result<Vec<Value>, String> {
    rows.iter().map(|r| from_kwargs(model, r)).collect()
}

/// `node_allocation()`.
pub async fn node_allocation(st: &WazuhState) -> Result<Value, PyErr> {
    let result = fetch(st, "/_cat/allocation", true).await?.and_then(|v| {
        let rows = reshape(
            &v,
            &[
                ("disk_used", "disk.used"),
                ("disk_available", "disk.avail"),
                ("disk_total", "disk.total"),
                ("disk_percent", "disk.percent"),
                ("node", "node"),
            ],
        )?;
        validate_rows(&NODE_ALLOCATION, rows)
    });
    match result {
        Ok(rows) => Ok(json!({
            "node_allocation": rows,
            "message": "Successfully collected Wazuh Indexer node allocation",
            "success": true,
        })),
        Err(e) => Err(PyErr::Other(format!(
            "Node allocation check failed with error: {e}"
        ))),
    }
}

/// `format_indices_stats(GET /_cat/indices?format=json)`.
async fn indices_rows(st: &WazuhState) -> Result<Result<Vec<Value>, String>, PyErr> {
    Ok(fetch(st, "/_cat/indices", true).await?.and_then(|v| {
        reshape(
            &v,
            &[
                ("index", "index"),
                ("docs_count", "docs.count"),
                ("store_size", "store.size"),
                ("replica_count", "rep"),
                ("health", "health"),
            ],
        )
    }))
}

/// `filter_index_dicts_by_customers`.
async fn filter_by_customers(
    st: &WazuhState,
    rows: Vec<Value>,
    codes: Option<&[String]>,
) -> Result<Vec<Value>, PyErr> {
    let Some(codes) = codes else {
        return Ok(rows);
    };
    if codes.is_empty() {
        return Ok(Vec::new());
    }
    let matchers = customer_matchers(&st.ctx.db, codes).await?;
    if matchers.is_empty() {
        return Ok(Vec::new());
    }
    Ok(rows
        .into_iter()
        .filter(|r| index_matches_customer(r["index"].as_str().unwrap_or_default(), &matchers))
        .collect())
}

/// `indices_stats(customer_codes)` — the response before `filter_and_limit`.
pub async fn indices_stats(st: &WazuhState, codes: Option<&[String]>) -> Result<Vec<Value>, PyErr> {
    let rows = match indices_rows(st).await? {
        Ok(rows) => rows,
        Err(e) => {
            return Err(PyErr::Other(format!(
                "Indices stats check failed with error: {e}"
            )));
        }
    };
    let rows = filter_by_customers(st, rows, codes).await.map_err(|e| {
        PyErr::Other(format!(
            "Indices stats check failed with error: {}",
            e.py_str()
        ))
    })?;
    validate_rows(&INDICES_STATS, rows)
        .map_err(|e| PyErr::Other(format!("Indices stats check failed with error: {e}")))
}

/// `filter_and_limit(rows, search_params, key=row.index)`.
pub fn filter_and_limit(rows: Vec<Value>, search: Option<&str>, limit: Option<i64>) -> Vec<Value> {
    let mut rows = rows;
    if let Some(needle) = search.filter(|s| !s.is_empty()) {
        let needle = needle.to_lowercase();
        rows.retain(|r| {
            r["index"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase()
                .contains(&needle)
        });
    }
    if let Some(n) = limit {
        rows.truncate(usize::try_from(n).unwrap_or(0));
    }
    rows
}

/// `shards()`.
pub async fn shards(st: &WazuhState) -> Result<Value, PyErr> {
    let result = fetch(st, "/_cat/shards", true).await?.and_then(|v| {
        let rows = reshape(
            &v,
            &[
                ("index", "index"),
                ("shard", "shard"),
                ("state", "state"),
                ("size", "store"),
                ("node", "node"),
            ],
        )?;
        validate_rows(&SHARDS, rows)
    });
    match result {
        Ok(rows) => Ok(json!({
            "shards": rows,
            "message": "Successfully collected Wazuh Indexer shards",
            "success": true,
        })),
        Err(e) => Err(PyErr::Other(format!("Shards check failed with error: {e}"))),
    }
}

/// `resize_wazuh_index_fields()`: `PUT /wazuh*/_settings`; failures are
/// logged and swallowed (the route answers `null` either way).
pub async fn resize_fields(st: &WazuhState) -> Result<(), PyErr> {
    let es = client(st).await?;
    let body = json!({"index.mapping.total_fields.limit": 2000});
    match es
        .perform(Method::PUT, "/wazuh*/_settings", &[], Some(&body))
        .await
    {
        Ok(_) => tracing::info!("Successfully resized the Wazuh index fields"),
        Err(e) => tracing::error!("An error occurred: {e}"),
    }
    Ok(())
}

static DASH: OnceLock<Option<Regex>> = OnceLock::new();
static UNDERSCORE: OnceLock<Option<Regex>> = OnceLock::new();
static SIZE: OnceLock<Option<Regex>> = OnceLock::new();

/// `extract_customer_from_index`.
pub fn extract_customer(index: &str) -> String {
    let dash = crate::regex(&DASH, r"^[^-_]+-([^_]+)_");
    let underscore = crate::regex(&UNDERSCORE, r"^[^_]+_([^_]+)_");
    dash.and_then(|r| r.captures(index))
        .or_else(|| underscore.and_then(|r| r.captures(index)))
        .and_then(|c| c.get(1))
        .map_or_else(|| "unknown".into(), |m| m.as_str().to_string())
}

/// Python's `float(text)` for `[\d.]+`.
fn py_float(text: &str) -> Result<f64, String> {
    text.parse::<f64>()
        .map_err(|_| format!("could not convert string to float: {}", str_repr(text)))
}

/// `int(float)` (`OverflowError` for infinities).
fn py_int(f: f64) -> Result<i128, String> {
    if f.is_infinite() {
        return Err("cannot convert float infinity to integer".into());
    }
    if f.is_nan() {
        return Err("cannot convert float NaN to integer".into());
    }
    Ok(f.trunc() as i128)
}

/// `parse_size_to_bytes`.
pub fn parse_size_to_bytes(size: &Value) -> Result<i128, String> {
    let text = match size {
        Value::Null => return Ok(0),
        Value::String(s) if s.is_empty() || s == "Store size not found" => return Ok(0),
        Value::String(s) => s.to_lowercase().trim().to_string(),
        other => {
            return Err(format!(
                "'{}' object has no attribute 'lower'",
                py_type(other)
            ));
        }
    };
    let pattern = crate::regex(&SIZE, r"^([\d.]+)\s*([a-z]+)$");
    if let Some(c) = pattern.and_then(|p| p.captures(&text)) {
        let value = py_float(c.get(1).map_or("", |m| m.as_str()))?;
        let unit = c.get(2).map_or("", |m| m.as_str());
        let mult: f64 = match unit {
            "b" => 1.0,
            "kb" => 1024.0,
            "mb" => 1024f64.powi(2),
            "gb" => 1024f64.powi(3),
            "tb" => 1024f64.powi(4),
            _ => 1.0,
        };
        return py_int(value * mult);
    }
    match text.replace('_', "").parse::<f64>() {
        Ok(f) if !text.starts_with('_') && !text.ends_with('_') => py_int(f),
        _ => Ok(0),
    }
}

/// `bytes_to_human_readable`.
pub fn human(bytes: i128) -> String {
    let mut size = bytes as f64;
    for unit in ["b", "kb", "mb", "gb", "tb"] {
        if size.abs() < 1024.0 {
            return format!("{size:.2}{unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.2}pb")
}

/// `indices_size_per_customer(customer_codes)` — errors already worded as
/// the route words them.
pub async fn size_per_customer(st: &WazuhState, codes: Option<&[String]>) -> Result<Value, String> {
    let inner = |e: String| format!("Indices size per customer check failed with error: {e}");
    let rows = match indices_rows(st).await {
        Err(e) => return Err(e.py_str()),
        Ok(Err(e)) => return Err(inner(e)),
        Ok(Ok(rows)) => rows,
    };
    let rows = filter_by_customers(st, rows, codes)
        .await
        .map_err(|e| inner(e.py_str()))?;
    let mut per: Vec<(String, i128, i64, Vec<Value>)> = Vec::new();
    for row in &rows {
        let index = row.get("index").cloned().unwrap_or(json!(""));
        let store = row.get("store_size").cloned().unwrap_or(json!("0b"));
        let name = match &index {
            Value::String(s) => s.clone(),
            other => {
                return Err(inner(format!(
                    "expected string or bytes-like object, got '{}'",
                    py_type(other)
                )));
            }
        };
        let customer = extract_customer(&name);
        let bytes = parse_size_to_bytes(&store).map_err(inner)?;
        match per.iter_mut().find(|(c, ..)| *c == customer) {
            Some(entry) => {
                entry.1 += bytes;
                entry.2 += 1;
                entry.3.push(index);
            }
            None => per.push((customer, bytes, 1, vec![index])),
        }
    }
    per.sort_by(|a, b| a.0.cmp(&b.0));
    let sizes: Vec<Value> = per
        .into_iter()
        .map(|(customer, bytes, count, indices)| {
            json!({
                "customer": customer,
                "total_size_bytes": i64::try_from(bytes).unwrap_or(i64::MAX),
                "total_size_human": human(bytes),
                "index_count": count,
                "indices": indices,
            })
        })
        .collect();
    Ok(json!({
        "customer_sizes": sizes,
        "message": "Successfully collected Wazuh Indexer indices size per customer",
        "success": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customer_names_and_sizes() {
        assert_eq!(extract_customer("wazuh-copilot_37"), "copilot");
        assert_eq!(extract_customer("dev-taylor_37"), "taylor");
        assert_eq!(extract_customer("wazuh_509dine2v_0"), "509dine2v");
        assert_eq!(extract_customer(".kibana"), "unknown");
        assert_eq!(parse_size_to_bytes(&json!("1.2gb")), Ok(1_288_490_188));
        assert_eq!(parse_size_to_bytes(&json!("500mb")), Ok(524_288_000));
        assert_eq!(parse_size_to_bytes(&json!("1024")), Ok(1024));
        assert_eq!(parse_size_to_bytes(&json!("abc")), Ok(0));
        assert_eq!(parse_size_to_bytes(&json!(null)), Ok(0));
        assert_eq!(
            parse_size_to_bytes(&json!("1.2.3kb")).unwrap_err(),
            "could not convert string to float: '1.2.3'"
        );
        assert_eq!(human(123), "123.00b");
        assert_eq!(human(1_288_490_188), "1.20gb");
        assert_eq!(human(0), "0.00b");
    }
}
