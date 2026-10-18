//! The upstream-facing services of `services/copilot_searches.py`,
//! `publish.py` and `custom_repos.test_repo_fetch`, and the Wazuh logtest
//! wrapper (`wazuh_manager/services/logtest.py`).

use copilot_auth::AccessScope;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use copilot_auth::pyvalue::PyValue;
use copilot_graylog::client::DEFAULT_CONNECTOR;
use copilot_threat_intel::httpx::{self, Request};
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_wazuh::es::{Es, Flavor, make_path};
use copilot_wazuh::manager::client::{Body, PutKind, send_put};
use copilot_yaml::{LoadError, Value};
use http::Method;
use num_bigint_dig::BigInt;

use crate::caches::{self, Kind};
use crate::py::{self, get, s};
use crate::pyd;
use crate::rules;
use crate::schema;
use crate::{SearchesState, custom_repos, linter};

// --- parameters ---------------------------------------------------------------------------

/// `merged_params`: the rule's parameter names (any key) and their values.
pub type Params = Vec<(Value, Value)>;

fn param_lookup<'a>(params: &'a Params, name: &str) -> Option<&'a Value> {
    params
        .iter()
        .find(|(k, _)| k.as_str() == Some(name))
        .map(|(_, v)| v)
}

/// The first `${name}` from `from` (`\$\{([^}]+)\}`): start, end, name.
fn next_placeholder(chars: &[char], from: usize) -> Option<(usize, usize, String)> {
    let mut i = from;
    while i + 2 < chars.len() {
        if chars[i] == '$' && chars[i + 1] == '{' {
            if let Some(off) = chars[i + 2..].iter().position(|c| *c == '}') {
                if off > 0 {
                    let end = i + 2 + off;
                    return Some((i, end + 1, chars[i + 2..end].iter().collect()));
                }
            }
        }
        i += 1;
    }
    None
}

/// `_substitute_parameters(obj, parameters)`.
pub fn substitute(obj: &Value, params: &Params) -> Value {
    match obj {
        Value::Str(t) => {
            let chars: Vec<char> = t.chars().collect();
            if let Some((0, end, name)) = next_placeholder(&chars, 0) {
                if end == chars.len() {
                    if let Some(v) = param_lookup(params, &name) {
                        return v.clone();
                    }
                }
            }
            let mut out = String::new();
            let mut pos = 0;
            while let Some((start, end, name)) = next_placeholder(&chars, pos) {
                out.extend(&chars[pos..start]);
                match param_lookup(params, &name) {
                    Some(v) => out.push_str(&v.py_str()),
                    None => out.extend(&chars[start..end]),
                }
                pos = end;
            }
            out.extend(&chars[pos..]);
            Value::Str(out)
        }
        Value::Dict(items) => Value::Dict(Arc::new(
            items
                .iter()
                .map(|(k, v)| (k.clone(), substitute(v, params)))
                .collect(),
        )),
        Value::List(items) => py::list(items.iter().map(|v| substitute(v, params)).collect()),
        other => other.clone(),
    }
}

/// `_validate_parameters(rule, provided)`: the merged parameters, or the
/// `ValueError` text of the missing ones.
pub fn validate_parameters(rule: &Value, provided: &[(String, Value)]) -> PyResult<Params> {
    let mut merged: Params = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for (name, def) in py::items(&get(rule, "parameters", py::dict(vec![]))?)? {
        let required = get(&def, "required", Value::Bool(false))?;
        let default = get(&def, "default", Value::None)?;
        let given = name
            .as_str()
            .and_then(|n| provided.iter().rev().find(|(k, _)| k == n))
            .map(|(_, v)| v.clone());
        let value = match given {
            Some(v) => Some(v),
            None if !matches!(default, Value::None) => Some(default),
            None => {
                if required.truthy() {
                    let description = get(&def, "description", s(""))?;
                    let input = py::dict(vec![
                        ("parameter", name.clone()),
                        (
                            "message",
                            s(format!(
                                "Required parameter '{}' is missing. {}",
                                name.py_str(),
                                description.py_str()
                            )),
                        ),
                    ]);
                    let built = pyd::build(&SEARCH_VALIDATION_ERROR, &input)?;
                    errors.push(format!(
                        "{}: {}",
                        built
                            .get("parameter")
                            .map(Value::py_str)
                            .unwrap_or_default(),
                        built.get("message").map(Value::py_str).unwrap_or_default()
                    ));
                }
                None
            }
        };
        if let Some(v) = value {
            let key = py::hash_key(&name)?;
            match merged
                .iter_mut()
                .find(|(k, _)| py::hash_key(k).ok().as_deref() == Some(key.as_str()))
            {
                Some(slot) => slot.1 = v,
                None => merged.push((name, v)),
            }
        }
    }
    if !errors.is_empty() {
        return Err(PyExc::ValueError(format!(
            "Parameter validation failed: {}",
            errors.join("; ")
        )));
    }
    Ok(merged)
}

/// `SearchValidationError`.
pub static SEARCH_VALIDATION_ERROR: pyd::Model = pyd::Model {
    title: "SearchValidationError",
    fields: &[
        pyd::Field::req("parameter", pyd::Ty::Str),
        pyd::Field::req("message", pyd::Ty::Str),
    ],
    after: None,
};

// --- /execute -----------------------------------------------------------------------------

/// `json.dumps` as elasticsearch-py's `JSONSerializer` writes a body
/// (`ensure_ascii=False`, compact, `date`/`datetime` as `isoformat()`).
pub fn es_dumps(v: &Value) -> Result<String, String> {
    fn key(k: &Value) -> Result<String, String> {
        Ok(match k {
            Value::Str(t) => t.clone(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => float_json(*f),
            Value::Bool(true) => "true".into(),
            Value::Bool(false) => "false".into(),
            Value::None => "null".into(),
            other => {
                return Err(format!(
                    "TypeError('keys must be str, int, float, bool or None, not {}')",
                    other.type_name()
                ));
            }
        })
    }
    fn float_json(f: f64) -> String {
        if f.is_nan() {
            "NaN".into()
        } else if f.is_infinite() {
            if f > 0.0 {
                "Infinity".into()
            } else {
                "-Infinity".into()
            }
        } else {
            copilot_yaml::float_repr(f)
        }
    }
    fn string(t: &str, out: &mut String) {
        out.push_str(&serde_json::to_string(t).unwrap_or_default());
    }
    fn walk(v: &Value, out: &mut String) -> Result<(), String> {
        match v {
            Value::None => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Int(i) => out.push_str(&i.to_string()),
            Value::Float(f) => out.push_str(&float_json(*f)),
            Value::Str(t) => string(t, out),
            Value::Date(d) => string(&d.isoformat(), out),
            Value::DateTime(d) => string(&d.isoformat(), out),
            Value::List(items) | Value::Tuple(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    walk(item, out)?;
                }
                out.push(']');
            }
            Value::Dict(items) => {
                out.push('{');
                for (i, (k, val)) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    string(&key(k)?, out);
                    out.push(':');
                    walk(val, out)?;
                }
                out.push('}');
            }
            other => {
                return Err(format!(
                    "TypeError(\"Unable to serialize {} (type: <class '{}'>)\")",
                    other.py_repr(),
                    other.type_name()
                ));
            }
        }
        Ok(())
    }
    let mut out = String::new();
    walk(v, &mut out).map_err(|e| format!("({}, {e})", v.py_repr()))?;
    Ok(out)
}

/// The `/execute` request.
#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    /// `rule_id`.
    pub rule_id: String,
    /// `index_pattern`.
    pub index_pattern: String,
    /// `parameters`.
    pub parameters: Vec<(String, Value)>,
    /// `size`.
    pub size: Option<i64>,
}

/// `execute_rule_search(request)`.
pub async fn execute_rule_search(
    st: &SearchesState,
    scope: &AccessScope,
    req: &ExecuteRequest,
) -> PyResult<Value> {
    caches::ensure_loaded(st, Kind::Rules).await?;
    let set = crate::caches::visible_rules(st, scope);
    let Some(rule) = set.by_id(&req.rule_id) else {
        return Err(PyExc::ValueError(format!(
            "Rule with ID '{}' not found",
            req.rule_id
        )));
    };
    let search_body = search_body(rule, req)?;
    tracing::info!(
        "Executing search for rule '{}' on index '{}'",
        req.rule_id,
        req.index_pattern
    );
    let es = Es::connect(&st.wazuh.es, &st.ctx.connectors, Flavor::Async)
        .await
        .map_err(|e| match e {
            copilot_wazuh::es::ConnectError::Http(d) => PyExc::http(500, d),
            copilot_wazuh::es::ConnectError::Db(d) => PyExc::Other("OperationalError", d),
        })?;
    let outcome: PyResult<Value> = async {
        let payload = es_dumps(&search_body).map_err(|e| PyExc::Other("SerializationError", e))?;
        let response = es
            .perform_raw(
                Method::POST,
                &make_path(&[req.index_pattern.as_str(), "_search"]),
                &[],
                Some(payload.into_bytes()),
            )
            .await
            .map_err(|e| PyExc::Other("TransportError", e.to_string()))?;
        search_response(rule, req, &search_body, &py::from_json(&response))
    }
    .await;
    outcome.map_err(|e| {
        tracing::error!("Search execution failed: {}", e.display());
        PyExc::ValueError(format!("Search execution failed: {}", e.display()))
    })
}

/// The search body `execute_rule_search` builds (its parameter check
/// included).
pub fn search_body(rule: &Value, req: &ExecuteRequest) -> PyResult<Value> {
    let mut all_params = req.parameters.clone();
    all_params.retain(|(k, _)| k != "INDEX_PATTERN");
    all_params.push(("INDEX_PATTERN".into(), s(req.index_pattern.clone())));
    let merged = validate_parameters(rule, &all_params)?;
    let search_def = get(rule, "search", py::dict(vec![]))?;
    if !search_def.truthy() {
        return Err(PyExc::ValueError(format!(
            "Rule '{}' does not contain a search definition",
            req.rule_id
        )));
    }
    let query = get(&search_def, "query", py::dict(vec![]))?;
    let mut body: Vec<(Value, Value)> = vec![(s("query"), substitute(&query, &merged))];
    let size = match req.size {
        Some(n) => py::int(n),
        None if py::contains_key(&search_def, "size")? => py::getitem(&search_def, "size")?,
        None => py::int(100),
    };
    body.push((s("size"), size));
    if py::contains_key(&search_def, "sort")? {
        body.push((
            s("sort"),
            substitute(&py::getitem(&search_def, "sort")?, &merged),
        ));
    }
    if py::contains_key(&search_def, "_source")? {
        body.push((s("_source"), py::getitem(&search_def, "_source")?));
    }
    Ok(Value::Dict(Arc::new(body)))
}

/// `ExecuteSearchResponse` from the indexer's answer.
pub fn search_response(
    rule: &Value,
    req: &ExecuteRequest,
    search_body: &Value,
    response: &Value,
) -> PyResult<Value> {
    let hits_data = get(response, "hits", py::dict(vec![]))?;
    let total_hits = get(&hits_data, "total", py::dict(vec![]))?;
    let total_count = if total_hits.is_dict() {
        get(&total_hits, "value", py::int(0))?
    } else {
        total_hits
    };
    let mut hits = Vec::new();
    for hit in py::iterate(&get(&hits_data, "hits", py::list(vec![]))?)? {
        let input = py::dict(vec![
            ("index", get(&hit, "_index", s(""))?),
            ("id", get(&hit, "_id", s(""))?),
            ("score", get(&hit, "_score", Value::None)?),
            ("source", get(&hit, "_source", py::dict(vec![]))?),
        ]);
        hits.push(pyd::build(&schema::SEARCH_HIT, &input)?);
    }
    let n = hits.len() as i64;
    let out = py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s("Search executed successfully")),
        ("rule_id", s(req.rule_id.clone())),
        ("rule_name", get(rule, "name", s(""))?),
        ("total_hits", total_count),
        ("returned_hits", py::int(n)),
        ("took_ms", get(response, "took", py::int(0))?),
        ("hits", py::list(hits)),
        ("query_executed", search_body.clone()),
    ]);
    pyd::build(&schema::EXECUTE_SEARCH_RESPONSE, &out)
}

// --- /graylog -----------------------------------------------------------------------------

/// `generate_graylog_query(request)`.
pub async fn generate_graylog_query(
    st: &SearchesState,
    scope: &AccessScope,
    rule_id: &str,
    parameters: &[(String, Value)],
) -> PyResult<Value> {
    caches::ensure_loaded(st, Kind::Rules).await?;
    let set = crate::caches::visible_rules(st, scope);
    let Some(rule) = set.by_id(rule_id) else {
        return Err(PyExc::ValueError(format!(
            "Rule with ID '{rule_id}' not found"
        )));
    };
    graylog_query(rule, rule_id, parameters)
}

/// `generate_graylog_query`'s answer for a cached rule.
pub fn graylog_query(
    rule: &Value,
    rule_id: &str,
    parameters: &[(String, Value)],
) -> PyResult<Value> {
    let graylog = get(rule, "graylog", Value::None)?;
    if !graylog.truthy() || !graylog.is_dict() {
        return Err(PyExc::ValueError(format!(
            "Rule '{rule_id}' does not contain a Graylog query"
        )));
    }
    let original = get(&graylog, "query", s(""))?;
    if !original.truthy() {
        return Err(PyExc::ValueError(format!(
            "Rule '{rule_id}' has an empty Graylog query"
        )));
    }
    let merged = validate_parameters(rule, parameters)?;
    let substituted = substitute(&original, &merged);
    tracing::info!("Generated Graylog query for rule '{rule_id}'");
    pyd::build(
        &schema::GRAYLOG_QUERY_RESPONSE,
        &py::dict(vec![
            ("success", Value::Bool(true)),
            ("message", s("Graylog query generated successfully")),
            ("rule_id", s(rule_id)),
            ("rule_name", get(rule, "name", s(""))?),
            ("graylog_query", substituted),
            ("original_query", original),
        ]),
    )
}

// --- Graylog event definitions ------------------------------------------------------------

/// The provisioning request (`ProvisionGraylogAlertRequest`).
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    /// `rule_id`.
    pub rule_id: String,
    /// `search_within_seconds`.
    pub search_within_seconds: i64,
    /// `execute_every_seconds`.
    pub execute_every_seconds: i64,
    /// `streams`.
    pub streams: Vec<String>,
    /// `custom_title`.
    pub custom_title: Option<String>,
    /// `priority`.
    pub priority: i64,
    /// `event_limit`.
    pub event_limit: i64,
}

/// `get_all_event_definitions()`: the titles, or the exception's `str()`.
pub async fn event_definition_titles(st: &SearchesState) -> PyResult<Vec<String>> {
    let dump = copilot_graylog::services::event_definitions(&st.graylog).await?;
    let defs = copilot_upstream::py::get(&dump, "event_definitions")?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    Ok(copilot_upstream::py::iterate(&defs)?
        .iter()
        .filter_map(|d| d.get("title").map(PyValue::py_str))
        .collect())
}

/// `value[0]`.
fn index0(v: &Value) -> PyResult<Value> {
    match v {
        Value::List(items) | Value::Tuple(items) => items
            .first()
            .cloned()
            .ok_or_else(|| PyExc::IndexError("list index out of range".into())),
        Value::Str(t) => t
            .chars()
            .next()
            .map(|c| s(c.to_string()))
            .ok_or_else(|| PyExc::IndexError("string index out of range".into())),
        Value::Dict(items) => items
            .iter()
            .find(|(k, _)| k.py_eq(&py::int(0)))
            .map(|(_, v)| v.clone())
            .ok_or_else(|| PyExc::KeyError("0".into())),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            py::tp_name(other)
        ))),
    }
}

/// `_get_alert_source_from_rule(rule)`.
fn alert_source(rule: &Value) -> PyResult<String> {
    let sources = get(rule, "data_source", py::list(vec![]))?;
    if sources.truthy() {
        let first = index0(&sources)?;
        return Ok(py::upper(&first)?.replace([' ', '-'], "_"));
    }
    Ok(match rule.get("_platform").and_then(Value::as_str) {
        Some("linux") => "LINUX".into(),
        Some("windows") => "WINDOWS".into(),
        _ => "COPILOT_SEARCH".into(),
    })
}

/// `_parse_duration_to_ms(value)` for the `str` an `AggregationConfig` holds.
fn duration_ms(value: &str) -> PyResult<BigInt> {
    let text = copilot_jinja::unicode::lower(py::py_strip(value));
    if text.is_empty() {
        return Err(PyExc::ValueError("Duration must not be empty".into()));
    }
    let invalid = || {
        PyExc::ValueError(format!(
            "Invalid duration: {}",
            copilot_yaml::str_repr(value)
        ))
    };
    let last = text.chars().last().unwrap_or(' ');
    let unit = match last {
        's' => Some(1.0),
        'm' => Some(60.0),
        'h' => Some(3600.0),
        'd' => Some(86400.0),
        _ => None,
    };
    let seconds = match unit {
        Some(u) => {
            let head: String = text.chars().take(text.chars().count() - 1).collect();
            copilot_yaml::pyint::parse_float(&head).map_err(|_| invalid())? * u
        }
        None => copilot_yaml::pyint::parse_float(&text).map_err(|_| invalid())?,
    };
    if seconds <= 0.0 {
        return Err(PyExc::ValueError(format!(
            "Duration must be positive: {}",
            copilot_yaml::str_repr(value)
        )));
    }
    py::py_int(&Value::Float(seconds * 1000.0))
}

fn p_str(t: &str) -> PyValue {
    PyValue::Str(t.to_string())
}

fn p_dict(items: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn provider(template: &str) -> PyValue {
    p_dict(vec![
        ("data_type", p_str("string")),
        (
            "providers",
            PyValue::List(vec![p_dict(vec![
                ("template", p_str(template)),
                ("type", p_str("template-v1")),
                ("require_values", PyValue::Bool(true)),
            ])]),
        ),
    ])
}

/// `provision_graylog_alert_from_rule(request)`: the response dump.
pub async fn provision_from_rule(
    st: &SearchesState,
    scope: &AccessScope,
    req: &ProvisionRequest,
) -> PyResult<Value> {
    caches::ensure_loaded(st, Kind::Rules).await?;
    let set = crate::caches::visible_rules(st, scope);
    let Some(rule) = set.by_id(&req.rule_id) else {
        return Err(PyExc::ValueError(format!(
            "Rule with ID '{}' not found",
            req.rule_id
        )));
    };
    let graylog = get(rule, "graylog", Value::None)?;
    if !graylog.truthy() || !graylog.is_dict() {
        return Err(PyExc::ValueError(format!(
            "Rule '{}' does not contain a Graylog query",
            req.rule_id
        )));
    }
    let graylog_query = get(&graylog, "query", s(""))?;
    if !graylog_query.truthy() {
        return Err(PyExc::ValueError(format!(
            "Rule '{}' has an empty Graylog query",
            req.rule_id
        )));
    }
    let rule_name = get(rule, "name", s(req.rule_id.clone()))?;
    let description = get(rule, "description", s(""))?;
    let severity = get(
        &get(rule, "response", py::dict(vec![]))?,
        "severity",
        s("medium"),
    )?;
    let source = alert_source(rule)?;
    let title = match req.custom_title.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => t.to_string(),
        None => py::upper(&rule_name)?.replace(' ', " - "),
    };
    let priority = if req.priority != 2 {
        req.priority
    } else {
        match py::lower(&severity)?.as_str() {
            "low" => 1,
            "medium" => 2,
            "high" | "critical" => 3,
            _ => 2,
        }
    };
    tracing::info!(
        "Provisioning Graylog alert for rule '{}' with title '{title}'",
        req.rule_id
    );
    let aggregation = match get(rule, "aggregation", Value::None)? {
        raw @ Value::Dict(_) => {
            rules::kwargs_check(&raw)?;
            match schema::aggregation(&raw) {
                Ok(dump) if dump.get("enabled").is_some_and(Value::truthy) => Some(dump),
                Ok(_) => None,
                Err(invalid) => {
                    return Err(PyExc::ValueError(format!(
                        "Invalid aggregation block: {}",
                        invalid.text()
                    )));
                }
            }
        }
        _ => None,
    };
    let (series, group_by, conditions, within_ms, every_ms) = match &aggregation {
        Some(a) => {
            let series_id = "copilot-agg-0";
            let function = a.get("function").and_then(Value::as_str).unwrap_or("count");
            let field = a.get("field").cloned().unwrap_or(Value::None);
            let series = if function == "distinct_count" {
                PyValue::List(vec![p_dict(vec![
                    ("id", p_str(series_id)),
                    ("type", p_str("card")),
                    ("field", py::to_py(&field).unwrap_or(PyValue::None)),
                ])])
            } else {
                PyValue::List(vec![p_dict(vec![
                    ("id", p_str(series_id)),
                    ("type", p_str("count")),
                    ("field", PyValue::None),
                ])])
            };
            let condition = a.get("condition").map(Value::py_str).unwrap_or_default();
            let threshold = a.get("threshold").map(Value::py_str).unwrap_or_default();
            let conditions = p_dict(vec![(
                "expression",
                p_dict(vec![
                    ("expr", p_str(&condition)),
                    (
                        "left",
                        p_dict(vec![
                            ("expr", p_str("number-ref")),
                            ("ref", p_str(series_id)),
                        ]),
                    ),
                    (
                        "right",
                        p_dict(vec![
                            ("expr", p_str("number")),
                            ("value", PyValue::Int(threshold)),
                        ]),
                    ),
                ]),
            )]);
            let group_by = a
                .get("group_by")
                .and_then(py::to_py)
                .unwrap_or(PyValue::List(Vec::new()));
            let window = a.get("window").map(Value::py_str).unwrap_or_default();
            let within = duration_ms(&window)?;
            let every = match a.get("execute_every").and_then(Value::as_str) {
                Some(e) if !e.is_empty() => duration_ms(e)?,
                _ => BigInt::from(req.execute_every_seconds) * 1000,
            };
            tracing::info!(
                "Rule '{}' provisioned as AGGREGATION event definition",
                req.rule_id
            );
            (series, group_by, conditions, within, every)
        }
        None => (
            PyValue::List(Vec::new()),
            PyValue::List(Vec::new()),
            p_dict(vec![("expression", PyValue::None)]),
            BigInt::from(req.search_within_seconds) * 1000,
            BigInt::from(req.execute_every_seconds) * 1000,
        ),
    };
    // `GraylogAlertProvisionConfig(...)` is built (and validated) first,
    // then the field spec, then the outer model: only the rule's `query` and
    // `description` can fail.
    let config_input = py::dict(vec![
        ("query", graylog_query.clone()),
        ("query_parameters", py::list(vec![])),
        ("streams", py::str_list(req.streams.clone())),
        ("search_within_ms", Value::Int(within_ms.clone())),
        ("execute_every_ms", Value::Int(every_ms.clone())),
        ("group_by", py::from_py(&group_by)),
        ("series", py::from_py(&series)),
        ("conditions", py::from_py(&conditions)),
        ("type", s("aggregation-v1")),
        ("event_limit", py::int(req.event_limit)),
    ]);
    pyd::build(&schema::GRAYLOG_ALERT_PROVISION_CONFIG, &config_input)?;
    pyd::build(
        &schema::GRAYLOG_ALERT_PROVISION_MODEL,
        &py::dict(vec![
            ("title", s(title.clone())),
            ("description", description.clone()),
            ("priority", py::int(priority)),
            ("config", py::dict(vec![])),
            ("field_spec", py::dict(vec![])),
            ("key_spec", py::list(vec![])),
            ("notification_settings", py::dict(vec![])),
            ("alert", Value::Bool(true)),
        ]),
    )?;
    let config = vec![
        (
            "query".to_string(),
            py::to_py(&graylog_query).unwrap_or(PyValue::None),
        ),
        ("query_parameters".to_string(), PyValue::List(Vec::new())),
        (
            "streams".to_string(),
            PyValue::List(req.streams.iter().map(|t| p_str(t)).collect()),
        ),
        (
            "search_within_ms".to_string(),
            PyValue::Int(within_ms.to_string()),
        ),
        (
            "execute_every_ms".to_string(),
            PyValue::Int(every_ms.to_string()),
        ),
        ("group_by".to_string(), group_by),
        ("series".to_string(), series),
        ("conditions".to_string(), conditions),
        ("type".to_string(), p_str("aggregation-v1")),
        (
            "event_limit".to_string(),
            PyValue::Int(req.event_limit.to_string()),
        ),
    ];
    let entity = p_dict(vec![
        ("title", p_str(&title)),
        (
            "description",
            py::to_py(&description).unwrap_or(PyValue::None),
        ),
        ("priority", PyValue::Int(priority.to_string())),
        ("config", PyValue::Dict(config)),
        (
            "field_spec",
            p_dict(vec![
                ("ALERT_ID", provider("${source._id}")),
                ("CUSTOMER_CODE", provider("${source.agent_labels_customer}")),
                ("ALERT_SOURCE", provider(&source)),
                ("COPILOT_ALERT_ID", provider("NONE")),
                ("RULE_ID", provider(&req.rule_id)),
            ]),
        ),
        ("key_spec", PyValue::List(Vec::new())),
        (
            "notification_settings",
            p_dict(vec![
                ("grace_period_ms", PyValue::Int("0".into())),
                ("backlog_size", PyValue::None),
            ]),
        ),
        ("notifications", PyValue::List(Vec::new())),
        ("alert", PyValue::Bool(true)),
    ]);
    // `provision_alert_definition(alert_model)`, the monitoring alerts' own:
    // `event_limit` dropped below Graylog 5.2, then the one `create_entity`.
    copilot_monitoring_alerts::services::provision_alert_definition(
        &st.graylog,
        DEFAULT_CONNECTOR,
        entity,
    )
    .await?;
    tracing::info!(
        "Successfully provisioned Graylog alert '{title}' for rule '{}'",
        req.rule_id
    );
    pyd::build(
        &schema::PROVISION_GRAYLOG_ALERT_RESPONSE,
        &py::dict(vec![
            ("success", Value::Bool(true)),
            (
                "message",
                s(format!("Graylog alert '{title}' provisioned successfully")),
            ),
            ("rule_id", s(req.rule_id.clone())),
            ("rule_name", rule_name),
            ("alert_title", s(title)),
            ("graylog_query", graylog_query),
        ]),
    )
}

// --- logtest ------------------------------------------------------------------------------

/// `run_logtest(event, log_format, location)`: `(matched, rule, alert)`, or
/// the exception's `str()`.
pub async fn run_logtest(
    st: &SearchesState,
    event: &str,
    log_format: &str,
    location: &str,
) -> Result<(bool, Value, Value), String> {
    if py::py_strip(event).is_empty() {
        return Err("400: event must be a non-empty log line".into());
    }
    let payload = p_dict(vec![
        ("event", p_str(event)),
        ("log_format", p_str(log_format)),
        ("location", p_str(location)),
    ]);
    let body = py_dumps(&payload, Dumps::DEFAULT).unwrap_or_default();
    let response = send_put(
        &st.wazuh,
        "/logtest",
        Some(Body::Text(body)),
        None,
        PutKind::Json,
    )
    .await
    .map_err(|e| e.py_str())?;
    let response = py::from_json(&response);
    let success = match &response {
        Value::None => false,
        r => get(r, "success", Value::None)
            .map_err(|e| e.text())?
            .truthy(),
    };
    if !response.truthy() || !success {
        let detail = if response.truthy() {
            get(&response, "message", s("Wazuh Manager logtest failed"))
                .map_err(|e| e.text())?
                .py_str()
        } else {
            "Wazuh Manager not reachable".into()
        };
        return Err(format!("503: {detail}"));
    }
    let parse = || -> PyResult<(bool, Value, Value)> {
        let raw = match get(&response, "data", Value::None)? {
            v if v.truthy() => v,
            _ => py::dict(vec![]),
        };
        let inner = match get(&raw, "data", Value::None)? {
            v if v.truthy() => v,
            _ => py::dict(vec![]),
        };
        let output = match get(&inner, "output", Value::None)? {
            v if v.truthy() => v,
            _ => py::dict(vec![]),
        };
        let rule = extract_rule_summary(&output)?;
        let matched = !matches!(rule, Value::None);
        let alert = if output.truthy() {
            output.clone()
        } else {
            Value::None
        };
        Ok((matched, rule, alert))
    };
    parse().map_err(|e| e.text())
}

/// `_extract_rule_summary(output)`.
fn extract_rule_summary(output: &Value) -> PyResult<Value> {
    let rule = get(output, "rule", Value::None)?;
    if !rule.is_dict() {
        return Ok(Value::None);
    }
    let rid = get(&rule, "id", Value::None)?;
    let rid_int = match &rid {
        Value::None => None,
        v => match py::py_int(v) {
            Ok(n) => Some(n),
            Err(PyExc::TypeError(_) | PyExc::ValueError(_)) => None,
            Err(e) => return Err(e),
        },
    };
    let Some(rid_int) = rid_int.filter(|n| *n != BigInt::from(0)) else {
        return Ok(Value::None);
    };
    let or_list = |v: Value| if v.truthy() { v } else { py::list(vec![]) };
    let mitre = match get(&rule, "mitre", Value::None)? {
        v if v.truthy() => v,
        _ => py::dict(vec![]),
    };
    Ok(py::dict(vec![
        ("id", Value::Int(rid_int)),
        ("level", get(&rule, "level", Value::None)?),
        (
            "description",
            match get(&rule, "description", Value::None)? {
                v if v.truthy() => v,
                _ => s(""),
            },
        ),
        ("groups", or_list(get(&rule, "groups", Value::None)?)),
        ("mitre", or_list(get(&mitre, "id", Value::None)?)),
        ("pci_dss", or_list(get(&rule, "pci_dss", Value::None)?)),
        ("gdpr", or_list(get(&rule, "gdpr", Value::None)?)),
        ("hipaa", or_list(get(&rule, "hipaa", Value::None)?)),
        (
            "nist_800_53",
            or_list(get(&rule, "nist_800_53", Value::None)?),
        ),
        ("firedtimes", get(&rule, "firedtimes", Value::None)?),
    ]))
}

// --- custom repositories on GitHub --------------------------------------------------------

/// `test_repo_fetch(repo, branch, token)`: `{ok, rules_found, error}`.
pub async fn test_repo_fetch(
    st: &SearchesState,
    repo: &str,
    branch: &str,
    token: Option<String>,
) -> PyResult<Value> {
    let token = token
        .filter(|t| !t.is_empty())
        .or_else(|| st.settings.github_token.clone());
    let req = caches::github_request(
        Method::GET,
        format!(
            "{}/repos/{repo}/git/trees/{branch}?recursive=1",
            st.settings.github_api
        ),
        token.as_deref(),
    )
    .timeout(Duration::from_secs(20));
    let fail = |e: httpx::HttpxError| -> PyResult<Value> {
        if e.is_http_error() {
            Ok(repo_result(
                false,
                0,
                Some(format!("Could not reach GitHub: {}", e.message)),
            ))
        } else {
            Err(e.into_py())
        }
    };
    let resp = match httpx::send(req).await {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    if resp.status == 404 {
        return Ok(repo_result(
            false,
            0,
            Some("Repo or branch not found (or the token lacks access).".into()),
        ));
    }
    if resp.status == 401 || resp.status == 403 {
        return Ok(repo_result(
            false,
            0,
            Some(format!("GitHub rejected the token ({}).", resp.status)),
        ));
    }
    if let Err(e) = resp.raise_for_status() {
        return fail(e);
    }
    let tree_data = py::from_py(&resp.json()?);
    let tree = get(&tree_data, "tree", py::list(vec![]))?;
    let mut n = 0i64;
    for item in py::iterate(&tree)? {
        if get(&item, "type", Value::None)?.as_str() != Some("blob") {
            continue;
        }
        let path = get(&item, "path", s(""))?;
        let Value::Str(p) = &path else {
            return Err(py::no_attr(&path, "startswith"));
        };
        if !p.starts_with("detections/") {
            continue;
        }
        if p.ends_with(".yaml") || p.ends_with(".yml") {
            n += 1;
        }
    }
    Ok(repo_result(true, n, None))
}

fn repo_result(ok: bool, n: i64, error: Option<String>) -> Value {
    py::dict(vec![
        ("ok", Value::Bool(ok)),
        ("rules_found", py::int(n)),
        ("error", py::opt_str(error)),
    ])
}

fn publish_err(msg: impl Into<String>, findings: Option<Value>) -> Value {
    let msg = msg.into();
    let mut items = vec![
        ("success", Value::Bool(false)),
        ("message", s(msg.clone())),
        ("error", s(msg)),
    ];
    if let Some(f) = findings {
        items.push(("findings", f));
    }
    py::dict(items)
}

/// `_slug(name)`.
fn slug(name: &str) -> String {
    let base = if name.is_empty() { "rule" } else { name };
    let lowered = copilot_jinja::unicode::lower(base);
    let mut out = String::new();
    let mut in_run = false;
    for c in lowered.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('-');
            in_run = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "rule".into()
    } else {
        trimmed.to_string()
    }
}

/// `_PATH_RE.match(path)`.
fn path_ok(path: &str) -> bool {
    let t = path.strip_suffix('\n').unwrap_or(path);
    let Some(rest) = t.strip_prefix("detections/") else {
        return false;
    };
    let body = if let Some(b) = rest.strip_suffix(".yaml") {
        b
    } else if let Some(b) = rest.strip_suffix(".yml") {
        b
    } else {
        return false;
    };
    let class2 = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/');
    let mut chars = body.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '-' => {}
        _ => return false,
    }
    chars.all(class2)
}

/// `_gh_message(resp)`.
fn gh_message(resp: &httpx::Response) -> PyResult<String> {
    match resp.json() {
        Ok(v) => {
            let v = py::from_py(&v);
            Ok(get(&v, "message", s(resp.text()))?.py_str())
        }
        Err(_) => Ok(resp.text()),
    }
}

/// `publish_rule(rule_yaml, customer_code, message, path)`.
pub async fn publish_rule(
    st: &SearchesState,
    rule_yaml: &str,
    customer_code: &str,
    message: Option<&str>,
    path: Option<&str>,
) -> PyResult<Value> {
    let data = match copilot_yaml::safe_load(rule_yaml) {
        Ok(d) => d,
        Err(LoadError::Yaml(e)) => {
            return Ok(publish_err(
                format!("Rule YAML is not parseable: {e}"),
                None,
            ));
        }
        Err(LoadError::Python(e)) => return Err(linter::load_exc(e)),
    };
    if !data.is_dict() {
        return Ok(publish_err("Rule must be a YAML mapping.", None));
    }
    let name_raw = get(&data, "name", Value::None)?;
    let name = if name_raw.truthy() {
        py::py_strip(&name_raw.py_str()).to_string()
    } else {
        String::new()
    };
    if name.is_empty() {
        return Ok(publish_err("Rule has no name.", None));
    }
    let lint = linter::lint_result(rule_yaml)?;
    if !lint.valid() {
        return Ok(publish_err(
            format!(
                "Rule has {} validation error(s) — fix them before publishing.",
                lint.error_count()
            ),
            Some(py::list(
                lint.findings
                    .iter()
                    .map(linter::Finding::to_value)
                    .collect(),
            )),
        ));
    }
    if customer_code.is_empty() {
        return Ok(publish_err("Select a customer to publish to.", None));
    }
    let cfg = custom_repos::get(&st.store, customer_code).await?;
    let Some(cfg) = cfg.filter(|c| !c.repo.is_empty()) else {
        return Ok(publish_err(
            format!(
                "Customer '{customer_code}' has no custom repository configured. Add one under \
                 Custom repos first."
            ),
            None,
        ));
    };
    let Some(token) = cfg.token_text() else {
        return Ok(publish_err(
            format!(
                "The custom repo for '{customer_code}' has no write token. Add a GitHub PAT with \
                 'contents:write' in Custom repos to publish."
            ),
            None,
        ));
    };
    let repo = cfg.repo.clone();
    let branch = if cfg.branch.is_empty() {
        "main".to_string()
    } else {
        cfg.branch.clone()
    };
    let given = py::py_strip(path.unwrap_or_default()).to_string();
    let target = if given.is_empty() {
        format!("detections/custom/{}.yaml", slug(&name))
    } else {
        given
    };
    if target.contains('\\') || target.contains("..") || !path_ok(&target) {
        return Ok(publish_err(
            "path must be a YAML file under detections/ (e.g. detections/custom/my-rule.yaml) — \
             no '..', backslashes, or other locations.",
            None,
        ));
    }
    let id_raw = get(&data, "id", Value::None)?;
    let rule_id = if id_raw.truthy() {
        py::py_strip(&id_raw.py_str()).to_string()
    } else {
        String::new()
    };
    let mut existing: Option<Value> = None;
    if !rule_id.is_empty() {
        match caches::ensure_loaded(st, Kind::Rules).await {
            Ok(()) => existing = st.caches.rules.get().by_id(&rule_id).cloned(),
            Err(e) => tracing::warn!(
                "[publish] id-collision check skipped (cache unavailable): {}",
                e.text()
            ),
        }
    }
    if let Some(existing) = existing {
        let prov = existing.get("_provenance").cloned().unwrap_or(Value::None);
        let owner = existing
            .get("_owner_customer_code")
            .cloned()
            .unwrap_or(Value::None);
        let file = existing.get("_file_path").cloned().unwrap_or(Value::None);
        let same_file = prov.as_str() == Some("custom")
            && owner.as_str() == Some(customer_code)
            && file.as_str() == Some(target.as_str());
        if !same_file {
            let where_ = if prov.as_str() != Some("custom") {
                "the shared catalog".to_string()
            } else {
                format!("'{}' (customer {})", file.py_str(), owner.py_str())
            };
            let ename = existing.get("name").cloned().unwrap_or(Value::None);
            return Ok(publish_err(
                format!(
                    "Rule id {rule_id} is already used by '{}' in {where_}. Give this rule a new \
                     UUID (or publish to that rule's existing path to update it).",
                    ename.py_str()
                ),
                None,
            ));
        }
    }
    let content = base64::engine::general_purpose::STANDARD.encode(rule_yaml.as_bytes());
    let base = |m: Method, url: String| {
        Request::new(m, url)
            .header("Accept", Some("application/vnd.github+json"))
            .header("Authorization", Some(&format!("Bearer {token}")))
            .header("X-GitHub-Api-Version", Some("2022-11-28"))
            .timeout(Duration::from_secs(30))
    };
    let url = format!("{}/repos/{repo}/contents/{target}", st.settings.github_api);
    let client = httpx::Client::new(Duration::from_secs(30)).map_err(|e| e.into_py())?;
    let transport = |e: httpx::HttpxError| -> PyResult<Value> {
        if e.is_http_error() {
            tracing::warn!("[publish] transport error: {}", e.message);
            Ok(publish_err(
                format!("Could not reach GitHub: {}", e.message),
                None,
            ))
        } else {
            Err(e.into_py())
        }
    };
    let get_resp = match httpx::send_on(
        &client,
        base(Method::GET, url.clone()).params(vec![("ref".into(), branch.clone())]),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return transport(e),
    };
    let sha = match get_resp.status {
        200 => {
            let v = py::from_py(&get_resp.json()?);
            get(&v, "sha", Value::None)?
        }
        404 => Value::None,
        401 | 403 => {
            return Ok(publish_err(
                format!(
                    "GitHub rejected the token ({}). Check it has write access to {repo}.",
                    get_resp.status
                ),
                None,
            ));
        }
        other => {
            return Ok(publish_err(
                format!("GitHub read failed ({other}): {}", gh_message(&get_resp)?),
                None,
            ));
        }
    };
    let action = if sha.truthy() { "updated" } else { "created" };
    let commit_message = match message.filter(|m| !m.is_empty()) {
        Some(m) => m.to_string(),
        None => format!(
            "{} detection rule: {name}",
            if sha.truthy() { "Update" } else { "Add" }
        ),
    };
    let mut body = vec![
        ("message".to_string(), p_str(&commit_message)),
        ("content".to_string(), p_str(&content)),
        ("branch".to_string(), p_str(&branch)),
    ];
    if sha.truthy() {
        body.push(("sha".to_string(), py::to_py(&sha).unwrap_or(PyValue::None)));
    }
    let put_resp =
        match httpx::send_on(&client, base(Method::PUT, url).json(PyValue::Dict(body))).await {
            Ok(r) => r,
            Err(e) => return transport(e),
        };
    if put_resp.status != 200 && put_resp.status != 201 {
        return Ok(publish_err(
            format!(
                "GitHub publish failed ({}): {}",
                put_resp.status,
                gh_message(&put_resp)?
            ),
            None,
        ));
    }
    let result = py::from_py(&put_resp.json()?);
    let commit = match get(&result, "commit", py::dict(vec![]))? {
        v if v.truthy() => v,
        _ => py::dict(vec![]),
    };
    let content_v = match get(&result, "content", py::dict(vec![]))? {
        v if v.truthy() => v,
        _ => py::dict(vec![]),
    };
    tracing::info!("[publish] {action} {repo}/{target}@{branch} for customer {customer_code}");
    Ok(py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s(format!("Rule {action} in {repo}"))),
        ("action", s(action)),
        ("repo", s(repo)),
        ("branch", s(branch)),
        ("path", s(target)),
        ("commit_url", get(&commit, "html_url", Value::None)?),
        ("html_url", get(&content_v, "html_url", Value::None)?),
        ("error", Value::None),
    ]))
}
