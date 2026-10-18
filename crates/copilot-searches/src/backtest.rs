//! `services/backtest.py` and `services/graylog_search.py`: a rule's Graylog
//! query replayed over one customer's stream, with Python's local analysis
//! (sparkline, samples, top values, the sliding-window threshold
//! simulation). The searches are `requests.post` calls with `Accept:
//! application/json` and `X-Requested-By: CoPilot`, Basic auth, TLS
//! unverified, 60 s.

use std::collections::HashMap;
use std::sync::Arc;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::http::{PyHttp, PyRequest};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_yaml::{LoadError, Value};
use http::Method;
use num_bigint_dig::BigInt;
use num_traits::ToPrimitive;

use crate::linter::query_fields;
use crate::py::{self, get, s};

/// `MAX_RANGE_SECONDS`.
pub const MAX_RANGE_SECONDS: i64 = 30 * 86400;
/// `DEFAULT_RANGE_SECONDS`.
pub const DEFAULT_RANGE_SECONDS: i64 = 7 * 86400;
/// `FETCH_CAP`.
pub const FETCH_CAP: usize = 10_000;
/// `SAMPLE_SIZE`.
pub const SAMPLE_SIZE: usize = 20;
const MAX_SAMPLE_FIELDS: usize = 14;
const MAX_DETAIL_FIELDS: usize = 500;
const RESERVED: &[&str] = &["AND", "OR", "NOT", "TO", "_exists_"];

fn err(msg: impl Into<String>) -> Value {
    let msg = msg.into();
    py::dict(vec![
        ("success", Value::Bool(false)),
        ("message", s(msg.clone())),
        ("error", s(msg)),
    ])
}

/// `_STREAM_ID_RE.match(stream)`: 24 hex characters (any case), a final
/// newline allowed.
pub fn is_stream_id(t: &str) -> bool {
    let t = t.strip_suffix('\n').unwrap_or(t);
    t.chars().count() == 24 && t.chars().all(|c| c.is_ascii_hexdigit())
}

/// `_parse_window_seconds(value)`.
pub fn parse_window_seconds(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(_) => None,
        Value::Int(i) => (*i > BigInt::from(0)).then(|| i.to_i64().unwrap_or(i64::MAX)),
        Value::Float(f) => {
            if *f > 0.0 {
                Some(f.trunc() as i64)
            } else {
                None
            }
        }
        other => {
            let raw = if other.truthy() {
                other.py_str()
            } else {
                String::new()
            };
            let text = copilot_jinja::unicode::lower(py::py_strip(&raw));
            let last = text.chars().last()?;
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
                    copilot_yaml::pyint::parse_float(&head).ok()? * u
                }
                None => copilot_yaml::pyint::parse_float(&text).ok()?,
            };
            if seconds > 0.0 {
                if seconds.is_infinite() {
                    // `int(inf)`: the OverflowError Python lets escape.
                    return Some(i64::MAX);
                }
                Some(seconds.trunc() as i64)
            } else {
                None
            }
        }
    }
}

/// `_to_epoch(ts)`.
pub fn to_epoch(ts: &Value) -> Option<f64> {
    match ts {
        Value::None => None,
        Value::Int(i) => i.to_f64(),
        Value::Float(f) => Some(*f),
        other => {
            let raw = other.py_str();
            let mut t = py::py_strip(&raw).to_string();
            if t.is_empty() {
                return None;
            }
            t = t.replace('Z', "+00:00").replacen(' ', "T", 1);
            t = normalise_offset(&t);
            let parsed = copilot_ingest::py::fromisoformat(&t).ok()?;
            let base = parsed.wall.and_utc().timestamp_micros();
            let micros = base - parsed.offset_us.unwrap_or(0);
            Some(micros as f64 / 1_000_000.0)
        }
    }
}

/// `re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)`.
fn normalise_offset(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let try_at = |end: usize| -> Option<String> {
        if end < 5 {
            return None;
        }
        let start = end - 5;
        let sign = chars[start];
        if !(sign == '+' || sign == '-') {
            return None;
        }
        let digits = &chars[start + 1..end];
        if !digits
            .iter()
            .all(|c| copilot_jinja::unicode::is_decimal(*c))
        {
            return None;
        }
        let mut out: String = chars[..start + 3].iter().collect();
        out.push(':');
        out.extend(&chars[start + 3..end]);
        out.extend(&chars[end..]);
        Some(out)
    };
    // `$` matches at the end, or before a final newline (tried in that
    // order of position: the earlier one first).
    if chars.last() == Some(&'\n') {
        if let Some(out) = try_at(chars.len() - 1) {
            return out;
        }
    }
    try_at(chars.len()).unwrap_or_else(|| s.to_string())
}

/// `_query_fields(query)`.
pub fn backtest_query_fields(query: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in query_fields(query, false) {
        if !RESERVED.contains(&m.as_str()) && !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

fn schema_names(resp: &Value) -> PyResult<Vec<String>> {
    let schema = get(resp, "schema", py::list(vec![]))?;
    let schema = if schema.truthy() {
        schema
    } else {
        py::list(vec![])
    };
    let mut out = Vec::new();
    for col in py::iterate(&schema)? {
        if col.is_dict() {
            let mut name = Value::None;
            for k in ["field", "name", "column"] {
                let v = get(&col, k, Value::None)?;
                if v.truthy() {
                    name = v;
                    break;
                }
            }
            out.push(if name.truthy() {
                name.py_str()
            } else {
                String::new()
            });
        } else {
            out.push(col.py_str());
        }
    }
    Ok(out)
}

fn row_to_dict(row: &Value, names: &[String]) -> Value {
    match row {
        Value::Dict(_) => row.clone(),
        Value::List(items) => {
            let mut out: Vec<(Value, Value)> = Vec::new();
            for (i, v) in items.iter().enumerate() {
                let k = names.get(i).cloned().unwrap_or_else(|| format!("col{i}"));
                match out
                    .iter_mut()
                    .find(|(key, _)| key.as_str() == Some(k.as_str()))
                {
                    Some(slot) => slot.1 = v.clone(),
                    None => out.push((s(k), v.clone())),
                }
            }
            Value::Dict(Arc::new(out))
        }
        other => py::dict(vec![("value", other.clone())]),
    }
}

fn utc_label(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

fn sparkline(rows: &[(f64, Value)], bucket: i64) -> Vec<Value> {
    let mut counts: Vec<(i64, i64)> = Vec::new();
    for (ts, _) in rows {
        let key = (ts / bucket as f64).floor() as i64;
        match counts.iter_mut().find(|(k, _)| *k == key) {
            Some(c) => c.1 += 1,
            None => counts.push((key, 1)),
        }
    }
    counts.sort_by_key(|(k, _)| *k);
    counts
        .into_iter()
        .map(|(k, n)| {
            py::dict(vec![
                ("bucket", s(utc_label(k * bucket))),
                ("count", py::int(n)),
            ])
        })
        .collect()
}

fn top_fields(samples: &[Value], candidates: &[String]) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = Vec::new();
    for field in candidates {
        let mut counts: Vec<(String, i64)> = Vec::new();
        for sample in samples {
            let val = sample.get(field).cloned().unwrap_or(Value::None);
            if matches!(val, Value::None) || val.as_str() == Some("") {
                continue;
            }
            let k = val.py_str();
            match counts.iter_mut().find(|(c, _)| *c == k) {
                Some(c) => c.1 += 1,
                None => counts.push((k, 1)),
            }
        }
        if counts.len() > 1 {
            counts.sort_by_key(|c| std::cmp::Reverse(c.1));
            let top: Vec<Value> = counts
                .into_iter()
                .take(5)
                .map(|(v, c)| py::dict(vec![("value", s(v)), ("count", py::int(c))]))
                .collect();
            match out.iter_mut().find(|(f, _)| f == field) {
                Some(slot) => slot.1 = py::list(top),
                None => out.push((field.clone(), py::list(top))),
            }
        }
    }
    out
}

#[derive(Clone, Copy)]
enum Op {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
}

impl Op {
    fn of(c: &str) -> Op {
        match c {
            ">=" => Op::Ge,
            "<" => Op::Lt,
            "<=" => Op::Le,
            "==" => Op::Eq,
            _ => Op::Gt,
        }
    }

    fn apply(self, a: i64, b: i64) -> bool {
        match self {
            Op::Gt => a > b,
            Op::Ge => a >= b,
            Op::Lt => a < b,
            Op::Le => a <= b,
            Op::Eq => a == b,
        }
    }
}

/// `_sliding_alerts(events, window, threshold, op, distinct)`.
fn sliding_alerts(
    mut events: Vec<(f64, Option<String>)>,
    window: i64,
    threshold: i64,
    op: Op,
    distinct: bool,
) -> (i64, i64) {
    events.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let n = events.len();
    let (mut i, mut r, mut alerts, mut peak) = (0usize, 0usize, 0i64, 0i64);
    let mut counts: HashMap<Option<String>, i64> = HashMap::new();
    let mut active = 0i64;
    let w = window as f64;
    while i < n {
        if r < i {
            r = i;
            counts.clear();
            active = 0;
        }
        while r < n && events[r].0 < events[i].0 + w {
            if distinct {
                let c = counts.entry(events[r].1.clone()).or_insert(0);
                if *c == 0 {
                    active += 1;
                }
                *c += 1;
            }
            r += 1;
        }
        let metric = if distinct { active } else { (r - i) as i64 };
        peak = peak.max(metric);
        let drop =
            |counts: &mut HashMap<Option<String>, i64>, active: &mut i64, v: &Option<String>| {
                if let Some(c) = counts.get_mut(v) {
                    *c -= 1;
                    if *c == 0 {
                        *active -= 1;
                    }
                }
            };
        if op.apply(metric, threshold) {
            alerts += 1;
            let wend = events[i].0 + w;
            while i < n && events[i].0 < wend {
                if distinct {
                    let v = events[i].1.clone();
                    drop(&mut counts, &mut active, &v);
                }
                i += 1;
            }
        } else {
            if distinct {
                let v = events[i].1.clone();
                drop(&mut counts, &mut active, &v);
            }
            i += 1;
        }
    }
    (alerts, peak)
}

/// One group's key and its `(timestamp, value)` events.
type Group = (Vec<String>, Vec<(f64, Option<String>)>);

/// The messages fetch: the column names, the row count, the timed rows.
type Fetched = (Vec<Value>, usize, Vec<(f64, Value)>);

/// `_simulate_aggregation(rows, agg, truncated)`.
fn simulate(rows: &[(f64, Value)], agg: &Value, truncated: bool) -> PyResult<Option<Value>> {
    let window = get(agg, "window", Value::None)?;
    let Some(window_seconds) = parse_window_seconds(&window).filter(|w| *w != 0) else {
        return Ok(None);
    };
    if window_seconds == i64::MAX {
        return Err(PyExc::Other(
            "OverflowError",
            "cannot convert float infinity to integer".into(),
        ));
    }
    let condition = match get(agg, "condition", Value::None)? {
        v if v.truthy() => v,
        _ => s(">"),
    };
    let op = match condition.as_str() {
        Some(c @ (">" | ">=" | "<" | "<=" | "==")) => Op::of(c),
        _ => {
            // `_OPS.get(condition, …)` hashes the condition first.
            py::hash_key(&condition)?;
            Op::Gt
        }
    };
    let raw_threshold = match get(agg, "threshold", Value::None)? {
        v if v.truthy() => v,
        _ => py::int(1),
    };
    let threshold = match py::py_int(&raw_threshold) {
        Ok(t) => t,
        Err(PyExc::ValueError(_) | PyExc::TypeError(_)) => BigInt::from(1),
        Err(e) => return Err(e),
    };
    let threshold_i = threshold.to_i64().unwrap_or(i64::MAX);
    let function = match get(agg, "function", Value::None)? {
        v if v.truthy() => v,
        _ => s("count"),
    };
    let function = py::lower(&function)?;
    let field = get(agg, "field", Value::None)?;
    let distinct = function == "distinct_count";
    let group_by_raw = match get(agg, "group_by", Value::None)? {
        v if v.truthy() => v,
        _ => py::list(vec![]),
    };
    let group_by: Vec<Value> = py::iterate(&group_by_raw)?
        .into_iter()
        .filter(Value::truthy)
        .collect();
    let mut groups: Vec<Group> = Vec::new();
    for (ts, row) in rows {
        let gkey: Vec<String> = if group_by.is_empty() {
            vec!["*".into()]
        } else {
            let mut k = Vec::new();
            for g in &group_by {
                k.push(row_get(row, g)?.py_str());
            }
            k
        };
        let val = if distinct {
            Some(row_get(row, &field)?.py_str())
        } else {
            None
        };
        match groups.iter_mut().find(|(k, _)| *k == gkey) {
            Some(slot) => slot.1.push((*ts, val)),
            None => groups.push((gkey, vec![(*ts, val)])),
        }
    }
    let alerts_at = |th: i64| -> i64 {
        groups
            .iter()
            .map(|(_, evs)| sliding_alerts(evs.clone(), window_seconds, th, op, distinct).0)
            .sum()
    };
    let mut offenders: Vec<(i64, i64, String)> = Vec::new();
    let mut estimated = 0i64;
    for (gkey, evs) in &groups {
        let (alerts, peak) = sliding_alerts(evs.clone(), window_seconds, threshold_i, op, distinct);
        estimated += alerts;
        if alerts > 0 {
            let label = if group_by.is_empty() {
                "(all events)".to_string()
            } else {
                gkey.iter()
                    .enumerate()
                    .map(|(i, gv)| format!("{}={gv}", group_by[i].py_str()))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            offenders.push((alerts, peak, label));
        }
    }
    offenders.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    let mut ths: Vec<i64> = [0.5, 0.75, 1.0, 1.5, 2.0]
        .iter()
        .map(|m| {
            let x = threshold_i as f64 * m;
            // `round()` is half-to-even.
            let r = x.round();
            let r = if (x - x.trunc()).abs() == 0.5 && (r as i64) % 2 != 0 {
                r - x.signum()
            } else {
                r
            };
            (r as i64).max(1)
        })
        .collect();
    ths.sort();
    ths.dedup();
    let sensitivity: Vec<Value> = ths
        .into_iter()
        .map(|th| {
            py::dict(vec![
                ("threshold", py::int(th)),
                ("alerts", py::int(alerts_at(th))),
            ])
        })
        .collect();
    Ok(Some(py::dict(vec![
        ("window", s(window.py_str())),
        ("window_seconds", py::int(window_seconds)),
        ("function", s(function)),
        ("field", field),
        ("group_by", py::list(group_by)),
        ("threshold", Value::Int(threshold)),
        ("condition", condition),
        ("estimated_alerts", py::int(estimated)),
        (
            "top_offenders",
            py::list(
                offenders
                    .into_iter()
                    .take(10)
                    .map(|(a, p, l)| {
                        py::dict(vec![
                            ("group", s(l)),
                            ("windows_alerting", py::int(a)),
                            ("peak", py::int(p)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("sensitivity", py::list(sensitivity)),
        ("truncated", Value::Bool(truncated)),
    ])))
}

/// `row.get(key, "")` with a key of any hashable type.
fn row_get(row: &Value, key: &Value) -> PyResult<Value> {
    py::hash_key(key)?;
    match row {
        Value::Dict(items) => Ok(items
            .iter()
            .find(|(k, _)| k.py_eq(key))
            .map_or_else(|| s(""), |(_, v)| v.clone())),
        other => Err(py::no_attr(other, "get")),
    }
}

/// The Graylog connector the backtest reads (`get_current_graylog_connector()`
/// outside any context: the default one).
pub const CONNECTOR: &str = copilot_graylog::client::DEFAULT_CONNECTOR;

/// `_post(endpoint, body)`.
async fn post(
    st: &crate::SearchesState,
    http: &PyHttp,
    endpoint: &str,
    body: PyValue,
) -> PyResult<PyValue> {
    let row = st
        .ctx
        .connectors
        .get(CONNECTOR)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .ok_or_else(|| PyExc::http(500, format!("Graylog connector '{CONNECTOR}' not found")))?;
    let req = PyRequest::new(Method::POST, format!("{}{endpoint}", row.connector_url))
        .header("X-Requested-By", "CoPilot")
        .header("Accept", "application/json")
        .basic(
            row.connector_username.clone(),
            row.connector_password.clone(),
        )
        .json(Some(body));
    let resp = http.send(req).await?;
    if resp.status != 200 {
        let mut detail = PyValue::Str(resp.text());
        if let Ok(parsed) = resp.json() {
            match &parsed {
                PyValue::Dict(_) => {
                    if let Some(m) = parsed.get("message") {
                        detail = m.clone();
                    }
                }
                PyValue::List(items) => {
                    if let Some(first @ PyValue::Dict(_)) = items.first() {
                        let msg = first
                            .get("message")
                            .cloned()
                            .unwrap_or(PyValue::Str(String::new()));
                        let path = first
                            .get("path")
                            .cloned()
                            .unwrap_or(PyValue::Str(String::new()));
                        detail = if path.truthy() {
                            PyValue::Str(format!("{} ({})", msg.py_str(), path.py_str()))
                        } else if msg.truthy() {
                            msg
                        } else {
                            detail
                        };
                    }
                }
                _ => {}
            }
        }
        return Err(PyExc::http(
            502,
            format!(
                "Graylog search failed ({}): {}",
                resp.status,
                detail.py_str()
            ),
        ));
    }
    match resp.json() {
        Ok(v) if v.truthy() => Ok(v),
        Ok(_) => Ok(PyValue::Dict(Vec::new())),
        Err(_) => Err(PyExc::http(
            502,
            "Graylog returned a non-JSON search response.",
        )),
    }
}

fn to_json(v: &Value) -> PyResult<PyValue> {
    py::to_py(v).ok_or_else(|| {
        PyExc::TypeError(format!(
            "Object of type {} is not JSON serializable",
            v.type_name()
        ))
    })
}

/// `search_messages(query, streams, fields, size, range_seconds)`.
async fn search_messages(
    st: &crate::SearchesState,
    http: &PyHttp,
    query: &str,
    stream: &str,
    fields: &[Value],
    size: usize,
    range_seconds: i64,
) -> PyResult<Value> {
    let streams: Vec<PyValue> = if stream.is_empty() {
        Vec::new()
    } else {
        vec![PyValue::Str(stream.to_string())]
    };
    let fields: Vec<PyValue> = fields.iter().map(to_json).collect::<PyResult<_>>()?;
    let body = PyValue::Dict(vec![
        ("query".into(), PyValue::Str(query.to_string())),
        ("streams".into(), PyValue::List(streams)),
        (
            "timerange".into(),
            PyValue::Dict(vec![
                ("type".into(), PyValue::Str("relative".into())),
                ("range".into(), PyValue::Int(range_seconds.to_string())),
            ]),
        ),
        ("fields".into(), PyValue::List(fields)),
        ("size".into(), PyValue::Int(size.to_string())),
    ]);
    post(st, http, "/api/search/messages", body)
        .await
        .map(|v| py::from_py(&v))
}

/// `list_stream_fields(stream)`: `[]` on any failure.
async fn list_stream_fields(st: &crate::SearchesState, http: &PyHttp, stream: &str) -> Vec<String> {
    if stream.is_empty() {
        return Vec::new();
    }
    let body = PyValue::Dict(vec![(
        "streams".into(),
        PyValue::List(vec![PyValue::Str(stream.to_string())]),
    )]);
    let data = match post(st, http, "/api/views/fields", body).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("[backtest] list_stream_fields failed: {}", e.display());
            return Vec::new();
        }
    };
    let data = if data.truthy() {
        data
    } else {
        PyValue::List(Vec::new())
    };
    match copilot_upstream::py::iterate(&data) {
        Ok(items) => items
            .iter()
            .filter_map(|f| match f {
                PyValue::Dict(_) => f.get("name").filter(|n| n.truthy()).map(PyValue::py_str),
                _ => None,
            })
            .collect(),
        Err(e) => {
            tracing::warn!("[backtest] list_stream_fields failed: {}", e.display());
            Vec::new()
        }
    }
}

fn contains_value(list: &[Value], v: &Value) -> bool {
    list.iter().any(|x| x.py_eq(v))
}

fn round2(x: f64) -> f64 {
    py::py_round(x, 2)
}

/// `run_backtest(rule_yaml, customer_code, range_seconds)`.
pub async fn run_backtest(
    st: &crate::SearchesState,
    http: &PyHttp,
    rule_yaml: &str,
    customer_code: &str,
    range_seconds: i64,
) -> PyResult<Value> {
    let range_seconds = range_seconds.clamp(300, MAX_RANGE_SECONDS);
    let range_seconds = if range_seconds == 0 {
        DEFAULT_RANGE_SECONDS
    } else {
        range_seconds
    };
    let data = match copilot_yaml::safe_load(rule_yaml) {
        Ok(d) => d,
        Err(LoadError::Yaml(e)) => return Ok(err(format!("Rule YAML is not parseable: {e}"))),
        Err(LoadError::Python(e)) => return Err(crate::linter::load_exc(e)),
    };
    if !data.is_dict() {
        return Ok(err("Rule must be a YAML mapping."));
    }
    let graylog = match get(&data, "graylog", Value::None)? {
        v if v.truthy() => v,
        _ => py::dict(vec![]),
    };
    let q = match get(&graylog, "query", Value::None)? {
        v if v.truthy() => v,
        _ => s(""),
    };
    let query = py::strip(&q)?;
    if query.is_empty() {
        return Ok(err("Rule has no graylog.query to backtest."));
    }
    let agg_raw = get(&data, "aggregation", Value::None)?;
    let agg_enabled = agg_raw.is_dict() && get(&agg_raw, "enabled", Value::None)?.truthy();
    if customer_code.is_empty() {
        return Ok(err("Select a customer to backtest against."));
    }
    let stream = crate::db::customer_stream(&st.ctx, customer_code)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e))?;
    let Some(stream) = stream.filter(|s| !s.is_empty()) else {
        return Ok(err(format!(
            "Customer '{customer_code}' has no Graylog stream configured."
        )));
    };
    if !is_stream_id(&stream) {
        return Ok(err(format!(
            "Customer '{customer_code}' has a placeholder/invalid Graylog stream ('{stream}'). \
             Set a real Graylog stream on the customer to backtest."
        )));
    }
    let qfields = backtest_query_fields(&query);
    let mut agg_fields: Vec<Value> = Vec::new();
    if agg_raw.is_dict() {
        let gb = match get(&agg_raw, "group_by", Value::None)? {
            v if v.truthy() => v,
            _ => py::list(vec![]),
        };
        for f in py::iterate(&gb)? {
            if f.truthy() {
                agg_fields.push(f);
            }
        }
        if agg_raw.truthy() {
            let f = get(&agg_raw, "field", Value::None)?;
            if f.truthy() {
                agg_fields.push(f);
            }
        }
    }
    let mut fetch_fields: Vec<Value> = Vec::new();
    let base: Vec<Value> = ["timestamp", "source", "message"]
        .iter()
        .map(|t| s(*t))
        .chain(qfields.iter().map(|t| s(t.clone())))
        .chain(agg_fields.iter().cloned())
        .collect();
    for f in base {
        if f.truthy() && !contains_value(&fetch_fields, &f) {
            fetch_fields.push(f);
        }
    }
    fetch_fields.truncate(MAX_SAMPLE_FIELDS);

    let rows: Vec<(f64, Value)>;
    let sample_fields: Vec<Value>;
    let fetched: usize;
    let fetch: PyResult<Fetched> = async {
        let resp = search_messages(
            st,
            http,
            &query,
            &stream,
            &fetch_fields,
            FETCH_CAP,
            range_seconds,
        )
        .await?;
        let names = schema_names(&resp)?;
        let names: Vec<Value> = if names.is_empty() {
            fetch_fields.clone()
        } else {
            names.into_iter().map(s).collect()
        };
        let name_text: Vec<String> = names.iter().map(Value::py_str).collect();
        let datarows = match get(&resp, "datarows", Value::None)? {
            v if v.truthy() => v,
            _ => py::list(vec![]),
        };
        let count = py::len(&datarows)?;
        let mut out = Vec::new();
        for r in py::iterate(&datarows)? {
            let d = row_to_dict(&r, &name_text);
            let ts = get(&d, "timestamp", Value::None)?;
            if let Some(ts) = to_epoch(&ts) {
                out.push((ts, d));
            }
        }
        Ok((names, count, out))
    }
    .await;
    match fetch {
        Ok((names, count, out)) => {
            sample_fields = names;
            fetched = count;
            rows = out;
        }
        Err(e) => {
            let detail = match &e {
                PyExc::Http(_, d) => d.clone(),
                other => other.text(),
            };
            tracing::warn!("[backtest] messages fetch failed: {}", e.display());
            return Ok(err(format!("Graylog search failed: {detail}")));
        }
    }
    let truncated = fetched >= FETCH_CAP;
    let total = fetched;
    let (bucket_unit, bucket_seconds) = if range_seconds <= 2 * 86400 {
        ("1h", 3600)
    } else {
        ("1d", 86400)
    };
    let per_bucket = sparkline(&rows, bucket_seconds);
    let mut samples: Vec<Value> = rows
        .iter()
        .take(SAMPLE_SIZE)
        .map(|(_, d)| d.clone())
        .collect();
    let all: Vec<Value> = rows.iter().map(|(_, d)| d.clone()).collect();
    let mut candidates = vec!["source".to_string()];
    candidates.extend(qfields.iter().take(3).cloned());
    let top = top_fields(&all, &candidates);

    let mut missing_fields: Vec<Value> = Vec::new();
    let stream_fields = list_stream_fields(st, http, &stream).await;
    let enrich: PyResult<()> = async {
        if stream_fields.len() >= 5 {
            let mut candidates: Vec<Value> = Vec::new();
            let mut keys: Vec<String> = Vec::new();
            for f in qfields
                .iter()
                .map(|t| s(t.clone()))
                .chain(agg_fields.iter().cloned())
            {
                if f.truthy() && !matches!(f.as_str(), Some("timestamp" | "source" | "message")) {
                    let k = py::hash_key(&f)?;
                    if !keys.contains(&k) {
                        keys.push(k);
                        candidates.push(f);
                    }
                }
            }
            let missing: Vec<Value> = candidates
                .into_iter()
                .filter(|f| {
                    !f.as_str()
                        .is_some_and(|t| stream_fields.iter().any(|k| k == t))
                })
                .collect();
            missing_fields = crate::mitre::sorted_values(missing)?;
        }
        if !stream_fields.is_empty() {
            let mut detail: Vec<Value> = Vec::new();
            for f in ["timestamp", "source", "message", "full_message"]
                .iter()
                .map(|t| s(*t))
                .chain(stream_fields.iter().map(|t| s(t.clone())))
            {
                if f.truthy() && !contains_value(&detail, &f) {
                    detail.push(f);
                }
            }
            detail.truncate(MAX_DETAIL_FIELDS);
            let rich_resp = search_messages(
                st,
                http,
                &query,
                &stream,
                &detail,
                SAMPLE_SIZE,
                range_seconds,
            )
            .await?;
            let names = schema_names(&rich_resp)?;
            let names: Vec<String> = if names.is_empty() {
                detail.iter().map(Value::py_str).collect()
            } else {
                names
            };
            let datarows = match get(&rich_resp, "datarows", Value::None)? {
                v if v.truthy() => v,
                _ => py::list(vec![]),
            };
            let mut rich: Vec<Value> = Vec::new();
            for r in py::iterate(&datarows)?.into_iter().take(SAMPLE_SIZE) {
                let d = row_to_dict(&r, &names);
                let kept: Vec<(Value, Value)> = py::items(&d)?
                    .into_iter()
                    .filter(|(_, v)| {
                        !(matches!(v, Value::None)
                            || v.as_str() == Some("")
                            || v.as_str() == Some("-"))
                    })
                    .collect();
                rich.push(Value::Dict(Arc::new(kept)));
            }
            if !rich.is_empty() {
                samples = rich;
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = enrich {
        tracing::warn!(
            "[backtest] rich sample fetch failed (non-fatal): {}",
            e.display()
        );
    }

    let days = (range_seconds as f64 / 86400.0).max(1.0);
    let mut aggregation = Value::None;
    if agg_enabled {
        if let Some(mut a) = simulate(&rows, &agg_raw, truncated)? {
            let estimated = a
                .get("estimated_alerts")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if let Value::Dict(items) = &mut a {
                Arc::make_mut(items).push((
                    s("per_day_alerts"),
                    Value::Float(round2(estimated as f64 / days)),
                ));
            }
            aggregation = a;
        }
    }
    let note = if truncated {
        s(format!(
            "Hit the {}-event analysis cap — this rule matches at least this many events in the \
             window. Figures are a lower bound over the most recent events; tighten the query or \
             shorten the window for exact numbers.",
            "10,000"
        ))
    } else if agg_enabled && matches!(aggregation, Value::None) {
        s(
            "Aggregation block present but its window is unparseable — showing raw event volume only.",
        )
    } else {
        Value::None
    };
    let mode = if aggregation.truthy() {
        "aggregation"
    } else {
        "messages"
    };
    Ok(py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s("Backtest complete")),
        ("mode", s(mode)),
        ("customer_code", s(customer_code)),
        ("stream_id", s(stream)),
        ("range_seconds", py::int(range_seconds)),
        ("query", s(query.clone())),
        ("total_hits", py::int(total as i64)),
        ("per_day_avg", Value::Float(round2(total as f64 / days))),
        ("fetched", py::int(fetched as i64)),
        ("truncated", Value::Bool(truncated)),
        ("per_bucket", py::list(per_bucket)),
        ("bucket_unit", s(bucket_unit)),
        ("samples", py::list(samples)),
        ("sample_fields", py::list(sample_fields)),
        (
            "top_fields",
            Value::Dict(Arc::new(top.into_iter().map(|(k, v)| (s(k), v)).collect())),
        ),
        ("aggregation", aggregation),
        ("missing_fields", py::list(missing_fields)),
        ("note", note),
        ("error", Value::None),
    ]))
}
