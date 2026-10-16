//! `wazuh_indexer/services/alerts.py`: alerts per index, the per-host and
//! per-rule counts, Graylog event hydration and one alert by id.

use chrono::{Duration, NaiveDateTime};
use futures::future::join_all;
use reqwest::Method;
use serde_json::{Map, Value, json};

use copilot_auth::pyvalue::str_repr;

use crate::WazuhState;
use crate::error::{PyErr, key_error};
use crate::es::{Es, make_path, require};
use crate::indexer::schema::{AlertsSearchBody, GraylogAlertsSearchBody};
use crate::indexer::services::{
    async_client, client, collect_indices, customer_matchers, index_matches_customer,
};
use crate::pymodel::{self, Model};

/// `SkippableWazuhIndexerClientErrors`.
const SKIPPABLE: &str = "No mapping found for [timestamp_utc] in order to sort on";

/// `TEXT_TIMESTAMP_FIELDS`.
const TEXT_TIMESTAMP_FIELDS: &[&str] = &["timestamp_utc"];

/// `datetime.isoformat()` of a naive value.
pub fn isoformat(t: NaiveDateTime) -> String {
    if t.and_utc().timestamp_subsec_micros() == 0 {
        t.format("%Y-%m-%dT%H:%M:%S").to_string()
    } else {
        t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
    }
}

/// `datetime.utcnow()` (microseconds).
fn utcnow() -> NaiveDateTime {
    copilot_core::time::now_utc_micros()
}

/// `timedelta(hours|days|weeks=n)` subtracted from `utcnow()`, as
/// `_get_time_range_start` / `parse_timerange` do; Python's
/// `OverflowError`s for absurd amounts.
pub fn time_range_start(timerange: &str) -> Result<String, PyErr> {
    let (amount, unit) = timerange.split_at(timerange.len().saturating_sub(1));
    let n: i64 = amount.parse().map_err(|_| {
        PyErr::Value(format!(
            "invalid literal for int() with base 10: {}",
            str_repr(amount)
        ))
    })?;
    let overflow = || PyErr::Other("date value out of range".into());
    let delta = match unit {
        "h" => Duration::try_hours(n),
        "d" => Duration::try_days(n),
        "w" => Duration::try_weeks(n),
        _ => {
            return Err(PyErr::Value(
                "Invalid timerange format. Expected a string like '24h', '1d', '1w', etc.".into(),
            ));
        }
    }
    .ok_or_else(overflow)?;
    let start = utcnow().checked_sub_signed(delta).ok_or_else(overflow)?;
    if start
        < chrono::NaiveDate::from_ymd_opt(1, 1, 1)
            .unwrap_or_default()
            .into()
    {
        return Err(overflow());
    }
    Ok(format!("{}Z", isoformat(start)))
}

/// `time_range_query(field, gte, lte)`.
pub fn time_range_query(field: &str, gte: &str, lte: &str) -> Value {
    let text = TEXT_TIMESTAMP_FIELDS.contains(&field);
    let f = if text { "timestamp" } else { field };
    let mut range = Map::new();
    range.insert("gte".into(), json!(gte));
    range.insert("lte".into(), json!(lte));
    if f == "timestamp" {
        range.insert("format".into(), json!("strict_date_optional_time"));
    }
    json!({"range": {f: range}})
}

/// `AlertsQueryBuilder`'s query for one index.
fn alerts_query(body: &AlertsSearchBody, host: bool, start: &str) -> Value {
    let mut must = vec![
        time_range_query(&body.timestamp_field, start, "now"),
        json!({"match": {body.alert_field.clone(): body.alert_value}}),
    ];
    if host {
        must.push(
            json!({"match_phrase": {"agent_name": body.agent_name.clone().unwrap_or_default()}}),
        );
    }
    json!({
        "query": {"bool": {"must": must}},
        "sort": [{body.timestamp_field.clone(): {"order": "desc"}}],
    })
}

/// Python truthiness of a `json.loads` value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `x["hits"]["hits"]` as Python indexes it.
fn hits(v: &Value) -> Result<Vec<Value>, PyErr> {
    let outer = v.get("hits").ok_or_else(|| index_error(v, "hits"))?;
    let inner = outer
        .get("hits")
        .ok_or_else(|| index_error(outer, "hits"))?;
    match inner {
        Value::Array(items) => Ok(items.clone()),
        Value::Object(map) => Ok(map.keys().map(|k| json!(k)).collect()),
        other => Err(PyErr::Other(format!(
            "'{}' object is not iterable",
            super::py_type(other)
        ))),
    }
}

/// The exception `value[key]` raises on a `json.loads` value.
fn index_error(v: &Value, key: &str) -> PyErr {
    match v {
        Value::Object(_) => key_error(key),
        Value::Array(_) => PyErr::Other("list indices must be integers or slices, not str".into()),
        Value::String(_) => PyErr::Other("string indices must be integers, not 'str'".into()),
        other => PyErr::Other(format!(
            "'{}' object is not subscriptable",
            super::py_type(other)
        )),
    }
}

/// `collect_alerts_generic(index_name, body, is_host_specific)`: the hits,
/// retrying once with `timestamp` when the index cannot sort on
/// `timestamp_utc` — and leaving `body.timestamp_field` changed, as the
/// Python call does to the shared body.
pub async fn collect_alerts_generic(
    st: &WazuhState,
    index: &str,
    body: &mut AlertsSearchBody,
    host: bool,
) -> Result<Vec<Value>, PyErr> {
    for _ in 0..50 {
        let es = client(st).await?;
        let start = time_range_start(&body.timerange)?;
        let query = alerts_query(body, host, &start);
        let path = make_path(&[index, "_search"]);
        match es
            .perform(
                Method::POST,
                &path,
                &[("size", body.size.to_string())],
                Some(&query),
            )
            .await
        {
            Ok(v) => return hits(&v),
            Err(e) if e.is_request_error() => {
                let text = e.to_string();
                if text.contains(SKIPPABLE) {
                    body.timestamp_field = "timestamp".into();
                    continue;
                }
                return Err(PyErr::server(format!(
                    "An error occurred while collecting alerts: {text}"
                )));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(PyErr::Other(
        "maximum recursion depth exceeded while calling a Python object".into(),
    ))
}

/// The per-index loop's handling of an `HTTPException`.
fn index_failure(index: &str, e: PyErr) -> Result<(), PyErr> {
    match e.detail() {
        Some(detail) if detail.contains(SKIPPABLE) => {
            tracing::warn!(index, "skipping index: {detail}");
            Ok(())
        }
        Some(detail) => Err(PyErr::server(format!(
            "An error occurred while processing index {index}: {detail}"
        ))),
        None => Err(e),
    }
}

/// `get_alerts_generic(search_body, is_host_specific, index_name)` — the
/// `{alerts_summary, success, message}` dict, before its response model.
///
/// `scope` (not in Python, which reads every tenant's indices): a scoped
/// caller's customer codes; only the indices named after one of them are
/// searched (`index_matches_customer`, the rule of `/wazuh_indexer/indices`).
pub async fn get_alerts_generic(
    st: &WazuhState,
    body: &mut AlertsSearchBody,
    host: bool,
    index_name: Option<&str>,
    scope: Option<&[String]>,
) -> Result<Value, PyErr> {
    let indices = collect_indices(st, false).await?;
    let list = match index_name {
        Some(i) => vec![i.to_string()],
        None => scope_indices(st, indices, scope).await?,
    };
    let mut summary = Vec::new();
    for index in &list {
        match collect_alerts_generic(st, index, body, host).await {
            Ok(alerts) => {
                if !alerts.is_empty() {
                    summary.push(json!({
                        "index_name": index,
                        "total_alerts": alerts.len(),
                        "alerts": alerts,
                    }));
                }
            }
            Err(e) => index_failure(index, e)?,
        }
    }
    let message = if summary.is_empty() {
        "No alerts found".to_string()
    } else {
        format!(
            "Succesfully collected top {} alerts for each index",
            body.size
        )
    };
    let success = !summary.is_empty();
    Ok(json!({"alerts_summary": summary, "success": success, "message": message}))
}

/// One `alert["_source"][field]` lookup.
fn source_field(alert: &Value, field: &str) -> Result<Value, PyErr> {
    let source = alert
        .get("_source")
        .ok_or_else(|| index_error(alert, "_source"))?;
    source
        .get(field)
        .cloned()
        .ok_or_else(|| index_error(source, field))
}

/// A tuple element's hash identity (`1 == 1.0 == True`); lists and dicts
/// are unhashable.
fn hash_key(v: &Value) -> Result<String, PyErr> {
    Ok(match v {
        Value::Null => "None".into(),
        Value::Bool(b) => format!("n:{}", i64::from(*b)),
        Value::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 9e15 => format!("n:{}", f as i64),
            _ => format!("n:{n}"),
        },
        Value::String(s) => format!("s:{s}"),
        Value::Array(_) => return Err(PyErr::Other("unhashable type: 'list'".into())),
        Value::Object(_) => return Err(PyErr::Other("unhashable type: 'dict'".into())),
    })
}

/// `collect_and_aggregate_alerts(field_names, search_body)`: the count per
/// value tuple, in first-seen order.
pub async fn collect_and_aggregate(
    st: &WazuhState,
    fields: &[&str],
    body: &mut AlertsSearchBody,
    scope: Option<&[String]>,
) -> Result<Vec<(Vec<Value>, i64)>, PyErr> {
    let indices = collect_indices(st, false).await?;
    let indices = scope_indices(st, indices, scope).await?;
    let mut out: Vec<(Vec<String>, Vec<Value>, i64)> = Vec::new();
    for index in &indices {
        match collect_alerts_generic(st, index, body, false).await {
            Ok(alerts) => {
                for alert in &alerts {
                    let mut values = Vec::with_capacity(fields.len());
                    let mut keys = Vec::with_capacity(fields.len());
                    for f in fields {
                        let v = source_field(alert, f)?;
                        keys.push(hash_key(&v)?);
                        values.push(v);
                    }
                    match out.iter_mut().find(|(k, _, _)| *k == keys) {
                        Some(entry) => entry.2 += 1,
                        None => out.push((keys, values, 1)),
                    }
                }
            }
            Err(e) => index_failure(index, e)?,
        }
    }
    Ok(out.into_iter().map(|(_, v, n)| (v, n)).collect())
}

/// Build one count model (`AlertsByHost(...)`), raising its
/// `ValidationError` as Python does.
pub fn count_item(model: &Model, pairs: Vec<(&str, Value)>) -> Result<Value, PyErr> {
    let input: Map<String, Value> = pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    Ok(pymodel::validate(model, &Value::Object(input))?)
}

/// `parse_timerange` (the Graylog fetch).
fn parse_timerange(timerange: &str) -> Result<String, PyErr> {
    match timerange.chars().last() {
        Some('h' | 'd' | 'w') => time_range_start(timerange),
        _ => Err(PyErr::http(
            400,
            "Invalid timerange unit. Must be one of 'h', 'd', or 'w'.",
        )),
    }
}

/// `get_single_alert_details`: the document, or the `AlertNotFound` stub.
pub async fn single_alert(es: &Es, index: &str, id: &str) -> Result<Value, PyErr> {
    require(&[index, id])?;
    match es
        .perform(Method::GET, &make_path(&[index, "_doc", id]), &[], None)
        .await
    {
        Ok(v) => Ok(v),
        Err(e) if e.is_not_found() => Ok(json!({
            "_index": index,
            "_id": id,
            "_source": {"message": "alert not found"},
        })),
        Err(e) => Err(e.into()),
    }
}

/// The indices a scoped caller may read: those named after one of their
/// customers (`None`: every index).
pub async fn scope_indices(
    st: &WazuhState,
    indices: Vec<String>,
    scope: Option<&[String]>,
) -> Result<Vec<String>, PyErr> {
    let Some(codes) = scope else {
        return Ok(indices);
    };
    let matchers = customer_matchers(&st.ctx.db, codes).await?;
    Ok(indices
        .into_iter()
        .filter(|i| index_matches_customer(i, &matchers))
        .collect())
}

/// Whether a scoped caller may read `index` (`None`: anyone may).
pub async fn index_in_scope(
    st: &WazuhState,
    index: &str,
    scope: Option<&[String]>,
) -> Result<bool, PyErr> {
    let Some(codes) = scope else {
        return Ok(true);
    };
    let matchers = customer_matchers(&st.ctx.db, codes).await?;
    Ok(index_matches_customer(index, &matchers))
}

/// `get_alert_by_id(index_name, alert_id)`.
///
/// An index outside a scoped caller's customers reads as a missing
/// document (the `AlertNotFound` stub), without asking the indexer.
pub async fn alert_by_id(
    st: &WazuhState,
    index: &str,
    id: &str,
    scope: Option<&[String]>,
) -> Result<Value, PyErr> {
    let es = async_client(st).await?;
    let (index, id) = (index.trim(), id.trim());
    if !index_in_scope(st, index, scope).await? {
        require(&[index, id])?;
        return Ok(json!({
            "_index": index,
            "_id": id,
            "_source": {"message": "alert not found"},
        }));
    }
    single_alert(&es, index, id).await
}

/// `get_graylog_alerts(request, index_filter, customer_codes)`.
pub async fn graylog_alerts(
    st: &WazuhState,
    req: &GraylogAlertsSearchBody,
    index_filter: Option<&str>,
    customer_codes: Option<&[String]>,
) -> Result<Vec<Value>, PyErr> {
    // fetch_alerts_from_graylog
    let es = async_client(st).await?;
    let query = json!({
        "size": req.size,
        "query": {"bool": {"must": [{"range": {"timestamp": {
            "gte": parse_timerange(&req.timerange)?,
            "format": "strict_date_optional_time",
        }}}]}},
    });
    let response = es
        .perform(
            Method::POST,
            &make_path(&[&req.index_prefix, "_search"]),
            &[],
            Some(&query),
        )
        .await?;
    let hits = hits(&response)?;
    let es = async_client(st).await?;
    // process_alert_hits
    let mut wanted = Vec::new();
    for hit in &hits {
        let origin = hit.get("_source").and_then(|s| s.get("origin_context"));
        let Some(origin) = origin.filter(|o| truthy(o)) else {
            continue;
        };
        let Some(text) = origin.as_str() else {
            continue;
        };
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        let (index_name, index_id) = (parts[parts.len() - 2], parts[parts.len() - 1]);
        if index_filter.is_some_and(|f| f != index_name) {
            continue;
        }
        wanted.push((index_name.to_string(), index_id.to_string()));
    }
    let details = join_all(wanted.iter().map(|(i, d)| single_alert(&es, i, d))).await;
    let mut grouped: Vec<(String, Vec<Value>)> = Vec::new();
    for detail in details {
        let detail = detail?;
        let index = match detail.get("_index") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => return Err(index_error(&detail, "_index")),
        };
        match grouped.iter_mut().find(|(i, _)| *i == index) {
            Some((_, list)) => list.push(detail),
            None => grouped.push((index, vec![detail])),
        }
    }
    let alerts: Vec<Value> = grouped
        .into_iter()
        .map(|(index, list)| {
            json!({"index_name": index, "total_alerts": list.len(), "alerts": list})
        })
        .collect();
    let Some(codes) = customer_codes else {
        return Ok(alerts);
    };
    if codes.is_empty() {
        return Ok(Vec::new());
    }
    let matchers = customer_matchers(&st.ctx.db, codes).await?;
    if matchers.is_empty() {
        return Ok(Vec::new());
    }
    Ok(alerts
        .into_iter()
        .filter(|a| index_matches_customer(a["index_name"].as_str().unwrap_or_default(), &matchers))
        .collect())
}

/// The `AlertsSearchResponse` validation of an alert summary list (`alerts`
/// must be documents).
pub fn summary_response(
    title: &'static Model,
    summary: Vec<Value>,
    success: bool,
    message: String,
) -> Result<Value, PyErr> {
    let input = json!({"alerts_summary": summary, "success": success, "message": message});
    Ok(pymodel::validate(title, &input)?)
}
