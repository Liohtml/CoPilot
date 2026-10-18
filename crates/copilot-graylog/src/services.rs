//! Port of `app/connectors/graylog/services/` (collector, events,
//! management, monitoring, pipelines, streams), statement by statement:
//! the same requests in the same order, the same subscripts, and the same
//! `try`/`except` structure — which exception becomes which answer is part
//! of the contract (`Failed to collect streams key: 'total'`, a Pydantic
//! `ValidationError` as the `ValueError` handler's 400, …).
//!
//! Every function returns the response model's JSON-mode dump.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Model, construct, construct_star, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, get, getitem, iterate, type_name};
use copilot_web::form::py_strip;

use crate::client::GraylogClient;
use crate::schema::*;

const COLLECTOR: &str = "app.connectors.graylog.schema.collector";
const EVENTS: &str = "app.connectors.graylog.schema.events";
const PIPELINES: &str = "app.connectors.graylog.schema.pipelines";
const STREAMS: &str = "app.connectors.graylog.schema.streams";

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn t() -> PyValue {
    PyValue::Bool(true)
}

/// `except KeyError as e: raise HTTPException(500, key(e))` then
/// `except Exception as e: raise HTTPException(500, other(e))`.
fn key_or_other(e: PyExc, key: &str, other: &str) -> PyExc {
    match e {
        PyExc::KeyError(k) => PyExc::http(500, format!("{key}: {k}")),
        e => PyExc::http(500, format!("{other}: {}", e.display())),
    }
}

/// `[Model(**item) for item in value]`.
fn each_star(model: &'static Model, qualname: &str, value: &PyValue) -> PyResult<Vec<PyValue>> {
    iterate(value)?
        .iter()
        .map(|item| construct_star(model, &format!("{qualname}.{}", model.name), item))
        .collect()
}

// --- collector -----------------------------------------------------------

/// `get_indices_full()`.
pub async fn indices_full(c: &GraylogClient) -> PyResult<PyValue> {
    let reply = c.get("/api/system/indexer/indices", &[]).await?;
    let indices_data = getitem(&reply.data, "all")
        .and_then(|all| getitem(all, "indices"))
        .map_err(|e| match e {
            PyExc::KeyError(_) => PyExc::http(500, "Failed to collect indices key"),
            other => other,
        })?
        .clone();
    let items = match &indices_data {
        PyValue::Dict(entries) => entries
            .iter()
            .map(|(name, info)| {
                construct(
                    &GRAYLOG_INDEX_ITEM,
                    &kwargs(vec![("index_name", s(name)), ("index_info", info.clone())]),
                )
            })
            .collect::<PyResult<Vec<_>>>()?,
        PyValue::List(entries) => entries
            .iter()
            .map(|index| {
                let name = getitem(index, "index_name")?.clone();
                construct(
                    &GRAYLOG_INDEX_ITEM,
                    &kwargs(vec![("index_name", name), ("index_info", index.clone())]),
                )
            })
            .collect::<PyResult<Vec<_>>>()?,
        _ => return Err(PyExc::http(500, "Unexpected format for indices data")),
    };
    construct(
        &GRAYLOG_INDICES_RESPONSE,
        &kwargs(vec![
            ("indices", PyValue::List(items)),
            ("success", t()),
            ("message", s("Indices collected successfully")),
        ]),
    )
}

/// `get_index_names()`.
pub async fn index_names(c: &GraylogClient) -> PyResult<Vec<String>> {
    let full = indices_full(c).await?;
    Ok(match field(&full, "indices") {
        PyValue::List(items) => items
            .iter()
            .filter_map(|i| field(i, "index_name").as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    })
}

/// `fetch_configured_inputs()`.
async fn configured_inputs(c: &GraylogClient) -> PyResult<Vec<PyValue>> {
    let reply = c.get("/api/system/inputs", &[]).await?;
    each_star(
        &CONFIGURED_INPUT,
        COLLECTOR,
        getitem(&reply.data, "inputs")?,
    )
}

/// `fetch_running_inputs()`.
async fn running_inputs(c: &GraylogClient) -> PyResult<Vec<PyValue>> {
    let reply = c.get("/api/system/inputstates", &[]).await?;
    each_star(&RUNNING_INPUT, COLLECTOR, getitem(&reply.data, "states")?)
}

/// `get_inputs()`.
pub async fn inputs(c: &GraylogClient) -> PyResult<PyValue> {
    let configured = configured_inputs(c).await?;
    let running = running_inputs(c).await?;
    construct(
        &GRAYLOG_INPUTS_RESPONSE,
        &kwargs(vec![
            ("configured_inputs", PyValue::List(configured)),
            ("running_inputs", PyValue::List(running)),
            ("success", t()),
            ("message", s("Successfully retrieved inputs")),
        ]),
    )
}

/// `get_inputs_running()`.
pub async fn inputs_running(c: &GraylogClient) -> PyResult<PyValue> {
    let running = running_inputs(c).await?;
    construct(
        &RUNNING_INPUTS_RESPONSE,
        &kwargs(vec![
            ("running_inputs", PyValue::List(running)),
            ("success", t()),
            ("message", s("Successfully retrieved running inputs")),
        ]),
    )
}

/// `get_inputs_configured()`.
pub async fn inputs_configured(c: &GraylogClient) -> PyResult<PyValue> {
    let configured = configured_inputs(c).await?;
    construct(
        &CONFIGURED_INPUTS_RESPONSE,
        &kwargs(vec![
            ("configured_inputs", PyValue::List(configured)),
            ("success", t()),
            ("message", s("Successfully retrieved configured inputs")),
        ]),
    )
}

/// `get_input_ids()`.
pub async fn input_ids(c: &GraylogClient) -> PyResult<Vec<String>> {
    Ok(configured_inputs(c)
        .await?
        .iter()
        .filter_map(|i| field(i, "id").as_str().map(str::to_string))
        .collect())
}

// --- events --------------------------------------------------------------

/// Python's `int >= value` for a `json.loads` value.
fn int_ge(left: usize, right: &PyValue) -> PyResult<bool> {
    let l = left as f64;
    match right {
        PyValue::Int(i) => Ok(match i.parse::<i128>() {
            Ok(r) => (left as i128) >= r,
            // Beyond i128: only the sign matters.
            Err(_) => i.starts_with('-'),
        }),
        PyValue::Float(f) => Ok(l >= *f),
        PyValue::Bool(b) => Ok(left >= usize::from(*b)),
        other => Err(PyExc::TypeError(format!(
            "'>=' not supported between instances of 'int' and '{}'",
            type_name(other)
        ))),
    }
}

/// `get_event_definitions()`: every page of `/api/events/definitions`.
pub async fn event_definitions(c: &GraylogClient) -> PyResult<PyValue> {
    event_definitions_on(c, crate::client::DEFAULT_CONNECTOR).await
}

/// `get_event_definitions()` under a Graylog context (`set_graylog_context`):
/// the same pages from `connector`.
pub async fn event_definitions_on(c: &GraylogClient, connector: &str) -> PyResult<PyValue> {
    let mut all: Vec<PyValue> = Vec::new();
    let mut page: u64 = 1;
    loop {
        let reply = c
            .get_on(
                connector,
                "/api/events/definitions",
                &[("per_page", "500".to_string()), ("page", page.to_string())],
            )
            .await?;
        let data = &reply.data;
        let batch = getitem(data, "event_definitions").map_err(|e| match e {
            PyExc::KeyError(_) => PyExc::http(500, "Failed to collect event definitions key"),
            other => other,
        })?;
        all.extend(iterate(batch)?);
        let total = get(data, "total")?.filter(|v| !matches!(v, PyValue::None));
        let done = match total {
            None => !batch.truthy(),
            Some(total) => int_ge(all.len(), total)? || !batch.truthy(),
        };
        // Python would loop for ever on a Graylog that never reaches its
        // own total; stop after ten million definitions' worth of pages.
        if done || page >= 20_000 {
            break;
        }
        page += 1;
    }
    let definitions = all
        .iter()
        .map(|d| construct_star(&EVENT_DEFINITION, &format!("{EVENTS}.EventDefinition"), d))
        .collect::<PyResult<Vec<_>>>()?;
    construct(
        &GRAYLOG_EVENT_DEFINITIONS_RESPONSE,
        &kwargs(vec![
            ("event_definitions", PyValue::List(definitions)),
            ("success", t()),
            ("message", s("Event definitions collected successfully")),
        ]),
    )
}

/// `get_alerts(alert_query)`: `alert_query` is the validated `AlertQuery`.
pub async fn alerts(c: &GraylogClient, alert_query: PyValue) -> PyResult<PyValue> {
    let reply = c.post("/api/events/search", Some(alert_query)).await?;
    let raw = &reply.data;
    let events = each_star(&ALERT_EVENT, EVENTS, getitem(raw, "events")?)?;
    let context = construct_star(
        &CONTEXT,
        &format!("{EVENTS}.Context"),
        getitem(raw, "context")?,
    )?;
    let duration = getitem(raw, "duration")?.clone();
    let parameters = construct_star(
        &PARAMETERS,
        &format!("{EVENTS}.Parameters"),
        getitem(raw, "parameters")?,
    )?;
    let total_events = getitem(raw, "total_events")?.clone();
    let used_indices = getitem(raw, "used_indices")?.clone();
    let alerts = construct(
        &ALERTS,
        &kwargs(vec![
            ("context", context),
            ("duration", duration),
            ("events", PyValue::List(events)),
            ("parameters", parameters),
            ("total_events", total_events),
            ("used_indices", used_indices),
        ]),
    )?;
    construct(
        &GRAYLOG_ALERTS_RESPONSE,
        &kwargs(vec![
            ("alerts", alerts),
            ("message", s("Successfully collected alerts")),
            ("success", t()),
        ]),
    )
}

// --- management ----------------------------------------------------------

/// `get_url_whitelist_entries()`.
pub async fn url_whitelist_entries(c: &GraylogClient) -> PyResult<PyValue> {
    let reply = c.url_allowlist().await?;
    construct(
        &URL_WHITELIST_ENTRY_RESPONSE,
        &kwargs(vec![
            ("url_whitelist_entries", reply.data),
            ("success", t()),
            ("message", s("URL whitelist entries collected successfully")),
        ]),
    )
}

fn success_message(success: bool, message: String) -> PyResult<PyValue> {
    construct(
        &SUCCESS_MESSAGE,
        &kwargs(vec![
            ("success", PyValue::Bool(success)),
            ("message", PyValue::Str(message)),
        ]),
    )
}

/// `verify_index_name`: the stripped name, if Graylog manages it.
pub async fn verify_index_name(c: &GraylogClient, raw: &str) -> PyResult<String> {
    let name = py_strip(raw).to_string();
    if !index_names(c).await?.contains(&name) {
        return Err(PyExc::http(
            400,
            format!("Index name '{name}' is not managed by Graylog or no longer exists."),
        ));
    }
    Ok(name)
}

/// `delete_index(index_name)`.
pub async fn delete_index(c: &GraylogClient, name: &str) -> PyResult<PyValue> {
    c.delete(&format!("/api/system/indexer/indices/{name}"), &[])
        .await?;
    if index_names(c).await?.iter().any(|n| n == name) {
        success_message(
            false,
            format!(
                "Failed to delete index {name}. If the index is still in use, it cannot be deleted."
            ),
        )
    } else {
        success_message(true, format!("Successfully deleted index {name}"))
    }
}

/// `verify_input_id`.
pub async fn verify_input_id(c: &GraylogClient, raw: &str) -> PyResult<String> {
    let id = py_strip(raw).to_string();
    if !input_ids(c).await?.contains(&id) {
        return Err(PyExc::http(
            400,
            format!("Input ID '{id}' is not managed by Graylog or no longer exists."),
        ));
    }
    Ok(id)
}

/// `stop_input(input_id)`.
pub async fn stop_input(c: &GraylogClient, id: &str) -> PyResult<PyValue> {
    let reply = c
        .delete(&format!("/api/system/inputstates/{id}"), &[])
        .await?;
    if reply.success {
        success_message(true, format!("Successfully stopped input {id}"))
    } else {
        success_message(false, format!("Failed to stop input {id}"))
    }
}

/// `start_input(input_id)`.
pub async fn start_input(c: &GraylogClient, id: &str) -> PyResult<PyValue> {
    let reply = c
        .put(&format!("/api/system/inputstates/{id}"), None)
        .await?
        .ok_or_else(|| PyExc::TypeError("'NoneType' object is not subscriptable".into()))?;
    if reply.success {
        success_message(true, format!("Successfully started input {id}"))
    } else {
        success_message(false, format!("Failed to start input {id}"))
    }
}

/// `get_stream_ids()`.
pub async fn stream_ids(c: &GraylogClient) -> PyResult<Vec<String>> {
    let reply = c.get("/api/streams", &[]).await?;
    let ids = (|| -> PyResult<Vec<PyValue>> {
        iterate(getitem(&reply.data, "streams")?)?
            .iter()
            .map(|stream| getitem(stream, "id").cloned())
            .collect()
    })()
    .map_err(|e| {
        key_or_other(
            e,
            "Failed to collect streams key",
            "Failed to collect streams",
        )
    })?;
    Ok(ids
        .iter()
        .filter_map(|id| id.as_str().map(str::to_string))
        .collect())
}

/// `verify_stream_id`: the stripped id, if it names a Graylog stream.
pub async fn verify_stream_id(c: &GraylogClient, raw: &str) -> PyResult<String> {
    let id = py_strip(raw).to_string();
    if !stream_ids(c).await?.contains(&id) {
        return Err(PyExc::http(
            400,
            format!("Stream ID '{id}' is not managed by Graylog or no longer exists."),
        ));
    }
    Ok(id)
}

/// `stop_stream(stream_id)` (`pause`).
pub async fn stop_stream(c: &GraylogClient, id: &str) -> PyResult<PyValue> {
    let reply = c.post(&format!("/api/streams/{id}/pause"), None).await?;
    if reply.success {
        success_message(true, format!("Successfully stopped stream {id}"))
    } else {
        success_message(false, format!("Failed to stop stream {id}"))
    }
}

/// `start_stream(stream_id)` (`resume`).
pub async fn start_stream(c: &GraylogClient, id: &str) -> PyResult<PyValue> {
    let reply = c.post(&format!("/api/streams/{id}/resume"), None).await?;
    if reply.success {
        success_message(true, format!("Successfully started stream {id}"))
    } else {
        success_message(false, format!("Failed to start stream {id}"))
    }
}

// --- monitoring ----------------------------------------------------------

/// `get_messages(page_number)`.
pub async fn messages(c: &GraylogClient, page_number: &str) -> PyResult<PyValue> {
    let reply = c
        .get("/api/system/messages", &[("page", page_number.to_string())])
        .await?;
    (|| -> PyResult<PyValue> {
        let data = &reply.data;
        let mut list = Vec::new();
        for message in iterate(getitem(data, "messages")?)? {
            let caller = getitem(&message, "caller")?.clone();
            let content = getitem(&message, "content")?.clone();
            let node_id = getitem(&message, "node_id")?.clone();
            let timestamp = getitem(&message, "timestamp")?.clone();
            list.push(construct(
                &GRAYLOG_MESSAGES,
                &kwargs(vec![
                    ("caller", caller),
                    ("content", content),
                    ("node_id", node_id),
                    ("timestamp", timestamp),
                ]),
            )?);
        }
        let total = getitem(data, "total")?.clone();
        construct(
            &GRAYLOG_MESSAGES_RESPONSE,
            &kwargs(vec![
                ("graylog_messages", PyValue::List(list)),
                ("success", t()),
                ("message", s("Messages collected successfully")),
                ("total_messages", total),
            ]),
        )
    })()
    .map_err(|e| {
        key_or_other(
            e,
            "Failed to collect messages key",
            "Failed to collect messages",
        )
    })
}

/// `{**a, **b}` for `json.loads` values.
fn merge_mappings(a: &PyValue, b: &PyValue) -> PyResult<Vec<(String, PyValue)>> {
    let mut out: Vec<(String, PyValue)> = Vec::new();
    for part in [a, b] {
        let PyValue::Dict(items) = part else {
            return Err(PyExc::TypeError(format!(
                "'{}' object is not a mapping",
                type_name(part)
            )));
        };
        for (k, v) in items {
            match out.iter_mut().find(|(key, _)| key == k) {
                Some(slot) => slot.1 = v.clone(),
                None => out.push((k.clone(), v.clone())),
            }
        }
    }
    Ok(out)
}

/// `get_metrics()`: `/api/system/metrics` and `/api/system/journal`,
/// concurrently (`asyncio.gather`; when both fail, the metrics error is the
/// one reported).
pub async fn metrics(c: &GraylogClient) -> PyResult<PyValue> {
    let (throughput, journal) = tokio::join!(
        c.get("/api/system/metrics", &[]),
        c.get("/api/system/journal", &[])
    );
    let throughput = throughput?;
    let journal = journal?;
    (|| -> PyResult<PyValue> {
        let gauges = getitem(&throughput.data, "gauges")?;
        let counters = getitem(&throughput.data, "counters")?;
        let merged = merge_mappings(gauges, counters)?;
        let mut list = Vec::new();
        for (name, data) in &merged {
            if !THROUGHPUT_METRIC_NAMES.contains(&name.as_str()) {
                continue;
            }
            let value = get(data, "value")?
                .cloned()
                .unwrap_or_else(|| PyValue::Int("0".into()));
            list.push(construct(
                &GRAYLOG_THROUGHPUT_METRICS,
                &kwargs(vec![("metric", s(name)), ("value", value)]),
            )?);
        }
        let entries = construct(
            &GRAYLOG_UNCOMMITTED_JOURNAL_ENTRIES,
            &kwargs(vec![(
                "uncommitted_journal_entries",
                getitem(&journal.data, "uncommitted_journal_entries")?.clone(),
            )]),
        )?;
        construct(
            &GRAYLOG_METRICS_RESPONSE,
            &kwargs(vec![
                ("throughput_metrics", PyValue::List(list)),
                (
                    "uncommitted_journal_entries",
                    field(&entries, "uncommitted_journal_entries").clone(),
                ),
                ("success", t()),
                ("message", s("Metrics collected successfully")),
            ]),
        )
    })()
    .map_err(|e| {
        key_or_other(
            e,
            "Failed to collect metrics key",
            "Failed to collect metrics",
        )
    })
}

/// `get_event_notifications()`.
pub async fn event_notifications(c: &GraylogClient) -> PyResult<PyValue> {
    let reply = c.get("/api/events/notifications", &[]).await?;
    construct(
        &GRAYLOG_EVENT_NOTIFICATIONS_RESPONSE,
        &kwargs(vec![
            ("event_notifications", reply.data),
            ("success", t()),
            ("message", s("Event notifications collected successfully")),
        ]),
    )
    .map_err(|e| {
        key_or_other(
            e,
            "Failed to collect event notifications key",
            "Failed to collect event notifications",
        )
    })
}

// --- pipelines -----------------------------------------------------------

/// `get_pipelines()`.
pub async fn pipelines(c: &GraylogClient) -> PyResult<PyValue> {
    pipelines_on(c, crate::client::DEFAULT_CONNECTOR).await
}

/// `get_pipelines()` under a Graylog context (`set_graylog_context`): the
/// pipelines of `connector`.
pub async fn pipelines_on(c: &GraylogClient, connector: &str) -> PyResult<PyValue> {
    let reply = c
        .get_on(connector, "/api/system/pipelines/pipeline", &[])
        .await?;
    (|| -> PyResult<PyValue> {
        let list = each_star(&PIPELINE, PIPELINES, &reply.data)?;
        construct(
            &GRAYLOG_PIPELINES_RESPONSE,
            &kwargs(vec![
                ("pipelines", PyValue::List(list)),
                ("success", t()),
                ("message", s("Pipelines collected successfully")),
            ]),
        )
    })()
    .map_err(|e| {
        key_or_other(
            e,
            "Failed to collect pipelines key",
            "Failed to collect pipelines",
        )
    })
}

/// `get_pipeline_rules()`.
pub async fn pipeline_rules(c: &GraylogClient) -> PyResult<PyValue> {
    let reply = c.get("/api/system/pipelines/rule", &[]).await?;
    (|| -> PyResult<PyValue> {
        let list = each_star(&PIPELINE_RULE, PIPELINES, &reply.data)?;
        construct(
            &PIPELINE_RULES_RESPONSE,
            &kwargs(vec![
                ("pipeline_rules", PyValue::List(list)),
                ("success", t()),
                ("message", s("Pipeline rules collected successfully")),
            ]),
        )
    })()
    .map_err(|e| {
        key_or_other(
            e,
            "Failed to collect pipeline rules key",
            "Failed to collect pipeline rules",
        )
    })
}

/// `get_pipeline_rule_by_id(rule_id)`.
pub async fn pipeline_rule_by_id(c: &GraylogClient, rule_id: &str) -> PyResult<PyValue> {
    let reply = c
        .get(&format!("/api/system/pipelines/rule/{rule_id}"), &[])
        .await?;
    (|| -> PyResult<PyValue> {
        let rule = construct_star(
            &PIPELINE_RULE,
            &format!("{PIPELINES}.PipelineRule"),
            &reply.data,
        )?;
        construct(
            &PIPELINE_RULES_RESPONSE,
            &kwargs(vec![
                ("pipeline_rules", PyValue::List(vec![rule])),
                ("success", t()),
                ("message", s("Pipeline rules collected successfully")),
            ]),
        )
    })()
    .map_err(|e| {
        key_or_other(
            e,
            "Failed to collect pipeline rules key",
            "Failed to collect pipeline rules",
        )
    })
}

/// `GET /pipeline/full`: the pipelines with each stage's rule ids, looked up
/// by rule title (the last rule of a title wins; an unknown title is `None`).
pub async fn pipelines_with_rule_ids(c: &GraylogClient) -> PyResult<PyValue> {
    let pipelines = pipelines(c).await?;
    let rules = pipeline_rules(c).await?;
    let mut title_to_id: Vec<(String, PyValue)> = Vec::new();
    if let PyValue::List(items) = field(&rules, "pipeline_rules") {
        for rule in items {
            let title = field(rule, "title").py_str();
            let id = field(rule, "id").clone();
            match title_to_id.iter_mut().find(|(t, _)| *t == title) {
                Some(slot) => slot.1 = id,
                None => title_to_id.push((title, id)),
            }
        }
    }
    let mut out = Vec::new();
    if let PyValue::List(items) = field(&pipelines, "pipelines") {
        for pipeline in items {
            let mut stages = Vec::new();
            if let PyValue::List(stage_items) = field(pipeline, "stages") {
                for stage in stage_items {
                    let mut rule_ids = Vec::new();
                    if let PyValue::List(rules) = field(stage, "rules") {
                        for title in rules {
                            let title = title.py_str();
                            rule_ids.push(
                                title_to_id
                                    .iter()
                                    .find(|(t, _)| *t == title)
                                    .map_or(PyValue::None, |(_, id)| id.clone()),
                            );
                        }
                    }
                    let mut kw = match stage {
                        PyValue::Dict(items) => items.clone(),
                        _ => Vec::new(),
                    };
                    kw.push(("rule_ids".into(), PyValue::List(rule_ids)));
                    stages.push(construct(&STAGE_WITH_RULE_ID, &PyValue::Dict(kw))?);
                }
            }
            let mut dict = match pipeline {
                PyValue::Dict(items) => items.clone(),
                _ => Vec::new(),
            };
            if let Some(slot) = dict.iter_mut().find(|(k, _)| k == "stages") {
                slot.1 = PyValue::List(stages);
            }
            out.push(construct(&PIPELINE_WITH_RULE_ID, &PyValue::Dict(dict))?);
        }
    }
    construct(
        &GRAYLOG_PIPELINES_RESPONSE_WITH_RULE_ID,
        &kwargs(vec![
            ("pipelines", PyValue::List(out)),
            ("success", field(&pipelines, "success").clone()),
            ("message", field(&pipelines, "message").clone()),
        ]),
    )
}

// --- streams -------------------------------------------------------------

/// `get_streams()`.
pub async fn streams(c: &GraylogClient) -> PyResult<PyValue> {
    let reply = c.get("/api/streams", &[]).await?;
    (|| -> PyResult<PyValue> {
        let data = &reply.data;
        let list = each_star(&STREAM, STREAMS, getitem(data, "streams")?)?;
        let total = getitem(data, "total")?.clone();
        construct(
            &GRAYLOG_STREAMS_RESPONSE,
            &kwargs(vec![
                ("streams", PyValue::List(list)),
                ("success", t()),
                ("message", s("Streams collected successfully")),
                ("total", total),
            ]),
        )
    })()
    .map_err(|e| {
        key_or_other(
            e,
            "Failed to collect streams key",
            "Failed to collect streams",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn mapping_merge_keeps_first_positions() {
        let a = loads(r#"{"x": 1, "y": 2}"#).unwrap();
        let b = loads(r#"{"y": 3, "z": 4}"#).unwrap();
        let merged = merge_mappings(&a, &b).unwrap();
        assert_eq!(PyValue::Dict(merged).py_repr(), "{'x': 1, 'y': 3, 'z': 4}");
        assert_eq!(
            merge_mappings(&PyValue::List(vec![]), &b)
                .unwrap_err()
                .text(),
            "'list' object is not a mapping"
        );
    }

    #[test]
    fn comparisons_raise_like_python() {
        assert!(int_ge(3, &PyValue::Int("3".into())).unwrap());
        assert!(!int_ge(2, &PyValue::Float(2.5)).unwrap());
        assert!(
            int_ge(
                2,
                &PyValue::Int("-99999999999999999999999999999999999".into())
            )
            .unwrap()
        );
        assert_eq!(
            int_ge(1, &PyValue::Str("3".into())).unwrap_err().text(),
            "'>=' not supported between instances of 'int' and 'str'"
        );
    }
}
