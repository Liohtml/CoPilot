//! Graylog threshold alerts — port of
//! `app/incidents/services/threshold_alert.py` and
//! `app/incidents/config/threshold_index_mapping.py`.
//!
//! A threshold event names no document, so the first event matching its
//! replay query (and group-by values) inside its window stands in for one:
//! its index and id are stored with the alert, its asset field names the
//! asset, and the replay itself is kept (`incident_management_threshold_alert_metadata`)
//! for the alert's timeline.

use chrono::NaiveDateTime;

use copilot_auth::pyvalue::PyValue;
use copilot_wazuh::error::PyErr;

use crate::IngestState;
use crate::es;
use crate::py::{dict_get, strftime_millis};

/// `DEFAULT_TIME_FIELD`.
const DEFAULT_TIME_FIELD: &str = "timestamp";
const NOT_APPLICABLE: &str = "not_applicable";

/// `_parse_env_mapping()`: `THRESHOLD_SOURCE_INDEX_MAPPING`, lower-cased
/// sources, malformed entries skipped.
fn env_mapping(raw: Option<&str>) -> Vec<(String, (String, String))> {
    let raw = raw.map(crate::py::py_strip).unwrap_or_default();
    if raw.is_empty() {
        return Vec::new();
    }
    let Ok(PyValue::Dict(parsed)) = copilot_upstream::json::py_loads(raw) else {
        tracing::warn!(target: "copilot::ingest", "THRESHOLD_SOURCE_INDEX_MAPPING is not a JSON object, ignoring it");
        return Vec::new();
    };
    let mut out: Vec<(String, (String, String))> = Vec::new();
    for (source, value) in parsed {
        let entry = match &value {
            PyValue::Str(s) if !crate::py::py_strip(s).is_empty() => Some((
                crate::py::py_strip(s).to_string(),
                DEFAULT_TIME_FIELD.to_string(),
            )),
            PyValue::List(items) if !items.is_empty() && items[0].truthy() => {
                let pattern = crate::py::py_strip(&items[0].py_str()).to_string();
                let time = match items.get(1) {
                    Some(t) if t.truthy() => crate::py::py_strip(&t.py_str()).to_string(),
                    _ => DEFAULT_TIME_FIELD.to_string(),
                };
                Some((pattern, time))
            }
            _ => None,
        };
        match entry {
            Some(e) => {
                let key = source.to_lowercase();
                match out.iter_mut().find(|(k, _)| *k == key) {
                    Some(slot) => slot.1 = e,
                    None => out.push((key, e)),
                }
            }
            None => tracing::warn!(
                target: "copilot::ingest",
                "Ignoring THRESHOLD_SOURCE_INDEX_MAPPING entry for '{source}'"
            ),
        }
    }
    out
}

/// `get_index_config_for_source(source)`: `(index_pattern, time_field)`,
/// `None` where Python raises its `ValueError`.
pub fn index_config_for_source(st: &IngestState, source: &str) -> Option<(String, String)> {
    let key = source.to_lowercase();
    let mut configured: Vec<(String, (String, String))> = vec![
        (
            "wazuh".into(),
            ("wazuh-*".into(), DEFAULT_TIME_FIELD.into()),
        ),
        (
            "office365".into(),
            ("office365-*".into(), DEFAULT_TIME_FIELD.into()),
        ),
    ];
    for (k, v) in env_mapping(st.env.threshold_source_index_mapping.as_deref()) {
        match configured.iter_mut().find(|(c, _)| *c == k) {
            Some(slot) => slot.1 = v,
            None => configured.push((k, v)),
        }
    }
    if let Some((_, cfg)) = configured.into_iter().find(|(k, _)| *k == key) {
        return Some(cfg);
    }
    let fallback = st
        .env
        .threshold_source_index_fallback_enabled
        .as_deref()
        .unwrap_or("true");
    if matches!(
        crate::py::py_strip(fallback).to_lowercase().as_str(),
        "true" | "1" | "yes"
    ) {
        return Some((format!("{key}-*"), DEFAULT_TIME_FIELD.into()));
    }
    None
}

/// The replay query of a threshold event: its Lucene query, its window and
/// every truthy group-by value.
fn replay_query(
    query: &str,
    time_field: &str,
    start: NaiveDateTime,
    end: NaiveDateTime,
    group_by: &[(String, PyValue)],
) -> PyValue {
    let mut must = vec![
        PyValue::Dict(vec![(
            "query_string".into(),
            PyValue::Dict(vec![
                ("query".into(), PyValue::Str(query.into())),
                ("default_operator".into(), PyValue::Str("AND".into())),
            ]),
        )]),
        PyValue::Dict(vec![(
            "range".into(),
            PyValue::Dict(vec![(
                time_field.into(),
                PyValue::Dict(vec![
                    ("gte".into(), PyValue::Str(strftime_millis(start))),
                    ("lte".into(), PyValue::Str(strftime_millis(end))),
                ]),
            )]),
        )]),
    ];
    for (name, value) in group_by {
        if value.truthy() {
            must.push(PyValue::Dict(vec![(
                "match".into(),
                PyValue::Dict(vec![(name.clone(), value.clone())]),
            )]));
        }
    }
    PyValue::Dict(vec![
        (
            "query".into(),
            PyValue::Dict(vec![(
                "bool".into(),
                PyValue::Dict(vec![("must".into(), PyValue::List(must))]),
            )]),
        ),
        (
            "sort".into(),
            PyValue::List(vec![PyValue::Dict(vec![(
                time_field.into(),
                PyValue::Dict(vec![("order".into(), PyValue::Str("asc".into()))]),
            )])]),
        ),
    ])
}

/// `response["hits"]["hits"]` as it is (`Err`: Python's `KeyError`/`TypeError`).
pub fn hits_of(response: &PyValue) -> Result<PyValue, String> {
    Ok(crate::source::getitem(crate::source::getitem(response, "hits")?, "hits")?.clone())
}

/// `resolve_threshold_event`: `(index, id)` of the first matching event, or
/// the `not_applicable` pair.
pub async fn resolve_threshold_event(
    st: &IngestState,
    query: &str,
    start: NaiveDateTime,
    end: NaiveDateTime,
    group_by: &[(String, PyValue)],
    source: &str,
) -> Result<(String, String), PyErr> {
    let none = || (NOT_APPLICABLE.to_string(), NOT_APPLICABLE.to_string());
    let Some((index_pattern, time_field)) = index_config_for_source(st, source) else {
        return Ok(none());
    };
    let client = es::async_client(st).await?;
    let body = replay_query(query, &time_field, start, end, group_by);
    let response = match es::search(&client, &index_pattern, &body, Some(1), None).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Error resolving threshold event: {e}");
            return Ok(none());
        }
    };
    let first = match hits_of(&response) {
        Ok(PyValue::List(h)) => h.into_iter().next(),
        Ok(other) if !other.truthy() => None,
        Ok(other) => {
            tracing::error!(target: "copilot::ingest", "Error resolving threshold event: hits is a {}", crate::py::type_name(&other));
            return Ok(none());
        }
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Error resolving threshold event: {e}");
            return Ok(none());
        }
    };
    let Some(hit) = first else {
        tracing::warn!(target: "copilot::ingest", "No matching event found for threshold alert in '{index_pattern}'");
        return Ok(none());
    };
    let index = crate::source::getitem(&hit, "_index").cloned();
    let id = crate::source::getitem(&hit, "_id").cloned();
    match (index, id) {
        (Ok(PyValue::Str(i)), Ok(PyValue::Str(d))) => Ok((i, d)),
        (Ok(i), Ok(d)) => Ok((i.py_str(), d.py_str())),
        (Err(e), _) | (_, Err(e)) => {
            tracing::error!(target: "copilot::ingest", "Error resolving threshold event: {e}");
            Ok(none())
        }
    }
}

/// The resolved index/id as the route holds them (`str` in Python: a
/// non-string `_index` would be the value itself; this keeps its text).
pub fn is_resolved(index: &str, id: &str) -> bool {
    index != NOT_APPLICABLE && id != NOT_APPLICABLE
}

/// `resolve_threshold_asset`: the first configured asset field holding a
/// truthy value in the resolved document, else `"No asset found"`.
pub async fn resolve_threshold_asset(
    st: &IngestState,
    index: &str,
    id: &str,
    source: &str,
) -> Result<PyValue, PyErr> {
    let no_asset = || PyValue::Str("No asset found".into());
    if !is_resolved(index, id) {
        return Ok(no_asset());
    }
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT incident_management_assetfieldname.field_name \
         FROM incident_management_assetfieldname WHERE incident_management_assetfieldname.source = ?",
    )
    .bind(source)
    .fetch_all(st.ctx.db.pool())
    .await?;
    let Some(asset_field) = names.into_iter().next().filter(|n| !n.is_empty()) else {
        tracing::warn!(target: "copilot::ingest", "No asset field name configured for source '{source}'");
        return Ok(no_asset());
    };
    let candidates: Vec<String> = asset_field
        .split(',')
        .map(|f| crate::py::py_strip(f).to_string())
        .collect();
    let client = es::async_client(st).await?;
    let doc = match es::get(&client, index, id).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Error fetching event for asset resolution: {e}");
            return Ok(no_asset());
        }
    };
    // `doc.get("_source", {})`.
    let source_doc = match &doc {
        PyValue::Dict(d) => dict_get(d, "_source")
            .cloned()
            .unwrap_or(PyValue::Dict(Vec::new())),
        _ => return Ok(no_asset()),
    };
    for field in &candidates {
        let found = match &source_doc {
            PyValue::Dict(d) => dict_get(d, field).cloned(),
            PyValue::Str(s) if s.contains(field.as_str()) => {
                // `field in "<str>"` is a substring test; `"<str>"[field]`
                // is then a TypeError.
                return Ok(no_asset());
            }
            _ => None,
        };
        if let Some(v) = found.filter(PyValue::truthy) {
            return Ok(v);
        }
    }
    Ok(no_asset())
}

/// `save_threshold_metadata`.
#[allow(clippy::too_many_arguments)]
pub async fn save_threshold_metadata(
    st: &IngestState,
    alert_id: i64,
    event_definition_id: &str,
    replay_query: &str,
    start: NaiveDateTime,
    end: NaiveDateTime,
    group_by: &[(String, PyValue)],
    source_streams: &[String],
    source: &str,
    resolved_index: &str,
    resolved_id: &str,
) -> Result<(), PyErr> {
    let streams = PyValue::List(source_streams.iter().cloned().map(PyValue::Str).collect());
    sqlx::query(
        "INSERT INTO incident_management_threshold_alert_metadata (alert_id, event_definition_id, \
         replay_query, timerange_start, timerange_end, group_by_fields, source_streams, source, \
         resolved_index_name, resolved_index_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(alert_id)
    .bind(event_definition_id)
    .bind(replay_query)
    .bind(copilot_core::time::mysql_datetime(start))
    .bind(copilot_core::time::mysql_datetime(end))
    .bind(crate::py::dumps_compact_allow_nan(&PyValue::Dict(
        group_by.to_vec(),
    )))
    .bind(crate::py::dumps_compact_allow_nan(&streams))
    .bind(source)
    .bind(resolved_index)
    .bind(resolved_id)
    .execute(st.ctx.db.pool())
    .await?;
    Ok(())
}

/// A stored threshold replay.
#[derive(Debug, Clone, sqlx::FromRow)]
struct Metadata {
    replay_query: String,
    timerange_start: NaiveDateTime,
    timerange_end: NaiveDateTime,
    group_by_fields: Option<sqlx::types::Json<serde_json::Value>>,
    source: String,
}

const METADATA_COLS: &str = "replay_query, timerange_start, timerange_end, group_by_fields, source";

/// `retrieve_threshold_alert_timeline`: `None` when the alert is no
/// threshold alert; the replay's first 50 events otherwise (`[]` on any
/// failure).
pub async fn threshold_timeline(
    st: &IngestState,
    alert_id: Option<i64>,
    index_name: &str,
    index_id: &str,
) -> Result<Option<PyValue>, PyErr> {
    let mut metadata: Option<Metadata> = None;
    if let Some(id) = alert_id {
        let rows: Vec<Metadata> = sqlx::query_as(&format!(
            "SELECT {METADATA_COLS} FROM incident_management_threshold_alert_metadata WHERE alert_id = ?"
        ))
        .bind(id)
        .fetch_all(st.ctx.db.pool())
        .await?;
        metadata = rows.into_iter().next();
    }
    if metadata.is_none() {
        let rows: Vec<Metadata> = sqlx::query_as(&format!(
            "SELECT {METADATA_COLS} FROM incident_management_threshold_alert_metadata \
             WHERE resolved_index_name = ? AND resolved_index_id = ?"
        ))
        .bind(index_name)
        .bind(index_id)
        .fetch_all(st.ctx.db.pool())
        .await?;
        metadata = rows.into_iter().next();
    }
    let Some(m) = metadata else {
        return Ok(None);
    };
    let Some((index_pattern, time_field)) = index_config_for_source(st, &m.source) else {
        tracing::warn!(target: "copilot::ingest", "Cannot retrieve threshold timeline: source '{}' is not mapped", m.source);
        return Ok(Some(PyValue::List(Vec::new())));
    };
    let client = es::async_client(st).await?;
    // `metadata.group_by_fields or {}`, then `.items()`.
    let group_by = match m.group_by_fields.map(|j| crate::py::to_py(&j.0)) {
        Some(PyValue::Dict(d)) => d,
        Some(v) if v.truthy() => return Ok(Some(PyValue::List(Vec::new()))),
        _ => Vec::new(),
    };
    let body = replay_query(
        &m.replay_query,
        &time_field,
        m.timerange_start,
        m.timerange_end,
        &group_by,
    );
    match es::search(&client, &index_pattern, &body, Some(50), None).await {
        Ok(r) => Ok(Some(hits_of(&r).unwrap_or(PyValue::List(Vec::new())))),
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Error fetching threshold alert timeline: {e}");
            Ok(Some(PyValue::List(Vec::new())))
        }
    }
}
