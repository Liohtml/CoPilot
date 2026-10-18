//! Alerts from Graylog events — port of
//! `app/incidents/services/alert_collection.py`, `POST /create/auto` and the
//! `invoke_alert_creation_collect` job.
//!
//! Graylog writes an event for every alert definition into its
//! `gl-events*` indices with `fields.COPILOT_ALERT_ID = "NONE"`; each event's
//! `origin_context` names the document that fired it. The collector takes
//! the oldest unstamped events, creates (or merges) the alert for each
//! document and stamps the event with the CoPilot id, in batches of 100, at
//! most ten batches a run.

use serde_json::{Value, json};

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty, validate};
use copilot_wazuh::error::PyErr;

use crate::IngestState;
use crate::create::create_alert;
use crate::es;
use crate::py::{dict_get, dict_set};

const OPT_STR: Ty = Ty::Nullable(&Ty::Str);

static FIELDS: Model = Model::new(
    "Fields",
    &[
        Field::opt("ALERT_ID", OPT_STR),
        Field::opt("ALERT_SOURCE", OPT_STR),
        Field::opt("CUSTOMER_CODE", OPT_STR),
        Field::opt("COPILOT_ALERT_ID", OPT_STR),
    ],
);

fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

static SOURCE: Model = Model::new(
    "Source",
    &[
        Field::req("id", Ty::Str),
        Field::req("event_definition_type", Ty::Str),
        Field::req("event_definition_id", Ty::Str),
        Field::req("origin_context", Ty::Str),
        Field::req("timestamp", Ty::Str),
        Field::req("timestamp_processing", Ty::Str),
        Field::opt("timerange_start", OPT_STR),
        Field::opt("timerange_end", OPT_STR),
        Field::req("streams", Ty::List(&Ty::Str)),
        Field::req("source_streams", Ty::List(&Ty::Str)),
        Field::req("message", Ty::Str),
        Field::req("source", Ty::Str),
        Field::req("key_tuple", Ty::List(&Ty::Str)),
        Field::req("key", Ty::Str),
        Field::req("priority", Ty::Int),
        Field::req("alert", Ty::Bool),
        Field::req("fields", Ty::Model(&FIELDS)),
        Field::def("group_by_fields", Ty::Dict(&Ty::Any), empty_dict),
        Field::opt("original_alert_id", OPT_STR),
        Field::opt("original_alert_index_name", OPT_STR),
    ],
);

static ALERT_PAYLOAD_ITEM: Model = Model::new(
    "AlertPayloadItem",
    &[
        Field::req("index", Ty::Str).alias("_index"),
        Field::req("id", Ty::Str).alias("_id"),
        Field::opt("score", Ty::Nullable(&Ty::Float)).alias("_score"),
        Field::req("source", Ty::Model(&SOURCE)).alias("_source"),
    ],
);

/// One Graylog event to collect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventItem {
    /// `_index` (the `gl-events` index).
    pub index: String,
    /// `_id`.
    pub id: String,
    /// `_source.origin_context`.
    pub origin_context: String,
}

/// `Source.extract_origin_context` (`mode="before"`): a six-part
/// `origin_context` names the document.
fn with_origin_parts(hit: &PyValue) -> PyValue {
    let PyValue::Dict(items) = hit else {
        return hit.clone();
    };
    let mut items = items.clone();
    if let Some(PyValue::Dict(source)) = dict_get(&items, "_source").cloned() {
        let mut source = source;
        let origin = dict_get(&source, "origin_context").cloned();
        let parts: Option<Vec<String>> = match origin {
            None => Some(vec![String::new()]),
            Some(PyValue::Str(s)) => Some(s.split(':').map(str::to_string).collect()),
            Some(_) => None,
        };
        if let Some(parts) = parts {
            if parts.len() == 6 {
                dict_set(
                    &mut source,
                    "original_alert_id",
                    PyValue::Str(parts[5].clone()),
                );
                dict_set(
                    &mut source,
                    "original_alert_index_name",
                    PyValue::Str(parts[4].clone()),
                );
            }
        }
        dict_set(&mut items, "_source", PyValue::Dict(source));
    }
    PyValue::Dict(items)
}

/// `[AlertPayloadItem(**hit) for hit in hits]`; `None` when one fails.
fn items_of(hits: &[PyValue]) -> Option<Vec<EventItem>> {
    let mut out = Vec::new();
    for hit in hits {
        if !matches!(hit, PyValue::Dict(_)) {
            return None;
        }
        let dump = validate(&ALERT_PAYLOAD_ITEM, &with_origin_parts(hit)).ok()?;
        let s = |v: &PyValue| v.as_str().unwrap_or_default().to_string();
        let source = dump.get("_source")?;
        out.push(EventItem {
            index: s(dump.get("_index")?),
            id: s(dump.get("_id")?),
            origin_context: s(source.get("origin_context")?),
        });
    }
    Some(out)
}

/// `return_graylog_events_index_names()`: the `gl-events*` indices.
pub async fn graylog_event_indices(st: &IngestState) -> Result<Vec<String>, PyErr> {
    let client = es::sync_client(st).await?;
    let aliases = es::get_alias(&client, "gl-events*").await?;
    match aliases {
        PyValue::Dict(d) => Ok(d.into_iter().map(|(k, _)| k).collect()),
        other => Err(PyErr::Other(format!(
            "'{}' object has no attribute 'keys'",
            crate::py::type_name(&other)
        ))),
    }
}

/// `construct_query()`.
fn not_created_query() -> PyValue {
    crate::py::to_py(&json!({
        "query": {"bool": {"must": [{"term": {"fields.COPILOT_ALERT_ID": "NONE"}}]}},
        "sort": [{"timestamp": {"order": "asc"}}],
    }))
}

/// `fetch_alerts_batch`: one index's events and its match count (`[]`, 0
/// on any failure).
async fn fetch_batch(
    client: &copilot_wazuh::es::Es,
    index: &str,
    size: usize,
) -> Result<(Vec<EventItem>, i64), PyErr> {
    let response = match es::search(client, index, &not_created_query(), Some(size as i64), None)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Error fetching alerts from index {index}: {e}");
            return Ok((Vec::new(), 0));
        }
    };
    let hits = response.get("hits");
    let (Some(PyValue::List(list)), Some(total)) = (
        hits.and_then(|h| h.get("hits")),
        hits.and_then(|h| h.get("total")),
    ) else {
        return Ok((Vec::new(), 0));
    };
    let total = match total {
        PyValue::Dict(_) => match total.get("value") {
            Some(v) => v.clone(),
            None => return Ok((Vec::new(), 0)),
        },
        other => other.clone(),
    };
    let Some(items) = items_of(list) else {
        return Ok((Vec::new(), 0));
    };
    let total = match total {
        PyValue::Int(i) => i.parse::<i64>().unwrap_or(i64::MAX),
        PyValue::Bool(b) => i64::from(b),
        PyValue::Float(f) => f as i64,
        other => {
            return Err(PyErr::Other(format!(
                "unsupported operand type(s) for +=: 'int' and '{}'",
                crate::py::type_name(&other)
            )));
        }
    };
    Ok((items, total))
}

/// `get_alerts_not_created_in_copilot(batch_size)`: up to `batch_size`
/// events from the indices in order, and the sum of their match counts.
pub async fn alerts_not_created(
    st: &IngestState,
    batch_size: usize,
) -> Result<(Vec<EventItem>, i64), PyErr> {
    let indices = graylog_event_indices(st).await?;
    let client = es::async_client(st).await?;
    let mut alerts: Vec<EventItem> = Vec::new();
    let mut total: i64 = 0;
    for index in indices {
        if alerts.len() >= batch_size {
            break;
        }
        let (batch, index_total) = fetch_batch(&client, &index, batch_size - alerts.len()).await?;
        alerts.extend(batch);
        total = total.saturating_add(index_total);
    }
    Ok((alerts, total))
}

/// `get_original_alert_index_name`: after `es:`, up to the next `:`.
pub fn original_index_name(origin: &str) -> String {
    origin
        .rsplit("es:")
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// `get_original_alert_id`: the last `:` part, after its last `_`.
pub fn original_alert_id(origin: &str) -> String {
    origin
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .rsplit('_')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// `add_copilot_alert_id`: `fields.COPILOT_ALERT_ID` on the Graylog event.
async fn stamp_event(st: &IngestState, event: &EventItem, alert_id: i64) -> Result<(), PyErr> {
    let client = es::async_client(st).await?;
    let body = PyValue::Dict(vec![(
        "doc".into(),
        PyValue::Dict(vec![(
            "fields".into(),
            PyValue::Dict(vec![(
                "COPILOT_ALERT_ID".into(),
                PyValue::Str(alert_id.to_string()),
            )]),
        )]),
    )]);
    es::update_lifting_write_block(
        &client,
        &event.index,
        &event.id,
        &body,
        &format!(
            "add CoPilot alert ID {alert_id} to Graylog event {} in index {}",
            event.id, event.index
        ),
    )
    .await;
    Ok(())
}

/// `BATCH_SIZE` and `MAX_BATCHES` of the auto route.
const BATCH_SIZE: usize = 100;
const MAX_BATCHES: usize = 10;

/// `create_alert_auto_route`: the `AutoCreateAlertResponse` body.
pub async fn create_alerts_auto(st: &IngestState) -> Result<Value, PyErr> {
    let mut total_created = 0i64;
    let mut total_failed = 0i64;
    let mut batches = 0usize;
    let mut total_remaining = 0i64;
    let mut last_len = 0usize;
    for _ in 0..MAX_BATCHES {
        let (alerts, remaining) = alerts_not_created(st, BATCH_SIZE).await?;
        total_remaining = remaining;
        last_len = alerts.len();
        if alerts.is_empty() {
            break;
        }
        for event in &alerts {
            let index_name = original_index_name(&event.origin_context);
            let doc_id = original_alert_id(&event.origin_context);
            let created = async {
                let id = create_alert(st, &index_name, &doc_id).await?;
                stamp_event(st, event, id).await
            }
            .await;
            match created {
                Ok(()) => total_created += 1,
                Err(e) => {
                    tracing::error!(
                        target: "copilot::ingest",
                        "Failed to create alert {} from index {}: {}",
                        event.id,
                        event.index,
                        e.py_str()
                    );
                    total_failed += 1;
                }
            }
        }
        batches += 1;
        if alerts.len() < BATCH_SIZE {
            break;
        }
    }
    let mut message = format!(
        "Processed {batches} batches: {total_created} alerts created, {total_failed} failed"
    );
    if total_remaining > 0 {
        message.push_str(&format!(
            ". {total_remaining} alerts remaining for next run"
        ));
    }
    let remaining = if batches < MAX_BATCHES {
        (total_remaining - last_len as i64).max(0)
    } else {
        total_remaining
    };
    Ok(json!({
        "success": true,
        "message": message,
        "alerts_created": total_created,
        "alerts_failed": total_failed,
        "batches_processed": batches,
        "alerts_remaining": remaining,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_context_parts() {
        let o = "urn:graylog:message:es:wazuh-alerts-4.x_12:abc_def";
        assert_eq!(original_index_name(o), "wazuh-alerts-4.x_12");
        assert_eq!(original_alert_id(o), "def");
        assert_eq!(original_index_name("no-colon"), "no-colon");
        assert_eq!(original_alert_id("no-colon"), "no-colon");
    }
}
