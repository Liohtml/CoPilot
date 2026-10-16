//! `app/siem/services/events.py`: the event search of one event source
//! (scroll-based paging), one document, and the source's field names
//! (`_field_caps`).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::{PyExc, PyResult, get, getitem, iterate, len, type_name};

use crate::SiemState;
use crate::fnmatch::fnmatchcase;
use crate::indexer;
use crate::py::{db, dict, http, int, model, s};
use crate::schema::{EVENT_DOCUMENT_RESPONSE, EVENTS_QUERY_RESPONSE, FIELD_MAPPING};
use crate::store::{self, EventSourceRow};
use crate::timerange;

/// `EventsQueryParams`.
#[derive(Debug, Clone, Default)]
pub struct EventsQuery {
    /// `timerange`.
    pub timerange: String,
    /// `page_size`.
    pub page_size: i64,
    /// `scroll_id`.
    pub scroll_id: Option<String>,
    /// `query` (Lucene).
    pub query: Option<String>,
    /// `time_from`.
    pub time_from: Option<String>,
    /// `time_to`.
    pub time_to: Option<String>,
}

/// `get_event_source_by_customer_and_name`: 404 when unknown, 400 when
/// disabled.
pub async fn source_named(st: &SiemState, code: &str, name: &str) -> PyResult<EventSourceRow> {
    let Some(source) = store::event_source_named(&st.ctx.db, code, name)
        .await
        .map_err(db)?
    else {
        return Err(http(
            404,
            format!("Event source '{name}' not found for customer {code}"),
        ));
    };
    if !source.enabled {
        return Err(http(400, format!("Event source '{name}' is disabled")));
    }
    Ok(source)
}

/// `_event_from_hit(hit)`: `{**hit["_source"], "_id": …, "_index": …}`.
fn event_from_hit(hit: &PyValue) -> PyResult<PyValue> {
    let source = getitem(hit, "_source")?;
    let PyValue::Dict(items) = source else {
        return Err(PyExc::TypeError(format!(
            "'{}' object is not a mapping",
            type_name(source)
        )));
    };
    let mut out = items.clone();
    for key in ["_id", "_index"] {
        let value = getitem(hit, key)?.clone();
        match out.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value,
            None => out.push((key.to_string(), value)),
        }
    }
    Ok(PyValue::Dict(out))
}

/// `x["hits"]["total"]["value"]` if a dict, else `x["hits"]["total"]`.
fn total_of(resp: &PyValue) -> PyResult<PyValue> {
    let total = getitem(getitem(resp, "hits")?, "total")?;
    Ok(match total {
        PyValue::Dict(_) => getitem(total, "value")?.clone(),
        other => other.clone(),
    })
}

/// `len(hits) >= total` (Python's comparison of an int with what the indexer
/// sent).
fn at_least(n: usize, total: &PyValue) -> PyResult<bool> {
    let n = n as f64;
    match total {
        PyValue::Int(t) => Ok(t
            .parse::<f64>()
            .map(|t| n >= t)
            .unwrap_or(t.starts_with('-'))),
        PyValue::Float(f) => Ok(n >= *f),
        PyValue::Bool(b) => Ok(n >= f64::from(u8::from(*b))),
        other => Err(PyExc::TypeError(format!(
            "'>=' not supported between instances of 'int' and '{}'",
            type_name(other)
        ))),
    }
}

/// `es.clear_scroll(...)`, failures only logged (`_clear_scroll`).
async fn clear(es: &copilot_wazuh::es::Es, scroll_id: &PyValue) {
    let id = scroll_id.py_str();
    if let Err(e) = indexer::clear_scroll(es, &id).await {
        tracing::warn!("Failed to clear scroll context: {e}");
    }
}

fn es(e: copilot_wazuh::es::EsError) -> PyExc {
    match e {
        copilot_wazuh::es::EsError::Value(v) => PyExc::ValueError(v),
        other => PyExc::Other("TransportError", other.to_string()),
    }
}

/// `query_events(customer_code, source_name, params)`: the next page of a
/// scroll (no event source lookup, as in Python), or the first search.
pub async fn query(st: &SiemState, code: &str, name: &str, q: &EventsQuery) -> PyResult<PyValue> {
    if let Some(scroll_id) = q.scroll_id.as_deref().filter(|s| !s.is_empty()) {
        return scroll_next(st, scroll_id).await;
    }
    let source = source_named(st, code, name).await?;
    let client = indexer::client(st).await?;
    initial(&client, &source, q)
        .await
        .map_err(|e| http(500, format!("Error querying events: {}", e.display())))
}

async fn initial(
    client: &copilot_wazuh::es::Es,
    source: &EventSourceRow,
    q: &EventsQuery,
) -> PyResult<PyValue> {
    let range = match (q.time_from.as_deref(), q.time_to.as_deref()) {
        (Some(from), Some(to)) if !from.is_empty() && !to.is_empty() => {
            timerange::absolute(from, to, &source.time_field)
        }
        _ => timerange::relative(&q.timerange, &source.time_field)?,
    };
    let mut must = vec![range];
    if let Some(lucene) = q.query.as_deref().filter(|l| !l.is_empty()) {
        must.push(dict(vec![(
            "query_string",
            dict(vec![("query", s(lucene)), ("default_operator", s("AND"))]),
        )]));
    }
    let body = dict(vec![
        (
            "query",
            dict(vec![("bool", dict(vec![("must", PyValue::List(must))]))]),
        ),
        (
            "sort",
            PyValue::List(vec![dict(vec![(
                &source.time_field,
                dict(vec![("order", s("desc"))]),
            )])]),
        ),
    ]);
    let resp = indexer::search(
        client,
        &source.index_pattern,
        &body,
        Some(q.page_size),
        Some("5m"),
    )
    .await
    .map_err(es)?;
    let hits = getitem(getitem(&resp, "hits")?, "hits")?.clone();
    let total = total_of(&resp)?;
    let mut scroll_id = get(&resp, "_scroll_id")?.cloned().unwrap_or(PyValue::None);
    let count = len(&hits)?;
    if at_least(count, &total)? && scroll_id.truthy() {
        clear(client, &scroll_id).await;
        scroll_id = PyValue::None;
    }
    let events = iterate(&hits)?
        .iter()
        .map(event_from_hit)
        .collect::<PyResult<Vec<_>>>()?;
    model(
        &EVENTS_QUERY_RESPONSE,
        vec![
            ("events", PyValue::List(events)),
            ("total", total.clone()),
            ("scroll_id", scroll_id),
            ("page_size", int(q.page_size)),
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(format!("Retrieved {count} of {} events", total.py_str())),
            ),
        ],
    )
}

async fn scroll_next(st: &SiemState, scroll_id: &str) -> PyResult<PyValue> {
    let client = indexer::client(st).await?;
    let result: PyResult<PyValue> = async {
        let resp = indexer::scroll(&client, scroll_id, "5m")
            .await
            .map_err(es)?;
        let hits = getitem(getitem(&resp, "hits")?, "hits")?.clone();
        let total = total_of(&resp)?;
        let new_id = get(&resp, "_scroll_id")?.cloned().unwrap_or(PyValue::None);
        if !hits.truthy() {
            if new_id.truthy() {
                clear(&client, &new_id).await;
            }
            return model(
                &EVENTS_QUERY_RESPONSE,
                vec![
                    ("events", PyValue::List(Vec::new())),
                    ("total", total),
                    ("scroll_id", PyValue::None),
                    ("page_size", int(0)),
                    ("success", PyValue::Bool(true)),
                    ("message", s("No more results")),
                ],
            );
        }
        let count = len(&hits)?;
        let events = iterate(&hits)?
            .iter()
            .map(event_from_hit)
            .collect::<PyResult<Vec<_>>>()?;
        model(
            &EVENTS_QUERY_RESPONSE,
            vec![
                ("events", PyValue::List(events)),
                ("total", total.clone()),
                ("scroll_id", new_id),
                ("page_size", int(count as i64)),
                ("success", PyValue::Bool(true)),
                (
                    "message",
                    s(format!("Retrieved {count} of {} events", total.py_str())),
                ),
            ],
        )
    }
    .await;
    result.map_err(|e| http(500, format!("Error scrolling events: {}", e.display())))
}

/// `get_event_document(customer_code, source_name, index_name, event_id)`.
pub async fn document(
    st: &SiemState,
    code: &str,
    name: &str,
    index_name: &str,
    event_id: &str,
) -> PyResult<PyValue> {
    let source = source_named(st, code, name).await?;
    if !fnmatchcase(index_name, &source.index_pattern) {
        return Err(http(
            400,
            format!(
                "Index '{index_name}' does not match event source pattern '{}'",
                source.index_pattern
            ),
        ));
    }
    let client = indexer::client(st).await?;
    match indexer::get(&client, index_name, event_id).await {
        Ok(doc) => {
            let built: PyResult<PyValue> = event_from_hit(&doc).and_then(|event| {
                model(
                    &EVENT_DOCUMENT_RESPONSE,
                    vec![
                        ("event", event),
                        ("success", PyValue::Bool(true)),
                        ("message", s("Event retrieved")),
                    ],
                )
            });
            built.map_err(|e| http(500, format!("Error fetching event: {}", e.display())))
        }
        Err(e) if e.is_not_found() => Err(http(
            404,
            format!("Event '{event_id}' not found in index '{index_name}'"),
        )),
        Err(e) => Err(http(
            500,
            format!("Error fetching event: {}", es(e).display()),
        )),
    }
}

/// `_leaf_types(caps_by_type)`.
fn leaf_types(caps: &PyValue) -> Vec<String> {
    match caps {
        PyValue::Dict(items) => {
            let mut out: Vec<String> = items
                .iter()
                .map(|(k, _)| k.clone())
                .filter(|k| k != "object" && k != "nested")
                .collect();
            out.sort();
            out.dedup();
            out
        }
        _ => Vec::new(),
    }
}

/// `_fields_from_field_caps(field_caps)`.
fn fields_from_field_caps(field_caps: &PyValue) -> PyResult<Vec<PyValue>> {
    let PyValue::Dict(items) = field_caps else {
        return Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'items'",
            type_name(field_caps)
        )));
    };
    let leaf_names: Vec<&str> = items
        .iter()
        .filter(|(_, caps)| !leaf_types(caps).is_empty())
        .map(|(n, _)| n.as_str())
        .collect();
    let mut fields: Vec<(String, String)> = Vec::new();
    for (name, caps_by_type) in items {
        let types = leaf_types(caps_by_type);
        if types.is_empty() {
            continue;
        }
        let PyValue::Dict(by_type) = caps_by_type else {
            continue;
        };
        let mut metadata = false;
        for (_, caps) in by_type {
            if let PyValue::Dict(_) = caps {
                if get(caps, "metadata_field")?.is_some_and(PyValue::truthy) {
                    metadata = true;
                    break;
                }
            }
        }
        if metadata {
            continue;
        }
        if let Some((parent, _)) = name.rsplit_once('.') {
            if !parent.is_empty() && leaf_names.contains(&parent) {
                continue;
            }
        }
        fields.push((name.clone(), types.join(", ")));
    }
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    fields
        .into_iter()
        .map(|(field, ty)| model(&FIELD_MAPPING, vec![("field", s(field)), ("type", s(ty))]))
        .collect()
}

/// `get_field_mappings(customer_code, source_name)`: the fields of every
/// index the pattern spans (`_field_caps`).
pub async fn field_mappings(st: &SiemState, code: &str, name: &str) -> PyResult<PyValue> {
    let source = source_named(st, code, name).await?;
    let client = indexer::client(st).await?;
    let result: PyResult<PyValue> = async {
        let resp = indexer::field_caps(&client, &source.index_pattern)
            .await
            .map_err(es)?;
        let caps = get(&resp, "fields")?
            .cloned()
            .unwrap_or(PyValue::Dict(Vec::new()));
        let fields = fields_from_field_caps(&caps)?;
        let n = fields.len();
        Ok(dict(vec![
            ("fields", PyValue::List(fields)),
            ("total", int(n as i64)),
            ("index_pattern", s(&source.index_pattern)),
            ("success", PyValue::Bool(true)),
            ("message", s(format!("Retrieved {n} field mappings"))),
        ]))
    }
    .await;
    result.map_err(|e| {
        http(
            500,
            format!("Error retrieving field mappings: {}", e.display()),
        )
    })
}
