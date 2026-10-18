//! `execute_panels` (`app/siem/services/dashboards.py`) — the one panel
//! executor, shared by `POST /panel-data` (built-in and custom templates)
//! and `POST /custom/preview`, so a dashboard being built renders exactly
//! like it will once saved.
//!
//! Every panel runs one search (two on the fallbacks) against the event
//! source's index pattern, inside the time window, with its own Lucene
//! filter ANDed with the dashboard-wide `default_query`. A panel's failure
//! is caught and becomes that panel's `error` (`str(e)` of what Python
//! raised); what Python raises outside its `try` (a panel without `id` or
//! `type`, a time range that does not parse, no indexer connector) fails
//! the whole request.
//!
//! The fallbacks are Python's: a terms aggregation the indexer refuses on a
//! `text` field (`_is_text_field_agg_error`: the `search_phase_execution_
//! exception` type *and* "Text fields are not optimised" in the error body)
//! is asked again on `<field>.keyword`; a table that cannot be sorted by the
//! time field (any `RequestError`) is asked again unsorted.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::model::{Loc, construct, kwargs};
use copilot_upstream::py::{PyExc, PyResult, getitem, iterate, py_eq, type_name};
use copilot_wazuh::es::{Es, EsError};

use crate::SiemState;
use crate::indexer;
use crate::py::{AnyKeyDict, hashable, model_with_key_errors, set_item, str_keys};
use crate::schema::PANEL_RESULT;
use crate::timerange;

/// The results, keyed by panel id in insertion order (a Python `dict`: a
/// repeated id keeps its first position and its last result).
pub type PanelResults = AnyKeyDict;

fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn int(n: i64) -> PyValue {
    PyValue::Int(n.to_string())
}

/// `PanelResult(**kwargs)`.
fn panel_result(pairs: Vec<(&str, PyValue)>) -> PyResult<PyValue> {
    construct(&PANEL_RESULT, &kwargs(pairs))
}

/// `_compute_histogram_interval(timerange)`.
pub fn histogram_interval(timerange: &str) -> &'static str {
    match timerange {
        "1h" => "1m",
        "6h" => "10m",
        "24h" => "30m",
        "3d" => "3h",
        "7d" => "6h",
        "14d" => "12h",
        "30d" => "1d",
        _ => "1h",
    }
}

/// `_is_text_field_agg_error(exc)`.
pub fn is_text_field_agg_error(e: &EsError) -> bool {
    let EsError::Transport { error, info, .. } = e else {
        return false;
    };
    let info = info.as_ref().filter(|i| i.truthy()).map(PyValue::py_str);
    py_eq(error, &s("search_phase_execution_exception"))
        && info
            .unwrap_or_default()
            .contains("Text fields are not optimised")
}

/// `_extract_field(source, path)`: `path in source`, then `source[path]`
/// or the walk down `path.split(".")`, Python's exceptions included (a
/// stored table field need not be a `str`, a `_source` need not be a dict).
pub fn extract_field(source: &PyValue, path: &PyValue) -> PyResult<PyValue> {
    let found = match source {
        PyValue::Dict(items) => {
            hashable(path)?;
            items
                .iter()
                .find(|(k, _)| py_eq(&s(k.as_str()), path))
                .map(|(_, v)| v.clone())
        }
        PyValue::List(items) => {
            if items.iter().any(|v| py_eq(v, path)) {
                Some(list_index(items, path)?)
            } else {
                None
            }
        }
        PyValue::Str(text) => match path {
            PyValue::Str(p) if text.contains(p.as_str()) => {
                return Err(PyExc::TypeError(
                    "string indices must be integers, not 'str'".into(),
                ));
            }
            PyValue::Str(_) => None,
            other => {
                return Err(PyExc::TypeError(format!(
                    "'in <string>' requires string as left operand, not {}",
                    type_name(other)
                )));
            }
        },
        other => {
            return Err(PyExc::TypeError(format!(
                "argument of type '{}' is not iterable",
                type_name(other)
            )));
        }
    };
    let value = match found {
        Some(v) => v,
        None => {
            let PyValue::Str(path) = path else {
                return Err(PyExc::AttributeError(format!(
                    "'{}' object has no attribute 'split'",
                    type_name(path)
                )));
            };
            let mut value = source.clone();
            for part in path.split('.') {
                let next = match &value {
                    PyValue::Dict(items) => items
                        .iter()
                        .find(|(k, _)| k == part)
                        .map(|(_, v)| v.clone()),
                    _ => None,
                };
                match next {
                    Some(v) => value = v,
                    None => return Ok(PyValue::None),
                }
            }
            value
        }
    };
    Ok(match value {
        v @ (PyValue::Dict(_) | PyValue::List(_)) => {
            s(py_dumps(&v, Dumps::DEFAULT).map_err(|e| PyExc::ValueError(e.to_string()))?)
        }
        v => v,
    })
}

/// `items[index]` for a list (an `int`, or a `bool` as one).
fn list_index(items: &[PyValue], index: &PyValue) -> PyResult<PyValue> {
    let i: i128 = match index {
        PyValue::Bool(b) => i128::from(*b),
        PyValue::Int(n) => n.parse().unwrap_or(i128::MAX),
        other => {
            return Err(PyExc::TypeError(format!(
                "list indices must be integers or slices, not {}",
                type_name(other)
            )));
        }
    };
    let len = i128::try_from(items.len()).unwrap_or(i128::MAX);
    let at = if i < 0 { i + len } else { i };
    usize::try_from(at)
        .ok()
        .and_then(|at| items.get(at))
        .cloned()
        .ok_or_else(|| PyExc::Other("IndexError", "list index out of range".into()))
}

/// `x.get(key)` on a panel already known to be subscriptable by `str`.
fn get(panel: &PyValue, key: &str) -> PyValue {
    panel.get(key).cloned().unwrap_or(PyValue::None)
}

/// The search body `{"query": {"bool": {"must": must}}, "size": 0}`.
fn base_body(must: &[PyValue]) -> Vec<(String, PyValue)> {
    vec![
        (
            "query".into(),
            dict(vec![(
                "bool",
                dict(vec![("must", PyValue::List(must.to_vec()))]),
            )]),
        ),
        ("size".into(), int(0)),
    ]
}

fn set(body: &mut Vec<(String, PyValue)>, key: &str, value: PyValue) {
    match body.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => body.push((key.to_string(), value)),
    }
}

fn es_exc(e: EsError) -> PyExc {
    match e {
        EsError::Value(v) => PyExc::ValueError(v),
        other => PyExc::Other("TransportError", other.to_string()),
    }
}

/// `[x[key] for x in items]`.
fn pluck(items: &PyValue, key: &str) -> PyResult<Vec<PyValue>> {
    iterate(items)?
        .iter()
        .map(|b| getitem(b, key).cloned())
        .collect()
}

/// One panel's `try` block: its result, or the exception the block raised.
async fn run_panel(
    es: &Es,
    panel: &PyValue,
    ptype: &PyValue,
    filters: &Filters,
    index_pattern: &str,
    time_field: &str,
    timerange: &str,
) -> PyResult<PyValue> {
    let lucene = match get(panel, "lucene") {
        v if v.truthy() => v,
        _ => s("*"),
    };
    let field = get(panel, "field");
    let table_fields = match get(panel, "fields") {
        v if v.truthy() => v,
        _ => PyValue::List(Vec::new()),
    };
    let size = match get(panel, "size") {
        v if v.truthy() => v,
        _ => int(10),
    };
    // `[*time_filter, {"query_string": …}]`, then the dashboard's filter.
    let mut clauses = vec![
        filters.time.clone(),
        dict(vec![(
            "query_string",
            dict(vec![("query", lucene), ("default_operator", s("AND"))]),
        )]),
    ];
    if let Some(base) = &filters.base {
        clauses.push(base.clone());
    }
    let mut body = base_body(&clauses);
    let is = |name: &str| ptype.as_str() == Some(name);
    if is("stat") {
        let resp = indexer::search(es, index_pattern, &PyValue::Dict(body), None, None)
            .await
            .map_err(es_exc)?;
        let total = getitem(getitem(&resp, "hits")?, "total")?;
        let count = match total {
            PyValue::Dict(_) => getitem(total, "value")?.clone(),
            other => other.clone(),
        };
        return panel_result(vec![("type", s("stat")), ("value", count)]);
    }
    if is("histogram") {
        set(
            &mut body,
            "aggs",
            dict(vec![(
                "over_time",
                dict(vec![(
                    "date_histogram",
                    dict(vec![
                        ("field", s(time_field)),
                        ("fixed_interval", s(histogram_interval(timerange))),
                        ("min_doc_count", int(0)),
                    ]),
                )]),
            )]),
        );
        let resp = indexer::search(es, index_pattern, &PyValue::Dict(body), None, None)
            .await
            .map_err(es_exc)?;
        let buckets = getitem(
            getitem(getitem(&resp, "aggregations")?, "over_time")?,
            "buckets",
        )?;
        let labels = pluck(buckets, "key_as_string")?;
        let data = pluck(buckets, "doc_count")?;
        return panel_result(vec![
            ("type", s("histogram")),
            ("labels", PyValue::List(labels)),
            ("data", PyValue::List(data)),
        ]);
    }
    if is("pie") || is("bar_h") {
        if !field.truthy() {
            return panel_result(vec![
                ("type", ptype.clone()),
                ("error", s("No field specified for aggregation")),
            ]);
        }
        let terms = |agg_field: PyValue| {
            dict(vec![(
                "top_values",
                dict(vec![(
                    "terms",
                    dict(vec![("field", agg_field), ("size", size.clone())]),
                )]),
            )])
        };
        set(&mut body, "aggs", terms(field.clone()));
        let resp = match indexer::search(
            es,
            index_pattern,
            &PyValue::Dict(body.clone()),
            None,
            None,
        )
        .await
        {
            Ok(r) => r,
            Err(e) if e.is_request_error() && is_text_field_agg_error(&e) => {
                let field_text = match &field {
                    PyValue::Str(f) => f.clone(),
                    other => {
                        return Err(PyExc::AttributeError(format!(
                            "'{}' object has no attribute 'endswith'",
                            type_name(other)
                        )));
                    }
                };
                if !field_text.ends_with(".keyword") {
                    tracing::info!(
                        "Panel: '{field_text}' is text-typed in {index_pattern}; retrying \
                             with '{field_text}.keyword'"
                    );
                    set(&mut body, "aggs", terms(s(format!("{field_text}.keyword"))));
                    indexer::search(es, index_pattern, &PyValue::Dict(body), None, None)
                        .await
                        .map_err(es_exc)?
                } else {
                    return Err(es_exc(e));
                }
            }
            Err(e) => return Err(es_exc(e)),
        };
        let buckets = getitem(
            getitem(getitem(&resp, "aggregations")?, "top_values")?,
            "buckets",
        )?;
        let labels: Vec<PyValue> = pluck(buckets, "key")?
            .iter()
            .map(|k| s(k.py_str()))
            .collect();
        let data = pluck(buckets, "doc_count")?;
        return panel_result(vec![
            ("type", ptype.clone()),
            ("labels", PyValue::List(labels)),
            ("data", PyValue::List(data)),
        ]);
    }
    if is("table") {
        if !table_fields.truthy() {
            return panel_result(vec![
                ("type", ptype.clone()),
                ("error", s("No fields specified for the table")),
            ]);
        }
        set(&mut body, "size", size);
        set(&mut body, "_source", table_fields.clone());
        set(
            &mut body,
            "sort",
            PyValue::List(vec![dict(vec![(
                time_field,
                dict(vec![("order", s("desc"))]),
            )])]),
        );
        let resp = match indexer::search(
            es,
            index_pattern,
            &PyValue::Dict(body.clone()),
            None,
            None,
        )
        .await
        {
            Ok(r) => r,
            Err(e) if e.is_request_error() => {
                tracing::info!(
                    "Panel: cannot sort {index_pattern} by '{time_field}'; retrying unsorted"
                );
                body.retain(|(k, _)| k != "sort");
                indexer::search(es, index_pattern, &PyValue::Dict(body), None, None)
                    .await
                    .map_err(es_exc)?
            }
            Err(e) => return Err(es_exc(e)),
        };
        let fields = iterate(&table_fields)?;
        // `[{f: _extract_field(hit.get("_source") or {}, f) for f in
        // table_fields} for hit in …]`: a row's keys are the fields as
        // stored, so a non-`str` one is the response model's key error.
        let mut rows = Vec::new();
        let mut key_errors = Vec::new();
        for (i, hit) in iterate(getitem(getitem(&resp, "hits")?, "hits")?)?
            .iter()
            .enumerate()
        {
            let source = match copilot_upstream::py::get(hit, "_source")? {
                Some(v) if v.truthy() => v.clone(),
                _ => PyValue::Dict(Vec::new()),
            };
            let mut row = AnyKeyDict::new();
            for f in &fields {
                let value = extract_field(&source, f)?;
                set_item(&mut row, f.clone(), value)?;
            }
            let (row, errors) = str_keys(&[Loc::Key("rows".into()), Loc::Index(i)], &row);
            rows.push(row);
            key_errors.extend(errors);
        }
        return model_with_key_errors(
            &PANEL_RESULT,
            vec![
                ("type", ptype.clone()),
                ("columns", table_fields),
                ("rows", PyValue::List(rows)),
            ],
            Vec::new(),
            key_errors,
        );
    }
    panel_result(vec![
        ("type", ptype.clone()),
        (
            "error",
            s(format!("Unknown panel type: {}", ptype.py_str())),
        ),
    ])
}

/// The clauses every panel's query carries: the time window and, when the
/// dashboard narrows it, its `default_query`.
struct Filters {
    time: PyValue,
    base: Option<PyValue>,
}

/// `execute_panels(panels, index_pattern, time_field, timerange,
/// base_query)`.
pub async fn execute_panels(
    st: &SiemState,
    panels: &PyValue,
    index_pattern: &str,
    time_field: &str,
    timerange: &str,
    base_query: &str,
) -> PyResult<PanelResults> {
    let time_filter = timerange::relative(timerange, time_field)?;
    let base_query = match copilot_web::form::py_strip(if base_query.is_empty() {
        "*"
    } else {
        base_query
    }) {
        "" => "*".to_string(),
        q => q.to_string(),
    };
    let es = indexer::client(st).await?;
    let filters = Filters {
        time: time_filter,
        base: (base_query != "*").then(|| {
            dict(vec![(
                "query_string",
                dict(vec![
                    ("query", s(&base_query)),
                    ("default_operator", s("AND")),
                ]),
            )])
        }),
    };
    let mut results = PanelResults::new();
    for panel in iterate(panels)? {
        let pid = getitem(&panel, "id")?.clone();
        let ptype = getitem(&panel, "type")?.clone();
        let outcome = run_panel(
            &es,
            &panel,
            &ptype,
            &filters,
            index_pattern,
            time_field,
            timerange,
        )
        .await;
        // `results[pid] = …` is inside the `try` too: an unhashable id is
        // caught, and raised again by the `except` block's own assignment.
        let outcome = outcome.and_then(|r| set_item(&mut results, pid.clone(), r));
        if let Err(e) = outcome {
            tracing::error!("Error querying panel {}: {}", pid.py_str(), e.display());
            let result = panel_result(vec![("type", ptype.clone()), ("error", s(e.display()))])?;
            set_item(&mut results, pid, result)?;
        }
    }
    Ok(results)
}
