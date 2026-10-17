//! Port of `services/opencti.py`: the GraphQL answers flattened into
//! CoPilot's models, line by line — Python's `dict.get`/`or` semantics, the
//! models validated as Pydantic validates them (a `ValidationError` is the
//! `ValueError` handler's 400 with its text), every other exception raised
//! where CPython raises it.

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::model::{construct, field};
use copilot_upstream::py::{PyExc, PyResult, getitem, iterate};

use super::queries;
use super::schema;
use super::transport::{self, CONNECTOR};
use crate::py::{dict, get, gt, int, lower, or, or_dict, or_list, s, strip};

/// `_edges(connection)`.
fn edges(connection: &PyValue) -> PyResult<Vec<PyValue>> {
    let mut out = Vec::new();
    for edge in iterate(&or_list(get(&or_dict(connection.clone()), "edges")?))? {
        if edge.truthy() && !matches!(get(&edge, "node")?, PyValue::None) {
            out.push(getitem(&edge, "node")?.clone());
        }
    }
    Ok(out)
}

/// `_global_count(connection)`: the raw `globalCount`, or 0.
fn global_count(connection: &PyValue) -> PyResult<PyValue> {
    let page_info = or_dict(get(&or_dict(connection.clone()), "pageInfo")?);
    Ok(or(get(&page_info, "globalCount")?, int(0)))
}

/// `_meta(node)`.
fn meta(node: &PyValue) -> PyResult<Vec<(&'static str, PyValue)>> {
    let id = getitem(node, "id")?.clone();
    let standard_id = get(node, "standard_id")?;
    let entity_type = or(get(node, "entity_type")?, s("Unknown"));
    let created_at = get(node, "created_at")?;
    let updated_at = get(node, "updated_at")?;
    let created_by = get(&or_dict(get(node, "createdBy")?), "name")?;
    let mut labels = Vec::new();
    for label in iterate(&or_list(get(node, "objectLabel")?))? {
        if label.truthy() && get(&label, "value")?.truthy() {
            labels.push(label);
        }
    }
    let mut markings = Vec::new();
    for marking in iterate(&or_list(get(node, "objectMarking")?))? {
        if marking.truthy() && get(&marking, "definition")?.truthy() {
            markings.push(getitem(&marking, "definition")?.clone());
        }
    }
    Ok(vec![
        ("id", id),
        ("standard_id", standard_id),
        ("entity_type", entity_type),
        ("created_at", created_at),
        ("updated_at", updated_at),
        ("created_by", created_by),
        ("labels", PyValue::List(labels)),
        ("markings", PyValue::List(markings)),
    ])
}

/// `parse_indicator(node)`: the model's JSON dump.
pub fn parse_indicator(node: &PyValue) -> PyResult<PyValue> {
    let mut kwargs = meta(node)?;
    kwargs.extend([
        ("name", get(node, "name")?),
        ("description", get(node, "description")?),
        ("pattern", get(node, "pattern")?),
        ("pattern_type", get(node, "pattern_type")?),
        (
            "main_observable_type",
            get(node, "x_opencti_main_observable_type")?,
        ),
        ("score", get(node, "x_opencti_score")?),
        ("confidence", get(node, "confidence")?),
        ("valid_from", get(node, "valid_from")?),
        ("valid_until", get(node, "valid_until")?),
        ("revoked", get(node, "revoked")?),
    ]);
    construct(&schema::INDICATOR, &dict(kwargs))
}

/// `parse_observable(node)`.
pub fn parse_observable(node: &PyValue) -> PyResult<PyValue> {
    let mut kwargs = meta(node)?;
    let value = get(node, "observable_value")?;
    let description = get(node, "x_opencti_description")?;
    let score = get(node, "x_opencti_score")?;
    let file_name = get(node, "name")?;
    let mut hashes = Vec::new();
    for h in iterate(&or_list(get(node, "hashes")?))? {
        if h.truthy() && get(&h, "algorithm")?.truthy() && get(&h, "hash")?.truthy() {
            hashes.push(h);
        }
    }
    let indicators_conn = get(node, "indicators")?;
    let mut indicators = Vec::new();
    for n in edges(&indicators_conn)? {
        indicators.push(parse_indicator(&n)?);
    }
    let indicators_count = global_count(&indicators_conn)?;
    let reports_conn = get(node, "reports")?;
    let reports = edges(&reports_conn)?;
    let reports_count = global_count(&reports_conn)?;
    kwargs.extend([
        ("value", value),
        ("description", description),
        ("score", score),
        ("file_name", file_name),
        ("hashes", PyValue::List(hashes)),
        ("indicators", PyValue::List(indicators)),
        ("indicators_count", indicators_count),
        ("reports", PyValue::List(reports)),
        ("reports_count", reports_count),
    ]);
    construct(&schema::OBSERVABLE, &dict(kwargs))
}

/// `parse_entity(node)`.
pub fn parse_entity(node: &PyValue) -> PyResult<PyValue> {
    let representative = or_dict(get(node, "representative")?);
    let mut kwargs = meta(node)?;
    kwargs.extend([
        ("parent_types", or_list(get(node, "parent_types")?)),
        ("name", get(&representative, "main")?),
        ("description", get(&representative, "secondary")?),
        ("confidence", get(node, "confidence")?),
        ("score", get(node, "x_opencti_score")?),
        (
            "external_references",
            PyValue::List(edges(&get(node, "externalReferences")?)?),
        ),
    ]);
    construct(&schema::ENTITY, &dict(kwargs))
}

/// `_raise_on_failure(response, action)`: `data or {}`.
fn raise_on_failure(response: transport::Envelope, action: &str) -> PyResult<PyValue> {
    if !response.success {
        let detail = if response.message.is_empty() {
            format!("Failed to {action}")
        } else {
            response.message
        };
        return Err(PyExc::http(500, detail));
    }
    Ok(or_dict(response.data))
}

/// `get_availability()`: the connector row only, never OpenCTI.
pub async fn availability(cache: &ConnectorCache) -> PyResult<PyValue> {
    let Some(row) = transport::connector_row(cache, CONNECTOR).await? else {
        return construct(
            &schema::AVAILABILITY_RESPONSE,
            &dict(vec![
                ("success", PyValue::Bool(true)),
                ("message", s("OpenCTI connector is not installed")),
                ("configured", PyValue::Bool(false)),
                ("verified", PyValue::Bool(false)),
            ]),
        );
    };
    let configured = !strip(&row.connector_url).is_empty()
        && !strip(row.connector_api_key.as_deref().unwrap_or("")).is_empty();
    let verified = configured && row.connector_verified;
    let platform_url = if verified {
        s(transport::resolve_platform_url(
            &row.connector_url,
            row.connector_extra_data.as_deref(),
        )?)
    } else {
        PyValue::None
    };
    construct(
        &schema::AVAILABILITY_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(if verified {
                    "OpenCTI connector is verified"
                } else {
                    "OpenCTI connector is not verified"
                }),
            ),
            ("configured", PyValue::Bool(configured)),
            ("verified", PyValue::Bool(verified)),
            ("platform_url", platform_url),
        ]),
    )
}

/// `get_platform_info()`.
pub async fn platform_info(cache: &ConnectorCache) -> PyResult<PyValue> {
    tracing::info!("Fetching OpenCTI platform info");
    let response =
        transport::send_graphql_request(cache, queries::ABOUT_QUERY, PyValue::Dict(Vec::new()))
            .await?;
    let data = raise_on_failure(response, "fetch OpenCTI platform info")?;
    let about = or_dict(get(&data, "about")?);
    let me = or_dict(get(&data, "me")?);
    let about_model = construct(
        &schema::ABOUT,
        &dict(vec![
            ("version", get(&about, "version")?),
            ("dependencies", or_list(get(&about, "dependencies")?)),
            ("user_name", get(&me, "name")?),
            ("user_email", get(&me, "user_email")?),
        ]),
    )?;
    construct(
        &schema::ABOUT_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            ("message", s("OpenCTI platform info retrieved successfully")),
            ("about", about_model),
        ]),
    )
}

/// `filter_item(key, values, operator, mode)`.
fn filter_item(keys: &[&str], values: Vec<PyValue>, operator: &str) -> PyValue {
    dict(vec![
        ("key", PyValue::List(keys.iter().map(|k| s(*k)).collect())),
        ("values", PyValue::List(values)),
        ("operator", s(operator)),
        ("mode", s("or")),
    ])
}

/// `filter_group(filters)` (mode `and`).
fn filter_group(filters: Vec<PyValue>) -> PyValue {
    dict(vec![
        ("mode", s("and")),
        ("filters", PyValue::List(filters)),
        ("filterGroups", PyValue::List(Vec::new())),
    ])
}

/// The observables of a lookup answer: `[parse_observable(node) for node in
/// _edges(connection)]`.
fn observables(connection: &PyValue) -> PyResult<Vec<PyValue>> {
    edges(connection)?.iter().map(parse_observable).collect()
}

/// `lookup_observable(value, first)`: one IOC by exact value.
pub async fn lookup_observable(
    cache: &ConnectorCache,
    value: &str,
    first: &str,
) -> PyResult<PyValue> {
    let value = strip(value);
    if value.is_empty() {
        return Err(PyExc::http(400, "An observable value is required"));
    }
    tracing::info!("Looking up observable in OpenCTI: {value}");
    let variables = dict(vec![
        (
            "filters",
            filter_group(vec![filter_item(
                &queries::OBSERVABLE_LOOKUP_KEYS,
                vec![s(value)],
                "eq",
            )]),
        ),
        ("first", PyValue::Int(first.to_string())),
        ("indicators", int(10)),
        ("reports", int(5)),
    ]);
    let response =
        transport::send_graphql_request(cache, queries::OBSERVABLE_LOOKUP_QUERY, variables).await?;
    let data = raise_on_failure(response, "look up observable in OpenCTI")?;
    let connection = get(&data, "stixCyberObservables")?;
    let observables = observables(&connection)?;
    let found = !observables.is_empty();
    construct(
        &schema::LOOKUP_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(if found {
                    format!("Found {} matching observables", observables.len())
                } else {
                    "No matching observable found in OpenCTI".to_string()
                }),
            ),
            ("value", s(value)),
            ("found", PyValue::Bool(found)),
            ("total", global_count(&connection)?),
            ("observables", PyValue::List(observables)),
        ]),
    )
}

/// `BATCH_OBSERVABLES_PER_VALUE`.
const BATCH_OBSERVABLES_PER_VALUE: usize = 5;
/// `BATCH_MAX_OBSERVABLES`.
const BATCH_MAX_OBSERVABLES: usize = 500;

/// `_match_keys(observable)`: its value and every hash, lower-cased.
fn match_keys(observable: &PyValue) -> Vec<String> {
    let mut keys = Vec::new();
    if let PyValue::Str(v) = field(observable, "value") {
        if !v.is_empty() {
            keys.push(lower(v));
        }
    }
    if let PyValue::List(hashes) = field(observable, "hashes") {
        for h in hashes {
            if let PyValue::Str(hash) = field(h, "hash") {
                keys.push(lower(hash));
            }
        }
    }
    keys
}

/// `lookup_observables(values)`: many IOCs in one query, mapped back to the
/// values they match.
pub async fn lookup_observables(cache: &ConnectorCache, values: &[String]) -> PyResult<PyValue> {
    tracing::info!("Batch lookup of {} observables in OpenCTI", values.len());
    let first = (values.len() * BATCH_OBSERVABLES_PER_VALUE).clamp(50, BATCH_MAX_OBSERVABLES);
    let variables = dict(vec![
        (
            "filters",
            filter_group(vec![filter_item(
                &queries::OBSERVABLE_LOOKUP_KEYS,
                values.iter().map(|v| s(v.clone())).collect(),
                "eq",
            )]),
        ),
        ("first", int(first)),
        ("indicators", int(5)),
        ("reports", int(3)),
    ]);
    let response =
        transport::send_graphql_request(cache, queries::OBSERVABLE_LOOKUP_QUERY, variables).await?;
    let data = raise_on_failure(response, "look up observables in OpenCTI")?;
    let connection = get(&data, "stixCyberObservables")?;
    let observables = observables(&connection)?;
    let mut matches: Vec<(String, Vec<PyValue>)> =
        values.iter().map(|v| (lower(v), Vec::new())).collect();
    for observable in &observables {
        let keys = match_keys(observable);
        for (key, found) in matches.iter_mut() {
            if keys.contains(key) {
                found.push(observable.clone());
            }
        }
    }
    let mut results = Vec::new();
    let mut found_count = 0;
    for value in values {
        let key = lower(value);
        let found = matches
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, f)| f.clone())
            .unwrap_or_default();
        if !found.is_empty() {
            found_count += 1;
        }
        results.push(construct(
            &schema::VALUE_LOOKUP,
            &dict(vec![
                ("value", s(value.clone())),
                ("found", PyValue::Bool(!found.is_empty())),
                ("observables", PyValue::List(found)),
            ]),
        )?);
    }
    let truncated = gt(&global_count(&connection)?, &int(observables.len()))?;
    construct(
        &schema::BATCH_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(format!(
                    "{found_count} of {} values found in OpenCTI",
                    values.len()
                )),
            ),
            ("results", PyValue::List(results)),
            ("truncated", PyValue::Bool(truncated)),
        ]),
    )
}

/// The query of `GET /indicators`, validated.
#[derive(Debug, Clone, Default)]
pub struct IndicatorQuery {
    /// `search`.
    pub search: Option<String>,
    /// `first` (Python's `int` text).
    pub first: String,
    /// `after`.
    pub after: Option<String>,
    /// `min_score` (Python's `int` text).
    pub min_score: Option<String>,
    /// `main_observable_type`.
    pub main_observable_type: Option<String>,
}

/// `search_indicators(...)`: one page, newest first.
pub async fn search_indicators(cache: &ConnectorCache, q: &IndicatorQuery) -> PyResult<PyValue> {
    tracing::info!(
        "Searching OpenCTI indicators (search={:?}, first={}, after={:?})",
        q.search,
        q.first,
        q.after
    );
    let mut filters = Vec::new();
    if let Some(score) = &q.min_score {
        filters.push(filter_item(
            &["x_opencti_score"],
            vec![s(score.clone())],
            "gte",
        ));
    }
    if let Some(kind) = q.main_observable_type.as_ref().filter(|k| !k.is_empty()) {
        filters.push(filter_item(
            &["x_opencti_main_observable_type"],
            vec![s(kind.clone())],
            "eq",
        ));
    }
    let opt = |v: &Option<String>| match v {
        Some(text) if !text.is_empty() => s(text.clone()),
        _ => PyValue::None,
    };
    let variables = dict(vec![
        ("search", opt(&q.search)),
        (
            "filters",
            if filters.is_empty() {
                PyValue::None
            } else {
                filter_group(filters)
            },
        ),
        ("first", PyValue::Int(q.first.clone())),
        ("after", opt(&q.after)),
    ]);
    let response =
        transport::send_graphql_request(cache, queries::INDICATORS_QUERY, variables).await?;
    let data = raise_on_failure(response, "search OpenCTI indicators")?;
    let connection = or_dict(get(&data, "indicators")?);
    let page_info = or_dict(get(&connection, "pageInfo")?);
    let mut indicators = Vec::new();
    for node in edges(&connection)? {
        indicators.push(parse_indicator(&node)?);
    }
    let page = construct(
        &schema::PAGE_INFO,
        &dict(vec![
            ("global_count", get(&page_info, "globalCount")?),
            (
                "has_next_page",
                PyValue::Bool(get(&page_info, "hasNextPage")?.truthy()),
            ),
            (
                "end_cursor",
                or(get(&page_info, "endCursor")?, PyValue::None),
            ),
        ]),
    )?;
    construct(
        &schema::INDICATORS_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(format!("Retrieved {} indicators", indicators.len())),
            ),
            ("indicators", PyValue::List(indicators)),
            ("page_info", page),
        ]),
    )
}

/// `get_entity(entity_id)`: any STIX core object; 404 when OpenCTI answers
/// `null`.
pub async fn entity(cache: &ConnectorCache, entity_id: &str) -> PyResult<PyValue> {
    tracing::info!("Fetching OpenCTI entity {entity_id}");
    let response = transport::send_graphql_request(
        cache,
        queries::ENTITY_QUERY,
        dict(vec![("id", s(entity_id))]),
    )
    .await?;
    let data = raise_on_failure(response, "fetch OpenCTI entity")?;
    let node = get(&data, "stixCoreObject")?;
    if !node.truthy() {
        return Err(PyExc::http(
            404,
            format!("No OpenCTI entity found with id {entity_id}"),
        ));
    }
    let entity = parse_entity(&node)?;
    construct(
        &schema::ENTITY_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            ("message", s("OpenCTI entity retrieved successfully")),
            ("entity", entity),
        ]),
    )
}
