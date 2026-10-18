//! The two MITRE alert searches of `wazuh_manager/routes/mitre.py`:
//! `GET /mitre/techniques/alerts` (`search_mitre_techniques_in_alerts`) and
//! `GET /mitre/techniques/{technique_id}/alerts` (`get_alerts_by_mitre_id`).
//!
//! Both read the manager's technique list (`get_mitre_techniques(limit=1000)`,
//! and for the first the tactics too) for names and tactics — a failure
//! there is an empty mapping, as Python's `except` makes it —, then search
//! the index pattern with `AsyncElasticsearch` (aiohttp's headers, a `POST
//! /{pattern}/_search` with `JSONSerializer.dumps`' compact body), trying
//! the MITRE id fields in Python's order (the caller's `mitre_field` first)
//! until one answers; any failure on a field (the search, an answer of an
//! unexpected shape) moves to the next one, as the per-field `except` does.
//! The answers keep Python's operations on whatever came back (`str(key)
//! .strip()`, the `hits.total` fallback, the `[:2]` slice that only a list
//! or a string survives).
//!
//! A scoped caller's search covers only the indices named after one of
//! their customers (`index_matches_customer`, the rule of `/api/alerts`):
//! one more filter clause, `_index` matching `*<matcher>*` for each
//! customer's code and names; Python searched every tenant's indices
//! (RUST_MIGRATION.md §4). A caller with no such matcher gets the answer of
//! an empty search without the indexer being asked. A deployment-wide
//! caller's requests are byte for byte Python's.

use chrono::Utc;
use copilot_auth::access::AccessScope;
use copilot_searches::py::{self, py_strip};
use copilot_upstream::json::{Dumps, py_dumps_allow_nan};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_wazuh::WazuhState;
use copilot_wazuh::es::{ConnectError, Es, Flavor, make_path};
use copilot_wazuh::indexer::services::alerts::isoformat;
use copilot_wazuh::indexer::services::customer_matchers;
use copilot_wazuh::manager::client::Param;
use copilot_wazuh::manager::services::{get_mitre, lists};
use copilot_web::ApiError;
use copilot_yaml::Value;
use num_bigint_dig::BigInt;
use reqwest::Method;

/// `field_options` before the caller's field.
const ID_FIELDS: [&str; 3] = ["rule_mitre_id", "rule.mitre.id", "mitre.id"];
/// `name_field_options`, paired with `field_options` by position.
const NAME_FIELDS: [&str; 3] = [
    "rule_mitre_technique",
    "rule.mitre.technique",
    "mitre.technique",
];
/// `"Unknown Technique"`.
pub const UNKNOWN: &str = "Unknown Technique";
/// The count query's `size`.
const COUNT_SIZE: i64 = 10_000;
/// Characters an index name cannot hold: a matcher with one never matches.
const NOT_IN_INDEX_NAMES: &[char] = &['\\', '/', '*', '?', '"', '<', '>', '|', ' ', ',', '#', ':'];

/// Which indices a search may read.
#[derive(Debug, Clone)]
pub enum Tenant {
    /// Every index (a deployment-wide caller): Python's request.
    All,
    /// Only those this clause keeps (`_index` named after a customer).
    Indices(Value),
    /// None: the indexer is not asked.
    Nothing,
}

/// The search scope of a caller.
pub async fn tenant(st: &WazuhState, scope: &AccessScope) -> Result<Tenant, ApiError> {
    let AccessScope::Customers(codes) = scope else {
        return Ok(Tenant::All);
    };
    let matchers = customer_matchers(&st.ctx.db, codes)
        .await
        .map_err(ApiError::from)?;
    let usable: Vec<String> = matchers
        .into_iter()
        .filter(|m| !m.contains(NOT_IN_INDEX_NAMES))
        .collect();
    if usable.is_empty() {
        return Ok(Tenant::Nothing);
    }
    let should = usable
        .iter()
        .map(|m| {
            py::dict(vec![(
                "wildcard",
                py::dict(vec![("_index", py::s(format!("*{m}*")))]),
            )])
        })
        .collect();
    Ok(Tenant::Indices(py::dict(vec![(
        "bool",
        py::dict(vec![
            ("should", py::list(should)),
            ("minimum_should_match", py::int(1)),
        ]),
    )])))
}

/// What both routes read from the query.
#[derive(Debug, Clone)]
pub struct Search {
    /// `time_range`.
    pub time_range: String,
    /// `size`.
    pub size: BigInt,
    /// `(page - 1) * size`.
    pub offset: BigInt,
    /// The route's `additional_filters`.
    pub filters: Vec<Value>,
    /// `index_pattern`.
    pub index_pattern: String,
    /// `mitre_field`.
    pub mitre_field: Option<String>,
}

/// A small `dict[str, T]` (assignment keeps an existing key's place).
#[derive(Debug, Clone)]
pub struct Mapping<T>(Vec<(String, T)>);

impl<T> Default for Mapping<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T: Clone> Mapping<T> {
    fn set(&mut self, key: &str, value: T) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value,
            None => self.0.push((key.to_string(), value)),
        }
    }

    /// `mapping.get(key)`.
    pub fn get(&self, key: &str) -> Option<&T> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// `bool(mapping)`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn text<'a>(item: &'a serde_json::Value, key: &str) -> &'a str {
    item.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

fn results(answer: &serde_json::Value) -> &[serde_json::Value] {
    answer
        .get("results")
        .and_then(serde_json::Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// `get_mitre_<what>(limit=1000)`: the validated items, or `None` where
/// Python's call raised.
async fn mitre_items(
    st: &WazuhState,
    list: copilot_wazuh::manager::services::MitreList,
) -> Option<serde_json::Value> {
    get_mitre(st, list, vec![("limit".to_string(), Param::Int(1000))])
        .await
        .map_err(|e| tracing::error!("Error building technique mapping: {}", e.py_str()))
        .ok()
}

/// `_build_technique_id_name_mapping()`.
pub async fn technique_names(st: &WazuhState) -> Mapping<String> {
    let mut mapping = Mapping::default();
    let Some(answer) = mitre_items(st, lists::TECHNIQUES).await else {
        return mapping;
    };
    for technique in results(&answer) {
        let id = text(technique, "id");
        let name = text(technique, "name");
        if !id.is_empty() {
            mapping.set(id, name.to_string());
            if let Some(rest) = id.strip_prefix('T') {
                mapping.set(rest, name.to_string());
            }
        }
    }
    tracing::info!("Built mapping for {} MITRE techniques", mapping.0.len());
    mapping
}

/// `_build_technique_tactic_mapping()`: an id (and the external id, with
/// and without its `T`) → the technique's tactics.
pub async fn technique_tactics(st: &WazuhState) -> Mapping<Value> {
    let mut mapping = Mapping::default();
    let Some(techniques) = mitre_items(st, lists::TECHNIQUES).await else {
        return mapping;
    };
    // Inside the same `try`: a failed tactics call is an empty mapping.
    let Some(tactics) = mitre_items(st, lists::TACTICS).await else {
        return mapping;
    };
    let mut names: Mapping<(String, String)> = Mapping::default();
    for tactic in results(&tactics) {
        let id = text(tactic, "id");
        if !id.is_empty() {
            names.set(
                id,
                (
                    text(tactic, "name").to_string(),
                    text(tactic, "short_name").to_string(),
                ),
            );
        }
    }
    for technique in results(&techniques) {
        let id = text(technique, "id");
        if id.is_empty() {
            continue;
        }
        let ids = technique
            .get("tactics")
            .and_then(serde_json::Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let infos = ids
            .iter()
            .map(|t| {
                let tactic = t.as_str().unwrap_or("");
                let (name, short) = names
                    .get(tactic)
                    .cloned()
                    .unwrap_or_else(|| (String::from("Unknown"), String::new()));
                py::dict(vec![
                    ("id", py::s(tactic)),
                    ("name", py::s(name)),
                    ("short_name", py::s(short)),
                ])
            })
            .collect();
        let infos = py::list(infos);
        let external = text(technique, "external_id");
        if !external.is_empty() {
            mapping.set(external, infos.clone());
            if let Some(rest) = external.strip_prefix('T') {
                mapping.set(rest, infos.clone());
            }
        }
        mapping.set(id, infos);
    }
    mapping
}

/// `_get_wazuh_indexer_client()`: its `HTTPException(503, …)`.
async fn client(st: &WazuhState) -> PyResult<Es> {
    Es::connect(&st.es, &st.ctx.connectors, Flavor::Async)
        .await
        .map_err(|e| {
            let inner = match e {
                ConnectError::Http(d) => PyExc::http(500, d),
                ConnectError::Db(d) => PyExc::Other("OperationalError", d),
            };
            tracing::error!("Failed to create OpenSearch client: {}", inner.display());
            PyExc::http(
                503,
                format!("Unable to connect to Wazuh Indexer: {}", inner.display()),
            )
        })
}

/// `client.search(index=…, body=…)`: the answer as `json.loads` makes it,
/// or the exception (its text only logged).
async fn search(es: &Es, index: &str, body: &Value) -> PyResult<Value> {
    let Some(py_body) = py::to_py(body) else {
        return Err(PyExc::TypeError("Unable to serialize the body".into()));
    };
    let payload = py_dumps_allow_nan(&py_body, Dumps::HTTPX).into_bytes();
    es.perform_raw(
        Method::POST,
        &make_path(&[index, "_search"]),
        &[],
        Some(payload),
    )
    .await
    .map(|v| py::from_json(&v))
    .map_err(|e| PyExc::Other("TransportError", e.to_string()))
}

fn int_of(n: &BigInt) -> Value {
    Value::Int(n.clone())
}

/// `{"range": {"timestamp": {"from": time_range, "to": "now"}}}`.
fn time_range(range: &str) -> Value {
    py::dict(vec![(
        "range",
        py::dict(vec![(
            "timestamp",
            py::dict(vec![("from", py::s(range)), ("to", py::s("now"))]),
        )]),
    )])
}

/// The painless source of `_build_mitre_search_query` (its f-string, line
/// by line).
fn script_source(field: &str) -> String {
    [
        "",
        &format!("    def field_value = doc['{field}'].value;"),
        "    if (field_value != null && field_value != '') {",
        "        def techniques = new ArrayList();",
        "        // Split by comma and clean up whitespace",
        "        def parts = field_value.splitOnToken(',');",
        "        for (def part : parts) {",
        "            def cleaned = part.trim();",
        "            if (cleaned != '') {",
        "                techniques.add(cleaned);",
        "            }",
        "        }",
        "        return techniques;",
        "    }",
        "    return [];",
        "    ",
    ]
    .join("\n")
}

/// `_build_mitre_search_query(...)["body"]` (its `size` is always 0).
pub fn aggregation_body(
    s: &Search,
    size: &BigInt,
    offset: &BigInt,
    field: &str,
    name_field: Option<&str>,
    tenant: Option<&Value>,
) -> Value {
    let mut filters = vec![
        py::dict(vec![("match_all", py::dict(vec![]))]),
        time_range(&s.time_range),
        py::dict(vec![("exists", py::dict(vec![("field", py::s(field))]))]),
    ];
    filters.extend(s.filters.iter().cloned());
    filters.extend(tenant.cloned());
    let mut techniques = vec![(
        "terms",
        py::dict(vec![
            (
                "script",
                py::dict(vec![
                    ("source", py::s(script_source(field))),
                    ("lang", py::s("painless")),
                ]),
            ),
            ("size", int_of(size)),
            ("order", py::dict(vec![("_count", py::s("desc"))])),
        ]),
    )];
    if let Some(name) = name_field {
        techniques.push((
            "aggs",
            py::dict(vec![(
                "technique_name",
                py::dict(vec![(
                    "terms",
                    py::dict(vec![("field", py::s(name)), ("size", py::int(1))]),
                )]),
            )]),
        ));
    }
    py::dict(vec![
        ("size", py::int(0)),
        ("from", int_of(offset)),
        (
            "query",
            py::dict(vec![(
                "bool",
                py::dict(vec![
                    ("must", py::list(vec![])),
                    ("filter", py::list(filters)),
                    ("should", py::list(vec![])),
                    ("must_not", py::list(vec![])),
                ]),
            )]),
        ),
        ("aggs", py::dict(vec![("techniques", py::dict(techniques))])),
    ])
}

/// `_build_mitre_alerts_query(...)["body"]`.
pub fn alerts_body(s: &Search, technique_id: &str, field: &str, tenant: Option<&Value>) -> Value {
    let mitre = py::dict(vec![(
        "bool",
        py::dict(vec![
            (
                "should",
                py::list(vec![
                    py::dict(vec![("term", py::dict(vec![(field, py::s(technique_id))]))]),
                    py::dict(vec![(
                        "wildcard",
                        py::dict(vec![(field, py::s(format!("*{technique_id}*")))]),
                    )]),
                    py::dict(vec![(
                        "query_string",
                        py::dict(vec![
                            (
                                "query",
                                py::s(format!(
                                    "{field}:\"{technique_id}\" OR {field}:\"*{technique_id}*\""
                                )),
                            ),
                            ("analyze_wildcard", Value::Bool(true)),
                        ]),
                    )]),
                ]),
            ),
            ("minimum_should_match", py::int(1)),
        ]),
    )]);
    let mut filters = vec![time_range(&s.time_range), mitre];
    filters.extend(s.filters.iter().cloned());
    filters.extend(tenant.cloned());
    py::dict(vec![
        ("size", int_of(&s.size)),
        ("from", int_of(&s.offset)),
        (
            "query",
            py::dict(vec![(
                "bool",
                py::dict(vec![("filter", py::list(filters))]),
            )]),
        ),
        ("_source", Value::Bool(true)),
        (
            "sort",
            py::list(vec![py::dict(vec![(
                "timestamp",
                py::dict(vec![("order", py::s("desc"))]),
            )])]),
        ),
        ("track_total_hits", Value::Bool(true)),
    ])
}

/// The caller's field first, then Python's three.
fn field_options(mitre_field: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = ID_FIELDS.iter().map(|f| (*f).to_string()).collect();
    if let Some(f) = mitre_field.filter(|f| !f.is_empty()) {
        out.insert(0, f.to_string());
    }
    out
}

/// `response["hits"]["total"]["value"] if isinstance(…, dict) and "value"
/// in … else response["hits"]["total"]`.
fn total_hits(response: &Value) -> PyResult<Value> {
    let total = py::getitem(&py::getitem(response, "hits")?, "total")?;
    if matches!(total, Value::Dict(_)) && py::contains_key(&total, "value")? {
        return py::getitem(&total, "value");
    }
    Ok(total)
}

/// `x[0]` once `len(x) > 0` held.
fn first(v: &Value) -> PyResult<Value> {
    match v {
        Value::List(items) | Value::Tuple(items) => {
            Ok(items.first().cloned().unwrap_or(Value::None))
        }
        Value::Str(t) => Ok(py::s(
            t.chars().next().map(String::from).unwrap_or_default(),
        )),
        Value::Dict(_) => Err(PyExc::KeyError("0".into())),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            py::tp_name(other)
        ))),
    }
}

/// `x[:2]` (only evaluated, for the log line).
fn slice_check(v: &Value) -> PyResult<()> {
    match v {
        Value::List(_) | Value::Tuple(_) | Value::Str(_) | Value::Bytes(_) => Ok(()),
        Value::Dict(_) => Err(PyExc::TypeError("unhashable type: 'slice'".into())),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            py::tp_name(other)
        ))),
    }
}

/// `datetime.utcnow().isoformat() + "Z"`.
fn last_seen() -> String {
    format!("{}Z", isoformat(Utc::now().naive_utc()))
}

/// What `search_mitre_techniques_in_alerts` returns (the keys the route
/// reads).
#[derive(Debug, Clone)]
pub struct Techniques {
    /// `total_alerts`.
    pub total_alerts: Value,
    /// `techniques`.
    pub techniques: Vec<Value>,
    /// `total_techniques_count`.
    pub total_count: Value,
    /// `field_used`.
    pub field_used: Option<String>,
}

/// `_process_mitre_search_results(...)`: the total, the techniques.
fn process(
    response: &Value,
    names: &Mapping<String>,
    name_field: Option<&str>,
    tactics: &Mapping<Value>,
) -> PyResult<(Value, Vec<Value>)> {
    if !response.truthy()
        || !py::contains_key(response, "aggregations")?
        || !py::contains_key(&py::getitem(response, "aggregations")?, "techniques")?
    {
        tracing::warn!("MITRE search response missing aggregations");
        return Ok((py::int(0), Vec::new()));
    }
    let buckets = py::getitem(
        &py::getitem(&py::getitem(response, "aggregations")?, "techniques")?,
        "buckets",
    )?;
    if buckets.truthy() {
        slice_check(&buckets)?;
    }
    let total = total_hits(response)?;
    let mut techniques = Vec::new();
    for bucket in py::iterate(&buckets)? {
        let key = py::getitem(&bucket, "key")?;
        if !key.truthy() {
            continue;
        }
        let technique_id = py_strip(&key.py_str()).to_string();
        if technique_id.is_empty() {
            continue;
        }
        let mut technique_name = py::s(UNKNOWN);
        if name_field.is_some()
            && py::contains_key(&bucket, "technique_name")?
            && py::contains_key(&py::getitem(&bucket, "technique_name")?, "buckets")?
        {
            let name_buckets = py::getitem(&py::getitem(&bucket, "technique_name")?, "buckets")?;
            if name_buckets.truthy() && py::len(&name_buckets)? > 0 {
                let key = py::getitem(&first(&name_buckets)?, "key")?;
                if key.truthy() {
                    technique_name = key;
                }
            }
        }
        let mut found = Value::None;
        if !tactics.is_empty() {
            if let Some(t) = tactics.get(&technique_id) {
                found = t.clone();
            } else if !technique_id.starts_with('T') {
                if let Some(t) = tactics.get(&format!("T{technique_id}")) {
                    found = t.clone();
                }
            } else if let Some(t) = tactics.get(&technique_id[1..]) {
                found = t.clone();
            }
        }
        let technique_tactics = match found {
            Value::None => py::list(Vec::new()),
            t => t,
        };
        if technique_name.as_str() == Some(UNKNOWN) {
            technique_name = py::s(names.get(&technique_id).map_or(UNKNOWN, String::as_str));
        }
        let count = py::getitem(&bucket, "doc_count")?;
        techniques.push(py::dict(vec![
            ("technique_id", py::s(technique_id)),
            ("technique_name", technique_name),
            ("count", count),
            ("last_seen", py::s(last_seen())),
            ("tactics", technique_tactics),
        ]));
    }
    Ok((total, techniques))
}

/// One field of the loop: `Ok(None)` when its count query found nothing.
async fn techniques_with_field(
    es: &Es,
    s: &Search,
    field: &str,
    name_field: Option<&str>,
    names: &Mapping<String>,
    tactics: &Mapping<Value>,
    tenant: Option<&Value>,
) -> PyResult<Option<Techniques>> {
    tracing::info!("Trying MITRE search with field: {field} (name field: {name_field:?})");
    let count_body = aggregation_body(
        s,
        &BigInt::from(COUNT_SIZE),
        &BigInt::from(0),
        field,
        name_field,
        tenant,
    );
    let counted = search(es, &s.index_pattern, &count_body).await?;
    let aggregations = py::get_none(&counted, "aggregations")?;
    if !aggregations.truthy() {
        return Ok(None);
    }
    let techniques = py::get_none(&aggregations, "techniques")?;
    if !techniques.truthy() {
        return Ok(None);
    }
    let buckets = py::get_none(&techniques, "buckets")?;
    if !buckets.truthy() {
        return Ok(None);
    }
    let total_count = py::len(&buckets)?;
    let body = aggregation_body(s, &s.size, &s.offset, field, name_field, tenant);
    let answer = search(es, &s.index_pattern, &body).await?;
    let (total_alerts, found) = process(&answer, names, name_field, tactics)?;
    tracing::info!(
        "Found {} MITRE techniques on this page, {total_count} total with field '{field}'",
        found.len()
    );
    Ok(Some(Techniques {
        total_alerts,
        techniques: found,
        total_count: py::int(i64::try_from(total_count).unwrap_or(i64::MAX)),
        field_used: Some(field.to_string()),
    }))
}

/// `search_mitre_techniques_in_alerts(...)`: its result, or its
/// `HTTPException(500, "Error searching MITRE techniques: …")`.
pub async fn techniques_in_alerts(
    st: &WazuhState,
    s: &Search,
    tenant: &Tenant,
) -> PyResult<Techniques> {
    let inner = async {
        let names = technique_names(st).await;
        let tactics = technique_tactics(st).await;
        let es = client(st).await?;
        let none = Techniques {
            total_alerts: py::int(0),
            techniques: Vec::new(),
            total_count: py::int(0),
            field_used: None,
        };
        let clause = match tenant {
            Tenant::All => None,
            Tenant::Indices(c) => Some(c),
            Tenant::Nothing => return Ok(none),
        };
        let fields = field_options(s.mitre_field.as_deref());
        for (i, field) in fields.iter().enumerate() {
            let name_field = NAME_FIELDS.get(i).copied();
            match techniques_with_field(&es, s, field, name_field, &names, &tactics, clause).await {
                Ok(Some(found)) => return Ok(found),
                Ok(None) => {
                    tracing::warn!("No results found with field '{field}', trying next option")
                }
                Err(e) => tracing::warn!("Error with field '{field}': {}", e.display()),
            }
        }
        tracing::warn!("No MITRE techniques found with any field option");
        Ok(none)
    };
    inner.await.map_err(|e: PyExc| {
        PyExc::http(
            500,
            format!("Error searching MITRE techniques: {}", e.display()),
        )
    })
}

/// What `get_alerts_by_mitre_id` returns.
#[derive(Debug, Clone)]
pub struct Alerts {
    /// `technique_name`.
    pub technique_name: String,
    /// `total_alerts`.
    pub total_alerts: Value,
    /// `alerts`.
    pub alerts: Vec<Value>,
    /// `field_used`.
    pub field_used: Option<String>,
}

/// `technique_mapping[…]` with and without the `T`.
fn name_of(names: &Mapping<String>, technique_id: &str) -> String {
    if let Some(n) = names.get(technique_id) {
        return n.clone();
    }
    if let Some(rest) = technique_id.strip_prefix('T') {
        if let Some(n) = names.get(rest) {
            return n.clone();
        }
    } else if let Some(n) = names.get(&format!("T{technique_id}")) {
        return n.clone();
    }
    UNKNOWN.to_string()
}

async fn alerts_with_field(
    es: &Es,
    s: &Search,
    technique_id: &str,
    field: &str,
    tenant: Option<&Value>,
) -> PyResult<Option<(Value, Vec<Value>)>> {
    tracing::info!("Trying to search alerts with field: {field}");
    let body = alerts_body(s, technique_id, field, tenant);
    let response = search(es, &s.index_pattern, &body).await?;
    if !py::get_none(&response, "hits")?.truthy() {
        return Ok(None);
    }
    let hits = py::getitem(&response, "hits")?;
    if !py::get_none(&hits, "hits")?.truthy() {
        return Ok(None);
    }
    let list = py::getitem(&hits, "hits")?;
    if py::len(&list)? == 0 {
        return Ok(None);
    }
    let total = total_hits(&response)?;
    let mut documents = Vec::new();
    for hit in py::iterate(&list)? {
        documents.push(py::getitem(&hit, "_source")?);
    }
    Ok(Some((total, documents)))
}

/// `get_alerts_by_mitre_id(...)`. `Err` is the exception that leaves it:
/// the client's 503 meets `except AsyncElasticsearch`, which is no
/// exception class, so it is a `TypeError` — uvicorn's bare 500.
pub async fn alerts_for_technique(
    st: &WazuhState,
    s: &Search,
    technique_id: &str,
    tenant: &Tenant,
) -> PyResult<Alerts> {
    let names = technique_names(st).await;
    let technique_name = name_of(&names, technique_id);
    let es = client(st).await.map_err(|e| {
        tracing::error!("{}", e.display());
        PyExc::TypeError(
            "catching classes that do not inherit from BaseException is not allowed".into(),
        )
    })?;
    let clause = match tenant {
        Tenant::All => None,
        Tenant::Indices(c) => Some(c),
        Tenant::Nothing => {
            return Ok(Alerts {
                technique_name,
                total_alerts: py::int(0),
                alerts: Vec::new(),
                field_used: None,
            });
        }
    };
    for field in field_options(s.mitre_field.as_deref()) {
        match alerts_with_field(&es, s, technique_id, &field, clause).await {
            Ok(Some((total_alerts, alerts))) => {
                return Ok(Alerts {
                    technique_name,
                    total_alerts,
                    alerts,
                    field_used: Some(field),
                });
            }
            Ok(None) => {
                tracing::warn!("No alerts found for technique {technique_id} with field '{field}'")
            }
            Err(e) => tracing::warn!("Error searching with field '{field}': {}", e.display()),
        }
    }
    Ok(Alerts {
        technique_name,
        total_alerts: py::int(0),
        alerts: Vec::new(),
        field_used: None,
    })
}

/// Python's `a // b` on integers (`ZeroDivisionError` for `b == 0`).
pub fn floor_div(a: &BigInt, b: &BigInt) -> PyResult<BigInt> {
    let zero = BigInt::from(0);
    if *b == zero {
        return Err(PyExc::Other(
            "ZeroDivisionError",
            "integer division or modulo by zero".into(),
        ));
    }
    let q = a / b;
    let r = a - &q * b;
    if r != zero && ((r < zero) != (*b < zero)) {
        Ok(q - BigInt::from(1))
    } else {
        Ok(q)
    }
}

/// Python's `x // y` on floats (`_float_div_mod`).
fn float_floor_div(x: f64, y: f64) -> PyResult<f64> {
    if y == 0.0 {
        return Err(PyExc::Other(
            "ZeroDivisionError",
            "float floor division by zero".into(),
        ));
    }
    let m = x % y;
    let mut div = (x - m) / y;
    if m != 0.0 && ((y < 0.0) != (m < 0.0)) {
        div -= 1.0;
    }
    if div != 0.0 {
        let mut floordiv = div.floor();
        if div - floordiv > 0.5 {
            floordiv += 1.0;
        }
        Ok(floordiv)
    } else {
        Ok(0.0_f64.copysign(x / y))
    }
}

/// `(total + size - 1) // size` on whatever `total` is (an `int`, a `bool`
/// or a `float` from the indexer; anything else is CPython's `TypeError`).
pub fn pages_of(total: &Value, size: &BigInt) -> PyResult<Value> {
    match total {
        Value::Int(_) | Value::Bool(_) => {
            let n = py::as_bigint(total).unwrap_or_default();
            Ok(Value::Int(floor_div(&(n + size - BigInt::from(1)), size)?))
        }
        Value::Float(f) => {
            let s = py::py_float(&Value::Int(size.clone()))?;
            float_floor_div(*f + s - 1.0, s).map(Value::Float)
        }
        other => Err(PyExc::TypeError(format!(
            "unsupported operand type(s) for +: '{}' and 'int'",
            py::tp_name(other)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_is_python_s_text() {
        // `repr()` of the f-string's value in `services/mitre.py`.
        assert_eq!(
            script_source("rule.mitre.id"),
            "\n    def field_value = doc['rule.mitre.id'].value;\n    if (field_value != null && \
             field_value != '') {\n        def techniques = new ArrayList();\n        // Split \
             by comma and clean up whitespace\n        def parts = \
             field_value.splitOnToken(',');\n        for (def part : parts) {\n            def \
             cleaned = part.trim();\n            if (cleaned != '') {\n                \
             techniques.add(cleaned);\n            }\n        }\n        return \
             techniques;\n    }\n    return [];\n    "
        );
    }

    #[test]
    fn python_floor_division() {
        let b = |n: i64| BigInt::from(n);
        assert_eq!(floor_div(&b(7), &b(-3)).unwrap(), b(-3));
        assert_eq!(floor_div(&b(-7), &b(3)).unwrap(), b(-3));
        assert_eq!(floor_div(&b(-1), &b(25)).unwrap(), b(-1));
        assert!(floor_div(&b(1), &b(0)).is_err());
        assert_eq!(float_floor_div(29.0, 25.0).unwrap(), 1.0);
        assert_eq!(float_floor_div(-1.5, 2.0).unwrap(), -1.0);
        assert!(float_floor_div(1.0, 0.0).is_err());
        assert_eq!(
            pages_of(&Value::Float(5.0), &b(25)).unwrap().py_repr(),
            "1.0"
        );
        assert_eq!(pages_of(&Value::Bool(true), &b(1)).unwrap().py_repr(), "1");
        assert!(pages_of(&py::s("5"), &b(1)).is_err());
    }
}
