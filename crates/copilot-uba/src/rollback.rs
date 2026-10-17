//! Roll SOCFortress UBA back for one customer (#1241) — port of
//! `services/rollback.py` (`GET|POST …/rollback`, `GET …/rollbacks[/{id}]`).
//!
//! Rollback removes what setup ([`crate::provision`]) put next to the
//! customer's streams, and only that, in an order that never leaves Graylog
//! routing to something that is gone: disconnect the UBA ROUTING pipelines,
//! detach and delete the output to UBA, delete the pipelines then their
//! rules, the feed streams, the customer's UBA ALERTS stream (the shared
//! input only with the last customer's), deactivate the customer in UBA,
//! then check the customer's own streams and Graylog's event definitions.
//!
//! An object is removed only when it is recorded for the customer
//! (`uba_provisioned_resource`) or carries setup's title, *and* still looks
//! like what setup makes *and* nothing else uses it; anything else is a
//! conflict and left alone. Every step is idempotent and a failed step does
//! not stop the independent ones. The report (snapshot, steps, checks) is a
//! `uba_rollback` row.
//!
//! The plan ([`compute_plan`]) is pure and pinned by Python's own fixtures
//! (`tests/test_uba_rollback.py`, ported in `rollback_tests.rs`). Graylog
//! objects are keyed by their `id`, which Graylog always sends as a string;
//! an id of another type is refused as an unsupported answer (a bare 500).

use std::sync::LazyLock;

use chrono::{NaiveDateTime, Timelike, Utc};
use copilot_auth::pyvalue::{PyValue, loads};
use copilot_core::time::now_utc_naive;
use copilot_db::Db;
use copilot_db::schema::TableRequirement;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::model::construct;
use copilot_upstream::py::{self, PyExc, PyResult, getitem, py_eq, type_name};
use http::Method;
use regex::Regex;

use crate::client::{Call, UbaError};
use crate::ops::{GraylogOps, Ops, UbaOps};
use crate::ownership::{
    self, ALERTS_INPUT, ALERTS_STREAM, FEED_STREAM, OUTPUT, Owned, ROUTING_PIPELINE, ROUTING_RULE,
    Row, WAZUH_RULES,
};
use crate::provision::{GELF_OUTPUT, GELF_TCP_INPUT, Step};
use crate::pyfmt::lower;
use crate::pyops::{
    OrderedMap, PyDict, contains, empty_dict, empty_list, format, get_or, hashable, join, list_eq,
    or_else, sorted, startswith, str_key, text, unsupported,
};
use crate::schema::{ROLLBACK_PLAN, ROLLBACK_REPORT, ROLLBACK_SUMMARY};
use crate::services::tenant;

/// `uba_rollback`'s columns.
pub const TABLE: TableRequirement = TableRequirement {
    table: "uba_rollback",
    columns: &[
        "id",
        "customer_code",
        "status",
        "started_at",
        "finished_at",
        "actor_user_id",
        "actor_username",
        "message",
        "snapshot",
        "steps",
        "verification",
    ],
};

/// A rollback "running" for longer died with its process (`RUNNING_FOR`).
pub const RUNNING_FOR_MINUTES: i64 = 10;

// Python's `\s` in a `str` pattern is `str.isspace()`: the regex crate's
// `\s` plus U+001C..U+001F.
static RULE_IN_PIPELINE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?m)^[\s\x1c-\x1f]*rule[\s\x1c-\x1f]+"([^"]+)""#).ok());
static ROUTE_TO: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"route_to_stream[\s\x1c-\x1f]*\([\s\x1c-\x1f]*name[\s\x1c-\x1f]*:[\s\x1c-\x1f]*"([^"]+)""#,
    )
    .ok()
});

fn findall(re: &Option<Regex>, value: &PyValue) -> PyResult<Vec<PyValue>> {
    match value {
        PyValue::Str(s) => Ok(re
            .iter()
            .flat_map(|re| re.captures_iter(s))
            .filter_map(|c| c.get(1))
            .map(|m| PyValue::Str(m.as_str().to_string()))
            .collect()),
        other => Err(PyExc::TypeError(format!(
            "expected string or bytes-like object, got '{}'",
            type_name(other)
        ))),
    }
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn dict(items: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// `DEFAULT_NAMES`: setup's object names, used when UBA cannot be asked.
pub fn default_names() -> PyValue {
    dict(vec![
        (
            "sources",
            dict(vec![("WAZUH", s("wazuh")), ("O365", s("office365"))]),
        ),
        ("feed_stream", s("UBA FEED - {source} - {tenant}")),
        ("routing_pipeline", s("UBA ROUTING - {source} - {tenant}")),
        ("output", s("UBA GELF - {tenant}")),
        ("alerts_input", s("UBA ALERTS")),
        ("alerts_stream", s("UBA ALERTS - {tenant}")),
    ])
}

// --- what Graylog holds -----------------------------------------------------------------------

/// `GraylogState`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GraylogState {
    /// Streams by id.
    pub streams: OrderedMap<PyValue>,
    /// Pipelines by id.
    pub pipelines: OrderedMap<PyValue>,
    /// Rules by id.
    pub rules: OrderedMap<PyValue>,
    /// Outputs by id.
    pub outputs: OrderedMap<PyValue>,
    /// Inputs by id.
    pub inputs: OrderedMap<PyValue>,
    /// Stream id → pipeline ids.
    pub connections: OrderedMap<Vec<PyValue>>,
    /// `None`: could not be read.
    pub event_definitions: Option<Vec<PyValue>>,
}

impl GraylogState {
    /// `pipeline_rules(pipeline_id)`: the rule titles of its stages, else
    /// those its source names.
    pub fn pipeline_rules(&self, pipeline_id: &str) -> PyResult<Vec<PyValue>> {
        let pipeline = or_else(self.pipelines.get(pipeline_id), empty_dict());
        let mut titles = Vec::new();
        for stage in py::iterate(&or_else(py::get(&pipeline, "stages")?, empty_list()))? {
            titles.extend(py::iterate(&or_else(
                py::get(&stage, "rules")?,
                empty_list(),
            ))?);
        }
        if !titles.is_empty() {
            return Ok(titles);
        }
        findall(
            &RULE_IN_PIPELINE,
            &or_else(py::get(&pipeline, "source")?, s("")),
        )
    }

    /// `pipeline_streams(pipeline_id)`: the streams it is connected to.
    pub fn pipeline_streams(&self, pipeline_id: &str) -> Vec<String> {
        let id = s(pipeline_id);
        let mut out: Vec<String> = self
            .connections
            .iter()
            .filter(|(_, pipelines)| pipelines.iter().any(|p| py_eq(p, &id)))
            .map(|(k, _)| k.clone())
            .collect();
        out.sort();
        out
    }

    /// `stream_outputs(stream_id)`.
    pub fn stream_outputs(&self, stream_id: &str) -> PyResult<Vec<PyValue>> {
        let stream = or_else(self.streams.get(stream_id), empty_dict());
        let outputs = or_else(py::get(&stream, "outputs")?, empty_list());
        py::iterate(&outputs)?
            .into_iter()
            .map(|o| match &o {
                PyValue::Dict(_) => getitem(&o, "id").cloned(),
                other => Ok(PyValue::Str(other.py_str())),
            })
            .collect()
    }

    /// `output_streams(output_id)`: the streams it is attached to.
    pub fn output_streams(&self, output_id: &str) -> PyResult<Vec<String>> {
        let id = s(output_id);
        let mut out = Vec::new();
        for stream_id in self.streams.keys() {
            if self
                .stream_outputs(stream_id)?
                .iter()
                .any(|o| py_eq(o, &id))
            {
                out.push(stream_id.clone());
            }
        }
        out.sort();
        Ok(out)
    }

    /// `definitions_on(stream_id)`: the event definitions that read it.
    pub fn definitions_on(&self, stream_id: &str) -> PyResult<Vec<PyValue>> {
        let id = s(stream_id);
        let mut out = Vec::new();
        for d in self.event_definitions.iter().flatten() {
            let config = or_else(py::get(d, "config")?, empty_dict());
            let streams = or_else(py::get(&config, "streams")?, empty_list());
            if contains(&streams, &id)? {
                out.push(d.clone());
            }
        }
        Ok(out)
    }

    fn connections_of(&self, stream_id: &str) -> Vec<PyValue> {
        self.connections.get(stream_id).cloned().unwrap_or_default()
    }
}

/// `_get(endpoint, key, params)`.
async fn data(
    g: &dyn GraylogOps,
    endpoint: &str,
    key: Option<&str>,
    params: &[(&str, String)],
) -> PyResult<PyValue> {
    let data = g.get(endpoint, params).await?.data;
    match key {
        Some(k) => get_or(&or_else(Some(&data), empty_dict()), k, empty_list()),
        None => Ok(or_else(Some(&data), empty_list())),
    }
}

/// A Graylog id used as a dict key.
fn id_key(value: &PyValue, what: &str) -> PyResult<String> {
    hashable(value)?;
    match value {
        PyValue::Str(v) => Ok(v.clone()),
        other => Err(unsupported(what, other)),
    }
}

fn by_id(list: &PyValue) -> PyResult<OrderedMap<PyValue>> {
    let mut map = OrderedMap::default();
    for o in py::iterate(list)? {
        let id = id_key(getitem(&o, "id")?, "A Graylog object's id")?;
        map.insert(id, o);
    }
    Ok(map)
}

/// `len(found) >= total`.
fn at_least(found: usize, total: &PyValue) -> PyResult<bool> {
    let n = i128::try_from(found).unwrap_or(i128::MAX);
    match total {
        PyValue::Bool(b) => Ok(n >= i128::from(*b)),
        PyValue::Int(t) => Ok(match t.parse::<i128>() {
            Ok(t) => n >= t,
            Err(_) => t.starts_with('-'),
        }),
        PyValue::Float(f) => Ok((found as f64) >= *f),
        other => Err(PyExc::TypeError(format!(
            "'>=' not supported between instances of 'int' and '{}'",
            type_name(other)
        ))),
    }
}

async fn event_definitions(g: &dyn GraylogOps) -> PyResult<Option<Vec<PyValue>>> {
    let mut found = Vec::new();
    let mut page: u32 = 1;
    loop {
        let params = [("per_page", "500".to_string()), ("page", page.to_string())];
        let data = match data(g, "/api/events/definitions", None, &params).await {
            Ok(d) => d,
            Err(PyExc::Http(_, detail)) => {
                tracing::warn!(
                    "UBA rollback: could not read Graylog's event definitions: {detail}"
                );
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let d = or_else(Some(&data), empty_dict());
        let batch = or_else(py::get(&d, "event_definitions")?, empty_list());
        found.extend(py::iterate(&batch)?);
        let total = py::get(&d, "total")?.cloned().unwrap_or(PyValue::None);
        if !batch.truthy() {
            return Ok(Some(found));
        }
        if !matches!(total, PyValue::None) && at_least(found.len(), &total)? {
            return Ok(Some(found));
        }
        if page >= 50 {
            return Ok(Some(found));
        }
        page += 1;
    }
}

/// `read_graylog()`, in Python's order.
pub async fn read_graylog(g: &dyn GraylogOps) -> PyResult<GraylogState> {
    let mut connections: OrderedMap<Vec<PyValue>> = OrderedMap::default();
    for c in py::iterate(&data(g, "/api/system/pipelines/connections", None, &[]).await?)? {
        let key = id_key(
            getitem(&c, "stream_id")?,
            "A pipeline connection's stream_id",
        )?;
        if !connections.contains(&key) {
            connections.insert(key.clone(), Vec::new());
        }
        let more = py::iterate(&or_else(py::get(&c, "pipeline_ids")?, empty_list()))?;
        if let Some(v) = connections.get_mut(&key) {
            v.extend(more);
        }
    }
    let streams = by_id(&data(g, "/api/streams", Some("streams"), &[]).await?)?;
    let pipelines = by_id(&data(g, "/api/system/pipelines/pipeline", None, &[]).await?)?;
    let rules = by_id(&data(g, "/api/system/pipelines/rule", None, &[]).await?)?;
    let outputs = by_id(&data(g, "/api/system/outputs", Some("outputs"), &[]).await?)?;
    let inputs = by_id(&data(g, "/api/system/inputs", Some("inputs"), &[]).await?)?;
    Ok(GraylogState {
        streams,
        pipelines,
        rules,
        outputs,
        inputs,
        connections,
        event_definitions: event_definitions(g).await?,
    })
}

// --- what the customer owns ---------------------------------------------------------------------

/// What the plan reads from the database (read-only, loaded up front).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// `_source_stream_ids`: the customer's Wazuh and Office365 streams.
    pub source_streams: Vec<String>,
    /// `ownership.active(session, customer_code)`.
    pub recorded: Vec<Row>,
    /// `ownership.active(session)`.
    pub all_active: Vec<Row>,
}

/// Load [`Facts`] with SQLAlchemy's statements.
pub async fn load_facts(db: &Db, customer_code: &str) -> Result<Facts, sqlx::Error> {
    let meta: Option<(String,)> = sqlx::query_as(
        "SELECT customersmeta.customer_meta_graylog_stream FROM customersmeta \
         WHERE customersmeta.customer_code = ?",
    )
    .bind(customer_code)
    .fetch_all(db.pool())
    .await?
    .into_iter()
    .next();
    let mut ids: Vec<String> = Vec::new();
    if let Some((stream,)) = meta.filter(|(s,)| !s.is_empty()) {
        ids.push(stream);
    }
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT customer_integrations_meta.graylog_stream_id FROM customer_integrations_meta \
         WHERE customer_integrations_meta.customer_code = ? \
         AND customer_integrations_meta.integration_name = ?",
    )
    .bind(customer_code)
    .bind("Office365")
    .fetch_all(db.pool())
    .await?;
    for (stream,) in rows {
        if !stream.is_empty() && !ids.contains(&stream) {
            ids.push(stream);
        }
    }
    Ok(Facts {
        source_streams: ids,
        recorded: ownership::active(db, Some(customer_code)).await?,
        all_active: ownership::active(db, None).await?,
    })
}

/// What happens to an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Removed by the rollback.
    Remove,
    /// Left in place on purpose.
    Keep,
    /// Looks like UBA's but is not provably the customer's: never touched.
    Conflict,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Action::Remove => "remove",
            Action::Keep => "keep",
            Action::Conflict => "conflict",
        }
    }
}

/// `Item`: one object of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Its kind.
    pub kind: &'static str,
    /// The Graylog id.
    pub graylog_id: String,
    /// Its title.
    pub title: String,
    /// `WAZUH` / `O365`.
    pub source: Option<String>,
    /// Recorded by setup.
    pub recorded: bool,
    /// Used by every customer.
    pub shared: bool,
    /// Why (shown).
    pub detail: String,
    /// What happens to it.
    pub action: Action,
}

impl Item {
    fn new(kind: &'static str, graylog_id: &str, title: &str, source: Option<String>) -> Self {
        Self {
            kind,
            graylog_id: graylog_id.to_string(),
            title: title.to_string(),
            source,
            recorded: false,
            shared: false,
            detail: String::new(),
            action: Action::Remove,
        }
    }

    /// `out()`: the `UbaRollbackItem`.
    pub fn out(&self) -> PyValue {
        dict(vec![
            ("kind", s(self.kind)),
            ("id", s(&self.graylog_id)),
            ("title", s(&self.title)),
            ("source", self.source.as_deref().map_or(PyValue::None, s)),
            ("recorded", PyValue::Bool(self.recorded)),
            ("detail", s(&self.detail)),
        ])
    }

    /// `owned()`: what [`ownership::mark_removed`] records.
    pub fn owned(&self) -> Owned {
        Owned {
            kind: self.kind,
            graylog_id: self.graylog_id.clone(),
            title: self.title.clone(),
            source: self.source.clone(),
            shared: self.shared,
            origin: if self.recorded { "found" } else { "adopted" },
        }
    }

    fn conflict(&mut self, why: String) {
        self.action = Action::Conflict;
        self.detail = why;
    }
}

/// `Plan`.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// The customer.
    pub customer_code: String,
    /// UBA's object names (setup's defaults merged under them).
    pub names: PyValue,
    /// Graylog before the rollback.
    pub state: GraylogState,
    /// The customer's own streams.
    pub source_streams: Vec<String>,
    /// The objects found.
    pub items: Vec<Item>,
    /// Recorded, no longer in Graylog.
    pub gone: Vec<Item>,
    /// UBA's onboarding state (`None`: UBA does not know the customer).
    pub uba: Option<PyValue>,
    /// Why UBA could not be asked.
    pub uba_problem: Option<String>,
}

impl Plan {
    /// `of(kind, action)`: indices into `items`.
    pub fn of(&self, kind: &str, action: Option<Action>) -> Vec<usize> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.kind == kind && action.is_none_or(|a| i.action == a))
            .map(|(n, _)| n)
            .collect()
    }

    fn ids(&self, kind: &str, action: Option<Action>) -> Vec<String> {
        self.of(kind, action)
            .into_iter()
            .map(|n| self.items[n].graylog_id.clone())
            .collect()
    }
}

/// `list(names["sources"])`.
fn source_names(names: &PyValue) -> PyResult<Vec<String>> {
    py::iterate(getitem(names, "sources")?)?
        .iter()
        .map(|v| match v {
            PyValue::Str(x) => Ok(x.clone()),
            other => Err(unsupported("A UBA source name", other)),
        })
        .collect()
}

/// `names[key].format(source=…, tenant=…)` for every source: title → source.
fn titles_per_source(
    names: &PyValue,
    key: &str,
    sources: &[String],
    code: &str,
) -> PyResult<Vec<(String, Option<String>)>> {
    let template = getitem(names, key)?;
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for source in sources {
        let title = format(template, &[("source", source), ("tenant", code)])?;
        match out.iter_mut().find(|(t, _)| *t == title) {
            Some(slot) => slot.1 = Some(source.clone()),
            None => out.push((title, Some(source.clone()))),
        }
    }
    Ok(out)
}

/// `current or fallback` for an optional source name.
fn or_source(
    current: &Option<String>,
    fallback: impl FnOnce() -> Option<String>,
) -> Option<String> {
    match current {
        Some(v) if !v.is_empty() => current.clone(),
        _ => fallback(),
    }
}

fn title_source(titles: &[(String, Option<String>)], title: &str) -> Option<String> {
    titles
        .iter()
        .find(|(t, _)| t == title)
        .and_then(|(_, s)| s.clone())
}

/// `_candidates(plan, kind, recorded, objects, titles)`: recorded objects
/// of `kind`, plus objects carrying one of `titles`.
fn candidates(
    gone: &mut Vec<Item>,
    kind: &'static str,
    recorded: &[Row],
    objects: &OrderedMap<PyValue>,
    titles: &[(String, Option<String>)],
) -> PyResult<Vec<Item>> {
    let mut found: OrderedMap<Item> = OrderedMap::default();
    for row in recorded.iter().filter(|r| r.kind == kind) {
        let Some(obj) = objects.get(&row.graylog_id) else {
            let mut item = Item::new(kind, &row.graylog_id, &row.title, row.source.clone());
            item.recorded = true;
            item.shared = row.shared;
            gone.push(item);
            continue;
        };
        let title = match py::get(obj, "title")? {
            Some(t) if t.truthy() => match t {
                PyValue::Str(t) => t.clone(),
                other => return Err(unsupported("A Graylog object's title", other)),
            },
            _ => row.title.clone(),
        };
        let mut item = Item::new(kind, &row.graylog_id, &title, row.source.clone());
        item.recorded = true;
        item.shared = row.shared;
        found.insert(row.graylog_id.clone(), item);
    }
    for (id, obj) in objects.iter() {
        if found.contains(id) {
            continue;
        }
        let title = py::get(obj, "title")?.cloned().unwrap_or(PyValue::None);
        if let Some(t) = str_key(&title)? {
            if let Some((t, source)) = titles.iter().find(|(x, _)| x == t) {
                found.insert(id.clone(), Item::new(kind, id, t, source.clone()));
            }
        }
    }
    Ok(found.values().cloned().collect())
}

fn routes_to(rule: &PyValue) -> PyResult<Vec<PyValue>> {
    findall(&ROUTE_TO, &or_else(py::get(rule, "source")?, s("")))
}

fn title_or(obj: Option<&PyValue>, fallback: PyValue) -> PyResult<PyValue> {
    match obj {
        Some(o) => get_or(o, "title", fallback),
        None => Ok(fallback),
    }
}

/// The plan, from what was read (`build_plan` after its reads).
pub fn compute_plan(
    customer_code: &str,
    names: PyValue,
    state: GraylogState,
    facts: &Facts,
    uba: Option<PyValue>,
    uba_problem: Option<String>,
) -> PyResult<Plan> {
    let mut plan = Plan {
        customer_code: customer_code.to_string(),
        names,
        state,
        source_streams: facts.source_streams.clone(),
        items: Vec::new(),
        gone: Vec::new(),
        uba,
        uba_problem,
    };
    let code = customer_code;
    let names = plan.names.clone();
    let sources = source_names(&names)?;
    let protected = facts.source_streams.clone();
    let recorded = &facts.recorded;

    // Feed streams.
    let feed_titles = titles_per_source(&names, "feed_stream", &sources, code)?;
    for mut item in candidates(
        &mut plan.gone,
        FEED_STREAM,
        recorded,
        &plan.state.streams,
        &feed_titles,
    )? {
        let stream = plan
            .state
            .streams
            .get(&item.graylog_id)
            .cloned()
            .unwrap_or_else(empty_dict);
        item.source = or_source(&item.source, || title_source(&feed_titles, &item.title));
        if protected.contains(&item.graylog_id)
            || get_or(&stream, "is_default", PyValue::None)?.truthy()
        {
            item.conflict("is one of the customer's own streams".into());
        } else if !item.title.starts_with("UBA FEED - ")
            || get_or(&stream, "rules", PyValue::None)?.truthy()
        {
            item.conflict(
                "does not look like a UBA feed stream (renamed, or it has stream rules)".into(),
            );
        }
        plan.items.push(item);
    }

    // Routing pipelines: only the customer's UBA routing rules may run in them.
    let mut feeds: Vec<String> = plan
        .of(FEED_STREAM, None)
        .into_iter()
        .map(|n| plan.items[n].title.clone())
        .collect();
    for source in &sources {
        let t = format(
            getitem(&names, "feed_stream")?,
            &[("source", source), ("tenant", code)],
        )?;
        if !feeds.contains(&t) {
            feeds.push(t);
        }
    }
    let starts_with_feed = |r: &PyValue| -> PyResult<bool> {
        for t in &feeds {
            if startswith(r, &format!("{t} - "))? {
                return Ok(true);
            }
        }
        Ok(false)
    };
    let pipeline_titles = titles_per_source(&names, "routing_pipeline", &sources, code)?;
    for mut item in candidates(
        &mut plan.gone,
        ROUTING_PIPELINE,
        recorded,
        &plan.state.pipelines,
        &pipeline_titles,
    )? {
        item.source = or_source(&item.source, || title_source(&pipeline_titles, &item.title));
        let mut foreign = Vec::new();
        for r in plan.state.pipeline_rules(&item.graylog_id)? {
            if !starts_with_feed(&r)? {
                foreign.push(r);
            }
        }
        let connected = plan.state.pipeline_streams(&item.graylog_id);
        if !item.title.starts_with("UBA ROUTING - ") || !foreign.is_empty() {
            let why = if foreign.is_empty() {
                "renamed".to_string()
            } else {
                let five: Vec<PyValue> = foreign.iter().take(5).cloned().collect();
                format!("runs rules UBA setup did not make: {}", join(", ", &five)?)
            };
            item.conflict(why);
        } else {
            item.detail = format!("connected to {} stream(s)", connected.len());
        }
        plan.items.push(item);
    }
    let removable_pipelines = plan.ids(ROUTING_PIPELINE, Some(Action::Remove));

    // Routing rules: route only to the customer's feed streams, run by no
    // other pipeline.
    let mut rule_titles: Vec<(String, Option<String>)> = Vec::new();
    for r in plan.state.rules.values() {
        let title = get_or(r, "title", s(""))?;
        if starts_with_feed(&title)? {
            let key = getitem(r, "title")?;
            if let Some(k) = str_key(key)? {
                if !rule_titles.iter().any(|(t, _)| t == k) {
                    rule_titles.push((k.to_string(), None));
                }
            }
        }
    }
    for mut item in candidates(
        &mut plan.gone,
        ROUTING_RULE,
        recorded,
        &plan.state.rules,
        &rule_titles,
    )? {
        let rule = plan
            .state
            .rules
            .get(&item.graylog_id)
            .cloned()
            .unwrap_or_else(empty_dict);
        let targets = routes_to(&rule)?;
        let title = s(&item.title);
        let mut users = Vec::new();
        for p in plan.state.pipelines.keys() {
            if plan
                .state
                .pipeline_rules(p)?
                .iter()
                .any(|r| py_eq(r, &title))
                && !removable_pipelines.contains(p)
            {
                users.push(p.clone());
            }
        }
        let all_feeds = targets
            .iter()
            .all(|t| t.as_str().is_some_and(|t| feeds.iter().any(|f| f == t)));
        if targets.is_empty() || !all_feeds {
            item.conflict("does not route to the customer's UBA feed streams".into());
        } else if !users.is_empty() {
            let mut names_of = Vec::new();
            for p in &users {
                names_of.push(title_or(plan.state.pipelines.get(p), s(p))?);
            }
            item.conflict(format!(
                "also run by pipeline(s) {}",
                join(", ", &names_of)?
            ));
        } else {
            item.source = or_source(&item.source, || {
                feed_titles
                    .iter()
                    .find(|(t, _)| item.title.starts_with(&format!("{t} - ")))
                    .and_then(|(_, s)| s.clone())
            });
        }
        plan.items.push(item);
    }
    let removable_rules: Vec<String> = plan
        .of(ROUTING_RULE, Some(Action::Remove))
        .into_iter()
        .map(|n| plan.items[n].title.clone())
        .collect();

    // A feed stream another rule still routes to stays.
    for n in plan.of(FEED_STREAM, Some(Action::Remove)) {
        let item_title = s(&plan.items[n].title);
        let mut routing_here = Vec::new();
        for r in plan.state.rules.values() {
            if routes_to(r)?.iter().any(|t| py_eq(t, &item_title)) {
                let title = getitem(r, "title")?;
                hashable(title)?;
                if !title
                    .as_str()
                    .is_some_and(|t| removable_rules.iter().any(|x| x == t))
                {
                    routing_here.push(title.clone());
                }
            }
        }
        let others = plan.state.connections_of(&plan.items[n].graylog_id);
        let definitions = plan.state.definitions_on(&plan.items[n].graylog_id)?;
        if !routing_here.is_empty() {
            let five: Vec<PyValue> = routing_here.into_iter().take(5).collect();
            let why = format!(
                "rule(s) UBA setup did not make route to it: {}",
                join(", ", &five)?
            );
            plan.items[n].conflict(why);
        } else if !others.is_empty() {
            let why = format!("{} pipeline(s) are connected to it", others.len());
            plan.items[n].conflict(why);
        } else if !definitions.is_empty() {
            let mut five = Vec::new();
            for d in definitions.iter().take(5) {
                let id = get_or(d, "id", PyValue::None)?;
                five.push(get_or(d, "title", id)?);
            }
            let why = format!("event definition(s) read it: {}", join(", ", &five)?);
            plan.items[n].conflict(why);
        }
    }

    // The output to UBA.
    let output_title = format(getitem(&names, "output")?, &[("tenant", code)])?;
    let feed_ids = plan.ids(FEED_STREAM, None);
    for mut item in candidates(
        &mut plan.gone,
        OUTPUT,
        recorded,
        &plan.state.outputs,
        &[(output_title.clone(), None)],
    )? {
        let output = plan
            .state
            .outputs
            .get(&item.graylog_id)
            .cloned()
            .unwrap_or_else(empty_dict);
        let elsewhere: Vec<String> = plan
            .state
            .output_streams(&item.graylog_id)?
            .into_iter()
            .filter(|s| !feed_ids.contains(s))
            .collect();
        let kind = get_or(&output, "type", PyValue::None)?;
        let gelf = py_eq(&kind, &PyValue::None) || py_eq(&kind, &s(GELF_OUTPUT));
        if !gelf || !item.title.starts_with("UBA GELF - ") {
            item.conflict("is not a UBA GELF output".into());
        } else if !elsewhere.is_empty() {
            item.action = Action::Keep;
            let mut titles = Vec::new();
            for sid in elsewhere.iter().take(5) {
                titles.push(title_or(plan.state.streams.get(sid), s(sid))?);
            }
            item.detail = format!(
                "also attached to {}: only detached from the customer's feed streams",
                join(", ", &titles)?
            );
        } else {
            let cfg = or_else(py::get(&output, "configuration")?, empty_dict());
            item.detail = format!(
                "-> {}:{}",
                text(&get_or(&cfg, "hostname", PyValue::None)?),
                text(&get_or(&cfg, "port", PyValue::None)?)
            );
        }
        plan.items.push(item);
    }

    // The customer's UBA ALERTS stream.
    let alerts_title = format(getitem(&names, "alerts_stream")?, &[("tenant", code)])?;
    for mut item in candidates(
        &mut plan.gone,
        ALERTS_STREAM,
        recorded,
        &plan.state.streams,
        &[(alerts_title.clone(), None)],
    )? {
        let stream = plan
            .state
            .streams
            .get(&item.graylog_id)
            .cloned()
            .unwrap_or_else(empty_dict);
        let mut customer_rule = false;
        for r in py::iterate(&or_else(py::get(&stream, "rules")?, empty_list()))? {
            if py_eq(
                &get_or(&r, "field", PyValue::None)?,
                &s("agent_labels_customer"),
            ) && lower(&text(&get_or(&r, "value", s(""))?)) == lower(code)
            {
                customer_rule = true;
                break;
            }
        }
        let mut uses: Vec<PyValue> = Vec::new();
        for p in plan.state.connections_of(&item.graylog_id) {
            hashable(&p)?;
            uses.push(title_or(plan.state.pipelines.get_py(&p), p.clone())?);
        }
        for d in plan.state.definitions_on(&item.graylog_id)? {
            let id = get_or(&d, "id", PyValue::None)?;
            uses.push(s(&format!(
                "event definition {}",
                text(&get_or(&d, "title", id)?)
            )));
        }
        for o in plan.state.stream_outputs(&item.graylog_id)? {
            hashable(&o)?;
            uses.push(s(&format!(
                "output {}",
                text(&title_or(plan.state.outputs.get_py(&o), o.clone())?)
            )));
        }
        if protected.contains(&item.graylog_id)
            || !item.title.starts_with("UBA ALERTS - ")
            || !customer_rule
        {
            item.conflict("does not look like the customer's UBA alerts stream".into());
        } else if !uses.is_empty() {
            let five: Vec<PyValue> = uses.into_iter().take(5).collect();
            item.conflict(format!("still used by {}", join(", ", &five)?));
        } else {
            item.detail = "its alerts stay in the index".into();
        }
        plan.items.push(item);
    }

    // The shared input: only once no customer has a UBA alerts stream left.
    let removed_alerts = plan.ids(ALERTS_STREAM, Some(Action::Remove));
    let mut remaining: Vec<PyValue> = Vec::new();
    for (sid, stream) in plan.state.streams.iter() {
        if startswith(&get_or(stream, "title", s(""))?, "UBA ALERTS - ")?
            && !removed_alerts.contains(sid)
        {
            remaining.push(getitem(stream, "title")?.clone());
        }
    }
    let mut others: Vec<String> = Vec::new();
    for r in &facts.all_active {
        if r.kind == ALERTS_STREAM
            && r.customer_code != code
            && plan.state.streams.contains(&r.graylog_id)
            && !others.contains(&r.customer_code)
        {
            others.push(r.customer_code.clone());
        }
    }
    others.sort();
    let input_name = getitem(&names, "alerts_input")?.clone();
    let input_titles: Vec<(String, Option<String>)> = if plan.of(ALERTS_STREAM, None).is_empty() {
        Vec::new()
    } else {
        match str_key(&input_name)? {
            Some(t) => vec![(t.to_string(), None)],
            None => Vec::new(),
        }
    };
    for mut item in candidates(
        &mut plan.gone,
        ALERTS_INPUT,
        recorded,
        &plan.state.inputs,
        &input_titles,
    )? {
        item.shared = true;
        let input = plan
            .state
            .inputs
            .get(&item.graylog_id)
            .cloned()
            .unwrap_or_else(empty_dict);
        let kind = get_or(&input, "type", PyValue::None)?;
        if !(py_eq(&kind, &PyValue::None) || py_eq(&kind, &s(GELF_TCP_INPUT))) {
            item.conflict("is not a GELF TCP input".into());
        } else if !remaining.is_empty() || !others.is_empty() {
            item.action = Action::Keep;
            let users: Vec<PyValue> = if remaining.is_empty() {
                others.iter().take(5).map(|c| s(c)).collect()
            } else {
                remaining.iter().take(5).cloned().collect()
            };
            item.detail = format!("shared: still used by {}", join(", ", &users)?);
        } else {
            item.detail = "shared, and no other customer has a UBA alerts stream".into();
        }
        plan.items.push(item);
    }

    // The Wazuh rules: never removed.
    for row in recorded.iter().filter(|r| r.kind == WAZUH_RULES) {
        let mut item = Item::new(WAZUH_RULES, &row.graylog_id, &row.title, None);
        item.recorded = true;
        item.shared = true;
        item.action = Action::Keep;
        item.detail =
            "shared by every customer on the Wazuh manager; removing them needs a manager restart"
                .into();
        plan.items.push(item);
    }
    Ok(plan)
}

/// `_names()`: UBA's object names; setup's defaults when UBA cannot be
/// asked (not an error here).
async fn names(uba: &dyn UbaOps) -> PyResult<PyValue> {
    let info = match uba.call(Call::get("/v1/provisioning")).await {
        Ok(info) => info,
        Err(UbaError::Request { detail, .. }) => {
            tracing::info!(
                "UBA rollback: UBA's object names unavailable ({detail}); using setup's defaults"
            );
            return Ok(default_names());
        }
        Err(UbaError::Py(e)) => return Err(e),
    };
    let graylog = or_else(py::get(&info, "graylog")?, empty_dict());
    let PyValue::Dict(over) = graylog else {
        return Err(PyExc::TypeError(format!(
            "'{}' object is not a mapping",
            type_name(&graylog)
        )));
    };
    let PyValue::Dict(mut merged) = default_names() else {
        return Ok(default_names());
    };
    for (k, v) in over {
        match merged.iter_mut().find(|(m, _)| *m == k) {
            Some(slot) => slot.1 = v,
            None => merged.push((k, v)),
        }
    }
    Ok(PyValue::Dict(merged))
}

/// `_onboarding(customer_code)`: the state and why UBA could not be asked.
async fn onboarding(
    uba: &dyn UbaOps,
    customer_code: &str,
) -> PyResult<(Option<PyValue>, Option<String>)> {
    match uba
        .call(Call::get(format!("{}/onboarding", tenant(customer_code))))
        .await
    {
        Ok(PyValue::None) => Ok((None, None)),
        Ok(v) => Ok((Some(v), None)),
        Err(UbaError::Request { status: 404, .. }) => Ok((None, None)),
        Err(UbaError::Request { detail, .. }) => Ok((None, Some(detail))),
        Err(UbaError::Py(e)) => Err(e),
    }
}

/// `build_plan(customer_code)`: UBA's names, Graylog, UBA's state, then
/// the plan.
pub async fn build_plan(ops: Ops<'_>, customer_code: &str, facts: &Facts) -> PyResult<Plan> {
    let names = names(ops.uba).await?;
    let state = read_graylog(ops.graylog).await?;
    let (uba, problem) = onboarding(ops.uba, customer_code).await?;
    compute_plan(customer_code, names, state, facts, uba, problem)
}

fn ordered(plan: &Plan, indices: Vec<usize>) -> Vec<usize> {
    let mut out = indices;
    out.sort_by(|a, b| {
        let key = |n: &usize| {
            let i = &plan.items[*n];
            (
                ownership::ORDER
                    .iter()
                    .position(|k| *k == i.kind)
                    .unwrap_or(99),
                i.source.clone().unwrap_or_default(),
                i.title.clone(),
            )
        };
        key(a).cmp(&key(b))
    });
    out
}

/// `plan_response(plan)`: the preview, and how many objects it removes.
pub fn plan_response(plan: &Plan) -> PyResult<(PyValue, usize)> {
    let all: Vec<usize> = (0..plan.items.len()).collect();
    let mut remove: Vec<PyValue> = ordered(plan, all)
        .into_iter()
        .filter(|n| plan.items[*n].action == Action::Remove)
        .map(|n| plan.items[n].out())
        .collect();
    let tenant_item = |detail: &str| {
        dict(vec![
            ("kind", s("uba_tenant")),
            ("id", s(&plan.customer_code)),
            ("title", s(&format!("UBA tenant {}", plan.customer_code))),
            ("detail", s(detail)),
        ])
    };
    let active = match &plan.uba {
        Some(u) if u.truthy() => get_or(u, "active", PyValue::None)?.truthy(),
        _ => false,
    };
    if active {
        remove.push(tenant_item("deactivated; its data is kept"));
    } else if plan.uba.is_none() && plan.uba_problem.as_deref().is_some_and(|p| !p.is_empty()) {
        remove.push(tenant_item(
            "UBA could not be asked: deactivating it is tried, and the rest of the rollback runs either way",
        ));
    }
    let state = &plan.state;
    let mut sources = Vec::new();
    for sid in &plan.source_streams {
        let stream = or_else(state.streams.get(sid), empty_dict());
        let mut pipelines = Vec::new();
        for p in state.connections_of(sid) {
            hashable(&p)?;
            pipelines.push(title_or(state.pipelines.get_py(&p), p.clone())?);
        }
        sources.push(dict(vec![
            ("id", s(sid)),
            ("title", get_or(&stream, "title", PyValue::None)?),
            ("exists", PyValue::Bool(state.streams.contains(sid))),
            ("pipelines", PyValue::List(pipelines)),
        ]));
    }
    let count = remove.len();
    let message = if count > 0 {
        format!("{count} object(s) to remove for {}", plan.customer_code)
    } else {
        format!(
            "UBA is not set up for {}: nothing to roll back",
            plan.customer_code
        )
    };
    let of_action = |a: Action| -> PyValue {
        PyValue::List(
            plan.items
                .iter()
                .filter(|i| i.action == a)
                .map(Item::out)
                .collect(),
        )
    };
    let response = construct(
        &ROLLBACK_PLAN,
        &dict(vec![
            ("message", s(&message)),
            ("remove", PyValue::List(remove)),
            ("keep", of_action(Action::Keep)),
            ("conflicts", of_action(Action::Conflict)),
            ("source_streams", PyValue::List(sources)),
            ("uba", plan.uba.clone().unwrap_or(PyValue::None)),
            (
                "uba_problem",
                plan.uba_problem.as_deref().map_or(PyValue::None, s),
            ),
        ]),
    )?;
    Ok((response, count))
}

// --- doing it -----------------------------------------------------------------------------------

/// `UbaRollbackCheck`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// What.
    pub check: String,
    /// `None`: could not be checked.
    pub ok: Option<bool>,
    /// More.
    pub detail: String,
}

impl Check {
    fn new(check: impl Into<String>, ok: Option<bool>, detail: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            ok,
            detail: detail.into(),
        }
    }

    /// `model_dump()`.
    pub fn dump(&self) -> PyValue {
        dict(vec![
            ("check", s(&self.check)),
            ("ok", self.ok.map_or(PyValue::None, PyValue::Bool)),
            ("detail", s(&self.detail)),
        ])
    }
}

/// `_Run`.
#[derive(Debug, Clone, Default)]
pub struct Run {
    /// The report.
    pub steps: Vec<Step>,
    /// What was removed (or was gone already).
    pub removed: Vec<Item>,
    /// Routing pipelines no longer connected to any stream.
    pub disconnected: Vec<String>,
    /// A step failed.
    pub failed: bool,
}

impl Run {
    fn add(&mut self, step: impl Into<String>, status: &str, detail: impl Into<String>) {
        let step = step.into();
        let detail = detail.into();
        tracing::info!(
            "UBA rollback: {}",
            format!("{step}: {status} {detail}").trim_end()
        );
        if status == "failed" {
            self.failed = true;
        }
        self.steps.push(Step {
            step,
            status: status.to_string(),
            detail,
        });
    }

    fn removed_ids(&self, kind: &str) -> Vec<String> {
        self.removed
            .iter()
            .filter(|i| i.kind == kind)
            .map(|i| i.graylog_id.clone())
            .collect()
    }
}

/// `_error(e)`: the detail of an `HTTPException` or a `UbaRequestError`,
/// else `str(e)`.
pub fn error_text(e: &PyExc) -> String {
    e.text()
}

async fn exists(g: &dyn GraylogOps, endpoint: &str) -> PyResult<bool> {
    match g.get(endpoint, &[]).await {
        Ok(_) => Ok(true),
        Err(PyExc::Http(404, _)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// `_delete(endpoint, check)`: "removed", or "gone" when it already was;
/// raises when Graylog refused.
async fn delete(g: &dyn GraylogOps, endpoint: &str, check: Option<&str>) -> PyResult<&'static str> {
    let reason = match g.delete(endpoint).await {
        Ok(r) if r.success => return Ok("removed"),
        Ok(r) if !r.message.is_empty() => r.message,
        Ok(_) => format!("DELETE {endpoint} failed"),
        Err(PyExc::Http(_, detail)) => detail,
        Err(e) => return Err(e),
    };
    if !exists(g, check.unwrap_or(endpoint)).await? {
        return Ok("gone");
    }
    Err(PyExc::Http(502, reason))
}

/// `execute(plan, run)`: the steps, in order.
pub async fn execute(ops: Ops<'_>, plan: &Plan, run: &mut Run) -> PyResult<()> {
    let g = ops.graylog;
    let state = &plan.state;
    for item in &plan.gone {
        run.removed.push(item.clone());
        run.add(
            format!("{} {}", item.kind, item.title),
            "gone",
            "no longer in Graylog",
        );
    }

    // 1. Stop the routing first.
    let pipelines = ordered(plan, plan.of(ROUTING_PIPELINE, Some(Action::Remove)));
    for &n in &pipelines {
        let item = &plan.items[n];
        let streams = state.pipeline_streams(&item.graylog_id);
        let attempt: PyResult<()> = async {
            if !streams.is_empty() {
                g.post(
                    "/api/system/pipelines/connections/to_pipeline",
                    Some(dict(vec![
                        ("pipeline_id", s(&item.graylog_id)),
                        ("stream_ids", empty_list()),
                    ])),
                )
                .await?;
                run.add(
                    format!("pipeline {}", item.title),
                    "disconnected",
                    format!("from {} stream(s)", streams.len()),
                );
            }
            Ok(())
        }
        .await;
        match attempt {
            Ok(()) => {
                if !run.disconnected.contains(&item.graylog_id) {
                    run.disconnected.push(item.graylog_id.clone());
                }
            }
            Err(e) => run.add(
                format!("pipeline {}", item.title),
                "failed",
                format!("could not be disconnected: {}", error_text(&e)),
            ),
        }
    }
    let mut stopped_sources: Vec<Option<String>> = Vec::new();
    for n in plan.of(ROUTING_PIPELINE, Some(Action::Remove)) {
        let item = &plan.items[n];
        if !run.disconnected.contains(&item.graylog_id) && !stopped_sources.contains(&item.source) {
            stopped_sources.push(item.source.clone());
        }
    }

    // 2. The output.
    let feed_ids = plan.ids(FEED_STREAM, None);
    for n in plan.of(OUTPUT, None) {
        let item = &plan.items[n];
        if item.action == Action::Conflict {
            continue;
        }
        let attempt: PyResult<()> = async {
            for stream_id in state.output_streams(&item.graylog_id)? {
                if feed_ids.contains(&stream_id) {
                    delete(
                        g,
                        &format!("/api/streams/{stream_id}/outputs/{}", item.graylog_id),
                        Some(&format!("/api/streams/{stream_id}")),
                    )
                    .await?;
                    let title = title_or(state.streams.get(&stream_id), s(&stream_id))?;
                    run.add(
                        format!("output {}", item.title),
                        "detached",
                        format!("from {}", text(&title)),
                    );
                }
            }
            if item.action == Action::Remove {
                let outcome =
                    delete(g, &format!("/api/system/outputs/{}", item.graylog_id), None).await?;
                run.add(format!("output {}", item.title), outcome, "");
                run.removed.push(item.clone());
            } else {
                run.add(
                    format!("output {}", item.title),
                    "kept",
                    item.detail.clone(),
                );
            }
            Ok(())
        }
        .await;
        if let Err(e) = attempt {
            run.add(format!("output {}", item.title), "failed", error_text(&e));
        }
    }

    // 3. Pipelines, then their rules.
    for &n in &pipelines {
        let item = &plan.items[n];
        if !run.disconnected.contains(&item.graylog_id) {
            continue;
        }
        match delete(
            g,
            &format!("/api/system/pipelines/pipeline/{}", item.graylog_id),
            None,
        )
        .await
        {
            Ok(outcome) => {
                run.add(format!("pipeline {}", item.title), outcome, "");
                run.removed.push(item.clone());
            }
            Err(e) => {
                if !stopped_sources.contains(&item.source) {
                    stopped_sources.push(item.source.clone());
                }
                run.add(format!("pipeline {}", item.title), "failed", error_text(&e));
            }
        }
    }
    let deleted_pipelines = run.removed_ids(ROUTING_PIPELINE);
    for n in ordered(plan, plan.of(ROUTING_RULE, Some(Action::Remove))) {
        let item = &plan.items[n];
        let title = s(&item.title);
        let mut runners = false;
        for p in state.pipelines.keys() {
            if state.pipeline_rules(p)?.iter().any(|r| py_eq(r, &title))
                && !deleted_pipelines.contains(p)
            {
                runners = true;
            }
        }
        if runners {
            run.add(
                format!("rule {}", item.title),
                "skipped",
                "its pipeline could not be removed",
            );
            continue;
        }
        match delete(
            g,
            &format!("/api/system/pipelines/rule/{}", item.graylog_id),
            None,
        )
        .await
        {
            Ok(outcome) => {
                run.add(format!("rule {}", item.title), outcome, "");
                run.removed.push(item.clone());
            }
            Err(e) => run.add(format!("rule {}", item.title), "failed", error_text(&e)),
        }
    }

    // 4. Feed streams, unless their routing is still in place.
    for n in ordered(plan, plan.of(FEED_STREAM, Some(Action::Remove))) {
        let item = &plan.items[n];
        if stopped_sources.contains(&item.source) {
            run.add(
                format!("stream {}", item.title),
                "skipped",
                "its routing pipeline is still in place",
            );
            continue;
        }
        match delete(g, &format!("/api/streams/{}", item.graylog_id), None).await {
            Ok(outcome) => {
                run.add(format!("stream {}", item.title), outcome, "");
                run.removed.push(item.clone());
            }
            Err(e) => run.add(format!("stream {}", item.title), "failed", error_text(&e)),
        }
    }

    // 5. Alerts stream, then the shared input.
    let mut removed_alerts: Vec<usize> = Vec::new();
    for n in plan.of(ALERTS_STREAM, Some(Action::Remove)) {
        let item = &plan.items[n];
        match delete(g, &format!("/api/streams/{}", item.graylog_id), None).await {
            Ok(outcome) => {
                run.add(
                    format!("stream {}", item.title),
                    outcome,
                    item.detail.clone(),
                );
                run.removed.push(item.clone());
                removed_alerts.push(n);
            }
            Err(e) => run.add(format!("stream {}", item.title), "failed", error_text(&e)),
        }
    }
    let alerts_left = plan
        .of(ALERTS_STREAM, Some(Action::Remove))
        .iter()
        .any(|n| !removed_alerts.contains(n));
    for n in plan.of(ALERTS_INPUT, None) {
        let item = &plan.items[n];
        if item.action != Action::Remove || alerts_left {
            let detail = if item.action != Action::Remove {
                item.detail.clone()
            } else {
                "the customer's alerts stream is still there".to_string()
            };
            run.add(format!("input {}", item.title), "kept", detail);
            continue;
        }
        match delete(g, &format!("/api/system/inputs/{}", item.graylog_id), None).await {
            Ok(outcome) => {
                run.add(
                    format!("input {}", item.title),
                    outcome,
                    item.detail.clone(),
                );
                run.removed.push(item.clone());
            }
            Err(e) => run.add(format!("input {}", item.title), "failed", error_text(&e)),
        }
    }

    for item in &plan.items {
        if item.action == Action::Conflict {
            run.add(
                format!("{} {}", item.kind, item.title),
                "conflict",
                format!("left alone: {}", item.detail),
            );
        } else if item.kind == WAZUH_RULES {
            run.add(
                format!("Wazuh rules {}", item.title),
                "kept",
                item.detail.clone(),
            );
        }
    }

    // 6. UBA, last: the Graylog side no longer sends it anything.
    let uba_active = match &plan.uba {
        Some(u) => get_or(u, "active", PyValue::None)?.truthy(),
        None => false,
    };
    if plan.uba.is_none() && plan.uba_problem.is_none() {
        run.add("UBA tenant", "skipped", "UBA does not know this customer");
    } else if plan.uba.is_some() && !uba_active {
        run.add("UBA tenant", "skipped", "already inactive");
    } else {
        match ops
            .uba
            .call(
                Call::new(Method::PUT, tenant(&plan.customer_code))
                    .json(dict(vec![("active", PyValue::Bool(false))])),
            )
            .await
        {
            Ok(_) => run.add(
                "UBA tenant",
                "deactivated",
                "its entities, alerts and verdicts are kept",
            ),
            Err(UbaError::Request { status: 404, .. }) => {
                run.add("UBA tenant", "skipped", "UBA does not know this customer");
            }
            Err(UbaError::Request { detail, .. }) => run.add(
                "UBA tenant",
                "failed",
                format!(
                    "{detail}: Graylog no longer sends UBA anything; roll back again once UBA answers"
                ),
            ),
            Err(UbaError::Py(e)) => return Err(e),
        }
    }
    Ok(())
}

// --- checking it --------------------------------------------------------------------------------

fn fingerprint(definitions: &[PyValue]) -> PyResult<PyDict> {
    let mut out = PyDict::default();
    for d in definitions {
        out.set(
            get_or(d, "id", PyValue::None)?,
            get_or(d, "state", PyValue::None)?,
        )?;
    }
    Ok(out)
}

/// `verify(plan, run)`: the customer's streams, Graylog's event
/// definitions, the routing and the output to UBA, UBA's state.
pub async fn verify(ops: Ops<'_>, plan: &Plan, run: &Run) -> PyResult<Vec<Check>> {
    let before = &plan.state;
    let mut checks = Vec::new();
    let after = match read_graylog(ops.graylog).await {
        Ok(a) => a,
        Err(e) => return Ok(vec![Check::new("Graylog read back", None, error_text(&e))]),
    };
    let mut removed_pipelines = run.disconnected.clone();
    for id in run.removed_ids(ROUTING_PIPELINE) {
        if !removed_pipelines.contains(&id) {
            removed_pipelines.push(id);
        }
    }
    for sid in &plan.source_streams {
        let was_stream = or_else(before.streams.get(sid), empty_dict());
        let title = or_else(py::get(&was_stream, "title")?, s(sid));
        let title = text(&title);
        let (Some(was), now) = (before.streams.get(sid), after.streams.get(sid)) else {
            checks.push(Check::new(
                format!("stream {title}"),
                None,
                "not in Graylog before the rollback either",
            ));
            continue;
        };
        let disabled =
            |v: &PyValue| -> PyResult<bool> { Ok(get_or(v, "disabled", PyValue::None)?.truthy()) };
        let running = match now {
            Some(n) => disabled(n)? == disabled(was)?,
            None => false,
        };
        let state_text = match now {
            Some(n) if n.truthy() && disabled(n)? => "paused",
            _ => "running",
        };
        checks.push(Check::new(
            format!("stream {title}"),
            Some(running),
            if now.is_some() { state_text } else { "gone" },
        ));
        let mut expected = Vec::new();
        for p in before.connections_of(sid) {
            hashable(&p)?;
            if !p
                .as_str()
                .is_some_and(|p| removed_pipelines.iter().any(|r| r == p))
            {
                expected.push(p);
            }
        }
        let expected = sorted(expected)?;
        let kept = sorted(after.connections_of(sid))?;
        let mut kept_names = Vec::new();
        for p in &kept {
            hashable(p)?;
            kept_names.push(title_or(after.pipelines.get_py(p), p.clone())?);
        }
        let names = join(", ", &kept_names)?;
        let names = if names.is_empty() {
            "none".to_string()
        } else {
            names
        };
        let same = list_eq(&kept, &expected);
        checks.push(Check::new(
            format!("pipelines of {title}"),
            Some(same),
            if same {
                format!("{} kept: {names}", kept.len())
            } else {
                format!("expected {}, found {}: {names}", expected.len(), kept.len())
            },
        ));
    }
    match (&before.event_definitions, &after.event_definitions) {
        (Some(b), Some(a)) => {
            let same = fingerprint(b)?.same(&fingerprint(a)?);
            checks.push(Check::new(
                "event definitions",
                Some(same),
                if same {
                    format!("{} unchanged", a.len())
                } else {
                    format!("{} before, {} after", b.len(), a.len())
                },
            ));
        }
        _ => checks.push(Check::new(
            "event definitions",
            None,
            "Graylog's event definitions could not be read",
        )),
    }
    let left = removed_pipelines
        .iter()
        .filter(|p| {
            let id = s(p);
            after
                .connections
                .values()
                .any(|ids| ids.iter().any(|i| py_eq(i, &id)))
        })
        .count();
    checks.push(Check::new(
        "UBA routing",
        Some(left == 0),
        if left == 0 {
            "no routing to UBA left".to_string()
        } else {
            format!("{left} still connected")
        },
    ));
    let feeds = plan.ids(FEED_STREAM, None);
    let mut attached = 0;
    let mut removed_outputs: Vec<String> = Vec::new();
    for id in run.removed_ids(OUTPUT) {
        if !removed_outputs.contains(&id) {
            removed_outputs.push(id);
        }
    }
    attached += removed_outputs
        .iter()
        .filter(|o| after.outputs.contains(o))
        .count();
    for n in plan.of(OUTPUT, None) {
        let item = &plan.items[n];
        if item.action != Action::Conflict
            && after
                .output_streams(&item.graylog_id)?
                .iter()
                .any(|sid| feeds.contains(sid))
        {
            attached += 1;
        }
    }
    checks.push(Check::new(
        "output to UBA",
        Some(attached == 0),
        if attached == 0 {
            "no stream of the customer sends to UBA"
        } else {
            "still attached"
        },
    ));
    if run
        .steps
        .iter()
        .any(|s| s.step == "UBA tenant" && s.status == "deactivated")
    {
        let (state, problem) = onboarding(ops.uba, &plan.customer_code).await?;
        let inactive = match &state {
            None => true,
            Some(u) => !get_or(u, "active", PyValue::None)?.truthy(),
        };
        let ok = if problem.as_deref().is_some_and(|p| !p.is_empty()) {
            None
        } else {
            Some(inactive)
        };
        let detail = match problem.filter(|p| !p.is_empty()) {
            Some(p) => p,
            None => if inactive { "inactive" } else { "still active" }.to_string(),
        };
        checks.push(Check::new("UBA tenant", ok, detail));
    }
    Ok(checks)
}

// --- the report ---------------------------------------------------------------------------------

/// `now_utc().isoformat()`.
pub fn iso_now() -> String {
    let now = Utc::now();
    let micros = now.nanosecond() / 1000 % 1_000_000;
    if micros == 0 {
        now.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        format!("{}.{micros:06}+00:00", now.format("%Y-%m-%dT%H:%M:%S"))
    }
}

/// `_snapshot(plan)`: Graylog and UBA before the rollback.
pub fn snapshot(plan: &Plan, taken_at: &str) -> PyResult<PyValue> {
    let state = &plan.state;
    let store = |kind: &str| -> Option<&OrderedMap<PyValue>> {
        match kind {
            FEED_STREAM | ALERTS_STREAM => Some(&state.streams),
            ROUTING_PIPELINE => Some(&state.pipelines),
            ROUTING_RULE => Some(&state.rules),
            OUTPUT => Some(&state.outputs),
            ALERTS_INPUT => Some(&state.inputs),
            _ => None,
        }
    };
    let objects: Vec<PyValue> = plan
        .items
        .iter()
        .filter_map(|i| {
            store(i.kind).map(|objects| {
                dict(vec![
                    ("kind", s(i.kind)),
                    ("action", s(i.action.as_str())),
                    (
                        "object",
                        objects.get(&i.graylog_id).cloned().unwrap_or(PyValue::None),
                    ),
                ])
            })
        })
        .collect();
    let mut connections: Vec<(String, PyValue)> = Vec::new();
    for i in plan.items.iter().filter(|i| i.kind == ROUTING_PIPELINE) {
        let streams = PyValue::List(
            state
                .pipeline_streams(&i.graylog_id)
                .iter()
                .map(|x| s(x))
                .collect(),
        );
        match connections.iter_mut().find(|(k, _)| *k == i.graylog_id) {
            Some(slot) => slot.1 = streams,
            None => connections.push((i.graylog_id.clone(), streams)),
        }
    }
    let mut sources = Vec::new();
    for sid in &plan.source_streams {
        let stream = or_else(state.streams.get(sid), empty_dict());
        sources.push(dict(vec![
            ("id", s(sid)),
            ("title", get_or(&stream, "title", PyValue::None)?),
            ("disabled", get_or(&stream, "disabled", PyValue::None)?),
            ("pipelines", PyValue::List(state.connections_of(sid))),
        ]));
    }
    let definitions = match &state.event_definitions {
        None => PyValue::None,
        Some(defs) => {
            let mut out = Vec::new();
            for d in defs {
                out.push(dict(vec![
                    ("id", get_or(d, "id", PyValue::None)?),
                    ("title", get_or(d, "title", PyValue::None)?),
                    ("state", get_or(d, "state", PyValue::None)?),
                ]));
            }
            PyValue::List(out)
        }
    };
    Ok(dict(vec![
        ("taken_at", s(taken_at)),
        ("names", plan.names.clone()),
        ("uba", plan.uba.clone().unwrap_or(PyValue::None)),
        ("objects", PyValue::List(objects)),
        ("connections", PyValue::Dict(connections)),
        ("source_streams", PyValue::List(sources)),
        ("event_definitions", definitions),
    ]))
}

/// The run's status and message (`roll_back`'s last lines).
pub fn outcome(customer_code: &str, run: &Run, checks: &[Check]) -> (&'static str, String) {
    let unverified = checks.iter().any(|c| c.ok == Some(false));
    let status = if run.failed || unverified {
        "partial"
    } else {
        "completed"
    };
    let conflicts = run.steps.iter().filter(|s| s.status == "conflict").count();
    let removed = run
        .steps
        .iter()
        .filter(|s| s.status == "removed" || s.status == "gone")
        .count();
    let mut message = format!("UBA rolled back for {customer_code}: {removed} object(s) removed");
    if conflicts > 0 {
        message.push_str(&format!(", {conflicts} left for review"));
    }
    if status != "completed" {
        message.push_str("; some steps failed or a check did not pass: run the rollback again");
    }
    (status, message)
}

/// Execute, then verify; anything that escapes is the run's last step
/// (`never leave the row "running"`).
pub async fn run_all(ops: Ops<'_>, plan: &Plan) -> (Run, Vec<Check>) {
    let mut run = Run::default();
    let checks = match execute(ops, plan, &mut run).await {
        Ok(()) => match verify(ops, plan, &run).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "UBA rollback of {} stopped: {}",
                    plan.customer_code,
                    error_text(&e)
                );
                run.add("rollback", "failed", error_text(&e));
                Vec::new()
            }
        },
        Err(e) => {
            tracing::error!(
                "UBA rollback of {} stopped: {}",
                plan.customer_code,
                error_text(&e)
            );
            run.add("rollback", "failed", error_text(&e));
            Vec::new()
        }
    };
    (run, checks)
}

fn db_error(e: sqlx::Error) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

fn json_text(value: &PyValue) -> PyResult<String> {
    py_dumps(value, Dumps::DEFAULT)
        .map_err(|_| PyExc::ValueError("Out of range float values are not JSON compliant".into()))
}

/// `roll_back(customer_code, …)`: the report (`UbaRollbackReport`).
pub async fn roll_back(
    ops: Ops<'_>,
    db: &Db,
    customer_code: &str,
    actor_user_id: i32,
    actor_username: &str,
) -> PyResult<PyValue> {
    let since = Utc::now().naive_utc() - chrono::Duration::minutes(RUNNING_FOR_MINUTES);
    let running: Vec<(i32,)> = sqlx::query_as(
        "SELECT uba_rollback.id FROM uba_rollback WHERE uba_rollback.customer_code = ? \
         AND uba_rollback.status = ? AND uba_rollback.started_at > ?",
    )
    .bind(customer_code)
    .bind("running")
    .bind(since)
    .fetch_all(db.pool())
    .await
    .map_err(db_error)?;
    if !running.is_empty() {
        return Err(PyExc::Http(
            409,
            format!("A UBA rollback of {customer_code} is already running"),
        ));
    }

    let facts = load_facts(db, customer_code).await.map_err(db_error)?;
    let plan = build_plan(ops, customer_code, &facts).await?;
    let (preview, remove) = plan_response(&plan)?;
    if remove == 0 && plan.gone.is_empty() {
        let message = preview
            .get("message")
            .map(PyValue::py_str)
            .unwrap_or_default();
        return Err(PyExc::Http(409, message));
    }

    let started_at = now_utc_naive();
    let snapshot = json_text(&snapshot(&plan, &iso_now())?)?;
    let id = sqlx::query(
        "INSERT INTO uba_rollback (customer_code, status, started_at, finished_at, \
         actor_user_id, actor_username, message, snapshot, steps, verification) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(customer_code)
    .bind("running")
    .bind(started_at)
    .bind(None::<NaiveDateTime>)
    .bind(actor_user_id)
    .bind(actor_username)
    .bind(None::<String>)
    .bind(snapshot)
    .bind("null")
    .bind("null")
    .execute(db.pool())
    .await
    .map_err(db_error)?
    .last_insert_id();
    let id = i64::try_from(id).unwrap_or(i64::MAX);

    let (run, checks) = run_all(ops, &plan).await;
    let (status, message) = outcome(customer_code, &run, &checks);
    let steps = json_text(&PyValue::List(run.steps.iter().map(Step::dump).collect()))?;
    let verification = json_text(&PyValue::List(checks.iter().map(Check::dump).collect()))?;
    let owned: Vec<Owned> = run.removed.iter().map(Item::owned).collect();
    let finished: Result<(), sqlx::Error> = async {
        let mut tx = db.pool().begin().await?;
        sqlx::query(
            "UPDATE uba_rollback SET status=?, finished_at=?, message=?, steps=?, \
             verification=? WHERE uba_rollback.id = ?",
        )
        .bind(status)
        .bind(now_utc_naive())
        .bind(&message)
        .bind(&steps)
        .bind(&verification)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        ownership::mark_removed(&mut tx, customer_code, &owned, id).await?;
        tx.commit().await
    }
    .await;
    finished.map_err(db_error)?;
    match get_rollback_row(db, id).await.map_err(db_error)? {
        Some(row) => report(&row),
        None => Err(PyExc::Other(
            "InvalidRequestError",
            "Could not refresh instance".into(),
        )),
    }
}

/// A `uba_rollback` row, its JSON columns as MySQL renders them.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct RollbackRow {
    /// Primary key.
    pub id: i32,
    /// The customer.
    pub customer_code: String,
    /// `running`, `completed`, `partial` or `failed`.
    pub status: String,
    /// When it started.
    pub started_at: NaiveDateTime,
    /// When it finished.
    pub finished_at: Option<NaiveDateTime>,
    /// Who ran it.
    pub actor_username: Option<String>,
    /// The summary.
    pub message: Option<String>,
    /// `snapshot`.
    pub snapshot: Option<String>,
    /// `steps`.
    pub steps: Option<String>,
    /// `verification`.
    pub verification: Option<String>,
}

const ROW_COLUMNS: &str = "uba_rollback.id, uba_rollback.customer_code, uba_rollback.status, \
     uba_rollback.started_at, uba_rollback.finished_at, uba_rollback.actor_username, \
     uba_rollback.message, CAST(uba_rollback.snapshot AS CHAR) AS snapshot, \
     CAST(uba_rollback.steps AS CHAR) AS steps, \
     CAST(uba_rollback.verification AS CHAR) AS verification";

/// `session.get(UbaRollback, id)`.
pub async fn get_rollback_row(db: &Db, id: i64) -> Result<Option<RollbackRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM uba_rollback WHERE uba_rollback.id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await
}

/// `list_rollbacks(customer_code)`: newest first, 20 at most.
pub async fn list_rollbacks(db: &Db, customer_code: &str) -> Result<Vec<RollbackRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM uba_rollback WHERE uba_rollback.customer_code = ? \
         ORDER BY uba_rollback.id DESC LIMIT ?"
    ))
    .bind(customer_code)
    .bind(20_i64)
    .fetch_all(db.pool())
    .await
}

fn datetime(t: &NaiveDateTime) -> PyValue {
    s(&t.format("%Y-%m-%dT%H:%M:%S").to_string())
}

fn json_column(text: &Option<String>) -> PyResult<PyValue> {
    match text {
        None => Ok(PyValue::None),
        Some(t) => loads(t).map_err(|_| PyExc::JsonDecode("Expecting value".into())),
    }
}

fn summary_fields(row: &RollbackRow) -> Vec<(&'static str, PyValue)> {
    vec![
        ("id", PyValue::Int(row.id.to_string())),
        ("customer_code", s(&row.customer_code)),
        ("status", s(&row.status)),
        ("started_at", datetime(&row.started_at)),
        (
            "finished_at",
            row.finished_at.as_ref().map_or(PyValue::None, datetime),
        ),
        (
            "actor_username",
            row.actor_username.as_deref().map_or(PyValue::None, s),
        ),
        ("message", row.message.as_deref().map_or(PyValue::None, s)),
    ]
}

/// `UbaRollbackSummary.model_validate(row)`.
pub fn summary(row: &RollbackRow) -> PyResult<PyValue> {
    construct(&ROLLBACK_SUMMARY, &dict(summary_fields(row)))
}

/// `UbaRollbackReport.model_validate(row)` (a `running` row's `null`
/// steps fail its validation, as in Python).
pub fn report(row: &RollbackRow) -> PyResult<PyValue> {
    let mut fields = summary_fields(row);
    fields.push(("steps", json_column(&row.steps)?));
    fields.push(("verification", json_column(&row.verification)?));
    fields.push(("snapshot", json_column(&row.snapshot)?));
    construct(&ROLLBACK_REPORT, &dict(fields))
}
