//! Set SOCFortress UBA up for a customer — port of `services/provision.py`
//! (`GET …/provisioning`, `POST …/provision`, `PUT …/mode`).
//!
//! UBA decides *what* to create (`GET /v1/provisioning`: object names, where
//! Graylog reaches UBA's GELF receiver, where the UBA ALERTS input listens,
//! the routing rules per source, the Wazuh rules it relies on); CoPilot
//! creates it next to the customer's streams, in Python's order:
//!
//! 1. Register the customer with UBA (`PUT /v1/tenants/{code}`) — before
//!    Graylog routes anything to it.
//! 2. Per source (WAZUH, O365): a "UBA FEED" stream in the source stream's
//!    index set, the routing rules, a "UBA ROUTING" pipeline connected with
//!    `to_pipeline` to the source stream(s) only.
//! 3. One GELF output to UBA (UDP when UBA offers it), attached to the feed
//!    streams.
//! 4. The "UBA ALERTS" input (once per Graylog) and the customer's
//!    "UBA ALERTS - <code>" stream in the Wazuh index set.
//! 5. Optional: the Wazuh rules, uploaded, then the manager restarted.
//!
//! Every object created or found is recorded for the customer
//! ([`crate::ownership`]), even when a later step failed. Each Graylog call
//! is `GraylogClient`'s (`create_entity` for the two streams, flat for the
//! rest), and fails as the Python helper fails.

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_upstream::model::construct;
use copilot_upstream::py::{self, PyExc, PyResult, getitem, py_eq};
use http::Method;

use crate::client::{Call, UbaError, UbaResult};
use crate::ops::{GraylogOps, Ops, UbaOps, WazuhOps};
use crate::ownership::{self, Owned};
use crate::pyfmt::lower;
use crate::pyops::{
    OrderedMap, attribute, empty_dict, empty_list, get_or, hashable, or_else, str_key, strip, text,
    unsupported,
};
use crate::schema::{MODE_RESPONSE, PROVISION_RESPONSE, PROVISION_STATUS, ProvisionRequest};
use crate::services::tenant;

/// `GELF_OUTPUT`.
pub const GELF_OUTPUT: &str = "org.graylog2.outputs.GelfOutput";
/// `GELF_TCP_INPUT`.
pub const GELF_TCP_INPUT: &str = "org.graylog2.inputs.gelf.tcp.GELFTCPInput";

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn dict(items: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn int(n: i64) -> PyValue {
    PyValue::Int(n.to_string())
}

fn http(status: u16, detail: impl Into<String>) -> PyExc {
    PyExc::Http(status, detail.into())
}

// --- what CoPilot holds about the customer ------------------------------------------------

/// The customer's `customersmeta` row (the first, as `.first()` takes it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// `customer_name`.
    pub customer_name: String,
    /// `customer_meta_graylog_stream`.
    pub graylog_stream: String,
    /// `customer_meta_graylog_index`.
    pub graylog_index: String,
}

/// One Office365 instance's `customer_integrations_meta` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct O365 {
    /// `graylog_stream_id`.
    pub stream_id: String,
    /// `graylog_index_id`.
    pub index_id: String,
    /// `instance_name`.
    pub instance: Option<String>,
}

/// What setup reads from the database (all of it read-only, so it is
/// loaded up front: the answers are the same as Python's reads in between
/// its calls).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// `_customer_meta`.
    pub meta: Option<Meta>,
    /// The customer's Office365 rows (in table order).
    pub o365: Vec<O365>,
    /// `_office365_tenant_ids`.
    pub tenant_ids: Vec<String>,
}

/// Load [`Facts`] with SQLAlchemy's statements.
pub async fn load_facts(db: &Db, customer_code: &str) -> Result<Facts, sqlx::Error> {
    let meta: Option<(String, String, String)> = sqlx::query_as(
        "SELECT customersmeta.customer_name, customersmeta.customer_meta_graylog_stream, \
         customersmeta.customer_meta_graylog_index FROM customersmeta \
         WHERE customersmeta.customer_code = ?",
    )
    .bind(customer_code)
    .fetch_all(db.pool())
    .await?
    .into_iter()
    .next();
    let o365: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT customer_integrations_meta.graylog_stream_id, \
         customer_integrations_meta.graylog_index_id, customer_integrations_meta.instance_name \
         FROM customer_integrations_meta \
         WHERE customer_integrations_meta.customer_code = ? \
         AND customer_integrations_meta.integration_name = ?",
    )
    .bind(customer_code)
    .bind("Office365")
    .fetch_all(db.pool())
    .await?;
    let values: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT integration_auth_keys.auth_value FROM integration_auth_keys \
         INNER JOIN integration_subscriptions \
         ON integration_auth_keys.subscription_id = integration_subscriptions.id \
         INNER JOIN integration_services \
         ON integration_subscriptions.integration_service_id = integration_services.id \
         INNER JOIN customer_integrations \
         ON customer_integrations.id = integration_subscriptions.customer_id \
         WHERE customer_integrations.customer_code = ? \
         AND integration_services.service_name = ? \
         AND integration_auth_keys.auth_key_name = ?",
    )
    .bind(customer_code)
    .bind("Office365")
    .bind("TENANT_ID")
    .fetch_all(db.pool())
    .await?;
    Ok(Facts {
        meta: meta.map(|(customer_name, graylog_stream, graylog_index)| Meta {
            customer_name,
            graylog_stream,
            graylog_index,
        }),
        o365: o365
            .into_iter()
            .map(|(stream_id, index_id, instance)| O365 {
                stream_id,
                index_id,
                instance,
            })
            .collect(),
        tenant_ids: tenant_ids(values.into_iter().filter_map(|(v,)| v)),
    })
}

/// `sorted({str(v).strip().lower() for v in values if v and str(v).strip()})`.
pub fn tenant_ids(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = values
        .into_iter()
        .filter(|v| !strip(v).is_empty())
        .map(|v| lower(strip(&v)))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A source stream (`UbaSourceStream`); `index_set_id` becomes Graylog's
/// value once resolved.
#[derive(Debug, Clone, PartialEq)]
pub struct Source {
    /// The stream id CoPilot recorded.
    pub stream_id: String,
    /// The index set it writes to.
    pub index_set_id: PyValue,
    /// The Office365 instance.
    pub instance: Option<String>,
}

/// The streams UBA reads from, per UBA source name (`WAZUH`, `O365`).
pub type Sources = Vec<(String, Vec<Source>)>;

/// `_source_streams(customer_code)`.
pub fn source_streams(customer_code: &str, facts: &Facts) -> PyResult<Sources> {
    let meta = match &facts.meta {
        Some(m) if !m.graylog_stream.is_empty() => m,
        _ => {
            return Err(http(
                409,
                format!(
                    "Customer {customer_code} has no Wazuh stream on record: provision the customer first"
                ),
            ));
        }
    };
    let mut sources = vec![(
        "WAZUH".to_string(),
        vec![Source {
            stream_id: meta.graylog_stream.clone(),
            index_set_id: s(&meta.graylog_index),
            instance: None,
        }],
    )];
    let o365: Vec<Source> = facts
        .o365
        .iter()
        .filter(|r| !r.stream_id.is_empty())
        .map(|r| Source {
            stream_id: r.stream_id.clone(),
            index_set_id: s(&r.index_id),
            instance: r.instance.clone(),
        })
        .collect();
    if !o365.is_empty() {
        sources.push(("O365".to_string(), o365));
    }
    Ok(sources)
}

/// `_resolve_index_sets(sources)`: each source stream's index set as
/// Graylog has it, not as CoPilot recorded it.
pub async fn resolve_index_sets(g: &dyn GraylogOps, sources: &mut Sources) -> PyResult<()> {
    for (name, streams) in sources.iter_mut() {
        for source in streams.iter_mut() {
            let stream = match g
                .get(&format!("/api/streams/{}", source.stream_id), &[])
                .await
            {
                Ok(reply) => or_else(Some(&reply.data), empty_dict()),
                Err(PyExc::Http(404, _)) => empty_dict(),
                Err(e) => return Err(e),
            };
            let index_set = py::get(&stream, "index_set_id")?.cloned();
            let Some(index_set) = index_set.filter(PyValue::truthy) else {
                let mut which = format!("{name} stream {}", source.stream_id);
                if let Some(instance) = source.instance.as_deref().filter(|i| !i.is_empty()) {
                    which.push_str(&format!(" ({instance})"));
                }
                return Err(http(
                    409,
                    format!(
                        "The {which} CoPilot has on record is not in Graylog: provision that source again first"
                    ),
                ));
            };
            if !py_eq(&index_set, &source.index_set_id) {
                tracing::info!(
                    "UBA provisioning: {name} stream {} writes to index set {}, not {} as recorded; using Graylog's",
                    source.stream_id,
                    text(&index_set),
                    text(&source.index_set_id)
                );
            }
            source.index_set_id = index_set;
        }
        let mut distinct: Vec<&PyValue> = Vec::new();
        for source in streams.iter() {
            hashable(&source.index_set_id)?;
            if !distinct.iter().any(|d| py_eq(d, &source.index_set_id)) {
                distinct.push(&source.index_set_id);
            }
        }
        if distinct.len() > 1 {
            return Err(http(
                409,
                format!(
                    "The customer's {name} streams write to different index sets: one UBA feed stream cannot sit next to all of them"
                ),
            ));
        }
    }
    Ok(())
}

// --- steps ----------------------------------------------------------------------------------

/// `UbaProvisionStep`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// What.
    pub step: String,
    /// Its outcome.
    pub status: String,
    /// More.
    pub detail: String,
}

impl Step {
    /// `model_dump()`.
    pub fn dump(&self) -> PyValue {
        dict(vec![
            ("step", s(&self.step)),
            ("status", s(&self.status)),
            ("detail", s(&self.detail)),
        ])
    }
}

/// `_Steps`: the report and every object created or found.
#[derive(Debug, Clone, Default)]
pub struct Steps {
    /// The report.
    pub items: Vec<Step>,
    /// Recorded for the customer.
    pub owned: Vec<Owned>,
}

impl Steps {
    fn own(
        &mut self,
        kind: &'static str,
        graylog_id: &PyValue,
        title: &str,
        created: bool,
        source: Option<&str>,
        shared: bool,
    ) {
        self.owned.push(Owned {
            kind,
            graylog_id: text(graylog_id),
            title: title.to_string(),
            source: source.map(str::to_string),
            shared,
            origin: if created { "created" } else { "found" },
        });
    }

    fn add(&mut self, step: impl Into<String>, status: &str, detail: impl Into<String>) {
        let step = step.into();
        let detail = detail.into();
        tracing::info!(
            "UBA provisioning: {}",
            format!("{step}: {status} {detail}").trim_end()
        );
        self.items.push(Step {
            step,
            status: status.to_string(),
            detail,
        });
    }
}

// --- Graylog --------------------------------------------------------------------------------

/// `_list(endpoint, key)`: `(data or {}).get(key, [])`, or `data or []`.
pub async fn list(g: &dyn GraylogOps, endpoint: &str, key: Option<&str>) -> PyResult<PyValue> {
    let data = g.get(endpoint, &[]).await?.data;
    match key {
        Some(k) => get_or(&or_else(Some(&data), empty_dict()), k, empty_list()),
        None => Ok(or_else(Some(&data), empty_list())),
    }
}

/// `{o["title"]: o for o in objects}`: only a `str` title can be looked up.
fn by_title(objects: &PyValue) -> PyResult<OrderedMap<PyValue>> {
    let mut map = OrderedMap::default();
    for o in py::iterate(objects)? {
        let title = getitem(&o, "title")?;
        if let Some(t) = str_key(title)? {
            let t = t.to_string();
            map.insert(t, o);
        }
    }
    Ok(map)
}

/// `_put(endpoint, data)`: `send_put_request` reports some failures as
/// `success: false` instead of raising.
async fn put(g: &dyn GraylogOps, endpoint: &str, data: PyValue) -> PyResult<()> {
    match g.put(endpoint, Some(data)).await? {
        Some(r) if r.success => Ok(()),
        Some(r) if !r.message.is_empty() => Err(http(502, r.message)),
        _ => Err(http(502, format!("Graylog PUT {endpoint} failed"))),
    }
}

/// `_index_prefix(index_set_id)`.
async fn index_prefix(g: &dyn GraylogOps, index_set_id: &PyValue) -> PyResult<PyValue> {
    let id = text(index_set_id);
    let reply = g
        .get(&format!("/api/system/indices/index_sets/{id}"), &[])
        .await?;
    let data = or_else(Some(&reply.data), empty_dict());
    match py::get(&data, "index_prefix")? {
        Some(p) if p.truthy() => Ok(p.clone()),
        _ => Err(http(
            502,
            format!("Graylog index set {id} has no index prefix"),
        )),
    }
}

/// `str(value)` of a value UBA names a Graylog object with.
fn need_str(what: &str, value: &PyValue) -> PyResult<String> {
    match value {
        PyValue::Str(v) => Ok(v.clone()),
        other => Err(unsupported(what, other)),
    }
}

async fn feed_stream(
    g: &dyn GraylogOps,
    title: &str,
    name: &str,
    source: &Source,
    streams: &OrderedMap<PyValue>,
    steps: &mut Steps,
) -> PyResult<PyValue> {
    if let Some(existing) = streams.get(title) {
        let index_set = py::get(existing, "index_set_id")?
            .cloned()
            .unwrap_or(PyValue::None);
        if !py_eq(&index_set, &source.index_set_id) {
            return Err(http(
                409,
                format!(
                    "Stream {title} writes to another index set than its source stream: messages would be indexed twice"
                ),
            ));
        }
        steps.add(format!("stream {title}"), "exists", "");
        let id = getitem(existing, "id")?.clone();
        steps.own(ownership::FEED_STREAM, &id, title, false, Some(name), false);
        return Ok(id);
    }
    let created = g
        .create_stream(dict(vec![
            ("title", s(title)),
            (
                "description",
                s("SOCFortress UBA feed: filled by its UBA ROUTING pipeline, sent to UBA by its output"),
            ),
            ("rules", empty_list()),
            ("matching_type", s("AND")),
            ("remove_matches_from_default_stream", PyValue::Bool(true)),
            ("index_set_id", source.index_set_id.clone()),
        ]))
        .await?;
    let stream_id = getitem(&created.data, "stream_id")?.clone();
    steps.own(
        ownership::FEED_STREAM,
        &stream_id,
        title,
        true,
        Some(name),
        false,
    );
    g.post(&format!("/api/streams/{}/resume", text(&stream_id)), None)
        .await?;
    steps.add(format!("stream {title}"), "created", "");
    Ok(stream_id)
}

/// `_rule_title(source)`: `source.split('"', 2)[1]`.
fn rule_title(source: &PyValue) -> PyResult<String> {
    match source {
        PyValue::Str(text) => text
            .split('"')
            .nth(1)
            .map(str::to_string)
            .ok_or_else(|| PyExc::IndexError("list index out of range".into())),
        other => Err(attribute(other, "split")),
    }
}

/// `x.get("source", "").strip()`.
fn stripped_source(obj: &PyValue) -> PyResult<String> {
    match get_or(obj, "source", s(""))? {
        PyValue::Str(v) => Ok(strip(&v).to_string()),
        other => Err(attribute(&other, "strip")),
    }
}

#[allow(clippy::too_many_arguments)]
async fn routing(
    g: &dyn GraylogOps,
    pipeline_title: &str,
    name: &str,
    stage: &PyValue,
    rule_sources: &PyValue,
    source_stream_ids: &[String],
    steps: &mut Steps,
) -> PyResult<()> {
    let rules = by_title(&list(g, "/api/system/pipelines/rule", None).await?)?;
    let mut titles = Vec::new();
    for source in py::iterate(rule_sources)? {
        let title = rule_title(&source)?;
        titles.push(title.clone());
        let body = dict(vec![
            ("title", s(&title)),
            ("description", s("SOCFortress UBA routing")),
            ("source", source.clone()),
        ]);
        if let Some(rule) = rules.get(&title) {
            let id = getitem(rule, "id")?.clone();
            steps.own(
                ownership::ROUTING_RULE,
                &id,
                &title,
                false,
                Some(name),
                false,
            );
            let current = stripped_source(rule)?;
            let wanted = strip(source.as_str().unwrap_or_default()).to_string();
            if current != wanted {
                put(
                    g,
                    &format!("/api/system/pipelines/rule/{}", text(&id)),
                    body,
                )
                .await?;
                steps.add(format!("rule {title}"), "updated", "");
            } else {
                steps.add(format!("rule {title}"), "exists", "");
            }
        } else {
            let created = g.post("/api/system/pipelines/rule", Some(body)).await?;
            let data = or_else(Some(&created.data), empty_dict());
            if let Some(id) = py::get(&data, "id")?.filter(|v| v.truthy()) {
                steps.own(ownership::ROUTING_RULE, id, &title, true, Some(name), false);
            }
            steps.add(format!("rule {title}"), "created", "");
        }
    }

    let mut source = format!(
        "pipeline \"{pipeline_title}\"\nstage {} match either\n",
        text(stage)
    );
    for t in &titles {
        source.push_str(&format!("rule \"{t}\"\n"));
    }
    source.push_str("end");
    let body = dict(vec![
        ("title", s(pipeline_title)),
        ("description", s("SOCFortress UBA routing")),
        ("source", s(&source)),
    ]);
    let pipelines = by_title(&list(g, "/api/system/pipelines/pipeline", None).await?)?;
    let pipeline_id = if let Some(existing) = pipelines.get(pipeline_title) {
        let id = getitem(existing, "id")?.clone();
        steps.own(
            ownership::ROUTING_PIPELINE,
            &id,
            pipeline_title,
            false,
            Some(name),
            false,
        );
        if stripped_source(existing)? != strip(&source) {
            put(
                g,
                &format!("/api/system/pipelines/pipeline/{}", text(&id)),
                body,
            )
            .await?;
            steps.add(format!("pipeline {pipeline_title}"), "updated", "");
        } else {
            steps.add(format!("pipeline {pipeline_title}"), "exists", "");
        }
        id
    } else {
        let created = g.post("/api/system/pipelines/pipeline", Some(body)).await?;
        let id = getitem(&created.data, "id")?.clone();
        steps.own(
            ownership::ROUTING_PIPELINE,
            &id,
            pipeline_title,
            true,
            Some(name),
            false,
        );
        steps.add(format!("pipeline {pipeline_title}"), "created", "");
        id
    };
    // to_pipeline sets this pipeline's streams (ours alone); to_stream would
    // replace the source stream's other pipelines.
    g.post(
        "/api/system/pipelines/connections/to_pipeline",
        Some(dict(vec![
            ("pipeline_id", pipeline_id),
            (
                "stream_ids",
                PyValue::List(source_stream_ids.iter().map(|i| s(i)).collect()),
            ),
        ])),
    )
    .await?;
    steps.add(
        format!("pipeline {pipeline_title}"),
        "connected",
        format!("to {} source stream(s)", source_stream_ids.len()),
    );
    Ok(())
}

async fn output(
    g: &dyn GraylogOps,
    title: &str,
    host: &PyValue,
    port: &PyValue,
    protocol: &str,
    feed_stream_ids: &[PyValue],
    steps: &mut Steps,
) -> PyResult<()> {
    let config = dict(vec![
        ("hostname", host.clone()),
        ("port", port.clone()),
        ("protocol", s(protocol)),
        ("connect_timeout", int(1000)),
        ("reconnect_delay", int(500)),
        ("tcp_no_delay", PyValue::Bool(false)),
        ("tcp_keep_alive", PyValue::Bool(true)),
        ("tls_verification_enabled", PyValue::Bool(false)),
        ("tls_trust_cert_chain", s("")),
        ("queue_size", int(512)),
        ("max_inflight_sends", int(512)),
    ]);
    let where_to = format!("-> {}:{} {protocol}", text(host), text(port));
    let outputs = by_title(&list(g, "/api/system/outputs", Some("outputs")).await?)?;
    let output_id = if let Some(existing) = outputs.get(title) {
        let id = getitem(existing, "id")?.clone();
        steps.own(ownership::OUTPUT, &id, title, false, None, false);
        let current = or_else(py::get(existing, "configuration")?, empty_dict());
        let field = |k: &str| -> PyResult<PyValue> { get_or(&current, k, PyValue::None) };
        let same = py_eq(&field("hostname")?, host)
            && py_eq(&field("port")?, port)
            && py_eq(&field("protocol")?, &s(protocol));
        if !same {
            put(
                g,
                &format!("/api/system/outputs/{}", text(&id)),
                dict(vec![
                    ("title", s(title)),
                    ("type", s(GELF_OUTPUT)),
                    ("configuration", config),
                ]),
            )
            .await?;
            steps.add(format!("output {title}"), "updated", where_to);
        } else {
            steps.add(format!("output {title}"), "exists", where_to);
        }
        id
    } else {
        let created = g
            .post(
                "/api/system/outputs",
                Some(dict(vec![
                    ("title", s(title)),
                    ("type", s(GELF_OUTPUT)),
                    ("configuration", config),
                    ("streams", empty_list()),
                ])),
            )
            .await?;
        let id = getitem(&created.data, "id")?.clone();
        steps.own(ownership::OUTPUT, &id, title, true, None, false);
        steps.add(format!("output {title}"), "created", where_to);
        id
    };
    for stream_id in feed_stream_ids {
        g.post(
            &format!("/api/streams/{}/outputs", text(stream_id)),
            Some(dict(vec![(
                "outputs",
                PyValue::List(vec![output_id.clone()]),
            )])),
        )
        .await?;
    }
    steps.add(
        format!("output {title}"),
        "attached",
        format!("to {} feed stream(s)", feed_stream_ids.len()),
    );
    Ok(())
}

/// `_protocol(feed_output)`: UDP when UBA says its receiver takes it.
pub fn protocol(feed_output: &PyValue) -> PyResult<&'static str> {
    let value = or_else(py::get(feed_output, "protocol")?, s("tcp"));
    Ok(if lower(&text(&value)) == "udp" {
        "UDP"
    } else {
        "TCP"
    })
}

async fn alerts(
    g: &dyn GraylogOps,
    info: &PyValue,
    customer_code: &str,
    wazuh_index_set: &PyValue,
    steps: &mut Steps,
) -> PyResult<()> {
    let names = getitem(info, "graylog")?;
    let listen = getitem(info, "alerts_input")?;
    let inputs = by_title(&list(g, "/api/system/inputs", Some("inputs")).await?)?;
    let input_name = getitem(names, "alerts_input")?;
    hashable(input_name)?;
    let input_title = need_str("UBA's alerts_input name", input_name)?;
    if let Some(existing) = inputs.get(&input_title) {
        let id = getitem(existing, "id")?.clone();
        steps.own(
            ownership::ALERTS_INPUT,
            &id,
            &input_title,
            false,
            None,
            true,
        );
        let attrs = or_else(py::get(existing, "attributes")?, empty_dict());
        let detail = format!(
            "{}:{}",
            text(&get_or(&attrs, "bind_address", PyValue::None)?),
            text(&get_or(&attrs, "port", PyValue::None)?)
        );
        steps.add(format!("input {input_title}"), "exists", detail);
    } else {
        let bind_address = getitem(listen, "bind_address")?.clone();
        let port = getitem(listen, "port")?.clone();
        let created = g
            .post(
                "/api/system/inputs",
                Some(dict(vec![
                    ("title", s(&input_title)),
                    ("type", s(GELF_TCP_INPUT)),
                    ("global", PyValue::Bool(true)),
                    (
                        "configuration",
                        dict(vec![
                            ("bind_address", bind_address),
                            ("port", port),
                            ("use_null_delimiter", PyValue::Bool(true)),
                            ("max_message_size", int(2_097_152)),
                            ("recv_buffer_size", int(1_048_576)),
                            ("number_worker_threads", int(2)),
                            ("tcp_keepalive", PyValue::Bool(true)),
                            ("tls_enable", PyValue::Bool(false)),
                            ("charset_name", s("UTF-8")),
                            ("decompress_size_limit", int(8_388_608)),
                        ]),
                    ),
                ])),
            )
            .await?;
        let data = or_else(Some(&created.data), empty_dict());
        if let Some(id) = py::get(&data, "id")?.filter(|v| v.truthy()) {
            steps.own(ownership::ALERTS_INPUT, id, &input_title, true, None, true);
        }
        let detail = format!(
            "{}:{}",
            text(getitem(listen, "bind_address")?),
            text(getitem(listen, "port")?)
        );
        steps.add(format!("input {input_title}"), "created", detail);
    }

    let title = crate::pyops::format(
        getitem(names, "alerts_stream")?,
        &[("tenant", customer_code)],
    )?;
    let streams = by_title(&list(g, "/api/streams", Some("streams")).await?)?;
    if let Some(existing) = streams.get(&title) {
        let id = getitem(existing, "id")?.clone();
        steps.own(ownership::ALERTS_STREAM, &id, &title, false, None, false);
        steps.add(format!("stream {title}"), "exists", "");
        return Ok(());
    }
    let wanted = getitem(names, "alerts_stream_rules")?;
    let PyValue::Dict(pairs) = wanted else {
        return Err(attribute(wanted, "items"));
    };
    let mut rules = Vec::new();
    for (field, value) in pairs {
        rules.push(dict(vec![
            ("field", s(field)),
            ("type", int(1)),
            (
                "value",
                s(&crate::pyops::format(value, &[("tenant", customer_code)])?),
            ),
            ("inverted", PyValue::Bool(false)),
            ("description", s("UBA")),
        ]));
    }
    let created = g
        .create_stream(dict(vec![
            ("title", s(&title)),
            (
                "description",
                s("SOCFortress UBA alerts (no UBA pipeline may be connected: loop guard)"),
            ),
            ("rules", PyValue::List(rules)),
            ("matching_type", s("AND")),
            ("remove_matches_from_default_stream", PyValue::Bool(true)),
            ("index_set_id", wazuh_index_set.clone()),
        ]))
        .await?;
    let stream_id = getitem(&created.data, "stream_id")?.clone();
    steps.own(
        ownership::ALERTS_STREAM,
        &stream_id,
        &title,
        true,
        None,
        false,
    );
    g.post(&format!("/api/streams/{}/resume", text(&stream_id)), None)
        .await?;
    steps.add(
        format!("stream {title}"),
        "created",
        "in the Wazuh index set",
    );
    Ok(())
}

async fn wazuh_rules(w: &dyn WazuhOps, files: &PyValue, steps: &mut Steps) -> PyResult<()> {
    let files = py::iterate(files)?;
    for f in &files {
        let filename = getitem(f, "filename")?;
        let content = getitem(f, "content")?;
        let PyValue::Str(content) = content else {
            return Err(attribute(content, "encode"));
        };
        let filename = need_str("A Wazuh rules file name", filename)?;
        w.upload_rules(&filename, content.as_bytes().to_vec())
            .await?;
        steps.own(
            ownership::WAZUH_RULES,
            &s(&filename),
            &filename,
            true,
            None,
            true,
        );
        steps.add(format!("Wazuh rules {filename}"), "uploaded", "");
    }
    if !files.is_empty() {
        w.restart().await?;
        steps.add(
            "Wazuh manager",
            "restarted",
            "check that the log shipper (e.g. Fluent Bit) still ships alerts.json after the restart",
        );
    }
    Ok(())
}

// --- entry points ---------------------------------------------------------------------------

fn request_error(reason: &'static str, detail: String, status: u16) -> UbaError {
    UbaError::Request {
        reason,
        detail,
        status,
    }
}

/// `_provisioning_info()`.
async fn provisioning_info(uba: &dyn UbaOps) -> UbaResult<PyValue> {
    let info = uba.call(Call::get("/v1/provisioning")).await?;
    let mut missing = Vec::new();
    for (name, key) in [
        ("UBA_PROVISION_FEED_HOST", "feed_output"),
        ("UBA_PROVISION_ALERTS_BIND", "alerts_input"),
    ] {
        if !py::get(&info, key)?.is_some_and(PyValue::truthy) {
            missing.push(name);
        }
    }
    if !missing.is_empty() {
        return Err(request_error(
            "not_configured",
            format!(
                "SOCFortress UBA does not say where Graylog reaches it: set {} in UBA's environment",
                missing.join(" and ")
            ),
            409,
        ));
    }
    Ok(info)
}

/// `uba_request("GET", …/onboarding)`, a 404 being `None`.
async fn onboarding(uba: &dyn UbaOps, customer_code: &str) -> UbaResult<PyValue> {
    match uba
        .call(Call::get(format!("{}/onboarding", tenant(customer_code))))
        .await
    {
        Ok(v) => Ok(v),
        Err(UbaError::Request { status: 404, .. }) => Ok(PyValue::None),
        Err(e) => Err(e),
    }
}

/// `onboarding and onboarding.get("active")`.
fn is_active(onboarding: &PyValue) -> PyResult<bool> {
    if !onboarding.truthy() {
        return Ok(false);
    }
    Ok(py::get(onboarding, "active")?.is_some_and(PyValue::truthy))
}

/// `get_provisioning_status(customer_code)`.
pub async fn status(ops: Ops<'_>, customer_code: &str, facts: &Facts) -> UbaResult<PyValue> {
    let resolved: PyResult<Sources> = async {
        let mut sources = source_streams(customer_code, facts)?;
        resolve_index_sets(ops.graylog, &mut sources).await?;
        Ok(sources)
    }
    .await;
    let (sources, problem) = match resolved {
        Ok(sources) => (sources, PyValue::None),
        Err(PyExc::Http(_, detail)) => (Vec::new(), PyValue::Str(detail)),
        Err(e) => return Err(UbaError::Py(e)),
    };
    let onboarding = onboarding(ops.uba, customer_code).await?;
    let message = if is_active(&onboarding)? {
        "UBA is set up for this customer"
    } else {
        "UBA is not set up"
    };
    Ok(construct(
        &PROVISION_STATUS,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            ("message", s(message)),
            (
                "sources",
                PyValue::Dict(
                    sources
                        .iter()
                        .map(|(k, v)| (k.clone(), int(i64::try_from(v.len()).unwrap_or(0))))
                        .collect(),
                ),
            ),
            (
                "office365_tenants",
                PyValue::List(facts.tenant_ids.iter().map(|t| s(t)).collect()),
            ),
            ("problem", problem),
            ("onboarding", onboarding),
        ]),
    )?)
}

/// The default index pattern UBA uses for an integration
/// (`DEFAULT_INDEX[integration].format(code=…)`).
fn default_index(integration: &PyValue, code: &str) -> PyResult<String> {
    hashable(integration)?;
    match integration.as_str() {
        Some("wazuh") => Ok(format!("wazuh-{code}_*")),
        Some("office365") => Ok(format!("office365-{code}_*,graylog_*")),
        _ => Err(PyExc::KeyError(integration.py_repr())),
    }
}

/// `provision_uba(customer_code, request)`: the steps, then the objects
/// recorded for the customer whatever happened.
pub async fn provision(
    ops: Ops<'_>,
    db: &Db,
    customer_code: &str,
    request: &ProvisionRequest,
    facts: &Facts,
) -> UbaResult<PyValue> {
    let (result, owned) = run(ops, customer_code, request, facts).await;
    if let Some(owned) = owned {
        record_ownership(db, customer_code, &owned).await;
    }
    result
}

/// The setup itself: its answer, and the objects to record for the
/// customer (`None` when it stopped before the first Graylog step, where
/// Python records nothing).
pub async fn run(
    ops: Ops<'_>,
    customer_code: &str,
    request: &ProvisionRequest,
    facts: &Facts,
) -> (UbaResult<PyValue>, Option<Vec<Owned>>) {
    let mut steps = Steps::default();
    let registration = match register(ops, customer_code, request, facts, &mut steps).await {
        Ok(r) => r,
        Err(e) => return (Err(e), None),
    };
    let (info, names, sources, registration) = registration;
    let outcome = provision_steps(
        ops,
        customer_code,
        request,
        &info,
        &names,
        &sources,
        &mut steps,
    )
    .await;
    // Recorded even when a step failed: what was created before it is the
    // customer's too.
    let owned = Some(steps.owned.clone());
    if let Err(e) = outcome {
        return (Err(e), owned);
    }
    let answer = construct(
        &PROVISION_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(&format!(
                    "UBA is set up for {customer_code}: it replays history, then goes live"
                )),
            ),
            (
                "steps",
                PyValue::List(steps.items.iter().map(Step::dump).collect()),
            ),
            ("onboarding", registration),
        ]),
    )
    .map_err(UbaError::Py);
    (answer, owned)
}

type Registered = (PyValue, PyValue, Sources, PyValue);

/// UBA's names, the customer's sources, then the registration with UBA.
async fn register(
    ops: Ops<'_>,
    customer_code: &str,
    request: &ProvisionRequest,
    facts: &Facts,
    steps: &mut Steps,
) -> UbaResult<Registered> {
    let info = provisioning_info(ops.uba).await?;
    let names = getitem(&info, "graylog")?.clone();
    let mut sources = source_streams(customer_code, facts)?;
    resolve_index_sets(ops.graylog, &mut sources).await?;
    let tenant_ids = &facts.tenant_ids;
    let customer_name = facts
        .meta
        .as_ref()
        .map(|m| m.customer_name.clone())
        .unwrap_or_default();

    // 1. Register with UBA first.
    let mut indices: Vec<(String, PyValue)> = Vec::new();
    for (name, streams) in &sources {
        let integration = getitem(getitem(&names, "sources")?, name)?.clone();
        let prefix = index_prefix(ops.graylog, &streams[0].index_set_id).await?;
        let default = default_index(&integration, &lower(customer_code))?;
        let wanted = format!("{}_*", text(&prefix));
        if !default.starts_with(&wanted) {
            let key = need_str("A UBA integration name", &integration)?;
            match indices.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = s(&wanted),
                None => indices.push((key, s(&wanted))),
            }
        }
    }
    let bootstrap_days = request.bootstrap_days.clone();
    let registration = ops
        .uba
        .call(
            Call::new(Method::PUT, tenant(customer_code)).json(dict(vec![
                ("name", s(&customer_name)),
                ("active", PyValue::Bool(true)),
                ("bootstrap_days", PyValue::Int(bootstrap_days.clone())),
                (
                    "office365_organization_ids",
                    PyValue::List(tenant_ids.iter().map(|t| s(t)).collect()),
                ),
                (
                    "indices",
                    if indices.is_empty() {
                        PyValue::None
                    } else {
                        PyValue::Dict(indices)
                    },
                ),
            ])),
        )
        .await?;
    let status = get_or(&registration, "status", PyValue::None)?;
    steps.add(
        "UBA tenant",
        "registered",
        format!(
            "{}; {} Microsoft 365 tenant(s); {bootstrap_days} day(s) of history",
            text(&status),
            tenant_ids.len()
        ),
    );
    Ok((info, names, sources, registration))
}

async fn provision_steps(
    ops: Ops<'_>,
    customer_code: &str,
    request: &ProvisionRequest,
    info: &PyValue,
    names: &PyValue,
    sources: &Sources,
    steps: &mut Steps,
) -> UbaResult<()> {
    let g = ops.graylog;
    // 2-3. Feed streams, routing, output.
    let streams = by_title(&list(g, "/api/streams", Some("streams")).await?)?;
    let mut feed_ids = Vec::new();
    for (name, source_streams) in sources {
        let integration = getitem(getitem(names, "sources")?, name)?.clone();
        let title = crate::pyops::format(
            getitem(names, "feed_stream")?,
            &[("source", name), ("tenant", customer_code)],
        )?;
        feed_ids.push(feed_stream(g, &title, name, &source_streams[0], &streams, steps).await?);
        let rules = ops
            .uba
            .call(
                Call::get(format!(
                    "/v1/integrations/{}/graylog-rules",
                    text(&integration)
                ))
                .params(vec![("stream".to_string(), s(&title))]),
            )
            .await?;
        let rule_sources = getitem(&rules, "rules")?.clone();
        let pipeline_title = crate::pyops::format(
            getitem(names, "routing_pipeline")?,
            &[("source", name), ("tenant", customer_code)],
        )?;
        let stage = getitem(names, "pipeline_stage")?.clone();
        let stream_ids: Vec<String> = source_streams.iter().map(|s| s.stream_id.clone()).collect();
        routing(
            g,
            &pipeline_title,
            name,
            &stage,
            &rule_sources,
            &stream_ids,
            steps,
        )
        .await?;
    }
    let feed_output = getitem(info, "feed_output")?;
    let output_title =
        crate::pyops::format(getitem(names, "output")?, &[("tenant", customer_code)])?;
    let host = getitem(feed_output, "host")?.clone();
    let port = getitem(feed_output, "port")?.clone();
    let proto = protocol(feed_output)?;
    output(g, &output_title, &host, &port, proto, &feed_ids, steps).await?;

    // 4. Alerts back into Graylog.
    let wazuh_index_set = sources
        .iter()
        .find(|(k, _)| k == "WAZUH")
        .and_then(|(_, v)| v.first())
        .map(|s| s.index_set_id.clone())
        .unwrap_or(PyValue::None);
    alerts(g, info, customer_code, &wazuh_index_set, steps).await?;

    // 5. Optional Wazuh rules.
    if request.deploy_wazuh_rules {
        let files = or_else(py::get(info, "wazuh_rules")?, empty_list());
        wazuh_rules(ops.wazuh, &files, steps).await?;
    } else {
        steps.add("Wazuh rules", "skipped", "not requested");
    }
    Ok(())
}

/// `_record_ownership`: committed on its own; a failure is logged and
/// rolled back, never the request's.
pub async fn record_ownership(db: &Db, customer_code: &str, owned: &[Owned]) {
    let result: Result<(), sqlx::Error> = async {
        let mut tx = db.pool().begin().await?;
        ownership::record(&mut tx, customer_code, owned).await?;
        tx.commit().await
    }
    .await;
    if let Err(e) = result {
        tracing::error!(
            "UBA provisioning: recording the Graylog objects of {customer_code} failed: {e}"
        );
    }
}

/// `set_mode(customer_code, mode)`: active or learning, only for a customer
/// UBA serves.
pub async fn set_mode(uba: &dyn UbaOps, customer_code: &str, mode: &str) -> UbaResult<PyValue> {
    let onboarding = onboarding(uba, customer_code).await?;
    if !is_active(&onboarding)? {
        return Err(request_error(
            "not_active",
            format!("UBA is not set up for {customer_code}: set it up first"),
            409,
        ));
    }
    // "active" is sent too: a UBA without modes reads a registration that
    // leaves it out as active=true.
    let result = uba
        .call(
            Call::new(Method::PUT, tenant(customer_code)).json(dict(vec![
                ("active", PyValue::Bool(true)),
                ("mode", s(mode)),
            ])),
        )
        .await?;
    if !py_eq(&get_or(&result, "mode", PyValue::None)?, &s(mode)) {
        return Err(request_error(
            "unsupported",
            "This SOCFortress UBA version has no learning mode: upgrade UBA".into(),
            409,
        ));
    }
    let text = if mode == "active" {
        "UBA alerts reach CoPilot again"
    } else {
        "UBA keeps learning; its alerts stay in UBA"
    };
    Ok(construct(
        &MODE_RESPONSE,
        &dict(vec![
            ("success", PyValue::Bool(true)),
            ("message", s(&format!("{customer_code}: {text}"))),
            ("onboarding", result),
        ]),
    )?)
}
