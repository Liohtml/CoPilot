//! WAF events into the SIEM (#1169) — port of
//! `app/customer_waf/services/forwarding.py`.
//!
//! Set up, per WAF: a Graylog **Syslog TCP input** on a free port of
//! `WAF_SYSLOG_PORT_RANGE` with three static fields (`syslog_type=waf`,
//! `syslog_customer=<code>`, `waf_name`) and three extractors (the JSON is
//! flattened with the load-bearing `waf_` prefix), and a **syslog forwarder
//! on the WAF**. Per customer, shared by sibling WAFs: the `waf-<code>` index
//! set and the "SOCFORTRESS WAF - <code>" stream (created through
//! `create_entity`, the one wrapped endpoint here). Every step that creates
//! something registers an undo; a failure unwinds newest-first, and what was
//! *reused* is never undone. Teardown removes the forwarder and the input, the
//! stream only with the customer's last forwarding WAF, never the index set.

use copilot_auth::pyvalue::PyValue;
use copilot_core::time::now_utc_micros;
use copilot_graylog::client::{DEFAULT_CONNECTOR, EntityKind};
use copilot_upstream::model::kwargs;
use copilot_upstream::py::{PyExc, get, getitem, int_of, iterate};
use http::Method;

use crate::client::{Call, WafError, WafResult};
use crate::services::{WafState, capabilities_for_roles};
use crate::store::{self, WafRow};

/// `SYSLOG_TYPE`.
pub const SYSLOG_TYPE: &str = "waf";
/// `WAF_SOURCE`.
pub const WAF_SOURCE: &str = "socfortress-waf";
/// `SYSLOG_INPUT_TYPE`.
pub const SYSLOG_INPUT_TYPE: &str = "org.graylog2.inputs.syslog.tcp.SyslogTCPInput";
/// `DEFAULT_PORT_RANGE`.
pub const DEFAULT_PORT_RANGE: &str = "5600-5699";

/// `ForwardingError`: `status_code`, rollback already done.
#[derive(Debug, Clone, PartialEq)]
pub struct ForwardingError {
    /// `detail`.
    pub detail: String,
    /// `status_code`.
    pub status: u16,
    /// What the rollback could not undo.
    pub rollback_failures: Vec<String>,
}

impl ForwardingError {
    fn new(detail: impl Into<String>, status: u16) -> Self {
        Self {
            detail: detail.into(),
            status,
            rollback_failures: Vec::new(),
        }
    }
}

/// What provisioning can raise.
#[derive(Debug, Clone, PartialEq)]
pub enum ProvisionError {
    /// `ForwardingError`.
    Forwarding(ForwardingError),
    /// Anything else, by its Python class.
    Waf(WafError),
}

impl From<WafError> for ProvisionError {
    fn from(e: WafError) -> Self {
        Self::Waf(e)
    }
}

impl From<PyExc> for ProvisionError {
    fn from(e: PyExc) -> Self {
        Self::Waf(WafError::Py(e))
    }
}

/// `input_title`.
pub fn input_title(row: &WafRow) -> String {
    format!("SOCFORTRESS WAF - {} - {}", row.customer_code, row.name)
}

/// `stream_title`.
pub fn stream_title(code: &str) -> String {
    format!("SOCFORTRESS WAF - {code}")
}

/// `index_prefix` (Graylog index prefixes are lower case).
pub fn index_prefix(code: &str) -> String {
    format!("waf-{}", code.to_lowercase())
}

/// `port_range()`.
pub fn port_range(raw: Option<&str>) -> Result<(i64, i64), ForwardingError> {
    // `(os.environ.get(…) or DEFAULT_PORT_RANGE).strip()`.
    let raw = copilot_web::form::py_strip(match raw {
        Some(r) if !r.is_empty() => r,
        _ => DEFAULT_PORT_RANGE,
    });
    let bad = || {
        ForwardingError::new(
            format!("WAF_SYSLOG_PORT_RANGE must look like 5600-5699, got '{raw}'"),
            400,
        )
    };
    let (a, b) = raw.split_once('-').ok_or_else(bad)?;
    let parse = |p: &str| int_of(&PyValue::Str(p.to_string())).ok();
    let low: i64 = parse(a).and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    let high: i64 = parse(b).and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    if !(1024 <= low && low <= high && high <= 65535) {
        return Err(ForwardingError::new(
            format!("WAF_SYSLOG_PORT_RANGE '{raw}' is outside 1024-65535"),
            400,
        ));
    }
    Ok((low, high))
}

/// `default_syslog_host()`.
pub fn default_syslog_host(raw: Option<&str>) -> Option<String> {
    let host = copilot_web::form::py_strip(raw.unwrap_or_default());
    (!host.is_empty()).then(|| host.to_string())
}

fn pick_port(used: &[i64], low: i64, high: i64) -> Result<i64, ForwardingError> {
    (low..=high).find(|p| !used.contains(p)).ok_or_else(|| {
        ForwardingError::new(
            format!(
                "No free port left in {low}-{high} for a new WAF input. Widen \
                 WAF_SYSLOG_PORT_RANGE."
            ),
            409,
        )
    })
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn b(v: bool) -> PyValue {
    PyValue::Bool(v)
}

fn n(v: i64) -> PyValue {
    PyValue::Int(v.to_string())
}

/// `input_payload`.
pub fn input_payload(row: &WafRow, port: i64) -> PyValue {
    kwargs(vec![
        ("title", PyValue::Str(input_title(row))),
        ("type", s(SYSLOG_INPUT_TYPE)),
        ("global", b(true)),
        (
            "configuration",
            kwargs(vec![
                ("bind_address", s("0.0.0.0")),
                ("port", n(port)),
                ("tls_enable", b(false)),
                ("recv_buffer_size", n(1_048_576)),
                ("tcp_keepalive", b(false)),
                ("use_null_delimiter", b(false)),
                ("max_message_size", n(2_097_152)),
                ("force_rdns", b(false)),
                ("allow_override_date", b(true)),
                ("store_full_message", b(false)),
                ("expand_structured_data", b(false)),
                ("number_worker_threads", n(2)),
                ("charset_name", s("UTF-8")),
            ]),
        ),
    ])
}

/// `static_fields`.
pub fn static_fields(row: &WafRow) -> Vec<PyValue> {
    vec![
        kwargs(vec![("key", s("syslog_type")), ("value", s(SYSLOG_TYPE))]),
        kwargs(vec![
            ("key", s("syslog_customer")),
            ("value", PyValue::Str(row.customer_code.clone())),
        ]),
        kwargs(vec![
            ("key", s("waf_name")),
            ("value", PyValue::Str(row.name.clone())),
        ]),
    ]
}

/// `extractor_payloads`.
pub fn extractor_payloads() -> Vec<PyValue> {
    vec![
        kwargs(vec![
            ("title", s("WAF - pull the JSON out of the syslog message")),
            ("extractor_type", s("regex")),
            ("source_field", s("message")),
            ("target_field", s("waf_json")),
            ("cursor_strategy", s("copy")),
            ("condition_type", s("string")),
            ("condition_value", s(WAF_SOURCE)),
            (
                "extractor_config",
                kwargs(vec![("regex_value", s(r"^\S+ - (\{.*\})$"))]),
            ),
            ("converters", PyValue::List(Vec::new())),
            ("order", n(0)),
        ]),
        kwargs(vec![
            ("title", s("WAF - expand the JSON into waf_* fields")),
            ("extractor_type", s("json")),
            ("source_field", s("waf_json")),
            ("target_field", s("")),
            ("cursor_strategy", s("copy")),
            ("condition_type", s("none")),
            ("condition_value", s("")),
            (
                "extractor_config",
                kwargs(vec![
                    ("flatten", b(true)),
                    ("list_separator", s(", ")),
                    ("key_separator", s("_")),
                    ("kv_separator", s("=")),
                    ("key_prefix", s("waf_")),
                    ("replace_key_whitespace", b(true)),
                    ("key_whitespace_replacement", s("_")),
                ]),
            ),
            ("converters", PyValue::List(Vec::new())),
            ("order", n(1)),
        ]),
        kwargs(vec![
            ("title", s("WAF - first matched rule message")),
            ("extractor_type", s("regex")),
            ("source_field", s("waf_json")),
            ("target_field", s("waf_rule_msg")),
            ("cursor_strategy", s("copy")),
            ("condition_type", s("string")),
            ("condition_value", s("\"matched_rules\":[{")),
            (
                "extractor_config",
                kwargs(vec![(
                    "regex_value",
                    s(r#""matched_rules":\[\{"id":"[^"]*","msg":"((?:[^"\\]|\\.)*)""#),
                )]),
            ),
            ("converters", PyValue::List(Vec::new())),
            ("order", n(2)),
        ]),
    ]
}

/// `index_set_payload` (`creation_date` is `utcnow()` with microseconds).
pub fn index_set_payload(code: &str, customer_name: &str) -> PyValue {
    let now = now_utc_micros();
    kwargs(vec![
        ("title", PyValue::Str(format!("{customer_name} - WAF"))),
        (
            "description",
            PyValue::Str(format!("{code} - SOCFortress WAF events")),
        ),
        ("index_prefix", PyValue::Str(index_prefix(code))),
        (
            "rotation_strategy_class",
            s("org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy"),
        ),
        (
            "rotation_strategy",
            kwargs(vec![
                (
                    "type",
                    s("org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig"),
                ),
                ("rotation_period", s("P1D")),
                ("rotate_empty_index_set", b(false)),
                ("max_rotation_period", PyValue::None),
            ]),
        ),
        (
            "retention_strategy_class",
            s("org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy"),
        ),
        (
            "retention_strategy",
            kwargs(vec![
                (
                    "type",
                    s("org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig"),
                ),
                ("max_number_of_indices", n(30)),
            ]),
        ),
        (
            "creation_date",
            PyValue::Str(now.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()),
        ),
        ("index_analyzer", s("standard")),
        ("shards", n(1)),
        ("replicas", n(0)),
        ("index_optimization_max_num_segments", n(1)),
        ("index_optimization_disabled", b(false)),
        ("writable", b(true)),
        ("field_type_refresh_interval", n(5000)),
    ])
}

/// `stream_payload`.
pub fn stream_payload(code: &str, index_set_id: &PyValue) -> PyValue {
    let rule = |field: &str, value: &str| {
        kwargs(vec![
            ("field", s(field)),
            ("type", n(1)),
            ("inverted", b(false)),
            ("value", s(value)),
        ])
    };
    kwargs(vec![
        ("title", PyValue::Str(stream_title(code))),
        (
            "description",
            PyValue::Str(format!("SOCFortress WAF events for customer {code}")),
        ),
        ("index_set_id", index_set_id.clone()),
        (
            "rules",
            PyValue::List(vec![
                rule("syslog_type", SYSLOG_TYPE),
                rule("syslog_customer", code),
            ]),
        ),
        ("matching_type", s("AND")),
        ("remove_matches_from_default_stream", b(true)),
        ("content_pack", PyValue::None),
    ])
}

/// `forwarder_payload`.
pub fn forwarder_payload(row: &WafRow, host: &str, port: i64) -> PyValue {
    kwargs(vec![
        (
            "name",
            PyValue::Str(format!("CoPilot SIEM ({})", row.customer_code)),
        ),
        ("type", s("syslog")),
        ("is_enabled", b(true)),
        ("syslog_host", s(host)),
        ("syslog_port", n(port)),
        ("syslog_tls", b(false)),
        ("syslog_app_name", s("waf-platform")),
    ])
}

/// One undo step.
enum Undo {
    GraylogDelete(String, Vec<(&'static str, String)>),
    WafDelete(String),
}

/// The undo stack (`_Rollback`).
struct Rollback {
    steps: Vec<(String, Undo)>,
}

impl Rollback {
    async fn run(self, st: &WafState, row: &WafRow) -> Vec<String> {
        let mut failures = Vec::new();
        for (description, undo) in self.steps.into_iter().rev() {
            let result = match undo {
                Undo::GraylogDelete(endpoint, params) => {
                    let params: Vec<(&str, String)> =
                        params.iter().map(|(k, v)| (*k, v.clone())).collect();
                    st.graylog
                        .delete(&endpoint, &params)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.display())
                }
                Undo::WafDelete(path) => st
                    .client
                    .request(row, Call::new(Method::DELETE, path))
                    .await
                    .map(|_| ())
                    .map_err(|e| match e {
                        WafError::Request { detail, .. } => detail,
                        WafError::Crypto(c) => c.message,
                        WafError::Py(p) => p.display(),
                    }),
            };
            match result {
                Ok(()) => tracing::info!("WAF forwarding rollback: undid {description}"),
                Err(e) => {
                    tracing::error!("WAF forwarding rollback: could not undo {description}: {e}");
                    failures.push(format!("{description}: {e}"));
                }
            }
        }
        failures
    }
}

/// `int((i.get("attributes") or {}).get("port"))`, skipping what `int()`
/// refuses.
fn used_ports(inputs: &PyValue) -> Result<Vec<i64>, PyExc> {
    let mut ports = Vec::new();
    for i in iterate(inputs)? {
        let attrs = get(&i, "attributes")?.cloned().unwrap_or(PyValue::None);
        let attrs = if attrs.truthy() {
            attrs
        } else {
            PyValue::Dict(Vec::new())
        };
        let port = get(&attrs, "port")?.cloned().unwrap_or(PyValue::None);
        match int_of(&port) {
            Ok(p) => {
                if let Ok(p) = p.parse::<i64>() {
                    ports.push(p);
                }
            }
            Err(PyExc::TypeError(_) | PyExc::ValueError(_)) => {}
            Err(other) => return Err(other),
        }
    }
    Ok(ports)
}

/// `next((s["id"] for s in data.get(key, []) if s.get(field) == value), None)`.
fn find_id(data: &PyValue, key: &str, field: &str, value: &str) -> Result<Option<PyValue>, PyExc> {
    let list = get(data, key)?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    for item in iterate(&list)? {
        if get(&item, field)?.and_then(PyValue::as_str) == Some(value) {
            return Ok(Some(getitem(&item, "id")?.clone()));
        }
    }
    Ok(None)
}

/// Whether Python's `except (HTTPException, WafRequestError, ForwardingError,
/// KeyError, TypeError)` catches it.
fn rolled_back(e: &ProvisionError) -> bool {
    matches!(
        e,
        ProvisionError::Forwarding(_)
            | ProvisionError::Waf(WafError::Request { .. })
            | ProvisionError::Waf(WafError::Py(
                PyExc::Http(..) | PyExc::KeyError(_) | PyExc::TypeError(_)
            ))
    )
}

/// `ProvisionResult`.
#[derive(Debug, Clone, PartialEq)]
pub struct Provisioned {
    /// The row after the commit.
    pub row: WafRow,
    /// `test_success`.
    pub test_success: Option<bool>,
    /// `test_message`.
    pub test_message: PyValue,
    /// `reused`.
    pub reused: Vec<String>,
}

struct Created {
    port: i64,
    input_id: PyValue,
    index_set_id: PyValue,
    stream_id: PyValue,
    forwarder_id: String,
}

/// The `try` block of `provision`, registering undos as it goes.
async fn create_objects(
    st: &WafState,
    row: &WafRow,
    host: &str,
    low: i64,
    high: i64,
    rollback: &mut Rollback,
    reused: &mut Vec<String>,
) -> Result<Created, ProvisionError> {
    let inputs = st.graylog.get("/api/system/inputs", &[]).await?;
    let list = get(&inputs.data, "inputs")?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    let port = pick_port(&used_ports(&list)?, low, high).map_err(ProvisionError::Forwarding)?;

    let created = st
        .graylog
        .post("/api/system/inputs", Some(input_payload(row, port)))
        .await?;
    let input_id = getitem(&created.data, "id")?.clone();
    let input_text = input_id.py_str();
    rollback.steps.push((
        format!("Graylog input {input_text}"),
        Undo::GraylogDelete(format!("/api/system/inputs/{input_text}"), Vec::new()),
    ));
    for sf in static_fields(row) {
        st.graylog
            .post(
                &format!("/api/system/inputs/{input_text}/staticfields"),
                Some(sf),
            )
            .await?;
    }
    for ex in extractor_payloads() {
        st.graylog
            .post(
                &format!("/api/system/inputs/{input_text}/extractors"),
                Some(ex),
            )
            .await?;
    }

    let sets = st
        .graylog
        .get(
            "/api/system/indices/index_sets",
            &[("skip_config_check", "true".to_string())],
        )
        .await?;
    let found = find_id(
        &sets.data,
        "index_sets",
        "index_prefix",
        &index_prefix(&row.customer_code),
    )?;
    let index_set_id = match found.filter(PyValue::truthy) {
        Some(id) => {
            reused.push(format!("index set {}", index_prefix(&row.customer_code)));
            id
        }
        None => {
            let name = store::customer_name(&st.ctx.db, &row.customer_code)
                .await
                .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
                .unwrap_or_else(|| row.customer_code.clone());
            let reply = st
                .graylog
                .post(
                    "/api/system/indices/index_sets",
                    Some(index_set_payload(&row.customer_code, &name)),
                )
                .await?;
            let id = getitem(&reply.data, "id")?.clone();
            let text = id.py_str();
            rollback.steps.push((
                format!("Graylog index set {text}"),
                Undo::GraylogDelete(
                    format!("/api/system/indices/index_sets/{text}"),
                    vec![("delete_indices", "true".to_string())],
                ),
            ));
            id
        }
    };

    let streams = st.graylog.get("/api/streams", &[]).await?;
    let found = find_id(
        &streams.data,
        "streams",
        "title",
        &stream_title(&row.customer_code),
    )?;
    let stream_id = match found.filter(PyValue::truthy) {
        Some(id) => {
            reused.push(format!("stream '{}'", stream_title(&row.customer_code)));
            id
        }
        None => {
            let reply = st
                .graylog
                .create_entity(
                    DEFAULT_CONNECTOR,
                    &EntityKind::Stream,
                    stream_payload(&row.customer_code, &index_set_id),
                    None,
                )
                .await?;
            let id = getitem(&reply.data, "stream_id")?.clone();
            let text = id.py_str();
            rollback.steps.push((
                format!("Graylog stream {text}"),
                Undo::GraylogDelete(format!("/api/streams/{text}"), Vec::new()),
            ));
            st.graylog
                .post(&format!("/api/streams/{text}/resume"), None)
                .await?;
            id
        }
    };

    let forwarder = st
        .client
        .request(
            row,
            Call::new(Method::POST, "/forwarders/")
                .json(forwarder_payload(row, host, port))
                .timeout(30.0),
        )
        .await?;
    let forwarder_id = getitem(&forwarder, "id")?.py_str();
    rollback.steps.push((
        format!("WAF forwarder {forwarder_id}"),
        Undo::WafDelete(format!("/forwarders/{forwarder_id}")),
    ));
    Ok(Created {
        port,
        input_id,
        index_set_id,
        stream_id,
        forwarder_id,
    })
}

/// An id the ORM stores in a `varchar(64)` column (Python assigns the JSON
/// value; strings are the case Graylog produces).
fn id_text(v: &PyValue) -> String {
    match v {
        PyValue::Str(s) => s.clone(),
        other => other.py_str(),
    }
}

/// `provision`.
pub async fn provision(
    st: &WafState,
    row: &WafRow,
    host: &str,
) -> Result<Provisioned, ProvisionError> {
    if row.forwarding_provisioned_at.is_some() {
        return Err(ProvisionError::Forwarding(ForwardingError::new(
            "Event forwarding is already set up for this WAF — remove it first to change it.",
            409,
        )));
    }
    let me = st.client.request(row, Call::get("/users/me")).await?;
    let roles = get(&me, "roles")?.cloned().unwrap_or(PyValue::None);
    let mut names = Vec::new();
    if roles.truthy() {
        for r in iterate(&roles)? {
            if matches!(r, PyValue::Dict(_)) {
                match get(&r, "name")?.cloned().unwrap_or(PyValue::None) {
                    PyValue::Str(name) => names.push(name),
                    PyValue::List(_) | PyValue::Dict(_) => {
                        return Err(PyExc::TypeError("unhashable type".into()).into());
                    }
                    _ => names.push(String::new()),
                }
            }
        }
    }
    if !capabilities_for_roles(&names).can_manage_forwarders {
        return Err(ProvisionError::Forwarding(ForwardingError::new(
            "The WAF token's user can't create log forwarders (needs the WAF 'admin' role). Use \
             a token for an admin user, or set up the forwarder on the WAF by hand.",
            400,
        )));
    }
    let (low, high) =
        port_range(st.env.syslog_port_range.as_deref()).map_err(ProvisionError::Forwarding)?;
    let mut rollback = Rollback { steps: Vec::new() };
    let mut reused = Vec::new();
    let created = match create_objects(st, row, host, low, high, &mut rollback, &mut reused).await {
        Ok(c) => c,
        Err(e) if rolled_back(&e) => {
            let failures = rollback.run(st, row).await;
            let detail = match &e {
                ProvisionError::Forwarding(f) => f.detail.clone(),
                ProvisionError::Waf(w) => w.detail_or_str(),
            };
            tracing::error!(
                "WAF {}: event forwarding provisioning failed: {detail}",
                row.id
            );
            return Err(ProvisionError::Forwarding(match e {
                ProvisionError::Forwarding(mut f) => {
                    f.rollback_failures = failures;
                    f
                }
                ProvisionError::Waf(_) => ForwardingError {
                    detail: format!("Setting up event forwarding failed: {detail}"),
                    status: 502,
                    rollback_failures: failures,
                },
            }));
        }
        Err(e) => return Err(e),
    };
    let mut updated = row.clone();
    updated.syslog_host = Some(host.to_string());
    updated.syslog_port = i32::try_from(created.port).ok();
    updated.graylog_input_id = Some(id_text(&created.input_id));
    updated.graylog_stream_id = Some(id_text(&created.stream_id));
    updated.graylog_index_set_id = Some(id_text(&created.index_set_id));
    updated.waf_forwarder_id = Some(created.forwarder_id.clone());
    updated.forwarding_provisioned_at = Some(now_utc_micros());
    store::write_forwarding(&st.ctx.db, &updated)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
    let fresh = store::get(&st.ctx.db, i64::from(row.id))
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .ok_or_else(|| PyExc::Other("ObjectDeletedError", "row".into()))?;
    tracing::info!(
        "WAF {} ({}/{}): forwarding to {host}:{}, input {}, stream {}",
        fresh.id,
        fresh.customer_code,
        fresh.name,
        created.port,
        created.input_id.py_str(),
        created.stream_id.py_str()
    );
    let test = st
        .client
        .request(
            &fresh,
            Call::new(
                Method::POST,
                format!("/forwarders/{}/test", created.forwarder_id),
            )
            .timeout(30.0),
        )
        .await;
    let (test_success, test_message) = match test {
        Ok(t) => (
            Some(get(&t, "success")?.is_some_and(PyValue::truthy)),
            get(&t, "message")?.cloned().unwrap_or(PyValue::None),
        ),
        Err(WafError::Request { detail, .. }) => (Some(false), PyValue::Str(detail)),
        Err(other) => return Err(other.into()),
    };
    Ok(Provisioned {
        row: fresh,
        test_success,
        test_message,
        reused,
    })
}

/// `deprovision`: the warnings for anything that could not be removed.
pub async fn deprovision(st: &WafState, row: &WafRow) -> WafResult<(Vec<String>, WafRow)> {
    let mut warnings = Vec::new();
    if let Some(fid) = row.waf_forwarder_id.as_deref().filter(|f| !f.is_empty()) {
        match st
            .client
            .request(
                row,
                Call::new(Method::DELETE, format!("/forwarders/{fid}")).allow_disabled(),
            )
            .await
        {
            Ok(_) => {}
            Err(WafError::Request { reason, detail, .. }) => {
                if reason != "not_found" {
                    warnings.push(format!(
                        "Could not remove the forwarder on WAF '{}' ({detail}). Remove it in \
                         the WAF UI.",
                        row.name
                    ));
                }
            }
            Err(other) => return Err(other),
        }
    }
    if let Some(iid) = row.graylog_input_id.as_deref().filter(|i| !i.is_empty()) {
        match st
            .graylog
            .delete(&format!("/api/system/inputs/{iid}"), &[])
            .await
        {
            Ok(_) => {}
            Err(PyExc::Http(_, detail)) => {
                warnings.push(format!("Could not remove Graylog input {iid}: {detail}"));
            }
            Err(other) => return Err(other.into()),
        }
    }
    if let Some(sid) = row.graylog_stream_id.as_deref().filter(|s| !s.is_empty()) {
        let siblings = store::siblings_forwarding(&st.ctx.db, &row.customer_code, row.id)
            .await
            .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
        if !siblings {
            match st.graylog.delete(&format!("/api/streams/{sid}"), &[]).await {
                Ok(_) => {}
                Err(PyExc::Http(_, detail)) => {
                    warnings.push(format!("Could not remove Graylog stream {sid}: {detail}"));
                }
                Err(other) => return Err(other.into()),
            }
        }
    }
    let mut cleared = row.clone();
    cleared.syslog_host = None;
    cleared.syslog_port = None;
    cleared.graylog_input_id = None;
    cleared.graylog_stream_id = None;
    cleared.graylog_index_set_id = None;
    cleared.waf_forwarder_id = None;
    cleared.forwarding_provisioned_at = None;
    store::write_forwarding(&st.ctx.db, &cleared)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
    let fresh = store::get(&st.ctx.db, i64::from(row.id))
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .unwrap_or(cleared);
    Ok((warnings, fresh))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn port_ranges_like_python() {
        let v: Value = serde_json::from_str(include_str!("waf_vectors.json")).unwrap();
        for case in v["port_ranges"].as_array().unwrap() {
            let got = port_range(case["value"].as_str());
            match case.get("range") {
                Some(r) => {
                    let (lo, hi) = got.unwrap_or_else(|e| panic!("{case}: {e:?}"));
                    assert_eq!(Value::from(vec![lo, hi]), *r, "{case}");
                }
                None => {
                    let e = got.unwrap_err();
                    assert_eq!(e.detail, case["error"].as_str().unwrap(), "{case}");
                    assert_eq!(i64::from(e.status), case["status"].as_i64().unwrap());
                }
            }
        }
    }
}
