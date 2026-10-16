//! CoPilot alerts from SOCFortress WAF events (#1169, phase 4b) — port of
//! `app/customer_waf/services/alerts.py` and of the part of
//! `app/integrations/monitoring_alert/routes/provision.py` that reaches it.
//!
//! Two Monitoring Alerts catalog entries, provisioned once per Graylog (the
//! customer comes from each event's `syslog_customer`), both pinned to the
//! default Graylog connector (`PINNED_TO_DEFAULT_GRAYLOG`):
//!
//! - **SOCFORTRESS WAF BLOCKED**, per event: `syslog_type:waf AND
//!   waf_action:blocked` with `COPILOT_ALERT_ID=NONE`, for the collector.
//! - **SOCFORTRESS WAF BRUTE FORCE**, a threshold (`count() >= 30` per customer
//!   and client IP over 5 minutes) delivered by an HTTP notification to
//!   `/api/incidents/alerts/create/threshold` — `ALERT_FORWARDING_IP` and
//!   `GRAYLOG_API_HEADER_VALUE` are required before anything is created.
//!
//! Both register `waf` in the incident field-mapping tables (idempotent).
//! `POST /api/monitoring_alert/provision` is ported for these two alert names
//! only: the route reads the body, and any other alert goes to Python whole.

use copilot_auth::pyvalue::PyValue;
use copilot_graylog::client::{DEFAULT_CONNECTOR, EntityKind};
use copilot_incidents::requests::FieldAndAssetNames;
use copilot_upstream::model::{field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, get, getitem, iterate, py_eq};
use rand::RngCore;

use crate::forwarding::SYSLOG_TYPE;
use crate::services::WafState;

/// `BLOCKED_TITLE`.
pub const BLOCKED_TITLE: &str = "SOCFORTRESS WAF BLOCKED";
/// `BRUTE_FORCE_TITLE`.
pub const BRUTE_FORCE_TITLE: &str = "SOCFORTRESS WAF BRUTE FORCE";
/// `THRESHOLD_NOTIFICATION_TITLE`.
pub const THRESHOLD_NOTIFICATION_TITLE: &str = "SEND TO COPILOT - WAF THRESHOLD";
/// `THRESHOLD_ROUTE`.
pub const THRESHOLD_ROUTE: &str = "/api/incidents/alerts/create/threshold";
/// The alert names this port answers (`PINNED_TO_DEFAULT_GRAYLOG`).
pub const WAF_ALERTS: &[&str] = &["SOCFORTRESS_WAF_BLOCKED", "SOCFORTRESS_WAF_BRUTE_FORCE"];

const ALERT_FIELDS: &[&str] = &[
    "waf_rule_msg",
    "waf_action",
    "waf_client_ip",
    "waf_method",
    "waf_host",
    "waf_uri",
    "waf_rule_id",
    "waf_severity",
    "waf_anomaly_score",
    "waf_matched_rules",
    "waf_name",
    "waf_site_id",
    "waf_transaction_id",
];

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn n(v: i64) -> PyValue {
    PyValue::Int(v.to_string())
}

fn b(v: bool) -> PyValue {
    PyValue::Bool(v)
}

/// `ensure_waf_alert_source`: `waf` in the five field-mapping tables.
pub async fn ensure_waf_alert_source(st: &WafState) -> Result<(), copilot_web::ApiError> {
    copilot_incidents::dictionary::create(
        &st.ctx.db,
        &FieldAndAssetNames {
            field_names: ALERT_FIELDS.iter().map(|f| (*f).to_string()).collect(),
            asset_name: "waf_host".into(),
            timefield_name: "timestamp".into(),
            alert_title_name: "waf_rule_msg".into(),
            ioc_field_names: Some(vec!["waf_client_ip".into()]),
            source: SYSLOG_TYPE.into(),
        },
    )
    .await?;
    tracing::info!("WAF alert source 'waf' registered in the incident field-mapping tables");
    Ok(())
}

fn template(value: &str) -> PyValue {
    kwargs(vec![
        ("data_type", s("string")),
        (
            "providers",
            PyValue::List(vec![kwargs(vec![
                ("type", s("template-v1")),
                ("template", s(value)),
                ("require_values", b(true)),
            ])]),
        ),
    ])
}

fn query() -> PyValue {
    PyValue::Str(format!("syslog_type:{SYSLOG_TYPE} AND waf_action:blocked"))
}

/// `blocked_definition`.
pub fn blocked_definition(execute_every_ms: PyValue, search_within_ms: PyValue) -> PyValue {
    kwargs(vec![
        ("title", s(BLOCKED_TITLE)),
        (
            "description",
            s(
                "A SOCFortress WAF blocked a request. Creates (or adds to) a CoPilot alert per rule \
               and customer.",
            ),
        ),
        ("priority", n(2)),
        ("alert", b(true)),
        (
            "config",
            kwargs(vec![
                ("type", s("aggregation-v1")),
                ("query", query()),
                ("query_parameters", PyValue::List(Vec::new())),
                ("streams", PyValue::List(Vec::new())),
                ("group_by", PyValue::List(Vec::new())),
                ("series", PyValue::List(Vec::new())),
                ("conditions", kwargs(vec![("expression", PyValue::None)])),
                ("search_within_ms", search_within_ms),
                ("execute_every_ms", execute_every_ms),
                ("event_limit", n(1000)),
            ]),
        ),
        (
            "field_spec",
            kwargs(vec![
                ("ALERT_ID", template("${source._id}")),
                ("CUSTOMER_CODE", template("${source.syslog_customer}")),
                ("ALERT_SOURCE", template("SOCFORTRESS_WAF")),
                ("COPILOT_ALERT_ID", template("NONE")),
            ]),
        ),
        ("key_spec", PyValue::List(Vec::new())),
        (
            "notification_settings",
            kwargs(vec![
                ("grace_period_ms", n(0)),
                ("backlog_size", PyValue::None),
            ]),
        ),
        ("notifications", PyValue::List(Vec::new())),
    ])
}

/// `brute_force_definition`.
pub fn brute_force_definition(notification_id: PyValue) -> PyValue {
    let series = "waf-blocks-count";
    kwargs(vec![
        ("title", s(BRUTE_FORCE_TITLE)),
        (
            "description",
            s("30+ requests from one IP blocked by a customer's SOCFortress WAF within 5 minutes."),
        ),
        ("priority", n(3)),
        ("alert", b(true)),
        (
            "config",
            kwargs(vec![
                ("type", s("aggregation-v1")),
                ("query", query()),
                ("query_parameters", PyValue::List(Vec::new())),
                ("streams", PyValue::List(Vec::new())),
                (
                    "group_by",
                    PyValue::List(vec![s("syslog_customer"), s("waf_client_ip")]),
                ),
                (
                    "series",
                    PyValue::List(vec![kwargs(vec![
                        ("id", s(series)),
                        ("type", s("count")),
                        ("field", PyValue::None),
                    ])]),
                ),
                (
                    "conditions",
                    kwargs(vec![(
                        "expression",
                        kwargs(vec![
                            ("expr", s(">=")),
                            (
                                "left",
                                kwargs(vec![("expr", s("number-ref")), ("ref", s(series))]),
                            ),
                            (
                                "right",
                                kwargs(vec![("expr", s("number")), ("value", n(30))]),
                            ),
                        ]),
                    )]),
                ),
                ("search_within_ms", n(300_000)),
                ("execute_every_ms", n(60_000)),
                ("event_limit", n(1000)),
            ]),
        ),
        (
            "field_spec",
            kwargs(vec![
                ("CUSTOMER_CODE", template("${source.syslog_customer}")),
                ("SOURCE", template(SYSLOG_TYPE)),
                (
                    "ALERT_DESCRIPTION",
                    template("30+ blocked requests from ${source.waf_client_ip} in 5 minutes"),
                ),
                ("ASSET_NAME", template("${source.waf_client_ip}")),
            ]),
        ),
        ("key_spec", PyValue::List(Vec::new())),
        (
            "notification_settings",
            kwargs(vec![
                ("grace_period_ms", n(0)),
                ("backlog_size", PyValue::None),
            ]),
        ),
        (
            "notifications",
            PyValue::List(vec![kwargs(vec![
                ("notification_id", notification_id),
                ("notification_parameters", PyValue::None),
            ])]),
        ),
    ])
}

/// `threshold_webhook_url`.
pub fn threshold_webhook_url(st: &WafState) -> PyResult<String> {
    let host = copilot_web::form::py_strip(st.env.alert_forwarding_ip.as_deref().unwrap_or(""));
    if host.is_empty() || host == "0.0.0.0" {
        return Err(PyExc::http(
            400,
            format!(
                "ALERT_FORWARDING_IP is not set: Graylog needs CoPilot's address to deliver WAF \
                 brute-force alerts (it POSTs to http://<ALERT_FORWARDING_IP>:5000\
                 {THRESHOLD_ROUTE})."
            ),
        ));
    }
    Ok(format!("http://{host}:5000{THRESHOLD_ROUTE}"))
}

/// `threshold_header_value`.
pub fn threshold_header_value(st: &WafState) -> PyResult<String> {
    let value = copilot_web::form::py_strip(
        st.env
            .graylog_api_header_value
            .as_ref()
            .map(|s| s.expose())
            .unwrap_or(""),
    );
    if value.is_empty() {
        return Err(PyExc::http(
            400,
            "GRAYLOG_API_HEADER_VALUE is not set: the threshold route refuses unauthenticated \
             Graylog webhooks.",
        ));
    }
    Ok(value.to_string())
}

/// `notification_payload`.
pub fn notification_payload(url: &str, header_value: &str) -> PyValue {
    kwargs(vec![
        ("title", s(THRESHOLD_NOTIFICATION_TITLE)),
        (
            "description",
            s("Delivers threshold alerts (e.g. WAF brute force) to CoPilot's threshold route"),
        ),
        (
            "config",
            kwargs(vec![
                ("type", s("http-notification-v1")),
                ("url", s(url)),
                ("api_key_as_header", b(true)),
                ("api_key", s("graylog")),
                ("api_secret", kwargs(vec![("set_value", s(header_value))])),
                ("skip_tls_verification", b(false)),
            ]),
        ),
    ])
}

/// `secrets.token_hex(12)`.
fn token_hex() -> String {
    let mut bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// `_ensure_url_allowlisted`: the 7.x path, else the 6.x one.
async fn ensure_url_allowlisted(st: &WafState, url: &str) -> PyResult<()> {
    let (endpoint, current) = match st.graylog.get("/api/system/urlallowlist", &[]).await {
        Ok(r) => ("/api/system/urlallowlist", r.data),
        Err(e) if e.is_http() => (
            "/api/system/urlwhitelist",
            st.graylog.get("/api/system/urlwhitelist", &[]).await?.data,
        ),
        Err(e) => return Err(e),
    };
    let mut entries = match get(&current, "entries")? {
        Some(v) => iterate(v)?,
        None => Vec::new(),
    };
    let disabled = get(&current, "disabled")?.is_some_and(PyValue::truthy);
    if disabled {
        return Ok(());
    }
    for e in &entries {
        let literal = get(e, "type")?.is_some_and(|t| py_eq(t, &s("literal")));
        if literal && get(e, "value")?.is_some_and(|v| py_eq(v, &s(url))) {
            return Ok(());
        }
    }
    entries.push(kwargs(vec![
        ("id", PyValue::Str(token_hex())),
        (
            "title",
            PyValue::Str(format!(
                "\"{THRESHOLD_NOTIFICATION_TITLE}\" alert notification"
            )),
        ),
        ("type", s("literal")),
        ("value", s(url)),
    ]));
    st.graylog
        .put(
            endpoint,
            Some(kwargs(vec![
                ("entries", PyValue::List(entries)),
                ("disabled", b(disabled)),
            ])),
        )
        .await?;
    tracing::info!("Added {url} to Graylog's URL allowlist");
    Ok(())
}

/// `ensure_threshold_notification`: the existing notification's id, or a
/// new one's.
pub async fn ensure_threshold_notification(st: &WafState) -> PyResult<PyValue> {
    let url = threshold_webhook_url(st)?;
    let header_value = threshold_header_value(st)?;
    let data = st
        .graylog
        .get(
            "/api/events/notifications",
            &[("per_page", "500".to_string())],
        )
        .await?
        .data;
    let list = get(&data, "notifications")?
        .cloned()
        .unwrap_or(PyValue::List(Vec::new()));
    for item in iterate(&list)? {
        if get(&item, "title")?.is_some_and(|t| py_eq(t, &s(THRESHOLD_NOTIFICATION_TITLE))) {
            let id = getitem(&item, "id")?.clone();
            if id.truthy() {
                return Ok(id);
            }
            break;
        }
    }
    ensure_url_allowlisted(st, &url).await?;
    let created = st
        .graylog
        .create_entity(
            DEFAULT_CONNECTOR,
            &EntityKind::EventNotification,
            notification_payload(&url, &header_value),
            None,
        )
        .await?;
    Ok(getitem(&created.data, "id")?.clone())
}

/// `check_if_event_definition_exists`: 400 when the title is taken.
pub async fn check_event_definition(st: &WafState, title: &str) -> PyResult<()> {
    let dump = copilot_graylog::services::event_definitions(&st.graylog).await?;
    if let PyValue::List(defs) = field(&dump, "event_definitions") {
        if defs
            .iter()
            .any(|d| field(d, "title").as_str() == Some(title))
        {
            return Err(PyExc::http(
                400,
                format!("Event definition {title} already exists"),
            ));
        }
    }
    Ok(())
}

/// What the provision functions can raise.
#[derive(Debug)]
pub enum AlertError {
    /// A Python exception.
    Py(PyExc),
    /// A database failure.
    Api(copilot_web::ApiError),
}

impl From<PyExc> for AlertError {
    fn from(e: PyExc) -> Self {
        Self::Py(e)
    }
}

impl From<copilot_web::ApiError> for AlertError {
    fn from(e: copilot_web::ApiError) -> Self {
        Self::Api(e)
    }
}

/// `provision_blocked_alert`.
pub async fn provision_blocked_alert(
    st: &WafState,
    execute_every_seconds: i128,
    search_within_seconds: i128,
) -> Result<(), AlertError> {
    ensure_waf_alert_source(st).await?;
    st.graylog
        .create_entity(
            DEFAULT_CONNECTOR,
            &EntityKind::EventDefinition,
            blocked_definition(
                PyValue::Int((execute_every_seconds * 1000).to_string()),
                PyValue::Int((search_within_seconds * 1000).to_string()),
            ),
            None,
        )
        .await?;
    tracing::info!("Provisioned Graylog event definition {BLOCKED_TITLE}");
    Ok(())
}

/// `provision_brute_force_alert`.
pub async fn provision_brute_force_alert(st: &WafState) -> Result<(), AlertError> {
    let notification_id = ensure_threshold_notification(st).await?;
    ensure_waf_alert_source(st).await?;
    st.graylog
        .create_entity(
            DEFAULT_CONNECTOR,
            &EntityKind::EventDefinition,
            brute_force_definition(notification_id.clone()),
            None,
        )
        .await?;
    tracing::info!(
        "Provisioned Graylog event definition {BRUTE_FORCE_TITLE} (notification {})",
        notification_id.py_str()
    );
    Ok(())
}
