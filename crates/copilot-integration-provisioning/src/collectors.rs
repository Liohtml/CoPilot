//! The CrowdStrike, Defender for Endpoint and Bitdefender `POST /provision`
//! routes — `app/integrations/{crowdstrike,defender_for_endpoint,
//! bitdefender}/{routes,services,schema}/provision.py`, which differ only in
//! data ([`COLLECTORS`]): each sets up the Graylog side of a collector that
//! runs next to the stack, and writes that collector's docker-compose file
//! and configuration under the Python backend's `data/` directory.
//!
//! Python's order, on the default `Graylog` connector:
//!
//! 1. the customer's integrations (404 without any), the one holding the
//!    service (an `AttributeError` when none does), its keys (404 without
//!    any), the keys' model (Pydantic's 400), `int()` of the port (the
//!    `ValueError` 400), the customer details' model (the 400 a `null`
//!    retention or replica count ends in);
//! 2. the customer's Grafana organization (404 without a meta row);
//! 3. the content packs (rendered, inserted, installed), the stream they
//!    created, a new index set, the packs' ids, the input, the processing
//!    pipeline (CrowdStrike; the two others store a fixed text);
//! 4. the stream moved to the index set — and, for CrowdStrike, connected to
//!    its pipeline;
//! 5. the Grafana datasource, folder and dashboards, the
//!    `customer_network_connectors_meta` row;
//! 6. the files: `<data>/<customer name>/` created when missing, the
//!    docker-compose file and the collector's configuration (`cs.falconhose
//!    client.cfg`, `filebeat.yml` and a `data/` directory, `config.json`);
//! 7. `deployed`; Bitdefender then pushes its settings to GravityZone and
//!    answers whatever JSON came back as success.
//!
//! The customer's name has its spaces replaced by `_` before step 2 and
//! names the directory. Nothing is rolled back, as in Python.
//!
//! Two deliberate differences (§4): the body's `customer_code` must be one of
//! the caller's customers (403), and a customer name holding a `/` or a NUL,
//! or `..`, is refused with a 400 before anything is created — Python
//! provisioned Graylog and Grafana, then failed writing the docker-compose
//! file (whose name holds the customer's), or wrote outside the data
//! directory.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use copilot_auth::pyvalue::PyValue;
use copilot_core::cloud_env::CloudEnv;
use copilot_grafana_dashboards::templates::{self as dashboards, DashboardClass};
use copilot_graylog::client::DEFAULT_CONNECTOR;
use copilot_integrations::integrations::store::CustomerIntegration;
use copilot_threat_intel::httpx;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::model::{Field, Model, Ty, construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, int_of};
use copilot_web::AppContext;

use crate::grafana::{self, Datasource};
use crate::graylog::{self, IndexSet, Keywords};
use crate::integrations::{integrations_of, set_deployed};
use crate::network::{Tools, provision_dashboards};
use crate::store::{self, NetworkMeta};

/// Where the meta row's `graylog_pipeline_id` comes from.
#[derive(Debug, Clone, Copy)]
pub enum Pipeline {
    /// `get_pipeline_id(subscription)[0]`, and the stream connected to it.
    Subscription(&'static str),
    /// A fixed text; the stream is connected to nothing.
    Fixed(&'static str),
}

/// Which of the meta row's folder fields Grafana's answer fills.
#[derive(Debug, Clone, Copy)]
pub enum FolderField {
    /// `grafana_folder.uid`.
    Uid,
    /// `grafana_folder.id`.
    Id,
}

/// The collector's files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Files {
    /// `<name>_docker-compose.yml` and `cs.falconhoseclient.cfg`.
    CrowdStrike,
    /// `<name>_docker-compose-defender-for-endpoint.yml`, `filebeat.yml` and
    /// the `data/` directory.
    Defender,
    /// `<name>_bitdefender_docker-compose.yml` and `config.json`.
    Bitdefender,
}

/// What one collector's provisioning varies.
#[derive(Debug)]
pub struct Collector {
    /// The router's prefix (`/api/<route>/provision`).
    pub route: &'static str,
    /// The service: the forced `integration_name`, the subscription's
    /// service and the `deployed` row's.
    pub service: &'static str,
    /// The name in the missing-keys 404.
    pub label: &'static str,
    /// The request model.
    pub request: &'static Model,
    /// The auth keys' model.
    pub auth_keys: &'static Model,
    /// The customer details' model.
    pub details: &'static Model,
    /// The key whose `int()` is the syslog port.
    pub port_key: &'static str,
    /// `protocal_type`.
    pub protocol: &'static str,
    /// The content packs' tag.
    pub tag: &'static str,
    /// `index_prefix`'s head (`<prefix>-<code>`), and the datasource's
    /// database's.
    pub prefix: &'static str,
    /// The index set's title and description after `<customer> - `.
    pub index_title: &'static str,
    /// The stream's title after `<customer> - `.
    pub stream_title: &'static str,
    /// The input's title after `<customer> - `.
    pub input_title: &'static str,
    /// The meta row's pipeline.
    pub pipeline: Pipeline,
    /// The meta row's `network_connector_name`.
    pub meta_name: &'static str,
    /// The datasource's name and the folder's title.
    pub grafana_name: &'static str,
    /// The meta row's folder field.
    pub folder_field: FolderField,
    /// The dashboards provisioned.
    pub dashboards: &'static DashboardClass,
    /// The files written.
    pub files: Files,
    /// The success message.
    pub message: &'static str,
}

fn thirty() -> PyValue {
    PyValue::Int("30".into())
}

fn zero() -> PyValue {
    PyValue::Int("0".into())
}

macro_rules! forced {
    ($fname:ident, $value:expr) => {
        fn $fname() -> PyValue {
            PyValue::Str($value.into())
        }
    };
}

forced!(crowdstrike, "Crowdstrike");
forced!(defender, "DefenderForEndpoint");
forced!(bitdefender, "Bitdefender");

/// `ProvisionCrowdstrikeRequest`.
pub static PROVISION_CROWDSTRIKE_REQUEST: Model = Model::new(
    "ProvisionCrowdstrikeRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, crowdstrike),
        Field::def("hot_data_retention", Ty::Nullable(&Ty::Int), thirty),
        Field::def("index_replicas", Ty::Nullable(&Ty::Int), zero),
    ],
);

/// `ProvisionDefenderForEndpointRequest`.
pub static PROVISION_DEFENDER_FOR_ENDPOINT_REQUEST: Model = Model::new(
    "ProvisionDefenderForEndpointRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, defender),
        Field::def("hot_data_retention", Ty::Nullable(&Ty::Int), thirty),
        Field::def("index_replicas", Ty::Nullable(&Ty::Int), zero),
    ],
);

/// `ProvisionBitdefenderRequest` (its field default is `Bitdefender`, its
/// validator forces `BitDefender`).
pub static PROVISION_BITDEFENDER_REQUEST: Model = Model::new(
    "ProvisionBitdefenderRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, bitdefender),
        Field::def("hot_data_retention", Ty::Nullable(&Ty::Int), thirty),
        Field::def("index_replicas", Ty::Nullable(&Ty::Int), zero),
    ],
);

/// `ProvisionCrowdstrikeAuthKeys`.
pub static PROVISION_CROWDSTRIKE_AUTH_KEYS: Model = Model::new(
    "ProvisionCrowdstrikeAuthKeys",
    &[
        Field::req("CLIENT_ID", Ty::Str),
        Field::req("CLIENT_SECRET", Ty::Str),
        Field::req("BASE_URL", Ty::Str),
        Field::req("SYSLOG_PORT", Ty::Str),
    ],
);

/// `ProvisionDefenderForEndpointAuthKeys`.
pub static PROVISION_DEFENDER_FOR_ENDPOINT_AUTH_KEYS: Model = Model::new(
    "ProvisionDefenderForEndpointAuthKeys",
    &[
        Field::req("CLIENT_ID", Ty::Str),
        Field::req("CLIENT_SECRET", Ty::Str),
        Field::req("TENANT_ID", Ty::Str),
        Field::req("SYSLOG_PORT", Ty::Str),
    ],
);

/// `ProvisionBitdefenderAuthKeys`.
pub static PROVISION_BITDEFENDER_AUTH_KEYS: Model = Model::new(
    "ProvisionBitdefenderAuthKeys",
    &[
        Field::req("BASIC_AUTH_USERNAME", Ty::Str),
        Field::req("BASIC_AUTH_PASSWORD", Ty::Str),
        Field::req("WEBSERVER_HOSTNAME", Ty::Str),
        Field::req("WEBSERVER_PORT", Ty::Str),
        Field::req("GRAYLOG_PORT", Ty::Str),
        Field::req("API_KEY", Ty::Str),
    ],
);

macro_rules! details {
    ($name:ident, $title:expr) => {
        #[doc = concat!("`", $title, "`.")]
        pub static $name: Model = Model::new(
            $title,
            &[
                Field::req("customer_name", Ty::Str),
                Field::req("customer_code", Ty::Str),
                Field::req("protocal_type", Ty::Str),
                Field::req("syslog_port", Ty::Int),
                Field::req("hot_data_retention", Ty::Int),
                Field::req("index_replicas", Ty::Int),
            ],
        );
    };
}

details!(CROWDSTRIKE_CUSTOMER_DETAILS, "CrowdstrikeCustomerDetails");
details!(
    DEFENDER_FOR_ENDPOINT_CUSTOMER_DETAILS,
    "DefenderForEndpointCustomerDetails"
);
details!(BITDEFENDER_CUSTOMER_DETAILS, "BitdefenderCustomerDetails");

/// CrowdStrike, Defender for Endpoint, Bitdefender.
pub static COLLECTORS: &[Collector] = &[
    Collector {
        route: "crowdstrike",
        service: "Crowdstrike",
        label: "Crowdstrike",
        request: &PROVISION_CROWDSTRIKE_REQUEST,
        auth_keys: &PROVISION_CROWDSTRIKE_AUTH_KEYS,
        details: &CROWDSTRIKE_CUSTOMER_DETAILS,
        port_key: "SYSLOG_PORT",
        protocol: "TCP",
        tag: "CROWDSTRIKE",
        prefix: "crowdstrike",
        index_title: "CROWDSTRIKE EVENTS",
        stream_title: "CROWDSTRIKE LOGS AND EVENTS",
        input_title: "CROWDSTRIKE LOGS AND EVENTS",
        pipeline: Pipeline::Subscription("CROWDSTRIKE"),
        meta_name: "CROWDSTRIKE",
        grafana_name: "CROWDSTRIKE",
        folder_field: FolderField::Uid,
        dashboards: &dashboards::CROWDSTRIKE,
        files: Files::CrowdStrike,
        message: "Crowdstrike customer provisioned successfully",
    },
    Collector {
        route: "defender_for_endpoint",
        service: "DefenderForEndpoint",
        label: "defender_for_endpoint",
        request: &PROVISION_DEFENDER_FOR_ENDPOINT_REQUEST,
        auth_keys: &PROVISION_DEFENDER_FOR_ENDPOINT_AUTH_KEYS,
        details: &DEFENDER_FOR_ENDPOINT_CUSTOMER_DETAILS,
        port_key: "SYSLOG_PORT",
        protocol: "TCP",
        tag: "DEFENDER_FOR_ENDPOINT",
        prefix: "defender-for-endpoint",
        index_title: "DEFENDER FOR ENDPOINT EVENTS",
        stream_title: "DEFENDER FOR ENDPOINT LOGS AND EVENTS",
        input_title: "DEFENDER FOR ENDPOINT",
        pipeline: Pipeline::Fixed("not_set"),
        meta_name: "DefenderForEndpoint",
        grafana_name: "DEFENDER FOR ENDPOINT",
        folder_field: FolderField::Id,
        dashboards: &dashboards::DEFENDER_FOR_ENDPOINT,
        files: Files::Defender,
        message: "Defender For Endpoint for customer provisioned successfully",
    },
    Collector {
        route: "bitdefender",
        service: "BitDefender",
        label: "Bitdefender",
        request: &PROVISION_BITDEFENDER_REQUEST,
        auth_keys: &PROVISION_BITDEFENDER_AUTH_KEYS,
        details: &BITDEFENDER_CUSTOMER_DETAILS,
        port_key: "GRAYLOG_PORT",
        protocol: "Tcp",
        tag: "BITDEFENDER",
        prefix: "bitdefender",
        index_title: "BITDEFENDER EVENTS",
        stream_title: "BITDEFENDER LOGS AND EVENTS",
        input_title: "BITDEFENDER LOGS AND EVENTS",
        pipeline: Pipeline::Fixed("NONE"),
        meta_name: "BITDEFENDER",
        grafana_name: "BITDEFENDER",
        folder_field: FolderField::Uid,
        dashboards: &dashboards::BITDEFENDER,
        files: Files::Bitdefender,
        message: "Bitdefender customer provisioned successfully",
    },
];

// --- the templates ---------------------------------------------------------------

/// `crowdstrike/templates/docker-compose.yml`, from the backend's tree.
pub const CROWDSTRIKE_COMPOSE: &str =
    include_str!("../../../backend/app/integrations/crowdstrike/templates/docker-compose.yml");
/// `crowdstrike/templates/cs.falconhoseclient.cfg`.
pub const CROWDSTRIKE_CFG: &str =
    include_str!("../../../backend/app/integrations/crowdstrike/templates/cs.falconhoseclient.cfg");
/// `defender_for_endpoint/templates/docker-compose.yml`.
pub const DEFENDER_COMPOSE: &str = include_str!(
    "../../../backend/app/integrations/defender_for_endpoint/templates/docker-compose.yml"
);
/// `defender_for_endpoint/templates/filebeat.yml`.
pub const DEFENDER_FILEBEAT: &str =
    include_str!("../../../backend/app/integrations/defender_for_endpoint/templates/filebeat.yml");
/// `bitdefender/templates/docker-compose.yml`.
pub const BITDEFENDER_COMPOSE: &str =
    include_str!("../../../backend/app/integrations/bitdefender/templates/docker-compose.yml");

/// GravityZone's push-settings endpoint, its host replaceable for the tests.
pub const GRAVITYZONE_URL: &str = "https://cloud.gravityzone.bitdefender.com";

/// The event types Bitdefender's push subscribes to, in Python's order.
pub const GRAVITYZONE_EVENT_TYPES: &[&str] = &[
    "adcloudgz",
    "antiexploit",
    "aph",
    "av",
    "avc",
    "dp",
    "endpoint-moved-in",
    "endpoint-moved-out",
    "exchange-malware",
    "exchange-user-credentials",
    "fw",
    "hd",
    "hwid-change",
    "install",
    "modules",
    "network-monitor",
    "network-sandboxing",
    "new-incident",
    "ransomware-mitigation",
    "registration",
    "supa-update-status",
    "sva",
    "sva-load",
    "task-status",
    "troubleshooting-activity",
    "uc",
    "uninstall",
];

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn text(dump: &PyValue, key: &str) -> String {
    field(dump, key).py_str()
}

// --- the renderings (pure; pinned by the vectors) ----------------------------------

/// The file name of the docker-compose file.
pub fn compose_file_name(files: Files, name: &str) -> String {
    match files {
        Files::CrowdStrike => format!("{name}_docker-compose.yml"),
        Files::Defender => format!("{name}_docker-compose-defender-for-endpoint.yml"),
        Files::Bitdefender => format!("{name}_bitdefender_docker-compose.yml"),
    }
}

/// `load_and_replace_docker_compose(customer_name[, port])`.
pub fn render_compose(files: Files, name: &str, keys: &PyValue) -> String {
    match files {
        Files::CrowdStrike => CROWDSTRIKE_COMPOSE.replace("CUSTOMER_NAME", name),
        Files::Defender => DEFENDER_COMPOSE.replace("CUSTOMER_NAME", name),
        Files::Bitdefender => BITDEFENDER_COMPOSE
            .replace("CUSTOMER_NAME", name)
            .replace("PORT", &text(keys, "WEBSERVER_PORT")),
    }
}

/// `str(<connector 3's url>)` with `https://`, `http://` and `:9000` taken
/// out (`None` when there is no such row).
pub fn syslog_host(url: Option<&str>) -> String {
    url.unwrap_or("None")
        .replace("https://", "")
        .replace("http://", "")
        .replace(":9000", "")
}

/// `cs.falconhoseclient.cfg` with the keys and the syslog target replaced
/// in Python's order.
pub fn render_falconhose_cfg(keys: &PyValue, host: &str) -> String {
    CROWDSTRIKE_CFG
        .replace("REPLACE_BASE_URL", &text(keys, "BASE_URL"))
        .replace("REPLACE_CLIENT_ID", &text(keys, "CLIENT_ID"))
        .replace("REPLACE_CLIENT_SECRET", &text(keys, "CLIENT_SECRET"))
        .replace("REPLACE_SYSLOG_HOST", host)
        .replace("REPLACE_SYSLOG_PORT", &text(keys, "SYSLOG_PORT"))
}

/// `filebeat.yml` with the keys and the syslog target replaced in Python's
/// order.
pub fn render_filebeat(keys: &PyValue, host: &str) -> String {
    DEFENDER_FILEBEAT
        .replace("REPLACE_TENANT_ID", &text(keys, "TENANT_ID"))
        .replace("REPLACE_CLIENT_ID", &text(keys, "CLIENT_ID"))
        .replace("REPLACE_CLIENT_SECRET", &text(keys, "CLIENT_SECRET"))
        .replace("REPLACE_SYSLOG_HOST", host)
        .replace("REPLACE_SYSLOG_PORT", &text(keys, "SYSLOG_PORT"))
}

/// `base64_auth_header_generator(username, password)`.
pub fn basic_auth(user: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

/// `json.dumps(data, indent=4)` of Bitdefender's `config.json`: `int()` of
/// the two ports (the webserver's `ValueError` raised here, after the
/// docker-compose file was written).
pub fn render_config_json(keys: &PyValue, protocol: &str, host: &str) -> PyResult<String> {
    let port = int_of(field(keys, "WEBSERVER_PORT"))?;
    let syslog_port = int_of(field(keys, "GRAYLOG_PORT"))?;
    let auth = basic_auth(
        &text(keys, "BASIC_AUTH_USERNAME"),
        &text(keys, "BASIC_AUTH_PASSWORD"),
    );
    let quote = |v: &str| py_dumps(&s(v), Dumps::DEFAULT).unwrap_or_default();
    Ok(format!(
        "{{\n    \"port\": {port},\n    \"syslog_port\": {syslog_port},\n    \"transport\": \
         {},\n    \"target\": {},\n    \"authentication_string\": {},\n    \"secure\": {{\n        \
         \"enabled\": true,\n        \"key\": \"api/config/server.key\",\n        \"cert\": \
         \"api/config/server.crt\"\n    }}\n}}",
        quote(protocol),
        quote(host),
        quote(&auth)
    ))
}

/// The GravityZone call's `authorization` header: `Basic` over `<key>:`.
pub fn gravityzone_authorization(api_key: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{api_key}:"))
    )
}

/// `send_configuration_to_bitdefender`'s `json=` body.
pub fn gravityzone_body(keys: &PyValue) -> PyValue {
    let events = PyValue::Dict(
        GRAVITYZONE_EVENT_TYPES
            .iter()
            .map(|t| ((*t).to_string(), PyValue::Bool(true)))
            .collect(),
    );
    kwargs(vec![
        ("id", s("1")),
        ("jsonrpc", s("2.0")),
        ("method", s("setPushEventSettings")),
        (
            "params",
            kwargs(vec![
                (
                    "serviceSettings",
                    kwargs(vec![
                        ("requireValidSslCertificate", PyValue::Bool(false)),
                        (
                            "authorization",
                            s(&basic_auth(
                                &text(keys, "BASIC_AUTH_USERNAME"),
                                &text(keys, "BASIC_AUTH_PASSWORD"),
                            )),
                        ),
                        (
                            "url",
                            s(&format!(
                                "https://{}:{}/api",
                                text(keys, "WEBSERVER_HOSTNAME"),
                                text(keys, "WEBSERVER_PORT")
                            )),
                        ),
                    ]),
                ),
                ("serviceType", s("cef")),
                ("status", PyValue::Int("1".into())),
                ("subscribeToEventTypes", events),
            ]),
        ),
    ])
}

/// Whether `name` (spaces already replaced) can name the collector's
/// directory and prefix its file names: no `/` (Python's file name then
/// names a directory that does not exist — or, for an absolute or `..` path,
/// one outside the data directory), not `..`, no NUL.
pub fn safe_directory_name(name: &str) -> bool {
    !name.contains('/') && !name.contains('\0') && name != ".."
}

// --- the flow ------------------------------------------------------------------------

fn os_error(e: &std::io::Error) -> PyExc {
    PyExc::Other("OSError", e.to_string())
}

/// `os.path.exists(path)` then `os.makedirs(path)` when it is not.
fn make_directory_if_missing(path: &Path) -> PyResult<()> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| os_error(&e))?;
    }
    Ok(())
}

/// One file written whole (`open(…, "w"/"wb")`, UTF-8).
fn write_file(path: &Path, data: &str) -> PyResult<()> {
    std::fs::write(path, data.as_bytes()).map_err(|e| os_error(&e))
}

/// The customer's integration holding `collector`'s service and its keys in
/// dict order (`get_customer_integration_response`,
/// `find_customer_integration`, `extract_<x>_auth_keys`).
async fn integration_and_keys(
    ctx: &AppContext,
    collector: &Collector,
    code: &str,
) -> PyResult<(CustomerIntegration, Vec<(String, PyValue)>)> {
    let list = integrations_of(ctx, code).await?;
    let serves = |ci: &CustomerIntegration| {
        ci.subscriptions.iter().any(|sub| {
            sub.service
                .as_ref()
                .is_some_and(|v| v.service_name == collector.service)
        })
    };
    let Some(found) = list.into_iter().find(serves) else {
        return Err(PyExc::AttributeError(
            "'NoneType' object has no attribute 'integration_subscriptions'".into(),
        ));
    };
    let mut keys: Vec<(String, PyValue)> = Vec::new();
    for sub in &found.subscriptions {
        if sub
            .service
            .as_ref()
            .is_some_and(|v| v.service_name == collector.service)
        {
            for k in &sub.keys {
                match keys.iter_mut().find(|(name, _)| *name == k.auth_key_name) {
                    Some(slot) => slot.1 = s(&k.auth_value),
                    None => keys.push((k.auth_key_name.clone(), s(&k.auth_value))),
                }
            }
        }
    }
    if keys.is_empty() {
        return Err(PyExc::http(
            404,
            format!(
                "No auth keys found for {label} integration. Please create auth keys for {label} \
                 integration.",
                label = collector.label
            ),
        ));
    }
    Ok((found, keys))
}

/// The route's work once the body is read and its customer checked against
/// the caller: the response dump.
pub async fn provision(
    ctx: &AppContext,
    tools: Tools<'_>,
    env: &CloudEnv,
    collector: &Collector,
    request: &PyValue,
) -> PyResult<PyValue> {
    let code = text(request, "customer_code");
    let (integration, keys) = integration_and_keys(ctx, collector, &code).await?;
    let keys = construct(collector.auth_keys, &PyValue::Dict(keys))?;
    let syslog_port = int_of(field(&keys, collector.port_key))?;
    let details = construct(
        collector.details,
        &kwargs(vec![
            ("customer_code", s(&code)),
            ("customer_name", s(&integration.customer_name)),
            ("protocal_type", s(collector.protocol)),
            ("syslog_port", PyValue::Int(syslog_port)),
            (
                "hot_data_retention",
                field(request, "hot_data_retention").clone(),
            ),
            ("index_replicas", field(request, "index_replicas").clone()),
        ]),
    )?;
    let name = text(&details, "customer_name").replace(' ', "_");
    if !safe_directory_name(&name) {
        return Err(PyExc::http(
            400,
            format!(
                "Customer name '{name}' cannot name a directory under the backend's data \
                 directory."
            ),
        ));
    }
    provision_collector(ctx, tools, env, collector, &details, &name, &keys).await?;
    Ok(kwargs(vec![
        ("success", PyValue::Bool(true)),
        ("message", s(collector.message)),
    ]))
}

/// `provision_<x>(customer_details, keys, session)`.
async fn provision_collector(
    ctx: &AppContext,
    tools: Tools<'_>,
    env: &CloudEnv,
    collector: &Collector,
    details: &PyValue,
    name: &str,
    keys: &PyValue,
) -> PyResult<()> {
    let (db, gl, conn) = (tools.db, tools.graylog, DEFAULT_CONNECTOR);
    let code = text(details, "customer_code");
    if store::grafana_org_attribute(db, &code).await?.is_none() {
        return Err(PyExc::http(
            404,
            "Grafana organization ID not found. Please provision Grafana for the customer first.",
        ));
    }
    let keywords = Keywords {
        customer_name: name.to_string(),
        customer_code: code.clone(),
        protocol_type: Some(collector.protocol),
        syslog_port: text(details, "syslog_port"),
        tls_cert_file: None,
        tls_key_file: None,
    };
    graylog::provision_network_content_packs(gl, conn, collector.tag, &keywords).await?;

    // `get_stream_and_index_ids`.
    let stream_id =
        graylog::stream_id_by_name(gl, conn, &format!("{name} - {}", collector.stream_title))
            .await?;
    let creation_date = graylog::creation_date();
    let shards = grafana::shard_number(tools.wazuh).await?;
    let index_set = graylog::index_set_config(&IndexSet {
        title: format!("{name} - {}", collector.index_title),
        description: format!("{name} - {}", collector.index_title),
        index_prefix: format!("{}-{code}", collector.prefix),
        max_indices: field(details, "hot_data_retention").clone(),
        shards,
        replicas: field(details, "index_replicas").clone(),
        creation_date,
    })?;
    let index_id = graylog::create_index_set(gl, conn, index_set).await?;
    let pack_stream_id =
        graylog::content_pack_id_by_name(gl, conn, &format!("{name}_{}_STREAM", collector.tag))
            .await?;
    // `protocal_type` is always the TCP branch's ("TCP", or Bitdefender's
    // "Tcp").
    let pack_input_id =
        graylog::content_pack_id_by_name(gl, conn, &format!("{name}_{}_INPUT_TCP", collector.tag))
            .await?;

    // `create_customer_network_connector_meta`.
    let input_id =
        graylog::input_id_by_name(gl, conn, &format!("{name} - {}", collector.input_title)).await?;
    let pipeline_id = match collector.pipeline {
        Pipeline::Subscription(subscription) => {
            match graylog::pipeline_id(gl, conn, subscription).await? {
                PyValue::List(ids) => ids.first().cloned().unwrap_or(PyValue::None),
                _ => PyValue::None,
            }
        }
        Pipeline::Fixed(value) => s(value),
    };
    let org_attribute = store::grafana_org_attribute(db, &code).await?;
    let mut meta = NetworkMeta {
        customer_code: code.clone(),
        network_connector_name: collector.meta_name,
        graylog_stream_id: stream_id.clone(),
        graylog_input_id: input_id,
        graylog_pipeline_id: pipeline_id,
        graylog_content_pack_input_id: pack_input_id,
        graylog_content_pack_stream_id: pack_stream_id,
        grafana_org_id: org_attribute,
        graylog_index_id: index_id.clone(),
        grafana_dashboard_folder_id: PyValue::None,
        grafana_datasource_uid: PyValue::None,
    };
    graylog::assign_stream_to_index(gl, conn, &stream_id, &index_id).await?;
    if let Pipeline::Subscription(subscription) = collector.pipeline {
        let pipeline_ids = graylog::pipeline_id(gl, conn, subscription).await?;
        graylog::connect_stream_to_pipeline(gl, conn, &stream_id, &pipeline_ids).await?;
    }

    // Grafana.
    let datasource_uid = grafana::create_datasource(
        db,
        tools.grafana,
        tools.wazuh,
        &code,
        &Datasource {
            name: collector.grafana_name.to_string(),
            database: format!("{}-{code}*", collector.prefix),
            log_level_field: "severity",
            log_message_field: "summary",
            data_links: None,
        },
    )
    .await?;
    meta.grafana_datasource_uid = datasource_uid.clone();
    let org = store::grafana_org_id(db, &code).await?;
    let folder = grafana::create_folder(tools.grafana, &org, collector.grafana_name).await?;
    provision_dashboards(tools, collector.dashboards, &code, &folder, &datasource_uid).await?;
    meta.grafana_dashboard_folder_id = match collector.folder_field {
        FolderField::Uid => field(&folder, "uid").clone(),
        FolderField::Id => field(&folder, "id").clone(),
    };
    store::insert_network_meta(db, &meta).await?;

    write_files(tools, env, collector, name, keys).await?;
    set_deployed(ctx, &code, collector.service).await?;
    if collector.files == Files::Bitdefender {
        send_configuration_to_bitdefender(env, keys).await?;
    }
    Ok(())
}

/// The collector's directory and files, in Python's order (connector id 3,
/// the syslog target, read between the two files).
async fn write_files(
    tools: Tools<'_>,
    env: &CloudEnv,
    collector: &Collector,
    name: &str,
    keys: &PyValue,
) -> PyResult<()> {
    let folder: PathBuf = Path::new(env.backend_data_dir()).join(name);
    write_compose(&folder, collector.files, name, keys)?;
    let url = store::connector_by_id(tools.db, 3)
        .await?
        .map(|row| row.connector_url);
    write_config(&folder, collector, keys, &syslog_host(url.as_deref()))
}

/// The directory (and Defender's `data/`), then the docker-compose file.
pub fn write_compose(folder: &Path, files: Files, name: &str, keys: &PyValue) -> PyResult<()> {
    make_directory_if_missing(folder)?;
    if files == Files::Defender {
        make_directory_if_missing(&folder.join("data"))?;
    }
    write_file(
        &folder.join(compose_file_name(files, name)),
        &render_compose(files, name, keys),
    )
}

/// The collector's configuration, its syslog target `host`.
pub fn write_config(
    folder: &Path,
    collector: &Collector,
    keys: &PyValue,
    host: &str,
) -> PyResult<()> {
    match collector.files {
        Files::CrowdStrike => write_file(
            &folder.join("cs.falconhoseclient.cfg"),
            &render_falconhose_cfg(keys, host),
        ),
        Files::Defender => write_file(&folder.join("filebeat.yml"), &render_filebeat(keys, host)),
        Files::Bitdefender => {
            let data = render_config_json(keys, collector.protocol, host)?;
            // `os.makedirs(customer_upload_folder, exist_ok=True)`.
            std::fs::create_dir_all(folder).map_err(|e| os_error(&e))?;
            write_file(&folder.join("config.json"), &data)
        }
    }
}

/// `send_configuration_to_bitdefender(keys)`: httpx's POST, its answer's
/// JSON (a `JSONDecodeError` is the handler's 400) unused.
async fn send_configuration_to_bitdefender(env: &CloudEnv, keys: &PyValue) -> PyResult<()> {
    let base = env.bitdefender_url.as_deref().unwrap_or(GRAVITYZONE_URL);
    let authorization = gravityzone_authorization(&text(keys, "API_KEY"));
    let request = httpx::Request::new(http::Method::POST, format!("{base}/api/v1.0/jsonrpc/push"))
        .header("authorization", Some(&authorization))
        .header("cache-control", Some("no-cache"))
        .header("content-type", Some("application/json"))
        .json(gravityzone_body(keys))
        .verify(false);
    let response = httpx::send(request)
        .await
        .map_err(httpx::HttpxError::into_py)?;
    response.json()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_templates_have_no_carriage_return() {
        // Python reads them with universal newlines; byte-for-byte equality
        // with `include_str!` holds only while they carry none.
        for t in [
            CROWDSTRIKE_COMPOSE,
            CROWDSTRIKE_CFG,
            DEFENDER_COMPOSE,
            DEFENDER_FILEBEAT,
            BITDEFENDER_COMPOSE,
        ] {
            assert!(!t.contains('\r'));
        }
    }

    #[test]
    fn unsafe_names_are_refused() {
        for name in ["Acme_Corp", "a..b", ".hidden", "", ".", "..."] {
            assert!(safe_directory_name(name), "{name}");
        }
        for name in ["..", "../x", "A/S", "/etc", "a\0b", "x/.."] {
            assert!(!safe_directory_name(name), "{name}");
        }
    }
}

#[cfg(test)]
mod vectors {
    //! `collector_vectors.json` (`scripts/gen-remaining-provisioning-vectors.py`)
    //! against the three integrations' Python.

    use axum::response::IntoResponse;
    use copilot_auth::pyvalue::loads;
    use copilot_monitoring_alerts::body::PyBody;
    use copilot_web::ApiError;
    use serde_json::Value;

    use super::*;

    fn doc() -> Value {
        serde_json::from_str(include_str!("collector_vectors.json")).unwrap()
    }

    fn text_of(v: &Value) -> &str {
        v.as_str().unwrap()
    }

    fn dumps(v: &PyValue) -> String {
        py_dumps(v, Dumps::DEFAULT).unwrap()
    }

    async fn answer(e: ApiError) -> (u16, String) {
        let resp = e.into_response();
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn collector(route: &str) -> &'static Collector {
        COLLECTORS.iter().find(|c| c.route == route).unwrap()
    }

    #[tokio::test]
    async fn bodies_and_models_are_pydantic_s() {
        let d = doc();
        assert_eq!(d.as_object().unwrap().len(), COLLECTORS.len());
        for (route, v) in d.as_object().unwrap() {
            let c = collector(route);
            for case in v["requests"].as_array().unwrap() {
                let input = text_of(&case["input"]);
                let body = PyBody::read(Some("application/json"), input.as_bytes()).unwrap();
                let status = case["status"].as_u64().unwrap();
                match crate::routes::read_forced(&body, c.request, "integration_name", c.service) {
                    Ok(dump) => {
                        assert_eq!(status, 200, "{route} {input}");
                        assert_eq!(dumps(&dump), text_of(&case["dump"]), "{route} {input}");
                    }
                    Err(e) => {
                        let (got, body) = answer(e).await;
                        assert_eq!(u64::from(got), status, "{route} {input}: {body}");
                        if status != 500 {
                            assert_eq!(body, text_of(&case["body"]), "{route} {input}");
                        }
                    }
                }
            }
            for (key, model) in [("auth_keys", c.auth_keys), ("details", c.details)] {
                for case in v[key].as_array().unwrap() {
                    let input = loads(text_of(&case["input"])).unwrap();
                    match construct(model, &input) {
                        Ok(dump) => assert_eq!(dumps(&dump), text_of(&case["dump"]), "{route}"),
                        Err(PyExc::Validation(e)) => {
                            assert_eq!(e, text_of(&case["error"]), "{route}");
                        }
                        Err(other) => panic!("{route}: {other:?}"),
                    }
                }
            }
        }
    }

    /// Every file under `dir`, by its path relative to it (`None` for a
    /// directory), sorted as `sorted(rglob("*"))`.
    fn tree(dir: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Option<Vec<u8>>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                if path.is_dir() {
                    out.push((rel, None));
                    walk(root, &path, out);
                } else {
                    out.push((rel, Some(std::fs::read(&path).unwrap())));
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    #[test]
    fn the_files_are_written_byte_for_byte() {
        use sha2::Digest;
        let d = doc();
        let base = std::env::temp_dir().join(format!("collector-vectors-{}", std::process::id()));
        for (route, v) in d.as_object().unwrap() {
            let c = collector(route);
            for (i, case) in v["files"].as_array().unwrap().iter().enumerate() {
                let keys =
                    construct(c.auth_keys, &loads(&case["keys"].to_string()).unwrap()).unwrap();
                let name = text_of(&case["name"]);
                let host = syslog_host(case["url"].as_str());
                let dir = base.join(format!("{route}-{i}"));
                std::fs::create_dir_all(&dir).unwrap();
                let folder = dir.join(name);
                write_compose(&folder, c.files, name, &keys).unwrap();
                match (
                    write_config(&folder, c, &keys, &host),
                    case.get("exception"),
                ) {
                    (Ok(()), None) => {}
                    (Err(e), Some(want)) => assert_eq!(e.text(), text_of(&want[1]), "{route}"),
                    (got, want) => panic!("{route} {i}: {got:?} where Python gives {want:?}"),
                }
                let got = tree(&folder);
                let want = case["files"].as_object().unwrap();
                assert_eq!(got.len(), want.len(), "{route} {i}: {got:?}");
                for (rel, content) in &got {
                    let w = &want[rel.as_str()];
                    match content {
                        None => assert!(w.is_null(), "{route} {rel}"),
                        Some(bytes) if w.is_object() => {
                            assert_eq!(bytes.len() as u64, w["len"].as_u64().unwrap());
                            assert_eq!(
                                hex::encode(sha2::Sha256::digest(bytes)),
                                text_of(&w["sha256"]),
                                "{route} {rel}"
                            );
                        }
                        Some(bytes) => {
                            assert_eq!(String::from_utf8_lossy(bytes), text_of(w), "{route} {rel}");
                        }
                    }
                }
            }
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn gravityzone_is_sent_what_httpx_sends() {
        let d = doc();
        let c = collector("bitdefender");
        for case in d["bitdefender"]["gravityzone"].as_array().unwrap() {
            let keys = construct(c.auth_keys, &loads(&case["keys"].to_string()).unwrap()).unwrap();
            assert_eq!(
                text_of(&case["url"]),
                format!("{GRAVITYZONE_URL}/api/v1.0/jsonrpc/push")
            );
            let headers: Vec<(&str, &str)> = case["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| (text_of(&h[0]), text_of(&h[1])))
                .collect();
            let auth = gravityzone_authorization(&text(&keys, "API_KEY"));
            assert!(headers.contains(&("authorization", auth.as_str())));
            assert_eq!(
                py_dumps(&gravityzone_body(&keys), Dumps::HTTPX).unwrap(),
                text_of(&case["body"])
            );
        }
    }
}
