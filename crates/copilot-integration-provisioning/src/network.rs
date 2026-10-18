//! The Fortinet, SonicWall and SentinelOne stack provisioning —
//! `stack_provisioning/graylog/routes/{fortinet,sonicwall,sentinelone}.py`
//! and their services, which differ only in data ([`NETWORKS`]).
//!
//! Every Graylog call of the request goes to `Graylog-Network` (the routes
//! set `GraylogContext.NETWORK`), the Graylog 7 probe included. In Python's
//! order:
//!
//! 1. the customer's network connectors (404 without any), the one holding
//!    the service (an `AttributeError` when none does), its keys (404 without
//!    any); Fortinet's TCP/UDP choice (400 for both or neither); the keys
//!    read (`KeyError` is a bare 500, `int()`'s `ValueError` the 400);
//! 2. the customer's Grafana organization (404 without a meta row);
//! 3. the content packs: each skipped when a pack named after the customer
//!    exists, else rendered (two fresh UUIDs per pack), inserted, installed;
//! 4. the stream the packs created, a new index set (`<prefix>-<code>`,
//!    daily, the body's retention and replicas, one shard per indexer node),
//!    the two packs' ids, the input, the processing pipeline;
//! 5. the stream moved to the index set and connected to the pipeline;
//! 6. the Grafana datasource, folder and dashboards;
//! 7. the `customer_network_connectors_meta` row, then `deployed`.
//!
//! What the run creates is rolled back newest-first when a later step
//! fails ([`copilot_provisioning::rollback`]: the content packs it inserted
//! with their installations, the stream they made, the index set, the
//! datasource, the folder, the meta row, `deployed`), where Python left
//! them for the retry to trip over; the answer is the failure's, as in
//! Python. Two deliberate differences (RUST_MIGRATION.md §4): that
//! rollback, and the body's `customer_code` must be one of the caller's
//! customers (403 otherwise; Python provisioned any tenant).

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_grafana::GrafanaClient;
use copilot_grafana_dashboards::templates::{self as dashboards, DashboardClass};
use copilot_graylog::GraylogClient;
use copilot_graylog::client::NETWORK_CONNECTOR;
use copilot_integrations::network_connectors::schema::connector_dump;
use copilot_integrations::network_connectors::store::{CustomerConnector, customer_connectors};
use copilot_provisioning::rollback::{self, Rollback, Undo, UndoTools, id_text};
use copilot_upstream::model::{Model, construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, int_of};
use copilot_wazuh::WazuhState;

use crate::grafana::{self, Datasource};
use crate::graylog::{self, IndexSet, Keywords};
use crate::schema::{
    PROVISION_FORTINET_REQUEST, PROVISION_SENTINELONE_REQUEST, PROVISION_SONICWALL_REQUEST,
};
use crate::store::{self, NetworkMeta};

/// What one network connector's provisioning varies.
#[derive(Debug)]
pub struct Network {
    /// The route's last segment.
    pub route: &'static str,
    /// The service name (forced `integration_name`, the subscription's
    /// service, the `deployed` row).
    pub service: &'static str,
    /// The name in the missing-keys 404.
    pub label: &'static str,
    /// The content packs' tag, the pipeline subscription, the datasource,
    /// folder and meta row name.
    pub tag: &'static str,
    /// `index_prefix`'s head (`<prefix>-<code>`).
    pub prefix: &'static str,
    /// The index set's title and description after `<customer> - `.
    pub index_title: &'static str,
    /// The stream's title after `<customer> - `.
    pub stream_title: &'static str,
    /// The input's title after `<customer> - `.
    pub input_title: &'static str,
    /// Whether the keys carry the TLS certificate and key (read before the
    /// port).
    pub tls: bool,
    /// The dashboards provisioned.
    pub dashboards: &'static DashboardClass,
    /// The success message.
    pub message: &'static str,
    /// The request model.
    pub request: &'static Model,
}

/// Fortinet, SonicWall, SentinelOne.
pub static NETWORKS: &[Network] = &[
    Network {
        route: "fortinet",
        service: "Fortinet",
        label: "Fortinet",
        tag: "FORTINET",
        prefix: "fortinet",
        index_title: "FORTINET EVENTS",
        stream_title: "FORTINET LOGS AND EVENTS",
        input_title: "FORTINET LOGS AND EVENTS",
        tls: false,
        dashboards: &dashboards::FORTINET,
        message: "Fortinet customer provisioned successfully",
        request: &PROVISION_FORTINET_REQUEST,
    },
    Network {
        route: "sonicwall",
        service: "Sonicwall",
        label: "Sonicwall",
        tag: "SONICWALL",
        prefix: "sonicwall",
        index_title: "SONICWALL EVENTS",
        stream_title: "SONICWALL LOGS AND EVENTS",
        input_title: "SONICWALL FIREWALL LOGS AND EVENTS - TLS",
        tls: true,
        dashboards: &dashboards::SONICWALL,
        message: "Sonicwall customer provisioned successfully",
        request: &PROVISION_SONICWALL_REQUEST,
    },
    Network {
        route: "sentinelone",
        service: "Sentinelone",
        label: "SentinelOne",
        tag: "SENTINELONE",
        prefix: "sentinelone",
        index_title: "SENTINELONE ALERTS AND EVENTS",
        stream_title: "SENTINELONE ALERTS AND EVENTS",
        input_title: "SENTINELONE ALERTS AND EVENTS",
        tls: true,
        dashboards: &dashboards::SENTINELONE,
        message: "SentinelOne customer provisioned successfully",
        request: &PROVISION_SENTINELONE_REQUEST,
    },
];

impl<'a> Tools<'a> {
    /// What a rollback reaches.
    pub fn undo(&self) -> UndoTools<'a> {
        UndoTools {
            db: self.db,
            graylog: self.graylog,
            grafana: self.grafana,
            wazuh: Some(self.wazuh),
        }
    }
}

/// The tools a flow uses.
#[derive(Debug, Clone, Copy)]
pub struct Tools<'a> {
    /// The database.
    pub db: &'a Db,
    /// The Graylog client.
    pub graylog: &'a GraylogClient,
    /// The Grafana client.
    pub grafana: &'a GrafanaClient,
    /// The Wazuh indexer (shard count, OpenSearch version).
    pub wazuh: &'a WazuhState,
}

fn text(dump: &PyValue, key: &str) -> String {
    field(dump, key).py_str()
}

/// `dict[key]` of the keys (a `KeyError`, uncaught).
fn key<'a>(keys: &'a [(String, String)], name: &str) -> PyResult<&'a str> {
    keys.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| PyExc::key_error(name))
}

/// `get_customer_integration_response` then `find_customer_network_connector`
/// then `extract_<x>_keys`: the connector and its keys, in dict order.
async fn connector_and_keys(
    db: &Db,
    network: &Network,
    code: &str,
) -> PyResult<(CustomerConnector, Vec<(String, String)>)> {
    let list = customer_connectors(db, Some(code))
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
    // `CustomerNetworkConnectorsResponse(available_network_connectors=…)`.
    for c in &list {
        connector_dump(c, false).map_err(|e| PyExc::Other("ValidationError", e.into()))?;
    }
    if list.is_empty() {
        return Err(PyExc::http(404, "Customer integration settings not found."));
    }
    let serves = |c: &CustomerConnector| {
        c.subscriptions.iter().any(|s| {
            s.service
                .as_ref()
                .is_some_and(|v| v.service_name == network.service)
        })
    };
    let Some(found) = list.into_iter().find(serves) else {
        return Err(PyExc::AttributeError(
            "'NoneType' object has no attribute 'network_connectors_subscriptions'".into(),
        ));
    };
    let mut keys: Vec<(String, String)> = Vec::new();
    for sub in &found.subscriptions {
        if sub
            .service
            .as_ref()
            .is_some_and(|v| v.service_name == network.service)
        {
            for k in &sub.keys {
                match keys.iter_mut().find(|(name, _)| *name == k.auth_key_name) {
                    Some(slot) => slot.1 = k.auth_value.clone(),
                    None => keys.push((k.auth_key_name.clone(), k.auth_value.clone())),
                }
            }
        }
    }
    if keys.is_empty() {
        return Err(PyExc::http(
            404,
            format!(
                "No auth keys found for {label} integration. Please create auth keys for {label} \
                 network connector.",
                label = network.label
            ),
        ));
    }
    Ok((found, keys))
}

/// The route: `request` is the validated body, its customer already checked
/// against the caller.
pub async fn provision(
    tools: Tools<'_>,
    network: &Network,
    request: &PyValue,
) -> PyResult<PyValue> {
    let code = text(request, "customer_code");
    let (connector, keys) = connector_and_keys(tools.db, network, &code).await?;
    let protocol = if network.route == "fortinet" {
        let tcp = field(request, "tcp_enabled").truthy();
        let udp = field(request, "udp_enabled").truthy();
        Some(match (tcp, udp) {
            (true, true) => {
                return Err(PyExc::http(
                    400,
                    "Both TCP and UDP are enabled. Please choose one of them.",
                ));
            }
            (true, false) => "TCP",
            (false, true) => "UDP",
            (false, false) => {
                return Err(PyExc::http(400, "Either TCP or UDP should be enabled."));
            }
        })
    } else {
        None
    };
    let (tls_cert_file, tls_key_file) = if network.tls {
        (
            Some(key(&keys, "TLS_CERT_FILE")?.to_string()),
            Some(key(&keys, "TLS_KEY_FILE")?.to_string()),
        )
    } else {
        (None, None)
    };
    let syslog_port = int_of(&PyValue::Str(key(&keys, "SYSLOG_PORT")?.to_string()))?;
    let keywords = Keywords {
        customer_name: connector.customer_name.clone(),
        customer_code: code.clone(),
        protocol_type: protocol,
        syslog_port,
        tls_cert_file,
        tls_key_file,
    };
    let mut rollback = Rollback::default();
    let outcome = provision_customer(
        tools,
        network,
        &keywords,
        field(request, "hot_data_retention"),
        field(request, "index_replicas"),
        &mut rollback,
    )
    .await;
    if outcome.is_err() {
        rollback.run(tools.undo()).await;
    }
    outcome?;
    Ok(kwargs(vec![
        ("success", PyValue::Bool(true)),
        ("message", PyValue::Str(network.message.into())),
    ]))
}

/// `provision_<x>(customer_details, keys, session)`.
async fn provision_customer(
    tools: Tools<'_>,
    network: &Network,
    keywords: &Keywords,
    hot_data_retention: &PyValue,
    index_replicas: &PyValue,
    rollback: &mut Rollback,
) -> PyResult<()> {
    let (db, gl, net) = (tools.db, tools.graylog, NETWORK_CONNECTOR);
    let code = keywords.customer_code.as_str();
    let name = keywords.customer_name.as_str();
    if store::grafana_org_attribute(db, code).await?.is_none() {
        return Err(PyExc::http(
            404,
            "Grafana organization ID not found. Please provision Grafana for the customer first.",
        ));
    }
    let own_stream =
        graylog::provision_network_content_packs(gl, net, network.tag, keywords, rollback).await?;

    // `get_stream_and_index_ids`.
    let stream_id =
        graylog::stream_id_by_name(gl, net, &format!("{name} - {}", network.stream_title)).await?;
    let creation_date = graylog::creation_date();
    let shards = grafana::shard_number(tools.wazuh).await?;
    let index_set = graylog::index_set_config(&IndexSet {
        title: format!("{name} - {}", network.index_title),
        description: format!("{name} - {}", network.index_title),
        index_prefix: format!("{}-{code}", network.prefix),
        max_indices: hot_data_retention.clone(),
        shards,
        replicas: index_replicas.clone(),
        creation_date,
    })?;
    let index_id = graylog::create_index_set(gl, net, index_set).await?;
    register_index_set(rollback, net, &index_id);
    let pack_stream_id =
        graylog::content_pack_id_by_name(gl, net, &format!("{name}_{}_STREAM", network.tag))
            .await?;
    let input_pack = match keywords.protocol_type {
        Some(protocol) => format!("{name}_{}_INPUT_SYSLOG_{protocol}", network.tag),
        None => format!("{name}_{}_INPUT_SYSLOG_TLS", network.tag),
    };
    let pack_input_id = graylog::content_pack_id_by_name(gl, net, &input_pack).await?;

    // `create_customer_network_connector_meta`.
    let input_id =
        graylog::input_id_by_name(gl, net, &format!("{name} - {}", network.input_title)).await?;
    let pipeline = graylog::pipeline_id(gl, net, network.tag).await?;
    let pipeline_id = match &pipeline {
        PyValue::List(ids) => ids.first().cloned().unwrap_or(PyValue::None),
        _ => PyValue::None,
    };
    let org_attribute = store::grafana_org_attribute(db, code).await?;
    let mut meta = NetworkMeta {
        customer_code: code.to_string(),
        network_connector_name: network.tag,
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

    graylog::assign_stream_to_index(gl, net, &stream_id, &index_id).await?;
    if own_stream {
        // Graylog keeps an index set a stream is assigned to: the pack's
        // stream goes first (its pack's uninstall then skips it).
        register_stream(rollback, net, &stream_id);
    } else if let Some(id) = rollback::id_text(&index_id) {
        // A stream found and reused now writes into the new index set.
        rollback.keep_index_set(&id);
    }
    let pipeline_ids = graylog::pipeline_id(gl, net, network.tag).await?;
    graylog::connect_stream_to_pipeline(gl, net, &stream_id, &pipeline_ids).await?;

    // Grafana.
    let datasource_uid = grafana::create_datasource(
        db,
        tools.grafana,
        tools.wazuh,
        code,
        &Datasource {
            name: network.tag.to_string(),
            database: format!("{}-{code}*", network.prefix),
            log_level_field: "severity",
            log_message_field: "summary",
            data_links: None,
        },
    )
    .await?;
    meta.grafana_datasource_uid = datasource_uid.clone();
    let org = store::grafana_org_id(db, code).await?;
    register_datasource(rollback, &org, &datasource_uid);
    let folder = grafana::create_folder(tools.grafana, &org, network.tag).await?;
    register_folder(rollback, &org, &folder);
    provision_dashboards(tools, network.dashboards, code, &folder, &datasource_uid).await?;
    meta.grafana_dashboard_folder_id = field(&folder, "uid").clone();
    let meta_id = store::insert_network_meta(db, &meta).await?;
    rollback.add(
        format!("{} meta row {meta_id}", network.tag),
        Undo::Row {
            table: "customer_network_connectors_meta",
            id: meta_id,
        },
    );
    store::set_network_deployed(db, code, network.service, rollback).await
}

/// An index set this run created.
pub fn register_index_set(rollback: &mut Rollback, connector: &'static str, id: &PyValue) {
    if let Some(id) = id_text(id) {
        rollback.add(format!("index set {id}"), Undo::IndexSet { connector, id });
    }
}

/// A stream this run created (or a pack it installed made).
pub fn register_stream(rollback: &mut Rollback, connector: &'static str, id: &PyValue) {
    if let Some(id) = id_text(id) {
        rollback.add(format!("stream {id}"), Undo::Stream { connector, id });
    }
}

/// A datasource this run created in `org`.
pub fn register_datasource(rollback: &mut Rollback, org: &str, uid: &PyValue) {
    if let Some(uid) = id_text(uid) {
        rollback.add(
            format!("datasource {uid}"),
            Undo::Datasource {
                org: org.to_string(),
                uid,
            },
        );
    }
}

/// A folder this run created in `org` (its `GrafanaFolderCreationResponse`
/// dump: the undo deletes it by uid, the dashboards in it with it).
pub fn register_folder(rollback: &mut Rollback, org: &str, folder: &PyValue) {
    if let Some(uid) = id_text(field(folder, "uid")) {
        rollback.add(
            format!("folder {uid}"),
            Undo::Folder {
                org: org.to_string(),
                uid,
            },
        );
    }
}

/// `provision_dashboards(DashboardProvisionRequest(dashboards=[…],
/// organizationId=<meta org>, folderId=folder.id, datasourceUid=uid))`: the
/// organization is read again, and validated as an `int`.
pub async fn provision_dashboards(
    tools: Tools<'_>,
    class: &DashboardClass,
    code: &str,
    folder: &PyValue,
    datasource_uid: &PyValue,
) -> PyResult<()> {
    let org = store::grafana_org_id(tools.db, code).await?;
    let names = class.names().into_iter().map(PyValue::Str).collect();
    let request = construct(
        &copilot_grafana_dashboards::schema::DASHBOARD_PROVISION_REQUEST,
        &kwargs(vec![
            ("dashboards", PyValue::List(names)),
            ("organizationId", PyValue::Str(org)),
            ("folderId", field(folder, "id").clone()),
            ("datasourceUid", datasource_uid.clone()),
        ]),
    )?;
    copilot_grafana_dashboards::services::provision_dashboards(tools.grafana, &request).await?;
    Ok(())
}
