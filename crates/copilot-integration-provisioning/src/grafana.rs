//! The Grafana and Wazuh-indexer steps of the provisioning flows
//! (`customer_provisioning/services/grafana.py` and each module's
//! `create_grafana_datasource`):
//!
//! - the OpenSearch datasource: a fresh client, the service user switched to
//!   the customer's organization (`get_customer_meta`, 404 without a meta
//!   row), the URL and credentials of connector **id 1** (the Wazuh indexer
//!   by convention, three `get_connector_attribute(connector_id=1, …)`
//!   reads), the indexer's version (`GET /_nodes/_local?filter_path=…`),
//!   then `POST /datasources` with `GrafanaDatasource(...).model_dump()` —
//!   `pplEnabled` is dropped by the model, `dataLinks` takes its default;
//! - the folder (`POST /folders` with `{"title": …}`);
//! - the shard count (`output_shard_number_to_be_set_based_on_nodes`, the
//!   cluster's node count, through `copilot-wazuh`).

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_db::Db;
use copilot_grafana::GrafanaClient;
use copilot_grafana::client::CONNECTOR;
use copilot_upstream::model::{construct, construct_star, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_wazuh::WazuhState;
use copilot_wazuh::error::PyErr;
use http::Method;

use crate::schema::{
    GRAFANA_DATASOURCE, GRAFANA_DATASOURCE_CREATION_RESPONSE, GRAFANA_FOLDER_CREATION_RESPONSE,
    NODES_VERSION_RESPONSE, qualname,
};
use crate::store;

/// A `copilot-wazuh` exception as the Python exception it stands for.
pub fn wazuh_exc(e: PyErr) -> PyExc {
    match e {
        PyErr::Http { status, detail } => PyExc::Http(status, detail),
        PyErr::Value(text) => PyExc::ValueError(text),
        PyErr::Other(text) => PyExc::Other("Exception", text),
    }
}

fn serde_to_py(v: &serde_json::Value) -> PyResult<PyValue> {
    loads(&v.to_string()).map_err(|e| PyExc::Other("JSONDecodeError", e.to_string()))
}

/// `output_shard_number_to_be_set_based_on_nodes()`.
pub async fn shard_number(wazuh: &WazuhState) -> PyResult<PyValue> {
    let nodes = copilot_wazuh::indexer::services::monitoring::shard_number(wazuh)
        .await
        .map_err(wazuh_exc)?;
    serde_to_py(&nodes)
}

/// `get_opensearch_version()`: the first node's version.
pub async fn opensearch_version(wazuh: &WazuhState) -> PyResult<String> {
    let es = copilot_wazuh::indexer::services::client(wazuh)
        .await
        .map_err(wazuh_exc)?;
    let answer = es
        .perform(
            Method::GET,
            "/_nodes/_local",
            &[("filter_path", "nodes.*.version".to_string())],
            None,
        )
        .await
        .map_err(|e| PyExc::Other("TransportError", e.to_string()))?;
    let answer = serde_to_py(&answer)?;
    let response = construct_star(&NODES_VERSION_RESPONSE, qualname::NODES_VERSION, &answer)?;
    if let PyValue::Dict(nodes) = field(&response, "nodes") {
        if let Some((_, info)) = nodes.first() {
            return Ok(field(info, "version").py_str());
        }
    }
    Err(PyExc::http(500, "Failed to retrieve OpenSearch version."))
}

/// The parts of an OpenSearch datasource the flows vary.
#[derive(Debug, Clone)]
pub struct Datasource {
    /// `name`.
    pub name: String,
    /// `database` (and `jsonData.database`).
    pub database: String,
    /// `jsonData.logLevelField`.
    pub log_level_field: &'static str,
    /// `jsonData.logMessageField`.
    pub log_message_field: &'static str,
}

fn opt_str(v: Option<String>) -> PyValue {
    v.map_or(PyValue::None, PyValue::Str)
}

/// `create_grafana_datasource(customer_code, session)`: the new
/// datasource's `uid`.
pub async fn create_datasource(
    db: &Db,
    grafana: &GrafanaClient,
    wazuh: &WazuhState,
    customer_code: &str,
    spec: &Datasource,
) -> PyResult<PyValue> {
    let api = grafana.create(CONNECTOR).await?;
    let org = store::grafana_org_id(db, customer_code).await?;
    grafana.switch_organization(&api, &org).await?;
    let indexer = store::connector_by_id(db, 1).await?;
    let (url, user, password) = match indexer {
        Some(row) => (
            PyValue::Str(row.connector_url),
            opt_str(row.connector_username),
            opt_str(row.connector_password),
        ),
        None => (PyValue::None, PyValue::None, PyValue::None),
    };
    let version = opensearch_version(wazuh).await?;
    let payload = construct(
        &GRAFANA_DATASOURCE,
        &kwargs(vec![
            ("name", PyValue::Str(spec.name.clone())),
            ("type", PyValue::Str("grafana-opensearch-datasource".into())),
            ("typeName", PyValue::Str("OpenSearch".into())),
            ("access", PyValue::Str("proxy".into())),
            ("url", url),
            ("database", PyValue::Str(spec.database.clone())),
            ("basicAuth", PyValue::Bool(true)),
            ("basicAuthUser", user),
            (
                "secureJsonData",
                kwargs(vec![("basicAuthPassword", password)]),
            ),
            ("isDefault", PyValue::Bool(false)),
            (
                "jsonData",
                kwargs(vec![
                    ("database", PyValue::Str(spec.database.clone())),
                    ("flavor", PyValue::Str("opensearch".into())),
                    ("includeFrozen", PyValue::Bool(false)),
                    ("logLevelField", PyValue::Str(spec.log_level_field.into())),
                    (
                        "logMessageField",
                        PyValue::Str(spec.log_message_field.into()),
                    ),
                    ("maxConcurrentShardRequests", PyValue::Int("5".into())),
                    ("pplEnabled", PyValue::Bool(true)),
                    ("timeField", PyValue::Str("timestamp".into())),
                    ("tlsSkipVerify", PyValue::Bool(true)),
                    ("version", PyValue::Str(version)),
                ]),
            ),
            ("readOnly", PyValue::Bool(true)),
        ]),
    )?;
    let answer = grafana
        .call(
            &api,
            Method::POST,
            "/datasources",
            Some(payload),
            Vec::new(),
        )
        .await?;
    let response = construct_star(
        &GRAFANA_DATASOURCE_CREATION_RESPONSE,
        qualname::DATASOURCE_RESPONSE,
        &answer,
    )?;
    Ok(field(field(&response, "datasource"), "uid").clone())
}

/// `create_grafana_folder(organization_id, folder_title)`: the folder's
/// `GrafanaFolderCreationResponse` dump (its `id` and `uid` are used).
pub async fn create_folder(
    grafana: &GrafanaClient,
    organization_id: &str,
    title: &str,
) -> PyResult<PyValue> {
    let api = grafana.create(CONNECTOR).await?;
    grafana.switch_organization(&api, organization_id).await?;
    let answer = grafana
        .call(
            &api,
            Method::POST,
            "/folders",
            Some(kwargs(vec![("title", PyValue::Str(title.into()))])),
            Vec::new(),
        )
        .await?;
    construct_star(
        &GRAFANA_FOLDER_CREATION_RESPONSE,
        qualname::FOLDER_RESPONSE,
        &answer,
    )
}
