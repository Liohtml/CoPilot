//! Customer provisioning — ports of
//! `app/customer_provisioning/{routes,services}/provision.py` (`POST
//! /provision`, `POST /provision/wazuh_worker`), of the Wazuh-group and
//! Grafana-organization steps of `services/{wazuh_manager,grafana}.py`, and of
//! `app/connectors/portainer/services/stack.py`'s stack creation (`POST
//! /api/portainer/create-wazuh-customer-stack`).
//!
//! `POST /provision`, in Python's order; what it creates is rolled back
//! newest-first when a later step fails (RUST_MIGRATION.md §4):
//!
//! 1. the query's customer exists (404), the body's ports unused by any
//!    other customer when a worker is asked for (400);
//! 2. `only_insert_into_db`: the `customersmeta` row from the body, answered;
//! 3. else the three tools verified (Graylog's roles of its user, the Wazuh
//!    manager's token, Grafana's test user created and deleted: a 500 naming
//!    the first that fails), the `Wazuh` pipeline, the customer's index set
//!    (the body's prefix, retention, shards and replicas), its stream (`OR`
//!    of the agents' customer label and the worker's node name, through
//!    `create_entity`), connected and resumed; the three Wazuh groups created
//!    and configured from the templates (each failure only logged); the
//!    Grafana organization, its WAZUH datasource (the `Wazuh-Indexer`
//!    connector's credentials, two data links), the `EDR` folder and the
//!    body's dashboards; the `customersmeta` and `custom_alert_creation_settings`
//!    rows; then the worker and HAProxy when asked for.
//!
//! The worker is provisioned by the `Wazuh Worker Provisioning` service — or,
//! when the Portainer connector is verified, by the provisioning worker of
//! every swarm node (`http://<node>:5003/provision_worker`), then the
//! customer's Portainer stack (the template compiled in from the backend's
//! tree, `str.replace`d as Python does) and its id on the customer's row.
//!
//! The templates are `include_str!`s of the backend's own files (one source).

pub mod schema;
mod verify;

use copilot_auth::pyvalue::PyValue;
use copilot_core::cloud_env::CloudEnv;
use copilot_db::Db;
use copilot_graylog::client::DEFAULT_CONNECTOR;
use copilot_portainer::PortainerClient;
use copilot_provisioning::rollback::{Rollback, Undo, id_text};
use copilot_upstream::http::{PyHttp, PyRequest};
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::model::{construct, construct_star, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_wazuh::manager::client::{self as manager, Body, PutKind};
use copilot_web::AppContext;
use http::Method;

use crate::grafana::{self, Datasource};
use crate::graylog::{self, IndexSet};
use crate::network::{
    Tools, register_datasource, register_folder, register_index_set, register_stream,
};
use schema::{
    CUSTOMER_PROVISION_META, GRAFANA_ORGANIZATION_CREATION, GRAFANA_ORGANIZATION_CREATION_QUALNAME,
    PROVISION_HAPROXY_REQUEST, PROVISION_WORKER_REQUEST,
};

pub use verify::verify_required_tools;

/// `customer_provisioning/templates/linux_agent.conf`, from the backend's
/// tree.
pub const LINUX_AGENT: &str =
    include_str!("../../../../backend/app/customer_provisioning/templates/linux_agent.conf");
/// `customer_provisioning/templates/windows_agent.conf`.
pub const WINDOWS_AGENT: &str =
    include_str!("../../../../backend/app/customer_provisioning/templates/windows_agent.conf");
/// `customer_provisioning/templates/mac_agent.conf`.
pub const MAC_AGENT: &str =
    include_str!("../../../../backend/app/customer_provisioning/templates/mac_agent.conf");
/// `connectors/portainer/templates/wazuh_worker_stack.yml`.
pub const WAZUH_WORKER_STACK: &str =
    include_str!("../../../../backend/app/connectors/portainer/templates/wazuh_worker_stack.yml");

/// The Wazuh groups and their configuration templates, in Python's order.
pub const GROUP_TEMPLATES: &[(&str, &str)] = &[
    ("Linux", LINUX_AGENT),
    ("Windows", WINDOWS_AGENT),
    ("Mac", MAC_AGENT),
];

/// The provisioning worker's port on a swarm node.
pub const WORKER_PORT: &str = "5003";

/// What the flows use.
#[derive(Clone, Copy)]
pub struct Customer<'a> {
    /// The shared context (database, connector rows).
    pub ctx: &'a AppContext,
    /// Graylog, Grafana, the Wazuh indexer and manager.
    pub tools: Tools<'a>,
    /// Portainer.
    pub portainer: &'a PortainerClient,
    /// `requests` (`timeout=60`, certificates verified) for the worker and
    /// HAProxy services.
    pub http: &'a PyHttp,
    /// The environment (the worker's port for the tests).
    pub env: &'a CloudEnv,
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn text(dump: &PyValue, key: &str) -> String {
    field(dump, key).py_str()
}

fn db_err(e: impl std::fmt::Display) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

fn wazuh_err(e: copilot_wazuh::error::PyErr) -> PyExc {
    grafana::wazuh_exc(e)
}

/// `str(e)` of what `get_wazuh_manager_version`'s `except Exception` caught.
fn caught_text(e: &PyExc) -> String {
    match e {
        PyExc::Http(status, detail) => format!("{status}: {detail}"),
        other => other.text(),
    }
}

// --- the database ----------------------------------------------------------------

/// `check_customer_exists(customer_code)`: the 404 without a `customers` row.
pub async fn check_customer_exists(db: &Db, code: &str) -> PyResult<()> {
    match copilot_db::customers::find_customer(db, code)
        .await
        .map_err(db_err)?
    {
        Some(_) => Ok(()),
        None => Err(PyExc::http(
            404,
            format!("Customer: {code} not found. Please create the customer first."),
        )),
    }
}

/// `check_unique_ports(request)`: the first meta row naming each port in
/// any of its three port columns — `column == None` being SQLAlchemy's
/// `IS NULL`, a port left `None` matches any row missing one.
async fn check_unique_ports(db: &Db, request: &PyValue) -> PyResult<()> {
    for (kind, key) in [
        ("Registration", "wazuh_registration_port"),
        ("Logs", "wazuh_logs_port"),
        ("Api", "wazuh_api_port"),
    ] {
        let rows: Vec<(String,)> = match crate::store::text(field(request, key)) {
            Some(port) => {
                sqlx::query_as(
                    "SELECT customersmeta.customer_code FROM customersmeta WHERE \
                     customersmeta.customer_meta_wazuh_registration_port = ? OR \
                     customersmeta.customer_meta_wazuh_log_ingestion_port = ? OR \
                     customersmeta.customer_meta_wazuh_api_port = ?",
                )
                .bind(&port)
                .bind(&port)
                .bind(&port)
                .persistent(false)
                .fetch_all(db.pool())
                .await
            }
            None => {
                sqlx::query_as(
                    "SELECT customersmeta.customer_code FROM customersmeta WHERE \
                     customersmeta.customer_meta_wazuh_registration_port IS NULL OR \
                     customersmeta.customer_meta_wazuh_log_ingestion_port IS NULL OR \
                     customersmeta.customer_meta_wazuh_api_port IS NULL",
                )
                .persistent(false)
                .fetch_all(db.pool())
                .await
            }
        }
        .map_err(db_err)?;
        if let Some((code,)) = rows.first() {
            return Err(PyExc::http(
                400,
                format!(
                    "Ports must be unique. {kind} port {} is already in use for customer {code}.",
                    field(request, key).py_str()
                ),
            ));
        }
    }
    Ok(())
}

/// The value a column takes: `None` is `NULL`, an `int` its digits, a `str`
/// itself.
fn column(v: &PyValue) -> Option<String> {
    crate::store::text(v)
}

/// `CustomersMeta(...)`, added and committed: its new id.
async fn insert_meta(db: &Db, values: &[(&'static str, PyValue)]) -> PyResult<i64> {
    let columns: Vec<&str> = values.iter().map(|(c, _)| *c).collect();
    let marks = vec!["?"; values.len()].join(", ");
    let sql = format!(
        "INSERT INTO customersmeta ({}) VALUES ({marks})",
        columns.join(", ")
    );
    let mut q = sqlx::query(&sql);
    for (_, v) in values {
        q = q.bind(column(v));
    }
    let done = q
        .persistent(false)
        .execute(db.pool())
        .await
        .map_err(db_err)?;
    i64::try_from(done.last_insert_id()).map_err(db_err)
}

/// The meta row as the response shows it: `keys_first` — the instance
/// itself (`only_insert_into_db`: its attributes in the order they were set,
/// the id last) — or its `model_dump()` validated again (the id first).
fn meta_dump(values: Vec<(&'static str, PyValue)>, id: i64, id_first: bool) -> PyValue {
    let id = ("id", PyValue::Int(id.to_string()));
    let mut out = Vec::with_capacity(values.len() + 1);
    if id_first {
        out.push(id.clone());
    }
    out.extend(values);
    if !id_first {
        out.push(id);
    }
    kwargs(out)
}

/// `f'dfir_iris_{customer_name.lower().replace(" ", "_")}'`.
pub fn iris_index(name: &str) -> String {
    format!("dfir_iris_{}", name.to_lowercase().replace(' ', "_"))
}

/// `update_customer_alert_settings_table(request, meta)`.
async fn insert_alert_settings(db: &Db, request: &PyValue) -> PyResult<i64> {
    let name = text(request, "customer_name");
    let done = sqlx::query(
        "INSERT INTO custom_alert_creation_settings (customer_code, customer_name, timefield, \
         iris_customer_id, iris_customer_name, iris_index, grafana_url, custom_message, nvd_url) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(text(request, "customer_code"))
    .bind(&name)
    .bind("timestamp_utc")
    .bind(None::<i64>)
    .bind(&name)
    .bind(iris_index(&name))
    .bind(text(request, "grafana_url"))
    .bind("Open In SOCFortress")
    .bind("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId")
    .persistent(false)
    .execute(db.pool())
    .await
    .map_err(db_err)?;
    i64::try_from(done.last_insert_id()).map_err(db_err)
}

/// `update_customer_portainer_stack_id(customer_name, stack_id)`.
async fn update_stack_id(db: &Db, name: &str, stack_id: &PyValue) -> PyResult<()> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT CAST(customersmeta.id AS SIGNED) FROM customersmeta WHERE \
         customersmeta.customer_name = ?",
    )
    .bind(name)
    .persistent(false)
    .fetch_all(db.pool())
    .await
    .map_err(db_err)?;
    match rows.len() {
        0 => {
            return Err(PyExc::http(
                404,
                format!("Customer {name} not found in database"),
            ));
        }
        1 => {}
        _ => {
            return Err(PyExc::Other(
                "MultipleResultsFound",
                "Multiple rows were found when one or none was required".into(),
            ));
        }
    }
    sqlx::query(
        "UPDATE customersmeta SET customer_meta_portainer_stack_id=? WHERE \
         customersmeta.customer_name = ?",
    )
    .bind(column(stack_id))
    .bind(name)
    .persistent(false)
    .execute(db.pool())
    .await
    .map_err(db_err)?;
    Ok(())
}

// --- the Wazuh manager -------------------------------------------------------------

/// `get_wazuh_manager_version()`: `response["data"]["data"]["api_version"]`,
/// any failure the 500 naming it.
pub async fn wazuh_manager_version(c: Customer<'_>) -> PyResult<PyValue> {
    let outcome = async {
        let response = manager::send_get(c.tools.wazuh, "/", None)
            .await
            .map_err(wazuh_err)?;
        let version = copilot_wazuh::pyops::index(&response, "data")
            .and_then(|d| copilot_wazuh::pyops::index(&d, "data"))
            .and_then(|d| copilot_wazuh::pyops::index(&d, "api_version"))
            .map_err(|e| PyExc::Other("KeyError", e))?;
        copilot_auth::pyvalue::loads(&version.to_string())
            .map_err(|e| PyExc::Other("JSONDecodeError", e.to_string()))
    }
    .await;
    outcome.map_err(|e| {
        let text = caught_text(&e);
        tracing::error!("Failed to fetch Wazuh Manager version: {text}");
        PyExc::http(
            500,
            format!("Failed to fetch Wazuh Manager version: {text}"),
        )
    })
}

/// `create_wazuh_groups(request)`: `POST /groups` for each group, every
/// failure only logged.
async fn create_wazuh_groups(c: Customer<'_>, code: &str, rollback: &mut Rollback) {
    for (group, _) in GROUP_TEMPLATES {
        let group_code = format!("{group}_{code}");
        tracing::info!("Creating group with code {group_code}");
        let body = kwargs(vec![("group_id", s(&group_code))]);
        let json = py_dumps(&body, Dumps::DEFAULT).unwrap_or_default();
        match manager::send_post_json(c.tools.wazuh, "/groups", json).await {
            Ok(response) => {
                tracing::info!("Response for {group_code}: {response}");
                // A group the manager created (not one it already had).
                if response.get("success").and_then(serde_json::Value::as_bool) == Some(true) {
                    rollback.add(
                        format!("Wazuh group {group_code}"),
                        Undo::WazuhGroup(group_code),
                    );
                }
            }
            Err(e) => tracing::error!("Error creating group {group_code}: {e:?}"),
        }
    }
}

/// `configure_wazuh_group`'s text: `REPLACE` is the group code's last
/// `_`-separated part, `CLUSTER_NAME` the cluster's name (`YOUR_PATH` when
/// it is empty or `None`).
pub fn group_configuration(template: &str, group_code: &str, cluster_name: &PyValue) -> String {
    let last = group_code.rsplit('_').next().unwrap_or(group_code);
    let cluster = if cluster_name.truthy() {
        cluster_name.py_str()
    } else {
        "YOUR_PATH".to_string()
    };
    template
        .replace("REPLACE", last)
        .replace("CLUSTER_NAME", &cluster)
}

/// `apply_group_configurations(request)`: each group's configuration `PUT`
/// as XML, every failure only logged.
async fn apply_group_configurations(c: Customer<'_>, request: &PyValue) {
    let code = text(request, "customer_code");
    for (group, template) in GROUP_TEMPLATES {
        let group_code = format!("{group}_{code}");
        tracing::info!("Configuring Wazuh group {group_code}");
        let config =
            group_configuration(template, &group_code, field(request, "wazuh_cluster_name"));
        if let Err(e) = manager::send_put(
            c.tools.wazuh,
            &format!("/groups/{group_code}/configuration"),
            Some(Body::Text(config)),
            None,
            PutKind::Xml,
        )
        .await
        {
            tracing::error!("Error configuring group {group_code}: {e:?}");
        }
    }
}

// --- the flows ------------------------------------------------------------------

/// The data links of the customer's WAZUH datasource.
pub fn wazuh_data_links(grafana_url: &str) -> PyValue {
    PyValue::List(vec![
        kwargs(vec![
            ("field", s("^data_vulnerability_cve$")),
            ("url", s("https://nvd.nist.gov/vuln/detail/${__value.raw}")),
        ]),
        kwargs(vec![
            ("field", s("^_id$")),
            (
                "url",
                s(&format!(
                    "{grafana_url}/explore?left=%7B%22datasource%22:%22WAZUH%22,%22queries%22:%5B%7B\
                     %22refId%22:%22A%22,%22query%22:%22_id:${{__value.raw}}%22,%22alias%22:%22%22,\
                     %22metrics%22:%5B%7B%22id%22:%221%22,%22type%22:%22logs%22,%22settings%22:\
                     %7B%22limit%22:%22500%22%7D%7D%5D,%22bucketAggs%22:%5B%7B%22type%22:%22date_histogram%22,%22id%22:%221%22,%22settings%22:%7B%22interval%22:%22auto%22%7D%7D%5D,%22timeField%22:\
                     %22timestamp%22%7D%5D,%22range%22:%7B%22from%22:%22now-6h%22,%22to%22:%22now%22%7D%7D"
                )),
            ),
        ]),
    ])
}

/// The customer's stream: two rules, matched with `OR`.
fn wazuh_event_stream(request: &PyValue, index_set_id: &PyValue) -> PyResult<PyValue> {
    let name = text(request, "customer_name");
    let code = text(request, "customer_code");
    let sanitized = code.replace(' ', "_");
    graylog::event_stream_config_matching(
        &format!("{name} - Wazuh EDR EVENTS"),
        &format!("{name} - Wazuh EDR EVENTS"),
        index_set_id,
        vec![
            ("agent_labels_customer", code.clone()),
            ("cluster_node", format!("wazuh-worker-{sanitized}-1")),
        ],
        "OR",
    )
}

/// `POST /provision`'s work once the body is read and checked: the response
/// dump.
pub async fn provision(c: Customer<'_>, request: &PyValue) -> PyResult<PyValue> {
    let db = c.tools.db;
    if field(request, "provision_wazuh_worker").truthy() {
        check_unique_ports(db, request).await?;
    }
    tracing::info!("Provisioning new customer");
    if matches!(field(request, "only_insert_into_db"), PyValue::Bool(true)) {
        tracing::info!("Only inserting into the database");
        let values = vec![
            ("customer_code", field(request, "customer_code").clone()),
            ("customer_name", field(request, "customer_name").clone()),
            (
                "customer_meta_graylog_index",
                field(request, "graylog_index_id").clone(),
            ),
            (
                "customer_meta_graylog_stream",
                field(request, "graylog_stream_id").clone(),
            ),
            (
                "customer_meta_grafana_org_id",
                field(request, "grafana_org_id").clone(),
            ),
            (
                "customer_meta_wazuh_group",
                field(request, "customer_code").clone(),
            ),
            (
                "customer_meta_index_retention",
                s(&text(request, "hot_data_retention")),
            ),
            (
                "customer_meta_wazuh_registration_port",
                field(request, "wazuh_registration_port").clone(),
            ),
            (
                "customer_meta_wazuh_log_ingestion_port",
                field(request, "wazuh_logs_port").clone(),
            ),
            (
                "customer_meta_wazuh_api_port",
                field(request, "wazuh_api_port").clone(),
            ),
            (
                "customer_meta_wazuh_auth_password",
                field(request, "wazuh_auth_password").clone(),
            ),
        ];
        let id = insert_meta(db, &values).await?;
        return Ok(kwargs(vec![
            (
                "message",
                s("Customer inserted into the database successfully"),
            ),
            ("success", PyValue::Bool(true)),
            ("customer_meta", meta_dump(values, id, false)),
            ("wazuh_worker_provisioned", PyValue::Bool(false)),
        ]));
    }
    // What the run creates is undone, newest first, when a later step fails
    // (RUST_MIGRATION.md §4: Python left it for the retry to trip over).
    let mut rollback = Rollback::default();
    let outcome = provision_wazuh_customer(c, request, &mut rollback).await;
    if outcome.is_err() {
        rollback.run(c.tools.undo()).await;
    }
    outcome
}

/// `provision_wazuh_customer(request)`.
async fn provision_wazuh_customer(
    c: Customer<'_>,
    request: &PyValue,
    rollback: &mut Rollback,
) -> PyResult<PyValue> {
    let (db, gl, conn) = (c.tools.db, c.tools.graylog, DEFAULT_CONNECTOR);
    verify_required_tools(c).await?;
    let name = text(request, "customer_name");
    tracing::info!("Provisioning new customer {name}");
    let pipeline_ids = graylog::pipeline_id(gl, conn, "Wazuh").await?;
    let index_set = graylog::index_set_config(&IndexSet {
        title: format!("{name} - Wazuh EDR EVENTS"),
        description: format!("{name} - Wazuh EDR EVENTS"),
        index_prefix: text(request, "customer_index_name"),
        max_indices: field(request, "hot_data_retention").clone(),
        shards: field(request, "index_shards").clone(),
        replicas: field(request, "index_replicas").clone(),
        creation_date: graylog::creation_date(),
    })?;
    let index_set_id = graylog::create_index_set(gl, conn, index_set).await?;
    register_index_set(rollback, conn, &index_set_id);
    let stream = wazuh_event_stream(request, &index_set_id)?;
    let stream_id = graylog::create_event_stream(gl, conn, stream).await?;
    register_stream(rollback, conn, &stream_id);
    graylog::connect_stream_to_pipeline(gl, conn, &stream_id, &pipeline_ids).await?;
    // `start_stream` answers a model, never `False`: its outcome is not read.
    copilot_graylog::services::start_stream(gl, &stream_id.py_str()).await?;
    create_wazuh_groups(c, &text(request, "customer_code"), rollback).await;
    apply_group_configurations(c, request).await;

    // Grafana: the organization, the datasource, the EDR folder, the dashboards.
    let api = c
        .tools
        .grafana
        .create(copilot_grafana::client::CONNECTOR)
        .await?;
    let answer = c
        .tools
        .grafana
        .call(
            &api,
            Method::POST,
            "/orgs",
            Some(kwargs(vec![(
                "name",
                field(request, "customer_grafana_org_name").clone(),
            )])),
            Vec::new(),
        )
        .await?;
    let organization = construct_star(
        &GRAFANA_ORGANIZATION_CREATION,
        GRAFANA_ORGANIZATION_CREATION_QUALNAME,
        &answer,
    )?;
    let org_id = field(&organization, "orgId").clone();
    if let Some(id) = id_text(&org_id) {
        rollback.add(
            format!("Grafana organization {id}"),
            Undo::GrafanaOrganization { id },
        );
    }
    let api = c
        .tools
        .grafana
        .create(copilot_grafana::client::CONNECTOR)
        .await?;
    c.tools
        .grafana
        .switch_organization(&api, &org_id.py_str())
        .await?;
    let credentials = grafana::credentials_by_name(c.ctx, "Wazuh-Indexer").await?;
    let grafana_url = text(request, "grafana_url");
    let datasource_uid = grafana::create_datasource_with(
        c.tools.grafana,
        c.tools.wazuh,
        &api,
        &Datasource {
            name: "WAZUH".into(),
            database: format!("{}*", text(request, "customer_index_name")),
            log_level_field: "syslog_level",
            log_message_field: "rule_description",
            data_links: Some(wazuh_data_links(&grafana_url)),
        },
        credentials,
    )
    .await?;
    register_datasource(rollback, &org_id.py_str(), &datasource_uid);
    tracing::info!("Creating EDR folder and dashboards");
    let folder = grafana::create_folder(c.tools.grafana, &org_id.py_str(), "EDR").await?;
    register_folder(rollback, &org_id.py_str(), &folder);
    let folder_id = field(&folder, "id").clone();
    let dashboards = construct(
        &copilot_grafana_dashboards::schema::DASHBOARD_PROVISION_REQUEST,
        &kwargs(vec![
            (
                "dashboards",
                field(field(request, "dashboards_to_include"), "dashboards").clone(),
            ),
            ("organizationId", org_id.clone()),
            ("folderId", folder_id.clone()),
            ("datasourceUid", datasource_uid.clone()),
            ("grafana_url", s(&grafana_url)),
        ]),
    )?;
    copilot_grafana_dashboards::services::provision_dashboards(c.tools.grafana, &dashboards)
        .await?;

    // `CustomerProvisionMeta(**provision_meta_data)`, in the dict's order.
    let meta = construct(
        &CUSTOMER_PROVISION_META,
        &kwargs(vec![
            ("pipeline_ids", pipeline_ids),
            ("index_set_id", index_set_id),
            ("stream_id", stream_id),
            ("grafana_organization_id", org_id),
            ("wazuh_datasource_uid", datasource_uid),
            ("grafana_edr_folder_id", folder_id),
        ]),
    )?;
    let values = vec![
        ("customer_code", field(request, "customer_code").clone()),
        ("customer_name", field(request, "customer_name").clone()),
        (
            "customer_meta_graylog_index",
            field(&meta, "index_set_id").clone(),
        ),
        (
            "customer_meta_graylog_stream",
            field(&meta, "stream_id").clone(),
        ),
        (
            "customer_meta_grafana_org_id",
            field(&meta, "grafana_organization_id").clone(),
        ),
        (
            "customer_meta_wazuh_group",
            field(request, "customer_code").clone(),
        ),
        (
            "customer_meta_index_retention",
            s(&text(request, "hot_data_retention")),
        ),
        (
            "customer_meta_wazuh_registration_port",
            field(request, "wazuh_registration_port").clone(),
        ),
        (
            "customer_meta_wazuh_log_ingestion_port",
            field(request, "wazuh_logs_port").clone(),
        ),
        (
            "customer_meta_wazuh_api_port",
            field(request, "wazuh_api_port").clone(),
        ),
        (
            "customer_meta_wazuh_auth_password",
            field(request, "wazuh_auth_password").clone(),
        ),
        (
            "customer_meta_iris_customer_id",
            field(&meta, "iris_customer_id").clone(),
        ),
    ];
    let id = insert_meta(db, &values).await?;
    rollback.add(
        format!("customersmeta row {id}"),
        Undo::Row {
            table: "customersmeta",
            id,
        },
    );
    let settings = insert_alert_settings(db, request).await?;
    rollback.add(
        format!("custom_alert_creation_settings row {settings}"),
        Undo::Row {
            table: "custom_alert_creation_settings",
            id: settings,
        },
    );
    let customer_meta = meta_dump(values, id, true);
    let answer = |message: String, worker: bool| {
        kwargs(vec![
            ("message", PyValue::Str(message)),
            ("success", PyValue::Bool(true)),
            ("customer_meta", customer_meta.clone()),
            ("wazuh_worker_provisioned", PyValue::Bool(worker)),
        ])
    };

    if matches!(
        field(request, "provision_wazuh_worker"),
        PyValue::Bool(true)
    ) {
        let worker = construct(
            &PROVISION_WORKER_REQUEST,
            &kwargs(
                [
                    "customer_name",
                    "customer_code",
                    "wazuh_auth_password",
                    "wazuh_registration_port",
                    "wazuh_logs_port",
                    "wazuh_api_port",
                    "wazuh_cluster_name",
                    "wazuh_cluster_key",
                    "wazuh_master_ip",
                ]
                .iter()
                .map(|k| (*k, field(request, k).clone()))
                .collect(),
            ),
        )?;
        let outcome = provision_wazuh_worker(c, worker).await?;
        if !field(&outcome, "success").truthy() {
            return Ok(answer(
                format!(
                    "Customer {name} provisioned successfully, but the Wazuh worker failed to \
                     provision"
                ),
                false,
            ));
        }
    }
    if matches!(field(request, "provision_ha_proxy"), PyValue::Bool(true)) {
        let haproxy = construct(
            &PROVISION_HAPROXY_REQUEST,
            &kwargs(vec![
                ("customer_name", field(request, "customer_name").clone()),
                (
                    "wazuh_registration_port",
                    field(request, "wazuh_registration_port").clone(),
                ),
                ("wazuh_logs_port", field(request, "wazuh_logs_port").clone()),
                (
                    "wazuh_worker_hostname",
                    field(request, "wazuh_worker_hostname").clone(),
                ),
            ]),
        )?;
        let outcome = provision_haproxy(c, haproxy).await?;
        if !field(&outcome, "success").truthy() {
            return Ok(answer(
                format!(
                    "Customer {name} provisioned successfully, but the HAProxy failed to provision"
                ),
                true,
            ));
        }
    }
    Ok(answer(
        format!("Customer {name} provisioned successfully"),
        true,
    ))
}

/// `dump[key] = value` (an attribute assigned on the model: not validated).
fn assign(dump: &mut PyValue, key: &str, value: PyValue) {
    if let PyValue::Dict(items) = dump {
        match items.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value,
            None => items.push((key.to_string(), value)),
        }
    }
}

fn worker_response(success: bool, message: impl Into<String>) -> PyValue {
    kwargs(vec![
        ("success", PyValue::Bool(success)),
        ("message", PyValue::Str(message.into())),
    ])
}

/// `run_blocking(requests.post, url, json=body, timeout=60)`: the status
/// and the text (a URL `requests` refuses is a `ValueError`).
async fn post(http: &PyHttp, url: String, body: &PyValue) -> PyResult<(u16, String)> {
    let resp = http
        .send(PyRequest::new(Method::POST, url).json(Some(body.clone())))
        .await
        .map_err(|e| match e {
            PyExc::Other("MissingSchema" | "InvalidURL" | "InvalidSchema", m) => {
                PyExc::ValueError(m)
            }
            other => other,
        })?;
    Ok((resp.status(), resp.text()))
}

/// `is_connector_verified(name)`.
async fn connector_verified(ctx: &AppContext, name: &str) -> PyResult<bool> {
    Ok(ctx
        .connectors
        .get(name)
        .await
        .map_err(db_err)?
        .is_some_and(|r| r.connector_verified))
}

/// `get_connector_attribute(connector_name=name, column_name="connector_url")`
/// as an f-string shows it (`None` without the row).
async fn connector_url(ctx: &AppContext, name: &str) -> PyResult<String> {
    Ok(ctx
        .connectors
        .get(name)
        .await
        .map_err(db_err)?
        .map_or_else(|| "None".to_string(), |r| r.connector_url))
}

/// `list_node_ips()`: each swarm node's `Status.Addr`.
async fn node_ips(c: Customer<'_>) -> PyResult<Vec<PyValue>> {
    let nodes = copilot_portainer::services::node_details(c.portainer).await?;
    Ok(match field(&nodes, "nodes") {
        PyValue::List(items) => items
            .iter()
            .map(|n| field(field(n, "Status"), "Addr").clone())
            .collect(),
        _ => Vec::new(),
    })
}

/// `provision_wazuh_worker(request)`: the `ProvisionWorkerResponse` dump.
pub async fn provision_wazuh_worker(c: Customer<'_>, mut request: PyValue) -> PyResult<PyValue> {
    tracing::info!("Provisioning Wazuh worker");
    if !connector_verified(c.ctx, "Portainer").await? {
        let endpoint = connector_url(c.ctx, "Wazuh Worker Provisioning").await?;
        tracing::info!("Wazuh Worker API endpoint: {endpoint}");
        assign(&mut request, "portainer_deployment", PyValue::Bool(false));
        let version = wazuh_manager_version(c).await?;
        assign(&mut request, "wazuh_manager_version", version);
        let (status, body) = post(c.http, format!("{endpoint}/provision_worker"), &request).await?;
        tracing::info!("Status code from Wazuh Worker: {status}");
        if status != 200 {
            return Ok(worker_response(
                false,
                format!("Failed to provision Wazuh worker: {body}"),
            ));
        }
        return Ok(worker_response(
            true,
            "Wazuh worker provisioned successfully",
        ));
    }
    assign(&mut request, "portainer_deployment", PyValue::Bool(true));
    let ips = node_ips(c).await?;
    for (index, ip) in ips.iter().enumerate() {
        assign(&mut request, "node_id", s(&(index + 1).to_string()));
        let url = format!(
            "http://{}:{}/provision_worker",
            ip.py_str(),
            c.env.provision_worker_port()
        );
        let (status, body) = post(c.http, url, &request).await?;
        tracing::info!("Status code from Wazuh Worker: {status}");
        if status != 200 {
            return Ok(worker_response(
                false,
                format!("Failed to provision Wazuh worker: {body}"),
            ));
        }
    }
    let stack = create_wazuh_customer_stack(c, &request).await?;
    update_stack_id(
        c.tools.db,
        &text(&request, "customer_name"),
        field(field(&stack, "data"), "Id"),
    )
    .await?;
    Ok(worker_response(
        true,
        "Wazuh worker provisioned successfully via Portainer",
    ))
}

/// `provision_haproxy(request)`: the `ProvisionWorkerResponse` dump.
async fn provision_haproxy(c: Customer<'_>, mut request: PyValue) -> PyResult<PyValue> {
    tracing::info!("Provisioning HAProxy");
    let portainer = connector_verified(c.ctx, "Portainer").await?;
    if portainer {
        assign(&mut request, "portainer_deployment", PyValue::Bool(true));
        let ips = node_ips(c).await?;
        assign(&mut request, "swarm_nodes", PyValue::List(ips));
    }
    let endpoint = connector_url(c.ctx, "HAProxy Provisioning").await?;
    tracing::info!("HAProxy API endpoint: {endpoint}");
    if !portainer {
        assign(&mut request, "portainer_deployment", PyValue::Bool(false));
    }
    let (status, body) = post(
        c.http,
        format!("{endpoint}/provision_worker/haproxy"),
        &request,
    )
    .await?;
    if status != 200 {
        return Ok(worker_response(
            false,
            format!("Failed to provision HAProxy: {body}"),
        ));
    }
    Ok(worker_response(
        true,
        if portainer {
            "HAProxy provisioned successfully via Portainer"
        } else {
            "HAProxy provisioned successfully"
        },
    ))
}

/// The stack template with `variables` replaced in turn
/// (`template.replace(placeholder, value)`: a value that is not a `str` is
/// the `TypeError`).
pub fn render_stack(variables: &[(&str, PyValue)]) -> PyResult<String> {
    let mut template = WAZUH_WORKER_STACK.to_string();
    for (placeholder, value) in variables {
        let PyValue::Str(value) = value else {
            return Err(PyExc::TypeError(format!(
                "replace() argument 2 must be str, not {}",
                match value {
                    PyValue::None => "None",
                    other => copilot_upstream::py::type_name(other),
                }
            )));
        };
        template = template.replace(placeholder, value);
    }
    Ok(template)
}

/// `_prepare_template_variables(request, node_count)`, in the dict's order.
pub fn stack_variables(
    request: &PyValue,
    version: PyValue,
    node_count: usize,
) -> Vec<(&'static str, PyValue)> {
    let name = text(request, "customer_name").replace(' ', "_");
    let code = text(request, "customer_code").replace(' ', "_");
    vec![
        ("{{ wazuh_worker_customer_code }}", s(&code)),
        ("{{ wazuh_manager_version }}", version),
        ("REPLACE_LOG", field(request, "wazuh_logs_port").clone()),
        (
            "REPLACE_REGISTRATION",
            field(request, "wazuh_registration_port").clone(),
        ),
        ("REPLACE_API", field(request, "wazuh_api_port").clone()),
        ("NUMBER_OF_NODES", s(&node_count.to_string())),
        ("customer_name", s(&name)),
        ("customer_code", s(&code)),
    ]
}

/// `create_wazuh_customer_stack(request)`: the `StackResponse` dump.
pub async fn create_wazuh_customer_stack(c: Customer<'_>, request: &PyValue) -> PyResult<PyValue> {
    tracing::info!(
        "Creating Wazuh stack for customer {}",
        text(request, "customer_name")
    );
    let node_count = node_ips(c).await?.len();
    let version = wazuh_manager_version(c).await?;
    let variables = stack_variables(request, version, node_count);
    let code = text(request, "customer_code").replace(' ', "_");
    let template = render_stack(&variables)?;
    let endpoint_id = copilot_portainer::services::endpoint_id(c.portainer).await?;
    let swarm_id = copilot_portainer::services::swarm_id(c.portainer).await?;
    let payload = kwargs(vec![
        ("Name", s(&format!("wazuh-worker-{code}"))),
        ("StackFileContent", PyValue::Str(template)),
        ("SwarmID", swarm_id),
        ("Env", PyValue::List(Vec::new())),
    ]);
    copilot_portainer::services::create_stack(c.portainer, &endpoint_id, payload).await
}

#[cfg(test)]
mod vectors;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_templates_have_no_carriage_return() {
        for t in [LINUX_AGENT, WINDOWS_AGENT, MAC_AGENT, WAZUH_WORKER_STACK] {
            assert!(!t.contains('\r'));
        }
    }

    #[test]
    fn group_configuration_keeps_python_s_split() {
        let out = group_configuration("<a>REPLACE</a><b>CLUSTER_NAME</b>", "Linux_AB_C", &s(""));
        assert_eq!(out, "<a>C</a><b>YOUR_PATH</b>");
        let out = group_configuration("REPLACE CLUSTER_NAME", "Mac_X", &s("prod"));
        assert_eq!(out, "X prod");
    }
}
