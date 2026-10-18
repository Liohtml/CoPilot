//! The integrations' `POST /provision` routes —
//! `app/integrations/{huntress,darktrace,duo,cato,carbonblack,mimecast,
//! sap_siem}/{routes,services,schema}/provision.py`, which differ only in
//! data ([`INTEGRATIONS`]), and `socfortress_mdr`'s, which only marks the
//! integration deployed ([`provision_mdr`]).
//!
//! Python's order, on the default `Graylog` connector:
//!
//! 1. the customer's integrations (404 without any);
//! 2. the index set (`<customer name> - <X>`, the prefix, 30 indices, no
//!    replica, one shard per indexer node or one), the event stream (two
//!    rules — `integration`, then `customer_code` — through
//!    `create_entity`, wrapped for Graylog 7), the stream resumed;
//! 3. the Grafana datasource, folder and dashboards;
//! 4. `create_integration_meta` (`copilot-integrations`' checks: the customer,
//!    its meta row, an existing row refused with the 400; an insert that fails
//!    is swallowed), the `deployed` flag;
//! 5. the scheduler jobs, one `add_scheduler_jobs` per job as the Python
//!    route calls it ([`hand_jobs`], `copilot-scheduler`: under the hand-over
//!    APScheduler's `add_job` goes to the Python process, the rows are
//!    written here).
//!
//! Nothing is rolled back, as in Python. One deliberate difference: the
//! body's `customer_code` must be one of the caller's customers (403, §4).

use copilot_auth::pyvalue::PyValue;
use copilot_grafana_dashboards::templates::{self as dashboards, DashboardClass};
use copilot_graylog::client::DEFAULT_CONNECTOR;
use copilot_integrations::integrations::schema::{
    CUSTOMER_INTEGRATIONS_META_SCHEMA, customer_integration_dump,
};
use copilot_integrations::integrations::services::create_meta_validated;
use copilot_integrations::integrations::store::{CustomerIntegration, customer_integrations};
use copilot_upstream::model::{Field, Model, Ty, construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::grafana::{self, Datasource};
use crate::graylog::{self, IndexSet};
use crate::network::{Tools, provision_dashboards};
use crate::store;

/// Where a job's interval comes from.
#[derive(Debug, Clone, Copy)]
pub enum Interval {
    /// The request's `time_interval`.
    Request,
    /// A fixed number of minutes.
    Fixed(i64),
}

/// The shard count of the index set.
#[derive(Debug, Clone, Copy)]
pub enum Shards {
    /// `output_shard_number_to_be_set_based_on_nodes()`.
    Nodes,
    /// A fixed count.
    Fixed(i64),
}

/// What one integration's provisioning varies.
#[derive(Debug)]
pub struct Integration {
    /// The router's prefix (`/api/<route>/provision`).
    pub route: &'static str,
    /// The request model (its `integration_name` forced by the
    /// `mode="before"` validator).
    pub request: &'static Model,
    /// The forced `integration_name`.
    pub request_name: &'static str,
    /// The index set's title after `<customer name> - `.
    pub index_title: &'static str,
    /// The index set's description after `<customer code> - `.
    pub index_description: &'static str,
    /// `index_prefix`.
    pub index_prefix: fn(&str) -> String,
    /// The shard count.
    pub shards: Shards,
    /// The stream's title and description after `<customer name> - `.
    pub stream_title: &'static str,
    /// The `integration` stream rule's value.
    pub stream_value: &'static str,
    /// The datasource's name.
    pub datasource: &'static str,
    /// The datasource's database before `<code>*`.
    pub database: &'static str,
    /// `jsonData.logLevelField`.
    pub log_level_field: &'static str,
    /// `jsonData.logMessageField`.
    pub log_message_field: &'static str,
    /// The folder's title.
    pub folder: &'static str,
    /// The dashboards provisioned.
    pub dashboards: &'static DashboardClass,
    /// The meta row's `integration_name` and the `deployed` row's service.
    pub meta_name: &'static str,
    /// The scheduler jobs (function name = job id), in the route's order.
    pub jobs: &'static [(&'static str, Interval)],
    /// The success message.
    pub message: &'static str,
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn fifteen() -> PyValue {
    PyValue::Int("15".into())
}

macro_rules! forced {
    ($fname:ident, $value:expr) => {
        fn $fname() -> PyValue {
            PyValue::Str($value.into())
        }
    };
}

forced!(huntress, "Huntress");
forced!(darktrace, "Darktrace");
forced!(duo, "Duo");
forced!(cato, "Cato");
forced!(carbonblack, "CarbonBlack");
forced!(mimecast, "Mimecast");
forced!(sap_siem, "SAP SIEM");
forced!(mdr, "SOCFortress MDR");

/// `ProvisionHuntressRequest`.
pub static PROVISION_HUNTRESS_REQUEST: Model = Model::new(
    "ProvisionHuntressRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("time_interval", Ty::Int),
        Field::def("integration_name", Ty::Str, huntress),
    ],
);

/// `ProvisionDarktraceRequest`.
pub static PROVISION_DARKTRACE_REQUEST: Model = Model::new(
    "ProvisionDarktraceRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("time_interval", Ty::Int, fifteen),
        Field::def("integration_name", Ty::Str, darktrace),
    ],
);

/// `ProvisionDuoRequest`.
pub static PROVISION_DUO_REQUEST: Model = Model::new(
    "ProvisionDuoRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("time_interval", Ty::Int, fifteen),
        Field::def("integration_name", Ty::Str, duo),
    ],
);

/// `ProvisionCatoRequest`.
pub static PROVISION_CATO_REQUEST: Model = Model::new(
    "ProvisionCatoRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("time_interval", Ty::Int),
        Field::def("integration_name", Ty::Str, cato),
    ],
);

/// `ProvisionCarbonBlackRequest`.
pub static PROVISION_CARBONBLACK_REQUEST: Model = Model::new(
    "ProvisionCarbonBlackRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("time_interval", Ty::Int),
        Field::def("integration_name", Ty::Str, carbonblack),
    ],
);

/// `ProvisionMimecastRequest`.
pub static PROVISION_MIMECAST_REQUEST: Model = Model::new(
    "ProvisionMimecastRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, mimecast),
    ],
);

/// `ProvisionSapSiemRequest`.
pub static PROVISION_SAP_SIEM_REQUEST: Model = Model::new(
    "ProvisionSapSiemRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("time_interval", Ty::Int),
        Field::def("integration_name", Ty::Str, sap_siem),
    ],
);

/// `ProvisionSOCFortressMDRRequest` (no validator: `integration_name` is
/// the body's).
pub static PROVISION_MDR_REQUEST: Model = Model::new(
    "ProvisionSOCFortressMDRRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, mdr),
    ],
);

/// The seven integrations that stand up Graylog and Grafana objects.
pub static INTEGRATIONS: &[Integration] = &[
    Integration {
        route: "huntress",
        request: &PROVISION_HUNTRESS_REQUEST,
        request_name: "Huntress",
        index_title: "HUNTRESS",
        index_description: "HUNTRESS",
        index_prefix: |code| format!("huntress_{code}"),
        shards: Shards::Nodes,
        stream_title: "HUNTRESS",
        stream_value: "huntress",
        datasource: "HUNTRESS",
        database: "huntress_",
        log_level_field: "severity",
        log_message_field: "summary",
        folder: "HUNTRESS",
        dashboards: &dashboards::HUNTRESS,
        meta_name: "Huntress",
        jobs: &[("invoke_huntress_integration_collect", Interval::Request)],
        message: "Huntress integration provisioned successfully.",
    },
    Integration {
        route: "darktrace",
        request: &PROVISION_DARKTRACE_REQUEST,
        request_name: "Darktrace",
        index_title: "DARKTRACE",
        index_description: "DARKTRACE",
        index_prefix: |code| format!("darktrace-{}-", code.to_lowercase()),
        shards: Shards::Nodes,
        stream_title: "DARKTRACE",
        stream_value: "darktrace",
        datasource: "DARKTRACE",
        database: "darktrace-",
        log_level_field: "severity",
        log_message_field: "summary",
        folder: "DARKTRACE",
        dashboards: &dashboards::DARKTRACE,
        meta_name: "Darktrace",
        jobs: &[("invoke_darktrace_integration_collect", Interval::Request)],
        message: "Darktrace integration provisioned successfully.",
    },
    Integration {
        route: "duo",
        request: &PROVISION_DUO_REQUEST,
        request_name: "Duo",
        index_title: "DUO",
        index_description: "DUO",
        index_prefix: |code| format!("duo-{}", code.to_lowercase()),
        shards: Shards::Nodes,
        stream_title: "DUO",
        stream_value: "duo",
        datasource: "DUO",
        database: "duo-",
        log_level_field: "severity",
        log_message_field: "summary",
        folder: "DUO",
        dashboards: &dashboards::DUO,
        meta_name: "Duo",
        jobs: &[("invoke_duo_integration_collect", Interval::Request)],
        message: "Duo integration provisioned successfully.",
    },
    Integration {
        route: "cato",
        request: &PROVISION_CATO_REQUEST,
        request_name: "Cato",
        index_title: "Cato",
        index_description: "CATO",
        index_prefix: |code| format!("cato_{code}"),
        shards: Shards::Nodes,
        stream_title: "CATO",
        stream_value: "cato",
        datasource: "CATO NETWORKS",
        database: "cato_",
        log_level_field: "severity",
        log_message_field: "summary",
        folder: "CATO",
        dashboards: &dashboards::CATO,
        meta_name: "CATO",
        jobs: &[("invoke_cato_integration_collect", Interval::Request)],
        message: "Cato integration provisioned successfully.",
    },
    Integration {
        route: "carbonblack",
        request: &PROVISION_CARBONBLACK_REQUEST,
        request_name: "CarbonBlack",
        index_title: "CARBONBLACK",
        index_description: "CARBONBLACK",
        index_prefix: |code| format!("carbonblack-{code}"),
        shards: Shards::Nodes,
        stream_title: "CARBONBLACK",
        stream_value: "carbonblack",
        datasource: "CARBONBLACK",
        database: "carbonblack-",
        log_level_field: "severity",
        log_message_field: "summary",
        folder: "CARBONBLACK",
        dashboards: &dashboards::CARBON_BLACK,
        meta_name: "CarbonBlack",
        jobs: &[(
            "invoke_carbonblack_integration_collection",
            Interval::Request,
        )],
        message: "CarbonBlack provisioned successfully",
    },
    Integration {
        route: "mimecast",
        request: &PROVISION_MIMECAST_REQUEST,
        request_name: "Mimecast",
        index_title: "Mimecast",
        index_description: "Mimecast",
        index_prefix: |code| format!("mimecast_{code}"),
        shards: Shards::Fixed(1),
        stream_title: "Mimecast",
        stream_value: "mimecast",
        datasource: "MIMECAST",
        database: "mimecast_",
        log_level_field: "syslog_level",
        log_message_field: "rule_description",
        folder: "MIMECAST",
        dashboards: &dashboards::MIMECAST,
        meta_name: "Mimecast",
        jobs: &[
            ("invoke_mimecast_integration_ttp", Interval::Fixed(15)),
            ("invoke_mimecast_integration", Interval::Fixed(5)),
        ],
        message: "Mimecast integration provisioned.",
    },
    Integration {
        route: "sap_siem",
        request: &PROVISION_SAP_SIEM_REQUEST,
        request_name: "SAP SIEM",
        index_title: "SAP SIEM",
        index_description: "SAP SIEM",
        index_prefix: |code| format!("sap_siem_{code}"),
        shards: Shards::Fixed(1),
        stream_title: "SAP SIEM",
        stream_value: "sap_siem",
        datasource: "SAP SIEM",
        database: "sap_siem_",
        log_level_field: "level",
        log_message_field: "params_loginID",
        folder: "SAP SIEM",
        dashboards: &dashboards::SAP_SIEM,
        meta_name: "SAP SIEM",
        jobs: &[
            ("invoke_sap_siem_integration_collection", Interval::Request),
            (
                "invoke_sap_siem_integration_suspicious_logins_analysis",
                Interval::Request,
            ),
            (
                "invoke_sap_siem_integration_multiple_logins_same_ip_analysis",
                Interval::Request,
            ),
        ],
        message: "SAP SIEM integration provisioned successfully.",
    },
];

fn py(e: PyExc) -> ApiError {
    e.unhandled()
}

fn db(e: impl std::fmt::Display) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

/// `get_customer_integration_response(code, session)`: the customer's
/// integrations (`CustomerIntegrationsResponse` built over them), 404 without
/// any.
pub async fn integrations_of(ctx: &AppContext, code: &str) -> PyResult<Vec<CustomerIntegration>> {
    let list = customer_integrations(&ctx.db, Some(code))
        .await
        .map_err(db)?;
    for ci in &list {
        customer_integration_dump(ci, false)
            .map_err(|e| PyExc::Other("ValidationError", e.into()))?;
    }
    if list.is_empty() {
        return Err(PyExc::http(404, "Customer integration settings not found."));
    }
    Ok(list)
}

/// `(await get_customer(code, session)).customer.customer_name` (404 for an
/// unknown customer).
async fn customer_name(ctx: &AppContext, code: &str) -> PyResult<String> {
    copilot_db::customers::find_customer(&ctx.db, code)
        .await
        .map_err(db)?
        .map(|c| c.customer_name)
        .ok_or_else(|| PyExc::http(404, format!("Customer with customer_code {code} not found")))
}

/// `provision_<x>(request, session)` — the integration's objects, its meta
/// row and `deployed`.
pub async fn provision(
    ctx: &AppContext,
    tools: Tools<'_>,
    integration: &Integration,
    code: &str,
) -> Result<(), ApiError> {
    let (gl, conn) = (tools.graylog, DEFAULT_CONNECTOR);
    // `build_index_set_config`: the keyword arguments in order.
    let title = format!(
        "{} - {}",
        customer_name(ctx, code).await.map_err(py)?,
        integration.index_title
    );
    let creation_date = graylog::creation_date();
    let shards = match integration.shards {
        Shards::Nodes => grafana::shard_number(tools.wazuh).await.map_err(py)?,
        Shards::Fixed(n) => PyValue::Int(n.to_string()),
    };
    let index_set = graylog::index_set_config(&IndexSet {
        title,
        description: format!("{code} - {}", integration.index_description),
        index_prefix: (integration.index_prefix)(code),
        max_indices: PyValue::Int("30".into()),
        shards,
        replicas: PyValue::Int("0".into()),
        creation_date,
    })
    .map_err(py)?;
    let index_set_id = graylog::create_index_set(gl, conn, index_set)
        .await
        .map_err(py)?;
    let stream_title = format!(
        "{} - {}",
        customer_name(ctx, code).await.map_err(py)?,
        integration.stream_title
    );
    let stream_description = format!(
        "{} - {}",
        customer_name(ctx, code).await.map_err(py)?,
        integration.stream_title
    );
    let stream = graylog::event_stream_config(
        &stream_title,
        &stream_description,
        &index_set_id,
        vec![
            ("integration", integration.stream_value.to_string()),
            ("customer_code", code.to_string()),
        ],
    )
    .map_err(py)?;
    let stream_id = graylog::create_event_stream(gl, conn, stream)
        .await
        .map_err(py)?;
    copilot_graylog::services::start_stream(gl, &stream_id.py_str())
        .await
        .map_err(py)?;

    // Grafana.
    let datasource_uid = grafana::create_datasource(
        tools.db,
        tools.grafana,
        tools.wazuh,
        code,
        &Datasource {
            name: integration.datasource.to_string(),
            database: format!("{}{code}*", integration.database),
            log_level_field: integration.log_level_field,
            log_message_field: integration.log_message_field,
            data_links: None,
        },
    )
    .await
    .map_err(py)?;
    let org = store::grafana_org_id(tools.db, code).await.map_err(py)?;
    let folder = grafana::create_folder(tools.grafana, &org, integration.folder)
        .await
        .map_err(py)?;
    provision_dashboards(
        tools,
        integration.dashboards,
        code,
        &folder,
        &datasource_uid,
    )
    .await
    .map_err(py)?;

    // `create_integration_meta_entry` (its answer ignored), then `deployed`.
    let org = store::grafana_org_id(tools.db, code).await.map_err(py)?;
    let meta = construct(
        &CUSTOMER_INTEGRATIONS_META_SCHEMA,
        &kwargs(vec![
            ("customer_code", s(code)),
            ("integration_name", s(integration.meta_name)),
            ("graylog_input_id", PyValue::None),
            ("graylog_index_id", index_set_id),
            ("graylog_stream_id", stream_id),
            ("grafana_org_id", PyValue::Str(org)),
            ("grafana_dashboard_folder_id", field(&folder, "id").clone()),
            ("grafana_datasource_uid", datasource_uid),
        ]),
    )
    .map_err(py)?;
    // Its insert cannot fail on values that fit the columns; one MySQL
    // refused would leave Python's session in need of a rollback, failing
    // the update below (unreachable: every value is an id Graylog or Grafana
    // gave, the organization and the customer's code).
    create_meta_validated(ctx, &meta).await?;
    set_deployed(ctx, code, integration.meta_name)
        .await
        .map_err(py)
}

/// `update_customer_integration_table(code, session)`: every row of the
/// customer and service set deployed.
pub async fn set_deployed(ctx: &AppContext, code: &str, service: &str) -> PyResult<()> {
    sqlx::query(
        "UPDATE customer_integrations SET deployed=1 WHERE customer_integrations.customer_code = \
         ? AND customer_integrations.integration_service_name = ?",
    )
    .bind(code)
    .bind(service)
    .persistent(false)
    .execute(ctx.db.pool())
    .await
    .map_err(db)?;
    Ok(())
}

/// The jobs of `integration` for a request (`time_interval` as validated).
pub fn jobs(integration: &Integration, request: &PyValue) -> Vec<PyValue> {
    integration
        .jobs
        .iter()
        .map(|(job, interval)| {
            let minutes = match interval {
                Interval::Request => field(request, "time_interval").clone(),
                Interval::Fixed(n) => PyValue::Int(n.to_string()),
            };
            kwargs(vec![
                ("function_name", s(job)),
                ("job_id", s(job)),
                ("time_interval", minutes),
            ])
        })
        .collect()
}

/// `add_scheduler_jobs(...)` for each job, in the route's order, through
/// this service's scheduler (`copilot_scheduler::writes`): the rows and the
/// grid here; APScheduler's `add_job` handed to the Python process while it
/// owns the schedule, nothing reaching it under `COPILOT_SCHEDULER_OWNER=rust`.
/// A failure is the one Python's `add_scheduler_jobs` raises (APScheduler's
/// own, or no Python backend: the bare 500).
pub async fn hand_jobs(
    scheduler: &copilot_scheduler::Scheduler,
    user: &CurrentUser,
    jobs: Vec<PyValue>,
) -> Result<(), ApiError> {
    let requests: Vec<copilot_scheduler::writes::JobRequest> = jobs
        .iter()
        .map(|j| copilot_scheduler::writes::JobRequest {
            function_name: field(j, "function_name").py_str(),
            job_id: field(j, "job_id").py_str(),
            time_interval: match field(j, "time_interval") {
                PyValue::Int(n) => n.parse::<i128>().unwrap_or(if n.starts_with('-') {
                    i128::MIN
                } else {
                    i128::MAX
                }),
                PyValue::Bool(b) => i128::from(*b),
                _ => 0,
            },
        })
        .collect();
    copilot_scheduler::writes::add_scheduler_jobs(scheduler, user, &requests).await
}

/// `POST /api/socfortress_mdr/provision`: the `COLLECTOR_UUID` key of the
/// integration named in the body (`find_customer_integration`: the first
/// with a subscription of that service), then `deployed`.
pub async fn provision_mdr(ctx: &AppContext, request: &PyValue) -> PyResult<PyValue> {
    let code = field(request, "customer_code").py_str();
    let name = field(request, "integration_name").py_str();
    let list = integrations_of(ctx, &code).await?;
    let serves = |ci: &&CustomerIntegration| {
        ci.subscriptions
            .iter()
            .any(|s| s.service.as_ref().is_some_and(|v| v.service_name == name))
    };
    let Some(ci) = list.iter().find(serves) else {
        return Err(PyExc::AttributeError(
            "'NoneType' object has no attribute 'integration_subscriptions'".into(),
        ));
    };
    let mut collector = None;
    'found: for sub in &ci.subscriptions {
        if sub
            .service
            .as_ref()
            .is_some_and(|v| v.service_name == MDR_SERVICE)
        {
            for key in &sub.keys {
                if key.auth_key_name == "COLLECTOR_UUID" {
                    collector = Some(key.auth_value.clone());
                    break 'found;
                }
            }
        }
    }
    let Some(collector) = collector else {
        return Err(PyExc::http(
            404,
            "COLLECTOR_UUID auth key not found for the SOCFortress MDR integration. Add the \
             integration with a COLLECTOR_UUID before deploying.",
        ));
    };
    // `str.strip()`: CPython's whitespace is Unicode's and the four
    // information separators U+001C–U+001F.
    if collector
        .trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
        .is_empty()
    {
        return Err(PyExc::http(
            400,
            "COLLECTOR_UUID is empty. Provide the MDR collector UUID before deploying.",
        ));
    }
    set_deployed(ctx, &code, MDR_SERVICE).await?;
    Ok(kwargs(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            s("SOCFortress MDR integration provisioned successfully."),
        ),
    ]))
}

/// `INTEGRATION_NAME` of the MDR module.
pub const MDR_SERVICE: &str = "SOCFortress MDR";
