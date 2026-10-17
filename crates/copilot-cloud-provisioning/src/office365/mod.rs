//! `POST /api/office365/provision` — `app/integrations/office365/` (routes,
//! `services/provision.py`): one Microsoft 365 tenant of a customer.
//!
//! What is per tenant is the Wazuh `<api_auth>` block and the Graylog stream
//! whose rule pins the tenant's organization id; what the customer's tenants
//! share is the `office365-<code>` index set and the Grafana datasource,
//! folder and dashboards (reused from the first metadata row found). In
//! Python's order, inside one `try`:
//!
//! 1. the manager's `ossec.conf` (`GET /manager/configuration?raw=True`,
//!    `response["data"]`), the tenant refused when its id is anywhere in it
//!    (400), the block added ([`config`]) and pushed (`PUT`, octet-stream;
//!    refused, it is tried once more without the `<api_type>` tag — a refusal
//!    then is only logged); the manager restarted;
//! 2. Graylog: the six pipeline rules (missing ones created, the broken
//!    `Office365 Timestamp - UTC` of earlier versions repaired), the
//!    pipeline, the index set unless reused, the tenant's stream (wrapped
//!    for Graylog 7), connected to the pipeline and resumed;
//! 3. Grafana unless reused: the `O365` datasource (its data link to
//!    connector id 12's URL), the `OFFICE 365` folder, the dashboards;
//! 4. the metadata row (`create_integration_meta`), `deployed` on this
//!    instance, the customer's legacy single-tenant column while empty.
//!
//! Any failure rolls back what this run created, newest-first ([`Rollback`]),
//! and answers `Office365 deployment failed and was rolled back: …` with the
//! failure's status (500 for anything but an `HTTPException`). One
//! deliberate difference (§4): the body's customer must be the caller's.

pub mod config;
pub mod schema;

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_grafana_dashboards::templates as dashboards;
use copilot_integration_provisioning::grafana::{self as grafana_steps, Datasource};
use copilot_integration_provisioning::graylog::{self as graylog_steps, IndexSet};
use copilot_integration_provisioning::store as prov_store;
use copilot_integrations::integrations::schema::CUSTOMER_INTEGRATIONS_META_SCHEMA;
use copilot_integrations::integrations::services::create_meta_validated;
use copilot_integrations::integrations::store as int_store;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_wazuh::manager::client::{self, Body, Param, PutKind};
use copilot_web::ApiError;
use serde_json::Value;

use crate::Tools;
use crate::graylog;
use crate::rollback::{Rollback, Style, Undo, detail_or_str, failure};
use config::Keys;
use schema::*;

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

/// A database failure as the exception SQLAlchemy raises.
pub fn db(e: impl std::fmt::Display) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

/// An `ApiError` a reused Rust service returned, as the Python exception.
pub fn api_exc(e: ApiError) -> PyExc {
    match e {
        ApiError::Http {
            status,
            detail: Value::String(detail),
        } => PyExc::Http(status.as_u16(), detail),
        ApiError::Http { status, detail } => PyExc::Http(status.as_u16(), detail.to_string()),
        other => PyExc::Other("Exception", other.to_string()),
    }
}

/// `response["data"]` of a helper's answer dict.
fn data_of(response: &Value) -> PyResult<Value> {
    match response {
        Value::Object(m) => m
            .get("data")
            .cloned()
            .ok_or_else(|| PyExc::key_error("data")),
        Value::Null => Err(PyExc::TypeError(
            "'NoneType' object is not subscriptable".into(),
        )),
        _ => Err(PyExc::key_error("data")),
    }
}

fn wazuh(e: copilot_wazuh::error::PyErr) -> PyExc {
    copilot_integration_provisioning::grafana::wazuh_exc(e)
}

/// Python truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `x == 0` (`False` and `0.0` are equal to `0`).
pub fn equals_zero(v: &Value) -> bool {
    match v {
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        _ => false,
    }
}

/// `response.get("success") and response["data"].get("error") == 0`: `Err`
/// where Python raises (a `None` answer, no `data`, a `data` that is not a
/// dict).
fn put_accepted(response: &Value) -> Result<bool, PyExc> {
    let Value::Object(m) = response else {
        return Err(PyExc::AttributeError(
            "'NoneType' object has no attribute 'get'".into(),
        ));
    };
    if !m.get("success").is_some_and(truthy) {
        return Ok(false);
    }
    match m.get("data") {
        None => Err(PyExc::key_error("data")),
        Some(Value::Object(d)) => Ok(d.get("error").is_some_and(equals_zero)),
        Some(_) => Err(PyExc::AttributeError(
            "object has no attribute 'get'".into(),
        )),
    }
}

/// `get_wazuh_configuration(...)`: the manager's raw `ossec.conf`.
pub async fn manager_configuration(tools: Tools<'_>) -> PyResult<String> {
    let params = vec![("raw".to_string(), Param::Bool(true))];
    let response = client::send_get(tools.wazuh, "/manager/configuration", Some(&params))
        .await
        .map_err(wazuh)?;
    match data_of(&response)? {
        Value::String(text) => Ok(text),
        other => Err(PyExc::TypeError(format!(
            "write() argument must be str, not {}",
            json_type(&other)
        ))),
    }
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "None",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `update_wazuh_configuration(keys)` on the text the edit left.
async fn update_configuration(tools: Tools<'_>, file: &str, keys: &Keys) -> PyResult<()> {
    let endpoint = "/manager/configuration";
    let first = client::send_put(
        tools.wazuh,
        endpoint,
        Some(Body::Bytes(file.as_bytes().to_vec())),
        None,
        PutKind::Binary,
    )
    .await
    .map_err(wazuh)
    .and_then(|r| put_accepted(&r));
    match first {
        Ok(true) => {
            tracing::info!("Wazuh configuration updated successfully.");
            return Ok(());
        }
        Ok(false) => tracing::error!("Failed to update Wazuh configuration."),
        Err(e) => tracing::error!(
            "Exception occurred during Wazuh configuration update: {}",
            e.display()
        ),
    }
    let modified = config::without_api_type(file, keys);
    let second = client::send_put(
        tools.wazuh,
        endpoint,
        Some(Body::Bytes(modified.into_bytes())),
        None,
        PutKind::Binary,
    )
    .await
    .map_err(wazuh)
    .and_then(|r| put_accepted(&r));
    match second {
        Ok(true) => tracing::info!(
            "Wazuh configuration updated successfully after removing <api_type> tag."
        ),
        Ok(false) => {
            tracing::error!("Failed to update Wazuh configuration after removing <api_type> tag.")
        }
        Err(e) => {
            tracing::error!(
                "Exception occurred during retry of Wazuh configuration update: {}",
                e.display()
            );
            return Err(PyExc::http(500, "Failed to update Wazuh configuration."));
        }
    }
    Ok(())
}

/// `restart_wazuh_manager()` (the answer is not looked at).
pub async fn restart_manager(tools: Tools<'_>) -> PyResult<()> {
    tracing::info!("Restarting Wazuh manager service.");
    client::send_put(tools.wazuh, "/manager/restart", None, None, PutKind::Json)
        .await
        .map_err(wazuh)?;
    Ok(())
}

/// The rules `repair_pipeline_rules` may rewrite: title → the marker of the
/// broken source.
const BROKEN_RULE_MARKERS: [(&str, &str); 1] =
    [(OFFICE365_TIMESTAMP, "data_office_365_CreationTime")];

fn rule_source(title: &str) -> String {
    match title {
        OFFICE365_TIMESTAMP => graylog::office365_utc_rule_source(title),
        OFFICE365_SYSLOG_TYPE => graylog::office365_syslog_type_rule_source(title),
        other => graylog::wazuh_rule_source(other).unwrap_or_default(),
    }
}

/// `check_pipeline_rules()`: the missing rules created, a broken earlier
/// version repaired.
async fn check_pipeline_rules(tools: Tools<'_>) -> PyResult<()> {
    let gl = tools.graylog;
    let rules = graylog::pipeline_rules(gl).await?;
    let missing: Vec<&str> = PIPELINE_RULE_TITLES
        .iter()
        .copied()
        .filter(|t| !rules.iter().any(|r| r.title == *t))
        .collect();
    for title in missing {
        tracing::info!("Creating pipeline rule {title}.");
        graylog::create_rule(gl, title, title, &rule_source(title)).await?;
    }
    for rule in &rules {
        let Some((_, marker)) = BROKEN_RULE_MARKERS.iter().find(|(t, _)| *t == rule.title) else {
            continue;
        };
        if !rule.source.contains(marker) {
            continue;
        }
        let description = match rule.description.as_deref() {
            Some(d) if !d.is_empty() => d.to_string(),
            _ => rule.title.clone(),
        };
        let (ok, message) = graylog::put_source(
            gl,
            &format!("/api/system/pipelines/rule/{}", rule.id),
            &rule.title,
            &description,
            &graylog::office365_utc_rule_source(&rule.title),
        )
        .await?;
        if ok {
            tracing::info!("Repaired pipeline rule {} (it read {marker})", rule.title);
        } else {
            tracing::error!(
                "Could not repair pipeline rule {}: {}",
                rule.title,
                message.unwrap_or_else(|| "None".into())
            );
        }
    }
    Ok(())
}

/// The OFFICE365 PROCESSING PIPELINE's source.
pub fn pipeline_source() -> String {
    format!(
        "pipeline \"{PIPELINE_TITLE}\"\nstage 0 match either\nrule \"{}\"\nrule \"{}\"\nrule \
         \"{}\"\nrule \"{}\"\nrule \"{OFFICE365_TIMESTAMP}\"\nrule \"{OFFICE365_SYSLOG_TYPE}\"\nend",
        graylog::WAZUH_ALERT,
        graylog::WAZUH_INFO,
        graylog::WAZUH_NOTICE,
        graylog::WAZUH_WARNING,
    )
}

/// `check_pipeline()`.
async fn check_pipeline(tools: Tools<'_>) -> PyResult<()> {
    let pipelines = graylog::pipelines(tools.graylog).await?;
    if !pipelines.iter().any(|p| p.title == PIPELINE_TITLE) {
        tracing::info!("Creating pipeline {PIPELINE_TITLE}.");
        graylog::create_pipeline(
            tools.graylog,
            PIPELINE_TITLE,
            PIPELINE_TITLE,
            &pipeline_source(),
        )
        .await?;
    }
    Ok(())
}

/// `(await get_customer(code, session)).customer.customer_name`.
pub async fn customer_name(db: &Db, code: &str) -> PyResult<String> {
    copilot_db::customers::find_customer(db, code)
        .await
        .map_err(crate::office365::db)?
        .map(|c| c.customer_name)
        .ok_or_else(|| PyExc::http(404, format!("Customer with customer_code {code} not found")))
}

/// `get_customer_default_settings_attribute("grafana_url")` or the
/// placeholder.
pub async fn default_grafana_url(db: &Db) -> PyResult<String> {
    let rows: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT customer_provisioning_default_settings.grafana_url \nFROM \
         customer_provisioning_default_settings",
    )
    .fetch_all(db.pool())
    .await
    .map_err(crate::office365::db)?;
    Ok(rows
        .into_iter()
        .next()
        .and_then(|(url,)| url)
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "grafana.company.local".into()))
}

/// The OpenSearch datasource's `dataLinks` (an `_id` explore link on
/// connector id 12's URL).
pub async fn explore_links(db: &Db, datasource_name: &str) -> PyResult<PyValue> {
    let grafana_url = prov_store::connector_by_id(db, 12)
        .await?
        .map_or_else(|| "None".to_string(), |r| r.connector_url);
    let url = format!(
        "{grafana_url}/explore?left=%7B%22datasource%22:%22{}%22,%22queries%22:%5B%7B\
         %22refId%22:%22A%22,%22query%22:%22_id:${{__value.raw}}%22,%22alias%22:%22%22,\
         %22metrics%22:%5B%7B%22id%22:%221%22,%22type%22:%22logs%22,%22settings%22:\
         %7B%22limit%22:%22500%22%7D%7D%5D,%22bucketAggs%22:%5B%7B%22type%22:%22date_histogram%22,%22id%22:%221%22,%22settings%22:%7B%22interval%22:%22auto%22%7D%7D%5D,%22timeField%22:\
         %22timestamp%22%7D%5D,%22range%22:%7B%22from%22:%22now-6h%22,%22to%22:%22now%22%7D%7D",
        copilot_web::pyurl::quote(datasource_name, "")
    );
    Ok(PyValue::List(vec![kwargs(vec![
        ("field", s("^_id$")),
        ("url", PyValue::Str(url)),
    ])]))
}

/// `provision_dashboards(DashboardProvisionRequest(...))` with a Grafana URL.
pub async fn provision_dashboards(
    tools: Tools<'_>,
    class: &dashboards::DashboardClass,
    org: &str,
    folder_id: &PyValue,
    datasource_uid: &str,
    grafana_url: Option<String>,
) -> PyResult<()> {
    let names = class.names().into_iter().map(PyValue::Str).collect();
    let mut kw = vec![
        ("dashboards", PyValue::List(names)),
        ("organizationId", s(org)),
        ("folderId", folder_id.clone()),
        ("datasourceUid", s(datasource_uid)),
    ];
    if let Some(url) = grafana_url {
        kw.push(("grafana_url", PyValue::Str(url)));
    }
    let request = construct(
        &copilot_grafana_dashboards::schema::DASHBOARD_PROVISION_REQUEST,
        &kwargs(kw),
    )?;
    copilot_grafana_dashboards::services::provision_dashboards(tools.grafana, &request).await?;
    Ok(())
}

/// The route's work once the body is read and the caller checked: the
/// response dump, or the error the route answers.
pub async fn provision(
    tools: Tools<'_>,
    code: &str,
    integration_name: &str,
    instance: Option<String>,
) -> PyResult<PyValue> {
    use copilot_integration_provisioning::integrations::integrations_of;
    let list = integrations_of(tools.ctx, code).await?;
    let instance = copilot_integrations::integrations::services::resolve_instance(
        tools.ctx,
        code,
        integration_name,
        copilot_integrations::sql::normalize_instance_name(instance.as_deref()),
    )
    .await
    .map_err(api_exc)?;
    // `find_customer_integration(..., match_instance=True)`.
    let found = list.iter().find(|ci| {
        ci.instance_name == instance
            && ci.subscriptions.iter().any(|s| {
                s.service
                    .as_ref()
                    .is_some_and(|v| v.service_name == integration_name)
            })
    });
    let Some(ci) = found else {
        return Err(PyExc::http(
            404,
            format!(
                "Office365 integration '{}' not found for customer {code}.",
                instance.as_deref().unwrap_or("None")
            ),
        ));
    };
    let mut keys: Vec<(String, PyValue)> = Vec::new();
    for sub in &ci.subscriptions {
        if sub
            .service
            .as_ref()
            .is_some_and(|v| v.service_name == "Office365")
        {
            for k in &sub.keys {
                match keys.iter_mut().find(|(n, _)| *n == k.auth_key_name) {
                    Some(slot) => slot.1 = s(&k.auth_value),
                    None => keys.push((k.auth_key_name.clone(), s(&k.auth_value))),
                }
            }
        }
    }
    if keys.is_empty() {
        return Err(PyExc::http(
            404,
            "No auth keys found for Office365 integration. Please create auth keys for Office365 \
             integration.",
        ));
    }
    let auth = construct(&PROVISION_OFFICE365_AUTH_KEYS, &PyValue::Dict(keys))?;
    let keys = Keys {
        tenant_id: field(&auth, "TENANT_ID").py_str(),
        client_id: field(&auth, "CLIENT_ID").py_str(),
        client_secret: field(&auth, "CLIENT_SECRET").py_str(),
        api_type: field(&auth, "API_TYPE").py_str(),
    };
    provision_office365(tools, code, &keys, instance.as_deref()).await
}

/// `provision_office365(customer_code, keys, session, instance_name)`.
pub async fn provision_office365(
    tools: Tools<'_>,
    code: &str,
    keys: &Keys,
    instance: Option<&str>,
) -> PyResult<PyValue> {
    tracing::info!(
        "Provisioning Office365 integration for customer {code} (instance: {}).",
        instance.unwrap_or("default")
    );
    let mut rollback = Rollback::default();
    if let Err(exc) = deploy(tools, code, keys, instance, &mut rollback).await {
        tracing::error!(
            "Office365 provisioning failed for customer {code}: {}. Rolling back.",
            exc.display()
        );
        let failures = rollback.run(tools, Style::Str).await;
        let mut message = format!(
            "Office365 deployment failed and was rolled back: {}",
            detail_or_str(&exc)
        );
        if !failures.is_empty() {
            message.push_str(" Some resources could not be removed automatically: ");
            message.push_str(&failures.join("; "));
            message.push('.');
        }
        return Err(failure(&exc, message));
    }
    let suffix = match instance {
        Some(name) => format!(" (tenant {name})."),
        None => ".".to_string(),
    };
    Ok(kwargs(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            PyValue::Str(format!(
                "Successfully provisioned Office365 integration for customer {code}{suffix}"
            )),
        ),
    ]))
}

async fn deploy(
    tools: Tools<'_>,
    code: &str,
    keys: &Keys,
    instance: Option<&str>,
    rollback: &mut Rollback,
) -> PyResult<()> {
    let db = &tools.ctx.db;
    let gl = tools.graylog;
    // Wazuh manager.
    let raw = manager_configuration(tools).await?;
    if raw.contains(keys.tenant_id.as_str()) {
        return Err(PyExc::http(
            400,
            format!(
                "Microsoft 365 tenant {} is already provisioned on the Wazuh manager.",
                keys.tenant_id
            ),
        ));
    }
    let file = config::configuration_to_push(&raw, keys)?;
    update_configuration(tools, &file, keys).await?;
    rollback.add(
        format!("the Wazuh api_auth block for tenant {}", keys.tenant_id),
        Undo::Office365Tenant(keys.tenant_id.clone()),
    );
    restart_manager(tools).await?;

    // Graylog.
    check_pipeline_rules(tools).await?;
    check_pipeline(tools).await?;
    let existing = int_store::meta_first(db, code, "Office365", None)
        .await
        .map_err(db_err)?;
    let index_set_id = match existing.as_ref().filter(|m| !m.graylog_index_id.is_empty()) {
        Some(m) => {
            tracing::info!(
                "Reusing this customer's Office365 index set: {}",
                m.graylog_index_id
            );
            s(&m.graylog_index_id)
        }
        None => {
            let lower = code.to_lowercase();
            let title = format!("{} - Office365", customer_name(db, &lower).await?);
            let creation_date = graylog_steps::creation_date();
            let shards = grafana_steps::shard_number(tools.wazuh).await?;
            let index_set = graylog_steps::index_set_config(&IndexSet {
                title,
                description: format!("{lower} - Office365"),
                index_prefix: format!("office365-{lower}"),
                max_indices: PyValue::Int("30".into()),
                shards,
                replicas: PyValue::Int("0".into()),
                creation_date,
            })?;
            let id = graylog_steps::create_index_set(
                gl,
                copilot_graylog::client::DEFAULT_CONNECTOR,
                index_set,
            )
            .await?;
            tracing::info!("Index set: {}", id.py_str());
            rollback.add(
                format!("Graylog index set {}", id.py_str()),
                Undo::IndexSet(id.py_str()),
            );
            id
        }
    };
    let name = customer_name(db, code).await?;
    let mut title = format!("{name} - Office365");
    if let Some(instance) = instance.filter(|i| !i.is_empty()) {
        title.push_str(&format!(" - {instance}"));
    }
    let stream = graylog_steps::event_stream_config(
        &title,
        &title,
        &index_set_id,
        vec![
            ("rule_group1", "office365".to_string()),
            ("data_office365_OrganizationId", keys.tenant_id.clone()),
        ],
    )?;
    let stream_id =
        graylog_steps::create_event_stream(gl, copilot_graylog::client::DEFAULT_CONNECTOR, stream)
            .await?;
    rollback.add(
        format!("Graylog stream {}", stream_id.py_str()),
        Undo::Stream(stream_id.py_str()),
    );
    let pipeline_ids = graylog::pipeline_id(gl, "OFFICE365").await?;
    graylog_steps::connect_stream_to_pipeline(
        gl,
        copilot_graylog::client::DEFAULT_CONNECTOR,
        &stream_id,
        &pipeline_ids,
    )
    .await?;
    copilot_graylog::services::start_stream(gl, &stream_id.py_str()).await?;

    // Grafana.
    let org = prov_store::grafana_org_id(db, code).await?;
    let reused = existing.as_ref().and_then(|m| {
        let uid = m
            .grafana_datasource_uid
            .as_deref()
            .filter(|u| !u.is_empty())?;
        let folder = Some(m.grafana_dashboard_folder_id.as_str()).filter(|f| !f.is_empty())?;
        Some((uid.to_string(), folder.to_string()))
    });
    let (datasource_uid, folder_id) = match reused {
        Some((uid, folder)) => {
            tracing::info!(
                "Reusing this customer's Office365 Grafana folder {folder} and datasource {uid}."
            );
            (s(&uid), s(&folder))
        }
        None => {
            let lower = code.to_lowercase();
            let api = tools
                .grafana
                .create(copilot_grafana::client::CONNECTOR)
                .await?;
            let links = explore_links(db, "O365").await?;
            let ds_org = prov_store::grafana_org_id(db, &lower).await?;
            let uid = grafana_steps::create_datasource_on(
                db,
                tools.grafana,
                tools.wazuh,
                &api,
                &ds_org,
                &Datasource {
                    name: "O365".into(),
                    database: format!("office365-{lower}*"),
                    log_level_field: "syslog_level",
                    log_message_field: "rule_description",
                    data_links: Some(links),
                },
            )
            .await?;
            rollback.add(
                format!("Grafana datasource {}", uid.py_str()),
                Undo::Datasource {
                    org: org.clone(),
                    uid: uid.py_str(),
                },
            );
            let folder = grafana_steps::create_folder(tools.grafana, &org, "OFFICE 365").await?;
            let folder_id = field(&folder, "id").clone();
            rollback.add(
                format!("Grafana folder {}", folder_id.py_str()),
                Undo::Folder {
                    org: org.clone(),
                    folder: folder_id.py_str(),
                },
            );
            let url = default_grafana_url(db).await?;
            provision_dashboards(
                tools,
                &dashboards::OFFICE365,
                &org,
                &folder_id,
                &uid.py_str(),
                Some(url),
            )
            .await?;
            (uid, folder_id)
        }
    };

    // The metadata, then `deployed`, then the customer's legacy column.
    let meta = construct(
        &CUSTOMER_INTEGRATIONS_META_SCHEMA,
        &kwargs(vec![
            ("customer_code", s(code)),
            ("integration_name", s("Office365")),
            ("instance_name", instance.map_or(PyValue::None, s)),
            ("graylog_input_id", PyValue::None),
            ("graylog_index_id", index_set_id),
            ("graylog_stream_id", stream_id),
            ("grafana_org_id", s(&org)),
            ("grafana_dashboard_folder_id", folder_id),
            ("grafana_datasource_uid", datasource_uid),
        ]),
    )?;
    create_meta_validated(tools.ctx, &meta)
        .await
        .map_err(api_exc)?;
    tracing::info!("Integration meta entry created for customer {code}.");
    set_deployed(db, code, "Office365", instance).await?;
    claim_legacy_tenant_column(db, code, &keys.tenant_id).await
}

fn db_err(e: sqlx::Error) -> PyExc {
    db(e)
}

/// `update_customer_integration_table(code, session, instance_name)`: this
/// instance of `service` flagged deployed.
pub async fn set_deployed(
    db: &Db,
    code: &str,
    service: &str,
    instance: Option<&str>,
) -> PyResult<()> {
    let clause = match instance {
        None => "customer_integrations.instance_name IS NULL",
        Some(_) => "customer_integrations.instance_name = ?",
    };
    let sql = format!(
        "UPDATE customer_integrations SET deployed=1 WHERE customer_integrations.customer_code = \
         ? AND customer_integrations.integration_service_name = ? AND {clause}"
    );
    let mut q = sqlx::query(&sql).bind(code).bind(service);
    if let Some(i) = instance {
        q = q.bind(i);
    }
    q.persistent(false)
        .execute(db.pool())
        .await
        .map_err(db_err)?;
    Ok(())
}

/// `update_customermeta_table(code, session, tenant_id)`: the legacy
/// single-tenant column, written only while empty.
async fn claim_legacy_tenant_column(db: &Db, code: &str, tenant: &str) -> PyResult<()> {
    sqlx::query(
        "UPDATE customersmeta SET customer_meta_office365_organization_id=? WHERE \
         customersmeta.customer_code = ? AND (customersmeta.customer_meta_office365_organization_id \
         IS NULL OR customersmeta.customer_meta_office365_organization_id = ?)",
    )
    .bind(tenant)
    .bind(code)
    .bind("")
    .persistent(false)
    .execute(db.pool())
    .await
    .map_err(db_err)?;
    Ok(())
}
