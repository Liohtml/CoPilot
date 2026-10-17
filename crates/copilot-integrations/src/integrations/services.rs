//! The logic of `app/integrations/routes.py`, check by check in its order.
//!
//! **Tenancy** (RUST_MIGRATION.md §4). Python checks the customer only where
//! it is a path parameter. Every body that names a customer
//! (`create_integration`, `create_integration_meta`, `delete_integration`,
//! `update_meta_auto`) is checked here against the caller's customers right
//! after it is validated, and the listings without a customer
//! (`/customer_integrations`, `/customer_integrations_meta`, the auth-key
//! lookup) are narrowed to the caller's customers: Python handed any analyst
//! every tenant's integrations, credentials included.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::field;
use copilot_upstream::respond::body_model;
use copilot_web::body::JsonBody;
use copilot_web::{ApiError, AppContext, CurrentUser};

use super::cleanup::{self, Resources};
use super::schema::{
    CUSTOMER_INTEGRATION_CREATE, CUSTOMER_INTEGRATIONS_META_SCHEMA, DELETE_CUSTOMER_INTEGRATION,
    UPDATE_CUSTOMER_INTEGRATION, UPDATE_META_AUTO_REQUEST, catalog_dump, customer_integration_dump,
    message_response, meta_dump, meta_response, meta_table_dump, network_meta_table_dump,
};
use super::store::{self, CustomerIntegration};
use super::{
    AWS, AWS_IDENTITY_AUTH_KEYS, MISSING_META_RECOVERY_HINT, MULTI_INSTANCE_INTEGRATIONS,
    NETWORK_INTEGRATIONS, is_unchanged_secret,
};
use crate::IntegrationsState;
use crate::sql::{dict, instance_differs, instance_matches, internal, normalize_instance_name, s};
use crate::table_model::{self, Bound, TableModel};

/// A handler's answer or what it does instead.
pub enum Outcome {
    /// The dump to answer with (200).
    Answer(PyValue),
    /// Hand the request to the Python backend unchanged.
    Python,
}

fn bad_request(detail: impl Into<String>) -> ApiError {
    ApiError::bad_request(detail)
}

fn not_found(detail: impl Into<String>) -> ApiError {
    ApiError::not_found(detail)
}

fn text<'a>(dump: &'a PyValue, key: &str) -> &'a str {
    field(dump, key).as_str().unwrap_or_default()
}

fn opt_text<'a>(dump: &'a PyValue, key: &str) -> Option<&'a str> {
    field(dump, key).as_str()
}

/// `(auth_key_name, auth_value)` of a validated key list.
fn keys(dump: &PyValue, key: &str) -> Vec<(String, String)> {
    match field(dump, key) {
        PyValue::List(items) => items
            .iter()
            .map(|k| {
                (
                    text(k, "auth_key_name").to_string(),
                    text(k, "auth_value").to_string(),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

// --- the catalog ------------------------------------------------------------

/// `GET /available_integrations`.
pub async fn available(ctx: &AppContext) -> Result<PyValue, ApiError> {
    let catalog = store::catalog(&ctx.db).await.map_err(internal)?;
    Ok(dict(vec![
        (
            "available_integrations",
            PyValue::List(catalog.iter().map(catalog_dump).collect()),
        ),
        (
            "message",
            s("Available integrations successfully retrieved."),
        ),
        ("success", PyValue::Bool(true)),
    ]))
}

/// `GET /available_integrations/{integration_id}`.
pub async fn available_one(ctx: &AppContext, id: i64) -> Result<PyValue, ApiError> {
    let entry = store::catalog_by_id(&ctx.db, id)
        .await
        .map_err(internal)?
        .ok_or_else(|| not_found(format!("Integration {id} not found")))?;
    Ok(dict(vec![
        ("available_integration", catalog_dump(&entry)),
        (
            "message",
            s("Available integration successfully retrieved."),
        ),
        ("success", PyValue::Bool(true)),
    ]))
}

/// `AvailableIntegrations` as a request body.
pub static AVAILABLE_INTEGRATIONS: TableModel = TableModel {
    class: "AvailableIntegrations",
    fields: &[
        "id",
        "integration_name",
        "description",
        "integration_details",
    ],
    defaulted: &["id"],
    relationships: &["auth_keys"],
};

/// `PUT /available_integrations`: the descriptions written (and committed),
/// then the response model refuses the table-model instances — the 400 of
/// the `ValueError` handler — unless the list was empty.
pub async fn update_available(ctx: &AppContext, body: &JsonBody) -> Result<PyValue, ApiError> {
    let items = table_model::read_list(body, &AVAILABLE_INTEGRATIONS)?;
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    for item in &items {
        let name = item.get("integration_name");
        let found: Option<i32> = match table_model::bound(&name)? {
            Bound::Null => None,
            b => {
                let sql = "SELECT available_integrations.id, available_integrations.integration_name, \
                     available_integrations.description, available_integrations.integration_details \
                     \nFROM available_integrations \nWHERE available_integrations.integration_name = ?";
                // Not cached: a statement MySQL ran with an integer keeps
                // comparing numerically when it is later sent a string, so
                // a numeric name would poison the connection's lookups.
                let q = sqlx::query_scalar::<_, i32>(sql).persistent(false);
                let q = match b {
                    Bound::Text(t) => q.bind(t),
                    Bound::Int(i) => q.bind(i),
                    Bound::Float(f) => q.bind(f),
                    Bound::Null => q,
                };
                q.fetch_all(&mut *tx)
                    .await
                    .map_err(internal)?
                    .into_iter()
                    .next()
            }
        };
        let Some(id) = found else {
            return Err(not_found(format!(
                "Integration {} not found.",
                name.py_str()
            )));
        };
        sqlx::query(
            "UPDATE available_integrations SET description=?, integration_details=? WHERE \
             available_integrations.id = ?",
        )
        .bind(table_model::stored(&item.get("description"))?)
        .bind(table_model::stored(&item.get("integration_details"))?)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    if items.is_empty() {
        return Ok(dict(vec![
            ("available_integrations", PyValue::List(Vec::new())),
            ("message", s("Available integrations successfully updated.")),
            ("success", PyValue::Bool(true)),
        ]));
    }
    Err(bad_request(table_model::model_type_errors(
        "AvailableIntegrationsResponse",
        "available_integrations",
        "IntegrationWithAuthKeys",
        &AVAILABLE_INTEGRATIONS,
        &items,
    )))
}

// --- customer integrations ----------------------------------------------------

/// Keep what the caller may see (`None`: everything).
fn narrow<T>(items: Vec<T>, visible: Option<&[String]>, code: impl Fn(&T) -> &str) -> Vec<T> {
    match visible {
        None => items,
        Some(codes) => items
            .into_iter()
            .filter(|i| codes.iter().any(|c| c == code(i)))
            .collect(),
    }
}

/// The customers the caller may see, `None` for deployment-wide.
async fn visible(ctx: &AppContext, user: &CurrentUser) -> Result<Option<Vec<String>>, ApiError> {
    Ok(user.access(ctx).await?.scoped_customer_codes(None))
}

fn integrations_response(
    cis: &[CustomerIntegration],
    processed: bool,
) -> Result<PyValue, ApiError> {
    let list = cis
        .iter()
        .map(|ci| customer_integration_dump(ci, processed))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;
    Ok(dict(vec![
        ("available_integrations", PyValue::List(list)),
        (
            "message",
            s("Customer integrations successfully retrieved."),
        ),
        ("success", PyValue::Bool(true)),
    ]))
}

/// `GET /customer_integrations` (the caller's customers').
pub async fn customer_integrations(
    ctx: &AppContext,
    user: &CurrentUser,
) -> Result<PyValue, ApiError> {
    let all = store::customer_integrations(&ctx.db, None)
        .await
        .map_err(internal)?;
    let codes = visible(ctx, user).await?;
    let seen = narrow(all, codes.as_deref(), |c| c.customer_code.as_str());
    integrations_response(&seen, true)
}

/// `GET /customer_integrations/{customer_code}`.
pub async fn customer_integrations_of(ctx: &AppContext, code: &str) -> Result<PyValue, ApiError> {
    let cis = store::customer_integrations(&ctx.db, Some(code))
        .await
        .map_err(internal)?;
    integrations_response(&cis, false)
}

/// `GET /customer_integrations_meta` (the caller's customers'); a failed
/// read lists nothing, as Python's `try`.
pub async fn metas(ctx: &AppContext, user: &CurrentUser) -> Result<PyValue, ApiError> {
    let all = match store::metas(&ctx.db, None).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Error while fetching customer integrations metadata: {e}");
            Vec::new()
        }
    };
    let codes = visible(ctx, user).await?;
    let seen = narrow(all, codes.as_deref(), |m| m.customer_code.as_str());
    Ok(meta_response(
        "Customer integrations metadata successfully retrieved.",
        true,
        Some(seen.iter().map(meta_dump).collect()),
    ))
}

/// `GET /customer_integrations_meta/{customer_code}`.
pub async fn metas_of(ctx: &AppContext, code: &str) -> Result<PyValue, ApiError> {
    let rows = store::metas(&ctx.db, Some(code)).await.map_err(internal)?;
    Ok(meta_response(
        "Customer integrations metadata successfully retrieved.",
        true,
        Some(rows.iter().map(meta_dump).collect()),
    ))
}

// --- validation ---------------------------------------------------------------

/// `validate_integration_name`.
async fn validate_integration_name(ctx: &AppContext, name: &str) -> Result<(), ApiError> {
    let catalog = store::catalog(&ctx.db).await.map_err(internal)?;
    if catalog.iter().any(|c| c.name == name) {
        Ok(())
    } else {
        Err(bad_request(format!(
            "Integration {name} is not a valid integration."
        )))
    }
}

/// The first catalog entry of `name`'s auth keys.
async fn catalog_keys(ctx: &AppContext, name: &str) -> Result<Vec<String>, ApiError> {
    let catalog = store::catalog(&ctx.db).await.map_err(internal)?;
    catalog
        .into_iter()
        .find(|c| c.name == name)
        .map(|c| c.keys)
        .ok_or_else(|| ApiError::internal("IndexError: list index out of range"))
}

/// `validate_customer_code` and `validate_customer_meta`.
async fn validate_customer(ctx: &AppContext, code: &str, what: &str) -> Result<(), ApiError> {
    if !store::customer_exists(&ctx.db, code)
        .await
        .map_err(internal)?
    {
        return Err(bad_request(format!("Customer {code} does not exist.")));
    }
    if !store::customer_meta_exists(&ctx.db, code)
        .await
        .map_err(internal)?
    {
        return Err(bad_request(format!(
            "Customer {code} meta does not exist. Please provision the customer before creating \
             an {what}."
        )));
    }
    Ok(())
}

/// `check_existing_customer_integration`.
async fn check_existing(
    ctx: &AppContext,
    code: &str,
    name: &str,
    instance: Option<&str>,
) -> Result<(), ApiError> {
    let existing = store::existing_instances(&ctx.db, code, name)
        .await
        .map_err(internal)?;
    if existing.is_empty() {
        return Ok(());
    }
    if !MULTI_INSTANCE_INTEGRATIONS.contains(&name) {
        return Err(bad_request(format!(
            "Customer integration {code} {name} already exists."
        )));
    }
    let Some(instance) = instance else {
        return Err(bad_request(format!(
            "Customer {code} already has a {name} integration. Provide an instance name to add \
             another one."
        )));
    };
    if existing.iter().any(|i| i.as_deref() == Some(instance)) {
        return Err(bad_request(format!(
            "Customer integration {code} {name} '{instance}' already exists."
        )));
    }
    Ok(())
}

/// `ensure_aws_account_not_owned_elsewhere`.
async fn ensure_aws_account_not_owned_elsewhere(
    ctx: &AppContext,
    code: &str,
    account: Option<&str>,
) -> Result<(), ApiError> {
    let account = copilot_web::form::py_strip(account.unwrap_or_default());
    if account.is_empty() {
        return Ok(());
    }
    for record in store::aws_instances(&ctx.db).await.map_err(internal)? {
        if record.account_id.as_deref() == Some(account) && record.customer_code != code {
            return Err(bad_request(format!(
                "AWS account {account} is already configured for customer {}.",
                record.customer_code
            )));
        }
    }
    Ok(())
}

/// `resolve_integration_instance`.
pub async fn resolve_instance(
    ctx: &AppContext,
    code: &str,
    name: &str,
    instance: Option<String>,
) -> Result<Option<String>, ApiError> {
    if instance.is_some() {
        return Ok(instance);
    }
    let instances = store::distinct_instances(&ctx.db, code, name)
        .await
        .map_err(internal)?;
    if instances.len() > 1 {
        let mut labels: Vec<String> = instances
            .iter()
            .map(|i| match i.as_deref() {
                Some(l) if !l.is_empty() => l.to_string(),
                _ => "unnamed".to_string(),
            })
            .collect();
        labels.sort();
        return Err(bad_request(format!(
            "Customer {code} has {} {name} instances ({}). Specify which one.",
            instances.len(),
            labels.join(", ")
        )));
    }
    Ok(instances.into_iter().next().flatten())
}

// --- create -------------------------------------------------------------------

/// `POST /create_integration`.
pub async fn create(
    ctx: &AppContext,
    user: &CurrentUser,
    body: &JsonBody,
) -> Result<PyValue, ApiError> {
    let req = body_model(body, &CUSTOMER_INTEGRATION_CREATE)?;
    let code = text(&req, "customer_code");
    let name = text(&req, "integration_name");
    user.enforce_customer(ctx, code).await?;
    validate_integration_name(ctx, name).await?;
    let wanted = catalog_keys(ctx, name).await?;
    let given = keys(&req, "integration_auth_keys");
    if let Some(missing) = wanted.iter().find(|k| !given.iter().any(|(n, _)| n == *k)) {
        return Err(bad_request(format!(
            "Integration auth key {missing} does not exist."
        )));
    }
    validate_customer(ctx, code, "integration").await?;
    let instance = normalize_instance_name(opt_text(&req, "instance_name"));
    if instance.is_some() && !MULTI_INSTANCE_INTEGRATIONS.contains(&name) {
        return Err(bad_request(format!(
            "{name} does not support multiple instances per customer."
        )));
    }
    check_existing(ctx, code, name, instance.as_deref()).await?;
    if name == AWS {
        let account = given
            .iter()
            .find(|(n, _)| n == "AWS_ACCOUNT_ID")
            .map(|(_, v)| v.as_str());
        ensure_aws_account_not_owned_elsewhere(ctx, code, account).await?;
    }
    let missing_service = || not_found(format!("Integration service {name} not found."));
    let (service_id, _) = store::catalog_first_by_name(&ctx.db, name)
        .await
        .map_err(internal)?
        .ok_or_else(missing_service)?;
    let (_, service_name) = store::catalog_first_by_name(&ctx.db, name)
        .await
        .map_err(internal)?
        .ok_or_else(missing_service)?;
    let config = field(&req, "integration_config");
    let pool = ctx.db.pool();
    let mut tx = pool.begin().await.map_err(internal)?;
    let svc =
        sqlx::query("INSERT INTO integration_services (service_name, auth_type) VALUES (?, ?)")
            .bind(name)
            .bind(text(config, "auth_type"))
            .execute(&mut *tx)
            .await
            .map_err(internal)?
            .last_insert_id();
    sqlx::query(
        "INSERT INTO integration_configs (integration_service_id, config_key, config_value) \
         VALUES (?, ?, ?)",
    )
    .bind(svc)
    .bind(text(config, "config_key"))
    .bind(text(config, "config_value"))
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    let ci = sqlx::query(
        "INSERT INTO customer_integrations (customer_code, customer_name, \
         integration_service_id, integration_service_name, instance_name, deployed) VALUES (?, \
         ?, ?, ?, ?, ?)",
    )
    .bind(code)
    .bind(text(&req, "customer_name"))
    .bind(service_id)
    .bind(&service_name)
    .bind(instance.as_deref())
    .bind(false)
    .execute(&mut *tx)
    .await
    .map_err(internal)?
    .last_insert_id();
    // One subscription per key, each committed on its own (the first with
    // the service, its config and the integration).
    let mut tx = Some(tx);
    for (key, value) in &given {
        let mut t = match tx.take() {
            Some(t) => t,
            None => pool.begin().await.map_err(internal)?,
        };
        let sub = sqlx::query(
            "INSERT INTO integration_subscriptions (customer_id, integration_service_id) VALUES \
             (?, ?)",
        )
        .bind(ci)
        .bind(svc)
        .execute(&mut *t)
        .await
        .map_err(internal)?
        .last_insert_id();
        sqlx::query(
            "INSERT INTO integration_auth_keys (subscription_id, auth_key_name, auth_value) \
             VALUES (?, ?, ?)",
        )
        .bind(sub)
        .bind(key)
        .bind(value)
        .execute(&mut *t)
        .await
        .map_err(internal)?;
        t.commit().await.map_err(internal)?;
    }
    // No key: nothing was ever committed (the session closes uncommitted).
    drop(tx);
    if name == "Office365" {
        let clause = instance_matches("customer_integrations.instance_name", instance.as_deref());
        let tenant = store::tenant_id(&ctx.db, code, name, &clause, true)
            .await
            .map_err(internal)?
            .ok_or_else(|| not_found(format!("Tenant ID for customer {code} not found.")))?;
        sqlx::query(
            "UPDATE custom_alert_creation_settings SET office365_organization_id=? WHERE \
             custom_alert_creation_settings.customer_code = ? AND \
             (custom_alert_creation_settings.office365_organization_id IS NULL OR \
             custom_alert_creation_settings.office365_organization_id = ?)",
        )
        .bind(&tenant)
        .bind(code)
        .bind("")
        .execute(pool)
        .await
        .map_err(internal)?;
    }
    Ok(dict(vec![
        (
            "message",
            s(format!(
                "Customer integration {code} {name} successfully created."
            )),
        ),
        ("success", PyValue::Bool(true)),
        ("additional_info", PyValue::None),
    ]))
}

/// `POST /create_integration_meta`.
pub async fn create_meta(
    ctx: &AppContext,
    user: &CurrentUser,
    body: &JsonBody,
) -> Result<PyValue, ApiError> {
    let req = body_model(body, &CUSTOMER_INTEGRATIONS_META_SCHEMA)?;
    user.enforce_customer(ctx, text(&req, "customer_code"))
        .await?;
    create_meta_validated(ctx, &req).await
}

/// `create_integration_meta(meta, session)` once `meta` is a validated
/// `CustomerIntegrationsMetaSchema` dump (the provisioning flows call it
/// directly, as Python's do): the customer and its meta row checked, an
/// existing row refused, then the insert, whose failure is `success: false`.
pub async fn create_meta_validated(ctx: &AppContext, req: &PyValue) -> Result<PyValue, ApiError> {
    let req = req.clone();
    let code = text(&req, "customer_code");
    let name = text(&req, "integration_name");
    validate_customer(ctx, code, "integration").await?;
    let instance = normalize_instance_name(opt_text(&req, "instance_name"));
    let clause = instance_matches(
        "customer_integrations_meta.instance_name",
        instance.as_deref(),
    );
    if store::meta_first(&ctx.db, code, name, Some(&clause))
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err(bad_request(format!(
            "Customer integration meta {code} {name} already exists."
        )));
    }
    let id = match field(&req, "id") {
        PyValue::Int(i) => i.parse::<i64>().ok(),
        _ => None,
    };
    let columns = "customer_code, integration_name, instance_name, graylog_input_id, \
                   graylog_index_id, graylog_stream_id, grafana_org_id, \
                   grafana_dashboard_folder_id, grafana_datasource_uid";
    let sql = match id {
        Some(_) => format!(
            "INSERT INTO customer_integrations_meta (id, {columns}) VALUES (?, ?, ?, ?, ?, ?, ?, \
             ?, ?, ?)"
        ),
        None => format!(
            "INSERT INTO customer_integrations_meta ({columns}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ),
    };
    let mut q = sqlx::query(&sql);
    if let Some(id) = id {
        q = q.bind(id);
    }
    let inserted = q
        .bind(code)
        .bind(name)
        .bind(opt_text(&req, "instance_name"))
        .bind(opt_text(&req, "graylog_input_id"))
        .bind(text(&req, "graylog_index_id"))
        .bind(text(&req, "graylog_stream_id"))
        .bind(text(&req, "grafana_org_id"))
        .bind(text(&req, "grafana_dashboard_folder_id"))
        .bind(opt_text(&req, "grafana_datasource_uid"))
        .execute(ctx.db.pool())
        .await;
    Ok(match inserted {
        Ok(_) => meta_response(
            "Customer integration metadata successfully created.",
            true,
            None,
        ),
        Err(e) => {
            tracing::error!("Error while creating customer integration metadata: {e}");
            meta_response(
                "Error while creating customer integration metadata.",
                false,
                None,
            )
        }
    })
}

// --- update -------------------------------------------------------------------

/// `generate_integration_response`.
fn integration_response(code: &str, name: &str) -> PyValue {
    let info = match name {
        "Office365" => Some(
            "Make sure to update the Office365 integration block in the Wazuh Manager ossec.conf \
             file and restart the Wazuh Manager service. Also make sure to update the Office365 \
             Graylog stream rule for this customer with the new organization ID if this has \
             changed. YouTube video: https://youtu.be/ihj2F2rA6BQ?si=p4c8Xnk6PX8r29IB",
        ),
        "Crowdstrike" => Some(
            "Make sure to update the Crowdstrike docker application with the new connection \
             details and restart the docker container. YouTube video: \
             https://youtu.be/YOVUOpZDEzM?si=jzpHw8vcnqnfVPzt",
        ),
        "BitDefender" => Some(
            "Make sure to update the BitDefender docker application with the new connection \
             details and restart the docker container.",
        ),
        _ => None,
    };
    message_response(
        format!("Customer integration {code} {name} successfully updated."),
        info.map(str::to_string),
    )
}

/// `ensure_aws_identity_unchanged`.
fn ensure_aws_identity_unchanged(
    ci: &CustomerIntegration,
    given: &[(String, String)],
) -> Result<(), ApiError> {
    let mut stored: Vec<(String, String)> = Vec::new();
    for sub in &ci.subscriptions {
        for key in &sub.keys {
            let value = copilot_web::form::py_strip(&key.auth_value).to_string();
            match stored.iter_mut().find(|(n, _)| *n == key.auth_key_name) {
                Some(slot) => slot.1 = value,
                None => stored.push((key.auth_key_name.clone(), value)),
            }
        }
    }
    for (name, value) in given {
        if !AWS_IDENTITY_AUTH_KEYS.contains(&name.as_str()) {
            continue;
        }
        let was = stored
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, v)| v.as_str());
        if copilot_web::form::py_strip(value) != was {
            return Err(bad_request(format!(
                "{name} cannot be changed on a deployed AWS integration: it identifies the \
                 buckets on the Wazuh manager and the Graylog streams. Delete the integration \
                 and add it again with the new value."
            )));
        }
    }
    Ok(())
}

/// `PUT /update_integration/{customer_code}` (the path's tenant already
/// checked).
pub async fn update(ctx: &AppContext, code: &str, body: &JsonBody) -> Result<PyValue, ApiError> {
    let req = body_model(body, &UPDATE_CUSTOMER_INTEGRATION)?;
    let name = text(&req, "integration_name");
    validate_integration_name(ctx, name).await?;
    let cis = store::customer_integrations(&ctx.db, Some(code))
        .await
        .map_err(internal)?;
    let instance = resolve_instance(
        ctx,
        code,
        name,
        normalize_instance_name(opt_text(&req, "instance_name")),
    )
    .await?;
    let ci = cis
        .iter()
        .filter(|ci| ci.instance_name == instance)
        .find(|ci| ci.has_service(name))
        .ok_or_else(|| not_found("Customer integration with specified service name not found."))?;
    let given = keys(&req, "integration_auth_keys");
    let catalog = catalog_keys(ctx, name).await?;
    if let Some((bad, _)) = given.iter().find(|(n, _)| !catalog.contains(n)) {
        return Err(bad_request(format!(
            "Integration auth key {bad} does not exist."
        )));
    }
    if name == AWS {
        if ci.deployed == Some(true) {
            ensure_aws_identity_unchanged(ci, &given)?;
        }
        let account = given
            .iter()
            .find(|(n, _)| n == "AWS_ACCOUNT_ID")
            .map(|(_, v)| v.as_str());
        ensure_aws_account_not_owned_elsewhere(ctx, code, account).await?;
    }
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    for (key, value) in &given {
        if is_unchanged_secret(key, value) {
            continue;
        }
        let Some(sub) = ci.subscription_with_key(name, key) else {
            return Err(not_found(format!("Integration auth key {key} not found.")));
        };
        sqlx::query("UPDATE integration_auth_keys SET auth_value=? WHERE integration_auth_keys.subscription_id = ?")
            .bind(value)
            .bind(sub)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    Ok(integration_response(code, name))
}

// --- delete -------------------------------------------------------------------

/// `generate_decommission_response`.
fn decommission_response(code: &str, name: &str, warnings: &[String]) -> PyValue {
    let mut info = match name {
        "Crowdstrike" => "Make sure to remove the Crowdstrike docker application.".to_string(),
        "BitDefender" => "Make sure to remove the BitDefender docker application.".to_string(),
        _ => String::new(),
    };
    if !warnings.is_empty() {
        let mut parts = vec![info.clone()];
        parts.extend(warnings.iter().cloned());
        info = copilot_web::form::py_strip(&parts.join(" ")).to_string();
    }
    message_response(
        format!("Customer integration {code} {name} successfully deleted."),
        (!info.is_empty()).then_some(info),
    )
}

/// `DELETE /delete_integration`.
pub async fn delete(
    st: &IntegrationsState,
    user: &CurrentUser,
    body: &JsonBody,
) -> Result<Outcome, ApiError> {
    let ctx = &st.ctx;
    let db = &ctx.db;
    let req = body_model(body, &DELETE_CUSTOMER_INTEGRATION)?;
    let code = text(&req, "customer_code");
    let name = text(&req, "integration_name");
    user.enforce_customer(ctx, code).await?;
    let is_network = NETWORK_INTEGRATIONS.contains(&name);
    let instance = resolve_instance(
        ctx,
        code,
        name,
        normalize_instance_name(opt_text(&req, "instance_name")),
    )
    .await?;
    let differs = instance_differs("customer_integrations.instance_name", instance.as_deref());
    let remaining = store::count_other_instances(db, code, name, &differs)
        .await
        .map_err(internal)?;
    let matches = instance_matches("customer_integrations.instance_name", instance.as_deref());
    let ids = store::customer_and_service_ids(db, code, name, &matches)
        .await
        .map_err(internal)?;
    let Some(&(customer_id, service_id)) = ids.first() else {
        return Err(not_found("Customer integration not found"));
    };
    let deployed = store::deployed(db, customer_id).await.map_err(internal)?;
    let is_deployed = deployed == Some(true);
    if name == AWS && is_deployed {
        // Its ossec.conf edit is AWS provisioning's, under that process's lock.
        return Ok(Outcome::Python);
    }
    let subscriptions = store::subscription_ids(db, customer_id, service_id)
        .await
        .map_err(internal)?;
    if subscriptions.is_empty() {
        return Err(not_found("No subscriptions found for customer integration"));
    }
    let mut warnings: Vec<String> = Vec::new();
    let tenant = if name == "Office365" {
        store::tenant_id(db, code, "Office365", &matches, false)
            .await
            .map_err(internal)?
    } else {
        None
    };
    let mut delete_meta: Option<(bool, Option<String>)> = None;
    if is_deployed {
        let resources = if is_network {
            store::network_meta_first(db, code, name)
                .await
                .map_err(internal)?
                .map(|m| Resources {
                    stream_id: m.graylog_stream_id,
                    index_id: m.graylog_index_id,
                    org_id: m.grafana_org_id,
                    folder_id: m.grafana_dashboard_folder_id,
                    datasource_uid: Some(m.grafana_datasource_uid),
                })
        } else {
            let clause = instance_matches(
                "customer_integrations_meta.instance_name",
                instance.as_deref(),
            );
            store::meta_first(db, code, name, Some(&clause))
                .await
                .map_err(internal)?
                .map(|m| Resources {
                    stream_id: m.graylog_stream_id,
                    index_id: m.graylog_index_id,
                    org_id: m.grafana_org_id,
                    folder_id: m.grafana_dashboard_folder_id,
                    datasource_uid: m.grafana_datasource_uid,
                })
        };
        match resources {
            None => {
                tracing::warn!(
                    "No metadata found for {name} / {code}; skipping infrastructure cleanup and \
                     removing the integration settings only"
                );
                warnings.push(format!(
                    "No metadata record was found for {name}, so the Graylog stream/index and \
                     Grafana folder/datasource could not be removed automatically. Delete any \
                     leftover Graylog and Grafana resources for this customer manually."
                ));
            }
            Some(resources) => {
                cleanup::cleanup(
                    &st.graylog,
                    &st.grafana,
                    &resources,
                    code,
                    name,
                    &mut warnings,
                    remaining > 0,
                )
                .await;
                delete_meta = Some((is_network, instance.clone()));
            }
        }
    }
    let mut tx = db.pool().begin().await.map_err(internal)?;
    if let Some((network, instance)) = &delete_meta {
        if *network {
            sqlx::query(
                "DELETE FROM customer_network_connectors_meta WHERE \
                 customer_network_connectors_meta.customer_code = ? AND \
                 customer_network_connectors_meta.network_connector_name = ?",
            )
            .bind(code)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        } else {
            let clause = instance_matches(
                "customer_integrations_meta.instance_name",
                instance.as_deref(),
            );
            let sql = format!(
                "DELETE FROM customer_integrations_meta WHERE \
                 customer_integrations_meta.customer_code = ? AND \
                 customer_integrations_meta.integration_name = ? AND {}",
                clause.0
            );
            let q = sqlx::query(&sql).bind(code).bind(name);
            crate::sql::bind_clause(q, &clause)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
        }
    }
    let marks = vec!["?"; subscriptions.len()].join(", ");
    let sql = format!(
        "DELETE FROM integration_auth_keys WHERE integration_auth_keys.subscription_id IN ({marks})"
    );
    let mut q = sqlx::query(&sql);
    for id in &subscriptions {
        q = q.bind(id);
    }
    q.execute(&mut *tx).await.map_err(internal)?;
    let sql = format!(
        "DELETE FROM integration_subscriptions WHERE integration_subscriptions.id IN ({marks})"
    );
    let mut q = sqlx::query(&sql);
    for id in &subscriptions {
        q = q.bind(id);
    }
    q.execute(&mut *tx).await.map_err(internal)?;
    sqlx::query(
        "DELETE FROM integration_configs WHERE integration_configs.integration_service_id = ?",
    )
    .bind(service_id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query("DELETE FROM integration_services WHERE integration_services.id = ?")
        .bind(service_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    sqlx::query("DELETE FROM customer_integrations WHERE customer_integrations.id = ?")
        .bind(customer_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    if let Some(tenant) = tenant.filter(|t| !t.is_empty()) {
        // `clear_office365_organization_id`: the legacy single-tenant columns
        // forget this tenant.
        let mut tx = db.pool().begin().await.map_err(internal)?;
        sqlx::query(
            "UPDATE custom_alert_creation_settings SET office365_organization_id=? WHERE \
             custom_alert_creation_settings.office365_organization_id = ?",
        )
        .bind(None::<String>)
        .bind(&tenant)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        sqlx::query(
            "UPDATE customersmeta SET customer_meta_office365_organization_id=? WHERE \
             customersmeta.customer_meta_office365_organization_id = ?",
        )
        .bind(None::<String>)
        .bind(&tenant)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        if let Err(e) = crate::office365::decommission_tenant(&st.wazuh, &tenant).await {
            tracing::warn!(
                "Failed to remove the Office365 api_auth block for tenant {tenant}: {}",
                e.display()
            );
            warnings.push(format!(
                "Could not remove the Office365 api_auth block for tenant {tenant} from the \
                 Wazuh manager ({}). Remove it from ossec.conf and restart the manager.",
                e.display()
            ));
        }
    }
    Ok(Outcome::Answer(decommission_response(
        code, name, &warnings,
    )))
}

// --- lookups and the metadata routes -------------------------------------------

/// `GET /integration_customer/{integration_name}/{auth_key_name}/{auth_key_value}`:
/// the first match among the caller's customers.
pub async fn customer_by_auth_key(
    ctx: &AppContext,
    user: &CurrentUser,
    integration: &str,
    key: &str,
    value: &str,
) -> Result<PyValue, ApiError> {
    let rows = store::customers_by_auth_key(&ctx.db, integration, key, value)
        .await
        .map_err(|e| ApiError::server_error(format!("Failed to look up customer: {e}")))?;
    let codes = visible(ctx, user).await?;
    let seen = narrow(rows, codes.as_deref(), |(c, _)| c.as_str());
    let Some((code, name)) = seen.into_iter().next() else {
        return Err(not_found(format!(
            "No customer found with {integration} integration having {key}={value}"
        )));
    };
    Ok(dict(vec![
        ("customer_code", s(code)),
        ("customer_name", s(name)),
        ("integration_name", s(integration)),
        ("auth_key_name", s(key)),
        ("success", PyValue::Bool(true)),
        ("message", s("Customer found successfully.")),
    ]))
}

fn server(e: impl std::fmt::Display) -> ApiError {
    ApiError::server_error(format!("Internal server error: {e}"))
}

/// `GET /meta_auto/{customer_code}/{integration_name}` (the path's tenant
/// already checked).
pub async fn meta_auto(
    ctx: &AppContext,
    code: &str,
    name: &str,
    instance: Option<&str>,
) -> Result<PyValue, ApiError> {
    let network = NETWORK_INTEGRATIONS.contains(&name);
    let data = if network {
        let meta = store::network_meta_first(&ctx.db, code, name)
            .await
            .map_err(server)?
            .ok_or_else(|| {
                not_found(format!(
                    "Network connector metadata not found for customer {code} and connector \
                     {name}. {MISSING_META_RECOVERY_HINT}"
                ))
            })?;
        network_meta_table_dump(&meta)
    } else {
        let instance = normalize_instance_name(instance);
        let clause = instance
            .as_deref()
            .map(|i| instance_matches("customer_integrations_meta.instance_name", Some(i)));
        let meta = store::meta_first(&ctx.db, code, name, clause.as_ref())
            .await
            .map_err(server)?
            .ok_or_else(|| {
                not_found(format!(
                    "Integration metadata not found for customer {code} and integration {name}. \
                     {MISSING_META_RECOVERY_HINT}"
                ))
            })?;
        meta_table_dump(&meta)
    };
    Ok(dict(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            s(format!("Successfully retrieved metadata for {code}/{name}")),
        ),
        ("data", data),
        (
            "table_type",
            s(if network {
                "network_connector"
            } else {
                "integration"
            }),
        ),
    ]))
}

const META_FIELDS: &[&str] = &[
    "graylog_input_id",
    "graylog_index_id",
    "graylog_stream_id",
    "grafana_org_id",
    "grafana_dashboard_folder_id",
    "grafana_datasource_uid",
];

const NETWORK_META_FIELDS: &[&str] = &[
    "graylog_input_id",
    "graylog_index_id",
    "graylog_stream_id",
    "graylog_pipeline_id",
    "graylog_content_pack_input_id",
    "graylog_content_pack_stream_id",
    "grafana_org_id",
    "grafana_dashboard_folder_id",
    "grafana_datasource_uid",
];

/// `PUT /update_meta_auto`: update the row, or create it when the
/// deployment never recorded one.
pub async fn update_meta_auto(
    ctx: &AppContext,
    user: &CurrentUser,
    body: &JsonBody,
) -> Result<PyValue, ApiError> {
    let req = body_model(body, &UPDATE_META_AUTO_REQUEST)?;
    let code = text(&req, "customer_code");
    let name = text(&req, "integration_name");
    user.enforce_customer(ctx, code).await?;
    let network = NETWORK_INTEGRATIONS.contains(&name);
    let (table, name_column, fields) = if network {
        (
            "customer_network_connectors_meta",
            "network_connector_name",
            NETWORK_META_FIELDS,
        )
    } else {
        (
            "customer_integrations_meta",
            "integration_name",
            META_FIELDS,
        )
    };
    let table_type = if network {
        "network connector"
    } else {
        "integration"
    };
    let instance = if network {
        None
    } else {
        normalize_instance_name(opt_text(&req, "instance_name"))
    };
    let scope = instance
        .as_deref()
        .map(|i| instance_matches(&format!("{table}.instance_name"), Some(i)));
    let narrow_sql = scope
        .as_ref()
        .map_or(String::new(), |c| format!(" AND {}", c.0));
    let base_where = format!("{table}.customer_code = ? AND {table}.{name_column} = ?{narrow_sql}");
    let attempt = async {
        let sql = format!("SELECT {table}.id FROM {table} WHERE {base_where}");
        let mut q = sqlx::query(&sql).bind(code).bind(name);
        if let Some(c) = &scope {
            q = crate::sql::bind_clause(q, c);
        }
        let existing = !q.fetch_all(ctx.db.pool()).await?.is_empty();
        let update: Vec<(&str, &str)> = fields
            .iter()
            .filter_map(|f| opt_text(&req, f).map(|v| (*f, v)))
            .collect();
        if update.is_empty() {
            return Ok(None);
        }
        let action = if existing {
            let sets: Vec<String> = update.iter().map(|(f, _)| format!("{f}=?")).collect();
            let sql = format!("UPDATE {table} SET {} WHERE {base_where}", sets.join(", "));
            let mut q = sqlx::query(&sql);
            for (_, v) in &update {
                q = q.bind(*v);
            }
            q = q.bind(code).bind(name);
            if let Some(c) = &scope {
                q = crate::sql::bind_clause(q, c);
            }
            q.execute(ctx.db.pool()).await?;
            "Updated"
        } else {
            let mut columns: Vec<&str> = vec!["customer_code", name_column];
            let mut values: Vec<Option<String>> =
                vec![Some(code.to_string()), Some(name.to_string())];
            if !network {
                columns.push("instance_name");
                values.push(instance.clone());
            }
            for f in fields {
                columns.push(f);
                values.push(Some(
                    update
                        .iter()
                        .find(|(k, _)| k == f)
                        .map_or("", |(_, v)| v)
                        .to_string(),
                ));
            }
            let marks = vec!["?"; columns.len()].join(", ");
            let sql = format!(
                "INSERT INTO {table} ({}) VALUES ({marks})",
                columns.join(", ")
            );
            let mut q = sqlx::query(&sql);
            for v in &values {
                q = q.bind(v.as_deref());
            }
            q.execute(ctx.db.pool()).await?;
            "Created"
        };
        Ok::<_, sqlx::Error>(Some(action))
    }
    .await;
    match attempt {
        Ok(None) => Ok(dict(vec![
            ("success", PyValue::Bool(false)),
            ("message", s("No fields provided for update")),
        ])),
        Ok(Some(action)) => {
            tracing::info!(
                "{action} {table_type} metadata for customer {code}, {table_type} {name}"
            );
            Ok(dict(vec![
                ("success", PyValue::Bool(true)),
                (
                    "message",
                    s(format!(
                        "Successfully {} {table_type} metadata for {code}/{name}",
                        action.to_lowercase()
                    )),
                ),
            ]))
        }
        Err(e) => {
            tracing::error!("Error updating metadata: {e}");
            Err(server(e))
        }
    }
}
