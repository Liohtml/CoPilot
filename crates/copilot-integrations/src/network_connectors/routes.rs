//! `/api/network_connectors/*` — every route of
//! `network_connector_settings_router`, `require_any_scope("admin",
//! "analyst")`. As for the integrations, a body naming a customer is
//! checked against the caller's customers and the listings without a
//! customer are narrowed to them (RUST_MIGRATION.md §4).

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, get, post, put};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::field;
use copilot_upstream::respond::body_model;
use copilot_web::validate::path_int;
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, WithJson};

use super::schema::{
    CREATE, DELETE, META_SCHEMA, UPDATE, catalog_dump, connector_dump, meta_dump, meta_response,
};
use super::store::{self, CustomerConnector};
use crate::IntegrationsState;
use crate::sql::{dict, internal, ok, s};
use crate::table_model::{self, Bound, TableModel};

type Reader = Authorized<AdminOrAnalyst>;

/// The routes, by full path.
pub fn router(state: IntegrationsState) -> Router {
    let p = "/api/network_connectors";
    Router::new()
        .route(
            &format!("{p}/available_network_connectors"),
            get(available).put(update_available),
        )
        .route(
            &format!("{p}/available_network_connectors/{{network_connector_id}}"),
            get(available_one),
        )
        .route(&format!("{p}/customer_network_connectors"), get(connectors))
        .route(&format!("{p}/customer_network_connectors_meta"), get(metas))
        .route(
            &format!("{p}/customer_network_connectors/{{customer_code}}"),
            get(connectors_of),
        )
        .route(
            &format!("{p}/customer_network_connectors_meta/{{customer_code}}"),
            get(metas_of),
        )
        .route(&format!("{p}/create_network_connector"), post(create))
        .route(
            &format!("{p}/create_network_connector_meta"),
            post(create_meta),
        )
        .route(
            &format!("{p}/update_network_connector/{{customer_code}}"),
            put(update),
        )
        .route(&format!("{p}/delete_network_connector"), delete(remove))
        .route(
            &format!("{p}/delete_network_connector_meta"),
            delete(remove_meta),
        )
        .with_state(state)
}

fn text<'a>(dump: &'a PyValue, key: &str) -> &'a str {
    field(dump, key).as_str().unwrap_or_default()
}

fn keys(dump: &PyValue) -> Vec<(String, String)> {
    match field(dump, "network_connector_auth_keys") {
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

async fn visible(ctx: &AppContext, auth: &Reader) -> Result<Option<Vec<String>>, ApiError> {
    Ok(auth.access(ctx).await?.scoped_customer_codes(None))
}

fn seen<T>(items: Vec<T>, codes: Option<&[String]>, code: impl Fn(&T) -> &str) -> Vec<T> {
    match codes {
        None => items,
        Some(codes) => items
            .into_iter()
            .filter(|i| codes.iter().any(|c| c == code(i)))
            .collect(),
    }
}

async fn available(State(st): State<IntegrationsState>, _auth: Reader) -> ApiResult {
    let catalog = store::catalog(&st.ctx.db).await.map_err(internal)?;
    Ok(ok(&dict(vec![
        (
            "network_connector_keys",
            PyValue::List(catalog.iter().map(catalog_dump).collect()),
        ),
        (
            "message",
            s("Available network_connectors successfully retrieved."),
        ),
        ("success", PyValue::Bool(true)),
    ])))
}

async fn available_one(
    State(st): State<IntegrationsState>,
    _auth: Reader,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("network_connector_id", &raw)?;
    let entry = store::catalog_by_id(&st.ctx.db, id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found(format!("Network connector {id} not found")))?;
    Ok(ok(&dict(vec![
        ("network_connector", catalog_dump(&entry)),
        (
            "message",
            s("Available network connector successfully retrieved."),
        ),
        ("success", PyValue::Bool(true)),
    ])))
}

/// `AvailableNetworkConnectors` as a request body.
static AVAILABLE: TableModel = TableModel {
    class: "AvailableNetworkConnectors",
    fields: &[
        "id",
        "network_connector_name",
        "description",
        "network_connector_details",
    ],
    defaulted: &["id"],
    relationships: &["network_connector_keys"],
};

/// `PUT /available_network_connectors`: written and committed, then the
/// response is built with a field the model does not have — the 400 of its
/// `ValidationError`, whatever the list held.
async fn update_available(
    State(st): State<IntegrationsState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let ctx = &st.ctx;
    let items = table_model::read_list(&body, &AVAILABLE)?;
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    for item in &items {
        let name = item.get("network_connector_name");
        let found: Option<i32> = match table_model::bound(&name)? {
            Bound::Null => None,
            b => {
                let sql = "SELECT available_network_connectors.id, \
                     available_network_connectors.network_connector_name, \
                     available_network_connectors.description, \
                     available_network_connectors.network_connector_details \nFROM \
                     available_network_connectors \nWHERE \
                     available_network_connectors.network_connector_name = ?";
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
            return Err(ApiError::not_found(format!(
                "NetworkConnectors {} not found.",
                name.py_str()
            )));
        };
        sqlx::query(
            "UPDATE available_network_connectors SET description=?, network_connector_details=? \
             WHERE available_network_connectors.id = ?",
        )
        .bind(table_model::stored(&item.get("description"))?)
        .bind(table_model::stored(&item.get("network_connector_details"))?)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    let kwargs = PyValue::Dict(vec![
        (
            "available_network_connectors".into(),
            // Only the head and tail of this repr reach the message.
            PyValue::List(Vec::new()),
        ),
        (
            "message".into(),
            s("Available network_connectors successfully updated."),
        ),
        ("success".into(), PyValue::Bool(true)),
    ]);
    let repr = kwargs.py_repr().replacen(
        "[]",
        &format!(
            "[{}]",
            items
                .iter()
                .map(|i| i.repr(&AVAILABLE))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        1,
    );
    Err(ApiError::bad_request(format!(
        "1 validation error for AvailableNetworkConnectorsResponse\nnetwork_connector_keys\n  Field \
         required [type=missing, input_value={}, input_type=dict]\n    For further information \
         visit https://errors.pydantic.dev/{}/v/missing",
        copilot_upstream::model::truncate_repr(repr),
        copilot_upstream::model::PYDANTIC_VERSION
    )))
}

fn connectors_response(list: &[CustomerConnector], processed: bool) -> Result<PyValue, ApiError> {
    let dumps = list
        .iter()
        .map(|c| connector_dump(c, processed))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;
    Ok(dict(vec![
        ("available_network_connectors", PyValue::List(dumps)),
        (
            "message",
            s("Customer network_connectors successfully retrieved."),
        ),
        ("success", PyValue::Bool(true)),
    ]))
}

async fn connectors(State(st): State<IntegrationsState>, auth: Reader) -> ApiResult {
    let all = store::customer_connectors(&st.ctx.db, None)
        .await
        .map_err(internal)?;
    let codes = visible(&st.ctx, &auth).await?;
    let list = seen(all, codes.as_deref(), |c| c.customer_code.as_str());
    Ok(ok(&connectors_response(&list, true)?))
}

async fn connectors_of(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let list = store::customer_connectors(&st.ctx.db, Some(&code))
        .await
        .map_err(internal)?;
    Ok(ok(&connectors_response(&list, false)?))
}

async fn metas(State(st): State<IntegrationsState>, auth: Reader) -> ApiResult {
    let all = match store::metas(&st.ctx.db, None, None).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Error while fetching customer network_connectors metadata: {e}");
            Vec::new()
        }
    };
    let codes = visible(&st.ctx, &auth).await?;
    let list = seen(all, codes.as_deref(), |m| m.customer_code.as_str());
    Ok(ok(&meta_response(
        "Customer network_connectors metadata successfully retrieved.",
        true,
        Some(list.iter().map(meta_dump).collect()),
    )))
}

async fn metas_of(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let list = store::metas(&st.ctx.db, Some(&code), None)
        .await
        .map_err(internal)?;
    Ok(ok(&meta_response(
        "Customer network_connectors metadata successfully retrieved.",
        true,
        Some(list.iter().map(meta_dump).collect()),
    )))
}

/// `validate_network_connector_name`.
async fn validate_name(ctx: &AppContext, name: &str) -> Result<(), ApiError> {
    let catalog = store::catalog(&ctx.db).await.map_err(internal)?;
    if catalog.iter().any(|c| c.name == name) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "NetworkConnectors {name} is not a valid network_connector."
        )))
    }
}

async fn validate_customer(ctx: &AppContext, code: &str) -> Result<(), ApiError> {
    if !crate::integrations::store::customer_exists(&ctx.db, code)
        .await
        .map_err(internal)?
    {
        return Err(ApiError::bad_request(format!(
            "Customer {code} does not exist."
        )));
    }
    if !crate::integrations::store::customer_meta_exists(&ctx.db, code)
        .await
        .map_err(internal)?
    {
        return Err(ApiError::bad_request(format!(
            "Customer {code} meta does not exist. Please provision the customer before creating \
             an network_connector."
        )));
    }
    Ok(())
}

async fn create(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let ctx = &st.ctx;
    let req = body_model(&body, &CREATE)?;
    let code = text(&req, "customer_code");
    let name = text(&req, "network_connector_name");
    auth.enforce_customer(ctx, code).await?;
    validate_name(ctx, name).await?;
    let catalog = store::catalog(&ctx.db).await.map_err(internal)?;
    let wanted = catalog
        .into_iter()
        .find(|c| c.name == name)
        .map(|c| c.keys)
        .unwrap_or_default();
    let given = keys(&req);
    if let Some(missing) = wanted.iter().find(|k| !given.iter().any(|(n, _)| n == *k)) {
        return Err(ApiError::bad_request(format!(
            "NetworkConnectors auth key {missing} does not exist."
        )));
    }
    validate_customer(ctx, code).await?;
    if store::exists(&ctx.db, code, name).await.map_err(internal)? {
        return Err(ApiError::bad_request(format!(
            "Customer network_connector {code} {name} already exists."
        )));
    }
    let missing = || ApiError::not_found(format!("NetworkConnectors service {name} not found."));
    let (service_id, _) = store::catalog_first_by_name(&ctx.db, name)
        .await
        .map_err(internal)?
        .ok_or_else(missing)?;
    let (_, service_name) = store::catalog_first_by_name(&ctx.db, name)
        .await
        .map_err(internal)?
        .ok_or_else(missing)?;
    let config = field(&req, "network_connector_config");
    let pool = ctx.db.pool();
    let mut tx = pool.begin().await.map_err(internal)?;
    let svc = sqlx::query(
        "INSERT INTO network_connectors_services (service_name, auth_type) VALUES (?, ?)",
    )
    .bind(name)
    .bind(text(config, "auth_type"))
    .execute(&mut *tx)
    .await
    .map_err(internal)?
    .last_insert_id();
    sqlx::query(
        "INSERT INTO network_connectors_configs (network_connector_service_id, config_key, \
         config_value) VALUES (?, ?, ?)",
    )
    .bind(svc)
    .bind(text(config, "config_key"))
    .bind(text(config, "config_value"))
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    let connector = sqlx::query(
        "INSERT INTO customer_network_connectors (customer_code, customer_name, \
         network_connector_service_id, network_connector_service_name, deployed) VALUES (?, ?, \
         ?, ?, ?)",
    )
    .bind(code)
    .bind(text(&req, "customer_name"))
    .bind(service_id)
    .bind(&service_name)
    .bind(false)
    .execute(&mut *tx)
    .await
    .map_err(internal)?
    .last_insert_id();
    let mut tx = Some(tx);
    for (key, value) in &given {
        let mut t = match tx.take() {
            Some(t) => t,
            None => pool.begin().await.map_err(internal)?,
        };
        let sub = sqlx::query(
            "INSERT INTO network_connectors_subscriptions (customer_id, \
             network_connectors_service_id) VALUES (?, ?)",
        )
        .bind(connector)
        .bind(svc)
        .execute(&mut *t)
        .await
        .map_err(internal)?
        .last_insert_id();
        sqlx::query(
            "INSERT INTO network_connectors_keys (subscription_id, auth_key_name, auth_value) \
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
    drop(tx);
    Ok(ok(&dict(vec![
        (
            "message",
            s(format!(
                "Customer network_connector {code} {name} successfully created."
            )),
        ),
        ("success", PyValue::Bool(true)),
    ])))
}

async fn create_meta(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let ctx = &st.ctx;
    let req = body_model(&body, &META_SCHEMA)?;
    let code = text(&req, "customer_code");
    let name = text(&req, "network_connector_name");
    auth.enforce_customer(ctx, code).await?;
    validate_customer(ctx, code).await?;
    if !store::metas(&ctx.db, Some(code), Some(name))
        .await
        .map_err(internal)?
        .is_empty()
    {
        return Err(ApiError::bad_request(format!(
            "Customer network_connector meta {code} {name} already exists."
        )));
    }
    let id = match field(&req, "id") {
        PyValue::Int(i) => i.parse::<i64>().ok(),
        _ => None,
    };
    let columns = "customer_code, network_connector_name, graylog_input_id, graylog_index_id, \
                   graylog_stream_id, graylog_pipeline_id, graylog_content_pack_input_id, \
                   graylog_content_pack_stream_id, grafana_org_id, grafana_dashboard_folder_id, \
                   grafana_datasource_uid";
    // The schema has no pipeline, content-pack or datasource field: those
    // NOT NULL columns get NULL and MySQL refuses the row.
    let sql = match id {
        Some(_) => format!(
            "INSERT INTO customer_network_connectors_meta (id, {columns}) VALUES (?, ?, ?, ?, ?, \
             ?, NULL, NULL, NULL, ?, ?, NULL)"
        ),
        None => format!(
            "INSERT INTO customer_network_connectors_meta ({columns}) VALUES (?, ?, ?, ?, ?, \
             NULL, NULL, NULL, ?, ?, NULL)"
        ),
    };
    let mut q = sqlx::query(&sql);
    if let Some(id) = id {
        q = q.bind(id);
    }
    let inserted = q
        .bind(code)
        .bind(name)
        .bind(field(&req, "graylog_input_id").as_str())
        .bind(text(&req, "graylog_index_id"))
        .bind(text(&req, "graylog_stream_id"))
        .bind(text(&req, "grafana_org_id"))
        .bind(text(&req, "grafana_dashboard_folder_id"))
        .execute(ctx.db.pool())
        .await;
    Ok(ok(&match inserted {
        Ok(_) => meta_response(
            "Customer network_connector metadata successfully created.",
            true,
            None,
        ),
        Err(e) => {
            tracing::error!("Error while creating customer network_connector metadata: {e}");
            meta_response(
                "Error while creating customer network_connector metadata.",
                false,
                None,
            )
        }
    }))
}

async fn update(
    State(st): State<IntegrationsState>,
    Path(code): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let ctx = &st.ctx;
    auth.enforce_customer(ctx, &code).await?;
    let req = body_model(&body, &UPDATE)?;
    let name = text(&req, "network_connector_name");
    validate_name(ctx, name).await?;
    let list = store::customer_connectors(&ctx.db, Some(&code))
        .await
        .map_err(internal)?;
    let found = list.iter().any(|c| {
        c.subscriptions
            .iter()
            .any(|s| s.service.as_ref().is_some_and(|v| v.service_name == name))
    });
    if !found {
        return Err(ApiError::not_found(
            "Customer network_connector with specified service name not found.",
        ));
    }
    // `validate_network_connector_auth_key_update` reads
    // `NetworkConnectorsWithAuthKeys.auth_keys`, which does not exist.
    Err(ApiError::internal(
        "AttributeError: 'NetworkConnectorsWithAuthKeys' object has no attribute 'auth_keys'",
    ))
}

async fn remove(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let ctx = &st.ctx;
    let req = body_model(&body, &DELETE)?;
    let code = text(&req, "customer_code");
    let name = text(&req, "network_connector_name");
    auth.enforce_customer(ctx, code).await?;
    let ids = store::customer_and_service_ids(&ctx.db, code, name)
        .await
        .map_err(internal)?;
    let Some(&(customer_id, service_id)) = ids.first() else {
        return Err(ApiError::not_found("Customer network_connector not found"));
    };
    let subs = store::subscription_ids(&ctx.db, customer_id, service_id)
        .await
        .map_err(internal)?;
    if subs.is_empty() {
        return Err(ApiError::not_found(
            "No subscriptions found for customer network_connector",
        ));
    }
    let marks = vec!["?"; subs.len()].join(", ");
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    let sql = format!(
        "DELETE FROM network_connectors_keys WHERE network_connectors_keys.subscription_id IN \
         ({marks})"
    );
    let mut q = sqlx::query(&sql);
    for id in &subs {
        q = q.bind(id);
    }
    q.execute(&mut *tx).await.map_err(internal)?;
    let sql = format!(
        "DELETE FROM network_connectors_subscriptions WHERE network_connectors_subscriptions.id \
         IN ({marks})"
    );
    let mut q = sqlx::query(&sql);
    for id in &subs {
        q = q.bind(id);
    }
    q.execute(&mut *tx).await.map_err(internal)?;
    sqlx::query(
        "DELETE FROM network_connectors_configs WHERE \
         network_connectors_configs.network_connector_service_id = ?",
    )
    .bind(service_id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query("DELETE FROM network_connectors_services WHERE network_connectors_services.id = ?")
        .bind(service_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    sqlx::query("DELETE FROM customer_network_connectors WHERE customer_network_connectors.id = ?")
        .bind(customer_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(ok(&dict(vec![
        (
            "message",
            s(format!(
                "Customer network_connector {code} {name} successfully deleted."
            )),
        ),
        ("success", PyValue::Bool(true)),
    ])))
}

async fn remove_meta(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let ctx = &st.ctx;
    let req = body_model(&body, &META_SCHEMA)?;
    let code = text(&req, "customer_code");
    let name = text(&req, "network_connector_name");
    auth.enforce_customer(ctx, code).await?;
    let deleted = sqlx::query(
        "DELETE FROM customer_network_connectors_meta WHERE \
         customer_network_connectors_meta.customer_code = ? AND \
         customer_network_connectors_meta.network_connector_name = ?",
    )
    .bind(code)
    .bind(name)
    .execute(ctx.db.pool())
    .await;
    Ok(ok(&match deleted {
        Ok(_) => meta_response(
            "Customer network_connector metadata successfully deleted.",
            true,
            None,
        ),
        Err(e) => {
            tracing::error!("Error while deleting customer network_connector metadata: {e}");
            meta_response(
                "Error while deleting customer network_connector metadata.",
                false,
                None,
            )
        }
    }))
}
