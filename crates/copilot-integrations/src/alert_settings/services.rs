//! The alert creation settings' flows: tenancy by customer name, the reads
//! and the writes, each answering what Python's route answers.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Ty, field};
use copilot_upstream::respond::{body_model, body_value};
use copilot_web::body::JsonBody;
use copilot_web::{ApiError, AppContext, CurrentUser};
use http::StatusCode;

use super::NVD_URL;
use super::schema::{
    EVENT_ORDER_CREATE, SETTINGS_CREATE, configs_dump, order_dump, settings_dump, table_dump,
};
use super::store::{self, By};
use crate::sql::{dict, internal, s};

/// `List[EventOrderCreate]` (the `PUT` body).
static ORDERS: Ty = Ty::List(&Ty::Model(&EVENT_ORDER_CREATE));

/// `verify_customer_name_access`: the name's first settings row names the
/// owner; no row is no permission for a scoped caller.
pub async fn name_access(ctx: &AppContext, user: &CurrentUser, name: &str) -> Result<(), ApiError> {
    let owner = store::code_of_name(&ctx.db, name).await.map_err(internal)?;
    user.enforce_owned(ctx, owner.as_deref(), &format!("customer {name}"))
        .await
}

fn missing_settings() -> ApiError {
    ApiError::not_found("Alert creation settings not found.")
}

fn text<'a>(v: &'a PyValue, key: &str) -> &'a str {
    field(v, key).as_str().unwrap_or_default()
}

fn list(v: &PyValue) -> &[PyValue] {
    match v {
        PyValue::List(items) => items,
        _ => &[],
    }
}

fn config_triple(c: &PyValue) -> (&str, &str, &str) {
    (text(c, "event_id"), text(c, "field"), text(c, "value"))
}

/// `GET /{customer_code}/event_configs` (the path's tenant already checked).
pub async fn event_configs(ctx: &AppContext, code: &str) -> Result<PyValue, ApiError> {
    let settings = store::load(&ctx.db, By::Code(code))
        .await
        .map_err(internal)?;
    let orders = settings.map(|s| s.orders).unwrap_or_default();
    if orders.is_empty() {
        return Err(ApiError::not_found(
            "No event configs found for this customer.",
        ));
    }
    Ok(PyValue::List(orders.iter().map(configs_dump).collect()))
}

/// `POST /create`: the body's customer checked, then the row, every order
/// and every config in one transaction; the answer is the table model as
/// stored.
pub async fn create(
    ctx: &AppContext,
    user: &CurrentUser,
    body: &JsonBody,
) -> Result<PyValue, ApiError> {
    let req = body_model(body, &SETTINGS_CREATE)?;
    let code = text(&req, "customer_code");
    user.enforce_customer(ctx, code).await?;
    if store::exists_for_code(&ctx.db, code)
        .await
        .map_err(internal)?
    {
        return Err(ApiError::http(
            StatusCode::OK,
            "Alert creation settings already exist.",
        ));
    }
    let opt = |k: &str| field(&req, k).as_str().map(str::to_string);
    let iris = match field(&req, "iris_customer_id") {
        PyValue::Int(i) => Some(i.clone()),
        _ => None,
    };
    // A `None` column is left out of the INSERT, so `nvd_url` falls back to
    // its default.
    let nvd = opt("nvd_url").unwrap_or_else(|| NVD_URL.to_string());
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    let id = sqlx::query(
        "INSERT INTO custom_alert_creation_settings (customer_code, customer_name, \
         excluded_wazuh_rules, excluded_suricata_rules, timefield, office365_organization_id, \
         iris_customer_id, iris_customer_name, iris_index, grafana_url, misp_url, opencti_url, \
         custom_message, shuffle_endpoint, nvd_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
         ?, ?, ?)",
    )
    .bind(code)
    .bind(text(&req, "customer_name"))
    .bind(opt("excluded_wazuh_rules"))
    .bind(opt("excluded_suricata_rules"))
    .bind(opt("timefield"))
    .bind(opt("office365_organization_id"))
    .bind(iris)
    .bind(opt("iris_customer_name"))
    .bind(opt("iris_index"))
    .bind(opt("grafana_url"))
    .bind(opt("misp_url"))
    .bind(opt("opencti_url"))
    .bind(opt("custom_message"))
    .bind(opt("shuffle_endpoint"))
    .bind(nvd)
    .execute(&mut *tx)
    .await
    .map_err(internal)?
    .last_insert_id();
    let id = i64::try_from(id).map_err(ApiError::internal)?;
    // Every order first, then every config (the unit of work's order).
    let orders = list(field(&req, "event_orders"));
    let mut order_ids = Vec::new();
    for order in orders {
        order_ids.push(
            store::insert_order(&mut tx, id, text(order, "order_label"))
                .await
                .map_err(internal)?,
        );
    }
    for (order, order_id) in orders.iter().zip(&order_ids) {
        for config in list(field(order, "event_configs")) {
            store::insert_config(&mut tx, *order_id, config_triple(config))
                .await
                .map_err(internal)?;
        }
    }
    tx.commit().await.map_err(internal)?;
    let row = store::load(&ctx.db, By::Id(id))
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("the settings row vanished"))?;
    Ok(table_dump(&row))
}

/// `GET /{customer_name}` (the name's owner already checked).
pub async fn by_name(ctx: &AppContext, name: &str) -> Result<PyValue, ApiError> {
    let settings = store::load(&ctx.db, By::Name(name))
        .await
        .map_err(internal)?
        .ok_or_else(missing_settings)?;
    Ok(settings_dump(&settings))
}

/// `POST /{customer_name}/event`: a new order and its configs.
pub async fn add_event_order(
    ctx: &AppContext,
    name: &str,
    body: &JsonBody,
) -> Result<PyValue, ApiError> {
    let req = body_model(body, &EVENT_ORDER_CREATE)?;
    let settings = store::load(&ctx.db, By::Name(name))
        .await
        .map_err(internal)?
        .ok_or_else(missing_settings)?;
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    let order_id = store::insert_order(&mut tx, settings.id, text(&req, "order_label"))
        .await
        .map_err(internal)?;
    for config in list(field(&req, "event_configs")) {
        store::insert_config(&mut tx, order_id, config_triple(config))
            .await
            .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    // The re-query finds the order in the identity map, whose configs are
    // the ones just added, in that order.
    let configs = list(field(&req, "event_configs"))
        .iter()
        .enumerate()
        .map(|(i, c)| store::EventConfig {
            id: i as i64,
            event_id: text(c, "event_id").to_string(),
            field: text(c, "field").to_string(),
            value: text(c, "value").to_string(),
        })
        .collect();
    Ok(order_dump(&store::EventOrder {
        id: order_id,
        order_label: text(&req, "order_label").to_string(),
        configs,
    }))
}

/// `PUT /{customer_name}`: configs appended to existing orders.
pub async fn update_event_orders(
    ctx: &AppContext,
    name: &str,
    body: &JsonBody,
) -> Result<PyValue, ApiError> {
    let req = body_value(body, &ORDERS)?;
    let mut settings = store::load(&ctx.db, By::Name(name))
        .await
        .map_err(internal)?
        .ok_or_else(missing_settings)?;
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    for order in list(&req) {
        let label = text(order, "order_label");
        let Some(existing) = settings.orders.iter_mut().find(|o| o.order_label == label) else {
            return Err(ApiError::not_found(format!(
                "Event order with order_label: {label} not found."
            )));
        };
        for config in list(field(order, "event_configs")) {
            let (event_id, field_name, value) = config_triple(config);
            store::insert_config(&mut tx, existing.id, (event_id, field_name, value))
                .await
                .map_err(internal)?;
            // The new row joins the loaded collection (`back_populates`).
            existing.configs.push(store::EventConfig {
                id: 0,
                event_id: event_id.to_string(),
                field: field_name.to_string(),
                value: value.to_string(),
            });
        }
    }
    tx.commit().await.map_err(internal)?;
    // `refresh(settings)` reloads the orders with the joined load they came
    // with; an order already in the identity map keeps the collection it
    // holds in memory (loaded order, then the appended rows).
    let mut refreshed = store::load(&ctx.db, By::Id(settings.id))
        .await
        .map_err(internal)?
        .ok_or_else(missing_settings)?;
    for order in &mut refreshed.orders {
        if let Some(held) = settings.orders.iter_mut().find(|o| o.id == order.id) {
            order.configs = std::mem::take(&mut held.configs);
        }
    }
    Ok(settings_dump(&refreshed))
}

/// `DELETE /{customer_name}/event/{order_label}`: the order and its
/// configs; its conditions stay, their key nulled.
pub async fn delete_event_order(
    ctx: &AppContext,
    name: &str,
    label: &str,
) -> Result<PyValue, ApiError> {
    let settings = store::load(&ctx.db, By::Name(name))
        .await
        .map_err(internal)?
        .ok_or_else(missing_settings)?;
    let Some(order) = settings.orders.iter().find(|o| o.order_label == label) else {
        return Err(ApiError::not_found(format!(
            "Event order with order_label: {label} not found."
        )));
    };
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    // Deleting the order nulls its conditions' key (no delete cascade).
    sqlx::query(
        "UPDATE custom_alert_creation_condition SET event_order_id=NULL WHERE \
         custom_alert_creation_condition.event_order_id = ?",
    )
    .bind(order.id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    for config in &order.configs {
        sqlx::query(
            "DELETE FROM custom_alert_creation_event_config WHERE \
             custom_alert_creation_event_config.id = ?",
        )
        .bind(config.id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }
    sqlx::query(
        "DELETE FROM custom_alert_creation_event_order WHERE \
         custom_alert_creation_event_order.id = ?",
    )
    .bind(order.id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(dict(vec![
        (
            "message",
            s(format!(
                "Event order with order_label: {label} and related alert creation event configs \
                 deleted."
            )),
        ),
        ("success", PyValue::Bool(true)),
    ]))
}
