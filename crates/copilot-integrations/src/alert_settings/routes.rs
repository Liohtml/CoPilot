//! `/api/api/v1/alert_settings/*` — the six routes, all
//! `require_any_scope("admin", "analyst")`.
//!
//! One path parameter name serves both keys (`{customer}`): it is the code
//! in `/{…}/event_configs` and the name everywhere else. `GET /create`
//! (the name `create`) and the other methods on `/create` reach Python
//! through the 405 hand-off, which answers them as its `/{customer_name}`
//! routes.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use copilot_web::{AdminOrAnalyst, ApiResult, Authorized, WithJson};

use super::services;
use crate::IntegrationsState;
use crate::sql::ok;

type Reader = Authorized<AdminOrAnalyst>;

/// The routes, by full path.
pub fn router(state: IntegrationsState) -> Router {
    let p = "/api/api/v1/alert_settings";
    Router::new()
        .route(
            &format!("{p}/{{customer}}/event_configs"),
            get(event_configs),
        )
        .route(&format!("{p}/create"), post(create))
        .route(
            &format!("{p}/{{customer}}"),
            get(get_settings).put(update_event_orders),
        )
        .route(&format!("{p}/{{customer}}/event"), post(add_event_order))
        .route(
            &format!("{p}/{{customer}}/event/{{order_label}}"),
            delete(delete_event_order),
        )
        .with_state(state)
}

async fn event_configs(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(ok(&services::event_configs(&st.ctx, &code).await?))
}

async fn create(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    Ok(ok(&services::create(&st.ctx, &auth, &body).await?))
}

async fn get_settings(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path(name): Path<String>,
) -> ApiResult {
    services::name_access(&st.ctx, &auth, &name).await?;
    Ok(ok(&services::by_name(&st.ctx, &name).await?))
}

async fn add_event_order(
    State(st): State<IntegrationsState>,
    Path(name): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    services::name_access(&st.ctx, &auth, &name).await?;
    Ok(ok(&services::add_event_order(&st.ctx, &name, &body).await?))
}

async fn update_event_orders(
    State(st): State<IntegrationsState>,
    Path(name): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    services::name_access(&st.ctx, &auth, &name).await?;
    Ok(ok(
        &services::update_event_orders(&st.ctx, &name, &body).await?
    ))
}

async fn delete_event_order(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path((name, label)): Path<(String, String)>,
) -> ApiResult {
    services::name_access(&st.ctx, &auth, &name).await?;
    Ok(ok(
        &services::delete_event_order(&st.ctx, &name, &label).await?
    ))
}
