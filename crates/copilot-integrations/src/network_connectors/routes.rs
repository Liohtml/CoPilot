//! `/api/network_connectors/*` — every route of
//! `network_connector_settings_router`, `require_any_scope("admin",
//! "analyst")`.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, get, post, put};
use copilot_web::validate::path_int;
use copilot_web::{AdminOrAnalyst, ApiResult, Authorized, WithJson};

use super::services;
use crate::IntegrationsState;
use crate::sql::ok;

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

async fn available(State(st): State<IntegrationsState>, _auth: Reader) -> ApiResult {
    Ok(ok(&services::available(&st.ctx).await?))
}

async fn available_one(
    State(st): State<IntegrationsState>,
    _auth: Reader,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("network_connector_id", &raw)?;
    Ok(ok(&services::available_one(&st.ctx, id).await?))
}

async fn update_available(
    State(st): State<IntegrationsState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    Ok(ok(&services::update_available(&st.ctx, &body).await?))
}

async fn connectors(State(st): State<IntegrationsState>, auth: Reader) -> ApiResult {
    Ok(ok(&services::connectors(&st.ctx, &auth).await?))
}

async fn connectors_of(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(ok(&services::connectors_of(&st.ctx, &code).await?))
}

async fn metas(State(st): State<IntegrationsState>, auth: Reader) -> ApiResult {
    Ok(ok(&services::metas(&st.ctx, &auth).await?))
}

async fn metas_of(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(ok(&services::metas_of(&st.ctx, &code).await?))
}

async fn create(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    Ok(ok(&services::create(&st.ctx, &auth, &body).await?))
}

async fn create_meta(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    Ok(ok(&services::create_meta(&st.ctx, &auth, &body).await?))
}

async fn update(
    State(st): State<IntegrationsState>,
    Path(code): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(ok(&services::update(&st.ctx, &code, &body).await?))
}

async fn remove(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    Ok(ok(&services::remove(&st.ctx, &auth, &body).await?))
}

async fn remove_meta(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    Ok(ok(&services::remove_meta(&st.ctx, &auth, &body).await?))
}
