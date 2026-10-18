//! `/api/integrations/*` — every route of `integration_settings_router`.
//!
//! All are `require_any_scope("admin", "analyst")`; those with a
//! `{customer_code}` in the path carry `verify_customer_code_access`,
//! checked before the query and the body are validated (FastAPI's order).
//! The provisioning routes of individual integrations
//! (`/api/office365/provision`, the AWS ones, `/api/integrations/modules/*`)
//! are not part of this router.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, get, post, put};
use copilot_web::validate::path_int;
use copilot_web::{AdminOrAnalyst, ApiResult, Authorized, QueryPairs, WithJson};

use super::services;
use crate::IntegrationsState;
use crate::sql::ok;

type Reader = Authorized<AdminOrAnalyst>;

/// The routes, by full path.
pub fn router(state: IntegrationsState) -> Router {
    let p = "/api/integrations";
    Router::new()
        .route(
            &format!("{p}/available_integrations"),
            get(available).put(update_available),
        )
        .route(
            &format!("{p}/available_integrations/{{integration_id}}"),
            get(available_one),
        )
        .route(
            &format!("{p}/customer_integrations"),
            get(customer_integrations),
        )
        .route(&format!("{p}/customer_integrations_meta"), get(metas))
        .route(
            &format!("{p}/customer_integrations/{{customer_code}}"),
            get(customer_integrations_of),
        )
        .route(
            &format!("{p}/customer_integrations_meta/{{customer_code}}"),
            get(metas_of),
        )
        .route(&format!("{p}/create_integration"), post(create))
        .route(&format!("{p}/create_integration_meta"), post(create_meta))
        .route(
            &format!("{p}/update_integration/{{customer_code}}"),
            put(update),
        )
        .route(
            &format!("{p}/delete_integration"),
            delete(delete_integration),
        )
        .route(
            &format!(
                "{p}/integration_customer/{{integration_name}}/{{auth_key_name}}/{{auth_key_value}}"
            ),
            get(customer_by_auth_key),
        )
        .route(
            &format!("{p}/meta_auto/{{customer_code}}/{{integration_name}}"),
            get(meta_auto),
        )
        .route(&format!("{p}/update_meta_auto"), put(update_meta_auto))
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
    let id = path_int("integration_id", &raw)?;
    Ok(ok(&services::available_one(&st.ctx, id).await?))
}

async fn update_available(
    State(st): State<IntegrationsState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    Ok(ok(&services::update_available(&st.ctx, &body).await?))
}

async fn customer_integrations(State(st): State<IntegrationsState>, auth: Reader) -> ApiResult {
    Ok(ok(&services::customer_integrations(&st.ctx, &auth).await?))
}

async fn metas(State(st): State<IntegrationsState>, auth: Reader) -> ApiResult {
    Ok(ok(&services::metas(&st.ctx, &auth).await?))
}

async fn customer_integrations_of(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    Ok(ok(
        &services::customer_integrations_of(&st.ctx, &code).await?
    ))
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

async fn delete_integration(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    Ok(ok(&services::delete(&st, &auth, &body).await?))
}

async fn customer_by_auth_key(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path((integration, key, value)): Path<(String, String, String)>,
) -> ApiResult {
    Ok(ok(&services::customer_by_auth_key(
        &st.ctx,
        &auth,
        &integration,
        &key,
        &value,
    )
    .await?))
}

async fn meta_auto(
    State(st): State<IntegrationsState>,
    auth: Reader,
    Path((code, name)): Path<(String, String)>,
    query: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &code).await?;
    let instance = query.get("instance_name");
    Ok(ok(
        &services::meta_auto(&st.ctx, &code, &name, instance).await?
    ))
}

async fn update_meta_auto(
    State(st): State<IntegrationsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    Ok(ok(&services::update_meta_auto(&st.ctx, &auth, &body).await?))
}
