//! `/api/connectors` — `app/connectors/routes.py`.
//!
//! | Route | Guard | Here |
//! |---|---|---|
//! | `GET ""` | `get_current_user(scopes=["admin"])` | Rust |
//! | `GET /{connector_id}` | `require_any_scope("admin")` | Rust |
//!
//! Everything else on these paths (the YAML upload, which writes a file on
//! the Python host) is not routed here and falls through to the legacy
//! backend.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use copilot_web::validate::path_int;
use copilot_web::{AdminOnly, ApiError, ApiResult, Authorized, ScopedUser};

use crate::ConnectorsState;
use crate::schema::{ConnectorListResponse, ConnectorsListResponse};
use crate::services;

/// The router, mounted at `/api/connectors`.
pub fn router(state: ConnectorsState) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/{connector_id}", get(get_one))
        .with_state(state)
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

/// `GET ""`: every connector, secrets included (admin only).
async fn list(_admin: ScopedUser<AdminOnly>, State(st): State<ConnectorsState>) -> ApiResult {
    let connectors = services::list(&st.ctx.db).await?;
    if connectors.is_empty() {
        return Err(ApiError::not_found("No connectors found"));
    }
    Ok(json(ConnectorsListResponse {
        connectors,
        success: true,
        message: "Connectors fetched successfully".into(),
    }))
}

/// `GET /{connector_id}` (admin only, GHSA-c5pw-2h98-r798).
async fn get_one(
    _admin: Authorized<AdminOnly>,
    State(st): State<ConnectorsState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("connector_id", &raw)?;
    let connector = services::get(&st.ctx.db, id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("No connector found for ID: {id}")))?;
    Ok(json(ConnectorListResponse {
        connector,
        success: true,
        message: "Connector fetched successfully".into(),
    }))
}
