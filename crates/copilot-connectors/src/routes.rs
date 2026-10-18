//! `/api/connectors` — `app/connectors/routes.py`.
//!
//! | Route | Guard | Here |
//! |---|---|---|
//! | `GET ""` | `get_current_user(scopes=["admin"])` | Rust |
//! | `GET /{connector_id}` | `require_any_scope("admin")` | Rust |
//! | `PUT /{connector_id}` | `get_current_user(scopes=["admin"])` | Rust |
//! | `POST /verify/{connector_id}` | `require_any_scope("admin", "analyst")` | Rust |
//! | `POST /upload/{connector_identifier}` | `get_current_user(scopes=["admin"])` | Rust ([`crate::upload`]), the verification that follows included |
//!
//! An update writes the row, then verifies the connector (the tool's API
//! is called) and records `connector.update`. The binary registers a
//! verifier for every connector `get_connector_service` knows
//! ([`crate::verify::PYTHON_VERIFIED`], pinned by the standalone e2e suite),
//! so a connector without one is a name Python does not support either:
//! its update is written and left unverified, its verification is the 404
//! `verify_connector_by_id`'s `None` is.

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;

use copilot_core::audit::AuditRecord;
use copilot_web::validate::path_int;
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, CurrentUser, ScopedUser, WithJson,
};

use crate::ConnectorsState;
use crate::schema::{ConnectorListResponse, ConnectorOut, ConnectorsListResponse, UpdateConnector};
use crate::services;

/// The router, mounted at `/api/connectors`.
pub fn router(state: ConnectorsState) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/{connector_id}", get(get_one).put(update))
        .route("/verify/{connector_id}", post(verify))
        .route(
            "/upload/{connector_identifier}",
            post(crate::upload::upload),
        )
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
        .ok_or_else(|| not_found(id))?;
    Ok(json(ConnectorListResponse {
        connector,
        success: true,
        message: "Connector fetched successfully".into(),
    }))
}

fn not_found(id: i64) -> ApiError {
    ApiError::not_found(format!("No connector found for ID: {id}"))
}

/// `PUT /{connector_id}`: `update_connector_by_id`, then
/// `verify_connector_by_id`, then the `connector.update` audit row.
async fn update(
    State(st): State<ConnectorsState>,
    Path(raw): Path<String>,
    WithJson(user, body): WithJson<ScopedUser<AdminOnly>>,
) -> ApiResult {
    let id = path_int("connector_id", &raw)?;
    let body = body.model(UpdateConnector::read)?;
    let Some((row, history)) = services::load(&st.ctx.db, id).await? else {
        return Err(not_found(id));
    };
    let name = row.connector_name.clone();
    let verifier = st.verifiers.get(&name);
    let now = Utc::now().naive_utc();
    services::write_update(&st.ctx.db, row.id, &body, now).await?;
    st.ctx.connectors.invalidate(&name);
    let mut updated = row;
    updated.connector_url = body.connector_url.clone();
    updated.connector_username = body.connector_username.clone();
    updated.connector_password = body.connector_password.clone();
    updated.connector_api_key = body.connector_api_key.clone();
    updated.connector_extra_data = body.connector_extra_data.clone();
    updated.connector_last_updated = now;
    let row_id = updated.id;
    let connector = ConnectorOut::from_row(updated, history);
    if let Some(v) = verifier {
        // `verify_connector_by_id` swallows its failures here.
        if let Err(e) = verify_and_record(&st, row_id, &name, v.as_ref()).await {
            tracing::error!("Failed to verify connector {name}: {e}");
        }
    }
    audit(&st, &user, id, &name);
    Ok(json(ConnectorListResponse {
        connector,
        success: true,
        message: "Connector updated successfully".into(),
    }))
}

fn audit(st: &ConnectorsState, user: &CurrentUser, id: i64, name: &str) {
    // Identity only: connector values hold secrets.
    st.ctx.audit.record(
        AuditRecord::new("connector.update")
            .actor(Some(user.id), Some(&user.username))
            .entity("connector", id)
            .details(format!("Connector '{name}' configuration updated"))
            .source_ip(user.source_ip.clone()),
    );
}

/// The verification and its bookkeeping (`connector_verified`, the
/// timestamp, the cache); `None` where Python's `verify_connector_by_id`
/// returns `None`.
async fn verify_and_record(
    st: &ConnectorsState,
    id: i32,
    name: &str,
    verifier: &dyn crate::ConnectorVerifier,
) -> Result<crate::VerifyOutcome, ApiError> {
    let Some(outcome) = verifier.verify(&st.ctx.connectors, name).await else {
        return Ok(None);
    };
    let now = Utc::now().naive_utc();
    services::write_verified(&st.ctx.db, id, outcome.connection_successful, now).await?;
    st.ctx.connectors.invalidate(name);
    Ok(Some(outcome))
}

/// `POST /verify/{connector_id}`.
async fn verify(
    _user: Authorized<AdminOrAnalyst>,
    State(st): State<ConnectorsState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("connector_id", &raw)?;
    let Some((row, _)) = services::load(&st.ctx.db, id).await? else {
        return Err(not_found(id));
    };
    let name = row.connector_name;
    let Some(verifier) = st.verifiers.get(&name) else {
        // Python's "not supported" (`get_connector_service` → `None`).
        return Err(not_found(id));
    };
    match verify_and_record(&st, row.id, &name, verifier.as_ref()).await? {
        None => Err(not_found(id)),
        Some(o) if !o.connection_successful => Err(ApiError::http(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to verify connector: {}", o.message),
        )),
        Some(o) => Ok(json(o)),
    }
}
