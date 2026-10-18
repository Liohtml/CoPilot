//! `/api/connectors` — `app/connectors/routes.py`.
//!
//! | Route | Guard | Here |
//! |---|---|---|
//! | `GET ""` | `get_current_user(scopes=["admin"])` | Rust |
//! | `GET /{connector_id}` | `require_any_scope("admin")` | Rust |
//! | `PUT /{connector_id}` | `get_current_user(scopes=["admin"])` | Rust for a connector this build verifies, else Python |
//! | `POST /verify/{connector_id}` | `require_any_scope("admin", "analyst")` | Rust for a connector this build verifies, else Python |
//! | `POST /upload/{connector_identifier}` | `get_current_user(scopes=["admin"])` | Rust ([`crate::upload`]); the verification that follows as `POST /verify` |
//!
//! An update writes the row, then verifies the connector (the tool's API
//! is called) and records `connector.update`. Both steps need the tool's
//! verifier, so a connector whose tool is still served by Python is handed
//! to Python whole — after the same 404 / validation checks — and this
//! process forgets its cached row once Python has answered. Without a
//! legacy backend such a connector is updated here and left as verified as
//! it was. The binary registers a verifier for every connector
//! `get_connector_service` knows (`copilot-verifiers` brought the last
//! twelve), so in it the hand-off is never taken.

use std::net::SocketAddr;

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{FromRequest, FromRequestParts, OriginalUri, Path, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use http::{HeaderMap, Method, Uri};

use copilot_core::audit::AuditRecord;
use copilot_web::body::JsonBody;
use copilot_web::validate::path_int;
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, CurrentUser, ScopedUser,
};

use crate::ConnectorsState;
use crate::schema::{ConnectorListResponse, ConnectorOut, ConnectorsListResponse, UpdateConnector};
use crate::services;
use crate::verify::PYTHON_VERIFIED;

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

/// The request as it came in, for a hand-off to the Python backend.
pub(crate) struct Received {
    method: Method,
    uri: Uri,
    pub(crate) headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    body: Bytes,
}

impl Received {
    /// What `parts` carry, the URI as the client sent it; the body follows
    /// ([`Received::with_body`]).
    pub(crate) fn capture(parts: &http::request::Parts) -> Self {
        Self {
            method: parts.method.clone(),
            uri: parts
                .extensions
                .get::<OriginalUri>()
                .map_or_else(|| parts.uri.clone(), |o| o.0.clone()),
            headers: parts.headers.clone(),
            peer: parts.extensions.get::<ConnectInfo<SocketAddr>>().cloned(),
            body: Bytes::new(),
        }
    }

    /// The same request with its body.
    pub(crate) fn with_body(self, body: Bytes) -> Self {
        Self { body, ..self }
    }

    /// The request again, for the legacy proxy.
    pub(crate) fn into_request(self) -> Request {
        let mut req = Request::new(Body::from(self.body));
        *req.method_mut() = self.method;
        *req.uri_mut() = self.uri;
        *req.headers_mut() = self.headers;
        if let Some(peer) = self.peer {
            req.extensions_mut().insert(peer);
        }
        req
    }
}

/// `WithJson` that also keeps the raw request.
struct WithJsonRaw<A>(A, JsonBody, Received);

impl<A, S> FromRequest<S> for WithJsonRaw<A>
where
    A: FromRequestParts<S> + Send,
    A::Rejection: IntoResponse,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Response> {
        let (mut parts, body) = req.into_parts();
        let ct = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let guard = A::from_request_parts(&mut parts, state)
            .await
            .map_err(IntoResponse::into_response);
        let received = Received::capture(&parts);
        let bytes = Bytes::from_request(Request::from_parts(parts, body), state)
            .await
            .map_err(IntoResponse::into_response)?;
        let json = JsonBody::read(ct.as_deref(), &bytes).map_err(IntoResponse::into_response)?;
        let guard = guard?;
        Ok(Self(guard, json, received.with_body(bytes)))
    }
}

/// Python answers for this connector: forward, then forget the row here.
pub(crate) async fn hand_off(
    st: &ConnectorsState,
    name: &str,
    received: Received,
) -> Option<Response> {
    let proxy = st.legacy.as_ref()?;
    let response = proxy.forward(received.into_request()).await;
    st.ctx.connectors.invalidate(name);
    Some(response)
}

/// `PUT /{connector_id}`: `update_connector_by_id`, then
/// `verify_connector_by_id`, then the `connector.update` audit row.
async fn update(
    State(st): State<ConnectorsState>,
    Path(raw): Path<String>,
    WithJsonRaw(user, body, received): WithJsonRaw<ScopedUser<AdminOnly>>,
) -> ApiResult {
    let id = path_int("connector_id", &raw)?;
    let body = body.model(UpdateConnector::read)?;
    let Some((row, history)) = services::load(&st.ctx.db, id).await? else {
        return Err(not_found(id));
    };
    let name = row.connector_name.clone();
    let verifier = st.verifiers.get(&name);
    if verifier.is_none() && PYTHON_VERIFIED.contains(&name.as_str()) {
        if let Some(response) = hand_off(&st, &name, received).await {
            return Ok(response);
        }
    }
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
    req: Request,
) -> ApiResult {
    let id = path_int("connector_id", &raw)?;
    let Some((row, _)) = services::load(&st.ctx.db, id).await? else {
        return Err(not_found(id));
    };
    let name = row.connector_name;
    let Some(verifier) = st.verifiers.get(&name) else {
        if PYTHON_VERIFIED.contains(&name.as_str()) {
            let (parts, body) = req.into_parts();
            let body = axum::body::to_bytes(body, 1 << 20)
                .await
                .map_err(|e| ApiError::bad_request(e.to_string()))?;
            let received = Received {
                method: parts.method,
                uri: parts
                    .extensions
                    .get::<OriginalUri>()
                    .map_or_else(|| parts.uri.clone(), |o| o.0.clone()),
                headers: parts.headers,
                peer: parts.extensions.get::<ConnectInfo<SocketAddr>>().cloned(),
                body,
            };
            if let Some(response) = hand_off(&st, &name, received).await {
                return Ok(response);
            }
        }
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
