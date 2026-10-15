//! `/api/auth/passkey/*` — `app/auth/routes/passkey.py`.
//!
//! | Route | Guard | A refused step |
//! |---|---|---|
//! | `GET /passkey/status` | none | — |
//! | `GET /passkey/me`, `/passkey/me/status` | admin, analyst | — |
//! | `DELETE /passkey/{id}` | admin, analyst | 404 |
//! | `POST /passkey/register/options`, `/register/verify` | admin, analyst | 400 |
//! | `POST /passkey/login/options` | none | 400 |
//! | `POST /passkey/login/verify` | none | 401 (403 for a portal user) |

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::Value;

use copilot_db::users;
use copilot_web::body::{JsonBody, WithJson};
use copilot_web::pyurl::header_latin1;
use copilot_web::validate::path_int;
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized};
use copilot_webauthn::device_name;

use crate::IdentityState;
use crate::passkey_schema::{
    Done, LoginOptionsRequest, PasskeyItem, PasskeyList, PasskeyLogin, PasskeyStatus,
    RegisterOptionsRequest, VerifyRequest,
};
use crate::services::login::is_customer_user;
use crate::services::passkeys::{self, PasskeyError};
use crate::services::sso::issue_token;

type Soc = Authorized<AdminOrAnalyst>;

/// The passkey routes, mounted under `/api/auth`.
pub fn router() -> Router<IdentityState> {
    Router::new()
        // `DELETE /passkey/{passkey_id}` also matches these two paths in
        // FastAPI (the GET routes only match their method): a 422 for the id.
        .route("/passkey/status", get(public_status).delete(delete_status))
        .route("/passkey/me", get(my_passkeys).delete(delete_me))
        .route("/passkey/me/status", get(my_status))
        .route("/passkey/{passkey_id}", delete(delete_passkey))
        .route("/passkey/register/options", post(register_options))
        .route("/passkey/register/verify", post(register_verify))
        .route("/passkey/login/options", post(login_options))
        .route("/passkey/login/verify", post(login_verify))
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

fn failure(e: PasskeyError, status: http::StatusCode) -> ApiError {
    match e {
        PasskeyError::Rejected(message) => ApiError::http(status, message),
        PasskeyError::Internal(e) => e,
    }
}

/// `_request_origin(request)`: the `Origin` the browser sent, mapped to an
/// allowed origin (400 otherwise).
fn request_origin(st: &IdentityState, headers: &HeaderMap) -> Result<String, ApiError> {
    st.relying_party
        .resolve_request_origin(header_latin1(headers, "origin").as_deref())
        .map_err(ApiError::bad_request)
}

async fn public_status(State(st): State<IdentityState>) -> ApiResult {
    let enabled =
        passkeys::configured(&st).map_err(|e| failure(e, http::StatusCode::BAD_REQUEST))?;
    Ok(json(PasskeyStatus {
        enabled,
        count: 0,
        message: "Passkey status retrieved",
        success: true,
    }))
}

/// `PasskeyItemResponse.transports`: `pk.transports or []` as `list[str]`.
fn transports(value: &Value) -> Result<Vec<String>, ApiError> {
    let invalid = || ApiError::internal("stored passkey transports are not a list of strings");
    match value {
        Value::Null | Value::Bool(false) => Ok(Vec::new()),
        Value::String(s) if s.is_empty() => Ok(Vec::new()),
        Value::Object(o) if o.is_empty() => Ok(Vec::new()),
        Value::Number(n) if n.as_f64() == Some(0.0) => Ok(Vec::new()),
        Value::Array(items) => items
            .iter()
            .map(|t| t.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(invalid),
        _ => Err(invalid()),
    }
}

async fn my_passkeys(State(st): State<IdentityState>, auth: Soc) -> ApiResult {
    let rows = passkeys::list(&st, auth.id).await?;
    let passkeys = rows
        .into_iter()
        .map(|pk| {
            Ok(PasskeyItem {
                id: pk.id,
                device_name: pk.device_name,
                created_at: pk.created_at,
                last_used_at: pk.last_used_at,
                transports: transports(&pk.transports.0)?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(json(PasskeyList {
        passkeys,
        message: "Passkeys retrieved",
        success: true,
    }))
}

async fn my_status(State(st): State<IdentityState>, auth: Soc) -> ApiResult {
    let count = passkeys::list(&st, auth.id).await?.len();
    Ok(json(PasskeyStatus {
        enabled: count > 0,
        count,
        message: "Passkey status retrieved",
        success: true,
    }))
}

async fn delete_passkey(
    State(st): State<IdentityState>,
    auth: Soc,
    Path(raw): Path<String>,
) -> ApiResult {
    let passkey_id = path_int("passkey_id", &raw)?;
    passkeys::delete(&st, auth.id, passkey_id)
        .await
        .map_err(|e| failure(e, http::StatusCode::NOT_FOUND))?;
    Ok(json(Done {
        message: "Passkey removed.",
        success: true,
    }))
}

async fn delete_me(st: State<IdentityState>, auth: Soc) -> ApiResult {
    delete_passkey(st, auth, Path("me".into())).await
}

async fn delete_status(st: State<IdentityState>, auth: Soc) -> ApiResult {
    delete_passkey(st, auth, Path("status".into())).await
}

async fn current_row(st: &IdentityState, auth: &Soc) -> Result<users::UserRow, ApiError> {
    users::find_by_id(&st.ctx.db, auth.id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("User not found"))
}

async fn register_options(
    State(st): State<IdentityState>,
    headers: HeaderMap,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(RegisterOptionsRequest::read)?;
    let user = current_row(&st, &auth).await?;
    let origin = request_origin(&st, &headers)?;
    let name = device_name(Some(&req.device_name));
    let options = passkeys::registration_options_for(&st, &user, &name, &origin)
        .await
        .map_err(|e| failure(e, http::StatusCode::BAD_REQUEST))?;
    Ok(json(options))
}

async fn register_verify(
    State(st): State<IdentityState>,
    headers: HeaderMap,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(VerifyRequest::read)?;
    let user = current_row(&st, &auth).await?;
    let origin = request_origin(&st, &headers)?;
    let name = device_name(req.device_name.as_deref());
    passkeys::register(
        &st,
        &user,
        &name,
        &req.challenge_token,
        &req.credential,
        &origin,
    )
    .await
    .map_err(|e| failure(e, http::StatusCode::BAD_REQUEST))?;
    Ok(json(Done {
        message: "Passkey registered successfully.",
        success: true,
    }))
}

async fn login_options(
    State(st): State<IdentityState>,
    headers: HeaderMap,
    body: JsonBody,
) -> ApiResult {
    let req = body.model(LoginOptionsRequest::read)?;
    let origin = request_origin(&st, &headers)?;
    let username = req
        .username
        .as_deref()
        .map(|u| u.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)));
    let options = passkeys::authentication_options_for(&st, username, &origin)
        .await
        .map_err(|e| failure(e, http::StatusCode::BAD_REQUEST))?;
    Ok(json(options))
}

async fn login_verify(
    State(st): State<IdentityState>,
    headers: HeaderMap,
    body: JsonBody,
) -> ApiResult {
    let req = body.model(VerifyRequest::read)?;
    let origin = request_origin(&st, &headers)?;
    let stored = passkeys::authenticate(&st, &req.challenge_token, &req.credential, &origin)
        .await
        .map_err(|e| failure(e, http::StatusCode::UNAUTHORIZED))?;
    let user = match users::find_by_id(&st.ctx.db, stored.user_id).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!(err = %e, "user lookup failed during passkey login");
            None
        }
    }
    .ok_or_else(|| ApiError::unauthorized("User not found"))?;
    if is_customer_user(user.role_id) {
        tracing::warn!(username = %user.username, "customer user attempted passkey login to the main portal");
        return Err(ApiError::forbidden(
            "This account is registered for the Customer Portal only. Please log in at the Customer Portal to access your account.",
        ));
    }
    let (access_token, requires_2fa) = issue_token(&st, &user).await?;
    tracing::info!(username = %user.username, requires_2fa, "passkey login");
    Ok(json(PasskeyLogin {
        access_token,
        token_type: "bearer",
        requires_2fa,
    }))
}
