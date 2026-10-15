//! `/api/auth/token`, `/token/customer-portal`, `/refresh` and `/2fa/*`.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};

use copilot_db::users;
use copilot_web::body::{Form, JsonBody, WithJson};
use copilot_web::{AnyPortalOrSoc, AnyUser, ApiError, ApiResult, Authorized, ClientIp, ScopedUser};

use crate::IdentityState;
use crate::schema::{
    BackupCodesResponse, Done, LoginForm, SecondFactor, StatusResponse, Token, ValidateRequest,
    read_verify,
};
use crate::services::login::{self, LoginOutcome, Portal};
use crate::services::two_factor::{self, FactorError};

/// The router mounted at `/api/auth` (the other `/auth` routes stay in
/// Python for now).
pub fn router(state: IdentityState) -> Router {
    Router::new()
        .route("/token", post(token))
        .route("/token/customer-portal", post(token_customer_portal))
        .route("/refresh", get(refresh))
        .route("/2fa/status", get(status))
        .route("/2fa/setup", post(setup))
        .route("/2fa/verify-setup", post(verify_setup))
        .route("/2fa/disable", delete(disable))
        .route("/2fa/validate", post(validate))
        .route("/2fa/backup-codes/regenerate", post(regenerate))
        .with_state(state)
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

fn login_response(outcome: LoginOutcome) -> Response {
    match outcome {
        LoginOutcome::Session(token) => json(token),
        LoginOutcome::TwoFactor(pending) => json(pending),
    }
}

async fn token(State(st): State<IdentityState>, ClientIp(ip): ClientIp, form: Form) -> ApiResult {
    let form = LoginForm::read(&form)?;
    Ok(login_response(
        login::password_login(&st, &form, Portal::Main, ip).await?,
    ))
}

async fn token_customer_portal(
    State(st): State<IdentityState>,
    ClientIp(ip): ClientIp,
    form: Form,
) -> ApiResult {
    let form = LoginForm::read(&form)?;
    Ok(login_response(
        login::password_login(&st, &form, Portal::Customer, ip).await?,
    ))
}

async fn refresh(State(st): State<IdentityState>, user: ScopedUser<AnyUser>) -> ApiResult {
    let (token, _) = login::session_token(&st, user.id, &user.username, user.role_id).await?;
    Ok(json(Token::bearer(token)))
}

type Guard = Authorized<AnyPortalOrSoc>;

/// A refused second factor is an `HTTPException(status, str(e))`.
fn factor_error(e: FactorError, status: http::StatusCode) -> ApiError {
    match e {
        FactorError::Rejected(message) => ApiError::http(status, message),
        FactorError::Internal(e) => e,
    }
}

fn bad_request(e: FactorError) -> ApiError {
    factor_error(e, http::StatusCode::BAD_REQUEST)
}

async fn status(State(st): State<IdentityState>, auth: Guard) -> ApiResult {
    Ok(json(StatusResponse {
        enabled: two_factor::status(&st, auth.id).await?,
        message: "2FA status retrieved",
        success: true,
    }))
}

async fn setup(State(st): State<IdentityState>, auth: Guard) -> ApiResult {
    let response = two_factor::setup(&st, auth.id, &auth.username)
        .await
        .map_err(bad_request)?;
    Ok(json(response))
}

async fn verify_setup(
    State(st): State<IdentityState>,
    WithJson(auth, body): WithJson<Guard>,
) -> ApiResult {
    let code = body.model(read_verify)?;
    two_factor::verify_setup(&st, auth.id, &code)
        .await
        .map_err(bad_request)?;
    Ok(json(Done {
        message: "Two-factor authentication is now enabled.",
        success: true,
    }))
}

async fn disable(
    State(st): State<IdentityState>,
    WithJson(auth, body): WithJson<Guard>,
) -> ApiResult {
    let factor = body.model(SecondFactor::read)?;
    if factor.is_empty() {
        return Err(ApiError::bad_request("Provide a TOTP code or backup code."));
    }
    two_factor::disable(&st, auth.id, &factor)
        .await
        .map_err(bad_request)?;
    Ok(json(Done {
        message: "Two-factor authentication has been disabled.",
        success: true,
    }))
}

async fn validate(
    State(st): State<IdentityState>,
    ClientIp(ip): ClientIp,
    body: JsonBody,
) -> ApiResult {
    let req = body.model(ValidateRequest::read)?;
    let username = st
        .ctx
        .jwt
        .decode_two_factor(&req.temp_token)
        .map_err(|e| ApiError::unauthorized(e.to_string()))?;
    let user = match users::find_by_username(&st.ctx.db, &username).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!(err = %e, "user lookup failed during 2FA validation");
            None
        }
    }
    .ok_or_else(|| ApiError::unauthorized("User not found"))?;
    if req.factor.is_empty() {
        return Err(ApiError::bad_request("Provide a TOTP code or backup code."));
    }
    if let Err(e) = two_factor::validate(&st, user.id, &req.factor).await {
        if matches!(e, FactorError::Rejected(_)) {
            login::second_factor_failed(&st, &user, ip);
        }
        return Err(factor_error(e, http::StatusCode::UNAUTHORIZED));
    }
    let (token, first) = login::session_token(&st, user.id, &user.username, user.role_id).await?;
    let details = if login::is_customer_user(user.role_id) {
        "Customer portal login (2FA)"
    } else {
        "Main portal login (2FA)"
    };
    tracing::info!(username = %user.username, "2FA login completed");
    login::finish_login(&st, &user, first.as_deref(), details, ip).await;
    Ok(json(Token::bearer(token)))
}

async fn regenerate(
    State(st): State<IdentityState>,
    WithJson(auth, body): WithJson<Guard>,
) -> ApiResult {
    let code = body.model(read_verify)?;
    let codes = two_factor::regenerate(&st, auth.id, &code)
        .await
        .map_err(bad_request)?;
    Ok(json(BackupCodesResponse {
        backup_codes: codes,
        message: "New backup codes generated. Save them — they are shown only once.",
        success: true,
    }))
}
