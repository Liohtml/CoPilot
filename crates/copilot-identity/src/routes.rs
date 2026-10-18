//! `/api/auth/token`, `/token/customer-portal`, `/refresh` and `/2fa/*`.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};

use copilot_db::users;
use copilot_web::body::{Form, JsonBody, WithJson};
use copilot_web::validate::{IntRules, StrRules, Validator, path_int};
use copilot_web::{
    AdminOnly, AnalystAdminOrPortal, AnalystOrAdmin, AnyPortalOrSoc, AnyUser, ApiError, ApiResult,
    Authorized, ClientIp, QueryPairs, ScopedUser,
};

use crate::IdentityState;
use crate::schema::{
    BackupCodesResponse, Done, LoginForm, SecondFactor, StatusResponse, Token, ValidateRequest,
    read_verify,
};
use crate::services::login::{self, LoginOutcome, Portal};
use crate::services::two_factor::{self, FactorError};
use crate::services::users as user_admin;
use crate::users_schema::{
    Assignment, LegacyLogin, Message, NewUser, PasswordReset, RoleChange, UserDetailResponse,
    UsersResponse,
};

/// The router mounted at `/api/auth` (the security-admin routes stay in
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
        .route("/register", post(register))
        .route("/login", post(legacy_login))
        .route("/users", get(list_users))
        .route("/users/{user_id}", get(user_detail))
        .route("/reset-password", post(reset_password))
        .route("/reset-password/me", post(reset_password_me))
        .route("/delete/{user_id}", delete(delete_user))
        .route("/users/{user_id}/role/by-name", put(change_role))
        .route(
            "/users/{user_id}/customers",
            post(assign_customers).get(user_customers),
        )
        .route("/me/customers", get(my_customers))
        .merge(crate::sso_routes::router())
        .merge(crate::passkey_routes::router())
        .merge(crate::security_routes::router())
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

// ---------------------------------------------------------------------------
// User management
// ---------------------------------------------------------------------------

type Admin = Authorized<AdminOnly>;

async fn register(
    State(st): State<IdentityState>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    let new = body.model(NewUser::read)?;
    user_admin::register(&st, &auth, &new).await?;
    Ok((
        http::StatusCode::CREATED,
        Json(Message {
            message: "User created successfully",
            success: true,
        }),
    )
        .into_response())
}

async fn legacy_login(State(st): State<IdentityState>, body: JsonBody) -> ApiResult {
    let req = body.model(LegacyLogin::read)?;
    Ok(json(user_admin::legacy_login(&st, &req).await?))
}

/// `search_query`: `search`, then `limit` (1–1000).
const SEARCH_LIMIT: IntRules = IntRules {
    ge: Some(1),
    le: Some(1000),
};

async fn list_users(
    State(st): State<IdentityState>,
    auth: Authorized<AnalystOrAdmin>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let search = q.opt_str(&mut v, "search", StrRules::any());
    let limit = q.opt_int(&mut v, "limit", SEARCH_LIMIT);
    v.finish()?;
    Ok(json(UsersResponse {
        users: user_admin::list(&st, &auth, search.as_deref(), limit).await?,
        message: "Users retrieved successfully",
        success: true,
    }))
}

async fn user_detail(
    State(st): State<IdentityState>,
    _auth: Authorized<AnalystOrAdmin>,
    Path(raw): Path<String>,
) -> ApiResult {
    let user_id = path_int("user_id", &raw)?;
    Ok(json(UserDetailResponse {
        success: true,
        message: "User retrieved successfully",
        user: user_admin::detail(&st, user_id).await?,
    }))
}

fn password_reset() -> Message {
    Message {
        message: "Password reset successfully",
        success: true,
    }
}

async fn reset_password(
    State(st): State<IdentityState>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    let req = body.model(PasswordReset::read)?;
    user_admin::admin_reset_password(&st, &auth, &req).await?;
    Ok(json(password_reset()))
}

async fn reset_password_me(
    State(st): State<IdentityState>,
    WithJson(auth, body): WithJson<Authorized<AnalystAdminOrPortal>>,
) -> ApiResult {
    let req = body.model(PasswordReset::read)?;
    user_admin::self_reset_password(&st, &auth, &req).await?;
    Ok(json(password_reset()))
}

async fn delete_user(
    State(st): State<IdentityState>,
    auth: Admin,
    Path(raw): Path<String>,
) -> ApiResult {
    let user_id = path_int("user_id", &raw)?;
    user_admin::delete(&st, &auth, user_id).await?;
    Ok(json(Message {
        message: "User deleted successfully.",
        success: true,
    }))
}

async fn change_role(
    State(st): State<IdentityState>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    let user_id = path_int("user_id", &raw)?;
    let req = body.model(RoleChange::read)?;
    Ok(json(
        user_admin::change_role(&st, &auth, user_id, &req).await?,
    ))
}

async fn assign_customers(
    State(st): State<IdentityState>,
    Path(raw): Path<String>,
    WithJson(_auth, body): WithJson<Admin>,
) -> ApiResult {
    let user_id = path_int("user_id", &raw)?;
    let codes = body.value(|v, value, at| v.str_items(value, at))?;
    Ok(json(user_admin::assign(&st, user_id, &codes).await?))
}

async fn user_customers(
    State(st): State<IdentityState>,
    _auth: Admin,
    Path(raw): Path<String>,
) -> ApiResult {
    let user_id = path_int("user_id", &raw)?;
    Ok(json(Assignment {
        success: true,
        customer_codes: user_admin::assignment(&st, user_id).await?,
    }))
}

async fn my_customers(State(st): State<IdentityState>, user: ScopedUser<AnyUser>) -> ApiResult {
    Ok(json(user_admin::my_customers(&st, &user).await?))
}
