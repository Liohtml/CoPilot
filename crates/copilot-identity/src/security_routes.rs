//! `/api/auth/security/*` — `app/auth/routes/security_admin.py`, the admin
//! Security tab on a customer. Every route is admin-only.
//!
//! | Route | Does |
//! |---|---|
//! | `GET /security/customers/{customer_code}/users` | the customer's users, with 2FA and last login |
//! | `GET /security/smtp-status` | whether `SMTP_HOST` is set |
//! | `DELETE /security/users/{user_id}/totp` | force-reset a user's 2FA (audited) |
//! | `GET /security/users/{user_id}/temp-password-email/options` | the temporary-password templates that can serve the user, best first |
//! | `POST /security/users/{user_id}/temp-password-email/preview` | the email rendered with a placeholder password |
//! | `POST /security/users/{user_id}/send-temp-password` | issue a temporary password and email it (audited) |

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};

use copilot_web::body::{JsonBody, WithJson};
use copilot_web::validate::{StrRules, Validator, path_int};
use copilot_web::{AdminOnly, ApiError, ApiResult, Authorized, QueryPairs};

use crate::IdentityState;
use crate::security_schema::{Action, SecurityUsers, SmtpStatus, TemplateChoice};
use crate::services::{security, temp_password};

type Admin = Authorized<AdminOnly>;

/// The Security routes, mounted under `/api/auth`.
pub fn router() -> Router<IdentityState> {
    Router::new()
        .route(
            "/security/customers/{customer_code}/users",
            get(customer_users),
        )
        .route("/security/smtp-status", get(smtp_status))
        .route("/security/users/{user_id}/totp", delete(reset_totp))
        .route(
            "/security/users/{user_id}/temp-password-email/options",
            get(template_options),
        )
        .route(
            "/security/users/{user_id}/temp-password-email/preview",
            post(preview),
        )
        .route(
            "/security/users/{user_id}/send-temp-password",
            post(send_temp_password),
        )
}

/// FastAPI validates the path and the body together: their errors are one
/// 422.
fn path_and_body<T>(
    user_id: Result<i64, ApiError>,
    body: Result<T, ApiError>,
) -> Result<(i64, T), ApiError> {
    match (user_id, body) {
        (Ok(id), Ok(body)) => Ok((id, body)),
        (Err(ApiError::Validation(mut a)), Err(ApiError::Validation(b))) => {
            a.extend(b);
            Err(ApiError::Validation(a))
        }
        (Err(e), _) | (_, Err(e)) => Err(e),
    }
}

/// `Optional[SendTempPasswordRequest] = None`: no body (or `null`) is the
/// empty choice.
fn optional_choice(body: &JsonBody) -> Result<TemplateChoice, ApiError> {
    match body {
        JsonBody::Missing => Ok(TemplateChoice::default()),
        other => other.model(TemplateChoice::read),
    }
}

async fn preview(
    State(st): State<IdentityState>,
    Path(raw): Path<String>,
    WithJson(_auth, body): WithJson<Admin>,
) -> ApiResult {
    let (user_id, choice) =
        path_and_body(path_int("user_id", &raw), body.model(TemplateChoice::read))?;
    Ok(json(temp_password::preview(&st, user_id, &choice).await?))
}

async fn send_temp_password(
    State(st): State<IdentityState>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    let (user_id, choice) = path_and_body(path_int("user_id", &raw), optional_choice(&body))?;
    let message = temp_password::send(&st, &auth, user_id, &choice).await?;
    Ok(json(Action {
        success: true,
        message,
    }))
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

async fn customer_users(
    State(st): State<IdentityState>,
    _auth: Admin,
    Path(customer_code): Path<String>,
) -> ApiResult {
    Ok(json(SecurityUsers {
        users: security::customer_users(&st, &customer_code).await?,
        success: true,
        message: "Users retrieved successfully",
    }))
}

async fn smtp_status(State(st): State<IdentityState>, _auth: Admin) -> ApiResult {
    Ok(json(SmtpStatus {
        configured: security::smtp_configured(&st)?,
        success: true,
        message: "SMTP status retrieved",
    }))
}

async fn reset_totp(
    State(st): State<IdentityState>,
    auth: Admin,
    Path(raw): Path<String>,
) -> ApiResult {
    let user_id = path_int("user_id", &raw)?;
    let message = security::reset_totp(&st, &auth, user_id).await?;
    Ok(json(Action {
        success: true,
        message: message.into(),
    }))
}

async fn template_options(
    State(st): State<IdentityState>,
    _auth: Admin,
    Path(raw): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let user_id = path_int("user_id", &raw)?;
    let mut v = Validator::new();
    let customer_code = q.opt_str(&mut v, "customer_code", StrRules::any());
    v.finish()?;
    Ok(json(
        security::template_options(&st, user_id, customer_code.as_deref()).await?,
    ))
}
