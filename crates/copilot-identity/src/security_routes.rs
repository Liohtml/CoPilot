//! `/api/auth/security/*` — `app/auth/routes/security_admin.py`, the admin
//! Security tab on a customer. Every route is admin-only.
//!
//! | Route | Does |
//! |---|---|
//! | `GET /security/customers/{customer_code}/users` | the customer's users, with 2FA and last login |
//! | `GET /security/smtp-status` | whether `SMTP_HOST` is set |
//! | `DELETE /security/users/{user_id}/totp` | force-reset a user's 2FA (audited) |
//! | `GET /security/users/{user_id}/temp-password-email/options` | the temporary-password templates that can serve the user, best first |

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};

use copilot_web::validate::{StrRules, Validator, path_int};
use copilot_web::{AdminOnly, ApiResult, Authorized, QueryPairs};

use crate::IdentityState;
use crate::security_schema::{Action, SecurityUsers, SmtpStatus};
use crate::services::security;

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
