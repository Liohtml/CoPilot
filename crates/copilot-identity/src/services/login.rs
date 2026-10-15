//! Password login and session issuance — `app/auth/routes/auth.py`
//! (`/token`, `/token/customer-portal`, `/refresh`) and the token half of
//! `/2fa/validate`.
//!
//! - A failed password, a portal mismatch and a failed second factor each
//!   write an `auth.login_failed` audit event; a finished login writes
//!   `auth.login` and stamps `last_login_at` (best effort).
//! - A user with 2FA enabled gets the 5-minute temp token instead of a
//!   session; the login finishes at `/2fa/validate`.
//! - Every token issued to a `customer_user` carries `customer_codes`.
//! - An unknown username still costs one bcrypt verification, so response
//!   time does not tell which usernames exist (Python answers those at once).

use serde_json::{Map, Value};

use copilot_auth::password::verify_password;
use copilot_core::audit::AuditRecord;
use copilot_core::roles::Role;
use copilot_db::totp;
use copilot_db::users::{self, UserRow};
use copilot_web::ApiError;

use crate::IdentityState;
use crate::schema::{LoginForm, Token, TwoFactorRequired};

/// `auth.login`.
pub const AUTH_LOGIN: &str = "auth.login";
/// `auth.login_failed`.
pub const AUTH_LOGIN_FAILED: &str = "auth.login_failed";

/// A cost-12 hash of a password nobody has: verified against when the
/// username is unknown, so both paths take a bcrypt's time.
const TIMING_HASH: &str = "$2b$12$RIFKFv9Jn.ej/kNvglVkeOdEKNO7Iim9.IKgnrTyXJyMFgId/znlG";

/// Which login form was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Portal {
    /// `POST /auth/token` — SOC users.
    Main,
    /// `POST /auth/token/customer-portal` — `customer_user` only.
    Customer,
}

/// A login's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// A session token.
    Session(Token),
    /// The 2FA temp token.
    TwoFactor(TwoFactorRequired),
}

/// Whether `role_id` is `customer_user`.
pub fn is_customer_user(role_id: Option<i32>) -> bool {
    role_id == Some(Role::CustomerUser.id())
}

async fn bcrypt_verify(password: &str, hash: &str) -> bool {
    let (password, hash) = (password.to_string(), hash.to_string());
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .unwrap_or(false)
}

/// `authenticate_user`: the user when the password matches. A database
/// error reads as "no such user", as in Python's `find_user`.
pub async fn authenticate(st: &IdentityState, username: &str, password: &str) -> Option<UserRow> {
    let found = match users::find_credentials(&st.ctx.db, username).await {
        Ok(found) => found,
        Err(e) => {
            tracing::error!(err = %e, "user lookup failed during login");
            None
        }
    };
    match found {
        None => {
            bcrypt_verify(password, TIMING_HASH).await;
            None
        }
        Some((user, hash)) => bcrypt_verify(password, &hash).await.then_some(user),
    }
}

/// Write an audit event (never fails the caller).
pub fn audit(st: &IdentityState, record: AuditRecord) {
    st.ctx.audit.record(record);
}

fn login_event(
    action: &str,
    user_id: Option<i32>,
    username: &str,
    ip: Option<String>,
) -> AuditRecord {
    AuditRecord::new(action)
        .actor(user_id, Some(username))
        .entity("user", username)
        .source_ip(ip)
}

/// `encode_token` for a user, with the `customer_codes` claim for a
/// `customer_user`. Returns the token and the user's first customer code.
pub async fn session_token(
    st: &IdentityState,
    user_id: i32,
    username: &str,
    role_id: Option<i32>,
) -> Result<(String, Option<String>), ApiError> {
    let (extra, first) = if is_customer_user(role_id) {
        let codes = users::assigned_customer_codes(&st.ctx.db, user_id).await?;
        let first = codes.first().cloned();
        let mut extra = Map::new();
        extra.insert("customer_codes".into(), Value::from(codes));
        (Some(extra), first)
    } else {
        (None, None)
    };
    // `get_role`: a user without a role row is an AttributeError in Python.
    let role_id =
        role_id.ok_or_else(|| ApiError::internal(format!("user {username} has no role")))?;
    let role = users::role_name(&st.ctx.db, role_id)
        .await?
        .ok_or_else(|| ApiError::internal(format!("role {role_id} not found")))?;
    let token = st
        .ctx
        .jwt
        .issue_session(
            username,
            &role,
            st.token_ttl_minutes.saturating_mul(60),
            extra,
        )
        .map_err(ApiError::internal)?;
    Ok((token, first))
}

/// `update_last_login` + the `auth.login` event.
pub async fn finish_login(
    st: &IdentityState,
    user: &UserRow,
    customer_code: Option<&str>,
    details: &str,
    ip: Option<String>,
) {
    if let Err(e) = users::touch_last_login(&st.ctx.db, user.id).await {
        tracing::error!(user_id = user.id, err = %e, "failed to update last_login_at");
    }
    audit(
        st,
        login_event(AUTH_LOGIN, Some(user.id), &user.username, ip)
            .customer(customer_code)
            .details(details),
    );
}

/// `login_for_access_token` / `login_for_customer_portal`.
pub async fn password_login(
    st: &IdentityState,
    form: &LoginForm,
    portal: Portal,
    ip: Option<String>,
) -> Result<LoginOutcome, ApiError> {
    let Some(user) = authenticate(st, &form.username, &form.password).await else {
        let which = match portal {
            Portal::Main => "main portal",
            Portal::Customer => "customer portal",
        };
        audit(
            st,
            login_event(AUTH_LOGIN_FAILED, None, &form.username, ip)
                .failed()
                .details(format!("Invalid username or password ({which})")),
        );
        return Err(ApiError::unauthorized("Incorrect username or password"));
    };
    let customer = is_customer_user(user.role_id);
    match portal {
        Portal::Main if customer => {
            tracing::warn!(username = %user.username, "customer user attempted to log in to the main portal");
            audit(
                st,
                login_event(AUTH_LOGIN_FAILED, Some(user.id), &user.username, ip)
                    .failed()
                    .details("customer_user role denied access to the main portal"),
            );
            return Err(ApiError::forbidden(
                "This account is registered for the Customer Portal only. Please log in at the Customer Portal to access your account.",
            ));
        }
        Portal::Customer if !customer => {
            audit(
                st,
                login_event(AUTH_LOGIN_FAILED, Some(user.id), &user.username, ip)
                    .failed()
                    .details("Non customer_user role denied access to the customer portal"),
            );
            return Err(ApiError::forbidden(
                "This account does not have access to the Customer Portal.",
            ));
        }
        _ => {}
    }
    if totp::is_enabled(&st.ctx.db, user.id).await? {
        tracing::info!(username = %user.username, "login requires 2FA verification");
        let temp = st
            .ctx
            .jwt
            .encode_two_factor(&user.username)
            .map_err(ApiError::internal)?;
        return Ok(LoginOutcome::TwoFactor(TwoFactorRequired {
            access_token: temp,
            token_type: "bearer",
            requires_2fa: true,
        }));
    }
    let (token, first) = session_token(st, user.id, &user.username, user.role_id).await?;
    tracing::info!(username = %user.username, "user logged in");
    let details = match portal {
        Portal::Main => "Main portal login",
        Portal::Customer => "Customer portal login",
    };
    finish_login(st, &user, first.as_deref(), details, ip).await;
    Ok(LoginOutcome::Session(Token::bearer(token)))
}

/// The failure event of a rejected second factor.
pub fn second_factor_failed(st: &IdentityState, user: &UserRow, ip: Option<String>) {
    audit(
        st,
        login_event(AUTH_LOGIN_FAILED, Some(user.id), &user.username, ip)
            .failed()
            .details("Failed second-factor (2FA) verification"),
    );
}
