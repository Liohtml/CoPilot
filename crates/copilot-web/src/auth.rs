//! Authentication extractors — port of `AuthHandler.require_any_scope`.
//!
//! [`Authorized<S>`] resolves, in the Python order:
//!
//! | Condition | Status | Detail |
//! |---|---|---|
//! | no `Authorization: Bearer …` | 401 | `Not authenticated` |
//! | expired | 401 | `Expired signature` |
//! | bad signature / malformed | 401 | `Invalid token` |
//! | 2FA temp token | 401 | `Two-factor authentication required. …` |
//! | no user row for `sub` | 401 | `User not found` |
//! | none of `S::SCOPES` in the token | 403 | `Insufficient permissions. Required one of: admin, analyst` |
//!
//! Put it first in a handler's arguments: FastAPI resolves route-level
//! dependencies before the body, so an unauthenticated request with a broken
//! body must be a 401, not a 422.

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts};
use http::request::Parts;
use tokio::sync::OnceCell;

use copilot_auth::{AccessScope, TokenError};
use copilot_db::users;

use crate::context::AppContext;
use crate::error::ApiError;

/// A set of scopes of which the caller needs at least one.
pub trait ScopeSet: Send + Sync + 'static {
    /// The scopes, in the order the error message names them.
    const SCOPES: &'static [&'static str];
}

/// `require_any_scope("admin", "analyst")` — admits responders too, whose
/// tokens carry `analyst`.
#[derive(Debug)]
pub struct AdminOrAnalyst;
impl ScopeSet for AdminOrAnalyst {
    const SCOPES: &'static [&'static str] = &["admin", "analyst"];
}

/// `require_any_scope("admin")`.
#[derive(Debug)]
pub struct AdminOnly;
impl ScopeSet for AdminOnly {
    const SCOPES: &'static [&'static str] = &["admin"];
}

/// `require_any_scope("admin", "analyst", "customer_user")`.
#[derive(Debug)]
pub struct AnyPortalOrSoc;
impl ScopeSet for AnyPortalOrSoc {
    const SCOPES: &'static [&'static str] = &["admin", "analyst", "customer_user"];
}

/// The authenticated caller.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// `user.id`.
    pub id: i32,
    /// `user.username`.
    pub username: String,
    /// Live `user.role_id` (tenancy follows this, not the token).
    pub role_id: Option<i32>,
    /// Token scopes (route gating follows these).
    pub scopes: Vec<String>,
    /// The raw bearer token, for hand-offs to the legacy backend.
    pub bearer: String,
    /// First `X-Forwarded-For` entry, else the peer address.
    pub source_ip: Option<String>,
    access: Arc<OnceCell<AccessScope>>,
}

impl CurrentUser {
    /// Build directly (tests, CLI).
    pub fn new(id: i32, username: &str, role_id: Option<i32>, scopes: Vec<String>) -> Self {
        Self {
            id,
            username: username.to_string(),
            role_id,
            scopes,
            bearer: String::new(),
            source_ip: None,
            access: Arc::default(),
        }
    }

    /// Whether the token carries any of `required`.
    pub fn has_any_scope(&self, required: &[&str]) -> bool {
        required.iter().any(|r| self.scopes.iter().any(|s| s == r))
    }

    /// The customers this user may see, read once per request
    /// (`get_user_accessible_customers`, memoised like `session.info`).
    pub async fn access(&self, ctx: &AppContext) -> Result<&AccessScope, ApiError> {
        self.access
            .get_or_try_init(|| async {
                let assigned = match self.role_id {
                    Some(1) | None => Vec::new(),
                    Some(_) => users::assigned_customer_codes(&ctx.db, self.id).await?,
                };
                Ok::<_, ApiError>(AccessScope::for_user(self.role_id, assigned))
            })
            .await
    }

    /// `enforce_customer_access`.
    pub async fn enforce_customer(&self, ctx: &AppContext, code: &str) -> Result<(), ApiError> {
        self.access(ctx).await?.enforce_customer(code)?;
        Ok(())
    }

    /// `enforce_owned_object_access` with an owner already resolved.
    pub async fn enforce_owned(
        &self,
        ctx: &AppContext,
        owner: Option<&str>,
        subject: &str,
    ) -> Result<(), ApiError> {
        self.access(ctx).await?.enforce_owned(owner, subject)?;
        Ok(())
    }
}

/// An authenticated caller holding one of `S::SCOPES`.
#[derive(Debug)]
pub struct Authorized<S: ScopeSet> {
    /// The caller.
    pub user: CurrentUser,
    _scopes: PhantomData<S>,
}

impl<S: ScopeSet> std::ops::Deref for Authorized<S> {
    type Target = CurrentUser;

    fn deref(&self) -> &CurrentUser {
        &self.user
    }
}

/// `OAuth2PasswordBearer`: the token from `Authorization: Bearer <token>`.
pub fn bearer_token(parts: &Parts) -> Option<String> {
    let value = parts
        .headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ').unwrap_or((value, ""));
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// `X-Forwarded-For`'s first entry, else the peer address.
pub fn source_ip(parts: &Parts) -> Option<String> {
    let forwarded = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    forwarded.or_else(|| {
        parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
    })
}

/// Token → user, without any scope requirement.
pub async fn authenticate(parts: &Parts, ctx: &AppContext) -> Result<CurrentUser, ApiError> {
    if let Some(user) = parts.extensions.get::<CurrentUser>() {
        return Ok(user.clone());
    }
    let token = bearer_token(parts).ok_or_else(|| ApiError::unauthorized("Not authenticated"))?;
    let claims = match ctx.jwt.decode_session(&token) {
        Ok(c) => c,
        Err(TokenError::MissingSubject) => {
            return Err(ApiError::internal("token without `sub`"));
        }
        Err(e) => return Err(ApiError::unauthorized(e.to_string())),
    };
    // `find_user` swallows database errors and returns None, so an outage
    // reads as "User not found" there too.
    let row = match users::find_by_username(&ctx.db, &claims.subject).await {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(err = %e, "user lookup failed");
            None
        }
    };
    let row = row.ok_or_else(|| ApiError::unauthorized("User not found"))?;
    Ok(CurrentUser {
        id: row.id,
        username: row.username,
        role_id: row.role_id,
        scopes: claims.scopes,
        bearer: token,
        source_ip: source_ip(parts),
        access: Arc::default(),
    })
}

impl<S, St> FromRequestParts<St> for Authorized<S>
where
    S: ScopeSet,
    AppContext: FromRef<St>,
    St: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, Self::Rejection> {
        let ctx = AppContext::from_ref(state);
        let user = authenticate(parts, &ctx).await?;
        if !user.has_any_scope(S::SCOPES) {
            return Err(ApiError::forbidden(format!(
                "Insufficient permissions. Required one of: {}",
                S::SCOPES.join(", ")
            )));
        }
        parts.extensions.insert(user.clone());
        Ok(Self {
            user,
            _scopes: PhantomData,
        })
    }
}

/// `Security(AuthHandler().get_current_user, scopes=S::SCOPES)` — the other
/// way a Python route is guarded. Unlike `require_any_scope` it needs
/// **every** scope in `S`, and `get_current_user` reports token failures
/// through its catch-all, so the texts differ:
///
/// | Condition | Status | Detail |
/// |---|---|---|
/// | no `Authorization: Bearer …` | 401 | `Not authenticated` |
/// | expired / invalid / 2FA temp | 401 | `Could not decode token: 401: <reason>` |
/// | no `sub` claim | 500 | — (Python's exception handler re-decodes the token and fails) |
/// | no user row | 401 | `User not found` |
/// | a scope of `S` missing | 403 | `Insufficient permissions. Required scope: <scope>` |
#[derive(Debug)]
pub struct ScopedUser<S: ScopeSet> {
    /// The caller.
    pub user: CurrentUser,
    _scopes: PhantomData<S>,
}

impl<S: ScopeSet> std::ops::Deref for ScopedUser<S> {
    type Target = CurrentUser;

    fn deref(&self) -> &CurrentUser {
        &self.user
    }
}

/// Map `require_any_scope`'s texts to `get_current_user`'s.
fn current_user_error(e: ApiError) -> ApiError {
    match e {
        ApiError::Http { status, detail } if status == http::StatusCode::UNAUTHORIZED => {
            let text = detail.as_str().unwrap_or_default();
            if text == "Not authenticated" || text == "User not found" {
                ApiError::unauthorized(text)
            } else {
                ApiError::unauthorized(format!("Could not decode token: 401: {text}"))
            }
        }
        other => other,
    }
}

impl<S, St> FromRequestParts<St> for ScopedUser<S>
where
    S: ScopeSet,
    AppContext: FromRef<St>,
    St: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, Self::Rejection> {
        let ctx = AppContext::from_ref(state);
        let user = authenticate(parts, &ctx)
            .await
            .map_err(current_user_error)?;
        if let Some(missing) = S::SCOPES.iter().find(|s| !user.has_any_scope(&[s])) {
            return Err(ApiError::forbidden(format!(
                "Insufficient permissions. Required scope: {missing}"
            )));
        }
        parts.extensions.insert(user.clone());
        Ok(Self {
            user,
            _scopes: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_current_user_wraps_token_failures() {
        let text = |e: ApiError| current_user_error(e).to_string();
        assert_eq!(
            text(ApiError::unauthorized("Expired signature")),
            "401: Could not decode token: 401: Expired signature"
        );
        assert_eq!(
            text(ApiError::unauthorized("Invalid token")),
            "401: Could not decode token: 401: Invalid token"
        );
        assert_eq!(
            text(ApiError::unauthorized("Not authenticated")),
            "401: Not authenticated"
        );
        assert_eq!(
            text(ApiError::unauthorized("User not found")),
            "401: User not found"
        );
    }

    use super::*;

    fn parts(auth: Option<&str>) -> Parts {
        let mut b = http::Request::builder().uri("/x");
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        b.header("x-forwarded-for", "10.0.0.9, 172.17.0.1")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn bearer_parsing_matches_oauth2_password_bearer() {
        assert_eq!(
            bearer_token(&parts(Some("Bearer abc"))).as_deref(),
            Some("abc")
        );
        assert_eq!(
            bearer_token(&parts(Some("bearer abc"))).as_deref(),
            Some("abc")
        );
        assert_eq!(bearer_token(&parts(Some("Basic abc"))), None);
        assert_eq!(bearer_token(&parts(Some("Bearer"))), None);
        assert_eq!(bearer_token(&parts(None)), None);
        assert_eq!(source_ip(&parts(None)).as_deref(), Some("10.0.0.9"));
    }

    #[test]
    fn scope_sets() {
        let responder =
            CurrentUser::new(1, "r", Some(5), vec!["responder".into(), "analyst".into()]);
        assert!(responder.has_any_scope(AdminOrAnalyst::SCOPES));
        assert!(!responder.has_any_scope(AdminOnly::SCOPES));
        assert_eq!(AdminOrAnalyst::SCOPES.join(", "), "admin, analyst");
    }
}
