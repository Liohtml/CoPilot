//! # copilot-identity — login and two-factor authentication
//!
//! Port of the token half of `app/auth/` — the first routes where the Rust
//! service *issues* tokens rather than only accepting them:
//!
//! | Route | Python | Guard |
//! |---|---|---|
//! | `POST /api/auth/token` | `login_for_access_token` (form) | none |
//! | `POST /api/auth/token/customer-portal` | `login_for_customer_portal` (form) | none |
//! | `GET /api/auth/refresh` | `refresh_token` | `get_current_user` |
//! | `GET /api/auth/2fa/status`, `POST /2fa/setup` | `routes/totp.py` | admin, analyst, customer_user |
//! | `POST /2fa/verify-setup`, `DELETE /2fa/disable`, `POST /2fa/backup-codes/regenerate` | `routes/totp.py` | admin, analyst, customer_user |
//! | `POST /api/auth/2fa/validate` | `validate_2fa_login` | the 2FA temp token |
//! | `POST /api/auth/register`, `/reset-password`, `DELETE /delete/{id}`, `PUT /users/{id}/role/by-name`, `GET`/`POST /users/{id}/customers` | `routes/auth.py`, `routes/customer_users.py` | admin |
//! | `GET /api/auth/users`, `/users/{id}` | `get_users`, `get_user_route` | analyst, admin |
//! | `POST /api/auth/reset-password/me` | `reset_password_me` | analyst, admin, customer_user |
//! | `GET /api/auth/me/customers` | `get_my_customer_access` | `get_current_user` |
//! | `POST /api/auth/login` (deprecated, JSON) | `login` | none |
//! | `/api/auth/sso/*` | `routes/sso.py` | see [`sso_routes`] |
//! | `/api/auth/passkey/*` | `routes/passkey.py` | see [`passkey_routes`] |
//!
//! Tokens are the ones Python issues (`copilot_auth::jwt`): a session token
//! from either backend works on both. The 2FA secrets stay readable by both
//! (`copilot_auth::fernet`, same key resolution). All six 2FA routes move
//! together because the brute-force counter ([`limiter`]) lives in memory:
//! split across two processes it would count half the guesses.
//!
//! SSO sign-ins and passkey logins issue the same tokens (a 2FA temp token
//! when the user has 2FA). The OAuth2 `state` is HMAC-signed and stateless,
//! and a passkey challenge lives in `webauthn_challenge`, so either flow may
//! start on one backend and finish on the other.
//!
//! Module map: [`schema`] (login and 2FA shapes), [`users_schema`] (user
//! management shapes), [`sso_schema`], [`passkey_schema`], [`services`]
//! (login, 2FA, users, SSO, passkeys), [`routes`], [`sso_routes`],
//! [`passkey_routes`], [`qr`] (the enrolment QR code), [`limiter`].

#![warn(missing_docs)]

pub mod limiter;
pub mod passkey_routes;
pub mod passkey_schema;
pub mod qr;
pub mod routes;
pub mod schema;
pub mod services;
pub mod sso_routes;
pub mod sso_schema;
pub mod users_schema;

use std::sync::Arc;

use axum::extract::FromRef;

use copilot_auth::Fernet;
use copilot_web::AppContext;
use copilot_webauthn::RelyingParty;

pub use limiter::TwoFactorLimiter;
pub use routes::router;
pub use services::sso::SsoClient;

/// State of the identity routes.
#[derive(Clone, Debug)]
pub struct IdentityState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// Key of the stored TOTP secrets.
    pub fernet: Arc<Fernet>,
    /// Failed second-factor attempts.
    pub limiter: Arc<TwoFactorLimiter>,
    /// `ACCESS_TOKEN_EXPIRE_MINUTES`.
    pub token_ttl_minutes: i64,
    /// The `WEBAUTHN_*` settings.
    pub relying_party: Arc<RelyingParty>,
    /// SSO state signing, identity-provider client and key caches.
    pub sso: Arc<SsoClient>,
}

impl FromRef<IdentityState> for AppContext {
    fn from_ref(s: &IdentityState) -> AppContext {
        s.ctx.clone()
    }
}
