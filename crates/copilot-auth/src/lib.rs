//! # copilot-auth — tokens, passwords and tenant scoping
//!
//! Pure port of the decision logic in `app/auth/utils.py` and
//! `app/middleware/customer_access.py`. No I/O: the HTTP layer
//! (`copilot-web`) feeds it the bearer token and the database rows.
//!
//! ## Interoperability
//! During the migration both backends run side by side against one MySQL and
//! one `JWT_SECRET`. A token issued by either is accepted by the other:
//! HS256, raw-UTF-8 secret, `{exp, iat, sub, scopes}` (+ `customer_codes` for
//! portal users), PyJWT's claim rules (see [`jwt`]). The 2FA temp token
//! (`type: 2fa_pending`) is never accepted as a session.
//!
//! Module map:
//! - [`jwt`]      — encode/decode session tokens
//! - [`password`] — bcrypt with the 72-byte cut
//! - [`access`]   — `AccessScope`: who may see which customer

#![warn(missing_docs)]

pub mod access;
pub mod jwt;
pub mod password;

pub use access::{AccessDenied, AccessScope};
pub use jwt::{JwtCodec, SessionClaims, TokenError};
