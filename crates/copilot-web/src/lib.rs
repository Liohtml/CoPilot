//! # copilot-web — the HTTP contract of the Python backend, in axum
//!
//! Every ported module builds its routes on this crate so the frontends and
//! Talon cannot tell which backend answered:
//!
//! - [`error`]      — FastAPI/`exception_handlers.py` error envelopes
//! - [`validate`]   — Pydantic-2-lax request validation and the 422 report
//! - [`datetime`]   — Pydantic's `datetime` parsing (the same `speedate`)
//! - [`auth`]       — `require_any_scope` / `get_current_user(scopes=…)` extractors
//! - [`body`]       — JSON/form bodies read before the dependencies, like FastAPI
//! - [`form`]       — Starlette's form parsing (urlencoded, multipart)
//! - [`email`]      — pydantic's `EmailStr` (email-validator)
//! - [`pyjson`]     — where CPython's `json.loads` reports a malformed body
//! - [`query`]      — query strings, `customer_codes_query`
//! - [`context`]    — [`AppContext`], the shared dependencies
//! - [`middleware`] — CORS, gzip, `log_entries` writes, security headers
//! - [`respond`]    — the `{success, message, …}` response helper
//!
//! ## Handler shape
//! FastAPI decodes the body first (a malformed JSON body is a 422 even
//! without a token), then checks the token, the path, tenancy, the query, and
//! only then validates the body against its model — so a request failing
//! several checks gets the same error from either backend:
//!
//! ```ignore
//! async fn handler(
//!     State(ctx): State<AppContext>,
//!     Path(raw): Path<String>,
//!     WithJson(auth, body): WithJson<Authorized<AdminOrAnalyst>>,
//! ) -> ApiResult { /* path_int → enforce_owned → body.model(…) → service */ }
//! ```

#![warn(missing_docs)]

pub mod auth;
pub mod body;
pub mod context;
pub mod datetime;
pub mod email;
pub mod error;
pub mod form;
pub mod middleware;
pub mod pyjson;
pub mod query;
pub mod respond;
pub mod validate;

pub use auth::{
    AdminOnly, AdminOrAnalyst, AnalystAdminOrPortal, AnalystOrAdmin, AnyPortalOrSoc, AnyUser,
    Authorized, ClientIp, CurrentUser, ScopeSet, ScopedUser,
};
pub use body::{Form, JsonBody, WithJson};
pub use context::{AppContext, AppDeps};
pub use error::{ApiError, ApiResult};
pub use query::QueryPairs;
pub use respond::ok;
