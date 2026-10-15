//! # copilot-web — the HTTP contract of the Python backend, in axum
//!
//! Every ported module builds its routes on this crate so the frontends and
//! Talon cannot tell which backend answered:
//!
//! - [`error`]      — FastAPI/`exception_handlers.py` error envelopes
//! - [`validate`]   — Pydantic-2-lax request validation and the 422 report
//! - [`datetime`]   — Pydantic's `datetime` parsing (the same `speedate`)
//! - [`auth`]       — `require_any_scope` / `get_current_user(scopes=…)` extractors
//! - [`query`]      — query strings, `customer_codes_query`
//! - [`context`]    — [`AppContext`], the shared dependencies
//! - [`middleware`] — CORS, gzip, `log_entries` writes, security headers
//! - [`respond`]    — the `{success, message, …}` response helper
//!
//! ## Handler shape
//! Auth first, then path parsing, tenancy, and only then the body — FastAPI's
//! dependency order, so a request failing several checks gets the same error
//! from either backend:
//!
//! ```ignore
//! async fn handler(
//!     auth: Authorized<AdminOrAnalyst>,
//!     State(ctx): State<AppContext>,
//!     Path(raw): Path<String>,
//!     body: Bytes,
//! ) -> ApiResult { /* path_int → enforce_owned → parse_json_body → service */ }
//! ```

#![warn(missing_docs)]

pub mod auth;
pub mod context;
pub mod datetime;
pub mod error;
pub mod middleware;
pub mod query;
pub mod respond;
pub mod validate;

pub use auth::{
    AdminOnly, AdminOrAnalyst, AnyPortalOrSoc, Authorized, CurrentUser, ScopeSet, ScopedUser,
};
pub use context::{AppContext, AppDeps};
pub use error::{ApiError, ApiResult};
pub use query::QueryPairs;
pub use respond::ok;
