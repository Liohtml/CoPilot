//! # copilot-standalone — every request answered by this service
//!
//! What `copilot.py`'s app does around its routers, so that no request needs
//! the Python process:
//!
//! - [`front`] — Starlette's routing of the decoded path for the whole
//!   service (`copilot_web::routing` over the Python app's own route table),
//!   FastAPI's 404 and 405 (`Allow` naming the first route whose path
//!   matched), `redirect_slashes=False`, `HEAD` only where Starlette adds it,
//!   CORS (`copilot_web::cors`) and the request timer; the legacy backend
//!   only for a path outside the Python app's routers;
//! - [`docs`] — `GET /openapi.json` (the document `app.openapi()` builds,
//!   compiled in), `/docs`, `/docs/oauth2-redirect`, `/redoc`, and `GET /`;
//! - [`static_files`] — the `/scoutsuite-report` mount (`StaticFiles`);
//! - [`python`] — the Python app as `scripts/gen-standalone-vectors.py`
//!   records it: its routes, pages and document.
//!
//! State kept by the process: the import time the document names (taken at
//! startup), the parsed table and the document (immutable).

#![warn(missing_docs)]

pub mod docs;
pub mod front;
mod parsedate;
pub mod python;
pub mod static_files;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod vectors;

use std::path::PathBuf;

use axum::Router;

pub use front::front;

/// The routes this crate serves: FastAPI's documentation, `GET /` and the
/// `/scoutsuite-report` mount over `report_dir`.
pub fn router(report_dir: PathBuf) -> Router {
    docs::init();
    docs::router().merge(static_files::router(report_dir))
}
