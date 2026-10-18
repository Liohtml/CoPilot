//! # copilot-intel-connectors — the OpenCTI and Cortex connectors
//!
//! - [`opencti`] — `/api/opencti` (availability, about, the IOC lookups,
//!   indicators, one entity) over the GraphQL transport Python uses
//!   (`send_graphql_request`, `paginate_graphql`: httpx 0.28, certificates
//!   unverified, `errors` at HTTP 200 a failure)
//! - [`cortex`] — `/api/analyzers` (the list, `POST /run` with the job
//!   polling) as cortex4py 2.1 sends it over `requests`
//! - [`verify`] — the `OpenCTI` and `Cortex` connector verifiers
//!
//! Neither connector holds tenant data: the routes are admin/analyst and
//! not tenant-scoped, as in Python. The Sublime connector (`/api/sublime`)
//! is `copilot-sublime`.
//!
//! State kept by the process: none beyond the shared connector cache.

#![warn(missing_docs)]

pub mod cortex;
pub mod opencti;
pub mod py;
pub mod verify;

#[cfg(test)]
mod vectors;

use axum::Router;
use axum::extract::FromRef;
use copilot_upstream::http::PyHttp;
use copilot_web::AppContext;

/// State of the two connectors' routes.
#[derive(Debug, Clone)]
pub struct IntelState {
    /// Shared dependencies (connector cache, auth).
    pub ctx: AppContext,
    /// `requests` for cortex4py (certificates unverified, no timeout).
    pub cortex_http: PyHttp,
}

impl IntelState {
    /// The state over `ctx`.
    pub fn new(ctx: AppContext) -> Result<Self, reqwest::Error> {
        Ok(Self {
            ctx,
            cortex_http: PyHttp::new(cortex::client::NO_TIMEOUT, false)?
                .with_exact_headers(cortex::client::NO_TIMEOUT, false)?,
        })
    }
}

impl FromRef<IntelState> for AppContext {
    fn from_ref(s: &IntelState) -> AppContext {
        s.ctx.clone()
    }
}

/// Both routers, with full paths (`/api/opencti/*`, `/api/analyzers*`).
pub fn router(state: IntelState) -> Router {
    opencti::routes::router(state.clone()).merge(cortex::routes::router(state))
}
