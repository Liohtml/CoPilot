//! # copilot-patch-tuesday — `/api/patch-tuesday`
//!
//! Port of `app/integrations/microsoft_patch_tuesday/` (routes, services,
//! schema): a month's Microsoft security updates from MSRC's CVRF API
//! (`/cvrf/v3.0/cvrf/{YYYY-Mmm}`), every CVE scored with FIRST's EPSS
//! (`?cve=` in chunks of at most 1900 characters) and matched against
//! CISA's Known Exploited Vulnerabilities catalog, then prioritised P0–P3.
//!
//! - [`routes`] — the six routes (`""`, `/summary`, `/cycles`, `/search`,
//!   `/priority/{priority_level}`, `/kev`)
//! - [`services`] — the fetches as `fetch_json` makes them (httpx 0.28 through
//!   `copilot_threat_intel::httpx`: a client per call, 60 s, `Accept:
//!   application/json`, `User-Agent: CoPilot-PatchTuesday/1.0`) and its
//!   `RuntimeError` texts; [`cvrf`] — what Python does with the documents,
//!   on whatever JSON came back ([`py`]: CPython's string and value
//!   semantics); [`schema`] — the response models
//! - [`urls`] — the three feeds, overridable for the parity harness only
//!
//! State kept by the process: none. Python caches nothing either — every
//! request fetches the three feeds again.

#![warn(missing_docs)]

pub mod cvrf;
pub mod py;
pub mod routes;
pub mod schema;
pub mod services;
pub mod urls;

#[cfg(test)]
mod vectors;

use std::sync::Arc;

use axum::extract::FromRef;
use copilot_gateway::LegacyProxy;
use copilot_web::AppContext;

pub use routes::router;

/// State of the Patch Tuesday routes.
#[derive(Clone)]
pub struct PatchTuesdayState {
    /// Shared dependencies (auth).
    pub ctx: AppContext,
    /// The feeds.
    pub urls: Arc<urls::Urls>,
    /// The Python backend, for a path with an encoded `/`.
    pub legacy: Option<LegacyProxy>,
}

impl std::fmt::Debug for PatchTuesdayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatchTuesdayState")
            .field("urls", &self.urls)
            .finish_non_exhaustive()
    }
}

impl PatchTuesdayState {
    /// The state, the feeds' URLs read from the environment.
    pub fn new(ctx: AppContext, legacy: Option<LegacyProxy>) -> Self {
        Self {
            ctx,
            urls: Arc::new(urls::Urls::from_env()),
            legacy,
        }
    }
}

impl FromRef<PatchTuesdayState> for AppContext {
    fn from_ref(s: &PatchTuesdayState) -> AppContext {
        s.ctx.clone()
    }
}
