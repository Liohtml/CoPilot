//! # copilot-assessments — the GitHub organization audit and Nuclei scans
//!
//! Port of `app/integrations/github_audit/` (`/api/github-audit`, 19 routes)
//! and `app/integrations/nuclei/` (`/api/nuclei`, 4 routes).
//!
//! - [`github`]: configurations, reports, check exclusions and baselines on
//!   their four tables, and the audit itself — the GitHub REST API as
//!   `GitHubAuditService` calls it over httpx 0.28, every check with
//!   Python's value semantics, the report written back as the route writes
//!   it. Tenancy (§4): every object a route names or addresses by id is the
//!   caller's customer's, fail closed.
//! - [`nuclei`]: the four proxies to the `copilot-nuclei-module` container.
//! - [`paths`]: both prefixes routed on the decoded path, as Starlette does.
//!
//! No per-process state: a request reads and writes the database and the
//! upstreams only, so either backend can answer any of these routes.

#![warn(missing_docs)]

pub mod github;
pub mod nuclei;
pub mod paths;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod vectors;

use axum::Router;
use axum::extract::FromRef;
use copilot_core::assessments_env::AssessmentsEnv;
use copilot_gateway::LegacyProxy;
use copilot_web::AppContext;

/// What the routes need.
#[derive(Clone)]
pub struct AssessmentsState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// `COPILOT_GITHUB_AUDIT_API_URL` (tests only): GitHub's API base.
    pub github_api: Option<String>,
    /// Where the Nuclei module is reached.
    pub nuclei: nuclei::services::Upstream,
    /// The Python backend, for the paths no route takes.
    pub legacy: Option<LegacyProxy>,
}

impl AssessmentsState {
    /// The state from the configuration's overrides.
    pub fn new(ctx: AppContext, env: &AssessmentsEnv, legacy: Option<LegacyProxy>) -> Self {
        Self {
            ctx,
            github_api: env.github_api_url.clone(),
            nuclei: nuclei::services::Upstream::new(env.nuclei_module_url.clone()),
            legacy,
        }
    }
}

impl FromRef<AssessmentsState> for AppContext {
    fn from_ref(s: &AssessmentsState) -> AppContext {
        s.ctx.clone()
    }
}

/// The columns this crate reads and writes.
pub const REQUIREMENTS: &[copilot_db::schema::TableRequirement] = github::store::REQUIREMENTS;

/// Both routers, by full path (`/api/github-audit/*`, `/api/nuclei/*`).
pub fn router(state: AssessmentsState) -> Router {
    let legacy = state.legacy.clone();
    let github = {
        let state = state.clone();
        paths::starlette_routing(
            move || github::routes::routes(state.clone()),
            "/api/github-audit",
            legacy.clone(),
        )
    };
    let nuclei = paths::starlette_routing(
        move || nuclei::routes::routes(state.clone()),
        "/api/nuclei",
        legacy,
    );
    Router::new().merge(github).merge(nuclei)
}
