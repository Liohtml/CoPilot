//! # copilot-wazuh-rules — the Wazuh manager's rule switches and the Atomic Red Team listings
//!
//! The routes of `app/connectors/wazuh_manager/routes/{rules,mitre}.py`
//! that `copilot-wazuh` left to Python, at their full paths under
//! `/api/wazuh_manager`:
//!
//! | Route | Guard |
//! |---|---|
//! | `GET /rule/disabled`, `POST /rule/disable`, `POST /rule/enable` | `get_current_user(scopes=["admin"])` |
//! | `POST /rule/exclude` | admin (`require_any_scope`) |
//! | `GET /mitre/atomic-tests`, `GET /mitre/techniques/{technique_id}/atomic-tests` | admin/analyst (`require_any_scope`) |
//!
//! - Disabling a rule finds its file through the manager, sets the rule's
//!   level to `1` in the file's JSON, writes the file back as XML
//!   (`xmltodict.unparse`, [`xmltodict`]), restarts the manager and records
//!   the rule and its previous level in `disabledrule`; enabling puts the
//!   recorded level back and deletes the row ([`rules`], [`services`]).
//!   Python could not do either (RUST_MIGRATION.md §4): the table had no
//!   migration, its endpoints lack their `/` and the file went up as JSON.
//! - The exclusion asks the AI module (`http://copilot-ai-module/
//!   wazuh-rule-exclusion`, httpx, 120 s) as Python does.
//! - The Atomic Red Team listings come from GitHub over aiohttp
//!   ([`aiohttp`], [`atomic`]), cached per process for a day.
//!
//! Nothing is tenant-scoped: rules and the ATT&CK tests are
//! deployment-wide, as in Python.

#![warn(missing_docs)]

pub mod aiohttp;
pub mod atomic;
pub mod routes;
pub mod rules;
pub mod schema;
pub mod services;
pub mod xmltodict;

use std::sync::Arc;

use axum::extract::FromRef;
use copilot_integration_modules::upstream::Upstream;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

pub use routes::router;

/// The routes' state.
#[derive(Debug, Clone)]
pub struct RulesState {
    /// The manager client (and the request context).
    pub wazuh: WazuhState,
    /// Where the AI module is reached (`COPILOT_INTEGRATION_MODULES_URL`,
    /// tests only).
    pub upstream: Upstream,
    /// The Atomic Red Team service and its per-process caches.
    pub atomic: Arc<atomic::AtomicService>,
}

impl RulesState {
    /// The state: the modules' override and the GitHub overrides
    /// (`COPILOT_GITHUB_RAW_URL`, `COPILOT_GITHUB_API_URL`) are for tests only.
    pub fn new(
        wazuh: WazuhState,
        modules_url: Option<String>,
        github_raw_url: Option<String>,
        github_api_url: Option<String>,
    ) -> Result<Self, String> {
        Ok(Self {
            wazuh,
            upstream: Upstream::new(modules_url),
            atomic: Arc::new(atomic::AtomicService::new(github_raw_url, github_api_url)?),
        })
    }
}

impl FromRef<RulesState> for AppContext {
    fn from_ref(s: &RulesState) -> AppContext {
        s.wazuh.ctx.clone()
    }
}

/// The `disabledrule` columns this crate reads and writes.
pub const REQUIREMENTS: &[copilot_db::schema::TableRequirement] =
    &[copilot_db::schema::TableRequirement {
        table: services::TABLE,
        columns: services::COLUMNS,
    }];
