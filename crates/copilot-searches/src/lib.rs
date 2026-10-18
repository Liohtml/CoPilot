//! # copilot-searches — the Detections Catalog (`/api/copilot_searches`)
//!
//! Port of `app/integrations/copilot_searches/` (38 routes): the CoPilot
//! Searches rule lists and details, the MITRE ATT&CK coverage, the rule
//! search on the Wazuh indexer, the Graylog query and event-definition
//! provisioning, the Detection Catalog views (stories, Wazuh ruleset with its
//! firing counts, coverage gaps, compliance, logtest), the rule editor's
//! linter, backtest and publish, and the per-tenant custom repositories.
//!
//! - [`caches`] — the four caches as state of this process: the rules from
//!   GitHub (and the custom repositories), the ATT&CK STIX bundle, the Wazuh
//!   ruleset, the firing counts; `cache_support.py`'s non-blocking refresh
//! - [`refresher`] — this process's own off-request refresh (Python's
//!   scheduler refreshes only Python's copies)
//! - [`rules`], [`catalog`], [`mitre`], [`linter`], [`backtest`],
//!   [`services`], [`custom_repos`] — the services
//! - [`py`], [`pyd`] — Python's operations and Pydantic's validation over a
//!   rule's `yaml.safe_load` values ([`copilot_yaml`])
//! - [`routes`] — the routes, dispatched on the decoded path as Starlette
//!   routes it
//!
//! Differences by design (§4 of `RUST_MIGRATION.md`), each a tenant leak:
//! `/backtest`, `/publish` and `/custom-repos/test` check the body's
//! `customer_code` against the caller's customers, and `GET /custom-repos`
//! lists a scoped caller's customers' repositories only.

#![warn(missing_docs)]

pub mod backtest;
pub mod caches;
pub mod catalog;
pub mod custom_repos;
pub mod db;
pub mod linter;
pub mod mitre;
pub mod py;
pub mod pyd;
pub mod refresher;
pub mod routes;
pub mod rules;
pub mod schema;
pub mod services;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRef;
use copilot_db::schema::TableRequirement;
use copilot_graylog::GraylogClient;
use copilot_objectstore::ObjectStore;
use copilot_upstream::http::PyHttp;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

pub use routes::router;

/// State of the catalog routes.
#[derive(Clone)]
pub struct SearchesState {
    /// Shared dependencies (database, connector cache, auth).
    pub ctx: AppContext,
    /// The Wazuh manager and indexer clients.
    pub wazuh: WazuhState,
    /// The Graylog client (event definitions).
    pub graylog: GraylogClient,
    /// `requests` towards Graylog's search API (the backtest): 60 s, TLS
    /// unverified.
    pub graylog_search: PyHttp,
    /// MinIO (the custom-repo pointers).
    pub store: ObjectStore,
    /// The upstream URLs, `GITHUB_TOKEN`, the refresher switch.
    pub settings: Arc<caches::Settings>,
    /// The four caches.
    pub caches: Arc<caches::Caches>,
}

impl std::fmt::Debug for SearchesState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchesState")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl SearchesState {
    /// The state, with the settings from the configuration and the caches
    /// empty.
    pub fn new(
        env: &copilot_core::catalog_env::CatalogEnv,
        ctx: AppContext,
        wazuh: WazuhState,
        graylog: GraylogClient,
        store: ObjectStore,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            ctx,
            wazuh,
            graylog,
            graylog_search: PyHttp::new(Duration::from_secs(60), false)?,
            store,
            settings: Arc::new(caches::Settings::from_config(env)),
            caches: Arc::default(),
        })
    }
}

impl FromRef<SearchesState> for AppContext {
    fn from_ref(s: &SearchesState) -> AppContext {
        s.ctx.clone()
    }
}

/// The columns this crate reads itself.
pub const REQUIREMENTS: &[TableRequirement] = &[TableRequirement {
    table: "customersmeta",
    columns: &["customer_code", "customer_meta_graylog_stream"],
}];
