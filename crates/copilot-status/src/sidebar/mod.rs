//! `GET /api/status/sidebar` — port of `app/status/` (the sidebar's
//! operational context) and of its two scheduler jobs
//! (`refresh_sidebar_indicators`, `refresh_sidebar_health`).
//!
//! Sixteen indicators, split as Python splits them (#1072):
//!
//! - two per user, computed on every request: the caller's unassigned open
//!   alerts (through [`copilot_db::visibility::AlertVisibility`]) and their
//!   open cases;
//! - fourteen deployment-wide (with their audience tags), assembled off the
//!   request path and served from memory: tag RBAC, the AI analyst and
//!   MemPalace queues, failed notification dispatches, the scheduler and
//!   agent-sync staleness, Talon, the core SOC tools, the Wazuh indexer, the
//!   Wazuh catalog (the Detections Catalog's own ruleset cache,
//!   `copilot-searches`), the InfluxDB health checks (their own cache and
//!   cadence), the connectors, the licence and the platform storage.
//!
//! The shared set and the InfluxDB value are state of this process, as they
//! are of each Python process: each backend computes its own from the same
//! database and upstreams, so serving either is the same answer (their
//! timing aside). [`refresher`] refreshes them every 4 and 6 minutes like
//! Python's two jobs, after a warm-up; with the refresher off a request
//! that finds them stale starts one background refresh, as Python's request
//! path does.
//!
//! - [`indicators`] — the builders
//! - [`services`] — the caches, the refreshes and the request
//! - [`routes`] — the route
//! - [`expiry`] — `_parse_license_expiry`

pub mod expiry;
pub mod indicators;
pub mod refresher;
pub mod routes;
pub mod schema;
pub mod services;

use std::sync::Arc;

use axum::extract::FromRef;
use copilot_influxdb::InfluxClient;
use copilot_objectstore::ObjectStore;
use copilot_searches::SearchesState;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

pub use routes::router;

/// What the sidebar reads from the environment.
#[derive(Debug, Clone)]
pub struct SidebarEnv {
    /// `ENVIRONMENT` as `os.getenv` sees it (default `PRODUCTION`).
    pub environment: String,
    /// `COPILOT_SIDEBAR_REFRESH`: whether this process refreshes its shared
    /// indicators itself (warm-up and the two loops); unset, it follows
    /// `COPILOT_CATALOG_REFRESH`, so the parity suites that turn the
    /// catalog's refresher off turn this one off too.
    pub refresh: bool,
    /// Where the release check goes (`COPILOT_VERSION_CHECK_URL`, else
    /// GitHub).
    pub version_check_url: String,
}

impl SidebarEnv {
    /// From the raw values the configuration read.
    pub fn new(
        environment: Option<String>,
        sidebar_refresh: Option<&str>,
        catalog_refresh: bool,
        version_check_url: Option<String>,
    ) -> Self {
        let refresh = match sidebar_refresh {
            None => catalog_refresh,
            Some(v) => !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            ),
        };
        Self {
            environment: environment.unwrap_or_else(|| "PRODUCTION".into()),
            refresh,
            version_check_url: version_check_url.unwrap_or_else(|| {
                copilot_platform::version::DEFAULT_VERSION_CHECK_URL.to_string()
            }),
        }
    }
}

/// State of the sidebar route and its refresher.
#[derive(Clone)]
pub struct SidebarState {
    /// Shared dependencies (database, auth, connector cache).
    pub ctx: AppContext,
    /// The Wazuh indexer (cluster health).
    pub wazuh: WazuhState,
    /// InfluxDB (the health checks).
    pub influx: InfluxClient,
    /// MinIO (the platform storage indicator).
    pub store: ObjectStore,
    /// The Detections Catalog (its Wazuh ruleset cache).
    pub searches: SearchesState,
    /// The environment.
    pub env: Arc<SidebarEnv>,
    /// This process's cached indicators and version.
    pub cache: Arc<services::SidebarCache>,
}

impl std::fmt::Debug for SidebarState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidebarState")
            .field("env", &self.env)
            .finish_non_exhaustive()
    }
}

impl FromRef<SidebarState> for AppContext {
    fn from_ref(s: &SidebarState) -> AppContext {
        s.ctx.clone()
    }
}
