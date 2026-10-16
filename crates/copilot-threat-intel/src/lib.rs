//! # copilot-threat-intel — `/api/threat_intel`
//!
//! Port of `app/threat_intel/` (the routes of `routes/epss.py` and
//! `routes/socfortress.py`, `services/`, `schema/`), with what those routes
//! call elsewhere: the cloud half of `app/integrations/copilot_mcp/`
//! (`query_mcp` for the `cyber-news` server) and the licence check of
//! `app/middleware/license.py` (`get_license`, `is_feature_enabled` and its
//! `license_cache`).
//!
//! - [`routes`] — the 11 routes: `POST /epss`, `/socfortress`,
//!   `/process_name`, `/virustotal`, `/virustotal/file/submit`,
//!   `/virustotal/file/analyze`, `GET /virustotal/analysis/{id}`,
//!   `/virustotal/file/{id}`, and `POST /ai/analyze-alert`,
//!   `/ai/wazuh-exclusion-rule`, `/ai/velociraptor-artifact-recommendation`
//! - [`httpx`] — httpx 0.28's `AsyncClient`, which every upstream but the
//!   licence server is called with; [`license`] — the licence check over
//!   `requests` (`copilot_upstream::http::PyHttp`)
//! - [`services`] / [`schema`] — the services and their Pydantic models
//!
//! The upstream URLs are Python's constants; [`urls`] lets the parity
//! harness point each at a stand-in.
//!
//! Difference by design (§4 of `RUST_MIGRATION.md`): the two AI routes that
//! comment on a CoPilot alert check, for a scoped caller, that the alert is
//! theirs before anything is sent (Python commented on any tenant's alert).

#![warn(missing_docs)]

pub mod httpx;
pub mod license;
pub mod py;
pub mod routes;
pub mod schema;
pub mod services;
pub mod urls;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRef;
use copilot_core::config::Secret;
use copilot_db::schema::TableRequirement;
use copilot_gateway::LegacyProxy;
use copilot_ingest::IngestState;
use copilot_upstream::http::PyHttp;
use copilot_web::AppContext;

pub use routes::router;

/// State of the threat-intel routes.
#[derive(Clone)]
pub struct ThreatIntelState {
    /// Shared dependencies (database, connector cache, auth).
    pub ctx: AppContext,
    /// The ingest's state: `get_single_alert_details` reads the indexer
    /// through it.
    pub ingest: IngestState,
    /// The upstream URLs.
    pub urls: Arc<urls::Urls>,
    /// `COPILOT_API_KEY` (`os.getenv`: `None` when unset).
    pub api_key: Option<Secret>,
    /// `requests` towards the licence server (10 s, TLS verified).
    pub license_http: PyHttp,
    /// The Python backend, for a path with an encoded `/`.
    pub legacy: Option<LegacyProxy>,
}

impl std::fmt::Debug for ThreatIntelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreatIntelState")
            .field("urls", &self.urls)
            .finish_non_exhaustive()
    }
}

impl ThreatIntelState {
    /// The state, with the upstream URLs read from the environment.
    pub fn new(
        ctx: AppContext,
        ingest: IngestState,
        api_key: Option<Secret>,
        legacy: Option<LegacyProxy>,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            ctx,
            ingest,
            urls: Arc::new(urls::Urls::from_env()),
            api_key,
            license_http: PyHttp::new(Duration::from_secs(10), true)?,
            legacy,
        })
    }
}

impl FromRef<ThreatIntelState> for AppContext {
    fn from_ref(s: &ThreatIntelState) -> AppContext {
        s.ctx.clone()
    }
}

/// The columns this crate reads or writes itself.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "license",
        columns: &["id", "license_key"],
    },
    TableRequirement {
        table: "license_cache",
        columns: &[
            "id",
            "license_key",
            "feature_name",
            "is_enabled",
            "cached_at",
            "expires_at",
            "license_data",
        ],
    },
    TableRequirement {
        table: "incident_management_comment",
        columns: &["id", "alert_id", "comment", "user_name", "created_at"],
    },
    TableRequirement {
        table: "agents",
        columns: &["agent_id", "os"],
    },
];
