//! # copilot-mcp — `/api/copilot_mcp`
//!
//! Port of `app/integrations/copilot_mcp/` (routes, `services/copilot_mcp.py`,
//! `services/example_questions.py`, schema): the MCP servers CoPilot can ask
//! (`GET /servers`, `/servers/{mcp_server}`), their example questions and
//! categories, and `POST /query`, which `MCPService.execute_query` sends to
//! the local `copilot-mcp` container (`http://copilot-mcp/mcp/{endpoint}`:
//! the Wazuh indexer and manager, CoPilot's MySQL, Velociraptor) or to
//! SOCFortress's cloud (`https://mcp.socfortress.co/query/{endpoint}`, with
//! the licence key as `x-api-key`, behind the `SOCFORTRESS AI` feature).
//!
//! - [`routes`] — the five routes; [`schema`] — `MCPServerType`, the routing
//!   table, the request model and the example-question tables
//! - the query itself is `copilot_threat_intel::services::mcp::execute_query`
//!   (the one Rust definition, which `/threat_intel/process_name` uses for
//!   `cyber-news`), and the licence check `cloud_license_key` beside it
//!
//! State kept by the process: none (the tables are constants, as in Python).

#![warn(missing_docs)]

pub mod routes;
pub mod schema;

#[cfg(test)]
mod vectors;

use axum::extract::FromRef;
use copilot_threat_intel::ThreatIntelState;
use copilot_web::AppContext;

pub use routes::router;

/// `MCPService._BASE_URLS[LOCAL]`.
pub const LOCAL_BASE: &str = "http://copilot-mcp/mcp";

/// State of the CoPilot MCP routes.
#[derive(Clone)]
pub struct McpState {
    /// Shared dependencies (auth).
    pub ctx: AppContext,
    /// The threat-intel state: the cloud base URL, the licence server and
    /// `COPILOT_API_KEY`.
    pub threat_intel: ThreatIntelState,
    /// The local services' base (`COPILOT_MCP_LOCAL_URL` — parity harness
    /// only — else [`LOCAL_BASE`]).
    pub local_base: String,
}

impl std::fmt::Debug for McpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpState")
            .field("local_base", &self.local_base)
            .finish_non_exhaustive()
    }
}

impl McpState {
    /// The state, the local base read from the environment.
    pub fn new(ctx: AppContext, threat_intel: ThreatIntelState) -> Self {
        let local_base = std::env::var("COPILOT_MCP_LOCAL_URL")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| LOCAL_BASE.to_string());
        Self {
            ctx,
            threat_intel,
            local_base,
        }
    }
}

impl FromRef<McpState> for AppContext {
    fn from_ref(s: &McpState) -> AppContext {
        s.ctx.clone()
    }
}
