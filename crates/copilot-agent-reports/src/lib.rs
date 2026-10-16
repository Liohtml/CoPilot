//! # copilot-agent-reports — the agents' report routers
//!
//! Port of the routers `app/routers/agents.py` mounts beside `/api/agents`:
//!
//! - [`vulnerabilities`] — `/api/vulnerabilities`: the sync of the Wazuh
//!   indexer's vulnerability states into `agent_vulnerabilities`, the
//!   statistics, the indexer search (with the per-CVE EPSS lookup) and the
//!   CSV reports stored in MinIO (`vulnerability-reports`)
//!
//! Upstreams are reached the way the Python libraries reach them: the
//! indexer through `copilot-wazuh`'s elasticsearch-py port, the manager
//! through its `requests` port, MinIO through `copilot-objectstore`
//! (miniopy-async) and api.first.org through `copilot-agents`' EPSS client.

#![warn(missing_docs)]

pub mod agents;
pub mod pyfmt;
pub mod query;
pub mod vulnerabilities;

use copilot_agents::services::epss::EpssClient;
use copilot_objectstore::ObjectStore;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

/// What these routers need.
#[derive(Debug, Clone)]
pub struct AgentReportsState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Wazuh indexer and manager clients.
    pub wazuh: WazuhState,
    /// MinIO.
    pub store: ObjectStore,
    /// api.first.org (`COPILOT_EPSS_URL` in the parity harness).
    pub epss: EpssClient,
}

impl axum::extract::FromRef<AgentReportsState> for AppContext {
    fn from_ref(s: &AgentReportsState) -> AppContext {
        s.ctx.clone()
    }
}

/// The columns these routers read and write.
pub fn requirements() -> Vec<copilot_db::schema::TableRequirement> {
    vulnerabilities::db::REQUIREMENTS.to_vec()
}
