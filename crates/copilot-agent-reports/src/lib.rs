//! # copilot-agent-reports — the agents' report routers
//!
//! Port of the routers `app/routers/agents.py` mounts beside `/api/agents`:
//!
//! - [`vulnerabilities`] — `/api/vulnerabilities`: the sync of the Wazuh
//!   indexer's vulnerability states into `agent_vulnerabilities`, the
//!   statistics, the indexer search (with the per-CVE EPSS lookup) and the
//!   CSV reports stored in MinIO (`vulnerability-reports`)
//! - [`sca`] — `/api/sca`: the SCA overview of every agent from the Wazuh
//!   manager (and its server-sent-events stream), the statistics, the CSV
//!   reports (`sca-reports`), the CoPilot-SCA policy catalog on GitHub and
//!   the package registry with its indexer lookup
//!
//! Upstreams are reached the way the Python libraries reach them: the
//! indexer through `copilot-wazuh`'s elasticsearch-py port, the manager
//! through its `requests` port, MinIO through `copilot-objectstore`
//! (miniopy-async), api.first.org through `copilot-agents`' EPSS client and
//! GitHub through an httpx-shaped client ([`httpx`]).

#![warn(missing_docs)]

pub mod agents;
pub mod httpx;
pub mod pyfmt;
pub mod query;
pub mod sca;
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
    /// The CoPilot-SCA repository (`COPILOT_SCA_REPO_URL` in the parity
    /// harness).
    pub sca_repo: sca::policies::ScaRepo,
}

impl axum::extract::FromRef<AgentReportsState> for AppContext {
    fn from_ref(s: &AgentReportsState) -> AppContext {
        s.ctx.clone()
    }
}

/// The columns these routers read and write.
pub fn requirements() -> Vec<copilot_db::schema::TableRequirement> {
    let mut all = vulnerabilities::db::REQUIREMENTS.to_vec();
    all.extend_from_slice(sca::db::REQUIREMENTS);
    all
}
