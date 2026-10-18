//! # copilot-agents — `/api/agents`
//!
//! Port of `app/agents/` as far as `/api/agents` reaches it:
//!
//! - [`routes`] — the 24 routes of `routes/agents.py`: the `agents` table
//!   (lists, lookups, the critical flag, the pinned Velociraptor id), bulk
//!   and single deletion with their Wazuh and Velociraptor calls and the
//!   `agent.delete` audit row, the sync, the agent's vulnerabilities and SCA
//!   results with their CSV exports (EPSS best-effort), the cases on the
//!   agent's hostname (#1256), outdated agents, the per-customer
//!   vulnerability sync to the Event Shipper
//! - [`services`] — the Wazuh and Velociraptor services, the #1195 client
//!   matching, the sync, the EPSS lookup, `csv.writer`
//! - [`jobs`] — `agent_sync`, taken over from APScheduler by the hand-over
//! - [`db`] / [`schema`] — the statements and the response shapes
//!
//! `/api/vulnerabilities`, `/api/sca` and `/api/syscollector` (the other
//! routers of `app/agents/`) are `copilot-agent-reports`'.

#![warn(missing_docs)]

pub mod db;
pub mod jobs;
pub mod routes;
pub mod schema;
pub mod services;

use copilot_velociraptor::VelociraptorClient;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

use crate::services::epss::EpssClient;

/// State of the agents routes and job.
#[derive(Debug, Clone)]
pub struct AgentsState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Wazuh manager and indexer clients.
    pub wazuh: WazuhState,
    /// The Velociraptor client.
    pub velociraptor: VelociraptorClient,
    /// The EPSS client of the vulnerability CSV.
    pub epss: EpssClient,
}

/// The columns this crate needs.
pub const REQUIREMENTS: &[copilot_db::schema::TableRequirement] = db::REQUIREMENTS;

pub use routes::router;
