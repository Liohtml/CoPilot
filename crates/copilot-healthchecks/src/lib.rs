//! # copilot-healthchecks — agent health from the `agents` table
//!
//! Port of the database half of `app/healthchecks/agents/` (`routes /
//! services / schema`), mounted at `/api/healthcheck`. An agent is unhealthy
//! when its last check-in is missing, in the future, or older than the
//! requested window; the Wazuh manager (`agent_id` `000`) is left out of the
//! fleet lists.
//!
//! `POST /api/healthcheck/logs` asks the Wazuh indexer whether the host
//! logged anything recently ([`logs`], on `copilot-wazuh`'s sync client); the
//! host's tenant is checked first, as in Python.
//!
//! - [`schema`]   — `ExtendedAgentModel`, `AgentHealthCheckResponse`, time window
//! - [`services`] — the classification (pure), also used by `copilot-customers`
//! - [`routes`]   — `/wazuh`, `/wazuh/{agent_id}`, `/velociraptor`, `/velociraptor/{agent_id}`
//! - [`logs`]     — `POST /logs` (`get_host_logs`)

#![warn(missing_docs)]

pub mod logs;
pub mod routes;
pub mod schema;
pub mod services;

pub use routes::router;
