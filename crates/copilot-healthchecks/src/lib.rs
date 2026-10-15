//! # copilot-healthchecks — agent health from the `agents` table
//!
//! Port of the database half of `app/healthchecks/agents/` (`routes /
//! services / schema`), mounted at `/api/healthcheck`. An agent is unhealthy
//! when its last check-in is missing, in the future, or older than the
//! requested window; the Wazuh manager (`agent_id` `000`) is left out of the
//! fleet lists.
//!
//! `POST /api/healthcheck/logs` searches the Wazuh indexer and stays in the
//! Python backend until the indexer connector is ported; it is simply not a
//! route here, so the legacy proxy serves it.
//!
//! - [`schema`]   — `ExtendedAgentModel`, `AgentHealthCheckResponse`, time window
//! - [`services`] — the classification (pure), also used by `copilot-customers`
//! - [`routes`]   — `/wazuh`, `/wazuh/{agent_id}`, `/velociraptor`, `/velociraptor/{agent_id}`

#![warn(missing_docs)]

pub mod routes;
pub mod schema;
pub mod services;

pub use routes::router;
