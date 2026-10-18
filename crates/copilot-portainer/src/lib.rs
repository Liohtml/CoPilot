//! # copilot-portainer — the Portainer connector
//!
//! Port of `app/connectors/portainer/` (`routes / services / schema`, and
//! `utils/universal.py` as [`client`]). Mounted at `/api/portainer`.
//!
//! - [`client`]   — [`PortainerClient`]: the JWT login and the GET / POST /
//!   DELETE helpers with Python's answers and errors, for later ports
//!   (customer provisioning and decommissioning)
//! - [`schema`]   — the Pydantic models, pinned by `model_vectors.json`
//! - [`services`] — swarm nodes, stacks (details, start, stop, delete), the
//!   customer's stack id in `customersmeta`
//! - [`routes`]   — eight routes (`create-wazuh-customer-stack` is
//!   `copilot-integration-provisioning`'s, with the customer provisioning
//!   that also creates the stack)

#![warn(missing_docs)]

use copilot_db::schema::TableRequirement;

pub mod client;
pub mod routes;
pub mod schema;
pub mod services;

pub use client::PortainerClient;
pub use routes::{PortainerState, router};

/// The columns the stack-id routes read and write.
pub const REQUIREMENTS: &[TableRequirement] = &[TableRequirement {
    table: "customersmeta",
    columns: &["id", "customer_name", "customer_meta_portainer_stack_id"],
}];
