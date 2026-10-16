//! `/api/syscollector` — `app/agents/wazuh/syscollector/`: an agent's
//! installed packages from the Wazuh manager, and the package search in the
//! indexer's `wazuh-states-inventory-packages-*`.

pub mod routes;
pub mod schema;
pub mod services;

pub use routes::router;
