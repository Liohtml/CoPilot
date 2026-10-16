//! `/api/sca` — `app/agents/sca/`: the overview of every agent's SCA
//! policies (and its event stream), the statistics, the CSV reports, the
//! CoPilot-SCA policy catalog and the package registry.

pub mod db;
pub mod policies;
pub mod registry;
pub mod routes;
pub mod schema;
pub mod services;
pub mod stream;

pub use routes::router;
