//! `/api/copilot_action`: the CoPilot Action inventory (an external
//! service) and its invocation on endpoints through Velociraptor.

pub mod client;
pub mod collect;
pub mod invoke;
pub mod routes;
pub mod schema;
pub mod services;
