//! # copilot-customers — customer reads
//!
//! Port of the `GET` routes of `app/customers/routes/customers.py`, mounted
//! at `/api/customers`. Creating, updating and deleting customers (and their
//! meta rows) provisions Graylog, Grafana and Wazuh, so those stay in the
//! Python backend: the same paths with another method are 405s here, which
//! the binary forwards to the legacy backend.
//!
//! Every route is admin/analyst. The list is scoped to the caller's
//! customers (it feeds every customer picker); the `{customer_code}` routes
//! check that customer before anything else.
//!
//! - [`schema`]   — `CustomerOut`, `CustomerMetaOut`, `AgentModel`, envelopes
//! - [`services`] — lookups with the Python 404 texts
//! - [`routes`]   — `/`, `/{code}`, `/{code}/meta`, `/{code}/full`,
//!   `/{code}/agents`, `/{code}/agents/healthcheck/{wazuh,velociraptor}`

#![warn(missing_docs)]

pub mod routes;
pub mod schema;
pub mod services;

pub use routes::router;
