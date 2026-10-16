//! `/api/network_connectors` — port of `app/network_connectors/` (routes,
//! schema, models): the integrations' twin on the `network_connectors_*`
//! tables, without instances.
//!
//! Python's edges are kept: `PUT /update_network_connector/{code}` reads an
//! attribute its schema does not have once the connector is found (a bare
//! 500), `POST /create_network_connector_meta` can never insert (its schema
//! lacks three `NOT NULL` columns: `success: false`), and
//! `PUT /available_network_connectors` commits, then fails to build its
//! response (the 400 of the `ValueError` handler). The network-connector
//! *provisioning* routes (`/api/stack_provisioning/graylog/provision/
//! {fortinet,sonicwall,sentinelone}`) are not part of this router.
//!
//! - [`schema`]   — the request models and the response dumps
//! - [`store`]    — the statements
//! - [`services`] — the flows
//! - [`routes`]   — the handlers

pub mod routes;
pub mod schema;
pub mod services;
pub mod store;
