//! # copilot-grafana — the Grafana connector
//!
//! Port of `app/connectors/grafana/` as CoPilot serves it over HTTP:
//! `/api/reporting/*` (but the Playwright PDF report) and
//! `/api/user/user/organization/add`.
//!
//! - [`client`]   — [`GrafanaClient`]: `create_grafana_client` and the
//!   `grafana_client` (niquests) requests, answers and errors; the element
//!   calls later ports need (organizations, dashboards, folders)
//! - [`schema`]   — the Pydantic models, pinned by `model_vectors.json`
//! - [`services`] — reporting reads, iframe links, adding a user to an org
//! - [`routes`]   — the six routes

#![warn(missing_docs)]

pub mod client;
pub mod routes;
pub mod schema;
pub mod services;

pub use client::GrafanaClient;
pub use routes::{GrafanaState, router};
