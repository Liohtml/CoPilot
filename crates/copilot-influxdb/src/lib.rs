//! # copilot-influxdb — the InfluxDB connector
//!
//! Port of `app/connectors/influxdb/` (`routes / services / schema`, and
//! `utils/universal.py` as [`client`]). Mounted at `/api/influxdb`.
//!
//! - [`client`]   — [`InfluxClient`]: Flux queries sent as `influxdb_client`
//!   (aiohttp) sends them, with its error texts; the v2 REST helpers
//!   (`_influxdb_request`, the org-id lookup) for the checks provisioning to
//!   build on
//! - [`flux`]     — the annotated-CSV parser (`FluxCsvParser`, tables mode)
//! - [`schema`]   — the Pydantic models, pinned by `model_vectors.json`
//! - [`services`] — alerts (current state per monitored thing, #1118),
//!   check names, hosts and the seven metrics views
//! - [`routes`]   — the 10 routes

#![warn(missing_docs)]

pub mod client;
pub mod flux;
pub mod routes;
pub mod schema;
pub mod services;

pub use client::InfluxClient;
pub use routes::{InfluxState, router};
