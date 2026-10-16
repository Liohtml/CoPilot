//! # copilot-graylog — the Graylog connector
//!
//! Port of `app/connectors/graylog/` (`routes / services / schema`, and
//! `utils/universal.py` as [`client`]) plus the Event Shipper it forwards to
//! (`/graylog/receiver`, [`gelf`]). Mounted at `/api/graylog`.
//!
//! - [`client`]   — [`GraylogClient`]: the helpers (`get`/`post`/`put`/`delete`
//!   with Python's error behaviour), the 6.x/7.x version probe and
//!   [`client::EntityKind`] (the four wrapped entity-creation endpoints), the
//!   URL allowlist fallback. Later ports (stack and customer provisioning,
//!   the WAF's event forwarding, UBA setup) build on it.
//! - [`schema`]   — the Pydantic models, pinned by `model_vectors.json`
//! - [`services`] — collector, events, management, monitoring, pipelines, streams
//! - [`gelf`]     — the Event Shipper (GELF over TCP)
//! - [`routes`]   — the 21 routes

#![warn(missing_docs)]

pub mod client;
pub mod gelf;
pub mod routes;
pub mod schema;
pub mod services;

pub use client::GraylogClient;
pub use routes::{GraylogState, router};
