//! # copilot-uba — the SOCFortress UBA connector
//!
//! Port of `app/connectors/uba/` (`routes / services / schema`, and
//! `utils/universal.py` as [`client`]), mounted at `/api/uba`. CoPilot is
//! the analyst UI for SOCFortress UBA (user behaviour analytics): UBA holds
//! the entities, alerts, signals, suppressions and verdicts, and these
//! routes pass its answers through.
//!
//! - [`client`]   — `uba_request` as httpx 0.28 sends it
//!   (`copilot_threat_intel::httpx`) and its error mapping: a UBA 401/403 is
//!   a 502 with a `reason`, never a CoPilot 401/403
//! - [`params`]   — the query, path and body parameters as FastAPI and
//!   Pydantic validate them
//! - [`schema`]   — the request bodies and the response models
//! - [`services`] — one function per UBA endpoint
//! - [`routes`]   — the routes, `verify_customer_code_access` on every one
//!   but `/availability`
//! - [`verify`]   — the `SOCFortress UBA` connector verifier

#![warn(missing_docs)]

pub mod client;
pub mod params;
pub mod routes;
pub mod schema;
pub mod services;
pub mod verify;

#[cfg(test)]
mod vectors;

use axum::extract::FromRef;
use copilot_db::schema::TableRequirement;
use copilot_graylog::GraylogClient;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

pub use client::UbaClient;
pub use routes::router;
pub use verify::verifiers;

/// State of the UBA routes.
#[derive(Debug, Clone)]
pub struct UbaState {
    /// Shared dependencies (database, connector cache, auth).
    pub ctx: AppContext,
    /// The UBA transport.
    pub client: UbaClient,
    /// Graylog (provisioning and rollback).
    pub graylog: GraylogClient,
    /// The Wazuh manager (the rules UBA relies on).
    pub wazuh: WazuhState,
}

impl UbaState {
    /// The state over the shared clients.
    pub fn new(ctx: AppContext, graylog: GraylogClient, wazuh: WazuhState) -> Self {
        Self {
            client: UbaClient::new(ctx.connectors.clone()),
            ctx,
            graylog,
            wazuh,
        }
    }
}

impl FromRef<UbaState> for AppContext {
    fn from_ref(s: &UbaState) -> AppContext {
        s.ctx.clone()
    }
}

/// The columns this crate reads or writes itself.
pub const REQUIREMENTS: &[TableRequirement] = &[];
