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
//! - [`verdict`]  — a UBA verdict written back onto the linked incident
//!   alert (#1239), audited and on its SLA clock
//! - [`verify`]   — the `SOCFortress UBA` connector verifier
//! - [`provision`] — setup (`GET …/provisioning`, `POST …/provision`) and
//!   the mode (`PUT …/mode`), through [`ops`]
//! - [`rollback`] — the rollback (#1241): plan, steps, checks and the
//!   `uba_rollback` report
//! - [`ownership`] — `uba_provisioned_resource`, what setup made for a
//!   customer

#![warn(missing_docs)]

pub mod client;
pub mod ops;
pub mod ownership;
pub mod params;
pub mod provision;
pub mod pyfmt;
pub mod pyops;
pub mod rollback;
pub mod routes;
pub mod schema;
pub mod services;
pub mod verdict;
pub mod verify;

#[cfg(test)]
mod provision_tests;
#[cfg(test)]
mod rollback_tests;
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

/// The columns this crate reads or writes itself (the incident alerts it
/// writes verdicts on are `copilot-incidents`').
pub const REQUIREMENTS: &[TableRequirement] = &[
    ownership::TABLE,
    rollback::TABLE,
    TableRequirement {
        table: "customersmeta",
        columns: &[
            "customer_code",
            "customer_name",
            "customer_meta_graylog_index",
            "customer_meta_graylog_stream",
        ],
    },
    TableRequirement {
        table: "customer_integrations_meta",
        columns: &[
            "customer_code",
            "integration_name",
            "instance_name",
            "graylog_index_id",
            "graylog_stream_id",
        ],
    },
    TableRequirement {
        table: "customer_integrations",
        columns: &["id", "customer_code"],
    },
    TableRequirement {
        table: "integration_subscriptions",
        columns: &["id", "customer_id", "integration_service_id"],
    },
    TableRequirement {
        table: "integration_services",
        columns: &["id", "service_name"],
    },
    TableRequirement {
        table: "integration_auth_keys",
        columns: &["subscription_id", "auth_key_name", "auth_value"],
    },
];
