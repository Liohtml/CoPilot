//! # copilot-connectors — the connector core
//!
//! Port of `app/connectors/{routes,services,schema,utils,cache}.py`: the
//! `/api/connectors` routes and the verification registry the tool crates
//! plug into.
//!
//! Connector rows are global (one per first-party tool) and cached per
//! process (`copilot_db::connectors::ConnectorCache`). A write here
//! invalidates this process's entry after its commit, as Python does; the
//! Python process — whose cache this one cannot reach — drops the row at its
//! next change check (`CONNECTOR_CACHE_CHECK_SECONDS`, `app/connectors/cache.py`).
//!
//! - [`schema`]   — `ConnectorResponse`, the envelopes, `UpdateConnector`
//! - [`services`] — reads (with `history_logs`), the update and verify writes
//! - [`verify`]   — [`ConnectorVerifier`] and the registry ([`Verifiers`])
//! - [`routes`]   — the handlers

#![warn(missing_docs)]

pub mod routes;
pub mod schema;
pub mod services;
pub mod verify;

use axum::extract::FromRef;
use copilot_gateway::LegacyProxy;
use copilot_web::AppContext;

pub use routes::router;
pub use verify::{ConnectorVerifier, Verifiers, VerifyOutcome};

/// The `connectorhistory` columns read with each connector.
pub const REQUIREMENTS: &[copilot_db::schema::TableRequirement] =
    &[copilot_db::schema::TableRequirement {
        table: "connectorhistory",
        columns: &[
            "id",
            "connector_id",
            "change_timestamp",
            "change_description",
        ],
    }];

/// State of the connector routes.
#[derive(Clone, Debug)]
pub struct ConnectorsState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The tools this build verifies itself.
    pub verifiers: Verifiers,
    /// The Python backend, which verifies (and updates) every other connector.
    pub legacy: Option<LegacyProxy>,
}

impl FromRef<ConnectorsState> for AppContext {
    fn from_ref(s: &ConnectorsState) -> AppContext {
        s.ctx.clone()
    }
}
