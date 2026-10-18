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
//! - [`upload`]   — `POST /upload/{connector_identifier}` (the YAML file
//!   written to the Python backend's data directory)

#![warn(missing_docs)]

pub mod routes;
pub mod schema;
pub mod services;
pub mod upload;
pub mod verify;

use axum::extract::FromRef;
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
    /// The tools this build verifies (every one `get_connector_service` knows).
    pub verifiers: Verifiers,
    /// The Python backend's data directory (`UPLOAD_FOLDER`,
    /// `COPILOT_BACKEND_DATA_DIR`), where a YAML upload is written.
    pub data_dir: std::path::PathBuf,
}

impl FromRef<ConnectorsState> for AppContext {
    fn from_ref(s: &ConnectorsState) -> AppContext {
        s.ctx.clone()
    }
}
