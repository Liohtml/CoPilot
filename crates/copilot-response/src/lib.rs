//! # copilot-response — the response routes
//!
//! Port of the routes that *act* on endpoints:
//!
//! - [`active_response`] — `/api/active_response` (`app/active_response/`:
//!   the supported responses, a script's description, the Wazuh invoke with
//!   its body-field tenancy) and the Graylog webhook `POST /api/graylog/invoke`
//! - [`sysmon`] — `/api/sysmon_config` but the upload: customers' Sysmon
//!   configs in MinIO (`copilot-objectstore`), deployed to the Wazuh master's
//!   provisioning worker as aiohttp posts them
//! - [`copilot_action`] — `/api/copilot_action`: the CoPilot Action
//!   inventory (an httpx client of the SOCFortress service) and the invoke,
//!   one Velociraptor collection per target
//!
//! Each module keeps the backend's `routes / services / schema` split.

#![warn(missing_docs)]

use std::sync::Arc;

use copilot_gateway::LegacyProxy;
use copilot_objectstore::ObjectStore;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

pub mod active_response;
pub mod copilot_action;
pub mod sysmon;

/// What the response routes read from the environment, as set.
#[derive(Debug, Clone, Default)]
pub struct ResponseEnv {
    /// `GRAYLOG_API_HEADER_VALUE` (the webhook's `graylog` header; unset or
    /// empty closes the route).
    pub graylog_api_header_value: Option<String>,
    /// The provisioning worker's port (`5003`; `COPILOT_PROVISION_WORKER_PORT`
    /// for the parity harness only).
    pub provision_worker_port: String,
    /// `COPILOT_API_KEY` (the CoPilot Action service's license key; unset or
    /// empty is the inventory routes' 500).
    pub copilot_api_key: Option<String>,
}

impl ResponseEnv {
    /// From the configuration.
    pub fn from_config(
        ingest: &copilot_core::ingest_env::IngestEnv,
        response: &copilot_core::response_env::ResponseEnv,
    ) -> Self {
        Self {
            graylog_api_header_value: ingest.graylog_api_header_value.clone(),
            provision_worker_port: response
                .provision_worker_port
                .clone()
                .unwrap_or_else(|| sysmon::worker::WORKER_PORT.to_string()),
            copilot_api_key: response
                .copilot_api_key
                .as_ref()
                .map(|k| k.expose().to_string()),
        }
    }
}

/// State of the response routes.
#[derive(Debug, Clone)]
pub struct ResponseState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Wazuh manager client.
    pub wazuh: WazuhState,
    /// The MinIO object store (the Sysmon configs).
    pub store: ObjectStore,
    /// The provisioning worker's client (the Sysmon deploy).
    pub worker: sysmon::worker::WorkerHttp,
    /// The CoPilot Action service's client.
    pub action: copilot_action::client::ActionHttp,
    /// The Velociraptor client (the CoPilot Action invoke).
    pub velociraptor: copilot_velociraptor::VelociraptorClient,
    /// The environment the routes read.
    pub env: Arc<ResponseEnv>,
    /// The Python backend (requests these routers hand over).
    pub legacy: Option<LegacyProxy>,
}

pub use active_response::routes::{graylog_router, router as active_response_router};
pub use copilot_action::routes::router as copilot_action_router;
pub use sysmon::routes::router as sysmon_router;
