//! # copilot-response — the response routes
//!
//! Port of the routes that *act* on endpoints:
//!
//! - [`active_response`] — `/api/active_response` (`app/active_response/`:
//!   the supported responses, a script's description, the Wazuh invoke with
//!   its body-field tenancy) and the Graylog webhook `POST /api/graylog/invoke`
//!
//! Each module keeps the backend's `routes / services / schema` split.

#![warn(missing_docs)]

use std::sync::Arc;

use copilot_gateway::LegacyProxy;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

pub mod active_response;

/// What the response routes read from the environment, as set.
#[derive(Debug, Clone, Default)]
pub struct ResponseEnv {
    /// `GRAYLOG_API_HEADER_VALUE` (the webhook's `graylog` header; unset or
    /// empty closes the route).
    pub graylog_api_header_value: Option<String>,
}

/// State of the response routes.
#[derive(Debug, Clone)]
pub struct ResponseState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Wazuh manager client.
    pub wazuh: WazuhState,
    /// The environment the routes read.
    pub env: Arc<ResponseEnv>,
    /// The Python backend (requests these routers hand over).
    pub legacy: Option<LegacyProxy>,
}

pub use active_response::routes::{graylog_router, router as active_response_router};
