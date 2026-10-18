//! # copilot-monitoring-alerts — the monitoring-alert catalog
//!
//! Port of `app/integrations/monitoring_alert/` (`routes / services /
//! schema`), mounted at `/api/monitoring_alert`:
//!
//! - `GET /available` — the catalog (`AvailableMonitoringAlerts`);
//! - `POST /provision` — one catalog alert as a Graylog event definition, on
//!   the default Graylog or the network one (`graylog_instance`), the two
//!   SOCFortress WAF alerts through `copilot-waf` and always on the default
//!   Graylog (`PINNED_TO_DEFAULT_GRAYLOG`);
//! - `POST /provision/custom` — an event definition from the request's own
//!   query, priority, streams and timings;
//! - `POST /provision/testing` — one test event to the Event Shipper (GELF
//!   over TCP, `copilot_graylog::gelf`).
//!
//! Modules:
//!
//! - [`catalog`]  — the alerts, one data row per Python provisioning function
//! - [`schema`]   — the request models and the `GraylogAlertProvision*` models
//! - [`services`] — the existence check, `provision_alert_definition`, the
//!   bodies, the test event
//! - [`body`]     — request bodies with CPython's `json.loads` values
//! - [`routes`]   — the four routes
//!
//! The only state this crate keeps is `copilot-graylog`'s: the connector
//! cache and the Graylog major version per connector (five minutes), the
//! same per-process caches the Python process keeps (`connector_cache`,
//! `_GRAYLOG_VERSION_CACHE`) — neither is written by these routes, so the two
//! backends never disagree for longer than those caches allow.

#![warn(missing_docs)]

pub mod body;
pub mod catalog;
pub mod routes;
pub mod schema;
pub mod services;

#[cfg(test)]
mod vectors;

use copilot_graylog::GraylogClient;
use copilot_waf::WafState;
use copilot_web::AppContext;

pub use routes::router;

/// Route state.
#[derive(Debug, Clone)]
pub struct MonitoringAlertState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Graylog client (both connectors).
    pub graylog: GraylogClient,
    /// The customer WAF module, for its two alerts.
    pub waf: WafState,
}

impl axum::extract::FromRef<MonitoringAlertState> for AppContext {
    fn from_ref(s: &MonitoringAlertState) -> AppContext {
        s.ctx.clone()
    }
}
