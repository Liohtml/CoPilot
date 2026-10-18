//! The state every ported route shares.

use std::sync::Arc;

use copilot_auth::JwtCodec;
use copilot_core::audit::SharedAuditSink;
use copilot_core::notify::{NotificationDefaults, SharedNotificationSink};
use copilot_db::Db;
use copilot_db::connectors::ConnectorCache;

/// Shared dependencies, built once by the binary. Cheap to clone.
#[derive(Clone)]
pub struct AppContext(Arc<AppDeps>);

/// What [`AppContext`] holds.
pub struct AppDeps {
    /// MySQL.
    pub db: Db,
    /// Session-token codec (shared `JWT_SECRET`).
    pub jwt: JwtCodec,
    /// Cached `connectors` rows.
    pub connectors: ConnectorCache,
    /// `audit_log` writer.
    pub audit: SharedAuditSink,
    /// Notification hand-off.
    pub notifications: SharedNotificationSink,
    /// `COPILOT_URL` / `DEFAULT_ALERT_SEVERITY`.
    pub notification_defaults: NotificationDefaults,
    /// Outbound HTTP client for connectors (TLS verification follows each
    /// connector's own rules; see the connector crates).
    pub http: reqwest::Client,
    /// Write `log_entries` rows for handled errors, like the Python handlers.
    pub log_handled_errors: bool,
}

impl AppContext {
    /// Wrap the dependencies.
    pub fn new(deps: AppDeps) -> Self {
        Self(Arc::new(deps))
    }
}

impl std::ops::Deref for AppContext {
    type Target = AppDeps;

    fn deref(&self) -> &AppDeps {
        &self.0
    }
}

impl std::fmt::Debug for AppContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppContext").finish_non_exhaustive()
    }
}
