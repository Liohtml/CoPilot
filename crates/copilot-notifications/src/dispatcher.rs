//! What a dispatch needs, wherever it starts (a route handler, the
//! in-process sink): the database, the connector cache, the outbound HTTP
//! clients and the deployment's notification settings. Cheap to clone.

use std::sync::Arc;

use copilot_core::notify::NotificationDefaults;
use copilot_db::Db;
use copilot_db::connectors::ConnectorCache;

use crate::channels::send::Outbound;

/// The dispatch dependencies.
#[derive(Clone)]
pub struct Dispatcher(Arc<Inner>);

struct Inner {
    db: Db,
    connectors: ConnectorCache,
    outbound: Outbound,
    defaults: NotificationDefaults,
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher").finish_non_exhaustive()
    }
}

impl Dispatcher {
    /// Build the dispatcher (and its HTTP clients).
    pub fn new(
        db: Db,
        connectors: ConnectorCache,
        defaults: NotificationDefaults,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self(Arc::new(Inner {
            db,
            connectors,
            outbound: Outbound::new()?,
            defaults,
        })))
    }

    /// MySQL.
    pub fn db(&self) -> &Db {
        &self.0.db
    }

    /// Cached `connectors` rows.
    pub fn connectors(&self) -> &ConnectorCache {
        &self.0.connectors
    }

    /// Outbound clients.
    pub fn outbound(&self) -> &Outbound {
        &self.0.outbound
    }

    /// `COPILOT_URL` / `DEFAULT_ALERT_SEVERITY`.
    pub fn defaults(&self) -> &NotificationDefaults {
        &self.0.defaults
    }
}
