//! Connector verification — `get_connector_service(name).verify_authentication`.
//!
//! Python maps every connector name to a function that calls the tool's API
//! (`verify_wazuh_indexer_connection`, `verify_graylog_connection`, …). Here a
//! tool's crate registers a [`ConnectorVerifier`] under the names it serves;
//! the binary assembles the [`Verifiers`]. A connector whose verifier is not
//! (yet) registered is verified by the Python backend: the routes forward the
//! request there (see `routes`).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use copilot_db::connectors::ConnectorCache;

use crate::schema::VerifyConnectorResponse;

/// What a verifier reports — the `{connectionSuccessful, message}` dict the
/// Python verifiers return. `None` stands for what makes
/// `verify_connector_by_id` give up (its `except Exception` → `None`): the
/// route then answers `404 No connector found for ID`.
pub type VerifyOutcome = Option<VerifyConnectorResponse>;

/// One tool's `verify_<tool>_connection(connector_name)`.
#[async_trait]
pub trait ConnectorVerifier: Send + Sync {
    /// Verify the connector `name`, reading its credentials the way the
    /// Python function does (through the connector cache).
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome;
}

/// Connector name → verifier.
#[derive(Clone, Default)]
pub struct Verifiers(Arc<HashMap<String, Arc<dyn ConnectorVerifier>>>);

impl std::fmt::Debug for Verifiers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&String> = self.0.keys().collect();
        names.sort();
        f.debug_tuple("Verifiers").field(&names).finish()
    }
}

impl Verifiers {
    /// Build from `(name, verifier)` pairs.
    pub fn new(entries: impl IntoIterator<Item = (String, Arc<dyn ConnectorVerifier>)>) -> Self {
        Self(Arc::new(entries.into_iter().collect()))
    }

    /// The verifier for `name`, if this build has one.
    pub fn get(&self, name: &str) -> Option<Arc<dyn ConnectorVerifier>> {
        self.0.get(name).cloned()
    }

    /// Whether this build verifies `name` itself.
    pub fn handles(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// The names this build verifies, sorted.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.0.keys().cloned().collect();
        names.sort();
        names
    }
}

/// `get_connector_service`'s map: every name Python can verify. A name
/// outside it is "not supported" in Python (`verify_connector_by_id` returns
/// `None`, the route 404s) and is answered the same way here.
pub const PYTHON_VERIFIED: &[&str] = &[
    "Wazuh-Manager",
    "Wazuh-Indexer",
    "Velociraptor",
    "Graylog",
    "Graylog-Network",
    "Cortex",
    "Shuffle",
    "Sublime",
    "InfluxDB",
    "Grafana",
    "Wazuh Worker Provisioning",
    "HAProxy Provisioning",
    "Event Shipper",
    "Alert Creation Provisioning",
    "VirusTotal",
    "Portainer",
    "Resend",
    "Talon",
    "OpenCTI",
    "SOCFortress UBA",
];
