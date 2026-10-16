//! The Wazuh connectors' verification — `verify_wazuh_indexer_connection`
//! and `verify_wazuh_manager_connection` — registered with
//! `copilot_connectors::Verifiers` under `Wazuh-Indexer` and `Wazuh-Manager`.

use async_trait::async_trait;
use reqwest::Method;

use copilot_connectors::schema::VerifyConnectorResponse;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;

use crate::WazuhState;
use crate::es::{self, Es, Flavor};

fn outcome(successful: bool, message: String) -> VerifyOutcome {
    Some(VerifyConnectorResponse {
        connection_successful: successful,
        message,
    })
}

/// `verify_wazuh_indexer_credentials`: `cluster.health()` with the row's
/// credentials (no placeholder check, as in Python).
#[derive(Debug, Clone)]
pub struct IndexerVerifier(pub WazuhState);

#[async_trait]
impl ConnectorVerifier for IndexerVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        // `attributes['connector_url']` before the `None` check: a missing
        // row is a `TypeError`, which `verify_connector_by_id` turns into `None`.
        let row = connectors.get(name).await.ok().flatten()?;
        let url = row.connector_url.clone();
        tracing::info!("Verifying the wazuh-indexer connection to {url}");
        let es = match Es::from_row(&self.0.es, &row, Flavor::Sync) {
            Ok(es) => es,
            Err(e) => {
                tracing::error!("Connection to {url} failed with error: {e}");
                return outcome(false, format!("Connection to {url} failed with error: {e}"));
            }
        };
        match es.perform(Method::GET, "/_cluster/health", &[], None).await {
            Ok(_) => outcome(true, "Wazuh Indexer connection successful".into()),
            Err(e) => {
                tracing::error!("Connection to {url} failed with error: {e}");
                outcome(false, format!("Connection to {url} failed with error: {e}"))
            }
        }
    }
}

/// `verify_wazuh_manager_credentials`: one `GET /security/user/authenticate`
/// (the token cache is not consulted, as in Python).
#[derive(Debug, Clone)]
pub struct ManagerVerifier(pub WazuhState);

#[async_trait]
impl ConnectorVerifier for ManagerVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        let row = connectors.get(name).await.ok().flatten()?;
        let url = row.connector_url.clone();
        tracing::info!("Verifying the wazuh-manager connection to {url}");
        match self.0.manager.authenticate(&row).await {
            Ok(200) => outcome(true, "Wazuh Manager authentication successful".into()),
            Ok(_) => outcome(false, format!("Connection to {url} failed")),
            Err(e) => {
                tracing::error!("Connection to {url} failed with error: {e}");
                outcome(false, format!("Connection to {url} failed with error."))
            }
        }
    }
}

/// The verifiers this crate provides, for the binary's registry.
pub fn verifiers(state: &WazuhState) -> Vec<(String, std::sync::Arc<dyn ConnectorVerifier>)> {
    vec![
        (
            es::CONNECTOR.to_string(),
            std::sync::Arc::new(IndexerVerifier(state.clone())) as _,
        ),
        (
            crate::manager::client::CONNECTOR.to_string(),
            std::sync::Arc::new(ManagerVerifier(state.clone())) as _,
        ),
    ]
}
