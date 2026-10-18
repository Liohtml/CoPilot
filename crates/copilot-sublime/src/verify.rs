//! `verify_sublime_connection` — registered with `copilot_connectors::Verifiers`
//! under `Sublime`: `GET {url}/v0/rules?limit=1` with the bearer key and
//! `Content-Type: application/json`; a 200 is a success, any other answer
//! names its text, a failure its exception.

use std::sync::Arc;

use async_trait::async_trait;

use copilot_connectors::schema::VerifyConnectorResponse;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;

use crate::client::{CONNECTOR, SublimeClient};

fn outcome(successful: bool, message: String) -> VerifyOutcome {
    Some(VerifyConnectorResponse {
        connection_successful: successful,
        message,
    })
}

/// The Sublime verifier.
#[derive(Debug, Clone)]
pub struct SublimeVerifier(pub SublimeClient);

#[async_trait]
impl ConnectorVerifier for SublimeVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        tracing::info!("Getting Sublime authentication token");
        let Some(row) = connectors.get(name).await.ok().flatten() else {
            tracing::error!("No Sublime connector found in the database");
            return None;
        };
        let url = row.connector_url.clone();
        tracing::info!("Verifying the Sublime connection to {url}");
        let req = SublimeClient::request(&row, "/v0/rules")
            .params(vec![("limit".to_string(), "1".to_string())]);
        match self.0.send(req).await {
            Ok(resp) if resp.status() == 200 => {
                tracing::info!("Connection to {url} successful");
                outcome(true, "Sublime connection successful".into())
            }
            Ok(resp) => {
                let text = format!("Connection to {url} failed with error: {}", resp.text());
                tracing::error!("{text}");
                outcome(false, text)
            }
            Err(e) => {
                let text = format!("Connection to {url} failed with error: {}", e.display());
                tracing::error!("{text}");
                outcome(false, text)
            }
        }
    }
}

/// The verifiers this crate provides, for the binary's registry.
pub fn verifiers(client: &SublimeClient) -> Vec<(String, Arc<dyn ConnectorVerifier>)> {
    vec![(
        CONNECTOR.to_string(),
        Arc::new(SublimeVerifier(client.clone())) as _,
    )]
}
