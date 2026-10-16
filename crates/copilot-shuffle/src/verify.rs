//! `verify_shuffle_connection` — registered with `copilot_connectors::Verifiers`
//! under `Shuffle`: `GET {url}/api/v1/apps/authentication` with the bearer
//! key; a 200 is a success, any other answer names its text, a failure its
//! exception.

use std::sync::Arc;

use async_trait::async_trait;
use http::Method;

use copilot_connectors::schema::VerifyConnectorResponse;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::http::PyRequest;

use crate::client::{CONNECTOR, ShuffleClient};

fn outcome(successful: bool, message: String) -> VerifyOutcome {
    Some(VerifyConnectorResponse {
        connection_successful: successful,
        message,
    })
}

/// The Shuffle verifier.
#[derive(Debug, Clone)]
pub struct ShuffleVerifier(pub ShuffleClient);

#[async_trait]
impl ConnectorVerifier for ShuffleVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        let row = connectors.get(name).await.ok().flatten()?;
        let url = row.connector_url.clone();
        tracing::info!("Verifying the Shuffle connection to {url}");
        let key = row.connector_api_key.as_deref().unwrap_or("None");
        let req = PyRequest::new(Method::GET, format!("{url}/api/v1/apps/authentication"))
            .header("Authorization", format!("Bearer {key}"));
        match self.0.send(req).await {
            Ok(resp) if resp.status() == 200 => {
                tracing::info!("Connection to {url} successful");
                outcome(true, "Shuffle connection successful".into())
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
pub fn verifiers(client: &ShuffleClient) -> Vec<(String, Arc<dyn ConnectorVerifier>)> {
    vec![(
        CONNECTOR.to_string(),
        Arc::new(ShuffleVerifier(client.clone())) as _,
    )]
}
