//! The two connectors' verifiers, registered with
//! `copilot_connectors::Verifiers` under `OpenCTI` and `Cortex`.
//!
//! - `verify_opencti_connection`: the `CoPilotVerify` document (`about`,
//!   `me`) over httpx, 15 s, certificates unverified; an `errors` array at
//!   HTTP 200 (a revoked token) is a failure, so is an answer without a
//!   version. What Python lets escape makes `verify_connector_by_id` give up
//!   (`None`: the route's 404).
//! - `verify_cortex_connection`: cortex4py's `Api(url, key)` and its
//!   `status` — read as the bound method, never called, so no request is
//!   sent: a row with an API key verifies, one without fails with `Api()`'s
//!   `TypeError` text.

use std::sync::Arc;

use async_trait::async_trait;
use copilot_connectors::schema::VerifyConnectorResponse;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;

use crate::{cortex, opencti};

fn outcome(successful: bool, message: String) -> VerifyOutcome {
    Some(VerifyConnectorResponse {
        connection_successful: successful,
        message,
    })
}

/// The OpenCTI verifier.
#[derive(Debug, Clone, Default)]
pub struct OpenCtiVerifier;

#[async_trait]
impl ConnectorVerifier for OpenCtiVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        let row = connectors.get(name).await.ok().flatten()?;
        let (ok, message) = opencti::transport::verify_credentials(&row).await.ok()?;
        outcome(ok, message)
    }
}

/// The Cortex verifier.
#[derive(Debug, Clone, Default)]
pub struct CortexVerifier;

#[async_trait]
impl ConnectorVerifier for CortexVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        let row = connectors.get(name).await.ok().flatten()?;
        let url = row.connector_url.clone();
        tracing::info!("Verifying the Cortex connection to {url}");
        if row.connector_api_key.is_none() {
            let text = format!(
                "Connection to {url} failed with error: URL and API key are required and must be \
                 of type string."
            );
            tracing::error!("{text}");
            return outcome(false, text);
        }
        tracing::debug!("Cortex connection successful");
        outcome(true, "Cortex connection successful".into())
    }
}

/// The verifiers this crate provides, for the binary's registry.
pub fn verifiers() -> Vec<(String, Arc<dyn ConnectorVerifier>)> {
    vec![
        (
            opencti::transport::CONNECTOR.to_string(),
            Arc::new(OpenCtiVerifier) as _,
        ),
        (
            cortex::client::CONNECTOR.to_string(),
            Arc::new(CortexVerifier) as _,
        ),
    ]
}
