//! `verify_graylog_connection(name)` for `Graylog` and `Graylog-Network`:
//! `GET {url}/api/authz/roles/user/{username}` over `requests` with Basic
//! auth, certificates unverified, 60 s; a 200 is the success, any other
//! answer names its text, an exception its `str()`.

use std::time::Duration;

use async_trait::async_trait;
use http::Method;

use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::http::{PyHttp, PyRequest};

use crate::outcome;

/// `GRAYLOG_REQUEST_TIMEOUT`.
const TIMEOUT: Duration = Duration::from_secs(60);

/// The Graylog verifier (either connector name).
#[derive(Debug, Clone, Copy)]
pub struct GraylogVerifier;

#[async_trait]
impl ConnectorVerifier for GraylogVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        tracing::info!("Getting Graylog authentication token");
        let Some(row) = connectors.get(name).await.ok()? else {
            tracing::error!("No Graylog connector found in the database");
            return None;
        };
        let url = row.connector_url.clone();
        tracing::info!("Verifying the graylog connection to {url}");
        let user = row
            .connector_username
            .clone()
            .unwrap_or_else(|| "None".into());
        let failed = |text: String| {
            let text = format!("Connection to {url} failed with error: {text}");
            tracing::error!("{text}");
            outcome(false, text)
        };
        let http = match PyHttp::new(TIMEOUT, false) {
            Ok(h) => h,
            Err(e) => return failed(e.to_string()),
        };
        let req = PyRequest::new(Method::GET, format!("{url}/api/authz/roles/user/{user}")).basic(
            row.connector_username.clone(),
            row.connector_password.clone(),
        );
        match http.send(req).await {
            Ok(resp) if resp.status() == 200 => {
                tracing::info!("Connection to {url} successful");
                outcome(true, "Graylog connection successful")
            }
            Ok(resp) => failed(resp.text()),
            Err(e) => failed(e.display()),
        }
    }
}
