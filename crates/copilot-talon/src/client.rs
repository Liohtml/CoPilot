//! HTTP client for Talon — port of `app/connectors/talon/utils/universal.py`.
//!
//! The endpoint and key come from the `connectors` row named `Talon`
//! (`connector_url`, `connector_api_key`), read through the connector cache
//! on every call so an operator's change applies without a restart.
//!
//! Timeouts match the Python helpers: GET connect 5 s / read 30 s, POST 120 s
//! unless the caller says otherwise, the `/message` stream with no read
//! timeout at all (an answer can take minutes). TLS verification is **off by
//! default**, as in Python (`verify=False`) — Talon runs on the private
//! network next to CoPilot, usually over plain HTTP; `TALON_VERIFY_TLS=true`
//! turns it on.

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use copilot_db::DbError;
use copilot_db::connectors::ConnectorCache;

use crate::contract::ErrorBody;

/// The `connectors.connector_name` CoPilot seeds for Talon.
pub const CONNECTOR_NAME: &str = "Talon";

/// Default POST timeout (`send_post_request(timeout=120)`).
pub const POST_TIMEOUT: Duration = Duration::from_secs(120);

/// Why a Talon call failed. `Display` strings are the messages the Python
/// helpers returned (and services raised as 500 details).
#[derive(Debug, thiserror::Error)]
pub enum TalonError {
    /// No `Talon` row in `connectors`.
    #[error("No Talon connector found in the database")]
    NotConfigured,
    /// Transport failure, non-2xx or a non-JSON body.
    #[error("Failed to send {method} request to {endpoint} with error: {cause}")]
    Request {
        /// `GET` / `POST`.
        method: &'static str,
        /// e.g. `/investigate`.
        endpoint: String,
        /// What went wrong (includes Talon's `{"error"}` text when present).
        cause: String,
    },
    /// Reading the connector row failed.
    #[error("{0}")]
    Db(#[from] DbError),
}

/// Talon connector: the cache to resolve credentials from and the HTTP client.
#[derive(Debug, Clone)]
pub struct TalonConnector {
    connectors: ConnectorCache,
    http: reqwest::Client,
}

/// Resolved credentials for one call.
#[derive(Clone)]
pub struct TalonEndpoint {
    base_url: String,
    api_key: String,
}

impl std::fmt::Debug for TalonEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TalonEndpoint")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl TalonConnector {
    /// Build the connector. Fails only if the TLS backend cannot initialise.
    pub fn new(connectors: ConnectorCache, verify_tls: bool) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(!verify_tls)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("copilot/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { connectors, http })
    }

    /// Resolve the current endpoint from the `connectors` table.
    pub async fn endpoint(&self) -> Result<TalonEndpoint, TalonError> {
        let row = self
            .connectors
            .get(CONNECTOR_NAME)
            .await?
            .ok_or(TalonError::NotConfigured)?;
        Ok(TalonEndpoint {
            base_url: row.connector_url.trim_end_matches('/').to_string(),
            api_key: row.connector_api_key.unwrap_or_default(),
        })
    }

    fn request(
        &self,
        ep: &TalonEndpoint,
        method: reqwest::Method,
        endpoint: &str,
    ) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{}", ep.base_url, endpoint))
            .header("x-api-key", &ep.api_key)
    }

    /// `send_get_request`: GET, JSON response body.
    pub async fn get(&self, endpoint: &str, query: &[(&str, String)]) -> Result<Value, TalonError> {
        let ep = self.endpoint().await?;
        let req = self
            .request(&ep, reqwest::Method::GET, endpoint)
            .query(query)
            .timeout(Duration::from_secs(35));
        send_json(req, "GET", endpoint).await
    }

    /// `send_post_request`: POST JSON, JSON response body.
    pub async fn post(
        &self,
        endpoint: &str,
        body: &impl Serialize,
        timeout: Duration,
    ) -> Result<Value, TalonError> {
        let ep = self.endpoint().await?;
        let req = self
            .request(&ep, reqwest::Method::POST, endpoint)
            .json(body)
            .timeout(timeout);
        send_json(req, "POST", endpoint).await
    }

    /// `send_post_request_sse`: POST JSON and hand back the streaming
    /// response once Talon answered 2xx.
    pub async fn post_stream(
        &self,
        endpoint: &str,
        body: &impl Serialize,
    ) -> Result<reqwest::Response, TalonError> {
        let ep = self.endpoint().await?;
        let resp = self
            .request(&ep, reqwest::Method::POST, endpoint)
            .json(body)
            .send()
            .await
            .map_err(|e| request_error("POST", endpoint, e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(request_error("POST", endpoint, status.to_string()));
        }
        Ok(resp)
    }
}

fn request_error(method: &'static str, endpoint: &str, cause: String) -> TalonError {
    TalonError::Request {
        method,
        endpoint: endpoint.to_string(),
        cause,
    }
}

async fn send_json(
    req: reqwest::RequestBuilder,
    method: &'static str,
    endpoint: &str,
) -> Result<Value, TalonError> {
    let resp = req
        .send()
        .await
        .map_err(|e| request_error(method, endpoint, e.to_string()))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| request_error(method, endpoint, e.to_string()))?;
    if !status.is_success() {
        let reason = serde_json::from_slice::<ErrorBody>(&bytes)
            .map(|b| format!("{status}: {}", b.error))
            .unwrap_or_else(|_| status.to_string());
        return Err(request_error(method, endpoint, reason));
    }
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| request_error(method, endpoint, format!("invalid JSON response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_match_python_helpers() {
        assert_eq!(
            TalonError::NotConfigured.to_string(),
            "No Talon connector found in the database"
        );
        let e = request_error("POST", "/investigate", "502 Bad Gateway".into());
        assert_eq!(
            e.to_string(),
            "Failed to send POST request to /investigate with error: 502 Bad Gateway"
        );
    }
}
