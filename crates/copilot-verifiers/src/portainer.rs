//! `verify_portainer_connection(name)`: `GET {url}/api/v1/apps/authentication`
//! with `Authorization: Bearer {api_key}` (2 s); unless it answers 200,
//! `POST urljoin(url, "/api/auth")` with `{"username", "password"}` (2 s),
//! whose 200 is the success "via JWT" (its `jwt` read: a missing key or a
//! non-JSON answer is the failure naming it). Both over `requests`,
//! certificates unverified.

use std::time::Duration;

use async_trait::async_trait;
use http::Method;

use copilot_auth::pyvalue::PyValue;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_portainer::client::urljoin_absolute;
use copilot_upstream::http::{PyHttp, PyRequest};
use copilot_upstream::model::kwargs;
use copilot_upstream::py::{PyExc, PyResult, getitem};

use crate::outcome;

/// `timeout=2`.
const TIMEOUT: Duration = Duration::from_secs(2);

/// The Portainer verifier.
#[derive(Debug, Clone, Copy)]
pub struct PortainerVerifier;

fn text(v: Option<&String>) -> PyValue {
    v.map_or(PyValue::None, |s| PyValue::Str(s.clone()))
}

#[async_trait]
impl ConnectorVerifier for PortainerVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        tracing::info!("Getting portainer authentication token");
        let Some(row) = connectors.get(name).await.ok()? else {
            tracing::error!("No portainer connector found in the database");
            return None;
        };
        let url = row.connector_url.clone();
        tracing::info!("Verifying the portainer connection to {url}");
        let result: PyResult<VerifyOutcome> = async {
            let http = PyHttp::new(TIMEOUT, false)
                .map_err(|e| PyExc::Other("Exception", e.to_string()))?;
            let key = row.connector_api_key.as_deref().unwrap_or("None");
            let apps = http
                .send(
                    PyRequest::new(Method::GET, format!("{url}/api/v1/apps/authentication"))
                        .header("Authorization", format!("Bearer {key}")),
                )
                .await?;
            if apps.status() == 200 {
                tracing::info!("Connection to {url} successful via API key");
                return Ok(outcome(true, "Portainer connection successful via API key"));
            }
            let body = kwargs(vec![
                ("username", text(row.connector_username.as_ref())),
                ("password", text(row.connector_password.as_ref())),
            ]);
            let jwt = http
                .send(
                    PyRequest::new(Method::POST, urljoin_absolute(&url, "/api/auth"))
                        .json(Some(body)),
                )
                .await?;
            if jwt.status() == 200 {
                let answer = jwt.json()?;
                getitem(&answer, "jwt")?;
                tracing::info!("JWT authentication successful");
                return Ok(outcome(true, "Portainer connection successful via JWT"));
            }
            tracing::error!(
                "Both API key and JWT authentication failed. JWT error: {}",
                jwt.text()
            );
            Ok(outcome(false, "Both API key and JWT authentication failed"))
        }
        .await;
        match result {
            Ok(o) => o,
            Err(e) => {
                let text = format!("Connection to {url} failed with error: {}", e.display());
                tracing::error!("{text}");
                outcome(false, text)
            }
        }
    }
}
