//! The healthcheck verifications of `app/utils.py` and the Talon connector:
//! one `requests.get(url, verify=False)` each (two for nothing: the worker
//! provisioning checks every host of a comma-separated URL).
//!
//! - `Wazuh Worker Provisioning`: `GET {host}/provision_worker/healthcheck`
//!   per host (`[h.strip() for h in url.split(",") if h.strip()]`, 10 s);
//!   the message counts the hosts that answered 200.
//! - `HAProxy Provisioning`: `GET {url}/provision_worker/healthcheck` (60 s).
//! - `Alert Creation Provisioning`: `GET {url}/provision_alert/healthcheck`.
//! - `VirusTotal`: `GET {url}/files/99017f6eebbac24f351415dd410d522d` with
//!   `x-apikey` (no header without a key: `requests` drops a `None` value).
//! - `Talon`: `GET {url}/health` (10 s).

use std::time::Duration;

use async_trait::async_trait;
use http::Method;

use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::http::{PyHttp, PyRequest, PyResponse};
use copilot_upstream::py::PyExc;

use crate::outcome;

/// `DEFAULT_HTTP_TIMEOUT`.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// The worker's and Talon's `timeout=10`.
const SHORT_TIMEOUT: Duration = Duration::from_secs(10);

/// One of the healthcheck verifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Healthcheck {
    /// `verify_wazuh_worker_provisioning_healtcheck`.
    WazuhWorker,
    /// `verify_haproxy_provisioning_healtcheck`.
    HaProxy,
    /// `verify_alert_creation_provisioning_healtcheck`.
    AlertCreation,
    /// `verify_virustotal_healtcheck`.
    VirusTotal,
    /// `verify_talon_credentials`.
    Talon,
}

impl Healthcheck {
    /// Every kind.
    pub const ALL: [Healthcheck; 5] = [
        Healthcheck::WazuhWorker,
        Healthcheck::HaProxy,
        Healthcheck::AlertCreation,
        Healthcheck::VirusTotal,
        Healthcheck::Talon,
    ];

    /// The connector name `get_connector_service` maps to it.
    pub fn connector(self) -> &'static str {
        match self {
            Healthcheck::WazuhWorker => "Wazuh Worker Provisioning",
            Healthcheck::HaProxy => "HAProxy Provisioning",
            Healthcheck::AlertCreation => "Alert Creation Provisioning",
            Healthcheck::VirusTotal => "VirusTotal",
            Healthcheck::Talon => "Talon",
        }
    }

    fn missing(self) -> &'static str {
        match self {
            Healthcheck::WazuhWorker => {
                "No Wazuh Worker Provisioning connector found in the database"
            }
            Healthcheck::HaProxy => "No HAPROXY Provisioning connector found in the database",
            Healthcheck::AlertCreation => {
                "No Alert Creation Provisioning connector found in the database"
            }
            Healthcheck::VirusTotal => "No VirusTotal connector found in the database",
            Healthcheck::Talon => "No Talon connector found in the database",
        }
    }
}

/// A healthcheck verifier.
#[derive(Debug, Clone, Copy)]
pub struct HealthcheckVerifier(pub Healthcheck);

async fn get(timeout: Duration, req: PyRequest) -> Result<PyResponse, PyExc> {
    let http = PyHttp::new(timeout, false).map_err(|e| PyExc::Other("Exception", e.to_string()))?;
    http.send(req).await
}

#[async_trait]
impl ConnectorVerifier for HealthcheckVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        if self.0 == Healthcheck::Talon {
            tracing::info!("Verifying Talon connection");
        }
        let Some(row) = connectors.get(name).await.ok()? else {
            tracing::error!("{}", self.0.missing());
            return None;
        };
        let url = row.connector_url.clone();
        match self.0 {
            Healthcheck::WazuhWorker => Some(worker(&url).await),
            Healthcheck::HaProxy | Healthcheck::AlertCreation | Healthcheck::VirusTotal => {
                let (what, path, ok) = match self.0 {
                    Healthcheck::HaProxy => (
                        "HAPROXY provisioning",
                        "/provision_worker/healthcheck".to_string(),
                        "Wazuh Worker Provisioning healthcheck successful",
                    ),
                    Healthcheck::AlertCreation => (
                        "Alert Creation provisioning",
                        "/provision_alert/healthcheck".to_string(),
                        "Alert Creation Provisioning healthcheck successful",
                    ),
                    _ => (
                        "VirusTotal",
                        "/files/99017f6eebbac24f351415dd410d522d".to_string(),
                        "VirusTotal healthcheck successful",
                    ),
                };
                tracing::info!("Verifying the {what} connection to {url}");
                let mut req = PyRequest::new(Method::GET, format!("{url}{path}"));
                if self.0 == Healthcheck::VirusTotal {
                    if let Some(key) = &row.connector_api_key {
                        req = req.header("x-apikey", key.clone());
                    }
                }
                match get(DEFAULT_TIMEOUT, req).await {
                    Ok(resp) if resp.status() == 200 => outcome(true, ok),
                    Ok(resp) => {
                        tracing::error!("Connection to {url} failed with error: {}", resp.text());
                        outcome(false, format!("Connection to {url} failed"))
                    }
                    Err(e) => {
                        tracing::error!("Connection to {url} failed with error: {}", e.display());
                        outcome(false, format!("Connection to {url} failed with error."))
                    }
                }
            }
            Healthcheck::Talon => {
                tracing::info!("Verifying the Talon connection to {url}");
                let req = PyRequest::new(Method::GET, format!("{url}/health"));
                match get(SHORT_TIMEOUT, req).await {
                    Ok(resp) if resp.status() == 200 => {
                        tracing::info!("Connection to {url} successful");
                        outcome(true, "Talon connection successful")
                    }
                    Ok(resp) => outcome(
                        false,
                        format!("Connection to {url} failed with status {}", resp.status()),
                    ),
                    Err(e) => outcome(
                        false,
                        format!("Connection to {url} failed with error: {}", e.display()),
                    ),
                }
            }
        }
    }
}

/// `verify_wazuh_worker_provisioning_healtcheck`: every host of the URL.
async fn worker(connector_url: &str) -> copilot_connectors::schema::VerifyConnectorResponse {
    use copilot_connectors::schema::VerifyConnectorResponse;
    tracing::info!("Verifying the wazuh-worker provisioning connection to {connector_url}");
    let hosts: Vec<String> = connector_url
        .split(',')
        .map(|h| copilot_web::form::py_strip(h).to_string())
        .filter(|h| !h.is_empty())
        .collect();
    if hosts.is_empty() {
        return VerifyConnectorResponse {
            connection_successful: false,
            message: "No valid hosts found in connector_url".into(),
        };
    }
    let (mut ok, mut failed) = (0usize, 0usize);
    for host in &hosts {
        tracing::info!("Testing connection to host: {host}");
        let req = PyRequest::new(Method::GET, format!("{host}/provision_worker/healthcheck"));
        match get(SHORT_TIMEOUT, req).await {
            Ok(resp) if resp.status() == 200 => {
                ok += 1;
                tracing::info!("Connection to {host} successful");
            }
            Ok(resp) => {
                failed += 1;
                tracing::error!("Connection to {host} failed with status {}", resp.status());
            }
            Err(e) => {
                failed += 1;
                tracing::error!("Connection to {host} failed with error: {}", e.display());
            }
        }
    }
    let message = if ok > 0 {
        if failed == 0 {
            format!("All {ok} hosts connected successfully")
        } else {
            format!("{ok} of {} hosts connected successfully", hosts.len())
        }
    } else {
        format!("All {} hosts failed to connect", hosts.len())
    };
    VerifyConnectorResponse {
        connection_successful: ok > 0,
        message,
    }
}
