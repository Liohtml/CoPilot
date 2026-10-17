//! `send_post_request` / `send_get_request` of `app/middleware/license.py`:
//! `requests.post(f"https://license.socfortress.co/{endpoint}",
//! headers=HEADERS, json=data, timeout=10)` (and `requests.get` without a
//! body) on a worker thread.
//!
//! `HEADERS` is `{"x-api-key": f"{os.getenv('COPILOT_API_KEY')}",
//! "Content-Type": "application/json", "module-version": "1.0"}` — the text
//! `None` when the variable is unset — merged after `requests`' session
//! headers, so the wire order is requests' ([`PyHttp::with_exact_headers`]).

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_core::config::Secret;
use copilot_upstream::http::{PyHttp, PyRequest};
use copilot_upstream::py::{PyExc, PyResult, get};
use http::Method;

/// The licence server Python calls (a module constant there).
pub const DEFAULT_LICENSE_URL: &str = "https://license.socfortress.co/";

/// `timeout=10`.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The `requests` client towards the licence server: 10 s, TLS verified,
/// requests' header order.
pub fn license_http() -> Result<PyHttp, reqwest::Error> {
    PyHttp::new(TIMEOUT, true)?.with_exact_headers(TIMEOUT, true)
}

/// `COPILOT_LICENSE_URL` (parity harness only), else Python's constant.
pub fn license_url_from_env() -> String {
    std::env::var("COPILOT_LICENSE_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_LICENSE_URL.to_string())
}

/// The licence server as `license.py` calls it.
#[derive(Clone)]
pub struct LicenseClient {
    /// `requests`.
    pub http: PyHttp,
    /// `https://license.socfortress.co/`, before the endpoint.
    pub base: String,
    /// `COPILOT_API_KEY` (`None` = unset, sent as the text `None`).
    pub api_key: Option<Secret>,
}

impl std::fmt::Debug for LicenseClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicenseClient")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

impl LicenseClient {
    /// A client for `base` (`COPILOT_LICENSE_URL` or the constant).
    pub fn new(base: String, api_key: Option<Secret>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: license_http()?,
            base,
            api_key,
        })
    }

    fn request(&self, method: Method, endpoint: &str) -> PyRequest {
        let api_key = self
            .api_key
            .as_ref()
            .map_or_else(|| "None".to_string(), |k| k.expose().to_string());
        PyRequest::new(method, format!("{}{endpoint}", self.base))
            .header("x-api-key", api_key)
            .header("Content-Type", "application/json")
            .header("module-version", "1.0")
    }

    /// `send_post_request(endpoint, data)`.
    pub async fn post(&self, endpoint: &str, data: PyValue) -> PyResult<PyValue> {
        tracing::info!("Sending POST request to {endpoint}");
        let attempt = async {
            let response = self
                .http
                .send(self.request(Method::POST, endpoint).json(Some(data)))
                .await?;
            if response.status() == 204 {
                return Ok(dict(vec![
                    ("success", PyValue::Bool(true)),
                    ("message", s("No content")),
                ]));
            }
            // `response.json()`, and on a `ValueError` the text instead.
            let payload = match response.json() {
                Ok(v) => v,
                Err(_) => {
                    let text = response.text();
                    dict(vec![(
                        "message",
                        PyValue::Str(if text.is_empty() {
                            "Unknown license server response".into()
                        } else {
                            text
                        }),
                    )])
                }
            };
            if response.status() >= 500 {
                let pick = |k: &str| -> PyResult<Option<PyValue>> {
                    Ok(get(&payload, k)?.filter(|v| v.truthy()).cloned())
                };
                let message = match pick("message")? {
                    Some(m) => m.py_str(),
                    None => match pick("detail")? {
                        Some(d) => d.py_str(),
                        None => "Internal server error".into(),
                    },
                };
                tracing::error!(
                    "License server error ({}) on {endpoint}: {message}",
                    response.status()
                );
                return Err(PyExc::http(502, format!("License server error: {message}")));
            }
            Ok(payload)
        };
        match attempt.await {
            Ok(v) => Ok(v),
            Err(e @ PyExc::Http(..)) => Err(e),
            Err(e) => {
                tracing::error!(
                    "Failed to send POST request to {endpoint} with error: {}",
                    e.display()
                );
                Err(PyExc::http(
                    500,
                    format!(
                        "Failed to send POST request to {endpoint} with error: {}",
                        e.display()
                    ),
                ))
            }
        }
    }

    /// `send_get_request(endpoint)`: no status check, any failure (the
    /// JSON included) the 500.
    pub async fn get(&self, endpoint: &str) -> PyResult<PyValue> {
        tracing::info!("Sending GET request to {endpoint}");
        let attempt = async {
            let response = self.http.send(self.request(Method::GET, endpoint)).await?;
            if response.status() == 204 {
                return Ok(dict(vec![
                    ("success", PyValue::Bool(true)),
                    ("message", s("No content")),
                ]));
            }
            response.json()
        };
        attempt.await.map_err(|e| {
            tracing::error!(
                "Failed to send GET request to {endpoint} with error: {}",
                e.display()
            );
            PyExc::http(
                500,
                format!(
                    "Failed to send GET request to {endpoint} with error: {}",
                    e.display()
                ),
            )
        })
    }
}
