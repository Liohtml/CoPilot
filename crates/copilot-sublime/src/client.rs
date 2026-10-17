//! `app/connectors/sublime/utils/universal.py`: the `Sublime` connector row
//! read through the cache, then `requests.get` with `Authorization: Bearer
//! {key}` and `Content-Type: application/json`, `verify=False` and
//! `timeout=DEFAULT_HTTP_TIMEOUT` (60 s), header by header as `requests`
//! writes them.
//!
//! `send_get_request` answers `None` without a row; otherwise
//! `{"data": response.json(), "success": True, "message": …}` whatever the
//! status, or — the request or the JSON having failed —
//! `{"success": False, "message": "Failed to send GET request to {endpoint}
//! with error: {e}"}`.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::{ConnectorCache, ConnectorRow};
use copilot_upstream::http::{PyHttp, PyRequest, PyResponse};
use copilot_upstream::py::PyExc;
use http::Method;

/// The connector's name.
pub const CONNECTOR: &str = "Sublime";
/// `DEFAULT_HTTP_TIMEOUT`.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// Sublime's API: `requests` and the connector cache.
#[derive(Debug, Clone)]
pub struct SublimeClient {
    http: PyHttp,
    /// The connector rows.
    pub connectors: ConnectorCache,
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

impl SublimeClient {
    /// A client over the connector cache.
    pub fn new(connectors: ConnectorCache) -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: PyHttp::new(TIMEOUT, false)?.with_exact_headers(TIMEOUT, false)?,
            connectors,
        })
    }

    /// `get_connector_info_from_db(name, session)`.
    pub async fn row(&self, name: &str) -> Result<Option<ConnectorRow>, PyExc> {
        self.connectors
            .get(name)
            .await
            .map_err(|e| PyExc::Other("OperationalError", e.to_string()))
    }

    /// The helpers' request: `f"{connector_url}{endpoint}"` with their two
    /// headers (`Bearer None` for a row without a key, as the f-string
    /// writes it).
    pub fn request(row: &ConnectorRow, endpoint: &str) -> PyRequest {
        let key = row.connector_api_key.as_deref().unwrap_or("None");
        PyRequest::new(Method::GET, format!("{}{endpoint}", row.connector_url))
            .header("Authorization", format!("Bearer {key}"))
            .header("Content-Type", "application/json")
    }

    /// One request as `requests.get` sends it.
    pub async fn send(&self, req: PyRequest) -> Result<PyResponse, PyExc> {
        self.http.send(req).await
    }

    /// `send_get_request(endpoint)` (no `params`, the `Sublime` row).
    pub async fn get(&self, endpoint: &str) -> Result<Option<PyValue>, PyExc> {
        tracing::info!("Sending GET request to {endpoint}");
        let Some(row) = self.row(CONNECTOR).await? else {
            tracing::error!("No Sublime connector found in the database");
            return Ok(None);
        };
        let answer = match self.send(Self::request(&row, endpoint)).await {
            Ok(resp) => resp.json(),
            Err(e) => Err(e),
        };
        Ok(Some(match answer {
            Ok(data) => dict(vec![
                ("data", data),
                ("success", PyValue::Bool(true)),
                (
                    "message",
                    PyValue::Str("Successfully retrieved data".into()),
                ),
            ]),
            Err(e) => {
                let text = format!(
                    "Failed to send GET request to {endpoint} with error: {}",
                    e.display()
                );
                tracing::error!("{text}");
                dict(vec![
                    ("success", PyValue::Bool(false)),
                    ("message", PyValue::Str(text)),
                ])
            }
        }))
    }
}
