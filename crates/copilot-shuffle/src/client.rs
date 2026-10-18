//! `app/connectors/shuffle/utils/universal.py`: the connector row read
//! through the cache, then `requests` with `Authorization: Bearer {key}`,
//! `verify=False` and `timeout=DEFAULT_HTTP_TIMEOUT` (60 s) — and what each
//! helper gives back or raises.
//!
//! - `send_get_request`: `None` without a row; the answer's JSON as `data`
//!   whatever the status; any failure (the request, the JSON) is the 500
//!   `Failed to send GET request to {endpoint} with error: {e}`.
//! - `send_post_request` (`json=`): `None` without a row; a 204 is
//!   `data: None`; otherwise the JSON, with `success` false for a status of
//!   400 or more or a body that says `success: false` (its `reason` in the
//!   message). A JSON that does not parse is the 500 `Failed to send POST
//!   request to {endpoint} with error: {e}`; a request that fails before
//!   there is a response is the helper's own `UnboundLocalError` (its
//!   `except` logs `response`, which was never assigned).

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::{ConnectorCache, ConnectorRow};
use copilot_upstream::http::{PyHttp, PyRequest, PyResponse};
use copilot_upstream::py::PyExc;
use http::Method;

/// The connector's name.
pub const CONNECTOR: &str = "Shuffle";
/// `DEFAULT_HTTP_TIMEOUT`.
pub const TIMEOUT: Duration = Duration::from_secs(60);
/// What `send_post_request`'s `except` raises when the request failed.
pub const UNBOUND: &str =
    "cannot access local variable 'response' where it is not associated with a value";

/// The Shuffle client: `requests` and the connector cache.
#[derive(Debug, Clone)]
pub struct ShuffleClient {
    http: PyHttp,
    /// The connector rows.
    pub connectors: ConnectorCache,
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

impl ShuffleClient {
    /// A client over the connector cache.
    pub fn new(connectors: ConnectorCache) -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: PyHttp::new(TIMEOUT, false)?,
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

    fn request(row: &ConnectorRow, method: Method, endpoint: &str) -> PyRequest {
        let key = row.connector_api_key.as_deref().unwrap_or("None");
        PyRequest::new(method, format!("{}{endpoint}", row.connector_url))
            .header("Authorization", format!("Bearer {key}"))
            .header("Connection", "keep-alive")
    }

    /// One request as the helpers send it (`requests`' `Connection:
    /// keep-alive` added: hyper does not write it).
    pub async fn send(&self, req: PyRequest) -> Result<PyResponse, PyExc> {
        self.http.send(req.header("Connection", "keep-alive")).await
    }

    /// `send_get_request(endpoint, params, connector_name)`.
    pub async fn get(
        &self,
        endpoint: &str,
        params: Vec<(String, String)>,
        connector: &str,
    ) -> Result<Option<PyValue>, PyExc> {
        tracing::info!("Sending GET request to {endpoint}");
        let Some(row) = self.row(connector).await? else {
            tracing::error!("No Shuffle connector found in the database");
            return Ok(None);
        };
        let failed = |e: PyExc| {
            let text = format!(
                "Failed to send GET request to {endpoint} with error: {}",
                e.display()
            );
            tracing::error!("{text}");
            PyExc::http(500, text)
        };
        let req = Self::request(&row, Method::GET, endpoint).params(params);
        let resp = self.http.send(req).await.map_err(failed)?;
        let data = resp.json().map_err(failed)?;
        Ok(Some(dict(vec![
            ("data", data),
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("Successfully retrieved data".into()),
            ),
        ])))
    }

    /// `send_post_request(endpoint, data, connector_name)`.
    pub async fn post(
        &self,
        endpoint: &str,
        data: PyValue,
        connector: &str,
    ) -> Result<Option<PyValue>, PyExc> {
        tracing::info!("Sending POST request to {endpoint}");
        let Some(row) = self.row(connector).await? else {
            tracing::error!("No Shuffle connector found in the database");
            return Ok(None);
        };
        let req = Self::request(&row, Method::POST, endpoint).json(Some(data));
        let resp = match self.http.send(req).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    "Failed to send POST request to {endpoint} with error: {}",
                    e.display()
                );
                return Err(PyExc::Other("UnboundLocalError", UNBOUND.into()));
            }
        };
        if resp.status() == 204 {
            return Ok(Some(dict(vec![
                ("data", PyValue::None),
                ("success", PyValue::Bool(true)),
                (
                    "message",
                    PyValue::Str("Successfully completed request with no content".into()),
                ),
            ])));
        }
        let body = resp.json().map_err(|e| {
            let text = format!(
                "Failed to send POST request to {endpoint} with error: {}",
                e.display()
            );
            tracing::error!("{text}");
            PyExc::http(500, text)
        })?;
        let http_ok = resp.status() < 400;
        let body_ok = !matches!(body.get("success"), Some(PyValue::Bool(false)));
        let success = http_ok && body_ok;
        let message = if success {
            "Successfully retrieved data".to_string()
        } else {
            match body.get("reason").filter(|r| r.truthy()) {
                Some(reason) => format!("Shuffle returned success=false: {}", reason.py_str()),
                None => "Failed to retrieve data".to_string(),
            }
        };
        Ok(Some(dict(vec![
            ("data", body),
            ("success", PyValue::Bool(success)),
            ("message", PyValue::Str(message)),
        ])))
    }
}
