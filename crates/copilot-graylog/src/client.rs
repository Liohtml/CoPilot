//! The Graylog client — port of `app/connectors/graylog/utils/universal.py`
//! (and `routing.py`'s connector names).
//!
//! Every helper reads the connector row (`Graylog`, or `Graylog-Network`
//! for the network instance) through the connector cache, sends
//! `{connector_url}{endpoint}` with HTTP Basic and `X-Requested-By: CoPilot`
//! (Graylog's CSRF guard), a 60 s timeout and **no certificate
//! verification** (`verify=False`, as in Python: Graylog in a SOCFortress
//! stack serves a self-signed certificate), and answers the way the Python
//! helper did — including what it raised or swallowed:
//!
//! | Helper | Not configured | 404 / error status | Transport or JSON failure |
//! |---|---|---|---|
//! | [`GraylogClient::get`] | 500 `Connector Graylog not found` | 404 with Graylog's `message` (other statuses are *data*) | 500 `Failed to send GET request to … with error: …` |
//! | [`GraylogClient::post`] | the same 500 | 500 with Graylog's `message` or the body text | 500 `Failed to send POST request to …` |
//! | [`GraylogClient::delete`] | the same 500 | 404 with Graylog's `message` | `success: false`, not raised |
//! | [`GraylogClient::put`] | `None` (the caller fails on it) | 404 with Graylog's `message` | `success: false`, not raised |
//!
//! ## Graylog 6.x and 7.x
//!
//! Graylog 7.0 wraps the body of exactly four entity-creation POSTs in a
//! `CreateEntityRequest` (`{"entity": {…}}`) and rejects unknown properties,
//! so neither version accepts the other's shape. [`GraylogClient::create_entity`]
//! takes an [`EntityKind`] — only those four exist — probes `GET /api/system`
//! for the major version (cached per connector for five minutes; any failure
//! counts as 6 and is cached too, so 6.x deployments are unchanged) and wraps
//! only for 7+. Everything else (index sets, content-pack upload, pipelines,
//! `/events/search`, every PUT) is flat and goes through [`GraylogClient::post`].
//! 7.0 also replaced `/api/system/urlwhitelist` with `/api/system/urlallowlist`
//! ([`GraylogClient::url_allowlist`] tries the 7.x path first).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::{ConnectorCache, ConnectorRow};
use copilot_upstream::http::{PyHttp, PyRequest, PyResponse};
use copilot_upstream::py::{PyExc, PyResult, getitem};
use http::Method;

/// The default connector (`GraylogContext.WAZUH`).
pub const DEFAULT_CONNECTOR: &str = "Graylog";
/// The network-logs instance (`GraylogContext.NETWORK`).
pub const NETWORK_CONNECTOR: &str = "Graylog-Network";
/// `GRAYLOG_REQUEST_TIMEOUT`.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// `_GRAYLOG_VERSION_TTL_SECONDS`.
pub const VERSION_TTL: Duration = Duration::from_secs(300);
/// The major version assumed when the probe fails.
pub const DEFAULT_MAJOR: u64 = 6;

/// `get_graylog_connector_name(use_case=…)`: the connector for a use case
/// (`sonicwall`, `syslog`, `firewall`, `network` → the network instance).
pub fn connector_for_use_case(use_case: &str) -> &'static str {
    match use_case.to_lowercase().as_str() {
        "sonicwall" | "syslog" | "firewall" | "network" => NETWORK_CONNECTOR,
        _ => DEFAULT_CONNECTOR,
    }
}

/// What a helper returned (`{"data", "success", "message"}`).
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    /// `data` (`None` when there was none).
    pub data: PyValue,
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
}

impl Reply {
    fn ok(data: PyValue, message: &str) -> Self {
        Self {
            data,
            success: true,
            message: message.into(),
        }
    }

    fn failed(message: String) -> Self {
        Self {
            data: PyValue::None,
            success: false,
            message,
        }
    }
}

/// The four Graylog endpoints whose create body 7.0 wraps in a
/// `CreateEntityRequest`. Nothing else is wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityKind {
    /// `POST /api/streams`.
    Stream,
    /// `POST /api/events/definitions`.
    EventDefinition,
    /// `POST /api/events/notifications`.
    EventNotification,
    /// `POST /api/system/content_packs/{id}/{revision}/installations`.
    ContentPackInstallation {
        /// Content pack id.
        id: String,
        /// Revision.
        revision: i64,
    },
}

impl EntityKind {
    /// The endpoint.
    pub fn endpoint(&self) -> String {
        match self {
            EntityKind::Stream => "/api/streams".into(),
            EntityKind::EventDefinition => "/api/events/definitions".into(),
            EntityKind::EventNotification => "/api/events/notifications".into(),
            EntityKind::ContentPackInstallation { id, revision } => {
                format!("/api/system/content_packs/{id}/{revision}/installations")
            }
        }
    }
}

/// `send_post_request_create_entity`'s body: `{"entity": …}` (and
/// `share_request` when given) for Graylog 7+, the flat entity before.
pub fn create_entity_body(major: u64, entity: PyValue, share_request: Option<PyValue>) -> PyValue {
    if major >= 7 {
        let mut body = vec![("entity".to_string(), entity)];
        if let Some(share) = share_request {
            body.push(("share_request".to_string(), share));
        }
        PyValue::Dict(body)
    } else {
        entity
    }
}

/// `int(str(version).split("+")[0].split(".")[0].strip())`.
pub fn major_of(version: &PyValue) -> Option<u64> {
    let text = version.py_str();
    let head = text.split('+').next().unwrap_or_default();
    let major = head.split('.').next().unwrap_or_default();
    copilot_core::config::python_int(major).and_then(|n| u64::try_from(n).ok())
}

/// The Graylog connector: credentials from the cache, a `requests`-like
/// client, the version cache.
#[derive(Debug, Clone)]
pub struct GraylogClient {
    connectors: ConnectorCache,
    http: PyHttp,
    versions: Arc<Mutex<HashMap<String, (u64, Instant)>>>,
}

fn db_error(e: copilot_db::DbError) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

impl GraylogClient {
    /// Build the client (certificates are not verified, as in Python).
    pub fn new(connectors: ConnectorCache) -> Result<Self, reqwest::Error> {
        Ok(Self {
            connectors,
            http: PyHttp::new(REQUEST_TIMEOUT, false)?,
            versions: Arc::default(),
        })
    }

    async fn row(&self, connector: &str) -> PyResult<Option<ConnectorRow>> {
        self.connectors.get(connector).await.map_err(db_error)
    }

    fn request(row: &ConnectorRow, method: Method, endpoint: &str) -> PyRequest {
        PyRequest::new(method, format!("{}{endpoint}", row.connector_url))
            .header("X-Requested-By", "CoPilot")
            .basic(
                row.connector_username.clone(),
                row.connector_password.clone(),
            )
    }

    fn not_found(connector: &str) -> PyExc {
        PyExc::http(500, format!("Connector {connector} not found"))
    }

    /// `send_get_request(endpoint, params)` on the default connector.
    pub async fn get(&self, endpoint: &str, params: &[(&str, String)]) -> PyResult<Reply> {
        self.get_on(DEFAULT_CONNECTOR, endpoint, params).await
    }

    /// `send_get_request(endpoint, params, connector_name)`.
    pub async fn get_on(
        &self,
        connector: &str,
        endpoint: &str,
        params: &[(&str, String)],
    ) -> PyResult<Reply> {
        let row = self
            .row(connector)
            .await?
            .ok_or_else(|| Self::not_found(connector))?;
        let req = Self::request(&row, Method::GET, endpoint).params(
            params
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        );
        let fail = |e: PyExc| {
            PyExc::http(
                500,
                format!(
                    "Failed to send GET request to {endpoint} with error: {}",
                    e.text()
                ),
            )
        };
        let resp = self.http.send(req).await.map_err(fail)?;
        if resp.status == 404 {
            let body = resp.json().map_err(fail)?;
            let message = getitem(&body, "message").map_err(fail)?.py_str();
            return Err(PyExc::http(
                404,
                format!("Failed to send GET request to {endpoint} with error: {message}"),
            ));
        }
        let data = resp.json().map_err(fail)?;
        Ok(Reply::ok(data, "Successfully retrieved data"))
    }

    /// `send_post_request(endpoint, data)` on the default connector.
    pub async fn post(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Reply> {
        self.post_on(DEFAULT_CONNECTOR, endpoint, data).await
    }

    /// `send_post_request(endpoint, data, connector_name)`.
    pub async fn post_on(
        &self,
        connector: &str,
        endpoint: &str,
        data: Option<PyValue>,
    ) -> PyResult<Reply> {
        let row = self
            .row(connector)
            .await?
            .ok_or_else(|| Self::not_found(connector))?;
        let req = Self::request(&row, Method::POST, endpoint).json(data);
        let fail = |e: PyExc| {
            PyExc::http(
                500,
                format!(
                    "Failed to send POST request to {endpoint} with error: {}",
                    e.text()
                ),
            )
        };
        let resp = self.http.send(req).await.map_err(fail)?;
        match resp.status {
            200 => Ok(Reply::ok(
                resp.json().map_err(fail)?,
                "Successfully completed request",
            )),
            204 => Ok(Reply::ok(
                PyValue::None,
                "Successfully completed request with no content",
            )),
            201 | 202 => Ok(match resp.json() {
                Ok(v) => Reply::ok(v, "Successfully created data"),
                Err(_) => Reply::ok(
                    PyValue::None,
                    "Successfully completed request, but no data returned",
                ),
            }),
            status => {
                let reason = match resp.json() {
                    Ok(body) => {
                        let message = copilot_upstream::py::get(&body, "message").map_err(fail)?;
                        match message {
                            Some(m) if m.truthy() => m.py_str(),
                            _ => resp.text(),
                        }
                    }
                    Err(_) => {
                        let text = resp.text();
                        if text.is_empty() {
                            format!("HTTP {status}")
                        } else {
                            text
                        }
                    }
                };
                Err(PyExc::http(
                    500,
                    format!("Failed to send POST request to {endpoint} with error: {reason}"),
                ))
            }
        }
    }

    /// `send_delete_request(endpoint, params)` on the default connector.
    pub async fn delete(&self, endpoint: &str, params: &[(&str, String)]) -> PyResult<Reply> {
        self.delete_on(DEFAULT_CONNECTOR, endpoint, params).await
    }

    /// `send_delete_request(endpoint, params, connector_name)`.
    pub async fn delete_on(
        &self,
        connector: &str,
        endpoint: &str,
        params: &[(&str, String)],
    ) -> PyResult<Reply> {
        let row = self
            .row(connector)
            .await?
            .ok_or_else(|| Self::not_found(connector))?;
        let req = Self::request(&row, Method::DELETE, endpoint).params(
            params
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        );
        let swallowed = |e: PyExc| {
            Reply::failed(format!(
                "Failed to send DELETE request to {endpoint} with error: {}",
                e.text()
            ))
        };
        let resp: PyResponse = match self.http.send(req).await {
            Ok(r) => r,
            Err(e) => return Ok(swallowed(e)),
        };
        if resp.status != 200 && resp.status != 204 {
            let message = match resp
                .json()
                .and_then(|body| getitem(&body, "message").map(PyValue::py_str))
            {
                Ok(m) => m,
                Err(e) => return Ok(swallowed(e)),
            };
            return Err(PyExc::http(
                404,
                format!("Failed to send DELETE request to {endpoint} with error: {message}"),
            ));
        }
        Ok(Reply::ok(
            PyValue::Str("No content returned".into()),
            "Successfully deleted data",
        ))
    }

    /// `send_put_request(endpoint, data)` on the default connector; `None`
    /// when the connector is not configured (Python returns `None`).
    pub async fn put(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Option<Reply>> {
        self.put_on(DEFAULT_CONNECTOR, endpoint, data).await
    }

    /// `send_put_request(endpoint, data, connector_name)`.
    pub async fn put_on(
        &self,
        connector: &str,
        endpoint: &str,
        data: Option<PyValue>,
    ) -> PyResult<Option<Reply>> {
        let Some(row) = self.row(connector).await? else {
            return Ok(None);
        };
        let req = Self::request(&row, Method::PUT, endpoint).json(data);
        let swallowed = |e: PyExc| {
            Reply::failed(format!(
                "Failed to send PUT request to {endpoint} with error: {}",
                e.text()
            ))
        };
        let resp = match self.http.send(req).await {
            Ok(r) => r,
            Err(e) => return Ok(Some(swallowed(e))),
        };
        if resp.status != 200 && resp.status != 204 {
            let message = match resp.json().and_then(|body| {
                copilot_upstream::py::get(&body, "message")
                    .map(|m| m.map_or_else(String::new, PyValue::py_str))
            }) {
                Ok(m) => m,
                Err(e) => return Ok(Some(swallowed(e))),
            };
            return Err(PyExc::http(
                404,
                format!("Failed to send PUT request to {endpoint} with error: {message}"),
            ));
        }
        if resp.status == 204 {
            return Ok(Some(Reply::ok(
                PyValue::None,
                "Successfully sent PUT request, no content returned",
            )));
        }
        match resp.json() {
            Ok(v) => Ok(Some(Reply::ok(v, "Successfully retrieved data"))),
            Err(e) => Ok(Some(swallowed(e))),
        }
    }

    /// `get_graylog_major_version(connector_name)`.
    pub async fn major_version(&self, connector: &str) -> u64 {
        {
            let cache = self.versions.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((major, at)) = cache.get(connector) {
                if at.elapsed() < VERSION_TTL {
                    return *major;
                }
            }
        }
        let major = match self.get_on(connector, "/api/system", &[]).await {
            Ok(reply) => getitem(&reply.data, "version")
                .ok()
                .and_then(major_of)
                .unwrap_or(DEFAULT_MAJOR),
            Err(e) => {
                tracing::warn!(
                    connector,
                    err = %e.display(),
                    "could not determine the Graylog version, assuming {DEFAULT_MAJOR}"
                );
                DEFAULT_MAJOR
            }
        };
        let mut cache = self.versions.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(connector.to_string(), (major, Instant::now()));
        major
    }

    /// `send_post_request_create_entity(endpoint, entity, share_request)` on
    /// `connector`: wrapped for Graylog 7+, flat before.
    pub async fn create_entity(
        &self,
        connector: &str,
        kind: &EntityKind,
        entity: PyValue,
        share_request: Option<PyValue>,
    ) -> PyResult<Reply> {
        let major = self.major_version(connector).await;
        let body = create_entity_body(major, entity, share_request);
        self.post_on(connector, &kind.endpoint(), Some(body)).await
    }

    /// `GET /api/system/urlallowlist` (7.x), else `/api/system/urlwhitelist`
    /// (6.x) when the first raised.
    pub async fn url_allowlist(&self) -> PyResult<Reply> {
        match self.get("/api/system/urlallowlist", &[]).await {
            Err(e) if e.is_http() => self.get("/api/system/urlwhitelist", &[]).await,
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn exactly_four_endpoints_are_wrapped() {
        let kinds = [
            EntityKind::Stream,
            EntityKind::EventDefinition,
            EntityKind::EventNotification,
            EntityKind::ContentPackInstallation {
                id: "cp".into(),
                revision: 3,
            },
        ];
        let endpoints: Vec<String> = kinds.iter().map(EntityKind::endpoint).collect();
        assert_eq!(
            endpoints,
            [
                "/api/streams",
                "/api/events/definitions",
                "/api/events/notifications",
                "/api/system/content_packs/cp/3/installations",
            ]
        );
        let entity = loads(r#"{"title": "x"}"#).unwrap();
        assert_eq!(
            create_entity_body(6, entity.clone(), None).py_repr(),
            "{'title': 'x'}"
        );
        assert_eq!(
            create_entity_body(7, entity.clone(), None).py_repr(),
            "{'entity': {'title': 'x'}}"
        );
        assert_eq!(
            create_entity_body(8, entity, Some(PyValue::None)).py_repr(),
            "{'entity': {'title': 'x'}, 'share_request': None}"
        );
    }

    #[test]
    fn version_parsing_follows_int() {
        for (v, want) in [
            (r#""7.0.1+abc""#, Some(7)),
            (r#""6.1.4""#, Some(6)),
            (r#"" 7 .1""#, Some(7)),
            ("7", Some(7)),
            (r#""v7.0""#, None),
            ("null", None),
        ] {
            assert_eq!(major_of(&loads(v).unwrap()), want, "{v}");
        }
        assert_eq!(connector_for_use_case("SonicWall"), NETWORK_CONNECTOR);
        assert_eq!(connector_for_use_case("wazuh"), DEFAULT_CONNECTOR);
    }
}
