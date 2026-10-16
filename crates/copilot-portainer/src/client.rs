//! The Portainer client — port of `app/connectors/portainer/utils/universal.py`.
//!
//! Every helper reads the `Portainer` connector row (none: the helper
//! returns `None`, which its caller then subscripts — a bare 500), fetches a
//! fresh JWT (`POST urljoin(connector_url, "/api/auth")` with the user name
//! and password as JSON; `raise_for_status`, then `["jwt"]`), and sends
//! `{connector_url}{endpoint}` with `Authorization: Bearer <jwt>` and
//! `Content-Type: application/json`, a 60 s timeout and **no certificate
//! verification** (Python's `verify=False`: Portainer in a SOCFortress stack
//! serves a self-signed certificate). What each helper makes of the answer,
//! and of a failure, is Python's:
//!
//! | Helper | Answer | Transport or JSON failure |
//! |---|---|---|
//! | [`PortainerClient::get`] | `{"data": json, "success": true}` whatever the status | 500 `Failed to send GET request to … with error: …` |
//! | [`PortainerClient::post`] | 204: `data: None`; else the JSON, `success` = status < 400 | a JSON failure: 500 `Failed to send POST request …`; a transport failure: the `UnboundLocalError` its `except` clause raises (a bare 500) |
//! | [`PortainerClient::delete`] | 204 or a blank body: `data: None`; JSON: `success: true`; else `success` = status < 400 | 500 `Failed to send DELETE request …` |
//!
//! A failed authentication is 500 `Failed to authenticate with Portainer:
//! …` (an `HTTPError` such as `422 Client Error: Unprocessable Entity for
//! url: …`, a transport error, a body that is not JSON); an answer without
//! `jwt` is a `KeyError` nobody catches.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::{ConnectorCache, ConnectorRow};
use copilot_upstream::http::{PyHttp, PyRequest};
use copilot_upstream::py::{PyExc, PyResult, getitem};
use http::Method;

/// The connector's name.
pub const CONNECTOR: &str = "Portainer";
/// `DEFAULT_HTTP_TIMEOUT` (`app/blocking.py`).
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// What a helper returned (`{"data", "success", "message"}`).
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    /// `data`.
    pub data: PyValue,
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
}

impl Reply {
    fn new(data: PyValue, success: bool, message: impl Into<String>) -> Self {
        Self {
            data,
            success,
            message: message.into(),
        }
    }

    /// The dict Python returned.
    pub fn to_py(&self) -> PyValue {
        PyValue::Dict(vec![
            ("data".into(), self.data.clone()),
            ("success".into(), PyValue::Bool(self.success)),
            ("message".into(), PyValue::Str(self.message.clone())),
        ])
    }
}

/// The Portainer client.
#[derive(Debug, Clone)]
pub struct PortainerClient {
    connectors: ConnectorCache,
    http: PyHttp,
}

fn db_error(e: copilot_db::DbError) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

/// `uses_relative` / `uses_netloc` of `urllib.parse`.
const USES_RELATIVE: [&str; 20] = [
    "", "ftp", "http", "gopher", "nntp", "imap", "wais", "file", "https", "shttp", "mms",
    "prospero", "rtsp", "rtsps", "rtspu", "sftp", "svn", "svn+ssh", "ws", "wss",
];
const USES_NETLOC: [&str; 26] = [
    "", "ftp", "http", "gopher", "nntp", "telnet", "imap", "wais", "file", "mms", "https", "shttp",
    "snews", "prospero", "rtsp", "rtsps", "rtspu", "rsync", "svn", "svn+ssh", "sftp", "nfs", "git",
    "git+ssh", "ws", "wss",
];

/// `urllib.parse.urljoin(base, path)` for an absolute `path` without query
/// or fragment (`"/api/auth"`).
pub fn urljoin_absolute(base: &str, path: &str) -> String {
    if base.is_empty() {
        return path.to_string();
    }
    let base: String = base
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = base.as_str();
    let mut scheme = String::new();
    if let Some(i) = rest.find(':') {
        let head = &rest[..i];
        if i > 0
            && head.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && head
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = head.to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
    }
    if !USES_RELATIVE.contains(&scheme.as_str()) {
        return path.to_string();
    }
    let netloc = match rest.strip_prefix("//") {
        Some(after) if USES_NETLOC.contains(&scheme.as_str()) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            &after[..end]
        }
        _ => "",
    };
    // `urlunsplit`.
    let mut url = path.to_string();
    if !netloc.is_empty() || (!scheme.is_empty() && USES_NETLOC.contains(&scheme.as_str())) {
        url = format!("//{netloc}{url}");
    }
    if !scheme.is_empty() {
        url = format!("{scheme}:{url}");
    }
    url
}

impl PortainerClient {
    /// A client reading the connector row through `connectors`.
    pub fn new(connectors: ConnectorCache) -> Result<Self, reqwest::Error> {
        Ok(Self {
            connectors,
            http: PyHttp::new(TIMEOUT, false)?,
        })
    }

    /// `get_connector_info_from_db("Portainer")`.
    pub async fn row(&self) -> PyResult<Option<ConnectorRow>> {
        self.connectors.get(CONNECTOR).await.map_err(db_error)
    }

    /// `get_portainer_jwt()`.
    pub async fn jwt(&self) -> PyResult<String> {
        let row = self
            .row()
            .await?
            .ok_or_else(|| PyExc::TypeError("'NoneType' object is not subscriptable".into()))?;
        let auth = urljoin_absolute(&row.connector_url, "/api/auth");
        let str_or_none = |v: &Option<String>| v.clone().map_or(PyValue::None, PyValue::Str);
        let payload = PyValue::Dict(vec![
            ("username".into(), str_or_none(&row.connector_username)),
            ("password".into(), str_or_none(&row.connector_password)),
        ]);
        let failed = |e: PyExc| {
            PyExc::http(
                500,
                format!("Failed to authenticate with Portainer: {}", e.text()),
            )
        };
        let resp = self
            .http
            .send(PyRequest::new(Method::POST, auth).json(Some(payload)))
            .await
            .map_err(failed)?;
        resp.raise_for_status().map_err(failed)?;
        let body = resp.json().map_err(failed)?;
        Ok(getitem(&body, "jwt")?.py_str())
    }

    async fn send(
        &self,
        method: Method,
        endpoint: &str,
        params: Vec<(String, String)>,
        json: Option<PyValue>,
    ) -> PyResult<Option<(ConnectorRow, PyResult<copilot_upstream::http::PyResponse>)>> {
        let Some(row) = self.row().await? else {
            return Ok(None);
        };
        let jwt = self.jwt().await?;
        let req = PyRequest::new(method, format!("{}{endpoint}", row.connector_url))
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .params(params)
            .json(json);
        let resp = self.http.send(req).await;
        Ok(Some((row, resp)))
    }

    /// `send_get_request(endpoint, params)`.
    pub async fn get(
        &self,
        endpoint: &str,
        params: Vec<(String, String)>,
    ) -> PyResult<Option<Reply>> {
        let Some((_, resp)) = self.send(Method::GET, endpoint, params, None).await? else {
            return Ok(None);
        };
        let failed = |e: PyExc| {
            PyExc::http(
                500,
                format!(
                    "Failed to send GET request to {endpoint} with error: {}",
                    e.display()
                ),
            )
        };
        let data = resp.map_err(failed)?.json().map_err(failed)?;
        Ok(Some(Reply::new(data, true, "Successfully retrieved data")))
    }

    /// `send_post_request(endpoint, data)`.
    pub async fn post(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Option<Reply>> {
        let Some((_, resp)) = self.send(Method::POST, endpoint, Vec::new(), data).await? else {
            return Ok(None);
        };
        // `except Exception: logger.debug(f"Response: {response}")` with
        // `response` never assigned.
        let resp = resp.map_err(|_| {
            PyExc::Other(
                "UnboundLocalError",
                "cannot access local variable 'response' where it is not associated with a value"
                    .into(),
            )
        })?;
        if resp.status() == 204 {
            return Ok(Some(Reply::new(
                PyValue::None,
                true,
                "Successfully completed request with no content",
            )));
        }
        let data = resp.json().map_err(|e| {
            PyExc::http(
                500,
                format!(
                    "Failed to send POST request to {endpoint} with error: {}",
                    e.display()
                ),
            )
        })?;
        let ok = resp.status() < 400;
        Ok(Some(Reply::new(
            data,
            ok,
            if ok {
                "Successfully retrieved data"
            } else {
                "Failed to retrieve data"
            },
        )))
    }

    /// `send_delete_request(endpoint, params)`.
    pub async fn delete(
        &self,
        endpoint: &str,
        params: Vec<(String, String)>,
    ) -> PyResult<Option<Reply>> {
        let Some((_, resp)) = self.send(Method::DELETE, endpoint, params, None).await? else {
            return Ok(None);
        };
        let resp = resp.map_err(|e| {
            PyExc::http(
                500,
                format!(
                    "Failed to send DELETE request to {endpoint} with error: {}",
                    e.display()
                ),
            )
        })?;
        let status = resp.status();
        if status == 204 || copilot_web::form::py_strip(&resp.text()).is_empty() {
            return Ok(Some(Reply::new(
                PyValue::None,
                true,
                "Successfully deleted resource",
            )));
        }
        Ok(Some(match resp.json() {
            Ok(data) => Reply::new(data, true, "Successfully retrieved data"),
            Err(_) => Reply::new(
                PyValue::None,
                status < 400,
                format!("Delete operation completed with status code {status}"),
            ),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_auth_url_is_urljoin() {
        for (base, want) in [
            ("https://portainer:9443", "https://portainer:9443/api/auth"),
            (
                "https://portainer:9443/x/y?q=1",
                "https://portainer:9443/api/auth",
            ),
            ("HTTP://p:9000/", "http://p:9000/api/auth"),
            ("p:9443", "/api/auth"),
            ("127.0.0.1:9443", "/api/auth"),
            ("", "/api/auth"),
            ("http://", "http:///api/auth"),
            ("ftp://h", "ftp://h/api/auth"),
            ("mailto:x", "/api/auth"),
        ] {
            assert_eq!(urljoin_absolute(base, "/api/auth"), want, "{base:?}");
        }
    }
}
