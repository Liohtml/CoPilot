//! The UBA transport — port of `app/connectors/uba/utils/universal.py`.
//!
//! Every call is `uba_request`: httpx 0.28's `AsyncClient(timeout=…)`
//! ([`copilot_threat_intel::httpx`]) against `{connector_url}{path}` with
//! the connector's key as `x-api-key`, `Accept: application/json` and the
//! analyst as `X-UBA-Actor` (cut to 128 characters), `params=` without its
//! `None` values, `json=` as httpx encodes it, TLS verified (httpx's
//! default; UBA runs over plain HTTP on the private network or behind a
//! certificate CoPilot trusts), redirects not followed.
//!
//! **The error mapping is load-bearing.** A UBA 401/403 never becomes a
//! CoPilot 401/403 (the frontend would end the analyst's session): they are
//! 502s with a `reason` (`key_rejected`, `insufficient_scope`), 404 and 422
//! pass through as `not_found` / `invalid_request` with UBA's `detail`, any
//! other failure is a 502 (`upstream_error`, `unreachable`, `bad_response`),
//! a missing or incomplete connector a 409 (`not_configured`). What
//! `uba_request` does not catch — an `InvalidURL`, a header httpx cannot
//! encode, a `detail` list whose first entry is not a dict — leaves the route
//! as it leaves Python's ([`UbaError::Py`]).

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::{ConnectorCache, ConnectorRow};
use copilot_threat_intel::httpx;
use copilot_upstream::py::{self, PyExc, PyResult};
use copilot_web::form::py_strip;
use http::Method;

/// `UBA_CONNECTOR_NAME`.
pub const CONNECTOR: &str = "SOCFortress UBA";
/// `DEFAULT_TIMEOUT` (seconds).
pub const DEFAULT_TIMEOUT: f64 = 20.0;

/// What a UBA call raised.
#[derive(Debug, Clone, PartialEq)]
pub enum UbaError {
    /// `UbaRequestError(reason, detail, status_code)`.
    Request {
        /// The stable code for the UI.
        reason: &'static str,
        /// For humans.
        detail: String,
        /// The status the route answers.
        status: u16,
    },
    /// Anything else, handled where Python handles it.
    Py(PyExc),
}

impl UbaError {
    /// A `UbaRequestError`.
    pub fn request(reason: &'static str, detail: impl Into<String>, status: u16) -> Self {
        Self::Request {
            reason,
            detail: detail.into(),
            status,
        }
    }

    /// `e.status_code` of a `UbaRequestError`.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Request { status, .. } => Some(*status),
            Self::Py(_) => None,
        }
    }

    /// `e.detail` of a `UbaRequestError`.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Request { detail, .. } => Some(detail),
            Self::Py(_) => None,
        }
    }
}

impl From<PyExc> for UbaError {
    fn from(e: PyExc) -> Self {
        Self::Py(e)
    }
}

/// `Result` of a UBA call.
pub type UbaResult<T> = Result<T, UbaError>;

/// `normalize_base_url`: stripped, no trailing `/`, no trailing `/v1`.
pub fn normalize_base_url(connector_url: &str) -> String {
    let base = py_strip(connector_url).trim_end_matches('/');
    base.strip_suffix("/v1").unwrap_or(base).to_string()
}

/// `path_segment`: `quote(value, safe="")`.
pub fn path_segment(value: &str) -> String {
    copilot_web::pyurl::quote(value, "")
}

/// `f"{timeout:.0f}"`.
fn seconds(timeout: f64) -> String {
    format!("{timeout:.0}")
}

/// httpx's `primitive_value_to_str` for one `params=` value, a list or tuple
/// giving one pair per item.
pub fn param_texts(value: &PyValue) -> Vec<String> {
    fn one(v: &PyValue) -> String {
        match v {
            PyValue::Bool(true) => "true".into(),
            PyValue::Bool(false) => "false".into(),
            PyValue::None => String::new(),
            other => other.py_str(),
        }
    }
    match value {
        PyValue::List(items) => items.iter().map(one).collect(),
        other => vec![one(other)],
    }
}

/// One `uba_request(method, path, params=…, json=…, actor=…, timeout=…)`.
#[derive(Debug, Clone)]
pub struct Call {
    method: Method,
    path: String,
    params: Vec<(String, PyValue)>,
    json: Option<PyValue>,
    actor: Option<String>,
    timeout: f64,
}

impl Call {
    /// A call with Python's defaults.
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            params: Vec::new(),
            json: None,
            actor: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// `GET`.
    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::GET, path)
    }

    /// `params=` (a `None` value is dropped, as Python does).
    pub fn params(mut self, params: Vec<(String, PyValue)>) -> Self {
        self.params = params;
        self
    }

    /// `json=`.
    pub fn json(mut self, body: PyValue) -> Self {
        self.json = Some(body);
        self
    }

    /// `actor=`.
    pub fn actor(mut self, actor: &str) -> Self {
        self.actor = Some(actor.to_string());
        self
    }

    /// `timeout=`.
    pub fn timeout(mut self, seconds: f64) -> Self {
        self.timeout = seconds;
        self
    }

    /// The method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The path (before the base URL is prepended).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The `params=`.
    pub fn query(&self) -> &[(String, PyValue)] {
        &self.params
    }

    /// The `json=` body.
    pub fn body(&self) -> Option<&PyValue> {
        self.json.as_ref()
    }
}

/// The transport: the connector row through the cache, a client per call.
#[derive(Debug, Clone)]
pub struct UbaClient {
    connectors: ConnectorCache,
}

/// `_upstream_detail(response)`: UBA's `detail` string, or the first
/// FastAPI validation error as `loc.path: msg`; `""` otherwise.
pub fn upstream_detail(response: &httpx::Response) -> PyResult<String> {
    let Ok(body) = response.json() else {
        return Ok(String::new());
    };
    let detail = match &body {
        PyValue::Dict(_) => body.get("detail"),
        _ => None,
    };
    match detail {
        Some(PyValue::Str(s)) => Ok(s.clone()),
        Some(PyValue::List(items)) if !items.is_empty() => {
            let first = &items[0];
            let loc = py::get(first, "loc")?
                .cloned()
                .unwrap_or_else(|| PyValue::List(Vec::new()));
            let parts: Vec<String> = py::iterate(&loc)?.iter().map(PyValue::py_str).collect();
            let msg = py::get(first, "msg")?
                .map(PyValue::py_str)
                .unwrap_or_default();
            Ok(format!("{}: {msg}", parts.join(".")))
        }
        _ => Ok(String::new()),
    }
}

fn db_error(e: copilot_db::DbError) -> UbaError {
    UbaError::Py(PyExc::Other("OperationalError", e.to_string()))
}

impl UbaClient {
    /// The transport over the connector cache.
    pub fn new(connectors: ConnectorCache) -> Self {
        Self { connectors }
    }

    /// `get_uba_attributes()`.
    pub async fn attributes(&self) -> UbaResult<Option<ConnectorRow>> {
        self.connectors.get(CONNECTOR).await.map_err(db_error)
    }

    /// `uba_request(...)` with the stored connector row.
    pub async fn request(&self, call: Call) -> UbaResult<PyValue> {
        let attributes = self.attributes().await?;
        self.request_with(attributes.as_ref(), call).await
    }

    /// `uba_request(..., attributes=…)`: the decoded JSON body.
    pub async fn request_with(
        &self,
        attributes: Option<&ConnectorRow>,
        call: Call,
    ) -> UbaResult<PyValue> {
        let Some(attributes) = attributes else {
            return Err(UbaError::request(
                "not_configured",
                format!("No {CONNECTOR} connector found in the database"),
                409,
            ));
        };
        let base = normalize_base_url(&attributes.connector_url);
        let key = py_strip(attributes.connector_api_key.as_deref().unwrap_or("")).to_string();
        if base.is_empty() || key.is_empty() {
            return Err(UbaError::request(
                "not_configured",
                format!("The {CONNECTOR} connector needs a URL and an API key"),
                409,
            ));
        }
        let mut req = httpx::Request::new(call.method.clone(), format!("{base}{}", call.path))
            .header("x-api-key", Some(&key))
            .header("Accept", Some("application/json"))
            .timeout(Duration::from_secs_f64(call.timeout.max(0.001)));
        if let Some(actor) = call.actor.as_deref().filter(|a| !a.is_empty()) {
            let cut: String = actor.chars().take(128).collect();
            req = req.header("X-UBA-Actor", Some(&cut));
        }
        let params: Vec<(String, String)> = call
            .params
            .iter()
            .filter(|(_, v)| !matches!(v, PyValue::None))
            .flat_map(|(k, v)| param_texts(v).into_iter().map(move |t| (k.clone(), t)))
            .collect();
        if !params.is_empty() {
            req = req.params(params);
        }
        if let Some(body) = call.json.clone() {
            req = req.json(body);
        }
        let response = match httpx::send(req).await {
            Ok(r) => r,
            Err(e) if e.class.ends_with("Timeout") => {
                return Err(UbaError::request(
                    "unreachable",
                    format!(
                        "SOCFortress UBA did not respond within {}s",
                        seconds(call.timeout)
                    ),
                    502,
                ));
            }
            Err(e) if e.is_http_error() => {
                tracing::warn!("UBA {} {} failed: {}", call.method, call.path, e.class);
                return Err(UbaError::request(
                    "unreachable",
                    format!("Could not reach SOCFortress UBA at {base}: {}", e.class),
                    502,
                ));
            }
            Err(e) => return Err(UbaError::Py(e.into_py())),
        };
        match response.status {
            401 => Err(UbaError::request(
                "key_rejected",
                "SOCFortress UBA rejected the API key (revoked or wrong). Create one with \
                 `uba-admin api-keys create --name copilot --scope write` and update the \
                 connector.",
                502,
            )),
            403 => {
                let upstream = upstream_detail(&response)?;
                let upstream = if upstream.is_empty() {
                    "forbidden".to_string()
                } else {
                    upstream
                };
                Err(UbaError::request(
                    "insufficient_scope",
                    format!(
                        "The UBA API key's scope does not allow this ({upstream}). CoPilot needs \
                         a key with scope write; setting UBA up for a customer needs scope admin \
                         for that customer (or all: `--scope admin --tenants '*'`)."
                    ),
                    502,
                ))
            }
            404 => {
                let upstream = upstream_detail(&response)?;
                Err(UbaError::request(
                    "not_found",
                    if upstream.is_empty() {
                        "Not found in SOCFortress UBA".to_string()
                    } else {
                        upstream
                    },
                    404,
                ))
            }
            422 => {
                let upstream = upstream_detail(&response)?;
                Err(UbaError::request(
                    "invalid_request",
                    if upstream.is_empty() {
                        "SOCFortress UBA rejected the request".to_string()
                    } else {
                        upstream
                    },
                    422,
                ))
            }
            s if s >= 400 => {
                tracing::warn!("UBA {} {} returned HTTP {s}", call.method, call.path);
                Err(UbaError::request(
                    "upstream_error",
                    format!("SOCFortress UBA returned HTTP {s}"),
                    502,
                ))
            }
            _ => response.json().map_err(|_| {
                UbaError::request(
                    "bad_response",
                    format!(
                        "SOCFortress UBA returned a non-JSON response for {}: check the connector \
                         URL",
                        call.path
                    ),
                    502,
                )
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls_like_python() {
        for (input, want) in [
            ("http://172.17.0.1:8010", "http://172.17.0.1:8010"),
            (" http://uba:8010/v1/ ", "http://uba:8010"),
            ("http://uba:8010/v1/v1", "http://uba:8010/v1"),
            ("http://uba//", "http://uba"),
            ("", ""),
        ] {
            assert_eq!(normalize_base_url(input), want, "{input:?}");
        }
        assert_eq!(path_segment("windows-demo\\jdoe"), "windows-demo%5Cjdoe");
        assert_eq!(
            path_segment("upn:jane@contoso.com"),
            "upn%3Ajane%40contoso.com"
        );
        assert_eq!(seconds(20.0), "20");
        assert_eq!(seconds(10.0), "10");
    }

    #[test]
    fn params_like_httpx() {
        assert_eq!(param_texts(&PyValue::Bool(true)), ["true"]);
        assert_eq!(param_texts(&PyValue::Float(0.0)), ["0.0"]);
        assert_eq!(param_texts(&PyValue::Int("500".into())), ["500"]);
        assert_eq!(
            param_texts(&PyValue::List(vec![
                PyValue::None,
                PyValue::Str("a".into()),
                PyValue::Bool(false)
            ])),
            ["", "a", "false"]
        );
    }
}
