//! The Wazuh indexer client — elasticsearch-py 7.10.1 (`elasticsearch7`) as
//! CoPilot configures it (`wazuh_indexer/utils/universal.py`):
//!
//! ```python
//! Elasticsearch([url], http_auth=(user, password), verify_certs=False,
//!               timeout=15, max_retries=10, retry_on_timeout=False)
//! ```
//!
//! The same requests go out: `_make_path`'s quoting (`quote(p, safe=",*")`),
//! the query parameters in the API's own order, compact JSON bodies
//! (`separators=(",", ":")`, `ensure_ascii=False`), `Authorization: Basic`
//! over `user:password` in Latin-1, up to ten immediate retries on a
//! connection error or a 502/503/504, and the exceptions' `str()` where the
//! services put them into responses (`TransportError` and its subclasses,
//! `ConnectionError(...) caused by: NewConnectionError(...)`).
//!
//! **TLS is not verified**, as in Python (`verify_certs=False`): the indexer
//! ships a self-signed certificate. This is mirrored, not changed.

use std::time::Duration;

use base64::Engine;
use reqwest::Method;
use serde_json::Value;

use copilot_auth::pyvalue::{self, PyValue, str_repr};
use copilot_db::connectors::{ConnectorCache, ConnectorRow};
use copilot_upstream::http::OBJECT_ADDRESS;
use copilot_web::pyurl::{quote, urlencode};

/// The connector row the indexer client reads.
pub const CONNECTOR: &str = "Wazuh-Indexer";
/// The seeded placeholder URL (`create_wazuh_indexer_client` refuses it).
pub const PLACEHOLDER_URL: &str = "https://127.1.1.1:9200";
const MAX_RETRIES: usize = 10;
const RETRY_ON_STATUS: [u16; 3] = [502, 503, 504];
const TIMEOUT: Duration = Duration::from_secs(15);
const USER_AGENT: &str = "elasticsearch-py/7.10.1 (Python 3.11)";

/// The sync client (`run_blocking(es.search, …)`) or `AsyncElasticsearch`
/// (aiohttp, which also sends `Accept: */*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// `Elasticsearch` over urllib3.
    Sync,
    /// `AsyncElasticsearch` over aiohttp.
    Async,
}

/// Shared HTTP stack for every indexer call (connection reuse only).
#[derive(Debug, Clone)]
pub struct EsHttp {
    client: reqwest::Client,
}

impl EsHttp {
    /// Build the client: no certificate verification, HTTP/1.1, no
    /// redirects followed (urllib3's `Retry(False)` returns them), 15 s to
    /// connect and per read.
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(TIMEOUT)
            .read_timeout(TIMEOUT)
            .build()?;
        Ok(Self { client })
    }
}

/// Why no client could be built — `create_wazuh_indexer_client`'s
/// `HTTPException(500, detail)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// `HTTPException(status_code=500, detail=…)`.
    Http(String),
    /// The connector lookup itself failed (Python lets it escape: a bare 500).
    Db(String),
}

impl ConnectError {
    /// `str(HTTPException)` (`"500: detail"`), for the services that wrap it.
    pub fn py_str(&self) -> String {
        match self {
            ConnectError::Http(d) => format!("500: {d}"),
            ConnectError::Db(e) => e.clone(),
        }
    }
}

/// One indexer, ready to call.
#[derive(Debug, Clone)]
pub struct Es {
    http: EsHttp,
    base: String,
    authorization: String,
    flavor: Flavor,
    /// `HTTPConnection` or `HTTPSConnection` (connection-error texts).
    tls: bool,
    host: String,
    port: u16,
}

/// The parts of `urlparse(url)` `_normalize_hosts` uses.
struct HostSpec {
    tls: bool,
    host: String,
    port: Option<u16>,
    prefix: String,
}

/// `urllib.parse.urlparse(...).port`'s `ValueError`s.
fn parse_host(url: &str) -> Result<HostSpec, String> {
    let url = if url.contains("://") {
        url.to_string()
    } else {
        format!("//{url}")
    };
    // urlsplit: scheme = up to the first ':' when it looks like one.
    let (scheme, rest) = match url.find(':') {
        Some(i)
            if i > 0
                && url.as_bytes()[0].is_ascii_alphabetic()
                && url[..i]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) =>
        {
            (url[..i].to_ascii_lowercase(), &url[i + 1..])
        }
        _ => (String::new(), url.as_str()),
    };
    let (netloc, path) = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            (&after[..end], &after[end..])
        }
        None => ("", rest),
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let (host, port) = if let Some(bracketed) = hostinfo.strip_prefix('[') {
        let (h, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
        (
            h.to_string(),
            after.strip_prefix(':').filter(|p| !p.is_empty()),
        )
    } else {
        let (h, p) = hostinfo.split_once(':').unwrap_or((hostinfo, ""));
        (h.to_string(), (!p.is_empty()).then_some(p))
    };
    let port = match port {
        None => None,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => {
            let n: u64 = p.parse().unwrap_or(u64::MAX);
            if n > 65535 {
                return Err("Port out of range 0-65535".into());
            }
            u16::try_from(n).ok().filter(|n| *n != 0)
        }
        Some(p) => {
            return Err(format!(
                "Port could not be cast to integer value as {}",
                str_repr(p)
            ));
        }
    };
    let tls = scheme == "https";
    let prefix = if !path.is_empty() && path != "/" {
        format!("/{}", path.trim_matches('/'))
    } else {
        String::new()
    };
    Ok(HostSpec {
        tls,
        host: host.to_lowercase(),
        port: if tls { Some(port.unwrap_or(443)) } else { port },
        prefix,
    })
}

/// `"user:password".encode("latin-1")`'s `UnicodeEncodeError` text.
fn latin1(s: &str) -> Result<Vec<u8>, String> {
    let chars: Vec<char> = s.chars().collect();
    if let Some(start) = chars.iter().position(|c| u32::from(*c) > 0xff) {
        let mut end = start;
        while end < chars.len() && u32::from(chars[end]) > 0xff {
            end += 1;
        }
        let what = if end - start == 1 {
            let c = u32::from(chars[start]);
            let esc = if c < 0x10000 {
                format!("\\u{c:04x}")
            } else {
                format!("\\U{c:08x}")
            };
            format!("character '{esc}' in position {start}")
        } else {
            format!("characters in position {start}-{}", end - 1)
        };
        return Err(format!(
            "'latin-1' codec can't encode {what}: ordinal not in range(256)"
        ));
    }
    Ok(chars.iter().map(|c| u32::from(*c) as u8).collect())
}

impl Es {
    /// `create_wazuh_indexer_client(_async)("Wazuh-Indexer")`.
    pub async fn connect(
        http: &EsHttp,
        cache: &ConnectorCache,
        flavor: Flavor,
    ) -> Result<Self, ConnectError> {
        let row = cache
            .get(CONNECTOR)
            .await
            .map_err(|e| ConnectError::Db(e.to_string()))?
            .ok_or_else(|| {
                ConnectError::Http(format!("No {CONNECTOR} connector found in the database"))
            })?;
        Self::from_row(http, &row, flavor)
            .map_err(|e| ConnectError::Http(format!("Failed to create Elasticsearch client: {e}")))
            .and_then(|es| {
                if row.connector_url == PLACEHOLDER_URL {
                    Err(ConnectError::Http(format!(
                        "Please update the {CONNECTOR} connector URL"
                    )))
                } else {
                    Ok(es)
                }
            })
    }

    /// `Elasticsearch([url], http_auth=(user, password), …)`; `Err` is the
    /// constructor's exception text.
    pub fn from_row(http: &EsHttp, row: &ConnectorRow, flavor: Flavor) -> Result<Self, String> {
        let spec = parse_host(&row.connector_url)?;
        // `":".join((user, password))`.
        let user = row
            .connector_username
            .as_deref()
            .ok_or("sequence item 0: expected str instance, NoneType found")?;
        let password = row
            .connector_password
            .as_deref()
            .ok_or("sequence item 1: expected str instance, NoneType found")?;
        let raw = latin1(&format!("{user}:{password}"))?;
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        );
        let port = spec.port.unwrap_or(9200);
        let host_in_url = if spec.host.contains(':') {
            format!("[{}]", spec.host)
        } else {
            spec.host.clone()
        };
        let base = format!(
            "{}://{host_in_url}:{port}{}",
            if spec.tls { "https" } else { "http" },
            spec.prefix
        );
        Ok(Self {
            http: http.clone(),
            base,
            authorization,
            flavor,
            tls: spec.tls,
            host: spec.host,
            port,
        })
    }

    /// `transport.perform_request(method, path, params=…, body=…)`: the
    /// deserialized answer (`""` for an empty one).
    pub async fn perform(
        &self,
        method: Method,
        path: &str,
        params: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value, EsError> {
        let payload = body.map(|b| serde_json::to_vec(b).unwrap_or_default());
        self.perform_raw(method, path, params, payload).await
    }

    /// [`Es::perform`] with the body already serialized, for a caller that
    /// writes `JSONSerializer.dumps`' exact text (Python's float `repr`).
    pub async fn perform_raw(
        &self,
        method: Method,
        path: &str,
        params: &[(&str, String)],
        payload: Option<Vec<u8>>,
    ) -> Result<Value, EsError> {
        let mut url = format!("{}{path}", self.base);
        if !params.is_empty() {
            url.push('?');
            url.push_str(&urlencode(params));
        }
        let mut attempt = 0;
        loop {
            match self.once(&method, &url, payload.as_deref()).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    let retry = match &e {
                        EsError::Connection { .. } => true,
                        EsError::Transport { status, .. } => RETRY_ON_STATUS.contains(status),
                        _ => false,
                    };
                    if !retry || attempt == MAX_RETRIES {
                        return Err(e);
                    }
                    attempt += 1;
                }
            }
        }
    }

    async fn once(
        &self,
        method: &Method,
        url: &str,
        body: Option<&[u8]>,
    ) -> Result<Value, EsError> {
        let mut req = self
            .http
            .client
            .request(method.clone(), url)
            .header("connection", "keep-alive")
            .header("content-type", "application/json")
            .header("user-agent", USER_AGENT)
            .header("authorization", &self.authorization);
        if self.flavor == Flavor::Async {
            // aiohttp's defaults; it decompresses what it asked for.
            req = req
                .header("accept", "*/*")
                .header("accept-encoding", "gzip, deflate");
        }
        match body {
            Some(b) => req = req.body(b.to_vec()),
            // `Content-Length: 0` on a body-less request: urllib3 sends it for
            // the methods that expect a body, aiohttp for every method but
            // GET, HEAD, OPTIONS and TRACE (hyper writes none on its own).
            None if self.sends_zero_length(method) => {
                req = req.header("content-length", "0").body(Vec::new());
            }
            None => {}
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => return Err(self.transport_failure(&e).await),
        };
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let ctype = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => return Err(self.transport_failure(&e).await),
        };
        let bytes = if self.flavor == Flavor::Async {
            match copilot_upstream::http::decode_content(&headers, bytes) {
                Ok(b) => b,
                Err(e) => {
                    let error = format!(
                        "400, message='Can not decode content-encoding: {}'",
                        headers
                            .get(reqwest::header::CONTENT_ENCODING)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                    );
                    tracing::debug!("indexer answer not decodable: {}", e.text());
                    return Err(EsError::Connection {
                        error,
                        cause: "ClientPayloadError",
                    });
                }
            }
        } else {
            bytes
        };
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        if !(200..300).contains(&status) {
            return Err(raise_error(status, &raw));
        }
        if raw.is_empty() {
            return Ok(Value::String(String::new()));
        }
        // `Deserializer.loads(data, content_type)`.
        let mimetype = ctype
            .as_deref()
            .map(|c| c.split(';').next().unwrap_or_default().to_string())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "application/json".into());
        match mimetype.as_str() {
            "application/json" => serde_json::from_str(&raw).map_err(|_| {
                let msg = copilot_upstream::json::decode_error(&raw).unwrap_or_default();
                EsError::Serialization(format!(
                    "({}, JSONDecodeError({}))",
                    str_repr(&raw),
                    str_repr(&msg)
                ))
            }),
            "text/plain" => Ok(Value::String(raw)),
            other => Err(EsError::Serialization(format!(
                "Unknown mimetype, unable to deserialize: {other}"
            ))),
        }
    }

    /// Whether a body-less `method` carries `Content-Length: 0`.
    fn sends_zero_length(&self, method: &Method) -> bool {
        match self.flavor {
            Flavor::Sync => [Method::POST, Method::PUT, Method::PATCH].contains(method),
            Flavor::Async => {
                ![Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE].contains(method)
            }
        }
    }

    /// A connection-level failure as elasticsearch-py words it: over urllib3
    /// (the sync client) or aiohttp (`AsyncElasticsearch`).
    async fn transport_failure(&self, e: &reqwest::Error) -> EsError {
        if self.flavor == Flavor::Async {
            return self.aiohttp_failure(e).await;
        }
        if e.is_timeout() && !e.is_connect() {
            return EsError::Timeout {
                cause: format!(
                    "{}ConnectionPool(host={}, port={}): Read timed out. (read timeout=15)",
                    if self.tls { "HTTPS" } else { "HTTP" },
                    str_repr(&self.host),
                    self.port
                ),
            };
        }
        let conn = format!(
            "<urllib3.connection.{}Connection object at {OBJECT_ADDRESS}>",
            if self.tls { "HTTPS" } else { "HTTP" }
        );
        let detail = os_error_text(e);
        EsError::Connection {
            error: format!("{conn}: Failed to establish a new connection: {detail}"),
            cause: "NewConnectionError",
        }
    }
}

impl Es {
    /// `AIOHttpConnection.perform_request`'s `ConnectionError("N/A", str(e),
    /// e)` (or `ConnectionTimeout`) for what aiohttp raised.
    async fn aiohttp_failure(&self, e: &reqwest::Error) -> EsError {
        if e.is_timeout() {
            return EsError::Timeout {
                cause: String::new(),
            };
        }
        let connector = |strerror: String, cause: &'static str| EsError::Connection {
            error: format!(
                "Cannot connect to host {}:{} ssl:default [{strerror}]",
                self.host, self.port
            ),
            cause,
        };
        if e.is_connect() {
            let detail = os_error_text(e);
            if detail == "[Errno -2] Name or service not known" {
                return connector(
                    "Name or service not known".into(),
                    "ClientConnectorDNSError",
                );
            }
            if detail == "[Errno 111] Connection refused" {
                let addr = match self.host.parse::<std::net::IpAddr>() {
                    Ok(ip) => Some(std::net::SocketAddr::new(ip, self.port)),
                    Err(_) => tokio::net::lookup_host((self.host.as_str(), self.port))
                        .await
                        .ok()
                        .and_then(|mut a| a.next()),
                };
                let addr = match addr {
                    Some(std::net::SocketAddr::V4(a)) => {
                        format!("({}, {})", str_repr(&a.ip().to_string()), a.port())
                    }
                    Some(std::net::SocketAddr::V6(a)) => format!(
                        "({}, {}, {}, {})",
                        str_repr(&a.ip().to_string()),
                        a.port(),
                        a.flowinfo(),
                        a.scope_id()
                    ),
                    None => format!("({}, {})", str_repr(&self.host), self.port),
                };
                return connector(
                    format!("Connect call failed {addr}"),
                    "ClientConnectorError",
                );
            }
            return connector(detail, "ClientConnectorError");
        }
        EsError::Connection {
            error: "Server disconnected".into(),
            cause: "ServerDisconnectedError",
        }
    }
}

/// The `OSError` text Python's socket layer would report.
pub(crate) fn os_error_text(e: &reqwest::Error) -> String {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = source {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::ConnectionRefused => "[Errno 111] Connection refused".into(),
                std::io::ErrorKind::ConnectionReset => {
                    "[Errno 104] Connection reset by peer".into()
                }
                std::io::ErrorKind::HostUnreachable => "[Errno 113] No route to host".into(),
                std::io::ErrorKind::NetworkUnreachable => {
                    "[Errno 101] Network is unreachable".into()
                }
                std::io::ErrorKind::TimedOut => "timed out".into(),
                _ => io.to_string(),
            };
        }
        let text = s.to_string();
        if text.contains("dns error") || text.contains("failed to lookup address") {
            return "[Errno -2] Name or service not known".into();
        }
        source = s.source();
    }
    e.to_string()
}

/// `Connection._raise_error(status_code, raw_data)`.
fn raise_error(status: u16, raw: &str) -> EsError {
    let mut error = PyValue::Str(raw.to_string());
    let mut info = None;
    if !raw.is_empty() {
        if let Ok(parsed) = pyvalue::loads(raw) {
            if let Some(e) = parsed.get("error") {
                error = e.clone();
                if let PyValue::Dict(_) = e {
                    if let Some(t) = e.get("type") {
                        error = t.clone();
                    }
                }
            }
            info = Some(parsed);
        }
    }
    let class = match status {
        400 => "RequestError",
        401 => "AuthenticationException",
        403 => "AuthorizationException",
        404 => "NotFoundError",
        409 => "ConflictError",
        _ => "TransportError",
    };
    EsError::Transport {
        class,
        status,
        error,
        info,
    }
}

/// An exception the client raises, rendered as its Python `str()`.
#[derive(Debug, Clone, PartialEq)]
pub enum EsError {
    /// `TransportError` (status ≥ 400) and its subclasses.
    Transport {
        /// `RequestError`, `NotFoundError`, …
        class: &'static str,
        /// HTTP status.
        status: u16,
        /// `.error` (the error type, or the raw body).
        error: PyValue,
        /// `.info` (the parsed body).
        info: Option<PyValue>,
    },
    /// `ConnectionError("N/A", str(e), e)`.
    Connection {
        /// `str(e)` of urllib3's exception.
        error: String,
        /// Its class name.
        cause: &'static str,
    },
    /// `ConnectionTimeout` (not retried: `retry_on_timeout=False`).
    Timeout {
        /// `str(ReadTimeoutError)`.
        cause: String,
    },
    /// `SerializationError` (its full `str()`).
    Serialization(String),
    /// `ValueError("Empty value passed for a required argument.")`.
    Value(String),
}

impl EsError {
    /// `isinstance(e, NotFoundError)`.
    pub fn is_not_found(&self) -> bool {
        matches!(self, EsError::Transport { status: 404, .. })
    }

    /// `isinstance(e, RequestError)`.
    pub fn is_request_error(&self) -> bool {
        matches!(self, EsError::Transport { status: 400, .. })
    }

    /// `e.info` as a dict (the parsed error body), if any.
    pub fn info(&self) -> Option<&PyValue> {
        match self {
            EsError::Transport { info, .. } => info.as_ref(),
            _ => None,
        }
    }
}

impl std::fmt::Display for EsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EsError::Transport {
                class,
                status,
                error,
                info,
            } => {
                let mut parts = vec![status.to_string(), error.py_repr()];
                if let Some(cause) = info.as_ref().and_then(cause_of) {
                    parts.push(cause);
                }
                write!(f, "{class}({})", parts.join(", "))
            }
            EsError::Connection { error, cause } => {
                write!(f, "ConnectionError({error}) caused by: {cause}({error})")
            }
            EsError::Timeout { cause } if cause.is_empty() => {
                // aiohttp's whole-request timeout: `asyncio.TimeoutError()`.
                f.write_str("ConnectionTimeout caused by - TimeoutError()")
            }
            EsError::Timeout { cause } => {
                write!(f, "ConnectionTimeout caused by - ReadTimeoutError({cause})")
            }
            EsError::Serialization(s) | EsError::Value(s) => f.write_str(s),
        }
    }
}

/// `TransportError.__str__`'s `cause`: the root cause's reason (and resource
/// id/type) when `info["error"]` is a dict, else `repr(info["error"])`.
fn cause_of(info: &PyValue) -> Option<String> {
    if !info.truthy() {
        return None;
    }
    let err = info.get("error")?;
    let cause = match err {
        PyValue::Dict(_) => {
            let root = match err.get("root_cause") {
                Some(PyValue::List(items)) => items.first()?,
                _ => return None,
            };
            let reason = root.get("reason")?;
            let mut parts = vec![reason.py_repr()];
            for k in ["resource.id", "resource.type"] {
                if let Some(v) = root.get(k).filter(|v| v.truthy()) {
                    parts.push(v.py_str());
                }
            }
            parts.join(", ")
        }
        other => other.py_repr(),
    };
    (!cause.is_empty()).then_some(cause)
}

/// `_make_path(*parts)`: empty parts dropped, each quoted with `safe=",*"`.
pub fn make_path(parts: &[&str]) -> String {
    let kept: Vec<String> = parts
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| quote(p, ",*"))
        .collect();
    format!("/{}", kept.join("/"))
}

/// `_escape(bool)`.
pub fn flag(b: bool) -> String {
    if b { "true".into() } else { "false".into() }
}

/// The required-argument check of `get`, `snapshot.create`, … .
pub fn require(parts: &[&str]) -> Result<(), EsError> {
    if parts.iter().any(|p| p.is_empty()) {
        return Err(EsError::Value(
            "Empty value passed for a required argument.".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(status: u16, raw: &str) -> String {
        raise_error(status, raw).to_string()
    }

    #[test]
    fn transport_error_texts() {
        // Recorded with elasticsearch-py 7.10.1.
        assert_eq!(
            err(
                400,
                r#"{"error":{"root_cause":[{"type":"search_phase_execution_exception","reason":"No mapping found for [timestamp_utc] in order to sort on"}],"type":"search_phase_execution_exception","reason":"all shards failed"},"status":400}"#
            ),
            "RequestError(400, 'search_phase_execution_exception', 'No mapping found for [timestamp_utc] in order to sort on')"
        );
        assert_eq!(
            err(
                404,
                r#"{"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index [x]","resource.type":"index_or_alias","resource.id":"x","index":"x"}],"type":"index_not_found_exception"},"status":404}"#
            ),
            "NotFoundError(404, 'index_not_found_exception', 'no such index [x]', x, index_or_alias)"
        );
        assert_eq!(
            err(401, "Unauthorized"),
            "AuthenticationException(401, 'Unauthorized')"
        );
        assert_eq!(
            err(500, r#"{"error": "boom"}"#),
            "TransportError(500, 'boom', 'boom')"
        );
        assert_eq!(
            err(404, r#"{"_index":"a","_id":"b","found":false}"#),
            r#"NotFoundError(404, '{"_index":"a","_id":"b","found":false}')"#
        );
        assert_eq!(err(503, ""), "TransportError(503, '')");
    }

    #[test]
    fn hosts_parse_like_normalize_hosts() {
        let h = parse_host("https://Indexer.Local:9200").unwrap();
        assert_eq!(
            (h.tls, h.host.as_str(), h.port),
            (true, "indexer.local", Some(9200))
        );
        assert_eq!(parse_host("https://x").unwrap().port, Some(443));
        assert_eq!(parse_host("http://x").unwrap().port, None);
        assert_eq!(parse_host("10.0.0.1:9201").unwrap().port, Some(9201));
        assert_eq!(parse_host("http://x:9200/es/").unwrap().prefix, "/es");
        assert_eq!(
            parse_host("http://x:abc").err().as_deref(),
            Some("Port could not be cast to integer value as 'abc'")
        );
        assert_eq!(
            parse_host("http://x:70000").err().as_deref(),
            Some("Port out of range 0-65535")
        );
    }

    #[test]
    fn paths_and_auth() {
        assert_eq!(make_path(&["*", "_alias"]), "/*/_alias");
        assert_eq!(
            make_path(&["a b/c", "", "_doc", "x,y"]),
            "/a%20b%2Fc/_doc/x,y"
        );
        assert_eq!(
            latin1("ü:€").unwrap_err(),
            "'latin-1' codec can't encode character '\\u20ac' in position 2: ordinal not in range(256)"
        );
        assert_eq!(latin1("ü").unwrap(), vec![0xfc]);
    }
}
