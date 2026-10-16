//! `wazuh_manager/utils/universal.py`: the token flow and the GET / PUT
//! helpers, returning the dicts the Python helpers return (same keys, same
//! order, same texts) so the services can be ported line by line.
//!
//! **Tokens** come from `GET /security/user/authenticate` (Basic auth) and
//! are reused for 10 minutes less a 30 s margin, as in Python — but only for
//! the connector row they were issued against: a changed URL or credential
//! fetches a new one at once (Python keeps the old token, keyed by name, and
//! would send it to the new URL). A `GET` answered 401 drops the token,
//! authenticates again and retries once, as in Python; `PUT` does not.
//!
//! TLS is not verified (`verify=False`, mirrored); 60 s to connect and per
//! read (`WAZUH_REQUEST_TIMEOUT`); redirects are followed as `requests`
//! does (up to 30).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::Method;
use serde_json::{Map, Value, json};

use copilot_db::connectors::ConnectorRow;

use crate::WazuhState;
use crate::error::PyErr;
use crate::pyops;
use crate::requests::{self as rq, ConnectFailure, Origin};

/// The connector row.
pub const CONNECTOR: &str = "Wazuh-Manager";
/// `AUTH_FAILED_MESSAGE`.
pub const AUTH_FAILED_MESSAGE: &str =
    "Could not authenticate to the Wazuh Manager (unreachable or credentials rejected)";
const TIMEOUT: Duration = Duration::from_secs(60);
const TOKEN_TTL: Duration = Duration::from_secs(600);
const TOKEN_MARGIN: Duration = Duration::from_secs(30);

/// A query parameter value before `str()`.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    /// `True` / `False`.
    Bool(bool),
    /// An int.
    Int(i64),
    /// A string.
    Str(String),
}

impl Param {
    fn text(&self) -> String {
        match self {
            Param::Bool(b) => rq::param_bool(*b),
            Param::Int(i) => i.to_string(),
            Param::Str(s) => s.clone(),
        }
    }

    fn truthy(&self) -> bool {
        match self {
            Param::Bool(b) => *b,
            Param::Int(i) => *i != 0,
            Param::Str(s) => !s.is_empty(),
        }
    }
}

/// `params` in the dict's order.
pub type Params = Vec<(String, Param)>;

/// A request body, as `requests` sends `data=`.
#[derive(Debug, Clone)]
pub enum Body {
    /// Bytes as they are (a rule file).
    Bytes(Vec<u8>),
    /// A `str` (UTF-8 under urllib3 2).
    Text(String),
    /// `data={}`: no body at all.
    EmptyDict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RowKey {
    url: String,
    username: Option<String>,
    password: Option<String>,
}

impl RowKey {
    fn of(row: &ConnectorRow) -> Self {
        Self {
            url: row.connector_url.clone(),
            username: row.connector_username.clone(),
            password: row.connector_password.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct Cached {
    token: String,
    expires_at: Instant,
    key: RowKey,
}

/// The manager's HTTP stack and token cache (one per process, as Python's
/// module-level `_token_cache`).
#[derive(Debug, Clone)]
pub struct ManagerHttp {
    client: reqwest::Client,
    tokens: Arc<Mutex<HashMap<String, Cached>>>,
}

/// One answer.
#[derive(Debug, Clone)]
pub struct Reply {
    /// Status code.
    pub status: u16,
    reason: String,
    url: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Reply {
    /// `raise_for_status()`.
    pub fn raise_for_status(&self) -> Result<(), String> {
        match rq::http_error(self.status, &self.reason, &self.url) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// `response.text`.
    pub fn text(&self) -> String {
        rq::decode_text(self.content_type.as_deref(), &self.body)
    }

    /// `response.json()`; `Err` is the `JSONDecodeError` text.
    pub fn json(&self) -> Result<Value, String> {
        loads(&self.text())
    }
}

/// `json.loads(text)` as a `serde_json` value (Python's `NaN` and
/// `Infinity` read as `null`).
pub fn loads(text: &str) -> Result<Value, String> {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return Ok(v);
    }
    if let Some(msg) = copilot_upstream::json::decode_error(text) {
        return Err(msg);
    }
    copilot_auth::pyvalue::loads(text)
        .map(|v| to_json(&v))
        .map_err(|_| "Expecting value: line 1 column 1 (char 0)".to_string())
}

fn to_json(v: &copilot_auth::pyvalue::PyValue) -> Value {
    use copilot_auth::pyvalue::PyValue;
    match v {
        PyValue::None => Value::Null,
        PyValue::Bool(b) => Value::Bool(*b),
        PyValue::Int(i) => serde_json::from_str(i).unwrap_or(Value::Null),
        PyValue::Float(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
        PyValue::Str(s) => Value::String(s.clone()),
        PyValue::List(items) => Value::Array(items.iter().map(to_json).collect()),
        PyValue::Dict(items) => {
            Value::Object(items.iter().map(|(k, v)| (k.clone(), to_json(v))).collect())
        }
    }
}

/// `{"success": False, "message": …}`.
pub fn failure(message: impl Into<String>) -> Value {
    json!({"success": false, "message": message.into()})
}

/// `_auth_failed()`.
fn auth_failed() -> Value {
    tracing::error!("{AUTH_FAILED_MESSAGE}");
    failure(AUTH_FAILED_MESSAGE)
}

impl ManagerHttp {
    /// Build the client.
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::limited(30))
            .connect_timeout(TIMEOUT)
            .read_timeout(TIMEOUT)
            .build()?;
        Ok(Self {
            client,
            tokens: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn cached(&self, name: &str, key: &RowKey) -> Option<String> {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        let entry = tokens.get(name)?;
        if entry.key != *key || Instant::now() + TOKEN_MARGIN >= entry.expires_at {
            tokens.remove(name);
            return None;
        }
        Some(entry.token.clone())
    }

    fn store(&self, name: &str, key: RowKey, token: String) {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        tokens.insert(
            name.to_string(),
            Cached {
                token,
                expires_at: Instant::now() + TOKEN_TTL,
                key,
            },
        );
    }

    fn invalidate(&self, name: &str) {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        tokens.remove(name);
    }

    /// Forget every token (tests).
    pub fn clear_tokens(&self) {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        tokens.clear();
    }

    /// One request as `requests.<method>(url, headers=…, params=…,
    /// data=…, verify=False, timeout=60)` sends it.
    async fn send(
        &self,
        method: Method,
        url: &str,
        params: &[(String, String)],
        headers: &[(&str, String)],
        body: Option<&Body>,
    ) -> Result<Reply, String> {
        let prepared = rq::prepare_url(url, params).map_err(|e| e.0)?;
        let origin = rq::origin(&prepared).ok_or_else(|| format!("Failed to parse: {prepared}"))?;
        let mut req = self
            .client
            .request(method.clone(), prepared.as_str())
            .header("user-agent", rq::USER_AGENT)
            .header("accept-encoding", rq::ACCEPT_ENCODING)
            .header("accept", "*/*")
            .header("connection", "keep-alive");
        for (name, value) in headers {
            req = req.header(*name, value.as_str());
        }
        let payload: Option<Vec<u8>> = match body {
            Some(Body::Bytes(b)) => Some(b.clone()),
            Some(Body::Text(t)) => Some(t.as_bytes().to_vec()),
            Some(Body::EmptyDict) | None => None,
        };
        match payload {
            Some(p) => req = req.body(p),
            // `requests` sends `Content-Length: 0` on a body-less request of any
            // method but GET and HEAD; hyper writes none for an empty DELETE, so
            // the header is set here (hyper keeps a given length as the only one).
            None if method != Method::GET && method != Method::HEAD => {
                req = req.header("content-length", "0").body(Vec::new());
            }
            None => {}
        }
        let resp = req.send().await.map_err(|e| failure_text(&origin, &e))?;
        let status = resp.status();
        let reason = resp
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
            .unwrap_or_else(|| status.canonical_reason().unwrap_or_default().to_string());
        let final_url = if resp.url().as_str() == prepared
            || reqwest::Url::parse(&prepared).is_ok_and(|u| &u == resp.url())
        {
            prepared.clone()
        } else {
            resp.url().to_string()
        };
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = resp
            .bytes()
            .await
            .map_err(|e| failure_text(&origin, &e))?
            .to_vec();
        Ok(Reply {
            status: status.as_u16(),
            reason,
            url: final_url,
            content_type,
            body,
        })
    }

    /// `verify_wazuh_manager_credentials`'s one call: the status of
    /// `GET /security/user/authenticate`, or the exception's text.
    pub async fn authenticate(&self, row: &ConnectorRow) -> Result<u16, String> {
        let auth = rq::basic_auth(
            row.connector_username.as_deref(),
            row.connector_password.as_deref(),
        )
        .ok_or_else(|| "'latin-1' codec can't encode the credentials".to_string())?;
        let url = format!("{}/security/user/authenticate", row.connector_url);
        self.send(Method::GET, &url, &[], &[("authorization", auth)], None)
            .await
            .map(|r| r.status)
    }

    /// `create_wazuh_manager_client(name)`: the bearer token, or `None`.
    async fn token(&self, row: Option<&ConnectorRow>) -> Option<String> {
        let row = row?;
        let key = RowKey::of(row);
        if let Some(token) = self.cached(CONNECTOR, &key) {
            return Some(token);
        }
        tracing::info!("Fetching new Wazuh Manager authentication token for {CONNECTOR}");
        let auth = rq::basic_auth(
            row.connector_username.as_deref(),
            row.connector_password.as_deref(),
        )?;
        let url = format!("{}/security/user/authenticate", row.connector_url);
        let reply = match self
            .send(Method::GET, &url, &[], &[("authorization", auth)], None)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Connection to {} failed with error: {e}", row.connector_url);
                return None;
            }
        };
        if reply.status != 200 {
            tracing::error!(
                "Connection to {} failed with error: {}",
                row.connector_url,
                reply.text()
            );
            return None;
        }
        let token = reply
            .json()
            .ok()
            .and_then(|v| pyops::index(&v, "data").ok())
            .and_then(|d| pyops::index(&d, "token").ok())?;
        let token = pyops::py_str(&token);
        self.store(CONNECTOR, key, token.clone());
        Some(token)
    }
}

/// `str()` of the exception `requests` raised for a transport failure.
fn failure_text(origin: &Origin, e: &reqwest::Error) -> String {
    if e.is_timeout() && !e.is_connect() {
        return rq::read_timeout(origin, TIMEOUT.as_secs());
    }
    if e.is_connect() {
        if e.is_timeout() {
            return rq::connection_error(origin, &ConnectFailure::Timeout(TIMEOUT.as_secs()));
        }
        let os = crate::es::os_error_text(e);
        let failure = if os.starts_with("[Errno -2]") || os.starts_with("[Errno -3]") {
            ConnectFailure::Resolve(os)
        } else {
            ConnectFailure::Refused(os)
        };
        return rq::connection_error(origin, &failure);
    }
    let os = crate::es::os_error_text(e);
    if os.contains("Connection reset") {
        return "('Connection aborted.', ConnectionResetError(104, 'Connection reset by peer'))"
            .into();
    }
    "('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))"
        .into()
}

async fn row(st: &WazuhState) -> Result<Option<ConnectorRow>, PyErr> {
    Ok(st.ctx.connectors.get(CONNECTOR).await?)
}

fn texts(params: &[(String, Param)]) -> Vec<(String, String)> {
    params.iter().map(|(k, v)| (k.clone(), v.text())).collect()
}

fn bearer(token: &str) -> (&'static str, String) {
    ("authorization", format!("Bearer {token}"))
}

fn ok(data: Value, message: &str) -> Value {
    let mut m = Map::new();
    m.insert("data".into(), data);
    m.insert("success".into(), Value::Bool(true));
    m.insert("message".into(), Value::String(message.into()));
    Value::Object(m)
}

/// `send_get_request(endpoint, params)`.
pub async fn send_get(
    st: &WazuhState,
    endpoint: &str,
    params: Option<&[(String, Param)]>,
) -> Result<Value, PyErr> {
    tracing::info!("Sending GET request to {endpoint}");
    let http = &st.manager;
    let first_row = row(st).await?;
    let Some(token) = http.token(first_row.as_ref()).await else {
        return Ok(auth_failed());
    };
    let Some(attributes) = row(st).await? else {
        tracing::error!("No Wazuh Manager connector found in the database");
        return Ok(failure("No Wazuh Manager connector found in the database"));
    };
    let url = format!("{}{endpoint}", attributes.connector_url);
    let query = params.map(texts).unwrap_or_default();
    let is_raw = params.is_some_and(|p| {
        !p.is_empty()
            && p.iter()
                .rev()
                .find(|(k, _)| k == "raw")
                .is_some_and(|(_, v)| v.truthy())
    });
    let outcome: Result<Value, String> = async {
        if is_raw {
            let reply = http
                .send(Method::GET, &url, &query, &[bearer(&token)], None)
                .await?;
            reply.raise_for_status()?;
            return Ok(ok(
                Value::String(reply.text()),
                "Successfully retrieved data",
            ));
        }
        let mut reply = http
            .send(Method::GET, &url, &query, &[bearer(&token)], None)
            .await?;
        if reply.status == 401 {
            tracing::warn!("Received 401 Unauthorized, invalidating cached token and retrying");
            http.invalidate(CONNECTOR);
            let again = row(st).await.ok().flatten();
            let Some(token) = http.token(again.as_ref()).await else {
                return Ok(failure("Failed to re-authenticate with Wazuh Manager"));
            };
            reply = http
                .send(Method::GET, &url, &query, &[bearer(&token)], None)
                .await?;
        }
        reply.raise_for_status()?;
        Ok(ok(reply.json()?, "Successfully retrieved data"))
    }
    .await;
    Ok(outcome.unwrap_or_else(|e| {
        tracing::error!("Failed to send GET request to {endpoint} with error: {e}");
        failure(format!(
            "Failed to send GET request to {endpoint} with error: {e}"
        ))
    }))
}

/// How `send_put_request` labels the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutKind {
    /// `application/json` (the default).
    Json,
    /// `xml_data=True`.
    Xml,
    /// `binary_data=True`.
    Binary,
}

/// `send_put_request(endpoint, data, params, xml_data, binary_data)`;
/// `Value::Null` is its `None` (no connector row).
pub async fn send_put(
    st: &WazuhState,
    endpoint: &str,
    data: Option<Body>,
    params: Option<&[(String, Param)]>,
    kind: PutKind,
) -> Result<Value, PyErr> {
    tracing::info!("Sending PUT request to {endpoint}");
    let http = &st.manager;
    let first_row = row(st).await?;
    let token = http.token(first_row.as_ref()).await;
    let Some(attributes) = row(st).await? else {
        tracing::error!("No Wazuh Manager connector found in the database");
        return Ok(Value::Null);
    };
    let Some(token) = token else {
        return Ok(auth_failed());
    };
    let content_type = match kind {
        PutKind::Json => "application/json",
        PutKind::Xml => "application/xml",
        PutKind::Binary => "application/octet-stream",
    };
    let url = format!("{}{endpoint}", attributes.connector_url);
    let query = params.map(texts).unwrap_or_default();
    let reply = match http
        .send(
            Method::PUT,
            &url,
            &query,
            &[bearer(&token), ("content-type", content_type.to_string())],
            data.as_ref(),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return Ok(put_exception(endpoint, &e)),
    };
    if let Err(_http_error) = reply.raise_for_status() {
        let mut detail = Value::String(String::new());
        match reply.json() {
            Ok(Value::Object(map)) => {
                let json = Value::Object(map.clone());
                if let Some(d) = map.get("detail") {
                    detail = d.clone();
                } else if let Some(m) = map.get("message") {
                    detail = m.clone();
                } else if let Some(data) = map.get("data") {
                    match pyops::contains(data, "detail") {
                        Ok(true) => match pyops::index(data, "detail") {
                            Ok(d) => detail = d,
                            Err(e) => return Ok(put_exception(endpoint, &e)),
                        },
                        Ok(false) => {}
                        Err(e) => return Ok(put_exception(endpoint, &e)),
                    }
                }
                let _ = json;
            }
            Ok(_) => {}
            Err(_) => detail = Value::String(reply.text()),
        }
        let detail_text = pyops::py_str(&detail);
        tracing::error!("HTTP error {}: {detail_text}", reply.status);
        let mut m = Map::new();
        m.insert("success".into(), Value::Bool(false));
        m.insert("status_code".into(), Value::from(reply.status));
        m.insert(
            "message".into(),
            Value::String(format!("HTTP error {}: {detail_text}", reply.status)),
        );
        m.insert("error_detail".into(), detail);
        m.insert("raw_response".into(), Value::String(reply.text()));
        return Ok(Value::Object(m));
    }
    match reply.json() {
        Ok(v) => Ok(ok(v, "Successfully retrieved data")),
        Err(e) => Ok(put_exception(endpoint, &e)),
    }
}

/// `send_delete_request(endpoint, params)`; `Value::Null` is its `None` (no
/// connector row). Every failure is a `{"success": False, …}` answer.
pub async fn send_delete(
    st: &WazuhState,
    endpoint: &str,
    params: Option<&[(String, Param)]>,
) -> Result<Value, PyErr> {
    tracing::info!("Sending DELETE request to {endpoint}");
    let http = &st.manager;
    let first_row = row(st).await?;
    let token = http.token(first_row.as_ref()).await;
    let Some(attributes) = row(st).await? else {
        tracing::error!("No Wazuh Manager connector found in the database");
        return Ok(Value::Null);
    };
    let Some(token) = token else {
        return Ok(auth_failed());
    };
    let url = format!("{}{endpoint}", attributes.connector_url);
    let query = params.map(texts).unwrap_or_default();
    let outcome: Result<Value, String> = async {
        let reply = http
            .send(Method::DELETE, &url, &query, &[bearer(&token)], None)
            .await?;
        reply.raise_for_status()?;
        Ok(ok(reply.json()?, "Successfully deleted data"))
    }
    .await;
    Ok(outcome.unwrap_or_else(|e| {
        tracing::error!("Failed to send DELETE request to {endpoint} with error: {e}");
        failure(format!(
            "Failed to send DELETE request to {endpoint} with error: {e}"
        ))
    }))
}

fn put_exception(endpoint: &str, e: &str) -> Value {
    tracing::error!("Failed to send PUT request to {endpoint}: {e}");
    let mut m = Map::new();
    m.insert("success".into(), Value::Bool(false));
    m.insert(
        "message".into(),
        Value::String(format!(
            "Failed to send PUT request to {endpoint} with error: {e}"
        )),
    );
    m.insert("exception".into(), Value::String(e.to_string()));
    Value::Object(m)
}

/// `restart_service()`.
pub async fn restart_service(st: &WazuhState) -> Result<Value, PyErr> {
    tracing::info!("Restarting Wazuh Manager service");
    let http = &st.manager;
    let first_row = row(st).await?;
    let token = http.token(first_row.as_ref()).await;
    let Some(attributes) = row(st).await? else {
        return Ok(Value::Null);
    };
    let Some(token) = token else {
        return Ok(auth_failed());
    };
    let url = format!("{}/manager/restart", attributes.connector_url);
    let outcome: Result<Value, String> = async {
        let reply = http
            .send(Method::PUT, &url, &[], &[bearer(&token)], None)
            .await?;
        reply.raise_for_status()?;
        Ok(ok(reply.json()?, "Successfully restarted service"))
    }
    .await;
    Ok(outcome.unwrap_or_else(|e| {
        failure(format!(
            "Failed to restart Wazuh Manager service with error: {e}"
        ))
    }))
}

/// `restart_wazuh_manager_service()`; `Err` with `PyErr::Other` where
/// Python's `.get` on an unexpected shape escapes.
pub async fn restart_wazuh_manager_service(st: &WazuhState) -> Result<Value, PyErr> {
    tracing::info!("Restarting Wazuh Manager service");
    let status = send_get(st, "/cluster/status", None).await?;
    let succeeded = pyops::get(&status, "success", Value::Null)
        .map(|v| pyops::truthy(&v))
        .unwrap_or(false);
    if !succeeded {
        return Ok(failure("Failed to get cluster status before restart"));
    }
    let enabled = pyops::get(&status, "data", json!({}))
        .and_then(|d| pyops::get(&d, "data", json!({})))
        .and_then(|d| pyops::get(&d, "enabled", json!("unknown")))
        .map_err(PyErr::Other)?;
    if enabled == json!("no") {
        return restart_service(st).await;
    }
    if enabled == json!("yes") {
        let response = send_put(
            st,
            "/cluster/restart",
            Some(Body::EmptyDict),
            None,
            PutKind::Json,
        )
        .await?;
        let succeeded = pyops::get(&response, "success", Value::Null).map_err(PyErr::Other)?;
        if pyops::truthy(&succeeded) {
            return Ok(json!({
                "success": true,
                "message": "Wazuh Manager cluster restarted successfully",
            }));
        }
        return Ok(response);
    }
    tracing::warn!(
        "Unknown cluster status: {}, defaulting to service restart",
        pyops::py_str(&enabled)
    );
    restart_service(st).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// The request head one `send` writes, read off a plain TCP listener.
    async fn head_of(method: Method) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            )
            .unwrap();
            String::from_utf8(buf).unwrap()
        });
        let http = ManagerHttp::new().unwrap();
        let url = format!("http://127.0.0.1:{port}/agents");
        http.send(method, &url, &[], &[], None).await.unwrap();
        server.join().unwrap()
    }

    fn content_lengths(head: &str) -> Vec<String> {
        head.lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .map(|l| l.to_ascii_lowercase())
            .collect()
    }

    #[tokio::test]
    async fn a_bodyless_request_carries_one_zero_content_length_but_get() {
        for method in [Method::DELETE, Method::PUT, Method::POST] {
            let head = head_of(method.clone()).await;
            assert_eq!(
                content_lengths(&head),
                ["content-length: 0"],
                "{method}: {head}"
            );
        }
        let head = head_of(Method::GET).await;
        assert!(content_lengths(&head).is_empty(), "GET: {head}");
    }
}
