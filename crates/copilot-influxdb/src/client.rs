//! The InfluxDB client — port of `app/connectors/influxdb/utils/universal.py`
//! and of the request `influxdb_client`'s `InfluxDBClientAsync` sends for a
//! Flux query.
//!
//! **Queries** ([`InfluxClient::query`]) go out exactly as the Python client
//! library sends them: `POST {connector_url}/api/v2/query?org=…` (one
//! trailing `/` of the URL dropped; the org `urlencode`d, then requoted the
//! way yarl does), `Accept`/`Content-Type: application/json`,
//! `Authorization: Token <key>` only when the key is non-empty,
//! `User-Agent: influxdb-client-python/1.50.0`, `Accept-Encoding: gzip,
//! deflate` (the answer is decompressed), and the body
//! `{"extern": {"imports": [], "body": []}, "query": …, "dialect": {…}}`
//! with `json.dumps`'s spacing. The client library's whole-request timeout
//! is 10 s, **certificates are not verified** (`verify_ssl=False`, as in
//! Python: InfluxDB in a SOCFortress stack serves a self-signed certificate)
//! and redirects are followed (10 at most). The answer is the annotated CSV
//! [`crate::flux`] parses.
//!
//! What fails reads as aiohttp and the library word it, because the
//! services put `str(e)` into their answers:
//!
//! | Failure | Python exception | `str(e)` |
//! |---|---|---|
//! | non-2xx status | `ApiException` | `({status})\nReason: …\nHTTP response headers: <CIMultiDictProxy(…)>\nHTTP response body: b'…'\n` |
//! | connection refused | `ClientConnectorError` | `Cannot connect to host h:p ssl:default [Connect call failed ('ip', p)]` |
//! | unknown host | `ClientConnectorDNSError` | `Cannot connect to host h:p ssl:default [Name or service not known]` |
//! | no or unknown scheme | `NonHttpUrlClientError` | the URL |
//! | no host, bad port | `InvalidUrlClientError` | the URL |
//! | no answer within 10 s | `TimeoutError` | (empty) |
//! | the body stalls past 10 s | `CancelledError` — not an `Exception`: no service catches it, the request is a bare 500 |
//!
//! The response headers in an `ApiException` are printed in the case aiohttp
//! shows them: its own spelling for the headers it knows, the wire's for
//! the rest — which, InfluxDB being a Go server, is the canonical
//! `X-Influxdb-Build` form this client rebuilds from the lower-cased names
//! `http` keeps.
//!
//! **REST calls** ([`InfluxClient::rest`], `_influxdb_request`: checks,
//! notification endpoints and rules, `/api/v2/orgs`) go out as httpx sends
//! them: `{url without trailing /}{endpoint}`, `Authorization: Token <key>`,
//! a 60 s timeout, certificates verified only with `INFLUXDB_VERIFY_SSL`;
//! a transport failure is `HTTPException(500, "Failed to reach InfluxDB:
//! …")`, a status ≥ 300 `HTTPException(500, "InfluxDB request failed
//! (status): body")`, an empty body `None`.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use copilot_auth::pyvalue::{PyValue, bytes_repr, str_repr};
use copilot_db::connectors::{ConnectorCache, ConnectorRow};
use copilot_upstream::json::{Dumps, py_dumps, py_loads};
use copilot_upstream::py::{PyExc, PyResult};
use http::Method;
use tokio::time::Instant;

use crate::flux::{FluxTable, parse_tables};

/// The connector's name.
pub const CONNECTOR: &str = "InfluxDB";
/// `influxdb_client`'s default `timeout` (10 000 ms, the whole request).
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// `_influxdb_request`'s httpx timeout.
pub const REST_TIMEOUT: Duration = Duration::from_secs(60);
/// The client library's `User-Agent`.
pub const USER_AGENT: &str = "influxdb-client-python/1.50.0";
/// `HTTPException` detail when the connector row is missing.
pub const NO_CONNECTOR: &str = "No InfluxDB connector found in the database";

/// The InfluxDB client.
#[derive(Debug, Clone)]
pub struct InfluxClient {
    connectors: ConnectorCache,
    flux: FluxHttp,
    rest_http: reqwest::Client,
}

/// The HTTP side of a Flux query (no database needed).
#[derive(Debug, Clone)]
pub struct FluxHttp {
    http: reqwest::Client,
    timeout: Duration,
}

/// What `create_influxdb_client` returned: the URL and token a query goes
/// to (the org of a query is passed with each one, as the services do).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FluxSession {
    /// `connector_url`.
    pub url: String,
    /// `connector_api_key`.
    pub token: Option<String>,
}

/// `os.getenv("INFLUXDB_VERIFY_SSL", "False").lower() in ("true", "1", "yes")`.
pub fn rest_verifies_tls() -> bool {
    std::env::var("INFLUXDB_VERIFY_SSL")
        .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

fn db_error(e: copilot_db::DbError) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

impl InfluxClient {
    /// A client reading the connector row through `connectors`.
    pub fn new(connectors: ConnectorCache) -> Result<Self, reqwest::Error> {
        let rest_http = reqwest::Client::builder()
            .danger_accept_invalid_certs(!rest_verifies_tls())
            .timeout(REST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self {
            connectors,
            flux: FluxHttp::new()?,
            rest_http,
        })
    }

    /// `get_connector_info_from_db("InfluxDB")`.
    pub async fn row(&self) -> PyResult<Option<ConnectorRow>> {
        self.connectors.get(CONNECTOR).await.map_err(db_error)
    }

    /// `get_influxdb_attributes()`: the row, or `HTTPException(500)`.
    pub async fn attributes(&self) -> PyResult<ConnectorRow> {
        self.row()
            .await?
            .ok_or_else(|| PyExc::http(500, NO_CONNECTOR))
    }

    /// `get_influxdb_organization()`: the first item of
    /// `connector_extra_data` (`ORG,BUCKET`), unstripped.
    pub async fn organization(&self) -> PyResult<String> {
        let row = self.attributes().await?;
        Ok(org_of(row.connector_extra_data.as_deref())?.to_string())
    }

    /// `get_influxdb_bucket()` (the `utils` one, raising `HTTPException`s).
    pub async fn bucket(&self) -> PyResult<String> {
        let row = self.attributes().await?;
        let extra = row.connector_extra_data.as_deref().ok_or_else(none_split)?;
        let parts: Vec<&str> = extra.split(',').collect();
        match parts.get(1) {
            Some(b) => Ok(copilot_web::form::py_strip(b).to_string()),
            None => Err(PyExc::http(
                500,
                "Invalid connector_extra_data format for InfluxDB. Expected 'ORG,BUCKET'.",
            )),
        }
    }

    /// `create_influxdb_client("InfluxDB")`: `HTTPException(500)` without a
    /// row; anything failing while the client is built (the org lookup) is
    /// wrapped as `HTTPException(500, "Failed to create InfluxDB client: …")`.
    pub async fn create_client(&self) -> PyResult<FluxSession> {
        let row = self.attributes().await?;
        if let Err(e) = self.organization().await {
            return Err(PyExc::http(
                500,
                format!("Failed to create InfluxDB client: {}", e.display()),
            ));
        }
        Ok(FluxSession {
            url: row.connector_url,
            token: row.connector_api_key,
        })
    }

    /// `client.query_api().query(flux, org=org)`: the tables.
    pub async fn query(
        &self,
        session: &FluxSession,
        flux: &str,
        org: &str,
    ) -> PyResult<Vec<FluxTable>> {
        self.flux.query(session, flux, org).await
    }

    /// `_influxdb_request(method, endpoint, params, data)`: the decoded JSON
    /// answer (`None` for an empty one).
    pub async fn rest(
        &self,
        method: Method,
        endpoint: &str,
        params: &[(String, String)],
        json: Option<&PyValue>,
    ) -> PyResult<PyValue> {
        let row = self.attributes().await?;
        let url = format!("{}{endpoint}", row.connector_url.trim_end_matches('/'));
        let key = row.connector_api_key.as_deref().unwrap_or("None");
        let reach = |e: String| PyExc::http(500, format!("Failed to reach InfluxDB: {e}"));
        let parsed = match url.split_once("://") {
            Some((scheme, _))
                if matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") =>
            {
                reqwest::Url::parse(&url).map_err(|e| reach(e.to_string()))?
            }
            Some((scheme, _)) if !scheme.is_empty() && !scheme.contains('/') => {
                return Err(reach(format!(
                    "Request URL has an unsupported protocol '{}://'.",
                    scheme.to_ascii_lowercase()
                )));
            }
            _ => {
                return Err(reach(
                    "Request URL is missing an 'http://' or 'https://' protocol.".into(),
                ));
            }
        };
        let mut builder = self
            .rest_http
            .request(method, parsed)
            .header(http::header::AUTHORIZATION, format!("Token {key}"))
            .header(http::header::CONTENT_TYPE, "application/json");
        if !params.is_empty() {
            builder = builder.query(params);
        }
        if let Some(body) = json {
            let text = py_dumps(body, Dumps::HTTPX).map_err(|e| reach(format!("{e}")))?;
            builder = builder.body(text);
        }
        let resp = builder.send().await.map_err(|e| {
            let chain = error_chain(&e);
            reach(if e.is_timeout() {
                String::new()
            } else if chain.contains("failed to lookup") || chain.contains("dns error") {
                "[Errno -2] Name or service not known".into()
            } else if e.is_connect() {
                "All connection attempts failed".into()
            } else {
                chain
            })
        })?;
        let status = resp.status().as_u16();
        let body = resp.bytes().await.map_err(|e| reach(error_chain(&e)))?;
        if status >= 300 {
            return Err(PyExc::http(
                500,
                format!(
                    "InfluxDB request failed ({status}): {}",
                    String::from_utf8_lossy(&body)
                ),
            ));
        }
        if body.is_empty() {
            return Ok(PyValue::None);
        }
        py_loads(&String::from_utf8_lossy(&body)).map_err(PyExc::JsonDecode)
    }

    /// `get_influxdb_org_id()`: the id of the org the connector names.
    pub async fn org_id(&self) -> PyResult<String> {
        let org = self.organization().await?;
        let answer = self
            .rest(
                Method::GET,
                "/api/v2/orgs",
                &[("org".to_string(), org.clone())],
                None,
            )
            .await?;
        if let PyValue::Dict(_) = &answer {
            if let Some(PyValue::List(orgs)) = answer.get("orgs") {
                for o in orgs {
                    if o.get("name").and_then(PyValue::as_str) == Some(org.as_str()) {
                        if let Some(id) = o.get("id") {
                            return Ok(id.py_str());
                        }
                    }
                }
            }
        }
        Err(PyExc::http(
            404,
            format!("InfluxDB organization {org} not found"),
        ))
    }
}

impl InfluxClient {
    /// `client.ping()`: see [`FluxHttp::ping`].
    pub async fn ping(&self, session: &FluxSession) -> PyResult<()> {
        self.flux.ping(session).await
    }
}

impl FluxHttp {
    /// `client.ping()` (`PingService.get_ping_async()`): `GET {url}/ping`
    /// with the client's default headers (the token — or the URL's
    /// credentials —, the user agent), the REST client's `Content-Type` and
    /// aiohttp's `Accept: */*` and `Accept-Encoding`; a non-2xx answer is the `ApiException`, a transport
    /// failure aiohttp's, the 10 s whole-request timeout the `TimeoutError`.
    pub async fn ping(&self, session: &FluxSession) -> PyResult<()> {
        let deadline = Instant::now() + self.timeout;
        let base = session.url.strip_suffix('/').unwrap_or(&session.url);
        let url = format!("{base}/ping");
        let token = session.token.as_deref().filter(|t| !t.is_empty());
        let target = aiohttp_target(&url)?;
        if target.userinfo.is_some() && token.is_some() {
            return Err(PyExc::ValueError(
                "Cannot combine AUTHORIZATION header with AUTH argument or credentials encoded \
                 in URL"
                    .into(),
            ));
        }
        let mut builder = self.http.request(Method::GET, target.url.clone());
        if let Some(t) = token {
            builder = builder.header(http::header::AUTHORIZATION, format!("Token {t}"));
        } else if let Some((user, password)) = &target.userinfo {
            builder = builder.header(http::header::AUTHORIZATION, basic(user, password));
        }
        // The REST client adds `Content-Type: application/json` after the
        // default headers; aiohttp adds `Accept` and `Accept-Encoding`.
        let builder = builder
            .header(http::header::USER_AGENT, USER_AGENT)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::ACCEPT, "*/*")
            .header(http::header::ACCEPT_ENCODING, "gzip, deflate");
        let send = async {
            let addrs = resolve(&target).await?;
            builder
                .send()
                .await
                .map_err(|e| transport_error(&e, &target, &addrs))
        };
        let resp = match tokio::time::timeout_at(deadline, send).await {
            Ok(r) => r?,
            Err(_) => return Err(PyExc::Other("TimeoutError", String::new())),
        };
        let status = resp.status();
        let reason = resp
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
            .unwrap_or_else(|| status.canonical_reason().unwrap_or("").to_string());
        let headers = resp.headers().clone();
        let raw = match tokio::time::timeout_at(deadline, resp.bytes()).await {
            Ok(Ok(b)) => b,
            Ok(Err(_)) => {
                return Err(PyExc::Other(
                    "ClientPayloadError",
                    "Response payload is not completed".into(),
                ));
            }
            Err(_) => return Err(PyExc::Other("CancelledError", String::new())),
        };
        let body = decode_content(&headers, &raw)?;
        if !status.is_success() {
            return Err(api_exception(status.as_u16(), &reason, &headers, &body));
        }
        Ok(())
    }

    /// The client library's transport: no certificate verification, no
    /// proxies, 10 redirects, the 10 s whole-request timeout.
    pub fn new() -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .no_proxy()
            .build()?;
        Ok(Self {
            http,
            timeout: QUERY_TIMEOUT,
        })
    }

    /// Another whole-request timeout (tests; production keeps 10 s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// `client.query_api().query(flux, org=org)`: the tables.
    pub async fn query(
        &self,
        session: &FluxSession,
        flux: &str,
        org: &str,
    ) -> PyResult<Vec<FluxTable>> {
        let deadline = Instant::now() + self.timeout;
        let url = query_url(&session.url, org);
        let token = session.token.as_deref().filter(|t| !t.is_empty());
        let target = aiohttp_target(&url)?;
        if target.userinfo.is_some() && token.is_some() {
            return Err(PyExc::ValueError(
                "Cannot combine AUTHORIZATION header with AUTH argument or credentials encoded \
                 in URL"
                    .into(),
            ));
        }
        let body = query_body(flux);
        let mut builder = self
            .http
            .request(Method::POST, target.url.clone())
            .header(http::header::ACCEPT, "application/json")
            .header(http::header::CONTENT_TYPE, "application/json");
        if let Some(t) = token {
            builder = builder.header(http::header::AUTHORIZATION, format!("Token {t}"));
        } else if let Some((user, password)) = &target.userinfo {
            builder = builder.header(http::header::AUTHORIZATION, basic(user, password));
        }
        let builder = builder
            .header(http::header::USER_AGENT, USER_AGENT)
            .header(http::header::ACCEPT_ENCODING, "gzip, deflate")
            .body(body);
        let send = async {
            let addrs = resolve(&target).await?;
            builder
                .send()
                .await
                .map_err(|e| transport_error(&e, &target, &addrs))
        };
        let resp = match tokio::time::timeout_at(deadline, send).await {
            Ok(r) => r?,
            Err(_) => return Err(PyExc::Other("TimeoutError", String::new())),
        };
        let status = resp.status();
        let reason = resp
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
            .unwrap_or_else(|| status.canonical_reason().unwrap_or("").to_string());
        let headers = resp.headers().clone();
        let raw = match tokio::time::timeout_at(deadline, resp.bytes()).await {
            Ok(Ok(b)) => b,
            Ok(Err(_)) => {
                return Err(PyExc::Other(
                    "ClientPayloadError",
                    "Response payload is not completed".into(),
                ));
            }
            // aiohttp's timer cancels the task while it reads the body.
            Err(_) => return Err(PyExc::Other("CancelledError", String::new())),
        };
        let body = decode_content(&headers, &raw)?;
        if !status.is_success() {
            return Err(api_exception(status.as_u16(), &reason, &headers, &body));
        }
        let text = utf8(&body)?;
        parse_tables(&text)
    }
}

fn none_split() -> PyExc {
    PyExc::AttributeError("'NoneType' object has no attribute 'split'".into())
}

/// `connector_extra_data.split(",")[0]`.
pub fn org_of(extra: Option<&str>) -> PyResult<&str> {
    let extra = extra.ok_or_else(none_split)?;
    Ok(extra.split(',').next().unwrap_or(""))
}

/// `{url minus one trailing /}/api/v2/query?org=…`: `urlencode` (spaces as
/// `+`), then yarl's requoting, which decodes again what a query may carry
/// (`/?:@!$'()*,`) and keeps `&=+;` and everything else escaped.
pub fn query_url(url: &str, org: &str) -> String {
    let base = url.strip_suffix('/').unwrap_or(url);
    let mut q = String::new();
    for b in org.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                q.push(char::from(b));
            }
            b' ' => q.push('+'),
            b'?' | b'/' | b':' | b'@' | b'!' | b'$' | b'\'' | b'(' | b')' | b'*' | b',' => {
                q.push(char::from(b));
            }
            other => q.push_str(&format!("%{other:02X}")),
        }
    }
    format!("{base}/api/v2/query?org={q}")
}

/// The request body (`Query(query=…, dialect=default_dialect, extern=File())`).
pub fn query_body(flux: &str) -> String {
    let s = |v: &str| PyValue::Str(v.into());
    let body = PyValue::Dict(vec![
        (
            "extern".into(),
            PyValue::Dict(vec![
                ("imports".into(), PyValue::List(Vec::new())),
                ("body".into(), PyValue::List(Vec::new())),
            ]),
        ),
        ("query".into(), s(flux)),
        (
            "dialect".into(),
            PyValue::Dict(vec![
                ("header".into(), PyValue::Bool(true)),
                ("delimiter".into(), s(",")),
                (
                    "annotations".into(),
                    PyValue::List(vec![s("datatype"), s("group"), s("default")]),
                ),
                ("commentPrefix".into(), s("#")),
                ("dateTimeFormat".into(), s("RFC3339")),
            ]),
        ),
    ]);
    py_dumps(&body, Dumps::DEFAULT).unwrap_or_default()
}

/// Where a query goes once aiohttp has checked the URL.
#[derive(Debug, Clone)]
struct Target {
    url: reqwest::Url,
    host: String,
    port: u16,
    userinfo: Option<(String, String)>,
}

fn invalid_url(text: &str) -> PyExc {
    PyExc::Other("InvalidUrlClientError", text.to_string())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (
                b.get(i + 1).and_then(|c| char::from(*c).to_digit(16)),
                b.get(i + 2).and_then(|c| char::from(*c).to_digit(16)),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// aiohttp's checks of a request URL, in its order: yarl's parse
/// (`ValueError` → `InvalidUrlClientError` naming the URL as given), a
/// scheme it does not speak (`NonHttpUrlClientError`), no host
/// (`InvalidUrlClientError`).
fn aiohttp_target(raw: &str) -> PyResult<Target> {
    let s: String = raw
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let (scheme, rest) = match s.find(':') {
        Some(i)
            if i > 0
                && s[..i]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
        {
            (s[..i].to_ascii_lowercase(), &s[i + 1..])
        }
        _ => (String::new(), s.as_str()),
    };
    let (netloc, path) = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            (Some(&after[..end]), &after[end..])
        }
        None => (None, rest),
    };
    let special = matches!(scheme.as_str(), "http" | "https" | "ws" | "wss");
    let mut host = String::new();
    let mut port = None;
    let mut userinfo = None;
    if let Some(netloc) = netloc {
        if netloc.contains('[') != netloc.contains(']') {
            return Err(invalid_url(raw));
        }
        let (info, hostport) = match netloc.rfind('@') {
            Some(i) => (Some(&netloc[..i]), &netloc[i + 1..]),
            None => (None, netloc),
        };
        let (h, p) = if let Some(inner) = hostport.strip_prefix('[') {
            let Some(close) = inner.find(']') else {
                return Err(invalid_url(raw));
            };
            let after = &inner[close + 1..];
            let p = match after.strip_prefix(':') {
                Some(p) => Some(p),
                None if after.is_empty() => None,
                None => return Err(invalid_url(raw)),
            };
            (&inner[..close], p)
        } else {
            match hostport.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (hostport, None),
            }
        };
        if let Some(p) = p.filter(|p| !p.is_empty()) {
            if !p.chars().all(|c| c.is_ascii_digit()) {
                return Err(invalid_url(raw));
            }
            match p.parse::<u32>() {
                Ok(n) if n <= 65535 => port = Some(n as u16),
                _ => return Err(invalid_url(raw)),
            }
        }
        if special && h.is_empty() && (info.is_some() || p.is_some()) {
            return Err(invalid_url(raw));
        }
        host = h.to_lowercase();
        userinfo = info.map(|i| match i.split_once(':') {
            Some((u, pw)) => (percent_decode(u), percent_decode(pw)),
            None => (percent_decode(i), String::new()),
        });
    }
    if !matches!(scheme.as_str(), "" | "http" | "https" | "ws" | "wss") {
        return Err(PyExc::Other(
            "NonHttpUrlClientError",
            format!("{scheme}:{rest}"),
        ));
    }
    if host.is_empty() {
        let text = if scheme.is_empty() {
            s.clone()
        } else if netloc.is_some() || path.starts_with('/') {
            format!("{scheme}://{}{path}", netloc.unwrap_or(""))
        } else {
            format!("{scheme}:///{path}")
        };
        return Err(invalid_url(&text));
    }
    let tls = matches!(scheme.as_str(), "https" | "wss");
    let port = port.unwrap_or(if tls { 443 } else { 80 });
    let host_in_url = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let url = format!(
        "{}://{host_in_url}:{port}{}",
        if tls { "https" } else { "http" },
        if path.starts_with('/') || path.is_empty() {
            path.to_string()
        } else {
            format!("/{path}")
        }
    );
    let url = reqwest::Url::parse(&url).map_err(|_| invalid_url(raw))?;
    Ok(Target {
        url,
        host,
        port,
        userinfo,
    })
}

fn basic(user: &str, password: &str) -> String {
    use base64::Engine as _;
    let raw: Vec<u8> = format!("{user}:{password}")
        .chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
        .collect();
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

fn connector_error(target: &Target, strerror: &str) -> PyExc {
    PyExc::Other(
        "ClientConnectorError",
        format!(
            "Cannot connect to host {}:{} ssl:default [{strerror}]",
            target.host, target.port
        ),
    )
}

/// The addresses aiohttp would connect to (a DNS failure is its
/// `ClientConnectorDNSError`).
async fn resolve(target: &Target) -> PyResult<Vec<SocketAddr>> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, target.port)]);
    }
    match tokio::net::lookup_host((target.host.as_str(), target.port)).await {
        Ok(addrs) => Ok(addrs.collect()),
        Err(e) => {
            let text = e.to_string();
            let reason = text
                .strip_prefix("failed to lookup address information: ")
                .unwrap_or(&text)
                .to_string();
            Err(connector_error(target, &reason))
        }
    }
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(s) = source {
        parts.push(s.to_string());
        source = s.source();
    }
    parts.join(": ")
}

fn address_text(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(a) => format!("({}, {})", str_repr(&a.ip().to_string()), a.port()),
        SocketAddr::V6(a) => format!(
            "({}, {}, {}, {})",
            str_repr(&a.ip().to_string()),
            a.port(),
            a.flowinfo(),
            a.scope_id()
        ),
    }
}

fn transport_error(e: &reqwest::Error, target: &Target, addrs: &[SocketAddr]) -> PyExc {
    let chain = error_chain(e);
    if e.is_connect() {
        if chain.contains("Address family not supported") {
            return connector_error(target, "Address family not supported by protocol");
        }
        let addr = addrs
            .first()
            .copied()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], target.port)));
        return connector_error(
            target,
            &format!("Connect call failed {}", address_text(&addr)),
        );
    }
    if chain.contains("connection closed before message completed")
        || chain.contains("IncompleteMessage")
        || chain.contains("connection reset")
    {
        return PyExc::Other("ServerDisconnectedError", "Server disconnected".into());
    }
    if e.is_redirect() {
        return PyExc::Other("TooManyRedirects", chain);
    }
    PyExc::Other("ClientError", chain)
}

/// The body as aiohttp hands it over: `gzip`/`deflate` decoded.
fn decode_content(headers: &http::HeaderMap, raw: &[u8]) -> PyResult<Vec<u8>> {
    let encoding = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let failed = || {
        PyExc::Other(
            "ClientPayloadError",
            format!("400, message='Can not decode content-encoding: {encoding}'"),
        )
    };
    let mut out = Vec::new();
    match encoding.as_str() {
        "gzip" | "x-gzip" => {
            flate2::read::MultiGzDecoder::new(raw)
                .read_to_end(&mut out)
                .map_err(|_| failed())?;
        }
        "deflate" => {
            let zlib = raw.len() >= 2
                && raw[0] & 0x0f == 8
                && (u16::from(raw[0]) * 256 + u16::from(raw[1])) % 31 == 0;
            let result = if zlib {
                flate2::read::ZlibDecoder::new(raw).read_to_end(&mut out)
            } else {
                flate2::read::DeflateDecoder::new(raw).read_to_end(&mut out)
            };
            result.map_err(|_| failed())?;
        }
        _ => out = raw.to_vec(),
    }
    Ok(out)
}

/// The UTF-8 text (`UnicodeDecodeError` as Python words it).
fn utf8(body: &[u8]) -> PyResult<String> {
    match std::str::from_utf8(body) {
        Ok(s) => Ok(s.to_string()),
        Err(e) => {
            let start = e.valid_up_to();
            let (from, to, reason) = match e.error_len() {
                Some(n) => {
                    let first = body[start];
                    let reason = if (0x80..=0xC1).contains(&first) || first >= 0xF5 {
                        "invalid start byte"
                    } else {
                        "invalid continuation byte"
                    };
                    (start, start + n - 1, reason)
                }
                // The incremental decoder holds the incomplete tail back
                // and fails on it alone at the end.
                None => (0, body.len() - start - 1, "unexpected end of data"),
            };
            let text = if from == to {
                format!(
                    "'utf-8' codec can't decode byte 0x{:02x} in position {from}: {reason}",
                    body[start]
                )
            } else {
                format!("'utf-8' codec can't decode bytes in position {from}-{to}: {reason}")
            };
            Err(PyExc::Other("UnicodeDecodeError", text))
        }
    }
}

/// aiohttp's spelling of the headers it knows whose canonical Go form
/// differs (`aiohttp.hdrs`).
const AIOHTTP_SPELLINGS: [&str; 11] = [
    "Content-MD5",
    "Last-Event-ID",
    "Sec-WebSocket-Accept",
    "Sec-WebSocket-Extensions",
    "Sec-WebSocket-Key",
    "Sec-WebSocket-Key1",
    "Sec-WebSocket-Protocol",
    "Sec-WebSocket-Version",
    "TE",
    "URI",
    "WWW-Authenticate",
];

/// A lower-cased header name in the case aiohttp shows it.
pub fn header_case(name: &str) -> String {
    if let Some(known) = AIOHTTP_SPELLINGS
        .iter()
        .find(|k| k.eq_ignore_ascii_case(name))
    {
        return (*known).to_string();
    }
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for c in name.chars() {
        out.push(if upper {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        });
        upper = c == '-';
    }
    out
}

/// `str(ApiException(http_resp=…))`.
pub fn api_exception(status: u16, reason: &str, headers: &http::HeaderMap, body: &[u8]) -> PyExc {
    let mut text = format!("({status})\nReason: {reason}\n");
    if !headers.is_empty() {
        let items: Vec<String> = headers
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}: {}",
                    str_repr(&header_case(k.as_str())),
                    str_repr(&String::from_utf8_lossy(v.as_bytes()))
                )
            })
            .collect();
        text.push_str(&format!(
            "HTTP response headers: <CIMultiDictProxy({})>\n",
            items.join(", ")
        ));
    }
    if !body.is_empty() {
        text.push_str(&format!("HTTP response body: {}\n", bytes_repr(body)));
    }
    PyExc::Other("ApiException", text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_is_encoded_like_yarl_requotes_urlencode() {
        for (org, want) in [
            ("SOCFORTRESS", "org=SOCFORTRESS"),
            ("SOC FORTRESS", "org=SOC+FORTRESS"),
            ("a&b=c+d", "org=a%26b%3Dc%2Bd"),
            ("é/?#%41", "org=%C3%A9/?%23%2541"),
            ("~*!$'()*,;:@[]", "org=~*!$'()*,%3B:@%5B%5D"),
            ("a%2Fb", "org=a%252Fb"),
            ("x\u{0}y", "org=x%00y"),
            ("", "org="),
        ] {
            assert_eq!(
                query_url("http://h:1/", org),
                format!("http://h:1/api/v2/query?{want}"),
                "{org:?}"
            );
        }
        assert_eq!(
            query_url("http://h:1//", "o"),
            "http://h:1//api/v2/query?org=o"
        );
    }

    #[test]
    fn the_body_is_json_dumps_of_the_query() {
        assert_eq!(
            query_body("from(bucket: \"x\") é"),
            "{\"extern\": {\"imports\": [], \"body\": []}, \"query\": \"from(bucket: \\\"x\\\") \
             \\u00e9\", \"dialect\": {\"header\": true, \"delimiter\": \",\", \"annotations\": \
             [\"datatype\", \"group\", \"default\"], \"commentPrefix\": \"#\", \
             \"dateTimeFormat\": \"RFC3339\"}}"
        );
    }

    #[test]
    fn urls_fail_as_aiohttp_checks_them() {
        let text = |u: &str| aiohttp_target(u).map(|_| ()).unwrap_err().text();
        assert_eq!(
            text("127.0.0.1:5691/api/v2/query?org=SOC"),
            "127.0.0.1:5691/api/v2/query?org=SOC"
        );
        assert_eq!(text("/api/v2/query?org=SOC"), "/api/v2/query?org=SOC");
        assert_eq!(
            text("http://127.0.0.1:99999/api/v2/query?org=SOC"),
            "http://127.0.0.1:99999/api/v2/query?org=SOC"
        );
        assert_eq!(
            text("ftp://127.0.0.1/api/v2/query?org=SOC"),
            "ftp://127.0.0.1/api/v2/query?org=SOC"
        );
        assert_eq!(
            text("http://[::1/api/v2/query?org=SOC"),
            "http://[::1/api/v2/query?org=SOC"
        );
        assert_eq!(
            text("http:127.0.0.1:1/api/v2/query?org=SOC"),
            "http:///127.0.0.1:1/api/v2/query?org=SOC"
        );
        let t = aiohttp_target("HTTP://User:p%40ss@H.Example:8086/api/v2/query?org=S").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("h.example", 8086));
        assert_eq!(t.userinfo, Some(("User".into(), "p@ss".into())));
        assert_eq!(t.url.as_str(), "http://h.example:8086/api/v2/query?org=S");
        let t = aiohttp_target(" https://[::1]/x").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 443));
    }

    #[test]
    fn api_exceptions_print_like_the_library() {
        let mut h = http::HeaderMap::new();
        h.insert("content-type", "application/json".parse().unwrap());
        h.insert("x-influxdb-build", "OSS".parse().unwrap());
        h.insert("www-authenticate", "Token".parse().unwrap());
        assert_eq!(
            api_exception(401, "Unauthorized", &h, b"{\"code\":\"x\"}").text(),
            "(401)\nReason: Unauthorized\nHTTP response headers: <CIMultiDictProxy('Content-Type': \
             'application/json', 'X-Influxdb-Build': 'OSS', 'WWW-Authenticate': 'Token')>\nHTTP \
             response body: b'{\"code\":\"x\"}'\n"
        );
        assert_eq!(
            api_exception(500, "Whatever", &http::HeaderMap::new(), b"").text(),
            "(500)\nReason: Whatever\n"
        );
    }

    async fn raw_server(answer: &'static [u8]) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket.write_all(answer).await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });
        format!("http://{addr}")
    }

    fn client() -> FluxHttp {
        FluxHttp::new()
            .unwrap()
            .with_timeout(Duration::from_millis(300))
    }

    #[tokio::test]
    async fn the_deadline_covers_the_whole_request() {
        let silent = raw_server(b"").await;
        let session = FluxSession {
            url: silent,
            token: Some("t".into()),
        };
        let e = client().query(&session, "x", "o").await.unwrap_err();
        assert_eq!(e, PyExc::Other("TimeoutError", String::new()));
        // Headers in time, the body not: aiohttp's timer cancels the task,
        // which no `except Exception` catches.
        let stalled = raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/csv\r\nContent-Length: 100\r\n\r\n#datatype",
        )
        .await;
        let session = FluxSession {
            url: stalled,
            token: None,
        };
        let e = client().query(&session, "x", "o").await.unwrap_err();
        assert_eq!(e, PyExc::Other("CancelledError", String::new()));
        let custom = raw_server(b"HTTP/1.1 500 Whatever\r\nContent-Length: 0\r\n\r\n").await;
        let session = FluxSession {
            url: custom,
            token: None,
        };
        assert_eq!(
            client().query(&session, "x", "o").await.unwrap_err().text(),
            "(500)\nReason: Whatever\nHTTP response headers: <CIMultiDictProxy('Content-Length': \
             '0')>\n"
        );
    }

    #[test]
    fn decoding_errors_read_like_python() {
        assert_eq!(
            utf8(b"\xff\xfe").unwrap_err().text(),
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
        );
        assert_eq!(
            utf8(b"ab\xe2\x82x").unwrap_err().text(),
            "'utf-8' codec can't decode bytes in position 2-3: invalid continuation byte"
        );
        assert_eq!(
            utf8(b"abc\xe2").unwrap_err().text(),
            "'utf-8' codec can't decode byte 0xe2 in position 0: unexpected end of data"
        );
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            enc.write_all(b"#datatype").unwrap();
        }
        let mut h = http::HeaderMap::new();
        h.insert("content-encoding", "gzip".parse().unwrap());
        assert_eq!(decode_content(&h, &gz).unwrap(), b"#datatype");
    }
}
