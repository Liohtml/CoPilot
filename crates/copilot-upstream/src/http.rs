//! Outbound HTTP the way Python's `requests` (and its fork `niquests`, which
//! `grafana_client` uses) sends it — and fails.
//!
//! The connector helpers build their URL by concatenation
//! (`f"{connector_url}{endpoint}"`), pass `params=`, `auth=(user, password)`
//! and `json=`, and put `str(e)` of whatever went wrong into their answers.
//! [`PyRequest`] carries exactly those inputs; [`PyHttp::send`] prepares the
//! request as `PreparedRequest` does (URL checks and their exceptions, the
//! query appended with `urlencode`, HTTP Basic over latin-1, the body as
//! `json.dumps`) and words transport failures as urllib3 does:
//!
//! ```text
//! HTTPConnectionPool(host='127.0.0.1', port=1): Max retries exceeded with url: /api/system
//! (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x…>: Failed to
//! establish a new connection: [Errno 111] Connection refused'))
//! ```
//!
//! The one part that cannot match is that object's memory address, which
//! differs between any two Python processes too ([`OBJECT_ADDRESS`]).
//!
//! TLS certificates are **not verified** when the Python helper passed
//! `verify=False` (Graylog, Portainer, Grafana `?verify=false`): the tools
//! of a SOCFortress stack serve self-signed certificates, and the Rust port
//! keeps the deployment working exactly as before.

use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use copilot_auth::pyvalue::{PyValue, str_repr};
use http::{HeaderMap, Method};

use crate::json::{Dumps, py_dumps, py_loads};
use crate::py::PyExc;

/// Stands in for the memory address urllib3 prints in a connection error
/// (`<urllib3.connection.HTTPConnection object at 0x…>`).
pub const OBJECT_ADDRESS: &str = "0x7f0000000000";

/// One request, as the Python helper described it.
#[derive(Debug, Clone)]
pub struct PyRequest {
    /// Method.
    pub method: Method,
    /// The URL string the helper built (`f"{base}{endpoint}"`), unchanged.
    pub url: String,
    /// `params=` (already `str()`-ed), appended with `urlencode`.
    pub params: Vec<(String, String)>,
    /// Extra headers, in order.
    pub headers: Vec<(String, String)>,
    /// `auth=(user, password)` (`None` becomes `"None"`, as `str(None)`).
    pub basic_auth: Option<(Option<String>, Option<String>)>,
    /// `json=` (a value; `None` sends no body).
    pub json: Option<PyValue>,
    /// How the client library serializes `json=`.
    pub dumps: Dumps,
}

impl PyRequest {
    /// A request without body, params or auth.
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            params: Vec::new(),
            headers: Vec::new(),
            basic_auth: None,
            json: None,
            dumps: Dumps::DEFAULT,
        }
    }

    /// Add a header.
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    /// `auth=(user, password)`.
    pub fn basic(mut self, user: Option<String>, password: Option<String>) -> Self {
        self.basic_auth = Some((user, password));
        self
    }

    /// `params=`.
    pub fn params(mut self, params: Vec<(String, String)>) -> Self {
        self.params = params;
        self
    }

    /// `json=`.
    pub fn json(mut self, body: Option<PyValue>) -> Self {
        self.json = body;
        self
    }
}

/// A response, read whole.
#[derive(Debug, Clone)]
pub struct PyResponse {
    /// Status code.
    pub status: u16,
    /// Headers.
    pub headers: HeaderMap,
    /// Body bytes.
    pub body: Bytes,
}

impl PyResponse {
    /// `requests`' `Response.encoding` (`get_encoding_from_headers`).
    fn encoding(&self) -> Option<String> {
        let ct = self
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())?
            .to_string();
        let mut parts = ct.split(';');
        let main = parts.next().unwrap_or_default().trim().to_string();
        for p in parts {
            let p = p.trim();
            if let Some((k, v)) = p.split_once('=') {
                if k.trim().eq_ignore_ascii_case("charset") {
                    return Some(v.trim().trim_matches(['\'', '"']).to_string());
                }
            }
        }
        if main.contains("text") {
            return Some("ISO-8859-1".into());
        }
        if main.contains("application/json") {
            return Some("utf-8".into());
        }
        None
    }

    /// `response.text`.
    pub fn text(&self) -> String {
        match self.encoding().map(|e| e.to_ascii_lowercase()) {
            Some(e) if e == "iso-8859-1" || e == "latin-1" || e == "latin1" => {
                self.body.iter().map(|b| char::from(*b)).collect()
            }
            _ => String::from_utf8_lossy(&self.body).into_owned(),
        }
    }

    /// `response.json()`: the value, or `requests.JSONDecodeError`.
    pub fn json(&self) -> Result<PyValue, PyExc> {
        py_loads(&self.text()).map_err(PyExc::JsonDecode)
    }

    /// `response.status_code < 400` and similar checks read this.
    pub fn status(&self) -> u16 {
        self.status
    }
}

/// Which Python client library is being reproduced. Both run on the
/// urllib3-future the backend installs (it replaces `urllib3`), so they fail
/// alike; they differ in what they put on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// `requests` 2.33: `json=` as `application/json`, Basic over latin-1.
    Requests,
    /// `niquests` 3.18 (`grafana_client`): `json=` as
    /// `application/json;charset=utf-8`, Basic over UTF-8.
    Niquests,
}

/// A `requests`-like client.
#[derive(Debug, Clone)]
pub struct PyHttp {
    client: reqwest::Client,
    timeout_text: String,
    flavor: Flavor,
}

/// Parsed parts of an HTTP(S) URL (`urllib3.util.parse_url`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Parts {
    scheme: String,
    auth: Option<String>,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

impl PyHttp {
    /// A client with `requests`' `timeout=` (connect and read) that does
    /// not verify certificates when `verify` is false.
    pub fn new(timeout: Duration, verify: bool) -> Result<Self, reqwest::Error> {
        Self::build(timeout, verify, Flavor::Requests)
    }

    /// The same for `niquests` ([`Flavor::Niquests`]).
    pub fn niquests(timeout: Duration, verify: bool) -> Result<Self, reqwest::Error> {
        Self::build(timeout, verify, Flavor::Niquests)
    }

    fn build(timeout: Duration, verify: bool, flavor: Flavor) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!verify)
            .connect_timeout(timeout)
            .read_timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(30))
            .user_agent(match flavor {
                Flavor::Requests => "python-requests/2.33.1",
                Flavor::Niquests => "niquests/3.18.7",
            })
            .no_proxy()
            .build()?;
        Ok(Self {
            client,
            timeout_text: timeout_text(timeout),
            flavor,
        })
    }

    /// How Python wrote the timeout (`5.0` for a float, `60` for an int),
    /// which urllib3's timeout errors print.
    pub fn with_timeout_text(mut self, text: impl Into<String>) -> Self {
        self.timeout_text = text.into();
        self
    }

    /// Send `req` the way `requests.request(...)` does.
    pub async fn send(&self, req: PyRequest) -> Result<PyResponse, PyExc> {
        let url = prepare_url(&req.url, &req.params)?;
        let body = match &req.json {
            None => None,
            Some(v) => Some(
                py_dumps(v, req.dumps)
                    .map_err(|e| PyExc::Other("InvalidJSONError", format!("{e}")))?,
            ),
        };
        let auth = match &req.basic_auth {
            None => None,
            Some((user, password)) => {
                let (user, password) = (
                    user.as_deref().unwrap_or("None"),
                    password.as_deref().unwrap_or("None"),
                );
                Some(match self.flavor {
                    Flavor::Requests => basic_auth(user, password)?,
                    Flavor::Niquests => format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD
                            .encode(format!("{user}:{password}"))
                    ),
                })
            }
        };
        let Some(parts) = url.parts else {
            return Err(PyExc::Other(
                "InvalidSchema",
                format!(
                    "No connection adapters were found for {}",
                    str_repr(&url.url)
                ),
            ));
        };
        let mut builder = self.client.request(req.method.clone(), &url.url);
        // Both libraries' session defaults; the answer is decoded below.
        if !req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
        {
            builder = builder.header(http::header::ACCEPT_ENCODING, "gzip, deflate");
        }
        for (k, v) in &req.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        if let Some(a) = auth {
            builder = builder.header(http::header::AUTHORIZATION, a);
        }
        match body {
            Some(b) => {
                let content_type = match self.flavor {
                    Flavor::Requests => "application/json",
                    Flavor::Niquests => "application/json;charset=utf-8",
                };
                builder = builder
                    .header(http::header::CONTENT_TYPE, content_type)
                    .body(b.into_bytes());
            }
            None => {
                // `prepare_content_length`: every method but GET and HEAD
                // says `Content-Length: 0` when there is no body.
                if req.method != Method::GET && req.method != Method::HEAD {
                    builder = builder.header(http::header::CONTENT_LENGTH, "0");
                }
            }
        }
        let resp = match builder.send().await {
            Ok(r) => r,
            Err(e) => return Err(self.transport_error(&e, &parts)),
        };
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => return Err(self.transport_error(&e, &parts)),
        };
        let body = decode_content(&headers, body)?;
        Ok(PyResponse {
            status,
            headers,
            body,
        })
    }

    fn transport_error(&self, e: &reqwest::Error, parts: &Parts) -> PyExc {
        let https = parts.scheme == "https";
        let pool = format!(
            "{}ConnectionPool(host={}, port={})",
            if https { "HTTPS" } else { "HTTP" },
            str_repr(&parts.host.to_ascii_lowercase()),
            parts.port.unwrap_or(if https { 443 } else { 80 })
        );
        let conn = format!(
            "<urllib3.connection.{}Connection object at {OBJECT_ADDRESS}>",
            if https { "HTTPS" } else { "HTTP" }
        );
        let url = {
            let mut u = if parts.path.is_empty() {
                "/".to_string()
            } else {
                parts.path.clone()
            };
            if let Some(q) = &parts.query {
                u.push('?');
                u.push_str(q);
            }
            u
        };
        let secs = self.timeout_text.clone();
        let chain = error_chain(e);
        if e.is_timeout() {
            if e.is_connect() {
                return PyExc::Other(
                    "ConnectTimeout",
                    format!(
                        "{pool}: Max retries exceeded with url: {url} (Caused by \
                         ConnectTimeoutError({conn}, 'Connection to {} timed out. (connect \
                         timeout={secs})'))",
                        parts.host
                    ),
                );
            }
            return PyExc::Other(
                "ReadTimeout",
                format!("{pool}: Read timed out. (read timeout={secs})"),
            );
        }
        if e.is_connect() {
            let reason = if chain.contains("Connection refused") {
                "[Errno 111] Connection refused".to_string()
            } else if chain.contains("dns error") || chain.contains("failed to lookup") {
                // urllib3-future's resolver: the resolver's sentence, the
                // name, and how many resolvers it asked.
                let reason = chain
                    .split("failed to lookup address information: ")
                    .nth(1)
                    .map(|r| r.split(": ").next().unwrap_or(r))
                    .unwrap_or("Name or service not known");
                let host = parts.host.to_ascii_lowercase();
                return PyExc::Other(
                    "ConnectionError",
                    format!(
                        "{pool}: Max retries exceeded with url: {url} (Caused by \
                         NameResolutionError(\"{conn}: Failed to resolve '{host}' ({reason}: \
                         {host} using 1 resolver(s))\"))"
                    ),
                );
            } else if chain.contains("No route to host") {
                "[Errno 113] No route to host".to_string()
            } else if chain.contains("Network is unreachable") {
                "[Errno 101] Network is unreachable".to_string()
            } else {
                chain.clone()
            };
            return PyExc::Other(
                "ConnectionError",
                format!(
                    "{pool}: Max retries exceeded with url: {url} (Caused by \
                     NewConnectionError('{conn}: Failed to establish a new connection: \
                     {reason}'))"
                ),
            );
        }
        if chain.contains("connection closed before message completed")
            || chain.contains("IncompleteMessage")
        {
            return PyExc::Other(
                "ConnectionError",
                "Remote end closed connection without response".to_string(),
            );
        }
        if e.is_redirect() {
            return PyExc::Other("TooManyRedirects", "Exceeded 30 redirects.".to_string());
        }
        PyExc::Other("ConnectionError", chain)
    }
}

/// urllib3's `gzip` / `deflate` decoding of an answer (`deflate` is zlib,
/// else raw deflate, as urllib3's `DeflateDecoder` tries).
fn decode_content(headers: &HeaderMap, raw: Bytes) -> Result<Bytes, PyExc> {
    use std::io::Read as _;
    let encoding = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let failed = |e: &str| {
        PyExc::Other(
            "ContentDecodingError",
            format!(
                "('Received response with content-encoding: {encoding}, but failed to decode \
                 it.', error('Error -3 while decompressing data: {e}'))"
            ),
        )
    };
    let mut out = Vec::new();
    match encoding.as_str() {
        "gzip" | "x-gzip" => {
            flate2::read::MultiGzDecoder::new(&raw[..])
                .read_to_end(&mut out)
                .map_err(|_| failed("incorrect header check"))?;
        }
        "deflate" => {
            let zlib = flate2::read::ZlibDecoder::new(&raw[..]).read_to_end(&mut out);
            if zlib.is_err() {
                out.clear();
                flate2::read::DeflateDecoder::new(&raw[..])
                    .read_to_end(&mut out)
                    .map_err(|_| failed("invalid stored block lengths"))?;
            }
        }
        _ => return Ok(raw),
    }
    Ok(Bytes::from(out))
}

fn timeout_text(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs.fract() == 0.0 {
        format!("{}", d.as_secs())
    } else {
        copilot_auth::pyvalue::float_repr(secs)
    }
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

/// `_basic_auth_str`: `Basic base64(user:password)`, both latin-1 encoded.
pub fn basic_auth(user: &str, password: &str) -> Result<String, PyExc> {
    let mut raw = latin1(user)?;
    raw.push(b':');
    raw.extend(latin1(password)?);
    Ok(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    ))
}

/// `s.encode("latin1")`, with `UnicodeEncodeError`'s text.
fn latin1(s: &str) -> Result<Vec<u8>, PyExc> {
    let chars: Vec<char> = s.chars().collect();
    let bad: Vec<usize> = chars
        .iter()
        .enumerate()
        .filter(|(_, c)| (**c as u32) > 0xff)
        .map(|(i, _)| i)
        .collect();
    if let Some(&first) = bad.first() {
        // The error covers the first run of unencodable characters.
        let mut last = first;
        while chars.get(last + 1).is_some_and(|c| (*c as u32) > 0xff) {
            last += 1;
        }
        let msg = if first == last {
            format!(
                "'latin-1' codec can't encode character {} in position {first}: ordinal not in \
                 range(256)",
                char_escape(chars[first])
            )
        } else {
            format!(
                "'latin-1' codec can't encode characters in position {first}-{last}: ordinal \
                 not in range(256)"
            )
        };
        return Err(PyExc::ValueError(msg));
    }
    Ok(chars.iter().map(|c| *c as u32 as u8).collect())
}

/// `'€'` as the codec error prints it.
fn char_escape(c: char) -> String {
    let u = c as u32;
    if u <= 0xffff {
        format!("'\\u{u:04x}'")
    } else {
        format!("'\\U{u:08x}'")
    }
}

/// The URL `requests` sends, and its parts (`None` for a scheme it has no
/// adapter for, which fails at send time with `InvalidSchema`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Prepared {
    url: String,
    parts: Option<Parts>,
}

/// `PreparedRequest.prepare_url(url, params)`.
fn prepare_url(raw: &str, params: &[(String, String)]) -> Result<Prepared, PyExc> {
    let url = raw.trim_start();
    if url.contains(':') && !url.to_lowercase().starts_with("http") {
        return Ok(Prepared {
            url: url.to_string(),
            parts: None,
        });
    }
    let parts = parse_url(url)
        .ok_or_else(|| PyExc::Other("InvalidURL", format!("Failed to parse: {url}")))?;
    if parts.scheme.is_empty() {
        return Err(PyExc::Other(
            "MissingSchema",
            format!(
                "Invalid URL {}: No scheme supplied. Perhaps you meant https://{url}?",
                str_repr(url)
            ),
        ));
    }
    if parts.host.is_empty() {
        return Err(PyExc::Other(
            "InvalidURL",
            format!("Invalid URL {}: No host supplied", str_repr(url)),
        ));
    }
    if !parts.host.is_ascii() || parts.host.starts_with(['*', '.']) {
        return Err(PyExc::Other(
            "InvalidURL",
            "URL has an invalid label.".to_string(),
        ));
    }
    if !matches!(parts.scheme.as_str(), "http" | "https") {
        return Ok(Prepared {
            url: url.to_string(),
            parts: None,
        });
    }
    let mut netloc = String::new();
    if let Some(a) = &parts.auth {
        netloc.push_str(a);
        netloc.push('@');
    }
    netloc.push_str(&parts.host);
    if let Some(p) = parts.port {
        netloc.push_str(&format!(":{p}"));
    }
    let path = if parts.path.is_empty() {
        "/".to_string()
    } else {
        parts.path.clone()
    };
    let enc = urlencode(params);
    let query = match (&parts.query, enc.is_empty()) {
        (Some(q), false) => Some(format!("{q}&{enc}")),
        (None, false) => Some(enc),
        (q, true) => q.clone(),
    };
    let mut out = format!("{}://{netloc}{path}", parts.scheme);
    if let Some(q) = &query {
        out.push('?');
        out.push_str(q);
    }
    if let Some(f) = &parts.fragment {
        out.push('#');
        out.push_str(f);
    }
    let out = requote_uri(&out);
    let mut parts = parts;
    parts.path = requote_uri(&path);
    parts.query = query.map(|q| requote_uri(&q));
    Ok(Prepared {
        url: out,
        parts: Some(parts),
    })
}

/// `urllib3.util.parse_url`; `None` is a `LocationParseError`.
fn parse_url(url: &str) -> Option<Parts> {
    if url.is_empty() {
        return Some(Parts {
            scheme: String::new(),
            auth: None,
            host: String::new(),
            port: None,
            path: String::new(),
            query: None,
            fragment: None,
        });
    }
    // `_SCHEME_RE`: a scheme, or a leading `/`; otherwise `//` is prepended.
    let has_scheme = {
        let mut chars = url.chars();
        match chars.next() {
            Some('/') => true,
            Some(c) if c.is_ascii_alphabetic() => {
                let rest: String = chars.collect();
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '-'))
                    .unwrap_or(rest.len());
                rest[end..].starts_with(':')
            }
            _ => false,
        }
    };
    let owned;
    let url = if has_scheme {
        url
    } else {
        owned = format!("//{url}");
        &owned
    };
    // `_URI_RE`: (scheme:)? (//authority)? path (?query)? (#fragment)?
    let mut rest = url;
    let mut scheme = None;
    if let Some(colon) = rest.find(':') {
        let candidate = &rest[..colon];
        if !candidate.is_empty()
            && candidate
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            && candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = Some(candidate.to_ascii_lowercase());
            rest = &rest[colon + 1..];
        }
    }
    let mut authority = None;
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        authority = Some(&after[..end]);
        rest = &after[end..];
    }
    let (before_frag, fragment) = match rest.split_once('#') {
        Some((b, f)) => (b, Some(f.to_string())),
        None => (rest, None),
    };
    let (path, query) = match before_frag.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (before_frag.to_string(), None),
    };
    let normalize = scheme
        .as_deref()
        .is_none_or(|s| matches!(s, "http" | "https"));
    let (auth, host, port) = match authority {
        None => (None, String::new(), None),
        Some(a) => {
            let (auth, host_port) = match a.rsplit_once('@') {
                Some((au, h)) => ((!au.is_empty()).then(|| au.to_string()), h),
                None => (None, a),
            };
            let (host, port) = split_host_port(host_port)?;
            let auth = match (auth, normalize) {
                (Some(au), true) => Some(encode_invalid(&au, USERINFO_EXTRA)),
                (au, _) => au,
            };
            (auth, host, port)
        }
    };
    let host = if matches!(scheme.as_deref(), None | Some("http") | Some("https")) {
        host.to_ascii_lowercase()
    } else {
        host
    };
    let path = if normalize && !path.is_empty() {
        encode_invalid(&remove_dot_segments(&path), PATH_EXTRA)
    } else {
        path
    };
    let query = match query {
        Some(q) if normalize && !q.is_empty() => Some(encode_invalid(&q, QUERY_EXTRA)),
        q => q,
    };
    let fragment = match fragment {
        Some(f) if normalize && !f.is_empty() => Some(encode_invalid(&f, QUERY_EXTRA)),
        f => f,
    };
    Some(Parts {
        scheme: scheme.unwrap_or_default(),
        auth,
        host,
        port,
        path,
        query,
        fragment,
    })
}

/// `_HOST_PORT_RE` and the port range check.
fn split_host_port(host_port: &str) -> Option<(String, Option<u16>)> {
    let (host, port) = if let Some(stripped) = host_port.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = format!("[{}]", &stripped[..close]);
        let after = &stripped[close + 1..];
        match after.strip_prefix(':') {
            Some(p) => (host, Some(p)),
            None if after.is_empty() => (host, None),
            None => return None,
        }
    } else {
        match host_port.split_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (host_port.to_string(), None),
        }
    };
    if host.contains(['[', ']']) && !host.starts_with('[') {
        return None;
    }
    let port = match port {
        None | Some("") => None,
        Some(p) => {
            // `:0*?(|0|[1-9][0-9]{0,4})`
            if !p.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let trimmed = p.trim_start_matches('0');
            if trimmed.len() > 5 {
                return None;
            }
            let n: u32 = if trimmed.is_empty() {
                0
            } else {
                trimmed.parse().ok()?
            };
            Some(u16::try_from(n).ok()?)
        }
    };
    Some((host, port))
}

const USERINFO_EXTRA: &[u8] = b"!$&'()*+,;=:";
const PATH_EXTRA: &[u8] = b"!$&'()*+,;=:@/";
const QUERY_EXTRA: &[u8] = b"!$&'()*+,;=:@/?";

/// urllib3's `_encode_invalid_chars`: keep the allowed characters, keep `%`
/// only when every `%` starts a valid escape (escapes upper-cased), encode
/// the rest.
fn encode_invalid(component: &str, extra: &[u8]) -> String {
    let bytes = component.as_bytes();
    let mut upper = Vec::with_capacity(bytes.len());
    let mut escapes = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            escapes += 1;
            upper.push(b'%');
            upper.push(bytes[i + 1].to_ascii_uppercase());
            upper.push(bytes[i + 2].to_ascii_uppercase());
            i += 3;
        } else {
            upper.push(bytes[i]);
            i += 1;
        }
    }
    let percents = upper.iter().filter(|b| **b == b'%').count();
    let keep_percent = escapes == percents;
    let mut out = String::new();
    for &b in &upper {
        let allowed = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || extra.contains(&b);
        if (keep_percent && b == b'%') || (b < 128 && allowed) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// RFC 3986 `remove_dot_segments` (`_remove_path_dot_segments`).
fn remove_dot_segments(path: &str) -> String {
    let mut output: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "." => {}
            ".." => {
                if output.len() > 1 || (output.len() == 1 && !output[0].is_empty()) {
                    output.pop();
                }
            }
            s => output.push(s),
        }
    }
    if path.starts_with('/') && (output.is_empty() || !output[0].is_empty()) {
        output.insert(0, "");
    }
    if path.ends_with("/.") || path.ends_with("/..") {
        output.push("");
    }
    output.join("/")
}

/// `urllib.parse.quote_plus(s)` (safe: letters, digits, `_.-~`).
pub fn quote_plus(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(char::from(b));
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `urllib.parse.urlencode(pairs)`.
pub fn urlencode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `requests.utils.unquote_unreserved`; `None` is its `InvalidURL` (an
/// alphanumeric pair after `%` that is not hex).
fn unquote_unreserved(uri: &str) -> Option<String> {
    let mut parts = uri.split('%');
    let mut out = parts.next().unwrap_or_default().to_string();
    for part in parts {
        let h: String = part.chars().take(2).collect();
        if h.chars().count() == 2 && h.chars().all(char::is_alphanumeric) {
            let code = u32::from_str_radix(&h, 16).ok()?;
            let c = char::from_u32(code)?;
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
                out.push(c);
                out.push_str(&part[h.len()..]);
            } else {
                out.push('%');
                out.push_str(part);
            }
        } else {
            out.push('%');
            out.push_str(part);
        }
    }
    Some(out)
}

/// `urllib.parse.quote(s, safe=...)` over UTF-8 bytes.
fn quote(s: &str, safe: &[u8]) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') || safe.contains(&b)
        {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `requests.utils.requote_uri`.
pub fn requote_uri(uri: &str) -> String {
    match unquote_unreserved(uri) {
        Some(u) => quote(&u, b"!#$%&'()*+,/:;=?@[]~"),
        None => quote(uri, b"!#$&'()*+,/:;=?@[]~"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(url: &str) -> String {
        prepare_url(url, &[]).unwrap_err().text()
    }

    #[test]
    fn url_errors_read_like_requests() {
        assert_eq!(
            err("localhost/api"),
            "Invalid URL 'localhost/api': No scheme supplied. Perhaps you meant https://localhost/api?"
        );
        assert_eq!(
            err(""),
            "Invalid URL '': No scheme supplied. Perhaps you meant https://?"
        );
        assert_eq!(
            err("/api/system"),
            "Invalid URL '/api/system': No scheme supplied. Perhaps you meant https:///api/system?"
        );
        assert_eq!(
            err("http:///x"),
            "Invalid URL 'http:///x': No host supplied"
        );
        assert_eq!(
            err("http://127.0.0.1:99999/x"),
            "Failed to parse: http://127.0.0.1:99999/x"
        );
        let p = prepare_url("ftp://h/x", &[]).unwrap();
        assert!(p.parts.is_none());
        let p = prepare_url("127.0.0.1:9000/api", &[]).unwrap();
        assert!(
            p.parts.is_none(),
            "a colon without http is left to the adapter"
        );
    }

    #[test]
    fn params_are_appended() {
        let p = prepare_url(
            "http://g:9000/api/x?a=1",
            &[("per page".into(), "a/b~*".into())],
        )
        .unwrap();
        assert_eq!(p.url, "http://g:9000/api/x?a=1&per+page=a%2Fb~%2A");
        let p = prepare_url("http://G:9000", &[]).unwrap();
        assert_eq!(p.url, "http://g:9000/");
        let p = prepare_url("http://g/a b/%41%zz", &[]).unwrap();
        assert_eq!(p.url, "http://g/a%20b/%2541%25zz");
        let p = prepare_url("http://g/a b/%41%2F%/x", &[]).unwrap();
        assert_eq!(p.url, "http://g/a%20b/%2541%252F%25/x");
        let p = prepare_url("http://g/x/../y/./%7e%41?q=a b", &[]).unwrap();
        assert_eq!(p.url, "http://g/y/~A?q=a%20b");
    }

    #[test]
    fn basic_auth_is_latin1() {
        assert_eq!(basic_auth("admin", "pw").unwrap(), "Basic YWRtaW46cHc=");
        assert_eq!(basic_auth("None", "None").unwrap(), "Basic Tm9uZTpOb25l");
        assert_eq!(basic_auth("é", "").unwrap(), "Basic 6To=");
        assert_eq!(
            basic_auth("a€", "x").unwrap_err().text(),
            "'latin-1' codec can't encode character '\\u20ac' in position 1: ordinal not in range(256)"
        );
    }
}
