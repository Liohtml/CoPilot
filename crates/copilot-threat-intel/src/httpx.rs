//! httpx 0.28's `AsyncClient` as the threat-intel services use it: a client
//! per call (`async with httpx.AsyncClient(timeout=…) as client`), HTTP/1.1,
//! TLS verified, redirects not followed.
//!
//! What goes on the wire is httpx's: its URL parsing and normalisation
//! (`_urlparse.py`: control characters refused, the host lower-cased, the
//! default port dropped, `.`/`..` segments resolved, the path, query and
//! fragment quoted with their safe sets, an existing `%XX` kept), `params=`
//! as `urlencode`, the client's default headers (`Accept: */*`,
//! `Accept-Encoding: gzip, deflate`, `Connection: keep-alive`, `User-Agent:
//! python-httpx/0.28.1`) replaced case-insensitively by the caller's,
//! `json=` as compact UTF-8 `application/json`, `files=` / `data=` as its
//! multipart encoder (a random 32-hex boundary, the data fields first),
//! `Content-Length: 0` on a body-less POST, PUT or PATCH. The answer is
//! decoded (`gzip`, `deflate`) and every failure carries httpx's exception
//! class and `str()` text.
//!
//! The Rust URL stack sends two shapes differently, neither of which the
//! routes' inputs produce in practice: a `\` in a path goes out as `/`, and a
//! `%2E%2E` segment is resolved (httpx sends both as they are).

use std::time::Duration;

use bytes::Bytes;
use copilot_auth::pyvalue::{PyValue, loads_bytes, str_repr};
use copilot_upstream::http::urlencode;
use copilot_upstream::json::{Dumps, py_dumps, py_loads};
use copilot_upstream::py::PyExc;
use http::{HeaderMap, HeaderName, HeaderValue, Method};

/// httpx's `User-Agent`.
pub const USER_AGENT: &str = "python-httpx/0.28.1";
/// `httpx.AsyncClient()`'s timeout (`DEFAULT_TIMEOUT_CONFIG`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// An exception httpx raised: its class and `str()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpxError {
    /// `ConnectError`, `ReadTimeout`, `HTTPStatusError`, `InvalidURL`, …
    pub class: &'static str,
    /// `str(e)`.
    pub message: String,
}

impl HttpxError {
    fn new(class: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }

    /// `isinstance(e, httpx.HTTPStatusError)`.
    pub fn is_status_error(&self) -> bool {
        self.class == "HTTPStatusError"
    }

    /// `isinstance(e, httpx.RequestError)`: a transport, decoding or
    /// protocol failure.
    pub fn is_request_error(&self) -> bool {
        matches!(
            self.class,
            "ConnectError"
                | "ConnectTimeout"
                | "ReadTimeout"
                | "WriteTimeout"
                | "PoolTimeout"
                | "ReadError"
                | "WriteError"
                | "RemoteProtocolError"
                | "LocalProtocolError"
                | "UnsupportedProtocol"
                | "DecodingError"
        )
    }

    /// `isinstance(e, httpx.HTTPError)`.
    pub fn is_http_error(&self) -> bool {
        self.is_status_error() || self.is_request_error()
    }

    /// The exception left uncaught (`str()` kept): a `ValueError` (the
    /// header-encoding `UnicodeEncodeError`) is the handler's 400, anything
    /// else uvicorn's bare 500.
    pub fn into_py(self) -> PyExc {
        if self.class == "UnicodeEncodeError" {
            PyExc::ValueError(self.message)
        } else {
            PyExc::Other(self.class, self.message)
        }
    }
}

/// A `files=` entry: `(filename, content, content_type)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileField {
    /// The form field.
    pub name: String,
    /// The tuple's file name (`None` or empty: no `filename=` parameter).
    pub filename: Option<String>,
    /// The tuple's content type.
    pub content_type: String,
    /// The bytes.
    pub content: Vec<u8>,
}

/// What the request carries.
#[derive(Debug, Clone)]
pub enum Body {
    /// Nothing.
    Empty,
    /// `json=`.
    Json(PyValue),
    /// `data=` and `files=`.
    Multipart {
        /// The data fields, in their order.
        data: Vec<(String, String)>,
        /// The file fields.
        files: Vec<FileField>,
    },
}

/// One `client.get(…)` / `client.post(…)`.
#[derive(Debug, Clone)]
pub struct Request {
    method: Method,
    url: String,
    params: Vec<(String, String)>,
    /// `None` is a header given `None` (httpx's `TypeError`).
    headers: Vec<(String, Option<String>)>,
    body: Body,
    timeout: Duration,
}

impl Request {
    /// A request to `url` (the client's default timeout).
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            params: Vec::new(),
            headers: Vec::new(),
            body: Body::Empty,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// `params=`.
    pub fn params(mut self, params: Vec<(String, String)>) -> Self {
        self.params = params;
        self
    }

    /// One `headers=` entry.
    pub fn header(mut self, name: &str, value: Option<&str>) -> Self {
        self.headers
            .push((name.to_string(), value.map(str::to_string)));
        self
    }

    /// `json=`.
    pub fn json(mut self, value: PyValue) -> Self {
        self.body = Body::Json(value);
        self
    }

    /// `data=` and `files=`.
    pub fn multipart(mut self, data: Vec<(String, String)>, files: Vec<FileField>) -> Self {
        self.body = Body::Multipart { data, files };
        self
    }

    /// `timeout=` (connect and read alike, as `httpx.Timeout(t)`).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// An answer.
#[derive(Debug, Clone)]
pub struct Response {
    /// `status_code`.
    pub status: u16,
    /// `reason_phrase`: the status line's own text.
    pub reason: String,
    /// The headers.
    pub headers: HeaderMap,
    /// `content`, decoded.
    pub content: Bytes,
    /// `str(response.url)`.
    pub url: String,
}

impl Response {
    /// `response.is_success`.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// `response.raise_for_status()`.
    pub fn raise_for_status(&self) -> Result<(), HttpxError> {
        if self.is_success() {
            return Ok(());
        }
        let error_type = match self.status / 100 {
            1 => "Informational response",
            3 => "Redirect response",
            4 => "Client error",
            5 => "Server error",
            _ => "Invalid status code",
        };
        let location = self
            .headers
            .get(http::header::LOCATION)
            .filter(|_| matches!(self.status, 301 | 302 | 303 | 307 | 308))
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
        let redirect = location
            .map(|l| format!("Redirect location: '{l}'\n"))
            .unwrap_or_default();
        Err(HttpxError::new(
            "HTTPStatusError",
            format!(
                "{error_type} '{} {}' for url '{}'\n{redirect}For more information check: \
                 https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/{}",
                self.status, self.reason, self.url, self.status
            ),
        ))
    }

    /// `response.text`: the `charset` of the Content-Type, else UTF-8,
    /// undecodable bytes replaced.
    pub fn text(&self) -> String {
        let charset = self
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|ct| {
                ct.split(';').skip(1).find_map(|p| {
                    let (k, v) = p.split_once('=')?;
                    k.trim()
                        .eq_ignore_ascii_case("charset")
                        .then(|| v.trim().trim_matches(['"', '\'']).to_ascii_lowercase())
                })
            });
        match charset.as_deref() {
            Some("iso-8859-1" | "latin-1" | "latin1" | "l1") => {
                self.content.iter().map(|b| char::from(*b)).collect()
            }
            _ => String::from_utf8_lossy(&self.content).into_owned(),
        }
    }

    /// `response.json()`: `json.loads` of the bytes; a `JSONDecodeError`
    /// (a `ValueError`) otherwise.
    pub fn json(&self) -> Result<PyValue, PyExc> {
        loads_bytes(&self.content).map_err(|_| {
            PyExc::JsonDecode(
                py_loads(&String::from_utf8_lossy(&self.content))
                    .err()
                    .unwrap_or_else(|| "Expecting value: line 1 column 1 (char 0)".into()),
            )
        })
    }
}

// --- the URL -----------------------------------------------------------------------------

const SUB_DELIMS: &str = "!$&'()*+,;=";
const UNRESERVED: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// The printable ASCII characters but those listed.
fn safe_but(excluded: &[u8]) -> String {
    (0x20u8..0x7f)
        .filter(|b| !excluded.contains(b))
        .map(char::from)
        .collect()
}

fn path_safe() -> String {
    safe_but(&[0x20, 0x22, 0x23, 0x3C, 0x3E, 0x3F, 0x60, 0x7B, 0x7D])
}

fn query_safe() -> String {
    safe_but(&[0x20, 0x22, 0x23, 0x3C, 0x3E])
}

fn frag_safe() -> String {
    safe_but(&[0x20, 0x22, 0x3C, 0x3E, 0x60])
}

fn userinfo_safe() -> String {
    safe_but(&[
        0x20, 0x22, 0x23, 0x3C, 0x3E, 0x3F, 0x60, 0x7B, 0x7D, 0x2F, 0x3B, 0x3D, 0x40, 0x5B, 0x5C,
        0x5D, 0x5E, 0x7C,
    ])
}

/// `percent_encoded(string, safe)`.
fn percent_encoded(s: &str, safe: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if UNRESERVED.contains(c) || safe.contains(c) {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

/// `quote(string, safe)`: an existing `%XX` is kept as it is.
pub fn quote(s: &str, safe: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut plain_start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push_str(&percent_encoded(&s[plain_start..i], safe));
            out.push_str(&s[i..i + 3]);
            i += 3;
            plain_start = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&percent_encoded(&s[plain_start..], safe));
    out
}

/// `normalize_path`: drop `.` and `..` segments.
fn normalize_path(path: &str) -> String {
    if !path.contains('.') {
        return path.to_string();
    }
    let components: Vec<&str> = path.split('/').collect();
    if !components.iter().any(|c| *c == "." || *c == "..") {
        return path.to_string();
    }
    let mut output: Vec<&str> = Vec::new();
    for c in components {
        match c {
            "." => {}
            ".." => {
                if !output.is_empty() && output != [""] {
                    output.pop();
                }
            }
            other => output.push(other),
        }
    }
    output.join("/")
}

/// A parsed URL (`ParseResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    scheme: String,
    userinfo: String,
    host: String,
    port: Option<i64>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

fn invalid(message: impl Into<String>) -> HttpxError {
    HttpxError::new("InvalidURL", message)
}

/// `encode_host(host)`.
fn encode_host(host: &str) -> Result<String, HttpxError> {
    if host.is_empty() {
        return Ok(String::new());
    }
    let ipv4_style = {
        let parts: Vec<&str> = host.split('.').collect();
        parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    };
    if ipv4_style {
        return host
            .parse::<std::net::Ipv4Addr>()
            .map(|_| host.to_string())
            .map_err(|_| invalid(format!("Invalid IPv4 address: {}", str_repr(host))));
    }
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        let inner = &host[1..host.len() - 1];
        return inner
            .parse::<std::net::Ipv6Addr>()
            .map(|_| inner.to_string())
            .map_err(|_| invalid(format!("Invalid IPv6 address: {}", str_repr(host))));
    }
    if host.is_ascii() {
        let safe = format!("{SUB_DELIMS}\"`{{}}%|\\");
        return Ok(quote(&host.to_ascii_lowercase(), &safe));
    }
    let lowered = copilot_jinja::unicode::lower(host);
    url::Host::parse(&lowered)
        .ok()
        .and_then(|h| match h {
            url::Host::Domain(d) => Some(d),
            _ => None,
        })
        .ok_or_else(|| invalid(format!("Invalid IDNA hostname: {}", str_repr(host))))
}

/// `urlparse(url)`.
pub fn parse_url(url: &str) -> Result<Url, HttpxError> {
    if url.chars().count() > 65536 {
        return Err(invalid("URL too long"));
    }
    if let Some((idx, c)) = url.chars().enumerate().find(|(_, c)| c.is_ascii_control()) {
        return Err(invalid(format!(
            "Invalid non-printable ASCII character in URL, {} at position {idx}.",
            str_repr(&c.to_string())
        )));
    }
    // URL_REGEX: (?:scheme:)?(?://authority)?path(?:\?query)?(?:#fragment)?
    let mut rest = url;
    let mut scheme = String::new();
    if let Some(colon) = rest.find(':') {
        let candidate = &rest[..colon];
        let valid = candidate.is_empty()
            || (candidate.as_bytes()[0].is_ascii_alphabetic()
                && candidate
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')));
        if valid {
            scheme = candidate.to_string();
            rest = &rest[colon + 1..];
        }
    }
    let mut authority = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        authority = after[..end].to_string();
        rest = &after[end..];
    }
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let path = &rest[..path_end];
    rest = &rest[path_end..];
    let mut query = None;
    if let Some(after) = rest.strip_prefix('?') {
        let end = after.find('#').unwrap_or(after.len());
        query = Some(after[..end].to_string());
        rest = &after[end..];
    }
    let fragment = rest.strip_prefix('#').map(str::to_string);

    // AUTHORITY_REGEX: (?:userinfo@)?(\[.*\]|[^:@]*):?(port)?
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(at) => (&authority[..at], &authority[at + 1..]),
        None => ("", authority.as_str()),
    };
    let (host, port) = if hostport.starts_with('[') {
        match hostport.rfind(']') {
            Some(close) => {
                let tail = &hostport[close + 1..];
                (&hostport[..=close], tail.strip_prefix(':').unwrap_or(tail))
            }
            None => (hostport, ""),
        }
    } else {
        match hostport.find([':', '@']) {
            Some(i) => {
                let tail = &hostport[i..];
                (&hostport[..i], tail.strip_prefix(':').unwrap_or(tail))
            }
            None => (hostport, ""),
        }
    };
    let scheme = scheme.to_ascii_lowercase();
    let userinfo = quote(userinfo, &userinfo_safe());
    let host = encode_host(host)?;
    let port = if port.is_empty() {
        None
    } else {
        let n: i64 = port
            .trim()
            .replace('_', "")
            .parse()
            .map_err(|_| invalid(format!("Invalid port: {}", str_repr(port))))?;
        let default = match scheme.as_str() {
            "ftp" => Some(21),
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        };
        (Some(n) != default).then_some(n)
    };
    let has_scheme = !scheme.is_empty();
    let has_authority = !userinfo.is_empty() || !host.is_empty() || port.is_some();
    if has_authority && !path.is_empty() && !path.starts_with('/') {
        return Err(invalid(
            "For absolute URLs, path must be empty or begin with '/'",
        ));
    }
    if !has_scheme && !has_authority {
        if path.starts_with("//") {
            return Err(invalid(
                "Relative URLs cannot have a path starting with '//'",
            ));
        }
        if path.starts_with(':') {
            return Err(invalid(
                "Relative URLs cannot have a path starting with ':'",
            ));
        }
    }
    let path = if has_scheme || has_authority {
        normalize_path(path)
    } else {
        path.to_string()
    };
    Ok(Url {
        scheme,
        userinfo,
        host,
        port,
        path: quote(&path, &path_safe()),
        query: query.map(|q| quote(&q, &query_safe())),
        fragment: fragment.map(|f| quote(&f, &frag_safe())),
    })
}

impl Url {
    fn netloc(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(p) => format!("{host}:{p}"),
            None => host,
        }
    }

    fn authority(&self) -> String {
        let userinfo = if self.userinfo.is_empty() {
            String::new()
        } else {
            format!("{}@", self.userinfo)
        };
        format!("{userinfo}{}", self.netloc())
    }

    /// `str(url)`.
    pub fn render(&self) -> String {
        let mut out = String::new();
        if !self.scheme.is_empty() {
            out.push_str(&self.scheme);
            out.push(':');
        }
        let authority = self.authority();
        if !authority.is_empty() {
            out.push_str("//");
            out.push_str(&authority);
        }
        out.push_str(&self.path);
        if let Some(q) = &self.query {
            out.push('?');
            out.push_str(q);
        }
        if let Some(f) = &self.fragment {
            out.push('#');
            out.push_str(f);
        }
        out
    }

    /// The request target the connection sends (no fragment).
    fn target(&self) -> String {
        let mut out = format!("{}://{}", self.scheme, self.authority());
        out.push_str(if self.path.is_empty() {
            "/"
        } else {
            &self.path
        });
        if let Some(q) = &self.query {
            out.push('?');
            out.push_str(q);
        }
        out
    }
}

// --- the request -------------------------------------------------------------------------

/// The escape `UnicodeEncodeError` uses for one character.
fn char_escape(c: char) -> String {
    let n = u32::from(c);
    if n <= 0xff {
        format!("'\\x{n:02x}'")
    } else if n <= 0xffff {
        format!("'\\u{n:04x}'")
    } else {
        format!("'\\U{n:08x}'")
    }
}

/// The merged headers, in httpx's order and with its case-insensitive
/// replacement; `content` are the encoder's headers (`setdefault`).
fn merged_headers(
    user: &[(String, Option<String>)],
    content: &[(&str, String)],
    method: &Method,
) -> Result<Vec<(String, String)>, HttpxError> {
    let mut headers: Vec<(String, String)> = vec![
        ("Accept".into(), "*/*".into()),
        ("Accept-Encoding".into(), "gzip, deflate".into()),
        ("Connection".into(), "keep-alive".into()),
        ("User-Agent".into(), USER_AGENT.into()),
    ];
    for (name, value) in user {
        let Some(value) = value else {
            return Err(HttpxError::new(
                "TypeError",
                "Header value must be str or bytes, not <class 'NoneType'>",
            ));
        };
        if let Some(message) = header_ascii_error(value) {
            return Err(HttpxError::new("UnicodeEncodeError", message));
        }
        // `Headers.update`: every existing entry of that name is replaced
        // by the one new value, at the first one's place.
        let lower = name.to_ascii_lowercase();
        match headers
            .iter()
            .position(|(k, _)| k.to_ascii_lowercase() == lower)
        {
            Some(i) => {
                headers[i] = (name.clone(), value.clone());
                let mut j = i + 1;
                while j < headers.len() {
                    if headers[j].0.to_ascii_lowercase() == lower {
                        headers.remove(j);
                    } else {
                        j += 1;
                    }
                }
            }
            None => headers.push((name.clone(), value.clone())),
        }
    }
    for (name, value) in content {
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)) {
            headers.push(((*name).to_string(), value.clone()));
        }
    }
    let has_length = headers.iter().any(|(k, _)| {
        k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("transfer-encoding")
    });
    if !has_length && matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
        headers.insert(0, ("Content-Length".into(), "0".into()));
    }
    Ok(headers)
}

/// `'ascii' codec can't encode …`: httpx encodes header values as ASCII.
fn header_ascii_error(value: &str) -> Option<String> {
    let chars: Vec<char> = value.chars().collect();
    let first = chars.iter().position(|c| !c.is_ascii())?;
    let mut last = first;
    while last + 1 < chars.len() && !chars[last + 1].is_ascii() {
        last += 1;
    }
    Some(if first == last {
        format!(
            "'ascii' codec can't encode character {} in position {first}: ordinal not in \
             range(128)",
            char_escape(chars[first])
        )
    } else {
        format!(
            "'ascii' codec can't encode characters in position {first}-{last}: ordinal not in \
             range(128)"
        )
    })
}

/// `_format_form_param(name, value)`.
fn form_param(name: &str, value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        match c {
            '"' => out.push_str("%22"),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) <= 0x1f && c != '\u{1b}' => out.push_str(&format!("%{:02X}", c as u32)),
            c => out.push(c),
        }
    }
    format!("{name}=\"{out}\"")
}

/// `MultipartStream(data, files)`: the body and its Content-Type.
fn multipart_body(data: &[(String, String)], files: &[FileField]) -> (Vec<u8>, String) {
    let boundary = hex::encode(rand::random::<[u8; 16]>());
    let mut body = Vec::new();
    for (name, value) in data {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; ");
        body.extend_from_slice(form_param("name", name).as_bytes());
        body.extend_from_slice(b"\r\n\r\n");
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    for file in files {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; ");
        body.extend_from_slice(form_param("name", &file.name).as_bytes());
        if let Some(filename) = file.filename.as_deref().filter(|f| !f.is_empty()) {
            body.extend_from_slice(b"; ");
            body.extend_from_slice(form_param("filename", filename).as_bytes());
        }
        body.extend_from_slice(format!("\r\nContent-Type: {}", file.content_type).as_bytes());
        body.extend_from_slice(b"\r\n\r\n");
        body.extend_from_slice(&file.content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (body, format!("multipart/form-data; boundary={boundary}"))
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

/// How httpx words a failure to get an answer.
fn transport_error(e: &reqwest::Error) -> HttpxError {
    let chain = error_chain(e);
    if e.is_timeout() {
        let class = if e.is_connect() {
            "ConnectTimeout"
        } else {
            "ReadTimeout"
        };
        return HttpxError::new(class, "");
    }
    if chain.contains("dns error") || chain.contains("failed to lookup") {
        return HttpxError::new("ConnectError", "[Errno -2] Name or service not known");
    }
    if chain.contains("certificate") || chain.contains("UnknownIssuer") {
        return HttpxError::new(
            "ConnectError",
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local \
             issuer certificate (_ssl.c:1006)",
        );
    }
    if e.is_connect() {
        return HttpxError::new("ConnectError", "All connection attempts failed");
    }
    if chain.contains("connection closed before message completed")
        || chain.contains("IncompleteMessage")
    {
        return HttpxError::new(
            "RemoteProtocolError",
            "Server disconnected without sending a response.",
        );
    }
    HttpxError::new("ReadError", chain)
}

/// httpx's content decoders (`gzip`, `deflate`; unknown codings are left
/// alone), applied in reverse order of the header.
fn decode(headers: &HeaderMap, raw: Bytes) -> Result<Bytes, HttpxError> {
    use std::io::Read as _;
    let codings: Vec<String> = headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| matches!(v.as_str(), "gzip" | "deflate"))
        .collect();
    let mut data = raw;
    for coding in codings.iter().rev() {
        let mut out = Vec::new();
        if coding == "gzip" {
            flate2::read::GzDecoder::new(&data[..])
                .read_to_end(&mut out)
                .map_err(|_| {
                    HttpxError::new(
                        "DecodingError",
                        "Error -3 while decompressing data: incorrect header check",
                    )
                })?;
        } else if flate2::read::ZlibDecoder::new(&data[..])
            .read_to_end(&mut out)
            .is_err()
        {
            out.clear();
            flate2::read::DeflateDecoder::new(&data[..])
                .read_to_end(&mut out)
                .map_err(|_| {
                    HttpxError::new(
                        "DecodingError",
                        "Error -3 while decompressing data: invalid stored block lengths",
                    )
                })?;
        }
        data = Bytes::from(out);
    }
    Ok(data)
}

/// One `httpx.AsyncClient`, reused across requests (its connection pool):
/// what `async with httpx.AsyncClient(timeout=…) as client:` holds for
/// several calls. The timeout is the client's; a request's own is ignored.
#[derive(Debug, Clone)]
pub struct Client {
    inner: reqwest::Client,
}

impl Client {
    /// `httpx.AsyncClient(timeout=timeout)`.
    pub fn new(timeout: Duration) -> Result<Self, HttpxError> {
        reqwest::Client::builder()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeout)
            .read_timeout(timeout)
            .build()
            .map(|inner| Self { inner })
            .map_err(|e| HttpxError::new("ConnectError", error_chain(&e)))
    }
}

/// Send `req` the way `httpx.AsyncClient(timeout=…).request(…)` does.
pub async fn send(req: Request) -> Result<Response, HttpxError> {
    let client = reqwest::Client::builder()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(req.timeout)
        .read_timeout(req.timeout)
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|e| HttpxError::new("ConnectError", error_chain(&e)))?;
    send_with(&client, req).await
}

/// Send `req` on a [`Client`] (`client.request(…)` inside `async with`).
pub async fn send_on(client: &Client, req: Request) -> Result<Response, HttpxError> {
    send_with(&client.inner, req).await
}

async fn send_with(client: &reqwest::Client, req: Request) -> Result<Response, HttpxError> {
    let mut url = parse_url(&req.url)?;
    if !req.params.is_empty() {
        let encoded = urlencode(&req.params);
        let merged = match url.query.take() {
            Some(existing) if !existing.is_empty() => format!("{existing}&{encoded}"),
            _ => encoded,
        };
        url.query = Some(quote(&merged, &query_safe()));
    }
    let (body, content): (Vec<u8>, Vec<(&str, String)>) = match &req.body {
        Body::Empty => (Vec::new(), Vec::new()),
        Body::Json(value) => {
            let text = py_dumps(value, Dumps::HTTPX)
                .map_err(|e| HttpxError::new("ValueError", e.to_string()))?;
            let bytes = text.into_bytes();
            let len = bytes.len().to_string();
            (
                bytes,
                vec![
                    ("Content-Length", len),
                    ("Content-Type", "application/json".into()),
                ],
            )
        }
        Body::Multipart { data, files } => {
            let (bytes, ctype) = multipart_body(data, files);
            let len = bytes.len().to_string();
            (
                bytes,
                vec![("Content-Length", len), ("Content-Type", ctype)],
            )
        }
    };
    let headers = merged_headers(&req.headers, &content, &req.method)?;
    match url.scheme.as_str() {
        "http" | "https" => {}
        "" => {
            return Err(HttpxError::new(
                "UnsupportedProtocol",
                "Request URL is missing an 'http://' or 'https://' protocol.",
            ));
        }
        other => {
            return Err(HttpxError::new(
                "UnsupportedProtocol",
                format!("Request URL has an unsupported protocol '{other}://'."),
            ));
        }
    }
    let rendered = url.render();
    let target = reqwest::Url::parse(&url.target()).map_err(|e| invalid(e.to_string()))?;
    let mut map = HeaderMap::new();
    for (name, value) in &headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HttpxError::new("LocalProtocolError", "Illegal header name"))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| HttpxError::new("LocalProtocolError", "Illegal header value"))?;
        map.append(name, value);
    }
    let mut builder = client.request(req.method.clone(), target).headers(map);
    if !body.is_empty() || matches!(req.body, Body::Json(_) | Body::Multipart { .. }) {
        builder = builder.body(body);
    }
    let resp = builder.send().await.map_err(|e| transport_error(&e))?;
    let status = resp.status().as_u16();
    let reason = resp
        .extensions()
        .get::<hyper::ext::ReasonPhrase>()
        .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
        .unwrap_or_else(|| resp.status().canonical_reason().unwrap_or("").to_string());
    let headers = resp.headers().clone();
    let raw = resp.bytes().await.map_err(|e| transport_error(&e))?;
    let content = decode(&headers, raw)?;
    Ok(Response {
        status,
        reason,
        headers,
        content,
        url: rendered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_like_httpx() {
        // Recorded with httpx 0.28.1: `str(httpx.URL(text))`.
        let cases = [
            (
                "https://www.virustotal.com/api/v3/files/abc",
                "https://www.virustotal.com/api/v3/files/abc",
            ),
            (
                "https://WWW.VirusTotal.com:443/api/v3/a b",
                "https://www.virustotal.com/api/v3/a%20b",
            ),
            ("http://127.0.0.1:80/x/../y/./z", "http://127.0.0.1/y/z"),
            ("http://h/a?b#c", "http://h/a?b#c"),
            ("http://h/%41%zz{}", "http://h/%41%zz%7B%7D"),
            ("http://h/é", "http://h/%C3%A9"),
            (
                "http://h:8080/q?x=\"y\"&z=<w>",
                "http://h:8080/q?x=%22y%22&z=%3Cw%3E",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(parse_url(input).unwrap().render(), want, "{input}");
        }
        assert_eq!(
            parse_url("http://h/a\nb").unwrap_err().message,
            "Invalid non-printable ASCII character in URL, '\\n' at position 10."
        );
        assert_eq!(
            parse_url("http://h:x/").unwrap_err().message,
            "Invalid port: 'x'"
        );
        assert_eq!(
            parse_url("http://999.1.1.1/").unwrap_err().message,
            "Invalid IPv4 address: '999.1.1.1'"
        );
    }

    #[test]
    fn headers_merge_like_httpx() {
        let got = merged_headers(
            &[
                ("accept".into(), Some("application/json".into())),
                ("x-apikey".into(), Some("k".into())),
            ],
            &[("Content-Length", "3".into())],
            &Method::POST,
        )
        .unwrap();
        assert_eq!(
            got,
            vec![
                ("accept".to_string(), "application/json".to_string()),
                ("Accept-Encoding".into(), "gzip, deflate".into()),
                ("Connection".into(), "keep-alive".into()),
                ("User-Agent".into(), USER_AGENT.into()),
                ("x-apikey".into(), "k".into()),
                ("Content-Length".into(), "3".into()),
            ]
        );
        let empty = merged_headers(&[], &[], &Method::POST).unwrap();
        assert_eq!(empty[0], ("Content-Length".into(), "0".into()));
        assert_eq!(
            merged_headers(&[("k".into(), Some("é".into()))], &[], &Method::GET)
                .unwrap_err()
                .message,
            "'ascii' codec can't encode character '\\xe9' in position 0: ordinal not in \
             range(128)"
        );
    }

    #[test]
    fn form_params_escape_like_httpx() {
        assert_eq!(
            form_param("filename", "a\"b\\c\nd\u{1b}"),
            "filename=\"a%22b\\\\c%0Ad\u{1b}\""
        );
    }
}
