//! `aiohttp.ClientSession().get(url, headers=…)` (aiohttp 3.13 over yarl
//! 1.23) for the Atomic Red Team fetches: the URL as yarl encodes it, the
//! request aiohttp writes, the answer as `response.text()` /
//! `response.json()` read it, and aiohttp's exceptions with their texts.
//!
//! - The URL: `yarl.URL(text)` — tabs and line ends dropped, the fragment
//!   cut (never sent), the path requoted with `_Quoter(safe="@:",
//!   protected="/+")` and its dot segments removed, the query requoted with
//!   `_Quoter(safe="?/:@", protected="=+&;", qs=True)`; the request target is
//!   `raw_path_qs`. (A `'` in a query goes out as `%27`: the url crate's
//!   rule, where yarl keeps it.)
//! - The request: `Host`, the caller's headers, then `Accept: */*`,
//!   `Accept-Encoding: gzip, deflate` and `User-Agent: Python/3.11
//!   aiohttp/3.13.5` where the caller set none, title-cased, HTTP/1.1, no
//!   proxy (`trust_env=False`), five minutes for the whole exchange.
//! - The answer: `gzip`/`deflate` decoded as aiohttp decodes them; `text()`
//!   decodes with the `charset` (else UTF-8, strictly); `json()` refuses a
//!   type that is not `application/…json` (`ContentTypeError`), answers
//!   `None` for an empty body and is `json.loads` otherwise.
//! - Failures: a dropped `GET` is sent once more, then `InvalidUrlClientError`,
//!   `ClientConnectorError`
//!   (`Cannot connect to host h:p ssl:default [Connect call failed (…)]`),
//!   `ClientConnectorDNSError`, `ServerDisconnectedError`, a timeout's empty
//!   text.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_upstream::json::py_loads;
use copilot_upstream::py::PyExc;
use http::HeaderMap;

/// aiohttp's `User-Agent`.
pub const USER_AGENT: &str = "Python/3.11 aiohttp/3.13.5";
/// aiohttp's default whole-request timeout.
pub const TIMEOUT: Duration = Duration::from_secs(300);

const UNRESERVED: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
const SUB_DELIMS_WITHOUT_QS: &str = "!$'()*,";

/// yarl's `_Quoter(safe, protected, qs, requote=True)`.
pub fn requote(val: &str, safe: &str, protected: &str, qs: bool) -> String {
    let mut allowed = String::from(safe);
    allowed.push_str(UNRESERVED);
    allowed.push_str(SUB_DELIMS_WITHOUT_QS);
    if !qs {
        allowed.push_str("+&=;");
    }
    allowed.push_str(protected);
    let b = val.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut idx = 0;
    while idx < b.len() {
        let ch = b[idx];
        idx += 1;
        if ch == b'%' {
            if idx == b.len() {
                out.extend_from_slice(b"%25");
                continue;
            }
            if idx + 1 == b.len() {
                // Only one character after the `%`.
                out.extend_from_slice(b"%25");
                continue;
            }
            let h = b[idx].to_ascii_uppercase();
            let l = b[idx + 1].to_ascii_uppercase();
            let hex = |c: u8| char::from(c).to_digit(16);
            match (hex(h), hex(l)) {
                (Some(hv), Some(lv)) => {
                    let code = hv * 16 + lv;
                    let unquoted = char::from_u32(code).unwrap_or('\u{0}');
                    idx += 2;
                    if code < 0x80 && protected.contains(unquoted) {
                        out.extend_from_slice(&[b'%', h, l]);
                    } else if code < 0x80 && allowed.contains(unquoted) {
                        out.push(code as u8);
                    } else {
                        out.extend_from_slice(&[b'%', h, l]);
                    }
                }
                _ => out.extend_from_slice(b"%25"),
            }
            continue;
        }
        if qs && ch == b' ' {
            out.push(b'+');
            continue;
        }
        if ch < 0x80 && allowed.as_bytes().contains(&ch) {
            out.push(ch);
            continue;
        }
        out.extend_from_slice(format!("%{ch:02X}").as_bytes());
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// yarl's `normalize_path`: `.` and `..` segments removed.
pub fn normalize_path(path: &str) -> String {
    let (prefix, rest) = match path.strip_prefix('/') {
        Some(rest) => ("/", rest),
        None => ("", path),
    };
    let segments: Vec<&str> = rest.split('/').collect();
    let mut resolved: Vec<&str> = Vec::new();
    for seg in &segments {
        if *seg == ".." {
            resolved.pop();
        } else if *seg != "." {
            resolved.push(seg);
        }
    }
    if matches!(segments.last(), Some(&".") | Some(&"..")) {
        resolved.push("");
    }
    format!("{prefix}{}", resolved.join("/"))
}

/// A URL once yarl has encoded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `http` / `https`.
    pub scheme: String,
    /// The host, lower-cased.
    pub host: String,
    /// The port (the scheme's when none is given).
    pub port: u16,
    /// Whether the port was written.
    pub explicit_port: bool,
    /// `raw_path_qs`: what the request line names.
    pub path_qs: String,
}

impl Target {
    /// The `Host` header (`host_port_subcomponent`).
    pub fn host_header(&self) -> String {
        let default = if self.scheme == "https" { 443 } else { 80 };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// `str(url)` without its fragment (the `real_url` of an error).
    pub fn display(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.explicit_port {
            format!("{}://{host}:{}{}", self.scheme, self.port, self.path_qs)
        } else {
            format!("{}://{host}{}", self.scheme, self.path_qs)
        }
    }
}

fn invalid_url(text: &str) -> PyExc {
    PyExc::Other("InvalidUrlClientError", text.to_string())
}

/// `yarl.URL(raw)` and aiohttp's checks of it.
pub fn target(raw: &str) -> Result<Target, PyExc> {
    let cleaned: String = raw
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let Some((scheme, rest)) = cleaned.split_once("://") else {
        return Err(invalid_url(raw));
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(PyExc::Other("NonHttpUrlClientError", raw.to_string()));
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let netloc = &rest[..end];
    let after = &rest[end..];
    let after = after.split_once('#').map_or(after, |(a, _)| a);
    let (path, query) = match after.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (after, None),
    };
    let netloc = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let (host, port_text) = if let Some(inner) = netloc.strip_prefix('[') {
        let Some((h, after)) = inner.split_once(']') else {
            return Err(invalid_url(raw));
        };
        match after.strip_prefix(':') {
            Some(p) => (h, Some(p)),
            None if after.is_empty() => (h, None),
            None => return Err(invalid_url(raw)),
        }
    } else {
        match netloc.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (netloc, None),
        }
    };
    let port = match port_text.filter(|p| !p.is_empty()) {
        Some(p) => Some(p.parse::<u16>().map_err(|_| invalid_url(raw))?),
        None => None,
    };
    if host.is_empty() {
        return Err(invalid_url(raw));
    }
    let default = if scheme == "https" { 443 } else { 80 };
    let mut path_qs = if path.is_empty() {
        "/".to_string()
    } else {
        let p = requote(path, "@:", "/+", false);
        if p.contains('.') {
            normalize_path(&p)
        } else {
            p
        }
    };
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        path_qs.push('?');
        path_qs.push_str(&requote(q, "?/:@", "=+&;", true));
    }
    Ok(Target {
        scheme,
        host: host.to_lowercase(),
        port: port.unwrap_or(default),
        explicit_port: port.is_some(),
        path_qs,
    })
}

/// An answer, its body read and decoded.
#[derive(Debug, Clone)]
pub struct Answer {
    /// The status.
    pub status: u16,
    /// The headers.
    pub headers: HeaderMap,
    /// The body after `Content-Encoding`.
    pub body: Vec<u8>,
    /// `str(response.url)`.
    pub url: String,
}

impl Answer {
    /// `await response.text()`.
    pub fn text(&self) -> Result<String, PyExc> {
        decode(&self.body, &encoding_of(&self.headers))
    }

    /// `await response.json()`.
    pub fn json(&self) -> Result<PyValue, PyExc> {
        let ct = content_type(&self.headers).to_lowercase();
        let mimetype = ct.split(';').next().unwrap_or("").trim().to_string();
        if !is_json_type(&mimetype) {
            return Err(PyExc::Other(
                "ContentTypeError",
                format!(
                    "{}, message={}, url={}",
                    self.status,
                    str_repr(&format!(
                        "Attempt to decode JSON with unexpected mimetype: {ct}"
                    )),
                    str_repr(&self.url)
                ),
            ));
        }
        let start = self
            .body
            .iter()
            .position(|b| !b.is_ascii_whitespace() && *b != 0x0b)
            .unwrap_or(self.body.len());
        let end = self
            .body
            .iter()
            .rposition(|b| !b.is_ascii_whitespace() && *b != 0x0b)
            .map_or(start, |i| i + 1);
        let stripped = &self.body[start..end.max(start)];
        if stripped.is_empty() {
            return Ok(PyValue::None);
        }
        let text = decode(stripped, &encoding_of(&self.headers))?;
        py_loads(&text).map_err(PyExc::JsonDecode)
    }
}

/// The client (no proxy, as aiohttp without `trust_env`).
#[derive(Debug, Clone)]
pub struct AioHttp {
    client: reqwest::Client,
}

impl AioHttp {
    /// Build the client.
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .http1_only()
                .http1_title_case_headers()
                .redirect(reqwest::redirect::Policy::limited(10))
                .build()?,
        })
    }

    /// `session.get(url, headers=headers)` and the body read. A `GET` the
    /// server drops is sent once more (aiohttp's `retry_persistent_connection`
    /// for idempotent methods), within the same timeout.
    pub async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Answer, PyExc> {
        let t = target(url)?;
        let both = async {
            match self.attempt(url, &t, headers).await {
                Err(PyExc::Other("ServerDisconnectedError" | "ClientOSError", _)) => {
                    self.attempt(url, &t, headers).await
                }
                other => other,
            }
        };
        match tokio::time::timeout(TIMEOUT, both).await {
            Ok(r) => r,
            Err(_) => Err(PyExc::Other("TimeoutError", String::new())),
        }
    }

    async fn attempt(
        &self,
        url: &str,
        t: &Target,
        headers: &[(&str, &str)],
    ) -> Result<Answer, PyExc> {
        let send = async {
            let addrs = resolve(t).await?;
            let request_url = format!("{}://{}{}", t.scheme, t.host_header_with_port(), t.path_qs);
            let parsed = reqwest::Url::parse(&request_url).map_err(|_| invalid_url(url))?;
            let mut map = HeaderMap::new();
            let mut put = |name: &str, value: &str| {
                if let (Ok(n), Ok(v)) = (
                    http::header::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(value),
                ) {
                    map.append(n, v);
                }
            };
            put("host", &t.host_header());
            for (name, value) in headers {
                put(name, value);
            }
            let has = |name: &str| headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
            if !has("accept") {
                put("accept", "*/*");
            }
            if !has("accept-encoding") {
                put("accept-encoding", "gzip, deflate");
            }
            if !has("user-agent") {
                put("user-agent", USER_AGENT);
            }
            let resp = self
                .client
                .get(parsed)
                .headers(map)
                .send()
                .await
                .map_err(|e| transport_error(&e, t, &addrs))?;
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let raw = resp.bytes().await.map_err(|_| {
                PyExc::Other(
                    "ClientPayloadError",
                    "Response payload is not completed".into(),
                )
            })?;
            let body = decode_content(&headers, &raw)?;
            Ok(Answer {
                status,
                headers,
                body,
                url: t.display(),
            })
        };
        send.await
    }
}

impl Target {
    fn host_header_with_port(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{host}:{}", self.port)
    }
}

fn dns_failure(t: &Target, reason: &str) -> PyExc {
    PyExc::Other(
        "ClientConnectorDNSError",
        format!(
            "Cannot connect to host {}:{} ssl:default [{reason}]",
            t.host, t.port
        ),
    )
}

async fn resolve(t: &Target) -> Result<Vec<SocketAddr>, PyExc> {
    if let Ok(ip) = t.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, t.port)]);
    }
    match tokio::net::lookup_host((t.host.as_str(), t.port)).await {
        Ok(addrs) => {
            let addrs: Vec<SocketAddr> = addrs.collect();
            if addrs.is_empty() {
                Err(dns_failure(t, "Name or service not known"))
            } else {
                Ok(addrs)
            }
        }
        Err(e) => {
            let text = e.to_string();
            let reason = text
                .strip_prefix("failed to lookup address information: ")
                .unwrap_or(&text)
                .to_string();
            Err(dns_failure(t, &reason))
        }
    }
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

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(s) = source {
        parts.push(s.to_string());
        source = s.source();
    }
    parts.join(": ")
}

fn transport_error(e: &reqwest::Error, t: &Target, addrs: &[SocketAddr]) -> PyExc {
    let chain = error_chain(e);
    if e.is_timeout() {
        return PyExc::Other("TimeoutError", String::new());
    }
    if e.is_connect() {
        let addr = addrs
            .first()
            .copied()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], t.port)));
        return PyExc::Other(
            "ClientConnectorError",
            format!(
                "Cannot connect to host {}:{} ssl:default [Connect call failed {}]",
                t.host,
                t.port,
                address_text(&addr)
            ),
        );
    }
    if chain.contains("connection closed before message completed")
        || chain.contains("IncompleteMessage")
        || chain.contains("connection reset")
    {
        return PyExc::Other("ServerDisconnectedError", "Server disconnected".into());
    }
    PyExc::Other("ClientError", chain)
}

/// aiohttp's `gzip`/`deflate` decoding.
fn decode_content(headers: &HeaderMap, raw: &[u8]) -> Result<Vec<u8>, PyExc> {
    use std::io::Read as _;
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
        _ => return Ok(raw.to_vec()),
    }
    Ok(out)
}

fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(http::header::CONTENT_TYPE)
        .map(|v| {
            v.as_bytes()
                .iter()
                .map(|b| char::from(*b))
                .collect::<String>()
        })
        .unwrap_or_default()
}

/// `get_encoding()`: the `charset` parameter (the codecs Python knows by
/// the names a server sends), else UTF-8.
fn encoding_of(headers: &HeaderMap) -> String {
    let ct = content_type(headers);
    for param in ct.split(';').skip(1) {
        if let Some((k, v)) = param.split_once('=') {
            if k.trim().eq_ignore_ascii_case("charset") {
                let v = v
                    .trim()
                    .trim_matches('"')
                    .to_ascii_lowercase()
                    .replace('_', "-");
                return match v.as_str() {
                    "latin-1" | "latin1" | "iso-8859-1" | "iso8859-1" | "l1" => "iso8859-1".into(),
                    "ascii" | "us-ascii" => "ascii".into(),
                    _ => "utf-8".into(),
                };
            }
        }
    }
    "utf-8".into()
}

/// `bytes.decode(encoding, "strict")`.
fn decode(raw: &[u8], encoding: &str) -> Result<String, PyExc> {
    match encoding {
        "iso8859-1" => Ok(raw.iter().map(|b| char::from(*b)).collect()),
        "ascii" => match raw.iter().position(|b| *b >= 0x80) {
            None => Ok(raw.iter().map(|b| char::from(*b)).collect()),
            Some(i) => Err(PyExc::Other(
                "UnicodeDecodeError",
                format!(
                    "'ascii' codec can't decode byte 0x{:02x} in position {i}: ordinal not in \
                     range(128)",
                    raw[i]
                ),
            )),
        },
        _ => std::str::from_utf8(raw).map(str::to_string).map_err(|_| {
            PyExc::Other(
                "UnicodeDecodeError",
                copilot_yaml::pyint::utf8_decode_error(raw),
            )
        }),
    }
}

/// `^application/(?:[\w.+-]+?\+)?json`, on the lower-cased mimetype.
fn is_json_type(ct: &str) -> bool {
    let Some(rest) = ct.strip_prefix("application/") else {
        return false;
    };
    if rest.starts_with("json") {
        return true;
    }
    let mut seen = false;
    for (i, c) in rest.char_indices() {
        if c == '+' && seen && rest[i + 1..].starts_with("json") {
            return true;
        }
        if c.is_alphanumeric() || matches!(c, '_' | '.' | '+' | '-') {
            seen = true;
        } else {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_encoded_as_yarl_encodes_them() {
        let base = "https://raw.githubusercontent.com/x/atomics";
        for (id, want) in [
            ("T1003", "/x/atomics/T1003/T1003.md"),
            ("T1003 x", "/x/atomics/T1003%20x/T1003%20x.md"),
            ("T1003?x", "/x/atomics/T1003?x/T1003?x.md"),
            ("a#b", "/x/atomics/a"),
            ("%41%2f%zz", "/x/atomics/A%2F%25zz/A%2F%25zz.md"),
            ("..", "/x/...md"),
            ("T\u{e9}", "/x/atomics/T%C3%A9/T%C3%A9.md"),
            ("a|b^c\\d", "/x/atomics/a%7Cb%5Ec%5Cd/a%7Cb%5Ec%5Cd.md"),
        ] {
            let t = target(&format!("{base}/{id}/{id}.md")).unwrap();
            assert_eq!(t.path_qs, want, "{id:?}");
            assert_eq!(t.host_header(), "raw.githubusercontent.com");
        }
        let t = target("http://127.0.0.1:6443/raw/x").unwrap();
        assert_eq!(t.host_header(), "127.0.0.1:6443");
        assert_eq!(t.display(), "http://127.0.0.1:6443/raw/x");
    }
}
