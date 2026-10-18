//! The CoPilot Action inventory as `CopilotActionService` reaches it: one
//! `httpx.AsyncClient()` per call, `GET {BASE_URL}{path}` with `params=`
//! and the module's three headers, `timeout=30.0`, no redirects followed.
//!
//! On the wire that is httpx 0.28: `Accept-Encoding: gzip, deflate`,
//! `Connection: keep-alive`, `User-Agent: python-httpx/0.28.1`, the
//! caller's `Accept` replacing httpx's `*/*`, the query `urlencode`d
//! (`quote_plus`). Failures are httpx's exceptions with their texts:
//! `HTTPStatusError` from `raise_for_status()` (`Client error '404 Not Found'
//! for url '…'` and MDN's link), `ConnectError` (`All connection attempts
//! failed`, a resolver's `[Errno -2] Name or service not known`), the
//! timeouts (an empty text).
//!
//! `BASE_URL` is `https://copilot-action.socfortress.co`;
//! `COPILOT_ACTION_URL` replaces it for the parity harness only.

use std::time::Duration;

use bytes::Bytes;
use copilot_upstream::http::urlencode;
use http::HeaderMap;

/// `CopilotActionService.BASE_URL`.
pub const BASE_URL: &str = "https://copilot-action.socfortress.co";
/// `CopilotActionService.MODULE_VERSION`.
pub const MODULE_VERSION: &str = "1.0.0";
/// httpx's `User-Agent`.
pub const USER_AGENT: &str = "python-httpx/0.28.1";
/// `timeout=30.0`.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// Which httpx exception a call failed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpxError {
    /// `HTTPStatusError` (`raise_for_status`): its status and text.
    Status(u16, String),
    /// Another `httpx.HTTPError` (transport, timeout): its text.
    Transport(String),
}

impl HttpxError {
    /// `str(e)`.
    pub fn text(&self) -> String {
        match self {
            HttpxError::Status(_, t) | HttpxError::Transport(t) => t.clone(),
        }
    }
}

/// A 2xx answer.
#[derive(Debug, Clone)]
pub struct Answer {
    /// The body (decoded per `Content-Encoding`).
    pub body: Bytes,
}

/// The inventory client.
#[derive(Debug, Clone)]
pub struct ActionHttp {
    client: reqwest::Client,
    base: String,
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(s) = source {
        parts.push(s.to_string());
        source = s.source();
    }
    parts.join(": ")
}

/// httpx's text for a transport failure.
fn transport_text(e: &reqwest::Error) -> String {
    let chain = error_chain(e);
    if e.is_timeout() {
        String::new()
    } else if chain.contains("failed to lookup") || chain.contains("dns error") {
        "[Errno -2] Name or service not known".into()
    } else if chain.contains("certificate") {
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer \
         certificate (_ssl.c:1006)"
            .into()
    } else if e.is_connect() {
        "All connection attempts failed".into()
    } else if chain.contains("connection closed before message completed") {
        "Server disconnected without sending a response.".into()
    } else {
        chain
    }
}

/// httpx's (RFC 3986) path: percent-encode what it encodes, drop dot
/// segments. `raw` is `{BASE_URL}{path}` as Python formats it.
fn httpx_url(raw: &str) -> String {
    // Split off the fragment and the query as `httpx.URL` does.
    let without_fragment = raw.split('#').next().unwrap_or_default();
    let (before_query, query) = match without_fragment.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (without_fragment, None),
    };
    let Some((scheme, rest)) = before_query.split_once("://") else {
        return raw.to_string();
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let mut segments: Vec<String> = Vec::new();
    for seg in path.split('/').skip(1) {
        match seg {
            "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(encode_path(s)),
        }
    }
    // A trailing dot segment leaves no trailing slash (`/inventory/.` is
    // `/inventory`).
    let mut out = format!("{scheme}://{authority}");
    for s in &segments {
        out.push('/');
        out.push_str(s);
    }
    if segments.is_empty() {
        out.push('/');
    }
    if let Some(q) = query {
        out.push('?');
        out.push_str(&encode_query(q));
    }
    out
}

/// httpx's path quoting: unreserved, sub-delims, `:@`, `%` and the
/// characters it leaves alone (`\|^[]`) as they are; the rest as `%XX`.
fn encode_path(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || "-._~!$&'()*+,;=:@%\\|^[]".contains(c) {
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

fn encode_query(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || "-._~!$&'()*+,;=:@%/?\\|^[]".contains(c) {
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

/// `url` with its path's `\` as `%5C` (the query keeps them: the url
/// crate leaves a query's `\` alone).
fn wire_url(url: &str) -> String {
    let (before, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let mut out = before.replace('\\', "%5C");
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    out
}

fn decode_content(headers: &HeaderMap, raw: Bytes) -> Result<Bytes, String> {
    use std::io::Read as _;
    let encoding = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut out = Vec::new();
    match encoding.as_str() {
        "gzip" | "x-gzip" => {
            flate2::read::MultiGzDecoder::new(&raw[..])
                .read_to_end(&mut out)
                .map_err(|_| {
                    "Error -3 while decompressing data: incorrect header check".to_string()
                })?;
        }
        "deflate" => {
            if flate2::read::ZlibDecoder::new(&raw[..])
                .read_to_end(&mut out)
                .is_err()
            {
                out.clear();
                flate2::read::DeflateDecoder::new(&raw[..])
                    .read_to_end(&mut out)
                    .map_err(|_| {
                        "Error -3 while decompressing data: invalid stored block lengths"
                            .to_string()
                    })?;
            }
        }
        _ => return Ok(raw),
    }
    Ok(Bytes::from(out))
}

impl ActionHttp {
    /// The client; `base` is `COPILOT_ACTION_URL` when set (tests only).
    pub fn new(base: Option<String>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .http1_only()
                .connect_timeout(TIMEOUT)
                .read_timeout(TIMEOUT)
                .build()?,
            base: base.unwrap_or_else(|| BASE_URL.to_string()),
        })
    }

    /// `await client.get(f"{BASE_URL}{path}", headers=…, params=params,
    /// timeout=30.0)`, then `raise_for_status()`.
    pub async fn get(
        &self,
        path: &str,
        license_key: &str,
        params: &[(String, String)],
    ) -> Result<Answer, HttpxError> {
        let mut url = httpx_url(&format!("{}{path}", self.base));
        if !params.is_empty() {
            url.push(if url.contains('?') { '&' } else { '?' });
            url.push_str(&urlencode(params));
        }
        // The url crate reads a `\` of an http(s) path as `/`; httpx sends
        // it as it is. `%5C` is the same name to the server (§4).
        let target = reqwest::Url::parse(&wire_url(&url))
            .map_err(|e| HttpxError::Transport(e.to_string()))?;
        let resp = self
            .client
            .get(target)
            .header(http::header::ACCEPT_ENCODING, "gzip, deflate")
            .header(http::header::CONNECTION, "keep-alive")
            .header(http::header::USER_AGENT, USER_AGENT)
            .header("x-api-key", license_key)
            .header("module-version", MODULE_VERSION)
            .header(http::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| HttpxError::Transport(transport_text(&e)))?;
        let status = resp.status();
        let reason = resp
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
            .unwrap_or_else(|| status.canonical_reason().unwrap_or("").to_string());
        let headers = resp.headers().clone();
        let raw = resp
            .bytes()
            .await
            .map_err(|e| HttpxError::Transport(transport_text(&e)))?;
        let body = decode_content(&headers, raw).map_err(HttpxError::Transport)?;
        let code = status.as_u16();
        if !(200..300).contains(&code) {
            let error_type = match code / 100 {
                1 => "Informational response",
                3 => "Redirect response",
                4 => "Client error",
                5 => "Server error",
                _ => "Invalid status code",
            };
            let redirect = match headers.get(http::header::LOCATION) {
                Some(loc) if matches!(code, 301 | 302 | 303 | 307 | 308) => format!(
                    "Redirect location: '{}'\n",
                    String::from_utf8_lossy(loc.as_bytes())
                ),
                _ => String::new(),
            };
            return Err(HttpxError::Status(
                code,
                format!(
                    "{error_type} '{code} {reason}' for url '{url}'\n{redirect}For more \
                     information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/{code}"
                ),
            ));
        }
        Ok(Answer { body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_httpxs() {
        let base = "https://copilot-action.socfortress.co/inventory/";
        for (name, want) in [
            ("a b", "/inventory/a%20b"),
            ("é", "/inventory/%C3%A9"),
            ("a\"b", "/inventory/a%22b"),
            ("a<b>", "/inventory/a%3Cb%3E"),
            ("a{b}", "/inventory/a%7Bb%7D"),
            ("a`b", "/inventory/a%60b"),
            ("a|b^[c]'d;e=f@g:h", "/inventory/a|b^[c]'d;e=f@g:h"),
            ("a%2Fb", "/inventory/a%2Fb"),
            ("%41", "/inventory/%41"),
            (".", "/inventory"),
            ("a/./b", "/inventory/a/b"),
            ("a/../b", "/inventory/b"),
            ("..", "/"),
            ("a?b", "/inventory/a?b"),
            ("a#b", "/inventory/a"),
            ("a\\b", "/inventory/a\\b"),
        ] {
            let url = httpx_url(&format!("{base}{name}"));
            let path = url
                .strip_prefix("https://copilot-action.socfortress.co")
                .unwrap();
            assert_eq!(path, want, "{name}");
        }
        assert_eq!(
            reqwest::Url::parse(&wire_url("http://h/inventory/a\\b?q=a\\b"))
                .unwrap()
                .as_str(),
            "http://h/inventory/a%5Cb?q=a\\b"
        );
    }
}
