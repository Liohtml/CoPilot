//! `httpx.AsyncClient(timeout=15.0).get(url)` as the SCA policy services
//! send it, and the texts of what it raises: the transport errors'
//! `str()`, `raise_for_status()`'s `HTTPStatusError`, `response.text`
//! (the charset of the `Content-Type`, else UTF-8, invalid bytes replaced)
//! and `response.json()`'s `JSONDecodeError`.
//!
//! The request carries httpx's own headers (`Accept: */*`,
//! `Accept-Encoding: gzip, deflate`, `Connection: keep-alive`, its
//! `User-Agent`), redirects are not followed, and a gzip or deflate answer is
//! decoded as httpx decodes it.

use std::time::Duration;

use bytes::Bytes;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::PyExc;

/// httpx's `User-Agent`.
pub const USER_AGENT: &str = "python-httpx/0.28.1";

/// A client with httpx's per-phase timeout.
#[derive(Debug, Clone)]
pub struct HttpxClient {
    http: reqwest::Client,
}

/// An answer.
#[derive(Debug, Clone)]
pub struct HttpxResponse {
    /// Status code.
    pub status: u16,
    /// `reason_phrase`.
    pub reason: String,
    /// `response.url`.
    pub url: String,
    /// The `Location` header, for a redirect.
    pub location: Option<String>,
    /// The charset the `Content-Type` names.
    pub charset: Option<String>,
    /// The decoded body.
    pub body: Bytes,
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

/// `str()` of the httpx exception a transport failure raises.
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

fn decode(encoding: &str, raw: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut out = Vec::new();
    match encoding {
        "gzip" | "x-gzip" => {
            flate2::read::MultiGzDecoder::new(raw)
                .read_to_end(&mut out)
                .ok()?;
        }
        "deflate" => {
            if flate2::read::ZlibDecoder::new(raw)
                .read_to_end(&mut out)
                .is_err()
            {
                out.clear();
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut out)
                    .ok()?;
            }
        }
        _ => return Some(raw.to_vec()),
    }
    Some(out)
}

impl HttpxClient {
    /// `httpx.AsyncClient(timeout=…)`.
    pub fn new(timeout: Duration) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeout)
            .read_timeout(timeout)
            .build()?;
        Ok(Self { http })
    }

    /// `await client.get(url)`; `Err` is `str()` of the exception.
    pub async fn get(&self, url: &str) -> Result<HttpxResponse, String> {
        let resp = self
            .http
            .get(url)
            .header("accept", "*/*")
            .header("accept-encoding", "gzip, deflate")
            .header("connection", "keep-alive")
            .header("user-agent", USER_AGENT)
            .send()
            .await
            .map_err(|e| transport_text(&e))?;
        let status = resp.status();
        let reason = resp
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
            .or_else(|| status.canonical_reason().map(str::to_string))
            .unwrap_or_default();
        let header = |name: http::HeaderName| {
            resp.headers()
                .get(name)
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        };
        let location = header(http::header::LOCATION);
        let charset = header(http::header::CONTENT_TYPE).and_then(|ct| {
            ct.split(';').skip(1).find_map(|p| {
                let (k, v) = p.split_once('=')?;
                (k.trim().eq_ignore_ascii_case("charset"))
                    .then(|| v.trim().trim_matches('"').to_ascii_lowercase())
            })
        });
        let encoding = header(http::header::CONTENT_ENCODING)
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let url = resp.url().to_string();
        let raw = resp.bytes().await.map_err(|e| transport_text(&e))?;
        let body = decode(&encoding, &raw).ok_or_else(|| {
            "Error -3 while decompressing data: incorrect header check".to_string()
        })?;
        Ok(HttpxResponse {
            status: status.as_u16(),
            reason,
            url,
            location,
            charset,
            body: Bytes::from(body),
        })
    }
}

impl HttpxResponse {
    /// `raise_for_status()`: `Err` is the `HTTPStatusError`'s text.
    pub fn raise_for_status(&self) -> Result<(), String> {
        if (200..300).contains(&self.status) {
            return Ok(());
        }
        let kind = match self.status / 100 {
            1 => "Informational response",
            3 => "Redirect response",
            4 => "Client error",
            5 => "Server error",
            _ => "Invalid status code",
        };
        let redirect = matches!(self.status, 301 | 302 | 303 | 307 | 308);
        let mut text = format!(
            "{kind} '{} {}' for url '{}'\n",
            self.status, self.reason, self.url
        );
        if let (true, Some(loc)) = (redirect, &self.location) {
            text.push_str(&format!("Redirect location: '{loc}'\n"));
        }
        text.push_str(&format!(
            "For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/{}",
            self.status
        ));
        Err(text)
    }

    /// `response.text`.
    pub fn text(&self) -> String {
        match self.charset.as_deref() {
            Some("iso-8859-1" | "latin-1" | "latin1") => {
                self.body.iter().map(|&b| char::from(b)).collect()
            }
            Some("ascii" | "us-ascii") => self
                .body
                .iter()
                .map(|&b| if b < 128 { char::from(b) } else { '\u{fffd}' })
                .collect(),
            _ => String::from_utf8_lossy(&self.body).into_owned(),
        }
    }

    /// `response.json()`.
    pub fn json(&self) -> Result<PyValue, PyExc> {
        let text = String::from_utf8_lossy(&self.body);
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        copilot_upstream::json::py_loads(text).map_err(PyExc::JsonDecode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, reason: &str, location: Option<&str>) -> HttpxResponse {
        HttpxResponse {
            status,
            reason: reason.into(),
            url: "https://example.com/index.json".into(),
            location: location.map(str::to_string),
            charset: None,
            body: Bytes::new(),
        }
    }

    #[test]
    fn status_errors_read_as_httpx_words_them() {
        assert!(answer(200, "OK", None).raise_for_status().is_ok());
        assert_eq!(
            answer(404, "Not Found", None)
                .raise_for_status()
                .unwrap_err(),
            "Client error '404 Not Found' for url 'https://example.com/index.json'\nFor more \
             information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/404"
        );
        assert_eq!(
            answer(301, "Moved Permanently", Some("/x"))
                .raise_for_status()
                .unwrap_err(),
            "Redirect response '301 Moved Permanently' for url 'https://example.com/index.json'\n\
             Redirect location: '/x'\nFor more information check: \
             https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/301"
        );
    }
}
