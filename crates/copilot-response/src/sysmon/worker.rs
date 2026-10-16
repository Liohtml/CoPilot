//! `upload_to_wazuh`: the Sysmon config POSTed to the Wazuh master's
//! provisioning worker the way aiohttp 3.13 sends it, and its answer read
//! the way aiohttp reads it.
//!
//! The request: `POST http://{host}:5003/provision_worker/sysmon-config`
//! (the port is `COPILOT_PROVISION_WORKER_PORT` for the parity harness
//! only), `aiohttp.FormData` with a string field and a file field — so a
//! `multipart/form-data` body under a `uuid4().hex` boundary, each part with
//! its `Content-Type` before its `Content-Disposition` — and aiohttp's own
//! headers (`Accept: */*`, `Accept-Encoding: gzip, deflate`, `User-Agent:
//! Python/3.11 aiohttp/3.13.5`, `Content-Length`), no proxy (aiohttp's
//! `trust_env=False`), five minutes for the whole exchange.
//!
//! The answer: a 200's body is `response.json()` (a `ContentTypeError`
//! unless the type is `application/…json`, `None` for an empty body, else
//! `json.loads`), anything else `response.text()`. Failures are the
//! exceptions aiohttp raises, with their texts: `InvalidUrlClientError`
//! (the URL), `ClientConnectorError` / `ClientConnectorDNSError` (`Cannot
//! connect to host h:p ssl:default […]`), `ServerDisconnectedError`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_upstream::json::py_loads;
use copilot_upstream::py::PyExc;
use http::HeaderMap;

/// aiohttp's `User-Agent`.
pub const USER_AGENT: &str = "Python/3.11 aiohttp/3.13.5";
/// aiohttp's default whole-request timeout.
pub const TIMEOUT: Duration = Duration::from_secs(300);
/// The worker's port.
pub const WORKER_PORT: &str = "5003";
/// The worker's path.
pub const WORKER_PATH: &str = "/provision_worker/sysmon-config";

/// The client (no proxies, as aiohttp without `trust_env`).
#[derive(Debug, Clone)]
pub struct WorkerHttp {
    client: reqwest::Client,
}

/// What the worker answered.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// A 200: `await response.json()`.
    Json(PyValue),
    /// Any other status: `await response.text()`.
    Text(String),
}

impl WorkerHttp {
    /// Build the client.
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::limited(10))
                .build()?,
        })
    }

    /// `upload_to_wazuh(endpoint, customer_code, path)`: the form posted to
    /// `http://{host}:{port}{WORKER_PATH}`.
    pub async fn upload(
        &self,
        host: &str,
        port: &str,
        customer_code: &str,
        config: &[u8],
    ) -> Result<Answer, PyExc> {
        let url = format!("http://{host}:{port}{WORKER_PATH}");
        let boundary = uuid::Uuid::new_v4().simple().to_string();
        let body = form_body(&boundary, &customer_code.replace(' ', "_"), config);
        let send = async {
            let addrs = resolve(&url, host, port).await?;
            let port_n: u16 = port.parse().map_err(|_| invalid_url(&url))?;
            let target = reqwest::Url::parse(&url).map_err(|_| dns_failure(host, port))?;
            let resp = self
                .client
                .post(target)
                .header(http::header::ACCEPT, "*/*")
                .header(http::header::ACCEPT_ENCODING, "gzip, deflate")
                .header(http::header::USER_AGENT, USER_AGENT)
                .header(
                    http::header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(body)
                .send()
                .await
                .map_err(|e| transport_error(&e, host, port_n, &addrs))?;
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let raw = resp.bytes().await.map_err(|_| {
                PyExc::Other(
                    "ClientPayloadError",
                    "Response payload is not completed".into(),
                )
            })?;
            let raw = decode_content(&headers, raw)?;
            if status == 200 {
                Ok(Answer::Json(json_of(&headers, &raw, status, &url)?))
            } else {
                Ok(Answer::Text(text_of(&headers, &raw)?))
            }
        };
        match tokio::time::timeout(TIMEOUT, send).await {
            Ok(r) => r,
            Err(_) => Err(PyExc::Other("TimeoutError", String::new())),
        }
    }
}

/// `aiohttp.FormData` → `MultipartWriter("form-data", boundary)`.
pub fn form_body(boundary: &str, customer_code: &str, config: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Disposition: \
             form-data; name=\"customer_code\"\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(customer_code.as_bytes());
    out.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Type: application/xml\r\nContent-Disposition: \
             form-data; name=\"sysmon_config\"; filename=\"sysmon_config.xml\"\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(config);
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    out
}

fn invalid_url(url: &str) -> PyExc {
    PyExc::Other("InvalidUrlClientError", url.to_string())
}

fn dns_failure(host: &str, port: &str) -> PyExc {
    PyExc::Other(
        "ClientConnectorDNSError",
        format!("Cannot connect to host {host}:{port} ssl:default [Name or service not known]"),
    )
}

/// yarl's checks, then the resolver (`ClientConnectorDNSError`).
async fn resolve(url: &str, host: &str, port: &str) -> Result<Vec<SocketAddr>, PyExc> {
    if host.is_empty() || host.contains('[') || host.contains(']') {
        return Err(invalid_url(url));
    }
    let port_n: u16 = port.parse().map_err(|_| invalid_url(url))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port_n)]);
    }
    match tokio::net::lookup_host((host, port_n)).await {
        Ok(addrs) => {
            let addrs: Vec<SocketAddr> = addrs.collect();
            if addrs.is_empty() {
                Err(dns_failure(host, port))
            } else {
                Ok(addrs)
            }
        }
        Err(e) => {
            let text = e.to_string();
            let reason = text
                .strip_prefix("failed to lookup address information: ")
                .unwrap_or(&text);
            Err(PyExc::Other(
                "ClientConnectorDNSError",
                format!("Cannot connect to host {host}:{port} ssl:default [{reason}]"),
            ))
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

fn transport_error(e: &reqwest::Error, host: &str, port: u16, addrs: &[SocketAddr]) -> PyExc {
    let chain = error_chain(e);
    if e.is_connect() {
        let addr = addrs
            .first()
            .copied()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], port)));
        return PyExc::Other(
            "ClientConnectorError",
            format!(
                "Cannot connect to host {host}:{port} ssl:default [Connect call failed {}]",
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
fn decode_content(headers: &HeaderMap, raw: Bytes) -> Result<Bytes, PyExc> {
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
            flate2::read::MultiGzDecoder::new(&raw[..])
                .read_to_end(&mut out)
                .map_err(|_| failed())?;
        }
        "deflate" => {
            let zlib = raw.len() >= 2
                && raw[0] & 0x0f == 8
                && (u16::from(raw[0]) * 256 + u16::from(raw[1])) % 31 == 0;
            let result = if zlib {
                flate2::read::ZlibDecoder::new(&raw[..]).read_to_end(&mut out)
            } else {
                flate2::read::DeflateDecoder::new(&raw[..]).read_to_end(&mut out)
            };
            result.map_err(|_| failed())?;
        }
        _ => return Ok(raw),
    }
    Ok(Bytes::from(out))
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

/// `get_encoding()`: the `charset` parameter (when Python knows the
/// codec), else UTF-8.
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
        _ => copilot_objectstore::error::utf8(raw)
            .map_err(|e| PyExc::Other("UnicodeDecodeError", e.text())),
    }
}

/// `await response.text()`.
fn text_of(headers: &HeaderMap, raw: &[u8]) -> Result<String, PyExc> {
    decode(raw, &encoding_of(headers))
}

/// `^application/(?:[\w.+-]+?\+)?json`, on the lower-cased header.
fn is_json_type(ct: &str) -> bool {
    let Some(rest) = ct.strip_prefix("application/") else {
        return false;
    };
    if rest.starts_with("json") {
        return true;
    }
    // `[\w.+-]+?\+json`: some word characters, then `+json`.
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

/// `await response.json()`.
fn json_of(headers: &HeaderMap, raw: &[u8], status: u16, url: &str) -> Result<PyValue, PyExc> {
    let ct = content_type(headers).to_lowercase();
    if !is_json_type(&ct) {
        return Err(PyExc::Other(
            "ContentTypeError",
            format!(
                "{status}, message={}, url={}",
                str_repr(&format!(
                    "Attempt to decode JSON with unexpected mimetype: {ct}"
                )),
                str_repr(url)
            ),
        ));
    }
    let start = raw
        .iter()
        .position(|b| !b.is_ascii_whitespace() && *b != 0x0b)
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|b| !b.is_ascii_whitespace() && *b != 0x0b)
        .map_or(start, |i| i + 1);
    let stripped = &raw[start..end.max(start)];
    if stripped.is_empty() {
        return Ok(PyValue::None);
    }
    let text = decode(stripped, &encoding_of(headers))?;
    py_loads(&text).map_err(PyExc::JsonDecode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_is_aiohttps() {
        // aiohttp 3.13: `FormData` with `add_field("customer_code", "acme_x")`
        // and the file field, boundary fixed.
        let body = form_body("e4e4e984330641618392a81f7d4a9458", "acme_x", b"<Sysmon/>");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "--e4e4e984330641618392a81f7d4a9458\r\nContent-Type: text/plain; charset=utf-8\r\n\
             Content-Disposition: form-data; name=\"customer_code\"\r\n\r\nacme_x\r\n\
             --e4e4e984330641618392a81f7d4a9458\r\nContent-Type: application/xml\r\n\
             Content-Disposition: form-data; name=\"sysmon_config\"; \
             filename=\"sysmon_config.xml\"\r\n\r\n<Sysmon/>\r\n\
             --e4e4e984330641618392a81f7d4a9458--\r\n"
        );
    }

    #[test]
    fn json_types_follow_aiohttps_pattern() {
        for (ct, ok) in [
            ("application/json", true),
            ("application/json; charset=utf-8", true),
            ("application/problem+json", true),
            ("application/jsonx", true),
            ("text/json", false),
            ("application/x-ndjson", false),
            ("", false),
        ] {
            assert_eq!(is_json_type(ct), ok, "{ct}");
        }
    }
}
