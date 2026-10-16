//! HTTP transport to a SOCFortress WAF admin API — port of
//! `app/customer_waf/utils/universal.py`.
//!
//! One `customer_waf_instances` row, one client, built per request as
//! Python's `httpx.AsyncClient` is: `base_url` = the normalized API URL,
//! `Authorization: Bearer <decrypted token>`, `Accept: application/json`,
//! TLS verified against the row's CA (only that CA), the bundled roots, or not
//! at all when the operator left `verify_tls` off. The wire format is httpx
//! 0.28's: `params=` encoded like `urlencode` (`True` as `true`), `json=` as
//! compact UTF-8 JSON (`application/json`), `Content-Length: 0` on a
//! bodiless `POST`/`PUT`/`PATCH`, `Accept-Encoding: gzip, deflate`, no
//! redirects followed.
//!
//! **The error mapping is load-bearing.** A WAF 401/403 never becomes a
//! CoPilot 401/403 — the frontend would read it as the analyst's session
//! ending — so upstream failures are 502s with a stable `reason`
//! (`token_rejected`, `insufficient_role`, `unreachable`, `tls_error`, …),
//! 404 passes through as `not_found`, a disabled WAF is 409. The token lives
//! only in the outgoing header; nothing here logs it, its ciphertext or the
//! headers.

use std::time::Duration;

use bytes::Bytes;
use copilot_auth::pyvalue::PyValue;
use copilot_core::config::Secret;
use copilot_upstream::http::urlencode;
use copilot_upstream::json::{Dumps, py_dumps, py_loads};
use copilot_upstream::py::PyExc;
use copilot_web::form::py_strip;
use http::Method;

use crate::crypto::{self, CryptoError};
use crate::store::WafRow;

/// `API_PREFIX`.
pub const API_PREFIX: &str = "/api/v1";
/// `DEFAULT_TIMEOUT` (seconds).
pub const DEFAULT_TIMEOUT: f64 = 15.0;

/// Everything a WAF call can raise, by the class Python raises.
#[derive(Debug, Clone, PartialEq)]
pub enum WafError {
    /// `WafRequestError(reason, detail, status_code)`.
    Request {
        /// The stable code for the UI.
        reason: &'static str,
        /// For humans.
        detail: String,
        /// The status the route answers.
        status: u16,
    },
    /// `WafTokenCryptoError` (and its subclasses).
    Crypto(CryptoError),
    /// Anything else (`AttributeError`, a `ValidationError`, an
    /// `HTTPException`, …), handled where Python handles it.
    Py(PyExc),
}

impl WafError {
    fn request(reason: &'static str, detail: String) -> Self {
        Self::Request {
            reason,
            detail,
            status: 502,
        }
    }

    /// The `reason` of a `WafRequestError`.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Request { reason, .. } => Some(reason),
            _ => None,
        }
    }

    /// `getattr(e, "detail", None) or str(e)`.
    pub fn detail_or_str(&self) -> String {
        match self {
            Self::Request { detail, .. } => detail.clone(),
            Self::Crypto(c) => c.message.clone(),
            Self::Py(PyExc::Http(_, d)) if !d.is_empty() => d.clone(),
            Self::Py(e) => e.text(),
        }
    }
}

impl From<CryptoError> for WafError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<PyExc> for WafError {
    fn from(e: PyExc) -> Self {
        Self::Py(e)
    }
}

/// `WafResult`.
pub type WafResult<T> = Result<T, WafError>;

/// `normalize_api_url`: scheme + host (+ path prefix), no trailing `/`, no
/// `/api/v1`; the `ValueError` text otherwise.
pub fn normalize_api_url(api_url: &str) -> Result<String, String> {
    let url = py_strip(api_url).trim_end_matches('/');
    let parsed = copilot_webauthn::origin::urlsplit(url)?;
    if !matches!(parsed.scheme.as_str(), "http" | "https") || parsed.hostname().is_none() {
        return Err(
            "api_url must be a full http:// or https:// URL, e.g. https://waf.example.com:8080"
                .into(),
        );
    }
    Ok(url.strip_suffix(API_PREFIX).unwrap_or(url).to_string())
}

/// `f"{timeout:.0f}"`.
fn seconds(timeout: f64) -> String {
    format!("{timeout:.0}")
}

/// One call's options (`waf_request`'s keyword arguments).
#[derive(Debug, Clone)]
pub struct Call {
    /// Method.
    pub method: Method,
    /// Path relative to `/api/v1` (or to the base URL with `api: false`).
    pub path: String,
    /// `params=` (already `str()`-ed the way httpx does).
    pub params: Vec<(String, String)>,
    /// `json=`.
    pub json: Option<PyValue>,
    /// `timeout=` (seconds).
    pub timeout: f64,
    /// `api=`.
    pub api: bool,
    /// `allow_disabled=`.
    pub allow_disabled: bool,
}

impl Call {
    /// A call with Python's defaults.
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            params: Vec::new(),
            json: None,
            timeout: DEFAULT_TIMEOUT,
            api: true,
            allow_disabled: false,
        }
    }

    /// `GET`.
    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::GET, path)
    }

    /// With `params=`.
    pub fn params(mut self, params: Vec<(String, String)>) -> Self {
        self.params = params;
        self
    }

    /// With `json=`.
    pub fn json(mut self, body: PyValue) -> Self {
        self.json = Some(body);
        self
    }

    /// With `timeout=`.
    pub fn timeout(mut self, seconds: f64) -> Self {
        self.timeout = seconds;
        self
    }

    /// `api=False`.
    pub fn outside_api(mut self) -> Self {
        self.api = false;
        self
    }

    /// `allow_disabled=True`.
    pub fn allow_disabled(mut self) -> Self {
        self.allow_disabled = true;
        self
    }
}

/// The transport (stateless: each call builds its client, as Python does).
#[derive(Debug, Clone)]
pub struct WafClient {
    key: Option<Secret>,
}

/// The `detail` of a WAF error body, if it is a string.
fn upstream_detail(body: &Bytes) -> String {
    match std::str::from_utf8(body)
        .ok()
        .and_then(|t| py_loads(t).ok())
    {
        Some(PyValue::Dict(items)) => items
            .into_iter()
            .find(|(k, _)| k == "detail")
            .and_then(|(_, v)| match v {
                PyValue::Str(s) => Some(s),
                _ => None,
            })
            .unwrap_or_default(),
        _ => String::new(),
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

/// httpx's (urllib3-free) answer decoding: `gzip` / `deflate`.
fn decode(headers: &http::HeaderMap, raw: Bytes) -> Option<Bytes> {
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
                .ok()?;
        }
        "deflate" => {
            if flate2::read::ZlibDecoder::new(&raw[..])
                .read_to_end(&mut out)
                .is_err()
            {
                out.clear();
                flate2::read::DeflateDecoder::new(&raw[..])
                    .read_to_end(&mut out)
                    .ok()?;
            }
        }
        _ => return Some(raw),
    }
    Some(Bytes::from(out))
}

impl WafClient {
    /// A transport decrypting tokens with `WAF_TOKEN_ENCRYPTION_KEY`.
    pub fn new(key: Option<Secret>) -> Self {
        Self { key }
    }

    /// The key (for the crypto routes).
    pub fn key(&self) -> Option<&Secret> {
        self.key.as_ref()
    }

    fn build(&self, row: &WafRow, timeout: f64) -> WafResult<reqwest::Client> {
        let timeout = Duration::from_secs_f64(timeout.max(0.001));
        let mut b = reqwest::Client::builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("python-httpx/0.28.1");
        if !row.verify_tls {
            b = b.danger_accept_invalid_certs(true);
        } else if let Some(pem) = row.ca_cert_pem.as_deref().filter(|p| !p.is_empty()) {
            // `ssl.create_default_context(cadata=pem)`: only that CA. Its
            // `SSLError` is caught as a TLS failure; its `TypeError` is not.
            match crate::pem::check(pem) {
                crate::pem::PemCheck::Ok => {}
                crate::pem::PemCheck::SslError(text) => {
                    return Err(WafError::request(
                        "tls_error",
                        format!("TLS verification failed for WAF '{}': {text}", row.name),
                    ));
                }
                crate::pem::PemCheck::NotAscii => {
                    return Err(WafError::Py(PyExc::TypeError(
                        "cadata should be an ASCII string or a bytes-like object".into(),
                    )));
                }
            }
            let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes()).map_err(|e| {
                WafError::request(
                    "tls_error",
                    format!("TLS verification failed for WAF '{}': {e}", row.name),
                )
            })?;
            b = b.tls_built_in_root_certs(false);
            for c in certs {
                b = b.add_root_certificate(c);
            }
        }
        b.build()
            .map_err(|e| WafError::Py(PyExc::Other("RuntimeError", e.to_string())))
    }

    /// `waf_request`: the decoded JSON body (`None` for a 204).
    pub async fn request(&self, row: &WafRow, call: Call) -> WafResult<PyValue> {
        if !row.enabled && !call.allow_disabled {
            return Err(WafError::Request {
                reason: "disabled",
                detail: format!("WAF '{}' is disabled in CoPilot", row.name),
                status: 409,
            });
        }
        let url_path = if call.api {
            format!("{API_PREFIX}{}", call.path)
        } else {
            call.path.clone()
        };
        let where_ = format!("WAF {} ({}/{})", row.id, row.customer_code, row.name);
        let base = normalize_api_url(&row.api_url).map_err(PyExc::ValueError)?;
        // `_make_client`'s arguments in order: the URL, the TLS context, the token.
        let client = self.build(row, call.timeout)?;
        let token = crypto::decrypt_token(self.key.as_ref(), &row.service_token_encrypted)?;
        // httpx's `_merge_url`: the base gets a trailing `/`, the path loses
        // its leading one.
        let mut target = format!("{}/{}", base, url_path.trim_start_matches('/'));
        if !call.params.is_empty() {
            target.push('?');
            target.push_str(&urlencode(&call.params));
        }
        let mut req = client
            .request(call.method.clone(), &target)
            .header(http::header::ACCEPT_ENCODING, "gzip, deflate")
            .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(http::header::ACCEPT, "application/json");
        match &call.json {
            Some(body) => {
                let text = py_dumps(body, Dumps::HTTPX)
                    .map_err(|e| WafError::Py(PyExc::ValueError(e.to_string())))?;
                req = req
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(text.into_bytes());
            }
            None => {
                if matches!(call.method, Method::POST | Method::PUT | Method::PATCH) {
                    req = req.header(http::header::CONTENT_LENGTH, "0");
                }
            }
        }
        let sent = req.send().await;
        let resp = match sent {
            Ok(r) => r,
            Err(e) => return Err(self.transport_error(&e, row, &call, &url_path, &where_, &base)),
        };
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => return Err(self.transport_error(&e, row, &call, &url_path, &where_, &base)),
        };
        let body = decode(&headers, body).ok_or_else(|| {
            WafError::request(
                "unreachable",
                format!("Request to WAF '{}' failed: DecodingError", row.name),
            )
        })?;
        match status {
            401 => {
                return Err(WafError::request(
                    "token_rejected",
                    format!(
                        "WAF '{}' rejected the service token — it was revoked, disabled or \
                         expired, or its WAF user was disabled. Issue a new token in the WAF and \
                         update it here.",
                        row.name
                    ),
                ));
            }
            403 => {
                let upstream = upstream_detail(&body);
                let upstream = if upstream.is_empty() {
                    "forbidden".to_string()
                } else {
                    upstream
                };
                return Err(WafError::request(
                    "insufficient_role",
                    format!(
                        "The token's WAF user lacks permission for this action ({upstream}). \
                         Give that user a broader role in the WAF."
                    ),
                ));
            }
            404 => {
                let upstream = upstream_detail(&body);
                return Err(WafError::Request {
                    reason: "not_found",
                    detail: if upstream.is_empty() {
                        format!("Not found on WAF '{}'", row.name)
                    } else {
                        upstream
                    },
                    status: 404,
                });
            }
            s if s >= 400 => {
                tracing::warn!("{where_}: {} {url_path} returned HTTP {s}", call.method);
                return Err(WafError::request(
                    "upstream_error",
                    format!("WAF '{}' returned HTTP {s}", row.name),
                ));
            }
            204 => return Ok(PyValue::None),
            _ => {}
        }
        // `response.json()`: `json.loads` of the bytes.
        let parsed = copilot_auth::pyvalue::loads_bytes(&body).ok();
        parsed.ok_or_else(|| {
            WafError::request(
                "bad_response",
                format!(
                    "WAF '{}' returned a non-JSON response for {url_path} — check the API URL \
                     points at the WAF admin UI/API.",
                    row.name
                ),
            )
        })
    }

    fn transport_error(
        &self,
        e: &reqwest::Error,
        row: &WafRow,
        call: &Call,
        url_path: &str,
        where_: &str,
        base: &str,
    ) -> WafError {
        let chain = error_chain(e);
        if e.is_timeout() {
            tracing::warn!("{where_}: timed out on {} {url_path}", call.method);
            return WafError::request(
                "unreachable",
                format!(
                    "WAF '{}' did not respond within {}s",
                    row.name,
                    seconds(call.timeout)
                ),
            );
        }
        if e.is_connect() {
            if chain.contains("invalid peer certificate") || chain.contains("certificate") {
                return WafError::request(
                    "tls_error",
                    format!(
                        "TLS verification failed for WAF '{}'. Upload a trusted certificate on \
                         the WAF, or add its CA certificate here.",
                        row.name
                    ),
                );
            }
            tracing::warn!(
                "{where_}: connection failed on {} {url_path}: ConnectError",
                call.method
            );
            return WafError::request(
                "unreachable",
                format!("Could not connect to WAF '{}' at {base}", row.name),
            );
        }
        // httpx's other transport errors, by class name.
        let class = if chain.contains("connection closed before message completed")
            || chain.contains("IncompleteMessage")
            || chain.contains("incomplete")
            || chain.contains("unexpected EOF")
        {
            "RemoteProtocolError"
        } else if e.is_body() || e.is_decode() {
            "ReadError"
        } else if e.is_request() {
            "RemoteProtocolError"
        } else {
            "TransportError"
        };
        tracing::warn!("{where_}: {} {url_path} failed: {class}", call.method);
        WafError::request(
            "unreachable",
            format!("Request to WAF '{}' failed: {class}", row.name),
        )
    }

    /// `waf_get`.
    pub async fn get(&self, row: &WafRow, call: Call) -> WafResult<PyValue> {
        self.request(row, call).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_urls_like_python() {
        let v: serde_json::Value = serde_json::from_str(include_str!("waf_vectors.json")).unwrap();
        for case in v["api_urls"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let got = normalize_api_url(input);
            match case.get("ok") {
                Some(ok) => assert_eq!(got.as_deref(), Ok(ok.as_str().unwrap()), "{input:?}"),
                None => assert_eq!(
                    got.unwrap_err(),
                    case["error"].as_str().unwrap(),
                    "{input:?}"
                ),
            }
        }
        assert_eq!(seconds(15.0), "15");
        assert_eq!(seconds(5.0), "5");
    }
}
