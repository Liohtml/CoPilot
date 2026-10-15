//! What every provider shares: `SendResult`, the HTTP clients, a route's
//! stored config, connector credentials and the error texts of a failed
//! request (`services/dispatchers.py`).

use std::time::{Duration, Instant};

use copilot_auth::pyvalue::{self, PyValue};
use copilot_db::DbError;
use copilot_db::connectors::ConnectorCache;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::channels::Channel;
use crate::channels::config;
use crate::db::RouteRow;
use crate::pydantic;

/// `sent` | `failed` | `skipped`.
pub const SENT: &str = "sent";
/// A failed delivery.
pub const FAILED: &str = "failed";
/// A delivery not attempted.
pub const SKIPPED: &str = "skipped";

/// `SendResult`: one delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendResult {
    /// `sent` | `failed` | `skipped`.
    pub status: &'static str,
    /// Why not sent.
    pub error_message: Option<String>,
    /// Provider round-trip.
    pub latency_ms: Option<i64>,
    /// Vendor id of the delivery.
    pub provider_reference: Option<String>,
    /// The provider "raised" (Python: `send()` threw and the caller turned
    /// the exception into a failure, without a latency in the dispatch loop
    /// and with latency 0 in `deliver_one`).
    pub raised: bool,
}

impl SendResult {
    /// `SendResult.failed(message)` (latency 0).
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            status: FAILED,
            error_message: Some(message.into()),
            latency_ms: Some(0),
            provider_reference: None,
            raised: false,
        }
    }

    /// `SendResult.skipped(message)` (latency 0).
    pub fn skipped(message: impl Into<String>) -> Self {
        Self {
            status: SKIPPED,
            error_message: Some(message.into()),
            latency_ms: Some(0),
            provider_reference: None,
            raised: false,
        }
    }

    /// `send()` raised `{type_name}: {message}`: `Dispatcher exception: …`.
    pub fn raised(type_name: &str, message: impl std::fmt::Display) -> Self {
        Self {
            status: FAILED,
            error_message: Some(format!("Dispatcher exception: {type_name}: {message}")),
            latency_ms: None,
            provider_reference: None,
            raised: true,
        }
    }

    /// A dispatcher's `(status, error, latency, reference)` tuple.
    pub fn from_parts(
        status: &'static str,
        error_message: Option<String>,
        latency_ms: i64,
        provider_reference: Option<String>,
    ) -> Self {
        Self {
            status,
            error_message,
            latency_ms: Some(latency_ms),
            provider_reference,
            raised: false,
        }
    }
}

/// A connector's `(base_url, api_key, default_from)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Base URL.
    pub base_url: String,
    /// API key.
    pub api_key: String,
    /// Resend's `connector_extra_data` (default From address).
    pub default_from: Option<String>,
}

/// Why a connector cannot be used: the `HTTPException(503, detail)` the
/// Python helpers raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable(pub String);

/// `get_resend_connector` / `get_shuffle_connector`.
pub async fn connector_credentials(
    connectors: &ConnectorCache,
    channel: Channel,
) -> Result<Result<Credentials, Unavailable>, DbError> {
    let (name, default_url, missing, no_key) = match channel {
        Channel::Resend => (
            "Resend",
            "https://api.resend.com",
            "Resend connector is not configured in CoPilot. Add the Resend connector with a \
             valid API key before creating email notification routes.",
            "Resend connector is configured but has no API key set.",
        ),
        _ => (
            "Shuffle",
            "https://shuffler.io",
            "Shuffle connector is not configured in CoPilot. Add the Shuffle connector with a \
             valid API key before creating Shuffle-channel notification routes.",
            "Shuffle connector is configured but has no API key set.",
        ),
    };
    let Some(row) = connectors.get(name).await? else {
        return Ok(Err(Unavailable(missing.into())));
    };
    let api_key = row.connector_api_key.clone().unwrap_or_default();
    if api_key.is_empty() {
        return Ok(Err(Unavailable(no_key.into())));
    }
    Ok(Ok(Credentials {
        base_url: if row.connector_url.is_empty() {
            default_url.to_string()
        } else {
            row.connector_url.clone()
        },
        api_key,
        default_from: row.connector_extra_data.filter(|f| !f.is_empty()),
    }))
}

/// The outbound HTTP clients: TLS verified (webhook, Teams, Resend) and not
/// (Shuffle, which is often self-hosted behind a private CA — #1087).
#[derive(Debug, Clone)]
pub struct Outbound {
    /// Verified client.
    pub http: reqwest::Client,
    /// Shuffle's client (`verify=False`).
    pub shuffle: reqwest::Client,
}

impl Outbound {
    /// Build both clients. Redirects are not followed (httpx's default).
    pub fn new() -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let shuffle = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .build()?;
        Ok(Self { http, shuffle })
    }
}

/// `int((monotonic() - started) * 1000)`.
pub fn elapsed_ms(started: Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// `f"{type(e).__name__}: {e}"` for a request httpx could not complete: the
/// common cases in httpx's words, anything else under httpx's class with
/// reqwest's description.
pub fn transport_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return if e.is_connect() {
            "ConnectTimeout: ".to_string()
        } else {
            "ReadTimeout: ".to_string()
        };
    }
    if e.is_connect() {
        let text = format!("{e:?}");
        if text.contains("Connection refused") || text.contains("ConnectionRefused") {
            return "ConnectError: All connection attempts failed".to_string();
        }
        return format!("ConnectError: {}", error_chain(e));
    }
    if e.is_builder() {
        return format!("UnsupportedProtocol: {}", error_chain(e));
    }
    format!("{}: {}", "RemoteProtocolError", error_chain(e))
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

/// A response's `text` (lossy UTF-8) and its first 200 characters.
pub async fn response_text(resp: reqwest::Response) -> String {
    match resp.bytes().await {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(_) => String::new(),
    }
}

/// `text[:200]`.
pub fn first_200(text: &str) -> String {
    text.chars().take(200).collect()
}

/// `response.json()`: CPython's parse, or `None` (a `ValueError`).
pub fn response_json(text: &str) -> Option<PyValue> {
    pyvalue::loads(text).ok()
}

/// A dict-less value's `.get` failure, as Python words it.
pub fn no_get(v: &PyValue) -> String {
    format!(
        "AttributeError: '{}' object has no attribute 'get'",
        pydantic::input_type(v)
    )
}

/// `ChannelProvider.parse_config(route)`: the route's stored config,
/// validated; the error is the `ValueError` text.
pub fn parse_config(channel: Channel, route: &RouteRow) -> Result<PyValue, String> {
    let raw = route.config.as_deref().unwrap_or_default();
    if raw.is_empty() {
        return config::validate(channel, &[])
            .map_err(|e| pydantic::format(channel.model_name(), &e));
    }
    let data = match pyvalue::loads(raw) {
        Ok(v) => v,
        Err(_) => {
            let pos = copilot_web::pyjson::error_position(raw).unwrap_or(0);
            let (line, col) = line_col(raw, pos);
            return Err(format!(
                "config is not valid JSON: Expecting value: line {line} column {col} (char {pos})"
            ));
        }
    };
    let Some(items) = config::dict_items(&data) else {
        return Err("config must be a JSON object".into());
    };
    config::validate(channel, items).map_err(|e| pydantic::format(channel.model_name(), &e))
}

fn line_col(text: &str, pos: usize) -> (usize, usize) {
    let before: String = text.chars().take(pos).collect();
    let line = before.matches('\n').count() + 1;
    let col = match before.rfind('\n') {
        Some(i) => before[i + 1..].chars().count() + 1,
        None => pos + 1,
    };
    (line, col)
}

/// A string field of a validated config (`None` when null).
pub fn cfg_str(cfg: &PyValue, key: &str) -> Option<String> {
    cfg.get(key).and_then(PyValue::as_str).map(str::to_string)
}

/// `UnicodeEncodeError.__str__` for the first character run ASCII cannot
/// encode.
fn ascii_error(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let start = chars.iter().position(|c| !c.is_ascii())?;
    let end = start + chars[start..].iter().take_while(|c| !c.is_ascii()).count();
    let what = if end - start == 1 {
        let c = chars[start] as u32;
        let escaped = if c < 0x100 {
            format!("\\x{c:02x}")
        } else if c < 0x10000 {
            format!("\\u{c:04x}")
        } else {
            format!("\\U{c:08x}")
        };
        format!("character '{escaped}' in position {start}")
    } else {
        format!("characters in position {start}-{}", end - 1)
    };
    Some(format!(
        "UnicodeEncodeError: 'ascii' codec can't encode {what}: ordinal not in range(128)"
    ))
}

/// h11's `token`: a header name.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-!#$%&'*+.^_`|~".contains(&b))
}

/// h11's `field_value`: visible bytes, with spaces and tabs only between them.
fn is_field_value(value: &str) -> bool {
    let vchar = |b: u8| b != 0 && !b" \t\n\r\x0b\x0c".contains(&b);
    let bytes = value.as_bytes();
    match (bytes.first(), bytes.last()) {
        (None, _) | (_, None) => true,
        (Some(&first), Some(&last)) => {
            vchar(first)
                && vchar(last)
                && bytes.iter().all(|&b| vchar(b) || b == b' ' || b == b'\t')
        }
    }
}

/// What httpx raises for these request headers, if anything: it encodes
/// names and values as ASCII when it builds the request
/// (`UnicodeEncodeError`), and h11 validates them as it writes it
/// (`LocalProtocolError`). Python reports it as the delivery's error; h11's
/// check comes after the connection is made, ours before (the one case where
/// an unreachable host with a bad header reads differently).
pub fn python_header_error<K: AsRef<str>, V: AsRef<str>>(pairs: &[(K, V)]) -> Option<String> {
    for (k, v) in pairs {
        if let Some(e) = ascii_error(k.as_ref()).or_else(|| ascii_error(v.as_ref())) {
            return Some(e);
        }
    }
    for (k, v) in pairs {
        if !is_token(k.as_ref()) {
            return Some(format!(
                "LocalProtocolError: Illegal header name {}",
                py_bytes(k.as_ref())
            ));
        }
        if !is_field_value(v.as_ref()) {
            return Some(format!(
                "LocalProtocolError: Illegal header value {}",
                py_bytes(v.as_ref())
            ));
        }
    }
    None
}

/// Request headers as a Python dict holds them: later keys replace an
/// identical key in place, case-sensitively. `Err` is what httpx would raise.
pub fn header_map<K: AsRef<str>, V: AsRef<str>>(pairs: &[(K, V)]) -> Result<HeaderMap, String> {
    if let Some(e) = python_header_error(pairs) {
        return Err(e);
    }
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        let (k, v) = (k.as_ref(), v.as_ref());
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| format!("LocalProtocolError: Illegal header name {}", py_bytes(k)))?;
        let value = HeaderValue::from_str(v)
            .map_err(|_| format!("LocalProtocolError: Illegal header value {}", py_bytes(v)))?;
        map.append(name, value);
    }
    Ok(map)
}

fn py_bytes(s: &str) -> String {
    pyvalue::bytes_repr(s.as_bytes())
}

/// `dict.update` on a list of pairs.
pub fn dict_set(pairs: &mut Vec<(String, String)>, key: &str, value: &str) {
    match pairs.iter_mut().find(|(k, _)| k == key) {
        Some((_, v)) => *v = value.to_string(),
        None => pairs.push((key.to_string(), value.to_string())),
    }
}

/// A timeout as a `Duration`.
pub const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_errors_are_httpx_and_h11s() {
        let err = |k: &str, v: &str| python_header_error(&[(k, v)]);
        assert_eq!(
            err("Org-Id", " org-1").as_deref(),
            Some("LocalProtocolError: Illegal header value b' org-1'")
        );
        assert_eq!(
            err("Org-Id", "org-1 ").as_deref(),
            Some("LocalProtocolError: Illegal header value b'org-1 '")
        );
        assert_eq!(
            err("X Key", "v").as_deref(),
            Some("LocalProtocolError: Illegal header name b'X Key'")
        );
        assert_eq!(err("X", "a\tb"), None);
        assert_eq!(
            err("X", "a\nb").as_deref(),
            Some("LocalProtocolError: Illegal header value b'a\\nb'")
        );
        assert_eq!(err("X", ""), None);
        assert_eq!(err("X", "it's"), None);
        assert_eq!(
            err("X", "é").as_deref(),
            Some(
                "UnicodeEncodeError: 'ascii' codec can't encode character '\\xe9' in position 0: \
                 ordinal not in range(128)"
            )
        );
        assert_eq!(
            err("X", "ab——c").as_deref(),
            Some(
                "UnicodeEncodeError: 'ascii' codec can't encode characters in position 2-3: \
                 ordinal not in range(128)"
            )
        );
        assert_eq!(
            err("Xé", "v").as_deref(),
            Some(
                "UnicodeEncodeError: 'ascii' codec can't encode character '\\xe9' in position 1: \
                 ordinal not in range(128)"
            )
        );
        assert_eq!(
            err("X", "😀").as_deref(),
            Some(
                "UnicodeEncodeError: 'ascii' codec can't encode character '\\U0001f600' in position \
                 0: ordinal not in range(128)"
            )
        );
    }
}
