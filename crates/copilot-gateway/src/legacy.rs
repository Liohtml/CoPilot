//! Reverse proxy to the Python backend for every route not ported yet.
//!
//! The Rust service owns the port the frontends call (5000); a request whose
//! path or method it does not serve is streamed — request body, response
//! body, SSE included — to `COPILOT_LEGACY_URL` unchanged:
//!
//! - method, path, query and headers are kept, including `Host` (FastAPI
//!   builds `request.url` from it, e.g. for `log_entries.route`);
//! - hop-by-hop headers (RFC 9110 §7.6.1) are dropped both ways;
//! - `X-Forwarded-For` gains the peer address, `X-Forwarded-Proto` is set
//!   when absent;
//! - nothing is buffered, decompressed or re-encoded, and there is no total
//!   timeout (report generation and chat streams run for minutes);
//! - redirects are passed through, never followed;
//! - an unreachable backend is a 502 in CoPilot's error envelope.

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::response::{IntoResponse, Response};
use futures::TryStreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::json;

/// Headers that describe one connection, not the message.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The legacy backend.
#[derive(Debug, Clone)]
pub struct LegacyProxy {
    base: url::Url,
    client: reqwest::Client,
}

impl LegacyProxy {
    /// Proxy to `base` (scheme, host, port; any path prefix is kept).
    pub fn new(base: url::Url) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(Duration::from_secs(90))
            .build()?;
        Ok(Self { base, client })
    }

    /// The configured base URL.
    pub fn base(&self) -> &url::Url {
        &self.base
    }

    /// The HTTP client (shared with the notification bridge).
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Upstream URL for a request path + query.
    pub fn upstream_url(&self, path_and_query: &str) -> String {
        format!(
            "{}{}",
            self.base.as_str().trim_end_matches('/'),
            path_and_query
        )
    }

    /// Forward one request.
    pub async fn forward(&self, req: Request) -> Response {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string());
        let (parts, body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_string();
        let url = self.upstream_url(&path);
        let mut headers = strip_hop_by_hop(&parts.headers);
        add_forwarded(&mut headers, peer.as_deref());

        let upstream = self
            .client
            .request(parts.method.clone(), &url)
            .headers(headers)
            .body(reqwest::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await;
        let resp = match upstream {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!(method = %parts.method, path = %parts.uri.path(), err = %e,
                    "legacy backend unreachable");
                return (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(json!({
                        "success": false,
                        "message": "The CoPilot legacy backend is unavailable",
                    })),
                )
                    .into_response();
            }
        };
        let status = resp.status();
        let headers = strip_hop_by_hop(resp.headers());
        let stream = resp.bytes_stream().map_err(std::io::Error::other);
        let mut out = Response::new(Body::from_stream(stream));
        *out.status_mut() = status;
        *out.headers_mut() = headers;
        out
    }
}

/// Copy `headers` without the hop-by-hop ones (and any header named by
/// `Connection`).
pub fn strip_hop_by_hop(headers: &HeaderMap) -> HeaderMap {
    let named_by_connection: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let lower = name.as_str();
        if HOP_BY_HOP.contains(&lower) || named_by_connection.iter().any(|n| n == lower) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn add_forwarded(headers: &mut HeaderMap, peer: Option<&str>) {
    if let Some(peer) = peer {
        let value = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(prev) if !prev.trim().is_empty() => format!("{prev}, {peer}"),
            _ => peer.to_string(),
        };
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static("x-forwarded-for"), v);
        }
    }
    headers
        .entry(HeaderName::from_static("x-forwarded-proto"))
        .or_insert(HeaderValue::from_static("http"));
}

/// Axum handler: `.fallback(proxy_handler).with_state(proxy)`.
pub async fn proxy_handler(State(proxy): State<LegacyProxy>, req: Request) -> Response {
    proxy.forward(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_are_dropped() {
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-secret-hop"),
        );
        h.insert("x-secret-hop", HeaderValue::from_static("1"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("authorization", HeaderValue::from_static("Bearer t"));
        h.insert("content-type", HeaderValue::from_static("application/json"));
        let out = strip_hop_by_hop(&h);
        assert!(out.get("connection").is_none());
        assert!(out.get("x-secret-hop").is_none());
        assert!(out.get("transfer-encoding").is_none());
        assert_eq!(out.get("authorization").unwrap(), "Bearer t");
        assert_eq!(out.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn forwarded_for_is_appended() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        add_forwarded(&mut h, Some("172.17.0.1"));
        assert_eq!(h.get("x-forwarded-for").unwrap(), "10.0.0.1, 172.17.0.1");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn upstream_url_joins_cleanly() {
        let p = LegacyProxy::new(url::Url::parse("http://legacy:5000/").unwrap()).unwrap();
        assert_eq!(
            p.upstream_url("/api/agents?x=1"),
            "http://legacy:5000/api/agents?x=1"
        );
    }
}
