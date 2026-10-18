//! Starlette 1.0's `CORSMiddleware` as `copilot.py` configures it:
//! `allow_origins=["*"], allow_credentials=True, allow_methods=["*"],
//! allow_headers=["*"]`.
//!
//! - No `Origin`: the request passes untouched, and so does its answer.
//! - A preflight (`OPTIONS` with `Access-Control-Request-Method`) is
//!   answered here, whatever the path: `Vary: Origin`, the seven methods,
//!   `Max-Age: 600`, credentials, the origin mirrored, the requested headers
//!   mirrored; a method outside the seven (they are compared as sent, so
//!   `get` is one) or a private-network request is the 400
//!   `Disallowed CORS method, private-network`.
//! - Any other request with an `Origin` gets the origin mirrored (credentials
//!   are allowed, so never `*`), `Access-Control-Allow-Credentials: true`
//!   and `Vary: Origin`.
//!
//! In `copilot.py` the GZip middleware sits *outside* CORS, so the
//! `Vary: Accept-Encoding` it adds comes after CORS' `Origin`. Here the
//! compression happens inside (the router's compression layer, or a route
//! that applied `GZipMiddleware`'s rules itself), so a `Vary` the answer
//! already carries is that and is written after `Origin`, as Python's would
//! be. An answer marked [`PassThrough`] (the legacy backend's, which applied
//! its own CORS) is left as it is.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, StatusCode};

/// `CORSMiddleware`'s `ALL_METHODS` (`allow_methods=["*"]`).
pub const ALL_METHODS: [&str; 7] = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"];

/// A response extension: the answer is not this service's (the legacy
/// backend's), so CORS leaves it alone.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassThrough;

fn first<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a HeaderValue> {
    headers.get(name)
}

/// `bytes.decode("latin-1")`.
fn latin1(v: &HeaderValue) -> String {
    v.as_bytes().iter().map(|&b| char::from(b)).collect()
}

fn plain(status: StatusCode, text: &str, headers: Vec<(HeaderName, HeaderValue)>) -> Response {
    let mut resp = (status, text.to_string()).into_response();
    let h = resp.headers_mut();
    h.clear();
    for (k, v) in headers {
        h.append(k, v);
    }
    h.append(
        http::header::CONTENT_LENGTH,
        HeaderValue::from(text.len() as u64),
    );
    h.append(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn preflight(request: &HeaderMap, origin: &HeaderValue) -> Response {
    let mut headers: Vec<(HeaderName, HeaderValue)> = vec![
        (http::header::VARY, HeaderValue::from_static("Origin")),
        (
            http::header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT"),
        ),
        (
            http::header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        ),
        (
            http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        ),
        (http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone()),
    ];
    let mut failures: Vec<&str> = Vec::new();
    let method = first(request, "access-control-request-method")
        .map(latin1)
        .unwrap_or_default();
    if !ALL_METHODS.contains(&method.as_str()) {
        failures.push("method");
    }
    if let Some(requested) = first(request, "access-control-request-headers") {
        headers.push((
            http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            requested.clone(),
        ));
    }
    if request.contains_key("access-control-request-private-network") {
        failures.push("private-network");
    }
    if failures.is_empty() {
        plain(StatusCode::OK, "OK", headers)
    } else {
        let text = format!("Disallowed CORS {}", failures.join(", "));
        plain(StatusCode::BAD_REQUEST, &text, headers)
    }
}

/// `MutableHeaders.__setitem__`: the first value replaced in place, the
/// others dropped; appended when absent.
fn set_in_place(headers: &mut HeaderMap, name: HeaderName, value: HeaderValue) {
    // `HeaderMap::insert` keeps the entry's position and drops the others.
    headers.insert(name, value);
}

/// The simple-request headers on an answer.
pub fn apply_simple(headers: &mut HeaderMap, origin: &HeaderValue) {
    set_in_place(
        headers,
        http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        origin.clone(),
    );
    set_in_place(
        headers,
        http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    // Python's `Vary`: `Origin`, then what the (outer) GZip middleware adds.
    let mut value = b"Origin".to_vec();
    for existing in headers.get_all(http::header::VARY) {
        value.extend_from_slice(b", ");
        value.extend_from_slice(existing.as_bytes());
    }
    headers.remove(http::header::VARY);
    if let Ok(v) = HeaderValue::from_bytes(&value) {
        headers.append(http::header::VARY, v);
    }
}

/// The middleware.
pub async fn starlette_cors(req: Request, next: Next) -> Response {
    let Some(origin) = req.headers().get(http::header::ORIGIN).cloned() else {
        return next.run(req).await;
    };
    if req.method() == http::Method::OPTIONS
        && req.headers().contains_key("access-control-request-method")
    {
        return preflight(req.headers(), &origin);
    }
    let mut resp = next.run(req).await;
    if resp.extensions().get::<PassThrough>().is_none() {
        apply_simple(resp.headers_mut(), &origin);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vary_the_answer_carries_comes_after_origin() {
        let mut h = HeaderMap::new();
        h.append(
            http::header::VARY,
            HeaderValue::from_static("Accept-Encoding"),
        );
        apply_simple(&mut h, &HeaderValue::from_static("http://a"));
        assert_eq!(
            h.get(http::header::VARY).unwrap(),
            "Origin, Accept-Encoding"
        );
        assert_eq!(h.get("access-control-allow-origin").unwrap(), "http://a");
        assert_eq!(h.get("access-control-allow-credentials").unwrap(), "true");
    }
}
