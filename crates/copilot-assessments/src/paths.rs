//! Starlette routes the *decoded* path: `…/config/1%2Faudit` is
//! `…/config/1/audit` there (another route), `…/report/a%2Fb/x` matches no
//! route at all. axum routes the raw path, so a request whose path holds an
//! encoded `/` is routed again here on its decoded form — by these routes,
//! never handed to Python, so no encoded path reaches a Python handler that
//! lacks the tenant checks of the Rust one.
//!
//! The other escapes stay as they are: axum decodes each parameter once, as
//! Starlette's `unquote` of the whole path did. A request no route takes —
//! an unknown path, a method no route of that path has, a trailing slash
//! Starlette redirects — goes to the Python backend with its original URI
//! (FastAPI's 404 / 405 without one); Python answers it with the same
//! routing, so with a 404, 405 or redirect.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{ConnectInfo, OriginalUri, Request};
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use copilot_gateway::LegacyProxy;
use copilot_web::ApiError;
use tower::ServiceExt;

/// Whether a raw path holds an encoded `/`.
pub fn has_encoded_slash(path: &str) -> bool {
    path.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1] == b'2' && (w[2] == b'F' || w[2] == b'f'))
}

/// The raw path with every `%2F` decoded.
pub fn decode_slashes(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1] == b'2'
            && (bytes[i + 2] == b'F' || bytes[i + 2] == b'f')
        {
            out.push('/');
            i += 3;
        } else {
            // `path` is ASCII (a URI path), so byte and char indices agree.
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    out
}

fn original_uri(req: &Request) -> http::Uri {
    req.extensions()
        .get::<OriginalUri>()
        .map_or_else(|| req.uri().clone(), |o| o.0.clone())
}

/// The request with its path's `%2F`s decoded, as a fresh request: the
/// first routing's path parameters (an extension axum would extend, not
/// replace) are left behind; the original URI and the peer address are
/// carried over.
fn rerouted(req: Request) -> Request {
    let original = original_uri(&req);
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().cloned();
    let path = decode_slashes(original.path());
    let target = match original.query() {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    let (parts, body) = req.into_parts();
    let mut uri = parts.uri;
    if let Ok(pq) = target.parse::<http::uri::PathAndQuery>() {
        let mut uri_parts = original.clone().into_parts();
        uri_parts.path_and_query = Some(pq);
        if let Ok(decoded) = http::Uri::from_parts(uri_parts) {
            uri = decoded;
        }
    }
    let mut fresh = Request::new(body);
    *fresh.method_mut() = parts.method;
    *fresh.uri_mut() = uri;
    *fresh.version_mut() = parts.version;
    *fresh.headers_mut() = parts.headers;
    fresh.extensions_mut().insert(OriginalUri(original));
    if let Some(peer) = peer {
        fresh.extensions_mut().insert(peer);
    }
    fresh
}

/// A request no route takes: Python's answer for its original URI.
async fn unrouted(legacy: Option<LegacyProxy>, mut req: Request, wrong_method: bool) -> Response {
    *req.uri_mut() = original_uri(&req);
    match legacy {
        Some(proxy) => proxy.forward(req).await,
        None if wrong_method => ApiError::MethodNotAllowed.into_response(),
        None => ApiError::RouteNotFound.into_response(),
    }
}

async fn dispatch(inner: Router, req: Request) -> Response {
    match inner.oneshot(rerouted(req)).await {
        Ok(resp) => resp,
        Err(never) => match never {},
    }
}

/// `build()`'s routes (full paths under `prefix`) routed as Starlette
/// routes them.
pub fn starlette_routing(
    build: impl Fn() -> Router,
    prefix: &str,
    legacy: Option<LegacyProxy>,
) -> Router {
    let (l1, l2, l3, l4) = (
        legacy.clone(),
        legacy.clone(),
        legacy.clone(),
        legacy.clone(),
    );
    let inner = build()
        .method_not_allowed_fallback(move |req: Request| unrouted(l1.clone(), req, true))
        .fallback(move |req: Request| unrouted(l2.clone(), req, false));
    let reroute = {
        let inner = inner.clone();
        move |req: Request, next: Next| {
            let inner = inner.clone();
            async move {
                if has_encoded_slash(original_uri(&req).path()) {
                    dispatch(inner, req).await
                } else {
                    next.run(req).await
                }
            }
        }
    };
    let catch_all = move |req: Request| {
        let inner = inner.clone();
        let legacy = l4.clone();
        async move {
            if has_encoded_slash(original_uri(&req).path()) {
                dispatch(inner, req).await
            } else {
                unrouted(legacy, req, false).await
            }
        }
    };
    build()
        .method_not_allowed_fallback(move |req: Request| unrouted(l3.clone(), req, true))
        .layer(from_fn(reroute))
        .route(&format!("{prefix}/{{*rest}}"), any(catch_all))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_encoded_slashes_are_decoded() {
        assert!(has_encoded_slash("/a%2fb") && has_encoded_slash("/a%2Fb"));
        assert!(!has_encoded_slash("/a%252Fb") && !has_encoded_slash("/a/b%2"));
        assert_eq!(decode_slashes("/x/1%2Faudit"), "/x/1/audit");
        assert_eq!(decode_slashes("/x/a%252Fb%20c"), "/x/a%252Fb%20c");
        assert_eq!(decode_slashes("/x/a%2f%2F"), "/x/a//");
    }
}
