//! The front of the service: every request is routed as Starlette routes it
//! before axum sees it, and answered by this process.
//!
//! ```text
//! request ─► decide ─► timing ─► CORS ─► 405 (a path some route has, not this method)
//!                                     └► the service's router ─► the route Starlette chose
//!                                                             └► 404, or the legacy backend
//! ```
//!
//! [`decide`] reads `scope["path"]` (the decoded path), takes `Router.app`'s
//! decision against the Python app's table and records it
//! ([`copilot_web::routing::Routed`], with the raw target and the decoded
//! path), then hands axum the path that leads it to the same route
//! ([`RouteTable::routing_path`]). The request timer
//! (`copilot_status::performance`) and CORS (`copilot_web::cors`) wrap the
//! rest, as `copilot.py`'s middleware wrap its router.
//!
//! A path no route of the Python app has is FastAPI's 404 — unless a legacy
//! backend is configured (`COPILOT_LEGACY_URL`, kept for a staged rollout or
//! a rollback) *and* the path is outside the prefixes the Python app's
//! routers are mounted at, which is the one case a request is forwarded. A
//! route the Python app has is always answered here, every method: the
//! legacy backend is never asked for it.

use axum::Router;
use axum::extract::{MatchedPath, OriginalUri, Request, State};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode};
use tower::ServiceExt as _;

use copilot_gateway::LegacyProxy;
use copilot_web::cors::{PassThrough, starlette_cors};
use copilot_web::routing::{
    Decision, RawUri, RouteKind, RouteTable, Routed, ScopePath, quote_decoded, scope_path,
};

/// Paths this service has that the Python app has not (always answered
/// here).
pub const RUST_ONLY_PREFIX: &str = "/_copilot/";

/// Response extension: the template of the route that answered (axum's
/// `MatchedPath`), for the tests that check it is the one Starlette chose.
#[derive(Debug, Clone)]
pub struct MatchedRoute(pub String);

async fn record_matched(req: Request, next: Next) -> Response {
    let matched = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string());
    let mut resp = next.run(req).await;
    if let Some(m) = matched {
        resp.extensions_mut().insert(MatchedRoute(m));
    }
    resp
}

/// FastAPI's 404: `{"detail": "Not Found"}`.
pub fn not_found() -> Response {
    detail_json(StatusCode::NOT_FOUND, "Not Found", None)
}

/// FastAPI's 405 for a route's `Allow`.
pub fn method_not_allowed(allow: &str) -> Response {
    detail_json(
        StatusCode::METHOD_NOT_ALLOWED,
        "Method Not Allowed",
        Some(allow),
    )
}

/// `JSONResponse({"detail": …}, status, headers=…)`: the `Allow` header,
/// then the length and the type, as Starlette writes them.
fn detail_json(status: StatusCode, detail: &str, allow: Option<&str>) -> Response {
    let body = serde_json::json!({ "detail": detail }).to_string();
    let mut resp = Response::new(axum::body::Body::from(body.clone()));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    if let Some(allow) = allow.and_then(|a| HeaderValue::from_str(a).ok()) {
        h.append(http::header::ALLOW, allow);
    }
    h.append(
        http::header::CONTENT_LENGTH,
        HeaderValue::from(body.len() as u64),
    );
    h.append(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// The URI with `path` in place of its path, the query kept as sent.
fn with_path(uri: &http::Uri, path: &str) -> Option<http::Uri> {
    let pq = match uri.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(pq.parse().ok()?);
    http::Uri::from_parts(parts).ok()
}

/// Starlette's decision, recorded on the request, and the path axum routes.
async fn decide(
    State(table): State<&'static RouteTable>,
    mut req: Request,
    next: Next,
) -> Response {
    let raw = req.uri().clone();
    let decoded = scope_path(raw.path());
    let decision = table.decide(req.method().as_str(), &decoded);
    let (template, routing) = match &decision {
        Decision::Full { index, params } => (
            template_of(table, *index),
            table.routing_path(*index, params, &decoded),
        ),
        Decision::Partial { index } => (template_of(table, *index), quote_decoded(&decoded)),
        Decision::None => (None, quote_decoded(&decoded)),
    };
    if let Some(uri) = with_path(&raw, &routing) {
        *req.uri_mut() = uri.clone();
        req.extensions_mut().insert(OriginalUri(uri));
    }
    req.extensions_mut().insert(RawUri(raw));
    req.extensions_mut().insert(ScopePath(decoded));
    req.extensions_mut().insert(Routed { decision, template });
    next.run(req).await
}

/// The template Python's request timer records for the route at `index`:
/// an API route's path (its `path_params` substituted back), none for a
/// mount or a documentation route (their `path_params` are empty).
fn template_of(table: &RouteTable, index: usize) -> Option<String> {
    table
        .route(index)
        .filter(|r| r.kind == RouteKind::Api)
        .map(|r| r.path.clone())
}

#[derive(Clone)]
struct FrontState {
    table: &'static RouteTable,
    inner: Router,
}

#[derive(Clone)]
struct Unrouted {
    table: &'static RouteTable,
    legacy: Option<LegacyProxy>,
}

/// The 405 of a partial match; everything else to the service's router.
async fn dispatch(State(st): State<FrontState>, req: Request) -> Response {
    let partial = match req.extensions().get::<Routed>().map(|r| &r.decision) {
        Some(Decision::Partial { index }) => Some(*index),
        _ => None,
    };
    if let Some(index) = partial {
        let allow = st
            .table
            .route(index)
            .map(|r| r.allow_header())
            .unwrap_or_default();
        return method_not_allowed(&allow);
    }
    let mut resp = match st.inner.oneshot(req).await {
        Ok(resp) => resp,
        Err(never) => match never {},
    };
    // Starlette writes no length on a 1xx, 204 or 304 (`init_headers`);
    // axum's routes add `content-length: 0` to every bodiless answer, this
    // router's own route too unless the body's size is unknown.
    let status = resp.status();
    if (status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED)
        && resp
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .is_some_and(|v| v == "0")
    {
        resp.headers_mut().remove(http::header::CONTENT_LENGTH);
        let (parts, _) = resp.into_parts();
        let empty = futures::stream::empty::<Result<&'static [u8], std::convert::Infallible>>();
        resp = Response::from_parts(parts, axum::body::Body::from_stream(empty));
    }
    resp
}

/// What the service's router found no route for.
async fn unrouted(st: Unrouted, mut req: Request, wrong_method: bool) -> Response {
    let decision = req.extensions().get::<Routed>().map(|r| r.decision.clone());
    let decoded = req
        .extensions()
        .get::<ScopePath>()
        .map(|p| p.0.clone())
        .unwrap_or_else(|| scope_path(req.uri().path()));
    if let Some(Decision::Full { index, .. }) = decision {
        // A route of the Python app this build has no handler for: a bug
        // the standalone probe (`rust_parity_standalone_e2e.py`) rules out.
        let route = st
            .table
            .route(index)
            .map(|r| r.path.clone())
            .unwrap_or_default();
        tracing::error!(method = %req.method(), route, "no handler for a route of the Python app");
        return not_found();
    }
    let ours = st.table.owns(&decoded) || decoded.starts_with(RUST_ONLY_PREFIX);
    match &st.legacy {
        Some(proxy) if !ours => {
            if let Some(raw) = req.extensions().get::<RawUri>().map(|r| r.0.clone()) {
                *req.uri_mut() = raw;
            }
            let mut resp = proxy.forward(req).await;
            resp.extensions_mut().insert(PassThrough);
            resp
        }
        _ if wrong_method => {
            detail_json(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed", None)
        }
        _ => not_found(),
    }
}

/// The service's `router` behind Starlette's routing, the request timer and
/// CORS; `legacy` answers only the paths outside the Python app's routing.
/// (The Python app's table is compiled in; were it unreadable — which
/// `App::new` and the tests rule out — every request would be the bare 500.)
pub fn front(router: Router, legacy: Option<LegacyProxy>) -> Router {
    let table = match crate::python::app() {
        Ok(app) => &app.table,
        Err(e) => {
            return Router::new().fallback(move || async move {
                copilot_web::ApiError::internal(e).into_response()
            });
        }
    };
    let unrouted_state = Unrouted { table, legacy };
    let (a, b) = (unrouted_state.clone(), unrouted_state);
    let inner = router
        .layer(from_fn(record_matched))
        .method_not_allowed_fallback(move |req: Request| unrouted(a.clone(), req, true))
        .fallback(move |req: Request| unrouted(b.clone(), req, false));
    Router::new()
        .fallback(dispatch)
        .with_state(FrontState { table, inner })
        .layer(from_fn(starlette_cors))
        .layer(from_fn(copilot_status::performance::middleware::timing))
        .layer(from_fn_with_state(table, decide))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn errors_read_like_fastapi() {
        let r = method_not_allowed("GET");
        assert_eq!(r.status(), 405);
        let names: Vec<_> = r.headers().keys().map(|k| k.as_str().to_string()).collect();
        assert_eq!(names, ["allow", "content-length", "content-type"]);
        let body = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], br#"{"detail":"Method Not Allowed"}"#);
        let body = axum::body::to_bytes(not_found().into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"detail":"Not Found"}"#);
    }
}
