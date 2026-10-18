//! The service answering every request itself (`copilot-standalone`): the
//! production router on MySQL, a legacy backend replaced by a recorder.
//!
//! - every route of the Python app (the compiled-in table), token-less, at
//!   its path and with an encoded `/` in a parameter or in place of a
//!   separator, reaches a Rust handler — the one Starlette chooses — and
//!   never the legacy backend;
//! - FastAPI's 404 and 405 (`Allow` of the first route whose path matched),
//!   `redirect_slashes=False`, `HEAD`/`OPTIONS`, CORS;
//! - the decoded path routed as Starlette routes it, a conflict included
//!   (Starlette's declaration order against axum's static-first rule);
//! - `/docs`, `/docs/oauth2-redirect`, `/redoc`, `/openapi.json`, `GET /`,
//!   the `/scoutsuite-report` mount;
//! - the legacy backend for a path outside the Python app only;
//! - every connector Python verifies has a Rust verifier.
//!
//! Ports: `STANDALONE_E2E_PORT_BASE` (default 6600): +0 the recorder, +1 a
//! closed port the unauthenticated upstream calls go to.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod common;
use common::*;

use axum::body::Body;
use http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

use copilot_standalone::front::MatchedRoute;
use copilot_web::routing::{Decision, RouteKind};

const RECORDER: u16 = 0;
const CLOSED: u16 = 1;

fn port(offset: u16) -> u16 {
    std::env::var("STANDALONE_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6600)
        + offset
}

fn configured() -> bool {
    std::env::var("COPILOT_TEST_DATABASE_URL").is_ok()
}

async fn stand_in(offset: u16) -> MockServer {
    let mut tries = 0;
    let listener = loop {
        match std::net::TcpListener::bind(("127.0.0.1", port(offset))) {
            Ok(l) => break l,
            Err(_) if tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("cannot bind the stand-in on {}: {e}", port(offset)),
        }
    };
    MockServer::builder().listener(listener).start().await
}

/// A recorder answering 599 to anything.
async fn recorder() -> MockServer {
    let r = stand_in(RECORDER).await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(599).set_body_string("legacy"))
        .mount(&r)
        .await;
    r
}

/// What the unauthenticated routes would reach upstream goes to a closed port.
fn closed_env() -> String {
    let closed = format!("http://127.0.0.1:{}", port(CLOSED));
    format!(
        "COPILOT_VERSION_CHECK_URL={closed}/releases/latest\nCOPILOT_SSO_IDP_URL={closed}\n\
         COPILOT_CATALOG_REFRESH=false\nCOPILOT_SIDEBAR_REFRESH=false\n"
    )
}

struct Answer {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
    matched: Option<String>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

async fn send(h: &Harness, method: &str, uri: &str, headers: &[(&str, &str)]) -> Answer {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let resp = h
        .router
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let matched = resp.extensions().get::<MatchedRoute>().map(|m| m.0.clone());
    let body = axum::body::to_bytes(resp.into_body(), 64 << 20)
        .await
        .unwrap()
        .to_vec();
    Answer {
        status,
        headers,
        body,
        matched,
    }
}

/// A path template with its parameters' names erased (`{}` / `{*}`), axum's
/// spelling or Starlette's.
fn shape(template: &str) -> String {
    template
        .split('/')
        .map(|seg| {
            if seg.starts_with("{*") || seg.ends_with(":path}") {
                "{*}".to_string()
            } else if seg.starts_with('{') {
                "{}".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The route's path with each parameter filled in.
fn fill(template: &str, value: &str) -> String {
    template
        .split('/')
        .map(|seg| {
            if seg.ends_with(":path}") {
                format!("{value}/y")
            } else if seg.starts_with('{') {
                value.to_string()
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Routers that dispatch a whole prefix themselves, on the decoded path as
/// Starlette routes it (`copilot-searches`).
fn dispatched_by_prefix(matched: &str) -> bool {
    matched == "/api/copilot_searches" || matched == "/api/copilot_searches/{*rest}"
}

#[tokio::test]
async fn every_python_route_is_answered_by_its_rust_handler() {
    if !configured() {
        return;
    }
    let legacy = recorder().await;
    let h = harness_or_skip!(Some(&legacy), &closed_env());
    let table = &copilot_standalone::python::app().unwrap().table;
    let mut checked = 0;
    let mut mismatched = Vec::new();
    for (index, route) in table.routes().iter().enumerate() {
        if route.kind == RouteKind::Mount {
            continue;
        }
        for method in &route.methods {
            if method == "HEAD" {
                continue;
            }
            let path = fill(&route.path, "x");
            // Starlette's own decision for the request (an earlier route of
            // the same path and method answers it in Python too).
            let Decision::Full { index: chosen, .. } = table.decide(method, &path) else {
                panic!("{method} {path}: no full match in its own table");
            };
            let template = &table.route(chosen).unwrap().path;
            let a = send(&h, method, &path, &[]).await;
            let Some(matched) = a.matched.clone() else {
                mismatched.push(format!("{method} {path}: no Rust handler ({})", a.status));
                continue;
            };
            if shape(&matched) != shape(template) && !dispatched_by_prefix(&matched) {
                mismatched.push(format!(
                    "{method} {path}: Rust ran {matched}, Starlette {template}"
                ));
            }
            checked += 1;
            let _ = index;
        }
    }
    assert!(mismatched.is_empty(), "{}", mismatched.join("\n"));
    assert!(checked > 800, "{checked}");
    assert!(
        legacy.received_requests().await.unwrap().is_empty(),
        "a route of the Python app reached the legacy backend"
    );
}

#[tokio::test]
async fn encoded_slashes_never_reach_the_legacy_backend() {
    if !configured() {
        return;
    }
    let legacy = recorder().await;
    let h = harness_or_skip!(Some(&legacy), &closed_env());
    let table = &copilot_standalone::python::app().unwrap().table;
    let mut sent = 0;
    for route in table.routes() {
        if route.kind == RouteKind::Mount {
            continue;
        }
        let method = route.methods.iter().find(|m| *m != "HEAD").unwrap();
        // A parameter holding an encoded `/`.
        if route.path.contains('{') {
            let path = fill(&route.path, "a%2Fb");
            let decoded = copilot_web::routing::scope_path(&path);
            let a = send(&h, method, &path, &[]).await;
            if table.decide(method, &decoded) == Decision::None {
                assert_eq!(
                    (a.status, a.json()),
                    (StatusCode::NOT_FOUND, json!({"detail": "Not Found"})),
                    "{method} {path}"
                );
            }
            sent += 1;
        }
        // The last separator encoded: the same route as the plain path.
        let plain = fill(&route.path, "x");
        if let Some(cut) = plain.rfind('/').filter(|c| *c > 0) {
            let encoded = format!("{}%2F{}", &plain[..cut], &plain[cut + 1..]);
            let (a, b) = (
                send(&h, method, &plain, &[]).await,
                send(&h, method, &encoded, &[]).await,
            );
            assert_eq!(a.status, b.status, "{method} {encoded}");
            assert_eq!(a.matched, b.matched, "{method} {encoded}");
            sent += 2;
        }
    }
    assert!(sent > 1000, "{sent}");
    assert!(legacy.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn unmatched_paths_read_like_fastapi() {
    let h = harness_or_skip!(None);
    let not_found = json!({"detail": "Not Found"});
    for path in [
        "/api/nothing-here",
        "/api/customers/",
        "/api/agents/a/b/c",
        "/x",
        "/api",
        "/scoutsuite-report",
    ] {
        let a = send(&h, "GET", path, &[]).await;
        assert_eq!(
            (a.status, a.json()),
            (StatusCode::NOT_FOUND, not_found.clone()),
            "{path}"
        );
        assert_eq!(a.headers["content-type"], "application/json");
        assert!(a.headers.get("access-control-allow-origin").is_none());
    }
    // 405: the first route whose path matched names `Allow` (Python's
    // `GET /{connector_id}` comes before its `PUT`).
    let a = send(&h, "DELETE", "/api/connectors/1", &[]).await;
    assert_eq!(a.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(a.json(), json!({"detail": "Method Not Allowed"}));
    assert_eq!(a.headers["allow"], "GET");
    // FastAPI adds no HEAD to an API route; Starlette's documentation routes
    // have it.
    // (`POST /api/customers` is declared before its `GET`.)
    let a = send(&h, "HEAD", "/api/customers", &[]).await;
    assert_eq!(a.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(a.headers["allow"], "POST");
    let a = send(&h, "HEAD", "/docs", &[]).await;
    assert_eq!(a.status, StatusCode::OK);
    assert!(a.body.is_empty());
    let a = send(&h, "OPTIONS", "/api/customers", &[]).await;
    assert_eq!(a.status, StatusCode::METHOD_NOT_ALLOWED);
    let a = send(&h, "POST", "/docs", &[]).await;
    assert_eq!(a.status, StatusCode::METHOD_NOT_ALLOWED);
    // Python's order is its `set`'s, which varies per process (§4).
    assert_eq!(a.headers["allow"], "GET, HEAD");
    // CORS: a preflight anywhere, the origin mirrored on the 404.
    let a = send(
        &h,
        "OPTIONS",
        "/api/customers",
        &[
            ("origin", "http://localhost:5173"),
            ("access-control-request-method", "POST"),
        ],
    )
    .await;
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(a.body, b"OK");
    assert_eq!(
        a.headers["access-control-allow-origin"],
        "http://localhost:5173"
    );
    assert_eq!(
        a.headers["access-control-allow-methods"],
        "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT"
    );
    let a = send(&h, "GET", "/api/nothing", &[("origin", "http://a")]).await;
    assert_eq!(a.status, StatusCode::NOT_FOUND);
    assert_eq!(a.headers["access-control-allow-origin"], "http://a");
    assert_eq!(a.headers["access-control-allow-credentials"], "true");
    assert_eq!(a.headers["vary"], "Origin");
    // `GET /`.
    let a = send(&h, "GET", "/", &[]).await;
    assert_eq!(a.json(), json!({"message": "CoPilot - We Made It!"}));
    let a = send(&h, "POST", "/", &[]).await;
    assert_eq!(
        (a.status, a.headers["allow"].to_str().unwrap()),
        (StatusCode::METHOD_NOT_ALLOWED, "GET")
    );
}

#[tokio::test]
async fn the_decoded_path_is_routed_as_starlette_routes_it() {
    let h = harness_or_skip!(None);
    // An encoded `/` in place of a separator is that separator.
    let a = send(&h, "POST", "/api/connectors/verify%2F1", &[]).await;
    let b = send(&h, "POST", "/api/connectors/verify/1", &[]).await;
    assert_eq!((a.status, a.json()), (b.status, b.json()));
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    // In a parameter it splits the path: no route.
    let a = send(&h, "GET", "/api/customers/a%2Fb", &[]).await;
    assert_eq!(
        (a.status, a.json()),
        (StatusCode::NOT_FOUND, json!({"detail": "Not Found"}))
    );
    // Starlette's order: `DELETE /api/auth/passkey/{passkey_id}` takes
    // `status`, where axum would prefer the static `GET …/status` (a 405).
    let a = send(&h, "DELETE", "/api/auth/passkey/status", &[]).await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    assert_eq!(a.matched.as_deref(), Some("/api/auth/passkey/{passkey_id}"));
    // … and `GET /api/agents/sync` is the agent named `sync`.
    let a = send(&h, "GET", "/api/agents/sync", &[]).await;
    assert_eq!(a.matched.as_deref(), Some("/api/agents/{agent_id}"));
}

#[tokio::test]
async fn the_documentation_is_served() {
    let h = harness_or_skip!(None);
    let a = send(&h, "GET", "/openapi.json", &[]).await;
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(a.headers["content-type"], "application/json");
    let doc = a.json();
    assert_eq!(doc["info"]["title"], "CoPilot API");
    assert!(doc["paths"]["/api/customers"]["get"].is_object());
    let a = send(&h, "GET", "/openapi.json", &[("accept-encoding", "gzip")]).await;
    assert_eq!(a.headers["content-encoding"], "gzip");
    assert_eq!(a.headers["vary"], "Accept-Encoding");
    for (path, needle) in [
        ("/docs", "SwaggerUIBundle"),
        ("/redoc", "redoc"),
        ("/docs/oauth2-redirect", "oauth2"),
    ] {
        let a = send(&h, "GET", path, &[]).await;
        assert_eq!(a.status, StatusCode::OK, "{path}");
        assert_eq!(a.headers["content-type"], "text/html; charset=utf-8");
        assert!(String::from_utf8_lossy(&a.body).contains(needle), "{path}");
    }
}

/// The mount over a directory of its own, behind the front (no database).
#[tokio::test]
async fn the_mount_serves_the_report_directory() {
    let dir = tempfile::tempdir().unwrap();
    let reports = dir.path().join("scoutsuite-report");
    std::fs::create_dir_all(reports.join("sub")).unwrap();
    std::fs::write(reports.join("report.html"), "<p>scout</p>").unwrap();
    let router = copilot_standalone::front(copilot_standalone::router(reports), None);
    let call = |method: &'static str, uri: &'static str, header: Option<(&'static str, String)>| {
        let router = router.clone();
        async move {
            let mut b = Request::builder().method(method).uri(uri);
            if let Some((k, v)) = header {
                b = b.header(k, v);
            }
            let resp = router
                .oneshot(b.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap()
                .to_vec();
            (status, headers, body)
        }
    };
    let (st, headers, body) = call("GET", "/scoutsuite-report/report.html", None).await;
    assert_eq!(
        (st, body.as_slice()),
        (StatusCode::OK, &b"<p>scout</p>"[..])
    );
    assert_eq!(headers["content-type"], "text/html; charset=utf-8");
    let etag = headers["etag"].to_str().unwrap().to_string();
    let (st, headers, _) = call(
        "GET",
        "/scoutsuite-report/report.html",
        Some(("if-none-match", etag)),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_MODIFIED);
    assert_eq!(headers.len(), 3, "{headers:?}"); // etag and the request timer's two
    let (st, _, body) = call("GET", "/scoutsuite-report%2Freport.html", None).await;
    assert_eq!(
        (st, body.as_slice()),
        (StatusCode::OK, &b"<p>scout</p>"[..])
    );
    for uri in [
        "/scoutsuite-report/sub",
        "/scoutsuite-report/",
        "/scoutsuite-report/../x",
        "/scoutsuite-report",
    ] {
        let (st, _, body) = call("GET", uri, None).await;
        assert_eq!(
            (st, body.as_slice()),
            (StatusCode::NOT_FOUND, &br#"{"detail":"Not Found"}"#[..]),
            "{uri}"
        );
    }
    let (st, headers, body) = call("POST", "/scoutsuite-report/report.html", None).await;
    assert_eq!(
        (st, body.as_slice()),
        (
            StatusCode::METHOD_NOT_ALLOWED,
            &br#"{"detail":"Method Not Allowed"}"#[..]
        )
    );
    assert!(headers.get("allow").is_none());
    let (st, headers, body) = call("HEAD", "/scoutsuite-report/report.html", None).await;
    assert_eq!((st, body.len()), (StatusCode::OK, 0));
    assert_eq!(headers["content-length"], "12");
}

#[tokio::test]
async fn the_legacy_backend_answers_only_outside_the_python_app() {
    if !configured() {
        return;
    }
    let legacy = recorder().await;
    let h = harness_or_skip!(Some(&legacy), &closed_env());
    let a = send(&h, "GET", "/api/legacy-only-standalone/x", &[]).await;
    assert_eq!(a.status.as_u16(), 599);
    assert_eq!(legacy.received_requests().await.unwrap().len(), 1);
    // Under a Python router's prefix, or one of this service's own paths:
    // answered here.
    for (method, path) in [
        ("GET", "/api/customers/a/b/c"),
        ("GET", "/api/agents/"),
        ("PUT", "/api/customers"),
        ("GET", "/_copilot/health"),
        ("GET", "/docs"),
        ("GET", "/scoutsuite-report/nothing"),
    ] {
        let a = send(&h, method, path, &[]).await;
        assert_ne!(a.status.as_u16(), 599, "{method} {path}");
    }
    assert_eq!(legacy.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn every_connector_python_verifies_has_a_rust_verifier() {
    let h = harness_or_skip!(None);
    for name in copilot_connectors::verify::PYTHON_VERIFIED {
        assert!(h.app.verifiers.handles(name), "{name}");
    }
}

#[test]
fn ports_come_from_the_suite_range() {
    if std::env::var("STANDALONE_E2E_PORT_BASE").is_err() {
        assert_eq!(port(RECORDER), 6600);
        assert_eq!(port(CLOSED), 6601);
    }
}
