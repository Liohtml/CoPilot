//! `standalone_vectors.json` (`scripts/gen-standalone-vectors.py`): the
//! routing decisions, CORS, `parsedate` and the static mount, as Python
//! answers them.

use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::response::Response;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use serde_json::Value;
use tower::ServiceExt as _;

use copilot_web::routing::{Decision, scope_path};

fn vectors() -> &'static Value {
    static V: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    V.get_or_init(|| serde_json::from_str(include_str!("python/standalone_vectors.json")).unwrap())
}

#[test]
fn routing_decisions_are_starlettes() {
    let table = &crate::python::app().unwrap().table;
    let mut n = 0;
    for v in vectors()["routing"].as_array().unwrap() {
        let raw = v[0].as_str().unwrap();
        let method = v[1].as_str().unwrap();
        let decoded = v[2].as_str().unwrap();
        assert_eq!(scope_path(raw), decoded, "{raw}");
        let got = table.decide(method, decoded);
        let outcome = &v[3];
        match outcome[0].as_str().unwrap() {
            "full" => {
                let want_index = usize::try_from(outcome[1].as_u64().unwrap()).unwrap();
                let want_params: Vec<(String, String)> = outcome[2]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        (
                            p[0].as_str().unwrap().to_string(),
                            p[1].as_str().unwrap().to_string(),
                        )
                    })
                    .collect();
                // The mount's own `path` parameter is popped by `Mount.matches`.
                let got_params = match &got {
                    Decision::Full { index, params } if *index == want_index => {
                        if table.route(*index).unwrap().kind
                            == copilot_web::routing::RouteKind::Mount
                        {
                            Vec::new()
                        } else {
                            params.clone()
                        }
                    }
                    other => panic!("{method} {raw}: {other:?}, want full {want_index}"),
                };
                assert_eq!(got_params, want_params, "{method} {raw}");
            }
            "partial" => {
                let want = usize::try_from(outcome[1].as_u64().unwrap()).unwrap();
                assert_eq!(got, Decision::Partial { index: want }, "{method} {raw}");
            }
            _ => assert_eq!(got, Decision::None, "{method} {raw}"),
        }
        n += 1;
    }
    assert!(n > 10_000, "{n}");
}

fn latin1(s: &str) -> HeaderValue {
    let bytes: Vec<u8> = s
        .chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap())
        .collect();
    HeaderValue::from_bytes(&bytes).unwrap()
}

fn request_headers(v: &Value) -> HeaderMap {
    let mut h = HeaderMap::new();
    for pair in v.as_array().unwrap() {
        h.append(
            HeaderName::from_bytes(pair[0].as_str().unwrap().to_lowercase().as_bytes()).unwrap(),
            latin1(pair[1].as_str().unwrap()),
        );
    }
    h
}

/// `(name, value)` pairs, sorted (the order of distinct headers carries no
/// meaning, and the gzip middleware sits elsewhere in the two stacks); a
/// gzipped answer's length masked, a missing length filled in from the body
/// (hyper writes it) but on a 304 (Starlette writes none, nor does hyper).
fn normalised(headers: &HeaderMap, body_len: usize, status: u16) -> Vec<(String, String)> {
    let gz = headers.get("content-encoding").is_some_and(|v| v == "gzip");
    let mut out: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| {
            let value: String = v.as_bytes().iter().map(|&b| char::from(b)).collect();
            if k == "content-length" && gz {
                (k.to_string(), "*".to_string())
            } else {
                (k.to_string(), value)
            }
        })
        .collect();
    if !out.iter().any(|(k, _)| k == "content-length") && !gz && status != 304 {
        out.push(("content-length".into(), body_len.to_string()));
    }
    out.sort();
    out
}

fn expected(v: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p[0].as_str().unwrap().to_string(),
                p[1].as_str().unwrap().to_string(),
            )
        })
        .collect();
    out.sort();
    out
}

async fn body_of(resp: Response, gz: bool) -> Vec<u8> {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 24)
        .await
        .unwrap();
    if gz {
        use std::io::Read as _;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_end(&mut out)
            .unwrap();
        out
    } else {
        bytes.to_vec()
    }
}

fn latin1_text(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// The inner app of the CORS vectors, answered as this service's routes
/// answer: a 404 or a body through `GZipMiddleware`'s rules.
async fn cors_inner(req: Request<Body>) -> Response {
    if req
        .headers()
        .get("x-answer-size")
        .is_some_and(|v| v == "big")
    {
        let body = serde_json::json!({"items": vec!["x".repeat(40); 50]}).to_string();
        copilot_reports::starlette::response(
            http::StatusCode::OK,
            body.into_bytes(),
            Some("application/json"),
            &[],
            req.headers(),
        )
        .unwrap()
    } else {
        crate::front::not_found()
    }
}

#[tokio::test]
async fn cors_is_starlettes() {
    let app = axum::Router::new()
        .fallback(cors_inner)
        .layer(axum::middleware::from_fn(copilot_web::cors::starlette_cors));
    for v in vectors()["cors"].as_array().unwrap() {
        let mut req = Request::builder()
            .method(v["method"].as_str().unwrap())
            .uri("/x")
            .body(Body::empty())
            .unwrap();
        *req.headers_mut() = request_headers(&v["headers"]);
        let resp = app.clone().oneshot(req).await.unwrap();
        let resp_status = resp.status().as_u16();
        assert_eq!(resp_status, v["status"].as_u64().unwrap() as u16, "{v}");
        let headers = resp.headers().clone();
        let gz = headers.get("content-encoding").is_some_and(|x| x == "gzip");
        let body = body_of(resp, gz).await;
        assert_eq!(latin1_text(&body), v["body"].as_str().unwrap(), "{v}");
        assert_eq!(
            normalised(&headers, body.len(), resp_status),
            expected(&v["response_headers"]),
            "{}",
            v["headers"]
        );
    }
}

#[test]
fn parsedate_is_email_utils() {
    for v in vectors()["parsedate"].as_array().unwrap() {
        let text = v[0].as_str().unwrap();
        let want = v[1].as_array().map(|t| {
            let f: Vec<i64> = t.iter().map(|x| x.as_i64().unwrap()).collect();
            (f[0], f[1], f[2], f[3], f[4], f[5])
        });
        assert_eq!(crate::parsedate::parsedate(text), want, "{text:?}");
    }
}

fn set_mtime(path: &std::path::Path, mtime: f64) {
    let secs = mtime.trunc();
    let nanos = ((mtime - secs) * 1e9).round();
    let t = SystemTime::UNIX_EPOCH
        + Duration::from_secs(secs as u64)
        + Duration::from_nanos(nanos as u64);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

#[tokio::test]
async fn the_mount_is_staticfiles() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("scoutsuite-report");
    std::fs::create_dir_all(&base).unwrap();
    let st = &vectors()["static"];
    for (name, spec) in st["files"].as_object().unwrap() {
        let path = base.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let content = spec[0].as_str().unwrap();
        let bytes: Vec<u8> = if name == "image.png" {
            content
                .chars()
                .map(|c| u8::try_from(u32::from(c)).unwrap())
                .collect()
        } else {
            content.as_bytes().to_vec()
        };
        std::fs::write(&path, bytes).unwrap();
        set_mtime(&path, spec[1].as_f64().unwrap());
    }
    let outside = root.path().join("outside.txt");
    std::fs::write(&outside, "outside\n").unwrap();
    std::os::unix::fs::symlink(&outside, base.join("outside-link")).unwrap();

    let table = &crate::python::app().unwrap().table;
    for v in st["requests"].as_array().unwrap() {
        let method = Method::from_bytes(v["method"].as_str().unwrap().as_bytes()).unwrap();
        let raw = v["path"].as_str().unwrap();
        let decoded = scope_path(raw);
        // The router decides first: the mount takes every method.
        assert!(
            matches!(
                table.decide(method.as_str(), &decoded),
                Decision::Full { .. }
            ),
            "{raw}"
        );
        let resp =
            crate::static_files::respond(&base, &method, &decoded, &request_headers(&v["headers"]));
        let resp_status = resp.status().as_u16();
        assert_eq!(
            resp_status,
            v["status"].as_u64().unwrap() as u16,
            "{method} {raw}"
        );
        let headers = resp.headers().clone();
        let gz = headers.get("content-encoding").is_some_and(|x| x == "gzip");
        let mut body = body_of(resp, gz).await;
        let mut normal = normalised(
            &headers,
            if method == Method::HEAD {
                0
            } else {
                body.len()
            },
            resp_status,
        );
        if let Some(ct) = headers.get("content-type").and_then(|c| c.to_str().ok()) {
            if let Some(boundary) = ct.strip_prefix("multipart/byteranges; boundary=") {
                let text = latin1_text(&body).replace(boundary, "BOUNDARY");
                body = text
                    .chars()
                    .map(|c| u8::try_from(u32::from(c)).unwrap())
                    .collect();
                for (_, val) in &mut normal {
                    *val = val.replace(boundary, "BOUNDARY");
                }
            }
        }
        assert_eq!(normal, expected(&v["response_headers"]), "{method} {raw}");
        assert_eq!(
            latin1_text(&body),
            v["body"].as_str().unwrap(),
            "{method} {raw}"
        );
    }
}
