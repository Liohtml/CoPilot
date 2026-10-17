//! A Starlette `Response(content, status_code, headers, media_type)` as it
//! leaves the production app, for the routes that answer bytes (the logos,
//! the agents CSV).
//!
//! `init_headers`: the given headers (latin-1; a value that is not is the
//! `UnicodeEncodeError` — a `ValueError`, the backend's 400 — raised while
//! the response is built), then `content-length` (not for a 1xx, 204 or
//! 304), then the media type (`text/*` gains `; charset=utf-8`).
//!
//! Then `GZipMiddleware(minimum_size=1000)` for a one-message body, whose
//! rules differ from the compression layer's: from 1000 bytes up, `Vary:
//! Accept-Encoding` is added whether or not the client takes gzip, and the
//! body is gzipped (level 9) when the request's (first) `Accept-Encoding`
//! holds `gzip` — images included; a body with a `Content-Encoding` or a
//! `text/event-stream` one passes as it is. The response is marked
//! [`Uncompressed`] so the compression layer leaves it so.

use axum::body::Body;
use axum::response::Response;
use http::{HeaderMap, HeaderValue, StatusCode};

use copilot_objectstore::PyExc;
use copilot_objectstore::web::{gzip, latin1};
use copilot_web::ApiError;
use copilot_web::middleware::Uncompressed;

/// `GZipMiddleware`'s `minimum_size` in `copilot.py`.
pub const GZIP_MINIMUM_SIZE: usize = 1000;

fn py_exc(e: PyExc) -> ApiError {
    match e {
        PyExc::ValueError(text) => ApiError::bad_request(text),
        other => ApiError::internal(format!("{other:?}")),
    }
}

/// `MutableHeaders.__setitem__`: replace the first value in place (dropping
/// the others), else append.
fn set_header(raw: &mut Vec<(String, Vec<u8>)>, name: &str, value: Vec<u8>) {
    match raw.iter().position(|(k, _)| k == name) {
        Some(i) => {
            raw[i].1 = value;
            let mut seen = 0;
            raw.retain(|(k, _)| {
                if k == name {
                    seen += 1;
                    seen == 1
                } else {
                    true
                }
            });
        }
        None => raw.push((name.to_string(), value)),
    }
}

/// Build the response; `request` supplies `Accept-Encoding`.
pub fn response(
    status: StatusCode,
    content: Vec<u8>,
    media_type: Option<&str>,
    headers: &[(&str, String)],
    request: &HeaderMap,
) -> Result<Response, ApiError> {
    let mut raw: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, value) in headers {
        raw.push((name.to_ascii_lowercase(), latin1(value).map_err(py_exc)?));
    }
    let code = status.as_u16();
    if !raw.iter().any(|(k, _)| k == "content-length")
        && !(code < 200 || code == 204 || code == 304)
    {
        raw.push((
            "content-length".into(),
            content.len().to_string().into_bytes(),
        ));
    }
    if let Some(mt) = media_type {
        if !raw.iter().any(|(k, _)| k == "content-type") {
            let mut ct = mt.to_string();
            if ct.starts_with("text/") && !ct.to_lowercase().contains("charset=") {
                ct.push_str("; charset=utf-8");
            }
            raw.push(("content-type".into(), latin1(&ct).map_err(py_exc)?));
        }
    }

    let mut body = content;
    let encoded = raw.iter().any(|(k, _)| k == "content-encoding");
    let excluded = raw
        .iter()
        .find(|(k, _)| k == "content-type")
        .is_some_and(|(_, v)| v.starts_with(b"text/event-stream"));
    if !encoded && !excluded && body.len() >= GZIP_MINIMUM_SIZE {
        let vary = match raw.iter().find(|(k, _)| k == "vary") {
            Some((_, existing)) => {
                let mut v = existing.clone();
                v.extend_from_slice(b", Accept-Encoding");
                v
            }
            None => b"Accept-Encoding".to_vec(),
        };
        set_header(&mut raw, "vary", vary);
        let accept = request
            .get(http::header::ACCEPT_ENCODING)
            .map(|v| copilot_web::form::latin1(v.as_bytes()))
            .unwrap_or_default();
        if accept.contains("gzip") {
            body = gzip(&body).map_err(py_exc)?.to_vec();
            set_header(&mut raw, "content-encoding", b"gzip".to_vec());
            set_header(
                &mut raw,
                "content-length",
                body.len().to_string().into_bytes(),
            );
        }
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in raw {
        let value = HeaderValue::from_bytes(&value)
            .map_err(|_| ApiError::internal(format!("illegal header value for {name}")))?;
        builder = builder.header(name, value);
    }
    let mut response = builder
        .body(Body::from(body))
        .map_err(|e| ApiError::internal(e.to_string()))?;
    response.extensions_mut().insert(Uncompressed);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(r: &Response) -> Vec<(String, String)> {
        r.headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("?").to_string()))
            .collect()
    }

    #[test]
    fn small_bodies_pass_and_large_ones_vary() {
        let none = HeaderMap::new();
        let r = response(
            StatusCode::OK,
            b"abc".to_vec(),
            Some("text/csv"),
            &[],
            &none,
        )
        .unwrap();
        assert_eq!(
            headers(&r),
            [
                ("content-length".to_string(), "3".to_string()),
                (
                    "content-type".to_string(),
                    "text/csv; charset=utf-8".to_string()
                )
            ]
        );
        let big = vec![b'a'; 1500];
        let r = response(StatusCode::OK, big.clone(), Some("image/png"), &[], &none).unwrap();
        assert_eq!(r.headers()["vary"], "Accept-Encoding");
        assert_eq!(r.headers()["content-length"], "1500");
        let mut gz = HeaderMap::new();
        gz.insert("accept-encoding", "gzip, deflate".parse().unwrap());
        let r = response(StatusCode::OK, big, Some("image/png"), &[], &gz).unwrap();
        assert_eq!(r.headers()["content-encoding"], "gzip");
        assert_ne!(r.headers()["content-length"], "1500");
        let r = response(
            StatusCode::NOT_MODIFIED,
            Vec::new(),
            None,
            &[("ETag", "\"1\"".into())],
            &gz,
        )
        .unwrap();
        assert_eq!(headers(&r), [("etag".to_string(), "\"1\"".to_string())]);
    }

    #[test]
    fn a_header_that_is_not_latin1_is_the_value_error() {
        let err = response(
            StatusCode::OK,
            Vec::new(),
            Some("image/\u{100}"),
            &[],
            &HeaderMap::new(),
        )
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }
}
