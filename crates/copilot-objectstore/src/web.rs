//! HTTP plumbing the MinIO-backed routes share: the multipart body FastAPI
//! reads before its dependencies (`UploadFile = File(...)`, `Form(...)`),
//! Starlette's `StreamingResponse` for downloads, path parameters decoded the
//! way uvicorn decodes the path, and the hand-off of an encoded `/`.

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, FromRequestParts, OriginalUri, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use copilot_gateway::LegacyProxy;
use copilot_upstream::py::PyExc;
use copilot_web::ApiError;
use copilot_web::form::{FormData, FormError, FormValue, UploadPart, read_form_files};
use copilot_web::middleware::Uncompressed;
use copilot_web::validate::{Validator, loc};

/// `urllib.parse.unquote` (UTF-8, `errors="replace"`): what uvicorn makes of
/// the request path before Starlette routes it.
pub fn py_unquote(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut run: Vec<u8> = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    let flush = |run: &mut Vec<u8>, out: &mut String| {
        if !run.is_empty() {
            out.push_str(&String::from_utf8_lossy(run));
            run.clear();
        }
    };
    while i < bytes.len() {
        let b = bytes[i];
        if !b.is_ascii() {
            // A non-ASCII character is copied as it is.
            flush(&mut run, &mut out);
            let ch_len = s[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&s[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        if b == b'%' {
            let hex = s
                .get(i + 1..i + 3)
                .filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit()));
            if let Some(h) = hex {
                if let Ok(v) = u8::from_str_radix(h, 16) {
                    run.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        run.push(b);
        i += 1;
    }
    flush(&mut run, &mut out);
    out
}

/// The request path's segments, still percent-encoded (the router matched
/// on them).
pub fn raw_segments(req_path: &str) -> Vec<&str> {
    req_path.split('/').collect()
}

/// The `n`-th segment from the end of the path, decoded like uvicorn
/// (`0` is the last).
pub fn segment_from_end(uri: &http::Uri, n: usize) -> String {
    let segments = raw_segments(uri.path());
    let raw = segments
        .len()
        .checked_sub(n + 1)
        .and_then(|i| segments.get(i))
        .copied()
        .unwrap_or_default();
    py_unquote(raw)
}

/// Starlette routes the *decoded* path: `…/files/a%2Fb` is `…/files/a/b`
/// there, which none of these routes is. Such a request goes to the Python
/// backend (FastAPI's 404 without one).
pub async fn encoded_slash_to_legacy(
    State(legacy): State<Option<LegacyProxy>>,
    mut req: Request,
    next: Next,
) -> Response {
    let original = req
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| req.uri().clone(), |o| o.0.clone());
    if !original.path().to_ascii_lowercase().contains("%2f") {
        return next.run(req).await;
    }
    match legacy {
        Some(proxy) => {
            *req.uri_mut() = original;
            proxy.forward(req).await
        }
        None => ApiError::RouteNotFound.into_response(),
    }
}

/// `str.encode("latin-1")` of a header value, or the `UnicodeEncodeError`
/// (a `ValueError`) CPython raises.
pub fn latin1(value: &str) -> Result<Vec<u8>, PyExc> {
    let chars: Vec<char> = value.chars().collect();
    let Some(start) = chars.iter().position(|&c| u32::from(c) > 0xFF) else {
        return Ok(chars
            .iter()
            .map(|&c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
            .collect());
    };
    let end = chars[start..]
        .iter()
        .position(|&c| u32::from(c) <= 0xFF)
        .map_or(chars.len(), |p| start + p);
    let text = if end == start + 1 {
        let c = u32::from(chars[start]);
        let escaped = if c <= 0xFFFF {
            format!("\\u{c:04x}")
        } else {
            format!("\\U{c:08x}")
        };
        format!(
            "'latin-1' codec can't encode character '{escaped}' in position {start}: ordinal \
             not in range(256)"
        )
    } else {
        format!(
            "'latin-1' codec can't encode characters in position {start}-{}: ordinal not in \
             range(256)",
            end - 1
        )
    };
    Err(PyExc::ValueError(text))
}

/// `StreamingResponse(BytesIO(data), media_type=…, headers=…)` as it leaves
/// the production app: the given headers and the media type (a `text/*` one
/// gains `; charset=utf-8`) as latin-1, no `Content-Length` unless given, the
/// body streamed (chunked). Building it fails where Starlette's constructor
/// raises.
///
/// Then `GZipMiddleware(minimum_size=1000)`, whose rules differ from the
/// compression layer's for a stream: every chunk of a `StreamingResponse` is
/// sent with `more_body`, so a non-empty download gains `Vary:
/// Accept-Encoding` and, when the request's (first) `Accept-Encoding` holds
/// `gzip`, is gzipped (level 9) whatever its size or type, its
/// `Content-Length` dropped; an empty one and a `text/event-stream` one pass
/// as they are. The response is marked [`Uncompressed`] so the compression
/// layer leaves it so.
pub fn streaming_response(
    data: Bytes,
    media_type: Option<&str>,
    headers: &[(&str, String)],
    request: &http::HeaderMap,
) -> Result<Response, PyExc> {
    let mut builder = Response::builder().status(200);
    let mut raw: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, value) in headers {
        raw.push((name.to_ascii_lowercase(), latin1(value)?));
    }
    if let Some(mt) = media_type {
        if !raw.iter().any(|(k, _)| k == "content-type") {
            let mut ct = mt.to_string();
            if ct.starts_with("text/") && !ct.to_lowercase().contains("charset=") {
                ct.push_str("; charset=utf-8");
            }
            raw.push(("content-type".into(), latin1(&ct)?));
        }
    }
    let excluded = raw
        .iter()
        .any(|(k, v)| k == "content-type" && v.starts_with(b"text/event-stream"));
    let mut body = data;
    if !body.is_empty() && !excluded {
        raw.push(("vary".into(), b"Accept-Encoding".to_vec()));
        let accept: String = request
            .get(http::header::ACCEPT_ENCODING)
            .map(|v| v.as_bytes().iter().map(|&b| char::from(b)).collect())
            .unwrap_or_default();
        if accept.contains("gzip") {
            body = gzip(&body)?;
            raw.retain(|(k, _)| k != "content-length");
            raw.push(("content-encoding".into(), b"gzip".to_vec()));
        }
    }
    for (name, value) in raw {
        let value = http::HeaderValue::from_bytes(&value).map_err(|_| {
            PyExc::Other(
                "LocalProtocolError",
                format!(
                    "Illegal header value {}",
                    copilot_auth::pyvalue::bytes_repr(&value)
                ),
            )
        })?;
        builder = builder.header(name, value);
    }
    let stream = futures::stream::once(async move { Ok::<_, std::convert::Infallible>(body) });
    let mut response = builder
        .body(Body::from_stream(stream))
        .map_err(|e| PyExc::Other("RuntimeError", e.to_string()))?;
    response.extensions_mut().insert(Uncompressed);
    Ok(response)
}

/// `gzip.GzipFile(mode="wb", fileobj=BytesIO(), compresslevel=9)`: no file
/// name, the current time as `mtime`, `XFL` 2, `OS` 255.
pub fn gzip(data: &[u8]) -> Result<Bytes, PyExc> {
    use std::io::Write as _;
    let mtime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0);
    let mut encoder = flate2::GzBuilder::new()
        .mtime(mtime)
        .write(Vec::new(), flate2::Compression::new(9));
    encoder
        .write_all(data)
        .map_err(|e| PyExc::Other("OSError", e.to_string()))?;
    encoder
        .finish()
        .map(Bytes::from)
        .map_err(|e| PyExc::Other("OSError", e.to_string()))
}

/// A multipart (or other form) body read before the route's guard, as
/// FastAPI reads it: a body that does not parse is Starlette's 400 before
/// any token check, then the guard's own error.
pub struct UploadForm<A> {
    /// The guard (`require_any_scope`).
    pub auth: A,
    /// The form's fields.
    pub form: FormData,
    /// The file parts' content.
    pub uploads: Vec<UploadPart>,
}

impl<A, S> FromRequest<S> for UploadForm<A>
where
    A: FromRequestParts<S> + Send,
    A::Rejection: IntoResponse,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Response> {
        let content_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let (mut parts, body) = req.into_parts();
        let guard = A::from_request_parts(&mut parts, state)
            .await
            .map_err(IntoResponse::into_response);
        let raw = Bytes::from_request(Request::from_parts(parts, body), state)
            .await
            .map_err(IntoResponse::into_response)?;
        let (form, uploads) = read_form_files(content_type.as_deref(), &raw).map_err(|e| {
            let detail = match e {
                FormError::Rejected(message) => message,
                FormError::Malformed => "There was an error parsing the body".to_string(),
            };
            ApiError::detail(http::StatusCode::BAD_REQUEST, detail).into_response()
        })?;
        Ok(Self {
            auth: guard?,
            form,
            uploads,
        })
    }
}

impl<A> UploadForm<A> {
    /// `name: UploadFile = File(...)`: the last part of that name, or the
    /// error FastAPI reports (an empty value is a missing one).
    pub fn file(&self, v: &mut Validator, name: &str) -> Option<UploadPart> {
        match self.form.get(name) {
            Some(FormValue::File { .. }) => {
                self.uploads.iter().rev().find(|u| u.field == name).cloned()
            }
            Some(FormValue::Text(t)) if !t.is_empty() => {
                v.push(
                    "value_error",
                    loc("body", name),
                    "Value error, Expected UploadFile, received: <class 'str'>",
                );
                None
            }
            _ => {
                v.missing(loc("body", name));
                None
            }
        }
    }

    /// `name: str = Form(...)` (an empty value is a missing one).
    pub fn text(&self, v: &mut Validator, name: &str) -> Option<String> {
        match self.form.get(name) {
            Some(FormValue::Text(t)) if !t.is_empty() => Some(t.clone()),
            Some(FormValue::File { .. }) => {
                v.push(
                    "string_type",
                    loc("body", name),
                    "Input should be a valid string",
                );
                None
            }
            _ => {
                v.missing(loc("body", name));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_decode_like_uvicorn() {
        assert_eq!(py_unquote("a%20b%2Bc"), "a b+c");
        assert_eq!(py_unquote("%C3%A9"), "é");
        assert_eq!(py_unquote("%E9x"), "\u{fffd}x");
        assert_eq!(py_unquote("100%"), "100%");
        assert_eq!(py_unquote("%zz%4"), "%zz%4");
        assert_eq!(py_unquote("a+b"), "a+b");
        let uri: http::Uri = "/x/5/a%20b.txt".parse().unwrap();
        assert_eq!(segment_from_end(&uri, 0), "a b.txt");
        assert_eq!(segment_from_end(&uri, 1), "5");
    }

    #[test]
    fn header_values_encode_like_starlette() {
        assert_eq!(latin1("é").unwrap(), vec![0xE9]);
        assert_eq!(
            latin1("attachment; filename=€.txt").unwrap_err().text(),
            "'latin-1' codec can't encode character '\\u20ac' in position 21: ordinal not in \
             range(256)"
        );
        assert_eq!(
            latin1("x€€y").unwrap_err().text(),
            "'latin-1' codec can't encode characters in position 1-2: ordinal not in range(256)"
        );
        assert_eq!(
            latin1("😀").unwrap_err().text(),
            "'latin-1' codec can't encode character '\\U0001f600' in position 0: ordinal not in \
             range(256)"
        );
    }

    #[tokio::test]
    async fn downloads_carry_starlette_headers() {
        let plain = http::HeaderMap::new();
        let r = streaming_response(
            Bytes::from_static(b"abc"),
            Some("text/plain"),
            &[("Content-Disposition", "attachment; filename=a b.txt".into())],
            &plain,
        )
        .unwrap();
        assert_eq!(r.headers()["content-type"], "text/plain; charset=utf-8");
        assert_eq!(
            r.headers()["content-disposition"],
            "attachment; filename=a b.txt"
        );
        assert_eq!(r.headers()["vary"], "Accept-Encoding");
        assert!(r.headers().get("content-length").is_none());
        assert!(r.extensions().get::<Uncompressed>().is_some());
        let r = streaming_response(Bytes::new(), None, &[], &plain).unwrap();
        assert!(r.headers().get("content-type").is_none());
        assert!(
            r.headers().get("vary").is_none(),
            "an empty stream is not touched"
        );
    }

    #[tokio::test]
    async fn gzip_follows_starlettes_rules() {
        use std::io::Read as _;
        let mut gzip_ok = http::HeaderMap::new();
        gzip_ok.insert("accept-encoding", "gzip;q=0".parse().unwrap());
        let r = streaming_response(
            Bytes::from_static(b"\x89PNG tiny"),
            Some("image/png"),
            &[("Content-Length", "10".into())],
            &gzip_ok,
        )
        .unwrap();
        assert_eq!(r.headers()["content-encoding"], "gzip");
        assert_eq!(r.headers()["vary"], "Accept-Encoding");
        assert!(r.headers().get("content-length").is_none());
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        assert_eq!(&bytes[..4], b"\x1f\x8b\x08\x00");
        assert_eq!(bytes[8..10], [2, 255]);
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"\x89PNG tiny");
        let r = streaming_response(
            Bytes::from_static(b"data: x"),
            Some("text/event-stream"),
            &[],
            &gzip_ok,
        )
        .unwrap();
        assert!(r.headers().get("content-encoding").is_none());
        assert!(r.headers().get("vary").is_none());
    }
}
