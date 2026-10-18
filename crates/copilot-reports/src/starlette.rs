//! Starlette 1.0's `FileResponse` and `Response` as they leave the production
//! app, i.e. through `copilot.py`'s `GZipMiddleware(minimum_size=1000)`.
//!
//! A response is modelled as the ASGI messages Starlette sends — the start
//! (status, raw headers) and the body messages with their `more_body` — and
//! [`through_gzip`] applies the middleware's state machine to them:
//!
//! - a `Content-Encoding` already set, or a `text/event-stream` body, passes;
//! - a first message under 1000 bytes that is also the last passes;
//! - a complete body from 1000 bytes gains `Vary: Accept-Encoding` and, when
//!   the request's (first) `Accept-Encoding` holds `gzip`, is gzipped (level
//!   9) with its `Content-Length` set to the compressed size;
//! - a body sent in several messages (a file of 64 KiB or more) gains `Vary`
//!   and, gzipped, loses its `Content-Length` (chunked).
//!
//! `FileResponse(path, filename=…, media_type=…)`: `content-type`,
//! `accept-ranges: bytes`, `content-disposition` (`attachment;
//! filename="…"`, or `filename*=utf-8''…` when `quote()` changes the name),
//! then from `os.stat` `content-length`, `last-modified` (`formatdate(…,
//! usegmt=True)`) and `etag` (the MD5 of `str(st_mtime) + "-" +
//! str(st_size)`); the file read in 64 KiB messages; a `Range` header
//! answered as `_parse_range_header` decides (one range: 206 with
//! `content-range`; several: `multipart/byteranges`; a malformed one: 400
//! `Malformed range header.`-style text; a start past the end: 416 with
//! `Content-Range: bytes */size`), unless an `If-Range` names neither the
//! `last-modified` nor the `etag`.
//!
//! The responses are marked [`Uncompressed`]: these rules are already
//! applied, so the compression layer leaves them as they are.

use std::path::Path;

use axum::body::{Body, Bytes};
use axum::response::Response;
use http::{HeaderMap, HeaderValue, StatusCode};
use md5::{Digest as _, Md5};
use rand::RngCore as _;

use copilot_objectstore::PyExc;
use copilot_objectstore::web::{gzip, latin1};
use copilot_web::ApiError;
use copilot_web::middleware::Uncompressed;

/// `GZipMiddleware`'s `minimum_size` in `copilot.py`.
pub const GZIP_MINIMUM_SIZE: usize = 1000;
/// `FileResponse.chunk_size`.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// What Starlette hands the ASGI server: the start message and the body
/// messages (`(body, more_body)`).
#[derive(Debug, Clone)]
pub struct Asgi {
    /// `status`.
    pub status: StatusCode,
    /// The raw headers, names lower-cased, values latin-1.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body messages.
    pub body: Vec<(Bytes, bool)>,
}

fn header<'a>(raw: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    raw.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_slice())
}

/// `MutableHeaders.__setitem__`: the first value replaced in place, the
/// others dropped; appended when absent.
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

/// `MutableHeaders.add_vary_header("Accept-Encoding")`.
fn add_vary(raw: &mut Vec<(String, Vec<u8>)>) {
    let value = match header(raw, "vary") {
        Some(existing) => {
            let mut v = existing.to_vec();
            v.extend_from_slice(b", Accept-Encoding");
            v
        }
        None => b"Accept-Encoding".to_vec(),
    };
    set_header(raw, "vary", value);
}

/// The request's first `Accept-Encoding`, as Starlette's `Headers.get` reads it.
fn accept_encoding(request: &HeaderMap) -> String {
    request
        .get(http::header::ACCEPT_ENCODING)
        .map(|v| v.as_bytes().iter().map(|&b| char::from(b)).collect())
        .unwrap_or_default()
}

fn py_exc(e: PyExc) -> ApiError {
    match e {
        PyExc::ValueError(text) => ApiError::bad_request(text),
        other => ApiError::internal(format!("{other:?}")),
    }
}

/// `GZipMiddleware(minimum_size=1000)` over a response's messages, then the
/// response itself.
pub fn through_gzip(asgi: Asgi, request: &HeaderMap) -> Result<Response, ApiError> {
    let Asgi {
        status,
        mut headers,
        body,
    } = asgi;
    let encoded = header(&headers, "content-encoding").is_some();
    let excluded =
        header(&headers, "content-type").is_some_and(|ct| ct.starts_with(b"text/event-stream"));
    let gzip_ok = accept_encoding(request).contains("gzip");
    let mut out: Vec<u8> = Vec::new();
    let mut streamed = body.len() > 1;
    if encoded || excluded || body.is_empty() {
        for (chunk, _) in &body {
            out.extend_from_slice(chunk);
        }
    } else {
        let (first, more) = (&body[0].0, body[0].1);
        let total: Vec<u8> = body.iter().flat_map(|(c, _)| c.iter().copied()).collect();
        if first.len() < GZIP_MINIMUM_SIZE && !more {
            out = total;
        } else if !more {
            add_vary(&mut headers);
            if gzip_ok {
                out = gzip(&total).map_err(py_exc)?.to_vec();
                set_header(&mut headers, "content-encoding", b"gzip".to_vec());
                set_header(
                    &mut headers,
                    "content-length",
                    out.len().to_string().into_bytes(),
                );
            } else {
                out = total;
            }
        } else {
            add_vary(&mut headers);
            if gzip_ok {
                out = gzip(&total).map_err(py_exc)?.to_vec();
                set_header(&mut headers, "content-encoding", b"gzip".to_vec());
                headers.retain(|(k, _)| k != "content-length");
                streamed = true;
            } else {
                out = total;
            }
        }
    }
    let mut builder = Response::builder().status(status);
    let has_length = header(&headers, "content-length").is_some();
    for (name, value) in &headers {
        let v = HeaderValue::from_bytes(value)
            .map_err(|_| ApiError::internal(format!("illegal header value for {name}")))?;
        builder = builder.header(name.as_str(), v);
    }
    let body = if has_length || !streamed {
        Body::from(out)
    } else {
        let bytes = Bytes::from(out);
        Body::from_stream(futures::stream::once(async move {
            Ok::<_, std::convert::Infallible>(bytes)
        }))
    };
    let mut response = builder
        .body(body)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    response.extensions_mut().insert(Uncompressed);
    Ok(response)
}

/// `Response.init_headers(headers)` for a body of `len` bytes.
pub fn init_headers(
    status: StatusCode,
    media_type: Option<&str>,
    headers: &[(&str, String)],
    len: Option<usize>,
) -> Result<Vec<(String, Vec<u8>)>, ApiError> {
    let mut raw: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, value) in headers {
        raw.push((name.to_ascii_lowercase(), latin1(value).map_err(py_exc)?));
    }
    let code = status.as_u16();
    if let Some(len) = len {
        if header(&raw, "content-length").is_none() && !(code < 200 || code == 204 || code == 304) {
            raw.push(("content-length".into(), len.to_string().into_bytes()));
        }
    }
    if let Some(mt) = media_type {
        if header(&raw, "content-type").is_none() {
            let mut ct = mt.to_string();
            if ct.starts_with("text/") && !ct.to_lowercase().contains("charset=") {
                ct.push_str("; charset=utf-8");
            }
            raw.push(("content-type".into(), latin1(&ct).map_err(py_exc)?));
        }
    }
    Ok(raw)
}

/// `Response(content, status_code, headers, media_type)`.
pub fn response(
    status: StatusCode,
    content: Vec<u8>,
    media_type: Option<&str>,
    headers: &[(&str, String)],
    request: &HeaderMap,
) -> Result<Response, ApiError> {
    let raw = init_headers(status, media_type, headers, Some(content.len()))?;
    through_gzip(
        Asgi {
            status,
            headers: raw,
            body: vec![(Bytes::from(content), false)],
        },
        request,
    )
}

/// `PlainTextResponse(content, status_code, headers)`.
fn plain_text(status: StatusCode, content: &str, headers: &[(&str, String)]) -> Asgi {
    let raw =
        init_headers(status, Some("text/plain"), headers, Some(content.len())).unwrap_or_default();
    Asgi {
        status,
        headers: raw,
        body: vec![(Bytes::from(content.to_string()), false)],
    }
}

/// `repr()` of a float, as `str(st_mtime)` writes it.
fn float_repr(f: f64) -> String {
    let s = format!("{f}");
    if s.contains(['.', 'e', 'E']) || !f.is_finite() {
        s
    } else {
        format!("{s}.0")
    }
}

/// `email.utils.formatdate(timeval, usegmt=True)`.
fn formatdate(secs: i64) -> String {
    let t = chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default();
    t.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// `os.stat`'s `st_mtime` (`sec + nsec * 1e-9`) and `st_size`.
fn stat(path: &Path) -> std::io::Result<(f64, i64, u64)> {
    let meta = std::fs::metadata(path)?;
    let (secs, nanos) = mtime(&meta);
    let st_mtime = secs as f64 + f64::from(nanos) * 1e-9;
    Ok((st_mtime, secs, meta.len()))
}

#[cfg(unix)]
fn mtime(meta: &std::fs::Metadata) -> (i64, u32) {
    use std::os::unix::fs::MetadataExt as _;
    (meta.mtime(), u32::try_from(meta.mtime_nsec()).unwrap_or(0))
}

#[cfg(not(unix))]
fn mtime(meta: &std::fs::Metadata) -> (i64, u32) {
    meta.modified()
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or((0, 0), |d| {
            (i64::try_from(d.as_secs()).unwrap_or(0), d.subsec_nanos())
        })
}

/// `int(text)` for the parts of a `Range` header (already stripped).
fn py_int(text: &str) -> Option<i64> {
    let (neg, digits) = match text.as_bytes().first() {
        Some(b'+') => (false, &text[1..]),
        Some(b'-') => (true, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let mut n: i64 = 0;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        n = n.checked_mul(10)?.checked_add(i64::from(c.to_digit(10)?))?;
    }
    Some(if neg { -n } else { n })
}

enum RangeError {
    Malformed(&'static str),
    NotSatisfiable,
}

/// `FileResponse._parse_range_header(http_range, file_size)`.
fn parse_range_header(http_range: &str, size: i64) -> Result<Vec<(i64, i64)>, RangeError> {
    let Some((units, range)) = http_range.split_once('=') else {
        return Err(RangeError::Malformed("Malformed range header."));
    };
    if units.trim().to_lowercase() != "bytes" {
        return Err(RangeError::Malformed("Only support bytes range"));
    }
    let mut ranges: Vec<(i64, i64)> = Vec::new();
    for part in range.split(',') {
        let part = part.trim();
        if part.is_empty() || part == "-" || !part.contains('-') {
            continue;
        }
        let Some((start_str, end_str)) = part.split_once('-') else {
            continue;
        };
        let (start_str, end_str) = (start_str.trim(), end_str.trim());
        let start = if start_str.is_empty() {
            match py_int(end_str) {
                Some(e) => size - e,
                None => continue,
            }
        } else {
            match py_int(start_str) {
                Some(s) => s,
                None => continue,
            }
        };
        let end = if !start_str.is_empty() && !end_str.is_empty() {
            match py_int(end_str) {
                Some(e) if e < size => e + 1,
                Some(_) => size,
                None => continue,
            }
        } else {
            size
        };
        ranges.push((start, end));
    }
    if ranges.is_empty() {
        return Err(RangeError::Malformed(
            "Range header: range must be requested",
        ));
    }
    if ranges.iter().any(|(s, _)| !(0 <= *s && *s < size)) {
        return Err(RangeError::NotSatisfiable);
    }
    if ranges.iter().any(|(s, e)| s > e) {
        return Err(RangeError::Malformed(
            "Range header: start must be less than end",
        ));
    }
    if ranges.len() == 1 {
        return Ok(ranges);
    }
    ranges.sort_unstable();
    let mut merged: Vec<(i64, i64)> = vec![ranges[0]];
    for &(start, end) in &ranges[1..] {
        let last = merged.len() - 1;
        if start <= merged[last].1 {
            merged[last].1 = merged[last].1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    Ok(merged)
}

/// The messages of `data[start..end]` read in `CHUNK_SIZE` pieces, as
/// `_handle_single_range` sends them.
fn range_messages(data: &[u8], mut start: usize, end: usize) -> Vec<(Bytes, bool)> {
    let mut out = Vec::new();
    loop {
        let take = CHUNK_SIZE.min(end.saturating_sub(start));
        let chunk =
            Bytes::copy_from_slice(&data[start.min(data.len())..(start + take).min(data.len())]);
        start += chunk.len();
        let more = chunk.len() == CHUNK_SIZE && start < end;
        out.push((chunk, more));
        if !more {
            return out;
        }
    }
}

/// `FileResponse(path, filename=filename, media_type=media_type)`, sent for
/// `request`. A file that is not there is the `RuntimeError` Starlette raises
/// (a bare 500).
pub fn file_response(
    path: &Path,
    media_type: &str,
    filename: Option<&str>,
    request: &HeaderMap,
) -> Result<Response, ApiError> {
    file_response_for(path, media_type, filename, request, false)
}

/// The headers `FileResponse.__init__` and `set_stat_headers` give a file:
/// `content-type`, `accept-ranges`, `content-length`, `last-modified`, `etag`
/// (`StaticFiles` decides on them before the response is sent).
pub fn file_headers(path: &Path, media_type: &str) -> Result<Vec<(String, Vec<u8>)>, ApiError> {
    let mut raw = init_headers(StatusCode::OK, Some(media_type), &[], None)?;
    raw.push(("accept-ranges".into(), b"bytes".to_vec()));
    let (st_mtime, secs, size) = stat(path).map_err(|_| {
        ApiError::internal(format!("File at path {} does not exist.", path.display()))
    })?;
    let etag_base = format!("{}-{size}", float_repr(st_mtime));
    let etag = format!("\"{}\"", hex::encode(Md5::digest(etag_base.as_bytes())));
    raw.push(("content-length".into(), size.to_string().into_bytes()));
    raw.push(("last-modified".into(), formatdate(secs).into_bytes()));
    raw.push(("etag".into(), etag.into_bytes()));
    Ok(raw)
}

/// [`file_response`], sending the headers only when `head` (Starlette's
/// `send_header_only` for a `HEAD` request: one empty body message).
pub fn file_response_for(
    path: &Path,
    media_type: &str,
    filename: Option<&str>,
    request: &HeaderMap,
    head: bool,
) -> Result<Response, ApiError> {
    let mut raw = init_headers(StatusCode::OK, Some(media_type), &[], None)?;
    raw.push(("accept-ranges".into(), b"bytes".to_vec()));
    if let Some(name) = filename {
        let quoted = copilot_web::pyurl::quote(name, "/");
        let value = if quoted != name {
            format!("attachment; filename*=utf-8''{quoted}")
        } else {
            format!("attachment; filename=\"{name}\"")
        };
        raw.push((
            "content-disposition".into(),
            latin1(&value).map_err(py_exc)?,
        ));
    }
    let (st_mtime, secs, size) = stat(path).map_err(|_| {
        ApiError::internal(format!("File at path {} does not exist.", path.display()))
    })?;
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return Err(ApiError::internal(format!(
            "File at path {} is not a file.",
            path.display()
        )));
    }
    let etag_base = format!("{}-{size}", float_repr(st_mtime));
    let etag = format!("\"{}\"", hex::encode(Md5::digest(etag_base.as_bytes())));
    let last_modified = formatdate(secs);
    raw.push(("content-length".into(), size.to_string().into_bytes()));
    raw.push(("last-modified".into(), last_modified.clone().into_bytes()));
    raw.push(("etag".into(), etag.clone().into_bytes()));
    let data = std::fs::read(path).map_err(ApiError::internal)?;

    let latin = |name: http::HeaderName| -> Option<String> {
        request
            .get(name)
            .map(|v| v.as_bytes().iter().map(|&b| char::from(b)).collect())
    };
    let http_range = latin(http::header::RANGE);
    let if_range = latin(http::header::IF_RANGE);
    let use_range = match (&http_range, &if_range) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(_), Some(ir)) => *ir == last_modified || *ir == etag,
    };
    let size_i = i64::try_from(size).unwrap_or(i64::MAX);
    let header_only = || vec![(Bytes::new(), false)];
    let asgi = if !use_range {
        let mut body = Vec::new();
        let mut pos = 0;
        loop {
            if head {
                body = header_only();
                break;
            }
            let end = (pos + CHUNK_SIZE).min(data.len());
            let chunk = Bytes::copy_from_slice(&data[pos..end]);
            pos = end;
            let more = chunk.len() == CHUNK_SIZE;
            body.push((chunk, more));
            if !more {
                break;
            }
        }
        Asgi {
            status: StatusCode::OK,
            headers: raw,
            body,
        }
    } else {
        match parse_range_header(http_range.as_deref().unwrap_or_default(), size_i) {
            Err(RangeError::Malformed(text)) => plain_text(StatusCode::BAD_REQUEST, text, &[]),
            Err(RangeError::NotSatisfiable) => plain_text(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "",
                &[("Content-Range", format!("bytes */{size}"))],
            ),
            Ok(ranges) if ranges.len() == 1 => {
                let (start, end) = ranges[0];
                set_header(
                    &mut raw,
                    "content-range",
                    format!("bytes {start}-{}/{size}", end - 1).into_bytes(),
                );
                set_header(
                    &mut raw,
                    "content-length",
                    (end - start).to_string().into_bytes(),
                );
                let (start, end) = (
                    usize::try_from(start).unwrap_or(0),
                    usize::try_from(end).unwrap_or(0),
                );
                Asgi {
                    status: StatusCode::PARTIAL_CONTENT,
                    headers: raw,
                    body: if head {
                        header_only()
                    } else {
                        range_messages(&data, start, end)
                    },
                }
            }
            Ok(ranges) => {
                let mut token = [0u8; 13];
                rand::thread_rng().fill_bytes(&mut token);
                let boundary = hex::encode(token);
                let content_type = header(&raw, "content-type")
                    .map(|v| v.iter().map(|&b| char::from(b)).collect::<String>())
                    .unwrap_or_default();
                let static_len = 49 + boundary.len() + content_type.len() + size.to_string().len();
                let length: usize = ranges
                    .iter()
                    .map(|(s, e)| {
                        s.to_string().len()
                            + (e - 1).to_string().len()
                            + static_len
                            + usize::try_from(e - s).unwrap_or(0)
                    })
                    .sum::<usize>()
                    + 4
                    + boundary.len();
                set_header(
                    &mut raw,
                    "content-type",
                    format!("multipart/byteranges; boundary={boundary}").into_bytes(),
                );
                set_header(&mut raw, "content-length", length.to_string().into_bytes());
                let mut body = Vec::new();
                for &(start, end) in &ranges {
                    let head = format!(
                        "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes \
                         {start}-{}/{size}\r\n\r\n",
                        end - 1
                    );
                    body.push((Bytes::from(head), true));
                    let (mut s, e) = (
                        usize::try_from(start).unwrap_or(0),
                        usize::try_from(end).unwrap_or(0),
                    );
                    while s < e {
                        let take = CHUNK_SIZE.min(e - s);
                        body.push((Bytes::copy_from_slice(&data[s..s + take]), true));
                        s += take;
                    }
                    body.push((Bytes::from_static(b"\r\n"), true));
                }
                body.push((Bytes::from(format!("--{boundary}--")), false));
                if head {
                    body = header_only();
                }
                Asgi {
                    status: StatusCode::PARTIAL_CONTENT,
                    headers: raw,
                    body,
                }
            }
        }
    };
    through_gzip(asgi, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    fn headers(r: &Response) -> Vec<(String, String)> {
        r.headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("?").to_string()))
            .collect()
    }

    async fn body(r: Response) -> Vec<u8> {
        axum::body::to_bytes(r.into_body(), 1 << 24)
            .await
            .unwrap()
            .to_vec()
    }

    fn temp(data: &[u8]) -> std::path::PathBuf {
        crate::tempfile::named(".pdf", data).unwrap()
    }

    #[tokio::test]
    async fn a_file_response_carries_starlettes_headers() {
        let p = temp(b"%PDF-1.4 small");
        let r = file_response(
            &p,
            "application/pdf",
            Some("case_report.pdf"),
            &HeaderMap::new(),
        )
        .unwrap();
        let h = headers(&r);
        let names: Vec<&str> = h.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "content-type",
                "accept-ranges",
                "content-disposition",
                "content-length",
                "last-modified",
                "etag"
            ]
        );
        assert_eq!(h[2].1, "attachment; filename=\"case_report.pdf\"");
        assert_eq!(h[3].1, "14");
        assert!(h[4].1.ends_with(" GMT"));
        assert!(h[5].1.starts_with('"') && h[5].1.len() == 34);
        assert_eq!(body(r).await, b"%PDF-1.4 small");
        let r = file_response(&p, "application/pdf", Some("a b.pdf"), &HeaderMap::new()).unwrap();
        assert_eq!(
            r.headers()["content-disposition"],
            "attachment; filename*=utf-8''a%20b.pdf"
        );
        crate::tempfile::remove(&p);
        assert!(file_response(&p, "application/pdf", None, &HeaderMap::new()).is_err());
    }

    #[tokio::test]
    async fn gzip_follows_the_middleware() {
        let big = vec![b'x'; 5000];
        let p = temp(&big);
        let mut gz = HeaderMap::new();
        gz.insert("accept-encoding", "gzip, deflate".parse().unwrap());
        let r = file_response(&p, "application/pdf", None, &gz).unwrap();
        assert_eq!(r.headers()["vary"], "Accept-Encoding");
        assert_eq!(r.headers()["content-encoding"], "gzip");
        let len: usize = r.headers()["content-length"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let b = body(r).await;
        assert_eq!(b.len(), len);
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&b[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, big);
        let r = file_response(&p, "application/pdf", None, &HeaderMap::new()).unwrap();
        assert_eq!(r.headers()["vary"], "Accept-Encoding");
        assert_eq!(r.headers()["content-length"], "5000");
        crate::tempfile::remove(&p);
        // From 64 KiB the file is streamed: gzip drops the length.
        let huge = vec![b'y'; CHUNK_SIZE + 10];
        let p = temp(&huge);
        let r = file_response(&p, "application/pdf", None, &gz).unwrap();
        assert!(r.headers().get("content-length").is_none());
        assert_eq!(r.headers()["content-encoding"], "gzip");
        let r = file_response(&p, "application/pdf", None, &HeaderMap::new()).unwrap();
        assert_eq!(r.headers()["content-length"], (CHUNK_SIZE + 10).to_string());
        assert_eq!(r.headers()["vary"], "Accept-Encoding");
        crate::tempfile::remove(&p);
    }

    #[tokio::test]
    async fn ranges_follow_starlette() {
        let p = temp(b"0123456789");
        let mut req = HeaderMap::new();
        req.insert("range", "bytes=2-4".parse().unwrap());
        let r = file_response(&p, "application/pdf", None, &req).unwrap();
        assert_eq!(r.status(), 206);
        assert_eq!(r.headers()["content-range"], "bytes 2-4/10");
        assert_eq!(r.headers()["content-length"], "3");
        assert_eq!(body(r).await, b"234");
        req.insert("range", "bytes=20-".parse().unwrap());
        let r = file_response(&p, "application/pdf", None, &req).unwrap();
        assert_eq!(r.status(), 416);
        assert_eq!(r.headers()["content-range"], "bytes */10");
        req.insert("range", "items=1-2".parse().unwrap());
        let r = file_response(&p, "application/pdf", None, &req).unwrap();
        assert_eq!(r.status(), 400);
        assert_eq!(body(r).await, b"Only support bytes range");
        req.insert("range", "bytes=0-1,5-6".parse().unwrap());
        let r = file_response(&p, "application/pdf", None, &req).unwrap();
        assert_eq!(r.status(), 206);
        let len: usize = r.headers()["content-length"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let b = body(r).await;
        assert_eq!(b.len(), len);
        req.insert("if-range", "\"nope\"".parse().unwrap());
        let r = file_response(&p, "application/pdf", None, &req).unwrap();
        assert_eq!(r.status(), 200);
        crate::tempfile::remove(&p);
    }

    #[test]
    fn helpers_are_pythons() {
        assert_eq!(float_repr(1_792_278_168.0), "1792278168.0");
        assert_eq!(float_repr(1_792_278_168.5), "1792278168.5");
        assert_eq!(formatdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(py_int("1_0"), Some(10));
        assert_eq!(py_int("_1"), None);
        assert_eq!(py_int("+5"), Some(5));
    }

    #[tokio::test]
    async fn a_response_is_one_message() {
        let r = response(
            StatusCode::OK,
            vec![b'p'; 10],
            Some("application/pdf"),
            &[
                (
                    "Content-Disposition",
                    "attachment; filename=\"r.pdf\"".into(),
                ),
                ("Cache-Control", "no-store".into()),
            ],
            &HeaderMap::new(),
        )
        .unwrap();
        assert_eq!(
            headers(&r),
            [
                (
                    "content-disposition".to_string(),
                    "attachment; filename=\"r.pdf\"".to_string()
                ),
                ("cache-control".to_string(), "no-store".to_string()),
                ("content-length".to_string(), "10".to_string()),
                ("content-type".to_string(), "application/pdf".to_string()),
            ]
        );
    }
}
