//! Starlette 1.0's `FileResponse` (the PDF report) as it leaves the app
//! through `GZipMiddleware(minimum_size=1000)`: its headers
//! (`content-type`, `accept-ranges`, `content-disposition`,
//! `content-length`, `last-modified`, `etag` from the file's `stat`), its
//! `Range` handling (one range, several as `multipart/byteranges`, the 400
//! and 416 answers, `If-Range`), and the body sent in 64 KiB chunks — so a
//! file of 64 KiB or more is a stream the middleware gzips without a
//! length, a smaller one is compressed whole from 1000 bytes.

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use copilot_web::middleware::Uncompressed;
use md5::{Digest as _, Md5};

const CHUNK: usize = 64 * 1024;
const MINIMUM_SIZE: usize = 1000;

fn plain(status: u16, content: &str, extra: &[(&str, String)]) -> Response {
    let mut b = Response::builder()
        .status(status)
        .header("content-length", content.len().to_string())
        .header("content-type", "text/plain; charset=utf-8");
    for (k, v) in extra {
        b = b.header(*k, v.as_str());
    }
    b.body(Body::from(content.to_string()))
        .unwrap_or_else(|_| http::StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `_parse_range_header(http_range, file_size)`: the ranges, or the 400 /
/// 416 answer.
fn parse_range(http_range: &str, size: u64) -> Result<Vec<(u64, u64)>, Box<Response>> {
    let malformed = |msg: &str| Box::new(plain(400, msg, &[]));
    let Some((units, range)) = http_range.split_once('=') else {
        return Err(malformed("Malformed range header."));
    };
    if crate::py::lower(crate::py::strip(units)) != "bytes" {
        return Err(malformed("Only support bytes range"));
    }
    let mut ranges: Vec<(i128, i128)> = Vec::new();
    let size_i = i128::from(size);
    for part in range.split(',') {
        let part = crate::py::strip(part);
        if part.is_empty() || part == "-" || !part.contains('-') {
            continue;
        }
        let (start_s, end_s) = part.split_once('-').unwrap_or((part, ""));
        let (start_s, end_s) = (crate::py::strip(start_s), crate::py::strip(end_s));
        let parse = |s: &str| {
            crate::py::int_value(&crate::py::s(s))
                .ok()
                .and_then(|n| num_traits::ToPrimitive::to_i128(&n))
        };
        let start = if start_s.is_empty() {
            match parse(end_s) {
                Some(e) => size_i - e,
                None => continue,
            }
        } else {
            match parse(start_s) {
                Some(s) => s,
                None => continue,
            }
        };
        let end = if !start_s.is_empty() && !end_s.is_empty() {
            match parse(end_s) {
                Some(e) if e < size_i => e + 1,
                Some(_) => size_i,
                None => continue,
            }
        } else {
            size_i
        };
        ranges.push((start, end));
    }
    if ranges.is_empty() {
        return Err(malformed("Range header: range must be requested"));
    }
    if ranges.iter().any(|(s, _)| !(0 <= *s && *s < size_i)) {
        return Err(Box::new(plain(
            416,
            "",
            &[("content-range", format!("bytes */{size}"))],
        )));
    }
    if ranges.iter().any(|(s, e)| s > e) {
        return Err(malformed("Range header: start must be less than end"));
    }
    let mut ranges: Vec<(u64, u64)> = ranges
        .into_iter()
        .map(|(s, e)| (u64::try_from(s).unwrap_or(0), u64::try_from(e).unwrap_or(0)))
        .collect();
    if ranges.len() == 1 {
        return Ok(ranges);
    }
    ranges.sort_unstable();
    let mut merged = vec![ranges[0]];
    for (s, e) in ranges.into_iter().skip(1) {
        let last = merged.len() - 1;
        if s <= merged[last].1 {
            merged[last].1 = merged[last].1.max(e);
        } else {
            merged.push((s, e));
        }
    }
    Ok(merged)
}

/// `GZipMiddleware` on a response whose body went as `chunks` messages.
fn finish(
    status: u16,
    mut headers: Vec<(String, String)>,
    body: Vec<u8>,
    streamed: bool,
    request: &http::HeaderMap,
) -> Response {
    let accept = request
        .get(http::header::ACCEPT_ENCODING)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();
    let mut body = body;
    let mut chunked = false;
    if streamed || body.len() >= MINIMUM_SIZE {
        headers.push(("vary".into(), "Accept-Encoding".into()));
        if accept.contains("gzip") {
            if let Ok(zipped) = copilot_objectstore::web::gzip(&body) {
                body = zipped.to_vec();
                headers.push(("content-encoding".into(), "gzip".into()));
                headers.retain(|(k, _)| k != "content-length");
                if streamed {
                    // A stream the middleware compressed goes without a length.
                    chunked = true;
                } else {
                    headers.push(("content-length".into(), body.len().to_string()));
                }
            }
        }
    }
    let mut b = Response::builder().status(status);
    for (k, v) in &headers {
        b = b.header(k.as_str(), v.as_str());
    }
    let body = if chunked {
        Body::from_stream(futures::stream::once(async move {
            Ok::<_, std::io::Error>(bytes::Bytes::from(body))
        }))
    } else {
        Body::from(body)
    };
    let mut response = b
        .body(body)
        .unwrap_or_else(|_| http::StatusCode::INTERNAL_SERVER_ERROR.into_response());
    response.extensions_mut().insert(Uncompressed);
    response
}

/// `FileResponse(path, filename=…, media_type=…)` for a file holding
/// `data`, modified at `mtime`.
pub fn file_response(
    data: &[u8],
    mtime: std::time::SystemTime,
    filename: &str,
    media_type: &str,
    request: &http::HeaderMap,
    head: bool,
) -> Response {
    let since = mtime
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let st_mtime = since.as_secs() as f64 + f64::from(since.subsec_nanos()) * 1e-9;
    let size = data.len() as u64;
    let etag_base = format!("{}-{size}", copilot_auth::pyvalue::float_repr(st_mtime));
    let etag = format!("\"{}\"", hex::encode(Md5::digest(etag_base.as_bytes())));
    let last_modified = chrono::DateTime::<chrono::Utc>::from(mtime)
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    let quoted = copilot_web::pyurl::quote(filename, "/");
    let disposition = if quoted == filename {
        format!("attachment; filename=\"{filename}\"")
    } else {
        format!("attachment; filename*=utf-8''{quoted}")
    };
    let mut headers = vec![
        ("content-type".to_string(), media_type.to_string()),
        ("accept-ranges".into(), "bytes".into()),
        ("content-disposition".into(), disposition),
        ("content-length".into(), size.to_string()),
        ("last-modified".into(), last_modified.clone()),
        ("etag".into(), etag.clone()),
    ];
    let header = |name: &str| {
        request
            .get(name)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
    };
    let range = header("range");
    let if_range = header("if-range");
    let use_range = match (&range, &if_range) {
        (None, _) => false,
        (Some(_), Some(ir)) => *ir == last_modified || *ir == etag,
        (Some(_), None) => true,
    };
    let Some(range) = range.filter(|_| use_range) else {
        let body = if head { Vec::new() } else { data.to_vec() };
        return finish(200, headers, body, !head && data.len() >= CHUNK, request);
    };
    let ranges = match parse_range(&range, size) {
        Ok(r) => r,
        Err(answer) => return *answer,
    };
    if let [(start, end)] = ranges[..] {
        headers.push((
            "content-range".into(),
            format!("bytes {start}-{}/{size}", end - 1),
        ));
        set(&mut headers, "content-length", (end - start).to_string());
        let body = if head {
            Vec::new()
        } else {
            data[usize::try_from(start).unwrap_or(0)..usize::try_from(end).unwrap_or(0)].to_vec()
        };
        let streamed = !head && body.len() >= CHUNK && end - start > CHUNK as u64;
        return finish(206, headers, body, streamed, request);
    }
    let boundary = hex::encode(rand::random::<[u8; 13]>());
    let media = media_type.to_string();
    let part_header = |start: u64, end: u64| {
        format!(
            "--{boundary}\r\nContent-Type: {media}\r\nContent-Range: bytes {start}-{}/{size}\r\n\r\n",
            end - 1
        )
    };
    let mut content_length = 0u64;
    let mut body = Vec::new();
    for (start, end) in &ranges {
        let h = part_header(*start, *end);
        content_length += h.len() as u64 + (end - start) + 2;
        body.extend(h.as_bytes());
        body.extend(
            &data[usize::try_from(*start).unwrap_or(0)..usize::try_from(*end).unwrap_or(0)],
        );
        body.extend(b"\r\n");
    }
    let closing = format!("--{boundary}--");
    content_length += closing.len() as u64;
    body.extend(closing.as_bytes());
    set(
        &mut headers,
        "content-type",
        format!("multipart/byteranges; boundary={boundary}"),
    );
    set(&mut headers, "content-length", content_length.to_string());
    finish(
        206,
        headers,
        if head { Vec::new() } else { body },
        !head,
        request,
    )
}

fn set(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    match headers.iter_mut().find(|(k, _)| k == name) {
        Some(slot) => slot.1 = value,
        None => headers.push((name.to_string(), value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_parse_like_starlette() {
        assert_eq!(parse_range("bytes=0-9", 100).unwrap(), vec![(0, 10)]);
        assert_eq!(parse_range("bytes=-10", 100).unwrap(), vec![(90, 100)]);
        assert_eq!(parse_range("bytes=50-", 100).unwrap(), vec![(50, 100)]);
        assert_eq!(parse_range("bytes=0-5, 3-9", 100).unwrap(), vec![(0, 10)]);
        assert_eq!(parse_range("bytes=0-200", 100).unwrap(), vec![(0, 100)]);
        assert_eq!(parse_range("items=0-1", 100).unwrap_err().status(), 400);
        assert_eq!(parse_range("bytes=200-300", 100).unwrap_err().status(), 416);
        assert_eq!(parse_range("bytes", 100).unwrap_err().status(), 400);
        assert_eq!(parse_range("bytes=x-y", 100).unwrap_err().status(), 400);
    }
}
