//! The `/scoutsuite-report` mount: `app.mount("/scoutsuite-report",
//! StaticFiles(directory="scoutsuite-report"))`, Starlette 1.0's
//! `StaticFiles` with `html=False` over `{COPILOT_SCOUTSUITE_DIR}/scoutsuite-report`
//! (the directory ScoutSuite writes its reports to and `copilot-scoutsuite`
//! lists).
//!
//! A `Mount` matches `/scoutsuite-report/…` for every method (not the bare
//! `/scoutsuite-report`: that is the router's 404). Then, as `StaticFiles`:
//! a method other than `GET`/`HEAD` is the 405 without an `Allow` header;
//! the path within the mount (`get_route_path` against the mount's
//! `root_path`) is joined as `os.path.join(*path.split("/"))` and
//! `os.path.normpath`ed, resolved with its symlinks, and must stay inside
//! the directory (`os.path.commonpath`); a regular file is a `FileResponse`
//! (`copilot_reports::starlette`: `content-type` from `mimetypes.guess_type`,
//! `etag`, `last-modified`, ranges, `HEAD` sending the headers only), unless
//! `If-None-Match` names its etag (`tag.strip(" W/")`) or — without
//! `If-None-Match` — `If-Modified-Since` is not before its modification time
//! (`email.utils.parsedate`, compared field by field): the 304 with the
//! `etag` alone. Anything else is the 404 (a directory, a missing file, a
//! path that leaves the directory, a NUL, a name too long); a file this
//! process may not read is the 401 `PermissionError` maps to; any other
//! failure Starlette lets out is the bare 500.

use std::path::{Component, Path, PathBuf};

use axum::Router;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use http::{HeaderMap, Method, StatusCode};

use copilot_web::ApiError;
use copilot_web::routing::ScopePath;

/// The mount's prefix.
pub const MOUNT: &str = "/scoutsuite-report";

#[derive(Clone)]
struct StaticState {
    directory: PathBuf,
}

/// The mount's routes (`/scoutsuite-report/` and everything under it).
pub fn router(directory: PathBuf) -> Router {
    Router::new()
        .route(&format!("{MOUNT}/"), any(serve))
        .route(&format!("{MOUNT}/{{*path}}"), any(serve))
        .with_state(StaticState { directory })
}

/// `{"detail": …}` with the status: Starlette's `HTTPException` through
/// FastAPI's default handler.
fn detail(status: StatusCode, text: &str) -> Response {
    ApiError::detail(status, text).into_response()
}

/// `os.path.normpath(os.path.join(*route_path.split("/")))`.
pub fn get_path(route_path: &str) -> String {
    // `os.path.join` of the parts: an empty part adds nothing (a part that
    // starts with `/` cannot occur: the parts hold none).
    let joined = route_path
        .split('/')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    normpath(&joined)
}

/// `posixpath.normpath` of a relative path.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let mut out: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| *l != "..") {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    if out.is_empty() {
        ".".into()
    } else {
        out.join("/")
    }
}

/// The path within the mount: `get_route_path(scope)` with the mount's
/// `root_path` (`Mount.matches`: the matched prefix of the path).
pub fn route_path(scope_path: &str) -> String {
    // `^/scoutsuite\-report/(?P<path>.*)$`: `.*` stops at a newline, `$`
    // allows one final newline after it.
    let rest = scope_path.strip_prefix(MOUNT).unwrap_or(scope_path);
    let remainder = rest.strip_prefix('/').unwrap_or(rest);
    let param = remainder.split('\n').next().unwrap_or("");
    let remaining_path = format!("/{param}");
    let cut = scope_path.len().saturating_sub(remaining_path.len());
    let root_path = scope_path.get(..cut).unwrap_or("");
    // `get_route_path`: the path under `root_path` when it starts with it
    // and the next character is a `/`.
    if root_path.is_empty() || !scope_path.starts_with(root_path) {
        return scope_path.to_string();
    }
    if scope_path == root_path {
        return String::new();
    }
    match scope_path.as_bytes().get(root_path.len()) {
        Some(b'/') => scope_path[root_path.len()..].to_string(),
        _ => scope_path.to_string(),
    }
}

enum Lookup {
    File(PathBuf),
    NotFile,
    Missing,
    Denied,
    TooLong,
    Other(std::io::Error),
}

fn classify(e: std::io::Error) -> Lookup {
    match e.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::NotADirectory
        | std::io::ErrorKind::InvalidInput => Lookup::Missing,
        std::io::ErrorKind::PermissionDenied => Lookup::Denied,
        _ if e.raw_os_error() == Some(36) => Lookup::TooLong,
        _ => Lookup::Other(e),
    }
}

/// `lookup_path`: the resolved file inside the directory, if any.
fn lookup(directory: &Path, path: &str) -> Lookup {
    if path.contains('\0') {
        // `os.path.realpath` / `os.stat` refuse it: the `ValueError` 404.
        return Lookup::Missing;
    }
    let Ok(root) = std::fs::canonicalize(directory) else {
        return Lookup::Missing;
    };
    let joined = directory.join(path);
    let full = match std::fs::canonicalize(&joined) {
        Ok(f) => f,
        Err(e) => return classify(e),
    };
    // `os.path.commonpath([full_path, directory]) != directory`: outside.
    let inside = full.starts_with(&root)
        && full
            .components()
            .take(root.components().count())
            .eq(root.components());
    if !inside || full.components().any(|c| matches!(c, Component::ParentDir)) {
        return Lookup::Missing;
    }
    match std::fs::metadata(&full) {
        Ok(m) if m.is_file() => Lookup::File(full),
        Ok(_) => Lookup::NotFile,
        Err(e) => classify(e),
    }
}

/// `tag.strip(" W/")`.
fn strip_tag(tag: &str) -> &str {
    tag.trim_matches(|c| matches!(c, ' ' | 'W' | '/'))
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .map(|v| v.as_bytes().iter().map(|&b| char::from(b)).collect())
}

fn raw_header(raw: &[(String, Vec<u8>)], name: &str) -> Option<String> {
    raw.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.iter().map(|&b| char::from(b)).collect())
}

/// `StaticFiles.is_not_modified(response.headers, request.headers)`.
pub fn is_not_modified(response: &[(String, Vec<u8>)], request: &HeaderMap) -> bool {
    if let Some(if_none_match) = header_text(request, "if-none-match").filter(|v| !v.is_empty()) {
        let etag = raw_header(response, "etag").unwrap_or_default();
        return if_none_match.split(',').any(|tag| strip_tag(tag) == etag);
    }
    let Some(ims) = header_text(request, "if-modified-since") else {
        return false;
    };
    let last = raw_header(response, "last-modified").unwrap_or_default();
    match (
        crate::parsedate::parsedate(&ims),
        crate::parsedate::parsedate(&last),
    ) {
        (Some(ims), Some(last)) => ims >= last,
        _ => false,
    }
}

async fn serve(State(st): State<StaticState>, req: Request) -> Response {
    let method = req.method().clone();
    let scope = req
        .extensions()
        .get::<ScopePath>()
        .map(|p| p.0.clone())
        .unwrap_or_else(|| copilot_web::middleware::decoded_path(req.uri()));
    let request = req.headers().clone();
    respond(&st.directory, &method, &scope, &request)
}

/// The mount's answer for `method` on the decoded `scope_path`.
pub fn respond(
    directory: &Path,
    method: &Method,
    scope_path: &str,
    request: &HeaderMap,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return detail(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    }
    let path = get_path(&route_path(scope_path));
    let full = match lookup(directory, &path) {
        Lookup::File(f) => f,
        Lookup::NotFile | Lookup::Missing | Lookup::TooLong => {
            return detail(StatusCode::NOT_FOUND, "Not Found");
        }
        Lookup::Denied => return detail(StatusCode::UNAUTHORIZED, "Unauthorized"),
        Lookup::Other(e) => return ApiError::internal(e).into_response(),
    };
    let full_text = full.to_string_lossy().into_owned();
    let media_type = copilot_file_analysis::mimetypes::guess_type(&full_text)
        .unwrap_or_else(|| "text/plain".to_string());
    let headers = match copilot_reports::starlette::file_headers(&full, &media_type) {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    if is_not_modified(&headers, request) {
        // `NotModifiedResponse`: the response's cache headers only (here the
        // etag), a 304 without a body.
        let mut resp = Response::new(axum::body::Body::empty());
        *resp.status_mut() = StatusCode::NOT_MODIFIED;
        for (k, v) in &headers {
            if matches!(
                k.as_str(),
                "cache-control" | "content-location" | "date" | "etag" | "expires" | "vary"
            ) {
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(k.as_bytes()),
                    http::HeaderValue::from_bytes(v),
                ) {
                    resp.headers_mut().append(name, value);
                }
            }
        }
        resp.extensions_mut()
            .insert(copilot_web::middleware::Uncompressed);
        return resp;
    }
    copilot_reports::starlette::file_response_for(
        &full,
        &media_type,
        None,
        request,
        method == Method::HEAD,
    )
    .unwrap_or_else(IntoResponse::into_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_joined_and_normalised_as_posixpath() {
        assert_eq!(get_path("/a/b.html"), "a/b.html");
        assert_eq!(get_path("/"), ".");
        assert_eq!(get_path(""), ".");
        assert_eq!(get_path("/../../etc/passwd"), "../../etc/passwd");
        assert_eq!(get_path("/sub/../index.html"), "index.html");
        assert_eq!(get_path("//a//./b/"), "a/b");
        assert_eq!(normpath("a/../.."), "..");
    }

    #[test]
    fn the_route_path_is_get_route_paths() {
        assert_eq!(route_path("/scoutsuite-report/a/b.html"), "/a/b.html");
        assert_eq!(route_path("/scoutsuite-report/"), "/");
        // `$` before a final newline: the mount's `root_path` swallows the
        // path's start, `get_route_path` gives up and the whole path is used.
        assert_eq!(
            route_path("/scoutsuite-report/a.html\n"),
            "/scoutsuite-report/a.html\n"
        );
    }
}
