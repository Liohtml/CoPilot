//! FastAPI's own routes: `GET /openapi.json`, `/docs`, `/docs/oauth2-redirect`
//! and `/redoc` (Starlette routes: `GET` and the `HEAD` Starlette adds), and
//! the app's `GET /`.
//!
//! The document is the one `app.openapi()` builds, compiled in; FastAPI
//! answers it as `JSONResponse(schema)` (compact, `ensure_ascii=False`).
//! One value in it is computed when Python imports `app/utils.py`: the
//! example of `LogRetrieveModel.timestamp` is `datetime.now()`, local and
//! naive. It is this process's start, taken by [`init`] (`isoformat()`: the
//! microseconds only when not zero). The pages are `get_swagger_ui_html`,
//! `get_swagger_ui_oauth2_redirect_html` and `get_redoc_html` as
//! `FastAPI.setup` calls them (no `root_path`: uvicorn is started without
//! one), `HTMLResponse`s. Every answer leaves through `GZipMiddleware`'s
//! rules (`copilot_reports::starlette`).

use std::sync::OnceLock;

use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use http::{HeaderMap, StatusCode};

use crate::python;

/// The import time, as `datetime.now().isoformat()` writes it.
fn import_time() -> &'static str {
    static STAMP: OnceLock<String> = OnceLock::new();
    STAMP.get_or_init(|| isoformat(chrono::Local::now().naive_local()))
}

/// `datetime.isoformat()` of a naive datetime.
pub fn isoformat(t: chrono::NaiveDateTime) -> String {
    let base = t.format("%Y-%m-%dT%H:%M:%S").to_string();
    let micros = t.and_utc().timestamp_subsec_micros();
    if micros == 0 {
        base
    } else {
        format!("{base}.{micros:06}")
    }
}

/// Take the import time now (the binary calls it at startup, where Python
/// imports its modules).
pub fn init() {
    let _ = import_time();
}

/// `GET /openapi.json`'s body.
pub fn openapi_body() -> Result<&'static [u8], &'static str> {
    static BODY: OnceLock<Result<Vec<u8>, &'static str>> = OnceLock::new();
    BODY.get_or_init(|| {
        let app = python::app()?;
        let marker = serde_json::to_string(&app.import_time_marker).map_err(|_| "marker")?;
        let stamp = serde_json::to_string(import_time()).map_err(|_| "stamp")?;
        Ok(python::OPENAPI_TEMPLATE
            .replacen(&marker, &stamp, 1)
            .into_bytes())
    })
    .as_ref()
    .map(Vec::as_slice)
    .map_err(|e| *e)
}

fn starlette(content: &[u8], media_type: &str, request: &HeaderMap) -> Response {
    copilot_reports::starlette::response(
        StatusCode::OK,
        content.to_vec(),
        Some(media_type),
        &[],
        request,
    )
    .unwrap_or_else(IntoResponse::into_response)
}

async fn openapi(request: HeaderMap) -> Response {
    match openapi_body() {
        Ok(body) => starlette(body, "application/json", &request),
        Err(e) => copilot_web::ApiError::internal(e).into_response(),
    }
}

async fn page(request: HeaderMap, pick: fn(&python::Pages) -> &str) -> Response {
    match python::app() {
        Ok(app) => starlette(pick(&app.pages).as_bytes(), "text/html", &request),
        Err(e) => copilot_web::ApiError::internal(e).into_response(),
    }
}

/// `GET /`: `hello()`.
async fn root() -> Response {
    axum::Json(serde_json::json!({"message": "CoPilot - We Made It!"})).into_response()
}

/// The four documentation routes and `GET /` (full paths).
pub fn router() -> Router {
    let pages = python::app().map(|a| a.pages.clone()).ok();
    let path = |pick: fn(&python::Pages) -> &String, default: &str| {
        pages
            .as_ref()
            .map_or_else(|| default.to_string(), |p| pick(p).clone())
    };
    Router::new()
        .route(&path(|p| &p.openapi_url, "/openapi.json"), get(openapi))
        .route(
            &path(|p| &p.docs_url, "/docs"),
            get(|h: HeaderMap| page(h, |p| &p.swagger_ui)),
        )
        .route(
            &path(|p| &p.oauth2_redirect_url, "/docs/oauth2-redirect"),
            get(|h: HeaderMap| page(h, |p| &p.oauth2_redirect)),
        )
        .route(
            &path(|p| &p.redoc_url, "/redoc"),
            get(|h: HeaderMap| page(h, |p| &p.redoc)),
        )
        .route("/", get(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isoformat_drops_zero_microseconds() {
        let t = chrono::NaiveDate::from_ymd_opt(2026, 10, 18)
            .unwrap()
            .and_hms_micro_opt(5, 34, 21, 867_687)
            .unwrap();
        assert_eq!(isoformat(t), "2026-10-18T05:34:21.867687");
        let t = chrono::NaiveDate::from_ymd_opt(2026, 1, 2)
            .unwrap()
            .and_hms_micro_opt(3, 4, 5, 6)
            .unwrap();
        assert_eq!(isoformat(t), "2026-01-02T03:04:05.000006");
        assert_eq!(
            isoformat(t.with_nanosecond(0).unwrap()),
            "2026-01-02T03:04:05"
        );
    }

    #[test]
    fn the_document_names_the_import_time() {
        let body = std::str::from_utf8(openapi_body().unwrap()).unwrap();
        assert!(!body.contains("__COPILOT_IMPORT_TIME__"));
        assert!(body.contains(&format!("\"examples\":[\"{}\"]", import_time())));
    }

    use chrono::Timelike as _;
}
