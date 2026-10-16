//! Cross-cutting layers for the routes this service answers itself.
//!
//! - [`cors`] — Starlette's `CORSMiddleware(allow_origins=["*"],
//!   allow_credentials=True, …)`: mirror the origin, allow credentials.
//! - [`compression`] — `GZipMiddleware(minimum_size=1000)`; never SSE, and
//!   not for a response marked [`Uncompressed`].
//! - [`log_handled_errors`] — the `log_entries` row every Python exception
//!   handler writes, here written in the background so the response is not
//!   held up.
//! - [`security_headers`] — `nosniff` / `DENY` on JSON responses.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::HeaderValue;
use tower_http::compression::CompressionLayer;
use tower_http::compression::predicate::{NotForContentType, Predicate, SizeAbove};
use tower_http::cors::CorsLayer;

use copilot_db::audit::{ErrorLogEntry, insert_error_log};
use copilot_db::users;

use crate::context::AppContext;
use crate::error::LoggedError;

/// Permissive CORS mirroring Starlette's wildcard-with-credentials behaviour.
pub fn cors() -> CorsLayer {
    CorsLayer::very_permissive()
}

/// gzip above 1000 bytes, never for event streams or images, nor for a
/// response marked [`Uncompressed`].
pub fn compression() -> CompressionLayer<impl Predicate> {
    CompressionLayer::new().compress_when(
        SizeAbove::new(1000)
            .and(NotForContentType::GRPC)
            .and(NotForContentType::IMAGES)
            .and(NotForContentType::SSE)
            .and(not_marked),
    )
}

/// A response extension: the route already applied `GZipMiddleware`'s rules
/// (a `StreamingResponse` download), so [`compression`] leaves it as it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct Uncompressed;

fn not_marked(
    _: http::StatusCode,
    _: http::Version,
    _: &http::HeaderMap,
    extensions: &http::Extensions,
) -> bool {
    extensions.get::<Uncompressed>().is_none()
}

/// Defensive headers for API responses.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.entry("x-content-type-options")
        .or_insert(HeaderValue::from_static("nosniff"));
    h.entry("x-frame-options")
        .or_insert(HeaderValue::from_static("DENY"));
    resp
}

/// Write a `log_entries` row for responses carrying [`LoggedError`].
pub async fn log_handled_errors(
    State(ctx): State<AppContext>,
    req: Request,
    next: Next,
) -> Response {
    if !ctx.log_handled_errors {
        return next.run(req).await;
    }
    let method = req.method().to_string();
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    let route = format!("http://{host}{}", req.uri());
    let bearer = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' ').map(|(_, t)| t.to_string()));
    let resp = next.run(req).await;
    if let Some(logged) = resp.extensions().get::<LoggedError>() {
        let message = logged.message.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let user_id = match bearer {
                Some(token) => match ctx.jwt.decode_session(&token) {
                    Ok(claims) => users::find_by_username(&ctx.db, &claims.subject)
                        .await
                        .ok()
                        .flatten()
                        .map(|u| u.id),
                    Err(_) => None,
                },
                None => None,
            };
            let entry = ErrorLogEntry {
                user_id,
                route,
                method,
                message,
            };
            if let Err(e) = insert_error_log(&ctx.db, entry).await {
                tracing::warn!(err = %e, "failed to write log_entries row");
            }
        });
    }
    resp
}
