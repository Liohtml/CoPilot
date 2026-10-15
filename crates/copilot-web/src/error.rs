//! The error envelope — port of `app/middleware/exception_handlers.py`.
//!
//! | Python | Status | Body |
//! |---|---|---|
//! | `HTTPException(status, detail)` | `status` | `{"success": false, "message": detail}` |
//! | `RequestValidationError` | 422 | `{"message": first, "details": [{field, error_type, message}]}` |
//! | `ValueError` | 400 | `{"success": false, "message": str(e)}` |
//! | Starlette `HTTPException` (body read failures) | `status` | `{"detail": detail}` |
//! | unmatched route | 404 | `{"detail": "Not Found"}` |
//! | wrong method | 405 | `{"detail": "Method Not Allowed"}` |
//! | anything else | 500 | `Internal Server Error` (plain text) |
//!
//! The first three also write a `log_entries` row; the response carries a
//! [`LoggedError`] extension that `middleware::log_handled_errors` picks up.
//! Like the Python handler, the `WWW-Authenticate` header of auth failures is
//! not sent.

use axum::Json;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};

use crate::validate::ValidationItem;

/// Marker attached to responses whose error the Python backend would have
/// written to `log_entries`.
#[derive(Debug, Clone)]
pub struct LoggedError {
    /// The message written to `log_entries.message`.
    pub message: String,
}

/// An error a handler returns.
#[derive(Debug)]
pub enum ApiError {
    /// `HTTPException(status, detail)`.
    Http {
        /// Response status.
        status: StatusCode,
        /// `detail` (usually a string, occasionally structured).
        detail: Value,
    },
    /// `RequestValidationError` (422).
    Validation(Vec<ValidationItem>),
    /// A Starlette `HTTPException`, which the backend's handler does not
    /// catch: FastAPI's default `{"detail": …}`, no `log_entries` row (an
    /// unreadable body).
    Detail {
        /// Response status.
        status: StatusCode,
        /// `detail`.
        detail: String,
    },
    /// Starlette's routing 404 (`{"detail": "Not Found"}`).
    RouteNotFound,
    /// Starlette's routing 405.
    MethodNotAllowed,
    /// Unhandled failure: logged with its cause, answered as a bare 500.
    Internal(String),
}

/// Handler result.
pub type ApiResult<T = Response> = Result<T, ApiError>;

impl ApiError {
    /// `HTTPException(status, detail)` with a string detail.
    pub fn http(status: StatusCode, detail: impl Into<String>) -> Self {
        Self::Http {
            status,
            detail: Value::String(detail.into()),
        }
    }

    /// A Starlette `HTTPException` (`{"detail": …}`).
    pub fn detail(status: StatusCode, detail: impl Into<String>) -> Self {
        Self::Detail {
            status,
            detail: detail.into(),
        }
    }

    /// 400.
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::http(StatusCode::BAD_REQUEST, detail)
    }

    /// 401.
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::http(StatusCode::UNAUTHORIZED, detail)
    }

    /// 403.
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::http(StatusCode::FORBIDDEN, detail)
    }

    /// 404.
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::http(StatusCode::NOT_FOUND, detail)
    }

    /// 500 with a message the caller may see (Python's
    /// `HTTPException(500, detail=…)`).
    pub fn server_error(detail: impl Into<String>) -> Self {
        Self::http(StatusCode::INTERNAL_SERVER_ERROR, detail)
    }

    /// An unexpected failure; `cause` is logged, never sent.
    pub fn internal(cause: impl std::fmt::Display) -> Self {
        Self::Internal(cause.to_string())
    }

    /// Response status.
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::Http { status, .. } => *status,
            ApiError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::Detail { status, .. } => *status,
            ApiError::RouteNotFound => StatusCode::NOT_FOUND,
            ApiError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Http { status, detail } => match detail {
                Value::String(s) => write!(f, "{}: {s}", status.as_u16()),
                other => write!(f, "{}: {other}", status.as_u16()),
            },
            ApiError::Validation(items) => {
                let first = items.first().and_then(|i| i.message.as_deref());
                write!(f, "422: {}", first.unwrap_or("Validation Error"))
            }
            ApiError::Detail { status, detail } => write!(f, "{}: {detail}", status.as_u16()),
            ApiError::RouteNotFound => f.write_str("404: Not Found"),
            ApiError::MethodNotAllowed => f.write_str("405: Method Not Allowed"),
            ApiError::Internal(cause) => write!(f, "500: {cause}"),
        }
    }
}

impl From<copilot_db::DbError> for ApiError {
    fn from(e: copilot_db::DbError) -> Self {
        ApiError::internal(e)
    }
}

impl From<copilot_auth::AccessDenied> for ApiError {
    fn from(e: copilot_auth::AccessDenied) -> Self {
        ApiError::forbidden(e.to_string())
    }
}

#[derive(Serialize)]
struct ValidationBody<'a> {
    message: &'a str,
    details: &'a [ValidationItem],
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Http { status, detail } => {
                let logged = match &detail {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let mut resp =
                    (status, Json(json!({"success": false, "message": detail}))).into_response();
                resp.extensions_mut()
                    .insert(LoggedError { message: logged });
                resp
            }
            ApiError::Validation(items) => {
                let message = items
                    .first()
                    .and_then(|i| i.message.clone())
                    .unwrap_or_else(|| "Validation Error".to_string());
                let body = ValidationBody {
                    message: &message,
                    details: &items,
                };
                let mut resp = (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response();
                resp.extensions_mut().insert(LoggedError { message });
                resp
            }
            ApiError::Detail { status, detail } => {
                (status, Json(json!({ "detail": detail }))).into_response()
            }
            ApiError::RouteNotFound => {
                (StatusCode::NOT_FOUND, Json(json!({"detail": "Not Found"}))).into_response()
            }
            ApiError::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                Json(json!({"detail": "Method Not Allowed"})),
            )
                .into_response(),
            ApiError::Internal(cause) => {
                tracing::error!(err = %cause, "unhandled error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn http_exception_envelope() {
        let resp = ApiError::forbidden("Access denied to customer x").into_response();
        assert_eq!(resp.status(), 403);
        assert!(resp.extensions().get::<LoggedError>().is_some());
        assert_eq!(
            body(resp).await,
            json!({"success": false, "message": "Access denied to customer x"})
        );
    }

    #[tokio::test]
    async fn routing_errors_use_fastapi_detail() {
        let resp = ApiError::RouteNotFound.into_response();
        assert!(resp.extensions().get::<LoggedError>().is_none());
        assert_eq!(body(resp).await, json!({"detail": "Not Found"}));
    }
}
