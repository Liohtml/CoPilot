//! The exceptions the Python services raise, kept apart because callers
//! catch them selectively (`except HTTPException`, `except RequestError`,
//! `except Exception as e: … f"{e}"`) and because FastAPI answers each kind
//! differently.

use http::StatusCode;

use copilot_web::ApiError;

use crate::es::{ConnectError, EsError};
use crate::pymodel::ValidationError;

/// A Python exception on its way to FastAPI.
#[derive(Debug, Clone, PartialEq)]
pub enum PyErr {
    /// `HTTPException(status_code, detail)`.
    Http {
        /// Status.
        status: u16,
        /// Detail (a string everywhere in these modules).
        detail: String,
    },
    /// A `ValueError` — Pydantic's `ValidationError` included — which the
    /// backend's handler answers with 400 `{"success": false, "message"}`.
    Value(String),
    /// Anything else: uvicorn's bare 500. The text is `str(e)`, for the
    /// services that catch it and embed it.
    Other(String),
}

impl PyErr {
    /// `HTTPException(500, detail)`.
    pub fn server(detail: impl Into<String>) -> Self {
        PyErr::Http {
            status: 500,
            detail: detail.into(),
        }
    }

    /// `HTTPException(status, detail)`.
    pub fn http(status: u16, detail: impl Into<String>) -> Self {
        PyErr::Http {
            status,
            detail: detail.into(),
        }
    }

    /// `str(e)` (`"500: detail"` for an `HTTPException`).
    pub fn py_str(&self) -> String {
        match self {
            PyErr::Http { status, detail } => format!("{status}: {detail}"),
            PyErr::Value(s) | PyErr::Other(s) => s.clone(),
        }
    }

    /// `e.detail` of an `HTTPException`.
    pub fn detail(&self) -> Option<&str> {
        match self {
            PyErr::Http { detail, .. } => Some(detail),
            _ => None,
        }
    }
}

impl From<PyErr> for ApiError {
    fn from(e: PyErr) -> Self {
        match e {
            PyErr::Http { status, detail } => ApiError::http(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                detail,
            ),
            PyErr::Value(s) => ApiError::bad_request(s),
            PyErr::Other(s) => ApiError::internal(s),
        }
    }
}

impl From<ConnectError> for PyErr {
    fn from(e: ConnectError) -> Self {
        match e {
            ConnectError::Http(d) => PyErr::server(d),
            ConnectError::Db(e) => PyErr::Other(e),
        }
    }
}

impl From<EsError> for PyErr {
    fn from(e: EsError) -> Self {
        match e {
            EsError::Value(s) => PyErr::Value(s),
            other => PyErr::Other(other.to_string()),
        }
    }
}

impl From<ValidationError> for PyErr {
    fn from(e: ValidationError) -> Self {
        PyErr::Value(e.to_string())
    }
}

impl From<copilot_db::DbError> for PyErr {
    fn from(e: copilot_db::DbError) -> Self {
        PyErr::Other(e.to_string())
    }
}

impl From<sqlx::Error> for PyErr {
    fn from(e: sqlx::Error) -> Self {
        PyErr::Other(e.to_string())
    }
}

/// `KeyError(key)`'s `str()`: the key's `repr()`.
pub fn key_error(key: &str) -> PyErr {
    PyErr::Other(copilot_auth::pyvalue::str_repr(key))
}
