//! What a ported service raises: a Python exception (as a value, with the
//! class and `str()` the Python code would have raised), or a database
//! failure the port cannot word as SQLAlchemy does.

use copilot_upstream::py::PyExc;
use copilot_web::ApiError;

/// A service failure.
#[derive(Debug)]
pub enum Fail {
    /// The exception Python raises there.
    Py(PyExc),
    /// The database could not be asked (not provoked by any test).
    Db(String),
}

/// A service result.
pub type FailResult<T> = Result<T, Fail>;

impl Fail {
    /// `str(e)` — what a route's `except Exception as e` puts into its
    /// answer and a job's failure reports (`"404: …"` for an
    /// `HTTPException`).
    pub fn message(&self) -> String {
        match self {
            Fail::Py(e) => e.display(),
            Fail::Db(e) => e.clone(),
        }
    }

    /// The exception left uncaught by a route: the `HTTPException`
    /// envelope, the `ValueError` handler's 400, else uvicorn's bare 500.
    pub fn into_api(self) -> ApiError {
        match self {
            Fail::Py(e) => e.unhandled(),
            Fail::Db(e) => ApiError::internal(e),
        }
    }

    /// A class other than the handled ones (`RuntimeError`, `TypeError`, …).
    pub fn other(class: &'static str, message: impl Into<String>) -> Self {
        Fail::Py(PyExc::Other(class, message.into()))
    }
}

impl From<PyExc> for Fail {
    fn from(e: PyExc) -> Self {
        Fail::Py(e)
    }
}

impl From<sqlx::Error> for Fail {
    fn from(e: sqlx::Error) -> Self {
        Fail::Db(e.to_string())
    }
}

impl From<copilot_db::DbError> for Fail {
    fn from(e: copilot_db::DbError) -> Self {
        Fail::Db(e.to_string())
    }
}

impl From<Fail> for ApiError {
    fn from(e: Fail) -> Self {
        e.into_api()
    }
}
