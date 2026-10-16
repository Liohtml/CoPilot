//! Python exceptions as values, for services ported line by line.
//!
//! The connector services index into a tool's JSON (`data["all"]["indices"]`),
//! build Pydantic models from it and catch exceptions by class
//! (`except KeyError`, `except HTTPException`, `except Exception`). What
//! reaches the caller depends on which exception was raised where, and its
//! `str()` is often part of the answer (`Failed to collect streams key:
//! 'total'`). [`PyExc`] carries the class and that text, [`getitem`] raises
//! what CPython raises for a subscript, and [`PyExc::unhandled`] is what the
//! backend answers for an exception nobody caught: the `ValueError` handler's
//! 400 (`pydantic.ValidationError` and `JSONDecodeError` are `ValueError`s),
//! the `HTTPException` envelope, else a bare 500.

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_web::ApiError;
use http::StatusCode;

/// A Python exception: its class and `str(e)`.
#[derive(Debug, Clone, PartialEq)]
pub enum PyExc {
    /// `KeyError(key)`: `str(e)` is the key's `repr()`.
    KeyError(String),
    /// `TypeError`.
    TypeError(String),
    /// `AttributeError`.
    AttributeError(String),
    /// `IndexError`.
    IndexError(String),
    /// `ValueError` (also `int()`'s and `json.dumps`'s).
    ValueError(String),
    /// `pydantic.ValidationError` (a `ValueError`).
    Validation(String),
    /// `json.JSONDecodeError` / `requests.JSONDecodeError` (a `ValueError`).
    JsonDecode(String),
    /// `fastapi.HTTPException(status, detail)`.
    Http(u16, String),
    /// Anything else (`requests.ConnectionError`, a client library's own
    /// error): the class name and `str(e)`.
    Other(&'static str, String),
}

/// `Result` of a ported Python expression.
pub type PyResult<T> = Result<T, PyExc>;

impl PyExc {
    /// `KeyError(key)`.
    pub fn key_error(key: &str) -> Self {
        Self::KeyError(str_repr(key))
    }

    /// `HTTPException(status, detail)`.
    pub fn http(status: u16, detail: impl Into<String>) -> Self {
        Self::Http(status, detail.into())
    }

    /// `str(e)`.
    pub fn text(&self) -> String {
        match self {
            PyExc::KeyError(k) => k.clone(),
            PyExc::TypeError(m)
            | PyExc::AttributeError(m)
            | PyExc::IndexError(m)
            | PyExc::ValueError(m)
            | PyExc::Validation(m)
            | PyExc::JsonDecode(m)
            | PyExc::Http(_, m)
            | PyExc::Other(_, m) => m.clone(),
        }
    }

    /// `isinstance(e, ValueError)`.
    pub fn is_value_error(&self) -> bool {
        matches!(
            self,
            PyExc::ValueError(_) | PyExc::Validation(_) | PyExc::JsonDecode(_)
        )
    }

    /// `isinstance(e, HTTPException)`.
    pub fn is_http(&self) -> bool {
        matches!(self, PyExc::Http(..))
    }

    /// `str(HTTPException)`: `"{status}: {detail}"` (Starlette's `__str__`).
    pub fn http_str(status: u16, detail: &str) -> String {
        format!("{status}: {detail}")
    }

    /// `f"{e}"` where `e` may be an `HTTPException` (whose `str()` is
    /// `"{status}: {detail}"`).
    pub fn display(&self) -> String {
        match self {
            PyExc::Http(status, detail) => Self::http_str(*status, detail),
            other => other.text(),
        }
    }

    /// What the backend answers when this exception leaves the route: the
    /// `HTTPException` envelope, the `ValueError` handler's 400, or the bare
    /// 500 of anything else.
    pub fn unhandled(self) -> ApiError {
        match self {
            PyExc::Http(status, detail) => ApiError::http(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                detail,
            ),
            e if e.is_value_error() => ApiError::bad_request(e.text()),
            other => ApiError::internal(format!("{other:?}")),
        }
    }
}

impl From<PyExc> for ApiError {
    fn from(e: PyExc) -> Self {
        e.unhandled()
    }
}

/// `type(value).__name__` of a `json.loads` value.
pub fn type_name(v: &PyValue) -> &'static str {
    match v {
        PyValue::None => "NoneType",
        PyValue::Bool(_) => "bool",
        PyValue::Int(_) => "int",
        PyValue::Float(_) => "float",
        PyValue::Str(_) => "str",
        PyValue::List(_) => "list",
        PyValue::Dict(_) => "dict",
    }
}

/// `value[key]` with a `str` key, raising what CPython raises.
pub fn getitem<'a>(value: &'a PyValue, key: &str) -> PyResult<&'a PyValue> {
    match value {
        PyValue::Dict(items) => items
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .ok_or_else(|| PyExc::key_error(key)),
        PyValue::List(_) => Err(PyExc::TypeError(
            "list indices must be integers or slices, not str".into(),
        )),
        PyValue::Str(_) => Err(PyExc::TypeError(
            "string indices must be integers, not 'str'".into(),
        )),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        ))),
    }
}

/// `value.get(key)` (`AttributeError` on anything but a dict).
pub fn get<'a>(value: &'a PyValue, key: &str) -> PyResult<Option<&'a PyValue>> {
    match value {
        PyValue::Dict(items) => Ok(items.iter().find(|(k, _)| k == key).map(|(_, v)| v)),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'get'",
            type_name(other)
        ))),
    }
}

/// `for x in value` over a `json.loads` value: a list's items, a dict's keys,
/// a string's characters; `TypeError` for the rest.
pub fn iterate(value: &PyValue) -> PyResult<Vec<PyValue>> {
    match value {
        PyValue::List(items) => Ok(items.clone()),
        PyValue::Dict(items) => Ok(items.iter().map(|(k, _)| PyValue::Str(k.clone())).collect()),
        PyValue::Str(s) => Ok(s.chars().map(|c| PyValue::Str(c.to_string())).collect()),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not iterable",
            type_name(other)
        ))),
    }
}

/// `len(value)`.
pub fn len(value: &PyValue) -> PyResult<usize> {
    match value {
        PyValue::List(items) => Ok(items.len()),
        PyValue::Dict(items) => Ok(items.len()),
        PyValue::Str(s) => Ok(s.chars().count()),
        other => Err(PyExc::TypeError(format!(
            "object of type '{}' has no len()",
            type_name(other)
        ))),
    }
}

/// A `str` value, or `None`.
pub fn as_str(value: &PyValue) -> Option<&str> {
    match value {
        PyValue::Str(s) => Some(s),
        _ => None,
    }
}

/// `str(value)` (an f-string's rendering).
pub fn py_str(value: &PyValue) -> String {
    value.py_str()
}

/// Python `==` between two `json.loads` values (`1 == 1.0 == True`).
pub fn py_eq(a: &PyValue, b: &PyValue) -> bool {
    fn num(v: &PyValue) -> Option<f64> {
        match v {
            PyValue::Bool(b) => Some(f64::from(u8::from(*b))),
            PyValue::Int(i) => i.parse::<f64>().ok(),
            PyValue::Float(f) => Some(*f),
            _ => None,
        }
    }
    match (a, b) {
        (PyValue::Int(x), PyValue::Int(y)) => x == y,
        (PyValue::None, PyValue::None) => true,
        (PyValue::Str(x), PyValue::Str(y)) => x == y,
        (PyValue::List(x), PyValue::List(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q))
        }
        (PyValue::Dict(x), PyValue::Dict(y)) => {
            x.len() == y.len()
                && x.iter().all(|(k, v)| {
                    y.iter()
                        .find(|(k2, _)| k2 == k)
                        .is_some_and(|(_, v2)| py_eq(v, v2))
                })
        }
        _ => match (num(a), num(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(items: &[(&str, PyValue)]) -> PyValue {
        PyValue::Dict(
            items
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn subscripts_raise_like_cpython() {
        let v = d(&[("a", PyValue::Int("1".into()))]);
        assert_eq!(getitem(&v, "a").unwrap(), &PyValue::Int("1".into()));
        assert_eq!(getitem(&v, "b").unwrap_err().text(), "'b'");
        assert_eq!(
            getitem(&PyValue::List(vec![]), "a").unwrap_err(),
            PyExc::TypeError("list indices must be integers or slices, not str".into())
        );
        assert_eq!(
            getitem(&PyValue::None, "a").unwrap_err().text(),
            "'NoneType' object is not subscriptable"
        );
        assert_eq!(
            getitem(&PyValue::Str("x".into()), "a").unwrap_err().text(),
            "string indices must be integers, not 'str'"
        );
        assert_eq!(
            get(&PyValue::List(vec![]), "a").unwrap_err().text(),
            "'list' object has no attribute 'get'"
        );
    }

    #[test]
    fn unhandled_exceptions_map_to_the_handlers() {
        assert_eq!(
            PyExc::Validation("1 validation error".into())
                .unhandled()
                .status(),
            400
        );
        assert_eq!(PyExc::http(404, "x").unhandled().status(), 404);
        assert_eq!(PyExc::TypeError("x".into()).unhandled().status(), 500);
        assert_eq!(PyExc::http(500, "boom").display(), "500: boom");
    }

    #[test]
    fn python_equality() {
        assert!(py_eq(&PyValue::Int("1".into()), &PyValue::Float(1.0)));
        assert!(py_eq(&PyValue::Bool(true), &PyValue::Int("1".into())));
        assert!(!py_eq(&PyValue::Str("1".into()), &PyValue::Int("1".into())));
    }
}
