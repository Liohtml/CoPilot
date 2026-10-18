//! Request bodies as FastAPI reads them, with the values `json.loads` gives.
//!
//! [`copilot_web::WithJson`] keeps FastAPI's order (the body is decoded
//! before any dependency) but holds a `serde_json::Value`, which cannot carry
//! everything CPython's `json` accepts: integers beyond 64 bits, `NaN`,
//! `Infinity`. These routes send what they were given on to Graylog or the
//! Event Shipper (a window of `10**20` seconds becomes `10**23` ms in the
//! event definition; a test payload is shipped as `json.dumps` writes it),
//! so [`WithPyJson`] decodes the body once more with
//! [`copilot_auth::pyvalue::loads`], CPython's grammar. Where a body cannot be
//! decoded the answers are `WithJson`'s: the 422 `json_invalid` at CPython's
//! error position, the 400 for a body that is not UTF-8, both before the
//! token is looked at; a body sent without a JSON content type never matches
//! a model.

use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use copilot_auth::pyvalue::{self, PyValue};
use copilot_upstream::model::{self, Invalid, Model, PyError, Ty};
use copilot_upstream::respond::validation_error;
use copilot_web::ApiError;
use copilot_web::body::{BODY_PARSE_ERROR, is_json_content_type};
use copilot_web::form::latin1;
use copilot_web::pyjson;
use copilot_web::validate::{FieldError, LocPart};
use http::StatusCode;

/// A JSON route's body after FastAPI's pre-dependency read.
#[derive(Debug, Clone, PartialEq)]
pub enum PyBody {
    /// No body (or JSON `null`).
    Missing,
    /// A body sent without a JSON content type: never a model.
    NotJson,
    /// The value `json.loads` returns.
    Value(PyValue),
}

fn json_invalid(pos: usize) -> ApiError {
    ApiError::Validation(vec![
        FieldError {
            kind: "json_invalid".into(),
            loc: vec![LocPart::Key("body".into()), LocPart::Index(pos)],
            msg: "JSON decode error".into(),
        }
        .to_item(),
    ])
}

fn missing() -> ApiError {
    validation_error(
        vec![PyError {
            loc: Vec::new(),
            kind: "missing",
            msg: "Field required".into(),
            input: PyValue::None,
        }],
        "body",
    )
}

fn invalid(e: Invalid) -> ApiError {
    match e {
        Invalid::Errors(errors) => validation_error(errors, "body"),
        Invalid::Abort(status, detail) => ApiError::http(
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            detail,
        ),
    }
}

impl PyBody {
    /// Read a body as FastAPI does; `Err` is reported before any dependency.
    pub fn read(content_type: Option<&str>, bytes: &[u8]) -> Result<Self, ApiError> {
        if bytes.is_empty() {
            return Ok(Self::Missing);
        }
        if !content_type.is_some_and(is_json_content_type) {
            return Ok(Self::NotJson);
        }
        let text = pyjson::decode(bytes)
            .ok_or_else(|| ApiError::detail(StatusCode::BAD_REQUEST, BODY_PARSE_ERROR))?;
        if let Some(pos) = pyjson::error_position(text) {
            return Err(json_invalid(pos));
        }
        match pyvalue::loads(text) {
            Ok(PyValue::None) => Ok(Self::Missing),
            Ok(value) => Ok(Self::Value(value)),
            // Accepted by the scanner, refused by the value parser (nesting
            // deeper than CPython's recursion allows).
            Err(_) => Err(json_invalid(0)),
        }
    }

    /// The body validated as `model` (a FastAPI body parameter): the
    /// JSON-mode dump, or the 422 — or the `HTTPException` a field validator
    /// raised, which ends validation as it is.
    pub fn model(&self, model: &'static Model) -> Result<PyValue, ApiError> {
        match self {
            Self::Missing => Err(missing()),
            Self::Value(v @ PyValue::Dict(_)) => {
                model::validate_body(&Ty::Model(model), v).map_err(invalid)
            }
            _ => Err(validation_error(
                vec![PyError {
                    loc: Vec::new(),
                    kind: "model_attributes_type",
                    msg: "Input should be a valid dictionary or object to extract fields from"
                        .into(),
                    input: PyValue::None,
                }],
                "body",
            )),
        }
    }

    /// The body validated as `dict` (`request: dict`).
    pub fn dict(&self) -> Result<Vec<(String, PyValue)>, ApiError> {
        match self {
            Self::Missing => Err(missing()),
            Self::Value(PyValue::Dict(items)) => Ok(items.clone()),
            _ => Err(validation_error(
                vec![PyError {
                    loc: Vec::new(),
                    kind: "dict_type",
                    msg: "Input should be a valid dictionary".into(),
                    input: PyValue::None,
                }],
                "body",
            )),
        }
    }
}

/// An extractor `A` (the auth guard) and the body, reported in FastAPI's
/// order: decoding errors first, then `A`'s.
#[derive(Debug)]
pub struct WithPyJson<A>(pub A, pub PyBody);

impl<A, S> FromRequest<S> for WithPyJson<A>
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
            .map(|v| latin1(v.as_bytes()));
        let (mut parts, body) = req.into_parts();
        let guard = A::from_request_parts(&mut parts, state)
            .await
            .map_err(IntoResponse::into_response);
        let raw = Bytes::from_request(Request::from_parts(parts, body), state)
            .await
            .map_err(IntoResponse::into_response)?;
        let body =
            PyBody::read(content_type.as_deref(), &raw).map_err(IntoResponse::into_response)?;
        let guard = guard?;
        Ok(Self(guard, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: Option<&str> = Some("application/json");

    #[test]
    fn values_are_cpython_s() {
        let body = PyBody::read(
            JSON,
            br#"{"n": 100000000000000000000, "f": NaN, "i": -Infinity, "d": 1, "d": 2}"#,
        )
        .unwrap();
        let PyBody::Value(v) = body else {
            panic!("{body:?}")
        };
        assert_eq!(
            v.py_repr(),
            "{'n': 100000000000000000000, 'f': nan, 'i': -inf, 'd': 2}"
        );
        assert_eq!(PyBody::read(JSON, b"null").unwrap(), PyBody::Missing);
        assert_eq!(PyBody::read(JSON, b"").unwrap(), PyBody::Missing);
        assert_eq!(PyBody::read(None, b"{}").unwrap(), PyBody::NotJson);
        assert_eq!(
            PyBody::read(Some("text/plain"), b"{}").unwrap(),
            PyBody::NotJson
        );
    }

    #[test]
    fn undecodable_bodies_fail_as_fastapi_s() {
        let e = PyBody::read(JSON, b"{\"a\": }").unwrap_err();
        let ApiError::Validation(items) = e else {
            panic!("not a 422")
        };
        assert_eq!(items[0].field, "6");
        assert_eq!(items[0].error_type, "json_invalid");
        let e = PyBody::read(JSON, b"\xff").unwrap_err();
        assert_eq!(e.status(), 400);
    }

    #[test]
    fn a_dict_body() {
        let ok = PyBody::read(JSON, br#"{"a": 1}"#).unwrap().dict().unwrap();
        assert_eq!(ok.len(), 1);
        for raw in [&b"[1]"[..], b"\"x\"", b"3"] {
            let e = PyBody::read(JSON, raw).unwrap().dict().unwrap_err();
            let ApiError::Validation(items) = e else {
                panic!("not a 422")
            };
            assert_eq!(items[0].error_type, "value_error");
            assert_eq!(
                items[0].message.as_deref(),
                Some("Input should be a valid dictionary")
            );
        }
        assert_eq!(PyBody::NotJson.dict().unwrap_err().status(), 422);
        assert_eq!(PyBody::Missing.dict().unwrap_err().status(), 422);
    }
}
