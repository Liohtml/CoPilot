//! Request bodies the way FastAPI reads them — *before* it solves any
//! dependency (`fastapi/routing.py:get_request_handler`).
//!
//! FastAPI reads and decodes the body first, so a malformed JSON body is a
//! 422 `json_invalid` even without a token, while a body that decodes but
//! does not fit the model is reported only after the token, path and query
//! checks. The extractors here keep that order:
//!
//! | Body | FastAPI | Here |
//! |---|---|---|
//! | empty | body `None` → `Field required` at `("body",)` | [`JsonBody::Missing`] |
//! | `Content-Type` JSON (`application/json`, `*/*+json`), malformed | 422 `json_invalid` at `("body", pos)`, before auth | the extractor's rejection |
//! | JSON content type, not UTF-8 | 400 `{"detail": "There was an error parsing the body"}` | the extractor's rejection |
//! | any other or no `Content-Type` | raw bytes → `model_attributes_type` | [`JsonBody::NotJson`] |
//! | form route | `request.form()` ([`crate::form`]) | [`Form`] |
//!
//! Handler shape: `WithJson(auth, body): WithJson<Authorized<…>>` as the
//! last argument; the auth extractor still runs (its error is only reported
//! after the body's), then the handler checks path, query and
//! [`JsonBody::model`].

use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use serde_json::{Map, Value};

use crate::error::ApiError;
use crate::form::{self, FormData, FormError, latin1, py_strip};
use crate::pyjson;
use crate::validate::{FieldError, Loc, LocPart, Validator, body_loc};

/// FastAPI's answer when the body cannot be read at all.
pub const BODY_PARSE_ERROR: &str = "There was an error parsing the body";

/// A JSON route's body after FastAPI's pre-dependency read.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonBody {
    /// No body.
    Missing,
    /// Parsed JSON.
    Value(Value),
    /// A body sent without a JSON content type: never a model.
    NotJson,
}

/// `email.message.Message.get_content_type()` is JSON-ish.
pub fn is_json_content_type(value: &str) -> bool {
    let main = value.split(';').next().unwrap_or_default();
    let ctype = py_strip(main).to_lowercase();
    let mut parts = ctype.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("application"), Some(sub), None) => sub == "json" || sub.ends_with("+json"),
        _ => false,
    }
}

impl JsonBody {
    /// Read a body as FastAPI does; `Err` is reported before any dependency.
    pub fn read(content_type: Option<&str>, bytes: &[u8]) -> Result<Self, ApiError> {
        if bytes.is_empty() {
            return Ok(Self::Missing);
        }
        if !content_type.is_some_and(is_json_content_type) {
            return Ok(Self::NotJson);
        }
        let text = pyjson::decode(bytes)
            .ok_or_else(|| ApiError::detail(http::StatusCode::BAD_REQUEST, BODY_PARSE_ERROR))?;
        let invalid = |pos: usize| {
            ApiError::Validation(vec![
                FieldError {
                    kind: "json_invalid".into(),
                    loc: vec![LocPart::Key("body".into()), LocPart::Index(pos)],
                    msg: "JSON decode error".into(),
                }
                .to_item(),
            ])
        };
        if let Some(pos) = pyjson::error_position(text) {
            return Err(invalid(pos));
        }
        // CPython accepts what serde_json cannot hold (NaN, lone surrogates).
        serde_json::from_str(text)
            .map(Self::Value)
            .map_err(|_| invalid(0))
    }

    /// Validate the body as a model: `read` gets the validator, the object
    /// and its location (as [`crate::validate::parse_body_model`]).
    pub fn model<T>(
        &self,
        read: impl FnOnce(&mut Validator, &Map<String, Value>, &Loc) -> T,
    ) -> Result<T, ApiError> {
        let mut v = Validator::new();
        let root = body_loc();
        let out = match self {
            Self::Missing => {
                v.missing(root);
                None
            }
            Self::NotJson => v
                .object(&Value::Null, &root)
                .map(|obj| read(&mut v, obj, &root)),
            Self::Value(value) => v.object(value, &root).map(|obj| read(&mut v, obj, &root)),
        };
        v.finish()?;
        out.ok_or_else(|| ApiError::internal("JsonBody::model: object without errors"))
    }
}

impl JsonBody {
    /// Validate a body that is not a model (`List[str]`, …): `read` gets the
    /// value — `null` for a body sent without a JSON content type, which no
    /// such type accepts — and its location.
    pub fn value<T>(
        &self,
        read: impl FnOnce(&mut Validator, &Value, &Loc) -> T,
    ) -> Result<T, ApiError> {
        let mut v = Validator::new();
        let root = body_loc();
        let out = match self {
            Self::Missing => {
                v.missing(root);
                None
            }
            Self::NotJson => Some(read(&mut v, &Value::Null, &root)),
            Self::Value(value) => Some(read(&mut v, value, &root)),
        };
        v.finish()?;
        out.ok_or_else(|| ApiError::internal("JsonBody::value: missing body without errors"))
    }
}

fn content_type(req: &Request) -> Option<String> {
    req.headers()
        .get(http::header::CONTENT_TYPE)
        .map(|v| latin1(v.as_bytes()))
}

impl<S: Send + Sync> FromRequest<S> for JsonBody {
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Response> {
        let ct = content_type(&req);
        let body = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Self::read(ct.as_deref(), &body).map_err(IntoResponse::into_response)
    }
}

/// An extractor `A` (usually the auth guard) and the JSON body, reported in
/// FastAPI's order: body decoding errors first, then `A`'s.
#[derive(Debug)]
pub struct WithJson<A>(pub A, pub JsonBody);

impl<A, S> FromRequest<S> for WithJson<A>
where
    A: FromRequestParts<S> + Send,
    A::Rejection: IntoResponse,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Response> {
        let ct = content_type(&req);
        let (mut parts, body) = req.into_parts();
        let guard = A::from_request_parts(&mut parts, state)
            .await
            .map_err(IntoResponse::into_response);
        let raw = Bytes::from_request(Request::from_parts(parts, body), state)
            .await
            .map_err(IntoResponse::into_response)?;
        let json = JsonBody::read(ct.as_deref(), &raw).map_err(IntoResponse::into_response)?;
        let guard = guard?;
        Ok(Self(guard, json))
    }
}

/// A form route's body (`await request.form()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form(pub FormData);

impl<S: Send + Sync> FromRequest<S> for Form {
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Response> {
        let ct = content_type(&req);
        let raw = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        form::read_form(ct.as_deref(), &raw).map(Form).map_err(|e| {
            let detail = match e {
                FormError::Rejected(message) => message,
                FormError::Malformed => BODY_PARSE_ERROR.to_string(),
            };
            ApiError::detail(http::StatusCode::BAD_REQUEST, detail).into_response()
        })
    }
}

impl Form {
    /// A `Form()` string parameter, as FastAPI reads it: the last value for
    /// `name`; an empty string counts as absent; a file is `string_type`.
    /// `None` = absent (the caller decides between default and `missing`).
    pub fn text(&self, v: &mut Validator, name: &str) -> Option<String> {
        match self.0.get(name) {
            None => None,
            Some(form::FormValue::Text(t)) if t.is_empty() => None,
            Some(form::FormValue::Text(t)) => Some(t.clone()),
            Some(form::FormValue::File { .. }) => {
                v.push(
                    "string_type",
                    vec![LocPart::Key("body".into()), LocPart::Key(name.into())],
                    "Input should be a valid string",
                );
                None
            }
        }
    }

    /// A required `Form()` string parameter.
    pub fn req_text(&self, v: &mut Validator, name: &str) -> String {
        let present = self.0.get(name).is_some_and(|value| match value {
            form::FormValue::Text(t) => !t.is_empty(),
            form::FormValue::File { .. } => true,
        });
        if !present {
            v.missing(vec![LocPart::Key("body".into()), LocPart::Key(name.into())]);
            return String::new();
        }
        self.text(v, name).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_content_types_match_fastapi() {
        let doc: Value = serde_json::from_str(include_str!("form_vectors.json")).unwrap();
        for case in doc["json_content_types"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            assert_eq!(
                is_json_content_type(input),
                case["json"].as_bool().unwrap(),
                "{input:?}"
            );
        }
    }

    fn items(e: ApiError) -> Value {
        match e {
            ApiError::Validation(items) => serde_json::to_value(items).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn read_follows_fastapi() {
        let ct = Some("application/json");
        assert_eq!(JsonBody::read(ct, b"").unwrap(), JsonBody::Missing);
        assert_eq!(JsonBody::read(None, b"{}").unwrap(), JsonBody::NotJson);
        assert_eq!(
            JsonBody::read(Some("text/plain"), b"{}").unwrap(),
            JsonBody::NotJson
        );
        assert_eq!(
            JsonBody::read(ct, b"\xef\xbb\xbf{\"a\": 1}").unwrap(),
            JsonBody::Value(json!({"a": 1}))
        );
        assert_eq!(
            items(JsonBody::read(ct, b"  ").unwrap_err()),
            json!([{"field": "2", "error_type": "json_invalid",
                    "message": "Invalid JSON. Please check your JSON syntax and try again."}])
        );
        let not_utf8 = JsonBody::read(ct, b"{\"a\": \"\xff\"}").unwrap_err();
        assert_eq!(not_utf8.status(), 400);
        assert_eq!(
            items(JsonBody::read(ct, b"NaN").unwrap_err())[0]["field"],
            json!("0")
        );
    }

    #[test]
    fn model_errors() {
        let read = |v: &mut Validator, obj: &Map<String, Value>, at: &Loc| {
            v.req_str(obj, at, "code", Default::default())
        };
        let msg = |e: ApiError| items(e)[0]["message"].clone();
        assert_eq!(
            msg(JsonBody::Missing.model(read).unwrap_err()),
            json!("Missing data for required field.")
        );
        assert_eq!(
            msg(JsonBody::NotJson.model(read).unwrap_err()),
            json!("Input should be a valid dictionary or object to extract fields from")
        );
        assert_eq!(
            JsonBody::Value(json!({"code": "1"})).model(read).unwrap(),
            "1"
        );
    }

    #[test]
    fn form_fields() {
        let form = Form(
            form::read_form(
                Some("application/x-www-form-urlencoded"),
                b"username=&password=x&password=y",
            )
            .unwrap(),
        );
        let mut v = Validator::new();
        assert_eq!(form.req_text(&mut v, "password"), "y");
        assert_eq!(form.req_text(&mut v, "username"), "");
        assert_eq!(form.text(&mut v, "grant_type"), None);
        assert_eq!(v.errors().len(), 1);
    }
}
