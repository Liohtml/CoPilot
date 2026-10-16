//! FastAPI's side of a model: the request body validated against it (a 422
//! in `exception_handlers.py`'s format) and the response serialized from it.

use axum::response::{IntoResponse, Response};
use copilot_auth::pyvalue::PyValue;
use copilot_web::validate::{FieldError, LocPart};
use copilot_web::{ApiError, JsonBody};
use http::StatusCode;
use serde_json::Value;

use crate::json::pydantic_json;
use crate::model::{self, Invalid, Loc, Model, PyError, Ty};

/// A `serde_json` value as `json.loads` returns it.
pub fn from_json(value: &Value) -> PyValue {
    match value {
        Value::Null => PyValue::None,
        Value::Bool(b) => PyValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PyValue::Int(i.to_string())
            } else if let Some(u) = n.as_u64() {
                PyValue::Int(u.to_string())
            } else {
                PyValue::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => PyValue::Str(s.clone()),
        Value::Array(items) => PyValue::List(items.iter().map(from_json).collect()),
        Value::Object(map) => {
            PyValue::Dict(map.iter().map(|(k, v)| (k.clone(), from_json(v))).collect())
        }
    }
}

/// `200` with pydantic-core's JSON of a JSON-mode dump (a route's
/// `response_model`).
pub fn model_response(dump: &PyValue) -> Response {
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        pydantic_json(dump),
    )
        .into_response()
}

fn to_field_error(e: PyError, prefix: &str) -> FieldError {
    let mut loc = vec![LocPart::Key(prefix.to_string())];
    loc.extend(e.loc.into_iter().map(|l| match l {
        Loc::Key(k) => LocPart::Key(k),
        Loc::Index(i) => LocPart::Index(i),
    }));
    FieldError {
        kind: e.kind.to_string(),
        loc,
        msg: e.msg,
    }
}

/// A `RequestValidationError` from Pydantic error lines located under
/// `prefix` (`body`, `query`).
pub fn validation_error(errors: Vec<PyError>, prefix: &str) -> ApiError {
    ApiError::Validation(
        errors
            .into_iter()
            .map(|e| to_field_error(e, prefix).to_item())
            .collect(),
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

/// The request body validated as `model` (a FastAPI body parameter): the
/// JSON-mode dump, or the 422 (an `HTTPException` a validator raised passes
/// through as is).
pub fn body_model(body: &JsonBody, model: &'static Model) -> Result<PyValue, ApiError> {
    match body {
        JsonBody::Missing => Err(validation_error(
            vec![PyError {
                loc: Vec::new(),
                kind: "missing",
                msg: "Field required".into(),
                input: PyValue::None,
            }],
            "body",
        )),
        JsonBody::Value(v @ Value::Object(_)) => {
            model::validate_body(&Ty::Model(model), &from_json(v)).map_err(invalid)
        }
        _ => Err(validation_error(
            vec![PyError {
                loc: Vec::new(),
                kind: "model_attributes_type",
                msg: "Input should be a valid dictionary or object to extract fields from".into(),
                input: PyValue::None,
            }],
            "body",
        )),
    }
}

/// The request body validated as a non-model type (`payload: dict`).
pub fn body_value(body: &JsonBody, ty: &Ty) -> Result<PyValue, ApiError> {
    let input = match body {
        JsonBody::Missing => {
            return Err(validation_error(
                vec![PyError {
                    loc: Vec::new(),
                    kind: "missing",
                    msg: "Field required".into(),
                    input: PyValue::None,
                }],
                "body",
            ));
        }
        // Raw bytes: no JSON type accepts them.
        JsonBody::NotJson => PyValue::List(Vec::new()),
        JsonBody::Value(v) => from_json(v),
    };
    match (body, ty) {
        (JsonBody::NotJson, Ty::Dict(_)) => Err(validation_error(
            vec![PyError {
                loc: Vec::new(),
                kind: "dict_type",
                msg: "Input should be a valid dictionary".into(),
                input: PyValue::None,
            }],
            "body",
        )),
        _ => model::validate_body(ty, &input).map_err(invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Field;

    static BODY: Model = Model::new("Body", &[Field::req("input_id", Ty::Str)]);

    #[test]
    fn body_errors_are_fastapi_422s() {
        let e = body_model(&JsonBody::Missing, &BODY).unwrap_err();
        assert_eq!(e.status(), 422);
        let e =
            body_model(&JsonBody::Value(serde_json::json!({"input_id": 1})), &BODY).unwrap_err();
        let ApiError::Validation(items) = e else {
            panic!("not a 422")
        };
        assert_eq!(items[0].field, "input_id");
        assert_eq!(
            items[0].message.as_deref(),
            Some("input_id: Input should be a valid string")
        );
        let ok = body_model(
            &JsonBody::Value(serde_json::json!({"input_id": "a"})),
            &BODY,
        );
        assert_eq!(ok.unwrap().py_repr(), "{'input_id': 'a'}");
    }
}
