//! A SQLModel **table** model as a request body (`List[AvailableIntegrations]`,
//! `List[AvailableNetworkConnectors]`), which SQLModel does not validate.
//!
//! FastAPI checks that the body is a list and every item an object (else
//! `list_type` / `model_attributes_type`, the 422); the item's values are
//! then kept with their JSON types (`sqlmodel_table_construct`): the declared
//! fields it names, in declaration order, then the defaulted fields it does
//! not name. A relationship key it names is assigned to the relationship,
//! which only an empty list survives (anything else raises inside the
//! validation: a bare 500). An absent field reads as `None`.
//!
//! The instance's `repr()` (`Class(field=value, …)`, in that same order) is
//! what a `ValidationError` about it quotes.

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::model::truncate_repr;
use copilot_web::ApiError;
use copilot_web::body::JsonBody;
use copilot_web::validate::{FieldError, LocPart};
use serde_json::Value;

/// One table model.
#[derive(Debug)]
pub struct TableModel {
    /// The class name (`repr`, `input_type`).
    pub class: &'static str,
    /// The fields, in declaration order.
    pub fields: &'static [&'static str],
    /// The fields with a default (`id = None`), set when not named.
    pub defaulted: &'static [&'static str],
    /// The relationship attributes.
    pub relationships: &'static [&'static str],
}

/// One body item as the instance holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    /// The attributes in `__dict__` order.
    pub values: Vec<(&'static str, PyValue)>,
}

impl Item {
    /// `instance.<field>` (`None` when the body did not name it).
    pub fn get(&self, field: &str) -> PyValue {
        self.values
            .iter()
            .find(|(k, _)| *k == field)
            .map_or(PyValue::None, |(_, v)| v.clone())
    }

    /// `repr(instance)`.
    pub fn repr(&self, model: &TableModel) -> String {
        let parts: Vec<String> = self
            .values
            .iter()
            .map(|(k, v)| format!("{k}={}", v.py_repr()))
            .collect();
        format!("{}({})", model.class, parts.join(", "))
    }
}

fn py(v: &Value) -> PyValue {
    loads(&v.to_string()).unwrap_or(PyValue::None)
}

fn error(kind: &str, loc: Vec<LocPart>, msg: &str) -> ApiError {
    ApiError::Validation(vec![
        FieldError {
            kind: kind.into(),
            loc,
            msg: msg.into(),
        }
        .to_item(),
    ])
}

/// The body as `List[<table model>]`.
pub fn read_list(body: &JsonBody, model: &TableModel) -> Result<Vec<Item>, ApiError> {
    let body_loc = || vec![LocPart::Key("body".into())];
    let items = match body {
        JsonBody::Missing => return Err(error("missing", body_loc(), "Field required")),
        JsonBody::Value(Value::Array(items)) => items,
        _ => {
            return Err(error(
                "list_type",
                body_loc(),
                "Input should be a valid list",
            ));
        }
    };
    let mut errors = Vec::new();
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let Value::Object(map) = item else {
            errors.push(
                FieldError {
                    kind: "model_attributes_type".into(),
                    loc: vec![LocPart::Key("body".into()), LocPart::Index(i)],
                    msg: "Input should be a valid dictionary or object to extract fields from"
                        .into(),
                }
                .to_item(),
            );
            continue;
        };
        let mut values = Vec::new();
        for field in model.fields {
            if let Some(v) = map.get(*field) {
                values.push((*field, py(v)));
            }
        }
        for field in model.defaulted {
            if !map.contains_key(*field) {
                values.push((*field, PyValue::None));
            }
        }
        for rel in model.relationships {
            if let Some(v) = map.get(*rel) {
                if !matches!(v, Value::Array(a) if a.is_empty()) {
                    return Err(ApiError::internal(format!(
                        "{}.{rel}: only an empty list can be assigned",
                        model.class
                    )));
                }
            }
        }
        out.push(Item { values });
    }
    if !errors.is_empty() {
        return Err(ApiError::Validation(errors));
    }
    Ok(out)
}

/// `str(ValidationError)` for items that are not `item_model` instances
/// (`model_type`, the response model refusing the table model instances).
pub fn model_type_errors(
    title: &str,
    field: &str,
    item_model: &str,
    model: &TableModel,
    items: &[Item],
) -> String {
    let n = items.len();
    let mut out = format!(
        "{n} validation error{} for {title}",
        if n == 1 { "" } else { "s" }
    );
    for (i, item) in items.iter().enumerate() {
        out.push_str(&format!(
            "\n{field}.{i}\n  Input should be a valid dictionary or instance of {item_model} \
             [type=model_type, input_value={}, input_type={}]\n    For further information visit \
             https://errors.pydantic.dev/{}/v/model_type",
            truncate_repr(item.repr(model)),
            model.class,
            copilot_upstream::model::PYDANTIC_VERSION,
        ));
    }
    out
}

/// What a value binds as in a `WHERE column = …` (pymysql's literal):
/// strings as strings, numbers as numbers, `None` as `IS NULL`; a list or a
/// dict cannot be bound (a bare 500).
#[derive(Debug, Clone, PartialEq)]
pub enum Bound {
    /// `IS NULL`.
    Null,
    /// A string.
    Text(String),
    /// An integer.
    Int(i64),
    /// A float.
    Float(f64),
}

/// `Bound` of a value (`Err`: Python's driver cannot bind it).
pub fn bound(v: &PyValue) -> Result<Bound, ApiError> {
    match v {
        PyValue::None => Ok(Bound::Null),
        PyValue::Str(s) => Ok(Bound::Text(s.clone())),
        PyValue::Bool(b) => Ok(Bound::Int(i64::from(*b))),
        PyValue::Int(i) => Ok(i
            .parse::<i64>()
            .map_or_else(|_| Bound::Text(i.clone()), Bound::Int)),
        PyValue::Float(f) => Ok(Bound::Float(*f)),
        PyValue::List(_) | PyValue::Dict(_) => Err(ApiError::internal(
            "a list or a dict cannot be bound as a statement parameter",
        )),
    }
}

/// What an attribute assignment stores: pymysql's literal of the value,
/// converted by MySQL into the column (`5` → `'5'`, `True` → `'1'`, a
/// fraction as written).
pub fn stored(v: &PyValue) -> Result<Option<String>, ApiError> {
    Ok(match bound(v)? {
        Bound::Null => None,
        Bound::Text(s) => Some(s),
        Bound::Int(i) => Some(i.to_string()),
        Bound::Float(f) => Some(copilot_auth::pyvalue::float_repr(f)),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use serde_json::json;

    static MODEL: TableModel = TableModel {
        class: "AvailableIntegrations",
        fields: &[
            "id",
            "integration_name",
            "description",
            "integration_details",
        ],
        defaulted: &["id"],
        relationships: &["auth_keys"],
    };

    #[test]
    fn items_keep_declaration_order_then_defaults() {
        let body = JsonBody::Value(json!([
            {"integration_details": "nd", "integration_name": "Mimecast", "description": "a"},
            {"description": "d", "integration_name": "M", "id": 3, "integration_details": "x", "bogus": 1}
        ]));
        let items = read_list(&body, &MODEL).unwrap();
        assert_eq!(
            items[0].repr(&MODEL),
            "AvailableIntegrations(integration_name='Mimecast', description='a', \
             integration_details='nd', id=None)"
        );
        assert_eq!(
            truncate_repr(items[1].repr(&MODEL)),
            "AvailableIntegrations(id=...integration_details='x')"
        );
        assert_eq!(items[0].get("missing"), PyValue::None);
    }

    #[test]
    fn shapes_fastapi_refuses() {
        assert_eq!(
            read_list(&JsonBody::Missing, &MODEL).unwrap_err().status(),
            422
        );
        assert_eq!(
            read_list(&JsonBody::NotJson, &MODEL).unwrap_err().status(),
            422
        );
        assert_eq!(
            read_list(&JsonBody::Value(json!([1, "x"])), &MODEL)
                .unwrap_err()
                .status(),
            422
        );
        assert_eq!(
            read_list(&JsonBody::Value(json!([{"auth_keys": [1]}])), &MODEL)
                .unwrap_err()
                .status(),
            500
        );
        assert!(read_list(&JsonBody::Value(json!([{"auth_keys": []}])), &MODEL).is_ok());
    }
}
