//! `sublime_vectors.json` (`scripts/gen-sublime-vectors.py`): the request
//! and response models, the stored tags, the email lookups, SQLAlchemy's
//! parameter reprs and pymysql's literals, recorded from Python.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::NaiveDateTime;
use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::json::{Dumps, py_dumps_allow_nan, pydantic_json};
use copilot_upstream::model::{Invalid, Loc, Ty, format_validation_error, validate, validate_body};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::from_json;
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

use crate::schema::{ALERT_REQUEST_BODY, SUBLIME_ALERTS_SCHEMA};
use crate::services::email_of;
use crate::sql::{Param, Refused, literal, params_repr};

fn doc() -> Value {
    serde_json::from_str(include_str!("sublime_vectors.json")).unwrap()
}

fn as_json(v: &PyValue) -> Value {
    serde_json::from_str(&pydantic_json(v)).unwrap()
}

fn class(e: &PyExc) -> &'static str {
    match e {
        PyExc::KeyError(_) => "KeyError",
        PyExc::TypeError(_) => "TypeError",
        PyExc::AttributeError(_) => "AttributeError",
        PyExc::IndexError(_) => "IndexError",
        PyExc::ValueError(_) => "ValueError",
        PyExc::Validation(_) => "ValidationError",
        PyExc::JsonDecode(_) => "JSONDecodeError",
        PyExc::Http(..) => "HTTPException",
        PyExc::Other(c, _) => c,
    }
}

#[test]
fn request_bodies_validate_as_pydantic() {
    for case in doc()["requests"].as_array().unwrap() {
        let got = match validate_body(&Ty::Model(&ALERT_REQUEST_BODY), &from_json(&case["body"])) {
            Ok(dump) => json!({"ok": as_json(&dump)}),
            Err(Invalid::Errors(errors)) => json!({"errors": errors
                .iter()
                .map(|e| json!({
                    "type": e.kind,
                    "loc": e.loc.iter().map(|l| match l {
                        Loc::Key(k) => json!(k),
                        Loc::Index(i) => json!(i),
                    }).collect::<Vec<_>>(),
                    "msg": e.msg,
                }))
                .collect::<Vec<_>>()}),
            Err(other) => panic!("{other:?}"),
        };
        assert_eq!(got, case["outcome"], "{}", case["body"]);
    }
}

#[test]
fn stored_alerts_validate_as_pydantic() {
    for case in doc()["schemas"].as_array().unwrap() {
        let got = match validate(&SUBLIME_ALERTS_SCHEMA, &from_json(&case["row"])) {
            Ok(dump) => json!({"ok": as_json(&dump)}),
            Err(Invalid::Errors(errors)) => {
                json!({"error": format_validation_error(SUBLIME_ALERTS_SCHEMA.name, &errors)})
            }
            Err(other) => panic!("{other:?}"),
        };
        assert_eq!(got, case["outcome"], "{}", case["row"]);
    }
}

#[test]
fn tags_and_emails_as_python() {
    let d = doc();
    for case in d["tags"].as_array().unwrap() {
        assert_eq!(
            py_dumps_allow_nan(&from_json(&case["tags"]), Dumps::DEFAULT),
            case["dumps"].as_str().unwrap()
        );
    }
    for case in d["emails"].as_array().unwrap() {
        let data = loads(case["data"].as_str().unwrap()).unwrap();
        for (key, recipient) in [("sender", false), ("recipient", true)] {
            let got = match email_of(&data, recipient) {
                Ok(v) => json!({"ok": as_json(&v)}),
                Err(e) => json!({"error": {"class": class(&e), "text": e.text()}}),
            };
            assert_eq!(got, case[key], "{key} of {}", case["data"]);
        }
    }
}

#[test]
fn parameters_and_literals_as_sqlalchemy_and_pymysql() {
    let d = doc();
    for case in d["params"].as_array().unwrap() {
        let params: Vec<Param> = case["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                if let Some(t) = v.get("text") {
                    Param::Text(t.as_str().map(str::to_string))
                } else if let Some(n) = v.get("id") {
                    Param::Id(n.as_u64().unwrap())
                } else if let Some(t) = v.get("time") {
                    let t = t.as_str().unwrap();
                    let fmt = if t.contains('.') {
                        "%Y-%m-%d %H:%M:%S%.f"
                    } else {
                        "%Y-%m-%d %H:%M:%S"
                    };
                    Param::Time(NaiveDateTime::parse_from_str(t, fmt).unwrap())
                } else {
                    Param::Json(loads(v["json"].as_str().unwrap()).unwrap())
                }
            })
            .collect();
        assert_eq!(params_repr(&params), case["repr"].as_str().unwrap());
    }
    for case in d["literals"].as_array().unwrap() {
        let value = loads(case["value"].as_str().unwrap()).unwrap();
        let mut binds = Vec::new();
        let got = match literal(&value, &mut binds) {
            Ok(sql) => json!({"ok": sql}),
            Err(Refused::Dict) => json!({"error": {
                "class": "TypeError", "text": "dict can not be used as parameter"
            }}),
            Err(Refused::Float(s)) => json!({"error": {
                "class": "ProgrammingError", "text": format!("{s} can not be used with MySQL")
            }}),
        };
        assert_eq!(got, case["outcome"], "{}", case["value"]);
        assert!(binds.is_empty());
    }
}
