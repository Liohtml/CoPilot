//! `scoutsuite_vectors.json` (`scripts/gen-scoutsuite-vectors.py`): the
//! answers, the request models with the commands they become, the upload's
//! checks and `os.path.splitext`, recorded from Python.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::pydantic_json;
use copilot_upstream::model::{Invalid, Loc, Model, Ty, validate_body};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::from_json;
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

use crate::schema::{AWS_REQUEST, AZURE_REQUEST, options_response};
use crate::services::{aws_command, azure_command, check_upload, gcp_command, splitext_base};

fn doc() -> Value {
    serde_json::from_str(include_str!("scoutsuite_vectors.json")).unwrap()
}

fn as_json(v: &PyValue) -> Value {
    serde_json::from_str(&pydantic_json(v)).unwrap()
}

fn command(args: Vec<String>) -> Value {
    json!(
        std::iter::once("scout".to_string())
            .chain(args)
            .collect::<Vec<_>>()
    )
}

fn model_outcome(
    model: &'static Model,
    report_type: &str,
    cmd: fn(&PyValue) -> Vec<String>,
    body: &Value,
) -> Value {
    match validate_body(&Ty::Model(model), &from_json(body)) {
        Ok(dump) if dump.get("report_type").and_then(PyValue::as_str) != Some(report_type) => {
            json!({"http": [400, "Invalid report type."]})
        }
        Ok(dump) => json!({"ok": as_json(&dump), "command": command(cmd(&dump))}),
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
    }
}

#[test]
fn answers_and_requests_as_python() {
    let d = doc();
    assert_eq!(as_json(&options_response()), d["options"]);
    for case in d["aws"].as_array().unwrap() {
        let got = model_outcome(&AWS_REQUEST, "aws", aws_command, &case["body"]);
        assert_eq!(got, case["outcome"], "{}", case["body"]);
    }
    for case in d["azure"].as_array().unwrap() {
        let got = model_outcome(&AZURE_REQUEST, "azure", azure_command, &case["body"]);
        assert_eq!(got, case["outcome"], "{}", case["body"]);
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn uploads_are_checked_as_python() {
    for case in doc()["gcp"].as_array().unwrap() {
        let contents = unhex(case["contents"].as_str().unwrap());
        let got = match check_upload(&contents) {
            Ok(()) => json!({"command": command(gcp_command(
                "gcp-report",
                "/tmp/x/gcp-service-account.json"
            ))}),
            Err(PyExc::Http(status, text)) => {
                json!({"error": {"class": "HTTPException", "status": status, "text": text}})
            }
            Err(PyExc::ValueError(text)) => {
                json!({"error": {"class": "UnicodeDecodeError", "text": text}})
            }
            Err(other) => panic!("{other:?}"),
        };
        assert_eq!(got, case["outcome"], "{}", case["contents"]);
    }
}

#[test]
fn splitext_as_python() {
    for case in doc()["splitext"].as_array().unwrap() {
        assert_eq!(
            splitext_base(case["name"].as_str().unwrap()),
            case["base"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}
