//! `integration_modules_vectors.json` (`scripts/gen-integration-modules-vectors.py`):
//! the module models, the three requests carrying `set_time_bounds` and the
//! `time_range` pattern, `base64.b64decode` and Pydantic's `HttpUrl`, against
//! what the Python code returns or raises.

use chrono::NaiveDateTime;
use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::json::pydantic_json;
use copilot_upstream::model::{Model, construct, format_validation_error};
use copilot_upstream::py::PyExc;

use crate::collect::cato_keys;
use crate::mimecast::{b64decode, is_http_url};
use crate::sap_siem::{construct_bounded, validate_with_pattern};
use crate::schema;

fn doc() -> PyValue {
    loads(include_str!("integration_modules_vectors.json")).unwrap()
}

fn list<'a>(v: &'a PyValue, key: &str) -> &'a [PyValue] {
    match v.get(key) {
        Some(PyValue::List(items)) => items,
        other => panic!("{key}: {other:?}"),
    }
}

fn text(v: &PyValue, key: &str) -> String {
    v.get(key)
        .and_then(PyValue::as_str)
        .unwrap_or_default()
        .to_string()
}

fn now(doc: &PyValue) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(&text(doc, "now"), "%Y-%m-%dT%H:%M:%S%.f").unwrap()
}

/// `(class, text)` of the exception Python raised (`binascii.Error` is a
/// `ValueError`, as Rust carries it).
fn python_error(v: &PyValue) -> Option<(String, String)> {
    v.get("error").map(|e| {
        let class = text(e, "class");
        let class = if class == "Error" {
            "ValueError".to_string()
        } else {
            class
        };
        (class, text(e, "text"))
    })
}

fn rust_error(e: &PyExc) -> (String, String) {
    let class = match e {
        PyExc::KeyError(_) => "KeyError",
        PyExc::TypeError(_) => "TypeError",
        PyExc::AttributeError(_) => "AttributeError",
        PyExc::IndexError(_) => "IndexError",
        PyExc::ValueError(_) => "ValueError",
        PyExc::Validation(_) => "ValidationError",
        PyExc::JsonDecode(_) => "JSONDecodeError",
        PyExc::Http(..) => "HTTPException",
        PyExc::Other(class, _) => class,
    };
    (class.to_string(), e.text())
}

fn model(name: &str) -> &'static Model {
    match name {
        "HuntressAuthKeys" => &schema::HUNTRESS_KEYS,
        "DuoAuthKeys" => &schema::DUO_KEYS,
        "DarktraceAuthKeys" => &schema::DARKTRACE_KEYS,
        "MimecastAuthKeys" => &schema::MIMECAST_KEYS,
        "CarbonBlackAuthKeys" => &schema::CARBONBLACK_KEYS,
        "SapSiemAuthKeys" => &schema::SAP_KEYS,
        "CustomerDetails" => &schema::CUSTOMER_DETAILS,
        "InvokeSapSiemAnalysis" => &schema::SAP_ANALYSIS,
        "CollectDuo" => &schema::COLLECT_DUO,
        "CollectCato" => &schema::COLLECT_CATO,
        "CollectCarbonBlack" => &schema::COLLECT_CARBONBLACK,
        "CollectDarktrace" => &schema::COLLECT_DARKTRACE,
        "CollectMimecast" => &schema::COLLECT_MIMECAST,
        "DataItem" => &schema::DATA_ITEM,
        other => panic!("no model {other}"),
    }
}

fn check(name: &str, case: &PyValue, got: Result<PyValue, PyExc>) {
    let input = case.get("input").unwrap().py_repr();
    match (got, python_error(case)) {
        (Ok(mut dump), None) => {
            if let PyValue::Dict(items) = &mut dump {
                items.retain(|(k, _)| k != "headers");
            }
            assert_eq!(pydantic_json(&dump), text(case, "json"), "{name} {input}");
        }
        (Err(e), Some(want)) => assert_eq!(rust_error(&e), want, "{name} {input}"),
        (got, want) => panic!("{name} {input}: {got:?} vs {want:?}"),
    }
}

#[test]
fn models_validate_like_pydantic() {
    let doc = doc();
    let cases = list(&doc, "models");
    assert!(cases.len() >= 50);
    for case in cases {
        let name = text(case, "model");
        let input = case.get("input").unwrap();
        let got = if name == "CatoAuthKeys" {
            cato_keys(input)
        } else {
            construct(model(&name), input)
        };
        check(&name, case, got);
    }
}

#[test]
fn bounded_requests_validate_like_pydantic() {
    let doc = doc();
    let now = now(&doc);
    let cases = list(&doc, "bounded");
    assert!(cases.len() >= 35);
    for case in cases {
        let name = text(case, "model");
        let input = case.get("input").unwrap();
        let got = match name.as_str() {
            "InvokeSapSiemRequest" => construct_bounded(&schema::INVOKE_SAP, input, now),
            "MimecastRequest" => validate_with_pattern(&schema::MIMECAST_REQUEST, input, false)
                .map_err(|errors| {
                    PyExc::Validation(format_validation_error("MimecastRequest", &errors))
                }),
            "MimecastTTPURLSRequest" => {
                construct_bounded(&schema::MIMECAST_TTP_REQUEST, input, now).and_then(|dump| {
                    // `__init__`: `generate_headers` decodes the secret key.
                    let secret = dump.get("SecretKey").and_then(PyValue::as_str);
                    b64decode(secret.unwrap_or_default()).map(|_| dump)
                })
            }
            other => panic!("no request {other}"),
        };
        check(&name, case, got);
    }
}

#[test]
fn b64decode_like_python() {
    let doc = doc();
    for case in list(&doc, "b64decode") {
        let input = text(case, "input");
        match (b64decode(&input), python_error(case)) {
            (Ok(bytes), None) => {
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(hex, text(case, "hex"), "{input:?}");
            }
            (Err(e), Some(want)) => assert_eq!(rust_error(&e), want, "{input:?}"),
            (got, want) => panic!("{input:?}: {got:?} vs {want:?}"),
        }
    }
}

#[test]
fn http_urls_like_pydantic() {
    let doc = doc();
    for case in list(&doc, "http_urls") {
        let input = text(case, "input");
        let want = case.get("ok") == Some(&PyValue::Bool(true));
        assert_eq!(is_http_url(&input), want, "{input:?}");
    }
}
