//! `uba_vectors.json` (`scripts/gen-uba-vectors.py`): the request models,
//! the query and path parameter types, httpx's query encoding, `quote` and
//! (for provisioning) `str.format` / `str.lower`, against the Python
//! libraries.

use copilot_auth::pyvalue::{PyValue, float_repr};
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::respond::from_json;
use copilot_web::validate::{LocPart, Validator, body_loc, loc};
use serde_json::{Map, Value};

use crate::client::{param_texts, path_segment};
use crate::params::{self, NumSpec, StrSpec};
use crate::schema;

fn doc() -> Value {
    serde_json::from_str(include_str!("uba_vectors.json")).expect("vectors")
}

type Reader = fn(&mut Validator, &Map<String, Value>, &copilot_web::validate::Loc) -> PyValue;

fn reader(model: &str) -> Reader {
    match model {
        "feedback" => |v, o, a| schema::Feedback::read(v, o, a).dump,
        "suppression" => schema::suppression,
        "backtest" => schema::backtest,
        "score" => schema::score,
        "merge" => schema::merge,
        "rule_setting" => schema::rule_setting,
        "alert_threshold" => schema::alert_threshold,
        "mode" => {
            |v, o, a| PyValue::Dict(vec![("mode".into(), PyValue::Str(schema::mode(v, o, a)))])
        }
        "provision" => |v, o, a| {
            let r = schema::ProvisionRequest::read(v, o, a);
            PyValue::Dict(vec![
                ("bootstrap_days".into(), PyValue::Int(r.bootstrap_days)),
                (
                    "deploy_wazuh_rules".into(),
                    PyValue::Bool(r.deploy_wazuh_rules),
                ),
            ])
        },
        other => panic!("no reader for {other}"),
    }
}

fn loc_json(l: &[LocPart]) -> Value {
    Value::Array(
        l.iter()
            .skip(1)
            .map(|p| match p {
                LocPart::Key(k) => Value::String(k.clone()),
                LocPart::Index(i) => Value::from(*i),
            })
            .collect(),
    )
}

#[test]
fn request_bodies_validate_like_pydantic() {
    let doc = doc();
    let mut failures = Vec::new();
    for case in doc["bodies"].as_array().expect("bodies") {
        let model = case["model"].as_str().expect("model");
        let input = case["input"].as_object().expect("object");
        let mut v = Validator::new();
        let dump = reader(model)(&mut v, input, &body_loc());
        let got = if v.has_errors() {
            Err(Value::Array(
                v.errors()
                    .iter()
                    .map(|e| serde_json::json!([e.kind, loc_json(&e.loc), e.msg]))
                    .collect(),
            ))
        } else {
            Ok(py_dumps(&dump, Dumps::HTTPX).expect("dumps"))
        };
        let want = match case.get("dump") {
            Some(d) => Ok(d.as_str().expect("dump").to_string()),
            None => Err(case["errors"].clone()),
        };
        if got != want {
            failures.push(format!(
                "{model} {input:?}\n  want {want:?}\n  got  {got:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn query_parameters_validate_like_pydantic() {
    let doc = doc();
    let mut failures = Vec::new();
    for case in doc["queries"].as_array().expect("queries") {
        let ty = case["type"].as_str().expect("type");
        let raw = PyValue::Str(case["input"].as_str().expect("input").to_string());
        let mut v = Validator::new();
        let at = loc("query", "x");
        let got: Option<Value> = match ty {
            "float_ge0" => params::check_float(&mut v, &at, &raw, NumSpec::ge(0.0))
                .map(|f| Value::String(float_repr(f))),
            "int_ge1" => params::check_int(&mut v, &at, &raw, NumSpec::ge(1.0)).map(Value::String),
            "int_1_500" => {
                params::check_int(&mut v, &at, &raw, NumSpec::range(1.0, 500.0)).map(Value::String)
            }
            "int_1_100" => {
                params::check_int(&mut v, &at, &raw, NumSpec::range(1.0, 100.0)).map(Value::String)
            }
            "int" => params::check_int(&mut v, &at, &raw, NumSpec::ANY).map(Value::String),
            "bool" => params::check_bool(&mut v, &at, &raw).map(Value::Bool),
            "str_1_512" => {
                params::check_str(&mut v, &at, &raw, StrSpec::len(1, 512)).map(Value::String)
            }
            "str_2_200" => {
                params::check_str(&mut v, &at, &raw, StrSpec::len(2, 200)).map(Value::String)
            }
            "str_step" => {
                params::check_str(&mut v, &at, &raw, StrSpec::pattern("^(15m|1h|6h|1d)$"))
                    .map(Value::String)
            }
            "str_status" => {
                params::check_str(&mut v, &at, &raw, StrSpec::pattern("^(open|closed)$"))
                    .map(Value::String)
            }
            other => panic!("no type {other}"),
        };
        let got = match got {
            Some(value) => serde_json::json!({"value": value}),
            None => serde_json::json!({"error": v.errors()[0].kind}),
        };
        let want = match case.get("value") {
            Some(value) => serde_json::json!({"value": value}),
            None => serde_json::json!({"error": case["error"]}),
        };
        if got != want {
            failures.push(format!("{ty} {:?}: want {want} got {got}", case["input"]));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn query_strings_and_segments_like_httpx() {
    let doc = doc();
    for case in doc["params"].as_array().expect("params") {
        let pairs: Vec<(String, String)> = case["params"]
            .as_array()
            .expect("pairs")
            .iter()
            .flat_map(|pair| {
                let key = pair[0].as_str().expect("key").to_string();
                param_texts(&from_json(&pair[1]))
                    .into_iter()
                    .map(move |t| (key.clone(), t))
            })
            .collect();
        assert_eq!(
            copilot_upstream::http::urlencode(&pairs),
            case["query"].as_str().expect("query"),
            "{case}"
        );
    }
    for case in doc["segments"].as_array().expect("segments") {
        assert_eq!(
            path_segment(case["input"].as_str().expect("input")),
            case["quoted"].as_str().expect("quoted")
        );
    }
}
