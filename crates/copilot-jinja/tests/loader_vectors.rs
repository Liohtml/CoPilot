//! Every case of `src/jinja_loader_vectors.json` (generated through Jinja2's
//! own `SandboxedEnvironment` with a loader by
//! `scripts/gen-jinja-loader-vectors.py`) renders identically.

#![allow(clippy::unwrap_used)]

use copilot_jinja::{Autoescape, Data, Directory, Environment};
use serde_json::Value as Json;

fn data(v: &Json) -> Data {
    match v {
        Json::Null => Data::None,
        Json::Bool(b) => Data::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Data::Int(i128::from(i))
            } else if let Some(u) = n.as_u64() {
                Data::Int(i128::from(u))
            } else {
                Data::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Json::String(s) => Data::Str(s.clone()),
        Json::Array(a) => Data::List(a.iter().map(data).collect()),
        Json::Object(o) => {
            if let Some(Json::String(s)) = o.get("$dt") {
                let fmt = if s.contains('.') {
                    "%Y-%m-%dT%H:%M:%S%.f"
                } else {
                    "%Y-%m-%dT%H:%M:%S"
                };
                return Data::DateTime(chrono::NaiveDateTime::parse_from_str(s, fmt).unwrap());
            }
            if let Some(Json::String(s)) = o.get("$date") {
                return Data::Date(chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap());
            }
            if let Some(Json::Array(a)) = o.get("$tuple") {
                return Data::Tuple(a.iter().map(data).collect());
            }
            if let Some(Json::String(s)) = o.get("$markup") {
                return Data::Markup(s.clone());
            }
            Data::Dict(o.iter().map(|(k, v)| (k.clone(), data(v))).collect())
        }
    }
}

fn environment(case: &Json) -> Environment {
    let autoescape = match case["env"]["autoescape"].as_str().unwrap() {
        "off" => Autoescape::Off,
        "on" => Autoescape::On,
        _ => Autoescape::SelectHtml,
    };
    let mut env = Environment::new(autoescape);
    if case["env"]["strict"].as_bool().unwrap() {
        env = env.strict();
    }
    for (i, dir) in case["dirs"].as_array().unwrap().iter().enumerate() {
        env = env.with_directory(Directory {
            path: format!("<dir{i}>"),
            files: dir
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect(),
        });
    }
    env
}

#[test]
fn loads_templates_like_jinja2() {
    let doc: Json = serde_json::from_str(include_str!("../src/jinja_loader_vectors.json")).unwrap();
    let mut failures = Vec::new();
    let cases = doc["cases"].as_array().unwrap();
    for case in cases {
        let env = environment(case);
        let vars: Vec<(String, Data)> = case["vars"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), data(v)))
            .collect();
        let got = match case.get("render") {
            Some(name) => env.render(name.as_str().unwrap(), &vars),
            None => env.render_string(case["string"].as_str().unwrap(), &vars),
        };
        let got = match got {
            Ok(text) => serde_json::json!({"ok": text}),
            Err(e) => serde_json::json!({"error": {"type": e.kind, "message": e.message}}),
        };
        if got != case["outcome"] {
            failures.push(format!(
                "{}\n  want {}\n  got  {}",
                case.get("render").or(case.get("string")).unwrap(),
                case["outcome"],
                got
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
