//! Every case of `src/jinja_vectors.json` (generated through CoPilot's
//! Python renderer by `scripts/gen-jinja-vectors.py`) renders identically.

#![allow(clippy::unwrap_used)]

use copilot_jinja::{Event, Input, render};
use serde_json::Value as Json;

/// Object addresses (`<function str.format at 0x7f…>`) differ between runs.
fn without_addresses(v: &Json) -> Json {
    let re = regex::Regex::new(r"0x[0-9a-f]+").unwrap();
    match v {
        Json::String(s) => Json::String(re.replace_all(s, "0x…").into_owned()),
        Json::Object(o) => Json::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), without_addresses(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn input(v: &Json) -> Input {
    match v {
        Json::Null => Input::None,
        Json::Bool(b) => Input::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Input::Int(i128::from(i))
            } else if let Some(u) = n.as_u64() {
                Input::Int(i128::from(u))
            } else {
                Input::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Json::String(s) => Input::Str(s.clone()),
        Json::Array(a) => Input::List(a.iter().map(input).collect()),
        Json::Object(o) => Input::Dict(o.iter().map(|(k, v)| (k.clone(), input(v))).collect()),
    }
}

fn opt(v: &Json) -> Option<String> {
    v.as_str().map(str::to_string)
}

fn event(e: &Json) -> Event {
    Event {
        customer_code: opt(&e["customer_code"]),
        trigger: e["trigger"].as_str().unwrap().to_string(),
        severity: e["severity"].as_str().unwrap().to_string(),
        subject: e["subject"].as_str().unwrap().to_string(),
        summary: e["summary"].as_str().unwrap().to_string(),
        entity_type: e["entity_type"].as_str().unwrap().to_string(),
        entity_id: e["entity_id"].as_i64().unwrap(),
        dedupe_key: e["dedupe_key"].as_str().unwrap().to_string(),
        link_url: opt(&e["link_url"]),
        assignee_username: opt(&e["assignee_username"]),
        actor_username: opt(&e["actor_username"]),
        context: e["context"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), input(v)))
            .collect(),
    }
}

#[test]
fn renders_like_jinja2() {
    let doc: Json = serde_json::from_str(include_str!("../src/jinja_vectors.json")).unwrap();
    let mut failures = Vec::new();
    let cases = doc["cases"].as_array().unwrap();
    for case in cases {
        let ctx = &doc["contexts"][case["ctx"].as_str().unwrap()];
        let ev = event(&ctx["event"]);
        let extra: Vec<(String, Input)> = ctx["extra"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), input(v)))
            .collect();
        let source = case["source"].as_str().unwrap();
        let autoescape = case["autoescape"].as_bool().unwrap();
        let got = match render(source, &ev, autoescape, &extra) {
            Ok(s) => serde_json::json!({ "ok": s }),
            Err(e) => serde_json::json!({ "error": { "type": e.kind, "message": e.message } }),
        };
        if without_addresses(&got) != without_addresses(&case["outcome"]) {
            failures.push(format!(
                "{} {:?} (autoescape={autoescape}):\n  want {}\n  got  {}",
                case["name"], source, case["outcome"], got
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
