#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `yaml_vectors.json`: every case as PyYAML 6.0.3 loads it.

use serde_json::{Value as J, json};
use sha2::{Digest, Sha256};

use crate::{LoadError, Value, safe_load};

fn tagged(v: &Value) -> J {
    match v {
        Value::None => json!({"t": "none"}),
        Value::Bool(b) => json!({"t": "bool", "v": b}),
        Value::Int(i) => json!({"t": "int", "v": i.to_string()}),
        Value::Float(f) => json!({"t": "float", "v": crate::float_repr(*f)}),
        Value::Str(s) => json!({"t": "str", "v": s}),
        Value::Bytes(b) => json!({"t": "bytes", "v": hex::encode(b)}),
        Value::Date(d) => json!({"t": "date", "v": [d.year, d.month, d.day]}),
        Value::DateTime(d) => json!({
            "t": "datetime",
            "v": [d.date.year, d.date.month, d.date.day, d.hour, d.minute, d.second, d.microsecond],
            "offset": d.offset,
        }),
        Value::List(items) => {
            json!({"t": "list", "v": items.iter().map(tagged).collect::<Vec<_>>()})
        }
        Value::Tuple(items) => {
            json!({"t": "tuple", "v": items.iter().map(tagged).collect::<Vec<_>>()})
        }
        Value::Set(items) => {
            let mut v: Vec<J> = items.iter().map(tagged).collect();
            v.sort_by_key(sorted_json);
            json!({"t": "set", "v": v})
        }
        Value::Dict(items) => json!({
            "t": "dict",
            "v": items.iter().map(|(k, v)| json!([tagged(k), tagged(v)])).collect::<Vec<_>>(),
        }),
        Value::Recursive(_) => json!({"t": "rec"}),
    }
}

/// `json.dumps(e, sort_keys=True)`'s order, enough to sort set members.
fn sorted_json(v: &J) -> String {
    match v {
        J::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{:?}: {}", k, sorted_json(&m[*k])))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        J::Array(a) => format!(
            "[{}]",
            a.iter().map(sorted_json).collect::<Vec<_>>().join(", ")
        ),
        other => other.to_string(),
    }
}

fn apply_edit(text: &str, edit: &J) -> String {
    let pos = edit[0].as_u64().unwrap() as usize;
    let deleted = edit[1].as_u64().unwrap() as usize;
    let inserted = edit[2].as_str().unwrap();
    let chars: Vec<char> = text.chars().collect();
    let mut out: String = chars[..pos].iter().collect();
    out.push_str(inserted);
    out.extend(chars[pos + deleted..].iter());
    out
}

#[test]
fn every_vector_loads_as_pyyaml_loads_it() {
    let doc: J = serde_json::from_str(include_str!("yaml_vectors.json")).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    let mut inputs: std::collections::HashMap<String, String> = Default::default();
    let mut failures: Vec<String> = Vec::new();
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let input = match case.get("input") {
            Some(i) => i.as_str().unwrap().to_string(),
            None => {
                let d = &case["derive"];
                apply_edit(&inputs[d["from"].as_str().unwrap()], &d["edit"])
            }
        };
        inputs.insert(label.to_string(), input.clone());
        let got = safe_load(&input);
        let mut fail = |what: String| failures.push(format!("{label}: {what}"));
        if let Some(want) = case.get("yaml_error") {
            match &got {
                Err(LoadError::Yaml(e)) => {
                    if e.class() != want["class"] {
                        fail(format!("class {} != {}", e.class(), want["class"]));
                    }
                    if e.to_string() != want["str"].as_str().unwrap() {
                        fail(format!("str\n{}\n!=\n{}", e, want["str"].as_str().unwrap()));
                    }
                    if let Some(p) = want["problem"].as_str() {
                        if e.problem_text() != p {
                            fail(format!("problem {:?} != {p:?}", e.problem_text()));
                        }
                    }
                    let line = want["problem_line"].as_u64().map(|l| l as usize);
                    if e.problem_line() != line {
                        fail(format!("line {:?} != {line:?}", e.problem_line()));
                    }
                }
                other => fail(format!("expected {}, got {other:?}", want["str"])),
            }
            continue;
        }
        if let Some(want) = case.get("exception") {
            match &got {
                Err(LoadError::Python(e)) => {
                    if e.class != want["class"] || e.message != want["str"].as_str().unwrap() {
                        fail(format!("{e:?} != {want}"));
                    }
                }
                other => fail(format!("expected {want}, got {other:?}")),
            }
            continue;
        }
        let value = match got {
            Ok(v) => v,
            Err(e) => {
                fail(format!("unexpected error {e}"));
                continue;
            }
        };
        if let Some(want) = case.get("value") {
            let have = tagged(&value);
            if &have != want {
                fail(format!("value\n{have}\n!=\n{want}"));
            }
        }
        if let Some(want) = case.get("repr").and_then(J::as_str) {
            let have = value.py_repr();
            if have != want {
                fail(format!("repr {have} != {want}"));
            }
        }
        let json = value.to_pydantic_json();
        if let Some(want) = case.get("json").and_then(J::as_str) {
            match &json {
                Ok(j) if j == want => {}
                other => fail(format!("json {other:?} != {want}")),
            }
        }
        if let Some(want) = case.get("json_sha256").and_then(J::as_str) {
            match &json {
                Ok(j) if hex::encode(Sha256::digest(j.as_bytes())) == want => {}
                other => fail(format!("json digest of {other:?} != {want}")),
            }
        }
        if let Some(want) = case.get("json_error") {
            match &json {
                Err(e) if e.0 == want["str"].as_str().unwrap() => {}
                other => fail(format!("json {other:?} != error {want}")),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
