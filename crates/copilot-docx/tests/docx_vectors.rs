//! Every case of `src/docx_vectors.json` (written by docxtpl itself,
//! `scripts/gen-docx-vectors.py`) renders to the same members.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use copilot_docx::{Clock, DocxError};
use copilot_jinja::{Autoescape, Data, Environment};
use serde_json::Value as Json;
use sha2::Digest as _;

const BUNDLED: &[u8] =
    include_bytes!("../../../backend/app/incidents/templates/case_report_jinja_template.docx");

fn data(v: &Json) -> Data {
    match v {
        Json::Null => Data::None,
        Json::Bool(b) => Data::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Data::Int(i128::from(i))
            } else {
                Data::Float(n.as_f64().unwrap())
            }
        }
        Json::String(s) => Data::Str(s.clone()),
        Json::Array(a) => Data::List(a.iter().map(data).collect()),
        Json::Object(o) => {
            if let Some(Json::String(s)) = o.get("$dt") {
                return Data::DateTime(
                    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").unwrap(),
                );
            }
            Data::Dict(o.iter().map(|(k, v)| (k.clone(), data(v))).collect())
        }
    }
}

fn outcome(result: Result<Vec<(String, Vec<u8>)>, DocxError>, want: &Json) -> Json {
    match result {
        Err(DocxError::Value(m)) => {
            serde_json::json!({"error": {"kind": "ValueError", "message": m}})
        }
        Err(DocxError::Recover(m)) => {
            serde_json::json!({"error": {"kind": "Recover", "message": m}})
        }
        Err(DocxError::Internal(m)) => {
            // Only the kind is compared for a bare 500.
            let wanted = want["error"]["message"].clone();
            let _ = m;
            serde_json::json!({"error": {"kind": "Internal", "message": wanted}})
        }
        Ok(members) => {
            let texts: Vec<String> = want["members"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter(|m| m[1].is_string())
                        .map(|m| m[0].as_str().unwrap().to_string())
                        .collect()
                })
                .unwrap_or_default();
            let list: Vec<Json> = members
                .into_iter()
                .map(|(name, bytes)| {
                    if texts.contains(&name) {
                        serde_json::json!([name, String::from_utf8(bytes).unwrap()])
                    } else {
                        serde_json::json!([name, {"sha256": hex::encode(sha2::Sha256::digest(&bytes))}])
                    }
                })
                .collect();
            serde_json::json!({"members": list})
        }
    }
}

#[test]
fn renders_like_docxtpl() {
    let doc: Json = serde_json::from_str(include_str!("../src/docx_vectors.json")).unwrap();
    let clock = Clock {
        local: chrono::NaiveDate::from_ymd_opt(2026, 3, 4)
            .unwrap()
            .and_hms_opt(5, 6, 7)
            .unwrap(),
        utc: chrono::DateTime::parse_from_rfc3339(doc["clock"].as_str().unwrap())
            .unwrap()
            .with_timezone(&chrono::Utc),
    };
    let env = Environment::new(Autoescape::On);
    let mut failures = Vec::new();
    let cases = doc["cases"].as_array().unwrap();
    for (n, case) in cases.iter().enumerate() {
        let name = case["template"].as_str().unwrap();
        let template = if name == "@bundled" {
            BUNDLED.to_vec()
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(doc["templates"][name].as_str().unwrap())
                .unwrap()
        };
        let vars: Vec<(String, Data)> = case["vars"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), data(v)))
            .collect();
        let got = outcome(
            copilot_docx::render_members(&template, "<path>", &env, &vars, clock),
            &case["outcome"],
        );
        if got != case["outcome"] {
            let detail = match (got.get("members"), case["outcome"].get("members")) {
                (Some(g), Some(w)) => {
                    let g = g.as_array().unwrap();
                    let w = w.as_array().unwrap();
                    let mut d = format!("{} vs {} members", g.len(), w.len());
                    for (a, b) in g.iter().zip(w.iter()) {
                        if a != b {
                            d.push_str(&format!("\n    got  {}\n    want {}", a, b));
                            break;
                        }
                    }
                    d
                }
                _ => format!("got {got}\n    want {}", case["outcome"]),
            };
            failures.push(format!("case {n} ({name}): {detail}"));
        }
    }
    // The comparison covers the rendered text itself.
    let main = &cases[3]["outcome"]["members"];
    let body = main
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m[0] == "word/document.xml")
        .unwrap();
    assert!(
        body[1]
            .as_str()
            .unwrap()
            .contains("Case \u{201c}Alpha\u{201d} &amp; co")
    );
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
