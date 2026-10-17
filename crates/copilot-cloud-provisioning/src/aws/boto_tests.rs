//! `aws_vectors.json` (`scripts/gen-remaining-provisioning-vectors.py`):
//! botocore 1.43's requests and readings, one scripted call each, and the
//! AWS validation end to end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use chrono::{NaiveDate, NaiveDateTime};
use serde_json::{Map, Value, json};

use super::*;

/// The vectors.
pub(crate) fn doc() -> Value {
    serde_json::from_str(include_str!("../aws_vectors.json")).unwrap()
}

fn fixed_now() -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 10, 17)
        .unwrap()
        .and_hms_opt(12, 0, 0)
        .unwrap()
}

fn fixed_id() -> String {
    "00000000-0000-4000-8000-000000000000".into()
}

/// The hooks the generator froze.
pub(crate) fn hooks() -> Hooks {
    Hooks {
        now: fixed_now,
        invocation_id: fixed_id,
        sleep: false,
    }
}

/// A script replaying the answers Python's calls were given.
pub(crate) fn script(answers: &Value) -> Arc<Mutex<Script>> {
    let mut queue = VecDeque::new();
    for a in answers.as_array().unwrap() {
        let answer = match a.get("raise").and_then(Value::as_str) {
            Some("EndpointConnectionError") => Err(TransportError::Connect),
            Some("ConnectTimeoutError") => Err(TransportError::ConnectTimeout),
            Some("ReadTimeoutError") => Err(TransportError::ReadTimeout),
            Some(other) => panic!("unknown exception {other}"),
            None => Ok(WireAnswer {
                status: u16::try_from(a["status"].as_u64().unwrap()).unwrap(),
                headers: a["headers"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str().unwrap().to_string()))
                    .collect(),
                body: a["body"].as_str().unwrap().as_bytes().to_vec(),
            }),
        };
        queue.push_back(answer);
    }
    Arc::new(Mutex::new(Script {
        answers: queue,
        seen: Vec::new(),
    }))
}

/// The requests sent compared with Python's (every header but `Host`,
/// `Accept-Encoding` and the user agent, which botocore adds below
/// `before-send`).
pub(crate) fn assert_requests(name: &str, seen: &[WireRequest], want: &Value) {
    let want = want.as_array().unwrap();
    assert_eq!(
        seen.len(),
        want.len(),
        "{name}: {seen:#?} where Python sent {want:#?}"
    );
    for (got, w) in seen.iter().zip(want) {
        assert_eq!(got.method, w["method"].as_str().unwrap(), "{name}");
        assert_eq!(got.url, w["url"].as_str().unwrap(), "{name}");
        assert_eq!(
            String::from_utf8_lossy(&got.body),
            w["body"].as_str().unwrap(),
            "{name}"
        );
        let headers: Vec<(String, String)> = got
            .headers
            .iter()
            .filter(|(k, _)| !matches!(k.as_str(), "Host" | "Accept-Encoding" | "User-Agent"))
            .cloned()
            .collect();
        let expected: Vec<(String, String)> = w["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                (
                    title_case(h[0].as_str().unwrap()),
                    h[1].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(headers, expected, "{name}: {}", got.url);
        assert_eq!(got.headers[0].0, "Host");
        assert_eq!(
            got.headers[1],
            ("Accept-Encoding".into(), "identity".into())
        );
        assert!(got.headers.iter().any(|(k, _)| k == "User-Agent"));
    }
}

fn node_json(n: &Node) -> Value {
    match n {
        Node::Text(Some(t)) => Value::String(t.clone()),
        Node::Text(None) => Value::Null,
        Node::Dict(items) => Value::Object(
            items
                .iter()
                .map(|(k, v)| (k.clone(), node_json(v)))
                .collect::<Map<_, _>>(),
        ),
    }
}

fn headers_json(h: &[(String, String)]) -> Value {
    Value::Object(
        h.iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect(),
    )
}

/// `(type(e).__name__, str(e))` of an exception the call ends in.
pub(crate) fn exception(e: &BotoError) -> (String, String) {
    match e {
        BotoError::Network(c, t) | BotoError::Core(c, t) => ((*c).to_string(), t.clone()),
        BotoError::Parser(t) => ("ResponseParserError".into(), t.clone()),
        BotoError::Value(t) => ("ValueError".into(), t.clone()),
        BotoError::Key(t) => ("KeyError".into(), t.clone()),
        BotoError::Attribute(t) => ("AttributeError".into(), t.clone()),
        BotoError::Client(_) => ("ClientError".into(), String::new()),
    }
}

fn operation(v: &Value) -> Operation {
    let p = &v["params"];
    let text = |k: &str| p[k].as_str().map(str::to_string);
    match v["op"].as_str().unwrap() {
        "get_caller_identity" => Operation::GetCallerIdentity,
        "head_bucket" => Operation::HeadBucket {
            bucket: text("Bucket").unwrap(),
        },
        "list_objects_v2" => Operation::ListObjectsV2 {
            bucket: text("Bucket").unwrap(),
            prefix: text("Prefix").unwrap(),
            delimiter: text("Delimiter"),
            max_keys: p["MaxKeys"].as_i64(),
        },
        "get_object" => Operation::GetObject {
            bucket: text("Bucket").unwrap(),
            key: text("Key").unwrap(),
            range: text("Range").unwrap(),
        },
        other => panic!("{other}"),
    }
}

fn check_ok(name: &str, got: &Output, want: &Value) {
    let ok = &want["ok"];
    match got {
        Output::Identity { account } => {
            assert_eq!(account.as_deref(), ok["Account"].as_str(), "{name}");
        }
        Output::Head { headers } => assert_eq!(&headers_json(headers), &want["headers"], "{name}"),
        Output::Object => {}
        Output::List(list) => {
            let contents: Option<Vec<Value>> = list.contents.as_ref().map(|c| {
                c.iter()
                    .map(|o| {
                        let mut m = Map::new();
                        if let Some(k) = &o.key {
                            m.insert("Key".into(), json!(k));
                        }
                        if let Some(s) = o.size {
                            m.insert("Size".into(), json!(s));
                        }
                        if let Some(s) = &o.storage_class {
                            m.insert("StorageClass".into(), json!(s));
                        }
                        Value::Object(m)
                    })
                    .collect()
            });
            let want_contents: Option<Vec<Value>> = ok.get("Contents").map(|c| {
                c.as_array()
                    .unwrap()
                    .iter()
                    .map(|o| {
                        let mut m = Map::new();
                        for k in ["Key", "Size", "StorageClass"] {
                            if let Some(v) = o.get(k) {
                                m.insert(k.into(), v.clone());
                            }
                        }
                        Value::Object(m)
                    })
                    .collect()
            });
            assert_eq!(contents, want_contents, "{name}");
            let prefixes: Option<Vec<Value>> = list.common_prefixes.as_ref().map(|p| {
                p.iter()
                    .map(|p| match p {
                        Some(p) => json!({ "Prefix": p }),
                        None => json!({}),
                    })
                    .collect()
            });
            let want_prefixes = ok
                .get("CommonPrefixes")
                .map(|p| p.as_array().unwrap().clone());
            assert_eq!(prefixes, want_prefixes, "{name}");
        }
    }
}

#[test]
fn every_call_is_botocore_s() {
    let d = doc();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for v in d["calls"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let service = match v["service"].as_str().unwrap() {
            "sts" => Service::Sts,
            _ => Service::S3,
        };
        let s = script(&v["answers"]);
        let client = Client::new(
            service,
            v["region"].as_str().unwrap(),
            ("AKIAEXAMPLE000000000", "secret/key+x"),
            v["endpoint"].as_str().map(str::to_string),
            Transport::Script(s.clone()),
            hooks(),
        )
        .unwrap();
        let op = operation(v);
        let outcome = rt.block_on(client.call(&op));
        let seen = s.lock().unwrap().seen.clone();
        assert_requests(name, &seen, &v["requests"]);
        let want = &v["result"];
        match (&outcome, want) {
            (Ok(out), w) if w.get("ok").is_some() => check_ok(name, out, w),
            (Err(BotoError::Client(ce)), w) if w.get("client_error").is_some() => {
                let ce_want = &w["client_error"];
                assert_eq!(
                    ce.error.as_ref().map(node_json).unwrap_or(json!({})),
                    ce_want["error"],
                    "{name}"
                );
                assert_eq!(headers_json(&ce.headers), ce_want["headers"], "{name}");
            }
            (Err(e), w) if w.get("exception").is_some() => {
                let (class, text) = exception(e);
                assert_eq!(class, w["exception"][0].as_str().unwrap(), "{name}");
                assert_eq!(text, w["exception"][1].as_str().unwrap(), "{name}");
            }
            (got, w) => panic!("{name}: {got:?} where Python gives {w}"),
        }
    }
}
