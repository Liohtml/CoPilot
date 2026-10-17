//! `patch_tuesday_vectors.json` (`scripts/gen-patch-tuesday-vectors.py`):
//! the module's functions on odd inputs and whole runs with scripted feeds,
//! recorded from the Python module.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use chrono::NaiveDate;
use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::json::pydantic_json;
use copilot_upstream::py::{PyExc, PyResult};
use pretty_assertions::assert_eq;
use serde_json::Value;

use crate::cvrf::{self, Priority};
use crate::py::{normalize_text, safe_float};
use crate::services::{self, Clock, Fetch};
use crate::urls::Urls;

fn doc() -> Value {
    serde_json::from_str(include_str!("patch_tuesday_vectors.json")).unwrap()
}

fn py(text: &Value) -> PyValue {
    loads(text.as_str().unwrap()).unwrap()
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

/// `{"ok": …}` or `{"error": {"class", "text"}}`.
fn outcome<T>(r: PyResult<T>, ok: impl Fn(T) -> Value) -> Value {
    match r {
        Ok(v) => serde_json::json!({"ok": ok(v)}),
        Err(e) => serde_json::json!({"error": {"class": class(&e), "text": e.text()}}),
    }
}

fn same_float(a: Option<f64>, b: &PyValue) -> bool {
    match (a, b) {
        (None, PyValue::None) => true,
        (Some(x), PyValue::Float(y)) => x == *y || (x.is_nan() && y.is_nan()),
        (Some(x), PyValue::Int(i)) => i.parse::<f64>().ok() == Some(x),
        _ => false,
    }
}

#[test]
fn normalize_text_family_and_floats() {
    let d = doc();
    for case in d["normalize_text"].as_array().unwrap() {
        let got = normalize_text(&py(&case["input"]));
        assert_eq!(
            serde_json::json!({"ok": got}),
            case["output"],
            "{}",
            case["input"]
        );
    }
    for case in d["product_family"].as_array().unwrap() {
        let got = cvrf::product_family(&py(&case["input"]));
        assert_eq!(
            serde_json::json!({"ok": got}),
            case["output"],
            "{}",
            case["input"]
        );
    }
    for case in d["safe_float"].as_array().unwrap() {
        let got = safe_float(&py(&case["input"]));
        assert!(
            same_float(got, &py(&case["output"])),
            "{} → {got:?}",
            case["input"]
        );
    }
}

#[test]
fn document_readers() {
    let d = doc();
    for case in d["extract_cvss"].as_array().unwrap() {
        let got = cvrf::extract_cvss(&py(&case["input"]));
        match (&got, case["output"].get("ok")) {
            (Ok((score, vector)), Some(want)) => {
                let want = py(want);
                let PyValue::List(parts) = want else { panic!() };
                assert!(same_float(*score, &parts[0]), "{}", case["input"]);
                assert_eq!(vector.clone().map_or(PyValue::None, PyValue::Str), parts[1]);
            }
            _ => assert_eq!(
                outcome(got, |_| Value::Null),
                case["output"],
                "{}",
                case["input"]
            ),
        }
    }
    for case in d["extract_severity"].as_array().unwrap() {
        let got = cvrf::extract_severity(&py(&case["input"]));
        assert_eq!(
            outcome(got, |s| serde_json::json!(s)),
            case["output"],
            "{}",
            case["input"]
        );
    }
    for case in d["extract_kbs"].as_array().unwrap() {
        let got = cvrf::extract_kbs(&py(&case["input"]));
        assert_eq!(
            outcome(got, |s| serde_json::json!(s)),
            case["output"],
            "{}",
            case["input"]
        );
    }
    for case in d["build_product_lookup"].as_array().unwrap() {
        let got = cvrf::build_product_lookup(&py(&case["input"]));
        let want = &case["output"];
        match (got, want.get("ok")) {
            (Ok(map), Some(w)) => {
                let w: HashMap<String, String> = serde_json::from_value(w.clone()).unwrap();
                assert_eq!(map, w, "{}", case["input"]);
            }
            (got, _) => assert_eq!(outcome(got, |_| Value::Null), *want, "{}", case["input"]),
        }
    }
    for case in d["extract_affected_products"].as_array().unwrap() {
        let lookup: HashMap<String, String> =
            serde_json::from_value(case["lookup"].clone()).unwrap();
        let got = cvrf::extract_affected_products(&py(&case["input"]), &lookup);
        assert_eq!(
            outcome(got, |s| serde_json::json!(s)),
            case["output"],
            "{}",
            case["input"]
        );
    }
}

#[test]
fn priorities_and_dates() {
    let d = doc();
    let opt = |v: &Value| match py(v) {
        PyValue::None => None,
        PyValue::Float(f) => Some(f),
        other => panic!("{other:?}"),
    };
    for case in d["calculate_priority"].as_array().unwrap() {
        let got = cvrf::calculate_priority(
            case["severity"].as_str(),
            opt(&case["cvss"]),
            opt(&case["epss"]),
            case["family"].as_str().unwrap(),
            case["in_kev"].as_bool().unwrap(),
        );
        let reasons: Vec<String> = serde_json::from_value(case["reasons"].clone()).unwrap();
        assert_eq!(
            got,
            Priority {
                level: match case["priority"].as_str().unwrap() {
                    "P0" => "P0",
                    "P1" => "P1",
                    "P2" => "P2",
                    _ => "P3",
                },
                reasons,
                sla: got.sla,
            },
            "{case}"
        );
        let sla = &d["slas"][usize::try_from(case["sla"].as_u64().unwrap()).unwrap()];
        assert_eq!(got.sla, sla.as_str().unwrap());
    }
    for case in d["chunk_by_max_chars"].as_array().unwrap() {
        let items: Vec<String> = serde_json::from_value(case["items"].clone()).unwrap();
        let max = usize::try_from(case["max"].as_u64().unwrap()).unwrap();
        let got = cvrf::chunk_by_max_chars(&items, max);
        assert_eq!(serde_json::json!(got), case["chunks"]);
    }
    for case in d["second_tuesday"].as_array().unwrap() {
        let month = u32::try_from(case["month"].as_u64().unwrap()).unwrap();
        let got = services::second_tuesday(case["year"].as_i64().unwrap(), month).unwrap();
        assert_eq!(
            got.format("%Y-%m-%d").to_string(),
            case["date"].as_str().unwrap()
        );
    }
    for case in d["available_cycles"].as_array().unwrap() {
        let today = NaiveDate::parse_from_str(case["today"].as_str().unwrap(), "%Y-%m-%d").unwrap();
        let clock = Fixed(today, String::new());
        let got = pydantic_json(&services::get_available_cycles(&clock));
        assert_eq!(got, case["response"].as_str().unwrap(), "{}", case["today"]);
    }
}

struct Fixed(NaiveDate, String);

impl Clock for Fixed {
    fn today(&self) -> NaiveDate {
        self.0
    }
    fn now_utc(&self) -> String {
        self.1.clone()
    }
}

/// `fetch_json` replaced by the recorded answers, every call recorded.
struct Scripted {
    answers: Mutex<VecDeque<Value>>,
    calls: Mutex<Vec<Value>>,
}

impl Fetch for Scripted {
    async fn fetch_json(
        &self,
        url: &str,
        params: Option<Vec<(String, String)>>,
    ) -> PyResult<PyValue> {
        let params = params
            .map(|p| Value::Object(p.into_iter().map(|(k, v)| (k, Value::String(v))).collect()));
        self.calls
            .lock()
            .unwrap()
            .push(serde_json::json!({"url": url, "params": params}));
        let answer = self.answers.lock().unwrap().pop_front().expect("an answer");
        match answer.get("raise") {
            Some(text) => Err(PyExc::Other("RuntimeError", text.as_str().unwrap().into())),
            None => Ok(py(&answer["value"])),
        }
    }
}

#[tokio::test]
async fn whole_runs_with_scripted_feeds() {
    let d = doc();
    let urls = Urls::default();
    let now = d["now"].as_str().unwrap().replace("+00:00", "Z");
    let now = now.split('.').next().unwrap().to_string() + "Z";
    let clock = Fixed(NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(), now);
    for sc in d["scenarios"].as_array().unwrap() {
        let fetch = Scripted {
            answers: Mutex::new(sc["answers"].as_array().unwrap().iter().cloned().collect()),
            calls: Mutex::new(Vec::new()),
        };
        let cycle = sc["cycle"].as_str();
        let (epss, kev) = (sc["epss"].as_bool().unwrap(), sc["kev"].as_bool().unwrap());
        let dump = match sc["call"].as_str().unwrap() {
            "get" => services::get_patch_tuesday(&fetch, &clock, &urls, cycle, epss, kev)
                .await
                .dump(),
            "summary" => {
                let top = usize::try_from(sc["top_n"].as_u64().unwrap()).unwrap();
                services::get_patch_tuesday_summary(&fetch, &clock, &urls, cycle, epss, kev, top)
                    .await
            }
            _ => {
                let ids: Vec<String> = serde_json::from_value(sc["cve_ids"].clone()).unwrap();
                services::search_cves(&fetch, &clock, &urls, &ids, cycle, sc["product"].as_str())
                    .await
                    .dump()
            }
        };
        let name = sc["name"].as_str().unwrap();
        assert_eq!(
            Value::Array(fetch.calls.into_inner().unwrap()),
            sc["calls"],
            "{name}: calls"
        );
        assert_eq!(
            pydantic_json(&dump),
            sc["response"].as_str().unwrap(),
            "{name}"
        );
    }
}
