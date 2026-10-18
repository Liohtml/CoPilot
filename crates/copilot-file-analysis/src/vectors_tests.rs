//! The Python module's own outcomes (`file_analysis_vectors.json`,
//! `scripts/gen-file-analysis-vectors.py`) against this port's.

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::model::construct;
use copilot_upstream::py::{PyExc, PyResult};
use serde_json::Value;

use crate::{cape, mimetypes, orchestrator, py, report, reputation, store, verdict};

static VECTORS: &str = include_str!("file_analysis_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

fn input(text: &Value) -> PyValue {
    loads(text.as_str().expect("an input is JSON text")).expect("an input parses")
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

fn text_of(value: &PyValue) -> String {
    String::from_utf8(store::dumps(value)).expect("utf-8")
}

/// The Rust outcome in the vectors' shape.
fn outcome(result: PyResult<PyValue>) -> Value {
    match result {
        Ok(v) => serde_json::json!({ "ok": text_of(&v) }),
        Err(e) => serde_json::json!({ "error": { "class": class(&e), "text": e.text() } }),
    }
}

fn check(what: &str, expected: &Value, got: PyResult<PyValue>) {
    let got = outcome(got);
    assert_eq!(&got, expected, "{what}");
}

fn opt_str(v: &PyValue) -> String {
    match v {
        PyValue::Str(s) => s.clone(),
        // `None` / `""` / anything `_SEVERITY` lacks read alike.
        _ => String::new(),
    }
}

fn opt(v: &PyValue) -> Option<&PyValue> {
    match v {
        PyValue::None => None,
        other => Some(other),
    }
}

#[test]
fn engine_version_is_pythons() {
    assert_eq!(vectors()["engine_version"], store::ENGINE_VERSION);
}

#[test]
fn signature_names() {
    for row in vectors()["signature_names"].as_array().unwrap() {
        let name = input(&row["name"]);
        check(
            &format!("noise {name:?}"),
            &row["noise"],
            verdict::is_noise(&name).map(PyValue::Bool),
        );
        check(
            &format!("low {name:?}"),
            &row["low"],
            verdict::is_low_confidence(&name).map(PyValue::Bool),
        );
    }
}

#[test]
fn sandboxes() {
    for row in vectors()["sandboxes"].as_array().unwrap() {
        let s = input(&row["sandbox"]);
        let what = s.py_repr();
        check(
            &format!("meaningful {what}"),
            &row["meaningful"],
            verdict::meaningful_signatures(&s).map(PyValue::List),
        );
        check(
            &format!("stats {what}"),
            &row["stats"],
            verdict::noise_stats(&s).map(|(t, n, l, m)| {
                py::dict(vec![
                    ("total", py::int(i64::try_from(t).unwrap())),
                    ("noise", py::int(i64::try_from(n).unwrap())),
                    ("low_confidence", py::int(i64::try_from(l).unwrap())),
                    ("meaningful", py::int(m)),
                ])
            }),
        );
        check(
            &format!("evidence {what}"),
            &row["evidence"],
            verdict::dynamic_evidence(&s)
                .map(|v| PyValue::List(v.into_iter().map(py::s).collect())),
        );
        check(
            &format!("verdict {what}"),
            &row["verdict"],
            verdict::dynamic_verdict_from_report(&s).map(py::s),
        );
    }
}

#[test]
fn merge_and_reputation_verdicts() {
    let v = vectors();
    for row in v["merge_verdict"].as_array().unwrap() {
        let (a, b) = (input(&row["a"]), input(&row["b"]));
        let b_str = opt_str(&b);
        let b_opt = (!b_str.is_empty()).then_some(b_str.as_str());
        check(
            &format!("merge {a:?} {b:?}"),
            &row["out"],
            Ok(py::s(verdict::merge_verdict(&opt_str(&a), b_opt))),
        );
    }
    for row in v["verdict_from_reputation"].as_array().unwrap() {
        let rep = input(&row["rep"]);
        check(
            &format!("reputation {}", rep.py_repr()),
            &row["out"],
            verdict::verdict_from_reputation(opt(&rep), 5).map(py::s),
        );
    }
    let statics: Vec<PyValue> = v["statics"].as_array().unwrap().iter().map(input).collect();
    let sandboxes: Vec<PyValue> = v["sandboxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| input(&r["sandbox"]))
        .collect();
    let reps: Vec<PyValue> = v["reputations"]
        .as_array()
        .unwrap()
        .iter()
        .map(input)
        .collect();
    let inspectors: Vec<PyValue> = v["inspectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(input)
        .collect();
    let idx = |row: &Value, i: usize| row[i].as_i64().unwrap();
    for row in v["merge_all"].as_array().unwrap() {
        let (i, j, k) = (idx(row, 0), idx(row, 1), idx(row, 2));
        let (st, s, r) = (
            &statics[i as usize],
            &sandboxes[j as usize],
            &reps[k as usize],
        );
        check(
            &format!("merge_all {st:?} {} {}", s.py_repr(), r.py_repr()),
            &row[3],
            verdict::merge_all(&opt_str(st), opt(s), opt(r), 5).map(py::s),
        );
    }
    for row in v["explain"].as_array().unwrap() {
        let (i, j, k, m) = (idx(row, 0), idx(row, 1), idx(row, 2), idx(row, 3));
        let st = &statics[i as usize];
        let s = (j >= 0).then(|| &sandboxes[j as usize]);
        let (r, ins) = (&reps[k as usize], &inspectors[m as usize]);
        check(
            &format!("explain {i} {j} {k} {m}"),
            &row[4],
            verdict::explain_verdict(&opt_str(st), s.and_then(opt), opt(r), opt(ins)).map(py::s),
        );
    }
}

#[test]
fn summarize() {
    for row in vectors()["summarize"].as_array().unwrap() {
        let report = input(&row["report"]);
        check(
            &format!("summarize {}", text_of(&report)),
            &row["out"],
            cape::summarize(&report),
        );
    }
}

#[test]
fn reputation_parsing() {
    let v = vectors();
    for row in v["parse_report"].as_array().unwrap() {
        let answer = input(&row["answer"]);
        let data = copilot_upstream::py::getitem(&answer, "data")
            .unwrap()
            .clone();
        // `FileReportResponse(data=…)` refusing VirusTotal's answer is part of
        // the outcome.
        let parsed = construct(
            &copilot_threat_intel::schema::REPORT_RESPONSE,
            &py::dict(vec![
                ("data", data),
                ("success", PyValue::Bool(true)),
                ("message", py::s("File report retrieved successfully")),
            ]),
        )
        .and_then(|model| reputation::parse_report(&model, &"f".repeat(64)));
        check(
            &format!("parse_report {}", text_of(&answer)),
            &row["out"],
            parsed,
        );
    }
    for row in v["extract_intel"].as_array().unwrap() {
        let (attrs, behaviour) = (input(&row["attrs"]), input(&row["behaviour"]));
        check(
            &format!("extract_intel {}", text_of(&attrs)),
            &row["out"],
            reputation::extract_intel(&attrs, &behaviour),
        );
    }
}

#[test]
fn projections() {
    let v = vectors();
    for row in v["history_item"].as_array().unwrap() {
        let result = input(&row["result"]);
        check(
            &format!("history_item {}", text_of(&result)),
            &row["out"],
            store::history_item(&result),
        );
    }
    for row in v["should_escalate"].as_array().unwrap() {
        let inspector = input(&row["inspector"]);
        check(
            &format!("should_escalate {}", text_of(&inspector)),
            &row["out"],
            orchestrator::should_escalate(&inspector).map(PyValue::Bool),
        );
    }
    for row in v["report_file_name"].as_array().unwrap() {
        let result = input(&row["result"]);
        check(
            &format!("file_name {}", text_of(&result)),
            &row["out"],
            report::file_name(&result).map(py::s),
        );
    }
}

#[test]
fn report_context_and_html() {
    for row in vectors()["report"].as_array().unwrap() {
        let result = input(&row["result"]);
        let shots: Vec<Vec<u8>> = match &row["screenshots"] {
            Value::Array(items) => items
                .iter()
                .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
                .collect(),
            _ => Vec::new(),
        };
        let what = text_of(&result);
        let context = report::build_context(&result, Some("2026-01-02 03:04:05 UTC"), &shots);
        check(&format!("context {what}"), &row["context"], context.clone());
        if let Some(expected) = row.get("html") {
            let html = report::render(&context.unwrap())
                .map(py::s)
                .map_err(|e| PyExc::Other("TemplateError", e));
            let got = outcome(html);
            if &got != expected {
                let (Some(want), Some(have)) = (expected["ok"].as_str(), got["ok"].as_str()) else {
                    panic!("html {what}: {got} != {expected}");
                };
                let at = want
                    .chars()
                    .zip(have.chars())
                    .position(|(a, b)| a != b)
                    .unwrap_or(want.len().min(have.len()));
                let from = at.saturating_sub(120);
                panic!(
                    "html {what} differs at {at}:\n want …{}\n have …{}",
                    want.chars().skip(from).take(240).collect::<String>(),
                    have.chars().skip(from).take(240).collect::<String>()
                );
            }
        }
    }
}

#[test]
fn builtin_mimetypes() {
    let table = mimetypes::build(&[]);
    for row in vectors()["mimetypes"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let want = row["type"].as_str().map(str::to_string);
        assert_eq!(mimetypes::guess_with(&table, name), want, "{name}");
    }
}
