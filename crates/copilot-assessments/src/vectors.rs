//! `assessments_vectors.json` (`scripts/gen-assessments-vectors.py`): the
//! Python modules' behaviour recorded, replayed against the ports.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_upstream::http::urlencode;
use copilot_upstream::model::construct_star;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::from_json;
use copilot_web::validate::{LocPart, Validator, body_loc};
use serde_json::Value;

use crate::github::audit::{Audit, Fetch, Scope, Transport, py_round1};
use crate::github::schema::{
    AuditRequest, BaselineCreate, ConfigCreate, ConfigUpdate, ConfigValue, ExclusionCreate,
    ExclusionUpdate, ExclusionValue, wall_clock,
};
use crate::github::services::expected_checks;

fn vectors() -> Value {
    serde_json::from_str(include_str!("assessments_vectors.json")).expect("vectors parse")
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

#[test]
fn scores_round_like_python() {
    let doc = vectors();
    let mut failures = Vec::new();
    for pair in doc["round"].as_array().expect("round") {
        let (x, want) = (
            pair[0].as_f64().expect("x"),
            pair[1].as_f64().expect("want"),
        );
        if py_round1(x) != want {
            failures.push(format!("round({x}, 1): want {want}, got {}", py_round1(x)));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// --- request bodies -----------------------------------------------------------------------

fn text(s: &str) -> PyValue {
    PyValue::Str(s.to_string())
}

fn opt(s: Option<&String>) -> PyValue {
    s.map_or(PyValue::None, |s| text(s))
}

fn time(t: Option<chrono::NaiveDateTime>) -> PyValue {
    t.map_or(PyValue::None, |t| {
        text(&t.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
    })
}

fn list(items: Option<&Vec<String>>) -> PyValue {
    items.map_or(PyValue::None, |i| {
        PyValue::List(i.iter().map(|s| text(s)).collect())
    })
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Python's dump with its datetimes as the wall clock stored.
fn normalise(dump: PyValue) -> PyValue {
    const TIMES: &[&str] = &["token_expires_at", "expires_at"];
    let PyValue::Dict(items) = dump else {
        return dump;
    };
    PyValue::Dict(
        items
            .into_iter()
            .map(|(k, v)| match (TIMES.contains(&k.as_str()), &v) {
                (true, PyValue::Str(s)) => {
                    let t = wall_clock(s);
                    (k, time(t))
                }
                _ => (k, v),
            })
            .collect(),
    )
}

fn read(model: &str, v: &mut Validator, obj: &serde_json::Map<String, Value>) -> PyValue {
    let at = body_loc();
    match model {
        "ConfigCreate" => {
            let c = ConfigCreate::read(v, obj, &at);
            dict(vec![
                ("customer_code", text(&c.customer_code)),
                ("github_token", text(&c.github_token)),
                ("organization", text(&c.organization)),
                ("token_type", text(&c.token_type)),
                ("token_expires_at", time(c.token_expires_at)),
                ("enabled", PyValue::Bool(c.enabled)),
                ("auto_audit_enabled", PyValue::Bool(c.auto_audit_enabled)),
                ("audit_schedule_cron", opt(c.audit_schedule_cron.as_ref())),
                ("include_repos", PyValue::Bool(c.include_repos)),
                ("include_workflows", PyValue::Bool(c.include_workflows)),
                ("include_members", PyValue::Bool(c.include_members)),
                (
                    "include_archived_repos",
                    PyValue::Bool(c.include_archived_repos),
                ),
                ("repo_filter_mode", text(&c.repo_filter_mode)),
                ("repo_filter_list", list(c.repo_filter_list.as_ref())),
                ("notify_on_critical", PyValue::Bool(c.notify_on_critical)),
                ("notify_on_high", PyValue::Bool(c.notify_on_high)),
                (
                    "notification_webhook_url",
                    opt(c.notification_webhook_url.as_ref()),
                ),
                ("notification_email", opt(c.notification_email.as_ref())),
                (
                    "minimum_passing_score",
                    PyValue::Float(c.minimum_passing_score),
                ),
                ("created_by", opt(c.created_by.as_ref())),
            ])
        }
        "ConfigUpdate" => {
            let u = ConfigUpdate::read(v, obj, &at);
            PyValue::Dict(
                u.set
                    .into_iter()
                    .map(|(k, val)| {
                        let val = match val {
                            ConfigValue::Text(s) => text(&s),
                            ConfigValue::Flag(b) => PyValue::Bool(b),
                            ConfigValue::Time(t) => time(Some(t)),
                            ConfigValue::List(items) => list(Some(&items)),
                            ConfigValue::Number(f) => PyValue::Float(f),
                        };
                        (k.to_string(), val)
                    })
                    .collect(),
            )
        }
        "ExclusionCreate" => {
            let e = ExclusionCreate::read(v, obj, &at);
            dict(vec![
                ("check_id", text(&e.check_id)),
                ("resource_name", opt(e.resource_name.as_ref())),
                ("resource_type", opt(e.resource_type.as_ref())),
                ("reason", text(&e.reason)),
                ("approved_by", opt(e.approved_by.as_ref())),
                ("expires_at", time(e.expires_at)),
                ("created_by", text(&e.created_by)),
            ])
        }
        "ExclusionUpdate" => {
            let u = ExclusionUpdate::read(v, obj, &at);
            PyValue::Dict(
                u.set
                    .into_iter()
                    .map(|(k, val)| {
                        let val = match val {
                            ExclusionValue::Text(s) => text(&s),
                            ExclusionValue::Flag(b) => PyValue::Bool(b),
                            ExclusionValue::Time(t) => time(Some(t)),
                        };
                        (k.to_string(), val)
                    })
                    .collect(),
            )
        }
        "BaselineCreate" => {
            let b = BaselineCreate::read(v, obj, &at);
            dict(vec![
                ("name", text(&b.name)),
                ("description", opt(b.description.as_ref())),
                (
                    "expected_checks",
                    b.expected_checks.clone().unwrap_or(PyValue::None),
                ),
                (
                    "baseline_report_id",
                    b.baseline_report_id.map_or(PyValue::None, PyValue::Int),
                ),
                ("is_active", PyValue::Bool(b.is_active)),
                ("created_by", text(&b.created_by)),
            ])
        }
        "AuditRequest" => {
            let r = AuditRequest::read(v, obj, &at);
            dict(vec![
                ("organization", text(&r.organization)),
                ("include_repos", PyValue::Bool(r.include_repos)),
                ("include_workflows", PyValue::Bool(r.include_workflows)),
                ("include_members", PyValue::Bool(r.include_members)),
                ("repo_filter", list(r.repo_filter.as_ref())),
            ])
        }
        "NucleiScan" => {
            let host = copilot_uba::params::b_req_str(
                v,
                obj,
                &at,
                "host",
                copilot_uba::params::StrSpec::ANY,
            );
            dict(vec![("host", host)])
        }
        other => panic!("unknown model {other}"),
    }
}

#[test]
fn request_bodies_validate_like_pydantic() {
    let doc = vectors();
    let mut failures = Vec::new();
    for case in doc["requests"].as_array().expect("requests") {
        let model = case["model"].as_str().expect("model");
        let body: Value = serde_json::from_str(case["body"].as_str().expect("body")).expect("json");
        let mut v = Validator::new();
        let obj = body.as_object().expect("object body");
        let got = read(model, &mut v, obj);
        let label = format!("{model} {}", case["body"]);
        if let Some(want) = case.get("err") {
            let want: Vec<(String, Vec<String>, String)> = want
                .as_array()
                .expect("errors")
                .iter()
                .map(|e| {
                    (
                        e[0].as_str().expect("type").to_string(),
                        std::iter::once("body".to_string())
                            .chain(e[1].as_array().expect("loc").iter().map(|p| match p {
                                Value::String(s) => s.clone(),
                                other => other.to_string(),
                            }))
                            .collect(),
                        e[2].as_str().expect("msg").to_string(),
                    )
                })
                .collect();
            let got_errors: Vec<(String, Vec<String>, String)> = v
                .errors()
                .iter()
                .map(|e| {
                    (
                        e.kind.clone(),
                        e.loc
                            .iter()
                            .map(|p| match p {
                                LocPart::Key(k) => k.clone(),
                                LocPart::Index(i) => i.to_string(),
                            })
                            .collect(),
                        e.msg.clone(),
                    )
                })
                .collect();
            if got_errors != want {
                failures.push(format!("{label}\n  want {want:?}\n  got  {got_errors:?}"));
            }
        } else {
            let want = normalise(from_json(&case["ok"]));
            if v.has_errors() || got != want {
                failures.push(format!(
                    "{label}\n  want {want:?}\n  got  {got:?} {:?}",
                    v.errors()
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// --- the audit ----------------------------------------------------------------------------

struct Scripted {
    answers: HashMap<String, (u16, Option<String>)>,
    log: Mutex<Vec<String>>,
}

impl Transport for Scripted {
    fn get(
        &self,
        endpoint: String,
        params: Vec<(String, String)>,
    ) -> Pin<Box<dyn Future<Output = Fetch> + Send + '_>> {
        let key = if params.is_empty() {
            endpoint
        } else {
            format!("{endpoint}?{}", urlencode(&params))
        };
        if let Ok(mut log) = self.log.lock() {
            log.push(format!("GET {key}"));
        }
        let (status, body) = self.answers.get(&key).cloned().unwrap_or((404, None));
        let out = match status {
            200 => match body.as_deref().map(loads) {
                Some(Ok(v)) => (Some(v), 200),
                _ => (None, 500),
            },
            other => (None, other),
        };
        Box::pin(async move { out })
    }
}

fn mask_timestamp(mut dump: PyValue) -> PyValue {
    if let PyValue::Dict(items) = &mut dump {
        for (k, v) in items.iter_mut() {
            if k == "summary" {
                if let PyValue::Dict(summary) = v {
                    for (sk, sv) in summary.iter_mut() {
                        if sk == "audit_timestamp" {
                            *sv = PyValue::Str("<now>".into());
                        }
                    }
                }
            }
        }
    }
    dump
}

#[test]
fn audits_run_like_the_python_service() {
    let doc = vectors();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let mut failures = Vec::new();
    for case in doc["audits"].as_array().expect("audits") {
        let name = case["name"].as_str().expect("name");
        let answers = case["answers"]
            .as_object()
            .expect("answers")
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    (
                        v[0].as_u64().expect("status") as u16,
                        v[1].as_str().map(str::to_string),
                    ),
                )
            })
            .collect();
        let t = Scripted {
            answers,
            log: Mutex::new(Vec::new()),
        };
        let s = &case["scope"];
        let scope = Scope {
            organization: case["organization"].as_str().expect("org").to_string(),
            include_repos: s["include_repos"].as_bool().expect("repos"),
            include_workflows: s["include_workflows"].as_bool().expect("workflows"),
            include_members: s["include_members"].as_bool().expect("members"),
            repo_filter: s["repo_filter"].as_array().map(|a| {
                a.iter()
                    .map(|x| x.as_str().expect("name").to_string())
                    .collect()
            }),
        };
        let response = rt.block_on(Audit::new(&t, &scope.organization).run(&scope));
        let got = mask_timestamp(response.dump());
        let want = loads(case["response"].as_str().expect("response")).expect("loads");
        if got != want {
            failures.push(format!(
                "{name}\n  want {}\n  got  {}",
                want.py_repr(),
                got.py_repr()
            ));
        }
        let want_log: Vec<String> = case["requests"]
            .as_array()
            .expect("requests")
            .iter()
            .map(|r| r.as_str().expect("request").to_string())
            .collect();
        let got_log = t.log.lock().map(|l| l.clone()).unwrap_or_default();
        if got_log != want_log {
            failures.push(format!(
                "{name}: requests\n  want {want_log:?}\n  got  {got_log:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn baselines_extract_like_create_baseline() {
    let doc = vectors();
    let mut failures = Vec::new();
    for case in doc["baselines"].as_array().expect("baselines") {
        let report = loads(case["full_report"].as_str().expect("report")).expect("loads");
        let got = expected_checks(&report);
        match (case.get("ok"), got) {
            (Some(want), Ok(got)) => {
                let want = loads(want.as_str().expect("ok")).expect("loads");
                if want != got {
                    failures.push(format!("{report:?}: want {want:?}, got {got:?}"));
                }
            }
            (None, Err(e)) => {
                let want = &case["err"];
                if want["class"] != class(&e) || want["text"] != e.text().as_str() {
                    failures.push(format!("{report:?}: want {want}, got {e:?}"));
                }
            }
            (want, got) => failures.push(format!("{report:?}: want {want:?}, got {got:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn params_replace_the_query_as_httpx_does() {
    let doc = vectors();
    for case in doc["urls"].as_array().expect("urls") {
        let params: Vec<(String, String)> = case["params"]
            .as_array()
            .expect("params")
            .iter()
            .map(|p| {
                (
                    p[0].as_str().expect("k").to_string(),
                    p[1].as_str().expect("v").to_string(),
                )
            })
            .collect();
        let url = crate::github::client::with_params(case["url"].as_str().expect("url"), &params);
        let sent = copilot_threat_intel::httpx::parse_url(&url)
            .expect("parses")
            .render();
        assert_eq!(sent, case["sent"].as_str().expect("sent"), "{url}");
    }
}

#[test]
fn nuclei_answers_build_their_models() {
    use crate::nuclei::schema::{
        DELETE_RESPONSE, MODULE, REPORT_RESPONSE, REPORTS_RESPONSE, SCAN_RESPONSE,
    };
    let doc = vectors();
    let mut failures = Vec::new();
    for case in doc["nuclei"].as_array().expect("nuclei") {
        let model = match case["model"].as_str().expect("model") {
            "NucleiReportsAvailableResponse" => &REPORTS_RESPONSE,
            "NucleiReportCollectionResponse" => &REPORT_RESPONSE,
            "DeleteNucleiReportResponse" => &DELETE_RESPONSE,
            _ => &SCAN_RESPONSE,
        };
        let answer = loads(case["answer"].as_str().expect("answer")).expect("loads");
        let got = construct_star(model, &format!("{MODULE}.{}", model.name), &answer);
        match (case.get("ok"), got) {
            (Some(want), Ok(got)) => {
                if from_json(want) != got {
                    failures.push(format!("{}: want {want}, got {got:?}", model.name));
                }
            }
            (None, Err(e)) => {
                let want = &case["err"];
                if want["class"] != class(&e) || want["text"] != e.text().as_str() {
                    failures.push(format!("{} {answer:?}: want {want}, got {e:?}", model.name));
                }
            }
            (want, got) => failures.push(format!("{}: want {want:?}, got {got:?}", model.name)),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
