//! `tests/test_uba_rollback.py`, ported: Graylog as UBA setup leaves it next
//! to each customer's own Wazuh stream and pipeline, UBA and the ownership
//! records as fakes; the plan, the step order, the checks and the report
//! must come out as Python's do.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use copilot_auth::pyvalue::PyValue;
use copilot_graylog::client::Reply;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_upstream::respond::from_json;
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

use crate::client::{Call, UbaError, UbaResult};
use crate::ops::{GraylogOps, Ops, UbaOps, WazuhOps};
use crate::ownership::{self, Row};
use crate::provision::Step;
use crate::pyops::OrderedMap;
use crate::rollback::{self, Check, Facts};

pub(crate) const GELF_OUTPUT: &str = "org.graylog2.outputs.GelfOutput";
pub(crate) const GELF_TCP: &str = "org.graylog2.inputs.gelf.tcp.GELFTCPInput";

fn rule(feed: &str, selector: &str) -> Value {
    json!({
        "title": format!("{feed} - {selector}"),
        "source": format!(
            "rule \"{feed} - {selector}\"\nwhen true\nthen\n  set_field(\"uba_feed\", \"behavior\");\n  route_to_stream(name: \"{feed}\");\nend"
        ),
    })
}

fn pipeline(id: &str, title: &str, rules: &[String]) -> Value {
    let mut source = format!("pipeline \"{title}\"\nstage 10 match either\n");
    for r in rules {
        source.push_str(&format!("rule \"{r}\"\n"));
    }
    source.push_str("end");
    json!({
        "id": id,
        "title": title,
        "source": source,
        "stages": [{"stage": 10, "match": "EITHER", "rules": rules}],
    })
}

/// Graylog's state (the Python fake's dicts).
#[derive(Debug, Default)]
pub(crate) struct GraylogData {
    pub streams: OrderedMap<Value>,
    pub pipelines: OrderedMap<Value>,
    pub rules: OrderedMap<Value>,
    pub outputs: OrderedMap<Value>,
    pub inputs: OrderedMap<Value>,
    pub connections: OrderedMap<Vec<String>>,
    pub definitions: Vec<Value>,
    pub fail: Vec<(String, String)>,
    /// Someone else's change at the same moment as the disconnection.
    pub disconnect_on_post: Option<String>,
}

pub(crate) type Log = Arc<Mutex<Vec<(String, String)>>>;

pub(crate) struct FakeGraylog {
    pub data: Mutex<GraylogData>,
    pub calls: Log,
}

fn remove_key<V>(map: &mut OrderedMap<V>, key: &str) -> bool
where
    V: Clone,
{
    if !map.contains(key) {
        return false;
    }
    let mut rebuilt = OrderedMap::default();
    for (k, v) in map.iter() {
        if k != key {
            rebuilt.insert(k.clone(), v.clone());
        }
    }
    *map = rebuilt;
    true
}

fn http(status: u16, detail: impl Into<String>) -> PyExc {
    PyExc::Http(status, detail.into())
}

fn reply(data: Value) -> Reply {
    Reply {
        data: from_json(&data),
        success: true,
        message: String::new(),
    }
}

impl FakeGraylog {
    pub fn new(codes: &[&str]) -> Self {
        let mut d = GraylogData {
            definitions: vec![json!({
                "id": "ed1", "title": "WAZUH - HIGH", "state": "ENABLED", "config": {"streams": []}
            })],
            ..GraylogData::default()
        };
        d.inputs.insert(
            "in-uba".into(),
            json!({"id": "in-uba", "title": "UBA ALERTS", "type": GELF_TCP}),
        );
        let fake = Self {
            data: Mutex::new(d),
            calls: Arc::default(),
        };
        for code in codes {
            fake.add_customer(code);
        }
        fake
    }

    pub fn add_customer(&self, code: &str) {
        let mut d = self.data.lock().expect("lock");
        let src = format!("wazuh-{code}");
        d.streams.insert(
            src.clone(),
            json!({"id": src, "title": format!("{} - Wazuh", code.to_uppercase()),
                   "rules": [{"field": "agent_labels_customer"}], "outputs": []}),
        );
        d.pipelines.insert(
            format!("proc-{code}"),
            pipeline(
                &format!("proc-{code}"),
                "WAZUH PROCESSING",
                &["WAZUH ENRICH".to_string()],
            ),
        );
        let feed = format!("UBA FEED - WAZUH - {code}");
        d.streams.insert(
            format!("feed-{code}"),
            json!({"id": format!("feed-{code}"), "title": feed, "rules": [],
                   "outputs": [{"id": format!("out-{code}")}]}),
        );
        let mut titles = Vec::new();
        for (i, selector) in ["WINDOWS AUTH", "PROCESS"].iter().enumerate() {
            let rid = format!("rule-{code}-{i}");
            let mut r = rule(&feed, selector);
            r["id"] = json!(rid);
            titles.push(r["title"].as_str().expect("title").to_string());
            // {"id": rid, **_rule(...)}: the id first.
            let ordered = json!({"id": rid, "title": r["title"], "source": r["source"]});
            d.rules.insert(rid, ordered);
        }
        d.pipelines.insert(
            format!("route-{code}"),
            pipeline(
                &format!("route-{code}"),
                &format!("UBA ROUTING - WAZUH - {code}"),
                &titles,
            ),
        );
        d.connections
            .insert(src, vec![format!("proc-{code}"), format!("route-{code}")]);
        d.outputs.insert(
            format!("out-{code}"),
            json!({"id": format!("out-{code}"), "title": format!("UBA GELF - {code}"),
                   "type": GELF_OUTPUT, "configuration": {"hostname": "127.0.0.1", "port": 12203}}),
        );
        d.streams.insert(
            format!("alerts-{code}"),
            json!({"id": format!("alerts-{code}"), "title": format!("UBA ALERTS - {code}"),
                   "rules": [{"field": "syslog_type", "value": "uba"},
                             {"field": "agent_labels_customer", "value": code}],
                   "outputs": []}),
        );
    }

    fn check(&self, method: &str, endpoint: &str) -> PyResult<()> {
        self.calls
            .lock()
            .expect("lock")
            .push((method.to_string(), endpoint.to_string()));
        let d = self.data.lock().expect("lock");
        if d.fail.iter().any(|(m, e)| m == method && e == endpoint) {
            return Err(http(500, format!("Graylog refused {method} {endpoint}")));
        }
        Ok(())
    }

    pub fn writes(&self) -> Vec<(String, String)> {
        self.calls
            .lock()
            .expect("lock")
            .iter()
            .filter(|(m, _)| m != "GET" && m != "UBA GET")
            .cloned()
            .collect()
    }

    pub fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().expect("lock").clone()
    }
}

fn values(map: &OrderedMap<Value>) -> Value {
    Value::Array(map.values().cloned().collect())
}

#[async_trait]
impl GraylogOps for FakeGraylog {
    async fn get(&self, endpoint: &str, _params: &[(&str, String)]) -> PyResult<Reply> {
        self.check("GET", endpoint)?;
        let d = self.data.lock().expect("lock");
        let listed = match endpoint {
            "/api/streams" => Some(json!({"streams": values(&d.streams)})),
            "/api/system/pipelines/pipeline" => Some(values(&d.pipelines)),
            "/api/system/pipelines/rule" => Some(values(&d.rules)),
            "/api/system/outputs" => Some(json!({"outputs": values(&d.outputs)})),
            "/api/system/inputs" => Some(json!({"inputs": values(&d.inputs)})),
            "/api/system/pipelines/connections" => Some(Value::Array(
                d.connections
                    .iter()
                    .map(|(s, p)| json!({"stream_id": s, "pipeline_ids": p}))
                    .collect(),
            )),
            "/api/events/definitions" => Some(json!({
                "event_definitions": d.definitions, "total": d.definitions.len()
            })),
            _ => None,
        };
        if let Some(data) = listed {
            return Ok(reply(data));
        }
        for (prefix, store) in [
            ("/api/streams/", &d.streams),
            ("/api/system/pipelines/pipeline/", &d.pipelines),
            ("/api/system/pipelines/rule/", &d.rules),
            ("/api/system/outputs/", &d.outputs),
            ("/api/system/inputs/", &d.inputs),
        ] {
            if let Some(key) = endpoint.strip_prefix(prefix) {
                if let Some(obj) = store.get(key) {
                    return Ok(reply(obj.clone()));
                }
            }
        }
        Err(http(
            404,
            format!("Failed to send GET request to {endpoint}"),
        ))
    }

    async fn post(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Reply> {
        self.check("POST", endpoint)?;
        assert_eq!(endpoint, "/api/system/pipelines/connections/to_pipeline");
        let data = data.expect("body");
        let pid = data.get("pipeline_id").expect("pipeline_id").py_str();
        let mut d = self.data.lock().expect("lock");
        let keys: Vec<String> = d.connections.keys().cloned().collect();
        for k in keys {
            if let Some(list) = d.connections.get_mut(&k) {
                list.retain(|p| *p != pid);
            }
        }
        if let Some(PyValue::List(ids)) = data.get("stream_ids") {
            for s in ids {
                let s = s.py_str();
                if !d.connections.contains(&s) {
                    d.connections.insert(s.clone(), Vec::new());
                }
                if let Some(list) = d.connections.get_mut(&s) {
                    list.push(pid.clone());
                }
            }
        }
        if let Some(stream) = d.disconnect_on_post.clone() {
            d.connections.insert(stream, Vec::new());
        }
        Ok(reply(Value::Null))
    }

    async fn put(&self, endpoint: &str, _data: Option<PyValue>) -> PyResult<Option<Reply>> {
        panic!("no PUT expected: {endpoint}");
    }

    async fn delete(&self, endpoint: &str) -> PyResult<Reply> {
        self.check("DELETE", endpoint)?;
        let mut d = self.data.lock().expect("lock");
        let parts: Vec<&str> = endpoint.split('/').collect();
        if endpoint.starts_with("/api/streams/") && endpoint.contains("/outputs/") {
            let Some(stream) = d.streams.get_mut(parts[3]) else {
                return Err(http(404, "not found"));
            };
            if let Some(Value::Array(outs)) = stream.get_mut("outputs") {
                outs.retain(|o| o["id"] != json!(parts[5]));
            }
            return Ok(reply(Value::Null));
        }
        let prefixes = [
            "/api/streams/",
            "/api/system/pipelines/pipeline/",
            "/api/system/pipelines/rule/",
            "/api/system/outputs/",
            "/api/system/inputs/",
        ];
        for prefix in prefixes {
            let Some(key) = endpoint.strip_prefix(prefix) else {
                continue;
            };
            let key = key.to_string();
            let exists = match prefix {
                "/api/streams/" => d.streams.contains(&key),
                "/api/system/pipelines/pipeline/" => d.pipelines.contains(&key),
                "/api/system/pipelines/rule/" => d.rules.contains(&key),
                "/api/system/outputs/" => d.outputs.contains(&key),
                _ => d.inputs.contains(&key),
            };
            if !exists {
                return Err(http(404, "not found"));
            }
            if prefix == "/api/system/pipelines/pipeline/"
                && d.connections.values().any(|p| p.contains(&key))
            {
                return Err(http(404, "pipeline is still connected"));
            }
            match prefix {
                "/api/streams/" => {
                    remove_key(&mut d.streams, &key);
                    remove_key(&mut d.connections, &key);
                }
                "/api/system/pipelines/pipeline/" => {
                    remove_key(&mut d.pipelines, &key);
                }
                "/api/system/pipelines/rule/" => {
                    remove_key(&mut d.rules, &key);
                }
                "/api/system/outputs/" => {
                    remove_key(&mut d.outputs, &key);
                    let ids: Vec<String> = d.streams.keys().cloned().collect();
                    for id in ids {
                        if let Some(Value::Array(outs)) =
                            d.streams.get_mut(&id).and_then(|s| s.get_mut("outputs"))
                        {
                            outs.retain(|o| o["id"] != json!(key));
                        }
                    }
                }
                _ => {
                    remove_key(&mut d.inputs, &key);
                }
            }
            return Ok(reply(Value::Null));
        }
        panic!("{endpoint}");
    }

    async fn create_stream(&self, _entity: PyValue) -> PyResult<Reply> {
        panic!("no stream creation expected");
    }
}

/// UBA (`FakeUba`): its calls go to the shared log as `UBA <method>`.
pub(crate) struct FakeUba {
    pub active: Mutex<Option<bool>>,
    pub down: bool,
    pub calls: Mutex<Vec<(String, String, Option<PyValue>)>>,
    pub log: Option<Log>,
    /// A UBA without modes leaves `mode` out of its answers.
    pub no_modes: bool,
}

impl FakeUba {
    pub fn new(active: Option<bool>) -> Self {
        Self {
            active: Mutex::new(active),
            down: false,
            calls: Mutex::default(),
            log: None,
            no_modes: false,
        }
    }

    pub fn logging(mut self, log: &Log) -> Self {
        self.log = Some(log.clone());
        self
    }

    pub fn down() -> Self {
        let mut uba = Self::new(Some(true));
        uba.down = true;
        uba
    }
}

#[async_trait]
impl UbaOps for FakeUba {
    async fn call(&self, call: Call) -> UbaResult<PyValue> {
        let method = call.method().as_str().to_string();
        let path = call.path().to_string();
        self.calls
            .lock()
            .expect("lock")
            .push((method.clone(), path.clone(), call.body().cloned()));
        if let Some(log) = &self.log {
            log.lock()
                .expect("lock")
                .push((format!("UBA {method}"), path.clone()));
        }
        if self.down {
            return Err(UbaError::Request {
                reason: "unreachable",
                detail: "SOCFortress UBA is unreachable".into(),
                status: 502,
            });
        }
        if path == "/v1/provisioning" {
            let mut names = rollback::default_names();
            if let PyValue::Dict(items) = &mut names {
                items.push(("pipeline_stage".into(), PyValue::Int("10".into())));
            }
            return Ok(PyValue::Dict(vec![("graylog".into(), names)]));
        }
        let active = *self.active.lock().expect("lock");
        if path.ends_with("/onboarding") {
            let Some(active) = active else {
                return Err(UbaError::Request {
                    reason: "not_found",
                    detail: "unknown tenant".into(),
                    status: 404,
                });
            };
            return Ok(from_json(&json!({
                "tenant": "acme", "active": active,
                "status": if active { "live" } else { "inactive" }
            })));
        }
        if method == "PUT" {
            let body = call.body().cloned().unwrap_or(PyValue::None);
            let new_active = match body.get("active") {
                Some(PyValue::Bool(b)) => Some(*b),
                _ => active,
            };
            *self.active.lock().expect("lock") = new_active;
            let mode = body
                .get("mode")
                .cloned()
                .unwrap_or_else(|| PyValue::Str("active".into()));
            let tenant = path.rsplit('/').next().unwrap_or_default().to_string();
            let mut out = vec![
                ("tenant".to_string(), PyValue::Str(tenant)),
                (
                    "active".to_string(),
                    new_active.map_or(PyValue::None, PyValue::Bool),
                ),
            ];
            if !self.no_modes {
                out.push(("mode".to_string(), mode));
            }
            return Ok(PyValue::Dict(out));
        }
        panic!("{path}");
    }
}

pub(crate) struct NoWazuh;

#[async_trait]
impl WazuhOps for NoWazuh {
    async fn upload_rules(&self, filename: &str, _content: Vec<u8>) -> PyResult<()> {
        panic!("no upload expected: {filename}");
    }

    async fn restart(&self) -> PyResult<()> {
        panic!("no restart expected");
    }
}

fn row(
    code: &str,
    kind: &str,
    graylog_id: &str,
    title: &str,
    source: Option<&str>,
    shared: bool,
) -> Row {
    Row {
        id: 0,
        customer_code: code.into(),
        kind: kind.into(),
        graylog_id: graylog_id.into(),
        title: title.into(),
        source: source.map(str::to_string),
        shared,
    }
}

fn sources(code: &str) -> Vec<String> {
    match code {
        "acme" | "globex" => vec![format!("wazuh-{code}")],
        _ => Vec::new(),
    }
}

/// What `roll_back` returns, without the database.
struct Report {
    status: &'static str,
    steps: Vec<Step>,
    verification: Vec<Check>,
    snapshot: Value,
    /// `mark_removed`'s items: (kind, id, origin).
    removed: Vec<(String, String, String)>,
}

fn facts(code: &str, rows: &[Row]) -> Facts {
    Facts {
        source_streams: sources(code),
        recorded: rows
            .iter()
            .filter(|r| r.customer_code == code)
            .cloned()
            .collect(),
        all_active: rows.to_vec(),
    }
}

fn ops<'a>(g: &'a FakeGraylog, u: &'a FakeUba) -> Ops<'a> {
    Ops {
        graylog: g,
        uba: u,
        wazuh: &NoWazuh,
    }
}

async fn roll_back(g: &FakeGraylog, u: &FakeUba, rows: &[Row], code: &str) -> PyResult<Report> {
    let plan = rollback::build_plan(ops(g, u), code, &facts(code, rows)).await?;
    let (preview, remove) = rollback::plan_response(&plan)?;
    if remove == 0 && plan.gone.is_empty() {
        return Err(http(409, preview.get("message").expect("message").py_str()));
    }
    let snapshot = rollback::snapshot(&plan, "2026-10-17T00:00:00+00:00")?;
    let (run, verification) = rollback::run_all(ops(g, u), &plan).await;
    let (status, _) = rollback::outcome(code, &run, &verification);
    Ok(Report {
        status,
        steps: run.steps.clone(),
        verification,
        snapshot: copilot_upstream::json::pydantic_json(&snapshot)
            .parse()
            .expect("json"),
        removed: run
            .removed
            .iter()
            .map(|i| {
                let o = i.owned();
                (o.kind.to_string(), o.graylog_id, o.origin.to_string())
            })
            .collect(),
    })
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

fn status_of<'a>(report: &'a Report, step: &str) -> Option<&'a Step> {
    report.steps.iter().find(|s| s.step == step)
}

fn check<'a>(report: &'a Report, name: &str) -> &'a Check {
    report
        .verification
        .iter()
        .find(|c| c.check == name)
        .expect(name)
}

fn keys(map: &OrderedMap<Value>) -> Vec<String> {
    let mut k: Vec<String> = map.keys().cloned().collect();
    k.sort();
    k
}

fn pos(order: &[String], what: &str) -> usize {
    order.iter().position(|o| o == what).expect(what)
}

// -- the whole rollback ------------------------------------------------------------------------

#[test]
fn routing_goes_first_then_the_output_then_what_it_routed_to_and_uba_last() {
    let g = FakeGraylog::new(&["acme"]);
    let u = FakeUba::new(Some(true)).logging(&g.calls);
    let report = rt()
        .block_on(roll_back(&g, &u, &[], "acme"))
        .expect("report");

    let writes = g.writes();
    assert_eq!(
        writes[0],
        (
            "POST".into(),
            "/api/system/pipelines/connections/to_pipeline".into()
        )
    );
    let order: Vec<String> = writes.iter().map(|w| w.1.clone()).collect();
    assert!(
        pos(&order, "/api/streams/feed-acme/outputs/out-acme")
            < pos(&order, "/api/system/outputs/out-acme")
    );
    assert!(pos(&order, "/api/system/outputs/out-acme") < pos(&order, "/api/streams/feed-acme"));
    assert!(
        pos(&order, "/api/system/pipelines/pipeline/route-acme")
            < pos(&order, "/api/system/pipelines/rule/rule-acme-0")
    );
    assert_eq!(
        writes.last().expect("last"),
        &("UBA PUT".to_string(), "/v1/tenants/acme".to_string())
    );
    let calls = u.calls.lock().expect("lock");
    assert_eq!(
        calls[calls.len() - 2].2,
        Some(PyValue::Dict(vec![("active".into(), PyValue::Bool(false))]))
    );
    drop(calls);

    let d = g.data.lock().expect("lock");
    assert_eq!(keys(&d.streams), vec!["wazuh-acme"]);
    assert_eq!(
        d.connections.get("wazuh-acme"),
        Some(&vec!["proc-acme".to_string()])
    );
    assert_eq!(keys(&d.pipelines), vec!["proc-acme"]);
    assert!(d.rules.is_empty() && d.outputs.is_empty());
    assert!(
        d.inputs.is_empty(),
        "the last customer: the shared input goes too"
    );
    drop(d);
    assert_eq!(report.status, "completed", "{:?}", report.steps);
    assert_eq!(check(&report, "stream ACME - Wazuh").ok, Some(true));
    let pipelines = check(&report, "pipelines of ACME - Wazuh");
    assert_eq!(pipelines.ok, Some(true));
    assert!(pipelines.detail.contains("WAZUH PROCESSING"));
    for name in [
        "event definitions",
        "UBA routing",
        "output to UBA",
        "UBA tenant",
    ] {
        assert_eq!(check(&report, name).ok, Some(true), "{name}");
    }
    let before: Vec<String> = report.snapshot["objects"]
        .as_array()
        .expect("objects")
        .iter()
        .map(|o| o["object"]["id"].as_str().expect("id").to_string())
        .collect();
    for id in [
        "feed-acme",
        "route-acme",
        "out-acme",
        "alerts-acme",
        "rule-acme-0",
        "in-uba",
    ] {
        assert!(before.contains(&id.to_string()), "{id}");
    }
    assert_eq!(
        report.snapshot["connections"],
        json!({"route-acme": ["wazuh-acme"]})
    );
}

#[test]
fn objects_found_by_title_are_adopted_and_recorded_ones_marked_removed() {
    let g = FakeGraylog::new(&["acme"]);
    let u = FakeUba::new(Some(true));
    let rows = [row(
        "acme",
        ownership::OUTPUT,
        "out-acme",
        "UBA GELF - acme",
        None,
        false,
    )];
    let report = rt()
        .block_on(roll_back(&g, &u, &rows, "acme"))
        .expect("report");
    let origin = |kind: &str, id: &str| {
        report
            .removed
            .iter()
            .find(|(k, i, _)| k == kind && i == id)
            .map(|(_, _, o)| o.clone())
    };
    assert_eq!(
        origin(ownership::OUTPUT, "out-acme").as_deref(),
        Some("found")
    );
    assert_eq!(
        origin(ownership::FEED_STREAM, "feed-acme").as_deref(),
        Some("adopted")
    );
}

#[test]
fn another_customers_uba_and_the_shared_input_stay() {
    let g = FakeGraylog::new(&["acme", "globex"]);
    let u = FakeUba::new(Some(true));
    let report = rt()
        .block_on(roll_back(&g, &u, &[], "acme"))
        .expect("report");
    let d = g.data.lock().expect("lock");
    for id in ["feed-globex", "alerts-globex", "wazuh-globex"] {
        assert!(d.streams.contains(id), "{id}");
    }
    assert!(
        d.connections
            .get("wazuh-globex")
            .expect("globex")
            .contains(&"route-globex".to_string())
    );
    assert!(d.outputs.contains("out-globex") && d.inputs.contains("in-uba"));
    drop(d);
    let kept = status_of(&report, "input UBA ALERTS").expect("input");
    assert_eq!(kept.status, "kept");
    assert!(kept.detail.contains("UBA ALERTS - globex"));
    assert_eq!(report.status, "completed");
}

#[test]
fn the_preview_changes_nothing_and_lists_the_order() {
    let g = FakeGraylog::new(&["acme", "globex"]);
    let u = FakeUba::new(Some(true)).logging(&g.calls);
    let plan = rt()
        .block_on(rollback::build_plan(
            ops(&g, &u),
            "acme",
            &facts("acme", &[]),
        ))
        .expect("plan");
    let (preview, _) = rollback::plan_response(&plan).expect("preview");
    assert!(g.writes().is_empty());
    let preview: Value = copilot_upstream::json::pydantic_json(&preview)
        .parse()
        .expect("json");
    let kinds: Vec<&str> = preview["remove"]
        .as_array()
        .expect("remove")
        .iter()
        .map(|i| i["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(
        kinds,
        vec![
            "routing_pipeline",
            "output",
            "routing_rule",
            "routing_rule",
            "feed_stream",
            "alerts_stream",
            "uba_tenant"
        ]
    );
    let kept: Vec<&str> = preview["keep"]
        .as_array()
        .expect("keep")
        .iter()
        .map(|i| i["title"].as_str().expect("title"))
        .collect();
    assert_eq!(kept, vec!["UBA ALERTS"]);
    assert_eq!(
        preview["source_streams"],
        json!([{"id": "wazuh-acme", "title": "ACME - Wazuh", "exists": true,
                "pipelines": ["WAZUH PROCESSING", "UBA ROUTING - WAZUH - acme"]}])
    );
}

// -- what is never touched ---------------------------------------------------------------------

#[test]
fn a_pipeline_running_someone_elses_rule_is_left_and_so_is_what_it_routes_to() {
    let g = FakeGraylog::new(&["acme"]);
    {
        let mut d = g.data.lock().expect("lock");
        let p = d.pipelines.get_mut("route-acme").expect("route");
        p["stages"][0]["rules"]
            .as_array_mut()
            .expect("rules")
            .push(json!("HAND MADE ENRICHMENT"));
    }
    let u = FakeUba::new(Some(true));
    let report = rt()
        .block_on(roll_back(&g, &u, &[], "acme"))
        .expect("report");
    let d = g.data.lock().expect("lock");
    assert!(d.pipelines.contains("route-acme"));
    assert!(
        d.connections
            .get("wazuh-acme")
            .expect("acme")
            .contains(&"route-acme".to_string())
    );
    assert!(d.streams.contains("feed-acme"));
    assert!(d.rules.contains("rule-acme-0") && d.rules.contains("rule-acme-1"));
    assert!(!d.outputs.contains("out-acme"), "nothing sends to UBA");
    drop(d);
    assert_eq!(
        status_of(&report, "routing_pipeline UBA ROUTING - WAZUH - acme")
            .expect("pipeline")
            .status,
        "conflict"
    );
    assert_eq!(
        status_of(&report, "feed_stream UBA FEED - WAZUH - acme")
            .expect("feed")
            .status,
        "conflict"
    );
}

#[test]
fn a_stream_an_event_definition_reads_is_kept_and_the_input_with_it() {
    let g = FakeGraylog::new(&["acme"]);
    g.data.lock().expect("lock").definitions.push(json!({
        "id": "ed2", "title": "UBA HIGH RISK", "state": "ENABLED",
        "config": {"streams": ["alerts-acme"]}
    }));
    let u = FakeUba::new(Some(true));
    let report = rt()
        .block_on(roll_back(&g, &u, &[], "acme"))
        .expect("report");
    let d = g.data.lock().expect("lock");
    assert!(d.streams.contains("alerts-acme") && d.inputs.contains("in-uba"));
    drop(d);
    let conflict = status_of(&report, "alerts_stream UBA ALERTS - acme").expect("conflict");
    assert_eq!(conflict.status, "conflict");
    assert!(conflict.detail.contains("UBA HIGH RISK"));
    assert_eq!(check(&report, "event definitions").ok, Some(true));
}

#[test]
fn the_customers_own_stream_is_never_removed_even_if_recorded() {
    let g = FakeGraylog::new(&["acme"]);
    let u = FakeUba::new(Some(true));
    let rows = [row(
        "acme",
        ownership::FEED_STREAM,
        "wazuh-acme",
        "ACME - Wazuh",
        Some("WAZUH"),
        false,
    )];
    rt().block_on(roll_back(&g, &u, &rows, "acme"))
        .expect("report");
    assert!(g.data.lock().expect("lock").streams.contains("wazuh-acme"));
    assert!(
        !g.calls()
            .contains(&("DELETE".to_string(), "/api/streams/wazuh-acme".to_string()))
    );
}

#[test]
fn wazuh_rules_are_kept() {
    let g = FakeGraylog::new(&["acme"]);
    let u = FakeUba::new(Some(true));
    let rows = [row(
        "acme",
        ownership::WAZUH_RULES,
        "0950-uba.xml",
        "0950-uba.xml",
        None,
        true,
    )];
    let report = rt()
        .block_on(roll_back(&g, &u, &rows, "acme"))
        .expect("report");
    let step = report
        .steps
        .iter()
        .find(|s| s.step.starts_with("Wazuh rules"))
        .expect("step");
    assert_eq!(step.status, "kept");
    assert!(step.detail.contains("manager restart"));
}

#[test]
fn an_output_also_attached_elsewhere_is_only_detached() {
    let g = FakeGraylog::new(&["acme"]);
    g.data
        .lock()
        .expect("lock")
        .streams
        .get_mut("wazuh-acme")
        .expect("stream")["outputs"]
        .as_array_mut()
        .expect("outputs")
        .push(json!({"id": "out-acme"}));
    let u = FakeUba::new(Some(true));
    rt().block_on(roll_back(&g, &u, &[], "acme"))
        .expect("report");
    let d = g.data.lock().expect("lock");
    assert!(d.outputs.contains("out-acme"));
    assert_eq!(
        d.streams.get("wazuh-acme").expect("stream")["outputs"],
        json!([{"id": "out-acme"}])
    );
    assert!(!d.streams.contains("feed-acme"));
}

// -- failures ----------------------------------------------------------------------------------

#[test]
fn uba_down_does_not_stop_the_graylog_side() {
    let g = FakeGraylog::new(&["acme"]);
    let u = FakeUba::down();
    let report = rt()
        .block_on(roll_back(&g, &u, &[], "acme"))
        .expect("report");
    let d = g.data.lock().expect("lock");
    assert_eq!(keys(&d.streams), vec!["wazuh-acme"]);
    assert!(d.outputs.is_empty());
    drop(d);
    let tenant = status_of(&report, "UBA tenant").expect("tenant");
    assert_eq!(tenant.status, "failed");
    assert!(tenant.detail.contains("roll back again"));
    assert_eq!(report.status, "partial");
}

#[test]
fn a_pipeline_that_cannot_be_disconnected_keeps_its_feed_stream_and_rules() {
    let g = FakeGraylog::new(&["acme"]);
    g.data.lock().expect("lock").fail.push((
        "POST".into(),
        "/api/system/pipelines/connections/to_pipeline".into(),
    ));
    let u = FakeUba::new(Some(true));
    let report = rt()
        .block_on(roll_back(&g, &u, &[], "acme"))
        .expect("report");
    {
        let d = g.data.lock().expect("lock");
        assert!(d.streams.contains("feed-acme") && d.pipelines.contains("route-acme"));
        assert_eq!(d.rules.len(), 2);
    }
    assert_eq!(report.status, "partial");
    assert_eq!(
        status_of(&report, "stream UBA FEED - WAZUH - acme")
            .expect("feed")
            .status,
        "skipped"
    );

    g.data.lock().expect("lock").fail.clear();
    let again = rt()
        .block_on(roll_back(&g, &FakeUba::new(Some(false)), &[], "acme"))
        .expect("again");
    assert_eq!(again.status, "completed");
    assert_eq!(
        keys(&g.data.lock().expect("lock").streams),
        vec!["wazuh-acme"]
    );
}

#[test]
fn nothing_to_roll_back_is_a_409() {
    let g = FakeGraylog::new(&[]);
    let u = FakeUba::new(Some(false));
    match rt().block_on(roll_back(&g, &u, &[], "acme")) {
        Err(PyExc::Http(409, _)) => {}
        other => panic!("{:?}", other.map(|r| r.status)),
    }
}

#[test]
fn a_check_that_fails_makes_the_rollback_partial() {
    let g = FakeGraylog::new(&["acme"]);
    g.data.lock().expect("lock").disconnect_on_post = Some("wazuh-acme".into());
    let u = FakeUba::new(Some(true));
    let report = rt()
        .block_on(roll_back(&g, &u, &[], "acme"))
        .expect("report");
    assert_eq!(check(&report, "pipelines of ACME - Wazuh").ok, Some(false));
    assert_eq!(report.status, "partial");
}

// -- mode --------------------------------------------------------------------------------------

#[test]
fn learning_mode_is_sent_with_active_and_refused_for_a_rolled_back_customer() {
    let u = FakeUba::new(Some(true));
    let out = rt()
        .block_on(crate::provision::set_mode(&u, "acme", "learning"))
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        out.get("onboarding").and_then(|o| o.get("mode")),
        Some(&PyValue::Str("learning".into()))
    );
    let last = u.calls.lock().expect("lock").last().cloned().expect("call");
    assert_eq!(
        (last.0.as_str(), last.1.as_str()),
        ("PUT", "/v1/tenants/acme")
    );
    assert_eq!(
        last.2,
        Some(PyValue::Dict(vec![
            ("active".into(), PyValue::Bool(true)),
            ("mode".into(), PyValue::Str("learning".into())),
        ]))
    );

    match rt().block_on(crate::provision::set_mode(
        &FakeUba::new(Some(false)),
        "acme",
        "learning",
    )) {
        Err(UbaError::Request { status: 409, .. }) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_uba_without_modes_is_reported_not_silently_ignored() {
    let mut u = FakeUba::new(Some(true));
    u.no_modes = true;
    match rt().block_on(crate::provision::set_mode(&u, "acme", "learning")) {
        Err(UbaError::Request {
            reason: "unsupported",
            ..
        }) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn rule_titles_come_from_stages_else_the_source() {
    let mut state = rollback::GraylogState::default();
    state.pipelines.insert(
        "p".into(),
        from_json(&json!({"id": "p", "source": "pipeline \"x\"\nstage 1 match either\n  rule \"A - B\"\nrule \"C\"\nend"})),
    );
    assert_eq!(
        state.pipeline_rules("p").expect("rules"),
        vec![PyValue::Str("A - B".into()), PyValue::Str("C".into())]
    );
    state
        .pipelines
        .insert("q".into(), from_json(&json!({"id": "q", "source": 5})));
    assert_eq!(
        state.pipeline_rules("q").expect_err("int").text(),
        "expected string or bytes-like object, got 'int'"
    );
}
