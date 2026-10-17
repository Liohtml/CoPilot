//! `tests/test_uba_provisioning.py`, ported: Graylog and UBA as fakes, the
//! customer's records as [`Facts`]; registration first, feed streams in
//! their source's index set, `to_pipeline`, repair without duplicates,
//! every object recorded.

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
use crate::ownership::Owned;
use crate::provision::{self, Facts, Meta, O365, Step};
use crate::pyops::OrderedMap;
use crate::schema::ProvisionRequest;

const ORG: &str = "aaaaaaaa-0000-4000-8000-000000000001";

fn names() -> Value {
    json!({
        "sources": {"WAZUH": "wazuh", "O365": "office365"},
        "feed_stream": "UBA FEED - {source} - {tenant}",
        "routing_pipeline": "UBA ROUTING - {source} - {tenant}",
        "pipeline_stage": 10,
        "output": "UBA GELF - {tenant}",
        "alerts_input": "UBA ALERTS",
        "alerts_stream": "UBA ALERTS - {tenant}",
        "alerts_stream_rules": {"syslog_type": "uba", "agent_labels_customer": "{tenant}"},
    })
}

type Log = Arc<Mutex<Vec<(String, String)>>>;

#[derive(Default)]
struct Data {
    index_sets: OrderedMap<Value>,
    sources: OrderedMap<String>,
    streams: OrderedMap<Value>,
    rules: OrderedMap<Value>,
    pipelines: OrderedMap<Value>,
    outputs: OrderedMap<Value>,
    inputs: OrderedMap<Value>,
    connections: OrderedMap<Vec<String>>,
    attached: OrderedMap<Vec<String>>,
    next_id: u32,
    /// `post` refuses this endpoint.
    refuse_post: Option<String>,
    /// `put` answers `success: false`.
    refuse_put: bool,
}

struct FakeGraylog {
    data: Mutex<Data>,
    calls: Log,
}

fn reply(data: Value) -> Reply {
    Reply {
        data: from_json(&data),
        success: true,
        message: String::new(),
    }
}

fn to_json(v: &PyValue) -> Value {
    copilot_upstream::json::pydantic_json(v)
        .parse()
        .expect("json")
}

impl FakeGraylog {
    fn new(prefixes: &[(&str, &str)], sources: Option<&[(&str, &str)]>) -> Self {
        let mut d = Data::default();
        for (id, prefix) in prefixes {
            d.index_sets
                .insert((*id).into(), json!({"index_prefix": prefix}));
        }
        let default = [
            ("wazuh-src", "wazuh-set"),
            ("o365-a", "o365-set"),
            ("o365-b", "o365-set"),
        ];
        for (stream, set) in sources.unwrap_or(&default) {
            d.sources.insert((*stream).into(), (*set).into());
        }
        Self {
            data: Mutex::new(d),
            calls: Arc::default(),
        }
    }

    fn log(&self, method: &str, endpoint: &str) {
        self.calls
            .lock()
            .expect("lock")
            .push((method.into(), endpoint.into()));
    }

    fn by_title(map: &OrderedMap<Value>) -> OrderedMap<Value> {
        let mut out = OrderedMap::default();
        for v in map.values() {
            out.insert(v["title"].as_str().expect("title").to_string(), v.clone());
        }
        out
    }

    fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().expect("lock").clone()
    }
}

fn id(d: &mut Data) -> String {
    d.next_id += 1;
    format!("id{}", d.next_id)
}

fn merge(id: &str, data: &PyValue) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("id".into(), json!(id));
    if let Value::Object(m) = to_json(data) {
        out.extend(m);
    }
    Value::Object(out)
}

fn values(map: &OrderedMap<Value>) -> Value {
    Value::Array(map.values().cloned().collect())
}

#[async_trait]
impl GraylogOps for FakeGraylog {
    async fn get(&self, endpoint: &str, _params: &[(&str, String)]) -> PyResult<Reply> {
        self.log("GET", endpoint);
        let d = self.data.lock().expect("lock");
        if let Some(set) = endpoint.strip_prefix("/api/system/indices/index_sets/") {
            return Ok(reply(d.index_sets.get(set).cloned().expect("index set")));
        }
        if let Some(stream) = endpoint.strip_prefix("/api/streams/") {
            if let Some(set) = d.sources.get(stream) {
                return Ok(reply(json!({"id": stream, "index_set_id": set})));
            }
            if let Some(s) = d.streams.get(stream) {
                return Ok(reply(s.clone()));
            }
            return Err(PyExc::Http(
                404,
                format!("Failed to send GET request to {endpoint}: not found"),
            ));
        }
        let data = match endpoint {
            "/api/streams" => json!({"streams": values(&d.streams)}),
            "/api/system/pipelines/rule" => values(&d.rules),
            "/api/system/pipelines/pipeline" => values(&d.pipelines),
            "/api/system/outputs" => json!({"outputs": values(&d.outputs)}),
            "/api/system/inputs" => json!({"inputs": values(&d.inputs)}),
            other => panic!("{other}"),
        };
        Ok(reply(data))
    }

    async fn post(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Reply> {
        self.log("POST", endpoint);
        let mut d = self.data.lock().expect("lock");
        if d.refuse_post.as_deref() == Some(endpoint) {
            return Err(PyExc::Http(500, "refused".into()));
        }
        let data = data.unwrap_or(PyValue::None);
        match endpoint {
            "/api/system/pipelines/rule" => {
                let i = id(&mut d);
                let obj = merge(&i, &data);
                d.rules.insert(i, obj.clone());
                Ok(reply(obj))
            }
            "/api/system/pipelines/pipeline" => {
                let i = id(&mut d);
                let obj = merge(&i, &data);
                d.pipelines.insert(i, obj.clone());
                Ok(reply(obj))
            }
            "/api/system/pipelines/connections/to_pipeline" => {
                let body = to_json(&data);
                let ids: Vec<String> = body["stream_ids"]
                    .as_array()
                    .expect("ids")
                    .iter()
                    .map(|v| v.as_str().expect("id").to_string())
                    .collect();
                d.connections.insert(
                    body["pipeline_id"].as_str().expect("pipeline").to_string(),
                    ids,
                );
                Ok(reply(Value::Null))
            }
            "/api/system/outputs" => {
                let i = id(&mut d);
                let body = to_json(&data);
                d.outputs.insert(
                    i.clone(),
                    json!({"id": i, "title": body["title"], "configuration": body["configuration"]}),
                );
                Ok(reply(json!({"id": i})))
            }
            "/api/system/inputs" => {
                let i = id(&mut d);
                let body = to_json(&data);
                d.inputs.insert(
                    i.clone(),
                    json!({"id": i, "title": body["title"], "attributes": body["configuration"]}),
                );
                Ok(reply(json!({"id": i})))
            }
            e if e.ends_with("/outputs") => {
                let stream = e.split('/').nth(3).expect("stream").to_string();
                let outputs: Vec<String> = to_json(&data)["outputs"]
                    .as_array()
                    .expect("outputs")
                    .iter()
                    .map(|v| v.as_str().expect("id").to_string())
                    .collect();
                if !d.attached.contains(&stream) {
                    d.attached.insert(stream.clone(), Vec::new());
                }
                if let Some(list) = d.attached.get_mut(&stream) {
                    for o in outputs {
                        if !list.contains(&o) {
                            list.push(o);
                        }
                    }
                }
                Ok(reply(Value::Null))
            }
            e if e.ends_with("/resume") => Ok(reply(Value::Null)),
            other => panic!("{other}"),
        }
    }

    async fn put(&self, endpoint: &str, data: Option<PyValue>) -> PyResult<Option<Reply>> {
        self.log("PUT", endpoint);
        let mut d = self.data.lock().expect("lock");
        if d.refuse_put {
            return Ok(Some(Reply {
                data: PyValue::None,
                success: false,
                message: format!("Failed to send PUT request to {endpoint} with error: timeout"),
            }));
        }
        let body = to_json(&data.unwrap_or(PyValue::None));
        let i = endpoint.rsplit('/').next().expect("id").to_string();
        let target = if endpoint.contains("/rule/") {
            d.rules.get_mut(&i)
        } else if endpoint.contains("/pipeline/") {
            d.pipelines.get_mut(&i)
        } else {
            d.outputs.get_mut(&i)
        };
        let target = target.expect("object");
        if endpoint.contains("/outputs/") {
            target["title"] = body["title"].clone();
            target["configuration"] = body["configuration"].clone();
        } else if let (Value::Object(t), Value::Object(b)) = (target, body) {
            t.extend(b);
        }
        Ok(Some(reply(Value::Null)))
    }

    async fn delete(&self, endpoint: &str) -> PyResult<Reply> {
        panic!("no DELETE expected: {endpoint}");
    }

    async fn create_stream(&self, entity: PyValue) -> PyResult<Reply> {
        self.log("POST", "/api/streams");
        let mut d = self.data.lock().expect("lock");
        let i = id(&mut d);
        let obj = merge(&i, &entity);
        d.streams.insert(i.clone(), obj);
        Ok(reply(json!({"stream_id": i})))
    }
}

struct FakeUba {
    info: Value,
    calls: Mutex<Vec<(String, String, Option<Value>)>>,
    log: Log,
}

impl FakeUba {
    fn new(feed_host: Option<&str>, log: &Log, protocol: Option<&str>) -> Self {
        let feed = match feed_host {
            Some(h) => json!({"host": h, "port": 12203, "protocol": protocol}),
            None => Value::Null,
        };
        Self {
            info: json!({
                "graylog": names(),
                "feed_output": feed,
                "alerts_input": {"bind_address": "172.17.0.1", "port": 12204},
                "wazuh_rules": [{"filename": "0950-uba_windows_account_rules.xml", "content": "<group/>"}],
            }),
            calls: Mutex::default(),
            log: log.clone(),
        }
    }

    fn puts(&self) -> Vec<(String, String, Option<Value>)> {
        self.calls
            .lock()
            .expect("lock")
            .iter()
            .filter(|c| c.0 == "PUT")
            .cloned()
            .collect()
    }
}

#[async_trait]
impl UbaOps for FakeUba {
    async fn call(&self, call: Call) -> UbaResult<PyValue> {
        let method = call.method().as_str().to_string();
        let path = call.path().to_string();
        self.calls.lock().expect("lock").push((
            method.clone(),
            path.clone(),
            call.body().map(to_json),
        ));
        self.log
            .lock()
            .expect("lock")
            .push((format!("UBA {method}"), path.clone()));
        if path == "/v1/provisioning" {
            return Ok(from_json(&self.info));
        }
        if path.ends_with("/graylog-rules") {
            let source = if path.contains("office365") {
                "OFFICE365"
            } else {
                "WINDOWS AUTH"
            };
            let stream = call
                .query()
                .iter()
                .find(|(k, _)| k == "stream")
                .map(|(_, v)| v.py_str())
                .expect("stream");
            return Ok(from_json(&json!({"rules": [format!(
                "rule \"{stream} - {source}\"\nwhen true\nthen\n  route_to_stream(name: \"{stream}\");\nend"
            )]})));
        }
        if method == "PUT" && path.starts_with("/v1/tenants/") {
            let tenant = path.rsplit('/').next().unwrap_or_default();
            return Ok(from_json(
                &json!({"tenant": tenant, "status": "pending", "active": true}),
            ));
        }
        panic!("{path}");
    }
}

#[derive(Default)]
struct FakeWazuh {
    uploads: Mutex<Vec<(String, Vec<u8>)>>,
    restarts: Mutex<u32>,
}

#[async_trait]
impl WazuhOps for FakeWazuh {
    async fn upload_rules(&self, filename: &str, content: Vec<u8>) -> PyResult<()> {
        self.uploads
            .lock()
            .expect("lock")
            .push((filename.into(), content));
        Ok(())
    }

    async fn restart(&self) -> PyResult<()> {
        *self.restarts.lock().expect("lock") += 1;
        Ok(())
    }
}

fn facts(o365: bool) -> Facts {
    Facts {
        meta: Some(Meta {
            customer_name: "Acme Corp".into(),
            graylog_stream: "wazuh-src".into(),
            graylog_index: "wazuh-set".into(),
        }),
        o365: if o365 {
            vec![
                O365 {
                    stream_id: "o365-a".into(),
                    index_id: "o365-set".into(),
                    instance: None,
                },
                O365 {
                    stream_id: "o365-b".into(),
                    index_id: "o365-set".into(),
                    instance: Some("second".into()),
                },
            ]
        } else {
            Vec::new()
        },
        tenant_ids: vec![ORG.into()],
    }
}

fn request(days: &str, deploy: bool) -> ProvisionRequest {
    ProvisionRequest {
        bootstrap_days: days.into(),
        deploy_wazuh_rules: deploy,
    }
}

struct Outcome {
    result: UbaResult<PyValue>,
    owned: Option<Vec<Owned>>,
}

impl Outcome {
    fn steps(&self) -> Vec<Step> {
        let out = to_json(self.result.as_ref().expect("provisioned"));
        out["steps"]
            .as_array()
            .expect("steps")
            .iter()
            .map(|s| Step {
                step: s["step"].as_str().expect("step").into(),
                status: s["status"].as_str().expect("status").into(),
                detail: s["detail"].as_str().expect("detail").into(),
            })
            .collect()
    }

    fn status(&self, step: &str) -> Vec<String> {
        self.steps()
            .into_iter()
            .filter(|s| s.step == step)
            .map(|s| s.status)
            .collect()
    }
}

fn run(g: &FakeGraylog, u: &FakeUba, w: &FakeWazuh, req: &ProvisionRequest, f: &Facts) -> Outcome {
    let ops = Ops {
        graylog: g,
        uba: u,
        wazuh: w,
    };
    let (result, owned) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(provision::run(ops, "acme", req, f));
    Outcome { result, owned }
}

fn standard() -> FakeGraylog {
    FakeGraylog::new(
        &[("wazuh-set", "wazuh-acme"), ("o365-set", "office365-acme")],
        None,
    )
}

#[test]
fn a_customer_is_registered_first_then_routed_next_to_its_streams() {
    let g = standard();
    let u = FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp"));
    let out = run(
        &g,
        &u,
        &FakeWazuh::default(),
        &request("14", false),
        &facts(true),
    );

    let puts = u.puts();
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0].1, "/v1/tenants/acme");
    assert_eq!(
        puts[0].2,
        Some(json!({
            "name": "Acme Corp", "active": true, "bootstrap_days": 14,
            "office365_organization_ids": [ORG], "indices": null,
        }))
    );
    let writes: Vec<(String, String)> = g
        .calls()
        .into_iter()
        .filter(|c| matches!(c.0.as_str(), "POST" | "PUT" | "UBA PUT"))
        .collect();
    assert_eq!(writes[0], ("UBA PUT".into(), "/v1/tenants/acme".into()));
    assert_eq!(out.steps()[0].step, "UBA tenant");

    let d = g.data.lock().expect("lock");
    let streams = FakeGraylog::by_title(&d.streams);
    assert_eq!(
        streams.get("UBA FEED - WAZUH - acme").expect("feed")["index_set_id"],
        json!("wazuh-set")
    );
    assert_eq!(
        streams.get("UBA FEED - O365 - acme").expect("feed")["index_set_id"],
        json!("o365-set")
    );
    let pipelines = FakeGraylog::by_title(&d.pipelines);
    let wazuh_id = pipelines.get("UBA ROUTING - WAZUH - acme").expect("p")["id"]
        .as_str()
        .expect("id")
        .to_string();
    let o365 = pipelines.get("UBA ROUTING - O365 - acme").expect("p");
    assert_eq!(
        d.connections.get(&wazuh_id),
        Some(&vec!["wazuh-src".to_string()])
    );
    assert_eq!(
        d.connections.get(o365["id"].as_str().expect("id")),
        Some(&vec!["o365-a".to_string(), "o365-b".to_string()])
    );
    assert!(
        o365["source"]
            .as_str()
            .expect("source")
            .contains("stage 10 match either\nrule \"UBA FEED - O365 - acme - OFFICE365\"")
    );
    assert!(
        !g.calls()
            .iter()
            .any(|c| c.1.ends_with("/connections/to_stream"))
    );

    let outputs: Vec<&Value> = d.outputs.values().collect();
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["title"], json!("UBA GELF - acme"));
    assert_eq!(outputs[0]["configuration"]["hostname"], json!("127.0.0.1"));
    assert_eq!(outputs[0]["configuration"]["port"], json!(12203));
    let output_id = outputs[0]["id"].as_str().expect("id").to_string();
    let mut fed: Vec<String> = d
        .attached
        .iter()
        .filter(|(_, outs)| outs.contains(&output_id))
        .map(|(s, _)| s.clone())
        .collect();
    fed.sort();
    let mut feeds = vec![
        streams.get("UBA FEED - WAZUH - acme").expect("f")["id"]
            .as_str()
            .expect("id")
            .to_string(),
        streams.get("UBA FEED - O365 - acme").expect("f")["id"]
            .as_str()
            .expect("id")
            .to_string(),
    ];
    feeds.sort();
    assert_eq!(fed, feeds);

    let inputs: Vec<&Value> = d.inputs.values().collect();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0]["title"], json!("UBA ALERTS"));
    assert_eq!(inputs[0]["attributes"]["bind_address"], json!("172.17.0.1"));
    let alerts = streams.get("UBA ALERTS - acme").expect("alerts");
    assert_eq!(alerts["index_set_id"], json!("wazuh-set"));
    let rules: Vec<(String, String)> = alerts["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .map(|r| {
            (
                r["field"].as_str().expect("f").to_string(),
                r["value"].as_str().expect("v").to_string(),
            )
        })
        .collect();
    assert_eq!(
        rules,
        vec![
            ("syslog_type".to_string(), "uba".to_string()),
            ("agent_labels_customer".to_string(), "acme".to_string())
        ]
    );
    let alerts_id = alerts["id"].as_str().expect("id").to_string();
    assert!(d.connections.values().all(|v| !v.contains(&alerts_id)));
    drop(d);
    let steps = out.steps();
    let last = steps.last().expect("last");
    assert_eq!(
        (last.step.as_str(), last.status.as_str()),
        ("Wazuh rules", "skipped")
    );
}

#[test]
fn running_it_again_repairs_and_never_duplicates() {
    let g = standard();
    let w = FakeWazuh::default();
    run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &w,
        &request("14", false),
        &facts(true),
    );
    let counts = |g: &FakeGraylog| {
        let d = g.data.lock().expect("lock");
        (
            d.streams.len(),
            d.rules.len(),
            d.pipelines.len(),
            d.outputs.len(),
            d.inputs.len(),
        )
    };
    let before = counts(&g);
    let out = run(
        &g,
        &FakeUba::new(Some("10.0.0.5"), &g.calls, Some("udp")),
        &w,
        &request("14", false),
        &facts(true),
    );
    assert_eq!(counts(&g), before);
    assert_eq!(out.status("stream UBA FEED - WAZUH - acme"), vec!["exists"]);
    assert_eq!(
        out.status("rule UBA FEED - WAZUH - acme - WINDOWS AUTH"),
        vec!["exists"]
    );
    assert_eq!(
        out.status("pipeline UBA ROUTING - WAZUH - acme"),
        vec!["exists", "connected"]
    );
    assert!(
        !g.calls()
            .iter()
            .any(|c| c.0 == "PUT" && c.1.contains("/pipelines/pipeline/"))
    );
    assert_eq!(
        out.status("output UBA GELF - acme"),
        vec!["updated", "attached"]
    );
    let d = g.data.lock().expect("lock");
    let output = d.outputs.values().next().expect("output");
    assert_eq!(output["configuration"]["hostname"], json!("10.0.0.5"));
}

#[test]
fn a_pipeline_someone_changed_is_put_back() {
    let g = standard();
    let w = FakeWazuh::default();
    run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &w,
        &request("14", false),
        &facts(true),
    );
    let (id, original) = {
        let mut d = g.data.lock().expect("lock");
        let id = FakeGraylog::by_title(&d.pipelines)
            .get("UBA ROUTING - O365 - acme")
            .expect("p")["id"]
            .as_str()
            .expect("id")
            .to_string();
        let p = d.pipelines.get_mut(&id).expect("p");
        let original = p["source"].as_str().expect("source").to_string();
        p["source"] = json!(original.replace("stage 10", "stage 5"));
        (id, original)
    };
    let out = run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &w,
        &request("14", false),
        &facts(true),
    );
    assert_eq!(
        out.status("pipeline UBA ROUTING - O365 - acme")[0],
        "updated"
    );
    assert_eq!(
        g.data.lock().expect("lock").pipelines.get(&id).expect("p")["source"],
        json!(original)
    );
}

#[test]
fn index_sets_that_differ_from_ubas_defaults_are_registered() {
    let g = FakeGraylog::new(
        &[("wazuh-set", "acme-wazuh"), ("o365-set", "office365-acme")],
        None,
    );
    let u = FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp"));
    run(
        &g,
        &u,
        &FakeWazuh::default(),
        &request("14", false),
        &facts(true),
    );
    assert_eq!(
        u.puts()[0].2.as_ref().expect("body")["indices"],
        json!({"wazuh": "acme-wazuh_*"})
    );
}

#[test]
fn without_ubas_gelf_endpoints_nothing_is_created() {
    let g = standard();
    let u = FakeUba::new(None, &g.calls, Some("udp"));
    let out = run(
        &g,
        &u,
        &FakeWazuh::default(),
        &request("14", false),
        &facts(true),
    );
    match &out.result {
        Err(UbaError::Request {
            status: 409,
            detail,
            ..
        }) => {
            assert!(detail.contains("UBA_PROVISION_FEED_HOST"));
        }
        other => panic!("{other:?}"),
    }
    assert!(u.puts().is_empty());
    assert!(
        g.calls()
            .iter()
            .all(|c| c.0 == "GET" || c.0.starts_with("UBA"))
    );
    assert!(out.owned.is_none());
}

#[test]
fn a_feed_stream_in_another_index_set_is_refused() {
    let g = standard();
    g.data.lock().expect("lock").streams.insert(
        "x".into(),
        json!({"id": "x", "title": "UBA FEED - WAZUH - acme", "index_set_id": "elsewhere"}),
    );
    let out = run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &FakeWazuh::default(),
        &request("14", false),
        &facts(true),
    );
    match &out.result {
        Err(UbaError::Py(PyExc::Http(409, detail))) => assert!(detail.contains("indexed twice")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn wazuh_rules_are_uploaded_and_the_manager_restarted_only_on_request() {
    let g = FakeGraylog::new(&[("wazuh-set", "wazuh-acme")], None);
    let w = FakeWazuh::default();
    let out = run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &w,
        &request("7", true),
        &facts(false),
    );
    assert_eq!(
        *w.uploads.lock().expect("lock"),
        vec![(
            "0950-uba_windows_account_rules.xml".to_string(),
            b"<group/>".to_vec()
        )]
    );
    assert_eq!(*w.restarts.lock().expect("lock"), 1);
    let steps = out.steps();
    let tail: Vec<&str> = steps[steps.len() - 2..]
        .iter()
        .map(|s| s.status.as_str())
        .collect();
    assert_eq!(tail, vec!["uploaded", "restarted"]);
}

#[test]
fn the_index_set_comes_from_graylog_not_from_copilots_records() {
    let g = FakeGraylog::new(
        &[
            ("wazuh-set-new", "wazuh-acme"),
            ("o365-set-new", "office365-acme"),
        ],
        Some(&[
            ("wazuh-src", "wazuh-set-new"),
            ("o365-a", "o365-set-new"),
            ("o365-b", "o365-set-new"),
        ]),
    );
    let out = run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &FakeWazuh::default(),
        &request("14", false),
        &facts(true),
    );
    let d = g.data.lock().expect("lock");
    let streams = FakeGraylog::by_title(&d.streams);
    for (title, set) in [
        ("UBA FEED - WAZUH - acme", "wazuh-set-new"),
        ("UBA FEED - O365 - acme", "o365-set-new"),
        ("UBA ALERTS - acme", "wazuh-set-new"),
    ] {
        assert_eq!(streams.get(title).expect(title)["index_set_id"], json!(set));
    }
    drop(d);
    assert_eq!(out.steps()[0].step, "UBA tenant");
}

#[test]
fn a_source_stream_missing_from_graylog_stops_before_anything_is_created() {
    let g = FakeGraylog::new(
        &[("wazuh-set", "wazuh-acme"), ("o365-set", "office365-acme")],
        Some(&[("wazuh-src", "wazuh-set")]),
    );
    let u = FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp"));
    let out = run(
        &g,
        &u,
        &FakeWazuh::default(),
        &request("14", false),
        &facts(true),
    );
    match &out.result {
        Err(UbaError::Py(PyExc::Http(409, detail))) => {
            assert!(detail.contains("o365-a") && detail.contains("provision that source again"));
        }
        other => panic!("{other:?}"),
    }
    assert!(u.puts().is_empty());
    assert!(
        g.calls()
            .iter()
            .all(|c| c.0 == "GET" || c.0.starts_with("UBA"))
    );
}

#[test]
fn a_put_graylog_did_not_take_stops_setup() {
    let g = standard();
    let w = FakeWazuh::default();
    run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &w,
        &request("14", false),
        &facts(true),
    );
    g.data.lock().expect("lock").refuse_put = true;
    let out = run(
        &g,
        &FakeUba::new(Some("10.0.0.5"), &g.calls, Some("udp")),
        &w,
        &request("14", false),
        &facts(true),
    );
    match &out.result {
        Err(UbaError::Py(PyExc::Http(502, detail))) => assert!(detail.contains("timeout")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn every_object_is_recorded_for_the_customer_even_when_a_step_fails() {
    let g = standard();
    let out = run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &FakeWazuh::default(),
        &request("14", false),
        &facts(true),
    );
    let owned = out.owned.expect("owned");
    let find = |kind: &str, title: &str| {
        owned
            .iter()
            .find(|o| o.kind == kind && o.title == title)
            .cloned()
    };
    assert!(find("feed_stream", "UBA FEED - O365 - acme").is_some());
    assert!(find("output", "UBA GELF - acme").is_some());
    assert!(find("alerts_input", "UBA ALERTS").expect("input").shared);
    assert_eq!(
        find("routing_pipeline", "UBA ROUTING - WAZUH - acme")
            .expect("pipeline")
            .source
            .as_deref(),
        Some("WAZUH")
    );
    assert!(owned.iter().all(|o| o.origin == "created"));
    let d = g.data.lock().expect("lock");
    assert!(
        owned
            .iter()
            .filter(|o| o.kind == "routing_rule")
            .all(|o| d.rules.contains(&o.graylog_id))
    );
    drop(d);

    let g = standard();
    g.data.lock().expect("lock").refuse_post = Some("/api/system/outputs".into());
    let out = run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &FakeWazuh::default(),
        &request("14", false),
        &facts(true),
    );
    assert!(out.result.is_err());
    let mut kinds: Vec<&'static str> = out.owned.expect("owned").iter().map(|o| o.kind).collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(
        kinds,
        vec!["feed_stream", "routing_pipeline", "routing_rule"]
    );
}

#[test]
fn the_feed_output_is_udp_and_a_tcp_one_is_moved_to_udp() {
    let g = standard();
    let w = FakeWazuh::default();
    run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, None),
        &w,
        &request("14", false),
        &facts(true),
    );
    let protocol = |g: &FakeGraylog| {
        let d = g.data.lock().expect("lock");
        assert_eq!(d.outputs.len(), 1);
        d.outputs.values().next().expect("o")["configuration"]["protocol"].clone()
    };
    assert_eq!(protocol(&g), json!("TCP"));

    let out = run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &w,
        &request("14", false),
        &facts(true),
    );
    assert_eq!(protocol(&g), json!("UDP"));
    let step = out
        .steps()
        .into_iter()
        .find(|s| s.step == "output UBA GELF - acme" && s.status != "attached")
        .expect("step");
    assert_eq!(step.status, "updated");
    assert!(step.detail.ends_with("UDP"));
    let out = run(
        &g,
        &FakeUba::new(Some("127.0.0.1"), &g.calls, Some("udp")),
        &w,
        &request("14", false),
        &facts(true),
    );
    assert_eq!(out.status("output UBA GELF - acme")[0], "exists");
}

#[test]
fn tenant_ids_are_stripped_lowered_unique_and_sorted() {
    assert_eq!(
        provision::tenant_ids(vec![
            " B-Tenant ".to_string(),
            "a".into(),
            "  ".into(),
            "b-tenant".into(),
            "\u{1c}C\u{1f}".into(),
        ]),
        vec!["a".to_string(), "b-tenant".into(), "c".into()]
    );
}
