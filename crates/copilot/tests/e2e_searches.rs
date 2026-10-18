//! End-to-end tests of the Detections Catalog port (`copilot-searches`):
//! `/api/copilot_searches` on a real MySQL at the Alembic head, GitHub (API,
//! raw files and the ATT&CK bundle), the Wazuh manager and indexer, Graylog
//! and MinIO replaced by stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13310/copilot \
//!   cargo test -p copilot --test e2e_searches -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `CATALOG_E2E_PORT_BASE` (default 6180) and the
//! six ports after it (each test on ports of its own). The tests that need the upstreams call the crate's
//! router with its GitHub URLs on the stand-in (the production router keeps
//! the public ones); the connector rows they need are created and deleted
//! again (the harness runs with the connector cache off). Byte-for-byte
//! parity with Python is `backend/tests/e2e/rust_parity_catalog_e2e.py`'s
//! job; these pin the caches' contract, the tenancy rules and the shapes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use copilot_searches::SearchesState;
use copilot_searches::caches::{Kind, Settings};

#[macro_use]
mod common;
use common::*;

const P: &str = "/api/copilot_searches";
const GITHUB: u16 = 0;
const MANAGER: u16 = 1;
const INDEXER: u16 = 2;
const GRAYLOG: u16 = 3;
const MINIO: u16 = 4;
/// `wazuh_failures_degrade_the_catalog`'s GitHub, manager and closed indexer.
const FAILING: u16 = 5;
const CATALOG: &str = "socfortress/CoPilot-Search-Queries";
const STREAM: &str = "6600000000000000000000a1";

fn port(offset: u16) -> u16 {
    std::env::var("CATALOG_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6180)
        + offset
}

fn configured() -> bool {
    std::env::var("COPILOT_TEST_DATABASE_URL").is_ok()
}

/// A stand-in on its port, retried while the previous test's server lets
/// the port go (wiremock closes its listener on its own thread after the
/// `MockServer` is dropped).
async fn stand_in(offset: u16) -> MockServer {
    let mut tries = 0;
    let listener = loop {
        match std::net::TcpListener::bind(("127.0.0.1", port(offset))) {
            Ok(l) => break l,
            Err(_) if tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("cannot bind the stand-in on {}: {e}", port(offset)),
        }
    };
    MockServer::builder().listener(listener).start().await
}

// --- the corpus ------------------------------------------------------------------

/// The fixture rules (`crates/copilot-searches/tests/fixtures/rules`), by
/// repository path.
fn fixtures() -> BTreeMap<String, String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../copilot-searches/tests/fixtures/rules");
    let mut out = BTreeMap::new();
    let mut stack = vec![root.join("detections")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, std::fs::read_to_string(&p).unwrap());
            }
        }
    }
    out
}

const AGG_RULE: &str = "name: E2E Aggregated Logons\nid: e2e-agg-0001\nstatus: experimental\n\
description: Many logons.\ndata_source: [Windows Event-Log]\ntags:\n  analytic_story: [E2E Story]\n  \
mitre_attack_id: [T1078]\nresponse:\n  severity: high\ngraylog:\n  query: data_win_system_eventID:4625\n\
aggregation:\n  enabled: true\n  function: count\n  condition: '>='\n  threshold: 2\n  window: 10m\n";

const CUSTOM_RULE: &str = "name: Acme Custom Rule\nid: acme-custom-0001\nstatus: production\n\
description: A tenant's own rule.\ntags:\n  analytic_story: [Acme Story]\n  mitre_attack_id: [T1059.001]\n\
graylog:\n  query: process_name:evil.exe\n";

fn mitre_bundle() -> Value {
    let mut objects = vec![];
    for (ext, short, name) in [
        ("TA0002", "execution", "Execution"),
        ("TA0003", "persistence", "Persistence"),
        ("TA0006", "credential-access", "Credential Access"),
    ] {
        objects.push(json!({
            "type": "x-mitre-tactic", "name": name, "x_mitre_shortname": short,
            "external_references": [{"source_name": "mitre-attack", "external_id": ext}],
        }));
    }
    for (tid, phase, sub) in [
        ("T1059", "execution", false),
        ("T1059.001", "execution", true),
        ("T1078", "persistence", false),
        ("T1110", "credential-access", false),
        ("T1136", "persistence", false),
        ("T1136.001", "persistence", true),
    ] {
        objects.push(json!({
            "type": "attack-pattern", "name": format!("Technique {tid}"),
            "x_mitre_is_subtechnique": sub,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": phase}],
            "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                "url": format!("https://attack.mitre.org/techniques/{tid}")}],
        }));
    }
    json!({"type": "bundle", "objects": objects})
}

/// GitHub: the catalog's tree and files, `acme-org/rules` (one rule), the
/// bundle at `/mitre.json`, the Contents API of the publish.
async fn github(server: &MockServer) {
    let files = fixtures();
    let mut tree: Vec<Value> = files
        .keys()
        .map(|p| json!({"path": p, "type": "blob"}))
        .collect();
    tree.push(json!({"path": "detections/e2e/agg.yaml", "type": "blob"}));
    tree.push(json!({"path": "README.md", "type": "blob"}));
    let mut raw: BTreeMap<String, String> = files
        .into_iter()
        .map(|(p, t)| (format!("/{CATALOG}/main/{p}"), t))
        .collect();
    raw.insert(
        format!("/{CATALOG}/main/detections/e2e/agg.yaml"),
        AGG_RULE.to_string(),
    );
    raw.insert(
        "/acme-org/rules/main/detections/custom/acme.yaml".into(),
        CUSTOM_RULE.into(),
    );
    Mock::given(method("GET"))
        .and(path(format!("/repos/{CATALOG}/git/trees/main")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tree": tree})))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme-org/rules/git/trees/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tree": [
            {"path": "detections/custom/acme.yaml", "type": "blob"},
            {"path": "detections/custom/notes.md", "type": "blob"},
        ]})))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/mitre.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mitre_bundle()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/repos/acme-org/rules/contents/.*"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})))
        .mount(server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/repos/acme-org/rules/contents/.*"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "content": {"html_url": "https://github.com/acme-org/rules/blob/main/x.yaml"},
            "commit": {"html_url": "https://github.com/acme-org/rules/commit/abc"},
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .respond_with(
            move |req: &wiremock::Request| match raw.get(req.url.path()) {
                Some(t) => ResponseTemplate::new(200).set_body_string(t.clone()),
                None => ResponseTemplate::new(404).set_body_string("404: Not Found"),
            },
        )
        .mount(server)
        .await;
}

/// The Wazuh manager: three rules and `PUT /logtest`; `rules_fail` makes
/// `GET /rules` a 500.
async fn manager(server: &MockServer, rules_fail: bool) {
    Mock::given(path("/security/user/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "tok"}, "error": 0})),
        )
        .mount(server)
        .await;
    let rule = |id: i64, level: i64, desc: &str, pci: &[&str]| {
        json!({"filename": "0095-sshd_rules.xml", "relative_dirname": "ruleset/rules", "id": id,
            "level": level, "status": "enabled", "description": desc, "groups": ["sshd"],
            "pci_dss": pci, "mitre": ["T1110"], "details": {"if_sid": "5700"}})
    };
    let rules = ResponseTemplate::new(if rules_fail { 500 } else { 200 }).set_body_json(json!({
        "data": {"affected_items": [
            rule(5710, 5, "sshd: non-existent user", &["10.2.4"]),
            rule(5712, 10, "sshd: brute force", &["10.2.4", "11.4"]),
            rule(100001, 12, "dead local rule", &[]),
        ], "total_affected_items": 3},
        "error": 0,
    }));
    Mock::given(method("GET"))
        .and(path("/rules"))
        .respond_with(rules)
        .mount(server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/logtest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"error": 0, "data": {
            "output": {"rule": {"id": "5710", "level": 5, "description": "sshd: non-existent user",
                "groups": ["sshd"], "mitre": {"id": ["T1110"]}}, "full_log": "x"},
        }})))
        .mount(server)
        .await;
}

/// The indexer: firing counts on `rule.id`, a customer's own slice.
async fn indexer(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/_cat/indices"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([{"index": "wazuh-alerts-1"}])),
        )
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/_search$"))
        .respond_with(|req: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let customer = body["query"]["bool"]["filter"]
                .as_array()
                .map(|f| f.iter().any(|x| x.get("term").is_some()))
                .unwrap_or(false);
            let buckets = if customer {
                json!([{"key": "5712", "doc_count": 2, "last_7d": {"doc_count": 1}}])
            } else {
                json!([{"key": "5710", "doc_count": 12, "last_7d": {"doc_count": 3},
                    "last_seen": {"value_as_string": "2026-10-16T00:00:00.000Z"}}])
            };
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(300))
                .set_body_json(json!({"hits": {"hits": []}, "aggregations": {"by_rule": {"buckets": buckets}}}))
        })
        .mount(server)
        .await;
}

/// Graylog 7: no event definitions yet, creation answered, the backtest's
/// search API.
async fn graylog(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "facility": "graylog-server", "codename": "Siracusa",
            "node_id": "5ca1ab1e-0000-4000-8000-000000000001",
            "cluster_id": "c1a55e00-0000-4000-8000-000000000001", "version": "7.0.1+abc1234",
            "started_at": "2026-10-01T08:00:00.000Z", "hostname": "graylog01",
            "lifecycle": "running", "lb_status": "alive", "timezone": "UTC",
            "operating_system": "Linux 6.8.0", "is_processing": true,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/events/definitions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"event_definitions": [], "total": 0})),
        )
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/events/definitions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "ed1"})))
        .mount(server)
        .await;
    let rows: Vec<Value> = (0..6)
        .map(|i| json!([format!("2026-10-14T00:0{i}:00.000Z"), "host", "m", "4625"]))
        .collect();
    Mock::given(method("POST"))
        .and(path("/api/search/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schema": [{"field": "timestamp"}, {"field": "source"}, {"field": "message"},
                {"field": "data_win_system_eventID"}],
            "datarows": rows,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/views/fields"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"name": "timestamp"}])))
        .mount(server)
        .await;
}

// --- MinIO -----------------------------------------------------------------------

/// In-memory buckets answering the calls the custom-repo pointers make (no
/// signature check: the parity suite's stand-in verifies those).
type Buckets = Arc<Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>>;

async fn minio() -> Buckets {
    let state: Buckets = Arc::default();
    let shared = state.clone();
    let app = Router::new().fallback(move |req: Request<Body>| {
        let state = shared.clone();
        async move {
            let method = req.method().clone();
            let uri = req.uri().clone();
            let body = axum::body::to_bytes(req.into_body(), 1 << 20)
                .await
                .unwrap_or_default();
            let decoded = percent_decode(uri.path());
            let (bucket, key) = decoded[1..]
                .split_once('/')
                .map_or((decoded[1..].to_string(), String::new()), |(b, k)| {
                    (b.to_string(), k.to_string())
                });
            let query = uri.query().unwrap_or("");
            let mut buckets = state.lock().unwrap();
            let xml = |status: u16, text: String| {
                http::Response::builder()
                    .status(status)
                    .header("content-type", "application/xml")
                    .body(Body::from(text))
                    .unwrap()
            };
            let empty = |status: u16| {
                http::Response::builder()
                    .status(status)
                    .body(Body::empty())
                    .unwrap()
            };
            let missing = |code: &str| {
                xml(
                    404,
                    format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code>\
                         <Message>missing</Message><Resource>{decoded}</Resource></Error>"
                    ),
                )
            };
            if key.is_empty() {
                if method == http::Method::PUT {
                    buckets.entry(bucket).or_default();
                    return empty(200);
                }
                let Some(objects) = buckets.get(&bucket) else {
                    return if method == http::Method::HEAD {
                        empty(404)
                    } else {
                        missing("NoSuchBucket")
                    };
                };
                if query.contains("location") {
                    return xml(
                        200,
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint \
                         xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>"
                            .into(),
                    );
                }
                if method == http::Method::HEAD {
                    return empty(200);
                }
                let mut out = String::from(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult \
                     xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
                );
                out.push_str(&format!(
                    "<Name>{bucket}</Name><Prefix></Prefix><KeyCount>{}</KeyCount>\
                     <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>",
                    objects.len()
                ));
                for (k, v) in objects {
                    out.push_str(&format!(
                        "<Contents><Key>{k}</Key><LastModified>2026-01-02T03:04:05.000Z</LastModified>\
                         <ETag>&#34;e&#34;</ETag><Size>{}</Size></Contents>",
                        v.len()
                    ));
                }
                out.push_str("</ListBucketResult>");
                return xml(200, out);
            }
            let Some(objects) = buckets.get_mut(&bucket) else {
                return missing("NoSuchBucket");
            };
            match method {
                http::Method::PUT => {
                    objects.insert(key, body.to_vec());
                    http::Response::builder()
                        .status(200)
                        .header("etag", "\"e\"")
                        .body(Body::empty())
                        .unwrap()
                }
                http::Method::DELETE => {
                    objects.remove(&key);
                    empty(204)
                }
                _ => match objects.get(&key) {
                    None if method == http::Method::HEAD => empty(404),
                    None => missing("NoSuchKey"),
                    Some(data) => http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .header("etag", "\"e\"")
                        .header("last-modified", "Fri, 02 Jan 2026 03:04:05 GMT")
                        .header("content-length", data.len().to_string())
                        .body(if method == http::Method::HEAD {
                            Body::empty()
                        } else {
                            Body::from(data.clone())
                        })
                        .unwrap(),
                },
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port(MINIO)))
        .await
        .unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// --- the database ----------------------------------------------------------------

async fn connector(h: &Harness, name: &str, url: &str) {
    sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
        .bind(name)
        .execute(h.db.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_username, connector_password, connector_api_key, connector_description, \
         connector_supports, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         (?, '4.8', ?, '2026-01-02 03:04:05', 'u', 'p', NULL, 'desc', 'supports', 1, 1, \
         0, 0, 1, 0, 0, NULL, 1)",
    )
    .bind(name)
    .bind(url)
    .execute(h.db.pool())
    .await
    .unwrap();
}

async fn cleanup(h: &Harness) {
    let s = &h.suffix;
    for sql in [
        format!("DELETE FROM customersmeta WHERE customer_code LIKE '%{s}'"),
        "DELETE FROM connectors WHERE connector_name IN ('Wazuh-Manager', 'Wazuh-Indexer', 'Graylog')"
            .to_string(),
    ] {
        h.exec(&sql).await;
    }
}

fn env_for_minio() -> String {
    format!(
        "COPILOT_MINIO_ENDPOINT=127.0.0.1:{}\nMINIO_ROOT_USER=e2e\nMINIO_ROOT_PASSWORD=e2e-secret\n",
        port(MINIO)
    )
}

/// The crate's router, its GitHub URLs on the stand-in and its caches empty.
fn catalog(h: &Harness, github: &MockServer) -> (Router, SearchesState) {
    let st = SearchesState {
        settings: Arc::new(Settings {
            github_api: github.uri(),
            github_raw: github.uri(),
            mitre_stix: format!("{}/mitre.json", github.uri()),
            github_token: None,
            refresh: false,
        }),
        caches: Arc::default(),
        ..h.app.searches.clone()
    };
    (copilot_searches::router(st.clone()), st)
}

async fn call(
    router: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&v).unwrap()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, value)
}

async fn requests_to(
    server: &MockServer,
    method_: &str,
    path_prefix: &str,
) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method.as_str() == method_ && r.url.path().starts_with(path_prefix))
        .collect()
}

// --- the tests -------------------------------------------------------------------

#[tokio::test]
async fn production_router_serves_the_prefix() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    let (status, body) = h
        .call("GET", &format!("{P}/custom-repos"), Some(&portal), None)
        .await;
    assert_eq!(status, 403, "an analyst-only route: {body}");
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/validate"),
            Some(&analyst),
            Some(json!({"yaml": AGG_RULE})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["findings"].is_array(), "{body}");
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/validate"),
            Some(&analyst),
            Some(json!({"yaml": "name: [x"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["valid"], json!(false), "{body}");
    assert_eq!(body["findings"][0]["code"], json!("YAML_PARSE"), "{body}");
    let (status, _) = h
        .call_raw(
            "POST",
            &format!("{P}/validate"),
            None,
            Some("application/json"),
            "{",
        )
        .await;
    assert_eq!(status, 422, "malformed JSON before the token");
}

#[tokio::test]
async fn caches_tenancy_and_upstreams() {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return;
    }
    let gh = stand_in(GITHUB).await;
    let mgr = stand_in(MANAGER).await;
    let es = stand_in(INDEXER).await;
    let gl = stand_in(GRAYLOG).await;
    github(&gh).await;
    manager(&mgr, false).await;
    indexer(&es).await;
    graylog(&gl).await;
    let buckets = minio().await;
    let h = harness_or_skip!(None, &env_for_minio());
    h.seed().await;
    let s = h.suffix.clone();
    let (acme, beta) = (format!("acme{s}"), format!("beta{s}"));
    connector(&h, "Wazuh-Manager", &mgr.uri()).await;
    connector(&h, "Wazuh-Indexer", &es.uri()).await;
    connector(&h, "Graylog", &gl.uri()).await;
    h.exec(&format!(
        "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, \
         customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group) \
         VALUES ('{acme}', 'acme corp', 'idx', '{STREAM}', '1', 'grp')"
    ))
    .await;
    let (router, st) = catalog(&h, &gh);
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");

    // The rules load on the first list (ensure_loaded), from the tree.
    let (status, body) = call(&router, "GET", &format!("{P}/stats"), &portal, None).await;
    assert_eq!(status, 200, "{body}");
    let total = body["total_rules"].as_i64().unwrap();
    assert_eq!(total as usize, fixtures().len() + 1, "{body}");
    assert_eq!(requests_to(&gh, "GET", "/repos/").await.len(), 1);
    let (status, body) = call(
        &router,
        "GET",
        &format!("{P}/id/e2e-agg-0001"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["rule"]["name"],
        json!("E2E Aggregated Logons"),
        "{body}"
    );
    let (status, body) = call(
        &router,
        "GET",
        &format!("{P}/mitre/coverage"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tactics"].as_array().unwrap().len(), 3, "{body}");

    // A fresh cache is not fetched again.
    let before = gh.received_requests().await.unwrap().len();
    copilot_searches::refresher::refresh_catalog_caches(&st).await;
    assert_eq!(
        gh.received_requests().await.unwrap().len(),
        before,
        "TTL respected"
    );
    assert!(!st.caches.is_stale(Kind::Rules) && !st.caches.is_stale(Kind::Mitre));

    // The Wazuh ruleset and the firing counts load in the background: the
    // first look answers at once, empty.
    let (status, body) = call(
        &router,
        "GET",
        &format!("{P}/catalog/wazuh-rules"),
        &portal,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], json!(0), "{body}");
    let (_, stats) = call(&router, "GET", &format!("{P}/catalog/stats"), &portal, None).await;
    assert_eq!(stats["loading"], json!(true), "{stats}");
    let mut loaded = false;
    for _ in 0..100 {
        let (_, stats) = call(&router, "GET", &format!("{P}/catalog/stats"), &portal, None).await;
        if stats["loading"] == json!(false) {
            loaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(loaded, "the background refresh finishes");
    let (_, body) = call(
        &router,
        "GET",
        &format!("{P}/catalog/wazuh-rules"),
        &portal,
        None,
    )
    .await;
    assert_eq!(body["total"], json!(3), "{body}");
    let hot = body["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(5710))
        .unwrap();
    assert_eq!(hot["hits_30d"], json!(12), "{body}");
    assert_eq!(body["firing_stats_available"], json!(true), "{body}");

    // A customer's slice: their own customer only, unless deployment-wide.
    let (status, body) = call(
        &router,
        "GET",
        &format!("{P}/catalog/wazuh-rules?customer_code={acme}"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["customer_code"], json!(acme), "{body}");
    let hot = body["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(5712))
        .unwrap();
    assert_eq!(
        hot["hits_30d"],
        json!(2),
        "uncached per-customer slice: {body}"
    );
    let (status, _) = call(
        &router,
        "GET",
        &format!("{P}/catalog/wazuh-rules?customer_code={beta}"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &router,
        "GET",
        &format!("{P}/catalog/wazuh-rules?customer_code={beta}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, 200);

    // The logtest goes through the manager, not the admin-only route.
    let (status, body) = call(
        &router,
        "POST",
        &format!("{P}/catalog/wazuh-rules/test"),
        &portal,
        Some(json!({"event": "sshd: invalid user"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        (body["matched"].clone(), body["rule"]["id"].clone()),
        (json!(true), json!(5710))
    );

    // Custom repositories: the tenant's own pointer, the token never shown.
    let cr = format!("{P}/custom-repos");
    let (status, _) = call(
        &router,
        "PUT",
        &format!("{cr}/{beta}"),
        &analyst,
        Some(json!({"repo": "x/y"})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, body) = call(
        &router,
        "PUT",
        &format!("{cr}/{acme}"),
        &analyst,
        Some(json!({"repo": " acme-org/rules ", "token": "secret-token"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["repo"]["has_token"], json!(true), "{body}");
    assert!(!body.to_string().contains("secret-token"));
    let (status, _) = call(
        &router,
        "PUT",
        &format!("{cr}/{beta}"),
        &admin,
        Some(json!({"repo": "beta-org/rules", "enabled": false})),
    )
    .await;
    assert_eq!(status, 200);
    let stored = buckets.lock().unwrap()["copilot-searches"].clone();
    let record: Value =
        serde_json::from_slice(&stored[&format!("custom-repos/{acme}.json")]).unwrap();
    assert_eq!(
        record,
        json!({"customer_code": acme, "repo": "acme-org/rules", "branch": "main",
            "token": "secret-token", "enabled": true})
    );
    let (_, body) = call(&router, "GET", &cr, &admin, None).await;
    assert_eq!(body["repos"].as_array().map(Vec::len), Some(2), "{body}");
    let (_, body) = call(&router, "GET", &cr, &analyst, None).await;
    let codes: Vec<&str> = body["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["customer_code"].as_str().unwrap())
        .collect();
    assert_eq!(
        codes,
        [acme.as_str()],
        "§4: a scoped caller lists their customers' pointers"
    );

    // A refresh pulls the enabled custom repository with its own token.
    let (status, body) = call(&router, "POST", &format!("{P}/refresh"), &analyst, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["rules_loaded"].as_i64().unwrap(), total + 1, "{body}");
    let custom = requests_to(&gh, "GET", "/repos/acme-org/rules/git/trees/main").await;
    assert_eq!(custom.len(), 1);
    assert_eq!(
        custom[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer secret-token"
    );
    assert!(
        requests_to(&gh, "GET", "/repos/beta-org/").await.is_empty(),
        "disabled"
    );
    let (_, body) = call(
        &router,
        "GET",
        &format!("{P}/id/acme-custom-0001"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(body["rule"]["provenance"], json!("custom"), "{body}");
    assert_eq!(body["rule"]["owner_customer_code"], json!(acme), "{body}");
    // §4: a caller scoped to another customer sees the shared rules only
    // (Python listed every tenant's custom rules to everyone): the
    // responder, moved to beta, reads acme's custom rule as missing.
    h.exec(&format!(
        "UPDATE user_customer_access SET customer_code = '{beta}' WHERE user_id = (SELECT id \
         FROM `user` WHERE username = 'responder{}')",
        h.suffix
    ))
    .await;
    let other = h.token(&format!("responder{}", h.suffix), "analyst");
    let (status, body) = call(
        &router,
        "GET",
        &format!("{P}/id/acme-custom-0001"),
        &other,
        None,
    )
    .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (404, json!("Rule with ID 'acme-custom-0001' not found"))
    );
    for (token, want) in [(&other, total), (&analyst, total + 1), (&admin, total + 1)] {
        let (_, body) = call(&router, "GET", &format!("{P}?limit=500"), token, None).await;
        assert_eq!(body["total"].as_i64().unwrap(), want, "{body}");
        let (_, body) = call(&router, "GET", &format!("{P}/stats"), token, None).await;
        assert_eq!(body["total_rules"].as_i64().unwrap(), want, "{body}");
    }
    let (_, body) = call(
        &router,
        "POST",
        &format!("{P}/by-ids"),
        &other,
        Some(json!({"ids": ["acme-custom-0001"]})),
    )
    .await;
    assert_eq!(body["missing"], json!(["acme-custom-0001"]), "{body}");

    // §4: a body customer the caller may not see is refused before anything
    // is sent.
    let before_gl = gl.received_requests().await.unwrap().len();
    let before_gh = gh.received_requests().await.unwrap().len();
    for (route, body) in [
        ("backtest", json!({"yaml": AGG_RULE, "customer_code": beta})),
        ("publish", json!({"yaml": AGG_RULE, "customer_code": beta})),
        (
            "custom-repos/test",
            json!({"repo": "x/y", "customer_code": beta}),
        ),
    ] {
        let (status, resp) = call(
            &router,
            "POST",
            &format!("{P}/{route}"),
            &analyst,
            Some(body),
        )
        .await;
        assert_eq!(status, 403, "{route}: {resp}");
        assert_eq!(
            resp["message"],
            json!(format!("Access denied to customer {beta}"))
        );
    }
    assert_eq!(gl.received_requests().await.unwrap().len(), before_gl);
    assert_eq!(gh.received_requests().await.unwrap().len(), before_gh);

    // The backtest of the caller's own customer searches its stream.
    let (status, body) = call(
        &router,
        "POST",
        &format!("{P}/backtest"),
        &analyst,
        Some(json!({"yaml": AGG_RULE, "customer_code": acme, "range_seconds": 86400})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["total_hits"], json!(6), "{body}");
    let search = requests_to(&gl, "POST", "/api/search/messages").await;
    let sent: Value = serde_json::from_slice(&search[0].body).unwrap();
    assert_eq!(sent["streams"], json!([STREAM]));
    let (_, body) = call(
        &router,
        "POST",
        &format!("{P}/backtest"),
        &admin,
        Some(json!({"yaml": AGG_RULE, "customer_code": beta})),
    )
    .await;
    assert_eq!(
        body["message"],
        json!(format!(
            "Customer '{beta}' has no Graylog stream configured."
        )),
        "{body}"
    );

    // Publishing to the tenant's repository commits with its token.
    let (status, body) = call(
        &router,
        "POST",
        &format!("{P}/publish"),
        &analyst,
        Some(json!({"yaml": AGG_RULE.replace("id: e2e-agg-0001\n", "id: 0f8b2b0e-1a2b-4c3d-9e8f-001122334455\nversion: 1\nschema_version: '1.0'\n"), "customer_code": acme})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["action"], json!("created"), "{body}");
    let put = requests_to(&gh, "PUT", "/repos/acme-org/rules/contents/").await;
    assert_eq!(put.len(), 1);
    assert_eq!(
        put[0].url.path(),
        "/repos/acme-org/rules/contents/detections/custom/e2e-aggregated-logons.yaml"
    );

    // Graylog 7: the event definition is wrapped in a CreateEntityRequest.
    let (status, body) = call(
        &router,
        "POST",
        &format!("{P}/provision/graylog"),
        &analyst,
        Some(json!({"rule_id": "e2e-agg-0001", "streams": ["s1"]})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["alert_title"],
        json!("E2E - AGGREGATED - LOGONS"),
        "{body}"
    );
    let created = requests_to(&gl, "POST", "/api/events/definitions").await;
    let sent: Value = serde_json::from_slice(&created[0].body).unwrap();
    assert_eq!(sent["share_request"], Value::Null);
    assert_eq!(sent["entity"]["config"]["type"], json!("aggregation-v1"));
    assert_eq!(
        sent["entity"]["config"]["series"][0]["type"],
        json!("count")
    );

    // Deleting a pointer removes its object.
    let (status, _) = call(&router, "DELETE", &format!("{cr}/{acme}"), &analyst, None).await;
    assert_eq!(status, 200);
    let (status, _) = call(&router, "DELETE", &format!("{cr}/{beta}"), &admin, None).await;
    assert_eq!(status, 200);
    assert!(buckets.lock().unwrap()["copilot-searches"].is_empty());
    cleanup(&h).await;
}

#[tokio::test]
async fn wazuh_failures_degrade_the_catalog() {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return;
    }
    let gh = stand_in(FAILING).await;
    let mgr = stand_in(FAILING + 1).await;
    github(&gh).await;
    manager(&mgr, true).await;
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    connector(&h, "Wazuh-Manager", &mgr.uri()).await;
    // The indexer is a port nothing listens on.
    connector(
        &h,
        "Wazuh-Indexer",
        &format!("http://127.0.0.1:{}", port(FAILING + 2)),
    )
    .await;
    let (router, _) = catalog(&h, &gh);
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    let (status, body) = call(
        &router,
        "GET",
        &format!("{P}/catalog/wazuh-rules"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["available"], json!(true), "nothing tried yet: {body}");
    for _ in 0..100 {
        let (_, stats) = call(
            &router,
            "GET",
            &format!("{P}/catalog/stats"),
            &analyst,
            None,
        )
        .await;
        if stats["loading"] == json!(false) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (_, body) = call(
        &router,
        "GET",
        &format!("{P}/catalog/wazuh-rules"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(body["available"], json!(false), "{body}");
    assert!(body["unavailable_reason"].as_str().is_some(), "{body}");
    assert!(
        body["last_refresh"].as_str().is_some(),
        "a failure is a refresh: {body}"
    );
    assert_eq!(body["total"], json!(0), "{body}");
    assert_eq!(body["firing_stats_available"], json!(false), "{body}");
    let (status, body) = call(
        &router,
        "GET",
        &format!("{P}/catalog/wazuh-rules/5710"),
        &analyst,
        None,
    )
    .await;
    assert_eq!(status, 404, "{body}");
    cleanup(&h).await;
}
