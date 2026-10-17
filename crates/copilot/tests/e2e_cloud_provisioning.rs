//! End-to-end tests of the remaining provisioning — Office 365 and AWS
//! (`copilot-cloud-provisioning`, the deployed-AWS delete of
//! `copilot-integrations`), CrowdStrike, Defender for Endpoint and Bitdefender
//! (`copilot-integration-provisioning`), customer provisioning and the
//! Portainer Wazuh stack — through the production router on a real MySQL,
//! with the Wazuh manager, Graylog, Grafana, the indexer and the other
//! upstreams replaced by one stateful stand-in.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13310/copilot \
//!   cargo test -p copilot --test e2e_cloud_provisioning -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `CLOUD_PROVISIONING_E2E_PORT_BASE` (6831) and the
//! two ports after it (the third is AWS, reached through botocore's
//! `AWS_ENDPOINT_URL`). The connector rows a test points at them are replaced for
//! that test and restored (run single-threaded); seeded rows carry explicit
//! ids in 7850000–7859999 (the parity suite's are 7860000–7869999).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use http::StatusCode;
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, Request as WRequest, Respond, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

fn port(offset: u16) -> u16 {
    std::env::var("CLOUD_PROVISIONING_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6831)
        + offset
}

/// Whether the suite runs at all; checked before a stand-in binds a port.
fn configured() -> bool {
    std::env::var("COPILOT_TEST_DATABASE_URL").is_ok()
}

/// A stand-in on its port, retried while the previous test's server lets
/// the port go.
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

// --- the stand-in ----------------------------------------------------------------

/// One recorded request: method, path and query, body.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    body: Vec<u8>,
}

/// The tools' state.
#[derive(Debug, Default)]
struct World {
    seen: Vec<Seen>,
    /// The manager's ossec.conf.
    ossec: String,
    /// Whether a PUT of ossec.conf is refused (`error: 1`).
    refuse_ossec: bool,
    rules: Vec<Value>,
    pipelines: Vec<Value>,
    streams: Vec<Value>,
    index_sets: Vec<Value>,
    folders: Vec<Value>,
    datasources: Vec<Value>,
    counter: u32,
    /// `(method, path prefix)` → a fixed answer.
    fail: Vec<(String, String, u16, Value)>,
    /// The account STS answers for (AWS).
    aws_account: String,
}

#[derive(Clone)]
struct Tools(Arc<Mutex<World>>);

fn reply(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

impl Respond for Tools {
    fn respond(&self, req: &WRequest) -> ResponseTemplate {
        let mut w = self.0.lock().unwrap();
        let path = req.url.path().to_string();
        let target = match req.url.query() {
            Some(q) => format!("{path}?{q}"),
            None => path.clone(),
        };
        let method = req.method.to_string();
        w.seen.push(Seen {
            method: method.clone(),
            target,
            body: req.body.clone(),
        });
        for (m, prefix, status, body) in &w.fail {
            if *m == method && path.starts_with(prefix.as_str()) {
                return reply(*status, body.clone());
            }
        }
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        w.counter += 1;
        let n = w.counter;
        match (method.as_str(), path.as_str()) {
            // The Wazuh manager.
            ("GET", "/wazuh/security/user/authenticate") => {
                reply(200, json!({"data": {"token": "tok"}, "error": 0}))
            }
            ("GET", "/wazuh/manager/configuration") => ResponseTemplate::new(200)
                .set_body_raw(w.ossec.clone().into_bytes(), "application/xml"),
            ("PUT", "/wazuh/manager/configuration") => {
                if w.refuse_ossec {
                    return reply(
                        200,
                        json!({"data": {"total_failed_items": 1, "error": 1}, "error": 1}),
                    );
                }
                w.ossec = String::from_utf8(req.body.clone()).unwrap();
                reply(
                    200,
                    json!({"data": {"total_affected_items": 1, "error": 0}, "error": 0}),
                )
            }
            ("PUT", "/wazuh/manager/restart") => reply(200, json!({"data": {}, "error": 0})),
            ("GET", "/wazuh/manager/configuration/validation") => reply(
                200,
                json!({"data": {"affected_items": [{"name": "node01", "status": "OK"}],
                    "total_affected_items": 1, "total_failed_items": 0, "failed_items": []},
                    "message": "Validation was successfully checked", "error": 0}),
            ),
            ("GET", "/wazuh/manager/logs") => reply(
                200,
                json!({"data": {"affected_items": [], "total_affected_items": 0,
                    "total_failed_items": 0, "failed_items": []}, "error": 0}),
            ),
            // AWS: STS and the bucket (path-style, the endpoint override).
            ("POST", "/") => {
                let account = if w.aws_account.is_empty() {
                    "123456789012".to_string()
                } else {
                    w.aws_account.clone()
                };
                ResponseTemplate::new(200).set_body_raw(
                    format!(
                        "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>a</Arn>\
                         <UserId>u</UserId><Account>{account}</Account>\
                         </GetCallerIdentityResult></GetCallerIdentityResponse>"
                    )
                    .into_bytes(),
                    "text/xml",
                )
            }
            ("HEAD", AWS_BUCKET_PATH) => {
                ResponseTemplate::new(200).insert_header("x-amz-bucket-region", "eu-west-1")
            }
            ("GET", AWS_BUCKET_PATH) => {
                let contents = if req.url.query().unwrap_or_default().contains("delimiter") {
                    ""
                } else {
                    "<Contents><Key>AWSLogs/x.json.gz</Key><Size>9</Size></Contents>"
                };
                ResponseTemplate::new(200).set_body_raw(
                    format!("<ListBucketResult><EncodingType>url</EncodingType>{contents}</ListBucketResult>")
                        .into_bytes(),
                    "application/xml",
                )
            }
            ("GET", p) if p.starts_with("/e2e-aws-bucket/") => {
                ResponseTemplate::new(206).set_body_raw(b"x".to_vec(), "binary/octet-stream")
            }
            // Graylog.
            ("GET", "/graylog/api/system") => reply(200, json!({"version": "6.1.4"})),
            ("GET", "/graylog/api/system/pipelines/rule") => {
                reply(200, Value::Array(w.rules.clone()))
            }
            ("POST", "/graylog/api/system/pipelines/rule") => {
                let mut rule = body.clone();
                rule["id"] = json!(format!("rule-{n}"));
                rule["created_at"] = json!("2026-10-17T00:00:00.000Z");
                w.rules.push(rule.clone());
                reply(200, rule)
            }
            ("GET", "/graylog/api/system/pipelines/pipeline") => {
                reply(200, Value::Array(w.pipelines.clone()))
            }
            ("POST", "/graylog/api/system/pipelines/pipeline") => {
                let mut p = body.clone();
                p["id"] = json!(format!("pl-{n}"));
                p["created_at"] = json!("2026-10-17T00:00:00.000Z");
                p["stages"] = json!([]);
                w.pipelines.push(p.clone());
                reply(200, p)
            }
            ("POST", "/graylog/api/system/indices/index_sets") => {
                let mut is = body.clone();
                is["id"] = json!(format!("is-{n}"));
                is["can_be_default"] = json!(true);
                is["default"] = json!(false);
                is["rotation_strategy"]["max_rotation_period"] = Value::Null;
                w.index_sets.push(is.clone());
                reply(200, is)
            }
            ("POST", "/graylog/api/streams") => {
                let id = format!("st-{n}");
                w.streams.push(json!({"id": id, "title": body["title"]}));
                reply(201, json!({"stream_id": id}))
            }
            ("POST", "/graylog/api/system/pipelines/connections/to_stream") => reply(
                200,
                json!({"id": "conn", "stream_id": body["stream_id"], "pipeline_ids": body["pipeline_ids"]}),
            ),
            ("POST", p) if p.starts_with("/graylog/api/streams/") && p.ends_with("/resume") => {
                ResponseTemplate::new(204)
            }
            ("DELETE", p) if p.starts_with("/graylog/api/streams/") => {
                let id = p.trim_start_matches("/graylog/api/streams/");
                w.streams.retain(|s| s["id"] != json!(id));
                ResponseTemplate::new(204)
            }
            ("DELETE", p) if p.starts_with("/graylog/api/system/indices/index_sets/") => {
                let id = p.trim_start_matches("/graylog/api/system/indices/index_sets/");
                w.index_sets.retain(|s| s["id"] != json!(id));
                ResponseTemplate::new(204)
            }
            // Grafana.
            ("POST", p) if p.starts_with("/grafanaapi/user/using/") => {
                reply(200, json!({"message": "Active organization changed"}))
            }
            ("POST", "/grafanaapi/datasources") => {
                let uid = format!("ds-{n}");
                let mut ds = body.clone();
                ds["id"] = json!(n);
                ds["uid"] = json!(uid);
                ds["orgId"] = json!(7);
                ds["typeLogoUrl"] = json!("logo.svg");
                ds["user"] = json!("");
                ds["withCredentials"] = json!(false);
                ds["secureJsonFields"] = json!({"basicAuthPassword": true});
                ds["version"] = json!(1);
                w.datasources.push(ds.clone());
                reply(
                    200,
                    json!({"datasource": ds, "id": n, "message": "Datasource added", "name": body["name"]}),
                )
            }
            ("DELETE", p) if p.starts_with("/grafanaapi/datasources/uid/") => {
                let uid = p.trim_start_matches("/grafanaapi/datasources/uid/");
                w.datasources.retain(|d| d["uid"] != json!(uid));
                reply(200, json!({"message": "Data source deleted"}))
            }
            ("POST", "/grafanaapi/folders") => {
                let folder = json!({"id": 70 + n, "uid": format!("f-{n}"), "title": body["title"],
                    "url": "/dashboards/f", "hasAcl": false, "canSave": true, "canEdit": true,
                    "canAdmin": true, "canDelete": true, "createdBy": "admin",
                    "created": "2026-10-17T00:00:00Z", "updatedBy": "admin",
                    "updated": "2026-10-17T00:00:00Z", "version": 1});
                w.folders.push(folder.clone());
                reply(200, folder)
            }
            ("GET", "/grafanaapi/folders") => reply(200, Value::Array(w.folders.clone())),
            ("DELETE", p) if p.starts_with("/grafanaapi/folders/") => {
                let uid = p.trim_start_matches("/grafanaapi/folders/");
                w.folders.retain(|f| f["uid"] != json!(uid));
                reply(200, json!({"message": "Folder deleted", "id": 1}))
            }
            ("POST", "/grafanaapi/dashboards/db") => reply(
                200,
                json!({"id": n, "slug": "s", "status": "success", "uid": format!("d-{n}"),
                    "url": "/d/x", "version": 1}),
            ),
            // The Wazuh indexer.
            ("GET", "/_cluster/health") => reply(
                200,
                json!({
                    "active_primary_shards": 1, "active_shards": 1,
                    "active_shards_percent_as_number": 100.0, "cluster_name": "c",
                    "delayed_unassigned_shards": 0, "discovered_cluster_manager": true,
                    "discovered_master": true, "initializing_shards": 0, "number_of_data_nodes": 2,
                    "number_of_in_flight_fetch": 0, "number_of_nodes": 2, "number_of_pending_tasks": 0,
                    "relocating_shards": 0, "status": "green", "task_max_waiting_in_queue_millis": 0,
                    "timed_out": false, "unassigned_shards": 0
                }),
            ),
            ("GET", "/_nodes/_local") => {
                reply(200, json!({"nodes": {"n1": {"version": "2.19.1"}}}))
            }
            _ => reply(
                404,
                json!({"message": format!("no stand-in for {method} {path}")}),
            ),
        }
    }
}

impl Tools {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(World::default())))
    }

    fn with<T>(&self, f: impl FnOnce(&mut World) -> T) -> T {
        f(&mut self.0.lock().unwrap())
    }

    fn take(&self) -> Vec<Seen> {
        self.with(|w| std::mem::take(&mut w.seen))
    }
}

// --- connectors ------------------------------------------------------------------

/// A saved `connectors` row: id, name, url, username, password.
type ConnectorRow = (i64, String, Option<String>, Option<String>, Option<String>);

async fn set_connector(h: &Harness, name: &str, url: &str) -> Option<ConnectorRow> {
    let saved: Option<ConnectorRow> = sqlx::query_as(
        "SELECT id, connector_name, connector_url, connector_username, connector_password FROM \
         connectors WHERE connector_name = ? ORDER BY id LIMIT 1",
    )
    .bind(name)
    .fetch_optional(h.db.pool())
    .await
    .unwrap();
    match &saved {
        Some((id, ..)) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = 'e2e-user', \
                 connector_password = 'e2e-pass' WHERE id = ?",
            )
            .bind(url)
            .bind(id)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
        None => {
            sqlx::query(
                "INSERT INTO connectors (connector_name, connector_type, connector_url, \
                 connector_last_updated, connector_username, connector_password, \
                 connector_api_key, connector_description, connector_supports, \
                 connector_configured, connector_verified, connector_accepts_host_only, \
                 connector_accepts_api_key, connector_accepts_username_password, \
                 connector_accepts_file, connector_accepts_extra_data, connector_extra_data, \
                 connector_enabled) VALUES (?, '3', ?, UTC_TIMESTAMP(), 'e2e-user', 'e2e-pass', \
                 NULL, 'e2e', 'e2e', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
            )
            .bind(name)
            .bind(url)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
    }
    saved
}

async fn restore_connector(h: &Harness, name: &str, saved: Option<ConnectorRow>) {
    match saved {
        Some((id, _, url, user, pass)) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = ?, \
                 connector_password = ? WHERE id = ?",
            )
            .bind(url)
            .bind(user)
            .bind(pass)
            .bind(id)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
        None => {
            sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
                .bind(name)
                .execute(h.db.pool())
                .await
                .unwrap();
        }
    }
}

/// Connector id 1 (the datasources' indexer URL), as it was.
async fn point_id1(h: &Harness, url: &str) -> Option<ConnectorRow> {
    let saved: Option<ConnectorRow> = sqlx::query_as(
        "SELECT id, connector_name, connector_url, connector_username, connector_password FROM \
         connectors WHERE id = 1",
    )
    .fetch_optional(h.db.pool())
    .await
    .unwrap();
    if saved.is_some() {
        sqlx::query(
            "UPDATE connectors SET connector_url = ?, connector_username = 'e2e-user', \
             connector_password = 'e2e-pass' WHERE id = 1",
        )
        .bind(url)
        .execute(h.db.pool())
        .await
        .unwrap();
    } else {
        sqlx::query(
            "INSERT INTO connectors (id, connector_name, connector_type, connector_url, \
             connector_last_updated, connector_username, connector_password, connector_api_key, \
             connector_description, connector_supports, connector_configured, \
             connector_verified, connector_accepts_host_only, connector_accepts_api_key, \
             connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (1, \
             'Wazuh-Indexer', '3', ?, UTC_TIMESTAMP(), 'e2e-user', 'e2e-pass', NULL, 'e2e', \
             'e2e', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
        )
        .bind(url)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
    saved
}

async fn restore_id1(h: &Harness, saved: Option<ConnectorRow>) {
    match saved {
        Some(row) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = ?, \
                 connector_password = ? WHERE id = 1",
            )
            .bind(row.2)
            .bind(row.3)
            .bind(row.4)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
        None => {
            h.exec("DELETE FROM connectors WHERE id = 1").await;
        }
    }
}

/// The stand-ins and the connector rows pointed at them.
struct Env {
    tools: Tools,
    _main: MockServer,
    _indexer: MockServer,
    _aws: MockServer,
    saved: Vec<(&'static str, Option<ConnectorRow>)>,
    id1: Option<ConnectorRow>,
}

async fn env(h: &Harness) -> Env {
    let tools = Tools::new();
    let main = stand_in(0).await;
    let indexer = stand_in(1).await;
    let aws = stand_in(2).await;
    for server in [&main, &indexer, &aws] {
        Mock::given(wiremock::matchers::any())
            .respond_with(tools.clone())
            .mount(server)
            .await;
    }
    let id1 = point_id1(h, &indexer.uri()).await;
    let mut saved = Vec::new();
    for (name, url) in [
        ("Wazuh-Manager", format!("{}/wazuh", main.uri())),
        ("Graylog", format!("{}/graylog", main.uri())),
        ("Grafana", format!("{}/grafana", main.uri())),
        ("Wazuh-Indexer", indexer.uri()),
    ] {
        saved.push((name, set_connector(h, name, &url).await));
    }
    Env {
        tools,
        _main: main,
        _indexer: indexer,
        _aws: aws,
        saved,
        id1,
    }
}

async fn leave(h: &Harness, e: Env) {
    for (name, row) in e.saved.into_iter().rev() {
        if name == "Wazuh-Indexer" && row.as_ref().is_some_and(|r| r.0 == 1) {
            continue;
        }
        restore_connector(h, name, row).await;
    }
    restore_id1(h, e.id1).await;
}

// --- seeds -----------------------------------------------------------------------

/// One integration: `(id, service, instance, keys)`; the subscription takes
/// `id + 100`, the keys `id * 10 + i`.
async fn seed_integration(
    h: &Harness,
    code: &str,
    id: i64,
    service_id: i64,
    service: &str,
    instance: Option<&str>,
    keys: &[(&str, &str)],
) {
    sqlx::query(
        "INSERT IGNORE INTO integration_services (id, service_name, auth_type) VALUES (?, ?, 'API_KEY')",
    )
    .bind(service_id)
    .bind(service)
    .execute(h.db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO customer_integrations (id, customer_code, customer_name, \
         integration_service_id, integration_service_name, instance_name, deployed) VALUES (?, ?, \
         'Acme Corp', ?, ?, ?, 0)",
    )
    .bind(id)
    .bind(code)
    .bind(service_id)
    .bind(service)
    .bind(instance)
    .execute(h.db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) VALUES \
         (?, ?, ?)",
    )
    .bind(id + 100)
    .bind(id)
    .bind(service_id)
    .execute(h.db.pool())
    .await
    .unwrap();
    for (i, (k, v)) in keys.iter().enumerate() {
        sqlx::query(
            "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(id * 10 + i64::try_from(i).unwrap())
        .bind(id + 100)
        .bind(k)
        .bind(v)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

async fn unseed(h: &Harness, code: &str) {
    for sql in [
        "DELETE FROM integration_auth_keys WHERE id BETWEEN 78500000 AND 78599999",
        "DELETE FROM integration_subscriptions WHERE id BETWEEN 7850000 AND 7859999",
        "DELETE FROM customer_integrations WHERE id BETWEEN 7850000 AND 7859999",
        "DELETE FROM integration_services WHERE id BETWEEN 7850000 AND 7859999",
    ] {
        h.exec(sql).await;
    }
    for table in [
        "customer_integrations_meta",
        "customer_network_connectors_meta",
        "customersmeta",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE customer_code = ?"))
            .bind(code)
            .execute(h.db.pool())
            .await
            .unwrap();
    }
}

async fn seed_meta(h: &Harness, code: &str, org: &str) {
    sqlx::query(
        "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, \
         customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group) \
         VALUES (?, 'Acme Corp', 'i', 's', ?, 'g')",
    )
    .bind(code)
    .bind(org)
    .execute(h.db.pool())
    .await
    .unwrap();
}

fn lines(seen: &[Seen]) -> Vec<String> {
    seen.iter()
        .filter(|s| !s.target.ends_with("/security/user/authenticate"))
        .map(|s| format!("{} {}", s.method, s.target))
        .collect()
}

/// The AWS instance's bucket, as the stand-in serves it.
const AWS_BUCKET_PATH: &str = "/e2e-aws-bucket";

const OSSEC: &str = "<!-- Wazuh - Manager -->\n<ossec_config>\n  <global>\n    \
                     <jsonout_output>yes</jsonout_output>\n  </global>\n</ossec_config>\n";

// --- step 1: Office 365 ------------------------------------------------------------

#[tokio::test]
async fn office365_tenants_are_provisioned_and_rolled_back() {
    if !configured() {
        return;
    }
    let h = harness_or_skip!(None);
    let e = env(&h).await;
    h.seed().await;
    let code = h.code("acme");
    unseed(&h, &code).await;
    seed_meta(&h, &code, "7").await;
    let admin = h.token(&h.code("admin"), "admin");
    let analyst = h.token(&h.code("analyst"), "analyst");
    seed_integration(
        &h,
        &code,
        7_850_001,
        7_850_901,
        "Office365",
        None,
        &[
            ("TENANT_ID", "t-1"),
            ("CLIENT_ID", "c-1"),
            ("CLIENT_SECRET", "s-1"),
            ("API_TYPE", "commercial"),
        ],
    )
    .await;
    e.tools.with(|w| w.ossec = OSSEC.into());

    // No token; a list body (the before-validator's TypeError); another
    // tenant's customer (Rust only, §4).
    let (st, _) = h
        .call(
            "POST",
            "/api/office365/provision",
            None,
            Some(json!({"customer_code": code})),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = h
        .call(
            "POST",
            "/api/office365/provision",
            Some(&admin),
            Some(json!([1])),
        )
        .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    let beta = h.code("beta");
    let (st, body) = h
        .call(
            "POST",
            "/api/office365/provision",
            Some(&analyst),
            Some(json!({"customer_code": beta})),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
    assert!(e.tools.take().is_empty());

    // The first tenant: a new <office365> block, every Graylog and Grafana
    // object created, the rows written.
    let (st, body) = h
        .call(
            "POST",
            "/api/office365/provision",
            Some(&analyst),
            Some(json!({"customer_code": code, "integration_name": "ignored"})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"success": true,
            "message": format!("Successfully provisioned Office365 integration for customer {code}.")})
    );
    let seen = e.tools.take();
    let l = lines(&seen);
    assert_eq!(l[0], "GET /wazuh/manager/configuration?raw=True");
    assert_eq!(l[1], "PUT /wazuh/manager/configuration");
    assert_eq!(l[2], "PUT /wazuh/manager/restart");
    assert_eq!(l[3], "GET /graylog/api/system/pipelines/rule");
    assert_eq!(
        l.iter()
            .filter(|x| *x == "POST /graylog/api/system/pipelines/rule")
            .count(),
        6
    );
    assert!(l.contains(&"POST /graylog/api/system/pipelines/pipeline".to_string()));
    assert!(l.contains(&"POST /graylog/api/system/indices/index_sets".to_string()));
    assert!(l.contains(&"POST /grafanaapi/datasources".to_string()));
    assert!(l.contains(&"POST /grafanaapi/folders".to_string()));
    let pushed = e.tools.with(|w| w.ossec.clone());
    assert!(pushed.contains("<tenant_id>t-1</tenant_id>"), "{pushed}");
    assert!(pushed.contains("<office365>\n  <enabled>yes</enabled>"));
    assert!(
        !pushed.contains("Wazuh - Manager"),
        "comments dropped: {pushed}"
    );
    let ds = seen
        .iter()
        .find(|s| s.target == "/grafanaapi/datasources")
        .unwrap();
    let ds: Value = serde_json::from_slice(&ds.body).unwrap();
    assert_eq!(ds["name"], json!("O365"));
    assert_eq!(
        ds["database"],
        json!(format!("office365-{}*", code.to_lowercase()))
    );
    let link = ds["jsonData"]["dataLinks"][0]["url"].as_str().unwrap();
    assert!(
        link.contains("/explore?left=%7B%22datasource%22:%22O365%22"),
        "{link}"
    );
    let meta: (String, String, String) = sqlx::query_as(
        "SELECT graylog_index_id, graylog_stream_id, grafana_dashboard_folder_id FROM \
         customer_integrations_meta WHERE customer_code = ? AND integration_name = 'Office365'",
    )
    .bind(&code)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert!(
        meta.0.starts_with("is-") && meta.1.starts_with("st-"),
        "{meta:?}"
    );
    let deployed: Vec<(Option<bool>,)> =
        sqlx::query_as("SELECT deployed FROM customer_integrations WHERE customer_code = ?")
            .bind(&code)
            .fetch_all(h.db.pool())
            .await
            .unwrap();
    assert_eq!(deployed, vec![(Some(true),)]);
    let legacy: (Option<String>,) = sqlx::query_as(
        "SELECT customer_meta_office365_organization_id FROM customersmeta WHERE customer_code = ?",
    )
    .bind(&code)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(legacy.0.as_deref(), Some("t-1"));

    // The same tenant again: refused before anything changes.
    let (st, body) = h
        .call(
            "POST",
            "/api/office365/provision",
            Some(&admin),
            Some(json!({"customer_code": code})),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        json!(
            "Office365 deployment failed and was rolled back: Microsoft 365 tenant t-1 is already provisioned on the Wazuh manager."
        )
    );
    assert_eq!(
        lines(&e.tools.take()),
        ["GET /wazuh/manager/configuration?raw=True"]
    );

    // A second tenant: named instance, its api_auth block inserted, the
    // index set and Grafana reused; a Grafana failure is not reached.
    seed_integration(
        &h,
        &code,
        7_850_002,
        7_850_902,
        "Office365",
        Some("sub.onmicrosoft.com"),
        &[
            ("TENANT_ID", "t-2"),
            ("CLIENT_ID", "c-2"),
            ("CLIENT_SECRET", "s-2"),
            ("API_TYPE", "gcc"),
        ],
    )
    .await;
    // Several instances and none named: the 400.
    let (st, body) = h
        .call(
            "POST",
            "/api/office365/provision",
            Some(&admin),
            Some(json!({"customer_code": code})),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("Specify which one.")
    );
    // An unknown instance: the 404 naming it.
    let (st, body) = h
        .call(
            "POST",
            "/api/office365/provision",
            Some(&admin),
            Some(json!({"customer_code": code, "instance_name": "other.onmicrosoft.com"})),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        body["message"],
        json!(format!(
            "Office365 integration 'other.onmicrosoft.com' not found for customer {code}."
        ))
    );
    assert_eq!(lines(&e.tools.take()), Vec::<String>::new());
    // The name is stripped as `normalize_instance_name` strips it.
    let (st, body) = h
        .call(
            "POST",
            "/api/office365/provision",
            Some(&admin),
            Some(json!({"customer_code": code, "instance_name": " sub.onmicrosoft.com "})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body["message"],
        json!(format!(
            "Successfully provisioned Office365 integration for customer {code} (tenant sub.onmicrosoft.com)."
        ))
    );
    let l = lines(&e.tools.take());
    assert!(
        !l.iter()
            .any(|x| x.contains("index_sets") || x.contains("grafanaapi")),
        "{l:?}"
    );
    let pushed = e.tools.with(|w| w.ossec.clone());
    assert!(
        pushed.contains("<api_auth>\n   <tenant_id>t-2</tenant_id>"),
        "{pushed}"
    );
    assert!(pushed.contains("<tenant_id>t-1</tenant_id>"));

    // A failure after the manager was changed: everything this run created
    // is removed again, newest first, and the answer says so.
    sqlx::query("DELETE FROM customer_integrations_meta WHERE customer_code = ?")
        .bind(&code)
        .execute(h.db.pool())
        .await
        .unwrap();
    h.exec("UPDATE customer_integrations SET deployed = 0 WHERE id BETWEEN 7850000 AND 7859999")
        .await;
    e.tools.with(|w| {
        w.ossec = OSSEC.into();
        w.fail.push((
            "POST".into(),
            "/grafanaapi/folders".into(),
            409,
            json!({"message": "a folder with the same name already exists"}),
        ));
    });
    let (st, body) = h
        .call(
            "POST",
            "/api/office365/provision",
            Some(&admin),
            Some(json!({"customer_code": code, "instance_name": "sub.onmicrosoft.com"})),
        )
        .await;
    // Grafana's 409 is the answer's status (`GrafanaClientError.status_code`).
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    let message = body["message"].as_str().unwrap();
    assert!(
        message.starts_with("Office365 deployment failed and was rolled back: "),
        "{message}"
    );
    let l = lines(&e.tools.take());
    let at = l
        .iter()
        .position(|x| x == "POST /grafanaapi/folders")
        .unwrap();
    let undo: Vec<&String> = l[at + 1..].iter().collect();
    assert!(
        undo.iter()
            .any(|x| x.starts_with("DELETE /grafanaapi/datasources/uid/")),
        "{undo:?}"
    );
    assert!(
        undo.iter()
            .any(|x| x.starts_with("DELETE /graylog/api/streams/"))
    );
    assert!(
        undo.iter()
            .any(|x| x.starts_with("DELETE /graylog/api/system/indices/index_sets/"))
    );
    assert_eq!(undo.last().unwrap().as_str(), "PUT /wazuh/manager/restart");
    assert!(!e.tools.with(|w| w.ossec.contains("t-2")));
    let left: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM customer_integrations_meta WHERE customer_code = ?")
            .bind(&code)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(left.0, 0);

    // The manager refusing both pushes is only logged (Python's quirk).
    e.tools.with(|w| {
        w.fail.clear();
        w.refuse_ossec = true;
        w.ossec = OSSEC.into();
    });
    let (st, body) = h
        .call(
            "POST",
            "/api/office365/provision",
            Some(&admin),
            Some(json!({"customer_code": code, "instance_name": "sub.onmicrosoft.com"})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let puts = lines(&e.tools.take())
        .into_iter()
        .filter(|x| x == "PUT /wazuh/manager/configuration")
        .count();
    assert_eq!(puts, 2);

    unseed(&h, &code).await;
    leave(&h, e).await;
}

// --- step 2: AWS --------------------------------------------------------------------

/// The harness with botocore's endpoint override on the AWS stand-in and a
/// short watch of the manager's log after a restart.
fn aws_env_lines() -> String {
    format!(
        "AWS_ENDPOINT_URL=http://127.0.0.1:{}\nCOPILOT_AWS_PROFILE_CHECK_SECONDS=0.05,0.2\n",
        port(2)
    )
}

async fn set_key(h: &Harness, id: i64, value: &str) {
    sqlx::query("UPDATE integration_auth_keys SET auth_value = ? WHERE id = ?")
        .bind(value)
        .bind(id)
        .execute(h.db.pool())
        .await
        .unwrap();
}

async fn aws_meta(h: &Harness, code: &str) -> Vec<(String, String, Option<String>, String)> {
    sqlx::query_as(
        "SELECT graylog_index_id, graylog_stream_id, grafana_datasource_uid, \
         grafana_dashboard_folder_id FROM customer_integrations_meta WHERE customer_code = ? AND \
         integration_name = 'AWS'",
    )
    .bind(code)
    .fetch_all(h.db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn aws_accounts_are_validated_provisioned_resynced_and_deleted() {
    if !configured() {
        return;
    }
    let extra = aws_env_lines();
    let h = harness_or_skip!(None, &extra);
    let e = env(&h).await;
    h.seed().await;
    let code = h.code("acme");
    let beta = h.code("beta");
    unseed(&h, &code).await;
    unseed(&h, &beta).await;
    seed_meta(&h, &code, "7").await;
    let admin = h.token(&h.code("admin"), "admin");
    let analyst = h.token(&h.code("analyst"), "analyst");
    e.tools.with(|w| w.ossec = OSSEC.into());
    let provision = |who: &str, body: Value| {
        let who = who.to_string();
        let h = &h;
        async move {
            h.call("POST", "/api/aws/provision", Some(&who), Some(body))
                .await
        }
    };

    // No token; another tenant's customer (Python's own check); no
    // integration at all.
    let (st, _) = h
        .call(
            "POST",
            "/api/aws/provision",
            None,
            Some(json!({"customer_code": code})),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = provision(&analyst, json!({"customer_code": beta})).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, body) = provision(&analyst, json!({"customer_code": code})).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        body["message"],
        json!("Customer integration settings not found.")
    );

    // Keys Pydantic refuses: every bad field named.
    seed_integration(
        &h,
        &code,
        7_850_011,
        7_850_911,
        "AWS",
        None,
        &[
            ("ACCESS_KEY_ID", "AKIAE2E0000000000000"),
            ("SECRET_ACCESS_KEY", "e2e/secret"),
            ("AWS_ACCOUNT_ID", "123456789012"),
            ("BUCKET_NAME", "Bad_Bucket"),
            ("SERVICES", "cloudtrail,guardduty"),
        ],
    )
    .await;
    let (st, body) = provision(&admin, json!({"customer_code": code})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        json!(
            "The AWS integration's auth keys are not valid: BUCKET_NAME: Value error, BUCKET_NAME is not a valid S3 bucket name."
        )
    );
    set_key(&h, 78_500_113, "e2e-aws-bucket").await;

    // The key belongs to another account: refused before anything changes.
    e.tools.with(|w| w.aws_account = "999999999999".into());
    let (st, body) = provision(&admin, json!({"customer_code": code})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        json!(
            "AWS validation failed, nothing was changed: The access key belongs to AWS account 999999999999, not AWS_ACCOUNT_ID 123456789012. Correct AWS_ACCOUNT_ID or use a key from that account."
        )
    );
    assert_eq!(lines(&e.tools.take()), ["POST /"]);
    e.tools.with(|w| w.aws_account.clear());

    // A failure after the manager was changed: rolled back newest-first.
    e.tools.with(|w| {
        w.fail.push((
            "POST".into(),
            "/grafanaapi/folders".into(),
            409,
            json!({"message": "a folder with the same name already exists"}),
        ));
    });
    let (st, body) = provision(&admin, json!({"customer_code": code})).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("AWS deployment failed and was rolled back: "),
        "{body}"
    );
    let l = lines(&e.tools.take());
    // The pipeline rules are created, and not undone (as in Python).
    assert_eq!(
        l.iter()
            .filter(|x| *x == "POST /graylog/api/system/pipelines/rule")
            .count(),
        7
    );
    let at = l
        .iter()
        .position(|x| x == "POST /grafanaapi/folders")
        .unwrap();
    let undo = &l[at + 1..];
    assert_eq!(
        undo.iter()
            .filter(|x| x.starts_with("DELETE /graylog/api/streams/"))
            .count(),
        2,
        "{undo:?}"
    );
    assert_eq!(
        undo.iter()
            .filter(|x| x.starts_with("DELETE /graylog/api/system/indices/index_sets/"))
            .count(),
        2
    );
    assert_eq!(undo.last().unwrap(), "PUT /wazuh/manager/restart");
    assert!(!e.tools.with(|w| w.ossec.contains("e2e-aws-bucket")));
    assert!(aws_meta(&h, &code).await.is_empty());

    // Deployed: the buckets, a stream and an index set per service, the
    // folder and the datasources, the row, `deployed`.
    e.tools.with(|w| w.fail.clear());
    let (st, body) = provision(&admin, json!({"customer_code": code, "instance_name": " "})).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body["message"],
        json!(format!(
            "Successfully provisioned AWS cloudtrail, guardduty for customer {code}."
        ))
    );
    assert_eq!(body["warnings"], json!([]));
    assert_eq!(body["aws_config"]["detected"], json!(false));
    assert_eq!(
        body["aws_config"]["contents"],
        json!("[default]\nregion = eu-west-1\n")
    );
    let l = lines(&e.tools.take());
    assert_eq!(l[0], "POST /");
    assert_eq!(l[1], "HEAD /e2e-aws-bucket");
    assert!(l.contains(&"PUT /wazuh/manager/configuration".to_string()));
    assert!(l.contains(&"GET /wazuh/manager/configuration/validation".to_string()));
    assert!(!l.contains(&"POST /graylog/api/system/pipelines/rule".to_string()));
    assert_eq!(
        l.iter()
            .filter(|x| *x == "POST /grafanaapi/datasources")
            .count(),
        2
    );
    let ossec = e.tools.with(|w| w.ossec.clone());
    assert!(ossec.contains("<wodle name=\"aws-s3\">"), "{ossec}");
    assert_eq!(ossec.matches("<name>e2e-aws-bucket</name>").count(), 2);
    let meta = aws_meta(&h, &code).await;
    assert_eq!(meta.len(), 1);
    assert!(meta[0].0.starts_with("cloudtrail:is-"), "{meta:?}");
    assert!(meta[0].1.contains(",guardduty:st-"), "{meta:?}");
    let deployed: (Option<bool>,) =
        sqlx::query_as("SELECT deployed FROM customer_integrations WHERE id = 7850011")
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(deployed.0, Some(true));

    // A re-sync with nothing to change: the manager is not written.
    let (st, body) = provision(&admin, json!({"customer_code": code})).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let l = lines(&e.tools.take());
    assert!(
        !l.contains(&"PUT /wazuh/manager/configuration".to_string()),
        "{l:?}"
    );
    assert!(
        !l.iter()
            .any(|x| x.contains("index_sets") || x == "POST /graylog/api/streams")
    );

    // GuardDuty dropped from SERVICES: its bucket goes, then its stream —
    // only its stream: Python reads the other ids off the row it just
    // rewrote, which no longer names GuardDuty.
    set_key(&h, 78_500_114, "cloudtrail").await;
    let (st, body) = provision(&admin, json!({"customer_code": code})).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body["message"],
        json!(format!(
            "Successfully provisioned AWS cloudtrail for customer {code}."
        ))
    );
    let l = lines(&e.tools.take());
    assert!(
        l.iter()
            .any(|x| x.starts_with("DELETE /graylog/api/streams/")),
        "{l:?}"
    );
    assert!(
        !l.iter()
            .any(|x| x.starts_with("DELETE /grafanaapi/datasources/uid/")
                || x.starts_with("DELETE /graylog/api/system/indices/"))
    );
    assert_eq!(
        e.tools
            .with(|w| w.ossec.matches("<name>e2e-aws-bucket</name>").count()),
        1
    );

    // The same account for another customer: refused.
    seed_integration(
        &h,
        &beta,
        7_850_012,
        7_850_912,
        "AWS",
        None,
        &[
            ("ACCESS_KEY_ID", "AKIAE2E0000000000000"),
            ("SECRET_ACCESS_KEY", "e2e/secret"),
            ("AWS_ACCOUNT_ID", "123456789012"),
            ("BUCKET_NAME", "other-bucket"),
            ("SERVICES", "cloudtrail"),
        ],
    )
    .await;
    let (st, body) = provision(&admin, json!({"customer_code": beta})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        json!(format!(
            "AWS account 123456789012 is already configured for customer {code}."
        ))
    );
    assert!(e.tools.take().is_empty());

    // The deployed instance deleted in Rust: its bucket off the manager, its
    // stream, the index set, datasource and folder (the customer's last
    // instance); the metadata row stays, as Python leaves it.
    let (st, body) = h
        .call(
            "DELETE",
            "/api/integrations/delete_integration",
            Some(&admin),
            Some(json!({"customer_code": code, "integration_name": "AWS"})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body["message"],
        json!(format!(
            "Customer integration {code} AWS successfully deleted."
        ))
    );
    let l = lines(&e.tools.take());
    assert!(
        l.iter()
            .any(|x| x.starts_with("DELETE /grafanaapi/folders/")),
        "{l:?}"
    );
    assert_eq!(l.last().unwrap(), "PUT /wazuh/manager/restart");
    assert!(!e.tools.with(|w| w.ossec.contains("e2e-aws-bucket")));
    assert_eq!(aws_meta(&h, &code).await.len(), 1);

    unseed(&h, &code).await;
    unseed(&h, &beta).await;
    leave(&h, e).await;
}
