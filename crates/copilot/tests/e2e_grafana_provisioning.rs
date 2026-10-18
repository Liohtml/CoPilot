//! End-to-end tests of the Grafana dashboard provisioning
//! (`copilot-grafana-dashboards`) and of the integration and network-connector
//! provisioning built on it (`copilot-integration-provisioning`), through the
//! production router on a real MySQL, with Grafana, Graylog, the Wazuh
//! indexer and the Python backend replaced by local stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13308/copilot \
//!   cargo test -p copilot --test e2e_grafana_provisioning -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `GRAFANA_PROVISIONING_E2E_PORT_BASE` (6410) and the
//! four ports after it. The connector rows a test points at them are replaced
//! for that test and restored (run single-threaded); seeded rows carry
//! explicit ids in 7640000–7649999 (the parity suite's are 7650000–7659999).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::StatusCode;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const GRAFANA: u16 = 0;

fn port(offset: u16) -> u16 {
    std::env::var("GRAFANA_PROVISIONING_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6410)
        + offset
}

/// Whether the suite runs at all; checked before a stand-in binds a port, so
/// that `cargo test --workspace` (parallel, no database) never races for one.
fn configured() -> bool {
    std::env::var("COPILOT_TEST_DATABASE_URL").is_ok()
}

/// A stand-in on its port, retried while the previous test's server lets
/// the port go (wiremock closes its listener on its own thread).
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

// --- connectors ------------------------------------------------------------------

/// A saved `connectors` row: id, name, url, username, password.
type ConnectorRow = (i64, String, Option<String>, Option<String>, Option<String>);

/// Point connector `name` at `url` (updated in place when it exists, so its id
/// is kept); the row as it was, or `None` when there was none.
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

/// HTTP Basic for the stand-in connectors' `e2e-user` / `e2e-pass`.
const BASIC: &str = "Basic ZTJlLXVzZXI6ZTJlLXBhc3M=";

async fn grafana_ok(grafana: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/user/using/7"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "Active organization changed"})),
        )
        .mount(grafana)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/dashboards/db"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 41, "slug": "summary", "status": "success", "uid": "abc",
            "url": "/d/abc/summary", "version": 1, "folderUid": "f1"
        })))
        .mount(grafana)
        .await;
}

// --- step 1: dashboards --------------------------------------------------------------

#[tokio::test]
async fn dashboards_are_uploaded_as_python_uploads_them() {
    if !configured() {
        return;
    }
    let grafana = stand_in(GRAFANA).await;
    let h = harness_or_skip!(None);
    let saved = set_connector(&h, "Grafana", &grafana.uri()).await;
    h.seed().await;
    let admin = h.token(&h.code("admin"), "admin");
    grafana_ok(&grafana).await;

    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&admin),
            Some(json!({
                "dashboards": ["HUNTRESS_SUMMARY", "DUO_AUTH"],
                "organizationId": "7", "folderId": 12, "datasourceUid": "ds-1",
                "grafana_url": "https://grafana.example.com"
            })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let one = json!({"id": 41, "slug": "summary", "status": "success", "uid": "abc",
        "url": "/d/abc/summary", "version": 1});
    assert_eq!(
        body,
        json!({"provisioned_dashboards": [one, one], "success": true,
            "message": "All dashboards provisioned successfully"})
    );
    let sent = grafana.received_requests().await.unwrap();
    let paths: Vec<String> = sent
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect();
    assert_eq!(
        paths,
        [
            "POST /api/user/using/7",
            "POST /api/dashboards/db",
            "POST /api/user/using/7",
            "POST /api/dashboards/db"
        ]
    );
    for r in &sent {
        assert_eq!(
            r.headers.get("authorization").unwrap().to_str().unwrap(),
            BASIC
        );
        assert_eq!(
            r.headers.get("user-agent").unwrap().to_str().unwrap(),
            "grafana-client/5.1.0"
        );
    }
    // The switch has no body (`Content-Length: 0`); the upload is the edited
    // template as niquests writes `json=`.
    assert_eq!(sent[0].body, b"");
    assert_eq!(
        sent[1]
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json;charset=utf-8"
    );
    let upload: Value = serde_json::from_slice(&sent[1].body).unwrap();
    assert_eq!(upload["folderId"], json!(12));
    assert_eq!(upload["overwrite"], json!(true));
    let text = String::from_utf8(sent[1].body.clone()).unwrap();
    assert!(text.starts_with("{\"dashboard\": {"), "{}", &text[..40]);
    assert!(!text.contains("replace_datasource_uid"));
    assert!(text.contains("\"uid\": \"ds-1\""));

    // The customer-provisioning twin answers `ProvisionDashboardResponse`.
    let (st, body) = h
        .call(
            "POST",
            "/api/customer_provisioning/provision/dashboards",
            Some(&admin),
            Some(json!({
                "customer_name": "Acme",
                "dashboards_to_include": {"dashboards": ["MIMECAST_SUMMARY"], "organizationId": 99},
                "grafana_org_id": 7, "grafana_datasource_uid": "ds-2", "grafana_folder_id": 3,
                "grafana_url": "https://g.example.com"
            })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"message": "All dashboards provisioned successfully", "success": true})
    );
    restore_connector(&h, "Grafana", saved).await;
}

#[tokio::test]
async fn dashboard_failures_read_as_python_s() {
    if !configured() {
        return;
    }
    let grafana = stand_in(GRAFANA).await;
    let h = harness_or_skip!(None);
    let saved = set_connector(&h, "Grafana", &grafana.uri()).await;
    h.seed().await;
    let analyst = h.token(&h.code("analyst"), "analyst");
    // The analyst's customer holds Grafana organization 7; beta's is 8.
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    seed_meta(&h, &acme, "7").await;
    seed_meta(&h, &beta, "8").await;
    // Another tenant's organization, one no customer holds, and the default
    // (0) are refused before Grafana is asked (Python wrote into any).
    for (uri, body) in [
        (
            "/api/grafana/dashboards",
            json!({"dashboards": ["HUNTRESS_SUMMARY"], "organizationId": 8}),
        ),
        (
            "/api/grafana/dashboards",
            json!({"dashboards": ["HUNTRESS_SUMMARY"], "organizationId": "9"}),
        ),
        ("/api/grafana/dashboards", json!({"dashboards": []})),
        (
            "/api/customer_provisioning/provision/dashboards",
            json!({"customer_name": "x", "dashboards_to_include": {"dashboards": ["DUO_AUTH"]},
                "grafana_org_id": 8, "grafana_datasource_uid": "d", "grafana_folder_id": 1,
                "grafana_url": "https://g"}),
        ),
    ] {
        let org = body
            .get("organizationId")
            .or_else(|| body.get("grafana_org_id"))
            .map_or("0".to_string(), |v| {
                v.as_str().map_or(v.to_string(), String::from)
            });
        let (st, answer) = h.call("POST", uri, Some(&analyst), Some(body)).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{answer}");
        assert_eq!(
            answer["message"],
            json!(format!("Access denied to Grafana organization {org}"))
        );
    }
    // Validation comes first: an unknown dashboard is the 422, whatever the org.
    let (st, _) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": ["NOPE"], "organizationId": 8})),
        )
        .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(grafana.received_requests().await.unwrap().is_empty());
    Mock::given(method("POST"))
        .and(path("/api/user/using/7"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not found"})))
        .mount(&grafana)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": ["HUNTRESS_SUMMARY"], "organizationId": 7})),
        )
        .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body,
        json!({"success": false, "message":
            "Error updating dashboard: 500: Error updating dashboard: Client Error 404: Not found"})
    );
    // An unknown dashboard is the validator's 422; no token is a 401.
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": ["NOPE"]})),
        )
        .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["message"],
        json!("dashboards: Dashboard identifier \"NOPE\" is not recognized.")
    );
    let (st, _) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            None,
            Some(json!({"dashboards": []})),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // An empty list asks Grafana nothing.
    grafana.reset().await;
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": [], "organizationId": 7})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(grafana.received_requests().await.unwrap().is_empty());
    // Grafana's answer is validated outside the `except`: the 400 of the
    // `ValueError` handler.
    Mock::given(method("POST"))
        .and(path("/api/user/using/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "ok"})))
        .mount(&grafana)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/dashboards/db"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 1})))
        .mount(&grafana)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": ["DUO_AUTH"], "organizationId": 7})),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("5 validation errors for GrafanaDashboard\nslug\n")
    );
    restore_connector(&h, "Grafana", saved).await;
    // Without a Grafana connector row the client cannot be built.
    let saved = set_connector(&h, "Grafana", "x").await;
    h.exec("DELETE FROM connectors WHERE connector_name = 'Grafana'")
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": ["DUO_AUTH"], "organizationId": 7})),
        )
        .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body["message"],
        json!(
            "Error updating dashboard: 500: Error updating dashboard: 500: No Grafana connector \
             found in the database"
        )
    );
    if let Some(row) = saved {
        set_connector(&h, "Grafana", row.2.as_deref().unwrap_or_default()).await;
        restore_connector(&h, "Grafana", Some(row)).await;
    }
    h.exec(&format!(
        "DELETE FROM customersmeta WHERE customer_code IN ('{acme}', '{beta}')"
    ))
    .await;
}

// --- step 2: network connectors ------------------------------------------------------

const GRAYLOG: u16 = 1;
const INDEXER: u16 = 2;

/// Connector id 1 (the datasource's URL and credentials): the row as it was.
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

/// The tools of a provisioning request, pointed at the stand-ins.
struct World {
    grafana: MockServer,
    graylog: MockServer,
    indexer: MockServer,
    saved: Vec<(&'static str, Option<ConnectorRow>)>,
    id1: Option<ConnectorRow>,
}

async fn world(h: &Harness, graylog_connector: &'static str) -> World {
    let grafana = stand_in(GRAFANA).await;
    let graylog = stand_in(GRAYLOG).await;
    let indexer = stand_in(INDEXER).await;
    let id1 = point_id1(h, &indexer.uri()).await;
    let mut saved = Vec::new();
    for (name, url) in [
        ("Grafana", grafana.uri()),
        (graylog_connector, graylog.uri()),
        ("Wazuh-Indexer", indexer.uri()),
    ] {
        saved.push((name, set_connector(h, name, &url).await));
    }
    World {
        grafana,
        graylog,
        indexer,
        saved,
        id1,
    }
}

async fn leave(h: &Harness, w: World) {
    for (name, row) in w.saved.into_iter().rev() {
        if name == "Wazuh-Indexer" && row.as_ref().is_some_and(|r| r.0 == 1) {
            continue;
        }
        restore_connector(h, name, row).await;
    }
    restore_id1(h, w.id1).await;
}

fn listed_pack(name: &str, id: &str) -> Value {
    json!({"v": "1", "id": id, "rev": 1, "name": name, "summary": "s", "description": "d",
        "vendor": "v", "url": "https://example.com", "created_at": "2026-10-01T00:00:00.000Z",
        "server_version": "6.1.4", "parameters": [], "entities": []})
}

fn index_set_answer(body: &Value, id: &str) -> Value {
    let mut out = body.clone();
    let m = out.as_object_mut().unwrap();
    m.insert("id".into(), json!(id));
    m.insert("can_be_default".into(), json!(true));
    m.insert("default".into(), json!(false));
    m["rotation_strategy"]
        .as_object_mut()
        .unwrap()
        .insert("max_rotation_period".into(), Value::Null);
    out
}

/// What Graylog, the indexer and Grafana answer for a whole provisioning.
async fn tools_ok(w: &World, customer: &str, tag: &str) {
    use wiremock::Request as WRequest;
    let g = &w.graylog;
    Mock::given(method("GET"))
        .and(path("/api/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "facility": "graylog-server", "codename": "Noir", "node_id": "n",
            "cluster_id": "c", "version": "6.1.4+5c0f8a1", "started_at": "2026-10-01T00:00:00.000Z",
            "hostname": "graylog", "lifecycle": "running", "lb_status": "alive",
            "timezone": "UTC", "operating_system": "Linux", "is_processing": true
        })))
        .mount(g)
        .await;
    let input_pack = if tag == "FORTINET" {
        format!("{customer}_FORTINET_INPUT_SYSLOG_TCP")
    } else {
        format!("{customer}_{tag}_INPUT_SYSLOG_TLS")
    };
    Mock::given(method("GET"))
        .and(path("/api/system/content_packs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 2,
            "content_packs": [
                listed_pack(&format!("{customer}_{tag}_STREAM"), "cp-stream"),
                listed_pack(&input_pack, "cp-input"),
            ],
            "content_packs_metadata": {}
        })))
        .mount(g)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/content_packs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "x", "rev": 1})))
        .mount(g)
        .await;
    Mock::given(method("POST"))
        .and(wiremock::matchers::path_regex(
            r"^/api/system/content_packs/[^/]+/1/installations$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"installation": {}})))
        .mount(g)
        .await;
    let stream_title = match tag {
        "FORTINET" => "FORTINET LOGS AND EVENTS",
        "SONICWALL" => "SONICWALL LOGS AND EVENTS",
        _ => "SENTINELONE ALERTS AND EVENTS",
    };
    let input_title = match tag {
        "FORTINET" => "FORTINET LOGS AND EVENTS",
        "SONICWALL" => "SONICWALL FIREWALL LOGS AND EVENTS - TLS",
        _ => "SENTINELONE ALERTS AND EVENTS",
    };
    Mock::given(method("GET"))
        .and(path("/api/streams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "streams": [{"id": "st-0", "title": "other"},
                {"id": "st-1", "title": format!("{customer} - {stream_title}")}],
            "total": 2
        })))
        .mount(g)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/indices/index_sets"))
        .respond_with(|r: &WRequest| {
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            ResponseTemplate::new(200).set_body_json(index_set_answer(&body, "is-1"))
        })
        .mount(g)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "inputs": [{"id": "in-1", "title": format!("{customer} - {input_title}")}],
            "total": 1
        })))
        .mount(g)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system/pipelines/pipeline"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "pl-0", "title": "W", "description": "Wazuh processing", "source": "s",
             "stages": [{"match": "EITHER", "rules": ["r"], "stage": 0}],
             "created_at": "2026-10-01T00:00:00.000Z", "modified_at": null, "errors": null},
            {"id": "pl-1", "title": "N", "description": format!("{tag} Processing Pipeline"),
             "source": "s", "stages": [], "created_at": "2026-10-01T00:00:00.000Z"}
        ])))
        .mount(g)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/streams/st-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "st-1"})))
        .mount(g)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/pipelines/connections/to_stream"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "conn-1", "stream_id": "st-1", "pipeline_ids": ["pl-1"]
        })))
        .mount(g)
        .await;
    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active_primary_shards": 1, "active_shards": 1,
            "active_shards_percent_as_number": 100.0, "cluster_name": "c",
            "delayed_unassigned_shards": 0, "discovered_cluster_manager": true,
            "discovered_master": true, "initializing_shards": 0, "number_of_data_nodes": 3,
            "number_of_in_flight_fetch": 0, "number_of_nodes": 3, "number_of_pending_tasks": 0,
            "relocating_shards": 0, "status": "green", "task_max_waiting_in_queue_millis": 0,
            "timed_out": false, "unassigned_shards": 0
        })))
        .mount(&w.indexer)
        .await;
    Mock::given(method("GET"))
        .and(path("/_nodes/_local"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "nodes": {"n1": {"version": "2.19.1"}, "n2": {"version": "2.18.0"}}
        })))
        .mount(&w.indexer)
        .await;
    grafana_ok(&w.grafana).await;
    Mock::given(method("POST"))
        .and(path("/api/datasources"))
        .respond_with(|r: &WRequest| {
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({
                "datasource": {"id": 3, "uid": "ds-uid", "orgId": 7, "name": body["name"],
                    "type": body["type"], "typeLogoUrl": "x", "access": "proxy",
                    "url": body["url"], "user": "", "database": body["database"],
                    "basicAuth": true, "basicAuthUser": body["basicAuthUser"],
                    "withCredentials": false, "isDefault": false,
                    "jsonData": {"database": body["database"], "flavor": "opensearch",
                        "includeFrozen": false, "logLevelField": "severity",
                        "logMessageField": "summary", "maxConcurrentShardRequests": 5,
                        "timeField": "timestamp", "tlsSkipVerify": true, "version": "2.19.1"},
                    "secureJsonFields": {"basicAuthPassword": true}, "version": 1,
                    "readOnly": true},
                "id": 3, "message": "Datasource added", "name": body["name"]
            }))
        })
        .mount(&w.grafana)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/folders"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 12, "uid": "folder-uid", "title": tag, "url": "/dashboards/f/folder-uid",
            "hasAcl": false, "canSave": true, "canEdit": true, "canAdmin": true,
            "canDelete": true, "createdBy": "admin", "created": "2026-10-16T10:00:00Z",
            "updatedBy": "admin", "updated": "2026-10-16T10:00:00Z", "version": 1
        })))
        .mount(&w.grafana)
        .await;
}

/// The network connector `service` of `code`, with `keys`; ids from `base`.
async fn seed_network(h: &Harness, base: i64, code: &str, service: &str, keys: &[(&str, &str)]) {
    h.exec(&format!(
        "INSERT INTO network_connectors_services (id, service_name, auth_type) VALUES ({base}, \
         '{service}', 'Syslog')"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO customer_network_connectors (id, customer_code, customer_name, \
         network_connector_service_id, network_connector_service_name, deployed) VALUES \
         ({}, '{code}', 'acme corp', {base}, '{service}', 0)",
        base + 1
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO network_connectors_subscriptions (id, customer_id, \
         network_connectors_service_id) VALUES ({}, {}, {base})",
        base + 2,
        base + 1
    ))
    .await;
    for (i, (k, v)) in keys.iter().enumerate() {
        h.exec(&format!(
            "INSERT INTO network_connectors_keys (id, subscription_id, auth_key_name, auth_value) \
             VALUES ({}, {}, '{k}', '{v}')",
            base + 3 + i64::try_from(i).unwrap(),
            base + 2
        ))
        .await;
    }
}

async fn unseed_network(h: &Harness, code: &str) {
    for sql in [
        "DELETE FROM network_connectors_keys WHERE id BETWEEN 7640000 AND 7649999".into(),
        "DELETE FROM network_connectors_subscriptions WHERE id BETWEEN 7640000 AND 7649999".into(),
        "DELETE FROM customer_network_connectors WHERE id BETWEEN 7640000 AND 7649999".into(),
        "DELETE FROM network_connectors_services WHERE id BETWEEN 7640000 AND 7649999".into(),
        format!("DELETE FROM customer_network_connectors_meta WHERE customer_code = '{code}'"),
        format!("DELETE FROM customersmeta WHERE customer_code = '{code}'"),
    ] {
        h.exec(&sql).await;
    }
}

async fn seed_meta(h: &Harness, code: &str, org: &str) {
    h.exec(&format!(
        "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, \
         customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group) \
         VALUES ('{code}', 'acme corp', 'i', 's', '{org}', 'g')"
    ))
    .await;
}

fn sent_paths(requests: &[wiremock::Request]) -> Vec<String> {
    requests
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

#[tokio::test]
async fn network_connectors_are_provisioned_as_python_provisions_them() {
    if !configured() {
        return;
    }
    let h = harness_or_skip!(None);
    let w = world(&h, "Graylog-Network").await;
    h.seed().await;
    let acme = h.code("acme");
    let analyst = h.token(&h.code("analyst"), "analyst");
    seed_network(
        &h,
        7640100,
        &acme,
        "Fortinet",
        &[("SYSLOG_PORT", " +05_14")],
    )
    .await;
    seed_meta(&h, &acme, "7").await;
    tools_ok(&w, "acme corp", "FORTINET").await;

    let uri = "/api/stack_provisioning/graylog/provision/fortinet";
    let body = json!({"customer_code": acme, "tcp_enabled": true, "hot_data_retention": 30,
        "index_replicas": 1, "integration_name": "ignored"});
    let (st, answer) = h.call("POST", uri, Some(&analyst), Some(body)).await;
    assert_eq!(st, StatusCode::OK, "{answer}");
    assert_eq!(
        answer,
        json!({"success": true, "message": "Fortinet customer provisioned successfully"})
    );
    let sent = w.graylog.received_requests().await.unwrap();
    let packs = [
        "SOCFORTRESS_FORTINET_INPUT_SYSLOG_TCP",
        "SOCFORTRESS_FORTINET_PROCESSING_PIPELINE",
        "SOCFORTRESS_FORTINET_STREAM",
    ];
    let mut want = Vec::new();
    for (i, _) in packs.iter().enumerate() {
        want.push("GET /api/system/content_packs".to_string());
        want.push("POST /api/system/content_packs".to_string());
        if i == 0 {
            want.push("GET /api/system".to_string());
        }
        want.push("POST".to_string());
    }
    want.extend(
        [
            "GET /api/streams",
            "POST /api/system/indices/index_sets",
            "GET /api/system/content_packs",
            "GET /api/system/content_packs",
            "GET /api/system/inputs",
            "GET /api/system/pipelines/pipeline",
            "PUT /api/streams/st-1",
            "GET /api/system/pipelines/pipeline",
            "POST /api/system/pipelines/connections/to_stream",
        ]
        .map(String::from),
    );
    let got = sent_paths(&sent);
    assert_eq!(got.len(), want.len(), "{got:?}");
    for (g, w) in got.iter().zip(&want) {
        assert!(g.starts_with(w.as_str()), "{got:?}");
    }
    for r in &sent {
        assert_eq!(r.headers.get("authorization").unwrap(), BASIC);
        assert_eq!(r.headers.get("x-requested-by").unwrap(), "CoPilot");
    }
    // The inserted packs: keywords replaced, the port an int, fresh UUIDs.
    let inserted: Vec<Value> = sent
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/api/system/content_packs")
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect();
    assert_eq!(
        inserted[0]["name"],
        json!("acme corp_FORTINET_INPUT_SYSLOG_TCP")
    );
    let text = inserted[0].to_string();
    assert!(!text.contains("REPLACE_UUID") && !text.contains("SYSLOG_PORT"));
    assert!(text.contains("\"@value\":514"), "{text}");
    assert_ne!(inserted[0]["id"], inserted[2]["id"]);
    let install = sent
        .iter()
        .find(|r| r.url.path().ends_with("/installations"))
        .unwrap();
    assert_eq!(
        install.url.path(),
        format!(
            "/api/system/content_packs/{}/1/installations",
            inserted[0]["id"].as_str().unwrap()
        )
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&install.body).unwrap(),
        json!({"comment": "Installed by SOCFortress CoPilot"})
    );
    // The index set: daily, the body's retention and replicas, one shard per node.
    let index = sent
        .iter()
        .find(|r| r.url.path() == "/api/system/indices/index_sets")
        .unwrap();
    let index: Value = serde_json::from_slice(&index.body).unwrap();
    assert_eq!(index["title"], json!("acme corp - FORTINET EVENTS"));
    assert_eq!(index["index_prefix"], json!(format!("fortinet-{acme}")));
    assert_eq!(
        index["rotation_strategy"],
        json!({"type": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig",
            "rotation_period": "P1D"})
    );
    assert_eq!(
        index["retention_strategy"]["max_number_of_indices"],
        json!(30)
    );
    assert_eq!(
        (index["shards"].clone(), index["replicas"].clone()),
        (json!(3), json!(1))
    );
    let put = sent.iter().find(|r| r.method.as_str() == "PUT").unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&put.body).unwrap(),
        json!({"index_set_id": "is-1"})
    );
    let conn = sent.last().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&conn.body).unwrap(),
        json!({"stream_id": "st-1", "pipeline_ids": ["pl-1"]})
    );
    // Grafana: the datasource on connector id 1, the folder, three dashboards.
    let grafana = w.grafana.received_requests().await.unwrap();
    let mut want = vec!["POST /api/user/using/7", "POST /api/datasources"];
    want.extend(["POST /api/user/using/7", "POST /api/folders"]);
    for _ in 0..copilot_grafana_dashboards::templates::FORTINET
        .members
        .len()
    {
        want.extend(["POST /api/user/using/7", "POST /api/dashboards/db"]);
    }
    assert_eq!(sent_paths(&grafana), want);
    let ds: Value = serde_json::from_slice(&grafana[1].body).unwrap();
    assert_eq!(
        ds,
        json!({"name": "FORTINET", "type": "grafana-opensearch-datasource",
            "typeName": "OpenSearch", "access": "proxy", "url": w.indexer.uri(),
            "database": format!("fortinet-{acme}*"), "basicAuth": true,
            "basicAuthUser": "e2e-user", "secureJsonData": {"basicAuthPassword": "e2e-pass"},
            "isDefault": false, "jsonData": {"database": format!("fortinet-{acme}*"),
            "flavor": "opensearch", "version": "2.19.1", "includeFrozen": false,
            "logLevelField": "severity", "logMessageField": "summary",
            "maxConcurrentShardRequests": 5, "timeField": "timestamp", "tlsSkipVerify": true,
            "dataLinks": [{"field": "^data_vulnerability_cve$",
                "url": "https://nvd.nist.gov/vuln/detail"}]}, "readOnly": true})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&grafana[3].body).unwrap(),
        json!({"title": "FORTINET"})
    );
    let upload: Value = serde_json::from_slice(&grafana[5].body).unwrap();
    assert_eq!(upload["folderId"], json!(12));
    // The meta row and the flag.
    let meta: (
        String,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ) = sqlx::query_as(
        "SELECT network_connector_name, graylog_input_id, graylog_index_id, \
             graylog_stream_id, graylog_pipeline_id, graylog_content_pack_input_id, \
             graylog_content_pack_stream_id, grafana_org_id, grafana_dashboard_folder_id, \
             grafana_datasource_uid FROM customer_network_connectors_meta WHERE customer_code = ?",
    )
    .bind(&acme)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        meta,
        (
            "FORTINET".into(),
            Some("in-1".into()),
            "is-1".into(),
            "st-1".into(),
            "pl-1".into(),
            "cp-input".into(),
            "cp-stream".into(),
            "7".into(),
            "folder-uid".into(),
            "ds-uid".into()
        )
    );
    let deployed = h
        .scalar_i64("SELECT deployed FROM customer_network_connectors WHERE id = 7640101")
        .await;
    assert_eq!(deployed, 1);

    // Another tenant's customer is refused before anything is asked (Python
    // provisioned it).
    w.graylog.reset().await;
    let beta = h.code("beta");
    let (st, answer) = h
        .call(
            "POST",
            uri,
            Some(&analyst),
            Some(json!({"customer_code": beta, "tcp_enabled": true,
                "hot_data_retention": 30, "index_replicas": 1})),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{answer}");
    assert!(w.graylog.received_requests().await.unwrap().is_empty());
    // Python's refusals, in its order.
    let admin = h.token(&h.code("admin"), "admin");
    for (body, status, message) in [
        (
            json!({"customer_code": beta, "hot_data_retention": 1, "index_replicas": 1}),
            StatusCode::NOT_FOUND,
            json!("Customer integration settings not found."),
        ),
        (
            json!({"customer_code": acme, "tcp_enabled": true, "udp_enabled": true,
                "hot_data_retention": 1, "index_replicas": 1}),
            StatusCode::BAD_REQUEST,
            json!("Both TCP and UDP are enabled. Please choose one of them."),
        ),
        (
            json!({"customer_code": acme, "tcp_enabled": null, "hot_data_retention": 1,
                "index_replicas": 1}),
            StatusCode::BAD_REQUEST,
            json!("Either TCP or UDP should be enabled."),
        ),
    ] {
        let (st, answer) = h.call("POST", uri, Some(&admin), Some(body)).await;
        assert_eq!(st, status, "{answer}");
        assert_eq!(answer["message"], message);
    }
    // SonicWall's keys are read TLS first: a missing one is the bare 500.
    let (st, _) = h
        .call(
            "POST",
            "/api/stack_provisioning/graylog/provision/sonicwall",
            Some(&admin),
            Some(json!({"customer_code": acme, "hot_data_retention": 1, "index_replicas": 1})),
        )
        .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    // A body that is not an object fails the `mode="before"` validator.
    let (st, _) = h.call("POST", uri, Some(&admin), Some(json!([1]))).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    let (st, answer) = h
        .call(
            "POST",
            uri,
            Some(&admin),
            Some(json!({"customer_code": acme})),
        )
        .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert!(w.graylog.received_requests().await.unwrap().is_empty());

    unseed_network(&h, &acme).await;
    leave(&h, w).await;
}

// --- step 3: integrations ------------------------------------------------------------

const LEGACY: u16 = 3;

/// `service` for `code`, with `keys`; ids from `base`.
async fn seed_integration(
    h: &Harness,
    base: i64,
    code: &str,
    service: &str,
    keys: &[(&str, &str)],
) {
    h.exec(&format!(
        "INSERT INTO integration_services (id, service_name, auth_type) VALUES ({base}, \
         '{service}', 'API_KEY')"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO customer_integrations (id, customer_code, customer_name, \
         integration_service_id, integration_service_name, deployed) VALUES ({}, '{code}', \
         'acme corp', {base}, '{service}', 0)",
        base + 1
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) VALUES \
         ({}, {}, {base})",
        base + 2,
        base + 1
    ))
    .await;
    for (i, (k, v)) in keys.iter().enumerate() {
        h.exec(&format!(
            "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) \
             VALUES ({}, {}, '{k}', '{v}')",
            base + 3 + i64::try_from(i).unwrap(),
            base + 2
        ))
        .await;
    }
}

async fn unseed_integrations(h: &Harness, code: &str) {
    for sql in [
        "DELETE FROM integration_auth_keys WHERE id BETWEEN 7640000 AND 7649999".to_string(),
        "DELETE FROM integration_subscriptions WHERE id BETWEEN 7640000 AND 7649999".into(),
        "DELETE FROM customer_integrations WHERE id BETWEEN 7640000 AND 7649999".into(),
        "DELETE FROM integration_services WHERE id BETWEEN 7640000 AND 7649999".into(),
        format!("DELETE FROM customer_integrations_meta WHERE customer_code = '{code}'"),
        format!("DELETE FROM customersmeta WHERE customer_code = '{code}'"),
    ] {
        h.exec(&sql).await;
    }
}

async fn streams_ok(w: &World) {
    Mock::given(method("POST"))
        .and(path("/api/streams"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"stream_id": "st-9"})))
        .mount(&w.graylog)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/streams/st-9/resume"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&w.graylog)
        .await;
}

#[tokio::test]
async fn integrations_are_provisioned_as_python_provisions_them() {
    if !configured() {
        return;
    }
    let legacy = stand_in(LEGACY).await;
    Mock::given(method("POST"))
        .and(path("/api/scheduler/provisioning_jobs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"success": true, "message": "Jobs added successfully"})),
        )
        .mount(&legacy)
        .await;
    let h = harness_or_skip!(Some(&legacy));
    let w = world(&h, "Graylog").await;
    h.seed().await;
    let acme = h.code("acme");
    let analyst = h.token(&h.code("analyst"), "analyst");
    seed_integration(&h, 7640200, &acme, "Huntress", &[("API_KEY", "k")]).await;
    seed_integration(
        &h,
        7640300,
        &acme,
        "SOCFortress MDR",
        &[("COLLECTOR_UUID", " \u{1f} ")],
    )
    .await;
    seed_meta(&h, &acme, "7").await;
    tools_ok(&w, "acme corp", "FORTINET").await;
    streams_ok(&w).await;

    let (st, answer) = h
        .call(
            "POST",
            "/api/huntress/provision",
            Some(&analyst),
            Some(json!({"customer_code": acme, "time_interval": "7"})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{answer}");
    assert_eq!(
        answer,
        json!({"success": true, "message": "Huntress integration provisioned successfully."})
    );
    let sent = w.graylog.received_requests().await.unwrap();
    let paths: Vec<String> = sent_paths(&sent)
        .into_iter()
        .filter(|p| p != "GET /api/system")
        .collect();
    assert_eq!(
        paths,
        [
            "POST /api/system/indices/index_sets",
            "POST /api/streams",
            "POST /api/streams/st-9/resume"
        ]
    );
    let index: Value =
        serde_json::from_slice(&sent_body(&sent, "/api/system/indices/index_sets")).unwrap();
    assert_eq!(index["title"], json!("acme corp - HUNTRESS"));
    assert_eq!(index["description"], json!(format!("{acme} - HUNTRESS")));
    assert_eq!(index["index_prefix"], json!(format!("huntress_{acme}")));
    assert_eq!(
        (index["shards"].clone(), index["replicas"].clone()),
        (json!(3), json!(0))
    );
    let stream: Value = serde_json::from_slice(&sent_body(&sent, "/api/streams")).unwrap();
    assert_eq!(
        stream,
        json!({"title": "acme corp - HUNTRESS", "description": "acme corp - HUNTRESS",
            "index_set_id": "is-1", "rules": [
                {"field": "integration", "type": 1, "inverted": false, "value": "huntress"},
                {"field": "customer_code", "type": 1, "inverted": false, "value": acme}],
            "matching_type": "AND", "remove_matches_from_default_stream": true,
            "content_pack": null})
    );
    let grafana = w.grafana.received_requests().await.unwrap();
    let ds: Value = serde_json::from_slice(&grafana[1].body).unwrap();
    assert_eq!(ds["name"], json!("HUNTRESS"));
    assert_eq!(ds["database"], json!(format!("huntress_{acme}*")));
    // The meta row, the flag, and the job handed to Python with the caller's token.
    let meta: (
        String,
        Option<String>,
        String,
        String,
        String,
        String,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT integration_name, graylog_input_id, graylog_index_id, graylog_stream_id, \
             grafana_org_id, grafana_dashboard_folder_id, grafana_datasource_uid FROM \
             customer_integrations_meta WHERE customer_code = ?",
    )
    .bind(&acme)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        meta,
        (
            "Huntress".into(),
            None,
            "is-1".into(),
            "st-9".into(),
            "7".into(),
            "12".into(),
            Some("ds-uid".into())
        )
    );
    assert_eq!(
        h.scalar_i64("SELECT deployed FROM customer_integrations WHERE id = 7640201")
            .await,
        1
    );
    let hooks = legacy.received_requests().await.unwrap();
    assert_eq!(hooks.len(), 1);
    assert_eq!(
        hooks[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("Bearer {analyst}")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&hooks[0].body).unwrap(),
        json!({"jobs": [{"function_name": "invoke_huntress_integration_collect",
            "job_id": "invoke_huntress_integration_collect", "time_interval": 7}]})
    );

    // A second run finds the meta row: the 400 after the tools were asked,
    // and no job handed over.
    legacy.reset().await;
    let (st, answer) = h
        .call(
            "POST",
            "/api/huntress/provision",
            Some(&analyst),
            Some(json!({"customer_code": acme, "time_interval": 7})),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(
        answer["message"],
        json!(format!(
            "Customer integration meta {acme} Huntress already exists."
        ))
    );
    assert!(legacy.received_requests().await.unwrap().is_empty());

    // Another tenant's customer is refused first; a customer without
    // integrations is the 404.
    let beta = h.code("beta");
    let (st, _) = h
        .call(
            "POST",
            "/api/mimecast/provision",
            Some(&analyst),
            Some(json!({"customer_code": beta})),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let admin = h.token(&h.code("admin"), "admin");
    let (st, answer) = h
        .call(
            "POST",
            "/api/mimecast/provision",
            Some(&admin),
            Some(json!({"customer_code": beta})),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{answer}");
    // SOCFortress MDR: a COLLECTOR_UUID that is only whitespace is the 400.
    let (st, answer) = h
        .call(
            "POST",
            "/api/socfortress_mdr/provision",
            Some(&analyst),
            Some(json!({"customer_code": acme})),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(
        answer["message"],
        json!("COLLECTOR_UUID is empty. Provide the MDR collector UUID before deploying.")
    );
    h.exec("UPDATE integration_auth_keys SET auth_value = 'uuid-1' WHERE id = 7640303")
        .await;
    let (st, answer) = h
        .call(
            "POST",
            "/api/socfortress_mdr/provision",
            Some(&analyst),
            Some(json!({"customer_code": acme})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{answer}");
    assert_eq!(
        answer,
        json!({"success": true, "message": "SOCFortress MDR integration provisioned successfully."})
    );
    assert_eq!(
        h.scalar_i64("SELECT deployed FROM customer_integrations WHERE id = 7640301")
            .await,
        1
    );
    unseed_integrations(&h, &acme).await;
    leave(&h, w).await;
}

fn sent_body(requests: &[wiremock::Request], at: &str) -> Vec<u8> {
    requests
        .iter()
        .find(|r| r.url.path() == at)
        .unwrap()
        .body
        .clone()
}

// --- a failed run is rolled back; the datasource reads the indexer by name -----------

/// Graylog's and Grafana's answers to the undo of a run.
async fn undo_ok(w: &World) {
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(
            r"^/api/system/content_packs/[^/]+/installations$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "installations": [{"_id": "inst-1", "content_pack_id": "x"}], "total": 1
        })))
        .mount(&w.graylog)
        .await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&w.graylog)
        .await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "deleted"})))
        .mount(&w.grafana)
        .await;
}

/// A network provisioning whose folder Grafana refuses: what the run
/// created is undone newest-first — the datasource, the stream its pack
/// made, the index set, each pack it inserted (installation first) — and
/// it answers what it answered without the rollback (Python left all of
/// it behind; RUST_MIGRATION.md §4).
#[tokio::test]
async fn a_failed_network_provisioning_is_rolled_back() {
    if !configured() {
        return;
    }
    let h = harness_or_skip!(None);
    let w = world(&h, "Graylog-Network").await;
    h.seed().await;
    let acme = h.code("acme");
    let admin = h.token(&h.code("admin"), "admin");
    seed_network(&h, 7640500, &acme, "Fortinet", &[("SYSLOG_PORT", "514")]).await;
    seed_meta(&h, &acme, "7").await;
    Mock::given(method("POST"))
        .and(path("/api/folders"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "folder store down"})),
        )
        .with_priority(1)
        .mount(&w.grafana)
        .await;
    tools_ok(&w, "acme corp", "FORTINET").await;
    undo_ok(&w).await;

    let (st, answer) = h
        .call(
            "POST",
            "/api/stack_provisioning/graylog/provision/fortinet",
            Some(&admin),
            Some(json!({"customer_code": acme, "tcp_enabled": true,
                "hot_data_retention": 30, "index_replicas": 1})),
        )
        .await;
    // `grafana_client`'s `GrafanaServerError`, which nothing catches: uvicorn's
    // bare 500, with or without the rollback.
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "{answer}");
    assert_eq!(answer, json!("Internal Server Error"));
    let sent = w.graylog.received_requests().await.unwrap();
    let packs: Vec<String> = sent
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/api/system/content_packs")
        .map(|r| {
            serde_json::from_slice::<Value>(&r.body).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(packs.len(), 3);
    let at = sent
        .iter()
        .position(|r| r.url.path() == "/api/system/pipelines/connections/to_stream")
        .unwrap();
    let mut want = vec![
        "DELETE /api/streams/st-1".to_string(),
        "DELETE /api/system/indices/index_sets/is-1".to_string(),
    ];
    for id in packs.iter().rev() {
        want.push(format!("GET /api/system/content_packs/{id}/installations"));
        want.push(format!(
            "DELETE /api/system/content_packs/{id}/installations/inst-1"
        ));
        want.push(format!("DELETE /api/system/content_packs/{id}"));
    }
    assert_eq!(sent_paths(&sent[at + 1..]), want);
    for r in &sent[at + 1..] {
        assert_eq!(r.headers.get("authorization").unwrap(), BASIC);
    }
    let grafana = w.grafana.received_requests().await.unwrap();
    let paths = sent_paths(&grafana);
    assert_eq!(
        paths[paths.len() - 2..],
        [
            "POST /api/user/using/7".to_string(),
            "DELETE /api/datasources/uid/ds-uid".to_string()
        ]
    );
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM customer_network_connectors_meta WHERE customer_code = '{acme}'"
        ))
        .await,
        0
    );
    assert_eq!(
        h.scalar_i64("SELECT deployed FROM customer_network_connectors WHERE id = 7640501")
            .await,
        0
    );

    // An undo that fails is logged and the others still run.
    w.graylog.reset().await;
    w.grafana.reset().await;
    w.indexer.reset().await;
    Mock::given(method("POST"))
        .and(path("/api/folders"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "down"})))
        .with_priority(1)
        .mount(&w.grafana)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/streams/st-1"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "busy"})))
        .with_priority(1)
        .mount(&w.graylog)
        .await;
    tools_ok(&w, "acme corp", "FORTINET").await;
    undo_ok(&w).await;
    let (st, _) = h
        .call(
            "POST",
            "/api/stack_provisioning/graylog/provision/fortinet",
            Some(&admin),
            Some(json!({"customer_code": acme, "tcp_enabled": true,
                "hot_data_retention": 30, "index_replicas": 1})),
        )
        .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    let sent = w.graylog.received_requests().await.unwrap();
    let deletes = sent
        .iter()
        .filter(|r| r.method.as_str() == "DELETE")
        .count();
    assert_eq!(deletes, 1 + 1 + 3 * 2, "{:?}", sent_paths(&sent));

    unseed_network(&h, &acme).await;
    leave(&h, w).await;
}

/// The OpenSearch datasource takes the `Wazuh-Indexer` row's URL and
/// credentials, whatever its id; Python read connector id 1 (§4).
#[tokio::test]
async fn the_datasource_reads_the_indexer_connector_by_name() {
    if !configured() {
        return;
    }
    let h = harness_or_skip!(None);
    let w = world(&h, "Graylog-Network").await;
    let id1_name: Option<String> = w.id1.as_ref().map(|r| r.1.clone());
    // Id 1 is another connector now; the indexer's row is a new one.
    h.exec(
        "UPDATE connectors SET connector_name = 'E2E-NOT-THE-INDEXER', connector_url = \
         'http://127.0.0.1:9', connector_username = 'id1-user', connector_password = 'id1-pass' \
         WHERE id = 1",
    )
    .await;
    let named = set_connector(&h, "Wazuh-Indexer", &w.indexer.uri()).await;
    assert!(named.is_none());
    h.exec(
        "UPDATE connectors SET connector_username = 'named-user', connector_password = \
         'named-pass' WHERE connector_name = 'Wazuh-Indexer'",
    )
    .await;
    h.seed().await;
    let acme = h.code("acme");
    let admin = h.token(&h.code("admin"), "admin");
    seed_network(&h, 7640600, &acme, "Fortinet", &[("SYSLOG_PORT", "514")]).await;
    seed_meta(&h, &acme, "7").await;
    tools_ok(&w, "acme corp", "FORTINET").await;

    let (st, answer) = h
        .call(
            "POST",
            "/api/stack_provisioning/graylog/provision/fortinet",
            Some(&admin),
            Some(json!({"customer_code": acme, "tcp_enabled": true,
                "hot_data_retention": 30, "index_replicas": 1})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{answer}");
    let grafana = w.grafana.received_requests().await.unwrap();
    let ds: Value = serde_json::from_slice(&sent_body(&grafana, "/api/datasources")).unwrap();
    assert_eq!(ds["url"], json!(w.indexer.uri()));
    assert_eq!(ds["basicAuthUser"], json!("named-user"));
    assert_eq!(
        ds["secureJsonData"],
        json!({"basicAuthPassword": "named-pass"})
    );

    unseed_network(&h, &acme).await;
    restore_connector(&h, "Wazuh-Indexer", None).await;
    h.exec(&format!(
        "UPDATE connectors SET connector_name = '{}' WHERE id = 1",
        id1_name.as_deref().unwrap_or("Wazuh-Indexer")
    ))
    .await;
    leave(&h, w).await;
}
