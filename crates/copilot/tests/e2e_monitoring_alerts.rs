//! End-to-end tests of the monitoring-alert catalog (`copilot-monitoring-alerts`):
//! `/api/monitoring_alert/*` through the production router on a real MySQL,
//! with both Graylog connectors (`Graylog`, a 6.x; `Graylog-Network`, a 7.x),
//! the Event Shipper's GELF input and the Python backend replaced by local
//! stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13306/copilot \
//!   cargo test -p copilot --test e2e_monitoring_alerts -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `MONITORING_ALERTS_E2E_PORT_BASE` (6270) and the
//! three ports after it. The connector rows a test points at them are
//! replaced for that test and restored (run single-threaded).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use http::StatusCode;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const P: &str = "/api/monitoring_alert";

fn port(offset: u16) -> u16 {
    std::env::var("MONITORING_ALERTS_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6270)
        + offset
}

fn configured() -> bool {
    std::env::var("COPILOT_TEST_DATABASE_URL").is_ok()
}

/// A stand-in on one of this suite's ports: 0 the default Graylog, 1 the
/// network Graylog, 3 the Python backend (2 is the GELF input).
async fn stand_in(offset: u16) -> MockServer {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port(offset))).unwrap();
    MockServer::builder().listener(listener).start().await
}

/// A saved `connectors` row: url, username, password, extra data.
type SavedRow = (String, Option<String>, Option<String>, Option<String>);

struct Saved(String, Vec<SavedRow>);

/// Point connector `name` at `url`; what was there before.
async fn set_connector(h: &Harness, name: &str, url: &str, extra: Option<&str>) -> Saved {
    let saved: Vec<SavedRow> = sqlx::query_as(
        "SELECT connector_url, connector_username, connector_password, connector_extra_data \
         FROM connectors WHERE connector_name = ?",
    )
    .bind(name)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    remove_connector(h, name).await;
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, \
         connector_last_updated, connector_username, connector_password, connector_api_key, \
         connector_description, connector_supports, connector_configured, connector_verified, \
         connector_accepts_host_only, connector_accepts_api_key, \
         connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         (?, '3', ?, UTC_TIMESTAMP(), 'admin', 'secret', NULL, 'e2e', 'e2e', 1, 1, 0, 0, 1, 0, \
         0, ?, 1)",
    )
    .bind(name)
    .bind(url)
    .bind(extra)
    .execute(h.db.pool())
    .await
    .unwrap();
    Saved(name.to_string(), saved)
}

/// Remove connector `name`; what was there before.
async fn take_connector(h: &Harness, name: &str) -> Saved {
    let saved: Vec<SavedRow> = sqlx::query_as(
        "SELECT connector_url, connector_username, connector_password, connector_extra_data \
         FROM connectors WHERE connector_name = ?",
    )
    .bind(name)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    remove_connector(h, name).await;
    Saved(name.to_string(), saved)
}

async fn remove_connector(h: &Harness, name: &str) {
    sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
        .bind(name)
        .execute(h.db.pool())
        .await
        .unwrap();
}

async fn restore(h: &Harness, saved: Saved) {
    remove_connector(h, &saved.0).await;
    for (url, user, pw, extra) in saved.1 {
        sqlx::query(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, \
             connector_last_updated, connector_username, connector_password, \
             connector_description, connector_supports, connector_configured, \
             connector_verified, connector_accepts_host_only, connector_accepts_api_key, \
             connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (?, \
             '3', ?, UTC_TIMESTAMP(), ?, ?, 'restored', 'restored', 1, 1, 0, 0, 1, 0, 0, ?, 1)",
        )
        .bind(&saved.0)
        .bind(url)
        .bind(user)
        .bind(pw)
        .bind(extra)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

fn system(version: &str) -> Value {
    json!({
        "facility": "graylog-server", "codename": "Noir", "node_id": "n1",
        "cluster_id": "c1", "version": version, "started_at": "2026-10-01T00:00:00.000Z",
        "hostname": "graylog", "lifecycle": "running", "lb_status": "alive",
        "timezone": "UTC", "operating_system": "Linux", "is_processing": true
    })
}

fn definition(title: &str) -> Value {
    json!({
        "id": "d1", "title": title, "description": "d", "priority": 2, "alert": true,
        "config": {"type": "aggregation-v1", "query": "q", "query_parameters": [],
                   "streams": [], "group_by": [], "series": [],
                   "conditions": {"expression": null}, "search_within_ms": 1,
                   "execute_every_ms": 1, "event_limit": 1},
        "field_spec": {}, "key_spec": [],
        "notification_settings": {"grace_period_ms": 0, "backlog_size": 0},
        "notifications": [],
        "storage": [{"type": "persist-to-streams-v1", "streams": ["s"]}]
    })
}

/// A Graylog reporting `version`, with `definitions` defined.
async fn graylog(offset: u16, version: &str, definitions: Vec<Value>) -> MockServer {
    let server = stand_in(offset).await;
    let total = definitions.len();
    Mock::given(method("GET"))
        .and(path("/api/events/definitions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"event_definitions": definitions, "total": total})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(system(version)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/events/definitions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "new"})))
        .mount(&server)
        .await;
    server
}

/// The requests a stand-in received: method, path and query, JSON body.
async fn sent(server: &MockServer) -> Vec<(String, String, Value)> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| {
            let target = match r.url.query() {
                Some(q) => format!("{}?{q}", r.url.path()),
                None => r.url.path().to_string(),
            };
            let body = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            (r.method.to_string(), target, body)
        })
        .collect()
}

fn suricata(within_ms: u64, every_ms: u64, event_limit: bool) -> Value {
    let template = |t: &str| {
        json!({"data_type": "string",
               "providers": [{"template": t, "type": "template-v1", "require_values": true}]})
    };
    let mut config = json!({
        "query": "alert_severity:1 AND syslog_type:suricata", "query_parameters": [],
        "streams": [], "search_within_ms": within_ms, "execute_every_ms": every_ms,
        "group_by": [], "series": [], "conditions": {"expression": null},
        "type": "aggregation-v1"
    });
    if event_limit {
        config["event_limit"] = json!(1000);
    }
    json!({
        "title": "SURICATA ALERT SEVERITY 1", "description": "Alert on Suricata alerts",
        "priority": 2, "config": config,
        "field_spec": {
            "ALERT_ID": template("${source._id}"),
            "CUSTOMER_CODE": template("${source.agent_labels_customer}"),
            "ALERT_SOURCE": template("SURICATA"),
            "COPILOT_ALERT_ID": template("NONE")
        },
        "key_spec": [], "notification_settings": {"grace_period_ms": 0, "backlog_size": null},
        "notifications": [], "alert": true
    })
}

#[tokio::test]
async fn the_catalog_is_listed_to_analysts() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");
    let (status, body) = h
        .call("GET", &format!("{P}/available"), Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "Alerts retrieved successfully");
    let alerts = body["available_monitoring_alerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 51);
    assert_eq!(alerts[0]["name"], "WAZUH SYSLOG LEVEL ALERT");
    assert_eq!(alerts[4]["name"], "SOCFORTRESS WAF BLOCKED");
    let (status, _) = h.call("GET", &format!("{P}/available"), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h
        .call("GET", &format!("{P}/available"), Some(&portal), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_catalog_alert_on_graylog_6_and_7() {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return;
    }
    let h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let six = graylog(0, "6.1.4", vec![definition("OTHER")]).await;
    let seven = graylog(1, "7.0.1+abc", Vec::new()).await;
    let a = set_connector(&h, "Graylog", &six.uri(), None).await;
    let b = set_connector(&h, "Graylog-Network", &seven.uri(), None).await;

    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            Some(&analyst),
            Some(json!({"search_within_last": 60, "execute_every": "120",
                        "alert_name": "suricata alert severity 1"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"success": true,
               "message": "Monitoring alert SURICATA_ALERT_SEVERITY_1 provisioned successfully."})
    );
    let got = sent(&six).await;
    let targets: Vec<&str> = got.iter().map(|(_, t, _)| t.as_str()).collect();
    assert_eq!(
        targets,
        [
            "/api/events/definitions?per_page=500&page=1",
            "/api/system",
            "/api/system",
            "/api/events/definitions",
        ]
    );
    assert_eq!(got[3].2, suricata(60_000, 120_000, true));

    // The network instance: every call to Graylog-Network, the body wrapped.
    let (status, _) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            Some(&analyst),
            Some(json!({"search_within_last": 1, "execute_every": 2,
                        "alert_name": "SURICATA_ALERT_SEVERITY_1",
                        "graylog_instance": "network"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        sent(&six).await.len(),
        4,
        "the default Graylog is not asked"
    );
    let got = sent(&seven).await;
    assert_eq!(got.len(), 4);
    assert_eq!(got[3].2, json!({"entity": suricata(1000, 2000, true)}));

    // An unknown name: the validator's 400, before Graylog is asked.
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            Some(&analyst),
            Some(json!({"search_within_last": 1, "execute_every": 1,
                        "alert_name": "OTHER"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid alert name: OTHER. Must be one of: WAZUH_SYSLOG_LEVEL_ALERT, ")
    );
    restore(&h, a).await;
    restore(&h, b).await;
}

#[tokio::test]
async fn existing_definitions_old_graylogs_and_missing_connectors() {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return;
    }
    let h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let old = graylog(0, "5.1.9", vec![definition("WAZUH SYSLOG LEVEL ALERT")]).await;
    let a = set_connector(&h, "Graylog", &old.uri(), None).await;

    // The check uses the name with spaces, not the definition's title.
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            Some(&analyst),
            Some(json!({"search_within_last": 1, "execute_every": 1})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Event definition WAZUH SYSLOG LEVEL ALERT already exists"
    );

    // Below "5.2" as a string: no `event_limit`.
    let (status, _) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            Some(&analyst),
            Some(json!({"search_within_last": 1, "execute_every": 1,
                        "alert_name": "SURICATA_ALERT_SEVERITY_1"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let got = sent(&old).await;
    assert_eq!(got.last().unwrap().2, suricata(1000, 1000, false));

    // No Graylog-Network connector: the first call's 500.
    let network = take_connector(&h, "Graylog-Network").await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            Some(&analyst),
            Some(json!({"search_within_last": 1, "execute_every": 1,
                        "alert_name": "FORTINET_SYSTEM", "graylog_instance": "network"})),
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body,
        json!({"success": false, "message": "Connector Graylog-Network not found"})
    );

    // The WAF alerts are pinned to the default Graylog: its definitions
    // answer for a network request.
    let waf = graylog(1, "6.1.4", vec![definition("SOCFORTRESS WAF BLOCKED")]).await;
    let b = set_connector(&h, "Graylog", &waf.uri(), None).await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            Some(&analyst),
            Some(json!({"search_within_last": 1, "execute_every": 1,
                        "alert_name": "socfortress waf blocked",
                        "graylog_instance": "network"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Event definition SOCFORTRESS WAF BLOCKED already exists"
    );
    restore(&h, b).await;
    restore(&h, network).await;
    restore(&h, a).await;
}

#[tokio::test]
async fn request_validation_is_fastapi_s() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    // Malformed JSON is a 422 before the token is looked at.
    let (status, body) = h
        .call_raw(
            "POST",
            &format!("{P}/provision"),
            None,
            Some("application/json"),
            "{",
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"][0]["error_type"], "json_invalid");
    let (status, _) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            None,
            Some(json!({"execute_every": 0})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            Some(&analyst),
            Some(json!({"search_within_last": "x", "execute_every": 0})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid value: 0. Must be greater than 0.");
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision"),
            Some(&analyst),
            Some(json!({"search_within_last": 1.5, "execute_every": 1,
                        "graylog_instance": "graylog02"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"].as_array().unwrap().len(), 2);
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision/custom"),
            Some(&analyst),
            Some(
                json!({"alert_name": "x", "alert_description": "d", "alert_priority": "2",
                        "search_query": "q", "search_within_ms": 1, "execute_every_ms": 1}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"][0]["field"], "alert_priority");
}

#[tokio::test]
async fn a_custom_alert() {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return;
    }
    let h = harness_or_skip!(None);
    h.seed().await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let six = graylog(0, "6.1.4", Vec::new()).await;
    let seven = graylog(1, "7.0.1", Vec::new()).await;
    let a = set_connector(&h, "Graylog", &six.uri(), None).await;
    let b = set_connector(&h, "Graylog-Network", &seven.uri(), None).await;
    let body = json!({
        "alert_name": "MY_ALERT", "alert_description": "Mine", "alert_priority": 3.0,
        "search_query": "syslog_type:wazuh", "streams": ["s1"],
        "custom_fields": [{"name": "CUSTOMER CODE", "value": "nobody"}],
        "search_within_ms": 300000, "execute_every_ms": 60000,
        "graylog_instance": "network"
    });
    let (status, out) = h
        .call(
            "POST",
            &format!("{P}/provision/custom"),
            Some(&admin),
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(
        out["message"],
        "Monitoring alert MY_ALERT provisioned successfully."
    );
    assert!(sent(&six).await.is_empty());
    let got = sent(&seven).await;
    let entity = &got[3].2["entity"];
    assert_eq!(entity["title"], "MY_ALERT");
    assert_eq!(entity["priority"], 3);
    assert_eq!(entity["config"]["streams"], json!(["s1"]));
    assert_eq!(entity["config"]["search_within_ms"], 300000);
    assert_eq!(
        entity["field_spec"],
        json!({"COPILOT_ALERT_ID": {"data_type": "string", "providers": [
            {"template": "NONE", "type": "template-v1", "require_values": true}]}})
    );

    // `streams: null` passes the request model and fails the config model,
    // after the existence check.
    let mut null_streams = body.clone();
    null_streams["streams"] = Value::Null;
    null_streams["graylog_instance"] = json!("default");
    let (status, out) = h
        .call(
            "POST",
            &format!("{P}/provision/custom"),
            Some(&admin),
            Some(null_streams),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        out["message"]
            .as_str()
            .unwrap()
            .starts_with("1 validation error for GraylogAlertProvisionConfig\nstreams\n")
    );
    assert_eq!(sent(&six).await.len(), 1);
    restore(&h, a).await;
    restore(&h, b).await;
}

/// The bytes the next connection to the GELF input sends, until it closes.
async fn one_frame(listener: &tokio::net::TcpListener) -> Vec<u8> {
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    buf
}

#[tokio::test]
async fn the_test_event_is_one_gelf_frame() {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return;
    }
    let h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port(2)))
        .await
        .unwrap();
    let saved = set_connector(
        &h,
        "Event Shipper",
        "127.0.0.1",
        Some(&format!(" {}", port(2))),
    )
    .await;
    let testing = format!("{P}/provision/testing");
    let call = h.call(
        "POST",
        &testing,
        Some(&analyst),
        Some(json!({"message": "hello", "n": null, "x": {"y": null}})),
    );
    let (frame, (status, body)) = tokio::join!(one_frame(&listener), call);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"success": true, "message": "Event sent to log shipper successfully."})
    );
    assert_eq!(frame.last(), Some(&0));
    let gelf: Value = serde_json::from_slice(&frame[..frame.len() - 1]).unwrap();
    assert_eq!(gelf["version"], 1.1);
    assert_eq!(gelf["level"], 1);
    assert_eq!(
        gelf["short_message"],
        "{\"integration\": \"testing\", \"customer_code\": \"00002\", \"version\": \"1.0\", \
         \"message\": \"hello\", \"x\": {\"y\": null}}"
    );

    // A key the route passes itself: Python's TypeError, a bare 500.
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision/testing"),
            Some(&analyst),
            Some(json!({"customer_code": "00001"})),
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, json!("Internal Server Error"));

    // An unreachable shipper is not an error (asyncgelf returns it).
    drop(listener);
    let (status, _) = h
        .call(
            "POST",
            &format!("{P}/provision/testing"),
            Some(&analyst),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let shipper = take_connector(&h, "Event Shipper").await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{P}/provision/testing"),
            Some(&analyst),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body["message"],
        "Failed to initialize GelfLogger: 'NoneType' object is not subscriptable"
    );
    let (status, _) = h
        .call(
            "POST",
            &format!("{P}/provision/testing"),
            Some(&analyst),
            Some(json!([1])),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    restore(&h, shipper).await;
    restore(&h, saved).await;
}

#[tokio::test]
async fn other_methods_go_to_python() {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return;
    }
    let legacy = stand_in(3).await;
    let h = harness_or_skip!(Some(&legacy));
    Mock::given(method("DELETE"))
        .and(path("/api/monitoring_alert/provision"))
        .respond_with(
            ResponseTemplate::new(405).set_body_json(json!({"detail": "Method Not Allowed"})),
        )
        .expect(1)
        .mount(&legacy)
        .await;
    let (status, _) = h
        .call("DELETE", &format!("{P}/provision"), None, None)
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    // The routes themselves are answered here.
    let (status, _) = h.call("GET", &format!("{P}/available"), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(legacy.received_requests().await.unwrap().len(), 1);
}
