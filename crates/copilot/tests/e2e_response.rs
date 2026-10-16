//! End-to-end tests of the response routes (`copilot-response`) against a
//! real MySQL, the Wazuh manager replaced by a mock.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13308/copilot \
//!   cargo test -p copilot --test e2e_response -- --test-threads=1
//! ```
//!
//! The tests that need a connector row create it, point it at the stand-in
//! and delete it again (the harness runs with the connector cache off).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const GRAYLOG_HEADER: &str = "e2e-graylog-header";

/// An agent of `customer`; returns its `agent_id`.
async fn agent(h: &Harness, key: &str, hostname: &str, customer: &str, os: &str) -> String {
    let agent_id = format!("{}{key}", h.suffix);
    sqlx::query(
        "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, \
         velociraptor_id, velociraptor_last_seen, wazuh_agent_version, wazuh_agent_status, \
         velociraptor_agent_version, customer_code, quarantined, velociraptor_org, velociraptor_id_pinned) \
         VALUES (?, '10.0.0.1', ?, ?, 'grp', 0, '2026-10-15 08:00:00', NULL, NULL, 'Wazuh v4.9.0', \
         'active', NULL, ?, 0, NULL, 0)",
    )
    .bind(&agent_id)
    .bind(os)
    .bind(hostname)
    .bind(customer)
    .execute(h.db.pool())
    .await
    .unwrap();
    agent_id
}

/// A connector row.
async fn connector(h: &Harness, name: &str, url: &str, user: Option<&str>, key: Option<&str>) {
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_username, connector_password, connector_api_key, connector_description, \
         connector_supports, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         (?, '4.8', ?, '2026-01-02 03:04:05', ?, 'pw', ?, 'desc', 'supports', 1, 1, 0, 0, 1, 1, 0, NULL, 1)",
    )
    .bind(name)
    .bind(url)
    .bind(user)
    .bind(key)
    .execute(h.db.pool())
    .await
    .unwrap();
}

async fn cleanup(h: &Harness) {
    let s = &h.suffix;
    for sql in [
        format!("DELETE FROM agents WHERE agent_id LIKE '{s}%'"),
        "DELETE FROM connectors WHERE connector_name IN ('Wazuh-Manager')".to_string(),
    ] {
        h.exec(&sql).await;
    }
}

/// A Wazuh manager answering the token flow and `PUT /active-response`
/// with `status`/`body`.
async fn manager(status: u16, body: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/security/user/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "tok"}, "error": 0})),
        )
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/active-response"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(&server)
        .await;
    server
}

async fn puts(server: &MockServer) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect()
}

fn firewall(agents: Value) -> Value {
    json!({
        "command": "WINDOWS_FIREWALL",
        "alert": {"action": "block", "ip": " 1.1.1.1 ", "extra": 1},
        "params": {"wait_for_complete": true, "agents_list": agents},
    })
}

#[tokio::test]
async fn supported_and_describe() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");
    let (st, body) = h
        .call(
            "GET",
            "/api/active_response/supported",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({
            "supported_active_responses": [{
                "name": "WINDOWS_FIREWALL",
                "description": "Block or unblock any outbound traffic to the defined IP address via the Windows Firewall",
            }],
            "success": true,
            "message": "Supported Active Responses retrieved successfully",
        })
    );
    let (st, body) = h
        .call(
            "GET",
            "/api/active_response/describe/windows_firewall",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["active_response"]["name"], "windows_firewall");
    assert!(
        body["active_response"]["markdown_content"]
            .as_str()
            .unwrap()
            .contains("windows_firewall")
    );
    let (st, body) = h
        .call(
            "GET",
            "/api/active_response/describe/nope",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (404, json!("Active Response not found"))
    );
    // A member, but not the file's spelling: Python's FileNotFoundError.
    let (st, _) = h
        .call(
            "GET",
            "/api/active_response/describe/WINDOWS_FIREWALL",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 500);
    let (st, body) = h
        .call("GET", "/api/active_response/supported", Some(&portal), None)
        .await;
    assert_eq!(st, 403, "{body}");
    let (st, _) = h
        .call("GET", "/api/active_response/supported", None, None)
        .await;
    assert_eq!(st, 401);
}

#[tokio::test]
async fn supported_for_an_agent_follows_its_os_and_tenant() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let acme = h.code("acme");
    let beta = h.code("beta");
    let win = agent(
        &h,
        "w",
        &format!("win{}", h.suffix),
        &acme,
        "Microsoft Windows 11",
    )
    .await;
    let lin = agent(&h, "l", &format!("lin{}", h.suffix), &acme, "Ubuntu 24.04").await;
    let none = agent(&h, "n", &format!("none{}", h.suffix), &acme, "").await;
    let other = agent(
        &h,
        "b",
        &format!("bet{}", h.suffix),
        &beta,
        "Microsoft Windows 11",
    )
    .await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let get = |id: String| {
        let h = &h;
        let analyst = analyst.clone();
        async move {
            h.call(
                "GET",
                &format!("/api/active_response/supported/{id}"),
                Some(&analyst),
                None,
            )
            .await
        }
    };
    let (st, body) = get(win).await;
    assert_eq!(st, 200);
    assert_eq!(
        body["supported_active_responses"].as_array().unwrap().len(),
        1
    );
    let (st, body) = get(lin).await;
    assert_eq!(
        (st.as_u16(), body["supported_active_responses"].clone()),
        (200, json!([]))
    );
    let (st, body) = get(none).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (404, json!("Agent not found"))
    );
    // Another tenant's agent reads as missing — the 500 of `get_agent`.
    let (st, body) = get(other.clone()).await;
    assert_eq!(st, 500);
    assert_eq!(
        body["message"],
        json!(format!("Failed to fetch agent: {other}. Does it exist?"))
    );
    cleanup(&h).await;
}

#[tokio::test]
async fn invoke_validates_like_pydantic() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let call = |body: Value| {
        let h = &h;
        let admin = admin.clone();
        async move {
            h.call(
                "POST",
                "/api/active_response/invoke",
                Some(&admin),
                Some(body),
            )
            .await
        }
    };
    let (st, body) = call(json!({"command": "nope", "alert": {}, "params": {}})).await;
    assert_eq!(st, 400);
    assert_eq!(
        body["message"],
        "Invalid command: nope, must be one of windows_firewall, linux_firewall, sysmon_config_reload"
    );
    let (st, body) = call(json!({"command": "nope", "alert": 5})).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (422, json!("'alert' must be an object"))
    );
    let (st, body) = call(json!({"command": "linux_firewall", "alert": {"action": "block", "ip": "1.1.1.01"}, "params": {}})).await;
    assert_eq!(st, 422);
    assert_eq!(body["message"], "ip: '1.1.1.01' is not a valid IP address");
    let (st, body) = call(json!({"alert": {}, "params": {}})).await;
    assert_eq!(st, 422);
    assert_eq!(
        body["details"],
        json!([
            {"field": "command", "error_type": "missing", "message": "Missing data for required field."},
            {"field": "wait_for_complete", "error_type": "missing", "message": "Missing data for required field."},
        ])
    );
    let (st, body) = call(
        json!({"command": "sysmon_config_reload", "alert": {"action": "block"}, "params": {}}),
    )
    .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["message"],
        "action: Input should be <AlertAction.sysmon_config_reload: 'sysmon_config_reload'>"
    );
    let (st, body) = call(json!({"command": "linux_firewall", "alert": {"action": "unblock", "ip": "::1"},
        "params": {"wait_for_complete": true}, "custom": false, "endpoint": "/x", "arguments": [1]}))
    .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["details"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["message"].clone())
            .collect::<Vec<_>>(),
        vec![
            json!("endpoint: Input should be '/active-response'"),
            json!("arguments.0: Input should be a valid string"),
            json!("custom: Input should be True"),
        ]
    );
}

#[tokio::test]
async fn invoke_checks_the_targets_tenant_then_puts() {
    let h = harness_or_skip!(None);
    h.seed().await;
    cleanup(&h).await;
    let acme = h.code("acme");
    let beta = h.code("beta");
    let mine = agent(&h, "m", &format!("mine{}", h.suffix), &acme, "Windows").await;
    let theirs = agent(&h, "t", &format!("theirs{}", h.suffix), &beta, "Windows").await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let invoke = |tok: String, body: Value| {
        let h = &h;
        async move {
            h.call(
                "POST",
                "/api/active_response/invoke",
                Some(&tok),
                Some(body),
            )
            .await
        }
    };
    // No connector row: 503 — but the tenant checks come first.
    for agents in [json!(["*"]), json!([]), Value::Null] {
        let (st, body) = invoke(analyst.clone(), firewall(agents)).await;
        assert_eq!(st, 403, "{body}");
        assert_eq!(
            body["message"],
            "agents_list is required: a deployment-wide active response is limited to unscoped users"
        );
    }
    let (st, body) = invoke(
        analyst.clone(),
        firewall(json!([mine.clone(), theirs.clone()])),
    )
    .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to agent {theirs}")))
    );
    let (st, body) = invoke(analyst.clone(), firewall(json!([mine.clone()]))).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (503, json!("Wazuh Manager connector is not configured"))
    );

    let server = manager(
        200,
        json!({"data": {"affected_items": [mine.clone()]}, "error": 0}),
    )
    .await;
    connector(&h, "Wazuh-Manager", &server.uri(), Some("wazuh"), None).await;
    let (st, body) = invoke(analyst.clone(), firewall(json!([mine.clone()]))).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "Wazuh Active Response invoked successfully"})
    );
    let sent = puts(&server).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].url.query(),
        Some(format!("wait_for_complete=true&agents_list={mine}").as_str())
    );
    assert_eq!(
        String::from_utf8(sent[0].body.clone()).unwrap(),
        r#"{"command": "windows_firewall0", "arguments": [], "alert": {"action": "block", "ip": "1.1.1.1"}}"#
    );
    assert_eq!(
        sent[0].headers.get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(sent[0].headers.get("authorization").unwrap(), "Bearer tok");
    // The admin may fan out: `["*"]` sends no `agents_list` at all.
    let (st, _) = invoke(admin.clone(), firewall(json!(["*"]))).await;
    assert_eq!(st, 200);
    let sent = puts(&server).await;
    assert_eq!(sent[1].url.query(), Some("wait_for_complete=true"));
    cleanup(&h).await;

    // Wazuh says no: the 502 names Wazuh's own detail.
    let server = manager(400, json!({"title": "Bad Request", "detail": "bad agents"})).await;
    connector(&h, "Wazuh-Manager", &server.uri(), Some("wazuh"), None).await;
    let (st, body) = invoke(admin.clone(), firewall(json!(["001", "002"]))).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (502, json!("Wazuh Active Response failed: bad agents"))
    );
    let sent = puts(&server).await;
    assert_eq!(
        sent[0].url.query(),
        Some("wait_for_complete=true&agents_list=001&agents_list=002")
    );
    cleanup(&h).await;
}

fn notification(fields: Value) -> Value {
    json!({
        "event_definition_id": "a", "event_definition_type": "aggregation-v1",
        "event_definition_title": "T", "job_definition_id": "j", "job_trigger_id": "t",
        "event": {
            "id": "e", "event_definition_type": "x", "event_definition_id": "a",
            "origin_context": "urn", "timestamp": "2025-03-04T23:21:55.840Z",
            "timestamp_processing": "2025-03-04T23:26:03.450Z", "source_streams": ["s"],
            "message": "m", "source": "src", "key": "", "priority": 2, "alert": true,
            "fields": fields,
            "replay_info": {"timerange_start": "2025-03-04T23:21:03.360Z",
                "timerange_end": "2025-03-04T23:26:03.360Z", "query": "q", "streams": ["s"]},
        },
    })
}

async fn webhook(h: &Harness, header: Option<&str>, body: Value) -> (u16, Value) {
    let mut b = http::Request::builder()
        .method("POST")
        .uri("/api/graylog/invoke")
        .header("content-type", "application/json");
    if let Some(v) = header {
        b = b.header("graylog", v);
    }
    let req = b
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    use tower::ServiceExt;
    let resp = h.router.clone().oneshot(req).await.unwrap();
    let st = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (st, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_graylog_webhook_fails_closed_without_its_header() {
    let h = harness_or_skip!(None);
    let fields = json!({"COMMAND": "domain_sinkhole", "AGENT_ID": "032", "ACTION": "sinkhole", "VALUE": "example.com"});
    let (st, body) = webhook(&h, Some("anything"), notification(fields)).await;
    assert_eq!(
        (st, body["message"].clone()),
        (
            403,
            json!("Graylog header authentication is not configured")
        )
    );
}

#[tokio::test]
async fn the_graylog_webhook_forwards_the_event_fields() {
    let h = harness_or_skip!(
        None,
        &format!("GRAYLOG_API_HEADER_VALUE={GRAYLOG_HEADER}\n")
    );
    cleanup(&h).await;
    let fields = json!({"COMMAND": "domain_sinkhole", "AGENT_ID": "032", "ACTION": "sinkhole", "VALUE": "example.com"});
    let (st, body) = webhook(&h, Some("wrong"), notification(fields.clone())).await;
    assert_eq!(
        (st, body["message"].clone()),
        (403, json!("Invalid or missing Graylog header"))
    );
    let (st, body) = webhook(&h, None, notification(fields.clone())).await;
    assert_eq!(st, 403, "{body}");
    let (st, body) = webhook(
        &h,
        Some(GRAYLOG_HEADER),
        notification(
            json!({"COMMAND": "rm -rf /", "AGENT_ID": "032", "ACTION": "a", "VALUE": "v"}),
        ),
    )
    .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["message"],
        "event.fields.COMMAND: COMMAND must be a bare active-response script name (letters, digits, '_' or '-', max 64 chars)"
    );
    // No manager: still a success (the route ignores Wazuh's answer).
    let (st, body) = webhook(&h, Some(GRAYLOG_HEADER), notification(fields.clone())).await;
    assert_eq!((st, body["success"].clone()), (200, json!(true)));
    let server = manager(500, json!({"detail": "down"})).await;
    connector(&h, "Wazuh-Manager", &server.uri(), Some("wazuh"), None).await;
    let (st, _) = webhook(&h, Some(GRAYLOG_HEADER), notification(fields)).await;
    assert_eq!(st, 200);
    let sent = puts(&server).await;
    assert_eq!(
        sent[0].url.query(),
        Some("wait_for_complete=True&agents_list=032")
    );
    assert_eq!(
        String::from_utf8(sent[0].body.clone()).unwrap(),
        r#"{"command": "domain_sinkhole0", "arguments": [], "alert": {"action": "sinkhole", "value": "example.com"}}"#
    );
    cleanup(&h).await;
}
