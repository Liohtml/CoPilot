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
        format!("DELETE FROM agent_datastore WHERE agent_id LIKE '{s}%'"),
        format!("DELETE FROM agents WHERE agent_id LIKE '{s}%'"),
        "DELETE FROM connectors WHERE connector_name IN ('Wazuh-Manager', 'Velociraptor')"
            .to_string(),
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

// --- Sysmon configs -----------------------------------------------------------

const LOCATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>";

/// A MinIO stand-in holding `objects` in the `sysmon-configs` bucket.
async fn minio(objects: &[(String, &'static [u8])]) -> MockServer {
    use wiremock::matchers::query_param;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sysmon-configs"))
        .and(query_param("location", ""))
        .respond_with(ResponseTemplate::new(200).set_body_raw(LOCATION, "application/xml"))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/sysmon-configs"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut contents = String::new();
    for (key, data) in objects {
        Mock::given(method("HEAD"))
            .and(path(format!("/sysmon-configs/{key}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"abc\"")
                    .insert_header("content-type", "application/xml")
                    .insert_header("content-length", data.len().to_string().as_str()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/sysmon-configs/{key}")))
            .respond_with(ResponseTemplate::new(200).set_body_raw(*data, "application/xml"))
            .mount(&server)
            .await;
        contents.push_str(&format!(
            "<Contents><Key>{key}</Key><LastModified>2026-10-15T08:00:00.000Z</LastModified>\
             <ETag>&quot;abc&quot;</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            data.len()
        ));
    }
    let listing = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Name>sysmon-configs</Name><Prefix></Prefix><KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys>\
         <IsTruncated>false</IsTruncated>{contents}</ListBucketResult>",
        objects.len()
    );
    Mock::given(method("GET"))
        .and(path("/sysmon-configs"))
        .and(query_param("list-type", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(listing, "application/xml"))
        .mount(&server)
        .await;
    server
}

fn minio_env(s3: &MockServer, worker: Option<&MockServer>) -> String {
    let mut env = format!(
        "COPILOT_MINIO_ENDPOINT={}\nMINIO_ROOT_USER=e2e-minio\nMINIO_ROOT_PASSWORD=e2e-minio-secret\n",
        s3.address()
    );
    if let Some(w) = worker {
        env.push_str(&format!(
            "COPILOT_PROVISION_WORKER_PORT={}\n",
            w.address().port()
        ));
    }
    env
}

const SYSMON_XML: &[u8] = b"<Sysmon schemaversion=\"4.90\"><EventFiltering><RuleGroup groupRelation=\"or\"/></EventFiltering></Sysmon>\n";

#[tokio::test]
async fn sysmon_configs_are_read_by_tenant() {
    let probe = harness_or_skip!(None);
    let (acme, beta) = (probe.code("acme"), probe.code("beta"));
    let s3 = minio(&[
        (format!("{acme}/sysmon_config.xml"), SYSMON_XML),
        (format!("{beta}/sysmon_config.xml"), b"\xff\xfe"),
        (format!("{beta}/notes.txt"), b"x"),
    ])
    .await;
    // The same suffix, so the objects above are this harness's customers.
    let mut h = harness_or_skip!(None, &minio_env(&s3, None));
    h.suffix = probe.suffix.clone();
    h.seed().await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let responder = h.token(&format!("responder{}", h.suffix), "responder");
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/sysmon_config/content/{acme}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({
            "success": true,
            "message": "Successfully retrieved Sysmon config",
            "customer_code": acme,
            "config_content": String::from_utf8(SYSMON_XML.to_vec()).unwrap(),
        })
    );
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/sysmon_config/content/{beta}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (500, json!("Failed to decode config file as UTF-8"))
    );
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/sysmon_config/content/{acme}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            403,
            json!("Insufficient permissions. Required one of: admin, responder")
        )
    );
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/sysmon_config/content/{beta}"),
            Some(&responder),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to customer {beta}")))
    );
    let missing = format!("none{}", h.suffix);
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/sysmon_config/content/{missing}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            404,
            json!(format!(
                "File {missing}/sysmon_config.xml not found in bucket sysmon-configs"
            ))
        )
    );
    let (st, body) = h
        .call("GET", "/api/sysmon_config", Some(&admin), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["customer_codes"], json!([acme, beta]));
    let (_, body) = h
        .call("GET", "/api/sysmon_config", Some(&responder), None)
        .await;
    assert_eq!(body["customer_codes"], json!([acme]));
    // The download.
    let req = http::Request::builder()
        .uri(format!("/api/sysmon_config/{acme}"))
        .header("authorization", format!("Bearer {responder}"))
        .body(axum::body::Body::empty())
        .unwrap();
    use tower::ServiceExt;
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/xml");
    assert_eq!(
        resp.headers()["content-disposition"],
        format!("attachment; filename=sysmon_config_{acme}.xml").as_str()
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(&bytes[..], SYSMON_XML);
}

#[tokio::test]
async fn sysmon_deploy_posts_the_config_to_the_worker() {
    let probe = harness_or_skip!(None);
    let acme = probe.code("acme");
    let s3 = minio(&[(format!("{acme}/sysmon_config.xml"), SYSMON_XML)]).await;
    let worker = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/provision_worker/sysmon-config"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"success": true, "message": "Sysmon config deployed"})),
        )
        .mount(&worker)
        .await;
    let mut h = harness_or_skip!(None, &minio_env(&s3, Some(&worker)));
    h.suffix = probe.suffix.clone();
    h.seed().await;
    cleanup(&h).await;
    let responder = h.token(&format!("responder{}", h.suffix), "responder");
    let deploy = |code: String| {
        let h = &h;
        let responder = responder.clone();
        async move {
            h.call(
                "POST",
                &format!("/api/sysmon_config/deploy/{code}"),
                Some(&responder),
                None,
            )
            .await
        }
    };
    // No manager connector: urlparse(None).
    let (st, body) = deploy(acme.clone()).await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"success": false, "message": "Failed to get Wazuh endpoint", "customer_code": acme,
            "worker_success": false, "worker_message": null,
            "error_detail": "a bytes-like object is required, not 'str'"})
    );
    connector(
        &h,
        "Wazuh-Manager",
        "https://127.0.0.1:55000",
        Some("wazuh"),
        None,
    )
    .await;
    let (st, body) = deploy(acme.clone()).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": format!("Sysmon config successfully deployed for {acme}"),
            "customer_code": acme, "worker_success": true, "worker_message": "Sysmon config deployed",
            "error_detail": null})
    );
    let sent = worker.received_requests().await.unwrap();
    assert_eq!(sent.len(), 1);
    let ct = sent[0]
        .headers
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let boundary = ct.strip_prefix("multipart/form-data; boundary=").unwrap();
    assert_eq!(boundary.len(), 32);
    let body = String::from_utf8(sent[0].body.clone()).unwrap();
    assert!(
        body.contains(&format!("name=\"customer_code\"\r\n\r\n{acme}\r\n")),
        "{body}"
    );
    assert!(
        body.contains("filename=\"sysmon_config.xml\"\r\n\r\n<Sysmon"),
        "{body}"
    );
    assert_eq!(
        sent[0].headers.get("user-agent").unwrap(),
        "Python/3.11 aiohttp/3.13.5"
    );
    // Audited before the deploy.
    let n = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'response.sysmon_deploy' AND entity_id = '{acme}' \
             AND entity_type = 'sysmon_config' AND customer_code = '{acme}'"
        ))
        .await;
    assert!(n >= 1);
    // No config for this customer: the fetch's 404, as a result.
    let other = h.code("beta");
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/sysmon_config/deploy/{other}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body["message"],
        json!(format!("Failed to fetch Sysmon config for {other}"))
    );
    assert_eq!(
        body["error_detail"],
        json!(format!(
            "404: File {other}/sysmon_config.xml not found in bucket sysmon-configs"
        ))
    );
    // A responder of acme may not deploy beta's.
    let (st, _) = deploy(other).await;
    assert_eq!(st, 403);
    cleanup(&h).await;
}

// --- /api/copilot_action -------------------------------------------------------

const ACTION_KEY: &str = "e2e-action-key";

fn action_env(service: &MockServer, extra: &str) -> String {
    format!(
        "COPILOT_ACTION_URL={}\nCOPILOT_API_KEY={ACTION_KEY}\n{extra}",
        service.uri()
    )
}

fn action_item(name: &str) -> Value {
    json!({
        "copilot_action_name": name,
        "description": "Kill a process",
        "technology": "Linux",
        "script_parameters": [
            {"name": "Target", "type": "string", "required": true, "arg_position": "1"},
            {"name": "Mode", "type": "enum", "required": false, "enum": ["soft", "hard"]},
        ],
        "repo_url": "https://raw.example/kill.sh",
        "version": "1.2",
        "last_updated": "2026-10-01T08:00:00Z",
        "tags": ["process"],
    })
}

/// The CoPilot Action service: `/inventory`, `/metrics` and the detail of
/// `kill-process` (`missing` is a 404, `broken` a 500, `gone` a
/// `success: false`).
async fn action_service() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/inventory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "copilot_actions": [action_item("kill-process")],
            "message": "Returned 1 of 44 matching items",
            "success": true,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/inventory/kill-process"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "copilot_action": action_item("kill-process"),
            "message": "ok",
            "success": true,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/inventory/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"detail": "nope"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/inventory/broken"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/inventory/gone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "copilot_action": action_item("gone"),
            "message": "Action gone was Not Found upstream",
            "success": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok", "metrics": {"actions": 44}, "extra": 1,
        })))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn copilot_action_inventory_is_the_services() {
    let service = action_service().await;
    let h = harness_or_skip!(None, &action_env(&service, ""));
    h.seed().await;
    let responder = h.token(&format!("responder{}", h.suffix), "responder");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let get = |url: &'static str| {
        let h = &h;
        let responder = responder.clone();
        async move { h.call("GET", url, Some(&responder), None).await }
    };

    let (st, body) = h
        .call(
            "GET",
            "/api/copilot_action/technologies",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        json!("Insufficient permissions. Required one of: admin, responder")
    );
    let (st, body) = get("/api/copilot_action/technologies").await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"technologies": ["Wazuh", "Linux", "Windows", "macOS", "Network", "Cloud", "Velociraptor"],
            "total": 7, "message": "Successfully retrieved available technologies", "success": true})
    );

    // The query is validated before anything is asked.
    let (st, body) = get("/api/copilot_action/inventory?technology=Solaris&limit=0").await;
    assert_eq!(st, 422);
    assert_eq!(
        body["details"],
        json!([
            {"field": "technology", "error_type": "enum", "message": "Value is not a valid enumeration member."},
            {"field": "limit", "error_type": "greater_than_equal", "message": "Value is too small."},
        ])
    );
    assert!(service.received_requests().await.unwrap().is_empty());

    let (st, body) = get("/api/copilot_action/inventory").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({
            "copilot_actions": [{
                "copilot_action_name": "kill-process", "description": "Kill a process",
                "technology": "Linux", "icon": "linux",
                "script_parameters": [
                    {"name": "Target", "type": "string", "required": true, "description": null,
                        "default": null, "enum": null, "arg_position": "1"},
                    {"name": "Mode", "type": "enum", "required": false, "description": null,
                        "default": null, "enum": ["soft", "hard"], "arg_position": null},
                ],
                "repo_url": "https://raw.example/kill.sh", "script_name": null, "version": "1.2",
                "last_updated": "2026-10-01T08:00:00Z", "category": null, "tags": ["process"],
            }],
            "message": "Returned 1 of 44 matching items", "success": true, "total": 44,
            "count": 1, "limit": 100, "offset": 0, "has_more": true, "next_offset": 100,
            "prev_offset": null,
        })
    );
    let (st, body) =
        get("/api/copilot_action/inventory?technology=Linux&q=kill&limit=5&offset=10&refresh=true")
            .await;
    assert_eq!(st, 200);
    assert_eq!(
        (body["limit"].clone(), body["prev_offset"].clone()),
        (json!(5), json!(5))
    );
    let (st, body) = get("/api/copilot_action/inventory/count?tag=process").await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"total": 44, "message": "Successfully retrieved inventory count", "success": true,
            "current_page": 1, "total_pages": 1, "has_next": false, "has_prev": false,
            "items_per_page": 100, "total_items": 44})
    );
    let sent = service.received_requests().await.unwrap();
    let queries: Vec<Option<String>> = sent
        .iter()
        .map(|r| r.url.query().map(str::to_string))
        .collect();
    assert_eq!(
        queries,
        vec![
            None,
            Some("technology=Linux&q=kill&limit=5&offset=10&refresh=true".into()),
            Some("tag=process&limit=1".into()),
        ]
    );
    for (name, value) in [
        ("x-api-key", ACTION_KEY),
        ("module-version", "1.0.0"),
        ("accept", "application/json"),
        ("accept-encoding", "gzip, deflate"),
        ("user-agent", "python-httpx/0.28.1"),
        ("connection", "keep-alive"),
    ] {
        assert_eq!(sent[0].headers.get(name).unwrap(), value, "{name}");
    }

    let (st, body) = get("/api/copilot_action/inventory/kill-process").await;
    assert_eq!(st, 200);
    assert_eq!(body["copilot_action"]["icon"], json!("linux"));
    assert_eq!(body["message"], json!("ok"));
    let (st, body) = get("/api/copilot_action/inventory/missing").await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (404, json!("Action 'missing' not found"))
    );
    let (st, body) = get("/api/copilot_action/inventory/gone").await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (404, json!("Action gone was Not Found upstream"))
    );
    let (st, body) = get("/api/copilot_action/inventory/broken").await;
    assert_eq!(st, 500);
    let message = body["message"].as_str().unwrap();
    assert!(
        message.starts_with(
            "Error fetching action details: 1 validation error for ActionDetailResponse\ncopilot_action\n  \
             Input should be a valid dictionary or instance of ActiveResponseItem [type=model_type, \
             input_value=None, input_type=NoneType]"
        ),
        "{message}"
    );
    let (st, body) = get("/api/copilot_action/metrics").await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"status": "ok", "metrics": {"actions": 44},
            "message": "Successfully retrieved inventory metrics", "success": true})
    );
}

#[tokio::test]
async fn copilot_action_without_a_license_key_is_a_500() {
    let service = action_service().await;
    let h = harness_or_skip!(None, &format!("COPILOT_ACTION_URL={}\n", service.uri()));
    h.seed().await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    for url in [
        "/api/copilot_action/inventory",
        "/api/copilot_action/inventory/count",
        "/api/copilot_action/inventory/kill-process",
        "/api/copilot_action/metrics",
    ] {
        let (st, body) = h.call("GET", url, Some(&admin), None).await;
        assert_eq!(
            (st.as_u16(), body),
            (
                500,
                json!({"success": false, "message": "COPILOT_API_KEY environment variable not configured"})
            ),
            "{url}"
        );
    }
    // Validated first.
    let (st, _) = h
        .call(
            "GET",
            "/api/copilot_action/inventory?offset=-1",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 422);
    // The service is unreachable: its failure is the answer.
    let h = harness_or_skip!(
        None,
        "COPILOT_ACTION_URL=http://127.0.0.1:9\nCOPILOT_API_KEY=k\n"
    );
    h.seed().await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (st, body) = h
        .call("GET", "/api/copilot_action/inventory", Some(&admin), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"copilot_actions": [], "message": "HTTP error fetching inventory: All connection attempts failed",
            "success": false, "total": 0, "count": 0, "limit": 100, "offset": 0, "has_more": false,
            "next_offset": null, "prev_offset": null})
    );
    let (st, body) = h
        .call("GET", "/api/copilot_action/metrics", Some(&admin), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body["message"],
        json!("HTTP error fetching metrics: All connection attempts failed")
    );
}

/// MinIO with the `velociraptor-artifacts` bucket taking any object.
async fn artifacts_minio() -> MockServer {
    use wiremock::matchers::{path_regex, query_param};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/velociraptor-artifacts"))
        .and(query_param("location", ""))
        .respond_with(ResponseTemplate::new(200).set_body_raw(LOCATION, "application/xml"))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/velociraptor-artifacts"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("^/velociraptor-artifacts/.+"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"e\""))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn copilot_action_invoke_runs_on_the_callers_hosts_only() {
    use copilot_velociraptor::testing::{Answer, StandIn};
    let probe = harness_or_skip!(None);
    let s = probe.suffix.clone();
    let host = format!("act-{s}");
    let host_b = format!("actb-{s}");
    let service = action_service().await;
    let s3 = artifacts_minio().await;
    let velo = StandIn::start(move |args| {
        let vql = args.query[0].vql.clone();
        if vql.starts_with("SELECT base64encode(") {
            Answer::rows(&[r#"[{"Data": "UEsDBA=="}]"#])
        } else if vql.starts_with("SELECT os_info.hostname AS Hostname") {
            Answer::rows(&[r#"[{"Hostname": "velo-host"}]"#])
        } else if vql.starts_with("SELECT * FROM watch_monitoring") {
            Answer::rows(&[r#"[{"FlowId": "F.ABC"}]"#])
        } else if vql.starts_with("SELECT * FROM source(") {
            Answer::rows(&[r#"[{"Stdout": "killed"}]"#])
        } else if let Some(call) = vql
            .strip_prefix("SELECT ")
            .and_then(|v| v.strip_suffix(" FROM scope()"))
        {
            let row = json!([{ call: {"flow_id": "F.ABC"} }]).to_string();
            Answer::rows(&[&row])
        } else {
            Answer::rows(&["[]"])
        }
    })
    .await;
    let mut h = harness_or_skip!(None, &action_env(&service, &minio_env(&s3, None)));
    h.suffix = s.clone();
    h.seed().await;
    cleanup(&h).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let a1 = agent(&h, "a1", &host, &acme, "Ubuntu 24.04").await;
    let b1 = agent(&h, "b1", &host, &beta, "Ubuntu 22.04").await;
    agent(&h, "b2", &host_b, &beta, "Ubuntu 22.04").await;
    h.exec(&format!(
        "UPDATE agents SET velociraptor_org = 'root', velociraptor_id = CONCAT('C.', agent_id) \
         WHERE agent_id LIKE '{s}%'"
    ))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let config = velo.write_api_config(dir.path());
    connector(&h, "Velociraptor", "https://velo", None, Some(&config)).await;
    let responder = h.token(&format!("responder{s}"), "responder");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let admin = h.token(&format!("admin{s}"), "admin");
    let invoke = |token: String, body: Value| {
        let h = &h;
        async move {
            h.call(
                "POST",
                "/api/copilot_action/invoke",
                Some(&token),
                Some(body),
            )
            .await
        }
    };
    let body = |hosts: Value, params: Value| json!({"copilot_action_name": "kill-process", "agent_names": hosts, "parameters": params});

    let (st, _) = invoke(analyst.clone(), body(json!([host]), json!({"Target": "1"}))).await;
    assert_eq!(st, 403);
    // The body as Pydantic reads it.
    let (st, resp) = invoke(
        responder.clone(),
        json!({"copilot_action_name": "kill-process", "parameters": {"Target": 1}}),
    )
    .await;
    assert_eq!(st, 422);
    assert_eq!(
        resp["details"],
        json!([
            {"field": "agent_names", "error_type": "missing", "message": "Missing data for required field."},
            {"field": "str", "error_type": "value_error",
                "message": "parameters.Target.str: Input should be a valid string"},
            {"field": "list[ParameterKeyValue]", "error_type": "value_error",
                "message": "parameters.Target.list[ParameterKeyValue]: Input should be a valid list"},
        ])
    );
    let (st, resp) = invoke(responder.clone(), body(json!([]), json!(null))).await;
    assert_eq!(
        (st.as_u16(), resp["message"].clone()),
        (
            400,
            json!("Name at least one agent to invoke the action on")
        )
    );
    // One foreign host refuses the request, before anything runs.
    let (st, resp) = invoke(
        responder.clone(),
        body(json!([host, host_b]), json!({"Target": "1"})),
    )
    .await;
    assert_eq!(
        (st.as_u16(), resp["message"].clone()),
        (403, json!(format!("Access denied to host {host_b}")))
    );
    let (st, resp) = invoke(
        responder.clone(),
        body(json!([format!("nohost-{s}")]), json!({"Target": "1"})),
    )
    .await;
    assert_eq!(st, 403, "an unknown host is nobody's: {resp}");
    let (st, resp) = invoke(
        admin.clone(),
        body(json!([format!("nohost-{s}")]), json!({"Target": "1"})),
    )
    .await;
    assert_eq!(
        (st.as_u16(), resp["message"].clone()),
        (
            404,
            json!(format!("Agents with hostnames ['nohost-{s}'] not found"))
        )
    );
    assert!(velo.messages().is_empty());
    let audits = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'response.copilot_action_invoke' \
             AND entity_type = 'copilot_action' AND entity_id = 'kill-process' AND actor_username = 'responder{s}'"
        ))
        .await;
    assert_eq!(audits, 0, "refused before the audit row");

    // The parameters are checked against the action's.
    let (st, resp) = invoke(
        responder.clone(),
        body(json!([host]), json!({"Target": "1", "Other": "x"})),
    )
    .await;
    assert_eq!(
        (st.as_u16(), resp["message"].clone()),
        (
            400,
            json!(
                "Invalid parameters provided: ['Other']. Valid parameters are: ['Target', 'Mode', 'ScriptURL']"
            )
        )
    );
    let (st, resp) = invoke(
        responder.clone(),
        body(json!([host]), json!({"Mode": "soft"})),
    )
    .await;
    assert_eq!(
        (st.as_u16(), resp["message"].clone()),
        (400, json!("Missing required parameters: ['Target']"))
    );

    // The responder's host only: beta's agent of the same name is not touched.
    let (st, resp) = invoke(
        responder.clone(),
        body(json!([host]), json!({"Mode": "it's", "Target": "1234"})),
    )
    .await;
    assert_eq!(st, 200, "{resp}");
    let client_a = format!("C.{a1}");
    let zip = format!("velo-host-{client_a}-F.ABC.zip");
    assert_eq!(
        resp,
        json!({
            "responses": [{
                "message": "Successfully executed query", "success": true,
                "results": [{"Stdout": "killed"}],
                "file_info": {
                    "success": true,
                    "message": "Successfully fetched file from Velociraptor and uploaded to MinIO",
                    "bucket_name": "velociraptor-artifacts",
                    "object_key": format!("{a1}/F.ABC/{zip}"),
                    "file_name": zip,
                    "file_size": 4,
                    "file_hash": "8dcc7e601606217f3b754766511182a916b17e9a26a94c9d887104eba92e9bb2",
                },
            }],
            "message": "Successfully invoked action on all 1 agent(s). Check the appropriate Grafana dashboard for results.",
            "success": true,
        })
    );
    let vql = velo.vql();
    assert_eq!(
        vql[0],
        format!(
            "SELECT collect_client(org_id='root', client_id='{client_a}', \
             artifacts=['Linux.Execute.RemoteBashScript'], env=dict(`ScriptURL`='https://raw.example/kill.sh', \
             `Arg1`='1234', `Mode`='it\\'s')) FROM scope()"
        )
    );
    assert!(
        vql.iter().all(|q| !q.contains(&format!("C.{b1}"))),
        "{vql:?}"
    );
    let rows = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM agent_datastore WHERE agent_id = '{a1}' AND flow_id = 'F.ABC' \
             AND object_key = '{a1}/F.ABC/{zip}' AND file_size = 4 AND status = 'completed'"
        ))
        .await;
    assert_eq!(rows, 1);
    let puts: Vec<String> = s3
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "PUT")
        .map(|r| r.url.path().to_string())
        .collect();
    assert_eq!(
        puts,
        vec![format!("/velociraptor-artifacts/{a1}/F.ABC/{zip}")]
    );
    let audits = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'response.copilot_action_invoke' \
             AND entity_id = 'kill-process' AND actor_username = 'responder{s}'"
        ))
        .await;
    assert_eq!(
        audits, 3,
        "the parameter checks run after the audit row, as in Python"
    );

    // An admin reaches every agent of that name; an OS without an artifact
    // fails on its own.
    h.exec(&format!(
        "UPDATE agents SET os = 'Solaris 11' WHERE agent_id = '{b1}'"
    ))
    .await;
    let (st, resp) = invoke(admin.clone(), body(json!([host]), json!({"Target": "1"}))).await;
    assert_eq!(st, 200, "{resp}");
    assert_eq!(
        resp["message"],
        json!("Partially successful: 1 succeeded, 1 failed")
    );
    let failed: Vec<&Value> = resp["responses"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["success"] == json!(false))
        .collect();
    assert_eq!(
        failed,
        vec![&json!({
            "message": format!("Failed to invoke action on {host}: 500: Error invoking action on agent {host}: 400: Unsupported OS: Solaris 11"),
            "success": false, "results": [], "file_info": null,
        })]
    );
    cleanup(&h).await;
}
