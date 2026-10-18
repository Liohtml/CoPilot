//! End-to-end tests of the connector ports (`copilot-graylog`,
//! `copilot-influxdb`, `copilot-grafana`, `copilot-portainer`):
//! `/api/graylog`, `/api/influxdb`, `/api/reporting`, `/api/user` and
//! `/api/portainer` through the production router on a real MySQL, Graylog
//! (6.x and 7.x), the Event Shipper, InfluxDB, Grafana and Portainer replaced
//! by local stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13308/copilot \
//!   cargo test -p copilot --test e2e_graylog -- --test-threads=1
//! ```
//!
//! The `Graylog`, `Event Shipper`, `InfluxDB`, `Grafana` and `Portainer`
//! connector rows are replaced for each test and removed again (run
//! single-threaded).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::StatusCode;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use copilot_auth::pyvalue::loads;
use copilot_graylog::client::EntityKind;

#[macro_use]
mod common;
use common::*;

async fn set_connector(h: &Harness, name: &str, url: Option<&str>, extra: Option<&str>) {
    sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
        .bind(name)
        .execute(h.db.pool())
        .await
        .unwrap();
    if let Some(url) = url {
        sqlx::query(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, \
             connector_last_updated, connector_username, connector_password, connector_api_key, \
             connector_description, connector_supports, connector_configured, connector_verified, \
             connector_accepts_host_only, connector_accepts_api_key, \
             connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
             (?, '3', ?, UTC_TIMESTAMP(), 'admin', 'secret', NULL, 'e2e', 'e2e', 1, 1, 0, 0, 1, 0, \
             1, ?, 1)",
        )
        .bind(name)
        .bind(url)
        .bind(extra)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

async fn users(h: &Harness) -> (String, String, String) {
    let s = &h.suffix;
    for (name, role) in [("gadmin", 1), ("ganalyst", 2), ("gportal", 4)] {
        h.exec(&format!(
            "INSERT INTO `user` (username, password, email, created_at, role_id) \
             VALUES ('{name}{s}', 'x', '{name}@example.com', UTC_TIMESTAMP(), {role})"
        ))
        .await;
    }
    (
        h.token(&format!("gadmin{s}"), "admin"),
        h.token(&format!("ganalyst{s}"), "analyst"),
        h.token(&format!("gportal{s}"), "customer_user"),
    )
}

fn stream(id: &str, title: &str) -> Value {
    json!({
        "id": id, "creator_user_id": "admin", "outputs": [], "matching_type": "AND",
        "description": null, "created_at": "2026-01-01T00:00:00.000Z", "disabled": false,
        "rules": [{"field": "f", "stream_id": id, "id": "r1", "type": 1, "inverted": false, "value": "v"}],
        "title": title, "content_pack": null, "remove_matches_from_default_stream": false,
        "index_set_id": "is1", "is_default": false, "is_editable": true, "categories": []
    })
}

fn input(id: &str, tls_password: Value) -> Value {
    json!({
        "title": "GELF", "global": true, "name": "GELF TCP", "content_pack": null,
        "created_at": "2026-01-01T00:00:00.000Z", "type": "gelf", "creator_user_id": "admin",
        "attributes": {"recv_buffer_size": 1048576, "number_worker_threads": 2,
            "bind_address": "0.0.0.0", "port": 12201, "tls_key_password": tls_password,
            "max_message_size": 2097152},
        "static_fields": {}, "node": null, "id": id
    })
}

#[tokio::test]
async fn reads_follow_the_python_models() {
    let h = harness_or_skip!(None);
    let (_, analyst, portal) = users(&h).await;
    let graylog = MockServer::start().await;
    set_connector(&h, "Graylog", Some(&graylog.uri()), None).await;
    let mut s2 = stream("s2", "Two");
    s2.as_object_mut().unwrap().remove("description");
    Mock::given(method("GET"))
        .and(path("/api/streams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": "2",
            "streams": [stream("s1", "One"), s2]
        })))
        .mount(&graylog)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "inputs": [input("i6", json!("")), input("i7", json!({"is_set": true}))]
        })))
        .mount(&graylog)
        .await;

    let (status, body) = h
        .call("GET", "/api/graylog/streams", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], 2, "lax int");
    assert_eq!(body["streams"][0]["description"], Value::Null);
    assert_eq!(body["streams"][1]["description"], "No description provided");
    let keys: Vec<&str> = body["streams"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys[..4],
        [
            "content_pack",
            "created_at",
            "creator_user_id",
            "description"
        ]
    );
    assert!(!keys.contains(&"categories"), "extra keys are dropped");

    let (status, body) = h
        .call(
            "GET",
            "/api/graylog/inputs/configured",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let attrs = |i: usize| body["configured_inputs"][i]["attributes"].clone();
    assert_eq!(attrs(0)["tls_key_password"], "");
    assert_eq!(
        attrs(1)["tls_key_password"],
        "***",
        "Graylog 7's EncryptedValue"
    );
    assert_eq!(body["configured_inputs"][0]["global"], true, "by alias");

    let (status, body) = h
        .call("GET", "/api/graylog/streams", Some(&portal), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["message"],
        "Insufficient permissions. Required one of: admin, analyst"
    );

    // A model Graylog's answer does not fit: the ValueError handler's 400.
    graylog.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"inputs": [{"title": 5}]})))
        .mount(&graylog)
        .await;
    let (status, body) = h
        .call(
            "GET",
            "/api/graylog/inputs/configured",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"].as_str().unwrap().starts_with(
            "9 validation errors for ConfiguredInput\ntitle\n  Input should be a valid string"
        ),
        "{body}"
    );
    set_connector(&h, "Graylog", None, None).await;
    let (status, body) = h
        .call("GET", "/api/graylog/streams", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["message"], "Connector Graylog not found");
}

#[tokio::test]
async fn url_allowlist_falls_back_to_the_6x_path() {
    let h = harness_or_skip!(None);
    let (admin, analyst, _) = users(&h).await;
    let graylog = MockServer::start().await;
    set_connector(&h, "Graylog", Some(&graylog.uri()), None).await;
    let entries = json!({"entries": [{"id": "1", "value": "https://x", "title": "x", "type": "literal"}], "disabled": false});
    Mock::given(method("GET"))
        .and(path("/api/system/urlallowlist"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "HTTP 404 Not Found"})),
        )
        .mount(&graylog)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system/urlwhitelist"))
        .respond_with(ResponseTemplate::new(200).set_body_json(entries.clone()))
        .mount(&graylog)
        .await;
    let (status, body) = h
        .call("GET", "/api/graylog/url_whitelist", Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["url_whitelist_entries"], entries);
    let paths: Vec<String> = graylog
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert_eq!(
        paths,
        ["/api/system/urlallowlist", "/api/system/urlwhitelist"]
    );
    // get_current_user(scopes=["admin"]) words a missing scope differently.
    let (status, body) = h
        .call("GET", "/api/graylog/url_whitelist", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["message"],
        "Insufficient permissions. Required scope: admin"
    );
    set_connector(&h, "Graylog", None, None).await;
}

#[tokio::test]
async fn management_verifies_ids_against_graylog() {
    let h = harness_or_skip!(None);
    let (admin, _, _) = users(&h).await;
    let graylog = MockServer::start().await;
    set_connector(&h, "Graylog", Some(&graylog.uri()), None).await;
    Mock::given(method("GET"))
        .and(path("/api/streams"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"total": 1, "streams": [stream("s1", "One")]})),
        )
        .mount(&graylog)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/streams/s1/pause"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&graylog)
        .await;
    let (status, body) = h
        .call(
            "POST",
            "/api/graylog/stream/stop",
            Some(&admin),
            Some(json!({"stream_id": " s1\u{1f}"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "Successfully stopped stream s1"})
    );
    let pause = graylog.received_requests().await.unwrap();
    let pause = pause.last().unwrap();
    assert_eq!(pause.headers["x-requested-by"], "CoPilot");
    assert_eq!(pause.headers["content-length"], "0");
    assert_eq!(
        pause.headers["authorization"], "Basic YWRtaW46c2VjcmV0",
        "admin:secret"
    );
    let (status, body) = h
        .call(
            "POST",
            "/api/graylog/stream/start",
            Some(&admin),
            Some(json!({"stream_id": "nope"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Stream ID 'nope' is not managed by Graylog or no longer exists."
    );
    let (status, body) = h
        .call(
            "POST",
            "/api/graylog/stream/start",
            Some(&admin),
            Some(json!({"stream": 1})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"][0]["field"], "stream_id");
    set_connector(&h, "Graylog", None, None).await;
}

async fn graylog_with_version(version: Option<&str>) -> MockServer {
    let graylog = MockServer::start().await;
    let system = match version {
        Some(v) => ResponseTemplate::new(200).set_body_json(json!({"version": v})),
        None => ResponseTemplate::new(500).set_body_string("down"),
    };
    Mock::given(method("GET"))
        .and(path("/api/system"))
        .respond_with(system)
        .mount(&graylog)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/streams"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"stream_id": "new"})))
        .mount(&graylog)
        .await;
    graylog
}

#[tokio::test]
async fn entity_creation_is_wrapped_for_graylog_7_only() {
    for (version, wrapped) in [
        (Some("7.0.1+abc"), true),
        (Some("6.1.4"), false),
        (Some("8.0.0"), true),
        (None, false),
    ] {
        let h = harness_or_skip!(None);
        let graylog = graylog_with_version(version).await;
        set_connector(&h, "Graylog", Some(&graylog.uri()), None).await;
        let entity = loads(r#"{"title": "ACME", "index_set_id": "is1"}"#).unwrap();
        let reply = h
            .app
            .graylog
            .create_entity("Graylog", &EntityKind::Stream, entity, None)
            .await
            .unwrap();
        assert_eq!(reply.message, "Successfully created data");
        let requests = graylog.received_requests().await.unwrap();
        let post = requests
            .iter()
            .find(|r| r.method.as_str() == "POST")
            .unwrap();
        let body = String::from_utf8(post.body.clone()).unwrap();
        let want = if wrapped {
            r#"{"entity": {"title": "ACME", "index_set_id": "is1"}}"#
        } else {
            r#"{"title": "ACME", "index_set_id": "is1"}"#
        };
        assert_eq!(body, want, "{version:?}");
        // The probe is cached: a second creation does not ask again.
        let entity = loads(r#"{"title": "B"}"#).unwrap();
        h.app
            .graylog
            .create_entity("Graylog", &EntityKind::Stream, entity, None)
            .await
            .unwrap();
        let probes = graylog
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/api/system")
            .count();
        assert_eq!(probes, 1, "{version:?}");
        set_connector(&h, "Graylog", None, None).await;
    }
}

#[tokio::test]
async fn event_definitions_are_paged_until_the_total() {
    let h = harness_or_skip!(None);
    let (_, analyst, _) = users(&h).await;
    let graylog = MockServer::start().await;
    set_connector(&h, "Graylog", Some(&graylog.uri()), None).await;
    let def = |id: &str| {
        json!({"id": id, "title": id, "description": "d", "priority": 1, "alert": true,
            "config": {"conditions": {"expression": {"expr": ">", "left": {"expr": "number-ref", "ref": "x"}, "right": {"expr": "number", "value": 1}}}},
            "field_spec": {}, "key_spec": [], "notification_settings": {"grace_period_ms": 0, "backlog_size": 0},
            "storage": [{"type": "persist", "streams": []}], "_scope": "DEFAULT"})
    };
    for (page, items) in [("1", vec![def("a"), def("b")]), ("2", vec![def("c")])] {
        Mock::given(method("GET"))
            .and(path("/api/events/definitions"))
            .and(query_param("page", page))
            .and(query_param("per_page", "500"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"event_definitions": items, "total": 3})),
            )
            .mount(&graylog)
            .await;
    }
    let (status, body) = h
        .call(
            "GET",
            "/api/graylog/event/definitions",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["event_definitions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["a", "b", "c"]);
    assert_eq!(
        body["event_definitions"][0]["config"]["conditions"]["expression"]["left"],
        json!({"expr": "number-ref", "ref": "x", "value": null, "left": null, "right": null})
    );
    assert!(body["event_definitions"][0].get("_scope").is_none());
    set_connector(&h, "Graylog", None, None).await;
}

#[tokio::test]
async fn the_receiver_ships_one_gelf_frame() {
    let h = harness_or_skip!(None);
    let (admin, _, _) = users(&h).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    set_connector(&h, "Event Shipper", Some("127.0.0.1"), Some(&port)).await;
    let accept = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.unwrap();
        buf
    });
    let (status, body) = h
        .call(
            "POST",
            "/api/graylog/receiver",
            Some(&admin),
            Some(json!({"integration": "mimecast", "customer_code": "acme", "drop": null, "x": 1})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"message": "Message forwarded to Graylog", "success": true})
    );
    let frame = String::from_utf8(accept.await.unwrap()).unwrap();
    let host = copilot_graylog::gelf::getfqdn();
    assert_eq!(
        frame,
        format!(
            "{{\"version\": 1.1, \"host\": \"{host}\", \"short_message\": \"{{\\\"integration\\\": \
             \\\"mimecast\\\", \\\"customer_code\\\": \\\"acme\\\", \\\"x\\\": 1}}\", \"level\": 1}}\0"
        )
    );
    let (status, body) = h
        .call(
            "POST",
            "/api/graylog/receiver",
            Some(&admin),
            Some(json!({"integration": "x"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"].as_str().unwrap().starts_with(
            "1 validation error for EventShipperPayload\ncustomer_code\n  Field required"
        ),
        "{body}"
    );
    set_connector(&h, "Event Shipper", None, None).await;
    let (status, body) = h
        .call(
            "POST",
            "/api/graylog/receiver",
            Some(&admin),
            Some(json!({"integration": "x", "customer_code": "y"})),
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body["message"],
        "Failed to initialize GelfLogger: 'NoneType' object is not subscriptable"
    );
}

async fn set_influx(h: &Harness, url: Option<&str>, key: Option<&str>, extra: Option<&str>) {
    set_connector(h, "InfluxDB", url, extra).await;
    sqlx::query("UPDATE connectors SET connector_api_key = ? WHERE connector_name = 'InfluxDB'")
        .bind(key)
        .execute(h.db.pool())
        .await
        .unwrap();
}

/// `last()` per series: a unit that failed and recovered (two series, the
/// state tag `active` differs), and one still failed.
const INFLUX_STATES: &str = "#group,false,false,false,false,true,true,true,true,true\r\n\
    #datatype,string,long,dateTime:RFC3339,string,string,string,string,string,string\r\n\
    #default,_result,,,,,,,,\r\n\
    ,result,table,_time,_value,_check_id,_check_name,_level,host,active\r\n\
    ,,0,2026-10-15T10:00:00Z,wazuh failed,c1,CRITICAL SERVICES CHECK,crit,h1,failed\r\n\
    ,,1,2026-10-15T10:05:00Z,wazuh running,c1,CRITICAL SERVICES CHECK,ok,h1,active\r\n\
    ,,2,2026-10-15T10:04:00.5Z,graylog failed,c1,CRITICAL SERVICES CHECK,crit,h2,failed\r\n\r\n";

/// The rows query's answer (`group()`: one table, newest first).
const INFLUX_ROWS: &str = "#group,false,false,false,false,false,false,false,false,false\r\n\
    #datatype,string,long,dateTime:RFC3339,string,string,string,string,string,string\r\n\
    #default,_result,,,,,,,,\r\n\
    ,result,table,_time,_value,_check_id,_check_name,_level,host,active\r\n\
    ,,0,2026-10-15T10:05:00Z,wazuh running,c1,CRITICAL SERVICES CHECK,ok,h1,active\r\n\
    ,,0,2026-10-15T10:04:00.5Z,graylog failed,c1,CRITICAL SERVICES CHECK,crit,h2,failed\r\n\
    ,,0,2026-10-15T10:00:00Z,wazuh failed,c1,CRITICAL SERVICES CHECK,crit,h1,failed\r\n\r\n";

#[tokio::test]
async fn influxdb_alerts_follow_the_current_state() {
    let h = harness_or_skip!(None);
    let (_, analyst, portal) = users(&h).await;
    let influx = MockServer::start().await;
    set_influx(
        &h,
        Some(&influx.uri()),
        Some("tok"),
        Some("SOC FORTRESS,telegraf"),
    )
    .await;
    for (needle, csv) in [
        ("|> last()", INFLUX_STATES),
        ("|> limit(n: 500)", INFLUX_ROWS),
    ] {
        Mock::given(method("POST"))
            .and(path("/api/v2/query"))
            .and(query_param("org", "SOC FORTRESS"))
            .and(header("authorization", "Token tok"))
            .and(header("user-agent", "influxdb-client-python/1.50.0"))
            .and(body_string_contains(needle))
            .respond_with(ResponseTemplate::new(200).set_body_string(csv))
            .mount(&influx)
            .await;
    }

    let (status, body) = h
        .call("GET", "/api/influxdb/alerts", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], true, "{body}");
    let statuses: Vec<(&str, &str)> = body["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["message"].as_str().unwrap(),
                a["status"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        statuses,
        [
            ("wazuh running", "cleared"),
            ("graylog failed", "active"),
            ("wazuh failed", "cleared"),
        ],
        "a failure followed by a recovery is history"
    );
    assert_eq!(body["alerts"][1]["time"], "2026-10-15T10:04:00.500000Z");
    assert_eq!(body["alerts"][1]["sensor_type"], "CRITICAL");
    assert_eq!(body["alerts"][1]["severity"], "critical");
    assert_eq!(
        (&body["active_alerts_count"], &body["cleared_alerts_count"]),
        (&json!(1), &json!(2))
    );

    let (_, body) = h
        .call(
            "GET",
            "/api/influxdb/alerts?latest_only=true&status=active",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["alerts"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["alerts"][0]["message"], "graylog failed");

    let requests = influx.received_requests().await.unwrap();
    let sent: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        sent["dialect"]["annotations"],
        json!(["datatype", "group", "default"])
    );
    assert!(
        sent["query"].as_str().unwrap().starts_with(
            "import \"regexp\"\nfrom(bucket: \"_monitoring\")\n    |> range(start: -7d)"
        )
    );
    assert_eq!(requests[0].url.query(), Some("org=SOC+FORTRESS"));

    let (status, body) = h
        .call(
            "GET",
            "/api/influxdb/alerts?days=0&status=x",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (status, _) = h
        .call("GET", "/api/influxdb/alerts", Some(&portal), None)
        .await;
    assert_ne!(status, StatusCode::OK);
    set_influx(&h, None, None, None).await;
}

#[tokio::test]
async fn influxdb_metrics_and_failures() {
    let h = harness_or_skip!(None);
    let (admin, analyst, _) = users(&h).await;
    let influx = MockServer::start().await;
    set_influx(&h, Some(&influx.uri()), Some("tok"), Some("SOC,telegraf")).await;
    Mock::given(method("POST"))
        .and(path("/api/v2/query"))
        .and(body_string_contains(
            "schema.tagValues(bucket: \\\"telegraf\\\", tag: \\\"host\\\")",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "#datatype,string,long,string\r\n#group,false,false,false\r\n#default,_result,,\r\n\
             ,result,table,_value\r\n,,0,web-01\r\n,,0,\r\n,,0,db-01\r\n\r\n",
        ))
        .mount(&influx)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v2/query"))
        .and(body_string_contains("usage_system"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("x-platform-error-code", "unauthorized")
                .set_body_string("{\"code\":\"unauthorized\"}"),
        )
        .mount(&influx)
        .await;

    let (status, body) = h
        .call("GET", "/api/influxdb/metrics/hosts", Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "Successfully retrieved hosts", "hosts": ["db-01", "web-01"]})
    );

    let (status, body) = h
        .call(
            "GET",
            "/api/influxdb/metrics/cpu?host=web-01",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let message = body["message"].as_str().unwrap();
    assert!(
        message.starts_with("Error fetching CPU metrics: (401)\nReason: Unauthorized\nHTTP response headers: <CIMultiDictProxy("),
        "{message}"
    );
    assert!(
        message.contains("'X-Platform-Error-Code': 'unauthorized'"),
        "{message}"
    );
    assert!(
        message.ends_with("HTTP response body: b'{\"code\":\"unauthorized\"}'\n"),
        "{message}"
    );
    assert_eq!(body["data"], json!({}));

    let (status, body) = h
        .call("GET", "/api/influxdb/metrics/cpu", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    set_influx(&h, Some(&influx.uri()), Some("tok"), Some("SOC")).await;
    let (_, body) = h
        .call(
            "GET",
            "/api/influxdb/metrics/memory?host=x",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        body,
        json!({"success": false, "message": "Invalid connector_extra_data format for InfluxDB. Expected 'ORG,BUCKET'.", "data": {}})
    );
    set_influx(&h, Some(&influx.uri()), Some("tok"), None).await;
    let (_, body) = h
        .call("GET", "/api/influxdb/check-names", Some(&analyst), None)
        .await;
    assert_eq!(
        body["message"],
        "Failed to connect to InfluxDB: 500: Failed to create InfluxDB client: 'NoneType' object has no attribute 'split'"
    );
    set_influx(&h, None, None, None).await;
    let (_, body) = h
        .call("GET", "/api/influxdb/alerts", Some(&analyst), None)
        .await;
    assert_eq!(body["message"], "InfluxDB connector not found");
    assert_eq!(body["total_count"], 0);
}

#[tokio::test]
async fn grafana_reporting_reads_and_links() {
    let legacy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/reporting/generate-report"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python"})))
        .expect(0)
        .mount(&legacy)
        .await;
    let h = harness_or_skip!(Some(&legacy));
    let (_, analyst, portal) = users(&h).await;
    let grafana = MockServer::start().await;
    set_connector(&h, "Grafana", Some(&grafana.uri()), None).await;
    let basic = "Basic YWRtaW46c2VjcmV0"; // admin:secret
    Mock::given(method("GET"))
        .and(path("/api/orgs"))
        .and(header("authorization", basic))
        .and(header("user-agent", "grafana-client/5.1.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "name": "Main Org."},
            {"id": "44", "name": "ACME", "extra": true}
        ])))
        .mount(&grafana)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/user/using/44"))
        .and(header("content-length", "0"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "Active organization changed"})),
        )
        .mount(&grafana)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": 1}])))
        .mount(&grafana)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/uid/u1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"dashboard": {"panels": [
                {"id": 1, "title": "Row", "type": "row"},
                {"id": 2, "title": "Graph", "type": "timeseries", "gridPos": {"h": 1}}
            ]}})),
        )
        .mount(&grafana)
        .await;

    let (status, body) = h
        .call("GET", "/api/reporting/orgs", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["orgs"],
        json!([{"id": 1, "name": "Main Org."}, {"id": 44, "name": "ACME"}])
    );

    // The search answer misses required fields: the response model's
    // ValidationError is the ValueError handler's 400.
    let (status, body) = h
        .call("GET", "/api/reporting/dashboards/44", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"].as_str().unwrap().starts_with(
            "9 validation errors for GrafanaDashboardResponse\ndashboards.0.uid\n  Field required"
        ),
        "{body}"
    );
    let (status, _) = h
        .call("GET", "/api/reporting/dashboards/x", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, body) = h
        .call(
            "GET",
            "/api/reporting/dashboard_panels/u1",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["panels"],
        json!([{"fieldConfig": null, "gridPos": null, "id": 2, "options": null, "title": "Graph",
                "type": null, "collapsed": null, "panels": []}])
    );
    let (status, body) = h
        .call("GET", "/api/reporting/dashboard/nope", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("Failed to collect dashboard details: Client Error 404: "),
        "{body}"
    );

    let (status, body) = h
        .call(
            "POST",
            "/api/reporting/generate_iframe_links",
            Some(&analyst),
            Some(
                json!({"org_id": 44, "dashboard_title": "t", "dashboard_uid": "u1", "panel_id": 5,
                        "time_range": {"value": 2, "unit": "h"}}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let url = body["links"][0]["panel_url"].as_str().unwrap();
    let prefix = format!("{}/d-solo/u1/t?orgId=44&from=", grafana.uri());
    assert!(url.starts_with(&prefix), "{url}");
    let rest = &url[prefix.len()..];
    let (from, rest) = rest.split_once("&to=").unwrap();
    let (to, panel) = rest.split_once('&').unwrap();
    assert_eq!(panel, "panelId=5");
    let (from, to): (i64, i64) = (from.parse().unwrap(), to.parse().unwrap());
    assert_eq!(to - from, 2 * 3600 * 1000);
    let (status, body) = h
        .call(
            "POST",
            "/api/reporting/generate_iframe_links",
            Some(&analyst),
            Some(
                json!({"org_id": 44, "dashboard_title": "t", "dashboard_uid": "u1", "panel_id": 5,
                        "time_range": {"value": 2, "unit": "w"}}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Invalid time range unit: w. Must be one of ['m', 'h', 'd']"
    );

    // The PDF report is copilot-reports' now: the body's 422, here.
    let (status, body) = h
        .call(
            "POST",
            "/api/reporting/generate-report",
            Some(&analyst),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["details"][0]["field"], "company_name");
    let (status, _) = h
        .call("GET", "/api/reporting/orgs", Some(&portal), None)
        .await;
    assert_ne!(status, StatusCode::OK);
    set_connector(&h, "Grafana", None, None).await;
}

#[tokio::test]
async fn grafana_user_add_answers_the_validation_error() {
    let h = harness_or_skip!(None);
    let (admin, _, _) = users(&h).await;
    let grafana = MockServer::start().await;
    set_connector(&h, "Grafana", Some(&grafana.uri()), None).await;
    Mock::given(method("POST"))
        .and(path("/api/orgs/44/users"))
        .and(header("content-type", "application/json;charset=utf-8"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "User added to organization"})),
        )
        .mount(&grafana)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/orgs/1/users"))
        .respond_with(
            ResponseTemplate::new(409)
                .set_body_json(json!({"message": "User is already member of this organization"})),
        )
        .mount(&grafana)
        .await;
    let (status, body) = h
        .call(
            "POST",
            "/api/user/user/organization/add",
            Some(&admin),
            Some(json!({"loginorEmail": "é@x.io", "organizationId": "44"})),
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        body["message"].as_str().unwrap().starts_with(
            "Error adding user to organization: 1 validation error for \
             UserOrganizationAddResponse\nsuccess\n  Field required"
        ),
        "{body}"
    );
    let sent = grafana.received_requests().await.unwrap();
    assert_eq!(
        String::from_utf8(sent[0].body.clone()).unwrap(),
        "{\"loginorEmail\": \"\\u00e9@x.io\", \"role\": \"Viewer\"}"
    );
    let (_, body) = h
        .call(
            "POST",
            "/api/user/user/organization/add",
            Some(&admin),
            Some(json!({"loginorEmail": "a", "organizationId": "1"})),
        )
        .await;
    assert_eq!(
        body["message"],
        "Error adding user to organization: Client Error 409: User is already member of this organization"
    );
    set_connector(&h, "Grafana", Some("grafana:3000"), None).await;
    let (status, body) = h
        .call(
            "POST",
            "/api/user/user/organization/add",
            Some(&admin),
            Some(json!({"loginorEmail": "a", "organizationId": "1"})),
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body["message"],
        "Failed to create Grafana client: Invalid connector URL format"
    );
    set_connector(&h, "Grafana", None, None).await;
}

fn portainer_stack(id: i64, status: i64) -> Value {
    json!({
        "Id": id, "Name": format!("wazuh-worker-{id}"), "Type": 1, "EndpointId": 1,
        "SwarmId": "swarm", "EntryPoint": "docker-compose.yml", "Env": [],
        "ResourceControl": null, "Status": status, "ProjectPath": "/data/compose",
        "CreationDate": 1, "CreatedBy": "admin", "UpdateDate": 0, "UpdatedBy": "",
        "FromAppTemplate": false, "Namespace": "", "IsComposeFormat": false
    })
}

#[tokio::test]
async fn portainer_stacks_are_driven_through_a_fresh_jwt() {
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    let (admin, analyst, _) = users(&h).await;
    let portainer = MockServer::start().await;
    set_connector(&h, "Portainer", Some(&portainer.uri()), None).await;
    Mock::given(method("POST"))
        .and(path("/api/auth"))
        .and(body_string_contains(
            "\"username\": \"admin\", \"password\": \"secret\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jwt": "J1"})))
        .mount(&portainer)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/endpoints"))
        .and(header("authorization", "Bearer J1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Id": 9, "Name": "edge"}, {"Id": "3", "Name": "local"}
        ])))
        .mount(&portainer)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/stacks/6"))
        .and(query_param("endpointId", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(portainer_stack(6, 2)))
        .mount(&portainer)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/stacks/6/start"))
        .and(query_param("endpointId", "3"))
        .and(header("content-length", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(portainer_stack(6, 1)))
        .mount(&portainer)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/stacks/6"))
        .and(query_param("endpointId", "3"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&portainer)
        .await;

    let (status, body) = h
        .call(
            "POST",
            "/api/portainer/start-wazuh-customer-stack?stack_id=06",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["Status"], 1);
    // Stopped already: nothing is sent but the reads, then the delete.
    let (status, body) = h
        .call(
            "DELETE",
            "/api/portainer/delete-wazuh-customer-stack?stack_id=6",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"data": null, "success": true, "message": "Successfully deleted resource"})
    );
    let auths = portainer
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/api/auth")
        .count();
    assert_eq!(auths, 8, "every Portainer call logs in first");

    let (status, _) = h
        .call("GET", "/api/portainer/stacks", Some(&analyst), None)
        .await;
    assert_ne!(status, StatusCode::OK, "admin only");
    let (status, body) = h
        .call("GET", "/api/portainer/stack-details", Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // The customer's stack id lives in customersmeta.
    let s = &h.suffix;
    h.exec(&format!(
        "INSERT INTO customers (customer_code, customer_name, created_at) \
         VALUES ('pt{s}', 'Pt Co {s}', UTC_TIMESTAMP())"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, \
         customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group) \
         VALUES ('pt{s}', 'Pt Co {s}', 'i', 's', '1', 'g')"
    ))
    .await;
    let name = format!("Pt%20Co%20{s}");
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/portainer/get-customer-stack-id?customer_name={name}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        body["message"],
        format!("No Portainer stack ID found for customer Pt Co {s}")
    );
    let (status, body) = h
        .call(
            "POST",
            &format!("/api/portainer/update-customer-stack-id?customer_name={name}&stack_id=12"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/portainer/get-customer-stack-id?customer_name={name}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        body,
        json!({"stack_id": 12, "success": true, "message": "Customer stack ID retrieved successfully."})
    );
    h.exec(&format!(
        "DELETE FROM customersmeta WHERE customer_code = 'pt{s}'"
    ))
    .await;
    h.exec(&format!(
        "DELETE FROM customers WHERE customer_code = 'pt{s}'"
    ))
    .await;

    // Creating a stack is copilot-integration-provisioning's (driven by
    // `e2e_cloud_provisioning`): an empty body is its 422, nothing reaches
    // Python.
    let (status, body) = h
        .call(
            "POST",
            "/api/portainer/create-wazuh-customer-stack",
            Some(&admin),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        legacy
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.url.path() != "/api/portainer/create-wazuh-customer-stack")
    );
    set_connector(&h, "Portainer", None, None).await;
}
