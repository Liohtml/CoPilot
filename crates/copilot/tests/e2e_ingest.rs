//! End-to-end tests of alert creation and ingest (`copilot-ingest`): the
//! production router against a real MySQL at the Alembic head, the Wazuh
//! indexer, Talon and Shuffle replaced by local stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13307/copilot \
//!   cargo test -p copilot --test e2e_ingest -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `INGEST_E2E_PORT` (default 5710) and the two
//! ports after it. The tests borrow the real `Wazuh-Indexer`, `Talon` and
//! `Shuffle` connector rows (pointed at the stand-ins, given back after),
//! which is one reason the suite runs single-threaded.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use wiremock::matchers::{body_string, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const A: &str = "/api/incidents/alerts";
const D: &str = "/api/incidents/db_operations";
const GRAYLOG_HEADER: &str = "graylog-e2e-header";
const VELO_HEADER: &str = "velo-e2e-header";

fn base_port() -> u16 {
    std::env::var("INGEST_E2E_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5710)
}

/// A stand-in on `INGEST_E2E_PORT + offset`, retried while the previous
/// test's server lets the port go (wiremock closes its listener on its own
/// thread, after the test that dropped it has ended).
async fn stand_in(offset: u16) -> MockServer {
    let port = base_port() + offset;
    let mut tries = 0;
    let listener = loop {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => break l,
            Err(_) if tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("cannot bind the stand-in on {port}: {e}"),
        }
    };
    MockServer::builder().listener(listener).start().await
}

fn env() -> String {
    format!(
        "GRAYLOG_API_HEADER_VALUE={GRAYLOG_HEADER}\nVELOCIRAPTOR_API_HEADER_VALUE={VELO_HEADER}\n"
    )
}

/// A connector row's id, URL, username, password and API key.
type ConnectorRow = (i64, String, Option<String>, Option<String>, Option<String>);
type SavedRow = Option<ConnectorRow>;

/// Point the connector row `name` at `url` (creating it when absent);
/// returns what to give back.
async fn borrow(
    h: &Harness,
    name: &str,
    url: &str,
    user: &str,
    key: Option<&str>,
) -> (i64, SavedRow) {
    let existing: Option<ConnectorRow> = sqlx::query_as(
        "SELECT id, connector_url, connector_username, connector_password, connector_api_key \
             FROM connectors WHERE connector_name = ? ORDER BY id LIMIT 1",
    )
    .bind(name)
    .fetch_optional(h.db.pool())
    .await
    .unwrap();
    match existing {
        Some(row) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = ?, \
                 connector_password = 'pw-e2e', connector_api_key = ? WHERE id = ?",
            )
            .bind(url)
            .bind(user)
            .bind(key)
            .bind(row.0)
            .execute(h.db.pool())
            .await
            .unwrap();
            (row.0, Some(row))
        }
        None => {
            let id = sqlx::query(
                "INSERT INTO connectors (connector_name, connector_type, connector_url, \
                 connector_last_updated, connector_username, connector_password, connector_api_key, \
                 connector_description, connector_supports, connector_configured, connector_verified, \
                 connector_accepts_host_only, connector_accepts_api_key, \
                 connector_accepts_username_password, connector_accepts_file, \
                 connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
                 (?, '4.8', ?, '2026-01-02 03:04:05', ?, 'pw-e2e', ?, 'd', 's', 1, 1, 0, 0, 1, 0, 0, \
                 NULL, 1)",
            )
            .bind(name)
            .bind(url)
            .bind(user)
            .bind(key)
            .execute(h.db.pool())
            .await
            .unwrap()
            .last_insert_id();
            (i64::try_from(id).unwrap(), None)
        }
    }
}

async fn give_back(h: &Harness, id: i64, old: SavedRow) {
    match old {
        Some((_, url, user, pass, key)) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = ?, \
                 connector_password = ?, connector_api_key = ? WHERE id = ?",
            )
            .bind(url)
            .bind(user)
            .bind(pass)
            .bind(key)
            .bind(id)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
        None => {
            h.exec(&format!("DELETE FROM connectors WHERE id = {id}"))
                .await;
        }
    }
}

/// The ingest's settings for acme and the dictionaries of source `src<sfx>`.
async fn seed_ingest(h: &Harness) -> (i64, i64) {
    let alerts = h.seed().await;
    let s = &h.suffix;
    h.exec(&format!(
        "INSERT INTO custom_alert_creation_settings (customer_code, customer_name) \
         VALUES ('acme{s}', 'acme corp')"
    ))
    .await;
    for (table, name) in [
        ("incident_management_fieldname", "rule_id"),
        ("incident_management_fieldname", "rule_level"),
        ("incident_management_assetfieldname", "agent_name"),
        ("incident_management_timestampfieldname", "timestamp_utc"),
        (
            "incident_management_alerttitlefieldname",
            "rule_description",
        ),
        ("incident_management_iocfieldname", "src_ip"),
    ] {
        h.exec(&format!(
            "INSERT INTO {table} (source, field_name) VALUES ('src{s}', '{name}')"
        ))
        .await;
    }
    h.exec(&format!(
        "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, \
         wazuh_last_seen, velociraptor_id, wazuh_agent_version, wazuh_agent_status, customer_code, \
         quarantined) VALUES ('007{s}', '10.0.0.7', 'Windows', 'dc01-{s}', 'l', 0, \
         '2026-03-01 00:00:00', 'C.{s}', '4.8', 'active', 'acme{s}', 0)"
    ))
    .await;
    alerts
}

fn doc(h: &Harness, title: &str, host: &str, ip: &str) -> Value {
    let s = &h.suffix;
    json!({
        "_index": format!("idx-{s}"), "_type": "_doc", "_id": "d1", "_version": 1, "found": true,
        "_source": {
            "syslog_type": format!("src{s}"),
            "timestamp": "2026-03-01T10:00:00Z",
            "timestamp_utc": "2026-03-01T10:00:00.250Z",
            "rule_description": title,
            "rule_level": 12,
            "rule_id": 92900,
            "agent_name": host,
            "agent_labels_customer": format!("acme{s}"),
            "src_ip": ip,
            "process_id": "4242"
        }
    })
}

#[tokio::test]
async fn webhooks_fail_closed_and_routes_need_a_soc_token() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = &h.suffix;
    let portal = h.token(&format!("portal{s}"), "customer_user");

    // No header value configured: nobody gets in.
    for (route, tool) in [("threshold", "Graylog"), ("velo-sigma", "Velociraptor")] {
        let (status, body) = h
            .call(
                "POST",
                &format!("{A}/create/{route}"),
                None,
                Some(json!({})),
            )
            .await;
        assert_eq!(status, 403, "{body}");
        assert_eq!(
            body["message"],
            json!(format!("{tool} header authentication is not configured"))
        );
    }
    for (method_, route) in [
        ("GET", format!("{A}/index/names")),
        ("POST", format!("{A}/create/manual")),
        ("POST", format!("{A}/create/auto")),
        ("GET", format!("{A}/alert/1/velo-sigma/exclusion-draft")),
        ("GET", format!("{D}/available-source/x")),
    ] {
        let (status, _) = h.call(method_, &route, None, None).await;
        assert_eq!(status, 401, "{route}");
        let (status, _) = h.call(method_, &route, Some(&portal), None).await;
        assert_eq!(status, 403, "{route}");
    }

    let h = harness_or_skip!(None, &env());
    for (route, name, value) in [
        ("threshold", "graylog", GRAYLOG_HEADER),
        ("velo-sigma", "velociraptor", VELO_HEADER),
    ] {
        let uri = format!("{A}/create/{route}");
        let wrong = axum::body::Body::from("{}");
        let req = http::Request::builder()
            .method("POST")
            .uri(&uri)
            .header(name, "nope")
            .header("content-type", "application/json")
            .body(wrong)
            .unwrap();
        let resp = tower::ServiceExt::oneshot(h.router.clone(), req)
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        // The right header, an empty object: the body's 422 comes after it.
        let req = http::Request::builder()
            .method("POST")
            .uri(&uri)
            .header(name, value)
            .header("content-type", "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(h.router.clone(), req)
            .await
            .unwrap();
        assert_eq!(resp.status(), 422, "{route}");
    }
}

#[tokio::test]
async fn a_document_becomes_an_alert_then_merges_and_notifies() {
    let h = harness_or_skip!(None, &env());
    seed_ingest(&h).await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let es = stand_in(0).await;
    let talon = stand_in(1).await;
    let (es_id, es_old) = borrow(&h, "Wazuh-Indexer", &es.uri(), "indexer", None).await;
    let (talon_id, talon_old) = borrow(&h, "Talon", &talon.uri(), "", Some("talon-e2e")).await;
    h.exec(&format!(
        "INSERT INTO incident_management_ai_analyst_trigger_enabled (customer_code, enabled) \
         VALUES ('acme{s}', 1)"
    ))
    .await;
    let index = format!("idx-{s}");
    let title = format!("Mimikatz {s}");
    Mock::given(method("GET"))
        .and(path(format!("/{index}/_doc/d1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc(
            &h,
            &title,
            &format!("dc01-{s}"),
            "evil.exe|d41d8cd98f00b204e9800998ecf8427e",
        )))
        .mount(&es)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/{index}/_doc/d2")))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc(
            &h,
            &title,
            &format!("web-{s}"),
            "203.0.113.9",
        )))
        .mount(&es)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(format!("^/{index}/_update/d[12]$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": "updated"})))
        .expect(2)
        .mount(&es)
        .await;
    Mock::given(method("POST"))
        .and(path("/investigate"))
        .and(header("x-api-key", "talon-e2e"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(json!({"job_id": "j", "status": "queued"})),
        )
        .expect(1)
        .mount(&talon)
        .await;

    let (status, body) = h
        .call(
            "POST",
            &format!("{A}/create/manual"),
            Some(&admin),
            Some(json!({"index_name": index, "alert_id": "d1"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let alert = body["alert_id"].as_i64().unwrap();
    assert_eq!(body["message"], json!("Alert created in CoPilot"));

    let (severity, status_, source): (Option<String>, String, String) = sqlx::query_as(
        "SELECT severity, status, source FROM incident_management_alert WHERE id = ?",
    )
    .bind(alert)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        (severity.as_deref(), status_.as_str()),
        (Some("Critical"), "OPEN")
    );
    assert_eq!(source, format!("src{s}"));
    let (agent, velo, context): (Option<String>, Option<String>, Value) = sqlx::query_as::<
        _,
        (Option<String>, Option<String>, sqlx::types::Json<Value>),
    >(
        "SELECT a.agent_id, a.velociraptor_id, c.context FROM incident_management_asset a \
         JOIN incident_management_alertcontext c ON c.id = a.alert_context_id WHERE a.alert_linked = ?",
    )
    .bind(alert)
    .fetch_one(h.db.pool())
    .await
    .map(|(a, v, c)| (a, v, c.0))
    .unwrap();
    assert_eq!(agent, Some(format!("007{s}")));
    assert_eq!(velo, Some(format!("C.{s}")));
    assert_eq!(context["rule_id"], json!(92900));
    assert_eq!(context["process_name"], json!([]));
    // The composite IoC keeps its hash, and says where it came from.
    let (value, kind, description): (String, String, String) = sqlx::query_as(
        "SELECT i.value, i.type, i.description FROM incident_management_alert_to_ioc l \
         JOIN incident_management_ioc i ON i.id = l.ioc_id WHERE l.alert_id = ?",
    )
    .bind(alert)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        (value.as_str(), kind.as_str()),
        ("d41d8cd98f00b204e9800998ecf8427e", "HASH")
    );
    assert!(
        description.contains("extracted from composite value"),
        "{description}"
    );
    // The SLA clock started with the alert.
    let tracked = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM soc_sla_alert_tracking WHERE alert_id = {alert} AND severity = 'Critical'"
        ))
        .await;
    assert_eq!(tracked, 1);

    // The same title again: merged, its creation time moved to the trigger.
    let (status, body) = h
        .call(
            "POST",
            &format!("{A}/create/manual"),
            Some(&admin),
            Some(json!({"index_name": index, "alert_id": "d2"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["alert_id"].as_i64(), Some(alert));
    let assets = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM incident_management_asset WHERE alert_linked = {alert}"
        ))
        .await;
    assert_eq!(assets, 2);
    let moved = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM incident_management_alert WHERE id = {alert} AND \
             alert_creation_time = '2026-03-01 10:00:00'"
        ))
        .await;
    assert_eq!(
        moved, 1,
        "update_alert_creation_time takes the document's time"
    );

    // Talon is told on a task of its own, with the body requests sends.
    for _ in 0..50 {
        if !talon
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let sent = talon.received_requests().await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&sent[0].body),
        format!(
            "{{\"alert_id\": {alert}, \"customer_code\": \"acme{s}\", \"sender\": \"copilot\"}}"
        )
    );
    let updates: Vec<String> = es
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert_eq!(
        updates,
        vec![format!("{{\"doc\":{{\"alert_id\":{alert}}}}}"); 2]
    );

    // An unprovisioned customer is refused before anything is written.
    let mut other = doc(&h, &title, "x", "1.2.3.4");
    other["_source"]["agent_labels_customer"] = json!(format!("nobody{s}"));
    Mock::given(method("GET"))
        .and(path(format!("/{index}/_doc/d3")))
        .respond_with(ResponseTemplate::new(200).set_body_json(other))
        .mount(&es)
        .await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{A}/create/manual"),
            Some(&admin),
            Some(json!({"index_name": index, "alert_id": "d3"})),
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(
        body["message"],
        json!(format!(
            "Customer code nobody{s} is not valid. Has the customer been provisioned?"
        ))
    );

    give_back(&h, es_id, es_old).await;
    give_back(&h, talon_id, talon_old).await;
}

#[tokio::test]
async fn a_threshold_event_is_replayed_and_kept_for_its_timeline() {
    let h = harness_or_skip!(None, &env());
    seed_ingest(&h).await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let es = stand_in(0).await;
    let (es_id, es_old) = borrow(&h, "Wazuh-Indexer", &es.uri(), "indexer", None).await;
    let index = format!("src{s}-2026.03.01");
    let mut hit = doc(&h, "doc title", &format!("dc01-{s}"), "1.2.3.4");
    hit["_index"] = json!(index);
    hit["_id"] = json!("t1");
    Mock::given(method("POST"))
        .and(path(format!("/src{s}-*/_search")))
        .and(query_param("size", "1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"hits": {"hits": [hit.clone()]}})),
        )
        .mount(&es)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/{index}/_doc/t1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(hit.clone()))
        .mount(&es)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/{index}/_update/t1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": "updated"})))
        .mount(&es)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/src{s}-*/_search")))
        .and(query_param("size", "50"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"hits": {"hits": [hit, {"_id": "t2"}]}})),
        )
        .mount(&es)
        .await;
    let body = json!({
        "event_definition_id": "ed1", "event_definition_type": "aggregation-v1",
        "event_definition_title": "T", "job_definition_id": "j", "job_trigger_id": "t",
        "event": {
            "id": "e1", "event_definition_type": "aggregation-v1", "event_definition_id": "ed1",
            "timestamp": "2026-03-01T10:05:00.219Z", "timestamp_processing": 1772359501,
            "source_streams": ["s1"], "message": format!("Brute force {s}"), "source": "g",
            "key": "k", "priority": 2, "alert": true,
            "fields": {"CUSTOMER_CODE": format!("acme{s}"), "SOURCE": format!("src{s}"),
                       "ALERT_DESCRIPTION": "d", "EXTRA": 1},
            "group_by_fields": {"agent_name": format!("dc01-{s}")},
            "replay_info": {"timerange_start": "2026-03-01T10:00:00Z",
                            "timerange_end": "2026-03-01T10:05:00Z",
                            "query": "rule:auth", "streams": []}
        }
    });
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("{A}/create/threshold"))
        .header("graylog", GRAYLOG_HEADER)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(h.router.clone(), req)
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        answer["message"],
        json!("Alert threshold Graylog invoked successfully")
    );
    let alert = answer["alert_id"].as_i64().unwrap();

    let replay: (String, String, String, sqlx::types::Json<Value>) = sqlx::query_as(
        "SELECT replay_query, resolved_index_name, resolved_index_id, group_by_fields \
         FROM incident_management_threshold_alert_metadata WHERE alert_id = ?",
    )
    .bind(alert)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        (replay.0.as_str(), replay.1.as_str(), replay.2.as_str()),
        ("rule:auth", index.as_str(), "t1")
    );
    assert_eq!(replay.3.0, json!({"agent_name": format!("dc01-{s}")}));
    let asset: String = sqlx::query_scalar(
        "SELECT asset_name FROM incident_management_asset WHERE alert_linked = ?",
    )
    .bind(alert)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(asset, format!("dc01-{s}"));

    // The timeline replays the stored query.
    let (status, timeline) = h
        .call(
            "POST",
            &format!("{A}/alert/timeline"),
            Some(&admin),
            Some(json!({"index_name": index, "index_id": "t1", "alert_id": alert})),
        )
        .await;
    assert_eq!(status, 200, "{timeline}");
    assert_eq!(timeline["alert_timeline"].as_array().map(Vec::len), Some(2));
    give_back(&h, es_id, es_old).await;
}

fn sigma_event(record: i64) -> Value {
    json!({
        "System": {
            "Provider": {"Name": "Microsoft-Windows-Sysmon", "Guid": "{5770385F}"},
            "EventID": {"Value": 10}, "Version": 3, "Level": 4, "Task": 10, "Opcode": 0,
            "Keywords": 1, "TimeCreated": {"SystemTime": 1772359200.5}, "EventRecordID": record,
            "Execution": {"ProcessID": 1, "ThreadID": 2},
            "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "dc01",
            "Security": {"UserID": "S-1-5-18"}
        },
        "Message": "m",
        "EventData": {
            "RuleName": "r", "UtcTime": "t", "SourceProcessGUID": "g", "SourceProcessId": 1,
            "SourceThreadId": 2, "SourceImage": "C:\\Temp\\mimi.exe", "TargetProcessGUID": "g",
            "TargetProcessId": 3, "TargetImage": "C:\\Windows\\system32\\lsass.exe",
            "GrantedAccess": 5136, "CallTrace": "c", "SourceUser": "u", "TargetUser": "v"
        }
    })
}

#[tokio::test]
async fn the_sigma_ingest_excludes_falls_back_and_drafts_its_rule() {
    let h = harness_or_skip!(None, &env());
    seed_ingest(&h).await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let es = stand_in(0).await;
    let (es_id, es_old) = borrow(&h, "Wazuh-Indexer", &es.uri(), "indexer", None).await;
    Mock::given(method("POST"))
        .and(path(format!("/wazuh-{s}-*/_search")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits": {"hits": []}})))
        .mount(&es)
        .await;
    // Deployment-wide rules other tests left enabled would match these
    // alerts too: off for this test.
    let others: Vec<i32> = sqlx::query_scalar(
        "SELECT id FROM incident_management_velo_sigma_exclusion WHERE enabled = 1",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    h.exec("UPDATE incident_management_velo_sigma_exclusion SET enabled = 0")
        .await;
    h.exec(&format!(
        "INSERT INTO incident_management_velo_sigma_exclusion (name, channel, title, customer_code, \
         field_matches, created_by, created_at, match_count, enabled) VALUES ('Excl {s}', \
         'Microsoft-Windows-Sysmon/Operational', 'Excluded {s}', 'acme{s}', \
         '{{\"TargetImage\": \"regex:.*\\\\\\\\lsass.exe\"}}', 'e2e', '2026-03-01 00:00:00', 0, 1)"
    ))
    .await;

    let send = |title: String, record: i64| {
        let body = json!({
            "computer": format!("dc01-{s}"), "clientID": format!("C.{s}"),
            "channel": "Microsoft-Windows-Sysmon/Operational", "title": title, "level": "high",
            "event": sigma_event(record), "type": format!("sigma-{s}"),
            "index_pattern": format!("wazuh-{s}-*"), "sourceRef": format!("ref-{s}")
        });
        http::Request::builder()
            .method("POST")
            .uri(format!("{A}/create/velo-sigma"))
            .header("velociraptor", VELO_HEADER)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    };
    let json_of = |resp: axum::response::Response| async move {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap()
    };

    // Matched by the customer's rule: nothing is created, the rule counts it.
    let resp = tower::ServiceExt::oneshot(h.router.clone(), send(format!("Excluded {s}"), 1))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let answer = json_of(resp).await;
    assert_eq!(
        answer["message"],
        json!(format!("Alert excluded by rule: Excl {s}"))
    );
    assert_eq!(answer["alert_id"], Value::Null);
    let matched = h
        .scalar_i64(&format!(
            "SELECT match_count FROM incident_management_velo_sigma_exclusion WHERE name = 'Excl {s}'"
        ))
        .await;
    assert_eq!(matched, 1);

    // No Wazuh copy: the fallback alert, filed under the agent's customer.
    let resp = tower::ServiceExt::oneshot(h.router.clone(), send(format!("Fallback {s}"), 2))
        .await
        .unwrap();
    let answer = json_of(resp).await;
    let alert: i64 = sqlx::query_scalar(
        "SELECT id FROM incident_management_alert WHERE alert_name = ? AND customer_code = ?",
    )
    .bind(format!("Fallback {s}"))
    .bind(format!("acme{s}"))
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    // `VelociraptorSigmaAlertResponse.alert_id` is a str: Python's own
    // response fails to validate an int, and says so.
    assert_eq!(answer["success"], json!(false));
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains(&format!("input_value={alert}, input_type=int")),
        "{answer}"
    );
    let comments: Vec<String> = sqlx::query_scalar(
        "SELECT comment FROM incident_management_comment WHERE alert_id = ? ORDER BY id",
    )
    .bind(alert)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    assert!(
        comments[0].starts_with("Velociraptor Sigma Alert (No Wazuh match found)"),
        "{comments:?}"
    );
    assert!(
        comments[1].starts_with("Full Event Payload:\n```\n{"),
        "{comments:?}"
    );
    let tags: Vec<String> = sqlx::query_scalar(
        "SELECT t.tag FROM incident_management_alert_to_tag l JOIN incident_management_alerttag t \
         ON t.id = l.tag_id WHERE l.alert_id = ? ORDER BY t.id",
    )
    .bind(alert)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    assert!(tags.contains(&format!("sigma-{s}")), "{tags:?}");

    // The draft reads the payload back; the dry-run is the matcher.
    let (status, draft) = h
        .call(
            "GET",
            &format!("{A}/alert/{alert}/velo-sigma/exclusion-draft"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200, "{draft}");
    assert_eq!(draft["draft"]["title"], json!(format!("Fallback {s}")));
    assert_eq!(draft["draft"]["customer_code"], json!(format!("acme{s}")));
    assert_eq!(draft["draft"]["payload_available"], json!(true));
    let target = draft["draft"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == json!("TargetImage"))
        .cloned()
        .unwrap();
    assert_eq!(target["suggested"], json!(true));
    let (status, run) = h
        .call(
            "POST",
            &format!("{A}/alert/{alert}/velo-sigma/exclusion-dry-run"),
            Some(&admin),
            Some(json!({"title": format!("Fallback {s}"), "field_matches": {"TargetImage": target["value"]}})),
        )
        .await;
    assert_eq!(status, 200, "{run}");
    assert_eq!(run["matches"], json!(true));
    let (_, run) = h
        .call(
            "POST",
            &format!("{A}/alert/{alert}/velo-sigma/exclusion-dry-run"),
            Some(&admin),
            Some(json!({"channel": "Security", "customer_code": "other"})),
        )
        .await;
    assert_eq!(run["matches"], json!(false));
    assert_eq!(run["reasons"].as_array().map(Vec::len), Some(2), "{run}");

    if !others.is_empty() {
        let ids: Vec<String> = others.iter().map(i32::to_string).collect();
        h.exec(&format!(
            "UPDATE incident_management_velo_sigma_exclusion SET enabled = 1 WHERE id IN ({})",
            ids.join(",")
        ))
        .await;
    }
    give_back(&h, es_id, es_old).await;
}

#[tokio::test]
async fn the_indexer_reads_of_db_operations() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let es = stand_in(0).await;
    let (es_id, es_old) = borrow(&h, "Wazuh-Indexer", &es.uri(), "indexer", None).await;
    Mock::given(method("GET"))
        .and(path("/*/_alias"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wazuh-alerts-4.x-2026.03.01": {}, "wazuh-monitoring-2026.03": {},
            "office365-acme": {}, "other": {}
        })))
        .mount(&es)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/idx-{s}/_search")))
        .and(body_string(
            "{\"size\":10,\"query\":{\"bool\":{\"must\":[{\"exists\":{\"field\":\"syslog_type\"}}]}}}",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"hits": [{"_source": {"syslog_type": "integration", "integration": "office365"}}]}
        })))
        .mount(&es)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/idx-{s}/_mapping")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            format!("idx-{s}"): {"mappings": {"properties": {"b": {}, "a": {}}}}
        })))
        .mount(&es)
        .await;

    let (status, body) = h
        .call(
            "GET",
            &format!("{D}/available-source/idx-{s}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"source": "office365", "success": true, "message": "Source retrieved successfully"})
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("{D}/available-indices/wazuh"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["indices"], json!(["wazuh-alerts-4.x-2026.03.01"]));
    let (_, body) = h
        .call(
            "GET",
            &format!("{D}/mappings/fields-assets-title-and-timefield?index_name=idx-{s}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["available_mappings"], json!(["b", "a"]));
    let (status, body) = h
        .call(
            "GET",
            &format!("{D}/mappings/fields-assets-title-and-timefield"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 422, "{body}");
    give_back(&h, es_id, es_old).await;
}

#[tokio::test]
async fn the_collection_job_is_registered_and_collects() {
    let h = harness_or_skip!(
        None,
        &format!("{}COPILOT_RS_JOBS=invoke_alert_creation_collect\n", env())
    );
    seed_ingest(&h).await;
    let s = h.suffix.clone();
    assert!(
        h.app
            .scheduler
            .knows(copilot_ingest::INVOKE_ALERT_CREATION_COLLECT)
    );
    assert!(
        h.app
            .scheduler
            .opted_in(copilot_ingest::INVOKE_ALERT_CREATION_COLLECT)
    );
    let es = stand_in(0).await;
    let (es_id, es_old) = borrow(&h, "Wazuh-Indexer", &es.uri(), "indexer", None).await;
    let events = format!("gl-events_{s}");
    Mock::given(method("GET"))
        .and(path("/gl-events*/_alias"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ events.clone(): {} })))
        .mount(&es)
        .await;
    let event = |id: &str, doc: &str| {
        json!({"_index": events, "_id": id, "_source": {
            "id": id, "event_definition_type": "a", "event_definition_id": "e",
            "origin_context": format!("urn:graylog:message:es:idx-{s}:{doc}"),
            "timestamp": "t", "timestamp_processing": "t", "streams": [], "source_streams": [],
            "message": "m", "source": "s", "key_tuple": [], "key": "", "priority": 1,
            "alert": true, "fields": {"COPILOT_ALERT_ID": "NONE"}
        }})
    };
    Mock::given(method("POST"))
        .and(path(format!("/{events}/_search")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 2}, "hits": [event("ev1", "d1"), event("ev2", "gone")]}
        })))
        .mount(&es)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/idx-{s}/_doc/d1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc(
            &h,
            &format!("Collected {s}"),
            &format!("dc01-{s}"),
            "198.51.100.1",
        )))
        .mount(&es)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/idx-{s}/_doc/gone")))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"found": false})))
        .mount(&es)
        .await;
    Mock::given(method("POST"))
        .and(path_regex("/_update/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": "updated"})))
        .mount(&es)
        .await;

    let out = copilot_ingest::collect::create_alerts_auto(&h.app.ingest)
        .await
        .unwrap();
    assert_eq!(
        out["message"],
        json!("Processed 1 batches: 1 alerts created, 1 failed. 2 alerts remaining for next run")
    );
    assert_eq!(out["alerts_remaining"], json!(0));
    let created = h
        .scalar_i64(&format!(
            "SELECT id FROM incident_management_alert WHERE alert_name = 'Collected {s}'"
        ))
        .await;
    let stamped = es
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == format!("/{events}/_update/ev1"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        stamped,
        vec![format!(
            "{{\"doc\":{{\"fields\":{{\"COPILOT_ALERT_ID\":\"{created}\"}}}}}}"
        )]
    );
    give_back(&h, es_id, es_old).await;
}
