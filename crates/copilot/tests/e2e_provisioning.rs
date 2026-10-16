//! End-to-end tests of the provisioning ports (`copilot-waf`): `/api/customer_waf`
//! and the WAF alerts of `POST /api/monitoring_alert/provision`, through the
//! production router on a real MySQL, with the WAF admin API, Graylog and the
//! Python backend replaced by local stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13309/copilot \
//!   cargo test -p copilot --test e2e_provisioning -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `PROVISIONING_E2E_PORT_BASE` (5757) and the two
//! ports after it. The `Graylog` connector row is replaced for each test and
//! restored (run single-threaded).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::StatusCode;
use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use copilot_auth::Fernet;

#[macro_use]
mod common;
use common::*;

/// A Fernet key (`Fernet.generate_key()`'s shape).
const KEY: &str = "q83vEjmO2YW-bQjzAZp8kYC0Wf7zZcGq2hD2bGy9Xf4=";
const TOKEN: &str = "wafst_e2e_service_token_0123456789";

fn port(offset: u16) -> u16 {
    std::env::var("PROVISIONING_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(5757)
        + offset
}

/// A stand-in on one of this suite's ports.
async fn stand_in(offset: u16) -> MockServer {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port(offset))).unwrap();
    MockServer::builder().listener(listener).start().await
}

fn env() -> String {
    format!(
        "WAF_TOKEN_ENCRYPTION_KEY={KEY}\nWAF_SYSLOG_PORT_RANGE=5600-5602\n\
         ALERT_FORWARDING_IP=10.1.2.3\nGRAYLOG_API_HEADER_VALUE=hdr\n"
    )
}

/// A saved `connectors` row: name, url, username, password.
type ConnectorRow = (String, Option<String>, Option<String>, Option<String>);

struct Saved(Vec<ConnectorRow>);

async fn set_graylog(h: &Harness, url: &str) -> Saved {
    let saved: Vec<ConnectorRow> = sqlx::query_as(
        "SELECT connector_name, connector_url, connector_username, connector_password FROM \
         connectors WHERE connector_name = 'Graylog'",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    sqlx::query("DELETE FROM connectors WHERE connector_name = 'Graylog'")
        .execute(h.db.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, \
         connector_last_updated, connector_username, connector_password, connector_api_key, \
         connector_description, connector_supports, connector_configured, connector_verified, \
         connector_accepts_host_only, connector_accepts_api_key, \
         connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         ('Graylog', '3', ?, UTC_TIMESTAMP(), 'admin', 'secret', NULL, 'e2e', 'e2e', 1, 1, 0, 0, \
         1, 0, 0, NULL, 1)",
    )
    .bind(url)
    .execute(h.db.pool())
    .await
    .unwrap();
    Saved(saved)
}

async fn restore_graylog(h: &Harness, saved: Saved) {
    sqlx::query("DELETE FROM connectors WHERE connector_name = 'Graylog'")
        .execute(h.db.pool())
        .await
        .unwrap();
    for (name, url, user, pw) in saved.0 {
        sqlx::query(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, \
             connector_last_updated, connector_username, connector_password, \
             connector_description, connector_supports, connector_configured, \
             connector_verified, connector_accepts_host_only, connector_accepts_api_key, \
             connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_enabled) VALUES (?, '3', ?, \
             UTC_TIMESTAMP(), ?, ?, 'restored', 'restored', 1, 1, 0, 0, 1, 0, 0, 1)",
        )
        .bind(name)
        .bind(url)
        .bind(user)
        .bind(pw)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

/// A WAF row for `acme<sfx>` pointing at `url`; its id.
async fn waf_row(h: &Harness, name: &str, url: &str, enabled: bool) -> i64 {
    let f = Fernet::new(KEY).unwrap();
    sqlx::query(
        "INSERT INTO customer_waf_instances (customer_code, name, api_url, \
         service_token_encrypted, token_prefix, verify_tls, enabled, created_at) VALUES (?, ?, ?, \
         ?, 'wafst_e2e_se...', 0, ?, '2026-01-02 03:04:05')",
    )
    .bind(h.code("acme"))
    .bind(name)
    .bind(url)
    .bind(f.encrypt(TOKEN.as_bytes()))
    .bind(enabled)
    .execute(h.db.pool())
    .await
    .unwrap()
    .last_insert_id() as i64
}

async fn me(waf: &MockServer, roles: &[&str]) {
    Mock::given(method("GET"))
        .and(path("/api/v1/users/me"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "email": "svc@waf.test",
            "roles": roles.iter().map(|r| json!({"name": r})).collect::<Vec<_>>(),
        })))
        .mount(waf)
        .await;
}

#[tokio::test]
async fn instances_are_tenant_bound_and_the_token_write_only() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    let s = h.suffix.clone();
    let (admin, analyst) = (
        h.token(&format!("admin{s}"), "admin"),
        h.token(&format!("analyst{s}"), "analyst"),
    );
    let waf = stand_in(0).await;
    me(&waf, &["admin"]).await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"db": "ok"})))
        .mount(&waf)
        .await;
    let acme = format!("/api/customer_waf/{}", h.code("acme"));
    let beta = format!("/api/customer_waf/{}", h.code("beta"));

    let body = json!({"name": " prod ", "api_url": format!("{}/api/v1/", waf.uri()),
                      "service_token": format!("  {TOKEN} ")});
    let (status, created) = h
        .call("POST", &acme, Some(&admin), Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["message"], "WAF saved");
    assert_eq!(created["instance"]["name"], "prod");
    assert_eq!(created["instance"]["api_url"], waf.uri());
    assert_eq!(created["instance"]["token_prefix"], "wafst_e2e_se...");
    assert_eq!(created["instance"]["last_verified_role"], "admin");
    assert_eq!(
        created["verification"]["capabilities"],
        json!({"can_read": true, "can_block": true, "can_manage_forwarders": true})
    );
    assert_eq!(created["verification"]["health"], json!({"db": "ok"}));
    assert_eq!(
        created["warnings"][0],
        "The API URL uses http:// — the service token is sent in clear text. Prefer the WAF admin \
         UI's https listener."
    );
    let text = created.to_string();
    assert!(!text.contains(TOKEN), "the token never leaves");
    let id = created["instance"]["id"].as_i64().unwrap();
    let stored: (String,) =
        sqlx::query_as("SELECT service_token_encrypted FROM customer_waf_instances WHERE id = ?")
            .bind(id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_ne!(stored.0, TOKEN);
    assert_eq!(
        Fernet::new(KEY).unwrap().decrypt(&stored.0).unwrap(),
        TOKEN.as_bytes()
    );

    // A second WAF of the same name is a 409; another tenant's path a 403.
    let (status, dup) = h.call("POST", &acme, Some(&admin), Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{dup}");
    let (status, _) = h.call("GET", &beta, Some(&analyst), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // An id of another customer under this customer's path is a 404.
    let (status, nf) = h
        .call("GET", &format!("{beta}/{id}/sites"), Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        nf["message"],
        format!("WAF {id} not found for customer {}", h.code("beta"))
    );
    // Writes are admin-only; the analyst lists only their customers' WAFs.
    let (status, _) = h
        .call(
            "PUT",
            &format!("{acme}/{id}"),
            Some(&analyst),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, all) = h
        .call("GET", "/api/customer_waf", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        all["instances"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["customer_code"] == h.code("acme"))
    );
    assert_eq!(all["encryption_key_configured"], true);

    // A blank token keeps the stored one; a new URL resets the verified role.
    let (status, upd) = h
        .call(
            "PUT",
            &format!("{acme}/{id}"),
            Some(&admin),
            Some(json!({"service_token": "  ", "enabled": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{upd}");
    assert_eq!(upd["verification"], Value::Null);
    assert_eq!(upd["instance"]["enabled"], false);
    // A disabled WAF is a 409, not a WAF error.
    let (status, disabled) = h
        .call("GET", &format!("{acme}/{id}/sites"), Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(disabled["reason"], "disabled");

    let (status, del) = h
        .call("DELETE", &format!("{acme}/{id}"), Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        del["message"]
            .as_str()
            .unwrap()
            .contains("revoke it under Service Tokens")
    );
}

#[tokio::test]
async fn waf_failures_are_bad_gateways_never_logouts() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let waf = stand_in(0).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs/stats"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&waf)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/logs/"))
        .and(query_param("limit", "100"))
        .and(query_param("offset", "0"))
        .and(query_param("start_time", "2026-10-15T08:00:00+00:00"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": 7, "timestamp": "2026-10-15T10:00:00Z", "transaction_id": "t",
            "client_ip": "203.0.113.9", "method": "GET", "uri": "/", "host": "h",
            "action": "blocked", "raw_log": {"secret": "x"}
        }])))
        .mount(&waf)
        .await;
    let id = waf_row(&h, "reads", &waf.uri(), true).await;
    let base = format!("/api/customer_waf/{}/{id}", h.code("acme"));

    let (status, body) = h
        .call("GET", &format!("{base}/stats"), Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["reason"], "token_rejected");
    assert_eq!(body["success"], false);

    // A naive time is UTC, an aware one is converted: the WAF always gets an offset.
    let (status, events) = h
        .call(
            "GET",
            &format!("{base}/events?start_time=2026-10-15T10:00:00%2B02:00"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{events}");
    assert_eq!(events["events"][0]["id"], "7");
    assert!(events["events"][0].get("raw_log").is_none());

    let (status, invalid) = h
        .call(
            "GET",
            &format!("{base}/events?limit=0"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{invalid}");

    // Unreachable: a 502 with its own reason.
    let down = waf_row(&h, "down", "http://127.0.0.1:1", true).await;
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/customer_waf/{}/{down}/sites", h.code("acme")),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["reason"], "unreachable");
    assert_eq!(
        body["detail"],
        "Could not connect to WAF 'down' at http://127.0.0.1:1"
    );
}

#[tokio::test]
async fn blocks_create_one_rule_shape_and_unblock_disables() {
    let h = harness_or_skip!(None, &env());
    let (acme_alert, beta_alert) = h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let waf = stand_in(0).await;
    let disabled_rule = json!({
        "id": "r1", "rule_id": 900, "name": "CoPilot block: 203.0.113.50", "is_enabled": false,
        "field": "REMOTE_ADDR", "operator": "@ipMatch", "value": "203.0.113.50",
        "conf_text": "SecRule REMOTE_ADDR \"@ipMatch 203.0.113.50\" \"id:900,deny,tag:'copilot-block'\""
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/rules/custom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([disabled_rule])))
        .mount(&waf)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/rules/custom"))
        .and(body_string_contains(
            "\"raw_conf_text\":\"SecRule REMOTE_ADDR \\\"@ipMatch 203.0.113.7\\\" \
             \\\"id:AUTO,phase:1,deny,status:403,log,msg:'CoPilot block: \
             203.0.113.7',tag:'copilot-block'\\\"\"",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "r2", "rule_id": 901, "name": "CoPilot block: 203.0.113.7", "is_enabled": true,
            "field": "REMOTE_ADDR", "operator": "@ipMatch", "value": "203.0.113.7",
            "conf_text": "deny,tag:'copilot-block'"
        })))
        .expect(1)
        .mount(&waf)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/rules/custom/r1"))
        .and(body_string_contains("\"is_enabled\":true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r1", "rule_id": 900, "name": "CoPilot block: 203.0.113.50", "is_enabled": true,
            "field": "REMOTE_ADDR", "operator": "@ipMatch", "value": "203.0.113.50",
            "conf_text": "deny,tag:'copilot-block'"
        })))
        .expect(1)
        .mount(&waf)
        .await;
    let id = waf_row(&h, "blocks", &waf.uri(), true).await;
    let base = format!("/api/customer_waf/{}/{id}/blocks", h.code("acme"));

    let (status, created) = h
        .call(
            "POST",
            &base,
            Some(&analyst),
            Some(json!({"target": "203.0.113.7", "reason": "scan\n  from here", "alert_id": acme_alert})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["action"], "created");
    let comment: (String,) = sqlx::query_as(
        "SELECT comment FROM incident_management_comment WHERE alert_id = ? ORDER BY id DESC \
         LIMIT 1",
    )
    .bind(acme_alert)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        comment.0,
        format!(
            "WAF block: 203.0.113.7 blocked on WAF 'blocks' (rule 901) by analyst{}: scan from \
             here",
            h.suffix
        )
    );
    let (status, reenabled) = h
        .call(
            "POST",
            &base,
            Some(&analyst),
            Some(json!({"target": "203.0.113.50", "reason": "again"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reenabled["action"], "reenabled");

    // Another tenant's alert cannot be cited; a broad range is refused.
    let (status, foreign) = h
        .call(
            "POST",
            &base,
            Some(&analyst),
            Some(json!({"target": "203.0.113.8", "reason": "x", "alert_id": beta_alert})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{foreign}");
    let (status, broad) = h
        .call(
            "POST",
            &base,
            Some(&analyst),
            Some(json!({"target": "10.0.0.0/8", "reason": "x"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(broad["reason"], "invalid_target");
    // An IPv6 zone would reach the rule text: refused (RUST_MIGRATION.md §4).
    let (status, zone) = h
        .call(
            "POST",
            &base,
            Some(&analyst),
            Some(json!({"target": "fe80::1%x\",ctl:ruleEngine=Off,\"", "reason": "x"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{zone}");

    // The disabled rule is "already lifted"; nothing CoPilot made is a 404.
    let (status, lifted) = h
        .call(
            "DELETE",
            &format!("{base}?target=203.0.113.50"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{lifted}");
    assert_eq!(lifted["action"], "already_unblocked");
    let (status, none) = h
        .call(
            "DELETE",
            &format!("{base}?target=192.0.2.1"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(none["reason"], "not_blocked");
}

#[tokio::test]
async fn forwarding_rolls_back_what_it_created() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let waf = stand_in(0).await;
    let graylog = stand_in(1).await;
    let saved = set_graylog(&h, &graylog.uri()).await;
    me(&waf, &["admin"]).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/forwarders/"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&waf)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": "6.1.4"})))
        .mount(&graylog)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system/inputs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"inputs": [{"attributes": {"port": 5600}}]})),
        )
        .mount(&graylog)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/inputs"))
        .and(body_string_contains("\"port\": 5601"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "in1"})))
        .mount(&graylog)
        .await;
    for p in [
        "/api/system/inputs/in1/staticfields",
        "/api/system/inputs/in1/extractors",
    ] {
        Mock::given(method("POST"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(201))
            .mount(&graylog)
            .await;
    }
    for p in ["/api/system/indices/index_sets", "/api/streams"] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&graylog)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/api/system/indices/index_sets"))
        .and(body_string_contains("\"index_prefix\": \"waf-acme"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "is1"})))
        .mount(&graylog)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/streams"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"stream_id": "st1"})))
        .mount(&graylog)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/streams/st1/resume"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&graylog)
        .await;
    for p in [
        "/api/streams/st1",
        "/api/system/indices/index_sets/is1",
        "/api/system/inputs/in1",
    ] {
        Mock::given(method("DELETE"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&graylog)
            .await;
    }
    let id = waf_row(&h, "fwd", &waf.uri(), true).await;
    let (status, body) = h
        .call(
            "POST",
            &format!("/api/customer_waf/{}/{id}/forwarding", h.code("acme")),
            Some(&admin),
            Some(json!({"syslog_host": "10.0.0.9"})),
        )
        .await;
    restore_graylog(&h, saved).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["reason"], "forwarding_failed");
    assert_eq!(
        body["detail"],
        "Setting up event forwarding failed: WAF 'fwd' returned HTTP 500"
    );
    let provisioned: (Option<chrono::NaiveDateTime>,) =
        sqlx::query_as("SELECT forwarding_provisioned_at FROM customer_waf_instances WHERE id = ?")
            .bind(id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert!(provisioned.0.is_none(), "nothing is recorded");
}

#[tokio::test]
async fn monitoring_alerts_other_than_the_waf_go_to_python() {
    let legacy = stand_in(2).await;
    let h = harness_or_skip!(Some(&legacy), &env());
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    h.seed().await;
    Mock::given(method("POST"))
        .and(path("/api/monitoring_alert/provision"))
        .and(body_string_contains("WAZUH_SYSLOG_LEVEL_ALERT"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python"})))
        .expect(1)
        .mount(&legacy)
        .await;
    let (status, body) = h
        .call(
            "POST",
            "/api/monitoring_alert/provision",
            Some(&analyst),
            Some(json!({"search_within_last": 1, "execute_every": 1,
                        "alert_name": "WAZUH_SYSLOG_LEVEL_ALERT"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"from": "python"}));

    // A WAF alert is answered here: an existing definition is a 400.
    let graylog = stand_in(1).await;
    let saved = set_graylog(&h, &graylog.uri()).await;
    Mock::given(method("GET"))
        .and(path("/api/events/definitions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "event_definitions": [{
                "id": "d1", "title": "SOCFORTRESS WAF BLOCKED", "description": "d",
                "priority": 2, "alert": true,
                "config": {"type": "aggregation-v1", "query": "q", "query_parameters": [],
                           "streams": [], "group_by": [], "series": [],
                           "conditions": {"expression": null}, "search_within_ms": 1,
                           "execute_every_ms": 1, "event_limit": 1},
                "field_spec": {}, "key_spec": [],
                "notification_settings": {"grace_period_ms": 0, "backlog_size": 0},
                "notifications": [],
                "storage": [{"type": "persist-to-streams-v1", "streams": ["s"]}]
            }],
            "total": 1
        })))
        .mount(&graylog)
        .await;
    let (status, body) = h
        .call(
            "POST",
            "/api/monitoring_alert/provision",
            Some(&analyst),
            Some(json!({"search_within_last": 1, "execute_every": 1,
                        "alert_name": "socfortress waf blocked"})),
        )
        .await;
    restore_graylog(&h, saved).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Event definition SOCFORTRESS WAF BLOCKED already exists"
    );
}
