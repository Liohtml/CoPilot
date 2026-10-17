//! End-to-end tests of the provisioning ports: `/api/customer_waf` and the WAF
//! alerts of `POST /api/monitoring_alert/provision` (`copilot-waf`), and stack
//! provisioning (`copilot-provisioning`), through the production router on a
//! real MySQL, with the WAF admin API, Graylog, InfluxDB, Grafana and the
//! Python backend replaced by local stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13309/copilot \
//!   cargo test -p copilot --test e2e_provisioning -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `PROVISIONING_E2E_PORT_BASE` (5757) and the two
//! ports after it. The connector rows a test points at them are replaced for
//! that test and restored (run single-threaded).

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

/// Whether the suite runs at all. Checked before binding a stand-in the
/// harness needs (the legacy backend): without a database every test skips,
/// and `cargo test --workspace` runs them in parallel, so two of them must
/// not race for one port only to skip.
fn configured() -> bool {
    std::env::var("COPILOT_TEST_DATABASE_URL").is_ok()
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
async fn a_waf_monitoring_alert_checks_its_definition_first() {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return;
    }
    // (Every other monitoring alert is copilot-monitoring-alerts' too now:
    // `e2e_monitoring_alerts.rs`.)
    let h = harness_or_skip!(None, &env());
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    h.seed().await;

    // An existing definition is a 400.
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

// --- stack provisioning (copilot-provisioning) ---------------------------------

/// A saved `connectors` row: url, username, password, API key.
type SavedRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// A `connectors` row replaced for one test: what was there before.
struct SavedConnector(String, Vec<SavedRow>);

/// Point connector `name` at `url` (with a key and extra data); the old rows.
async fn replace_connector(
    h: &Harness,
    name: &str,
    url: &str,
    key: Option<&str>,
    extra: Option<&str>,
) -> SavedConnector {
    let saved: Vec<SavedRow> = sqlx::query_as(
        "SELECT connector_url, connector_username, connector_password, connector_api_key \
             FROM connectors WHERE connector_name = ?",
    )
    .bind(name)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
        .bind(name)
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
         (?, '3', ?, UTC_TIMESTAMP(), 'admin', 'secret', ?, 'e2e', 'e2e', 1, 1, 0, 0, 1, 0, 0, \
         ?, 1)",
    )
    .bind(name)
    .bind(url)
    .bind(key)
    .bind(extra)
    .execute(h.db.pool())
    .await
    .unwrap();
    SavedConnector(name.to_string(), saved)
}

async fn restore_connector(h: &Harness, saved: SavedConnector) {
    let SavedConnector(name, rows) = saved;
    sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
        .bind(&name)
        .execute(h.db.pool())
        .await
        .unwrap();
    for (url, user, pw, key) in rows {
        sqlx::query(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, \
             connector_last_updated, connector_username, connector_password, connector_api_key, \
             connector_description, connector_supports, connector_configured, \
             connector_verified, connector_accepts_host_only, connector_accepts_api_key, \
             connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_enabled) VALUES (?, '3', ?, \
             UTC_TIMESTAMP(), ?, ?, ?, 'restored', 'restored', 1, 1, 0, 0, 1, 0, 0, 1)",
        )
        .bind(&name)
        .bind(url)
        .bind(user)
        .bind(pw)
        .bind(key)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

fn graylog_system() -> Value {
    json!({"facility": "graylog-server", "codename": "Noir", "node_id": "n", "cluster_id": "c",
           "version": "6.1.4+d7b6e3c", "started_at": "2026-10-01T08:00:00.000Z",
           "hostname": "graylog01", "lifecycle": "running", "lb_status": "alive",
           "timezone": "UTC", "operating_system": "Linux", "is_processing": true})
}

#[tokio::test]
async fn content_packs_install_and_the_etw_rule_follows() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let graylog = stand_in(0).await;
    let saved = replace_connector(&h, "Graylog", &graylog.uri(), None, None).await;
    Mock::given(method("GET"))
        .and(path("/api/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graylog_system()))
        .mount(&graylog)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system/content_packs"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"total": 0, "content_packs": []})),
        )
        .expect(1)
        .mount(&graylog)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/content_packs"))
        .and(body_string_contains(
            "\"name\": \"SOCFORTRESS_WAZUH_CONTENT_PACK\"",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "x"})))
        .expect(1)
        .mount(&graylog)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/api/system/content_packs/261577fe-d9a2-4141-af74-635f085eee54/3/installations",
        ))
        .and(body_string_contains(
            "{\"comment\": \"Installed by SOCFortress CoPilot\"}",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&graylog)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/system/pipelines/rule"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&graylog)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/system/pipelines/rule"))
        .and(body_string_contains(
            "\"title\": \"Set Syslog Level to ALERT for ETW Registry\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "r"})))
        .expect(1)
        .mount(&graylog)
        .await;

    let uri = "/api/stack_provisioning/graylog/provision/content_pack";
    let (status, body) = h
        .call(
            "POST",
            uri,
            Some(&analyst),
            Some(json!({"content_pack_name": "SOCFORTRESS_SENTINELONE_INPUT_SYSLOG_TLS"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = h
        .call(
            "POST",
            uri,
            Some(&analyst),
            Some(json!({"content_pack_name": "SOCFORTRESS_WAZUH_CONTENT_PACK"})),
        )
        .await;
    restore_connector(&h, saved).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"success": true,
               "message": "SOCFORTRESS_WAZUH_CONTENT_PACK Content Pack provisioned successfully"})
    );
    graylog.verify().await;
}

#[tokio::test]
async fn influx_checks_are_skipped_unless_overwrite() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    let (admin, analyst) = (
        h.token(&format!("admin{}", h.suffix), "admin"),
        h.token(&format!("analyst{}", h.suffix), "analyst"),
    );
    let influx = stand_in(0).await;
    let saved = replace_connector(
        &h,
        "InfluxDB",
        &format!("{}/", influx.uri()),
        Some("tok"),
        Some("SOCFORTRESS,telegraf"),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/api/v2/orgs"))
        .and(query_param("org", "SOCFORTRESS"))
        .and(header("authorization", "Token tok"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"orgs": [{"id": "0a1b", "name": "SOCFORTRESS"}]})),
        )
        .mount(&influx)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v2/checks"))
        .and(query_param("limit", "100"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"checks": [{"id": "c-1", "name": "CPU CHECK"}]})),
        )
        .mount(&influx)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v2/checks/c-1"))
        .and(body_string_contains("\"orgID\":\"0a1b\""))
        .and(body_string_contains("from(bucket: \\\"telegraf\\\")"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "c-1"})))
        .expect(1)
        .mount(&influx)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v2/checks/c-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&influx)
        .await;

    let uri = "/api/stack_provisioning/influxdb/provision/check";
    let cpu = json!({"check_name": "SOCFORTRESS_INFLUXDB_CPU_CHECK"});
    let (status, skipped) = h.call("POST", uri, Some(&analyst), Some(cpu.clone())).await;
    assert_eq!(status, StatusCode::OK, "{skipped}");
    assert_eq!(skipped["results"][0]["action"], "skipped");
    assert_eq!(
        skipped["message"],
        "CPU CHECK already exists in InfluxDB and was left unchanged. Set overwrite to replace it."
    );
    let (status, updated) = h
        .call(
            "POST",
            uri,
            Some(&analyst),
            Some(json!({"check_name": "SOCFORTRESS_INFLUXDB_CPU_CHECK", "overwrite": true})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(
        updated["results"][0],
        json!({"name": "SOCFORTRESS_INFLUXDB_CPU_CHECK", "check_name": "CPU CHECK",
               "action": "updated", "check_id": "c-1"})
    );
    let (status, listed) = h
        .call(
            "GET",
            "/api/stack_provisioning/influxdb/available/checks",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let provisioned: Vec<bool> = listed["available_checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["provisioned"].as_bool().unwrap())
        .collect();
    assert_eq!(provisioned, [true, false, false, false]);
    let delete = "/api/stack_decommissioning/influxdb/check/SOCFORTRESS_INFLUXDB_CPU_CHECK";
    let (status, _) = h.call("DELETE", delete, Some(&analyst), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, deleted) = h.call("DELETE", delete, Some(&admin), None).await;
    restore_connector(&h, saved).await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(deleted["message"], "CPU CHECK decommissioned successfully");
    influx.verify().await;
}

#[tokio::test]
async fn network_connector_decommissioning_is_tenant_bound() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    let (admin, analyst) = (
        h.token(&format!("admin{}", h.suffix), "admin"),
        h.token(&format!("analyst{}", h.suffix), "analyst"),
    );
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    for code in [&acme, &beta] {
        sqlx::query(
            "INSERT INTO customer_network_connectors_meta (customer_code, network_connector_name, \
             graylog_input_id, graylog_index_id, graylog_stream_id, grafana_org_id, \
             grafana_dashboard_folder_id, graylog_pipeline_id, graylog_content_pack_input_id, \
             graylog_content_pack_stream_id, grafana_datasource_uid) VALUES (?, 'FORTINET', 'i', \
             'x', 's', '44', 'fold', 'p', 'cp-in', 'cp-st', 'ds')",
        )
        .bind(code)
        .execute(h.db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO customer_network_connectors (customer_code, customer_name, \
             network_connector_service_id, network_connector_service_name, deployed) VALUES \
             (?, 'n', 1, 'Fortinet', 1)",
        )
        .bind(code)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
    let graylog = stand_in(0).await;
    let grafana = stand_in(1).await;
    let saved_graylog = replace_connector(&h, "Graylog", &graylog.uri(), None, None).await;
    let saved_grafana = replace_connector(&h, "Grafana", &grafana.uri(), None, None).await;
    for pack in ["cp-in", "cp-st"] {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/system/content_packs/{pack}/installations"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"installations": [{"_id": format!("inst-{pack}")}]})),
            )
            .expect(1)
            .mount(&graylog)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/system/content_packs/{pack}/installations/inst-{pack}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&graylog)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/system/content_packs/{pack}")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&graylog)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/api/user/using/44"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "ok"})))
        .expect(2)
        .mount(&grafana)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/folders/fold"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&grafana)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/datasources/uid/ds"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 1})))
        .expect(1)
        .mount(&grafana)
        .await;

    let uri = "/api/stack_decommissioning/graylog/decommission/network_connector";
    // Python lets any analyst tear down any tenant's connector.
    let (status, refused) = h
        .call(
            "POST",
            uri,
            Some(&analyst),
            Some(json!({"network_connector": "fortinet", "customer_code": beta})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    let (status, body) = h
        .call(
            "POST",
            uri,
            Some(&admin),
            Some(json!({"network_connector": "fortinet", "customer_code": acme})),
        )
        .await;
    restore_connector(&h, saved_graylog).await;
    restore_connector(&h, saved_grafana).await;
    let left: Vec<(String,)> = sqlx::query_as(
        "SELECT customer_code FROM customer_network_connectors_meta WHERE customer_code IN (?, ?)",
    )
    .bind(&acme)
    .bind(&beta)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    let flags: Vec<(String, bool)> = sqlx::query_as(
        "SELECT customer_code, deployed FROM customer_network_connectors WHERE customer_code IN \
         (?, ?) ORDER BY customer_code",
    )
    .bind(&acme)
    .bind(&beta)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    for table in [
        "customer_network_connectors_meta",
        "customer_network_connectors",
    ] {
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE customer_code IN (?, ?)"
        ))
        .bind(&acme)
        .bind(&beta)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(left, [(beta.clone(),)]);
    assert_eq!(flags, [(acme, false), (beta, true)]);
    graylog.verify().await;
    grafana.verify().await;
}

// --- customer provisioning (copilot-provisioning::customer) -------------------

async fn set_verified(h: &Harness, name: &str, verified: bool) {
    sqlx::query("UPDATE connectors SET connector_verified = ? WHERE connector_name = ?")
        .bind(verified)
        .bind(name)
        .execute(h.db.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn default_settings_are_one_row() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let saved: Vec<(i32,)> =
        sqlx::query_as("SELECT id FROM customer_provisioning_default_settings")
            .fetch_all(h.db.pool())
            .await
            .unwrap();
    if !saved.is_empty() {
        eprintln!("customer_provisioning_default_settings is not empty; skipping");
        return;
    }
    let uri = "/api/customer_provisioning/default_settings";
    let (status, _) = h.call("GET", uri, Some(&analyst), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let body = json!({"cluster_name": "c", "cluster_key": 5, "master_ip": "10.0.0.5",
                      "grafana_url": "https://g", "wazuh_worker_hostname": "w"});
    let (status, created) = h
        .call("POST", uri, Some(&analyst), Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let settings = &created["customer_provisioning_default_settings"];
    // The values as sent (the table model is not validated), the id last.
    assert_eq!(settings["cluster_key"], 5);
    assert_eq!(settings["repo_url"], Value::Null);
    let keys: Vec<&String> = settings.as_object().unwrap().keys().collect();
    assert_eq!(keys.last().unwrap().as_str(), "id");
    let id = settings["id"].as_i64().unwrap();
    let (status, again) = h.call("POST", uri, Some(&analyst), Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{again}");
    let (status, updated) = h
        .call(
            "PUT",
            uri,
            Some(&analyst),
            Some(json!({"id": id, "master_ip": "10.9.9.9", "repo_url": "https://repo"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    let s = &updated["customer_provisioning_default_settings"];
    assert_eq!(s["cluster_key"], "5");
    assert_eq!(s["master_ip"], "10.9.9.9");
    assert_eq!(s["repo_url"], "https://repo");
    let (status, deleted) = h.call("DELETE", uri, Some(&analyst), None).await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    let (status, _) = h.call("DELETE", uri, Some(&analyst), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn decommissioning_a_customer_tears_down_every_tool() {
    let h = harness_or_skip!(None, &env());
    h.seed().await;
    let (admin, analyst) = (
        h.token(&format!("admin{}", h.suffix), "admin"),
        h.token(&format!("analyst{}", h.suffix), "analyst"),
    );
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    for code in [&acme, &beta] {
        sqlx::query(
            "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, \
             customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group, \
             customer_meta_wazuh_registration_port, customer_meta_wazuh_log_ingestion_port, \
             customer_meta_wazuh_auth_password) VALUES (?, ?, 'is-1', 'st-1', '44', ?, '1515', \
             '1514', 'pw')",
        )
        .bind(code)
        .bind(format!("{code} corp"))
        .bind(code)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
    let tools = stand_in(0).await;
    let base = tools.uri();
    let saved = vec![
        replace_connector(&h, "Wazuh-Manager", &format!("{base}/wazuh"), None, None).await,
        replace_connector(&h, "Graylog", &format!("{base}/graylog"), None, None).await,
        replace_connector(&h, "Grafana", &format!("{base}/grafana"), None, None).await,
        replace_connector(&h, "Portainer", &format!("{base}/portainer"), None, None).await,
        replace_connector(
            &h,
            "Wazuh Worker Provisioning",
            &format!("{base}/worker"),
            None,
            None,
        )
        .await,
        replace_connector(
            &h,
            "HAProxy Provisioning",
            &format!("{base}/haproxy"),
            None,
            None,
        )
        .await,
    ];
    set_verified(&h, "Portainer", false).await;
    set_verified(&h, "HAProxy Provisioning", false).await;
    Mock::given(method("GET"))
        .and(path("/wazuh/security/user/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "t"}})))
        .mount(&tools)
        .await;
    Mock::given(method("GET"))
        .and(path("/wazuh/agents"))
        .and(query_param("group", format!("Linux_{acme}").as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"affected_items": [{"id": "001"}]}})),
        )
        .mount(&tools)
        .await;
    Mock::given(method("GET"))
        .and(path("/wazuh/agents"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"affected_items": []}})),
        )
        .mount(&tools)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/wazuh/agents"))
        .and(query_param("agents_list", "001"))
        .and(query_param("older_than", "0s"))
        .and(header("authorization", "Bearer t"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {}})))
        .expect(1)
        .mount(&tools)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/wazuh/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {}})))
        .expect(3)
        .mount(&tools)
        .await;
    for p in [
        "/graylog/api/streams/st-1",
        "/graylog/api/system/indices/index_sets/is-1",
    ] {
        Mock::given(method("DELETE"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&tools)
            .await;
    }
    Mock::given(method("DELETE"))
        .and(path("/grafanaapi/orgs/44"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "deleted"})))
        .expect(1)
        .mount(&tools)
        .await;
    Mock::given(method("POST"))
        .and(path("/worker/provision_worker/decommission"))
        .and(body_string_contains(format!(
            "{{\"customer_name\": \"{acme} corp\", \"customer_code\": \"{acme}\", \
             \"portainer_deployment\": false}}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&tools)
        .await;

    let uri = "/api/customer_provisioning/decommission";
    let (status, refused) = h
        .call(
            "POST",
            &format!("{uri}?customer_code={beta}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    let (status, body) = h
        .call(
            "POST",
            &format!("{uri}?customer_code={acme}"),
            Some(&admin),
            None,
        )
        .await;
    for s in saved {
        restore_connector(&h, s).await;
    }
    let left: Vec<(String,)> =
        sqlx::query_as("SELECT customer_code FROM customersmeta WHERE customer_code IN (?, ?)")
            .bind(&acme)
            .bind(&beta)
            .fetch_all(h.db.pool())
            .await
            .unwrap();
    sqlx::query("DELETE FROM customersmeta WHERE customer_code IN (?, ?)")
        .bind(&acme)
        .bind(&beta)
        .execute(h.db.pool())
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["decomissioned_data"],
        json!({"agents_deleted": ["001"],
               "groups_deleted": [format!("Linux_{acme}"), format!("Windows_{acme}"),
                                  format!("Mac_{acme}")],
               "stream_deleted": "st-1", "index_deleted": "is-1"})
    );
    assert_eq!(body["manual_steps"], json!([]));
    assert_eq!(left, [(beta,)]);
    tools.verify().await;
}

#[tokio::test]
async fn template_bound_provisioning_stays_in_python() {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return;
    }
    let legacy = stand_in(2).await;
    let h = harness_or_skip!(Some(&legacy), &env());
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    h.seed().await;
    let routes = [
        "/api/customer_provisioning/provision",
        "/api/customer_provisioning/provision/wazuh_worker",
        "/api/stack_provisioning/graylog/provision/fortinet",
        "/api/stack_provisioning/graylog/provision/sonicwall",
        "/api/stack_provisioning/graylog/provision/sentinelone",
    ];
    for route in routes {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python"})))
            .expect(1)
            .mount(&legacy)
            .await;
    }
    for route in routes {
        let (status, body) = h
            .call("POST", route, Some(&analyst), Some(json!({"x": 1})))
            .await;
        assert_eq!(status, StatusCode::OK, "{route}: {body}");
        assert_eq!(body, json!({"from": "python"}), "{route}");
    }
    legacy.verify().await;
}
