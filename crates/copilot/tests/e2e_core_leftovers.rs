//! The core leftovers against a real MySQL at the Alembic head: the customer
//! writes (`copilot-customers`, the licence server a wiremock stand-in) and
//! the Wazuh manager's rule switches, exclusion and Atomic Red Team listings
//! (`copilot-wazuh-rules`: the manager, the AI module and GitHub stand-ins).
//!
//! `license` and `license_cache` are deployment-wide: each test puts the rows
//! it finds aside and restores them, so the suites can share one database.
//!
//! Stand-ins bind `CORE_LEFTOVERS_E2E_PORT_BASE` (default 6431) and the next
//! few ports.
//!
//! `COPILOT_TEST_DATABASE_URL=mysql://… cargo test -p copilot --test
//! e2e_core_leftovers -- --test-threads=1`

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod common;

use serde_json::{Value, json};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{Harness, harness_env};

// --- shared helpers ---------------------------------------------------------------------

fn port(offset: u16) -> u16 {
    std::env::var("CORE_LEFTOVERS_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6431)
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

async fn cleanup(h: &Harness) {
    let s = &h.suffix;
    for sql in [
        format!(
            "DELETE FROM user_customer_access WHERE user_id IN \
             (SELECT id FROM `user` WHERE username LIKE '%{s}')"
        ),
        format!("DELETE FROM `user` WHERE username LIKE '%{s}'"),
        format!("DELETE FROM incident_management_asset WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM incident_management_alert WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM agents WHERE hostname LIKE '%{s}'"),
        format!("DELETE FROM customersmeta WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM customers WHERE customer_code LIKE '%{s}'"),
    ] {
        let _ = sqlx::query(&sql).execute(h.db.pool()).await;
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SavedLicense {
    id: i32,
    license_key: String,
    customer_name: String,
    customer_email: String,
    company_name: String,
}

async fn save_licences(h: &Harness) -> Vec<SavedLicense> {
    let saved = sqlx::query_as::<_, SavedLicense>(
        "SELECT id, license_key, customer_name, customer_email, company_name FROM license",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    h.exec("DELETE FROM license").await;
    saved
}

async fn restore_licences(h: &Harness, saved: Vec<SavedLicense>) {
    h.exec("DELETE FROM license").await;
    for r in saved {
        sqlx::query(
            "INSERT INTO license (id, license_key, customer_name, customer_email, company_name) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(r.id)
        .bind(r.license_key)
        .bind(r.customer_name)
        .bind(r.customer_email)
        .bind(r.company_name)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

fn verify_answer(objects: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {"license": {"key": "k", "dataObjects": objects}, "success": true},
        "success": true,
    }))
}

// --- /api/customers writes ----------------------------------------------------------------

#[tokio::test]
async fn customer_writes_follow_python() {
    if !configured() {
        return;
    }
    let mut h = harness_or_skip!(None);
    h.seed().await;
    let saved = save_licences(&h).await;
    let key = format!("E2E-CUST-{}", h.suffix);
    h.exec(&format!(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) \
         VALUES ('{key}', 'n', 'e@example.com', 'c')"
    ))
    .await;
    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key = '{key}'"
    ))
    .await;
    let upstream = stand_in(0).await;
    h.router = copilot_customers::router(copilot_customers::CustomersState {
        ctx: h.app.ctx.clone(),
        license: copilot_license::LicenseClient::new(format!("{}/", upstream.uri()), None).unwrap(),
    });
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let body = |code: &str| {
        json!({
            "customer_code": code, "customer_name": "New Co", "contact_last_name": "Doe",
            "contact_first_name": "Jane", "phone": "123", "is_provisioned": "yes",
        })
    };
    let new_code = format!("new{s}");

    // Guards and validation, in FastAPI's order.
    let (st, _) = h
        .call("POST", "/", Some(&analyst), Some(body(&new_code)))
        .await;
    assert_eq!(st, 403);
    let (st, err) = h
        .call(
            "POST",
            "/",
            Some(&admin),
            Some(json!({"customer_code": 5, "customer_name": "x"})),
        )
        .await;
    assert_eq!(st, 422, "{err}");

    // Seats: enough → created, the answer is the body as sent.
    Mock::given(method("POST"))
        .and(path("/verify-license"))
        .and(body_json(json!({"license_key": key})))
        .respond_with(verify_answer(
            json!([{"name": "MSSP Seats", "intValue": 100_000}]),
        ))
        .up_to_n_times(1)
        .mount(&upstream)
        .await;
    let (st, out) = h
        .call("POST", "/", Some(&admin), Some(body(&new_code)))
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(out["message"], json!("Customer created successfully"));
    assert_eq!(out["customer"]["customer_code"], json!(new_code));
    assert_eq!(out["customer"]["is_provisioned"], json!(true));
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM customers WHERE customer_code = '{new_code}' AND phone = '123'"
        ))
        .await,
        1
    );

    // One seat: over the limit, nothing written.
    Mock::given(method("POST"))
        .and(path("/verify-license"))
        .respond_with(verify_answer(
            json!([{"name": "MSSP Seats", "intValue": 1}]),
        ))
        .up_to_n_times(1)
        .mount(&upstream)
        .await;
    let (st, out) = h
        .call("POST", "/", Some(&admin), Some(body(&format!("other{s}"))))
        .await;
    assert_eq!(st, 400, "{out}");
    let message = out["message"].as_str().unwrap();
    assert!(
        message.starts_with("You have reached your licensed customer limit (")
            && message.ends_with(
                "/1 seats). Please purchase additional MSSP seats to provision more customers."
            ),
        "{message}"
    );

    // No seat pack: the boolean ladder; "MSSP Unlimited" disabled in the cache.
    h.exec(&format!(
        "INSERT INTO license_cache (license_key, feature_name, is_enabled, cached_at, expires_at) \
         VALUES ('{key}', 'MSSP Unlimited', 0, UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 1 HOUR)"
    ))
    .await;
    Mock::given(method("POST"))
        .and(path("/verify-license"))
        .respond_with(verify_answer(json!([{"name": "AI", "intValue": 1}])))
        .mount(&upstream)
        .await;
    let (st, out) = h
        .call("POST", "/", Some(&admin), Some(body(&format!("other{s}"))))
        .await;
    assert_eq!(st, 400, "{out}");
    assert_eq!(
        out["message"],
        json!(
            "You have reached the maximum number of customers allowed for your license type. \
             Please upgrade your license to provision more customers."
        )
    );
    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key = '{key}'"
    ))
    .await;
    upstream.reset().await;

    // The code is unique (MySQL's collation compares it).
    Mock::given(method("POST"))
        .and(path("/verify-license"))
        .respond_with(verify_answer(
            json!([{"name": "MSSP Unlimited", "intValue": 1}]),
        ))
        .mount(&upstream)
        .await;
    let (st, out) = h
        .call(
            "POST",
            "/",
            Some(&admin),
            Some(body(&new_code.to_uppercase())),
        )
        .await;
    assert_eq!(st, 400);
    assert_eq!(
        out["message"],
        json!("Customer with this customer_code already exists")
    );

    // Update: every field set (an omitted one cleared), unknown → 404.
    let mut changed = body(&new_code);
    changed["customer_name"] = json!("Renamed Co");
    changed.as_object_mut().unwrap().remove("phone");
    let (st, out) = h
        .call(
            "PUT",
            &format!("/{}", new_code.to_uppercase()),
            Some(&admin),
            Some(changed.clone()),
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(out["customer"]["customer_name"], json!("Renamed Co"));
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM customers WHERE customer_code = '{new_code}' \
             AND customer_name = 'Renamed Co' AND phone IS NULL"
        ))
        .await,
        1
    );
    let (st, out) = h
        .call("PUT", &format!("/nosuch{s}"), Some(&admin), Some(changed))
        .await;
    assert_eq!(st, 404);
    assert_eq!(
        out["message"],
        json!(format!("Customer with customer_code nosuch{s} not found"))
    );

    // Meta: create (deprecated), update with exclude_unset, delete.
    let meta = |index: &str| {
        json!({
            "customer_meta_graylog_index": index, "customer_meta_graylog_stream": "s",
            "customer_meta_grafana_org_id": "1", "customer_meta_wazuh_group": "g",
            "customer_meta_index_retention": "30", "customer_meta_wazuh_registration_port": "1",
            "customer_meta_wazuh_log_ingestion_port": "2", "customer_meta_wazuh_api_port": "3",
            "customer_meta_wazuh_auth_password": "pw", "customer_meta_portainer_stack_id": "7",
        })
    };
    let (st, out) = h
        .call(
            "POST",
            &format!("/{new_code}/meta"),
            Some(&admin),
            Some(meta("idx")),
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(
        out["customer_meta"]["customer_meta_portainer_stack_id"],
        json!(7)
    );
    let mut update = meta("idx2");
    update
        .as_object_mut()
        .unwrap()
        .remove("customer_meta_portainer_stack_id");
    let (st, out) = h
        .call(
            "PUT",
            &format!("/{new_code}/meta"),
            Some(&admin),
            Some(update),
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(
        out["customer_meta"]["customer_meta_portainer_stack_id"],
        Value::Null
    );
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM customersmeta WHERE customer_code = '{new_code}' \
             AND customer_meta_graylog_index = 'idx2' AND customer_meta_portainer_stack_id = 7"
        ))
        .await,
        1
    );

    // A meta row makes the delete fail (its NOT NULL customer code).
    let (st, out) = h
        .call("DELETE", &format!("/{new_code}"), Some(&admin), None)
        .await;
    assert_eq!(st, 400, "{out}");
    assert_eq!(
        out["message"],
        json!(
            "Cannot delete customer due to existing dependencies. Please ensure all related data \
             is removed first."
        )
    );
    let (st, out) = h
        .call("DELETE", &format!("/{new_code}/meta"), Some(&admin), None)
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(
        out["customer_meta"]["customer_meta_graylog_index"],
        json!("idx2")
    );
    let (st, _) = h
        .call("DELETE", &format!("/{new_code}/meta"), Some(&admin), None)
        .await;
    assert_eq!(st, 404);

    // An assigned user: the users' 400.
    h.exec(&format!(
        "INSERT INTO user_customer_access (user_id, customer_code, created_at) \
         SELECT id, '{new_code}', UTC_TIMESTAMP() FROM `user` WHERE username = 'analyst{s}'"
    ))
    .await;
    let (st, out) = h
        .call("DELETE", &format!("/{new_code}"), Some(&admin), None)
        .await;
    assert_eq!(st, 400);
    assert!(
        out["message"]
            .as_str()
            .unwrap()
            .contains("There are still users assigned to this customer"),
        "{out}"
    );
    h.exec(&format!(
        "DELETE FROM user_customer_access WHERE customer_code = '{new_code}'"
    ))
    .await;

    // An agent: its customer code set to NULL, the customer deleted.
    h.exec(&format!(
        "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, \
         wazuh_last_seen, wazuh_agent_version, wazuh_agent_status, customer_code, quarantined) \
         VALUES ('e2e{s}', '1', 'l', 'host{s}', 'l', 0, UTC_TIMESTAMP(), '1', 'active', \
         '{new_code}', 0)"
    ))
    .await;
    let (st, out) = h
        .call("DELETE", &format!("/{new_code}"), Some(&admin), None)
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(
        out,
        json!({"success": true, "message": format!("Customer '{new_code}' deleted successfully")})
    );
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM agents WHERE hostname = 'host{s}' AND customer_code IS NULL"
        ))
        .await,
        1
    );
    let (st, _) = h
        .call("DELETE", &format!("/{new_code}"), Some(&admin), None)
        .await;
    assert_eq!(st, 404);

    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key = '{key}'"
    ))
    .await;
    restore_licences(&h, saved).await;
    cleanup(&h).await;
}

// --- /api/wazuh_manager rule switches, exclusion, Atomic Red Team ---------------------

#[derive(Debug, Clone, sqlx::FromRow)]
struct SavedConnector {
    connector_name: String,
    connector_url: String,
}

/// The `Wazuh-Manager` row pointed at `url` (the row found is restored by
/// [`restore_manager`]).
async fn point_manager(h: &Harness, url: &str) -> Vec<SavedConnector> {
    point_connector(h, "Wazuh-Manager", url).await
}

/// The connector row `name` pointed at `url`, created when missing (the
/// row found is restored by [`restore_connector`]).
async fn point_connector(h: &Harness, name: &str, url: &str) -> Vec<SavedConnector> {
    let saved = sqlx::query_as::<_, SavedConnector>(
        "SELECT connector_name, connector_url FROM connectors WHERE connector_name = ?",
    )
    .bind(name)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    if saved.is_empty() {
        sqlx::query(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, \
             connector_last_updated, connector_username, connector_password, connector_api_key, \
             connector_description, connector_supports, connector_configured, connector_verified, \
             connector_accepts_host_only, connector_accepts_api_key, \
             connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
             (?, '4.8', ?, '2026-01-02 03:04:05', 'wazuh', 'pw', NULL, 'desc', \
             'supports', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
        )
        .bind(name)
        .bind(url)
        .execute(h.db.pool())
        .await
        .unwrap();
    } else {
        sqlx::query("UPDATE connectors SET connector_url = ? WHERE connector_name = ?")
            .bind(url)
            .bind(name)
            .execute(h.db.pool())
            .await
            .unwrap();
    }
    saved
}

async fn restore_manager(h: &Harness, saved: Vec<SavedConnector>) {
    restore_connector(h, "Wazuh-Manager", saved).await;
}

async fn restore_connector(h: &Harness, name: &str, saved: Vec<SavedConnector>) {
    match saved.first() {
        None => {
            sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
                .bind(name)
                .execute(h.db.pool())
                .await
                .unwrap();
        }
        Some(row) => {
            sqlx::query("UPDATE connectors SET connector_url = ? WHERE connector_name = ?")
                .bind(&row.connector_url)
                .bind(&row.connector_name)
                .execute(h.db.pool())
                .await
                .unwrap();
        }
    }
}

fn rule_file(rule_id: &str, level: &str) -> Value {
    json!({"data": {"affected_items": [{"group": {
        "@name": "syslog,sshd,",
        "rule": [
            {"@id": "5700", "@level": "0", "decoded_as": "sshd", "description": "SSHD messages."},
            {"@id": rule_id, "@level": level, "if_sid": "5700",
             "match": "illegal user|invalid user", "description": "sshd: attempt & <bad>"}
        ]
    }}], "total_affected_items": 1}, "error": 0})
}

async fn wazuh_manager(rule_id: &str, filename: &str) -> MockServer {
    use wiremock::matchers::query_param;
    let server = stand_in(1).await;
    Mock::given(method("GET"))
        .and(path("/security/user/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "tok"}, "error": 0})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rules"))
        .and(query_param("rule_ids", rule_id))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "affected_items": [{"filename": filename, "id": 5710}], "total_affected_items": 1
        }, "error": 0})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rules"))
        .and(query_param("rule_ids", "404404"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "affected_items": [], "total_affected_items": 0
        }, "error": 0})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/rules/files/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_file(rule_id, "5")))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("/rules/files/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data": {"affected_items": [filename], "total_affected_items": 1}, "error": 0}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/manager/restart"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {}, "error": 0})))
        .mount(&server)
        .await;
    server
}

/// The rule file Python's `convert_to_xml` writes for [`rule_file`] at `level`.
fn expected_xml(rule_id: &str, level: &str) -> String {
    format!(
        "<group name=\"syslog,sshd,\">\n\t<rule id=\"5700\" level=\"0\">\n\t\t<decoded_as>sshd\
         </decoded_as>\n\t\t<description>SSHD messages.</description>\n\t</rule>\n\t<rule \
         id=\"{rule_id}\" level=\"{level}\">\n\t\t<if_sid>5700</if_sid>\n\t\t<match>illegal \
         user|invalid user</match>\n\t\t<description>sshd: attempt &amp; &lt;bad&gt;\
         </description>\n\t</rule>\n</group>"
    )
}

#[tokio::test]
async fn wazuh_rule_routes_follow_python() {
    if !configured() {
        return;
    }
    let extra = format!(
        "COPILOT_INTEGRATION_MODULES_URL=http://127.0.0.1:{}\n\
         COPILOT_GITHUB_RAW_URL=http://127.0.0.1:{}/raw\n\
         COPILOT_GITHUB_API_URL=http://127.0.0.1:{}/api\n",
        port(2),
        port(3),
        port(3)
    );
    let h = harness_or_skip!(None, &extra);
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let rule_id = format!("9{}", u32::from_str_radix(&s, 16).unwrap() % 100_000);
    let filename = "0095-sshd_rules.xml";
    h.exec(&format!(
        "DELETE FROM disabledrule WHERE rule_id = '{rule_id}'"
    ))
    .await;
    let manager = wazuh_manager(&rule_id, filename).await;
    let saved = point_manager(&h, &manager.uri()).await;
    let m = |p: &str| format!("/api/wazuh_manager{p}");

    // Guards and the body, in FastAPI's order.
    let (st, _) = h
        .call("GET", &m("/rule/disabled"), Some(&analyst), None)
        .await;
    assert_eq!(st, 403);
    let (st, out) = h
        .call_raw(
            "POST",
            &m("/rule/disable"),
            None,
            Some("application/json"),
            "{",
        )
        .await;
    assert_eq!(st, 422, "{out}");
    let (st, out) = h
        .call(
            "POST",
            &m("/rule/disable"),
            Some(&admin),
            Some(json!({"rule_id": 5})),
        )
        .await;
    assert_eq!(st, 422, "{out}");

    // Disable: the file goes back with level 1, the row keeps the old one.
    let body = json!({"rule_id": rule_id, "reason_for_disabling": "noise", "length_of_time": "1d"});
    let (st, out) = h
        .call(
            "POST",
            &m("/rule/disable"),
            Some(&admin),
            Some(body.clone()),
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(
        out,
        json!({"previous_level": "5", "message": format!(
            "Rule {rule_id} successfully processed in file {filename}."
        ), "success": true})
    );
    let sent = manager.received_requests().await.unwrap();
    let puts: Vec<_> = sent
        .iter()
        .filter(|r| r.method.as_str() == "PUT" && r.url.path().starts_with("/rules/files/"))
        .collect();
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0].url.query(), Some("overwrite=true"));
    assert_eq!(
        puts[0].headers.get("content-type").unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        String::from_utf8(puts[0].body.clone()).unwrap(),
        expected_xml(&rule_id, "1")
    );
    assert!(
        sent.iter()
            .any(|r| r.method.as_str() == "PUT" && r.url.path() == "/manager/restart")
    );
    let disabled_by: String = sqlx::query_scalar(
        "SELECT CONCAT(previous_level, '|', new_level, '|', reason_for_disabling, '|', \
         length_of_time, '|', disabled_by) FROM disabledrule WHERE rule_id = ?",
    )
    .bind(&rule_id)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(disabled_by, format!("5|1|noise|1d|admin{s}"));
    let (st, out) = h
        .call("POST", &m("/rule/disable"), Some(&admin), Some(body))
        .await;
    assert_eq!(
        (st.as_u16(), out),
        (
            500,
            json!({"success": false, "message": "Rule is already disabled"})
        )
    );
    let (st, out) = h
        .call("GET", &m("/rule/disabled"), Some(&admin), None)
        .await;
    assert_eq!(st, 200, "{out}");
    let mine: Vec<&Value> = out["disabled_rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["rule_id"] == json!(rule_id))
        .collect();
    assert_eq!(
        mine,
        vec![
            &json!({"rule_id": rule_id, "previous_level": "5", "new_level": "1",
                     "reason_for_disabling": "noise", "length_of_time": "1d",
                     "disabled_by": format!("admin{s}")})
        ]
    );
    assert_eq!(
        out["message"],
        json!("Successfully fetched all disabled rules")
    );

    // Enable: the recorded level goes back, the row goes.
    let enable = json!({"rule_id": rule_id, "reason_for_enabling": "fixed"});
    let (st, out) = h
        .call(
            "POST",
            &m("/rule/enable"),
            Some(&admin),
            Some(enable.clone()),
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(out["new_level"], Value::Null);
    let sent = manager.received_requests().await.unwrap();
    let last_put = sent
        .iter()
        .rfind(|r| r.method.as_str() == "PUT" && r.url.path().starts_with("/rules/files/"))
        .unwrap();
    assert_eq!(
        String::from_utf8(last_put.body.clone()).unwrap(),
        expected_xml(&rule_id, "5")
    );
    let (st, out) = h
        .call("POST", &m("/rule/enable"), Some(&admin), Some(enable))
        .await;
    assert_eq!(
        (st.as_u16(), out),
        (
            404,
            json!({"success": false, "message": "Rule is already enabled"})
        )
    );
    let missing = json!({"rule_id": "404404", "reason_for_disabling": "x", "length_of_time": "x"});
    let (st, out) = h
        .call("POST", &m("/rule/disable"), Some(&admin), Some(missing))
        .await;
    assert_eq!(st, 404, "{out}");
    assert_eq!(
        out["message"],
        json!("Rule 404404 not found. Make sure the rule ID is correct within the Wazuh Manager.")
    );

    // The exclusion: the AI module's answer, validated.
    let ai = stand_in(2).await;
    Mock::given(method("POST"))
        .and(path("/copilot-ai-module/wazuh-rule-exclusion"))
        .and(body_json(json!({"integration": "wazuh-rule-exclusion",
                              "prompt": {"rule_group1": "windows", "n": 1}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wazuh_rule": "<rule/>", "explanation": "e", "message": "m", "success": true
        })))
        .mount(&ai)
        .await;
    let ok = json!({"integration": "wazuh-rule-exclusion", "prompt": {"rule_group1": "windows", "n": 1}});
    let (st, out) = h
        .call("POST", &m("/rule/exclude"), Some(&admin), Some(ok))
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(out["wazuh_rule"], json!("<rule/>"));
    let (st, out) = h
        .call(
            "POST",
            &m("/rule/exclude"),
            Some(&admin),
            Some(json!({"integration": "x", "prompt": {}})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), out),
        (
            400,
            json!({"success": false, "message": "Invalid integration. Only 'wazuh-rule-exclusion' is supported."})
        )
    );
    let (st, _) = h
        .call(
            "POST",
            &m("/rule/exclude"),
            Some(&analyst),
            Some(json!({"integration": "x", "prompt": {}})),
        )
        .await;
    assert_eq!(st, 403);
    drop(ai);

    // Atomic Red Team: the index, then the process's cache.
    let github = stand_in(3).await;
    Mock::given(method("GET"))
        .and(path(
            "/raw/redcanaryco/atomic-red-team/refs/heads/master/atomics/Indexes/Indexes-Markdown/atomic-red-team-index.md",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "| [OS Credential Dumping](x) | T1003 | 12 |\n| [LSASS Memory](y) | T1003.001 | 7 |\n",
        ))
        .mount(&github)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/raw/redcanaryco/atomic-red-team/refs/heads/master/atomics/T1003/T1003.md",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("# OS Credential Dumping"))
        .mount(&github)
        .await;
    let (st, out) = h
        .call(
            "GET",
            &m("/mitre/atomic-tests?size=1&page=2"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(
        out["message"],
        json!("Found 2 MITRE techniques (page 2 of 2)")
    );
    assert_eq!(out["total_tests"], json!(19));
    assert_eq!(out["tests"][0]["technique_id"], json!("T1003.001"));
    let (st, out) = h
        .call("GET", &m("/mitre/atomic-tests"), Some(&analyst), None)
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(out["total_tests"], Value::Null);
    let index_fetches = github
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("atomic-red-team-index.md"))
        .count();
    assert_eq!(index_fetches, 1);
    let sent = github.received_requests().await.unwrap();
    let names: Vec<String> = sent[0]
        .headers
        .iter()
        .map(|(k, _)| k.as_str().to_string())
        .collect();
    assert!(names.contains(&"user-agent".to_string()), "{names:?}");
    assert_eq!(
        sent[0].headers.get("user-agent").unwrap(),
        "Python/3.11 aiohttp/3.13.5"
    );
    let (st, out) = h
        .call(
            "GET",
            &m("/mitre/atomic-tests?page=0&size=x"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 422, "{out}");
    let (st, out) = h
        .call(
            "GET",
            &m("/mitre/atomic-tests?size=0"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), out),
        (
            500,
            json!({"success": false, "message": "Error retrieving atomic tests: integer division or modulo by zero"})
        )
    );
    let (st, out) = h
        .call(
            "GET",
            &m("/mitre/techniques/attack-T1003/atomic-tests"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(
        out,
        json!({"success": true, "message": "Atomic Red Team tests retrieved for technique attack-T1003",
               "technique_id": "T1003", "markdown_content": "# OS Credential Dumping"})
    );
    let (st, out) = h
        .call(
            "GET",
            &m("/mitre/techniques/T9999/atomic-tests"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(out["success"], json!(false));
    assert_eq!(out["markdown_content"], Value::Null);

    restore_manager(&h, saved).await;
    h.exec(&format!(
        "DELETE FROM disabledrule WHERE rule_id = '{rule_id}'"
    ))
    .await;
    cleanup(&h).await;
}

// --- /api/healthcheck/logs, /api/carbonblack/test ------------------------------------------

#[tokio::test]
async fn host_logs_and_carbonblack_test_follow_python() {
    use wiremock::matchers::body_string_contains;
    if !configured() {
        return;
    }
    let extra = format!(
        "COPILOT_INTEGRATION_MODULES_URL=http://127.0.0.1:{}\n",
        port(2)
    );
    let h = harness_or_skip!(None, &extra);
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    for (host, code) in [("hl-ok", "acme"), ("hl-sick", "acme"), ("hl-other", "beta")] {
        h.exec(&format!(
            "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, \
             wazuh_last_seen, wazuh_agent_version, wazuh_agent_status, customer_code, quarantined) \
             VALUES ('{host}{s}', '1', 'l', '{host}{s}', 'l', 0, UTC_TIMESTAMP(), '1', 'active', \
             '{code}{s}', 0)"
        ))
        .await;
    }
    let indexer = stand_in(4).await;
    Mock::given(method("GET"))
        .and(path("/*/_alias"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wazuh-alerts-a": {"aliases": {}}, "wazuh-alerts-b": {"aliases": {}},
            "wazuh-alerts-c": {"aliases": {}}
        })))
        .mount(&indexer)
        .await;
    for index in ["wazuh-alerts-a", "wazuh-alerts-b", "wazuh-alerts-c"] {
        let hit = index == "wazuh-alerts-b";
        Mock::given(method("POST"))
            .and(path(format!("/{index}/_search")))
            .and(body_string_contains(format!("hl-ok{s}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hits": {"hits": if hit { json!([{"_source": {"x": 1}}]) } else { json!([]) }}
            })))
            .mount(&indexer)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/{index}/_search")))
            .and(body_string_contains(format!("hl-sick{s}")))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": "boom"})))
            .mount(&indexer)
            .await;
    }
    let saved = point_connector(&h, "Wazuh-Indexer", &indexer.uri()).await;
    let logs = "/api/healthcheck/logs";

    let (st, _) = h
        .call(
            "POST",
            logs,
            Some(&portal),
            Some(json!({"agent_name": format!("hl-ok{s}")})),
        )
        .await;
    assert_eq!(st, 403);
    let (st, out) = h
        .call(
            "POST",
            logs,
            Some(&admin),
            Some(json!({"agent_name": "x", "timerange": "5x", "size": "a"})),
        )
        .await;
    assert_eq!(st, 422, "{out}");
    let (st, out) = h
        .call(
            "POST",
            logs,
            Some(&admin),
            Some(json!({"agent_name": "x", "timerange": ""})),
        )
        .await;
    assert_eq!((st.as_u16(), out), (500, json!("Internal Server Error")));
    // Another tenant's host: refused before the indexer is asked.
    let (st, _) = h
        .call(
            "POST",
            logs,
            Some(&analyst),
            Some(json!({"agent_name": format!("hl-other{s}")})),
        )
        .await;
    assert_eq!(st, 403);
    let (st, out) = h
        .call(
            "POST",
            logs,
            Some(&analyst),
            Some(json!({"agent_name": format!("hl-ok{s}"), "timerange": "15m", "size": 3})),
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(
        out,
        json!({"logs_summary": [], "healthy": true, "success": true,
               "message": "Host is healthy. At least one log was found within the specified time range of 15m"})
    );
    let searches: Vec<_> = indexer
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().ends_with("/_search"))
        .collect();
    // The first index with a hit ends the search.
    assert_eq!(
        searches
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>(),
        vec!["/wazuh-alerts-a/_search", "/wazuh-alerts-b/_search"]
    );
    assert_eq!(searches[0].url.query(), Some("size=3"));
    let body: Value = serde_json::from_slice(&searches[0].body).unwrap();
    assert_eq!(
        body["query"]["bool"]["must"][1],
        json!({"match": {"syslog_level": "INFO"}})
    );
    assert_eq!(
        body["query"]["bool"]["must"][2],
        json!({"match_phrase": {"agent_name": format!("hl-ok{s}")}})
    );
    assert_eq!(body["sort"], json!([{"timestamp_utc": {"order": "desc"}}]));
    // Failing searches are skipped: unhealthy.
    let (st, out) = h
        .call(
            "POST",
            logs,
            Some(&admin),
            Some(json!({"agent_name": format!("hl-sick{s}")})),
        )
        .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(out["healthy"], json!(false));
    assert_eq!(
        out["message"],
        json!("Host is unhealthy. No logs were found within the specified time range of 24h")
    );
    restore_connector(&h, "Wazuh-Indexer", saved).await;

    // The CarbonBlack test: Python's guard, then the job.
    const JOB: &str = "invoke_carbonblack_integration_collection";
    #[derive(sqlx::FromRow)]
    struct JobRow {
        job_id: String,
        last_success: Option<chrono::NaiveDateTime>,
        time_interval: i32,
        extra_data: Option<String>,
        enabled: bool,
        job_description: Option<String>,
    }
    let saved_jobs = sqlx::query_as::<_, JobRow>(
        "SELECT job_id, last_success, time_interval, extra_data, enabled, job_description \
         FROM scheduled_job_metadata WHERE job_id = ? ORDER BY id",
    )
    .bind(JOB)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    let set_job = |enabled: i32| {
        format!(
            "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, enabled) \
             VALUES ('{JOB}', NULL, 5, {enabled})"
        )
    };
    let stamped = || async {
        sqlx::query_scalar::<_, Option<chrono::NaiveDateTime>>(
            "SELECT last_success FROM scheduled_job_metadata WHERE job_id = ? ORDER BY id LIMIT 1",
        )
        .bind(JOB)
        .fetch_one(h.db.pool())
        .await
        .unwrap()
    };
    let ok_body = json!({"success": true, "message": "CarbonBlack provisioned successfully"});
    h.exec(&format!(
        "DELETE FROM scheduled_job_metadata WHERE job_id = '{JOB}'"
    ))
    .await;
    let (st, _) = h
        .call("GET", "/api/carbonblack/test", Some(&portal), None)
        .await;
    assert_eq!(st, 403);
    // Disabled: skipped, still a success.
    h.exec(&set_job(0)).await;
    let (st, out) = h
        .call("GET", "/api/carbonblack/test", Some(&analyst), None)
        .await;
    assert_eq!((st.as_u16(), out), (200, ok_body.clone()));
    assert_eq!(stamped().await, None);
    // Enabled: run and stamped.
    h.exec(&format!(
        "UPDATE scheduled_job_metadata SET enabled = 1 WHERE job_id = '{JOB}'"
    ))
    .await;
    let (st, out) = h
        .call("GET", "/api/carbonblack/test", Some(&admin), None)
        .await;
    assert_eq!((st.as_u16(), out), (200, ok_body.clone()));
    assert!(stamped().await.is_some());
    // Two rows: `one_or_none()` raises after the run.
    h.exec(&set_job(1)).await;
    let (st, _) = h
        .call("GET", "/api/carbonblack/test", Some(&admin), None)
        .await;
    assert_eq!(st, 500);
    h.exec(&format!(
        "DELETE FROM scheduled_job_metadata WHERE job_id = '{JOB}'"
    ))
    .await;
    for r in saved_jobs {
        sqlx::query(
            "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, \
             extra_data, enabled, job_description) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(r.job_id)
        .bind(r.last_success)
        .bind(r.time_interval)
        .bind(r.extra_data)
        .bind(r.enabled)
        .bind(r.job_description)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
    h.exec(&format!("DELETE FROM agents WHERE hostname LIKE 'hl-%{s}'"))
        .await;
    cleanup(&h).await;
}
