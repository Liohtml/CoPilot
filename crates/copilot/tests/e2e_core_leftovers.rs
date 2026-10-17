//! The core leftovers against a real MySQL at the Alembic head: the customer
//! writes (`copilot-customers`, the licence server a wiremock stand-in).
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
