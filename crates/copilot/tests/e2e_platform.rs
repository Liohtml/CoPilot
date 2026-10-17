//! The platform-status modules against a real MySQL at the Alembic head:
//! `/api/logs` (`copilot-status`), `/api/license` (`copilot-license`, its
//! licence server a wiremock stand-in).
//!
//! `log_entries` and `license` are deployment-wide: each test puts the rows
//! it finds aside and restores them, so the suites can share one database.
//!
//! `COPILOT_TEST_DATABASE_URL=mysql://… cargo test -p copilot --test
//! e2e_platform -- --test-threads=1`

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod common;

use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{Harness, harness_env};

// --- shared helpers ---------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
struct SavedLog {
    id: i32,
    timestamp: chrono::NaiveDateTime,
    event_type: String,
    user_id: Option<i32>,
    route: Option<String>,
    method: Option<String>,
    status_code: i32,
    message: Option<String>,
    additional_info: Option<String>,
}

async fn save_logs(h: &Harness) -> Vec<SavedLog> {
    let saved = sqlx::query_as::<_, SavedLog>(
        "SELECT id, timestamp, event_type, user_id, route, method, status_code, message, \
         additional_info FROM log_entries ORDER BY id",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    h.exec("DELETE FROM log_entries").await;
    saved
}

async fn restore_logs(h: &Harness, saved: Vec<SavedLog>) {
    // Rows the handlers write after their answers land late: let them.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    h.exec("DELETE FROM log_entries").await;
    for chunk in saved.chunks(1000) {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(
            "INSERT INTO log_entries (id, timestamp, event_type, user_id, route, method, \
             status_code, message, additional_info) ",
        );
        qb.push_values(chunk, |mut b, r| {
            b.push_bind(r.id)
                .push_bind(r.timestamp)
                .push_bind(r.event_type.clone())
                .push_bind(r.user_id)
                .push_bind(r.route.clone())
                .push_bind(r.method.clone())
                .push_bind(r.status_code)
                .push_bind(r.message.clone())
                .push_bind(r.additional_info.clone());
        });
        qb.build().execute(h.db.pool()).await.unwrap();
    }
}

async fn user_id(h: &Harness, name: &str) -> i64 {
    h.scalar_i64(&format!(
        "SELECT id FROM `user` WHERE username = '{name}{}'",
        h.suffix
    ))
    .await
}

async fn cleanup_users(h: &Harness) {
    let s = &h.suffix;
    for sql in [
        format!(
            "DELETE FROM user_customer_access WHERE user_id IN \
             (SELECT id FROM `user` WHERE username LIKE '%{s}')"
        ),
        format!("DELETE FROM `user` WHERE username LIKE '%{s}'"),
        format!(
            "DELETE c FROM incident_management_alertcontext c JOIN incident_management_asset a \
             ON a.alert_context_id = c.id WHERE a.customer_code LIKE '%{s}'"
        ),
        format!("DELETE FROM incident_management_asset WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM incident_management_alert WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM customers WHERE customer_code LIKE '%{s}'"),
    ] {
        let _ = sqlx::query(&sql).execute(h.db.pool()).await;
    }
}

// --- /api/logs ----------------------------------------------------------------------------

#[tokio::test]
async fn the_error_log_reads_and_purges_like_python() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let saved = save_logs(&h).await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let admin_id = user_id(&h, "admin").await;

    // Empty: 404, and the handler logs it.
    let (st, body) = h.call("GET", "/api/logs", Some(&admin), None).await;
    assert_eq!(st, 404);
    assert_eq!(body, json!({"success": false, "message": "No logs found"}));
    // Admin only: `Security(get_current_user, scopes=["admin"])`'s 403.
    let (st, body) = h.call("GET", "/api/logs", Some(&analyst), None).await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        json!("Insufficient permissions. Required scope: admin")
    );

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    h.exec("DELETE FROM log_entries").await;

    for (event, uid, hours, message) in [
        ("Info", Some(admin_id), 2, "recent"),
        ("Error", None, 30, "yesterday"),
        ("Error", Some(admin_id), 240, "old"),
    ] {
        sqlx::query(
            "INSERT INTO log_entries (timestamp, event_type, user_id, route, method, status_code, \
             message) VALUES (UTC_TIMESTAMP() - INTERVAL ? HOUR, ?, ?, 'http://h/x', 'GET', 200, ?)",
        )
        .bind(hours)
        .bind(event)
        .bind(uid)
        .bind(message)
        .execute(h.db.pool())
        .await
        .unwrap();
    }

    let (st, body) = h.call("GET", "/api/logs", Some(&admin), None).await;
    assert_eq!(st, 200);
    let logs = body["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 3);
    let keys: Vec<&String> = logs[0].as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "event_type",
            "user_id",
            "route",
            "method",
            "status_code",
            "message",
            "additional_info",
            "timestamp"
        ]
    );
    assert_eq!(body["message"], json!("Logs fetched successfully"));

    let (st, body) = h
        .call("GET", &format!("/api/logs/{admin_id}"), Some(&admin), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["logs"].as_array().unwrap().len(), 2);
    // `1h` and `1w` both open one day; an int is days.
    for (range, want) in [
        (json!("1h"), 1),
        (json!("1w"), 1),
        (json!("2d"), 2),
        (json!(7), 2),
        (json!(" 7_0d"), 3),
    ] {
        let (st, body) = h
            .call(
                "POST",
                "/api/logs/timerange",
                Some(&admin),
                Some(json!({"time_range": range})),
            )
            .await;
        assert_eq!(st, 200, "{range}: {body}");
        assert_eq!(body["logs"].as_array().unwrap().len(), want, "{range}");
    }
    let (st, body) = h.call("POST", "/api/logs/Error", Some(&admin), None).await;
    assert_eq!(st, 200);
    assert_eq!(body["logs"].as_array().unwrap().len(), 2);
    let (st, body) = h
        .call("GET", "/api/logs/99999999999999999999", Some(&admin), None)
        .await;
    assert_eq!(st, 404);
    assert_eq!(
        body["message"],
        json!("No logs found for user ID: 99999999999999999999")
    );
    let (st, body) = h.call("GET", "/api/logs/abc", Some(&admin), None).await;
    assert_eq!(st, 422);
    assert_eq!(body["details"][0]["field"], json!("user_id"));

    let (st, body) = h
        .call(
            "POST",
            "/api/logs/timerange",
            Some(&admin),
            Some(json!({"time_range": "2w"})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(
        body,
        json!({"message": "Invalid time range. Use 'h' for hours, 'd' for days, and 'w' for weeks.",
               "details": [{"field": "time_range", "error_type": "value_error.time_range",
                            "message": "Invalid time range. Use 'h' for hours, 'd' for days, and 'w' for weeks."}]})
    );
    let (st, _) = h
        .call(
            "POST",
            "/api/logs/timerange",
            Some(&admin),
            Some(json!({"time_range": ""})),
        )
        .await;
    assert_eq!(st, 500, "value[-1] of an empty string is an IndexError");

    let (st, body) = h
        .call("POST", "/api/logs/Warning", Some(&admin), None)
        .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["details"][0]["message"],
        json!("Value is not a valid enumeration member.")
    );

    // Purge one day's rows, then everything.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let before = h.scalar_i64("SELECT COUNT(*) FROM log_entries").await;
    let (st, body) = h
        .call(
            "DELETE",
            "/api/logs/timerange",
            Some(&admin),
            Some(json!({"time_range": "1d"})),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"logs": [], "success": true, "message": "Logs purged successfully"})
    );
    // Everything inside the last day went, the error rows written meanwhile
    // included; the two older seeds stayed.
    assert!(before > 2);
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM log_entries WHERE message IN ('yesterday', 'old')")
            .await,
        2
    );
    assert_eq!(h.scalar_i64("SELECT COUNT(*) FROM log_entries").await, 2);
    let (st, _) = h.call("DELETE", "/api/logs", Some(&admin), None).await;
    assert_eq!(st, 200);
    assert_eq!(h.scalar_i64("SELECT COUNT(*) FROM log_entries").await, 0);

    restore_logs(&h, saved).await;
    cleanup_users(&h).await;
}

// --- /api/license -------------------------------------------------------------------------

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

fn licence_router(h: &Harness, upstream: &str) -> axum::Router {
    copilot_license::router(copilot_license::LicenseState {
        ctx: h.app.ctx.clone(),
        client: copilot_license::LicenseClient::new(
            format!("{upstream}/"),
            Some(copilot_core::config::Secret::new("e2e-api-key")),
        )
        .unwrap(),
    })
}

fn licence_object(key: &str) -> Value {
    json!({
        "productId": 1, "id": 7, "key": key, "created": "2026-01-02T03:04:05.120",
        "expires": "2027-01-02T03:04:05", "period": 365, "f1": true, "f2": false, "f3": false,
        "f4": false, "f5": false, "f6": false, "f7": false, "f8": false, "notes": "",
        "block": false, "globalId": 9,
        "customer": {"id": 3, "name": "E2E", "email": "e2e@example.com", "companyName": "E2E Co",
                     "created": "2025-06-01T00:00:00Z"},
        "activatedMachines": [], "trialActivation": false, "maxNoOfMachines": 0,
        "dataObjects": [{"name": "THREAT INTEL", "intValue": 1}, {"name": "AI", "intValue": 0}],
        "signDate": "2026-01-02T03:04:05+02:00"
    })
}

#[tokio::test]
async fn the_licence_routes_call_the_licence_server_like_python() {
    let mut h = harness_or_skip!(None);
    h.seed().await;
    let saved = save_licences(&h).await;
    let key = format!("E2E-{}", h.suffix);
    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key = '{key}'"
    ))
    .await;
    let upstream = MockServer::start().await;
    h.router = licence_router(&h, &upstream.uri());
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");

    let (st, body) = h.call("GET", "/get_license", Some(&analyst), None).await;
    assert_eq!(st, 404);
    assert_eq!(
        body["message"],
        json!("No license found. A license must be created first.")
    );
    let (st, _) = h.call("GET", "/get_license", Some(&portal), None).await;
    assert_eq!(st, 403);

    // `replace_license_in_db` without a licence verifies the key first.
    Mock::given(method("POST"))
        .and(path("/verify-license"))
        .and(header("x-api-key", "e2e-api-key"))
        .and(header("module-version", "1.0"))
        .and(body_json(json!({"license_key": key})))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data": {"license": licence_object(&key), "success": true, "message": "valid"}}),
        ))
        .mount(&upstream)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/replace_license_in_db",
            Some(&analyst),
            Some(json!({"license_key": key})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "License created successfully"})
    );
    let (st, body) = h.call("GET", "/get_license", Some(&analyst), None).await;
    assert_eq!(st, 200);
    assert_eq!(body["license_key"], json!(key));

    // Verification from the server caches every named data object for an hour.
    let (st, body) = h.call("GET", "/verify_license", Some(&analyst), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["license"]["created"],
        json!("2026-01-02T03:04:05.120000")
    );
    assert_eq!(
        body["license"]["signDate"],
        json!("2026-01-02T03:04:05+02:00")
    );
    assert_eq!(body["message"], json!("valid"));
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM license_cache WHERE license_key = '{key}'"
        ))
        .await,
        2
    );
    // … then answers from the cache.
    let (st, body) = h.call("GET", "/verify_license", Some(&analyst), None).await;
    assert_eq!(st, 200);
    assert_eq!(
        body["message"],
        json!("License verified successfully (from cache)")
    );
    let (st, body) = h
        .call(
            "GET",
            "/is_feature_enabled/THREAT%20INTEL",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"enabled": true, "success": true, "message": "Feature 'THREAT INTEL' is enabled"})
    );
    // A disabled feature: `IsFeatureEnabledResponse(status_code=400, …)`
    // misses two fields, and its ValidationError is the 400.
    let (st, body) = h
        .call("GET", "/is_feature_enabled/AI", Some(&analyst), None)
        .await;
    assert_eq!(st, 400);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("2 validation errors for IsFeatureEnabledResponse"),
        "{body}"
    );
    let (st, body) = h
        .call("GET", "/get_license_features", Some(&analyst), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["features"], json!(["THREAT INTEL"]));

    // The licence server's 5xx is a 502 naming its message.
    Mock::given(method("POST"))
        .and(path("/retrieve-docker-compose"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"message": "down"})))
        .mount(&upstream)
        .await;
    let (st, body) = h
        .call("POST", "/retrieve-docker-compose", Some(&analyst), None)
        .await;
    assert_eq!(st, 502);
    assert_eq!(body["message"], json!("License server error: down"));

    // Replacing an existing licence clears its cache.
    let (st, _) = h
        .call(
            "POST",
            "/replace_license_in_db",
            Some(&analyst),
            Some(json!({"license_key": format!("{key}-2")})),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM license_cache WHERE license_key = '{key}'"
        ))
        .await,
        0
    );

    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key LIKE '{key}%'"
    ))
    .await;
    restore_licences(&h, saved).await;
    cleanup_users(&h).await;
}
