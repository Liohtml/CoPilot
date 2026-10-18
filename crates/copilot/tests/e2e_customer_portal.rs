//! End-to-end tests of the Customer Portal port (`copilot-customer-portal`):
//! the global settings and their logo, the per-customer branding and what a
//! user resolves to (and its cache across two processes), the Overview and
//! its statement budget, the dashboard counters, the agents list and CSV,
//! `/me` — the production router against a real MySQL at the Alembic head.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13310/copilot \
//!   cargo test -p copilot --test e2e_customer_portal -- --test-threads=1
//! ```
//!
//! The global settings row is a singleton other suites read: the tests that
//! change it take it out first and put it back afterwards, even on failure.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use axum::body::Body;
use http::{HeaderMap, Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use copilot_db::Db;

#[macro_use]
mod common;
use common::*;

const P: &str = "/api/customer_portal";
/// The change-check interval both "processes" of the coherence test run with.
const CHECK: &str = "BRANDING_CACHE_CHECK_SECONDS=1\n";

/// A PNG-looking payload well over `GZipMiddleware`'s minimum (1000 bytes).
fn logo_bytes() -> Vec<u8> {
    let mut png = vec![
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, b'I', b'H', b'D', b'R',
    ];
    png.extend((0..1600u32).map(|i| u8::try_from(i % 251).unwrap()));
    png
}

fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

struct Raw {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn raw(h: &Harness, uri: &str, token: Option<&str>, headers: &[(&str, &str)]) -> Raw {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let resp = h
        .router
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 32 << 20)
        .await
        .unwrap()
        .to_vec();
    Raw {
        status,
        headers,
        body,
    }
}

fn header<'a>(r: &'a Raw, name: &str) -> &'a str {
    r.headers
        .get(name)
        .map(|v| v.to_str().unwrap())
        .unwrap_or("")
}

/// Take the global settings rows out (they are restored by [`restore`]).
async fn take_global(db: &Db) -> Vec<(i64, String)> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, JSON_OBJECT('id', id, 'title', title, 'logo_base64', logo_base64, \
         'logo_mime_type', logo_mime_type, 'brand_color', brand_color, 'updated_at', \
         DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s'), 'updated_by', updated_by) \
         FROM customer_portal_settings ORDER BY id",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    sqlx::query("DELETE FROM customer_portal_settings")
        .execute(db.pool())
        .await
        .unwrap();
    rows
}

async fn restore(db: &Db, rows: &[(i64, String)]) {
    sqlx::query("DELETE FROM customer_portal_settings")
        .execute(db.pool())
        .await
        .unwrap();
    for (_, row) in rows {
        sqlx::query(
            "INSERT INTO customer_portal_settings (id, title, logo_base64, logo_mime_type, \
             brand_color, updated_at, updated_by) SELECT j->>'$.id', j->>'$.title', \
             JSON_UNQUOTE(NULLIF(JSON_EXTRACT(j, '$.logo_base64'), CAST('null' AS JSON))), \
             JSON_UNQUOTE(NULLIF(JSON_EXTRACT(j, '$.logo_mime_type'), CAST('null' AS JSON))), \
             JSON_UNQUOTE(NULLIF(JSON_EXTRACT(j, '$.brand_color'), CAST('null' AS JSON))), \
             j->>'$.updated_at', \
             JSON_UNQUOTE(NULLIF(JSON_EXTRACT(j, '$.updated_by'), CAST('null' AS JSON))) \
             FROM (SELECT CAST(? AS JSON) AS j) AS t",
        )
        .bind(row)
        .execute(db.pool())
        .await
        .unwrap();
    }
}

/// The `Questions` the server counted (statements from every client).
async fn questions(db: &Db) -> i64 {
    let row: (String, String) = sqlx::query_as("SHOW GLOBAL STATUS LIKE 'Questions'")
        .persistent(false)
        .fetch_one(db.pool())
        .await
        .unwrap();
    row.1.parse().unwrap()
}

/// Statements one request costs: the fewest of three measurements, less
/// the probe's own.
async fn statements(h: &Harness, uri: &str, token: &str) -> i64 {
    let mut best = i64::MAX;
    for _ in 0..3 {
        let idle = {
            let a = questions(&h.db).await;
            questions(&h.db).await - a
        };
        let a = questions(&h.db).await;
        let (st, _) = h.call("GET", uri, Some(token), None).await;
        assert_eq!(st, 200);
        let used = questions(&h.db).await - a - idle;
        best = best.min(used);
    }
    best
}

async fn user_id(h: &Harness, name: &str) -> i64 {
    h.scalar_i64(&format!(
        "SELECT id FROM `user` WHERE username = '{name}{}'",
        h.suffix
    ))
    .await
}

/// Customers `acme`/`beta` (named), the harness users, a portal user of both
/// customers; alerts, cases, assets, agents and AI reports.
async fn seed(h: &Harness) {
    h.seed().await;
    let s = &h.suffix;
    h.exec(&format!(
        "UPDATE customers SET customer_name = CASE customer_code WHEN 'acme{s}' THEN 'Zulu Acme' \
         ELSE '  ' END WHERE customer_code IN ('acme{s}', 'beta{s}')"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO `user` (username, password, email, created_at, role_id) \
         VALUES ('both{s}', 'x', 'both@example.com', UTC_TIMESTAMP(), 4)"
    ))
    .await;
    for c in ["beta", "acme"] {
        h.exec(&format!(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) \
             SELECT id, '{c}{s}', UTC_TIMESTAMP() FROM `user` WHERE username = 'both{s}'"
        ))
        .await;
    }
    // acme: four more alerts (statuses), two cases, three agents, one AI report.
    let mut acme_alerts = Vec::new();
    for (i, status) in ["OPEN", "IN_PROGRESS", "CLOSED", "PENDING_CUSTOMER"]
        .iter()
        .enumerate()
    {
        let id = h
            .exec(&format!(
                "INSERT INTO incident_management_alert (alert_name, alert_description, status, \
                 alert_creation_time, customer_code, source, escalated) VALUES \
                 ('acme alert {i}', 'd{i}', '{status}', '2026-09-0{} 12:00:00.250', 'acme{s}', \
                 'office365', 0)",
                i + 1
            ))
            .await;
        acme_alerts.push(id);
    }
    let ctx = h
        .exec(
            "INSERT INTO incident_management_alertcontext (source, context) VALUES ('wazuh', '{}')",
        )
        .await;
    for name in ["host-b", "host-a"] {
        h.exec(&format!(
            "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, \
             customer_code, index_name, index_id) VALUES ({}, '{name}{s}', {ctx}, 'acme{s}', 'i', 'd')",
            acme_alerts[3]
        ))
        .await;
    }
    for (i, status) in ["OPEN", "CLOSED"].iter().enumerate() {
        let case = h
            .exec(&format!(
                "INSERT INTO incident_management_case (case_name, case_description, \
                 case_creation_time, case_status, assigned_to, customer_code, escalated) VALUES \
                 ('acme case {i}', 'cd', '2026-09-0{} 08:00:00', '{status}', 'analyst{s}', 'acme{s}', 0)",
                i + 1
            ))
            .await;
        for alert in &acme_alerts[..=i] {
            h.exec(&format!(
                "INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES ({case}, {alert})"
            ))
            .await;
        }
    }
    h.exec(&format!(
        "INSERT INTO incident_management_case (case_name, case_description, case_creation_time, \
         case_status, customer_code, escalated) VALUES ('beta case', 'cd', '2026-09-01 08:00:00', \
         'OPEN', 'beta{s}', 0)"
    ))
    .await;
    for (i, (status, critical, os, host)) in [
        ("active", 1, "Linux", "web-01"),
        ("disconnected", 0, "Windows", "Desk,\"7\""),
        ("active", 0, "linux", "db-02"),
        ("never_connected", 0, "", "ghost"),
    ]
    .iter()
    .enumerate()
    {
        let customer = if i == 3 { "beta" } else { "acme" };
        h.exec(&format!(
            "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, \
             wazuh_last_seen, wazuh_agent_version, wazuh_agent_status, customer_code, quarantined, \
             velociraptor_id_pinned) VALUES ('{s}{i}', '10.0.0.{i}', '{os}', '{}{s}', 'grp', {critical}, \
             '2026-10-15 08:00:0{i}', 'Wazuh v4.9.{i}', '{status}', '{customer}{s}', 0, 0)",
            host.replace('\'', "''")
        ))
        .await;
    }
    let job = format!("cp-job-{s}");
    h.exec(&format!(
        "INSERT INTO ai_analyst_job (id, alert_id, customer_code, status, triggered_by, created_at) \
         VALUES ('{job}', {}, 'acme{s}', 'completed', 'webhook', '2026-09-03 10:00:00')",
        acme_alerts[0]
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO ai_analyst_report (job_id, alert_id, customer_code, severity_assessment, \
         summary, created_at) VALUES ('{job}', {}, 'acme{s}', 'High', 'looks bad', \
         '2026-09-03 10:05:00')",
        acme_alerts[0]
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO customer_portal_ai_report_settings (customer_code, enabled, updated_at) \
         VALUES ('acme{s}', 1, UTC_TIMESTAMP())"
    ))
    .await;
}

async fn cleanup(h: &Harness) {
    let s = &h.suffix;
    for sql in [
        format!("DELETE FROM customer_portal_branding WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM customer_portal_ai_report_settings WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM ai_analyst_report WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM ai_analyst_job WHERE customer_code LIKE '%{s}'"),
        format!(
            "DELETE l FROM incident_management_casealertlink l JOIN incident_management_case c \
             ON c.id = l.case_id WHERE c.customer_code LIKE '%{s}'"
        ),
        format!("DELETE FROM incident_management_case WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM incident_management_asset WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM incident_management_alert WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM agents WHERE customer_code LIKE '%{s}'"),
        format!(
            "DELETE a FROM user_customer_access a JOIN `user` u ON u.id = a.user_id \
             WHERE u.username LIKE '%{s}'"
        ),
        format!(
            "DELETE l FROM log_entries l JOIN `user` u ON u.id = l.user_id \
             WHERE u.username LIKE '%{s}'"
        ),
        format!("DELETE FROM `user` WHERE username LIKE '%{s}'"),
        format!("DELETE FROM customers WHERE customer_code LIKE '%{s}'"),
    ] {
        h.exec(&sql).await;
    }
}

// ---------------------------------------------------------------------------
// Global settings and their logo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn global_settings_are_replaced_patched_and_served_with_their_logo() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let db = h.db.clone();
    let saved = take_global(&db).await;
    let outcome = tokio::spawn(global_settings_flow(h)).await;
    restore(&db, &saved).await;
    let h = outcome.unwrap();
    cleanup(&h).await;
}

async fn global_settings_flow(h: Harness) -> Harness {
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");

    // No row: the defaults, without writing one.
    let (st, body) = h.call("GET", &format!("{P}/settings"), None, None).await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"success": true, "message": "Portal settings retrieved successfully",
               "settings": {"id": 0, "title": "CoPilot", "logo_url": null, "logo_mime_type": null,
                            "brand_color": null, "updated_at": null}})
    );
    let (_, body) = h
        .call("GET", &format!("{P}/settings/global"), Some(&analyst), None)
        .await;
    assert_eq!(body["settings"]["id"], 0);
    let stamp = body["settings"]["updated_at"].as_str().unwrap();
    assert!(stamp.ends_with("+00:00") && stamp.len() >= 25, "{stamp}");
    let (st, _) = h
        .call("GET", &format!("{P}/settings/global"), Some(&portal), None)
        .await;
    assert_eq!(st, 403);
    let r = raw(&h, &format!("{P}/settings/logo"), None, &[]).await;
    assert_eq!(r.status, 404);
    assert_eq!(
        serde_json::from_slice::<Value>(&r.body).unwrap(),
        json!({"success": false, "message": "No portal logo configured"})
    );
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM customer_portal_settings")
            .await,
        0
    );

    // Guards and validation, in FastAPI's order.
    let (st, body) = h
        .call_raw(
            "POST",
            &format!("{P}/settings"),
            None,
            Some("application/json"),
            "{",
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["details"][0]["error_type"].clone()),
        (422, json!("json_invalid"))
    );
    let (st, body) = h
        .call(
            "POST",
            &format!("{P}/settings"),
            Some(&analyst),
            Some(json!({"brand_color": "red"})),
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        "Insufficient permissions. Required one of: admin"
    );
    let (st, body) = h
        .call(
            "POST",
            &format!("{P}/settings"),
            Some(&admin),
            Some(json!({"brand_color": "red"})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["message"],
        "brand_color: Expected a hex color like #RGB or #RRGGBB"
    );
    let (st, body) = h
        .call(
            "POST",
            &format!("{P}/settings"),
            Some(&admin),
            Some(json!({"logo_base64": "QQ=", "logo_mime_type": "application/pdf"})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["details"],
        json!([
            {"field": "logo_base64", "error_type": "value_error",
             "message": "logo_base64: Base64 data cannot be decoded"},
            {"field": "logo_mime_type", "error_type": "value_error",
             "message": "logo_mime_type: Unsupported MIME type. Allowed types are: image/png, image/jpeg, image/jpg, image/gif, image/svg+xml, image/webp"}
        ])
    );

    // Replace.
    let logo = logo_bytes();
    let (st, body) = h
        .call(
            "POST",
            &format!("{P}/settings"),
            Some(&admin),
            Some(json!({"title": "Acme SOC", "logo_base64": format!("data:image/png;base64,{}", b64(&logo)),
                        "logo_mime_type": "image/png", "brand_color": " #ABC "})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Portal settings updated successfully"})
        )
    );
    let admin_id = user_id(&h, "admin").await;
    let row: (String, Option<String>, Option<String>, Option<i64>, i64) = sqlx::query_as(
        "SELECT title, logo_mime_type, brand_color, updated_by, UNIX_TIMESTAMP(updated_at) \
         FROM customer_portal_settings",
    )
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        (&row.0, row.1.as_deref(), row.2.as_deref(), row.3),
        (
            &"Acme SOC".to_string(),
            Some("image/png"),
            Some("#abc"),
            Some(admin_id)
        )
    );
    let version = (row.4 * 1000).to_string();
    let (_, body) = h.call("GET", &format!("{P}/settings"), None, None).await;
    assert_eq!(
        body["settings"]["logo_url"],
        json!(format!("/customer_portal/settings/logo?v={version}"))
    );
    assert!(body["settings"].get("logo_base64").is_none());

    // The logo: bytes, validators, gzip as GZipMiddleware applies it.
    let r = raw(&h, &format!("{P}/settings/logo"), None, &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, logo);
    assert_eq!(header(&r, "etag"), format!("\"{version}\""));
    assert_eq!(header(&r, "cache-control"), "public, max-age=3600");
    assert_eq!(header(&r, "x-content-type-options"), "nosniff");
    assert_eq!(
        header(&r, "content-security-policy"),
        "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    );
    assert_eq!(header(&r, "content-type"), "image/png");
    assert_eq!(header(&r, "vary"), "Accept-Encoding");
    assert_eq!(header(&r, "content-length"), logo.len().to_string());
    let r = raw(
        &h,
        &format!("{P}/settings/logo"),
        None,
        &[("accept-encoding", "gzip")],
    )
    .await;
    assert_eq!(header(&r, "content-encoding"), "gzip");
    assert_eq!(&r.body[..2], &[0x1f, 0x8b]);
    let etag = format!("W/\"x\", \"{version}\"");
    let r = raw(
        &h,
        &format!("{P}/settings/logo"),
        None,
        &[("if-none-match", &etag)],
    )
    .await;
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    assert_eq!(header(&r, "cache-control"), "public, max-age=3600");
    assert_eq!(header(&r, "content-type"), "");

    // Patch: only what is sent; resets explicit.
    let (st, body) = h
        .call(
            "PATCH",
            &format!("{P}/settings"),
            Some(&admin),
            Some(json!({"title": null})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["message"],
        "title cannot be empty; to restore its default send reset: [\"title\"]"
    );
    assert_eq!(body["details"][0]["field"], "body");
    let (st, body) = h
        .call(
            "PATCH",
            &format!("{P}/settings"),
            Some(&admin),
            Some(json!({})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (422, json!("Nothing to update"))
    );
    let (st, _) = h
        .call(
            "PATCH",
            &format!("{P}/settings"),
            Some(&admin),
            Some(json!({"brand_color": "#123456", "reset": ["logo"]})),
        )
        .await;
    assert_eq!(st, 200);
    let (_, body) = h
        .call("GET", &format!("{P}/settings/global"), Some(&admin), None)
        .await;
    let settings = &body["settings"];
    assert_eq!(
        (
            &settings["title"],
            &settings["logo_base64"],
            &settings["logo_mime_type"],
            &settings["brand_color"]
        ),
        (
            &json!("Acme SOC"),
            &Value::Null,
            &Value::Null,
            &json!("#123456")
        )
    );
    let r = raw(&h, &format!("{P}/settings/logo"), None, &[]).await;
    assert_eq!(r.status, 404);

    // Replace with nothing: every default back.
    let (st, _) = h
        .call(
            "POST",
            &format!("{P}/settings"),
            Some(&admin),
            Some(json!({})),
        )
        .await;
    assert_eq!(st, 200);
    let (_, body) = h.call("GET", &format!("{P}/settings"), None, None).await;
    assert_eq!(body["settings"]["title"], "CoPilot");
    assert_eq!(body["settings"]["brand_color"], Value::Null);
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM customer_portal_settings")
            .await,
        1
    );
    h
}

// ---------------------------------------------------------------------------
// Per-customer branding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn branding_overrides_resolve_per_user_and_stay_in_the_tenant() {
    let h = harness_or_skip!(None, CHECK);
    seed(&h).await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let both = h.token(&format!("both{s}"), "customer_user");
    let (acme, beta) = (format!("acme{s}"), format!("beta{s}"));

    let (st, body) = h
        .call(
            "PUT",
            &format!("{P}/branding/nope{s}"),
            Some(&admin),
            Some(json!({"title": "x"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (404, json!(format!("Customer nope{s} not found")))
    );
    let (st, _) = h
        .call(
            "PUT",
            &format!("{P}/branding/{acme}"),
            Some(&analyst),
            Some(json!({})),
        )
        .await;
    assert_eq!(st, 403);
    // Starlette routes the decoded path: an encoded `/` is no route of the module.
    let (st, body) = h
        .call("GET", &format!("{P}/branding/{acme}%2Fx"), None, None)
        .await;
    assert_eq!((st.as_u16(), body), (404, json!({"detail": "Not Found"})));
    let (st, body) = h
        .call(
            "PUT",
            &format!("{P}/branding/{acme}"),
            Some(&admin),
            Some(
                json!({"enabled": "yes", "title": "  Acme Portal ", "logo_base64": "QQ==",
                        "brand_color": "#ABCDEF"}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["message"],
        "Customer branding override saved successfully"
    );
    let o = &body["override"];
    assert_eq!(
        (
            &o["customer_code"],
            &o["enabled"],
            &o["title"],
            &o["logo_base64"],
            &o["logo_mime_type"],
            &o["brand_color"]
        ),
        (
            &json!(acme),
            &json!(true),
            &json!("Acme Portal"),
            &json!("QQ=="),
            &Value::Null,
            &json!("#abcdef")
        )
    );
    assert_eq!(o["updated_by"], json!(user_id(&h, "admin").await));
    let effective = &body["effective"];
    assert_eq!(
        (
            &effective["title"],
            &effective["source"],
            &effective["customer_code"],
            &effective["logo_mime_type"]
        ),
        (
            &json!("Acme Portal"),
            &json!("custom"),
            &json!(acme),
            &json!("image/png")
        )
    );

    // Reads: the analyst only for their customer; the list narrowed to theirs.
    let (st, body) = h
        .call("GET", &format!("{P}/branding/{beta}"), Some(&analyst), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to customer {beta}")))
    );
    let (st, body) = h
        .call("GET", &format!("{P}/branding/{beta}"), Some(&admin), None)
        .await;
    assert_eq!(
        (
            st.as_u16(),
            body["override"].clone(),
            body["effective"]["source"].clone()
        ),
        (200, Value::Null, json!("global"))
    );
    h.call(
        "PUT",
        &format!("{P}/branding/{beta}"),
        Some(&admin),
        Some(json!({"enabled": false, "title": "Beta"})),
    )
    .await;
    let mine = |body: &Value| -> Vec<String> {
        body["overrides"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["customer_code"].as_str().unwrap().to_string())
            .filter(|c| c.ends_with(&s))
            .collect()
    };
    let (_, body) = h
        .call("GET", &format!("{P}/branding"), Some(&admin), None)
        .await;
    assert_eq!(mine(&body), [acme.clone(), beta.clone()]);
    let (_, body) = h
        .call("GET", &format!("{P}/branding"), Some(&analyst), None)
        .await;
    assert_eq!(body["overrides"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["overrides"][0]["customer_code"], json!(acme));
    assert_eq!(body["overrides"][0]["has_logo"], json!(true));

    // What each user resolves to.
    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/settings/effective"),
            Some(&portal),
            None,
        )
        .await;
    let settings = &body["settings"];
    assert_eq!(settings["source"], "custom");
    let version = settings["logo_url"]
        .as_str()
        .unwrap()
        .strip_prefix("/customer_portal/settings/effective/logo?v=")
        .unwrap()
        .to_string();
    assert_eq!(version.len(), 16);
    assert!(settings.get("logo_base64").is_none());
    for token in [&both, &admin] {
        let (_, body) = h
            .call("GET", &format!("{P}/settings/effective"), Some(token), None)
            .await;
        assert_eq!(body["settings"]["source"], "global", "{body}");
    }
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/settings/effective"),
            Some("garbage"),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (401, json!("Could not decode token: 401: Invalid token"))
    );

    let r = raw(
        &h,
        &format!("{P}/settings/effective/logo"),
        Some(&portal),
        &[],
    )
    .await;
    assert_eq!(
        (r.status, r.body.as_slice()),
        (StatusCode::OK, b"A".as_slice())
    );
    assert_eq!(header(&r, "etag"), format!("\"{version}\""));
    assert_eq!(header(&r, "cache-control"), "private, max-age=3600");
    assert!(
        !r.headers
            .get_all("vary")
            .iter()
            .any(|v| v.to_str().unwrap().contains("Accept-Encoding")),
        "under GZipMiddleware's minimum"
    );
    let tag = format!("\"{version}\"");
    let r = raw(
        &h,
        &format!("{P}/settings/effective/logo"),
        Some(&portal),
        &[("if-none-match", &tag)],
    )
    .await;
    assert_eq!(r.status, 304);
    let r = raw(
        &h,
        &format!("{P}/settings/effective/logo"),
        Some(&both),
        &[],
    )
    .await;
    assert_eq!(
        r.status.as_u16(),
        if global_has_logo(&h).await { 200 } else { 404 }
    );

    // Delete, twice.
    let (_, body) = h
        .call(
            "DELETE",
            &format!("{P}/branding/{acme}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        body["message"],
        "Customer branding override removed - inheriting global portal settings"
    );
    assert_eq!(
        (
            body["override"].clone(),
            body["effective"]["source"].clone()
        ),
        (Value::Null, json!("global"))
    );
    let (_, body) = h
        .call(
            "DELETE",
            &format!("{P}/branding/{acme}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        body["message"],
        "No branding override configured - already inheriting global portal settings"
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/settings/effective"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(body["settings"]["source"], "global");
    cleanup(&h).await;
}

async fn global_has_logo(h: &Harness) -> bool {
    h.scalar_i64(
        "SELECT COUNT(*) FROM (SELECT logo_base64 FROM customer_portal_settings LIMIT 1) AS g \
         WHERE COALESCE(TRIM(logo_base64), '') <> ''",
    )
    .await
        > 0
}

#[tokio::test]
async fn a_write_by_another_process_is_seen_within_the_check_interval() {
    let first = harness_or_skip!(None, CHECK);
    let second = harness_or_skip!(None, CHECK);
    seed(&first).await;
    let s = first.suffix.clone();
    let admin = first.token(&format!("admin{s}"), "admin");
    let portal = first.token(&format!("portal{s}"), "customer_user");
    let acme = format!("acme{s}");
    let settle = || tokio::time::sleep(Duration::from_millis(1300));

    let put = |t: &'static str| put_title(&first, &admin, &acme, t);
    put("One").await;
    assert_eq!(effective_title(&second, &portal).await, "One");
    put("Two").await;
    assert_eq!(
        effective_title(&first, &portal).await,
        "Two",
        "the writer forgets at once"
    );
    settle().await;
    assert_eq!(
        effective_title(&second, &portal).await,
        "Two",
        "the other process within the interval"
    );

    // Two writes in one second: the fingerprint carries the values, not only
    // the (rounded) save time.
    put("Three").await;
    settle().await;
    assert_eq!(effective_title(&second, &portal).await, "Three");
    put("Four").await;
    settle().await;
    assert_eq!(effective_title(&second, &portal).await, "Four");

    // An edit nobody announces (a MySQL shell) reaches both.
    first
        .exec(&format!(
            "UPDATE customer_portal_branding SET title = 'Direct' WHERE customer_code = '{acme}'"
        ))
        .await;
    settle().await;
    assert_eq!(effective_title(&first, &portal).await, "Direct");
    assert_eq!(effective_title(&second, &portal).await, "Direct");
    cleanup(&first).await;
}

async fn effective_title(h: &Harness, token: &str) -> String {
    let (_, body) = h
        .call("GET", &format!("{P}/settings/effective"), Some(token), None)
        .await;
    body["settings"]["title"].as_str().unwrap().to_string()
}

async fn put_title(h: &Harness, admin: &str, customer: &str, title: &str) {
    let (st, _) = h
        .call(
            "PUT",
            &format!("{P}/branding/{customer}"),
            Some(admin),
            Some(json!({"title": title})),
        )
        .await;
    assert_eq!(st, 200);
}

// ---------------------------------------------------------------------------
// Overview and dashboard counters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn overview_is_one_call_within_its_statement_budget() {
    let h = harness_or_skip!(None);
    seed(&h).await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let both = h.token(&format!("both{s}"), "customer_user");

    let (st, body) = h
        .call("GET", &format!("{P}/overview"), Some(&portal), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["message"], "Overview retrieved successfully");
    assert_eq!(
        body["alerts"]["counts"],
        json!({"total": 5, "open": 2, "in_progress": 1, "closed": 1, "pending_customer": 1})
    );
    let recent = body["alerts"]["recent"].as_array().unwrap();
    assert_eq!(recent.len(), 5);
    assert_eq!(recent[0]["alert_name"], "acme alert 3");
    assert_eq!(recent[0]["alert_creation_time"], "2026-09-04T12:00:00.000Z");
    assert_eq!(
        recent[0]["asset_names"],
        json!([format!("host-b{s}"), format!("host-a{s}")])
    );
    assert_eq!(recent[4]["asset_names"], json!(["dc01-acme"]));
    assert!(
        recent
            .iter()
            .all(|a| a["customer_code"] == json!(format!("acme{s}")))
    );
    assert_eq!(
        body["cases"]["counts"],
        json!({"total": 2, "open": 1, "in_progress": 0, "closed": 1, "pending_customer": 0})
    );
    assert_eq!(body["cases"]["recent"][0]["case_name"], "acme case 1");
    assert_eq!(body["cases"]["recent"][0]["alert_count"], 2);
    assert_eq!(body["cases"]["recent"][1]["alert_count"], 1);
    assert_eq!(
        body["agents"],
        json!({"total": 3, "online": 2, "offline": 1, "critical": 1, "error": null})
    );
    assert_eq!(body["ai"]["total_reports"], 1);
    assert_eq!(body["ai"]["severity_counts"], json!({"High": 1}));
    assert_eq!(body["ai"]["recent"][0]["summary"], "looks bad");

    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/overview?recent_limit=1&ai_limit=25"),
            Some(&both),
            None,
        )
        .await;
    assert_eq!(body["alerts"]["counts"]["total"], 6);
    assert_eq!(body["alerts"]["recent"].as_array().unwrap().len(), 1);
    assert_eq!(body["cases"]["counts"]["total"], 3);
    assert_eq!(body["agents"]["total"], 4);
    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/overview?customer_codes=beta{s}"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(
        body["alerts"]["counts"]["total"], 0,
        "a customer not theirs narrows to nothing"
    );
    assert_eq!(
        body["agents"],
        json!({"total": 0, "online": 0, "offline": 0, "critical": 0, "error": null})
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/overview?customer_codes=beta{s}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(body["alerts"]["counts"]["total"], 1);
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/overview?recent_limit=0&ai_limit=26"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(st, 422);
    let fields: Vec<&str> = body["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, ["recent_limit", "ai_limit"]);
    let (st, _) = h
        .call(
            "GET",
            &format!("{P}/overview?recent_limit=2.0"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(st, 200, "Pydantic reads 2.0 as 2");

    // Python's budget (`customer_portal_overview_e2e.py`): 12 statements.
    let used = statements(&h, &format!("{P}/overview"), &portal).await;
    assert!(used <= 12, "{used} statements");
    let used_analyst = statements(&h, &format!("{P}/overview"), &analyst).await;
    assert!(used_analyst <= 12, "{used_analyst} statements");
    assert!(
        used >= 8,
        "{used}: the probe must see the request's statements"
    );
    eprintln!("overview statements: portal user {used}, analyst {used_analyst}");

    // The counters agree with the Overview.
    let (_, body) = h
        .call("GET", &format!("{P}/dashboard/stats"), Some(&portal), None)
        .await;
    assert_eq!(
        body,
        json!({"total_alerts": 5, "total_cases": 2, "total_agents": 3, "success": true,
               "message": "Dashboard stats retrieved successfully"})
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/dashboard/alert-stats"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(
        body,
        json!({"total": 5, "open": 2, "in_progress": 1, "closed": 1, "pending_customer": 1,
               "success": true, "message": "Dashboard alert stats retrieved successfully"})
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/dashboard/case-stats?customer_codes=acme{s}"),
            Some(&both),
            None,
        )
        .await;
    assert_eq!(body["total"], 2);
    assert_eq!(
        body["message"],
        "Dashboard case stats retrieved successfully"
    );
    let (st, body) = h
        .call("GET", &format!("{P}/dashboard/stats"), None, None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (401, json!("Not authenticated"))
    );
    cleanup(&h).await;
}

// ---------------------------------------------------------------------------
// Agents, the CSV, /me
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agents_are_paged_filtered_and_exported_in_the_tenant() {
    let h = harness_or_skip!(None);
    seed(&h).await;
    let s = h.suffix.clone();
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let admin = h.token(&format!("admin{s}"), "admin");
    let responder = h.token(&format!("responder{s}"), "responder");

    let (st, body) = h
        .call("GET", &format!("{P}/agents"), Some(&portal), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["total"], 3);
    assert_eq!(body["message"], "3 agents found");
    assert_eq!(
        body["stats"],
        json!({"total": 3, "active": 2, "critical": 1, "offline": 1})
    );
    assert_eq!(body["statuses"], json!(["active", "disconnected"]));
    let os: Vec<String> = body["os_list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_str().unwrap().to_lowercase())
        .collect();
    assert_eq!(
        os,
        ["linux", "windows"],
        "DISTINCT under the column's collation"
    );
    let first = &body["agents"][0];
    let keys: Vec<&String> = first.as_object().unwrap().keys().collect();
    assert_eq!(keys[0], "id");
    assert_eq!(first["wazuh_last_seen"], "2026-10-15T08:00:00");

    let page = |q: &str| format!("{P}/agents?{q}");
    let (_, body) = h
        .call("GET", &page("page=2&page_size=2"), Some(&portal), None)
        .await;
    assert_eq!(body["agents"].as_array().unwrap().len(), 1);
    assert_eq!(body["total"], 3);
    let (_, body) = h
        .call("GET", &page("search=WEB"), Some(&portal), None)
        .await;
    assert_eq!(body["total"], 1);
    let (_, body) = h
        .call("GET", &page("critical=TRUE&os=LINUX"), Some(&portal), None)
        .await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["stats"]["total"], 3, "the cards ignore the filters");
    let (_, body) = h
        .call(
            "GET",
            &page(&format!("search=ghost{s}")),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(body["total"], 0, "never another tenant's");
    let (_, body) = h
        .call(
            "GET",
            &page(&format!("customer_codes[]=beta{s}")),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(body["total"], 1);
    let (_, body) = h
        .call(
            "GET",
            &page(&format!("customer_code=beta{s}")),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(body["total"], 1);
    let (st, body) = h
        .call(
            "GET",
            &page("page=0&page_size=101&critical=%20true"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(st, 422);
    let fields: Vec<&str> = body["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap())
        .collect();
    assert_eq!(
        fields,
        ["critical", "page", "page_size"],
        "the dependency's error first"
    );
    let (st, body) = h
        .call(
            "GET",
            &page(&format!("page={}", "9".repeat(30))),
            Some(&portal),
            None,
        )
        .await;
    // An OFFSET MySQL refuses was Python's bare 500; here the page past the
    // end is empty (RUST_MIGRATION.md §4).
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["agents"], json!([]));
    let (st, _) = h.call("GET", &page(""), Some(&responder), None).await;
    assert_eq!(st, 200, "a responder carries the analyst scope");

    let r = raw(&h, &format!("{P}/agents/export"), Some(&portal), &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(header(&r, "content-type"), "text/csv; charset=utf-8");
    let disposition = header(&r, "content-disposition");
    assert!(
        disposition.starts_with("attachment; filename=\"assets-export-")
            && disposition.ends_with(".csv\""),
        "{disposition}"
    );
    let text = String::from_utf8(r.body).unwrap();
    let lines: Vec<&str> = text.split("\r\n").collect();
    assert_eq!(
        lines[0],
        "Hostname,Agent ID,IP Address,Operating System,Status,Last Seen,Critical Asset,Agent Version,Customer Code"
    );
    assert_eq!(
        lines[1],
        format!(
            "web-01{s},{s}0,10.0.0.0,Linux,active,2026-10-15T08:00:00,Yes,Wazuh v4.9.0,acme{s}"
        )
    );
    assert_eq!(
        lines[2],
        format!(
            "\"Desk,\"\"7\"\"{s}\",{s}1,10.0.0.1,Windows,disconnected,2026-10-15T08:00:01,No,Wazuh v4.9.1,acme{s}"
        )
    );
    assert_eq!(lines.len(), 5, "three agents and the final line break");
    let r = raw(
        &h,
        &format!("{P}/agents/export?status=active"),
        Some(&portal),
        &[],
    )
    .await;
    assert_eq!(
        String::from_utf8(r.body).unwrap().matches("\r\n").count(),
        3
    );
    cleanup(&h).await;
}

#[tokio::test]
async fn me_lists_the_callers_customers_by_name_read_live() {
    let h = harness_or_skip!(None);
    seed(&h).await;
    let s = h.suffix.clone();
    let both = h.token(&format!("both{s}"), "customer_user");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let (st, body) = h.call("GET", &format!("{P}/me"), Some(&both), None).await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"success": true, "message": "Profile retrieved successfully",
        "username": format!("both{s}"), "role": "customer_user",
        "customers": [
            {"customer_code": format!("beta{s}"), "customer_name": format!("beta{s}")},
            {"customer_code": format!("acme{s}"), "customer_name": "Zulu Acme"}
        ]})
    );
    h.exec(&format!(
        "DELETE a FROM user_customer_access a JOIN `user` u ON u.id = a.user_id \
         WHERE u.username = 'both{s}' AND a.customer_code = 'beta{s}'"
    ))
    .await;
    let (_, body) = h.call("GET", &format!("{P}/me"), Some(&both), None).await;
    assert_eq!(
        body["customers"].as_array().unwrap().len(),
        1,
        "read live, not from the token"
    );
    let (st, body) = h
        .call("GET", &format!("{P}/me"), Some(&analyst), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            403,
            json!("Insufficient permissions. Required one of: customer_user")
        )
    );
    // A role id `RoleEnum` does not know was Python's ValueError, the 500;
    // here the user is refused (RUST_MIGRATION.md §4).
    h.exec(&format!(
        "UPDATE `user` SET role_id = NULL WHERE username = 'both{s}'"
    ))
    .await;
    let (st, body) = h.call("GET", &format!("{P}/me"), Some(&both), None).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            403,
            json!(format!("Access denied - user both{s} has no role"))
        )
    );
    cleanup(&h).await;
}
