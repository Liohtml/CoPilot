//! End-to-end tests of the report routes (`copilot-reports`): the case DOCX
//! and PDF reports, the customer reports' background generation and the SOC
//! operations report, through the production router on a real MySQL, MinIO
//! replaced by a wiremock stand-in.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13307/copilot \
//!   cargo test -p copilot --test e2e_reports -- --test-threads=1
//! ```
//!
//! The PDFs need `wkhtmltopdf` where `pdfkit` looks for it; without it the
//! same requests are checked for the failure they then are. Python's side of
//! these requests is `rust_parity_reports_e2e.py`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const LOCATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>";
const BUNDLED_DOCX: &[u8] =
    include_bytes!("../../../backend/app/incidents/templates/case_report_jinja_template.docx");
const DOCX_TYPE: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const BUNDLED_HTML: &[u8] =
    include_bytes!("../../../backend/app/incidents/templates/case_report_jinja_template.html");

/// Whether the suite runs at all; checked before the stand-in binds its
/// port, so that `cargo test --workspace` never races for one.
fn configured() -> bool {
    std::env::var("COPILOT_TEST_DATABASE_URL").is_ok()
}

/// `REPORTS_E2E_S3_PORT` (6304 by default).
fn s3_port() -> u16 {
    std::env::var("REPORTS_E2E_S3_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6304)
}

/// A MinIO stand-in on its port (retried while the previous test's server
/// lets it go): the two templates, and a report bucket that takes uploads.
async fn minio() -> MockServer {
    let mut tries = 0;
    let listener = loop {
        match std::net::TcpListener::bind(("127.0.0.1", s3_port())) {
            Ok(l) => break l,
            Err(_) if tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("cannot bind the MinIO stand-in on {}: {e}", s3_port()),
        }
    };
    let server = MockServer::builder().listener(listener).start().await;
    for bucket in [
        "copilot-case-report-templates",
        "incident-management-reports",
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/{bucket}")))
            .and(query_param("location", ""))
            .respond_with(ResponseTemplate::new(200).set_body_raw(LOCATION, "application/xml"))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path(format!("/{bucket}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
    }
    for (key, data, ct) in [
        ("t.docx", BUNDLED_DOCX, "application/octet-stream"),
        ("t.html", BUNDLED_HTML, "text/html"),
        ("bad.html", b"<p>caf\xe9</p>".as_slice(), "text/html"),
    ] {
        Mock::given(method("HEAD"))
            .and(path(format!("/copilot-case-report-templates/{key}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"abc\"")
                    .insert_header("content-type", ct)
                    .insert_header("content-length", data.len().to_string().as_str()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/copilot-case-report-templates/{key}")))
            .respond_with(ResponseTemplate::new(200).set_body_raw(data, ct))
            .mount(&server)
            .await;
    }
    Mock::given(method("HEAD"))
        .and(path("/copilot-case-report-templates/missing.docx"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    // The listing `download_data_store` logs before its 404.
    Mock::given(method("GET"))
        .and(path("/copilot-case-report-templates"))
        .and(query_param("list-type", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>copilot-case-report-templates</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
             <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>",
            "application/xml",
        ))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"def\""))
        .mount(&server)
        .await;
    server
}

fn minio_env(s3: &MockServer) -> String {
    format!(
        "COPILOT_MINIO_ENDPOINT={}\nMINIO_ROOT_USER=e2e-minio\nMINIO_ROOT_PASSWORD=e2e-minio-secret\n",
        s3.address()
    )
}

async fn raw(
    h: &Harness,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, http::HeaderMap, Vec<u8>) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&v).unwrap()))
            .unwrap(),
        None => {
            b = b.header("accept-encoding", "identity");
            b.body(Body::empty()).unwrap()
        }
    };
    let resp = h.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 << 20)
        .await
        .unwrap();
    (status, headers, bytes.to_vec())
}

fn have_wkhtmltopdf() -> bool {
    copilot_reports::pdfkit::find_binary().is_some()
}

/// A case of acme's linking its alert, with a comment; and one of beta's.
async fn seed_cases(h: &Harness, acme_alert: i64) -> (i64, i64) {
    let s = &h.suffix;
    let acme = h
        .exec(&format!(
            "INSERT INTO incident_management_case (case_name, case_description, case_creation_time, \
             case_status, customer_code, notification_invoked_number, escalated) VALUES \
             ('[INC] Report case {s}', 'Line one\nLine two', '2026-02-03 04:05:06', 'OPEN', 'acme{s}', 0, 0)"
        ))
        .await;
    h.exec(&format!(
        "INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES ({acme}, {acme_alert})"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO incident_management_case_comment (case_id, comment, user_name, created_at) \
         VALUES ({acme}, 'closing note', 'admin', '2026-02-04 00:00:00')"
    ))
    .await;
    let beta = h
        .exec(&format!(
            "INSERT INTO incident_management_case (case_name, case_description, case_creation_time, \
             case_status, customer_code, notification_invoked_number, escalated) VALUES \
             ('Beta case {s}', 'd', '2026-02-03 04:05:06', 'OPEN', 'beta{s}', 0, 0)"
        ))
        .await;
    (acme, beta)
}

async fn cleanup(h: &Harness, cases: &[i64]) {
    let s = &h.suffix;
    for c in cases {
        for stmt in [
            format!("DELETE FROM incident_management_case_comment WHERE case_id = {c}"),
            format!("DELETE FROM incident_management_casealertlink WHERE case_id = {c}"),
            format!("DELETE FROM soc_sla_case_tracking WHERE case_id = {c}"),
            format!("DELETE FROM incident_management_case WHERE id = {c}"),
        ] {
            h.exec(&stmt).await;
        }
    }
    for stmt in [
        format!(
            "DELETE FROM incident_management_customer_reports WHERE customer_code IN ('acme{s}', 'beta{s}')"
        ),
        format!(
            "DELETE FROM soc_sla_alert_tracking WHERE alert_id IN (SELECT id FROM incident_management_alert WHERE customer_code IN ('acme{s}', 'beta{s}'))"
        ),
        format!(
            "DELETE FROM incident_management_asset WHERE customer_code IN ('acme{s}', 'beta{s}')"
        ),
        format!(
            "DELETE FROM incident_management_alert WHERE customer_code IN ('acme{s}', 'beta{s}')"
        ),
        format!(
            "DELETE FROM user_customer_access WHERE user_id IN (SELECT id FROM `user` WHERE username LIKE '%{s}')"
        ),
        format!(
            "DELETE FROM log_entries WHERE user_id IN (SELECT id FROM `user` WHERE username LIKE '%{s}')"
        ),
        format!("DELETE FROM `user` WHERE username LIKE '%{s}'"),
        format!("DELETE FROM customers WHERE customer_code IN ('acme{s}', 'beta{s}')"),
    ] {
        h.exec(&stmt).await;
    }
}

#[tokio::test]
async fn case_reports_render_docx_and_pdf() {
    if !configured() {
        return;
    }
    let s3 = minio().await;
    let h = harness_or_skip!(None, &minio_env(&s3));
    let (acme_alert, _) = h.seed().await;
    let (acme, beta) = seed_cases(&h, acme_alert).await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let docx = "/api/incidents/report/generate-report-docx";
    let pdf = "/api/incidents/report/generate-report-pdf";

    // DOCX: the bundled template, rendered.
    let (st, headers, body) = raw(
        &h,
        "POST",
        docx,
        &admin,
        Some(json!({"case_id": acme, "template_name": "t.docx", "file_name": "report"})),
    )
    .await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        headers["content-disposition"],
        "attachment; filename=\"report.docx\""
    );
    let archive = copilot_docx::zip::Archive::open(&body).unwrap();
    let document = String::from_utf8(archive.read("word/document.xml").unwrap().unwrap()).unwrap();
    assert!(document.contains(&format!("[INC] Report case {}", h.suffix)));
    assert!(document.contains("Mimikatz acme"));
    assert!(!document.contains("{{"));

    // The checks before the rendering.
    let (st, body) = h
        .call(
            "POST",
            docx,
            Some(&admin),
            Some(json!({"case_id": i64::from(i32::MAX), "template_name": "t.docx"})),
        )
        .await;
    assert_eq!(
        (st, body["message"].clone()),
        (StatusCode::NOT_FOUND, json!("No cases found"))
    );
    let (st, body) = h
        .call(
            "POST",
            docx,
            Some(&analyst),
            Some(json!({"case_id": beta, "template_name": "t.docx"})),
        )
        .await;
    assert_eq!(st, 403, "{body}");
    assert_eq!(
        body["message"],
        format!("Access denied to case {beta} - insufficient customer permissions")
    );
    let (st, _) = h
        .call(
            "POST",
            docx,
            Some(&admin),
            Some(json!({"case_id": "x", "file_name": 5})),
        )
        .await;
    assert_eq!(st, 500);
    let (st, body) = h
        .call("POST", docx, Some(&admin), Some(json!({"case_id": "x"})))
        .await;
    assert_eq!(st, 422, "{body}");
    let (st, body) = h
        .call(
            "POST",
            docx,
            Some(&admin),
            Some(json!({"case_id": acme, "template_name": "missing.docx"})),
        )
        .await;
    assert_eq!(st, 404, "{body}");

    // PDF: through wkhtmltopdf (or its absence).
    let (st, headers, body) = raw(
        &h,
        "POST",
        pdf,
        &admin,
        Some(json!({"case_id": acme, "template_name": "t.html"})),
    )
    .await;
    if have_wkhtmltopdf() {
        assert_eq!(st, 200);
        assert!(body.starts_with(b"%PDF-"));
        assert_eq!(headers["content-type"], "application/pdf");
        assert_eq!(
            headers["content-disposition"],
            "attachment; filename=\"case_report.pdf\""
        );
    } else {
        assert_eq!(st, 500);
    }
    let (st, body) = h
        .call(
            "POST",
            pdf,
            Some(&admin),
            Some(json!({"case_id": acme, "template_name": "bad.html"})),
        )
        .await;
    assert_eq!(st, 400, "{body}");
    assert_eq!(
        body["message"],
        "'utf-8' codec can't decode byte 0xe9 in position 6: invalid continuation byte"
    );
    cleanup(&h, &[acme, beta]).await;
}

#[tokio::test]
async fn customer_reports_generate_in_the_background() {
    if !configured() {
        return;
    }
    let s3 = minio().await;
    let h = harness_or_skip!(None, &minio_env(&s3));
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let path = "/api/incidents/customer_reports/generate/background";
    let window = json!({
        "customer_code": format!("acme{s}"),
        "date_from": "2020-01-01T00:00:00",
        "date_to": "2100-01-01T00:00:00",
    });

    let (st, body) = h
        .call(
            "POST",
            path,
            Some(&admin),
            Some(json!({"customer_code": format!("acme{s}"), "date_from": "2026-02-01T00:00:00", "date_to": "2026-01-01T00:00:00"})),
        )
        .await;
    assert_eq!(st, 422, "{body}");
    assert_eq!(body["message"], "date_from must be earlier than date_to");
    let mut beta = window.clone();
    beta["customer_code"] = json!(format!("beta{s}"));
    let (st, body) = h.call("POST", path, Some(&analyst), Some(beta)).await;
    assert_eq!(st, 403, "{body}");
    assert_eq!(
        body["message"],
        format!("Access denied to customer beta{s}")
    );
    let mut nobody = window.clone();
    nobody["customer_code"] = json!(format!("nope{s}"));
    let (st, body) = h.call("POST", path, Some(&admin), Some(nobody)).await;
    assert_eq!(st, 404, "{body}");
    assert_eq!(body["message"], format!("Customer nope{s} not found"));

    for (token, extra) in [
        (
            &admin,
            json!({"report_template": "full", "report_name": "q1"}),
        ),
        (
            &analyst,
            json!({"report_template": "analytics", "include_sla": true, "brand_theme": "socfortress"}),
        ),
        (
            &portal,
            json!({"report_template": "executive", "include_sla": true}),
        ),
    ] {
        let mut req = window.clone();
        for (k, v) in extra.as_object().unwrap() {
            req[k] = v.clone();
        }
        let (st, body) = h.call("POST", path, Some(token), Some(req)).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body["status"], "processing");
        let id = body["report_id"].as_i64().unwrap();
        assert_eq!(
            body["download_url"],
            format!("/api/v1/incidents/customer_reports/{id}/download")
        );
        let mut status = String::new();
        for _ in 0..600 {
            status = sqlx::query_scalar::<_, String>(
                "SELECT status FROM incident_management_customer_reports WHERE id = ?",
            )
            .bind(id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
            if status != "processing" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let (error, filters, visible, alerts): (Option<String>, String, bool, i64) =
            sqlx::query_as(
                "SELECT error_message, filters_json, visible_to_customer, total_alerts \
             FROM incident_management_customer_reports WHERE id = ?",
            )
            .bind(id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
        if have_wkhtmltopdf() {
            assert_eq!(status, "completed", "{error:?}");
            assert_eq!(alerts, 1);
        } else {
            assert_eq!(status, "failed");
            assert!(
                error
                    .unwrap()
                    .starts_with("Failed to convert HTML to PDF: ")
            );
        }
        let filters: Value = serde_json::from_str(&filters).unwrap();
        // A customer user never publishes the SLA section, and always sees the report.
        if std::ptr::eq(token, &portal) {
            assert_eq!(filters["include_sla"], false);
            assert!(visible);
        }
    }
    cleanup(&h, &[]).await;
}

#[tokio::test]
async fn soc_report_is_a_pdf() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let base = "/api/soc_management/report";
    let (st, body) = h.call("GET", base, Some(&admin), None).await;
    assert_eq!(st, 422, "{body}");
    let (st, body) = h
        .call(
            "GET",
            &format!("{base}?date_from=2026-03-01T00:00:00&date_to=2026-02-01T00:00:00"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 400, "{body}");
    let (st, headers, body) = raw(
        &h,
        "GET",
        &format!(
            "{base}?date_from=2026-01-01T00:00:00&date_to=2026-04-01T00:00:00&customer_codes=acme{s}"
        ),
        &admin,
        None,
    )
    .await;
    if have_wkhtmltopdf() {
        assert_eq!(st, 200);
        assert!(body.starts_with(b"%PDF-"));
        assert_eq!(
            headers["content-disposition"],
            "attachment; filename=\"soc_report_20260101_20260401.pdf\""
        );
        assert_eq!(headers["cache-control"], "no-store");
    } else {
        assert_eq!(st, 500);
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "Failed to generate the SOC report");
    }
    cleanup(&h, &[]).await;
}

// --- The Grafana panel report ---------------------------------------------------------------------

const LOGIN_PAGE: &str = r#"<!doctype html><html><head><title>Grafana</title></head>
<body class="login-page"><form onsubmit="return false">
<input name="user"><input name="password" type="password">
<button data-testid="data-testid Login button" type="submit" id="b">Log in</button></form>
<script>
fetch('/api/live/hold').catch(() => {});
document.getElementById('b').addEventListener('click', async () => {
  const body = JSON.stringify({user: document.querySelector('input[name="user"]').value,
                               password: document.querySelector('input[name="password"]').value});
  const r = await fetch('/login', {method: 'POST', headers: {'content-type': 'application/json'}, body});
  if (r.ok) { window.location.href = '/'; }
});
</script></body></html>"#;
const HOME_PAGE: &str =
    r#"<!doctype html><html><body class="app-grafana"><p>home</p></body></html>"#;
const SOLO_PAGE: &str = r#"<!doctype html><html><body class="app-grafana" style="margin:0">
<div style="height:100vh;background:#36c"></div></body></html>"#;

/// `REPORTS_E2E_GRAFANA_PORT` (6305 by default).
fn grafana_port() -> u16 {
    std::env::var("REPORTS_E2E_GRAFANA_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6305)
}

/// Grafana as the browser meets it: the login page (holding one request
/// for a while, so the page is not idle before the click), the login —
/// accepted, or refused with a 401 —, `/` and a `d-solo` page.
async fn grafana(server: &MockServer, refuse: bool) {
    server.reset().await;
    let html = |body: &str| {
        ResponseTemplate::new(200)
            .set_body_raw(body.as_bytes().to_vec(), "text/html; charset=UTF-8")
    };
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(html(LOGIN_PAGE))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/live/hold"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("{}", "application/json")
                .set_delay(std::time::Duration::from_millis(1500)),
        )
        .mount(server)
        .await;
    let login = if refuse {
        ResponseTemplate::new(401).set_body_raw("{\"message\":\"Invalid\"}", "application/json")
    } else {
        ResponseTemplate::new(200)
            .set_body_raw("{\"message\":\"Logged in\"}", "application/json")
            .insert_header("set-cookie", "grafana_session=e2e; Path=/")
    };
    Mock::given(method("POST"))
        .and(path("/login"))
        .respond_with(login)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(html(HOME_PAGE))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex("^/d-solo/"))
        .respond_with(html(SOLO_PAGE))
        .mount(server)
        .await;
}

async fn grafana_server() -> MockServer {
    let mut tries = 0;
    let listener = loop {
        match std::net::TcpListener::bind(("127.0.0.1", grafana_port())) {
            Ok(l) => break l,
            Err(_) if tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!(
                "cannot bind the Grafana stand-in on {}: {e}",
                grafana_port()
            ),
        }
    };
    MockServer::builder().listener(listener).start().await
}

type LicenceRow = (i64, String, String, String, String);

/// The deployment's licence and Grafana rows put aside, the test's own in
/// their place (`REPORTING` cached as enabled or not).
async fn grafana_seed(h: &Harness, url: &str, key: &str, enabled: bool) -> Vec<LicenceRow> {
    let saved = sqlx::query_as::<_, LicenceRow>(
        "SELECT id, license_key, customer_name, customer_email, company_name FROM license",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    h.exec("DELETE FROM license").await;
    h.exec(&format!(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) \
         VALUES ('{key}', 'e2e', 'e2e@example.com', 'e2e')"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO license_cache (license_key, feature_name, is_enabled, cached_at, expires_at, \
         license_data) VALUES ('{key}', 'REPORTING', {}, UTC_TIMESTAMP(), \
         UTC_TIMESTAMP() + INTERVAL 1 HOUR, '{{}}')",
        i32::from(enabled)
    ))
    .await;
    h.exec(&format!(
        "UPDATE connectors SET connector_name = 'Grafana-e2e-{}' WHERE connector_name = 'Grafana'",
        h.suffix
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, \
         connector_last_updated, connector_username, connector_password, connector_api_key, \
         connector_description, connector_supports, connector_configured, connector_verified, \
         connector_accepts_host_only, connector_accepts_api_key, \
         connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         ('Grafana', '3', '{url}', UTC_TIMESTAMP(), 'admin', 'secret', NULL, 'e2e', 'e2e', 1, 1, \
         0, 0, 1, 0, 0, NULL, 1)"
    ))
    .await;
    saved
}

async fn grafana_restore(h: &Harness, key: &str, saved: Vec<LicenceRow>) {
    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key = '{key}'"
    ))
    .await;
    h.exec(&format!("DELETE FROM license WHERE license_key = '{key}'"))
        .await;
    for (id, k, name, email, company) in saved {
        sqlx::query(
            "INSERT INTO license (id, license_key, customer_name, customer_email, company_name) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(k)
        .bind(name)
        .bind(email)
        .bind(company)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
    h.exec(
        "DELETE FROM connectors WHERE connector_name = 'Grafana' AND connector_description = 'e2e'",
    )
    .await;
    h.exec(&format!(
        "UPDATE connectors SET connector_name = 'Grafana' WHERE connector_name = 'Grafana-e2e-{}'",
        h.suffix
    ))
    .await;
}

#[tokio::test]
async fn grafana_report_logs_in_shoots_panels_and_prints() {
    if !configured() {
        return;
    }
    let stand_in = grafana_server().await;
    grafana(&stand_in, false).await;
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let key = format!("e2e-reporting-{s}");
    let saved = grafana_seed(&h, &stand_in.uri(), &key, true).await;
    let admin = h.token(&format!("admin{s}"), "admin");
    let route = "/api/reporting/generate-report";
    let panel = |id: i64, width: i64| {
        json!({"panel_id": id, "org_id": 1, "dashboard_title": "HUNTRESS - SUMMARY",
               "dashboard_uid": "ab9b", "panel_width": width, "panel_height": 200})
    };
    let body = json!({
        "company_name": "Acme", "timerange_text": "Last 7 days",
        "logo_base64": "data:image/png;base64,AA", "timerange": "7d",
        "rows": [{"id": 1, "panels": [panel(5, 300), panel(5, 0)]}],
    });
    let chromium = copilot_reports::chromium::find_executable().is_some_and(|p| p.is_file());

    let (st, answer) = h
        .call("POST", route, Some(&admin), Some(body.clone()))
        .await;
    if chromium {
        assert_eq!(st, 200, "{answer}");
        assert_eq!(answer["message"], "Report generated successfully");
        assert_eq!(answer["success"], true);
        // `%PDF-` in base64.
        assert!(
            answer["base64_result"]
                .as_str()
                .unwrap()
                .starts_with("JVBERi0")
        );
        let requests = stand_in.received_requests().await.unwrap();
        let login = requests
            .iter()
            .find(|r| r.method.as_str() == "POST" && r.url.path() == "/login")
            .expect("the login was posted");
        assert_eq!(
            String::from_utf8_lossy(&login.body),
            "{\"user\":\"admin\",\"password\":\"secret\"}"
        );
        let solo: Vec<_> = requests
            .iter()
            .filter(|r| r.url.path().starts_with("/d-solo/"))
            .collect();
        // Both panels share a URL: one navigation.
        assert_eq!(solo.len(), 1);
        assert_eq!(solo[0].url.path(), "/d-solo/ab9b/HUNTRESS%20-%20SUMMARY");
        let query = solo[0].url.query().unwrap_or_default();
        assert!(query.starts_with("orgId=1&from="), "{query}");
        assert!(query.ends_with("&panelId=5&theme=None"), "{query}");

        // Grafana refuses the login.
        grafana(&stand_in, true).await;
        let (st, answer) = h
            .call("POST", route, Some(&admin), Some(body.clone()))
            .await;
        assert_eq!(st, 500, "{answer}");
        assert_eq!(answer["message"], "Failed to login to Grafana");
    } else {
        assert_eq!(st, 500);
    }

    // Before the browser: the time range, the unit, the licence.
    let mut bad = body.clone();
    bad["timerange"] = json!("7x");
    let (st, answer) = h.call("POST", route, Some(&admin), Some(bad)).await;
    assert_eq!(st, 400, "{answer}");
    assert_eq!(
        answer["message"],
        "Invalid time range unit: x. Must be one of ['m', 'h', 'd']"
    );
    bad = body.clone();
    bad["timerange"] = json!("d");
    let (st, answer) = h.call("POST", route, Some(&admin), Some(bad)).await;
    assert_eq!(st, 400, "{answer}");
    assert_eq!(
        answer["message"],
        "invalid literal for int() with base 10: ''"
    );
    h.exec(&format!(
        "UPDATE license_cache SET is_enabled = 0 WHERE license_key = '{key}'"
    ))
    .await;
    let (st, answer) = h
        .call("POST", route, Some(&admin), Some(body.clone()))
        .await;
    assert_eq!(st, 400, "{answer}");
    assert_eq!(
        answer["message"],
        "Feature is not enabled. You must purchase the REPORTING license to use this feature."
    );
    let (st, _) = h
        .call(
            "POST",
            route,
            Some(&h.token(&format!("portal{s}"), "customer_user")),
            Some(body),
        )
        .await;
    assert_eq!(st, 403);
    grafana_restore(&h, &key, saved).await;
    cleanup(&h, &[]).await;
}

// --- A DOCX only lxml can repair -------------------------------------------------------------------

/// `REPORTS_E2E_LEGACY_PORT` (6308 by default): the Python backend's stand-in.
fn legacy_port() -> u16 {
    std::env::var("REPORTS_E2E_LEGACY_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6308)
}

async fn legacy_server() -> MockServer {
    let mut tries = 0;
    let listener = loop {
        match std::net::TcpListener::bind(("127.0.0.1", legacy_port())) {
            Ok(l) => break l,
            Err(_) if tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("cannot bind the legacy stand-in on {}: {e}", legacy_port()),
        }
    };
    MockServer::builder().listener(listener).start().await
}

/// The bundled template with a body whose rendering is not well-formed
/// (`clean_tags` turns the `&lt;` into `<`, `safe` keeps it raw).
fn broken_docx() -> Vec<u8> {
    let archive = copilot_docx::zip::Archive::open(BUNDLED_DOCX).unwrap();
    let mut out = copilot_docx::zip::Writer::new(chrono::Utc::now().naive_utc());
    for member in &archive.members {
        let mut data = archive.read(&member.name).unwrap().unwrap();
        if member.name == "word/document.xml" {
            data = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{{ '&lt;b'|safe }}</w:t></w:r></w:p></w:body></w:document>"#
                .to_vec();
        }
        out.write(&member.name, &data).unwrap();
    }
    out.finish()
}

#[tokio::test]
async fn a_docx_only_lxml_can_repair_is_repaired_here() {
    if !configured() {
        return;
    }
    let s3 = minio().await;
    let broken = broken_docx();
    Mock::given(method("HEAD"))
        .and(path("/copilot-case-report-templates/broken.docx"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"b\"")
                .insert_header("content-length", broken.len().to_string().as_str()),
        )
        .mount(&s3)
        .await;
    Mock::given(method("GET"))
        .and(path("/copilot-case-report-templates/broken.docx"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(broken, "application/octet-stream"))
        .mount(&s3)
        .await;
    // The legacy backend is never asked.
    let legacy = legacy_server().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(599))
        .expect(0)
        .mount(&legacy)
        .await;
    let h = harness_or_skip!(Some(&legacy), &minio_env(&s3));
    let (acme_alert, _) = h.seed().await;
    let (acme, beta) = seed_cases(&h, acme_alert).await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let docx = "/api/incidents/report/generate-report-docx";
    let request = json!({"case_id": acme, "template_name": "broken.docx", "file_name": "r"});

    let (st, headers, body) = raw(&h, "POST", docx, &admin, Some(request)).await;
    assert_eq!(st, 200);
    assert_eq!(headers["content-type"], DOCX_TYPE);
    // libxml2's repair: the `<b` that lost its `>` is an empty element.
    let archive = copilot_docx::zip::Archive::open(&body).unwrap();
    let document = archive.read("word/document.xml").unwrap().unwrap();
    let document = String::from_utf8(document).unwrap();
    assert!(document.contains("<b/></w:t>"), "{document}");
    // The tenancy first.
    let (st, _) = h
        .call(
            "POST",
            docx,
            Some(&analyst),
            Some(json!({"case_id": beta, "template_name": "broken.docx"})),
        )
        .await;
    assert_eq!(st, 403);
    legacy.verify().await;
    cleanup(&h, &[acme, beta]).await;
}
