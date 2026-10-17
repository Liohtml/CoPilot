//! End-to-end tests of the Grafana dashboard provisioning
//! (`copilot-grafana-dashboards`) and of the integration and network-connector
//! provisioning built on it (`copilot-integration-provisioning`), through the
//! production router on a real MySQL, with Grafana, Graylog, the Wazuh
//! indexer and the Python backend replaced by local stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13308/copilot \
//!   cargo test -p copilot --test e2e_grafana_provisioning -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `GRAFANA_PROVISIONING_E2E_PORT_BASE` (6410) and the
//! four ports after it. The connector rows a test points at them are replaced
//! for that test and restored (run single-threaded); seeded rows carry
//! explicit ids in 7640000–7649999 (the parity suite's are 7650000–7659999).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::StatusCode;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const GRAFANA: u16 = 0;

fn port(offset: u16) -> u16 {
    std::env::var("GRAFANA_PROVISIONING_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6410)
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

// --- connectors ------------------------------------------------------------------

/// A saved `connectors` row: id, name, url, username, password.
type ConnectorRow = (i64, String, Option<String>, Option<String>, Option<String>);

/// Point connector `name` at `url` (updated in place when it exists, so its id
/// is kept); the row as it was, or `None` when there was none.
async fn set_connector(h: &Harness, name: &str, url: &str) -> Option<ConnectorRow> {
    let saved: Option<ConnectorRow> = sqlx::query_as(
        "SELECT id, connector_name, connector_url, connector_username, connector_password FROM \
         connectors WHERE connector_name = ? ORDER BY id LIMIT 1",
    )
    .bind(name)
    .fetch_optional(h.db.pool())
    .await
    .unwrap();
    match &saved {
        Some((id, ..)) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = 'e2e-user', \
                 connector_password = 'e2e-pass' WHERE id = ?",
            )
            .bind(url)
            .bind(id)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
        None => {
            sqlx::query(
                "INSERT INTO connectors (connector_name, connector_type, connector_url, \
                 connector_last_updated, connector_username, connector_password, \
                 connector_api_key, connector_description, connector_supports, \
                 connector_configured, connector_verified, connector_accepts_host_only, \
                 connector_accepts_api_key, connector_accepts_username_password, \
                 connector_accepts_file, connector_accepts_extra_data, connector_extra_data, \
                 connector_enabled) VALUES (?, '3', ?, UTC_TIMESTAMP(), 'e2e-user', 'e2e-pass', \
                 NULL, 'e2e', 'e2e', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
            )
            .bind(name)
            .bind(url)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
    }
    saved
}

async fn restore_connector(h: &Harness, name: &str, saved: Option<ConnectorRow>) {
    match saved {
        Some((id, _, url, user, pass)) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = ?, \
                 connector_password = ? WHERE id = ?",
            )
            .bind(url)
            .bind(user)
            .bind(pass)
            .bind(id)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
        None => {
            sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
                .bind(name)
                .execute(h.db.pool())
                .await
                .unwrap();
        }
    }
}

/// HTTP Basic for the stand-in connectors' `e2e-user` / `e2e-pass`.
const BASIC: &str = "Basic ZTJlLXVzZXI6ZTJlLXBhc3M=";

async fn grafana_ok(grafana: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/user/using/7"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "Active organization changed"})),
        )
        .mount(grafana)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/dashboards/db"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 41, "slug": "summary", "status": "success", "uid": "abc",
            "url": "/d/abc/summary", "version": 1, "folderUid": "f1"
        })))
        .mount(grafana)
        .await;
}

// --- step 1: dashboards --------------------------------------------------------------

#[tokio::test]
async fn dashboards_are_uploaded_as_python_uploads_them() {
    if !configured() {
        return;
    }
    let grafana = stand_in(GRAFANA).await;
    let h = harness_or_skip!(None);
    let saved = set_connector(&h, "Grafana", &grafana.uri()).await;
    h.seed().await;
    let admin = h.token(&h.code("admin"), "admin");
    grafana_ok(&grafana).await;

    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&admin),
            Some(json!({
                "dashboards": ["HUNTRESS_SUMMARY", "DUO_AUTH"],
                "organizationId": "7", "folderId": 12, "datasourceUid": "ds-1",
                "grafana_url": "https://grafana.example.com"
            })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let one = json!({"id": 41, "slug": "summary", "status": "success", "uid": "abc",
        "url": "/d/abc/summary", "version": 1});
    assert_eq!(
        body,
        json!({"provisioned_dashboards": [one, one], "success": true,
            "message": "All dashboards provisioned successfully"})
    );
    let sent = grafana.received_requests().await.unwrap();
    let paths: Vec<String> = sent
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect();
    assert_eq!(
        paths,
        [
            "POST /api/user/using/7",
            "POST /api/dashboards/db",
            "POST /api/user/using/7",
            "POST /api/dashboards/db"
        ]
    );
    for r in &sent {
        assert_eq!(
            r.headers.get("authorization").unwrap().to_str().unwrap(),
            BASIC
        );
        assert_eq!(
            r.headers.get("user-agent").unwrap().to_str().unwrap(),
            "grafana-client/5.1.0"
        );
    }
    // The switch has no body (`Content-Length: 0`); the upload is the edited
    // template as niquests writes `json=`.
    assert_eq!(sent[0].body, b"");
    assert_eq!(
        sent[1]
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json;charset=utf-8"
    );
    let upload: Value = serde_json::from_slice(&sent[1].body).unwrap();
    assert_eq!(upload["folderId"], json!(12));
    assert_eq!(upload["overwrite"], json!(true));
    let text = String::from_utf8(sent[1].body.clone()).unwrap();
    assert!(text.starts_with("{\"dashboard\": {"), "{}", &text[..40]);
    assert!(!text.contains("replace_datasource_uid"));
    assert!(text.contains("\"uid\": \"ds-1\""));

    // The customer-provisioning twin answers `ProvisionDashboardResponse`.
    let (st, body) = h
        .call(
            "POST",
            "/api/customer_provisioning/provision/dashboards",
            Some(&admin),
            Some(json!({
                "customer_name": "Acme",
                "dashboards_to_include": {"dashboards": ["MIMECAST_SUMMARY"], "organizationId": 99},
                "grafana_org_id": 7, "grafana_datasource_uid": "ds-2", "grafana_folder_id": 3,
                "grafana_url": "https://g.example.com"
            })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"message": "All dashboards provisioned successfully", "success": true})
    );
    restore_connector(&h, "Grafana", saved).await;
}

#[tokio::test]
async fn dashboard_failures_read_as_python_s() {
    if !configured() {
        return;
    }
    let grafana = stand_in(GRAFANA).await;
    let h = harness_or_skip!(None);
    let saved = set_connector(&h, "Grafana", &grafana.uri()).await;
    h.seed().await;
    let analyst = h.token(&h.code("analyst"), "analyst");
    Mock::given(method("POST"))
        .and(path("/api/user/using/7"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not found"})))
        .mount(&grafana)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": ["HUNTRESS_SUMMARY"], "organizationId": 7})),
        )
        .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body,
        json!({"success": false, "message":
            "Error updating dashboard: 500: Error updating dashboard: Client Error 404: Not found"})
    );
    // An unknown dashboard is the validator's 422; no token is a 401.
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": ["NOPE"]})),
        )
        .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["message"],
        json!("dashboards: Dashboard identifier \"NOPE\" is not recognized.")
    );
    let (st, _) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            None,
            Some(json!({"dashboards": []})),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // An empty list asks Grafana nothing.
    grafana.reset().await;
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": []})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(grafana.received_requests().await.unwrap().is_empty());
    // Grafana's answer is validated outside the `except`: the 400 of the
    // `ValueError` handler.
    Mock::given(method("POST"))
        .and(path("/api/user/using/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "ok"})))
        .mount(&grafana)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/dashboards/db"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 1})))
        .mount(&grafana)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": ["DUO_AUTH"], "organizationId": 7})),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("5 validation errors for GrafanaDashboard\nslug\n")
    );
    restore_connector(&h, "Grafana", saved).await;
    // Without a Grafana connector row the client cannot be built.
    let saved = set_connector(&h, "Grafana", "x").await;
    h.exec("DELETE FROM connectors WHERE connector_name = 'Grafana'")
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/grafana/dashboards",
            Some(&analyst),
            Some(json!({"dashboards": ["DUO_AUTH"]})),
        )
        .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body["message"],
        json!(
            "Error updating dashboard: 500: Error updating dashboard: 500: No Grafana connector \
             found in the database"
        )
    );
    if let Some(row) = saved {
        set_connector(&h, "Grafana", row.2.as_deref().unwrap_or_default()).await;
        restore_connector(&h, "Grafana", Some(row)).await;
    }
}
