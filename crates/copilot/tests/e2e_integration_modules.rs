//! End-to-end tests of the integration modules (`copilot-integration-modules`)
//! against a real MySQL, every upstream — the module containers and
//! Mimecast's region discovery — replaced by one recording mock reached
//! through `COPILOT_INTEGRATION_MODULES_URL`.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13309/copilot \
//!   cargo test -p copilot --test e2e_integration_modules -- --test-threads=1
//! ```
//!
//! The modules read connector rows by fixed ids (1, 10, 14) and the
//! `Event Shipper` by name: each test copies whatever rows hold those into a
//! backup table, writes its own and puts the originals back at the end (a
//! test that died half-way is repaired by the next one). Integration rows
//! use explicit ids from 7726000 on and are deleted again; the jobs read
//! every customer with an integration, so the suite needs one thread.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use copilot_scheduler::runner::ManualRun;

#[macro_use]
mod common;
use common::*;

const BACKUP: &str = "e2e_integration_modules_connectors";
const HUNTRESS: &str = "/copilot-huntress-module/collect";
const DUO: &str = "/copilot-duo-module/auth";
const CATO: &str = "/copilot-cato-module/collect";
const MIMECAST_MODULE: &str = "/copilot-mimecast-module/collect";
const SAP: &str = "/copilot-sap-module/sap-siem";
const DISCOVER: &str = "/api.mimecast.com/api/login/discover-authentication";
const B64_SECRET: &str = "c2VjcmV0LWtleQ==";

async fn restore_connectors(h: &Harness) {
    let backed_up: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() \
         AND table_name = ?",
    )
    .bind(BACKUP)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    if backed_up == 0 {
        return;
    }
    h.exec("DELETE FROM connectors WHERE id IN (1, 10, 14) OR connector_name = 'Event Shipper'")
        .await;
    h.exec(&format!("INSERT INTO connectors SELECT * FROM {BACKUP}"))
        .await;
    h.exec(&format!("DROP TABLE {BACKUP}")).await;
}

async fn connector(h: &Harness, id: Option<i64>, name: &str, url: &str, extra: Option<&str>) {
    let (user, password) = if id == Some(1) {
        (Some("indexer-user"), Some("indexer-pw"))
    } else {
        (None, None)
    };
    sqlx::query(
        "INSERT INTO connectors (id, connector_name, connector_type, connector_url, \
         connector_last_updated, connector_username, connector_password, connector_api_key, \
         connector_description, connector_supports, connector_configured, connector_verified, \
         connector_accepts_host_only, connector_accepts_api_key, \
         connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         (?, ?, '3', ?, UTC_TIMESTAMP(), ?, ?, NULL, 'e2e', 'e2e', 1, 1, 0, 0, 1, 0, 1, ?, 1)",
    )
    .bind(id)
    .bind(name)
    .bind(url)
    .bind(user)
    .bind(password)
    .bind(extra)
    .execute(h.db.pool())
    .await
    .unwrap();
}

/// The suite's connector rows, the originals moved aside.
async fn seed_connectors(h: &Harness) {
    restore_connectors(h).await;
    h.exec(&format!(
        "CREATE TABLE {BACKUP} AS SELECT * FROM connectors \
         WHERE id IN (1, 10, 14) OR connector_name = 'Event Shipper'"
    ))
    .await;
    h.exec("DELETE FROM connectors WHERE id IN (1, 10, 14) OR connector_name = 'Event Shipper'")
        .await;
    connector(
        h,
        Some(1),
        "Wazuh-Indexer",
        "https://indexer.example:9200",
        None,
    )
    .await;
    connector(h, Some(10), "Graylog", "10.0.0.10", Some("12210")).await;
    connector(h, Some(14), "Graylog-Network", "10.0.0.14", Some("12214")).await;
    connector(h, None, "Event Shipper", "10.0.0.5", Some("12201")).await;
}

async fn wipe_integrations(h: &Harness) {
    h.exec("DELETE FROM integration_auth_keys WHERE id BETWEEN 7726300 AND 7726499")
        .await;
    h.exec("DELETE FROM integration_subscriptions WHERE id BETWEEN 7726200 AND 7726299")
        .await;
    h.exec("DELETE FROM customer_integrations WHERE id BETWEEN 7726000 AND 7726099")
        .await;
    h.exec("DELETE FROM integration_services WHERE id BETWEEN 7726100 AND 7726199")
        .await;
}

/// One customer integration with its service, subscription and keys
/// (`n` < 20, at most ten keys).
async fn integration(h: &Harness, n: i64, code: &str, service: &str, keys: &[(&str, &str)]) {
    let (ci, svc, sub) = (7_726_000 + n, 7_726_100 + n, 7_726_200 + n);
    sqlx::query(
        "INSERT INTO integration_services (id, service_name, auth_type) VALUES (?, ?, 'API Key')",
    )
    .bind(svc)
    .bind(service)
    .execute(h.db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO customer_integrations (id, customer_code, customer_name, \
         integration_service_id, integration_service_name, instance_name, deployed) \
         VALUES (?, ?, 'e2e', 1, ?, NULL, 0)",
    )
    .bind(ci)
    .bind(code)
    .bind(service)
    .execute(h.db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) \
         VALUES (?, ?, ?)",
    )
    .bind(sub)
    .bind(ci)
    .bind(svc)
    .execute(h.db.pool())
    .await
    .unwrap();
    for (i, (k, v)) in keys.iter().enumerate() {
        sqlx::query(
            "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(7_726_300 + n * 10 + i64::try_from(i).unwrap())
        .bind(sub)
        .bind(k)
        .bind(v)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

async fn meta(h: &Harness, code: &str, iris: Option<i64>) {
    sqlx::query(
        "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, \
         customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group, \
         customer_meta_iris_customer_id) VALUES (?, 'e2e', 'i', 's', '1', 'g', ?)",
    )
    .bind(code)
    .bind(iris)
    .execute(h.db.pool())
    .await
    .unwrap();
}

/// A licence row unless one exists; returns whether this suite wrote it.
async fn license(h: &Harness) -> bool {
    h.exec("DELETE FROM license WHERE license_key = 'e2e-integration-modules'")
        .await;
    if h.scalar_i64("SELECT COUNT(*) FROM license").await > 0 {
        return false;
    }
    h.exec(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) \
         VALUES ('e2e-integration-modules', 'e2e', 'e2e@example.com', 'e2e')",
    )
    .await;
    true
}

/// The suite's IRIS ids (7726900–7726999), whoever's metadata carries them.
async fn wipe_meta(h: &Harness) {
    h.exec(
        "DELETE FROM customersmeta \
         WHERE customer_meta_iris_customer_id BETWEEN 7726900 AND 7726999",
    )
    .await;
}

async fn cleanup(h: &Harness, wrote_license: bool) {
    wipe_integrations(h).await;
    wipe_meta(h).await;
    if wrote_license {
        h.exec("DELETE FROM license WHERE license_key = 'e2e-integration-modules'")
            .await;
    }
    restore_connectors(h).await;
}

/// The `.env` lines pointing every upstream at `stub`.
fn upstream(stub: &str, extra: &str) -> String {
    format!("COPILOT_INTEGRATION_MODULES_URL={stub}\n{extra}")
}

/// The suite's rows: `(admin token, analyst token, whether the licence row
/// is the suite's)`.
async fn setup(h: &Harness) -> (String, String, bool) {
    h.seed().await;
    seed_connectors(h).await;
    wipe_integrations(h).await;
    wipe_meta(h).await;
    let wrote = license(h).await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    (admin, analyst, wrote)
}

async fn answer(server: &MockServer, at: &str, status: u16, body: Value) {
    Mock::given(method("POST"))
        .and(path(at.to_string()))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

fn header(req: &Request, name: &str) -> String {
    req.headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn sent(server: &MockServer, at: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == at)
        .collect()
}

/// httpx 0.28's `client.post(url, json=…)`: its headers, the body compact.
fn assert_httpx_json(req: &Request) {
    assert_eq!(header(req, "user-agent"), "python-httpx/0.28.1");
    assert_eq!(header(req, "accept"), "*/*");
    assert_eq!(header(req, "accept-encoding"), "gzip, deflate");
    assert_eq!(header(req, "connection"), "keep-alive");
    assert_eq!(header(req, "content-type"), "application/json");
    assert_eq!(header(req, "content-length"), req.body.len().to_string());
}

fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

const MODULES: &str = "/api/integrations/modules";

#[tokio::test]
async fn module_routes_post_what_python_posts() {
    let stub = MockServer::start().await;
    let h = harness_or_skip!(None, &upstream(&stub.uri(), ""));
    let (admin, analyst, wrote) = setup(&h).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    integration(
        &h,
        0,
        &acme,
        "Huntress",
        &[("API_KEY", "hk"), ("API_SECRET", "hs")],
    )
    .await;
    integration(
        &h,
        1,
        &acme,
        "DUO",
        &[
            ("API_HOSTNAME", "api-a.duosecurity.com"),
            ("INTEGRATION_KEY", "ik"),
            ("SECRET_KEY", "sk"),
        ],
    )
    .await;
    integration(
        &h,
        2,
        &acme,
        "CATO",
        &[
            ("API_KEY", "ck"),
            ("ACCOUNT_ID", " 42 "),
            ("EVENT_TYPES", "Security"),
            ("EVENT_SUB_TYPES", "IPS"),
        ],
    )
    .await;
    integration(
        &h,
        3,
        &acme,
        "Mimecast",
        &[
            ("APP_ID", "app"),
            ("APP_KEY", "appkey"),
            ("EMAIL_ADDRESS", "admin@acme.example"),
            ("ACCESS_KEY", "acc"),
            ("SECRET_KEY", B64_SECRET),
        ],
    )
    .await;
    integration(&h, 4, &beta, "Huntress", &[("API_KEY", "hk-b")]).await;
    integration(
        &h,
        5,
        &beta,
        "CATO",
        &[
            ("API_KEY", "ck"),
            ("ACCOUNT_ID", "5."),
            ("EVENT_TYPES", "Security"),
        ],
    )
    .await;
    for at in [HUNTRESS, DUO, CATO, MIMECAST_MODULE] {
        answer(&stub, at, 200, json!({"ok": true})).await;
    }
    let call = |token: Option<String>, route: &str, body: Value| {
        let h = &h;
        let uri = format!("{MODULES}/{route}");
        async move { h.call("POST", &uri, token.as_deref(), Some(body)).await }
    };

    // The body is read before the token; then the token, then the tenant.
    let (st, _) = h
        .call_raw(
            "POST",
            &format!("{MODULES}/huntress"),
            None,
            Some("application/json"),
            "{",
        )
        .await;
    assert_eq!(st, 422);
    let (st, _) = call(None, "huntress", json!({"customer_code": acme})).await;
    assert_eq!(st, 401);
    let (st, body) = call(
        Some(analyst.clone()),
        "huntress",
        json!({"customer_code": beta}),
    )
    .await;
    assert_eq!(st, 403, "{body}");
    let (st, body) = call(Some(analyst.clone()), "huntress", json!({})).await;
    assert_eq!(st, 422, "{body}");
    assert!(sent(&stub, HUNTRESS).await.is_empty());

    // Huntress: the Event Shipper, the indexer by id 1, the keys.
    let (st, body) = call(
        Some(analyst.clone()),
        "huntress",
        json!({"customer_code": acme}),
    )
    .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Huntress Events collected successfully."})
        )
    );
    let reqs = sent(&stub, HUNTRESS).await;
    assert_eq!(reqs.len(), 1);
    assert_httpx_json(&reqs[0]);
    assert_eq!(
        String::from_utf8_lossy(&reqs[0].body),
        format!(
            r#"{{"integration":"huntress","customer_code":"{acme}","graylog_host":"10.0.0.5","graylog_port":"12201","wazuh_indexer_host":"https://indexer.example:9200","wazuh_indexer_username":"indexer-user","wazuh_indexer_password":"indexer-pw","api_key":"hk","api_secret":"hs"}}"#
        )
    );

    // A failure is `success: false` with `str(e)`.
    let (st, body) = call(
        Some(admin.clone()),
        "huntress",
        json!({"customer_code": format!("nobody{}", h.suffix)}),
    )
    .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": false, "message": "404: Customer integration settings not found."})
        )
    );
    let (_, body) = call(
        Some(admin.clone()),
        "huntress",
        json!({"customer_code": beta}),
    )
    .await;
    assert_eq!(body["success"], false);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("1 validation error for HuntressAuthKeys\nAPI_SECRET\n  Field required"),
        "{body}"
    );
    let (_, body) = call(
        Some(admin.clone()),
        "huntress",
        json!({"customer_code": acme, "integration_name": "Nope"}),
    )
    .await;
    assert_eq!(
        body["message"],
        "404: No auth keys found for Huntress integration. Please create auth keys for Huntress \
         integration."
    );

    // Duo: the name is forced to "DUO", the endpoint and range fixed.
    let (_, body) = call(
        Some(analyst.clone()),
        "duo",
        json!({"customer_code": acme, "integration_name": "anything"}),
    )
    .await;
    assert_eq!(
        body,
        json!({"success": true, "message": "Duo Events collected successfully."})
    );
    let reqs = sent(&stub, DUO).await;
    assert_httpx_json(&reqs[0]);
    assert_eq!(
        serde_json::from_slice::<Value>(&reqs[0].body).unwrap(),
        json!({"integration": "duo", "customer_code": acme, "graylog_host": "10.0.0.5",
               "graylog_port": "12201", "integration_key": "ik", "secret_key": "sk",
               "api_host": "api-a.duosecurity.com", "api_endpoint": "/admin/v2/logs/authentication",
               "range": "15m"})
    );

    // Cato: Graylog by id 10, `int(ACCOUNT_ID)` as Pydantic reads it.
    let (_, body) = call(
        Some(analyst.clone()),
        "cato",
        json!({"customer_code": acme}),
    )
    .await;
    assert_eq!(
        body,
        json!({"success": true, "message": "Cato Events collected successfully."})
    );
    let reqs = sent(&stub, CATO).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reqs[0].body).unwrap(),
        json!({"integration": "cato", "customer_code": acme, "graylog_host": "10.0.0.10",
               "graylog_port": "12210", "api_key": "ck", "account_id": 42,
               "event_types": "Security", "event_sub_types": "IPS"})
    );
    let (_, body) = call(Some(admin.clone()), "cato", json!({"customer_code": beta})).await;
    let text = body["message"].as_str().unwrap();
    assert!(
        text.starts_with("2 validation errors for CatoAuthKeys\nACCOUNT_ID\n"),
        "{text}"
    );

    // Mimecast's module: Graylog by id 14, the licence.
    let (_, body) = call(
        Some(analyst.clone()),
        "mimecast",
        json!({"customer_code": acme}),
    )
    .await;
    assert_eq!(
        body,
        json!({"success": true, "message": "Mimecast Events collected successfully."})
    );
    let reqs = sent(&stub, MIMECAST_MODULE).await;
    let posted: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(posted["graylog_host"], "10.0.0.14");
    assert_eq!(posted["graylog_port"], "12214");
    assert_eq!(posted["secret_key"], B64_SECRET);
    assert_eq!(posted["time_range"], "15m");

    // A module answering 503: `raise_for_status()`'s text.
    stub.reset().await;
    answer(&stub, HUNTRESS, 503, json!({})).await;
    let (_, body) = call(
        Some(admin.clone()),
        "huntress",
        json!({"customer_code": acme}),
    )
    .await;
    let text = body["message"].as_str().unwrap();
    assert!(
        text.starts_with("Server error '503 Service Unavailable' for url '"),
        "{text}"
    );

    cleanup(&h, wrote).await;
}

#[tokio::test]
async fn an_unreachable_module_names_the_optional_container() {
    let base = format!("http://127.0.0.1:{}", closed_port());
    let h = harness_or_skip!(None, &upstream(&base, ""));
    let (admin, _analyst, wrote) = setup(&h).await;
    let acme = h.code("acme");
    integration(
        &h,
        0,
        &acme,
        "Huntress",
        &[("API_KEY", "hk"), ("API_SECRET", "hs")],
    )
    .await;
    integration(
        &h,
        1,
        &acme,
        "DUO",
        &[
            ("API_HOSTNAME", "h"),
            ("INTEGRATION_KEY", "ik"),
            ("SECRET_KEY", "sk"),
        ],
    )
    .await;
    let (_, body) = h
        .call(
            "POST",
            &format!("{MODULES}/huntress"),
            Some(&admin),
            Some(json!({"customer_code": acme})),
        )
        .await;
    assert_eq!(body["success"], false);
    assert_eq!(
        body["message"],
        "Could not reach the Huntress module at http://copilot-huntress-module/collect (All \
         connection attempts failed). This container is optional and is not started by the \
         default docker-compose stack — run ghcr.io/socfortress/copilot-huntress-module:latest \
         on the same Docker network as copilot-backend to enable Huntress collection."
    );
    let (_, body) = h
        .call(
            "POST",
            &format!("{MODULES}/duo"),
            Some(&admin),
            Some(json!({"customer_code": acme})),
        )
        .await;
    assert_eq!(
        body,
        json!({"success": false, "message": "All connection attempts failed"})
    );
    cleanup(&h, wrote).await;
}

#[tokio::test]
async fn sap_siem_collection_and_analyses() {
    let stub = MockServer::start().await;
    let h = harness_or_skip!(None, &upstream(&stub.uri(), ""));
    let (admin, analyst, wrote) = setup(&h).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    meta(&h, &acme, Some(7_726_901)).await;
    meta(&h, &beta, Some(7_726_902)).await;
    integration(
        &h,
        0,
        &acme,
        "SAP SIEM",
        &[
            ("API_KEY", "k1,k2"),
            ("SECRET_KEY", "s"),
            ("USER_KEY", "u"),
            ("API_DOMAIN", "audit.eu1.gigya.com"),
        ],
    )
    .await;
    integration(
        &h,
        1,
        &beta,
        "SAP SIEM",
        &[
            ("API_KEY", "single"),
            ("SECRET_KEY", "s"),
            ("API_DOMAIN", "audit.eu1.gigya.com"),
        ],
    )
    .await;
    answer(&stub, &format!("{SAP}/collect"), 200, json!({"ok": true})).await;
    answer(
        &stub,
        &format!("{SAP}/brute_force_failed_logins_multiple_ips"),
        200,
        json!({"ok": true}),
    )
    .await;

    // The time range's pattern is FastAPI's 422 (once the model validator
    // has computed the bounds from it).
    let (st, body) = h
        .call(
            "POST",
            &format!("{MODULES}/sap_siem"),
            Some(&analyst),
            Some(json!({"customer_code": acme, "time_range": "05m"})),
        )
        .await;
    assert_eq!(st, 422, "{body}");
    assert!(sent(&stub, &format!("{SAP}/collect")).await.is_empty());

    // One POST per comma-separated key, the bounds computed per request.
    let (st, body) = h
        .call(
            "POST",
            &format!("{MODULES}/sap_siem"),
            Some(&analyst),
            Some(json!({"customer_code": acme, "time_range": "10m", "threshold": 5})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "SAP SIEM Events collected successfully."})
        )
    );
    let reqs = sent(&stub, &format!("{SAP}/collect")).await;
    assert_eq!(reqs.len(), 2);
    for (req, key) in reqs.iter().zip(["k1", "k2"]) {
        assert_httpx_json(req);
        let mut posted: Value = serde_json::from_slice(&req.body).unwrap();
        for bound in ["lower_bound", "upper_bound"] {
            let text = posted[bound].as_str().unwrap().to_string();
            assert!(text.ends_with('Z') && text.len() == 24, "{text}");
            posted[bound] = json!("*");
        }
        assert_eq!(
            posted,
            json!({"customer_code": acme, "integration_name": "SAP SIEM", "threshold": 5,
                   "time_range": "10m", "lower_bound": "*", "upper_bound": "*",
                   "auth_keys": {"API_KEY": key, "SECRET_KEY": "s", "USER_KEY": "u",
                                 "API_DOMAIN": "audit.eu1.gigya.com"},
                   "customer_details": {"customer_code": acme, "iris_customer_id": 7_726_901}})
        );
    }

    // A single key is POSTed as one of several would be (Python's
    // `Depends` default stopped it with a bare 500: RUST_MIGRATION.md §4).
    let (st, _) = h
        .call(
            "POST",
            &format!("{MODULES}/sap_siem"),
            Some(&admin),
            Some(json!({"customer_code": beta})),
        )
        .await;
    assert_eq!(st, 200);
    let reqs = sent(&stub, &format!("{SAP}/collect")).await;
    assert_eq!(reqs.len(), 3);
    let posted: Value = serde_json::from_slice(&reqs[2].body).unwrap();
    assert_eq!(posted["auth_keys"]["API_KEY"], "single");

    // The analyses: the tenant is the IRIS id's customer (§4).
    let route = format!("{MODULES}/sap_siem/brute_force_failed_logins_multiple_ips");
    let (st, body) = h
        .call(
            "POST",
            &route,
            Some(&analyst),
            Some(json!({"iris_customer_id": 7_726_902})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            403,
            json!({"success": false, "message": "Access denied to IRIS customer 7726902"})
        )
    );
    let (st, _) = h
        .call(
            "POST",
            &route,
            Some(&analyst),
            Some(json!({"iris_customer_id": 7_726_999})),
        )
        .await;
    assert_eq!(st, 403);
    let (st, body) = h
        .call(
            "POST",
            &route,
            Some(&analyst),
            Some(json!({"iris_customer_id": "7726901", "threshold": 4})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "SAP SIEM Events collected successfully."})
        )
    );
    let reqs = sent(
        &stub,
        &format!("{SAP}/brute_force_failed_logins_multiple_ips"),
    )
    .await;
    assert_eq!(
        String::from_utf8_lossy(&reqs[0].body),
        r#"{"threshold":4,"time_range":15,"iris_customer_id":7726901}"#
    );
    // An id no customer carries is the admin's to send.
    let (st, _) = h
        .call(
            "POST",
            &route,
            Some(&admin),
            Some(json!({"iris_customer_id": 7_726_999})),
        )
        .await;
    assert_eq!(st, 200);

    cleanup(&h, wrote).await;
}

fn region(api: &str) -> Value {
    json!({"meta": {"status": 200}, "data": [{
        "emailAddress": "admin@acme.example", "emailToken": "t",
        "authenticate": ["Basic-Cloud"],
        "region": {"code": "eu", "api": api, "mpp": "https://mpp.example", "adminConsole": "https://admin.example",
                   "name": "eu", "location": "EU", "shortName": "eu", "url": "https://login.example"}
    }], "fail": []})
}

#[tokio::test]
async fn mimecast_routes_discover_then_collect() {
    let stub = MockServer::start().await;
    let files = tempfile::tempdir().unwrap();
    let h = harness_or_skip!(
        None,
        &upstream(
            &stub.uri(),
            &format!("COPILOT_MIMECAST_DIR={}\n", files.path().display())
        )
    );
    let (_admin, analyst, wrote) = setup(&h).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    integration(
        &h,
        0,
        &acme,
        "Mimecast",
        &[
            ("APP_ID", "app"),
            ("APP_KEY", "appkey"),
            ("EMAIL_ADDRESS", "admin@acme.example"),
            ("ACCESS_KEY", "acc"),
            ("SECRET_KEY", B64_SECRET),
        ],
    )
    .await;
    let invoke = |body: Value| {
        let (h, analyst) = (&h, &analyst);
        async move {
            h.call("POST", "/api/mimecast/invoke", Some(analyst), Some(body))
                .await
        }
    };
    let ttp = |body: Value| {
        let (h, analyst) = (&h, &analyst);
        async move {
            h.call("POST", "/api/mimecast/ttp/urls", Some(analyst), Some(body))
                .await
        }
    };

    let (st, _) = invoke(json!({"customer_code": beta})).await;
    assert_eq!(st, 403);

    // A region: Python's `HttpUrl + str` is a TypeError; here the region's
    // URL is the string Mimecast sent and both routes collect
    // (`e2e_fix_sweep` follows the files and the events).
    answer(
        &stub,
        DISCOVER,
        200,
        region(&format!("{}/eu-api", stub.uri())),
    )
    .await;
    answer(
        &stub,
        "/eu-api/api/audit/get-siem-logs",
        200,
        json!({"meta": {"status": 200}, "data": [], "fail": []}),
    )
    .await;
    answer(
        &stub,
        "/eu-api/api/ttp/url/get-logs",
        200,
        json!({"meta": {"pagination": {"pageSize": 0, "totalCount": 0}, "status": 200},
               "data": [{"clickLogs": []}], "fail": []}),
    )
    .await;
    let (st, body) = invoke(json!({"customer_code": acme})).await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Successfully invoked Mimecast integration."})
        )
    );
    let reqs = sent(&stub, DISCOVER).await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(header(&reqs[0], "x-mc-app-id"), "app");
    let req_id = header(&reqs[0], "x-mc-req-id");
    assert_eq!(
        req_id
            .char_indices()
            .filter(|(_, c)| *c == '-')
            .map(|(i, _)| i)
            .collect::<Vec<_>>(),
        [8, 13, 18, 23],
        "{req_id}"
    );
    assert_eq!(req_id.len(), 36);
    assert!(header(&reqs[0], "x-mc-date").ends_with(" UTC"));
    assert_eq!(header(&reqs[0], "user-agent"), "python-httpx/0.28.1");
    assert_eq!(
        String::from_utf8_lossy(&reqs[0].body),
        r#"{"data":[{"emailAddress":"admin@acme.example"}]}"#
    );
    let (st, _) = ttp(json!({"customer_code": acme, "time_range": "1h"})).await;
    assert_eq!(st, 200);
    let (st, _) = ttp(json!({"customer_code": acme, "time_range": "1x"})).await;
    assert_eq!(st, 422);

    // No region: /invoke's 400, /ttp/urls' IndexError.
    stub.reset().await;
    answer(
        &stub,
        DISCOVER,
        200,
        json!({"meta": {"status": 200}, "data": [], "fail": []}),
    )
    .await;
    let (st, body) = invoke(json!({"customer_code": acme})).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!("Unable to retrieve base URL for Mimecast integration.")
        )
    );
    let (st, _) = ttp(json!({"customer_code": acme})).await;
    assert_eq!(st, 500);

    // Discovery failing: the one 400 for both.
    stub.reset().await;
    answer(&stub, DISCOVER, 500, json!({})).await;
    for (st, body) in [
        invoke(json!({"customer_code": acme})).await,
        ttp(json!({"customer_code": acme})).await,
    ] {
        assert_eq!(
            (st.as_u16(), body["message"].clone()),
            (
                400,
                json!("Unable to retrieve base URL for Mimecast integration.")
            )
        );
    }

    cleanup(&h, wrote).await;
}

async fn job_row(h: &Harness, job_id: &str, enabled: bool, extra: Option<&str>) -> i64 {
    sqlx::query("DELETE FROM scheduled_job_metadata WHERE job_id = ?")
        .bind(job_id)
        .execute(h.db.pool())
        .await
        .unwrap();
    let res = sqlx::query(
        "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, extra_data, \
         enabled, job_description) VALUES (?, NULL, 10, ?, ?, 'e2e integration modules')",
    )
    .bind(job_id)
    .bind(extra)
    .bind(enabled)
    .execute(h.db.pool())
    .await
    .unwrap();
    i64::try_from(res.last_insert_id()).unwrap()
}

async fn stamped(h: &Harness, row: i64) -> bool {
    sqlx::query_scalar::<_, Option<chrono::NaiveDateTime>>(
        "SELECT last_success FROM scheduled_job_metadata WHERE id = ?",
    )
    .bind(row)
    .fetch_one(h.db.pool())
    .await
    .unwrap()
    .is_some()
}

const HUNTRESS_JOB: &str = "invoke_huntress_integration_collect";
const DUO_JOB: &str = "invoke_duo_integration_collect";
const SAP_JOB: &str = "invoke_sap_siem_integration_collection";
const BRUTE_JOB: &str = "invoke_sap_siem_integration_brute_force_failed_logins";

#[tokio::test]
async fn collection_jobs_run_here_when_handed_over() {
    let stub = MockServer::start().await;
    let h = harness_or_skip!(
        None,
        &upstream(
            &stub.uri(),
            &format!("COPILOT_RS_JOBS={HUNTRESS_JOB},{DUO_JOB},{SAP_JOB},{BRUTE_JOB}\n")
        )
    );
    let (_admin, _analyst, wrote) = setup(&h).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    meta(&h, &acme, Some(7_726_901)).await;
    integration(
        &h,
        0,
        &acme,
        "Huntress",
        &[("API_KEY", "hk"), ("API_SECRET", "hs")],
    )
    .await;
    integration(
        &h,
        1,
        &acme,
        "DUO",
        &[
            ("API_HOSTNAME", "h"),
            ("INTEGRATION_KEY", "ik"),
            ("SECRET_KEY", "sk"),
        ],
    )
    .await;
    integration(
        &h,
        2,
        &acme,
        "SAP SIEM",
        &[
            ("API_KEY", "k1,k2"),
            ("SECRET_KEY", "s"),
            ("API_DOMAIN", "audit.eu1.gigya.com"),
        ],
    )
    .await;
    for at in [HUNTRESS, DUO] {
        answer(&stub, at, 200, json!({"ok": true})).await;
    }
    answer(&stub, &format!("{SAP}/collect"), 200, json!({"ok": true})).await;
    answer(
        &stub,
        &format!("{SAP}/brute_force_failed_logins_multiple_ips"),
        200,
        json!({}),
    )
    .await;
    let scheduler = &h.app.scheduler;

    // Python's while its row is enabled.
    let huntress = job_row(&h, HUNTRESS_JOB, true, None).await;
    assert!(matches!(
        scheduler.run_now(HUNTRESS_JOB).await.unwrap(),
        ManualRun::NotOwned(_)
    ));
    assert!(sent(&stub, HUNTRESS).await.is_empty());

    // Handed over: the function's return value is the run's result, and
    // the Huntress job stamps nothing itself.
    sqlx::query("UPDATE scheduled_job_metadata SET enabled = 0 WHERE id = ?")
        .bind(huntress)
        .execute(h.db.pool())
        .await
        .unwrap();
    let customers = h
        .scalar_i64(
            "SELECT COUNT(*) FROM customer_integrations \
             WHERE integration_service_name = 'Huntress'",
        )
        .await;
    match scheduler.run_now(HUNTRESS_JOB).await.unwrap() {
        ManualRun::Ran(Ok(result)) => assert_eq!(
            result,
            Some(json!({"success": true,
                        "message": format!("Huntress integration invoked for {customers} customer(s).")}))
        ),
        other => panic!("{other:?}"),
    }
    assert!(!stamped(&h, huntress).await);
    assert_eq!(sent(&stub, HUNTRESS).await.len(), 1);

    // One customer failing fails the run with every failure named.
    integration(&h, 3, &beta, "Huntress", &[("API_KEY", "hk-b")]).await;
    match scheduler.run_now(HUNTRESS_JOB).await.unwrap() {
        ManualRun::Ran(Err(e)) => {
            assert!(
                e.0.starts_with("Huntress collection failed for 1 of "),
                "{}",
                e.0
            );
            assert!(
                e.0.contains(&format!("{beta}: 1 validation error for HuntressAuthKeys")),
                "{}",
                e.0
            );
        }
        other => panic!("{other:?}"),
    }

    // Duo stamps its own last_success, a manual run included.
    let duo = job_row(&h, DUO_JOB, false, None).await;
    match scheduler.run_now(DUO_JOB).await.unwrap() {
        ManualRun::Ran(Ok(result)) => assert_eq!(
            result,
            Some(json!({"success": true, "message": "Duo integration invoked."}))
        ),
        other => panic!("{other:?}"),
    }
    assert!(stamped(&h, duo).await);

    // SAP SIEM: the window is the row's interval in minutes.
    let sap = job_row(&h, SAP_JOB, false, None).await;
    match scheduler.run_now(SAP_JOB).await.unwrap() {
        ManualRun::Ran(Ok(_)) => {}
        other => panic!("{other:?}"),
    }
    assert!(stamped(&h, sap).await);
    let reqs = sent(&stub, &format!("{SAP}/collect")).await;
    assert_eq!(reqs.len(), 2);
    let posted: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(posted["time_range"], "10m");
    assert_eq!(posted["customer_code"], json!(acme));

    // An analysis reads `extra_data` (`threshold=…,time_range=…`).
    let brute = job_row(
        &h,
        BRUTE_JOB,
        false,
        Some("time_range=7,other=x,threshold=4"),
    )
    .await;
    match scheduler.run_now(BRUTE_JOB).await.unwrap() {
        ManualRun::Ran(Ok(result)) => assert_eq!(
            result.unwrap()["message"],
            "SAP SIEM integration invoked for brute force failed logins."
        ),
        other => panic!("{other:?}"),
    }
    assert!(stamped(&h, brute).await);
    let reqs = sent(
        &stub,
        &format!("{SAP}/brute_force_failed_logins_multiple_ips"),
    )
    .await;
    assert_eq!(
        String::from_utf8_lossy(&reqs[0].body),
        r#"{"threshold":4,"time_range":7,"iris_customer_id":7726901}"#
    );
    job_row(&h, BRUTE_JOB, false, Some("threshold")).await;
    match scheduler.run_now(BRUTE_JOB).await.unwrap() {
        ManualRun::Ran(Err(e)) => {
            assert_eq!(e.0, "not enough values to unpack (expected 2, got 1)")
        }
        other => panic!("{other:?}"),
    }

    for job in [HUNTRESS_JOB, DUO_JOB, SAP_JOB, BRUTE_JOB] {
        sqlx::query("DELETE FROM scheduled_job_metadata WHERE job_id = ?")
            .bind(job)
            .execute(h.db.pool())
            .await
            .unwrap();
    }
    cleanup(&h, wrote).await;
}
