//! End-to-end tests of `copilot-integrations` — `/api/integrations`,
//! `/api/api/v1/alert_settings` and `/api/network_connectors` — through the
//! production router on a real MySQL, with the Wazuh manager, Graylog,
//! Grafana and the Python backend replaced by local stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13309/copilot \
//!   cargo test -p copilot --test e2e_integrations -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `INTEGRATIONS_E2E_PORT_BASE` (5840) and the three
//! ports after it. Seeded rows carry explicit ids in 7520000–7529999 (the
//! parity suite's are 7530000–7539999); the connector rows a test points at
//! the stand-ins are replaced for that test and restored (run
//! single-threaded).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::StatusCode;
use serde_json::{Value, json};
use wiremock::matchers::{any, body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const WAZUH: u16 = 0;
const GRAYLOG: u16 = 1;
const GRAFANA: u16 = 2;
const LEGACY: u16 = 3;

fn port(offset: u16) -> u16 {
    std::env::var("INTEGRATIONS_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(5840)
        + offset
}

/// Whether the suite runs at all; checked before a stand-in binds a port, so
/// that `cargo test --workspace` (parallel, no database) never races for one.
fn configured() -> bool {
    std::env::var("COPILOT_TEST_DATABASE_URL").is_ok()
}

/// A stand-in on its port, retried while the previous test's server lets
/// the port go (wiremock closes its listener on its own thread after the
/// `MockServer` is dropped).
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

/// `'text'` or `NULL`.
fn lit(v: Option<&str>) -> String {
    v.map_or_else(|| "NULL".to_string(), |v| format!("'{v}'"))
}

// --- connectors ------------------------------------------------------------------

/// A saved `connectors` row: name, url, username, password.
type ConnectorRow = (String, Option<String>, Option<String>, Option<String>);

const TOOLS: [&str; 3] = ["Wazuh-Manager", "Graylog", "Grafana"];

/// Point the three connectors at the stand-ins; what was there before.
async fn swap_connectors(h: &Harness) -> Vec<ConnectorRow> {
    let saved: Vec<ConnectorRow> = sqlx::query_as(
        "SELECT connector_name, connector_url, connector_username, connector_password FROM \
         connectors WHERE connector_name IN ('Wazuh-Manager', 'Graylog', 'Grafana')",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    for (i, name) in TOOLS.iter().enumerate() {
        h.exec(&format!(
            "DELETE FROM connectors WHERE connector_name = '{name}'"
        ))
        .await;
        insert_connector(
            h,
            name,
            &format!("http://127.0.0.1:{}", port(i as u16)),
            Some("e2e-user"),
            Some("e2e-pass"),
        )
        .await;
    }
    saved
}

async fn insert_connector(
    h: &Harness,
    name: &str,
    url: &str,
    user: Option<&str>,
    pass: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, \
         connector_last_updated, connector_username, connector_password, connector_api_key, \
         connector_description, connector_supports, connector_configured, connector_verified, \
         connector_accepts_host_only, connector_accepts_api_key, \
         connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES (?, '3', \
         ?, UTC_TIMESTAMP(), ?, ?, NULL, 'e2e', 'e2e', 1, 1, 0, 0, 1, 0, 0, NULL, 1)",
    )
    .bind(name)
    .bind(url)
    .bind(user)
    .bind(pass)
    .execute(h.db.pool())
    .await
    .unwrap();
}

async fn restore_connectors(h: &Harness, saved: Vec<ConnectorRow>) {
    h.exec(
        "DELETE FROM connectors WHERE connector_name IN ('Wazuh-Manager', 'Graylog', 'Grafana')",
    )
    .await;
    for (name, url, user, pass) in saved {
        insert_connector(
            h,
            &name,
            url.as_deref().unwrap_or_default(),
            user.as_deref(),
            pass.as_deref(),
        )
        .await;
    }
}

// --- rows ------------------------------------------------------------------------

/// Every row this suite may have written: the seeded id ranges and whatever
/// the routes created for the harness's customers.
async fn wipe(h: &Harness) {
    let codes = format!("'{}', '{}'", h.code("acme"), h.code("beta"));
    let ids = |sql: String| async move {
        let found: Vec<i32> = sqlx::query_scalar(&sql)
            .fetch_all(h.db.pool())
            .await
            .unwrap();
        let mut list: Vec<String> = found.iter().map(i32::to_string).collect();
        list.push("0".into());
        list.join(", ")
    };
    let services = ids(format!(
        "SELECT s.integration_service_id FROM integration_subscriptions s JOIN \
         customer_integrations c ON c.id = s.customer_id WHERE c.customer_code IN ({codes})"
    ))
    .await;
    let network_services = ids(format!(
        "SELECT s.network_connectors_service_id FROM network_connectors_subscriptions s JOIN \
         customer_network_connectors c ON c.id = s.customer_id WHERE c.customer_code IN ({codes})"
    ))
    .await;
    for sql in [
        format!(
            "DELETE FROM integration_auth_keys WHERE id BETWEEN 7521400 AND 7521499 OR \
             subscription_id IN (SELECT s.id FROM integration_subscriptions s JOIN \
             customer_integrations c ON c.id = s.customer_id WHERE c.customer_code IN ({codes}))"
        ),
        format!(
            "DELETE FROM integration_subscriptions WHERE id BETWEEN 7521300 AND 7521399 OR \
             customer_id IN (SELECT id FROM customer_integrations WHERE customer_code IN \
             ({codes}))"
        ),
        format!(
            "DELETE FROM integration_configs WHERE id BETWEEN 7521200 AND 7521299 OR \
             integration_service_id IN ({services})"
        ),
        format!(
            "DELETE FROM integration_services WHERE id BETWEEN 7521100 AND 7521199 OR id IN \
             ({services})"
        ),
        format!(
            "DELETE FROM customer_integrations WHERE id BETWEEN 7521000 AND 7521099 OR \
             customer_code IN ({codes})"
        ),
        format!(
            "DELETE FROM customer_integrations_meta WHERE id BETWEEN 7521500 AND 7521599 OR \
             customer_code IN ({codes})"
        ),
        "DELETE FROM available_integrations_auth_keys WHERE integration_id BETWEEN 7520000 AND \
         7520099"
            .to_string(),
        "DELETE FROM available_integrations WHERE id BETWEEN 7520000 AND 7520099".to_string(),
        format!(
            "DELETE FROM network_connectors_keys WHERE id BETWEEN 7522400 AND 7522499 OR \
             subscription_id IN (SELECT s.id FROM network_connectors_subscriptions s JOIN \
             customer_network_connectors c ON c.id = s.customer_id WHERE c.customer_code IN \
             ({codes}))"
        ),
        format!(
            "DELETE FROM network_connectors_subscriptions WHERE id BETWEEN 7522300 AND 7522399 \
             OR customer_id IN (SELECT id FROM customer_network_connectors WHERE customer_code \
             IN ({codes}))"
        ),
        format!(
            "DELETE FROM network_connectors_configs WHERE id BETWEEN 7522200 AND 7522299 OR \
             network_connector_service_id IN ({network_services})"
        ),
        format!(
            "DELETE FROM network_connectors_services WHERE id BETWEEN 7522100 AND 7522199 OR id \
             IN ({network_services})"
        ),
        format!(
            "DELETE FROM customer_network_connectors WHERE id BETWEEN 7522000 AND 7522099 OR \
             customer_code IN ({codes})"
        ),
        format!(
            "DELETE FROM customer_network_connectors_meta WHERE id BETWEEN 7522500 AND 7522599 \
             OR customer_code IN ({codes})"
        ),
        "DELETE FROM available_network_connectors_keys WHERE network_connector_id BETWEEN \
         7520100 AND 7520199"
            .to_string(),
        "DELETE FROM available_network_connectors WHERE id BETWEEN 7520100 AND 7520199".to_string(),
        format!(
            "DELETE FROM custom_alert_creation_condition WHERE event_order_id IN (SELECT o.id \
             FROM custom_alert_creation_event_order o JOIN custom_alert_creation_settings s ON \
             s.id = o.alert_creation_settings_id WHERE s.customer_code IN ({codes}))"
        ),
        format!(
            "DELETE FROM custom_alert_creation_event_config WHERE event_order_id IN (SELECT o.id \
             FROM custom_alert_creation_event_order o JOIN custom_alert_creation_settings s ON \
             s.id = o.alert_creation_settings_id WHERE s.customer_code IN ({codes}))"
        ),
        format!(
            "DELETE FROM custom_alert_creation_event_order WHERE alert_creation_settings_id IN \
             (SELECT id FROM custom_alert_creation_settings WHERE customer_code IN ({codes}))"
        ),
        format!(
            "DELETE FROM custom_alert_creation_settings WHERE id BETWEEN 7523000 AND 7523099 OR \
             customer_code IN ({codes})"
        ),
        format!("DELETE FROM customersmeta WHERE customer_code IN ({codes})"),
    ] {
        h.exec(&sql).await;
    }
}

/// The harness's customers with their metadata (`customersmeta`), the
/// catalog this suite uses, then its own integrations.
async fn seed(h: &Harness, o365_org_of_acme: Option<&str>) {
    h.seed().await;
    wipe(h).await;
    for (c, org) in [("acme", o365_org_of_acme), ("beta", None)] {
        h.exec(&format!(
            "INSERT INTO customersmeta (customer_code, customer_name, \
             customer_meta_graylog_index, customer_meta_graylog_stream, \
             customer_meta_grafana_org_id, customer_meta_wazuh_group, \
             customer_meta_office365_organization_id) VALUES ('{}', '{c} corp', 'i', 's', '1', \
             'g', {})",
            h.code(c),
            lit(org)
        ))
        .await;
    }
    let tool = tool(h);
    for (id, name, keys) in [
        (
            7520001,
            "Office365",
            vec!["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"],
        ),
        (7520002, tool.as_str(), vec!["API_KEY"]),
    ] {
        h.exec(&format!(
            "INSERT INTO available_integrations (id, integration_name, description, \
             integration_details) VALUES ({id}, '{name}', 'd', 'x')"
        ))
        .await;
        for (j, key) in keys.iter().enumerate() {
            h.exec(&format!(
                "INSERT INTO available_integrations_auth_keys (id, integration_id, \
                 integration_name, auth_key_name) VALUES ({}, {id}, '{name}', '{key}')",
                (id - 7520000) * 10 + 7520000 + j as i64
            ))
            .await;
        }
    }
}

/// A single-instance integration only this harness's catalog has.
fn tool(h: &Harness) -> String {
    format!("E2eTool{}", h.suffix)
}

/// One customer integration (`n` picks its ids) with a subscription per key.
#[allow(clippy::too_many_arguments)]
async fn integration(
    h: &Harness,
    n: i64,
    customer: &str,
    name: &str,
    instance: Option<&str>,
    deployed: bool,
    keys: &[(&str, &str)],
) {
    let (ci, svc) = (7521000 + n, 7521100 + n);
    h.exec(&format!(
        "INSERT INTO integration_services (id, service_name, auth_type) VALUES ({svc}, \
         '{name}', 'OAuth')"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO integration_configs (id, integration_service_id, config_key, config_value) \
         VALUES ({}, {svc}, 'endpoint', 'https://x')",
        7521200 + n
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO customer_integrations (id, customer_code, customer_name, \
         integration_service_id, integration_service_name, instance_name, deployed) VALUES \
         ({ci}, '{}', '{customer} corp', 7520001, '{name}', {}, {})",
        h.code(customer),
        lit(instance),
        u8::from(deployed)
    ))
    .await;
    for (j, (key, value)) in keys.iter().enumerate() {
        let sub = 7521300 + n * 10 + j as i64;
        h.exec(&format!(
            "INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) \
             VALUES ({sub}, {ci}, {svc})"
        ))
        .await;
        h.exec(&format!(
            "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) \
             VALUES ({}, {sub}, '{key}', '{value}')",
            7521400 + n * 10 + j as i64
        ))
        .await;
    }
}

/// The metadata of a deployed integration.
#[allow(clippy::too_many_arguments)]
async fn meta(
    h: &Harness,
    id: i64,
    customer: &str,
    name: &str,
    instance: Option<&str>,
    stream: &str,
    index: &str,
    folder: &str,
    datasource: Option<&str>,
) {
    h.exec(&format!(
        "INSERT INTO customer_integrations_meta (id, customer_code, integration_name, \
         instance_name, graylog_input_id, graylog_index_id, graylog_stream_id, grafana_org_id, \
         grafana_dashboard_folder_id, grafana_datasource_uid) VALUES ({id}, '{}', '{name}', {}, \
         NULL, '{index}', '{stream}', '7', '{folder}', {})",
        h.code(customer),
        lit(instance),
        lit(datasource)
    ))
    .await;
}

async fn count(h: &Harness, sql: &str) -> i64 {
    h.scalar_i64(&format!("SELECT COUNT(*) FROM {sql}")).await
}

fn o365_keys(tenant: &str) -> Vec<Value> {
    vec![
        json!({"auth_key_name": "TENANT_ID", "auth_value": tenant}),
        json!({"auth_key_name": "CLIENT_ID", "auth_value": "c"}),
        json!({"auth_key_name": "CLIENT_SECRET", "auth_value": "s"}),
    ]
}

fn create_body(code: &str, name: &str, instance: Option<&str>, keys: Vec<Value>) -> Value {
    let mut body = json!({
        "customer_code": code,
        "customer_name": "Acme",
        "integration_name": name,
        "integration_config": {"auth_type": "OAuth", "config_key": "k", "config_value": "v"},
        "integration_auth_keys": keys,
    });
    if let Some(i) = instance {
        body["instance_name"] = json!(i);
    }
    body
}

// --- Wazuh ---------------------------------------------------------------------------

fn ossec(tenants: &[&str]) -> String {
    let blocks: String = tenants
        .iter()
        .map(|t| {
            format!(
                "\n    <api_auth>\n      <tenant_id>{t}</tenant_id>\n      \
                 <client_id>c</client_id>\n    </api_auth>"
            )
        })
        .collect();
    format!(
        "<ossec_config>\n  <global>\n    <jsonout_output>yes</jsonout_output>\n  </global>\n  \
         <office365>\n    <enabled>yes</enabled>{blocks}\n  </office365>\n</ossec_config>"
    )
}

/// The manager: a token, `config` as `ossec.conf`, and a write and a restart
/// that succeed.
async fn wazuh_manager(server: &MockServer, config: &str, writes: u64) {
    Mock::given(method("GET"))
        .and(path("/security/user/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "e2e"}, "error": 0})),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/manager/configuration"))
        .and(query_param("raw", "True"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(config.to_string(), "text/plain; charset=utf-8"),
        )
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/manager/configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data": {"affected_items": ["manager"], "total_affected_items": 1}, "error": 0}),
        ))
        .expect(writes)
        .mount(server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/manager/restart"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"affected_items": ["manager"]}, "error": 0})),
        )
        .expect(writes)
        .mount(server)
        .await;
}

/// The `ossec.conf` the manager was sent.
async fn written_config(server: &MockServer) -> String {
    let requests = server.received_requests().await.unwrap();
    let put = requests
        .iter()
        .find(|r| r.method.as_str() == "PUT" && r.url.path() == "/manager/configuration")
        .expect("no configuration written");
    assert_eq!(
        put.headers.get("content-type").unwrap(),
        "application/octet-stream"
    );
    String::from_utf8(put.body.clone()).unwrap()
}

// --- the tests ---------------------------------------------------------------------------

/// The unnamed instance (NULL) and named ones are different rows; a second
/// unnamed one is refused, a blank name is the unnamed one, and a route that
/// names no instance refuses to pick one of several.
#[tokio::test]
async fn office365_instances_are_told_apart_by_name() {
    let h = harness_or_skip!(None);
    seed(&h, None).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    integration(
        &h,
        1,
        "acme",
        "Office365",
        None,
        false,
        &[
            ("TENANT_ID", "t-a"),
            ("CLIENT_ID", "c"),
            ("CLIENT_SECRET", "s"),
        ],
    )
    .await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let url = "/api/integrations/create_integration";

    for instance in [None, Some("   ")] {
        let (status, body) = h
            .call(
                "POST",
                url,
                Some(&admin),
                Some(create_body(&acme, "Office365", instance, o365_keys("t-x"))),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body["message"],
            format!(
                "Customer {acme} already has a Office365 integration. Provide an instance name \
                 to add another one."
            )
        );
    }
    let (status, body) = h
        .call(
            "POST",
            url,
            Some(&admin),
            Some(create_body(
                &acme,
                "Office365",
                Some(" tenant-b "),
                o365_keys("t-b"),
            )),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"message": format!("Customer integration {acme} Office365 successfully created."), "success": true, "additional_info": null})
    );
    assert_eq!(
        count(&h, &format!("customer_integrations WHERE customer_code = '{acme}' AND instance_name = 'tenant-b'")).await,
        1
    );
    let (status, body) = h
        .call(
            "POST",
            url,
            Some(&admin),
            Some(create_body(
                &acme,
                "Office365",
                Some("tenant-b"),
                o365_keys("t-b"),
            )),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        format!("Customer integration {acme} Office365 'tenant-b' already exists.")
    );
    // A single-instance integration takes no name.
    let (status, body) = h
        .call(
            "POST",
            url,
            Some(&admin),
            Some(create_body(
                &acme,
                &tool(&h),
                Some("x"),
                vec![json!({"auth_key_name": "API_KEY", "auth_value": "k"})],
            )),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        format!(
            "{} does not support multiple instances per customer.",
            tool(&h)
        )
    );

    // Two instances: a route without a name refuses to choose.
    let update = format!("/api/integrations/update_integration/{acme}");
    let keys = json!([{"auth_key_name": "CLIENT_SECRET", "auth_value": "rotated"}]);
    let (status, body) = h
        .call(
            "PUT",
            &update,
            Some(&admin),
            Some(json!({"integration_name": "Office365", "integration_auth_keys": keys})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        format!(
            "Customer {acme} has 2 Office365 instances (tenant-b, unnamed). Specify which one."
        )
    );
    let (status, body) = h
        .call(
            "PUT",
            &update,
            Some(&admin),
            Some(json!({"integration_name": "Office365", "instance_name": "tenant-b", "integration_auth_keys": keys})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        count(&h, &format!(
            "integration_auth_keys k JOIN integration_subscriptions s ON s.id = k.subscription_id JOIN \
             customer_integrations c ON c.id = s.customer_id WHERE c.customer_code = '{acme}' AND \
             k.auth_value = 'rotated' AND c.instance_name = 'tenant-b'"
        ))
        .await,
        1
    );
    // By the instance, not the seeded id range: tenant-b's keys were created
    // through the API and take AUTO_INCREMENT ids, which fall inside that
    // range on a database whose counter is still below it.
    assert_eq!(
        count(&h, &format!(
            "integration_auth_keys k JOIN integration_subscriptions s ON s.id = k.subscription_id JOIN \
             customer_integrations c ON c.id = s.customer_id WHERE c.customer_code = '{acme}' AND \
             k.auth_value = 'rotated' AND c.instance_name IS NULL"
        ))
        .await,
        0,
        "the unnamed instance's secret was left alone"
    );

    // Another tenant's customer, named in the body or the path: 403.
    let (status, body) = h
        .call(
            "POST",
            url,
            Some(&analyst),
            Some(create_body(
                &beta,
                &tool(&h),
                None,
                vec![json!({"auth_key_name": "API_KEY", "auth_value": "k"})],
            )),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        count(
            &h,
            &format!("customer_integrations WHERE customer_code = '{beta}'")
        )
        .await,
        0
    );
    let (status, _) = h
        .call(
            "PUT",
            &format!("/api/integrations/update_integration/{beta}"),
            Some(&analyst),
            Some(json!({"integration_name": "Office365", "integration_auth_keys": keys})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    wipe(&h).await;
}

/// Lists without a customer show a scoped caller their customers only, and
/// the auth-key lookup does not name another tenant's customer.
#[tokio::test]
async fn lists_and_lookups_are_narrowed_to_the_caller() {
    let h = harness_or_skip!(None);
    seed(&h, None).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let tool = tool(&h);
    integration(&h, 1, "acme", &tool, None, false, &[("API_KEY", "k-acme")]).await;
    integration(&h, 2, "beta", &tool, None, false, &[("API_KEY", "k-beta")]).await;
    meta(&h, 7521501, "beta", &tool, None, "st", "is", "f", None).await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");

    let codes = |body: &Value, key: &str| -> Vec<String> {
        body[key]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|i| i["customer_code"].as_str())
            .filter(|c| *c == acme || *c == beta)
            .map(str::to_string)
            .collect()
    };
    let (status, body) = h
        .call(
            "GET",
            "/api/integrations/customer_integrations",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        codes(&body, "available_integrations"),
        [acme.clone(), beta.clone()]
    );
    let (_, body) = h
        .call(
            "GET",
            "/api/integrations/customer_integrations",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        codes(&body, "available_integrations"),
        std::slice::from_ref(&acme)
    );
    let (_, body) = h
        .call(
            "GET",
            "/api/integrations/customer_integrations_meta",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        codes(&body, "customer_integrations_meta"),
        Vec::<String>::new()
    );
    let (_, body) = h
        .call(
            "GET",
            "/api/integrations/customer_integrations_meta",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        codes(&body, "customer_integrations_meta"),
        std::slice::from_ref(&beta)
    );

    let lookup =
        |value: &str| format!("/api/integrations/integration_customer/{tool}/API_KEY/{value}");
    let (status, body) = h.call("GET", &lookup("k-acme"), Some(&analyst), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["customer_code"], json!(acme));
    let (status, _) = h.call("GET", &lookup("k-beta"), Some(&analyst), None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another tenant's key reads as unknown"
    );
    let (status, body) = h.call("GET", &lookup("k-beta"), Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["customer_code"], json!(beta));
    wipe(&h).await;
}

/// Deleting one of two deployed tenants removes its stream only (the index
/// set and Grafana are shared), its `<api_auth>` block, and the legacy
/// single-tenant columns that named it.
#[tokio::test]
async fn deleting_a_tenant_with_a_deployed_sibling_removes_its_stream_only() {
    if !configured() {
        return;
    }
    let (wazuh, graylog, grafana) = (
        stand_in(WAZUH).await,
        stand_in(GRAYLOG).await,
        stand_in(GRAFANA).await,
    );
    let h = harness_or_skip!(None);
    let saved = swap_connectors(&h).await;
    seed(&h, Some("t-b")).await;
    let acme = h.code("acme");
    integration(
        &h,
        1,
        "acme",
        "Office365",
        None,
        true,
        &[("TENANT_ID", "t-a"), ("CLIENT_ID", "c")],
    )
    .await;
    integration(
        &h,
        2,
        "acme",
        "Office365",
        Some("tenant-b"),
        true,
        &[("TENANT_ID", "t-b"), ("CLIENT_ID", "c")],
    )
    .await;
    meta(
        &h,
        7521501,
        "acme",
        "Office365",
        None,
        "st-a",
        "is-o365",
        "70",
        Some("ds-o365"),
    )
    .await;
    meta(
        &h,
        7521502,
        "acme",
        "Office365",
        Some("tenant-b"),
        "st-b",
        "is-o365",
        "70",
        Some("ds-o365"),
    )
    .await;
    h.exec(&format!(
        "INSERT INTO custom_alert_creation_settings (id, customer_code, customer_name, \
         excluded_wazuh_rules, office365_organization_id, iris_customer_id, timefield, nvd_url) \
         VALUES (7523001, '{acme}', 'Acme {}', '', 't-b', 1, 'timestamp', 'n')",
        h.suffix
    ))
    .await;

    wazuh_manager(&wazuh, &ossec(&["t-a", "t-b"]), 1).await;
    Mock::given(method("DELETE"))
        .and(path("/api/streams/st-b"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&graylog)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&grafana)
        .await;

    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (status, body) = h
        .call(
            "DELETE",
            "/api/integrations/delete_integration",
            Some(&admin),
            Some(json!({"customer_code": acme, "integration_name": "Office365", "instance_name": " tenant-b "})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"message": format!("Customer integration {acme} Office365 successfully deleted."), "success": true, "additional_info": null})
    );
    let config = written_config(&wazuh).await;
    assert!(config.contains("<tenant_id>t-a</tenant_id>"), "{config}");
    assert!(!config.contains("t-b"), "{config}");
    assert!(
        config.contains("<office365>"),
        "the block keeps its other tenant: {config}"
    );
    assert_eq!(
        count(&h, "customer_integrations WHERE id = 7521002").await,
        0
    );
    assert_eq!(
        count(&h, "customer_integrations WHERE id = 7521001").await,
        1
    );
    assert_eq!(
        count(&h, "customer_integrations_meta WHERE id = 7521502").await,
        0
    );
    assert_eq!(
        count(&h, "customer_integrations_meta WHERE id = 7521501").await,
        1
    );
    assert_eq!(
        count(&h, "custom_alert_creation_settings WHERE id = 7523001 AND office365_organization_id IS NULL").await,
        1
    );
    assert_eq!(
        count(&h, &format!("customersmeta WHERE customer_code = '{acme}' AND customer_meta_office365_organization_id IS NULL")).await,
        1
    );
    wipe(&h).await;
    restore_connectors(&h, saved).await;
}

/// Deleting the customer's last deployed tenant removes the stream, the
/// shared index set, the Grafana folder and datasource, and the whole
/// `<office365>` block.
#[tokio::test]
async fn deleting_the_last_tenant_removes_the_shared_infrastructure() {
    if !configured() {
        return;
    }
    let (wazuh, graylog, grafana) = (
        stand_in(WAZUH).await,
        stand_in(GRAYLOG).await,
        stand_in(GRAFANA).await,
    );
    let h = harness_or_skip!(None);
    let saved = swap_connectors(&h).await;
    seed(&h, None).await;
    let acme = h.code("acme");
    integration(
        &h,
        1,
        "acme",
        "Office365",
        None,
        true,
        &[("TENANT_ID", "t-a"), ("CLIENT_ID", "c")],
    )
    .await;
    meta(
        &h,
        7521501,
        "acme",
        "Office365",
        None,
        "st-a",
        "is-o365",
        "70",
        Some("ds-o365"),
    )
    .await;

    wazuh_manager(&wazuh, &ossec(&["t-a"]), 1).await;
    for p in [
        "/api/streams/st-a",
        "/api/system/indices/index_sets/is-o365",
    ] {
        Mock::given(method("DELETE"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&graylog)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/api/user/using/7"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "Active organization changed"})),
        )
        .expect(2)
        .mount(&grafana)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/folders"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{"id": 70, "uid": "f70", "title": "Office365"}])),
        )
        .expect(1)
        .mount(&grafana)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/folders/f70"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "Folder deleted", "id": 70})),
        )
        .expect(1)
        .mount(&grafana)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/datasources/uid/ds-o365"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"message": "Data source deleted"})),
        )
        .expect(1)
        .mount(&grafana)
        .await;

    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (status, body) = h
        .call(
            "DELETE",
            "/api/integrations/delete_integration",
            Some(&admin),
            Some(json!({"customer_code": acme, "integration_name": "Office365"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["additional_info"], Value::Null, "{body}");
    let config = written_config(&wazuh).await;
    assert!(!config.contains("office365"), "{config}");
    assert!(
        config.contains("<jsonout_output>yes</jsonout_output>"),
        "{config}"
    );
    assert_eq!(
        count(
            &h,
            &format!("customer_integrations WHERE customer_code = '{acme}'")
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &h,
            &format!("customer_integrations_meta WHERE customer_code = '{acme}'")
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &h,
            "integration_subscriptions WHERE id BETWEEN 7521300 AND 7521399"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &h,
            "integration_services WHERE id BETWEEN 7521100 AND 7521199"
        )
        .await,
        0
    );
    wipe(&h).await;
    restore_connectors(&h, saved).await;
}

/// A failing manager or Graylog never fails the delete: each becomes a
/// warning in `additional_info`, and the rows go.
#[tokio::test]
async fn upstream_failures_become_warnings() {
    if !configured() {
        return;
    }
    let (wazuh, graylog, _grafana) = (
        stand_in(WAZUH).await,
        stand_in(GRAYLOG).await,
        stand_in(GRAFANA).await,
    );
    let h = harness_or_skip!(None);
    let saved = swap_connectors(&h).await;
    seed(&h, None).await;
    let acme = h.code("acme");
    integration(
        &h,
        1,
        "acme",
        "Office365",
        None,
        true,
        &[("TENANT_ID", "t-a"), ("CLIENT_ID", "c")],
    )
    .await;
    integration(
        &h,
        2,
        "acme",
        "Office365",
        Some("b"),
        true,
        &[("TENANT_ID", "t-b"), ("CLIENT_ID", "c")],
    )
    .await;
    meta(
        &h,
        7521502,
        "acme",
        "Office365",
        Some("b"),
        "st-b",
        "is-o365",
        "70",
        None,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/security/user/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "e2e"}})))
        .mount(&wazuh)
        .await;
    Mock::given(method("GET"))
        .and(path("/manager/configuration"))
        .respond_with(ResponseTemplate::new(500).set_body_string("down"))
        .mount(&wazuh)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&wazuh)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/streams/st-b"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"type": "ApiError", "message": "Stream not found"})),
        )
        .expect(1)
        .mount(&graylog)
        .await;

    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (status, body) = h
        .call(
            "DELETE",
            "/api/integrations/delete_integration",
            Some(&admin),
            Some(json!({"customer_code": acme, "integration_name": "Office365", "instance_name": "b"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let info = body["additional_info"].as_str().unwrap();
    assert!(
        info.starts_with("Could not delete Graylog stream st-b: 404: "),
        "{info}"
    );
    assert!(
        info.contains(
            "Could not remove the Office365 api_auth block for tenant t-b from the Wazuh manager ("
        ),
        "{info}"
    );
    assert!(
        info.ends_with("Remove it from ossec.conf and restart the manager."),
        "{info}"
    );
    assert_eq!(
        count(&h, "customer_integrations WHERE id = 7521002").await,
        0
    );
    wipe(&h).await;
    restore_connectors(&h, saved).await;
}

/// A deployed AWS account is decommissioned by Python (its ossec.conf
/// reconcile shares a lock with AWS provisioning): the request goes there
/// whole and its answer comes back; an undeployed one is deleted in Rust.
#[tokio::test]
async fn deployed_aws_delete_is_handed_to_python() {
    if !configured() {
        return;
    }
    let legacy = stand_in(LEGACY).await;
    let h = harness_or_skip!(Some(&legacy));
    seed(&h, None).await;
    let acme = h.code("acme");
    integration(
        &h,
        1,
        "acme",
        "AWS",
        Some("acct-1"),
        false,
        &[("AWS_ACCOUNT_ID", "111")],
    )
    .await;
    integration(
        &h,
        2,
        "acme",
        "AWS",
        Some("acct-2"),
        true,
        &[("AWS_ACCOUNT_ID", "222")],
    )
    .await;
    let deployed =
        json!({"customer_code": acme, "integration_name": "AWS", "instance_name": "acct-2"});
    Mock::given(method("DELETE"))
        .and(path("/api/integrations/delete_integration"))
        .and(body_json(&deployed))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"message": "answered by Python", "success": true, "additional_info": null}),
        ))
        .expect(1)
        .mount(&legacy)
        .await;

    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (status, body) = h
        .call(
            "DELETE",
            "/api/integrations/delete_integration",
            Some(&admin),
            Some(deployed),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "answered by Python");
    assert_eq!(
        count(&h, "customer_integrations WHERE id = 7521002").await,
        1,
        "Rust left it to Python"
    );

    let (status, body) = h
        .call(
            "DELETE",
            "/api/integrations/delete_integration",
            Some(&admin),
            Some(json!({"customer_code": acme, "integration_name": "AWS", "instance_name": "acct-1"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["message"],
        format!("Customer integration {acme} AWS successfully deleted.")
    );
    assert_eq!(
        count(&h, "customer_integrations WHERE id = 7521001").await,
        0
    );
    wipe(&h).await;
}

/// Alert creation settings are addressed by the customer's *name*: the name
/// resolves to its owner, which the caller must see; an unknown name is
/// refused to a scoped caller (fail closed) and missing for an admin.
#[tokio::test]
async fn alert_settings_are_scoped_by_customer_name() {
    let h = harness_or_skip!(None);
    seed(&h, None).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let (acme_name, beta_name) = (format!("Acme {}", h.suffix), format!("Beta {}", h.suffix));
    for (id, code, name) in [(7523001, &acme, &acme_name), (7523002, &beta, &beta_name)] {
        h.exec(&format!(
            "INSERT INTO custom_alert_creation_settings (id, customer_code, customer_name, \
             excluded_wazuh_rules, iris_customer_id, timefield, nvd_url) VALUES ({id}, '{code}', \
             '{name}', '1', 1, 'timestamp', 'n')"
        ))
        .await;
        h.exec(&format!(
            "INSERT INTO custom_alert_creation_event_order (id, alert_creation_settings_id, \
             order_label) VALUES ({}, {id}, 'L1')",
            id + 100
        ))
        .await;
        h.exec(&format!(
            "INSERT INTO custom_alert_creation_event_config (id, event_order_id, event_id, field, \
             value) VALUES ({}, {}, 'e1', 'f', 'v')",
            id + 200,
            id + 100
        ))
        .await;
    }
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let base = "/api/api/v1/alert_settings";
    let enc = |n: &str| n.replace(' ', "%20");

    let (status, body) = h
        .call(
            "GET",
            &format!("{base}/{}", enc(&acme_name)),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["customer_code"], json!(acme));
    assert_eq!(
        body["event_orders"],
        json!([{"order_label": "L1", "event_configs": [{"event_id": "e1", "field": "f", "value": "v"}]}])
    );
    // MySQL compares names without case; so does the tenancy check's lookup.
    let (status, _) = h
        .call(
            "GET",
            &format!("{base}/{}", enc(&acme_name.to_uppercase())),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let beta_path = format!("{base}/{}", enc(&beta_name));
    for (verb, uri, body) in [
        ("GET", beta_path.clone(), None),
        (
            "POST",
            format!("{beta_path}/event"),
            Some(json!({"order_label": "L9", "event_configs": []})),
        ),
        (
            "PUT",
            beta_path.clone(),
            Some(json!([{"order_label": "L1", "event_configs": []}])),
        ),
        ("DELETE", format!("{beta_path}/event/L1"), None),
        ("GET", format!("{base}/{beta}/event_configs"), None),
    ] {
        let (status, body) = h.call(verb, &uri, Some(&analyst), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{verb} {uri}: {body}");
    }
    assert_eq!(
        count(&h, "custom_alert_creation_event_order WHERE id = 7523102").await,
        1,
        "B's order kept"
    );

    let unknown = format!("{base}/{}", enc(&format!("Nobody {}", h.suffix)));
    let (status, _) = h.call("GET", &unknown, Some(&analyst), None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an unknown name is no permission"
    );
    let (status, body) = h.call("GET", &unknown, Some(&admin), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["message"], "Alert creation settings not found.");

    // The body's customer code is the tenant of `/create`.
    let (status, _) = h
        .call(
            "POST",
            &format!("{base}/create"),
            Some(&analyst),
            Some(json!({"customer_code": beta, "customer_name": "x", "excluded_wazuh_rules": "", "timefield": "t", "iris_customer_id": 1, "event_orders": []})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The analyst's own: an order added, then configs appended to it.
    let acme_path = format!("{base}/{}", enc(&acme_name));
    let (status, body) = h
        .call("POST", &format!("{acme_path}/event"), Some(&analyst), Some(json!({"order_label": "L2", "event_configs": [{"event_id": "e2", "field": "f", "value": "v"}]})))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["order_label"], "L2");
    let (status, body) = h
        .call("PUT", &acme_path, Some(&analyst), Some(json!([{"order_label": "L1", "event_configs": [{"event_id": "e9", "field": "f", "value": "v"}]}])))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let l1 = body["event_orders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["order_label"] == "L1")
        .unwrap()
        .clone();
    assert_eq!(l1["event_configs"].as_array().unwrap().len(), 2, "{body}");
    let (status, body) = h
        .call(
            "DELETE",
            &format!("{acme_path}/event/L1"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["message"],
        "Event order with order_label: L1 and related alert creation event configs deleted."
    );
    assert_eq!(
        count(&h, "custom_alert_creation_event_order WHERE id = 7523101").await,
        0
    );
    wipe(&h).await;
}

/// Network connectors: lists narrowed to the caller's customers, and the
/// body's customer checked on create and delete.
#[tokio::test]
async fn network_connectors_are_scoped_to_the_caller() {
    let h = harness_or_skip!(None);
    seed(&h, None).await;
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let name = format!("E2eNet{}", h.suffix);
    h.exec(&format!(
        "INSERT INTO available_network_connectors (id, network_connector_name, description, \
         network_connector_details) VALUES (7520101, '{name}', 'd', 'x')"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO available_network_connectors_keys (id, network_connector_id, \
         network_connector_name, auth_key_name) VALUES (7520111, 7520101, '{name}', 'PORT')"
    ))
    .await;
    for (n, code) in [(1, &acme), (2, &beta)] {
        h.exec(&format!(
            "INSERT INTO network_connectors_services (id, service_name, auth_type) VALUES ({}, \
             '{name}', 'syslog')",
            7522100 + n
        ))
        .await;
        h.exec(&format!(
            "INSERT INTO customer_network_connectors (id, customer_code, customer_name, \
             network_connector_service_id, network_connector_service_name, deployed) VALUES ({}, \
             '{code}', 'c', 7520101, '{name}', 0)",
            7522000 + n
        ))
        .await;
        h.exec(&format!(
            "INSERT INTO network_connectors_subscriptions (id, customer_id, \
             network_connectors_service_id) VALUES ({}, {}, {})",
            7522300 + n,
            7522000 + n,
            7522100 + n
        ))
        .await;
        h.exec(&format!(
            "INSERT INTO network_connectors_keys (id, subscription_id, auth_key_name, auth_value) \
             VALUES ({}, {}, 'PORT', '514')",
            7522400 + n,
            7522300 + n
        ))
        .await;
    }
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let ours = |body: &Value| -> Vec<String> {
        body["available_network_connectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["customer_code"].as_str())
            .filter(|c| *c == acme || *c == beta)
            .map(str::to_string)
            .collect()
    };
    let list = "/api/network_connectors/customer_network_connectors";
    let (status, body) = h.call("GET", list, Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ours(&body), [acme.clone(), beta.clone()]);
    let (_, body) = h.call("GET", list, Some(&analyst), None).await;
    assert_eq!(ours(&body), std::slice::from_ref(&acme));

    let (status, _) = h
        .call(
            "POST",
            "/api/network_connectors/create_network_connector",
            Some(&analyst),
            Some(json!({
                "customer_code": beta, "customer_name": "b", "network_connector_name": name,
                "network_connector_config": {"auth_type": "syslog", "config_key": "k", "config_value": "v"},
                "network_connector_auth_keys": [{"auth_key_name": "PORT", "auth_value": "1"}],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let delete = json!({"customer_code": beta, "network_connector_name": name});
    let (status, _) = h
        .call(
            "DELETE",
            "/api/network_connectors/delete_network_connector",
            Some(&analyst),
            Some(delete.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        count(&h, "customer_network_connectors WHERE id = 7522002").await,
        1
    );
    let (status, body) = h
        .call(
            "DELETE",
            "/api/network_connectors/delete_network_connector",
            Some(&admin),
            Some(delete),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        count(&h, "customer_network_connectors WHERE id = 7522002").await,
        0
    );
    assert_eq!(
        count(&h, "network_connectors_keys WHERE id = 7522402").await,
        0
    );
    wipe(&h).await;
}

/// The catalog PUT answers its 400 after committing (Python's response
/// model refuses the table-model rows); a numeric name never poisons later
/// lookups by name on the same connection.
#[tokio::test]
async fn catalog_put_with_a_numeric_name_leaves_name_lookups_intact() {
    let h = harness_or_skip!(None);
    seed(&h, None).await;
    let acme = h.code("acme");
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let tool = tool(&h);
    for _ in 0..12 {
        let (status, _) = h
            .call(
                "PUT",
                "/api/integrations/available_integrations",
                Some(&admin),
                Some(json!([{"integration_name": 7520002, "description": "d", "integration_details": "x"}])),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, body) = h
        .call(
            "POST",
            "/api/integrations/create_integration",
            Some(&admin),
            Some(create_body(
                &acme,
                &tool,
                None,
                vec![json!({"auth_key_name": "API_KEY", "auth_value": "k"})],
            )),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        count(&h, &format!(
            "customer_integrations WHERE customer_code = '{acme}' AND integration_service_id = 7520002 \
             AND integration_service_name = '{tool}'"
        ))
        .await,
        1
    );
    let (status, body) = h
        .call(
            "PUT",
            "/api/integrations/available_integrations",
            Some(&admin),
            Some(json!([{"integration_name": tool, "description": "new", "integration_details": "x"}])),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("1 validation error for AvailableIntegrationsResponse"),
        "{body}"
    );
    assert_eq!(
        count(
            &h,
            "available_integrations WHERE id = 7520002 AND description = 'new'"
        )
        .await,
        1
    );
    wipe(&h).await;
}

#[test]
fn ports_come_from_the_suite_range() {
    // The default sits in the integrations suites' range (5840–5849).
    if std::env::var("INTEGRATIONS_E2E_PORT_BASE").is_err() {
        assert_eq!(port(WAZUH), 5840);
        assert_eq!(port(LEGACY), 5843);
    }
}
