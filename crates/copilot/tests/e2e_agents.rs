//! End-to-end tests of `/api/agents` (`copilot-agents`) and the Velociraptor
//! client (`copilot-velociraptor`) against a real MySQL, the Wazuh manager
//! replaced by a mock and Velociraptor by the crate's gRPC stand-in (mutual
//! TLS with its test certificates).
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13308/copilot \
//!   cargo test -p copilot --test e2e_agents -- --test-threads=1
//! ```
//!
//! The tests that need the deployment's `Wazuh-Manager` and `Velociraptor`
//! connector rows create them, point them at the stand-ins and delete them
//! again (the harness runs with the connector cache off).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use copilot_velociraptor::testing::{Answer, StandIn};

#[macro_use]
mod common;
use common::*;

/// `Agents`' columns in declaration order, the order every row is sent in.
const AGENT_FIELDS: [&str; 17] = [
    "id",
    "agent_id",
    "ip_address",
    "os",
    "hostname",
    "label",
    "critical_asset",
    "wazuh_last_seen",
    "velociraptor_id",
    "velociraptor_last_seen",
    "wazuh_agent_version",
    "wazuh_agent_status",
    "velociraptor_agent_version",
    "customer_code",
    "quarantined",
    "velociraptor_org",
    "velociraptor_id_pinned",
];

/// An agent of `customer`; returns its `agent_id`.
async fn agent(
    h: &Harness,
    key: &str,
    hostname: &str,
    customer: &str,
    velociraptor_id: Option<&str>,
) -> String {
    let agent_id = format!("{}{key}", h.suffix);
    sqlx::query(
        "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, wazuh_last_seen, \
         velociraptor_id, velociraptor_last_seen, wazuh_agent_version, wazuh_agent_status, \
         velociraptor_agent_version, customer_code, quarantined, velociraptor_org, velociraptor_id_pinned) \
         VALUES (?, '10.0.0.1', 'Ubuntu', ?, 'grp', 0, '2026-10-15 08:00:00', ?, NULL, 'Wazuh v4.9.0', \
         'active', NULL, ?, 0, NULL, 0)",
    )
    .bind(&agent_id)
    .bind(hostname)
    .bind(velociraptor_id)
    .bind(customer)
    .execute(h.db.pool())
    .await
    .unwrap();
    agent_id
}

async fn cleanup(h: &Harness) {
    let s = &h.suffix;
    for sql in [
        format!("DELETE FROM agents WHERE agent_id LIKE '{s}%' OR hostname LIKE '%{s}%'"),
        format!("DELETE FROM audit_log WHERE entity_type = 'agent' AND entity_id LIKE '{s}%'"),
        "DELETE FROM connectors WHERE connector_name IN ('Wazuh-Manager', 'Velociraptor')"
            .to_string(),
    ] {
        h.exec(&sql).await;
    }
}

/// A connector row; returns its id.
async fn connector(
    h: &Harness,
    name: &str,
    url: &str,
    user: Option<&str>,
    pass: Option<&str>,
    key: Option<&str>,
) -> i64 {
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_username, connector_password, connector_api_key, connector_description, \
         connector_supports, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         (?, '4.8', ?, '2026-01-02 03:04:05', ?, ?, ?, 'desc', 'supports', 1, 1, 0, 0, 1, 1, 0, NULL, 1)",
    )
    .bind(name)
    .bind(url)
    .bind(user)
    .bind(pass)
    .bind(key)
    .execute(h.db.pool())
    .await
    .unwrap()
    .last_insert_id()
    .try_into()
    .unwrap()
}

/// The Wazuh manager's token flow, mounted on `server`.
async fn manager_token(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/security/user/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "tok"}, "error": 0})),
        )
        .mount(server)
        .await;
}

fn agent_ids(body: &Value) -> Vec<String> {
    body["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["agent_id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn reads_follow_the_callers_customers() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let a1 = agent(&h, "a1", &format!("web-{s}"), &acme, None).await;
    let a2 = agent(&h, "a2", &format!("shared-{s}"), &acme, None).await;
    let b1 = agent(&h, "b1", &format!("shared-{s}"), &beta, None).await;
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");

    let (status, body) = h.call("GET", "/api/agents", Some(&analyst), None).await;
    assert_eq!(status, 200);
    let mut seen = agent_ids(&body);
    seen.sort();
    assert_eq!(
        seen,
        [a1.clone(), a2.clone()],
        "the analyst sees acme's agents only"
    );
    let first = body["agents"][0].as_object().unwrap();
    assert_eq!(
        first.keys().map(String::as_str).collect::<Vec<_>>(),
        AGENT_FIELDS
    );
    assert_eq!(body["message"], "Agents fetched successfully");

    let (_, body) = h
        .call(
            "GET",
            &format!("/api/agents?customer_codes={beta}"),
            Some(&analyst),
            None,
        )
        .await;
    assert!(
        agent_ids(&body).is_empty(),
        "asking for another tenant narrows to nothing"
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/agents?customer_codes={beta}&search=SHARED"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(agent_ids(&body), [b1.as_str()]);
    let (status, body) = h
        .call("GET", "/api/agents?limit=0", Some(&analyst), None)
        .await;
    assert_eq!(status, 422, "{body}");

    // Another tenant's agent reads as missing, and the route's `try` turns
    // its 404 into a 500, as in Python.
    let (status, body) = h
        .call("GET", &format!("/api/agents/{b1}"), Some(&portal), None)
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            500,
            json!(format!("Failed to fetch agent: {b1}. Does it exist?"))
        )
    );
    let (status, _) = h
        .call("GET", &format!("/api/agents/{a1}"), Some(&portal), None)
        .await;
    assert_eq!(status, 200);
    let (status, _) = h
        .call(
            "POST",
            &format!("/api/agents/{b1}/critical"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 500);
    let (status, body) = h
        .call(
            "POST",
            &format!("/api/agents/{a1}/critical"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (200, json!(format!("Agent {a1} marked as critical: True")))
    );
    let flagged = h
        .scalar_i64(&format!(
            "SELECT critical_asset FROM agents WHERE agent_id = '{a1}'"
        ))
        .await;
    assert_eq!(flagged, 1);

    // #1256: a hostname is no tenant key.
    let mut cases = Vec::new();
    for (code, name) in [(&acme, "acme case"), (&beta, "beta case")] {
        let alert = h
            .exec(&format!(
                "INSERT INTO incident_management_alert (alert_name, alert_description, status, alert_creation_time, \
                 customer_code, source, escalated) VALUES ('{name}', 'd', 'OPEN', UTC_TIMESTAMP(), '{code}', 'wazuh', 0)"
            ))
            .await;
        let ctx = h
            .exec("INSERT INTO incident_management_alertcontext (source, context) VALUES ('wazuh', '{}')")
            .await;
        h.exec(&format!(
            "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, customer_code, \
             index_name, index_id) VALUES ({alert}, 'shared-{s}', {ctx}, '{code}', 'idx', 'doc')"
        ))
        .await;
        let case = h
            .exec(&format!(
                "INSERT INTO incident_management_case (case_name, case_description, case_creation_time, case_status, \
                 customer_code, notification_invoked_number, escalated) VALUES ('{name}', 'd', UTC_TIMESTAMP(), 'OPEN', \
                 '{code}', 0, 0)"
            ))
            .await;
        h.exec(&format!(
            "INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES ({case}, {alert})"
        ))
        .await;
        cases.push((case, alert, ctx));
    }
    let names = |body: &Value| -> Vec<String> {
        body["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["case_name"].as_str().unwrap().to_string())
            .collect()
    };
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/agents/shared-{s}/cases"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        names(&body),
        ["acme case"],
        "beta's case never shows under acme's agent"
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/agents/shared-{s}/cases"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(names(&body), ["beta case", "acme case"], "newest first");
    let (status, _) = h
        .call(
            "GET",
            &format!("/api/agents/web-{s}x/cases"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 404);

    for (case, alert, ctx) in cases {
        h.exec(&format!(
            "DELETE FROM incident_management_casealertlink WHERE case_id = {case}"
        ))
        .await;
        h.exec(&format!(
            "DELETE FROM incident_management_case WHERE id = {case}"
        ))
        .await;
        h.exec(&format!(
            "DELETE FROM incident_management_asset WHERE alert_linked = {alert}"
        ))
        .await;
        h.exec(&format!(
            "DELETE FROM incident_management_alert WHERE id = {alert}"
        ))
        .await;
        h.exec(&format!(
            "DELETE FROM incident_management_alertcontext WHERE id = {ctx}"
        ))
        .await;
    }
    cleanup(&h).await;
}

#[tokio::test]
async fn deleting_an_agent_reaches_wazuh_and_velociraptor_and_is_audited() {
    let h = harness_or_skip!(None);
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let client_id = format!("C.{s}");
    let a1 = agent(&h, "d1", &format!("del-{s}"), &acme, Some(&client_id)).await;
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    let mgr = MockServer::start().await;
    manager_token(&mgr).await;
    Mock::given(method("DELETE"))
        .and(path("/agents"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"affected_items": [a1.clone()]}, "error": 0})),
        )
        .mount(&mgr)
        .await;
    let velo = StandIn::start(|_| Answer::rows(&[r#"[{"flow": "F.1"}]"#])).await;
    let dir = tempfile::tempdir().unwrap();
    let config = velo.write_api_config(dir.path());
    connector(
        &h,
        "Wazuh-Manager",
        &mgr.uri(),
        Some("wazuh"),
        Some("pw"),
        None,
    )
    .await;
    connector(
        &h,
        "Velociraptor",
        "https://velo",
        None,
        None,
        Some(&config),
    )
    .await;

    let (status, body) = h
        .call(
            "DELETE",
            &format!("/api/agents/{a1}/delete"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["message"], format!("Agent {a1} deleted successfully"));
    let left = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM agents WHERE agent_id = '{a1}'"
        ))
        .await;
    assert_eq!(left, 0);
    let deletes: Vec<String> = mgr
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "DELETE")
        .map(|r| r.url.query().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        deletes,
        [format!(
            "purge=True&agents_list={a1}&status=all&older_than=0s"
        )]
    );
    assert_eq!(
        velo.vql(),
        [format!(
            "SELECT collect_client(client_id='server', artifacts=['Server.Utils.DeleteClient'], env=dict(ClientIdList='{client_id}',ReallyDoIt='Y')) FROM scope()"
        )]
    );
    let msg = &velo.messages()[0];
    assert_eq!(
        (
            msg.max_wait,
            msg.org_id.as_str(),
            msg.query[0].name.as_str()
        ),
        (1, "root", "VQLRequest")
    );
    let mut audited = 0;
    for _ in 0..50 {
        audited = h
            .scalar_i64(&format!(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'agent.delete' AND entity_id = '{a1}' \
                 AND customer_code = '{acme}' AND JSON_EXTRACT(old_value, '$.velociraptor_id') = '{client_id}'"
            ))
            .await;
        if audited == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(audited, 1);

    // Another tenant's agent is a 404 and nothing upstream is asked.
    let beta = h.code("beta");
    let b1 = agent(&h, "d2", &format!("del2-{s}"), &beta, None).await;
    let before = mgr.received_requests().await.unwrap().len();
    let (status, _) = h
        .call(
            "DELETE",
            &format!("/api/agents/{b1}/delete"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 404);
    assert_eq!(mgr.received_requests().await.unwrap().len(), before);

    // Velociraptor refusing is reported, not fatal: the row still goes.
    let refusing = StandIn::start(|_| {
        Answer::Status(
            copilot_velociraptor::grpc::Code::PermissionDenied,
            "Permission denied: no".into(),
        )
    })
    .await;
    std::fs::write(
        &config,
        std::fs::read_to_string(&config)
            .unwrap()
            .replace(&velo.addr.to_string(), &refusing.addr.to_string()),
    )
    .unwrap();
    let a3 = agent(&h, "d3", &format!("del3-{s}"), &acme, Some(&client_id)).await;
    let (status, body) = h
        .call(
            "DELETE",
            &format!("/api/agents/{a3}/delete"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    let message = body["message"].as_str().unwrap();
    assert!(
        message.starts_with(&format!(
            "Agent {a3} deleted from CoPilot; upstream services reported: Velociraptor: 500: Failed to delete Velociraptor client {client_id}: 500: Failed to delete Velociraptor client {client_id}: 403: Velociraptor denied the query for org 'root'"
        )),
        "{message}"
    );
    cleanup(&h).await;
}

#[tokio::test]
async fn the_velociraptor_connector_is_verified_in_rust() {
    let h = harness_or_skip!(None);
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let velo = StandIn::start(|_| Answer::rows(&[r#"[{"Hostname": "velo"}]"#])).await;
    let dir = tempfile::tempdir().unwrap();
    let config = velo.write_api_config(dir.path());
    let id = connector(
        &h,
        "Velociraptor",
        "https://velo",
        None,
        None,
        Some(&config),
    )
    .await;
    h.exec(&format!(
        "UPDATE connectors SET connector_verified = 0 WHERE id = {id}"
    ))
    .await;

    let (status, body) = h
        .call(
            "POST",
            &format!("/api/connectors/verify/{id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"connectionSuccessful": true, "message": "Connection to Velociraptor successful"})
    );
    let verified = h
        .scalar_i64(&format!(
            "SELECT connector_verified FROM connectors WHERE id = {id}"
        ))
        .await;
    assert_eq!(verified, 1);
    let msg = &velo.messages()[0];
    assert_eq!(
        (
            msg.max_wait,
            msg.org_id.as_str(),
            msg.query[0].name.as_str(),
            msg.query[0].vql.as_str()
        ),
        (60, "", "ClientQuery", "SELECT * FROM info()")
    );
    let timeout = velo.requests.lock().unwrap()[0].1.clone();
    assert_eq!(
        timeout.as_deref(),
        Some("30S"),
        "VELOCIRAPTOR_QUERY_TIMEOUT's default"
    );

    // A config file that is gone fails the check with Python's text.
    std::fs::remove_file(&config).unwrap();
    let (status, body) = h
        .call(
            "POST",
            &format!("/api/connectors/verify/{id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 500);
    assert_eq!(
        body["message"],
        format!(
            "Failed to verify connector: Failed to get connector_api_key from the database: [Errno 2] No such file or directory: '{config}'"
        )
    );
    let verified = h
        .scalar_i64(&format!(
            "SELECT connector_verified FROM connectors WHERE id = {id}"
        ))
        .await;
    assert_eq!(verified, 0);
    cleanup(&h).await;
}

#[tokio::test]
async fn sync_writes_the_managers_agents_and_their_velociraptor_clients() {
    let h = harness_or_skip!(None);
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let admin = h.token(&format!("admin{s}"), "admin");
    let host = format!("sync-{s}");
    let mgr = MockServer::start().await;
    manager_token(&mgr).await;
    Mock::given(method("GET"))
        .and(path("/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "affected_items": [{
                    "id": format!("{s}01"),
                    "name": host,
                    "ip": "10.9.9.9",
                    "os": {"name": "Debian"},
                    "group": [format!("grp_{acme}")],
                    "lastKeepAlive": "2026-10-16T07:00:00+00:00",
                    "version": "Wazuh v4.9.1",
                    "status": "active",
                }],
                "total_affected_items": 1,
            },
            "error": 0,
        })))
        .mount(&mgr)
        .await;
    let client_id = format!("C.{s}");
    let client = json!([{
        "client_id": client_id,
        "agent_information": {"version": "0.7.2", "name": "v", "build_time": "t", "build_url": "u"},
        "os_info": {"system": "linux", "hostname": host, "release": "r", "machine": "m", "fqdn": "f", "mac_addresses": []},
        "first_seen_at": 1, "last_seen_at": 1_760_600_000_000_000_i64, "last_ip": "ip",
        "last_interrogate_flow_id": "F", "last_interrogate_artifact_name": "A", "labels": [],
        "last_hunt_timestamp": 0, "last_event_table_version": 0, "last_label_timestamp": 0,
    }])
    .to_string();
    let velo = StandIn::start(move |args| {
        let vql = &args.query[0].vql;
        if vql == "SELECT * FROM orgs()" {
            Answer::rows(&[r#"[{"Name": "root", "OrgId": "root"}]"#])
        } else if vql.contains("clients()") {
            Answer::rows(&[&client])
        } else {
            Answer::rows(&["[]"])
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let config = velo.write_api_config(dir.path());
    connector(
        &h,
        "Wazuh-Manager",
        &mgr.uri(),
        Some("wazuh"),
        Some("pw"),
        None,
    )
    .await;
    connector(
        &h,
        "Velociraptor",
        "https://velo",
        None,
        None,
        Some(&config),
    )
    .await;

    let (status, body) = h.call("POST", "/api/agents/sync", Some(&admin), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "Agents synced started successfully"})
    );
    let row: (String, String, Option<String>, Option<String>, Option<String>, String) = sqlx::query_as(
        "SELECT agent_id, customer_code, velociraptor_id, velociraptor_agent_version, velociraptor_org, \
         CAST(velociraptor_last_seen AS CHAR) FROM agents WHERE hostname = ?",
    )
    .bind(&host)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            format!("{s}01"),
            acme.clone(),
            Some(client_id.clone()),
            Some("0.7.2".into()),
            Some("root".into()),
            "2025-10-16 07:33:20".into()
        )
    );
    assert_eq!(
        velo.vql(),
        [
            "SELECT * FROM orgs()".to_string(),
            "SELECT * FROM query(org_id='root', query='SELECT * FROM clients()')".to_string()
        ]
    );

    // A scheduler token may run it too; a portal user may not.
    h.exec(&format!(
        "INSERT INTO `user` (username, password, email, created_at, role_id) \
         VALUES ('sched{s}', 'x', 'sched@example.com', UTC_TIMESTAMP(), 3)"
    ))
    .await;
    let sched = h.token(&format!("sched{s}"), "scheduler");
    let (status, _) = h.call("POST", "/api/agents/sync", Some(&sched), None).await;
    assert_eq!(status, 200);
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let (status, _) = h
        .call("POST", "/api/agents/sync", Some(&portal), None)
        .await;
    assert_eq!(status, 403);
    cleanup(&h).await;
}

#[tokio::test]
async fn validation_and_guards_keep_pythons_texts() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let acme = h.code("acme");
    let a1 = agent(&h, "v1", &format!("val-{s}"), &acme, None).await;

    let (status, body) = h
        .call(
            "POST",
            "/api/agents/bulk/delete/filter",
            Some(&analyst),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(
        body["message"],
        "At least one filter condition must be specified to prevent accidental bulk deletion of all agents"
    );
    let (status, body) = h
        .call(
            "POST",
            "/api/agents/bulk/delete/filter",
            Some(&analyst),
            Some(json!({"status": "gone"})),
        )
        .await;
    assert_eq!(status, 422, "{body}");
    let (status, body) = h
        .call(
            "PUT",
            &format!("/api/agents/{a1}/update?velociraptor_id=C.1'x"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (400, json!("Invalid Velociraptor client id"))
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/agents/{a1}/vulnerabilities/Severe"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 422, "{body}");
    let (status, body) = h
        .call("GET", "/api/agents/dashboard/agents", None, None)
        .await;
    assert_eq!(status, 403);
    assert!(
        body["message"].as_str().unwrap().contains("Grafana header"),
        "{body}"
    );
    let (status, _) = h
        .call(
            "GET",
            "/api/agents/sync/vulnerabilities",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 500, "the Python route always crashes");
    let (status, _) = h
        .call(
            "POST",
            &format!("/api/agents/sync/vulnerabilities/{}", h.code("beta")),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 403);
    cleanup(&h).await;
}

#[tokio::test]
async fn velociraptor_responses_run_on_the_callers_hosts_only() {
    let h = harness_or_skip!(None);
    h.seed().await;
    cleanup(&h).await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let client_id = format!("C.{s}");
    let host = format!("cmd-{s}");
    agent(&h, "c1", &host, &acme, Some(&client_id)).await;
    agent(
        &h,
        "c2",
        &format!("other-{s}"),
        &beta,
        Some(&format!("C.{s}b")),
    )
    .await;
    h.exec(&format!(
        "UPDATE agents SET velociraptor_org = 'root' WHERE agent_id LIKE '{s}%'"
    ))
    .await;
    let definitions = r#"[{"name": "Linux.Sys.BashShell", "description": "bash"},
        {"name": "Linux.Remediation.Quarantine", "description": "q"},
        {"name": "Windows.System.CmdShell", "description": "cmd"}]"#
        .to_string();
    let velo = StandIn::start(move |args| {
        let vql = args.query[0].vql.clone();
        if vql.starts_with("SELECT name,description,parameters FROM artifact_definitions()") {
            Answer::rows(&[&definitions])
        } else if let Some(call) = vql
            .strip_prefix("SELECT ")
            .and_then(|v| v.strip_suffix(" FROM scope()"))
        {
            let row = json!([{ call: {"flow_id": "F.ABC"} }]).to_string();
            Answer::rows(&[&row])
        } else if vql.starts_with("SELECT * FROM watch_monitoring") {
            Answer::rows(&[r#"[{"FlowId": "F.ABC"}]"#])
        } else if vql.starts_with("SELECT * FROM source(") {
            Answer::rows(&[r#"[{"Stdout": "uid=0(root)"}]"#])
        } else if vql.starts_with("SELECT * FROM flows(") {
            Answer::rows(&[r#"[{"session_id": "F.ABC", "request": {"specs": [{"artifact": "X"}, 1]}}, "junk"]"#])
        } else {
            Answer::rows(&["[]"])
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let config = velo.write_api_config(dir.path());
    connector(
        &h,
        "Velociraptor",
        "https://velo",
        None,
        None,
        Some(&config),
    )
    .await;
    let responder = h.token(&format!("responder{s}"), "responder");
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    let body = json!({"hostname": host, "artifact_name": "Linux.Sys.BashShell", "command": "id"});
    let (status, _) = h
        .call(
            "POST",
            "/api/artifacts/command",
            Some(&analyst),
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, 403, "a command is admin's or a responder's");
    let (status, resp) = h
        .call(
            "POST",
            "/api/artifacts/command",
            Some(&responder),
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, 200, "{resp}");
    assert_eq!(
        resp,
        json!({"message": "Successfully executed query", "success": true, "results": [{"Stdout": "uid=0(root)"}]})
    );
    let vql = velo.vql();
    assert_eq!(
        vql[1],
        format!(
            "SELECT collect_client(org_id='root', client_id='{client_id}', urgent=true, artifacts=['Linux.Sys.BashShell'], env=dict(Command='id')) FROM scope()"
        )
    );
    assert!(vql[2].ends_with("WHERE FlowId='F.ABC' LIMIT 1"), "{vql:?}");
    assert_eq!(
        vql[3],
        format!(
            "SELECT * FROM source(client_id='{client_id}', flow_id='F.ABC', artifact='Linux.Sys.BashShell')"
        )
    );
    let deadlines: Vec<Option<String>> = velo
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|(_, t)| t.clone())
        .collect();
    assert_eq!(
        deadlines[2].as_deref(),
        Some("5M"),
        "the flow wait's deadline (VELOCIRAPTOR_FLOW_TIMEOUT)"
    );

    // Another tenant's host: refused before Velociraptor is asked anything.
    let before = velo.messages().len();
    let (status, resp) = h
        .call(
            "POST",
            "/api/artifacts/command",
            Some(&responder),
            Some(json!({"hostname": format!("other-{s}"), "artifact_name": "Linux.Sys.BashShell"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (403, json!(format!("Access denied to host other-{s}")))
    );
    assert_eq!(velo.messages().len(), before);

    // Quarantine: the flag follows, and both responses are audited.
    let q = json!({"hostname": host, "action": "quarantine", "artifact_name": "Linux.Remediation.Quarantine"});
    let (status, resp) = h
        .call(
            "POST",
            "/api/artifacts/quarantine",
            Some(&responder),
            Some(q),
        )
        .await;
    assert_eq!(status, 200, "{resp}");
    assert!(
        velo.vql().iter().any(|v| v
            == &format!(
                "SELECT collect_client(org_id=\"root\", client_id=\"{client_id}\", artifacts=[\"Linux.Remediation.Quarantine\"], spec=dict(`Linux.Remediation.Quarantine`=dict())) FROM scope()"
            )),
        "{:?}",
        velo.vql()
    );
    let flagged = h
        .scalar_i64(&format!(
            "SELECT quarantined FROM agents WHERE hostname = '{host}'"
        ))
        .await;
    assert_eq!(flagged, 1);
    let mut audited = 0;
    for _ in 0..50 {
        audited = h
            .scalar_i64(&format!(
                "SELECT COUNT(*) FROM audit_log WHERE entity_type = 'agent' AND entity_id = '{host}' \
                 AND action IN ('response.command_execute', 'response.quarantine')"
            ))
            .await;
        if audited == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(audited, 2);

    // Flows: the malformed spec and row are dropped, not fatal.
    let (status, resp) = h
        .call("GET", &format!("/api/flows/{host}"), Some(&analyst), None)
        .await;
    assert_eq!(status, 200, "{resp}");
    assert_eq!(resp["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        resp["results"][0]["request"]["specs"],
        json!([{"artifact": "X", "parameters": null}])
    );
    let (status, resp) = h
        .call(
            "POST",
            "/api/flows/retrieve",
            Some(&analyst),
            Some(json!({"client_id": format!("C.{s}b"), "session_id": "F.1"})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (403, json!(format!("Access denied to client C.{s}b")))
    );
    let (status, resp) = h
        .call(
            "POST",
            "/api/flows/retrieve",
            Some(&analyst),
            Some(json!({"client_id": "x", "session_id": ""})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), resp["message"].clone()),
        (400, json!("The session_id cannot be an empty string"))
    );

    h.exec(&format!(
        "DELETE FROM audit_log WHERE entity_type = 'agent' AND entity_id = '{host}'"
    ))
    .await;
    cleanup(&h).await;
}
