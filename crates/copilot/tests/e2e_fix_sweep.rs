//! End-to-end tests of the fix sweep: features Python never ran (Mimecast's
//! collections, SAP SIEM with one key, …), the tenant leaks earlier ports
//! kept and flagged, the remaining connector verifiers and the two MITRE
//! alert routes — the production router on a real MySQL, every upstream a
//! local stand-in (wiremock, or a TCP listener for GELF).
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13309/copilot \
//!   cargo test -p copilot --test e2e_fix_sweep -- --test-threads=1
//! ```
//!
//! Rows use explicit ids from 7950000 on and are deleted again by those
//! ids; the connector rows a test needs (fixed ids, the `Event Shipper`)
//! are moved aside into a backup table and put back at the end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const BACKUP: &str = "e2e_fix_sweep_connectors";
const DISCOVER: &str = "/api.mimecast.com/api/login/discover-authentication";
const SECRET_B64: &str = "c2VjcmV0LWtleQ==";

// --- shared helpers ------------------------------------------------------------------------

/// Put back the connector rows a test moved aside (`names` by name, `ids`
/// by id).
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
    let ids: Vec<i64> = sqlx::query_scalar(&format!("SELECT id FROM {BACKUP}"))
        .fetch_all(h.db.pool())
        .await
        .unwrap();
    let names: Vec<String> = sqlx::query_scalar(&format!("SELECT connector_name FROM {BACKUP}"))
        .fetch_all(h.db.pool())
        .await
        .unwrap();
    for name in &names {
        sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
            .bind(name)
            .execute(h.db.pool())
            .await
            .unwrap();
    }
    for id in &ids {
        sqlx::query("DELETE FROM connectors WHERE id = ?")
            .bind(id)
            .execute(h.db.pool())
            .await
            .unwrap();
    }
    h.exec(&format!("INSERT INTO connectors SELECT * FROM {BACKUP}"))
        .await;
    h.exec(&format!("DROP TABLE {BACKUP}")).await;
}

/// Move the rows named `names` aside (they are put back by
/// [`restore_connectors`]).
async fn backup_connectors(h: &Harness, names: &[&str]) {
    restore_connectors(h).await;
    let list = names
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ");
    h.exec(&format!(
        "CREATE TABLE {BACKUP} AS SELECT * FROM connectors WHERE connector_name IN ({list})"
    ))
    .await;
    h.exec(&format!(
        "DELETE FROM connectors WHERE connector_name IN ({list})"
    ))
    .await;
}

/// One connector row (no id: AUTO_INCREMENT).
#[allow(clippy::too_many_arguments)]
async fn connector_row(
    h: &Harness,
    name: &str,
    url: &str,
    user: Option<&str>,
    password: Option<&str>,
    api_key: Option<&str>,
    extra: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, \
         connector_last_updated, connector_username, connector_password, connector_api_key, \
         connector_description, connector_supports, connector_configured, connector_verified, \
         connector_accepts_host_only, connector_accepts_api_key, \
         connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         (?, '3', ?, UTC_TIMESTAMP(), ?, ?, ?, 'e2e', 'e2e', 1, 0, 0, 0, 1, 0, 1, ?, 1)",
    )
    .bind(name)
    .bind(url)
    .bind(user)
    .bind(password)
    .bind(api_key)
    .bind(extra)
    .execute(h.db.pool())
    .await
    .unwrap();
}

/// The fix sweep's integration rows (7950000–7950999).
async fn wipe_integrations(h: &Harness) {
    for (table, column, lo) in [
        ("integration_auth_keys", "id", 7_950_300),
        ("integration_subscriptions", "id", 7_950_200),
        ("customer_integrations", "id", 7_950_000),
        ("integration_services", "id", 7_950_100),
    ] {
        let ids: Vec<String> = (lo..lo + 100).map(|i| i.to_string()).collect();
        h.exec(&format!(
            "DELETE FROM {table} WHERE {column} IN ({})",
            ids.join(",")
        ))
        .await;
    }
}

/// One customer integration with its service, subscription and keys.
async fn integration(h: &Harness, n: i64, code: &str, service: &str, keys: &[(&str, &str)]) {
    let (ci, svc, sub) = (7_950_000 + n, 7_950_100 + n, 7_950_200 + n);
    h.exec(&format!(
        "INSERT INTO integration_services (id, service_name, auth_type) VALUES ({svc}, '{service}', 'API Key')"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO customer_integrations (id, customer_code, customer_name, integration_service_id, \
         integration_service_name, instance_name, deployed) VALUES ({ci}, '{code}', 'e2e', 1, '{service}', NULL, 0)"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO integration_subscriptions (id, customer_id, integration_service_id) VALUES ({sub}, {ci}, {svc})"
    ))
    .await;
    for (i, (k, v)) in keys.iter().enumerate() {
        sqlx::query(
            "INSERT INTO integration_auth_keys (id, subscription_id, auth_key_name, auth_value) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(7_950_300 + n * 10 + i64::try_from(i).unwrap())
        .bind(sub)
        .bind(k)
        .bind(v)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
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

/// A GELF TCP input on a port of the OS's choosing: every connection's
/// bytes, NUL-terminated frames.
struct Gelf {
    port: u16,
    frames: Arc<Mutex<Vec<Value>>>,
}

impl Gelf {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let frames = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&frames);
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let mut bytes = Vec::new();
                let _ = conn.read_to_end(&mut bytes).await;
                for frame in bytes.split(|b| *b == 0).filter(|f| !f.is_empty()) {
                    let gelf: Value = serde_json::from_slice(frame).unwrap();
                    let message: Value =
                        serde_json::from_str(gelf["short_message"].as_str().unwrap()).unwrap();
                    sink.lock().unwrap().push(message);
                }
            }
        });
        Self { port, frames }
    }

    /// The messages received so far, once nothing new came for 200 ms.
    async fn take(&self) -> Vec<Value> {
        let mut seen = usize::MAX;
        for _ in 0..50 {
            let n = self.frames.lock().unwrap().len();
            if n == seen {
                break;
            }
            seen = n;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        std::mem::take(&mut *self.frames.lock().unwrap())
    }
}

/// CRC-32 (IEEE), for the test archives.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A stored (uncompressed) zip archive of `(name, data)` members.
fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in members {
        let offset = u32::try_from(out.len()).unwrap();
        let crc = crc32(data);
        let len = u32::try_from(data.len()).unwrap();
        let name_len = u16::try_from(name.len()).unwrap();
        out.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(b"PK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&len.to_le_bytes());
        central.extend_from_slice(&len.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = u32::try_from(out.len()).unwrap();
    let count = u16::try_from(members.len()).unwrap();
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00");
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&u32::try_from(central.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// One Wazuh agent of `code`.
async fn agent(h: &Harness, agent_id: &str, hostname: &str, code: &str) {
    sqlx::query(
        "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, \
         wazuh_last_seen, velociraptor_id, velociraptor_last_seen, wazuh_agent_version, \
         wazuh_agent_status, velociraptor_agent_version, customer_code, quarantined) VALUES \
         (?, '10.0.0.1', 'Linux', ?, 'l', 0, UTC_TIMESTAMP(), 'C.1', UTC_TIMESTAMP(), 'v4', \
         'active', 'v', ?, 0)",
    )
    .bind(agent_id)
    .bind(hostname)
    .bind(code)
    .execute(h.db.pool())
    .await
    .unwrap();
}

// --- 1. Mimecast: the SIEM download and the TTP URL pages ----------------------------------

fn region(api: &str) -> Value {
    json!({"meta": {"status": 200}, "data": [{
        "emailAddress": "admin@acme.example", "emailToken": "t",
        "authenticate": ["Basic-Cloud"],
        "region": {"code": "eu", "api": api, "mpp": "https://mpp.example",
                   "adminConsole": "https://admin.example", "name": "eu"}
    }], "fail": []})
}

fn click(n: u32) -> Value {
    json!({
        "userEmailAddress": format!("user{n}@acme.example"), "fromUserEmailAddress": "x@evil.example",
        "url": format!("https://evil.example/{n}"), "ttpDefinition": "Default", "subject": "hi",
        "action": "block", "adminOverride": "N/A", "userOverride": "None", "scanResult": "malicious",
        "category": "phishing", "sendingIp": "198.51.100.7", "userAwarenessAction": "n/a",
        "date": "2026-10-17T10:00:00+0000", "actions": "Blocked", "route": "inbound",
        "creationMethod": "User Click", "emailPartsDescription": ["Body"], "messageId": format!("<m{n}>"),
        "extra": "dropped"
    })
}

/// The signature Mimecast checks: `MC <access>:<b64 hmac-sha1>` over
/// `date:req_id:uri:app_key` with the decoded secret.
fn check_signature(req: &Request, uri: &str) {
    let date = header(req, "x-mc-date");
    let id = header(req, "x-mc-req-id");
    assert!(date.ends_with(" UTC"), "{date}");
    assert_eq!(id.len(), 36);
    let want = copilot_integration_modules::mimecast::siem::signature(
        b"secret-key",
        &format!("{date}:{id}:{uri}:appkey"),
    );
    assert_eq!(header(req, "authorization"), format!("MC acc:{want}"));
}

#[tokio::test]
async fn mimecast_collects_where_python_never_did() {
    let stub = MockServer::start().await;
    let gelf = Gelf::start().await;
    let dir = tempfile::tempdir().unwrap();
    let h = harness_or_skip!(
        None,
        &format!(
            "COPILOT_INTEGRATION_MODULES_URL={}\nCOPILOT_MIMECAST_DIR={}\n\
             COPILOT_RS_JOBS=invoke_mimecast_integration,invoke_mimecast_integration_ttp\n",
            stub.uri(),
            dir.path().display()
        )
    );
    h.seed().await;
    backup_connectors(&h, &["Event Shipper"]).await;
    connector_row(
        &h,
        "Event Shipper",
        "127.0.0.1",
        None,
        None,
        None,
        Some(&gelf.port.to_string()),
    )
    .await;
    wipe_integrations(&h).await;
    let acme = h.code("acme");
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
            ("SECRET_KEY", SECRET_B64),
        ],
    )
    .await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    Mock::given(method("POST"))
        .and(path(DISCOVER))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(region(&format!("{}/eu-api", stub.uri()))),
        )
        .mount(&stub)
        .await;
    let siem = "/eu-api/api/audit/get-siem-logs";
    let checkpoint = dir
        .path()
        .join("checkpoint")
        .join(format!("mimecast_{acme}.checkpoint"));
    let logs = dir.path().join("logs").join(&acme);

    // A page of logs: a zip of two files, the next token in its header.
    let archive = zip(&[
        (
            "mta_1.log",
            b"datetime=2026-10-17T10:00:00|aCode=a1|acc=X\nAct=Acc | Dir = in\n",
        ),
        ("mta_2.log", b"aCode=a2|junk|x=1=2\r\n"),
    ]);
    Mock::given(method("POST"))
        .and(path(siem))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .insert_header(
                    "Content-Disposition",
                    "attachment; filename=\"mta_page_1.zip\"",
                )
                .insert_header("mc-siem-token", "token-1")
                .set_body_bytes(archive),
        )
        .up_to_n_times(1)
        .mount(&stub)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/mimecast/invoke",
            Some(&analyst),
            Some(json!({"customer_code": acme})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Successfully invoked Mimecast integration."})
        )
    );
    let reqs = sent(&stub, siem).await;
    assert_eq!(reqs.len(), 1);
    check_signature(&reqs[0], "/api/audit/get-siem-logs");
    assert_eq!(header(&reqs[0], "x-mc-app-id"), "app");
    assert_eq!(header(&reqs[0], "content-type"), "application/json");
    assert_eq!(header(&reqs[0], "user-agent"), "python-requests/2.33.1");
    assert_eq!(
        String::from_utf8_lossy(&reqs[0].body),
        r#"{"data": [{"type": "MTA", "compress": true, "token": ""}]}"#
    );
    assert_eq!(std::fs::read_to_string(&checkpoint).unwrap(), "token-1");
    assert!(!logs.exists(), "the log directory is deleted");
    let mut events = gelf.take().await;
    events.sort_by_key(|e| e.to_string());
    let base = json!({"integration": "mimecast", "customer_code": acme, "version": "1.0"});
    let with = |fields: Value| {
        let mut e = base.clone();
        e.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        e
    };
    let mut want = vec![
        with(json!({"datetime": "2026-10-17T10:00:00", "aCode": "a1", "acc": "X"})),
        with(json!({"Act": "Acc", "Dir": "in"})),
        with(json!({"aCode": "a2", "x": "1=2"})),
    ];
    want.sort_by_key(|e| e.to_string());
    assert_eq!(events, want);

    // The next run sends the stored token; a JSON answer means no more logs.
    Mock::given(method("POST"))
        .and(path(siem))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"meta": {"status": 200}, "data": [], "fail": []})),
        )
        .mount(&stub)
        .await;
    let (st, _) = h
        .call(
            "POST",
            "/api/mimecast/invoke",
            Some(&analyst),
            Some(json!({"customer_code": acme})),
        )
        .await;
    assert_eq!(st, 200);
    let reqs = sent(&stub, siem).await;
    assert_eq!(
        String::from_utf8_lossy(&reqs[1].body),
        r#"{"data": [{"type": "MTA", "compress": true, "token": "token-1"}]}"#
    );
    assert!(gelf.take().await.is_empty());

    // The TTP URL pages: the page token carried, the same signed headers
    // on every page, the body the dict's repr.
    let ttp = "/eu-api/api/ttp/url/get-logs";
    Mock::given(method("POST"))
        .and(path(ttp))
        .and(wiremock::matchers::body_string_contains("pageToken"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta": {"pagination": {"pageSize": 1, "totalCount": 2}, "status": 200},
            "data": [{"clickLogs": [click(2)]}], "fail": []})))
        .mount(&stub)
        .await;
    Mock::given(method("POST"))
        .and(path(ttp))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta": {"pagination": {"pageSize": 1, "totalCount": 2, "next": "page-2"}, "status": 200},
            "data": [{"clickLogs": [click(1)]}], "fail": []})))
        .mount(&stub)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/mimecast/ttp/urls",
            Some(&analyst),
            Some(json!({"customer_code": acme, "time_range": "1h"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Mimecast TTP URL request successful"})
        )
    );
    let reqs = sent(&stub, ttp).await;
    assert_eq!(reqs.len(), 2);
    check_signature(&reqs[0], "/api/ttp/url/get-logs");
    assert_eq!(
        header(&reqs[0], "x-mc-req-id"),
        header(&reqs[1], "x-mc-req-id")
    );
    let shape = regex_like(&String::from_utf8_lossy(&reqs[0].body));
    assert_eq!(
        shape,
        "{'meta': {}, 'data': [{'oldestFirst': False, 'from': 'T', 'to': 'T', 'route': 'all', \
         'scanResult': 'all'}]}"
    );
    assert!(
        String::from_utf8_lossy(&reqs[1].body)
            .starts_with("{'meta': {'pagination': {'pageToken': 'page-2'}}, 'data': [")
    );
    let events = gelf.take().await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["url"], "https://evil.example/1");
    assert_eq!(events[0]["emailPartsDescription"], json!(["Body"]));
    assert!(events[0].get("extra").is_none());
    assert_eq!(
        events[0]
            .as_object()
            .unwrap()
            .keys()
            .take(4)
            .collect::<Vec<_>>(),
        [
            "integration",
            "customer_code",
            "version",
            "userEmailAddress"
        ]
    );

    // An answer that is not a zip: Python's `TypeError` (bytes to a text
    // file), the empty file left — so the next run is the walk's crash too.
    stub.reset().await;
    Mock::given(method("POST"))
        .and(path(DISCOVER))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(region(&format!("{}/eu-api", stub.uri()))),
        )
        .mount(&stub)
        .await;
    Mock::given(method("POST"))
        .and(path(siem))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .insert_header("Content-Disposition", "attachment; filename=\"mta.log\"")
                .insert_header("mc-siem-token", "token-2")
                .set_body_bytes(b"x=1".to_vec()),
        )
        .mount(&stub)
        .await;
    for _ in 0..2 {
        let (st, _) = h
            .call(
                "POST",
                "/api/mimecast/invoke",
                Some(&analyst),
                Some(json!({"customer_code": acme})),
            )
            .await;
        assert_eq!(st, 500);
    }
    assert_eq!(std::fs::read(logs.join("mta.log")).unwrap(), b"");
    assert_eq!(std::fs::read_to_string(&checkpoint).unwrap(), "token-2");
    std::fs::remove_dir_all(&logs).unwrap();

    // A broken archive: the 400 of `write_log_file`.
    stub.reset().await;
    Mock::given(method("POST"))
        .and(path(DISCOVER))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(region(&format!("{}/eu-api", stub.uri()))),
        )
        .mount(&stub)
        .await;
    Mock::given(method("POST"))
        .and(path(siem))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .insert_header("Content-Disposition", "attachment; filename=\"x.zip\"")
                .insert_header("mc-siem-token", "token-3")
                .set_body_bytes(b"not a zip".to_vec()),
        )
        .mount(&stub)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/mimecast/invoke",
            Some(&analyst),
            Some(json!({"customer_code": acme})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            400,
            json!({"success": false, "message": "Unable to extract zip file."})
        )
    );
    std::fs::remove_dir_all(&logs).ok();

    // The two collection jobs, handed over: every Mimecast customer, the
    // row stamped (only this suite's customer has the integration).
    stub.reset().await;
    Mock::given(method("POST"))
        .and(path(DISCOVER))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(region(&format!("{}/eu-api", stub.uri()))),
        )
        .mount(&stub)
        .await;
    Mock::given(method("POST"))
        .and(path(siem))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"meta": {"status": 200}, "data": [], "fail": []})),
        )
        .mount(&stub)
        .await;
    Mock::given(method("POST"))
        .and(path(ttp))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta": {"pagination": {"pageSize": 1, "totalCount": 1}, "status": 200},
            "data": [{"clickLogs": [click(3)]}], "fail": []})))
        .mount(&stub)
        .await;
    let others = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM customer_integrations WHERE integration_service_name = 'Mimecast' \
             AND customer_code <> '{acme}'"
        ))
        .await;
    if others == 0 {
        for job in [
            "invoke_mimecast_integration",
            "invoke_mimecast_integration_ttp",
        ] {
            h.exec(&format!(
                "DELETE FROM scheduled_job_metadata WHERE job_id = '{job}'"
            ))
            .await;
            let row = h
                .exec(&format!(
                    "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, \
                     extra_data, enabled, job_description) VALUES ('{job}', NULL, 5, NULL, 0, \
                     'e2e fix sweep')"
                ))
                .await;
            match h.app.scheduler.run_now(job).await.unwrap() {
                copilot_scheduler::runner::ManualRun::Ran(Ok(result)) => assert_eq!(
                    result,
                    Some(json!({"success": true, "message": "Mimecast integration invoked."}))
                ),
                other => panic!("{other:?}"),
            }
            assert_eq!(
                h.scalar_i64(&format!(
                    "SELECT COUNT(*) FROM scheduled_job_metadata WHERE id = {row} \
                     AND last_success IS NOT NULL"
                ))
                .await,
                1
            );
            h.exec(&format!(
                "DELETE FROM scheduled_job_metadata WHERE id = {row}"
            ))
            .await;
        }
        assert_eq!(sent(&stub, siem).await.len(), 1);
        assert_eq!(gelf.take().await.len(), 1);
    }

    wipe_integrations(&h).await;
    restore_connectors(&h).await;
}

/// The TTP body with its two times replaced by `T`.
fn regex_like(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some(i) = rest.find("+0000'") {
        let start = rest[..i].rfind('\'').unwrap();
        out.push_str(&rest[..=start]);
        out.push('T');
        rest = &rest[i + 5..];
    }
    out.push_str(rest);
    out
}

// --- 2. SAP SIEM with one API key ----------------------------------------------------------

#[tokio::test]
async fn sap_siem_with_one_key_collects() {
    let stub = MockServer::start().await;
    let h = harness_or_skip!(
        None,
        &format!("COPILOT_INTEGRATION_MODULES_URL={}\n", stub.uri())
    );
    h.seed().await;
    wipe_integrations(&h).await;
    let acme = h.code("acme");
    h.exec(&format!(
        "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, \
         customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group, \
         customer_meta_iris_customer_id) VALUES ('{acme}', 'e2e', 'i', 's', '1', 'g', 7950901)"
    ))
    .await;
    integration(
        &h,
        1,
        &acme,
        "SAP SIEM",
        &[
            ("API_KEY", "single"),
            ("SECRET_KEY", "s"),
            ("API_DOMAIN", "audit.eu1.gigya.com"),
        ],
    )
    .await;
    let at = "/copilot-sap-module/sap-siem/collect";
    Mock::given(method("POST"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&stub)
        .await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let (st, body) = h
        .call(
            "POST",
            "/api/integrations/modules/sap_siem",
            Some(&analyst),
            Some(json!({"customer_code": acme, "time_range": "10m"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "SAP SIEM Events collected successfully."})
        )
    );
    let reqs = sent(&stub, at).await;
    assert_eq!(reqs.len(), 1);
    let mut posted: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    for bound in ["lower_bound", "upper_bound"] {
        posted[bound] = json!("*");
    }
    assert_eq!(
        posted,
        json!({"customer_code": acme, "integration_name": "SAP SIEM", "threshold": 3,
               "time_range": "10m", "lower_bound": "*", "upper_bound": "*",
               "auth_keys": {"API_KEY": "single", "SECRET_KEY": "s", "USER_KEY": null,
                             "API_DOMAIN": "audit.eu1.gigya.com"},
               "customer_details": {"customer_code": acme, "iris_customer_id": 7_950_901}})
    );
    h.exec(&format!(
        "DELETE FROM customersmeta WHERE customer_code = '{acme}'"
    ))
    .await;
    wipe_integrations(&h).await;
}

// --- 3. The Customer Portal: a user without a role, an offset past every agent -------------

#[tokio::test]
async fn portal_me_without_a_role_and_agents_past_the_end() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let acme = h.code("acme");
    let roleless = format!("roleless{}", h.suffix);
    h.exec(&format!(
        "INSERT INTO `user` (username, password, email, created_at, role_id) \
         VALUES ('{roleless}', 'x', 'r@example.com', UTC_TIMESTAMP(), NULL)"
    ))
    .await;
    let token = h.token(&roleless, "customer_user");
    let (st, body) = h
        .call("GET", "/api/customer_portal/me", Some(&token), None)
        .await;
    assert_eq!(st, 403, "{body}");
    assert_eq!(
        body["message"],
        format!("Access denied - user {roleless} has no role")
    );

    // Three agents of acme; pages past the end are empty, whatever the
    // offset (MySQL refuses one beyond 64 bits: Python's 500).
    for n in 0..3 {
        agent(
            &h,
            &format!("fs{n}{}", h.suffix),
            &format!("fs-host-{n}{}", h.suffix),
            &acme,
        )
        .await;
    }
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");
    let page = |p: &str| {
        let (h, portal) = (&h, &portal);
        let uri = format!("/api/customer_portal/agents?page={p}&page_size=100");
        async move { h.call("GET", &uri, Some(portal), None).await }
    };
    let (st, first) = page("1").await;
    assert_eq!(st, 200, "{first}");
    assert_eq!(first["total"], 3);
    assert_eq!(first["agents"].as_array().unwrap().len(), 3);
    let (st, past) = page("2").await;
    assert_eq!(st, 200);
    assert_eq!(past["agents"], json!([]));
    for huge in [
        "184467440737095518",
        "1000000000000000000000",
        "99999999999999999999999999999999999999999",
    ] {
        let (st, body) = page(huge).await;
        assert_eq!(st, 200, "{huge}: {body}");
        let mut want = past.clone();
        want["agents"] = json!([]);
        assert_eq!(body, want, "{huge}");
    }
    h.exec(&format!(
        "DELETE FROM agents WHERE agent_id IN ('fs0{s}', 'fs1{s}', 'fs2{s}')",
        s = h.suffix
    ))
    .await;
    h.exec(&format!("DELETE FROM `user` WHERE username = '{roleless}'"))
        .await;
}
