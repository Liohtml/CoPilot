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

// --- the connector verifications -----------------------------------------------------------

/// A connector row: name, URL, user, password, API key, extra data.
type ConnectorSpec<'a> = (
    &'a str,
    String,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
);

/// The twelve connectors whose verification Python still answered.
const VERIFIED_NOW: [&str; 12] = [
    "Graylog",
    "Graylog-Network",
    "InfluxDB",
    "Grafana",
    "Wazuh Worker Provisioning",
    "HAProxy Provisioning",
    "Event Shipper",
    "Alert Creation Provisioning",
    "VirusTotal",
    "Portainer",
    "Resend",
    "Talon",
];

/// Every connector Python verified is verified in Rust now: the tool asked
/// as Python's function asks it, `connector_verified` written, the Python
/// backend never asked.
#[tokio::test]
async fn every_connector_is_verified_in_rust() {
    let legacy = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&legacy)
        .await;
    let h = harness_or_skip!(Some(&legacy));
    h.seed().await;
    let admin = h.token(&h.code("admin"), "admin");
    backup_connectors(&h, &VERIFIED_NOW).await;
    let tool = MockServer::start().await;
    let gelf = Gelf::start().await;
    let t = tool.uri();
    let ok = |body: Value| ResponseTemplate::new(200).set_body_json(body);
    for (m, p, resp) in [
        (
            "GET",
            "/graylog/api/authz/roles/user/u",
            ok(json!({"roles": []})),
        ),
        (
            "GET",
            "/glnet/api/authz/roles/user/u",
            ResponseTemplate::new(401).set_body_string("nope"),
        ),
        ("GET", "/influx/ping", ResponseTemplate::new(204)),
        (
            "POST",
            "/influx/api/v2/query",
            ResponseTemplate::new(200).insert_header("content-type", "text/csv; charset=utf-8"),
        ),
        (
            "POST",
            "/grafanaapi/admin/users",
            ok(json!({"id": 9, "message": "User created"})),
        ),
        (
            "DELETE",
            "/grafanaapi/admin/users/9",
            ok(json!({"message": "User deleted"})),
        ),
        (
            "GET",
            "/w1/provision_worker/healthcheck",
            ok(json!({"ok": true})),
        ),
        (
            "GET",
            "/w2/provision_worker/healthcheck",
            ResponseTemplate::new(500).set_body_string("down"),
        ),
        ("GET", "/ha/provision_worker/healthcheck", ok(json!({}))),
        (
            "GET",
            "/ac/provision_alert/healthcheck",
            ResponseTemplate::new(503).set_body_string("busy"),
        ),
        (
            "GET",
            "/vt/files/99017f6eebbac24f351415dd410d522d",
            ok(json!({"data": {}})),
        ),
        ("GET", "/talon/health", ok(json!({"status": "ok"}))),
        (
            "GET",
            "/pt/api/v1/apps/authentication",
            ResponseTemplate::new(401).set_body_string("no"),
        ),
        ("POST", "/api/auth", ok(json!({"jwt": "jwt-token"}))),
        (
            "GET",
            "/resend/domains",
            ResponseTemplate::new(401)
                .set_body_json(json!({"name": "restricted_api_key", "message": "restricted"})),
        ),
    ] {
        Mock::given(method(m))
            .and(path(p))
            .respond_with(resp)
            .mount(&tool)
            .await;
    }
    let gport = gelf.port.to_string();
    let rows: [ConnectorSpec<'_>; 12] = [
        (
            "Graylog",
            format!("{t}/graylog"),
            Some("u"),
            Some("p"),
            None,
            None,
        ),
        (
            "Graylog-Network",
            format!("{t}/glnet"),
            Some("u"),
            Some("p"),
            None,
            None,
        ),
        (
            "InfluxDB",
            format!("{t}/influx"),
            None,
            None,
            Some("tok"),
            Some("SOCFORTRESS,telegraf"),
        ),
        (
            "Grafana",
            format!("{t}/grafana"),
            Some("admin"),
            Some("pw"),
            None,
            None,
        ),
        (
            "Wazuh Worker Provisioning",
            format!("{t}/w1, {t}/w2 ,,"),
            None,
            None,
            None,
            None,
        ),
        (
            "HAProxy Provisioning",
            format!("{t}/ha"),
            None,
            None,
            None,
            None,
        ),
        (
            "Alert Creation Provisioning",
            format!("{t}/ac"),
            None,
            None,
            None,
            None,
        ),
        (
            "VirusTotal",
            format!("{t}/vt"),
            None,
            None,
            Some("vt-key"),
            None,
        ),
        ("Talon", format!("{t}/talon"), None, None, None, None),
        (
            "Event Shipper",
            "127.0.0.1".into(),
            None,
            None,
            None,
            Some(gport.as_str()),
        ),
        (
            "Portainer",
            format!("{t}/pt"),
            Some("u"),
            Some("p"),
            Some("k"),
            None,
        ),
        (
            "Resend",
            format!("{t}/resend"),
            None,
            None,
            Some("re_key"),
            None,
        ),
    ];
    for (name, url, user, pass, key, extra) in &rows {
        connector_row(&h, name, url, *user, *pass, *key, *extra).await;
    }
    let url_of = |n: &str| rows.iter().find(|r| r.0 == n).unwrap().1.clone();
    let want: [(&str, bool, String); 12] = [
        ("Graylog", true, "Graylog connection successful".into()),
        (
            "Graylog-Network",
            false,
            format!(
                "Connection to {} failed with error: nope",
                url_of("Graylog-Network")
            ),
        ),
        ("InfluxDB", true, "InfluxDB connection successful".into()),
        ("Grafana", true, "Grafana connection successful".into()),
        (
            "Wazuh Worker Provisioning",
            true,
            "1 of 2 hosts connected successfully".into(),
        ),
        (
            "HAProxy Provisioning",
            true,
            "Wazuh Worker Provisioning healthcheck successful".into(),
        ),
        (
            "Alert Creation Provisioning",
            false,
            format!(
                "Connection to {} failed",
                url_of("Alert Creation Provisioning")
            ),
        ),
        (
            "VirusTotal",
            true,
            "VirusTotal healthcheck successful".into(),
        ),
        ("Talon", true, "Talon connection successful".into()),
        (
            "Event Shipper",
            true,
            "Event shipper healthcheck successful".into(),
        ),
        (
            "Portainer",
            true,
            "Portainer connection successful via JWT".into(),
        ),
        (
            "Resend",
            true,
            "Resend connection successful (send-only restricted key). Sending works; management \
             endpoints are not accessible with this key."
                .into(),
        ),
    ];
    for (name, successful, message) in want {
        let id: i64 = sqlx::query_scalar("SELECT id FROM connectors WHERE connector_name = ?")
            .bind(name)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
        let (st, body) = h
            .call(
                "POST",
                &format!("/api/connectors/verify/{id}"),
                Some(&admin),
                None,
            )
            .await;
        // A failed verification is the route's 500 naming the message.
        if successful {
            assert_eq!(st, 200, "{name}: {body}");
            assert_eq!(
                body,
                json!({"connectionSuccessful": true, "message": message}),
                "{name}"
            );
        } else {
            assert_eq!(st, 500, "{name}: {body}");
            assert_eq!(
                body,
                json!({"success": false, "message": format!("Failed to verify connector: {message}")}),
                "{name}"
            );
        }
        let verified = h
            .scalar_i64(&format!(
                "SELECT connector_verified FROM connectors WHERE id = {id}"
            ))
            .await;
        assert_eq!(verified, i64::from(successful), "{name}");
    }
    let seen = tool.received_requests().await.unwrap();
    let find = |p: &str| seen.iter().find(|r| r.url.path() == p).unwrap();
    assert_eq!(
        header(find("/graylog/api/authz/roles/user/u"), "authorization"),
        "Basic dTpw"
    );
    let ping = find("/influx/ping");
    assert_eq!(header(ping, "authorization"), "Token tok");
    assert_eq!(header(ping, "user-agent"), "influxdb-client-python/1.50.0");
    assert_eq!(header(ping, "accept"), "*/*");
    assert_eq!(
        header(
            find("/vt/files/99017f6eebbac24f351415dd410d522d"),
            "x-apikey"
        ),
        "vt-key"
    );
    let auth = find("/api/auth");
    assert_eq!(
        serde_json::from_slice::<Value>(&auth.body).unwrap(),
        json!({"username": "u", "password": "p"})
    );
    assert_eq!(
        header(find("/resend/domains"), "authorization"),
        "Bearer re_key"
    );
    assert_eq!(
        header(find("/grafanaapi/admin/users"), "authorization"),
        "Basic YWRtaW46cHc="
    );
    assert_eq!(
        gelf.take().await,
        [
            json!({"integration": "event_shipper", "customer_code": "n/a",
            "message": "Healthcheck successful"})
        ]
    );

    // A missing row read before its `None` check (Grafana, InfluxDB) and a
    // URL the Grafana client refuses are Python's 404.
    h.exec(
        "UPDATE connectors SET connector_url = 'grafana.local' WHERE connector_name = 'Grafana'",
    )
    .await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM connectors WHERE connector_name = 'Grafana'")
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/connectors/verify/{id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 404, "{body}");
    // An InfluxDB status record fails `InfluxDBAlert`'s validation.
    tool.reset().await;
    Mock::given(method("GET"))
        .and(path("/influx/ping"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&tool)
        .await;
    Mock::given(method("POST"))
        .and(path("/influx/api/v2/query"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/csv; charset=utf-8")
                .set_body_string(
                    "#datatype,string,long,dateTime:RFC3339,string,string,string,string\r\n\
                     #group,false,false,false,false,false,false,false\r\n\
                     #default,_result,,,,,,\r\n\
                     ,result,table,time,message,checkID,checkName,level\r\n\
                     ,,0,2026-10-18T01:00:00Z,CPU high,0a1,CPU CHECK,crit\r\n\r\n",
                ),
        )
        .mount(&tool)
        .await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM connectors WHERE connector_name = 'InfluxDB'")
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/connectors/verify/{id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 500, "{body}");
    let text = body["message"].as_str().unwrap();
    assert!(
        text.starts_with(&format!(
            "Failed to verify connector: Connection to {t}/influx failed with error: 500: Failed \
             to fetch alerts from InfluxDB: 3 validation errors for InfluxDBAlert\ncheck_name\n  \
             Field required"
        )),
        "{text}"
    );

    for name in VERIFIED_NOW {
        sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
            .bind(name)
            .execute(h.db.pool())
            .await
            .unwrap();
    }
    restore_connectors(&h).await;
    legacy.verify().await;
}

// --- the MITRE alert searches -------------------------------------------------------------

/// The painless source `_build_mitre_search_query` sends for `field`.
fn painless(field: &str) -> String {
    [
        "",
        &format!("    def field_value = doc['{field}'].value;"),
        "    if (field_value != null && field_value != '') {",
        "        def techniques = new ArrayList();",
        "        // Split by comma and clean up whitespace",
        "        def parts = field_value.splitOnToken(',');",
        "        for (def part : parts) {",
        "            def cleaned = part.trim();",
        "            if (cleaned != '') {",
        "                techniques.add(cleaned);",
        "            }",
        "        }",
        "        return techniques;",
        "    }",
        "    return [];",
        "    ",
    ]
    .join("\n")
}

/// The aggregation body Python sends (`size` 0, the terms' size, `from`).
fn aggregation(field: &str, name: Option<&str>, terms: i64, from: i64, extra: &[Value]) -> String {
    let mut filters = vec![
        json!({"match_all": {}}),
        json!({"range": {"timestamp": {"from": "now-24h", "to": "now"}}}),
        json!({"exists": {"field": field}}),
    ];
    filters.extend(extra.iter().cloned());
    let mut techniques = json!({"terms": {
        "script": {"source": painless(field), "lang": "painless"},
        "size": terms,
        "order": {"_count": "desc"},
    }});
    if let Some(n) = name {
        techniques["aggs"] = json!({"technique_name": {"terms": {"field": n, "size": 1}}});
    }
    serde_json::to_string(&json!({
        "size": 0,
        "from": from,
        "query": {"bool": {"must": [], "filter": filters, "should": [], "must_not": []}},
        "aggs": {"techniques": techniques},
    }))
    .unwrap()
}

fn mitre_answer(items: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {"affected_items": items, "total_affected_items": 2},
        "error": 0,
    }))
}

#[tokio::test]
async fn mitre_alert_searches_follow_python() {
    use wiremock::matchers::body_string_contains;
    let legacy = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&legacy)
        .await;
    let h = harness_or_skip!(Some(&legacy));
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&h.code("admin"), "admin");
    let analyst = h.token(&h.code("analyst"), "analyst");
    h.exec(&format!(
        "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES \
         ('lonely{s}', 'x', 'lonely@example.com', UTC_TIMESTAMP(), 2)"
    ))
    .await;
    let lonely = h.token(&format!("lonely{s}"), "analyst");
    backup_connectors(&h, &["Wazuh-Manager", "Wazuh-Indexer"]).await;

    let manager = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/security/user/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "tok"}, "error": 0})),
        )
        .mount(&manager)
        .await;
    let technique = |id: &str, ext: &str, name: &str, tactic: &str| {
        json!({"description": "d", "name": name, "id": id, "modified_time": "m",
               "created_time": "c", "tactics": [tactic], "url": "u", "source": "s",
               "external_id": ext})
    };
    Mock::given(method("GET"))
        .and(path("/mitre/techniques"))
        .respond_with(mitre_answer(json!([
            technique(
                "attack-pattern--x1",
                "T1047",
                "Windows Management Instrumentation",
                "tac--exec"
            ),
            technique(
                "T1059",
                "T1059",
                "Command and Scripting Interpreter",
                "tac--gone"
            ),
        ])))
        .mount(&manager)
        .await;
    Mock::given(method("GET"))
        .and(path("/mitre/tactics"))
        .respond_with(mitre_answer(json!([{
            "description": "d", "name": "Execution", "id": "tac--exec", "modified_time": "m",
            "created_time": "c", "short_name": "execution", "techniques": [], "url": "u",
            "source": "s", "external_id": "TA0002"
        }])))
        .mount(&manager)
        .await;

    let indexer = MockServer::start().await;
    let empty = json!({"hits": {"total": {"value": 0}, "hits": []},
                       "aggregations": {"techniques": {"buckets": []}}});
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty))
        .with_priority(10)
        .mount(&indexer)
        .await;
    let bucket = |key: &str| json!({"key": key, "doc_count": 1});
    Mock::given(method("POST"))
        .and(path("/wazuh-*/_search"))
        .and(body_string_contains("doc['rule.mitre.id']"))
        .and(body_string_contains("\"size\":10000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 7}},
            "aggregations": {"techniques": {"buckets": [bucket("a"), bucket("b"), bucket("c")]}},
        })))
        .mount(&indexer)
        .await;
    Mock::given(method("POST"))
        .and(path("/wazuh-*/_search"))
        .and(body_string_contains("doc['rule.mitre.id']"))
        .and(body_string_contains("\"size\":25"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 7, "relation": "eq"}},
            "aggregations": {"techniques": {"buckets": [
                {"key": "T1047", "doc_count": 4, "technique_name": {"buckets": []}},
                {"key": " 1059 ", "doc_count": 3,
                 "technique_name": {"buckets": [{"key": "Command Interpreter", "doc_count": 3}]}},
                {"key": "", "doc_count": 1},
            ]}},
        })))
        .mount(&indexer)
        .await;
    Mock::given(method("POST"))
        .and(path("/wazuh-*/_search"))
        .and(body_string_contains("{\"term\":{\"custom.mitre\""))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": "boom"})))
        .mount(&indexer)
        .await;
    Mock::given(method("POST"))
        .and(path("/wazuh-*/_search"))
        .and(body_string_contains(
            "{\"term\":{\"rule_mitre_id\":\"T1059\"}}",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 2, "relation": "eq"},
                     "hits": [{"_source": {"a": 1}}, {"_source": {"b": 2}}]},
        })))
        .mount(&indexer)
        .await;
    connector_row(
        &h,
        "Wazuh-Manager",
        &manager.uri(),
        Some("wazuh"),
        Some("pw"),
        None,
        None,
    )
    .await;
    connector_row(
        &h,
        "Wazuh-Indexer",
        &indexer.uri(),
        Some("admin"),
        Some("pw"),
        None,
        None,
    )
    .await;
    let searches = |all: Vec<Request>| {
        all.into_iter()
            .filter(|r| r.url.path().ends_with("/_search"))
            .map(|r| String::from_utf8(r.body).unwrap())
            .collect::<Vec<_>>()
    };

    // The aggregation, as an admin: Python's requests exactly.
    let base = "/api/wazuh_manager/mitre/techniques";
    let (st, body) = h
        .call("GET", &format!("{base}/alerts"), Some(&admin), None)
        .await;
    assert_eq!(st, 200, "{body}");
    let techniques = body["techniques"].as_array().unwrap();
    assert_eq!(techniques.len(), 2, "{body}");
    for t in techniques {
        assert!(t["last_seen"].as_str().unwrap().ends_with('Z'));
    }
    let mut masked = body.clone();
    for t in masked["techniques"].as_array_mut().unwrap() {
        t["last_seen"] = json!("<now>");
    }
    assert_eq!(
        masked,
        json!({
            "success": true,
            "message": "Found 3 MITRE techniques in 7 alerts (page 1 of 1,)",
            "total_alerts": 7,
            "techniques_count": 3,
            "techniques": [
                {"technique_id": "T1047", "technique_name": "Unknown Technique", "count": 4,
                 "last_seen": "<now>",
                 "tactics": [{"id": "tac--exec", "name": "Execution", "short_name": "execution"}]},
                {"technique_id": "1059", "technique_name": "Command Interpreter", "count": 3,
                 "last_seen": "<now>",
                 "tactics": [{"id": "tac--gone", "name": "Unknown", "short_name": ""}]},
            ],
            "time_range": "now-24h",
            "field_used": "rule.mitre.id",
            "page": 1,
            "page_size": 25,
            "total_pages": 1,
        })
    );
    let sent_bodies = searches(indexer.received_requests().await.unwrap());
    assert_eq!(
        sent_bodies,
        vec![
            aggregation("rule_mitre_id", Some("rule_mitre_technique"), 10000, 0, &[]),
            aggregation("rule.mitre.id", Some("rule.mitre.technique"), 10000, 0, &[]),
            aggregation("rule.mitre.id", Some("rule.mitre.technique"), 25, 0, &[]),
        ]
    );
    let manager_calls: Vec<String> = manager
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().starts_with("/mitre"))
        .map(|r| format!("{}?{}", r.url.path(), r.url.query().unwrap_or("")))
        .collect();
    assert_eq!(
        manager_calls,
        [
            "/mitre/techniques?limit=1000",
            "/mitre/techniques?limit=1000",
            "/mitre/tactics?limit=1000"
        ]
    );

    // A scoped analyst's search is narrowed to the indices named after
    // their customers (§4); Python searched every tenant's.
    indexer.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {"techniques": {"buckets": []}},
        })))
        .mount(&indexer)
        .await;
    let tenant = json!({"bool": {"should": [
        {"wildcard": {"_index": format!("*acme{s}*")}},
        {"wildcard": {"_index": "*acme_corp*"}},
        {"wildcard": {"_index": "*acme-corp*"}},
    ], "minimum_should_match": 1}});
    let (st, body) = h
        .call(
            "GET",
            &format!("{base}/alerts?rule_level=007&rule_group=sshd&page=3&size=10"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["field_used"], Value::Null);
    assert_eq!(
        body["message"],
        "Found 0 MITRE techniques in 0 alerts (page 3 of 1,)"
    );
    let extra = [
        json!({"match_phrase": {"rule_level": {"query": "7"}}}),
        json!({"match_phrase": {"rule_groups": {"query": "sshd"}}}),
        tenant.clone(),
    ];
    assert_eq!(
        searches(indexer.received_requests().await.unwrap()),
        vec![
            aggregation(
                "rule_mitre_id",
                Some("rule_mitre_technique"),
                10000,
                0,
                &extra
            ),
            aggregation(
                "rule.mitre.id",
                Some("rule.mitre.technique"),
                10000,
                0,
                &extra
            ),
            aggregation("mitre.id", Some("mitre.technique"), 10000, 0, &extra),
        ]
    );

    // A scoped caller without a customer reads nothing: the indexer is not asked.
    indexer.reset().await;
    let (st, body) = h
        .call("GET", &format!("{base}/alerts"), Some(&lonely), None)
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["techniques"], json!([]));
    assert_eq!(body["total_pages"], 1);
    let (st, body) = h
        .call("GET", &format!("{base}/T1059/alerts"), Some(&lonely), None)
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["technique_name"], "Command and Scripting Interpreter");
    assert_eq!(body["total_alerts"], 0);
    assert!(indexer.received_requests().await.unwrap().is_empty());

    // The alerts of one technique: the caller's field first, a failing
    // field skipped, Python's paging arithmetic.
    Mock::given(method("POST"))
        .and(body_string_contains("{\"term\":{\"custom.mitre\""))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": "boom"})))
        .mount(&indexer)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains(
            "{\"term\":{\"rule_mitre_id\":\"T1059\"}}",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 2, "relation": "eq"},
                     "hits": [{"_source": {"a": 1}}, {"_source": {"b": 2}}]},
        })))
        .mount(&indexer)
        .await;
    let (st, body) = h
        .call(
            "GET",
            &format!(
                "{base}/T1059/alerts?time_range=now-7d&size=1&page=2&rule_level=7&\
                 mitre_field=custom.mitre&alert_id=doc-1"
            ),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({
            "success": true,
            "message": "Found 2 alerts for MITRE technique T1059 (page 2 of 2,)",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "total_alerts": 2,
            "alerts": [{"a": 1}, {"b": 2}],
            "field_used": "rule_mitre_id",
            "time_range": "now-7d",
            "page": 2,
            "page_size": 1,
            "total_pages": 2,
        })
    );
    let expected = |field: &str| {
        serde_json::to_string(&json!({
            "size": 1,
            "from": 1,
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"from": "now-7d", "to": "now"}}},
                {"bool": {"should": [
                    {"term": {field: "T1059"}},
                    {"wildcard": {field: "*T1059*"}},
                    {"query_string": {
                        "query": format!("{field}:\"T1059\" OR {field}:\"*T1059*\""),
                        "analyze_wildcard": true,
                    }},
                ], "minimum_should_match": 1}},
                {"match_phrase": {"rule_level": {"query": "7"}}},
                {"term": {"id": "doc-1"}},
            ]}},
            "_source": true,
            "sort": [{"timestamp": {"order": "desc"}}],
            "track_total_hits": true,
        }))
        .unwrap()
    };
    assert_eq!(
        searches(indexer.received_requests().await.unwrap()),
        vec![expected("custom.mitre"), expected("rule_mitre_id")]
    );

    // `size=0`: `(0 + 0 - 1) // 0` is Python's ZeroDivisionError, a bare 500.
    let (st, _) = h
        .call(
            "GET",
            &format!("{base}/T1059/alerts?size=0"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 500);

    // The FastAPI checks: the path pattern, then the query in its order.
    let (st, body) = h
        .call(
            "GET",
            &format!("{base}/X1059/alerts?page=0&mitre_field=a%20b"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 422, "{body}");
    let failed: Vec<(&str, &str)> = body["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["field"].as_str().unwrap(),
                d["error_type"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        failed,
        [
            ("technique_id", "string_pattern_mismatch"),
            ("page", "greater_than"),
            ("mitre_field", "string_pattern_mismatch"),
        ]
    );

    // Without an indexer connector: the 503 wrapped by the service's 500,
    // and for the second route the `except AsyncElasticsearch` TypeError.
    sqlx::query("DELETE FROM connectors WHERE connector_name = 'Wazuh-Indexer'")
        .execute(h.db.pool())
        .await
        .unwrap();
    let (st, body) = h
        .call("GET", &format!("{base}/alerts"), Some(&admin), None)
        .await;
    assert_eq!(st, 500, "{body}");
    assert_eq!(
        body["message"],
        "Error searching MITRE techniques: 503: Unable to connect to Wazuh Indexer: 500: No \
         Wazuh-Indexer connector found in the database"
    );
    let (st, _) = h
        .call("GET", &format!("{base}/T1059/alerts"), Some(&admin), None)
        .await;
    assert_eq!(st, 500);

    sqlx::query(
        "DELETE FROM connectors WHERE connector_name IN ('Wazuh-Manager', 'Wazuh-Indexer')",
    )
    .execute(h.db.pool())
    .await
    .unwrap();
    restore_connectors(&h).await;
    h.exec(&format!("DELETE FROM `user` WHERE username = 'lonely{s}'"))
        .await;
    legacy.verify().await;
}
