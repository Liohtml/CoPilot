//! End-to-end tests of the incidents module (`/api/incidents/*`): the
//! production router against a real MySQL at the Alembic head.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13306/copilot \
//!   cargo test -p copilot --test e2e_incidents -- --test-threads=1
//! ```
//!
//! Each test seeds its own customers and users (random suffix). Tag-access
//! settings are global, which is why the suite runs single-threaded.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const P: &str = "/api/incidents/db_operations";

/// Incident fixtures on top of the shared seed: a second alert for acme with
/// a tag, an IoC and a comment, a case per customer.
struct Seeded {
    acme: i64,
    beta: i64,
    tagged: i64,
    tag: i64,
    case_acme: i64,
    case_beta: i64,
}

async fn seed(h: &Harness) -> Seeded {
    let (acme, beta) = h.seed().await;
    let s = &h.suffix;
    let tagged = h
        .exec(&format!(
            "INSERT INTO incident_management_alert (alert_name, alert_description, status, \
             alert_creation_time, customer_code, source, escalated, verdict) VALUES \
             ('Tagged {s}', 'd', 'IN_PROGRESS', '2026-03-01 10:00:00', 'acme{s}', 'src{s}', 0, \
             'FALSE_POSITIVE')"
        ))
        .await;
    let tag = h
        .exec(&format!(
            "INSERT INTO incident_management_alerttag (tag) VALUES ('t{s}')"
        ))
        .await;
    h.exec(&format!(
        "INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES ({tagged}, {tag})"
    ))
    .await;
    let ioc = h
        .exec("INSERT INTO incident_management_ioc (value, type) VALUES ('10.9.8.7', 'IP')")
        .await;
    h.exec(&format!(
        "INSERT INTO incident_management_alert_to_ioc (alert_id, ioc_id) VALUES ({tagged}, {ioc})"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO incident_management_comment (alert_id, comment, user_name, created_at) \
         VALUES ({tagged}, 'look', 'analyst{s}', '2026-03-01 10:30:00')"
    ))
    .await;
    let mut cases = Vec::new();
    for (c, alert) in [("acme", tagged), ("beta", beta)] {
        let id = h
            .exec(&format!(
                "INSERT INTO incident_management_case (case_name, case_description, \
                 case_creation_time, case_status, customer_code, escalated) VALUES \
                 ('Case {c}{s}', 'cd', '2026-03-04 09:00:00', 'OPEN', '{c}{s}', 0)"
            ))
            .await;
        h.exec(&format!(
            "INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES ({id}, {alert})"
        ))
        .await;
        cases.push(id);
    }
    Seeded {
        acme,
        beta,
        tagged,
        tag,
        case_acme: cases[0],
        case_beta: cases[1],
    }
}

fn ids(body: &Value, key: &str) -> Vec<i64> {
    body[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_i64().unwrap())
        .collect()
}

#[tokio::test]
async fn alert_reads_follow_visibility_and_python_shapes() {
    let h = harness_or_skip!(None);
    let d = seed(&h).await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");

    // One alert, with every relationship, in AlertOut's field order.
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/alert/{}", d.tagged),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    let alert = &body["alerts"][0];
    let keys: Vec<&str> = alert
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "id",
            "alert_creation_time",
            "time_closed",
            "alert_name",
            "alert_description",
            "status",
            "customer_code",
            "source",
            "assigned_to",
            "escalated",
            "verdict",
            "verdict_reason",
            "verdict_note",
            "verdict_by",
            "verdict_at",
            "comments",
            "assets",
            "tags",
            "linked_cases",
            "iocs"
        ]
    );
    assert_eq!(alert["alert_creation_time"], "2026-03-01T10:00:00.000Z");
    assert_eq!(
        alert["tags"],
        json!([{"tag": format!("t{s}"), "id": d.tag}])
    );
    assert_eq!(alert["iocs"][0]["type"], "IP");
    assert_eq!(alert["linked_cases"][0]["id"], d.case_acme);
    assert_eq!(
        alert["comments"][0]["created_at"],
        "2026-03-01T10:30:00.000Z"
    );
    assert_eq!(body["total"], Value::Null);

    // Another tenant's alert: the customer check, after the 404 check.
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/alert/{}", d.beta),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        format!(
            "Access denied to alert {} - insufficient customer permissions",
            d.beta
        )
    );
    let (st, body) = h
        .call("GET", &format!("{P}/alert/999999999"), Some(&analyst), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (404, Some("Alert not found"))
    );

    // Path and query errors are one 422.
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/alerts/status/NOPE?page=0"),
            Some(&admin),
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
    assert_eq!(fields, ["status", "page"]);

    // The list is the caller's customers only, with per-status counts.
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/alerts?page_size=50"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(st, 200);
    let listed = ids(&body, "alerts");
    assert!(listed.contains(&d.acme) && listed.contains(&d.tagged));
    assert!(!listed.contains(&d.beta));
    assert_eq!(body["total"], 2);
    assert_eq!(body["open"], 1);
    assert_eq!(body["in_progress"], 1);
    assert_eq!(body["pending_customer"], 0);

    // The combined filter, its count sharing the page's visibility.
    let (st, body) = h
        .call(
            "GET",
            &format!(
                "{P}/alerts/filter?customer_codes=acme{s}&customer_codes=beta{s}&verdict=FALSE_POSITIVE"
            ),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(ids(&body, "alerts"), vec![d.tagged]);
    assert_eq!(body["total_filtered"], 1);
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/alerts/filter?date_from=2026-03-02&date_to=2026-03-01"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            422,
            json!({"success": false, "message": "date_from must not be after date_to"})
        )
    );

    // Filter options come from the visible alerts.
    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/alerts/filter-options"),
            Some(&analyst),
            None,
        )
        .await;
    assert!(
        body["tags"]
            .as_array()
            .unwrap()
            .contains(&json!(format!("t{s}")))
    );
    assert!(
        body["assets"]
            .as_array()
            .unwrap()
            .contains(&json!("dc01-acme"))
    );
    assert!(
        !body["assets"]
            .as_array()
            .unwrap()
            .contains(&json!("dc01-beta"))
    );
    assert_eq!(
        body["verdicts"],
        json!(["TRUE_POSITIVE", "FALSE_POSITIVE", "UNTRIAGED"])
    );
}

#[tokio::test]
async fn per_key_listings_close_the_empty_scope_leak() {
    let h = harness_or_skip!(None);
    let d = seed(&h).await;
    let s = h.suffix.clone();
    // An analyst without any customer.
    h.exec(&format!(
        "INSERT INTO `user` (username, password, email, created_at, role_id) \
         VALUES ('lonely{s}', 'x', 'l@example.com', UTC_TIMESTAMP(), 2)"
    ))
    .await;
    let lonely = h.token(&format!("lonely{s}"), "analyst");
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/alerts/source/wazuh"),
            Some(&lonely),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["alerts"], json!([]));
    assert_eq!(
        (body["total"].as_i64(), body["open"].as_i64()),
        (Some(0), Some(0))
    );

    // The admin branch: the key's own counts.
    let admin = h.token(&format!("admin{s}"), "admin");
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/alerts/source/src{s}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(ids(&body, "alerts"), vec![d.tagged]);
    assert_eq!(body["total"], 1);
    assert_eq!(body["in_progress"], 1);
    // An alert listed once per matching asset, as the ORM query does.
    h.exec(&format!(
        "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, \
         customer_code, index_name, index_id) SELECT {}, 'dc01-acme', alert_context_id, \
         customer_code, index_name, index_id FROM incident_management_asset WHERE alert_linked = {}",
        d.acme, d.acme
    ))
    .await;
    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/alerts/asset/dc01-acme"),
            Some(&admin),
            None,
        )
        .await;
    let listed = ids(&body, "alerts");
    assert_eq!(listed.iter().filter(|i| **i == d.acme).count(), 2);
}

#[tokio::test]
async fn tag_rbac_applies_to_one_alert_and_to_lists() {
    let h = harness_or_skip!(None);
    let configured = h
        .scalar_i64("SELECT COUNT(*) FROM incident_management_tag_access_settings")
        .await;
    if configured > 0 {
        eprintln!("tag access settings already configured; skipping");
        return;
    }
    let d = seed(&h).await;
    let s = h.suffix.clone();
    let settings = h
        .exec(
            "INSERT INTO incident_management_tag_access_settings (enabled, \
             untagged_alert_behavior, updated_at) VALUES (1, 'admin_only', UTC_TIMESTAMP())",
        )
        .await;
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let result = async {
        // No tag granted: the tagged alert is a 403 (tag check before customer
        // check) and the untagged one too (admin_only).
        let (st, body) = h
            .call(
                "GET",
                &format!("{P}/alert/{}", d.tagged),
                Some(&analyst),
                None,
            )
            .await;
        assert_eq!(st, 403);
        assert_eq!(
            body["message"],
            format!(
                "Access denied to alert {} - insufficient tag permissions",
                d.tagged
            )
        );
        let (_, body) = h
            .call("GET", &format!("{P}/alerts"), Some(&analyst), None)
            .await;
        assert_eq!(body["alerts"], json!([]));
        // The per-key listings go through the same visibility.
        let (_, body) = h
            .call(
                "GET",
                &format!("{P}/alerts/source/src{s}"),
                Some(&analyst),
                None,
            )
            .await;
        assert_eq!(body["alerts"], json!([]));
        h.exec(&format!(
            "INSERT INTO user_tag_access (user_id, tag_id, created_at) SELECT id, {}, \
             UTC_TIMESTAMP() FROM `user` WHERE username = 'analyst{s}'",
            d.tag
        ))
        .await;
        let (st, _) = h
            .call(
                "GET",
                &format!("{P}/alert/{}", d.tagged),
                Some(&analyst),
                None,
            )
            .await;
        assert_eq!(st, 200);
        let (_, body) = h
            .call("GET", &format!("{P}/alerts"), Some(&analyst), None)
            .await;
        assert_eq!(ids(&body, "alerts"), vec![d.tagged]);
    };
    result.await;
    h.exec(&format!(
        "DELETE FROM incident_management_tag_access_settings WHERE id = {settings}"
    ))
    .await;
    h.exec(&format!(
        "DELETE FROM user_tag_access WHERE tag_id = {}",
        d.tag
    ))
    .await;
}

#[tokio::test]
async fn case_reads_and_closed_leaks() {
    let h = harness_or_skip!(None);
    let d = seed(&h).await;
    let s = h.suffix.clone();
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/case/{}", d.case_acme),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    let case = &body["cases"][0];
    assert_eq!(case["alerts"][0]["id"], d.tagged);
    assert_eq!(case["case_creation_time"], "2026-03-04T09:00:00.000Z");
    assert_eq!(case["notification_invoked_number"], 0);
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/case/{}", d.case_beta),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        format!(
            "Access denied to case {} - insufficient customer permissions",
            d.case_beta
        )
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("{P}/cases?page_size=100"),
            Some(&analyst),
            None,
        )
        .await;
    let listed = ids(&body, "cases");
    assert!(listed.contains(&d.case_acme) && !listed.contains(&d.case_beta));
    assert_eq!(body["total"], 1);

    // Timeline and tasks are checked against the case first.
    h.exec(&format!(
        "INSERT INTO incident_management_case_event (case_id, event_type, actor, timestamp, payload) \
         VALUES ({}, 'case_created', 'seed', '2026-03-04 09:00:00', '{{\"source\": \"manual\"}}')",
        d.case_acme
    ))
    .await;
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/case/{}/timeline", d.case_acme),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["events"][0]["payload"], json!({"source": "manual"}));
    assert_eq!(body["events"][0]["timestamp"], "2026-03-04T09:00:00");
    let (st, _) = h
        .call(
            "GET",
            &format!("{P}/case/{}/tasks", d.case_beta),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403);

    // Python listed every tenant's case files to any analyst.
    for c in [d.case_acme, d.case_beta] {
        h.exec(&format!(
            "INSERT INTO incident_management_case_datastore (case_id, bucket_name, object_key, \
             file_name, upload_time, file_hash) VALUES ({c}, 'copilot-cases', 'k', 'f{s}', \
             UTC_TIMESTAMP(), 'h')"
        ))
        .await;
    }
    let (_, body) = h
        .call("GET", &format!("{P}/case/data-store"), Some(&analyst), None)
        .await;
    let cases: Vec<i64> = body["case_data_store"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["case_id"].as_i64().unwrap())
        .collect();
    assert!(cases.contains(&d.case_acme) && !cases.contains(&d.case_beta));

    // Python returned any tenant's alert context to any analyst.
    let ctx = h
        .scalar_i64(&format!(
            "SELECT alert_context_id FROM incident_management_asset WHERE alert_linked = {}",
            d.beta
        ))
        .await;
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/alert/context/{ctx}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        format!("Access denied to alert context {ctx}")
    );
    let (st, body) = h
        .call(
            "GET",
            &format!("{P}/alert/context/{ctx}"),
            Some(&h.token(&format!("admin{s}"), "admin")),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["alert_context"]["source"], "wazuh");
}

#[tokio::test]
async fn unported_paths_and_methods_reach_the_legacy_backend() {
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    h.seed().await;
    // The MinIO routes are copilot-objectstore's now (e2e_objectstore.rs), the
    // default-template upload included; the indexer reads copilot-ingest's
    // (e2e_ingest.rs), the case notification copilot-shuffle's
    // (e2e_response.rs). The DOCX/PDF reports stay Python.
    const R: &str = "/api/incidents/report";
    Mock::given(method("POST"))
        .and(path(format!("{R}/generate-report-docx")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python-post"})))
        .expect(1)
        .mount(&legacy)
        .await;
    Mock::given(path(format!("{P}/case-report-template/default-template")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python"})))
        .expect(0)
        .mount(&legacy)
        .await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let (st, body) = h
        .call(
            "POST",
            &format!("{R}/generate-report-docx"),
            Some(&admin),
            Some(json!({})),
        )
        .await;
    assert_eq!((st.as_u16(), body), (200, json!({"from": "python-post"})));
    // Answered here (no MinIO in this harness), never by Python.
    let (_, body) = h
        .call(
            "POST",
            &format!("{P}/case-report-template/default-template"),
            Some(&admin),
            None,
        )
        .await;
    assert_ne!(body, json!({"from": "python"}));
}

// ---------------------------------------------------------------------------
// Writes: SLA tracking, timeline, audit and notifications
// ---------------------------------------------------------------------------

use std::sync::Arc;

use copilot_core::audit::MemoryAuditSink;
use copilot_core::notify::{MemoryNotificationSink, NotificationDefaults, NotificationSeverity};
use copilot_db::connectors::ConnectorCache;
use copilot_web::{AppContext, AppDeps};

/// The incidents router over the harness database, with sinks that keep
/// what is emitted.
struct Sinks {
    router: axum::Router,
    notes: Arc<MemoryNotificationSink>,
    audit: Arc<MemoryAuditSink>,
}

fn with_sinks(h: &Harness) -> Sinks {
    let notes = Arc::new(MemoryNotificationSink::default());
    let audit = Arc::new(MemoryAuditSink::default());
    let ctx = AppContext::new(AppDeps {
        db: h.db.clone(),
        jwt: h.jwt.clone(),
        connectors: ConnectorCache::new(h.db.clone(), std::time::Duration::ZERO),
        audit: audit.clone(),
        notifications: notes.clone(),
        notification_defaults: NotificationDefaults {
            copilot_url: Some("https://copilot.example.com".into()),
            default_severity: NotificationSeverity::High,
        },
        http: reqwest::Client::new(),
        log_handled_errors: false,
    });
    let router = axum::Router::new().nest(P, copilot_incidents::db_operations(ctx));
    Sinks {
        router,
        notes,
        audit,
    }
}

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (u16, Value) {
    use tower::ServiceExt;
    let mut b = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let req = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            b.body(axum::body::Body::from(serde_json::to_vec(&v).unwrap()))
                .unwrap()
        }
        None => b.body(axum::body::Body::empty()).unwrap(),
    };
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes))),
    )
}

async fn tracking_row(
    h: &Harness,
    table: &str,
    key: &str,
    id: i64,
) -> Option<(
    String,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    i32,
)> {
    sqlx::query_as(&format!(
        "SELECT severity, tracked, first_ack_by, first_ack_action, resolved_by, reopen_count \
         FROM {table} WHERE {key} = ?"
    ))
    .bind(id)
    .fetch_optional(h.db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn alert_writes_track_sla_audit_and_notify() {
    let h = harness_or_skip!(None);
    let s = &h.suffix.clone();
    let seeded = seed(&h).await;
    let sinks = with_sinks(&h);
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let admin = h.token(&format!("admin{s}"), "admin");

    // Creation by a SOC user opens the clocks and is its first response.
    let (st, created) = send(
        &sinks.router,
        "POST",
        &format!("{P}/alert"),
        &analyst,
        Some(json!({
            "alert_name": format!("Created {s}"), "alert_description": "d", "status": "OPEN",
            "alert_creation_time": "2026-03-05T10:00:00+02:00", "customer_code": format!("acme{s}"),
            "source": "wazuh", "assigned_to": format!("analyst{s}"),
        })),
    )
    .await;
    assert_eq!(st, 200, "{created}");
    assert_eq!(created["alert_creation_time"], json!("2026-03-05T10:00:00"));
    let id = created["id"].as_i64().unwrap();
    let row = tracking_row(&h, "soc_sla_alert_tracking", "alert_id", id)
        .await
        .unwrap();
    assert_eq!(
        row,
        (
            "High".into(),
            true,
            Some(format!("analyst{s}")),
            Some("created".into()),
            None,
            0
        )
    );

    // Assignment notifies on a change only, with the alert's resolved severity.
    let assign = json!({"alert_id": id, "assigned_to": format!("admin{s}")});
    let (st, _) = send(
        &sinks.router,
        "PUT",
        &format!("{P}/alert/assigned-to"),
        &analyst,
        Some(assign.clone()),
    )
    .await;
    assert_eq!(st, 200);
    let (st, _) = send(
        &sinks.router,
        "PUT",
        &format!("{P}/alert/assigned-to"),
        &analyst,
        Some(assign),
    )
    .await;
    assert_eq!(st, 200);
    let events = sinks.notes.snapshot();
    assert_eq!(events.len(), 1, "{events:?}");
    let e = serde_json::to_value(&events[0]).unwrap();
    assert_eq!(
        e,
        json!({
            "customer_code": format!("acme{s}"), "trigger": "alert_assigned", "severity": "High",
            "subject": format!("Created {s}"), "summary": format!("Alert #{id} was assigned to admin{s}."),
            "entity_type": "alert", "entity_id": id,
            "dedupe_key": format!("alert:{id}:alert_assigned:admin{s}"), "link_url": null,
            "assignee_username": format!("admin{s}"), "actor_username": format!("analyst{s}"),
            "context": {"title": format!("Created {s}")},
        })
    );

    // Closing resolves; a reopen counts; a customer cannot put it on hold.
    for status in ["CLOSED", "OPEN"] {
        let (st, body) = send(
            &sinks.router,
            "PUT",
            &format!("{P}/alert/status"),
            &analyst,
            Some(json!({"alert_id": id, "status": status})),
        )
        .await;
        assert_eq!(st, 200, "{body}");
    }
    let row = tracking_row(&h, "soc_sla_alert_tracking", "alert_id", id)
        .await
        .unwrap();
    assert_eq!((row.4, row.5), (None, 1));
    let (st, body) = send(
        &sinks.router,
        "PUT",
        &format!("{P}/alert/status"),
        &portal,
        Some(json!({"alert_id": id, "status": "PENDING_CUSTOMER"})),
    )
    .await;
    assert_eq!(st, 403, "{body}");

    // A verdict is audited with the before/after values.
    let (st, body) = send(
        &sinks.router,
        "PUT",
        &format!("{P}/alert/verdict"),
        &analyst,
        Some(json!({"alert_id": id, "verdict": "FALSE_POSITIVE", "verdict_reason": "OTHER"})),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let audit = sinks.audit.snapshot();
    let verdict = audit
        .iter()
        .find(|r| r.action == "alert.verdict_set")
        .unwrap();
    assert_eq!(verdict.entity_id.as_deref(), Some(id.to_string().as_str()));
    assert_eq!(
        verdict.old_value,
        Some(
            json!({"verdict": null, "verdict_reason": null, "verdict_note": null, "verdict_by": null})
        )
    );
    assert_eq!(
        verdict.new_value,
        Some(json!({"verdict": "FALSE_POSITIVE", "verdict_reason": "OTHER", "verdict_note": null}))
    );

    // Tenancy: another tenant's alert is refused before anything is written.
    let (st, _) = send(
        &sinks.router,
        "PUT",
        &format!("{P}/alert/escalated"),
        &analyst,
        Some(json!({"alert_id": seeded.beta, "escalated": true})),
    )
    .await;
    assert_eq!(st, 403);
    let escalated: bool =
        sqlx::query_scalar("SELECT escalated FROM incident_management_alert WHERE id = ?")
            .bind(seeded.beta)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert!(!escalated);
    let (st, body) = send(
        &sinks.router,
        "POST",
        &format!("{P}/alerts/verdict-state"),
        &analyst,
        Some(json!({"alert_ids": [id, seeded.beta]})),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(body["missing"], json!([seeded.beta]));
    // ... and the settings of another tenant (a leak closed in Rust).
    let (st, _) = send(
        &sinks.router,
        "PUT",
        &format!("{P}/ai_trigger?customer_code=acme{s}"),
        &analyst,
        Some(json!({"customer_code": format!("beta{s}"), "enabled": true})),
    )
    .await;
    assert_eq!(st, 403);
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incident_management_ai_analyst_trigger_enabled WHERE customer_code = ?",
    )
    .bind(format!("beta{s}"))
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(rows, 0);
    let (st, _) = send(
        &sinks.router,
        "DELETE",
        &format!("{P}/alert/{id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(st, 200);
    assert!(
        tracking_row(&h, "soc_sla_alert_tracking", "alert_id", id)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn case_writes_keep_the_timeline_and_notify() {
    let h = harness_or_skip!(None);
    let s = &h.suffix.clone();
    let seeded = seed(&h).await;
    let sinks = with_sinks(&h);
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");

    let (st, body) = send(
        &sinks.router,
        "POST",
        &format!("{P}/case/create"),
        &analyst,
        Some(json!({
            "case_name": format!("Case {s}"), "case_description": "d", "case_creation_time": "2026-03-05",
            "case_status": "OPEN", "customer_code": format!("acme{s}"),
        })),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let case = body["case"]["id"].as_i64().unwrap();
    assert_eq!(
        body["case"]["case_creation_time"],
        json!("2026-03-05T00:00:00")
    );
    assert!(
        sinks
            .audit
            .snapshot()
            .iter()
            .any(|r| r.action == "case.create")
    );

    // Linking the alert: the case follows its severity (default High).
    let (st, body) = send(
        &sinks.router,
        "POST",
        &format!("{P}/case/alert-link"),
        &analyst,
        Some(json!({"case_id": case, "alert_id": seeded.acme})),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let row = tracking_row(&h, "soc_sla_case_tracking", "case_id", case)
        .await
        .unwrap();
    assert_eq!(
        (row.0.as_str(), row.1, row.3.as_deref()),
        ("High", true, Some("created"))
    );

    // Assignment notifies (internal scope, Informational).
    let (st, _) = send(
        &sinks.router,
        "PUT",
        &format!("{P}/case/assigned-to"),
        &analyst,
        Some(json!({"case_id": case, "assigned_to": format!("analyst{s}")})),
    )
    .await;
    assert_eq!(st, 200);
    let events = sinks.notes.snapshot();
    let e = serde_json::to_value(events.last().unwrap()).unwrap();
    assert_eq!(e["trigger"], json!("case_assigned"));
    assert_eq!(e["severity"], json!("Informational"));
    assert_eq!(
        e["dedupe_key"],
        json!(format!("case:{case}:case_assigned:analyst{s}"))
    );

    // Waiting on the customer takes the alert along; the customer's reply
    // hands both back.
    let (st, body) = send(
        &sinks.router,
        "PUT",
        &format!("{P}/case/status"),
        &analyst,
        Some(json!({"case_id": case, "status": "PENDING_CUSTOMER"})),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["cases"][0]["alerts"][0]["status"],
        json!("PENDING_CUSTOMER")
    );
    let (st, body) = send(
        &sinks.router,
        "POST",
        &format!("{P}/case/comment"),
        &portal,
        Some(json!({"case_id": case, "comment": "done", "user_name": "x"})),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["comment"]["user_name"], json!(format!("portal{s}")));
    let (status, alert_status): (String, String) = sqlx::query_as(
        "SELECT c.case_status, a.status FROM incident_management_case c, incident_management_alert a \
         WHERE c.id = ? AND a.id = ?",
    )
    .bind(case)
    .bind(seeded.acme)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        (status.as_str(), alert_status.as_str()),
        ("IN_PROGRESS", "IN_PROGRESS")
    );
    let timeline: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM incident_management_case_event WHERE case_id = ? ORDER BY id",
    )
    .bind(case)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        timeline,
        [
            "case_created",
            "alert_linked",
            "case_assigned",
            "case_status_changed",
            "comment_added",
            "case_status_changed"
        ]
    );
    let paused: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT paused_at FROM soc_sla_case_tracking WHERE case_id = ?")
            .bind(case)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert!(paused.is_none());
}

#[tokio::test]
async fn case_task_assignment_notifies_and_template_routes_split() {
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    let s = &h.suffix.clone();
    let seeded = seed(&h).await;
    let sinks = with_sinks(&h);
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    let (st, body) = send(
        &sinks.router,
        "POST",
        &format!("{P}/case/{}/tasks", seeded.case_acme),
        &analyst,
        Some(json!({"title": "Check the host", "mandatory": true})),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let task = body["task"]["id"].as_i64().unwrap();
    let (st, body) = send(
        &sinks.router,
        "PATCH",
        &format!("{P}/case/tasks/{task}"),
        &analyst,
        Some(json!({"assigned_to": format!(" admin{s} "), "status": "DONE"})),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["task"]["assigned_to"], json!(format!("admin{s}")));
    assert_eq!(body["task"]["completed_by"], json!(format!("analyst{s}")));
    let events = sinks.notes.snapshot();
    assert_eq!(events.len(), 1);
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap(),
        json!({
            "customer_code": null, "trigger": "case_task_assigned", "severity": "Informational",
            "subject": "Check the host",
            "summary": format!("Task 'Check the host' on case #{} was assigned to admin{s}.", seeded.case_acme),
            "entity_type": "case_task", "entity_id": task,
            "dedupe_key": format!("case_task:{task}:case_task_assigned:admin{s}"), "link_url": null,
            "assignee_username": format!("admin{s}"), "actor_username": format!("analyst{s}"),
            "context": {"title": "Check the host", "case_id": seeded.case_acme},
        })
    );
    let timeline: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM incident_management_case_event WHERE case_id = ? ORDER BY id",
    )
    .bind(seeded.case_acme)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    assert!(timeline.ends_with(&[
        "task_added".to_string(),
        "task_status_changed".to_string(),
        "task_assigned".to_string()
    ]));

    // Templates: the CRUD is Rust, and so are /suggest and the library
    // (copilot-case-templates, e2e_core_leftovers.rs): none reaches Python.
    const T: &str = "/api/incidents/case_templates";
    Mock::given(wiremock::matchers::path_regex(format!(
        "^{T}/(suggest|library)"
    )))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python"})))
    .expect(0)
    .mount(&legacy)
    .await;
    let admin = h.token(&format!("admin{s}"), "admin");
    let (st, body) = h
        .call(
            "GET",
            &format!("{T}/suggest?customer_code=x"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 200);
    assert_eq!(body["success"], json!(true), "{body}");
    let (st, body) = h
        .call("GET", &format!("{T}/999999999"), Some(&admin), None)
        .await;
    assert_eq!(st.as_u16(), 200);
    assert_eq!(
        body,
        json!({"template": null, "success": false, "message": "Template id=999999999 not found"})
    );
}

// ---------------------------------------------------------------------------
// /api/incidents/alerts: the Velociraptor Sigma exclusion rules
// ---------------------------------------------------------------------------

#[tokio::test]
async fn velo_sigma_exclusions_crud_tenancy_and_fall_through() {
    const A: &str = "/api/incidents/alerts";
    const X: &str = "/api/incidents/alerts/create/velo-sigma/exclusion";
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    let s = &h.suffix.clone();
    let seeded = seed(&h).await;
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let admin = h.token(&format!("admin{s}"), "admin");

    // Created in context: provenance checked, link comment left on the alert.
    let body = json!({
        "name": format!("Updater {s}"),
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "field_matches": {"Image": "C:\\u.exe", "CommandLine": "u --check"},
        "customer_code": format!("acme{s}"),
        "source_alert_id": seeded.tagged,
        "source_case_id": seeded.case_acme,
        "created_by": "spoofed",
    });
    let (st, created) = h.call("POST", X, Some(&analyst), Some(body)).await;
    assert_eq!(st.as_u16(), 200, "{created}");
    let rule = &created["exclusion_response"];
    let id = rule["id"].as_i64().unwrap();
    let keys: Vec<&str> = rule
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "name",
            "description",
            "channel",
            "title",
            "field_matches",
            "customer_code",
            "enabled",
            "source_alert_id",
            "source_case_id",
            "id",
            "created_by",
            "created_at",
            "last_matched_at",
            "match_count"
        ]
    );
    assert_eq!(rule["created_by"], json!(format!("analyst{s}")));
    // MySQL's JSON order, as the refresh reads it back.
    assert_eq!(
        serde_json::to_string(&rule["field_matches"]).unwrap(),
        r#"{"Image":"C:\\u.exe","CommandLine":"u --check"}"#
    );
    assert_eq!(
        created["message"],
        json!("Exclusion rule created successfully")
    );
    let comment: String = sqlx::query_scalar(
        "SELECT comment FROM incident_management_comment WHERE alert_id = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(seeded.tagged)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        comment,
        format!(
            "Exclusion rule created from this alert: #{id} \"Updater {s}\" (customer acme{s}, \
             enabled) by analyst{s}"
        )
    );

    // Provenance and customer of another tenant.
    for (body, want) in [
        (
            json!({"name": "x", "source_alert_id": seeded.beta}),
            format!(
                "Access denied to alert {} - insufficient customer permissions",
                seeded.beta
            ),
        ),
        (
            json!({"name": "x", "source_case_id": seeded.case_beta}),
            format!("Access denied to case {}", seeded.case_beta),
        ),
        (
            json!({"name": "x", "customer_code": format!("beta{s}")}),
            format!("Access denied to customer beta{s} - insufficient customer permissions"),
        ),
    ] {
        let (st, out) = h.call("POST", X, Some(&analyst), Some(body)).await;
        assert_eq!(st.as_u16(), 403, "{out}");
        assert_eq!(out["message"], json!(want));
    }
    let (st, out) = h
        .call(
            "POST",
            X,
            Some(&analyst),
            Some(json!({"name": "x", "source_case_id": 999999999})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), &out["message"]),
        (404, &json!("Case not found"))
    );

    // Another tenant's rule reads as missing; shared rules stay everyone's.
    let beta_rule = h
        .exec(&format!(
            "INSERT INTO incident_management_velo_sigma_exclusion (name, customer_code, created_by, \
             created_at, match_count, enabled, field_matches) VALUES ('Beta {s}', 'beta{s}', 'admin', \
             '2026-03-01 10:00:00', 0, 1, NULL)"
        ))
        .await;
    for (m, uri) in [
        ("GET", format!("{X}/{beta_rule}")),
        ("DELETE", format!("{X}/{beta_rule}")),
        (
            "POST",
            format!("{A}/velo-sigma/exclusion/{beta_rule}/toggle"),
        ),
    ] {
        let (st, out) = h.call(m, &uri, Some(&analyst), None).await;
        assert_eq!(
            (st.as_u16(), &out["message"]),
            (404, &json!("Exclusion rule not found")),
            "{m}"
        );
    }
    let (st, out) = h
        .call(
            "PATCH",
            &format!("{X}/{beta_rule}"),
            Some(&analyst),
            Some(json!({"name": "x"})),
        )
        .await;
    assert_eq!(st.as_u16(), 404, "{out}");
    let (_, listed) = h
        .call("GET", &format!("{X}?limit=1000"), Some(&analyst), None)
        .await;
    let seen: Vec<i64> = ids(&listed, "exclusions");
    assert!(seen.contains(&id) && !seen.contains(&beta_rule));
    assert_eq!(
        listed["pagination"]["total"].as_u64().unwrap() as usize,
        seen.len()
    );
    let (_, listed) = h
        .call("GET", &format!("{X}?limit=1000"), Some(&admin), None)
        .await;
    assert!(ids(&listed, "exclusions").contains(&beta_rule));
    let (_, one) = h
        .call(
            "GET",
            &format!("{X}?source_alert_id={}", seeded.tagged),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(ids(&one, "exclusions"), vec![id]);

    // Edits: only what was sent; a JSON null is stored as JSON null.
    let (st, out) = h
        .call(
            "PATCH",
            &format!("{X}/{id}"),
            Some(&analyst),
            Some(json!({"field_matches": null, "description": "benign", "customer_code": format!("beta{s}")})),
        )
        .await;
    assert_eq!(st.as_u16(), 403, "{out}");
    let (st, out) = h
        .call(
            "PATCH",
            &format!("{X}/{id}"),
            Some(&analyst),
            Some(json!({"field_matches": null, "description": "benign"})),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{out}");
    assert_eq!(out["exclusion_response"]["field_matches"], Value::Null);
    assert_eq!(
        out["exclusion_response"]["name"],
        json!(format!("Updater {s}"))
    );
    let (is_null, kind): (bool, Option<String>) = sqlx::query_as(
        "SELECT field_matches IS NULL, CAST(JSON_TYPE(field_matches) AS CHAR) FROM \
         incident_management_velo_sigma_exclusion WHERE id = ?",
    )
    .bind(id)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!((is_null, kind.as_deref()), (false, Some("NULL")));
    let (st, out) = h
        .call(
            "POST",
            &format!("{A}/velo-sigma/exclusion/{id}/toggle"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), &out["exclusion_response"]["enabled"]),
        (200, &json!(false))
    );
    let (st, out) = h
        .call("DELETE", &format!("{X}/{id}"), Some(&analyst), None)
        .await;
    assert_eq!(
        (st.as_u16(), out),
        (
            200,
            json!({"message": "Exclusion rule deleted successfully", "success": true})
        )
    );

    // The rest of /api/incidents/alerts is copilot-ingest's (e2e_ingest);
    // a method no Rust router takes is Python's.
    for (m, p) in [("PUT", "/create/velo-sigma/exclusion/1".to_string())] {
        Mock::given(method(m))
            .and(path(format!("{A}{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python"})))
            .mount(&legacy)
            .await;
        let (st, out) = h
            .call(m, &format!("{A}{p}"), Some(&admin), Some(json!({})))
            .await;
        assert_eq!(
            (st.as_u16(), out),
            (200, json!({"from": "python"})),
            "{m} {p}"
        );
    }
}

// ---------------------------------------------------------------------------
// Reports: the CSV exports and the customer-report list are Rust
// ---------------------------------------------------------------------------

#[tokio::test]
async fn csv_exports_and_report_list_split_with_python() {
    use tower::ServiceExt;
    const R: &str = "/api/incidents/report";
    const CR: &str = "/api/incidents/customer_reports";
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    let s = &h.suffix.clone();
    let seeded = seed(&h).await;
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let admin = h.token(&format!("admin{s}"), "admin");

    // The per-customer export: Python's headers and CSV dialect.
    h.exec(&format!(
        "UPDATE incident_management_case SET case_description = 'one, \"two\"\nthree' WHERE id = {}",
        seeded.case_acme
    ))
    .await;
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("{R}/generate-report-csv/acme{s}"))
        .header("authorization", format!("Bearer {analyst}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.headers()["content-type"], "text/csv; charset=utf-8");
    let disposition = resp.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        disposition.starts_with(&format!("attachment; filename=cases_export_acme{s}_")),
        "{disposition}"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let csv = String::from_utf8(bytes.to_vec()).unwrap();
    let mut lines = csv.split('\n');
    assert_eq!(
        lines.next().unwrap(),
        "Case ID,Case Name,Case Description,Case Creation Time,Case Status,Case Closed Time,\
         Case Assigned To,Case Customer Code,Alert ID,Alert Name,Alert Description,Alert Status,\
         Alert Creation Time,Alert Time Closed,Alert Source,Alert Assigned To,Assets,Tags,\
         Comments,Customer Code"
    );
    assert!(csv.contains(&format!(
        "{},Case acme{s},\"one, \"\"two\"\"\nthree\",2026-03-04 09:00:00,OPEN,,,acme{s},{},",
        seeded.case_acme, seeded.tagged
    )));
    assert!(csv.ends_with(&format!(",t{s},look,acme{s}\n")), "{csv}");

    // The whole-deployment export is the caller's customers' only.
    let (st, all) = h
        .call(
            "POST",
            &format!("{R}/generate-report-csv"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 200);
    let all = all.as_str().unwrap();
    assert!(all.contains(&format!(",acme{s}\n")) && !all.contains(&format!("beta{s}")));
    let (st, out) = h
        .call(
            "POST",
            &format!("{R}/generate-report-csv/beta{s}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), &out["message"]),
        (403, &json!(format!("Access denied to customer beta{s}")))
    );

    // Customer reports: the list and the switch here, the rest in Python.
    let report = h
        .exec(&format!(
            "INSERT INTO incident_management_customer_reports (report_name, customer_code, \
             bucket_name, object_key, file_name, file_size, file_hash, generated_at, generated_by, \
             generated_by_role, date_from, date_to, filters_json, total_alerts, total_cases, \
             open_cases, closed_cases, status, visible_to_customer) VALUES ('R {s}', 'acme{s}', \
             'b', 'k', 'r.pdf', 1, 'h', '2026-03-05 10:00:00', 1, 'admin', '2026-02-01 00:00:00', \
             '2026-02-28 00:00:00', '{{\"a\": 1}}', 0, 0, 0, 0, 'completed', 0)"
        ))
        .await;
    let (st, listed) = h
        .call(
            "GET",
            &format!("{CR}?customer_codes=acme{s}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{listed}");
    assert_eq!(listed["total_count"], json!(1));
    assert_eq!(listed["reports"][0]["filters_applied"], json!({"a": 1}));
    assert_eq!(
        listed["reports"][0]["download_url"],
        json!(format!(
            "/api/v1/incidents/customer_reports/{report}/download"
        ))
    );
    let (st, out) = h
        .call(
            "PATCH",
            &format!("{CR}/{report}/visibility"),
            Some(&analyst),
            Some(json!({"visible": true})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), out),
        (
            200,
            json!({"success": true, "message": "Report is now visible to the customer.",
                   "report_id": report, "visible_to_customer": true})
        )
    );
    for (m, p) in [
        ("POST", format!("{R}/generate-report-docx")),
        ("POST", format!("{R}/generate-report-pdf")),
        ("POST", format!("{CR}/generate/background")),
    ] {
        Mock::given(method(m))
            .and(path(p.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python"})))
            .mount(&legacy)
            .await;
        let (st, out) = h.call(m, &p, Some(&admin), Some(json!({}))).await;
        assert_eq!(
            (st.as_u16(), out),
            (200, json!({"from": "python"})),
            "{m} {p}"
        );
    }
}
