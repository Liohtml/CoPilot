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
    Mock::given(method("GET"))
        .and(path(format!("{P}/available-source/wazuh-alerts")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python-get"})))
        .mount(&legacy)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("{P}/alert/status")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python-put"})))
        .mount(&legacy)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{P}/case/data-store/download/1/f.txt")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python-dl"})))
        .mount(&legacy)
        .await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    for (m, uri, want) in [
        (
            "GET",
            format!("{P}/available-source/wazuh-alerts"),
            "python-get",
        ),
        ("PUT", format!("{P}/alert/status"), "python-put"),
        (
            "GET",
            format!("{P}/case/data-store/download/1/f.txt"),
            "python-dl",
        ),
    ] {
        let (st, body) = h.call(m, &uri, Some(&admin), Some(json!({}))).await;
        assert_eq!(
            (st.as_u16(), body),
            (200, json!({"from": want})),
            "{m} {uri}"
        );
    }
}
