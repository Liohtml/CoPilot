//! End-to-end tests: the production router against a real MySQL migrated to
//! the Alembic head, Talon and the Python backend replaced by recorders.
//!
//! Skipped unless `COPILOT_TEST_DATABASE_URL` points at a **disposable**
//! database (the backend's 13306 convention):
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13306/copilot \
//!   cargo test -p copilot --test e2e -- --test-threads=1
//! ```
//!
//! Every test seeds its own customers and users (random suffix), so reruns
//! never collide. Two things are global — the `Talon` connector row and the
//! tag-access settings — which is why the suite runs single-threaded.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use axum::body::Body;
use copilot_core::config::Secret;
use http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

#[tokio::test]
async fn auth_errors_match_the_python_backend() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let path = "/api/ai_analyst/alerts_with_reports";

    let (st, body) = h.call("GET", path, None, None).await;
    assert_eq!(st, 401);
    assert_eq!(
        body,
        json!({"success": false, "message": "Not authenticated"})
    );

    let (st, body) = h.call("GET", path, Some("not-a-jwt"), None).await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (401, Some("Invalid token"))
    );

    let expired = h
        .jwt
        .encode_claims(
            json!({"sub": format!("admin{s}"), "exp": 1})
                .as_object()
                .unwrap(),
        )
        .unwrap();
    let (st, body) = h.call("GET", path, Some(&expired), None).await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (401, Some("Expired signature"))
    );

    let pending = h
        .jwt
        .encode_claims(
            json!({"sub": format!("admin{s}"), "exp": 4_102_444_800_u64, "type": "2fa_pending"})
                .as_object()
                .unwrap(),
        )
        .unwrap();
    let (st, body) = h.call("GET", path, Some(&pending), None).await;
    assert_eq!(st, 401);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("Two-factor authentication required")
    );

    let (st, body) = h
        .call("GET", path, Some(&h.token("ghost-user-xyz", "admin")), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (401, Some("User not found"))
    );

    let (st, body) = h
        .call(
            "GET",
            path,
            Some(&h.token(&format!("portal{s}"), "customer_user")),
            None,
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        "Insufficient permissions. Required one of: admin, analyst"
    );

    // A responder's token carries "analyst" and passes.
    let (st, _) = h
        .call(
            "GET",
            path,
            Some(&h.token(&format!("responder{s}"), "responder")),
            None,
        )
        .await;
    assert_eq!(st, 200);

    // Unknown route without a legacy backend: FastAPI's 404 body.
    let (st, body) = h.call("GET", "/api/nothing-here", None, None).await;
    assert_eq!((st.as_u16(), body), (404, json!({"detail": "Not Found"})));

    // The 401s above were written to log_entries, like Python's handlers do.
    let mut logged = 0;
    for _ in 0..20 {
        logged = h
            .scalar_i64("SELECT COUNT(*) FROM log_entries WHERE message = 'User not found' AND event_type = 'Error'")
            .await;
        if logged > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        logged > 0,
        "expected a log_entries row for the handled error"
    );
}

#[tokio::test]
async fn tenant_scoping_is_fail_closed() {
    let h = harness_or_skip!(None);
    let (acme_alert, beta_alert) = h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    // Admin writes a job + report for each customer.
    for (alert, code) in [(acme_alert, h.code("acme")), (beta_alert, h.code("beta"))] {
        let job_id = format!("copilot-inv-{alert}-1");
        let (st, body) = h
            .call("POST", "/api/ai_analyst/jobs", Some(&admin),
                Some(json!({"id": job_id, "alert_id": alert, "customer_code": code, "triggered_by": "webhook"})))
            .await;
        assert_eq!(st, 200, "{body}");
        let (st, body) = h
            .call(
                "POST",
                "/api/ai_analyst/reports",
                Some(&admin),
                Some(json!({
                "job_id": job_id, "alert_id": alert, "customer_code": code,
                "severity_assessment": "High", "summary": "s", "report_markdown": "# r",
                "recommended_actions": "isolate"})),
            )
            .await;
        assert_eq!(st, 200, "{body}");
    }

    // The analyst sees acme only — even when naming no customer (Python leaked here).
    let (st, body) = h
        .call(
            "GET",
            "/api/ai_analyst/alerts_with_reports",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    let codes: Vec<&str> = body["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["customer_code"].as_str().unwrap())
        .collect();
    assert!(
        !codes.is_empty() && codes.iter().all(|c| *c == h.code("acme")),
        "{codes:?}"
    );
    let (_, body) = h
        .call(
            "GET",
            &format!(
                "/api/ai_analyst/alerts_with_reports?customer_codes={}",
                h.code("beta")
            ),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["alerts"], json!([]));
    assert_eq!(body["message"], "0 alerts with reports found");

    // Object tenancy: another tenant's alert, and a nonexistent id, are 403s.
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/ai_analyst/alert/{beta_alert}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str().map(str::to_string)),
        (403, Some(format!("Access denied to alert {beta_alert}")))
    );
    let (st, _) = h
        .call(
            "GET",
            "/api/ai_analyst/reports/999999999",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403);
    // …while an admin gets the service's 404.
    let (st, body) = h
        .call(
            "GET",
            "/api/ai_analyst/reports/999999999",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (404, Some("Report 999999999 not found"))
    );

    // Body tenancy.
    let (st, body) = h
        .call("POST", "/api/ai_analyst/palace_lessons", Some(&analyst),
            Some(json!({"customer_code": h.code("beta"), "lesson_type": "assets", "lesson_text": "x"})))
        .await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        format!("Access denied to customer {}", h.code("beta"))
    );

    // Path validation: FastAPI's int_parsing.
    let (st, body) = h
        .call("GET", "/api/ai_analyst/alert/abc", Some(&analyst), None)
        .await;
    assert_eq!(st, 422);
    assert_eq!(body["message"], "Input is not a valid integer.");
    assert_eq!(body["details"][0]["field"], "alert_id");
}

#[tokio::test]
async fn talon_and_ai_analyst_flow() {
    let talon = MockServer::start().await;
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    let (acme_alert, _beta_alert) = h.seed().await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    h.exec("DELETE FROM connectors WHERE connector_name = 'Talon'")
        .await;
    h.exec(&format!(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_api_key, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_enabled) VALUES \
         ('Talon', '3', '{}', UTC_TIMESTAMP(), 'talon-key', 1, 1, 0, 1, 0, 0, 0, 1)",
        talon.uri()
    ))
    .await;

    // --- Talon: the analyst asks for an investigation -------------------------
    Mock::given(method("POST"))
        .and(path("/investigate"))
        .and(header("x-api-key", "talon-key"))
        .and(body_json(
            json!({"alert_id": acme_alert, "customer_code": acme, "triggered_by": "manual",
                   "sender": "copilot-analyst"}),
        ))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "job_id": format!("copilot-inv-{acme_alert}-1760000000000"), "status": "queued",
            "template_override": null, "deduplicated": false})))
        .expect(1)
        .mount(&talon)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/talon/investigate",
            Some(&analyst),
            Some(json!({"alert_id": acme_alert, "customer_code": acme})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["message"], "Investigation triggered successfully");
    assert_eq!(body["data"]["status"], "queued");
    let (st, body) = h
        .call(
            "POST",
            "/api/talon/investigate",
            Some(&analyst),
            Some(json!({"alert_id": acme_alert, "customer_code": "someone-else"})),
        )
        .await;
    assert_eq!(st, 400);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("customer_code mismatch")
    );

    // --- Talon's agent writes back (admin token, as the MCP server uses) ------
    let job_id = format!("copilot-inv-{acme_alert}-1760000000000");
    // Status before the job exists: auto-created from the id.
    let (st, body) = h
        .call(
            "PATCH",
            &format!("/api/ai_analyst/jobs/{job_id}"),
            Some(&admin),
            Some(json!({"status": "running"})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["job"]["customer_code"], acme.as_str());
    assert_eq!(body["job"]["triggered_by"], "webhook");
    assert!(body["job"]["started_at"].is_string());
    let (st, body) = h
        .call(
            "POST",
            "/api/ai_analyst/jobs",
            Some(&admin),
            Some(json!({
            "id": job_id, "alert_id": acme_alert, "customer_code": acme,
            "triggered_by": "manual", "template_used": "sysmon_event_1.txt"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (200, Some("Job updated"))
    );
    assert_eq!(body["job"]["status"], "running");

    // A report without its body is refused with Python's message.
    let (st, body) = h
        .call(
            "POST",
            "/api/ai_analyst/reports",
            Some(&admin),
            Some(json!({"job_id": job_id, "alert_id": acme_alert, "customer_code": acme})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["message"],
        "Report body fields must be non-empty: severity_assessment, summary, report_markdown, recommended_actions. A report missing these persists a blank row in CoPilot."
    );

    // Notifications are dispatched in-process: a webhook route per AI
    // trigger, and the customer's AI report switch on (AI-sourced events
    // never reach a customer-facing route without it).
    h.exec(&format!(
        "INSERT INTO customer_portal_ai_report_settings (customer_code, enabled, updated_at) \
         VALUES ('{acme}', 1, UTC_TIMESTAMP())"
    ))
    .await;
    for (trigger, hook) in [
        ("investigation_complete", "/hook/ic"),
        ("ai_report_reviewed", "/hook/review"),
    ] {
        let (st, body) = h
            .call(
                "POST",
                &format!("/api/customers/{acme}/notification_routes"),
                Some(&admin),
                Some(json!({"name": format!("AI {trigger}"), "trigger": trigger,
                    "channel": "webhook", "min_severity": "Low",
                    "config": {"url": format!("{}{hook}", legacy.uri())}})),
            )
            .await;
        assert_eq!(st, 200, "{body}");
    }
    Mock::given(method("POST"))
        .and(wiremock::matchers::path_regex("^/hook/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&legacy)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/ai_analyst/reports",
            Some(&admin),
            Some(json!({
            "job_id": job_id, "alert_id": acme_alert, "customer_code": acme,
            "severity_assessment": "Critical", "summary": "Credential dumping.\u{0007}",
            "report_markdown": "# Report", "recommended_actions": "Isolate dc01"})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["message"], "Report submitted");
    assert_eq!(
        body["report"]["summary"], "Credential dumping.",
        "control characters stripped"
    );
    let report_id = body["report"]["id"].as_i64().unwrap();

    let (st, body) = h
        .call("POST", "/api/ai_analyst/iocs", Some(&admin), Some(json!({
            "report_id": report_id, "alert_id": acme_alert, "customer_code": acme,
            "iocs": [{"ioc_value": "203.0.113.7", "ioc_type": "ip", "vt_verdict": "malicious", "vt_score": "12/90"},
                     {"ioc_value": "mimikatz.exe", "ioc_type": "process"}]})))
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["message"], "2 IOCs submitted");
    assert_eq!(body["iocs_created"], 2);
    assert_eq!(body["iocs"][1]["vt_verdict"], "unknown");
    let ioc_id = body["iocs"][0]["id"].as_i64().unwrap();

    let (_, body) = h
        .call(
            "PATCH",
            &format!("/api/ai_analyst/jobs/{job_id}"),
            Some(&admin),
            Some(json!({"status": "completed"})),
        )
        .await;
    assert!(body["job"]["completed_at"].is_string());

    // --- The analyst reads it ----------------------------------------------
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/ai_analyst/alert/{acme_alert}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["message"], "Alert analysis retrieved");
    assert_eq!(body["job"]["status"], "completed");
    assert_eq!(body["report"]["id"], report_id);
    assert_eq!(body["iocs"].as_array().unwrap().len(), 2);
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/talon/jobs/{acme_alert}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["data"]["id"], job_id.as_str());
    assert_eq!(body["data"]["reports"][0]["id"], report_id);

    // --- Review: create, then edit (one row per reviewer) -------------------
    let review_path = format!("/api/ai_analyst/reports/{report_id}/review");
    let (st, body) = h
        .call(
            "POST",
            &review_path,
            Some(&analyst),
            Some(json!({
            "overall_verdict": "up", "template_choice": "correct", "rating_instructions": 4,
            "rating_artifacts": 5, "rating_severity": 3,
            "ioc_reviews": [{"ioc_id": ioc_id, "verdict_correct": true}]})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["message"], "Review created");
    assert_eq!(
        body["review"]["template_used"], "sysmon_event_1.txt",
        "inherited from the job"
    );
    let (_, body) = h
        .call(
            "POST",
            &review_path,
            Some(&analyst),
            Some(json!({"overall_verdict": "down"})),
        )
        .await;
    assert_eq!(body["message"], "Review updated");
    assert!(
        body["review"]["rating_instructions"].is_null(),
        "unsent fields are cleared on edit"
    );
    assert_eq!(body["review"]["ioc_reviews"], json!([]));
    let (st, body) = h
        .call(
            "POST",
            &review_path,
            Some(&analyst),
            Some(json!({"ioc_reviews": [{"ioc_id": 999999999, "verdict_correct": false}]})),
        )
        .await;
    assert_eq!(st, 400);
    assert_eq!(
        body["message"],
        format!("IOC 999999999 not found or does not belong to report {report_id}")
    );
    let (_, body) = h
        .call("GET", &format!("{review_path}/mine"), Some(&analyst), None)
        .await;
    assert_eq!(body["message"], "Existing review retrieved");

    let (_, stats) = h
        .call(
            "GET",
            &format!("/api/ai_analyst/reviews/customer/{acme}/stats?recent_limit=5"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(stats["total_reviews"], 1);
    assert_eq!(stats["thumbs_down"], 1);
    assert_eq!(stats["thumbs_up_pct"], 0.0);
    assert_eq!(
        stats["per_template"][0]["template_used"],
        "sysmon_event_1.txt"
    );

    // --- Notifications went out in-process: report + first review only -----
    // Each event is dispatched from a spawned task: wait for both.
    let mut hooks: Vec<(String, Value)> = Vec::new();
    for _ in 0..100 {
        hooks = legacy
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.url.path().starts_with("/hook/"))
            .map(|r| {
                (
                    r.url.path().to_string(),
                    serde_json::from_slice::<Value>(&r.body).unwrap(),
                )
            })
            .collect();
        if hooks.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    hooks.sort_by(|a, b| a.0.cmp(&b.0));
    let paths: Vec<&str> = hooks.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        vec!["/hook/ic", "/hook/review"],
        "one each, the edit sent nothing"
    );
    let link = format!("https://copilot.example.com/alerts/{acme_alert}");
    let ic = &hooks[0].1;
    assert_eq!(ic["customer_code"], acme.as_str());
    assert_eq!(ic["alert_id"], acme_alert);
    assert_eq!(ic["alert_name"], "Mimikatz acme");
    assert_eq!(ic["severity"], "Critical");
    assert_eq!(ic["summary"], "Credential dumping.");
    assert_eq!(ic["report_url"], link.as_str());
    let review = &hooks[1].1;
    assert_eq!(review["report_url"], link.as_str());
    assert_eq!(review["alert_name"], "Mimikatz acme");
    // The dispatch log holds the re-derived dedupe keys and the reviewer.
    let mut logged = Vec::new();
    for _ in 0..50 {
        logged = sqlx::query_as::<_, (String, String, Option<String>)>(&format!(
            "SELECT dedupe_key, status, triggered_by FROM notification_dispatch_log \
             WHERE customer_code = '{acme}' ORDER BY dedupe_key"
        ))
        .fetch_all(h.db.pool())
        .await
        .unwrap();
        if logged.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        logged,
        vec![
            (
                format!("alert:{acme_alert}:ai_report_reviewed"),
                "sent".into(),
                Some(format!("analyst{s}"))
            ),
            (
                format!("alert:{acme_alert}:investigation_complete"),
                "sent".into(),
                None
            ),
        ]
    );
    assert!(
        legacy
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .all(|r| r.url.path() != "/api/notifications/events"),
        "nothing is handed to the Python backend any more"
    );

    // --- Replay goes to Talon with the forced template -----------------------
    Mock::given(method("POST"))
        .and(path("/investigate"))
        .and(body_json(
            json!({"alert_id": acme_alert, "customer_code": acme, "triggered_by": "manual",
            "template_override": "sysmon_event_1.v2.txt", "sender": "copilot-replay"}),
        ))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(json!({"job_id": "j2", "status": "queued",
            "template_override": "sysmon_event_1.v2.txt", "deduplicated": false})),
        )
        .expect(1)
        .mount(&talon)
        .await;
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/ai_analyst/reports/{report_id}/replay"),
            Some(&analyst),
            Some(json!({"template_override": "sysmon_event_1.v2.txt", "customer_code": acme})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "Replay triggered", "data": {
        "job_id": "j2", "status": "queued", "template_override": "sysmon_event_1.v2.txt", "deduplicated": false}})
    );

    // --- Palace: queue, search, drain, consolidate ----------------------------
    for text in [
        "DC01 runs SCCM patching at 02:00",
        "dc01 runs sccm patching at 02:00 nightly",
    ] {
        let (st, body) = h
            .call("POST", "/api/ai_analyst/palace_lessons", Some(&analyst),
                Some(json!({"customer_code": acme, "lesson_type": "assets", "lesson_text": text, "durability": "one_off"})))
            .await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body["lesson"]["status"], "pending");
    }
    Mock::given(method("POST"))
        .and(path("/palace/lesson"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"drawer_id": "drawer-1"})))
        .mount(&talon)
        .await;
    let report = copilot_ai_analyst::palace_jobs::drain_once(&h.app.ctx, &h.app.talon)
        .await
        .unwrap();
    assert!(report.ingested >= 2, "{report:?}");
    let (_, digest) = h
        .call(
            "GET",
            &format!("/api/ai_analyst/palace_lessons/customer/{acme}/consolidation"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(digest["total_ingested"], 2);
    assert_eq!(digest["duplicate_candidates"].as_array().unwrap().len(), 1);
    assert_eq!(digest["upcoming_expirations"].as_array().unwrap().len(), 0);
    assert!(
        digest["markdown"]
            .as_str()
            .unwrap()
            .contains("near-duplicate pair(s)")
    );

    Mock::given(method("GET"))
        .and(path("/palace/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"lessons": [
            {"id": "drawer-1", "room": "assets", "text": "DC01 …", "score": 0.91, "extra": true}]})))
        .mount(&talon)
        .await;
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/ai_analyst/palace_lessons/customer/{acme}?query=sccm&limit=3"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["message"], "1 palace lessons matched");
    assert_eq!(
        body["lessons"][0],
        json!({"id": "drawer-1", "room": "assets", "wing": null,
        "text": "DC01 …", "source_file": null, "score": 0.91, "metadata": null})
    );
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/ai_analyst/palace_lessons/customer/{acme}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["details"][0]["field"].as_str()),
        (422, Some("query"))
    );

    // --- Chat streams through untouched --------------------------------------
    Mock::given(method("POST"))
        .and(path("/message"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(
                    "data: {\"type\":\"text\",\"content\":\"hi\"}\n\ndata: {\"type\":\"done\"}\n\n",
                ),
        )
        .mount(&talon)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/talon/message",
            Some(&analyst),
            Some(json!({"message": "hello"})),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        Value::String(
            "data: {\"type\":\"text\",\"content\":\"hi\"}\n\ndata: {\"type\":\"done\"}\n\n".into()
        )
    );
    let sent = talon.received_requests().await.unwrap();
    let msg: Value = serde_json::from_slice(
        &sent
            .iter()
            .rev()
            .find(|r| r.url.path() == "/message")
            .unwrap()
            .body,
    )
    .unwrap();
    let analyst_id = h
        .scalar_i64(&format!(
            "SELECT CAST(id AS SIGNED) FROM `user` WHERE username = 'analyst{s}'"
        ))
        .await;
    assert_eq!(
        msg,
        json!({"message": "hello", "sender": "copilot", "user_id": analyst_id.to_string(), "user_name": format!("analyst{s}")})
    );
}

#[tokio::test]
async fn unported_routes_are_proxied_to_the_python_backend() {
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    // (`/api/agents`, its report routers, `GET /api/sysmon_config`, the
    // Sublime connector and the file analysis are ported now: a path no Python
    // route has stands for the routes still in Python.)
    Mock::given(method("GET"))
        .and(path("/api/legacy-only-e2e/history"))
        .and(header("authorization", "Bearer abc"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-from", "python")
                .set_body_json(json!({"success": true, "agents": []})),
        )
        .expect(1)
        .mount(&legacy)
        .await;
    let (st, body) = h
        .call(
            "GET",
            "/api/legacy-only-e2e/history?customer_code=x",
            Some("abc"),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body, json!({"success": true, "agents": []}));
    let req = &legacy.received_requests().await.unwrap()[0];
    assert_eq!(req.url.query(), Some("customer_code=x"));

    // A method no route of a Python path has is answered here, as Starlette
    // answers it (the first route whose path matched names `Allow`): the
    // legacy backend is not asked about a path of the Python app.
    let before = legacy.received_requests().await.unwrap().len();
    let (st, body) = h
        .call("DELETE", "/api/ai_analyst/jobs/x", Some("abc"), None)
        .await;
    assert_eq!(st, 405);
    assert_eq!(body, json!({"detail": "Method Not Allowed"}));
    assert_eq!(legacy.received_requests().await.unwrap().len(), before);

    // Ported routes are not proxied.
    let (st, _) = h
        .call("GET", "/api/ai_analyst/alerts_with_reports", None, None)
        .await;
    assert_eq!(st, 401);
    assert_eq!(legacy.received_requests().await.unwrap().len(), before);
}

/// Poll until `sql` (a `COUNT(*)`) reaches `want`: audit rows are written by
/// a spawned task.
async fn wait_count(h: &Harness, sql: &str, want: i64) -> i64 {
    let mut n = 0;
    for _ in 0..40 {
        n = h.scalar_i64(sql).await;
        if n >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    n
}

impl Harness {
    async fn talon_connector(&self, talon: &MockServer) {
        self.exec("DELETE FROM connectors WHERE connector_name = 'Talon'")
            .await;
        self.exec(&format!(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
             connector_api_key, connector_configured, connector_verified, connector_accepts_host_only, \
             connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_enabled) VALUES \
             ('Talon', '3', '{}', UTC_TIMESTAMP(), 'talon-key', 1, 1, 0, 1, 0, 0, 0, 1)",
            talon.uri()
        ))
        .await;
    }

    async fn alert(&self, customer: &str, name: &str) -> i64 {
        self.exec(&format!(
            "INSERT INTO incident_management_alert (alert_name, alert_description, status, \
             alert_creation_time, customer_code, source, escalated) VALUES \
             ('{name}', 'd', 'OPEN', UTC_TIMESTAMP(), '{customer}', 'wazuh', 0)"
        ))
        .await
    }

    /// A job (`ago` minutes old) with one report; returns the report id.
    async fn analysis(
        &self,
        alert: i64,
        customer: &str,
        n: u32,
        status: &str,
        ago: u32,
        severity: &str,
    ) -> i64 {
        let job = format!("copilot-inv-{alert}-{n}{}", self.suffix);
        self.exec(&format!(
            "INSERT INTO ai_analyst_job (id, alert_id, customer_code, status, alert_type, triggered_by, \
             template_used, created_at, error_message) VALUES ('{job}', {alert}, '{customer}', '{status}', \
             'sigma', 'scheduled', 'internal-template', UTC_TIMESTAMP() - INTERVAL {ago} MINUTE, 'agent trace')"
        ))
        .await;
        self.exec(&format!(
            "INSERT INTO ai_analyst_report (job_id, alert_id, customer_code, severity_assessment, summary, \
             report_markdown, recommended_actions, created_at) VALUES ('{job}', {alert}, '{customer}', \
             '{severity}', 'summary {n}', '# report {n}', 'isolate', UTC_TIMESTAMP() - INTERVAL {ago} MINUTE)"
        ))
        .await
    }
}

#[tokio::test]
async fn customer_portal_ai_reports_flow() {
    let talon = MockServer::start().await;
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    let (acme_alert, beta_alert) = h.seed().await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let admin_id = h
        .scalar_i64(&format!(
            "SELECT id FROM `user` WHERE username = 'admin{s}'"
        ))
        .await;
    h.talon_connector(&talon).await;
    let settings_url = |c: &str| format!("/api/customer_portal/ai_reports/settings/{c}");
    let msg = |b: &Value| b["message"].as_str().unwrap_or_default().to_string();

    // --- Operator switch: read ---------------------------------------------------
    let (st, body) = h
        .call("GET", &settings_url(&acme), Some(&analyst), None)
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"settings": {"customer_code": acme, "enabled": false, "allow_customer_requests": false,
               "daily_request_limit": null, "requests_last_24h": 0, "updated_at": null, "updated_by": null},
               "success": true, "message": "Customer AI report settings retrieved successfully"})
    );
    let (st, body) = h
        .call("GET", &settings_url(&beta), Some(&analyst), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (403, format!("Access denied to customer {beta}"))
    );
    let (st, body) = h
        .call("GET", &settings_url(&acme), Some(&portal), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            403,
            "Insufficient permissions. Required one of: admin, analyst".into()
        )
    );

    // --- Operator switch: write (admin only, body before existence) ----------------
    let on = json!({"enabled": true});
    let (st, body) = h
        .call(
            "PUT",
            &settings_url(&acme),
            Some(&analyst),
            Some(on.clone()),
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            403,
            "Insufficient permissions. Required one of: admin".into()
        )
    );
    let (st, body) = h
        .call(
            "PUT",
            &settings_url("nosuch"),
            Some(&admin),
            Some(json!({"daily_request_limit": 0})),
        )
        .await;
    assert_eq!(st, 422, "{body}");
    assert_eq!(body["details"].as_array().unwrap().len(), 2, "{body}");
    let (st, body) = h
        .call(
            "PUT",
            &settings_url("nosuch"),
            Some(&admin),
            Some(on.clone()),
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (404, "Customer nosuch not found".into())
    );
    let (st, body) = h
        .call("PUT", &settings_url(&acme), Some(&admin), Some(on.clone()))
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["message"],
        "Customer AI report settings saved successfully"
    );
    assert_eq!(body["settings"]["enabled"], true);
    assert_eq!(body["settings"]["allow_customer_requests"], false);
    assert_eq!(body["settings"]["updated_by"], admin_id);
    assert!(
        body["settings"]["updated_at"].as_str().unwrap().len() == 19,
        "{body}"
    );
    let audit_sql = format!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'ai_report.settings_update' AND entity_id = '{acme}'"
    );
    assert_eq!(wait_count(&h, &audit_sql, 1).await, 1);
    let (st, _) = h
        .call("PUT", &settings_url(&acme), Some(&admin), Some(on.clone()))
        .await;
    assert_eq!(st, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        h.scalar_i64(&audit_sql).await,
        1,
        "an unchanged save is not audited"
    );

    // --- Availability --------------------------------------------------------------
    let avail = "/api/customer_portal/ai_reports/availability";
    let (_, body) = h.call("GET", avail, Some(&portal), None).await;
    assert_eq!(
        body,
        json!({"customer_code": null, "enabled": true, "success": true, "message": "AI reports are enabled"})
    );
    let (st, body) = h
        .call(
            "GET",
            &format!("{avail}?customer_code={beta}"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (403, format!("Access denied to customer {beta}"))
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("{avail}?customer_code={beta}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        body,
        json!({"customer_code": beta, "enabled": false, "success": true, "message": "AI reports are not enabled"})
    );

    // --- Findings: two jobs on acme's alert (latest wins), one on beta's -------------
    h.analysis(acme_alert, &acme, 1, "completed", 120, "Low")
        .await;
    let report = h
        .analysis(acme_alert, &acme, 2, "completed", 60, "High")
        .await;
    h.exec(&format!(
        "INSERT INTO ai_analyst_ioc (report_id, alert_id, customer_code, ioc_value, ioc_type, vt_verdict, \
         vt_score, created_at) VALUES ({report}, {acme_alert}, '{acme}', '1.2.3.4', 'ip', 'malicious', '5/90', \
         UTC_TIMESTAMP())"
    ))
    .await;
    h.analysis(beta_alert, &beta, 1, "completed", 30, "Medium")
        .await;

    let alert_url = |id: i64| format!("/api/customer_portal/ai_reports/alert/{id}");
    let (st, body) = h
        .call("GET", &alert_url(acme_alert), Some(&portal), None)
        .await;
    assert_eq!(st, 200, "{body}");
    let keys: Vec<_> = body.as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        [
            "alert_id",
            "enabled",
            "can_request",
            "has_analysis",
            "investigation",
            "report",
            "iocs",
            "success",
            "message"
        ]
    );
    assert_eq!(body["has_analysis"], true);
    assert_eq!(body["can_request"], false);
    assert_eq!(body["report"]["id"], report);
    assert_eq!(body["report"]["severity_assessment"], "High");
    assert_eq!(body["iocs"][0]["ioc_value"], "1.2.3.4");
    assert_eq!(body["investigation"]["triggered_by"], "scheduled");
    let raw = body.to_string();
    for leak in ["copilot-inv", "internal-template", "agent trace", "job_id"] {
        assert!(!raw.contains(leak), "{leak} reached the portal: {raw}");
    }
    let (st, body) = h
        .call("GET", &alert_url(beta_alert), Some(&portal), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            403,
            format!("Access denied to alert {beta_alert} - insufficient customer permissions")
        )
    );
    let (st, body) = h
        .call("GET", &alert_url(999_999_999), Some(&portal), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (404, "Alert 999999999 not found".into())
    );
    let (st, _) = h
        .call(
            "GET",
            "/api/customer_portal/ai_reports/alert/abc",
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(st, 422);
    // An admin reading beta (switch off) learns that, and nothing else.
    let (_, body) = h
        .call("GET", &alert_url(beta_alert), Some(&admin), None)
        .await;
    assert_eq!(body["enabled"], false);
    assert_eq!(body["report"], Value::Null);
    assert_eq!(
        body["message"],
        "AI analyst findings are not enabled for this customer"
    );

    // --- Insights: latest report per alert, switch and visibility applied -----------
    let insights = "/api/customer_portal/ai_reports/insights";
    let (_, body) = h.call("GET", insights, Some(&portal), None).await;
    assert_eq!(body["total_reports"], 1, "{body}");
    assert_eq!(body["severity_counts"], json!({"High": 1}));
    assert_eq!(body["recent"][0]["alert_id"], acme_alert);
    assert_eq!(body["recent"][0]["alert_name"], "Mimikatz acme");
    assert_eq!(body["message"], "1 alerts with an AI report found");
    let (_, body) = h
        .call(
            "GET",
            &format!("{insights}?customer_codes={beta}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(body["total_reports"], 0, "beta's switch is off: {body}");
    let (st, _) = h
        .call("GET", &format!("{insights}?limit=26"), Some(&portal), None)
        .await;
    assert_eq!(st, 422);

    // --- Requests ------------------------------------------------------------------
    let investigate = |id: i64| format!("/api/customer_portal/ai_reports/alert/{id}/investigate");
    let (st, body) = h
        .call("POST", &investigate(acme_alert), Some(&portal), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            403,
            "Requesting an AI analysis is not enabled for this customer".into()
        )
    );
    let refused_sql = format!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'ai_analysis.request' AND result = 'failure' \
         AND entity_id = '{acme_alert}'"
    );
    assert_eq!(wait_count(&h, &refused_sql, 1).await, 1);

    let (st, body) = h
        .call(
            "PUT",
            &settings_url(&acme),
            Some(&admin),
            Some(
                json!({"enabled": true, "allow_customer_requests": true, "daily_request_limit": 2}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["settings"]["daily_request_limit"], 2);

    let alert2 = h.alert(&acme, "second").await;
    let alert3 = h.alert(&acme, "third").await;
    let alert4 = h.alert(&acme, "fourth").await;
    let alert5 = h.alert(&acme, "fifth").await;
    for (id, status) in [(acme_alert, 202), (alert2, 500), (alert3, 202)] {
        Mock::given(method("POST"))
            .and(path("/investigate"))
            .and(header("x-api-key", "talon-key"))
            .and(body_json(
                json!({"alert_id": id, "customer_code": acme, "triggered_by": "manual",
                       "sender": "customer-portal"}),
            ))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({"job_id": "x", "status": "queued"})),
            )
            .expect(1)
            .mount(&talon)
            .await;
    }

    let (st, body) = h
        .call("POST", &investigate(acme_alert), Some(&portal), None)
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["message"],
        "AI analysis requested: it will appear here once the AI analyst has finished"
    );
    let stored: String = sqlx::query_scalar(&format!(
        "SELECT DATE_FORMAT(requested_at, '%Y-%m-%dT%H:%i:%s') FROM customer_portal_ai_request \
         WHERE alert_id = {acme_alert}"
    ))
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(body["requested_at"], stored);
    let (who, text): (String, String) = sqlx::query_as(&format!(
        "SELECT user_name, comment FROM incident_management_comment WHERE alert_id = {acme_alert}"
    ))
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        (who.as_str(), text.as_str()),
        (
            format!("portal{s}").as_str(),
            "AI analysis requested from the Customer Portal."
        )
    );

    // A double click: the request itself starts the cooldown.
    let (st, body) = h
        .call("POST", &investigate(acme_alert), Some(&portal), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            429,
            "This alert was analysed recently. You can request a new analysis in 30 minutes."
                .into()
        )
    );

    // Talon refuses: 502, nothing spent, Talon's text never reaches the customer.
    let (st, body) = h
        .call("POST", &investigate(alert2), Some(&portal), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            502,
            "The AI analyst could not start the analysis. Please try again later.".into()
        )
    );
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM customer_portal_ai_request WHERE alert_id = {alert2}"
        ))
        .await,
        0
    );

    let (st, body) = h
        .call("POST", &investigate(alert3), Some(&portal), None)
        .await;
    assert_eq!(st, 200, "{body}");
    let (st, body) = h
        .call("POST", &investigate(alert4), Some(&portal), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            429,
            "Your organization has reached its daily limit of AI analyses. Please try again later."
                .into()
        )
    );
    h.exec(&format!(
        "INSERT INTO ai_analyst_job (id, alert_id, customer_code, status, triggered_by, created_at) \
         VALUES ('copilot-inv-{alert5}-r{s}', {alert5}, '{acme}', 'running', 'manual', UTC_TIMESTAMP())"
    ))
    .await;
    let (st, body) = h
        .call("POST", &investigate(alert5), Some(&portal), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            409,
            "An AI analysis of this alert is already in progress".into()
        )
    );
    // The analyst cannot ask for another tenant's alert either.
    let (st, _) = h
        .call("POST", &investigate(beta_alert), Some(&analyst), None)
        .await;
    assert_eq!(st, 403);

    let (_, body) = h
        .call("GET", &settings_url(&acme), Some(&admin), None)
        .await;
    assert_eq!(body["settings"]["requests_last_24h"], 2);
    let ok_sql = format!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'ai_analysis.request' AND result = 'success' \
         AND customer_code = '{acme}'"
    );
    assert_eq!(wait_count(&h, &ok_sql, 2).await, 2);
    let failed_talon = format!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'ai_analysis.request' AND entity_id = '{alert2}' \
         AND details = 'The AI analyst could not start the analysis'"
    );
    assert_eq!(wait_count(&h, &failed_talon, 1).await, 1);

    // --- A path outside the Python app still reaches the legacy backend --------------
    Mock::given(method("GET"))
        .and(path("/api/legacy-only-e2e/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python"})))
        .expect(1)
        .mount(&legacy)
        .await;
    let (st, body) = h
        .call("GET", "/api/legacy-only-e2e/history", Some(&portal), None)
        .await;
    assert_eq!((st.as_u16(), body), (200, json!({"from": "python"})));
    // A method the Python app's path does not take is Starlette's 405, here.
    Mock::given(method("DELETE"))
        .and(path(settings_url(&acme)))
        .respond_with(
            ResponseTemplate::new(405).set_body_json(json!({"detail": "Method Not Allowed"})),
        )
        .expect(0)
        .mount(&legacy)
        .await;
    let (st, body) = h
        .call("DELETE", &settings_url(&acme), Some(&admin), None)
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (405, json!({"detail": "Method Not Allowed"}))
    );
}

#[tokio::test]
async fn customer_portal_ai_reports_follow_tag_rbac() {
    let h = harness_or_skip!(None);
    if h.scalar_i64("SELECT COUNT(*) FROM incident_management_tag_access_settings")
        .await
        > 0
    {
        eprintln!("tag access settings already configured in this database; skipping");
        return;
    }
    let (acme_alert, _) = h.seed().await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    h.exec(&format!(
        "INSERT INTO customer_portal_ai_report_settings (customer_code, enabled, allow_customer_requests, \
         updated_at) VALUES ('{acme}', 1, 0, UTC_TIMESTAMP())"
    ))
    .await;
    h.analysis(acme_alert, &acme, 1, "completed", 10, "High")
        .await;
    let tag = h
        .exec(&format!(
            "INSERT INTO incident_management_alerttag (tag) VALUES ('e2e{s}')"
        ))
        .await;
    h.exec(&format!(
        "INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES ({acme_alert}, {tag})"
    ))
    .await;
    let settings = h
        .exec(
            "INSERT INTO incident_management_tag_access_settings (enabled, untagged_alert_behavior, \
             updated_at) VALUES (1, 'admin_only', UTC_TIMESTAMP())",
        )
        .await;

    // Collect first, clean up, then assert: tag RBAC is global state.
    let alert_url = format!("/api/customer_portal/ai_reports/alert/{acme_alert}");
    let insights = "/api/customer_portal/ai_reports/insights";
    let denied = h.call("GET", &alert_url, Some(&analyst), None).await;
    let analyst_insights = h.call("GET", insights, Some(&analyst), None).await;
    let portal_insights = h.call("GET", insights, Some(&portal), None).await;
    h.exec(&format!(
        "INSERT INTO user_tag_access (user_id, tag_id, created_at) \
         SELECT id, {tag}, UTC_TIMESTAMP() FROM `user` WHERE username = 'analyst{s}'"
    ))
    .await;
    let granted = h.call("GET", &alert_url, Some(&analyst), None).await;
    let granted_insights = h.call("GET", insights, Some(&analyst), None).await;
    h.exec(&format!(
        "DELETE FROM incident_management_tag_access_settings WHERE id = {settings}"
    ))
    .await;
    h.exec(&format!("DELETE FROM user_tag_access WHERE tag_id = {tag}"))
        .await;
    h.exec(&format!(
        "DELETE FROM incident_management_alert_to_tag WHERE tag_id = {tag}"
    ))
    .await;
    h.exec(&format!(
        "DELETE FROM incident_management_alerttag WHERE id = {tag}"
    ))
    .await;

    assert_eq!(denied.0, 403);
    assert_eq!(
        denied.1["message"],
        format!("Access denied to alert {acme_alert} - insufficient tag permissions")
    );
    assert_eq!(
        analyst_insights.1["total_reports"], 0,
        "{}",
        analyst_insights.1
    );
    assert_eq!(
        portal_insights.1["total_reports"], 1,
        "portal users bypass tag RBAC"
    );
    assert_eq!(granted.0, 200, "{}", granted.1);
    assert_eq!(granted.1["has_analysis"], true);
    assert_eq!(granted_insights.1["total_reports"], 1);
}

impl Harness {
    /// An agent of `customer`, last seen `wazuh_ago` minutes ago (negative:
    /// in the future), with an optional Velociraptor check-in.
    async fn agent(
        &self,
        customer: &str,
        agent_id: &str,
        wazuh_ago: i64,
        velo_ago: Option<i64>,
    ) -> i64 {
        let (velo_id, velo_seen) = match velo_ago {
            Some(m) => (
                format!("'C.{agent_id}'"),
                format!("UTC_TIMESTAMP() - INTERVAL {m} MINUTE"),
            ),
            None => ("NULL".into(), "NULL".into()),
        };
        self.exec(&format!(
            "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, \
             wazuh_last_seen, velociraptor_id, velociraptor_last_seen, wazuh_agent_version, \
             wazuh_agent_status, customer_code, quarantined) VALUES ('{agent_id}', '10.0.0.1', \
             'Linux', 'host-{agent_id}', 'lbl', 0, UTC_TIMESTAMP() - INTERVAL {wazuh_ago} MINUTE, \
             {velo_id}, {velo_seen}, '4.9.0', 'active', '{customer}', 0)"
        ))
        .await
    }
}

#[tokio::test]
async fn customer_and_healthcheck_reads() {
    let legacy = MockServer::start().await;
    let h = harness_or_skip!(Some(&legacy));
    h.seed().await;
    let s = h.suffix.clone();
    let (acme, beta) = (h.code("acme"), h.code("beta"));
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let msg = |b: &Value| b["message"].as_str().unwrap_or_default().to_string();
    h.exec(&format!(
        "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, \
         customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group, \
         customer_meta_index_retention, customer_meta_portainer_stack_id) VALUES \
         ('{acme}', 'acme corp', 'idx', 'stream', '7', 'grp', '30d', 4)"
    ))
    .await;
    let (fresh, stale, future, velo, other) = (
        format!("a{s}1"),
        format!("a{s}2"),
        format!("a{s}3"),
        format!("a{s}4"),
        format!("b{s}1"),
    );
    h.agent(&acme, &fresh, 5, None).await;
    h.agent(&acme, &stale, 600, None).await;
    h.agent(&acme, &future, -600, None).await;
    h.agent(&acme, &velo, 1, Some(2)).await;
    h.agent(&beta, &other, 5, Some(5)).await;

    // --- List: scoped, searchable, capped ---------------------------------------
    let list = |q: &str| format!("/api/customers?search={s}{q}");
    let codes = |b: &Value| -> Vec<String> {
        b["customers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["customer_code"].as_str().unwrap().to_string())
            .collect()
    };
    let (st, body) = h.call("GET", &list(""), Some(&admin), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(codes(&body), [acme.clone(), beta.clone()]);
    assert_eq!(body["customers"][0]["is_provisioned"], true);
    assert_eq!(body["customers"][1]["is_provisioned"], false);
    assert_eq!(body["message"], "Customers fetched successfully");
    let (_, body) = h.call("GET", &list(""), Some(&analyst), None).await;
    assert_eq!(
        codes(&body),
        std::slice::from_ref(&acme),
        "an analyst sees only their customers"
    );
    let (_, body) = h.call("GET", &list("&limit=1"), Some(&admin), None).await;
    assert_eq!(codes(&body).len(), 1);
    let (st, body) = h.call("GET", &list("&limit=0"), Some(&admin), None).await;
    assert_eq!(st, 422, "{body}");
    let (st, body) = h.call("GET", &list(""), Some(&portal), None).await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            403,
            "Insufficient permissions. Required one of: admin, analyst".into()
        )
    );

    // --- One customer ----------------------------------------------------------
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/customers/{acme}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["customer"]["customer_name"], "acme corp");
    assert_eq!(body["customer"]["is_provisioned"], Value::Null);
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/customers/{beta}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (403, format!("Access denied to customer {beta}"))
    );
    let (st, body) = h
        .call("GET", "/api/customers/nosuch-e2e", Some(&admin), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            404,
            "Customer with customer_code nosuch-e2e not found".into()
        )
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/customers/{acme}/meta"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(body["customer_meta"]["customer_meta_portainer_stack_id"], 4);
    assert_eq!(
        body["customer_meta"]["customer_meta_wazuh_api_port"],
        Value::Null
    );
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/customers/{beta}/meta"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            404,
            format!("Customer meta with customer_code {beta} not found")
        )
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/customers/{beta}/full"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        body["message"],
        "Customer fetched successfully but customer meta not found"
    );
    assert_eq!(body["customer_meta"], Value::Null);
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/customers/{acme}/full"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        body["message"],
        "Customer and customer meta fetched successfully"
    );

    // --- Agents and their health -----------------------------------------------
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/customers/{acme}/agents"),
            Some(&analyst),
            None,
        )
        .await;
    let agents = body["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 4, "{body}");
    assert_eq!(agents[0]["wazuh_agent_status"], "active");
    assert_eq!(agents[0]["quarantined"], false);
    let ids = |b: &Value, key: &str| -> Vec<String> {
        b[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key}: {b}"))
            .iter()
            .map(|a| a["agent_id"].as_str().unwrap().to_string())
            .collect()
    };
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/customers/{acme}/agents/healthcheck/wazuh"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        ids(&body, "healthy_wazuh_agents"),
        [fresh.clone(), velo.clone()]
    );
    assert_eq!(
        ids(&body, "unhealthy_wazuh_agents"),
        [stale.clone(), future.clone()]
    );
    assert_eq!(body["healthy_velociraptor_agents"], Value::Null);
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/customers/{acme}/agents/healthcheck/velociraptor?minutes=1"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        ids(&body, "healthy_velociraptor_agents"),
        Vec::<String>::new(),
        "2 min > 1 min"
    );
    assert_eq!(ids(&body, "unhealthy_velociraptor_agents").len(), 4);
    let (st, _) = h
        .call(
            "GET",
            &format!("/api/customers/{acme}/agents/healthcheck/wazuh?days=x"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 422);

    let (_, body) = h
        .call("GET", "/api/healthcheck/wazuh", Some(&analyst), None)
        .await;
    let seen = [
        ids(&body, "healthy_wazuh_agents"),
        ids(&body, "unhealthy_wazuh_agents"),
    ]
    .concat();
    assert!(
        seen.contains(&fresh) && !seen.contains(&other),
        "scoped to acme: {seen:?}"
    );
    let (_, body) = h
        .call(
            "GET",
            "/api/healthcheck/velociraptor?hours=1",
            Some(&admin),
            None,
        )
        .await;
    assert!(ids(&body, "healthy_velociraptor_agents").contains(&other));
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/healthcheck/wazuh/{other}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (403, format!("Access denied to agent {other}"))
    );
    let (st, _) = h
        .call(
            "GET",
            "/api/healthcheck/wazuh/nope-e2e",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403, "an unknown agent fails closed for a scoped caller");
    let (st, body) = h
        .call("GET", "/api/healthcheck/wazuh/nope-e2e", Some(&admin), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (404, "Agent with agent_id nope-e2e not found".into())
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/healthcheck/velociraptor/{velo}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        ids(&body, "healthy_velociraptor_agents"),
        std::slice::from_ref(&velo)
    );

    // --- The writes are answered here (copilot-customers) ----------------------
    let before = legacy.received_requests().await.unwrap().len();
    for (m, p) in [
        ("POST", "/api/customers".to_string()),
        ("PUT", format!("/api/customers/{acme}")),
        ("POST", format!("/api/customers/{acme}/meta")),
    ] {
        let (st, _) = h.call(m, &p, Some(&admin), Some(json!({}))).await;
        assert_eq!(st.as_u16(), 422, "{m} {p}");
    }
    let (st, body) = h
        .call(
            "DELETE",
            "/api/customers/nosuch-e2e/meta",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 404);
    assert_eq!(
        msg(&body),
        "Customer meta with customer_code nosuch-e2e not found"
    );
    assert_eq!(legacy.received_requests().await.unwrap().len(), before);

    // --- The host logs are answered here too (the host before the indexer) ------
    let (st, _) = h
        .call(
            "POST",
            "/api/healthcheck/logs",
            Some(&admin),
            Some(json!({})),
        )
        .await;
    assert_eq!(st, 422);
    let (st, body) = h
        .call(
            "POST",
            "/api/healthcheck/logs",
            Some(&admin),
            Some(json!({"agent_name": "nosuch-e2e"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (404, "Agent with hostname nosuch-e2e not found".into())
    );
    let (st, _) = h
        .call(
            "POST",
            "/api/healthcheck/logs",
            Some(&analyst),
            Some(json!({"agent_name": "nosuch-e2e"})),
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(legacy.received_requests().await.unwrap().len(), before);
}

#[tokio::test]
async fn audit_reads_and_version_check() {
    let github = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tag_name": "v9.9.9", "name": "v9.9.9", "html_url": "https://example.com/r",
            "published_at": "2026-10-01T00:00:00Z", "body": "notes"})))
        .mount(&github)
        .await;
    let h = harness_or_skip!(
        None,
        &format!(
            "COPILOT_VERSION_CHECK_URL={}/releases/latest\n",
            github.uri()
        )
    );
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let msg = |b: &Value| b["message"].as_str().unwrap_or_default().to_string();

    // --- Version: no token needed ----------------------------------------------
    let (st, body) = h.call("GET", "/api/version/check", None, None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "New version v9.9.9 available!",
               "current_version": copilot_platform::version::CURRENT_VERSION,
               "latest_version": "9.9.9", "is_outdated": true,
               "release_url": "https://example.com/r", "release_notes": "notes",
               "published_at": "2026-10-01T00:00:00Z"})
    );

    // --- Audit: admin only, the get_current_user way ---------------------------
    let entity = format!("e2e{s}");
    for (i, (ts, result)) in [
        ("2026-01-01 10:00:00", "success"),
        ("2026-01-01 11:00:00", "failure"),
        ("2026-01-01 12:00:00", "success"),
    ]
    .into_iter()
    .enumerate()
    {
        h.exec(&format!(
            "INSERT INTO audit_log (timestamp, actor_user_id, actor_username, customer_code, action, \
             entity_type, entity_id, result, old_value, new_value, details) VALUES ('{ts}', 1, \
             'admin{s}', '{c}', 'case.create', 'case', '{entity}', '{result}', \
             '{{\"enabled\": false, \"a\": 1}}', NULL, 'row {i}')",
            c = h.code("acme")
        ))
        .await;
    }
    let audit = |q: &str| format!("/api/audit?entity_id={entity}{q}");
    let (st, body) = h.call("GET", &audit(""), Some(&admin), None).await;
    assert_eq!(st, 200, "{body}");
    let details: Vec<_> = body["audit_logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["details"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(details, ["row 2", "row 1", "row 0"], "newest first");
    assert_eq!(
        body["pagination"],
        json!({"total": 3, "skip": 0, "limit": 100})
    );
    assert_eq!(body["message"], "Retrieved 3 of 3 audit log entries");
    assert_eq!(
        body["audit_logs"][0]["old_value"],
        json!({"a": 1, "enabled": false}),
        "MySQL's JSON key order"
    );
    let (_, body) = h
        .call("GET", &audit("&result=failure"), Some(&admin), None)
        .await;
    assert_eq!(body["pagination"]["total"], 1);
    let (_, body) = h
        .call(
            "GET",
            &audit("&start_time=2026-01-01T11:00:00%2B05:00&skip=1&limit=1"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        body["pagination"],
        json!({"total": 2, "skip": 1, "limit": 1}),
        "offset dropped"
    );
    assert_eq!(body["audit_logs"][0]["details"], "row 1");
    let (_, body) = h
        .call("GET", &audit("&search=ROW%201"), Some(&admin), None)
        .await;
    assert_eq!(body["pagination"]["total"], 1, "case-insensitive search");
    let (st, body) = h
        .call("GET", &audit("&start_time=abc&limit=0"), Some(&admin), None)
        .await;
    assert_eq!(st, 422);
    assert_eq!(body["details"].as_array().unwrap().len(), 2, "{body}");
    assert_eq!(body["message"], "Value is too small.");
    assert_eq!(
        body["details"][1]["message"],
        "start_time: Input should be a valid datetime or date, input is too short"
    );

    let (st, body) = h.call("GET", &audit(""), Some(&analyst), None).await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            403,
            "Insufficient permissions. Required scope: admin".into()
        )
    );
    let (st, body) = h.call("GET", &audit(""), None, None).await;
    assert_eq!((st.as_u16(), msg(&body)), (401, "Not authenticated".into()));
    let (st, body) = h.call("GET", &audit(""), Some("garbage"), None).await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (401, "Could not decode token: 401: Invalid token".into())
    );

    let (_, body) = h
        .call("GET", "/api/audit/actions", Some(&admin), None)
        .await;
    assert!(
        body["actions"]
            .as_array()
            .unwrap()
            .contains(&json!("ai_analysis.request"))
    );
    assert_eq!(body["results"], json!(["success", "failure"]));
    let id = h
        .scalar_i64(&format!(
            "SELECT MIN(id) FROM audit_log WHERE entity_id = '{entity}'"
        ))
        .await;
    let (_, body) = h
        .call("GET", &format!("/api/audit/{id}"), Some(&admin), None)
        .await;
    assert_eq!(body["audit_log"]["details"], "row 0");
    assert_eq!(body["message"], "Audit log entry retrieved successfully");
    let (st, body) = h
        .call("GET", "/api/audit/999999999", Some(&admin), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (404, "Audit log 999999999 not found".into())
    );
    let (st, _) = h.call("GET", "/api/audit/abc", Some(&admin), None).await;
    assert_eq!(st, 422);
}

/// The current TOTP code of the secret stored for `username`.
async fn totp_now(h: &Harness, username: &str, offset: i64) -> String {
    let enc: String = sqlx::query_scalar(
        "SELECT t.secret_enc FROM user_totp t JOIN `user` u ON u.id = t.user_id WHERE u.username = ?",
    )
    .bind(username)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    // Python's key derivation: no TOTP_ENCRYPTION_KEY in this harness.
    let fernet = copilot_auth::Fernet::derived_from_jwt_secret(&Secret::new(SECRET));
    let secret = String::from_utf8(fernet.decrypt(&enc).unwrap()).unwrap();
    let totp = copilot_auth::totp::Totp::new(&secret).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp.code(copilot_auth::totp::counter_at(now).saturating_add_signed(offset))
}

#[tokio::test]
async fn login_refresh_and_two_factor_flow() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let hash = copilot_auth::password::hash_password("Pa55word!").unwrap();
    h.exec(&format!(
        "UPDATE `user` SET password = '{hash}' WHERE username IN ('admin{s}', 'analyst{s}', 'portal{s}')"
    ))
    .await;
    let (admin, analyst, portal) = (
        format!("admin{s}"),
        format!("analyst{s}"),
        format!("portal{s}"),
    );
    let audits = |action: &str, details: &str, user: &str| {
        format!(
            "SELECT COUNT(*) FROM audit_log WHERE action = '{action}' AND details = '{details}' \
             AND actor_username = '{user}'"
        )
    };

    // --- password login, urlencoded ------------------------------------
    let (st, body) = h.login("/api/auth/token", &admin, "Pa55word!").await;
    assert_eq!(st, 200, "{body}");
    let keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["access_token", "token_type"]);
    assert_eq!(body["token_type"], "bearer");
    let claims = h
        .jwt
        .decode_claims(body["access_token"].as_str().unwrap())
        .unwrap();
    let claim_keys: Vec<&str> = claims.keys().map(String::as_str).collect();
    assert_eq!(claim_keys, ["exp", "iat", "sub", "scopes"]);
    assert_eq!(claims["scopes"], json!(["admin"]));
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        1440 * 60
    );
    assert_eq!(
        wait_count(&h, &audits("auth.login", "Main portal login", &admin), 1).await,
        1
    );
    let stamped = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM `user` WHERE username = '{admin}' AND last_login_at IS NOT NULL"
        ))
        .await;
    assert_eq!(stamped, 1);

    // --- the same login as multipart (what the frontend's FormData sends)
    let multipart = format!(
        "--XyZ\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n{analyst}\r\n\
         --XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nPa55word!\r\n--XyZ--\r\n"
    );
    let (st, body) = h
        .call_raw(
            "POST",
            "/api/auth/token",
            None,
            Some("multipart/form-data; boundary=XyZ"),
            multipart,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let claims = h
        .jwt
        .decode_claims(body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims["scopes"], json!(["analyst"]));

    // --- refusals ---------------------------------------------------------
    let (st, body) = h.login("/api/auth/token", &admin, "wrong").await;
    assert_eq!(
        (st.as_u16(), body),
        (
            401,
            json!({"success": false, "message": "Incorrect username or password"})
        )
    );
    assert_eq!(
        wait_count(
            &h,
            &audits(
                "auth.login_failed",
                "Invalid username or password (main portal)",
                &admin
            ),
            1
        )
        .await,
        1
    );
    let (st, _) = h.login("/api/auth/token", &format!("nobody{s}"), "x").await;
    assert_eq!(st, 401);
    let (st, body) = h.login("/api/auth/token", &portal, "Pa55word!").await;
    assert_eq!(st, 403);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("Customer Portal only")
    );
    let (st, body) = h
        .login("/api/auth/token/customer-portal", &admin, "Pa55word!")
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (
            403,
            Some("This account does not have access to the Customer Portal.")
        )
    );
    let (st, body) = h
        .call_raw(
            "POST",
            "/api/auth/token",
            None,
            Some("application/x-www-form-urlencoded"),
            "username=&grant_type=x",
        )
        .await;
    assert_eq!(st, 422);
    let fields: Vec<&str> = body["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, ["grant_type", "username", "password"]);
    let (st, body) = h
        .call_raw(
            "POST",
            "/api/auth/token",
            None,
            Some("multipart/form-data"),
            "x",
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (400, json!({"detail": "Missing boundary in multipart."}))
    );

    // --- customer portal login carries the customer codes ----------------
    let (st, body) = h
        .login("/api/auth/token/customer-portal", &portal, "Pa55word!")
        .await;
    assert_eq!(st, 200, "{body}");
    let portal_token = body["access_token"].as_str().unwrap().to_string();
    let claims = h.jwt.decode_claims(&portal_token).unwrap();
    assert_eq!(claims["customer_codes"], json!([format!("acme{s}")]));
    let with_code = format!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login' AND actor_username = '{portal}' \
         AND customer_code = 'acme{s}' AND details = 'Customer portal login'"
    );
    assert_eq!(wait_count(&h, &with_code, 1).await, 1);

    // --- refresh ------------------------------------------------------------
    let (st, body) = h
        .call("GET", "/api/auth/refresh", Some(&portal_token), None)
        .await;
    assert_eq!(st, 200);
    let claims = h
        .jwt
        .decode_claims(body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims["customer_codes"], json!([format!("acme{s}")]));
    assert_eq!(claims["scopes"], json!(["customer_user"]));
    let (st, body) = h.call("GET", "/api/auth/refresh", None, None).await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (401, Some("Not authenticated"))
    );

    // --- 2FA enrolment ----------------------------------------------------
    let token = h.token(&admin, "admin");
    let (st, body) = h
        .call("GET", "/api/auth/2fa/status", Some(&token), None)
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"enabled": false, "message": "2FA status retrieved", "success": true})
        )
    );
    // Malformed JSON is reported before the missing token, like FastAPI.
    let (st, body) = h
        .call_raw(
            "POST",
            "/api/auth/2fa/verify-setup",
            None,
            Some("application/json"),
            "{bad",
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["details"][0]["field"].as_str()),
        (422, Some("1"))
    );
    let (st, _) = h
        .call("POST", "/api/auth/2fa/verify-setup", None, Some(json!({})))
        .await;
    assert_eq!(st, 401);

    let (st, setup) = h
        .call("POST", "/api/auth/2fa/setup", Some(&token), None)
        .await;
    assert_eq!(st, 200, "{setup}");
    let secret = setup["secret"].as_str().unwrap();
    assert_eq!(
        setup["otpauth_url"],
        format!("otpauth://totp/CoPilot:{admin}?secret={secret}&issuer=CoPilot")
    );
    assert!(
        setup["qr_data_uri"]
            .as_str()
            .unwrap()
            .starts_with("data:image/png;base64,")
    );
    let codes: Vec<String> = setup["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(codes.len(), 8);
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/verify-setup",
            Some(&token),
            Some(json!({"code": "abcdef"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (
            400,
            Some("Invalid verification code. Check your authenticator app and device clock.")
        )
    );
    let code = totp_now(&h, &admin, 0).await;
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/verify-setup",
            Some(&token),
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"message": "Two-factor authentication is now enabled.", "success": true})
        )
    );
    let (st, body) = h
        .call("POST", "/api/auth/2fa/setup", Some(&token), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (
            400,
            Some("2FA is already enabled. Disable it first to reconfigure.")
        )
    );

    // --- 2FA login ----------------------------------------------------------
    let (st, body) = h.login("/api/auth/token", &admin, "Pa55word!").await;
    assert_eq!(st, 200);
    assert_eq!(body["requires_2fa"], true);
    let temp = body["access_token"].as_str().unwrap().to_string();
    let (st, body) = h
        .call("GET", "/api/auth/2fa/status", Some(&temp), None)
        .await;
    assert_eq!(st, 401);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("Two-factor authentication required")
    );
    let validate = |factor: Value| {
        let mut b = json!({"temp_token": temp});
        b.as_object_mut()
            .unwrap()
            .extend(factor.as_object().unwrap().clone());
        b
    };
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/validate",
            None,
            Some(validate(json!({"code": ""}))),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (400, Some("Provide a TOTP code or backup code."))
    );
    // A code whose time step was already used is a replay (set the guard
    // ahead rather than racing the 30 s boundary).
    let admin_totp = format!(
        "UPDATE user_totp SET last_used_at = {{}} WHERE user_id = \
         (SELECT id FROM `user` WHERE username = '{admin}')"
    );
    let counter_now = || {
        copilot_auth::totp::counter_at(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    };
    h.exec(&admin_totp.replace("{}", &(counter_now() + 5).to_string()))
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/validate",
            None,
            Some(validate(json!({"code": totp_now(&h, &admin, 0).await}))),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (
            401,
            Some("This code has already been used. Wait for a new code.")
        )
    );
    let backup = format!("  {} ", codes[0].to_lowercase());
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/validate",
            None,
            Some(validate(json!({"backup_code": backup}))),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        h.jwt
            .decode_claims(body["access_token"].as_str().unwrap())
            .unwrap()["sub"],
        admin
    );
    assert_eq!(
        wait_count(
            &h,
            &audits("auth.login", "Main portal login (2FA)", &admin),
            1
        )
        .await,
        1
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/validate",
            None,
            Some(validate(json!({"backup_code": codes[0]}))),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (401, Some("Invalid backup code."))
    );
    // A later time step logs in and becomes the new guard.
    h.exec(&admin_totp.replace("{}", &(counter_now() - 2).to_string()))
        .await;
    let before = counter_now();
    let code = totp_now(&h, &admin, 0).await;
    let (st, _) = h
        .call(
            "POST",
            "/api/auth/2fa/validate",
            None,
            Some(validate(json!({"code": code}))),
        )
        .await;
    assert_eq!(st, 200);
    let guard = h
        .scalar_i64(&format!(
            "SELECT last_used_at FROM user_totp WHERE user_id = (SELECT id FROM `user` WHERE username = '{admin}')"
        ))
        .await;
    assert!(
        (before..=counter_now()).contains(&(guard as u64)),
        "{guard}"
    );

    // --- backup codes, disable --------------------------------------------
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/backup-codes/regenerate",
            Some(&token),
            Some(json!({"code": "abcdef"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (400, Some("Invalid authentication code."))
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/backup-codes/regenerate",
            Some(&token),
            Some(json!({"code": totp_now(&h, &admin, 0).await})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let fresh = body["backup_codes"][0].as_str().unwrap().to_string();
    let (st, _) = h
        .call(
            "POST",
            "/api/auth/2fa/validate",
            None,
            Some(validate(json!({"backup_code": codes[1]}))),
        )
        .await;
    assert_eq!(st, 401);
    let (st, body) = h
        .call(
            "DELETE",
            "/api/auth/2fa/disable",
            Some(&token),
            Some(json!({})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (400, Some("Provide a TOTP code or backup code."))
    );
    let (st, body) = h
        .call(
            "DELETE",
            "/api/auth/2fa/disable",
            Some(&token),
            Some(json!({"backup_code": fresh})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"message": "Two-factor authentication has been disabled.", "success": true})
        )
    );
    let (_, body) = h
        .call("GET", "/api/auth/2fa/status", Some(&token), None)
        .await;
    assert_eq!(body["enabled"], false);

    // --- a portal user's 2FA login, then the brute-force lockout ----------
    let ptoken = h.token(&portal, "customer_user");
    let (st, setup) = h
        .call("POST", "/api/auth/2fa/setup", Some(&ptoken), None)
        .await;
    assert_eq!(st, 200);
    let code = totp_now(&h, &portal, 0).await;
    let (st, _) = h
        .call(
            "POST",
            "/api/auth/2fa/verify-setup",
            Some(&ptoken),
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(st, 200);
    let (_, body) = h
        .login("/api/auth/token/customer-portal", &portal, "Pa55word!")
        .await;
    let ptemp = body["access_token"].as_str().unwrap().to_string();
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/validate",
            None,
            Some(json!({"temp_token": ptemp, "backup_code": setup["backup_codes"][3]})),
        )
        .await;
    assert_eq!(st, 200);
    let claims = h
        .jwt
        .decode_claims(body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims["customer_codes"], json!([format!("acme{s}")]));
    for _ in 0..5 {
        let (st, _) = h
            .call(
                "POST",
                "/api/auth/2fa/validate",
                None,
                Some(json!({"temp_token": ptemp, "code": "abcdef"})),
            )
            .await;
        assert_eq!(st, 401);
    }
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/2fa/validate",
            None,
            Some(json!({"temp_token": ptemp, "code": totp_now(&h, &portal, 1).await})),
        )
        .await;
    assert_eq!(st, 401);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("Too many failed 2FA attempts. Try again in "),
        "{body}"
    );
    assert_eq!(
        wait_count(
            &h,
            &audits(
                "auth.login_failed",
                "Failed second-factor (2FA) verification",
                &portal
            ),
            6
        )
        .await,
        6
    );
}

#[tokio::test]
async fn user_management_flow() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let (acme, beta) = (format!("acme{s}"), format!("beta{s}"));
    let new_name = format!("newbie{s}");
    let msg = |b: &Value| b["message"].as_str().unwrap_or_default().to_string();
    let register = |body: Value| {
        let mut base = json!({"username": new_name, "password": "Passw0rd!x",
            "email": format!("New.User{s}@Example.COM")});
        base.as_object_mut()
            .unwrap()
            .extend(body.as_object().unwrap().clone());
        base
    };

    // --- register: the #1219 rules, then a user -------------------------------
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/register",
            Some(&admin),
            Some(register(json!({}))),
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            400,
            "Analysts and responders must be assigned at least one customer".into()
        )
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/register",
            Some(&admin),
            Some(register(
                json!({"customer_codes": [acme.to_uppercase(), "nope"]}),
            )),
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            400,
            format!("Unknown customer code(s): {}, nope", acme.to_uppercase())
        )
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/register",
            Some(&admin),
            Some(register(json!({"role_id": 1, "customer_codes": [acme]}))),
        )
        .await;
    assert_eq!(st, 400, "{body}");
    assert!(msg(&body).starts_with("Admins see every customer"));
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/register",
            Some(&admin),
            Some(register(json!({"password": "short", "email": "nope"}))),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(body["details"].as_array().unwrap().len(), 2);
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/register",
            Some(&analyst),
            Some(register(json!({"customer_codes": [acme]}))),
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            403,
            "Insufficient permissions. Required one of: admin".into()
        )
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/register",
            Some(&admin),
            Some(register(
                json!({"role_id": "5", "customer_codes": [format!(" {acme} "), acme]}),
            )),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            201,
            json!({"message": "User created successfully", "success": true})
        )
    );
    let new_id = h
        .scalar_i64(&format!(
            "SELECT id FROM `user` WHERE username = '{new_name}'"
        ))
        .await;
    let stored_email: String = sqlx::query_scalar("SELECT email FROM `user` WHERE id = ?")
        .bind(new_id)
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(stored_email, format!("New.User{s}@example.com"));
    let created = format!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'user.create' AND entity_id = '{new_name}' \
         AND JSON_EXTRACT(new_value, '$.role_id') = 5"
    );
    assert_eq!(wait_count(&h, &created, 1).await, 1);
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/register",
            Some(&admin),
            Some(register(json!({"customer_codes": [acme]}))),
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (400, "Email is already registered".into())
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/register",
            Some(&admin),
            Some(register(
                json!({"email": format!("other{s}@example.com"), "customer_codes": [acme]}),
            )),
        )
        .await;
    assert_eq!((st.as_u16(), msg(&body)), (400, "Username is taken".into()));

    // --- reads ------------------------------------------------------------------
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/auth/users?search={s}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);
    let newbie = body["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == new_name.as_str())
        .unwrap()
        .clone();
    assert_eq!(
        newbie,
        json!({"id": new_id, "username": new_name, "email": stored_email, "role_id": 5,
               "role_name": "responder", "last_login_at": null, "customer_codes": [acme]})
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/auth/users?search={s}&limit=1"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["users"].as_array().unwrap().len(), 1);
    assert_eq!(body["users"][0]["customer_codes"], Value::Null);
    let (st, _) = h
        .call("GET", "/api/auth/users?limit=0", Some(&admin), None)
        .await;
    assert_eq!(st, 422);
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/auth/users/{new_id}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["user"]["role_name"].as_str()),
        (200, Some("responder"))
    );
    let (st, body) = h
        .call("GET", "/api/auth/users/999999999", Some(&admin), None)
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (404, "User 999999999 not found".into())
    );
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let (st, body) = h.call("GET", "/api/auth/users", Some(&portal), None).await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (
            403,
            "Insufficient permissions. Required one of: analyst, admin".into()
        )
    );

    // --- customers and roles ------------------------------------------------------
    let path = format!("/api/auth/users/{new_id}/customers");
    let (st, body) = h
        .call("POST", &path, Some(&admin), Some(json!([beta, acme, beta])))
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": format!("Assigned 2 customers to user {new_id}"),
                     "customer_codes": [beta, acme]})
        )
    );
    let (_, body) = h.call("GET", &path, Some(&admin), None).await;
    assert_eq!(body["customer_codes"].as_array().unwrap().len(), 2);
    let (st, body) = h
        .call("POST", &path, Some(&admin), Some(json!({"codes": [acme]})))
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (422, "Input should be a valid list".into())
    );
    let role = format!("/api/auth/users/{new_id}/role/by-name");
    let (st, body) = h
        .call(
            "PUT",
            &role,
            Some(&admin),
            Some(json!({"role_name": "wizard"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (400, "Invalid role name. Valid roles are: ['admin', 'analyst', 'scheduler', 'customer_user', 'responder']".into())
    );
    let (st, body) = h
        .call(
            "PUT",
            &role,
            Some(&admin),
            Some(json!({"role_name": "Analyst"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"message": format!("User {new_name} role updated successfully to Analyst"),
                     "success": true, "user_id": new_id, "new_role_name": "Analyst", "new_role_id": 2})
        )
    );
    let (st, body) = h
        .call(
            "PUT",
            &role,
            Some(&admin),
            Some(json!({"role_name": "admin", "customer_codes": [acme]})),
        )
        .await;
    assert_eq!(st, 400, "{body}");
    let (st, _) = h
        .call(
            "PUT",
            &role,
            Some(&admin),
            Some(json!({"role_name": "responder", "customer_codes": [acme]})),
        )
        .await;
    assert_eq!(st, 200);
    let changes = format!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'user.role_change' AND entity_id = '{new_name}'"
    );
    assert_eq!(wait_count(&h, &changes, 2).await, 2);
    let (_, body) = h
        .call("GET", "/api/auth/me/customers", Some(&analyst), None)
        .await;
    assert_eq!(
        body,
        json!({"success": true, "customer_codes": [acme], "scope": "assigned"})
    );
    let (_, body) = h
        .call("GET", "/api/auth/me/customers", Some(&admin), None)
        .await;
    assert_eq!(
        body,
        json!({"success": true, "customer_codes": ["*"], "scope": "deployment"})
    );

    // --- passwords --------------------------------------------------------------
    let (st, _) = h
        .call(
            "POST",
            "/api/auth/reset-password",
            Some(&admin),
            Some(json!({"username": new_name, "new_password": "Changed1!x"})),
        )
        .await;
    assert_eq!(st, 200);
    let (st, _) = h.login("/api/auth/token", &new_name, "Changed1!x").await;
    assert_eq!(st, 200);
    let mine = h.token(&new_name, "responder");
    let (st, body) = h
        .call("POST", "/api/auth/reset-password/me", Some(&mine),
              Some(json!({"username": new_name, "current_password": "wrong", "new_password": "Changed2!x"})))
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (400, "Current password is incorrect".into())
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/reset-password/me",
            Some(&mine),
            Some(json!({"username": format!("analyst{s}"), "new_password": "Changed2!x"})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (401, "Invalid token. Username does not match.".into())
    );
    let (st, _) = h
        .call("POST", "/api/auth/reset-password/me", Some(&mine),
              Some(json!({"username": new_name, "current_password": "Changed1!x", "new_password": "Changed2!x"})))
        .await;
    assert_eq!(st, 200);
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/login",
            None,
            Some(json!({"username": new_name, "password": "Changed2!x"})),
        )
        .await;
    assert_eq!(st, 200);
    let keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["token", "message", "success"]);
    let claims = h
        .jwt
        .decode_claims(body["token"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        86_400
    );
    // The seeded users' password is not a bcrypt hash: bcrypt's error escapes.
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/login",
            None,
            Some(json!({"username": format!("analyst{s}"), "password": "x"})),
        )
        .await;
    assert_eq!((st.as_u16(), msg(&body)), (400, "Invalid salt".into()));

    // --- delete ----------------------------------------------------------------------
    let (st, body) = h
        .call("DELETE", "/api/auth/delete/999999999", Some(&admin), None)
        .await;
    assert_eq!((st.as_u16(), msg(&body)), (404, "User not found.".into()));
    let tag = h
        .exec(&format!(
            "INSERT INTO incident_management_alerttag (tag) VALUES ('t{s}')"
        ))
        .await;
    h.exec(&format!(
        "INSERT INTO user_tag_access (user_id, tag_id, created_at) VALUES ({new_id}, {tag}, UTC_TIMESTAMP())"
    ))
    .await;
    let (st, body) = h
        .call(
            "DELETE",
            &format!("/api/auth/delete/{new_id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), msg(&body)),
        (500, "Error deleting user".into())
    );
    h.exec(&format!(
        "DELETE FROM user_tag_access WHERE user_id = {new_id}"
    ))
    .await;
    let (st, body) = h
        .call(
            "DELETE",
            &format!("/api/auth/delete/{new_id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"message": "User deleted successfully.", "success": true})
        )
    );
    let left = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM user_customer_access WHERE user_id = {new_id}"
        ))
        .await;
    assert_eq!(left, 0);
    let deleted = format!(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'user.delete' AND entity_id = '{new_name}'"
    );
    assert_eq!(wait_count(&h, &deleted, 1).await, 1);
}

#[tokio::test]
async fn startup_schema_check_passes_on_the_alembic_head() {
    let h = harness_or_skip!(None);
    let missing = copilot_db::schema::missing_columns(&h.db, &copilot::app::schema_requirements())
        .await
        .unwrap();
    assert!(missing.is_empty(), "missing: {missing:?}");
    let rev = copilot_db::schema::alembic_revision(&h.db).await.unwrap();
    assert!(
        rev.is_some(),
        "the e2e database must be migrated by Alembic"
    );
    let bogus = [copilot_db::schema::TableRequirement {
        table: "ai_analyst_job",
        columns: &["id", "no_such_column"],
    }];
    assert_eq!(
        copilot_db::schema::missing_columns(&h.db, &bogus)
            .await
            .unwrap(),
        vec!["ai_analyst_job.no_such_column".to_string()]
    );
}

// ---------------------------------------------------------------------------
// SSO and passkeys
// ---------------------------------------------------------------------------

/// The RSA test key of `scripts/gen-webauthn-vectors.py` (2048 bits).
const RSA_N: &str = "cb67661bceb57ab5148dde4ad0c060e489d998fbf783918fb1594d083945743d5b34100d655e567d007e21ae0d8177b567218a46ef0612f1ec26fdb537828aae0eccb3a34800ad38797bc3badfcd1ffb867a06a04e8528a0408992d45a99e5b4a61b1399e376f6f44646b08ecb234dd440ba6e91e5ffea04e008b5d89d8b7a7fffaf918fb553c1658cbae8c33c891ceed00aef0dedaf66b2c96aff3c569f2185bca1446f27f02f9db2df414f1b5938c4bffa7018c68c500d894aef044d72452986057fd483a50616e55b9528fae73508e06e255d1c0ddf1dbcf298cf155fa1b3242620afada2bdbbd8c1afaca69a329b8b67921ab4d97f98bcd240967afabd71";
const RSA_D: &str = "287e4a36a8fd3a1388a701a5154fe73a383348a088d2f98c88bb0579e8a4ea1238f0f16d294c119dcb1651302c6224e9c941451d0002ce8cb8fdbe2e70819d882f4c134b234f772cb20ab099a86a56bea533efd3c42e003b7efda46c8028f930f08c9d675a805983a1e5faca42a8a19aead3f2a53b0baa9413e1c809fabb44c491aa58c05b99d6f687ece86fd225244b47b6c8464359389be27e8c7fea29cf011b122f19e043524309bc290c37ec50ed74245bb020f35f0d04f8649e499a158e1b88b6ec98170cf6ef5f083b2bfd1a3b800645bd0bdebeb45f20346f6e1664f5d96a1c2a077cb01393cac123fd7c6575b7c53c9ddcf2cf7ade09d24344c1fa1";

fn b64u(data: &[u8]) -> String {
    copilot_auth::pybase64::bytes_to_base64url(data)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// An RS256 JWT signed with the test key (RSASSA-PKCS1-v1_5 by hand).
fn rs256(kid: &str, claims: Value) -> String {
    use sha2::Digest;
    let header = json!({"alg": "RS256", "typ": "JWT", "kid": kid});
    let input = format!(
        "{}.{}",
        b64u(&serde_json::to_vec(&header).unwrap()),
        b64u(&serde_json::to_vec(&claims).unwrap())
    );
    let n = num_bigint_dig::BigUint::parse_bytes(RSA_N.as_bytes(), 16).unwrap();
    let d = num_bigint_dig::BigUint::parse_bytes(RSA_D.as_bytes(), 16).unwrap();
    let mut t = vec![
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    t.extend(sha2::Sha256::digest(input.as_bytes()));
    let mut em = vec![0x00, 0x01];
    em.extend(vec![0xff; 256 - t.len() - 3]);
    em.push(0x00);
    em.extend(t);
    let s = num_bigint_dig::BigUint::from_bytes_be(&em)
        .modpow(&d, &n)
        .to_bytes_be();
    let mut sig = vec![0u8; 256 - s.len()];
    sig.extend(s);
    format!("{input}.{}", b64u(&sig))
}

fn jwks(kid: &str) -> Value {
    let n = num_bigint_dig::BigUint::parse_bytes(RSA_N.as_bytes(), 16).unwrap();
    json!({"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "n": b64u(&n.to_bytes_be()), "e": "AQAB"}]})
}

impl Harness {
    /// A request with extra headers; returns the response headers too.
    async fn send(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, http::HeaderMap, Value) {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&v).unwrap()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, headers, value)
    }

    /// `GET` that must redirect; the `Location`.
    async fn location(&self, uri: &str) -> String {
        let (st, headers, _) = self.send("GET", uri, &[], None, None).await;
        assert_eq!(st.as_u16(), 307, "{uri}");
        headers[http::header::LOCATION]
            .to_str()
            .unwrap()
            .to_string()
    }

    async fn new_user(&self, name: &str, email: &str, role: i32) -> i64 {
        self.exec(&format!(
            "INSERT INTO `user` (username, password, email, created_at, role_id) \
             VALUES ('{name}', 'x', '{email}', UTC_TIMESTAMP(), {role})"
        ))
        .await
    }

    async fn enable_totp(&self, user_id: i64) {
        self.exec(&format!(
            "INSERT INTO user_totp (user_id, secret_enc, enabled, backup_codes, created_at) \
             VALUES ({user_id}, 'x', 1, '[]', UTC_TIMESTAMP())"
        ))
        .await;
    }
}

/// The stub IdP answering one Azure code exchange with `id_token`.
async fn serve_azure(idp: &MockServer, tenant: &str, id_token: String) {
    idp.reset().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks("k1")))
        .mount(idp)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id_token": id_token})))
        .mount(idp)
        .await;
}

/// The `state` query parameter of a provider redirect.
fn state_of(location: &str) -> String {
    let query = location.split_once('?').unwrap().1;
    let raw = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("state="))
        .unwrap();
    raw.replace("%3A", ":")
}

#[tokio::test]
async fn sso_settings_allowlist_and_logins() {
    let idp = MockServer::start().await;
    let h = harness_or_skip!(None, &format!("COPILOT_SSO_IDP_URL={}\n", idp.uri()));
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&h.code("admin"), "admin");
    let analyst = h.token(&h.code("analyst"), "analyst");
    h.exec("DELETE FROM sso_config").await;

    // Status and settings before anything is configured.
    let (st, body) = h.call("GET", "/api/auth/sso/status", None, None).await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"sso_enabled": false, "azure_enabled": false, "google_enabled": false,
                   "cf_enabled": false, "azure_authorization_url": null,
                   "google_authorization_url": null})
        )
    );
    let (st, body) = h
        .call("GET", "/api/auth/sso/settings", Some(&admin), None)
        .await;
    assert_eq!(st.as_u16(), 200);
    assert_eq!(body["message"], "No SSO configuration found");
    assert_eq!(body["azure_client_secret_set"], false);
    let (st, body) = h
        .call("GET", "/api/auth/sso/settings", Some(&analyst), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            403,
            json!("Insufficient permissions. Required one of: admin")
        )
    );
    let (st, _, body) = h
        .send("GET", "/api/auth/sso/azure/login", &[], None, None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (400, json!("Azure SSO is not enabled"))
    );

    // Configure all three providers.
    let tenant = format!("tenant{s}");
    let team = format!("team{s}.cloudflareaccess.com");
    let settings = json!({
        "sso_enabled": true,
        "azure_enabled": true, "azure_tenant_id": tenant, "azure_client_id": "az-client",
        "azure_client_secret": "az-secret", "azure_redirect_uri": "https://soc.example/api/auth/sso/azure/callback",
        "google_enabled": "yes", "google_client_id": "g-client", "google_client_secret": "g-secret",
        "google_redirect_uri": "https://soc.example/api/auth/sso/google/callback",
        "cf_enabled": 1, "cf_team_domain": team, "cf_audience": "cf-aud",
    });
    let (st, body) = h
        .call(
            "PUT",
            "/api/auth/sso/settings",
            Some(&admin),
            Some(settings.clone()),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{body}");
    assert_eq!(body["message"], "SSO configuration updated successfully");
    assert_eq!(body["google_enabled"], true);
    assert_eq!(body["azure_client_secret_set"], true);
    assert!(body.get("azure_client_secret").is_none());
    // An empty secret keeps the stored one.
    let mut keep = settings.clone();
    keep["azure_client_secret"] = json!("");
    let (st, body) = h
        .call("PUT", "/api/auth/sso/settings", Some(&admin), Some(keep))
        .await;
    assert_eq!(
        (st.as_u16(), body["azure_client_secret_set"].clone()),
        (200, json!(true))
    );
    let stored: String =
        sqlx::query_scalar("SELECT azure_client_secret FROM sso_config WHERE id = 1")
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(stored, "az-secret");
    let (st, _) = h
        .call(
            "PUT",
            "/api/auth/sso/settings",
            Some(&admin),
            Some(json!({"sso_enabled": "maybe"})),
        )
        .await;
    assert_eq!(st.as_u16(), 422);
    let (_, body) = h.call("GET", "/api/auth/sso/status", None, None).await;
    assert_eq!(body["google_enabled"], true);

    // Allowlist.
    let new_mail = format!("New.SSO{s}@Example.COM");
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/sso/allowed-emails",
            Some(&admin),
            Some(json!({"email": new_mail, "role_id": "2"})),
        )
        .await;
    assert_eq!(st.as_u16(), 201, "{body}");
    assert_eq!(
        body["message"],
        format!("Email New.SSO{s}@example.com added to SSO allowlist")
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/sso/allowed-emails",
            Some(&admin),
            Some(json!({"email": format!("new.sso{s}@example.com")})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!(format!(
                "Email new.sso{s}@example.com is already in the allowlist"
            ))
        )
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/sso/allowed-emails",
            Some(&admin),
            Some(json!({"email": "x@example.com", "role_id": 3})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            422,
            json!("role_id: SSO users must be admins, analysts or responders")
        )
    );
    // A second address with the same local part, for the username collision.
    let twin = format!("new.sso{s}@other.example.com");
    h.call(
        "POST",
        "/api/auth/sso/allowed-emails",
        Some(&admin),
        Some(json!({"email": twin, "role_id": 5})),
    )
    .await;
    let (st, body) = h
        .call("GET", "/api/auth/sso/allowed-emails", Some(&admin), None)
        .await;
    assert_eq!(st.as_u16(), 200);
    let listed: Vec<&Value> = body["emails"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["email"].as_str().unwrap().contains(&format!("sso{s}")))
        .collect();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["role_id"], 2);
    assert!(listed[0]["created_at"].as_str().unwrap().contains('T'));
    let (st, body) = h
        .call(
            "DELETE",
            "/api/auth/sso/allowed-emails/999999999",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (404, json!("Email entry not found"))
    );

    // Azure: the redirect, then the callback through the stub IdP.
    let location = h.location("/api/auth/sso/azure/login").await;
    assert!(
        location.starts_with(&format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?client_id=az-client&response_type=code&redirect_uri=https%3A%2F%2Fsoc.example%2Fapi%2Fauth%2Fsso%2Fazure%2Fcallback&response_mode=query&scope=openid+profile+email&state="
        )),
        "{location}"
    );
    assert!(location.ends_with("&prompt=select_account"));
    let state = state_of(&location);
    let issuer = format!("https://login.microsoftonline.com/{tenant}/v2.0");
    let id_token = |email: &str, extra: Value| {
        let mut claims = json!({"iss": issuer, "aud": "az-client", "exp": now_secs() + 300,
                                "iat": now_secs() - 5, "sub": "abc", "email": email});
        for (k, v) in extra.as_object().unwrap() {
            claims[k] = v.clone();
        }
        rs256("k1", claims)
    };
    let token_path = format!("/login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let azure_login = |code: &'static str, id_token: String| {
        let (idp, tenant) = (&idp, tenant.clone());
        async move {
            serve_azure(idp, &tenant, id_token).await;
            code
        }
    };
    let first_mail = format!("new.sso{s}@example.com");
    let code = azure_login("code-1", id_token(&first_mail, json!({}))).await;
    let loc = h
        .location(&format!(
            "/api/auth/sso/azure/callback?code={code}&state={state}"
        ))
        .await;
    let token = loc.strip_prefix("/sso-callback#token=").expect(&loc);
    let claims = h.jwt.decode_session(token).unwrap();
    assert_eq!(claims.subject, format!("new.sso{s}"));
    assert_eq!(claims.scopes, vec!["analyst"]);
    let form = idp.received_requests().await.unwrap();
    let posted = form.iter().find(|r| r.method.as_str() == "POST").unwrap();
    let posted = String::from_utf8_lossy(&posted.body).into_owned();
    assert!(
        posted.contains("client_secret=az-secret") && posted.contains("code=code-1"),
        "{posted}"
    );
    // The second address gets the next free username and its own role.
    let code = azure_login("code-2", id_token(&twin, json!({}))).await;
    let loc = h
        .location(&format!(
            "/api/auth/sso/azure/callback?code={code}&state={state}"
        ))
        .await;
    let claims = h
        .jwt
        .decode_session(loc.strip_prefix("/sso-callback#token=").unwrap())
        .unwrap();
    assert_eq!(claims.subject, format!("new.sso{s}1"));
    assert_eq!(claims.scopes, vec!["responder", "analyst"]);
    // Existing users sign in without an allowlist entry; 2FA is honoured.
    let existing = h
        .new_user(&format!("sso2fa{s}"), &format!("sso2fa{s}@example.com"), 2)
        .await;
    h.enable_totp(existing).await;
    let code = azure_login(
        "code-3",
        id_token(&format!("SSO2FA{s}@example.com"), json!({})),
    )
    .await;
    let loc = h
        .location(&format!(
            "/api/auth/sso/azure/callback?code={code}&state={state}"
        ))
        .await;
    let (temp, flag) = loc
        .strip_prefix("/sso-callback#token=")
        .unwrap()
        .split_once('&')
        .unwrap();
    assert_eq!(flag, "requires_2fa=true");
    assert_eq!(h.jwt.decode_two_factor(temp).unwrap(), format!("sso2fa{s}"));

    // Refusals.
    let err = |detail: &str| format!("/login?error_message={detail}");
    assert_eq!(
        h.location("/api/auth/sso/azure/callback?error=access_denied")
            .await,
        err("Azure%20auth%20error%3A%20access_denied")
    );
    assert_eq!(
        h.location("/api/auth/sso/azure/callback?code=x").await,
        err("Missing%20code%20or%20state%20parameter")
    );
    assert_eq!(
        h.location("/api/auth/sso/azure/callback?code=x&state=a%3Ab%3Ac")
            .await,
        err("Invalid%20or%20expired%20OAuth2%20state%20parameter")
    );
    let code = azure_login(
        "c",
        id_token(&format!("stranger{s}@example.com"), json!({})),
    )
    .await;
    assert_eq!(
        h.location(&format!(
            "/api/auth/sso/azure/callback?code={code}&state={state}"
        ))
        .await,
        err(&format!(
            "Email%20stranger{s}%40example.com%20is%20not%20authorized%20for%20SSO%20access.%20Contact%20your%20administrator."
        ))
    );
    let code = azure_login("c", id_token(&first_mail, json!({"email_verified": false}))).await;
    assert_eq!(
        h.location(&format!(
            "/api/auth/sso/azure/callback?code={code}&state={state}"
        ))
        .await,
        err("Azure%20account%20email%20is%20not%20verified")
    );
    let code = azure_login("c", id_token(&first_mail, json!({"exp": now_secs() - 10}))).await;
    assert_eq!(
        h.location(&format!(
            "/api/auth/sso/azure/callback?code={code}&state={state}"
        ))
        .await,
        err("Azure%20authentication%20failed")
    );
    let code = azure_login("c", id_token(&first_mail, json!({"aud": "someone-else"}))).await;
    assert_eq!(
        h.location(&format!(
            "/api/auth/sso/azure/callback?code={code}&state={state}"
        ))
        .await,
        err("Azure%20authentication%20failed")
    );
    let unknown_kid = {
        let mut claims = json!({"iss": issuer, "aud": "az-client", "exp": now_secs() + 300, "email": first_mail});
        claims["sub"] = json!("abc");
        rs256("other-kid", claims)
    };
    let code = azure_login("c", unknown_kid).await;
    assert_eq!(
        h.location(&format!(
            "/api/auth/sso/azure/callback?code={code}&state={state}"
        ))
        .await,
        err("Unable%20to%20find%20matching%20signing%20key%20in%20Azure%20JWKS")
    );
    let refetched = idp
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "GET")
        .count();
    // The cached set (from the logins above) missed: one refetch, then the error.
    assert_eq!(refetched, 1, "a kid miss refetches the JWKS once");
    idp.reset().await;
    Mock::given(method("POST"))
        .and(path(token_path.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token": "x"})))
        .mount(&idp)
        .await;
    assert_eq!(
        h.location(&format!(
            "/api/auth/sso/azure/callback?code=c&state={state}"
        ))
        .await,
        err("No%20id_token%20in%20Azure%20response")
    );

    // Google.
    let location = h.location("/api/auth/sso/google/login").await;
    assert!(location.starts_with(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id=g-client&response_type=code&redirect_uri=https%3A%2F%2Fsoc.example%2Fapi%2Fauth%2Fsso%2Fgoogle%2Fcallback&scope=openid+email&state="
    ));
    assert!(location.ends_with("&access_type=online&prompt=select_account"));
    let state = state_of(&location);
    idp.reset().await;
    Mock::given(method("GET"))
        .and(path("/www.googleapis.com/oauth2/v3/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks("g1")))
        .mount(&idp)
        .await;
    let google_token = |verified: bool| {
        rs256(
            "g1",
            json!({"iss": "https://accounts.google.com", "aud": "g-client",
                   "exp": now_secs() + 300, "email": first_mail, "email_verified": verified}),
        )
    };
    Mock::given(method("POST"))
        .and(path("/oauth2.googleapis.com/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id_token": google_token(true)})),
        )
        .mount(&idp)
        .await;
    let loc = h
        .location(&format!(
            "/api/auth/sso/google/callback?code=g&state={state}"
        ))
        .await;
    let claims = h
        .jwt
        .decode_session(loc.strip_prefix("/sso-callback#token=").unwrap())
        .unwrap();
    assert_eq!(claims.subject, format!("new.sso{s}"));

    // Cloudflare Access.
    let cf_user = format!("cf{s}@example.com");
    h.new_user(&format!("cf{s}"), &cf_user, 2).await;
    idp.reset().await;
    Mock::given(method("GET"))
        .and(path(format!("/{team}/cdn-cgi/access/certs")))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks("cf1")))
        .mount(&idp)
        .await;
    let cf_token = |email: &str| {
        rs256(
            "cf1",
            json!({"iss": format!("https://{team}"), "aud": ["cf-aud"],
                   "exp": now_secs() + 300, "email": email}),
        )
    };
    let verify = "/api/auth/sso/cloudflare/verify";
    let (st, _, body) = h
        .send(
            "POST",
            verify,
            &[("cf-access-jwt-assertion", &cf_token(&cf_user))],
            None,
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{body}");
    assert_eq!(
        body["message"],
        "Cloudflare Access authentication successful"
    );
    assert!(body.get("requires_2fa").is_none());
    assert_eq!(
        h.jwt
            .decode_session(body["access_token"].as_str().unwrap())
            .unwrap()
            .subject,
        format!("cf{s}")
    );
    let cookie = format!("a=1; CF_Authorization={}", cf_token(&cf_user));
    let (st, _, _) = h
        .send("POST", verify, &[("cookie", &cookie)], None, None)
        .await;
    assert_eq!(st.as_u16(), 200);
    let (st, _, body) = h.send("POST", verify, &[], None, None).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            401,
            json!("No Cloudflare Access JWT found in request headers or cookies")
        )
    );
    let (st, _, body) = h
        .send(
            "POST",
            verify,
            &[(
                "cf-access-jwt-assertion",
                &cf_token(&format!("nobody{s}@example.com")),
            )],
            None,
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 403);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("is not authorized for SSO access")
    );
    let (st, _, body) = h
        .send(
            "POST",
            verify,
            &[("cf-access-jwt-assertion", "not.a.jwt")],
            None,
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (500, json!("Cloudflare authentication failed"))
    );
    h.exec("UPDATE sso_config SET cf_team_domain = 'evil.example.com' WHERE id = 1")
        .await;
    let (st, _, body) = h
        .send(
            "POST",
            verify,
            &[("cf-access-jwt-assertion", "x")],
            None,
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            401,
            json!(
                "Invalid Cloudflare team domain 'evil.example.com'. Must match *.cloudflareaccess.com"
            )
        )
    );
    h.exec("UPDATE sso_config SET cf_enabled = 0 WHERE id = 1")
        .await;
    let (st, _, body) = h.send("POST", verify, &[], None, None).await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (400, json!("Cloudflare Access SSO is not enabled"))
    );
    h.exec("DELETE FROM sso_config").await;
}

/// A software authenticator: one P-256 credential.
struct Authenticator {
    key: p256::ecdsa::SigningKey,
    id: Vec<u8>,
}

const RP_ORIGIN: &str = "http://localhost:5173";

impl Authenticator {
    fn new(seed: u8, id: &[u8]) -> Self {
        Self {
            key: p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap(),
            id: id.to_vec(),
        }
    }

    fn cose(&self) -> Vec<u8> {
        use copilot_webauthn::cbor::{Cbor, encode};
        let point = self.key.verifying_key().to_encoded_point(false);
        encode(&Cbor::Map(vec![
            (Cbor::int(1), Cbor::int(2)),
            (Cbor::int(3), Cbor::int(-7)),
            (Cbor::int(-1), Cbor::int(1)),
            (Cbor::int(-2), Cbor::Bytes(point.x().unwrap().to_vec())),
            (Cbor::int(-3), Cbor::Bytes(point.y().unwrap().to_vec())),
        ]))
        .unwrap()
    }

    fn client_data(kind: &str, challenge: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"type": kind, "challenge": challenge, "origin": RP_ORIGIN}))
            .unwrap()
    }

    fn rp_hash() -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(b"localhost").to_vec()
    }

    /// `navigator.credentials.create()`'s JSON for `options`.
    fn create(&self, options: &Value) -> Value {
        use copilot_webauthn::cbor::{Cbor, encode};
        let mut auth_data = Self::rp_hash();
        auth_data.push(0x45);
        auth_data.extend(0u32.to_be_bytes());
        auth_data.extend([0u8; 16]);
        auth_data.extend((self.id.len() as u16).to_be_bytes());
        auth_data.extend(&self.id);
        auth_data.extend(self.cose());
        let att = encode(&Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]))
        .unwrap();
        let cdj = Self::client_data("webauthn.create", options["challenge"].as_str().unwrap());
        json!({
            "id": b64u(&self.id), "rawId": b64u(&self.id), "type": "public-key",
            "response": {"clientDataJSON": b64u(&cdj), "attestationObject": b64u(&att),
                         "transports": ["internal"]},
            "clientExtensionResults": {}, "authenticatorAttachment": "platform",
        })
    }

    /// `navigator.credentials.get()`'s JSON for `options`.
    fn get(&self, options: &Value, sign_count: u32) -> Value {
        use p256::ecdsa::signature::Signer;
        use sha2::Digest;
        let mut auth_data = Self::rp_hash();
        auth_data.push(0x05);
        auth_data.extend(sign_count.to_be_bytes());
        let cdj = Self::client_data("webauthn.get", options["challenge"].as_str().unwrap());
        let mut signed = auth_data.clone();
        signed.extend(sha2::Sha256::digest(&cdj));
        let sig: p256::ecdsa::Signature = self.key.sign(&signed);
        json!({
            "id": b64u(&self.id), "rawId": b64u(&self.id), "type": "public-key",
            "response": {"clientDataJSON": b64u(&cdj), "authenticatorData": b64u(&auth_data),
                         "signature": b64u(sig.to_der().as_bytes()), "userHandle": null},
            "clientExtensionResults": {},
        })
    }
}

#[tokio::test]
async fn passkey_registration_and_login() {
    let h = harness_or_skip!(
        None,
        &format!("WEBAUTHN_ORIGINS={RP_ORIGIN}\nWEBAUTHN_RP_ID=localhost\n")
    );
    h.seed().await;
    let s = h.suffix.clone();
    let analyst_name = h.code("analyst");
    let analyst = h.token(&analyst_name, "analyst");
    let portal = h.token(&h.code("portal"), "customer_user");
    let origin = [("origin", RP_ORIGIN)];

    let (st, body) = h.call("GET", "/api/auth/passkey/status", None, None).await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"enabled": true, "count": 0, "message": "Passkey status retrieved", "success": true})
        )
    );
    let (st, body) = h
        .call("GET", "/api/auth/passkey/me/status", Some(&analyst), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["enabled"].clone(), body["count"].clone()),
        (200, json!(false), json!(0))
    );
    let (st, body) = h
        .call("GET", "/api/auth/passkey/me", Some(&portal), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            403,
            json!("Insufficient permissions. Required one of: admin, analyst")
        )
    );

    // Registration.
    let (st, _, options) = h
        .send(
            "POST",
            "/api/auth/passkey/register/options",
            &origin,
            Some(&analyst),
            Some(json!({"device_name": "  YubiKey  "})),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{options}");
    let analyst_id = h
        .scalar_i64(&format!(
            "SELECT id FROM `user` WHERE username = '{analyst_name}'"
        ))
        .await;
    assert_eq!(
        options["rp"],
        json!({"name": "SOCFortress CoPilot", "id": "localhost"})
    );
    assert_eq!(
        options["user"]["id"],
        b64u(analyst_id.to_string().as_bytes())
    );
    assert_eq!(options["user"]["name"], analyst_name);
    assert_eq!(options["excludeCredentials"], json!([]));
    assert_eq!(options["attestation"], "none");
    assert_eq!(options["deviceName"], "YubiKey");
    let keys: Vec<&String> = options.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "rp",
            "user",
            "challenge",
            "pubKeyCredParams",
            "timeout",
            "excludeCredentials",
            "authenticatorSelection",
            "attestation",
            "challengeToken",
            "deviceName"
        ]
    );
    let device = Authenticator::new(7, format!("cred-{s}").as_bytes());
    let credential = device.create(&options);
    let verify = |token: &Value, credential: &Value| json!({"challenge_token": token, "credential": credential, "device_name": " YubiKey "});
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/register/verify",
            &origin,
            Some(&analyst),
            Some(verify(&options["challengeToken"], &credential)),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"message": "Passkey registered successfully.", "success": true})
        )
    );
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/register/verify",
            &origin,
            Some(&analyst),
            Some(verify(&options["challengeToken"], &credential)),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (400, json!("Challenge not found or already used."))
    );
    let (st, body) = h
        .call("GET", "/api/auth/passkey/me", Some(&analyst), None)
        .await;
    assert_eq!(st.as_u16(), 200);
    let item = &body["passkeys"][0];
    assert_eq!(item["device_name"], "YubiKey");
    assert_eq!(item["transports"], json!(["internal"]));
    assert_eq!(item["last_used_at"], Value::Null);
    let passkey_id = item["id"].as_i64().unwrap();
    // The same credential again is refused, after its challenge is spent.
    let (_, _, options) = h
        .send(
            "POST",
            "/api/auth/passkey/register/options",
            &origin,
            Some(&analyst),
            Some(json!({})),
        )
        .await;
    assert_eq!(options["excludeCredentials"][0]["id"], b64u(&device.id));
    assert_eq!(
        options["excludeCredentials"][0]["transports"],
        json!(["internal"])
    );
    assert_eq!(options["deviceName"], "Passkey");
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/register/verify",
            &origin,
            Some(&analyst),
            Some(verify(&options["challengeToken"], &device.create(&options))),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (400, json!("This passkey is already registered."))
    );

    // Login.
    let (st, _, options) = h
        .send(
            "POST",
            "/api/auth/passkey/login/options",
            &origin,
            None,
            Some(json!({"username": format!(" {analyst_name} ")})),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{options}");
    assert_eq!(options["rpId"], "localhost");
    assert_eq!(options["allowCredentials"][0]["id"], b64u(&device.id));
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/login/verify",
            &origin,
            None,
            Some(json!({"challenge_token": options["challengeToken"], "credential": device.get(&options, 1)})),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{body}");
    assert_eq!(body["token_type"], "bearer");
    assert_eq!(body["requires_2fa"], false);
    let claims = h
        .jwt
        .decode_session(body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.subject, analyst_name);
    // A replayed counter is refused (username-less login this time).
    let (_, _, options) = h
        .send(
            "POST",
            "/api/auth/passkey/login/options",
            &origin,
            None,
            Some(json!({})),
        )
        .await;
    assert_eq!(options["allowCredentials"], json!([]));
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/login/verify",
            &origin,
            None,
            Some(json!({"challenge_token": options["challengeToken"], "credential": device.get(&options, 1)})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            401,
            json!("Response sign count of 1 was not greater than current count of 1")
        )
    );
    let (st, body) = h
        .call("GET", "/api/auth/passkey/me", Some(&analyst), None)
        .await;
    assert_eq!(st.as_u16(), 200);
    assert!(body["passkeys"][0]["last_used_at"].is_string());

    // Unknown passkey, 127.0.0.1, unknown user.
    let stranger = Authenticator::new(9, b"stranger");
    let (_, _, options) = h
        .send(
            "POST",
            "/api/auth/passkey/login/options",
            &origin,
            None,
            Some(json!({})),
        )
        .await;
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/login/verify",
            &origin,
            None,
            Some(json!({"challenge_token": options["challengeToken"], "credential": stranger.get(&options, 1)})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (401, json!("Unknown passkey."))
    );
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/login/options",
            &[("origin", "http://127.0.0.1:5173")],
            None,
            Some(json!({})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!(
                "Passkeys do not work on 127.0.0.1. Open http://localhost:5173 in your browser instead."
            )
        )
    );
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/login/options",
            &origin,
            None,
            Some(json!({"username": format!("ghost{s}")})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (400, json!("User not found."))
    );

    // Challenges: wrong flow, another user's, expired.
    let (_, _, login_options) = h
        .send(
            "POST",
            "/api/auth/passkey/login/options",
            &origin,
            None,
            Some(json!({})),
        )
        .await;
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/register/verify",
            &origin,
            Some(&analyst),
            Some(verify(&login_options["challengeToken"], &credential)),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (400, json!("Invalid challenge flow."))
    );
    let admin = h.token(&h.code("admin"), "admin");
    let (_, _, admin_options) = h
        .send(
            "POST",
            "/api/auth/passkey/register/options",
            &origin,
            Some(&admin),
            Some(json!({})),
        )
        .await;
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/register/verify",
            &origin,
            Some(&analyst),
            Some(verify(&admin_options["challengeToken"], &credential)),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!("Challenge does not match the authenticated user.")
        )
    );
    let expired = format!("expired-{s}");
    h.exec(&format!(
        "INSERT INTO webauthn_challenge (token, challenge, user_id, flow, expires_at, created_at) \
         VALUES ('{expired}', 'AA', NULL, 'login', UTC_TIMESTAMP() - INTERVAL 1 MINUTE, UTC_TIMESTAMP())"
    ))
    .await;
    let (st, _, body) = h
        .send(
            "POST",
            "/api/auth/passkey/login/verify",
            &origin,
            None,
            Some(json!({"challenge_token": expired, "credential": device.get(&options, 5)})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (401, json!("Challenge has expired. Please try again."))
    );
    let left = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM webauthn_challenge WHERE token = '{expired}'"
        ))
        .await;
    assert_eq!(left, 0, "an expired challenge is deleted");

    // A portal user's passkey cannot sign in to the main portal; 2FA users
    // get the temp token.
    let portal_id = h
        .scalar_i64(&format!(
            "SELECT id FROM `user` WHERE username = '{}'",
            h.code("portal")
        ))
        .await;
    let portal_device = Authenticator::new(11, format!("portal-{s}").as_bytes());
    let twofa_id = h
        .new_user(&format!("pk2fa{s}"), &format!("pk2fa{s}@example.com"), 2)
        .await;
    h.enable_totp(twofa_id).await;
    let twofa_device = Authenticator::new(13, format!("twofa-{s}").as_bytes());
    for (user_id, dev) in [(portal_id, &portal_device), (twofa_id, &twofa_device)] {
        h.exec(&format!(
            "INSERT INTO user_passkey (user_id, credential_id, public_key, sign_count, transports, \
             device_name, created_at) VALUES ({user_id}, '{}', '{}', 0, '[]', 'Passkey', UTC_TIMESTAMP())",
            b64u(&dev.id),
            b64u(&dev.cose())
        ))
        .await;
    }
    let login = async |dev: &Authenticator| {
        let (_, _, options) = h
            .send(
                "POST",
                "/api/auth/passkey/login/options",
                &origin,
                None,
                Some(json!({})),
            )
            .await;
        h.send(
            "POST",
            "/api/auth/passkey/login/verify",
            &origin,
            None,
            Some(json!({"challenge_token": options["challengeToken"], "credential": dev.get(&options, 0)})),
        )
        .await
    };
    let (st, _, body) = login(&portal_device).await;
    assert_eq!(st.as_u16(), 403);
    assert_eq!(
        body["message"],
        "This account is registered for the Customer Portal only. Please log in at the Customer Portal to access your account."
    );
    let (st, _, body) = login(&twofa_device).await;
    assert_eq!(
        (st.as_u16(), body["requires_2fa"].clone()),
        (200, json!(true))
    );
    assert_eq!(
        h.jwt
            .decode_two_factor(body["access_token"].as_str().unwrap())
            .unwrap(),
        format!("pk2fa{s}")
    );

    // Deletion: someone else's passkey is "not found", a bad id is a 422.
    let (st, body) = h
        .call(
            "DELETE",
            &format!("/api/auth/passkey/{passkey_id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (404, json!("Passkey not found."))
    );
    let (st, _) = h
        .call("DELETE", "/api/auth/passkey/me", Some(&analyst), None)
        .await;
    assert_eq!(st.as_u16(), 422);
    let (st, body) = h
        .call(
            "DELETE",
            &format!("/api/auth/passkey/{passkey_id}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (200, json!({"message": "Passkey removed.", "success": true}))
    );
    let (_, body) = h
        .call("GET", "/api/auth/passkey/me/status", Some(&analyst), None)
        .await;
    assert_eq!(body["count"], 0);
}

#[tokio::test]
async fn security_tab_reads_and_totp_reset() {
    let h = harness_or_skip!(None, "SMTP_HOST=smtp.example\nSMTP_USE_TLS=no\n");
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&h.code("admin"), "admin");
    let analyst = h.token(&h.code("analyst"), "analyst");
    let acme = h.code("acme");
    let beta = h.code("beta");

    let (st, body) = h
        .call("GET", "/api/auth/security/smtp-status", Some(&admin), None)
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"configured": true, "success": true, "message": "SMTP status retrieved"})
        )
    );
    let (st, _) = h
        .call(
            "GET",
            "/api/auth/security/smtp-status",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 403);

    // The customer's users: 2FA state from `user_totp`, role names from the enum.
    let portal_id = h
        .scalar_i64(&format!(
            "SELECT id FROM `user` WHERE username = 'portal{s}'"
        ))
        .await;
    h.enable_totp(portal_id).await;
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/auth/security/customers/{acme}/users"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 200);
    let users = body["users"].as_array().unwrap();
    let names: Vec<&str> = users
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            format!("analyst{s}"),
            format!("responder{s}"),
            format!("portal{s}")
        ]
    );
    assert_eq!(users[1]["role_name"], "responder");
    assert_eq!(users[2]["totp_enabled"], true);
    assert_eq!(users[0]["totp_enabled"], false);
    assert_eq!(users[0]["last_login_at"], Value::Null);

    // TOTP reset: once removed, then nothing to remove; audited both times.
    let uri = format!("/api/auth/security/users/{portal_id}/totp");
    let (st, body) = h.call("DELETE", &uri, Some(&admin), None).await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "Two-factor authentication has been reset."})
        )
    );
    let (_, body) = h.call("DELETE", &uri, Some(&admin), None).await;
    assert_eq!(
        body["message"],
        "The user had no two-factor authentication configured."
    );
    let (st, body) = h
        .call(
            "DELETE",
            "/api/auth/security/users/999999999/totp",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (404, json!("User 999999999 not found"))
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let audited = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'user.update' AND entity_id = 'portal{s}' \
             AND details LIKE 'Forced TOTP (2FA) reset by admin (%'"
        ))
        .await;
    assert_eq!(audited, 2);

    // Template options: this customer's first, shared next, built-in last,
    // another customer's never; a JSON template is not offered.
    for (name, code, fmt, default, updated) in [
        (
            "mine",
            format!("'{acme}'"),
            "html",
            0,
            "'2026-01-03 00:00:00'",
        ),
        (
            "shared",
            "NULL".to_string(),
            "text",
            0,
            "'2026-01-04 00:00:00'",
        ),
        (
            "builtin",
            "NULL".to_string(),
            "html",
            1,
            "'2026-01-05 00:00:00'",
        ),
        (
            "theirs",
            format!("'{beta}'"),
            "text",
            0,
            "'2026-01-06 00:00:00'",
        ),
        (
            "json",
            "NULL".to_string(),
            "json",
            0,
            "'2026-01-07 00:00:00'",
        ),
    ] {
        h.exec(&format!(
            "INSERT INTO notification_template (name, `trigger`, format, body_template, customer_code, \
             is_default, created_at, updated_at) VALUES ('{name}{s}', 'temp_password_issued', '{fmt}', \
             'B', {code}, {default}, UTC_TIMESTAMP(), {updated})"
        ))
        .await;
    }
    let (st, body) = h
        .call(
            "GET",
            &format!("/api/auth/security/users/{portal_id}/temp-password-email/options"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 200);
    assert_eq!(body["customer_code"], json!(acme));
    let ours: Vec<&str> = body["templates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .filter(|n| n.ends_with(s.as_str()))
        .collect();
    assert_eq!(
        ours,
        [
            format!("mine{s}"),
            format!("shared{s}"),
            format!("builtin{s}")
        ]
    );
    assert_eq!(body["resolved_template_id"], body["templates"][0]["id"]);
    let (st, body) = h
        .call(
            "GET",
            &format!(
                "/api/auth/security/users/{portal_id}/temp-password-email/options?customer_code={beta}"
            ),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!(format!(
                "User 'portal{s}' does not have access to customer '{beta}'."
            ))
        )
    );
}

#[tokio::test]
async fn smtp_settings_are_read_per_request() {
    let h = harness_or_skip!(None, "SMTP_HOST=smtp.example\nSMTP_PORT=2_5x\n");
    h.seed().await;
    let admin = h.token(&h.code("admin"), "admin");
    let (st, body) = h
        .call("GET", "/api/auth/security/smtp-status", Some(&admin), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (400, json!("invalid literal for int() with base 10: '2_5x'"))
    );
    let h = harness_or_skip!(None, "SMTP_HOST=\n");
    h.seed().await;
    let admin = h.token(&h.code("admin"), "admin");
    let (_, body) = h
        .call("GET", "/api/auth/security/smtp-status", Some(&admin), None)
        .await;
    assert_eq!(body["configured"], false);
}

/// What [`smtp_stub`] received: `(recipients, DATA)`.
type Mailbox = std::sync::Arc<std::sync::Mutex<Vec<(Vec<String>, String)>>>;

/// A recording SMTP server: `250` to everything, `550` for a recipient
/// containing "reject".
async fn smtp_stub() -> (u16, Mailbox) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mailbox: Mailbox = Default::default();
    let inbox = mailbox.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let inbox = inbox.clone();
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read);
                write.write_all(b"220 stub ESMTP\r\n").await.unwrap();
                let mut rcpts = Vec::new();
                loop {
                    let mut line = String::new();
                    if lines.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let upper = line.to_ascii_uppercase();
                    let reply: &[u8] = if upper.starts_with("EHLO") {
                        b"250-stub\r\n250 8BITMIME\r\n"
                    } else if upper.starts_with("RCPT") && line.contains("reject") {
                        b"550 5.1.1 no such user\r\n"
                    } else if upper.starts_with("RCPT") {
                        rcpts.push(line.trim().to_string());
                        b"250 OK\r\n"
                    } else if upper.starts_with("DATA") {
                        write.write_all(b"354 go\r\n").await.unwrap();
                        let mut data = String::new();
                        loop {
                            let mut l = String::new();
                            lines.read_line(&mut l).await.unwrap();
                            if l == ".\r\n" {
                                break;
                            }
                            data.push_str(&l);
                        }
                        inbox
                            .lock()
                            .unwrap()
                            .push((std::mem::take(&mut rcpts), data));
                        b"250 queued\r\n"
                    } else if upper.starts_with("QUIT") {
                        write.write_all(b"221 bye\r\n").await.unwrap();
                        return;
                    } else {
                        b"250 OK\r\n"
                    };
                    write.write_all(reply).await.unwrap();
                }
            });
        }
    });
    (port, mailbox)
}

#[tokio::test]
async fn temp_password_email_preview_and_send() {
    let (port, mailbox) = smtp_stub().await;
    let h = harness_or_skip!(
        None,
        &format!(
            "SMTP_HOST=127.0.0.1\nSMTP_PORT={port}\nSMTP_USE_TLS=false\nSMTP_FROM=copilot@e2e.test\n"
        )
    );
    h.seed().await;
    let s = h.suffix.clone();
    let admin = h.token(&h.code("admin"), "admin");
    let acme = h.code("acme");
    let beta = h.code("beta");
    let portal_id = h
        .scalar_i64(&format!(
            "SELECT id FROM `user` WHERE username = 'portal{s}'"
        ))
        .await;
    let base = format!("/api/auth/security/users/{portal_id}");
    // Shared templates from other tests would be resolved first; this test
    // needs the "no template" case.
    h.exec(
        "DELETE FROM notification_template WHERE `trigger` = 'temp_password_issued' \
         AND customer_code IS NULL",
    )
    .await;

    // No template: the plaintext body, with the placeholder password.
    let (st, body) = h
        .call(
            "POST",
            &format!("{base}/temp-password-email/preview"),
            Some(&admin),
            Some(json!({})),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{body}");
    assert_eq!(
        body,
        json!({
            "subject": "CoPilot — temporary password",
            "body": format!(
                "Hello portal{s},\n\nAn administrator has issued a temporary password for your CoPilot \
                 account.\n\nTemporary password: PREVIEW-Not-A-Real-Password\n\nFor your security, please \
                 sign in with this password and change it immediately.\nIf you did not expect this \
                 change, contact your security team.\n"
            ),
            "format": "text",
            "error": null,
            "success": true,
            "message": "Rendered",
        })
    );

    // The customer's HTML template, with its branding.
    h.exec(&format!(
        "INSERT INTO customer_portal_branding (customer_code, enabled, title, brand_color, updated_at) \
         VALUES ('{acme}', 1, 'Acme <Portal>', '#2563eb', UTC_TIMESTAMP())"
    ))
    .await;
    let good = h
        .exec(&format!(
            "INSERT INTO notification_template (name, `trigger`, format, subject_template, body_template, \
             customer_code, is_default, created_at, updated_at) VALUES ('good{s}', 'temp_password_issued', \
             'html', 'Hi {{{{ user_name }}}}\\n  at {{{{ customer_name }}}}', \
             '<p>PW[{{{{ temp_password }}}}]</p><a href=\"{{{{ login_url }}}}\">{{{{ branding.title }}}}</a>\
             <i>{{{{ branding.accent_strong }}}}</i>', '{acme}', 0, UTC_TIMESTAMP(), UTC_TIMESTAMP())"
        ))
        .await;
    let broken = h
        .exec(&format!(
            "INSERT INTO notification_template (name, `trigger`, format, body_template, customer_code, \
             is_default, created_at, updated_at) VALUES ('broken{s}', 'temp_password_issued', 'text', \
             '{{{{ nope }}}}', '{acme}', 0, UTC_TIMESTAMP(), '2020-01-01 00:00:00')"
        ))
        .await;
    let theirs = h
        .exec(&format!(
            "INSERT INTO notification_template (name, `trigger`, format, body_template, customer_code, \
             is_default, created_at, updated_at) VALUES ('theirs{s}', 'temp_password_issued', 'text', \
             'x', '{beta}', 0, UTC_TIMESTAMP(), UTC_TIMESTAMP())"
        ))
        .await;
    let (st, body) = h
        .call(
            "POST",
            &format!("{base}/temp-password-email/preview"),
            Some(&admin),
            Some(json!({})),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{body}");
    assert_eq!(body["subject"], json!(format!("Hi portal{s} at acme corp")));
    assert_eq!(body["format"], "html");
    assert_eq!(
        body["body"],
        json!(
            "<p>PW[PREVIEW-Not-A-Real-Password]</p><a href=\"https://copilot.example.com/login\">\
             Acme &lt;Portal&gt;</a><i>#2563eb</i>"
        )
    );

    // A template that fails shows its error; one that is another customer's is refused.
    let (st, body) = h
        .call(
            "POST",
            &format!("{base}/temp-password-email/preview"),
            Some(&admin),
            Some(json!({"template_id": broken, "customer_code": acme})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({
                "subject": null,
                "body": "",
                "format": "text",
                "error": "UndefinedError: 'nope' is undefined",
                "success": false,
                "message": "Template failed to render",
            })
        )
    );
    let (st, body) = h
        .call(
            "POST",
            &format!("{base}/temp-password-email/preview"),
            Some(&admin),
            Some(json!({"template_id": theirs})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!(format!(
                "That template belongs to customer '{beta}', not '{acme}'."
            ))
        )
    );
    // The path and the body are validated together.
    let (st, body) = h
        .call(
            "POST",
            "/api/auth/security/users/abc/temp-password-email/preview",
            Some(&admin),
            Some(json!({"template_id": "x"})),
        )
        .await;
    assert_eq!(st.as_u16(), 422);
    let fields: Vec<&str> = body["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, ["user_id", "template_id"], "{body}");

    // Sending with the broken template changes nothing.
    let password_before =
        sqlx::query_scalar::<_, String>("SELECT password FROM `user` WHERE id = ?")
            .bind(portal_id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    let (st, body) = h
        .call(
            "POST",
            &format!("{base}/send-temp-password"),
            Some(&admin),
            Some(json!({"template_id": broken})),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].clone()),
        (
            400,
            json!(
                "The email template could not be rendered, so nothing was sent and the password was left \
                 unchanged: UndefinedError: 'nope' is undefined"
            )
        )
    );
    assert!(mailbox.lock().unwrap().is_empty());

    // No body: the customer's template, emailed; the password works.
    let (st, body) = h
        .call(
            "POST",
            &format!("{base}/send-temp-password"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            200,
            json!({"success": true, "message": "A temporary password has been emailed to portal@example.com."})
        )
    );
    let (rcpts, data) = mailbox.lock().unwrap().pop().unwrap();
    assert_eq!(rcpts, ["RCPT TO:<portal@example.com>"]);
    assert!(data.contains("multipart/alternative"), "{data}");
    assert!(
        data.contains(&format!("Subject: Hi portal{s} at acme corp")),
        "{data}"
    );
    let start = data.find("PW[").unwrap_or_else(|| panic!("{data}")) + 3;
    let password = &data[start..start + data[start..].find(']').unwrap()];
    let hash = sqlx::query_scalar::<_, String>("SELECT password FROM `user` WHERE id = ?")
        .bind(portal_id)
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_ne!(hash, password_before);
    assert!(
        copilot_auth::password::verify_password(password, &hash),
        "{password}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let audited = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'user.update' AND entity_id = 'portal{s}' \
             AND details = 'Temporary password issued and emailed by admin using template ''good{s}'''"
        ))
        .await;
    assert_eq!(audited, 1);
    let _ = good;

    // A refused recipient: the password was already reset, and the answer says so.
    h.exec(&format!(
        "UPDATE `user` SET email = 'reject@example.com' WHERE id = {portal_id}"
    ))
    .await;
    let (st, body) = h
        .call(
            "POST",
            &format!("{base}/send-temp-password"),
            Some(&admin),
            Some(Value::Null),
        )
        .await;
    assert_eq!(st.as_u16(), 502, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("The password was reset but the email could not be sent: "),
        "{body}"
    );
}
