//! End-to-end tests of the notification module: the production router and
//! the in-process sink against a real MySQL at the Alembic head, every
//! provider (webhook, Resend, Shuffle) replaced by a recorder.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13306/copilot \
//!   cargo test -p copilot --test e2e_notifications -- --test-threads=1
//! ```
//!
//! The `Resend` and `Shuffle` connector rows are global, so the suite runs
//! single-threaded; everything else is seeded per test (random suffix).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use copilot_core::notify::{NotificationEvent, NotificationSeverity, NotificationTrigger};

#[macro_use]
mod common;
use common::*;

async fn recorded(server: &MockServer, prefix: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path().starts_with(prefix))
        .collect()
}

/// Wait until `n` requests under `prefix` arrived (spawned deliveries).
async fn wait_for(server: &MockServer, prefix: &str, n: usize) -> Vec<Request> {
    for _ in 0..100 {
        let got = recorded(server, prefix).await;
        if got.len() >= n {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    recorded(server, prefix).await
}

fn json_of(r: &Request) -> Value {
    serde_json::from_slice(&r.body).unwrap()
}

async fn connector(h: &Harness, name: &str, url: &str, key: &str, extra: Option<&str>) {
    h.exec(&format!(
        "DELETE FROM connectors WHERE connector_name = '{name}'"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_api_key, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         ('{name}', '3', '{url}', UTC_TIMESTAMP(), '{key}', 1, 1, 0, 1, 0, 0, 1, {}, 1)",
        extra.map_or("NULL".to_string(), |e| format!("'{e}'"))
    ))
    .await;
}

async fn ai_reports_on(h: &Harness, code: &str) {
    h.exec(&format!(
        "INSERT INTO customer_portal_ai_report_settings (customer_code, enabled, updated_at) \
         VALUES ('{code}', 1, UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE enabled = 1"
    ))
    .await;
}

#[tokio::test]
async fn routes_crud_validation_and_test_send() {
    let hooks = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("^/hook"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&hooks)
        .await;
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let beta = h.code("beta");
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let base = format!("/api/customers/{acme}/notification_routes");

    // Body errors are FastAPI's, reported before the token.
    let (st, _) = h
        .call_raw("POST", &base, None, Some("application/json"), "{")
        .await;
    assert_eq!(st, 422);
    let (st, body) = h.call("POST", &base, None, Some(json!({}))).await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (401, Some("Not authenticated"))
    );
    let (st, _) = h
        .call(
            "GET",
            &format!("/api/customers/{beta}/notification_routes"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403);
    let (st, body) = h
        .call(
            "POST",
            &base,
            Some(&admin),
            Some(
                json!({"name": "x", "trigger": "temp_password_issued", "channel": "webhook",
                "config": {"url": "http://x"}}),
            ),
        )
        .await;
    assert_eq!(st, 422, "{body}");
    let (st, body) = h
        .call(
            "POST",
            &base,
            Some(&admin),
            Some(
                json!({"name": "x", "trigger": "alert_created", "channel": "webhook",
                "config": {"url": "http://x", "method": "GET"}}),
            ),
        )
        .await;
    assert_eq!(st, 422, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("method must be POST or PUT"),
        "{body}"
    );

    // Create (the legacy trigger is rewritten), list, update.
    let (st, body) = h
        .call(
            "POST",
            &base,
            Some(&admin),
            Some(
                json!({"name": "SOC webhook", "trigger": "severity_critical_or_high",
                "channel": "webhook", "destination": "  team  ",
                "config": {"url": format!("{}/hook", hooks.uri()), "headers": {"X-Key": "s"}}}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["message"], "Route created");
    let route = &body["route"];
    assert_eq!(route["trigger"], "investigation_complete");
    assert_eq!(route["destination"], "team");
    assert_eq!(route["min_severity"], "Medium");
    assert_eq!(route["created_by"], format!("admin{s}"));
    assert_eq!(route["config"]["method"], "POST");
    let id = route["id"].as_i64().unwrap();

    let (st, body) = h.call("GET", &base, Some(&analyst), None).await;
    assert_eq!(st, 200);
    assert_eq!(body["message"], "1 route(s) retrieved");
    let (st, body) = h
        .call(
            "PATCH",
            &format!("{base}/{id}"),
            Some(&analyst),
            Some(json!({"name": "Renamed", "min_severity": "Low"})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["route"]["name"], "Renamed");
    assert!(body["route"]["updated_at"].is_string());
    // Path and body errors in one 422, after the tenancy check.
    let (st, body) = h
        .call(
            "PATCH",
            &format!("{base}/abc"),
            Some(&admin),
            Some(json!({"enabled": "maybe"})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(body["details"].as_array().unwrap().len(), 2, "{body}");
    let (st, _) = h
        .call(
            "PATCH",
            &format!("/api/customers/{beta}/notification_routes/{id}"),
            Some(&admin),
            Some(json!({"name": "x"})),
        )
        .await;
    assert_eq!(st, 404);

    // The test button sends a real message and logs it.
    let (st, outcome) = h
        .call("POST", &format!("{base}/{id}/test"), Some(&analyst), None)
        .await;
    assert_eq!(st, 200, "{outcome}");
    assert_eq!(outcome["status"], "sent");
    assert_eq!(outcome["route_name"], "Renamed");
    let sent = wait_for(&hooks, "/hook", 1).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].headers["x-key"], "s");
    assert_eq!(sent[0].headers["content-type"], "application/json");
    let payload = json_of(&sent[0]);
    assert_eq!(payload["customer_code"], acme.as_str());
    assert_eq!(payload["alert_id"], 0);
    assert_eq!(payload["alert_name"], "Test notification from CoPilot");
    assert_eq!(payload["severity"], "High");
    let (trigger_source, dedupe): (String, String) = sqlx::query_as(&format!(
        "SELECT trigger_source, dedupe_key FROM notification_dispatch_log WHERE route_id = {id}"
    ))
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(trigger_source, "test");
    assert!(dedupe.starts_with(&format!("test:{id}:")));
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/customers/{acme}/notification_dispatch_log"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["entries"][0]["status"], "sent");

    // Delete; the log entry stays.
    let (st, body) = h
        .call("DELETE", &format!("{base}/{id}"), Some(&admin), None)
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (200, Some("Route deleted"))
    );
    let (st, _) = h
        .call("DELETE", &format!("{base}/{id}"), Some(&admin), None)
        .await;
    assert_eq!(st, 404);

    // Internal routes are admin-only and refuse Shuffle.
    let (st, _) = h
        .call(
            "GET",
            "/api/internal_notification_routes",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403);
    let (st, body) = h
        .call(
            "POST",
            "/api/internal_notification_routes",
            Some(&admin),
            Some(
                json!({"name": "SOC", "trigger": "alert_assigned", "channel": "shuffle",
                "scope": "internal", "destination": "#soc", "shuffle_integration_id": 1,
                "config": {"app_id": "a"}}),
            ),
        )
        .await;
    assert_eq!(st, 400, "{body}");
    let (st, body) = h
        .call(
            "POST",
            "/api/internal_notification_routes",
            Some(&admin),
            Some(
                json!({"name": "SOC", "trigger": "alert_assigned", "channel": "webhook",
                "scope": "internal", "config": {"url": format!("{}/hook-int", hooks.uri())}}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let internal = body["route"]["id"].as_i64().unwrap();
    assert!(body["route"]["customer_code"].is_null());
    let (st, _) = h
        .call(
            "GET",
            &format!("/api/internal_notification_routes/{internal}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);
    let (st, _) = h
        .call(
            "DELETE",
            &format!("/api/internal_notification_routes/{internal}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);
}

#[tokio::test]
async fn talon_dispatch_gates_logs_and_resends() {
    let hooks = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("^/hook"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&hooks)
        .await;
    let h = harness_or_skip!(None);
    let (acme_alert, _) = h.seed().await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/customers/{acme}/notification_routes"),
            Some(&admin),
            Some(
                json!({"name": "AI", "trigger": "investigation_complete", "channel": "webhook",
                "min_severity": "High", "config": {"url": format!("{}/hook", hooks.uri())}}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let request = json!({"customer_code": acme, "alert_id": acme_alert,
        "trigger": "investigation_complete", "severity_assessment": "Critical",
        "summary": "Credential dumping.", "report_url": "https://r/1", "alert_name": "Mimikatz"});

    // The customer has not opted in to AI reports: logged as skipped.
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/dispatch",
            Some(&admin),
            Some(request.clone()),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["routes_matched"], 1);
    assert_eq!(body["skipped"], 1);
    assert_eq!(
        body["outcomes"][0]["error_message"],
        "AI reports are not enabled for this customer; notification suppressed."
    );
    assert!(recorded(&hooks, "/hook").await.is_empty());

    // Opted in: sent, and the skipped row is overwritten.
    ai_reports_on(&h, &acme).await;
    let (_, body) = h
        .call(
            "POST",
            "/api/notifications/dispatch",
            Some(&admin),
            Some(request.clone()),
        )
        .await;
    assert_eq!(body["dispatched"], 1, "{body}");
    assert_eq!(
        body["message"],
        format!("Dispatched 1 of 1 matching route(s) for customer {acme} alert {acme_alert}")
    );
    let sent = recorded(&hooks, "/hook").await;
    assert_eq!(json_of(&sent[0])["report_url"], "https://r/1");
    assert_eq!(json_of(&sent[0])["alert_name"], "Mimikatz");

    // Again: the provider is called, the log refuses the second `sent`.
    let (_, body) = h
        .call(
            "POST",
            "/api/notifications/dispatch",
            Some(&admin),
            Some(request.clone()),
        )
        .await;
    assert_eq!(body["skipped"], 1, "{body}");
    assert_eq!(
        body["outcomes"][0]["error_message"],
        "Already dispatched (idempotency)"
    );
    assert_eq!(recorded(&hooks, "/hook").await.len(), 2, "send, then log");
    let rows = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM notification_dispatch_log WHERE customer_code = '{acme}' \
             AND status = 'sent'"
        ))
        .await;
    assert_eq!(rows, 1);

    // Below the route's floor: nothing matches.
    let (_, body) = h
        .call(
            "POST",
            "/api/notifications/dispatch",
            Some(&admin),
            Some(json!({"customer_code": acme, "alert_id": acme_alert,
                "trigger": "investigation_complete", "severity_assessment": "Medium",
                "summary": "s"})),
        )
        .await;
    assert_eq!(body["routes_matched"], 0);

    // Not in Python: the body's tenant is checked against the caller.
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/dispatch",
            Some(&analyst),
            Some(json!({"customer_code": h.code("beta"), "alert_id": 1,
                "trigger": "investigation_complete", "severity_assessment": "High",
                "summary": "s"})),
        )
        .await;
    assert_eq!(st, 403, "{body}");
}

#[tokio::test]
async fn the_sink_dispatches_in_process_with_the_bridge_checks() {
    let hooks = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("^/hook"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&hooks)
        .await;
    let h = harness_or_skip!(None);
    let (acme_alert, beta_alert) = h.seed().await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    ai_reports_on(&h, &acme).await;
    for (trigger, hook) in [
        ("alert_created", "/hook/created"),
        ("ai_report_reviewed", "/hook/review"),
    ] {
        let (st, body) = h
            .call(
                "POST",
                &format!("/api/customers/{acme}/notification_routes"),
                Some(&admin),
                Some(
                    json!({"name": trigger, "trigger": trigger, "channel": "webhook",
                    "min_severity": "Low", "config": {"url": format!("{}{hook}", hooks.uri())}}),
                ),
            )
            .await;
        assert_eq!(st, 200, "{body}");
    }
    let event = |trigger: NotificationTrigger, alert: i64, code: &str| NotificationEvent {
        customer_code: Some(code.to_string()),
        trigger,
        severity: NotificationSeverity::High,
        subject: "S".into(),
        summary: "x".into(),
        entity_type: "alert".into(),
        entity_id: alert,
        dedupe_key: "forged".into(),
        link_url: Some("https://evil.example".into()),
        assignee_username: None,
        actor_username: Some(format!("analyst{s}")),
        context: serde_json::Map::new(),
    };
    let sink = h.app.ctx.notifications.clone();
    // Not an AI trigger: dispatched as given (CoPilot's own emit), no token.
    sink.emit(
        event(NotificationTrigger::AlertCreated, acme_alert, &acme),
        None,
    );
    let got = wait_for(&hooks, "/hook/created", 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(json_of(&got[0])["report_url"], "https://evil.example");
    // An AI trigger: the dedupe key and link are re-derived from the alert.
    sink.emit(
        event(NotificationTrigger::AiReportReviewed, acme_alert, &acme),
        Some(analyst.clone()),
    );
    let got = wait_for(&hooks, "/hook/review", 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(
        json_of(&got[0])["report_url"],
        format!("https://copilot.example.com/alerts/{acme_alert}")
    );
    let dedupe: String = sqlx::query_scalar(&format!(
        "SELECT dedupe_key FROM notification_dispatch_log WHERE customer_code = '{acme}' \
         AND `trigger` = 'ai_report_reviewed'"
    ))
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(dedupe, format!("alert:{acme_alert}:ai_report_reviewed"));
    // Refused like the bridge: another customer's alert, a caller who may not
    // see the alert's customer, an alert that does not exist.
    sink.emit(
        event(NotificationTrigger::AiReportReviewed, beta_alert, &acme),
        Some(admin.clone()),
    );
    sink.emit(
        event(
            NotificationTrigger::AiReportReviewed,
            beta_alert,
            &h.code("beta"),
        ),
        Some(analyst.clone()),
    );
    sink.emit(
        event(
            NotificationTrigger::InvestigationComplete,
            999_999_999,
            &acme,
        ),
        Some(admin.clone()),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(recorded(&hooks, "/hook/review").await.len(), 1);
    let refused = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM notification_dispatch_log WHERE entity_id IN ({beta_alert}, 999999999) \
             AND `trigger` IN ('ai_report_reviewed', 'investigation_complete')"
        ))
        .await;
    assert_eq!(refused, 0);

    // The former bridge endpoint: 202, then the same dispatch.
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/events",
            Some(&analyst),
            Some(
                json!({"customer_code": acme, "trigger": "alert_created", "severity": "High",
                "subject": "S", "summary": "x", "entity_id": acme_alert, "dedupe_key": "k"}),
            ),
        )
        .await;
    assert_eq!(
        st, 400,
        "only AI-analyst triggers cross the endpoint: {body}"
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/events",
            Some(&analyst),
            Some(
                json!({"customer_code": h.code("beta"), "trigger": "ai_report_reviewed",
                "severity": "High", "subject": "S", "summary": "x", "entity_id": 999_999_999,
                "dedupe_key": "k"}),
            ),
        )
        .await;
    assert_eq!(
        st, 403,
        "an unknown alert is checked against the body's customer: {body}"
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/events",
            Some(&admin),
            Some(
                json!({"customer_code": acme, "trigger": "ai_report_reviewed", "severity": "High",
                "subject": "S", "summary": "x", "entity_id": 999_999_999, "dedupe_key": "k"}),
            ),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (404, Some("Alert 999999999 not found"))
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/events",
            Some(&admin),
            Some(
                json!({"customer_code": acme, "trigger": "investigation_complete",
                "severity": "High", "subject": "S", "summary": "x", "entity_id": acme_alert,
                "dedupe_key": "k"}),
            ),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body),
        (
            202,
            json!({"success": true, "message": "Notification event queued"})
        )
    );
}

#[tokio::test]
async fn templates_manual_send_and_resend() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .and(header("authorization", "Bearer re_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "msg-1"})))
        .mount(&resend)
        .await;
    let h = harness_or_skip!(None);
    let (acme_alert, beta_alert) = h.seed().await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    connector(
        &h,
        "Resend",
        &resend.uri(),
        "re_key",
        Some("soc@example.com"),
    )
    .await;

    // An AI report with a table, for the markdown → HTML path.
    let job = format!("copilot-inv-{acme_alert}-e2e{s}");
    h.exec(&format!(
        "INSERT INTO ai_analyst_job (id, alert_id, customer_code, status, triggered_by, created_at) \
         VALUES ('{job}', {acme_alert}, '{acme}', 'completed', 'webhook', UTC_TIMESTAMP())"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO ai_analyst_report (job_id, alert_id, customer_code, severity_assessment, summary, \
         report_markdown, recommended_actions, created_at) VALUES ('{job}', {acme_alert}, '{acme}', \
         'High', 'Dumped.', '| IOC | Verdict |\\n|:--|--:|\\n| 1.2.3.4 | bad |', 'Isolate', UTC_TIMESTAMP())"
    ))
    .await;

    // Templates: admin writes, analysts read their own customers' and shared.
    let (st, _) = h
        .call(
            "POST",
            "/api/notifications/templates",
            Some(&analyst),
            Some(json!({"name": "t", "body_template": "x"})),
        )
        .await;
    assert_eq!(st, 403);
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/templates",
            Some(&admin),
            Some(json!({"name": "  broken ", "body_template": "{{ x "})),
        )
        .await;
    assert_eq!(st, 400, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("body_template is not valid Jinja: ")
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/templates",
            Some(&admin),
            Some(
                json!({"name": "  Email ", "format": "markdown", "customer_code": acme,
                "subject_template": "{{ event.subject }} for {{ event.customer_code }}",
                "body_template": "**{{ event.subject }}**\n\n{{ context.ai_report.markdown }}"}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["template"]["name"], "Email");
    let tpl = body["template"]["id"].as_i64().unwrap();
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/templates/preview",
            Some(&analyst),
            Some(json!({"body_template": "{{ event.subject }} {{ nope.x }}"})),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["success"], false);
    assert_eq!(body["message"], "Template failed to render");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .starts_with("UndefinedError: "),
        "{body}"
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("/api/notifications/templates?customer_code={acme}"),
            Some(&analyst),
            None,
        )
        .await;
    assert!(
        body["templates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"] == tpl)
    );
    let (st, _) = h
        .call(
            "GET",
            &format!(
                "/api/notifications/templates?customer_code={}",
                h.code("beta")
            ),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 403);

    // A Resend route on the template; manual send needs admin for it.
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/customers/{acme}/notification_routes"),
            Some(&admin),
            Some(
                json!({"name": "Mail", "trigger": "alert_created", "channel": "resend",
                "template_id": tpl, "config": {"to": "ops@example.com", "max_per_hour": 1}}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let route = body["route"]["id"].as_i64().unwrap();
    let send = json!({"entity_type": "alert", "entity_id": acme_alert, "route_id": route,
        "include_ai_report": true});
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/send",
            Some(&analyst),
            Some(send.clone()),
        )
        .await;
    assert_eq!(
        (st.as_u16(), body["message"].as_str()),
        (
            403,
            Some(
                "Sending to a customer-facing route requires admin. An internal route is \
                 available for sharing within the SOC."
            )
        )
    );
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/send",
            Some(&admin),
            Some(json!({"entity_type": "alert", "entity_id": beta_alert, "route_id": route})),
        )
        .await;
    assert_eq!(st, 400, "{body}");
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/send/preview",
            Some(&admin),
            Some(send.clone()),
        )
        .await;
    assert_eq!(st, 400, "AI reports are off for the customer: {body}");
    ai_reports_on(&h, &acme).await;
    let (st, body) = h
        .call(
            "POST",
            "/api/notifications/send/preview",
            Some(&admin),
            Some(send.clone()),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["subject"], format!("Mimikatz acme for {acme}"));
    assert!(
        body["body"]
            .as_str()
            .unwrap()
            .starts_with("**Mimikatz acme**")
    );

    let (st, outcome) = h
        .call(
            "POST",
            "/api/notifications/send",
            Some(&admin),
            Some(send.clone()),
        )
        .await;
    assert_eq!(st, 200, "{outcome}");
    assert_eq!(outcome["status"], "sent");
    assert_eq!(outcome["provider_reference"], "msg-1");
    let mails = recorded(&resend, "/emails").await;
    let mail = json_of(&mails[0]);
    assert_eq!(mail["from"], "soc@example.com");
    assert_eq!(mail["to"], json!(["ops@example.com"]));
    assert_eq!(
        mail["subject"],
        format!("[CoPilot] Mimikatz acme for {acme}")
    );
    let html = mail["html"].as_str().unwrap();
    assert!(
        html.starts_with("<div style=\"font-family:system-ui"),
        "{html}"
    );
    assert!(
        html.contains(
            "<td style=\"border:1px solid #d1d5db;padding:6px 10px;vertical-align:top;\
             text-align:right\">bad</td>"
        ),
        "{html}"
    );
    // The route allows one an hour.
    let (_, outcome) = h
        .call(
            "POST",
            "/api/notifications/send",
            Some(&admin),
            Some(send.clone()),
        )
        .await;
    assert_eq!(outcome["status"], "skipped");
    assert_eq!(
        outcome["error_message"],
        "Rate limit reached for this route (1/1 in the last hour)."
    );
    let (_, quota) = h
        .call(
            "GET",
            &format!("/api/notification_channels/resend/quota?customer_code={acme}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(quota["configured"], true);
    assert_eq!(quota["customer_sent"], 1);
    assert_eq!(quota["limit"], 1000);

    // The template is in use: an edit that breaks the route is refused,
    // deleting it detaches the route.
    let (st, body) = h
        .call(
            "PATCH",
            &format!("/api/notifications/templates/{tpl}"),
            Some(&admin),
            Some(json!({"format": "json"})),
        )
        .await;
    assert_eq!(st, 400, "{body}");
    let (st, body) = h
        .call(
            "DELETE",
            &format!("/api/notifications/templates/{tpl}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body["message"],
        "Template deleted; 1 route(s) fell back to their channel default"
    );
    let detached = h
        .scalar_i64(&format!(
            "SELECT COUNT(*) FROM customer_notification_route WHERE id = {route} AND template_id IS NULL"
        ))
        .await;
    assert_eq!(detached, 1);
    h.exec("DELETE FROM connectors WHERE connector_name = 'Resend'")
        .await;
}

#[tokio::test]
async fn shuffle_integrations_lookups_and_delivery() {
    let shuffle = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "org-1", "name": "Acme", "role": "admin", "creator_org": ""},
            {"id": "org-2", "name": "Sub", "creator_org": "org-1"},
            {"name": "no id"}
        ])))
        .mount(&shuffle)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/apps"))
        .and(header("org-id", "org-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "app-1", "name": "Slack", "description": "chat", "large_image": ""}
        ])))
        .mount(&shuffle)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/apps/app-1/mcp"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"success": true, "execution_id": "ex-9"})),
        )
        .mount(&shuffle)
        .await;
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = h.suffix.clone();
    let acme = h.code("acme");
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    h.exec("DELETE FROM connectors WHERE connector_name = 'Shuffle'")
        .await;
    let (st, body) = h
        .call(
            "GET",
            "/api/notifications/shuffle/orgs",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 503, "{body}");
    connector(&h, "Shuffle", &shuffle.uri(), "sh_key", None).await;
    let (st, body) = h
        .call(
            "GET",
            "/api/notifications/shuffle/orgs",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["message"], "2 org(s) retrieved");
    assert!(body["orgs"][0]["creator_org"].is_null());
    assert_eq!(body["orgs"][1]["creator_org"], "org-1");

    let base = format!("/api/customers/{acme}/shuffle_integrations");
    let (st, body) = h
        .call(
            "POST",
            &base,
            Some(&analyst),
            Some(json!({"display_name": "Acme Shuffle", "shuffle_org_id": " org-1 "})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["integration"]["shuffle_org_id"], "org-1");
    let integration = body["integration"]["id"].as_i64().unwrap();
    let (_, body) = h
        .call(
            "GET",
            &format!("{base}/{integration}/apps"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["apps"][0]["id"], "app-1", "{body}");
    let (_, body) = h
        .call(
            "GET",
            &format!("{base}/{integration}/verify"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["app_count"], 1);

    let (st, body) = h
        .call(
            "POST",
            &format!("/api/customers/{acme}/notification_routes"),
            Some(&admin),
            Some(
                json!({"name": "Shuffle", "trigger": "alert_created", "channel": "shuffle",
                "destination": "#soc", "shuffle_integration_id": integration,
                "config": {"app_id": "app-1"}}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let route = body["route"]["id"].as_i64().unwrap();
    let (_, outcome) = h
        .call(
            "POST",
            &format!("/api/customers/{acme}/notification_routes/{route}/test"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(outcome["status"], "sent", "{outcome}");
    assert_eq!(outcome["provider_reference"], "ex-9");
    let calls = recorded(&shuffle, "/api/v1/apps/app-1/mcp").await;
    assert_eq!(calls[0].headers["authorization"], "Bearer sh_key");
    assert_eq!(calls[0].headers["org-id"], "org-1");
    let rpc = json_of(&calls[0]);
    assert_eq!(rpc["method"], "tools/call");
    assert_eq!(rpc["params"]["tool_id"], "app-1");
    assert!(
        rpc["params"]["input"]["text"]
            .as_str()
            .unwrap()
            .starts_with("Send to ")
    );
    // A referenced integration cannot be deleted.
    let (st, body) = h
        .call(
            "DELETE",
            &format!("{base}/{integration}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 409, "{body}");
    h.exec("DELETE FROM connectors WHERE connector_name = 'Shuffle'")
        .await;
}
