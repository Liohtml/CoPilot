//! End-to-end tests of the SOC Management port (`copilot-soc-management`,
//! `copilot-sla`): the production router against a real MySQL at the Alembic
//! head, the Python backend replaced by a recorder where a path falls through.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13309/copilot \
//!   cargo test -p copilot --test e2e_soc -- --test-threads=1
//! ```
//!
//! Every item is dated in March 2026 or in 2099, so its SLA state does not
//! depend on when the suite runs; the expected figures were worked out by
//! hand and match what `domain/analytics.py` computes for the same rows.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::NaiveDateTime;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const S: &str = "/api/soc_management";
const PERIOD: &str = "date_from=2026-03-01T00:00:00&date_to=2026-03-08T00:00:00";

/// The items of one test (ids by key).
struct Items {
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
    b1: i64,
    case: i64,
}

#[allow(clippy::too_many_arguments)]
async fn alert(
    h: &Harness,
    customer: &str,
    title: &str,
    status: &str,
    severity: &str,
    assigned: Option<&str>,
    verdict: Option<&str>,
    tracking: &str,
) -> i64 {
    let s = &h.suffix;
    let id = h
        .exec(&format!(
            "INSERT INTO incident_management_alert (alert_name, alert_description, status, \
             alert_creation_time, customer_code, source, escalated, assigned_to, severity, \
             verdict) VALUES ('{title}', 'd', '{status}', '2026-03-02 10:00:00', '{customer}{s}', \
             'wazuh', 0, {}, '{severity}', {})",
            assigned.map_or("NULL".into(), |a| format!("'{a}{s}'")),
            verdict.map_or("NULL".into(), |v| format!("'{v}'")),
        ))
        .await;
    h.exec(&format!(
        "INSERT INTO soc_sla_alert_tracking (alert_id, severity, reopen_count, updated_at, \
         paused_seconds, pause_credit_seconds, {tracking_cols}) VALUES ({id}, '{severity}', 0, \
         '2026-03-01 00:00:00', 0, 0, {tracking})",
        tracking_cols = "opened_at, ack_due_at, resolve_due_at, first_ack_at, first_ack_by, \
                         resolved_at, resolved_by, paused_at, tracked, business_hours",
        tracking = tracking.replace("{s}", s),
    ))
    .await;
    id
}

async fn seed(h: &Harness) -> Items {
    h.seed().await;
    let s = &h.suffix;
    let a1 = alert(
        h,
        "acme",
        "Brute",
        "CLOSED",
        "High",
        Some("analyst"),
        Some("FALSE_POSITIVE"),
        "'2026-03-02 10:00:00', '2026-03-02 11:00:00', '2026-03-02 18:00:00', \
         '2026-03-02 10:30:00', 'analyst{s}', '2026-03-02 12:00:00', 'analyst{s}', NULL, 1, 0",
    )
    .await;
    let a2 = alert(
        h,
        "acme",
        "Brute",
        "CLOSED",
        "High",
        None,
        Some("TRUE_POSITIVE"),
        "'2026-03-02 11:00:00', '2026-03-02 12:00:00', '2026-03-02 19:00:00', \
         '2026-03-02 13:00:00', 'admin{s}', '2026-03-03 10:00:00', 'portal{s}', NULL, 1, 0",
    )
    .await;
    let a3 = alert(
        h,
        "acme",
        "EDR",
        "OPEN",
        "Critical",
        None,
        None,
        "'2026-03-03 09:00:00', '2026-03-03 09:15:00', '2026-03-03 13:00:00', NULL, NULL, \
         NULL, NULL, NULL, 1, 0",
    )
    .await;
    let a4 = alert(
        h,
        "acme",
        "Phish",
        "IN_PROGRESS",
        "Medium",
        Some("analyst"),
        None,
        "'2026-03-04 09:00:00', '2026-03-04 13:00:00', '2099-01-01 00:00:00', \
         '2026-03-04 09:10:00', 'analyst{s}', NULL, NULL, NULL, 1, 0",
    )
    .await;
    let a5 = alert(
        h,
        "acme",
        "Scan",
        "PENDING_CUSTOMER",
        "Low",
        Some("analyst"),
        None,
        "'2026-03-04 08:00:00', '2026-03-04 16:00:00', '2026-03-07 08:00:00', NULL, NULL, \
         NULL, NULL, '2026-03-04 10:00:00', 1, 0",
    )
    .await;
    // Backfilled before tracking began: volumes only.
    alert(
        h,
        "acme",
        "Old",
        "OPEN",
        "High",
        None,
        None,
        "'2026-03-05 08:00:00', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0",
    )
    .await;
    let b1 = alert(
        h,
        "beta",
        "Brute",
        "OPEN",
        "High",
        None,
        None,
        "'2026-03-02 12:00:00', '2026-03-02 13:00:00', '2026-03-02 20:00:00', NULL, NULL, \
         NULL, NULL, NULL, 1, 0",
    )
    .await;
    let case = h
        .exec(&format!(
            "INSERT INTO incident_management_case (case_name, case_description, \
             case_creation_time, case_status, customer_code, escalated, assigned_to) VALUES \
             ('Case {s}', 'cd', '2026-03-03 09:30:00', 'IN_PROGRESS', 'acme{s}', 0, 'analyst{s}')"
        ))
        .await;
    h.exec(&format!(
        "INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES ({case}, {a3})"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO soc_sla_case_tracking (case_id, severity, opened_at, ack_due_at, \
         resolve_due_at, first_ack_at, first_ack_by, first_ack_action, reopen_count, tracked, \
         updated_at, business_hours, paused_seconds, pause_credit_seconds) VALUES ({case}, \
         'Critical', '2026-03-03 09:30:00', '2026-03-03 10:00:00', '2026-03-04 09:30:00', \
         '2026-03-03 09:30:00', 'analyst{s}', 'created', 0, 1, '2026-03-03 09:30:00', 0, 0, 0)"
    ))
    .await;
    Items {
        a1,
        a2,
        a3,
        a4,
        a5,
        b1,
        case,
    }
}

fn codes(h: &Harness) -> String {
    format!("customer_codes=acme{0}&customer_codes=beta{0}", h.suffix)
}

#[tokio::test]
async fn dashboard_figures_match_the_python_analytics() {
    let h = harness_or_skip!(None);
    let items = seed(&h).await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (status, d) = h
        .call(
            "GET",
            &format!("{S}/dashboard?{PERIOD}&{}", codes(&h)),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200, "{d}");
    let alerts = &d["headline"]["alerts"];
    assert_eq!(alerts["opened"], 7);
    assert_eq!(alerts["resolved"], 2);
    assert_eq!(alerts["resolved_by_customer"], 1);
    assert_eq!(
        alerts["tta"],
        json!({"count": 3, "mean": 3200.0, "median": 1800.0, "p90": 6120.0})
    );
    assert_eq!(
        alerts["ttr"],
        json!({"count": 2, "mean": 45000.0, "median": 45000.0, "p90": 75240.0})
    );
    assert_eq!(
        alerts["sla"]["ack"],
        json!({"met": 2, "breached": 3, "at_risk": 0, "on_track": 0, "paused": 1,
            "not_tracked": 1, "decided": 5, "rate": 40.0})
    );
    assert_eq!(alerts["sla"]["resolve"]["rate"], 25.0);
    assert_eq!(alerts["sla"]["resolve"]["on_track"], 1);
    assert_eq!(d["headline"]["false_positive_rate"], 50.0);
    assert_eq!(d["headline"]["case_conversion_rate"], 14.3);
    assert_eq!(d["headline"]["cases"]["opened"], 1);
    assert_eq!(d["period"]["bucket"], "day");
    assert_eq!(d["period"]["previous_from"], "2026-02-22T00:00:00");
    assert_eq!(d["trends"].as_array().unwrap().len(), 7);
    assert_eq!(d["trends"][1]["alerts_opened"], 3);
    // Most overdue first: beta's acknowledge clock, then acme's.
    let attention: Vec<(i64, String)> = d["attention"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["id"].as_i64().unwrap(),
                i["clock"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        attention[..2],
        [(items.b1, "ack".to_string()), (items.a3, "ack".to_string())]
    );
    let names: Vec<&str> = d["analysts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["username"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [format!("analyst{}", h.suffix), format!("admin{}", h.suffix)]
    );
    assert_eq!(d["workload"]["waiting_on_customer"], 1);
    assert_eq!(
        d["customers"][0]["customer_code"],
        format!("acme{}", h.suffix)
    );
    assert_eq!(d["customers"][0]["customer_name"], "acme corp");
    assert_eq!(d["customers"][0]["top_rule"], "Brute");
    // Several customers in scope: the global policy is shown.
    assert_eq!(d["policy"]["customer_code"], Value::Null);
    assert_eq!(d["policy"]["cells"].as_array().unwrap().len(), 10);

    // An analyst: every aggregate of their customers, only their own row.
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let (status, d) = h
        .call(
            "GET",
            &format!("{S}/dashboard?{PERIOD}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(d["viewer"]["sees_all_analysts"], false);
    assert_eq!(d["customer_codes"], json!([format!("acme{}", h.suffix)]));
    assert_eq!(d["headline"]["alerts"]["opened"], 6);
    assert_eq!(d["analysts"].as_array().unwrap().len(), 1);
    assert_eq!(d["policy"]["customer_code"], format!("acme{}", h.suffix));

    // The item badges.
    let (status, item) = h
        .call(
            "GET",
            &format!("{S}/items/alert/{}/sla", items.a5),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(item["ack"]["state"], "paused");
    assert_eq!(item["ack"]["target_minutes"], 480);
    assert!(item["paused_seconds"].as_i64().unwrap() > 0);
    let (status, item) = h
        .call(
            "GET",
            &format!("{S}/items/case/{}/sla", items.case),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(item["ack"]["action"], "created");
    assert_eq!(item["ack"]["state"], "met");
    let (status, body) = h
        .call(
            "GET",
            &format!("{S}/items/alert/{}/sla", items.b1),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body),
        (404, json!({"success": false, "message": "Alert not found"}))
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("{S}/attention?state=at_risk&entity=alert"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["total"], 0);
    let (status, body) = h
        .call(
            "GET",
            &format!("{S}/attention?state=met"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (400, json!("state must be breached or at_risk"))
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("{S}/sources?customer_codes=acme{}", h.suffix),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["sources"], json!([{"source": "wazuh", "alerts": 7}]));
    let _ = (items.a1, items.a2, items.a4);
}

#[tokio::test]
async fn dashboard_refuses_bad_periods_and_non_soc_callers() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (status, body) = h
        .call(
            "GET",
            &format!("{S}/dashboard?date_from=2026-02-01&date_to=2026-01-01"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (400, json!("The period must start before it ends"))
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("{S}/dashboard?bucket=year"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 422);
    let fields: Vec<&str> = body["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, ["date_from", "date_to", "bucket"]);
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");
    let (status, body) = h
        .call(
            "GET",
            &format!("{S}/dashboard?{PERIOD}"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            403,
            json!("Insufficient permissions. Required one of: admin, analyst")
        )
    );
}

async fn due_of(h: &Harness, id: i64) -> (Option<NaiveDateTime>, Option<NaiveDateTime>, bool) {
    sqlx::query_as(
        "SELECT ack_due_at, resolve_due_at, business_hours FROM soc_sla_alert_tracking \
         WHERE alert_id = ?",
    )
    .bind(id)
    .fetch_one(h.db.pool())
    .await
    .unwrap()
}

fn at(s: &str) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
}

#[tokio::test]
async fn policy_and_calendar_writes_retarget_running_clocks_only() {
    let h = harness_or_skip!(None);
    let items = seed(&h).await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let body = json!({
        "customer_code": format!("acme{s}"),
        "cells": [
            {"entity": "alert", "severity": "Medium", "ack_minutes": 60, "resolve_minutes": 600},
            {"entity": "alert", "severity": "High", "inherit": true},
        ],
        "apply_to_open": true,
    });
    let (status, _) = h
        .call(
            "PUT",
            &format!("{S}/policies"),
            Some(&analyst),
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, 403);
    let (status, out) = h
        .call("PUT", &format!("{S}/policies"), Some(&admin), Some(body))
        .await;
    assert_eq!(status, 200, "{out}");
    assert_eq!(
        out["message"],
        format!("Saved customer acme{s}; 1 open item(s) re-targeted")
    );
    assert_eq!(out["retargeted"], 1);
    let medium = &out["policy"]["cells"][2];
    assert_eq!(
        medium,
        &json!({"entity": "alert", "severity": "Medium", "ack_minutes": 60,
            "resolve_minutes": 600, "business_hours": false, "source": "customer"})
    );
    // a4 was acknowledged: only its resolve clock moves.
    assert_eq!(
        due_of(&h, items.a4).await,
        (
            Some(at("2026-03-04 13:00:00")),
            Some(at("2026-03-04 19:00:00")),
            false
        )
    );
    let (_, overrides) = h
        .call(
            "GET",
            &format!("{S}/policies/overrides"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        overrides["overrides"][0]["customer_code"],
        format!("acme{s}")
    );
    assert_eq!(overrides["overrides"][0]["cells"], 1);
    assert_eq!(overrides["overrides"][0]["updated_by"], format!("admin{s}"));

    // Business hours: a Rome calendar and a business-hours Medium cell.
    let cal = json!({
        "customer_code": format!("acme{s}"),
        "timezone": "Europe/Rome",
        "week": {"tue": [["09:00", "17:00"]], "wed": [["09:00", "17:00"]]},
        "holidays": ["2026-03-10"],
    });
    let (status, out) = h
        .call("PUT", &format!("{S}/calendars"), Some(&admin), Some(cal))
        .await;
    assert_eq!(status, 200, "{out}");
    assert_eq!(out["message"], format!("Saved customer acme{s}"));
    assert_eq!(out["calendar"]["source"], "customer");
    assert_eq!(out["calendar"]["week"]["tue"], json!([["09:00", "17:00"]]));
    assert_eq!(out["calendar"]["week"]["mon"], json!([]));
    let body = json!({
        "customer_code": format!("acme{s}"),
        "cells": [{"entity": "alert", "severity": "Medium", "ack_minutes": 60,
            "resolve_minutes": 600, "business_hours": true}],
        "apply_to_open": true,
    });
    let (status, out) = h
        .call("PUT", &format!("{S}/policies"), Some(&admin), Some(body))
        .await;
    assert_eq!(status, 200);
    assert_eq!(out["retargeted"], 1);
    // Opened Wednesday 2026-03-04 09:00 UTC (10:00 Rome): 7 working hours that
    // Wednesday, the remaining 3 on Tuesday 2026-03-10 — a holiday — so on
    // Wednesday 2026-03-11, 09:00–12:00 Rome = 08:00–11:00 UTC.
    assert_eq!(
        due_of(&h, items.a4).await,
        (
            Some(at("2026-03-04 13:00:00")),
            Some(at("2026-03-11 11:00:00")),
            true
        )
    );
    let (status, item) = h
        .call(
            "GET",
            &format!("{S}/items/alert/{}/sla", items.a4),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(item["business_hours"], true);
    assert_eq!(item["calendar_timezone"], "Europe/Rome");
    assert_eq!(item["resolve"]["target_minutes"], 600);

    let (status, out) = h
        .call(
            "DELETE",
            &format!("{S}/calendars/acme{s}?apply_to_open=true"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        out["message"],
        format!("acme{s} now follows the global calendar")
    );
    assert_ne!(out["calendar"]["source"], "customer");
    let (_, out) = h
        .call(
            "DELETE",
            &format!("{S}/calendars/acme{s}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(
        out["message"],
        format!("acme{s} had no calendar of its own")
    );
    let (status, out) = h
        .call(
            "DELETE",
            &format!("{S}/policies/acme{s}?apply_to_open=yes"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        out["message"],
        format!("Removed 1 override(s); acme{s} now follows the global policy")
    );
    let (status, body) = h
        .call(
            "PUT",
            &format!("{S}/calendars"),
            Some(&admin),
            Some(json!({"timezone": "Mars/Base", "week": {"mon": [["09:00", "17:00"]]}})),
        )
        .await;
    assert_eq!(status, 422);
    assert_eq!(
        body["details"][0]["message"],
        "Unknown timezone 'Mars/Base'"
    );
}

#[tokio::test]
async fn portal_sla_page_is_opt_in_and_person_free() {
    let h = harness_or_skip!(None);
    seed(&h).await;
    let s = h.suffix.clone();
    let admin = h.token(&format!("admin{s}"), "admin");
    let portal = h.token(&format!("portal{s}"), "customer_user");
    let (status, body) = h
        .call(
            "GET",
            "/api/customer_portal/sla/availability",
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["enabled"], false);
    let overview = format!("/api/customer_portal/sla/overview?{PERIOD}");
    let (_, body) = h.call("GET", &overview, Some(&portal), None).await;
    assert_eq!(
        body,
        json!({"enabled": false, "customer_codes": [], "date_from": null, "date_to": null,
            "bucket": null, "tracking_since": null, "alerts": null, "cases": null,
            "previous_alerts": null, "previous_cases": null, "targets": [], "trend": [],
            "open_now": null, "success": true,
            "message": "The SLA page is not enabled for this customer"})
    );
    let (status, body) = h
        .call(
            "PUT",
            &format!("/api/customer_portal/sla/settings/nope{s}"),
            Some(&admin),
            Some(json!({"enabled": true})),
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (404, json!(format!("Customer nope{s} not found")))
    );
    let (status, body) = h
        .call(
            "PUT",
            &format!("/api/customer_portal/sla/settings/acme{s}"),
            Some(&admin),
            Some(json!({"enabled": true})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["enabled"], true);
    assert_eq!(body["message"], "Customer SLA settings saved successfully");
    let (_, body) = h
        .call(
            "GET",
            "/api/customer_portal/sla/availability",
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(body["enabled"], true);
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/customer_portal/sla/availability?customer_code=beta{s}"),
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (403, json!(format!("Access denied to customer beta{s}")))
    );
    let (status, body) = h.call("GET", &overview, Some(&portal), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["customer_codes"], json!([format!("acme{s}")]));
    assert_eq!(body["alerts"]["opened"], 6);
    assert_eq!(body["open_now"]["waiting_on_you"], 1);
    let text = body.to_string();
    for person in ["analyst", "admin", "portal"] {
        assert!(
            !text.contains(&format!("{person}{s}")),
            "{person} leaked into the portal SLA page"
        );
    }
    let (status, body) = h
        .call(
            "GET",
            "/api/customer_portal/sla/overview?date_from=2026-02-01&date_to=2026-01-01",
            Some(&portal),
            None,
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(
        body["message"],
        "Invalid period: it must start before it ends and span at most 366 days"
    );
}

#[tokio::test]
async fn report_falls_through_to_python() {
    let legacy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/soc_management/report"))
        .respond_with(ResponseTemplate::new(200).set_body_string("%PDF-1.4 python"))
        .mount(&legacy)
        .await;
    let h = harness_or_skip!(Some(&legacy));
    h.seed().await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (status, body) = h
        .call("GET", &format!("{S}/report?{PERIOD}"), Some(&admin), None)
        .await;
    assert_eq!((status.as_u16(), body), (200, json!("%PDF-1.4 python")));
}
