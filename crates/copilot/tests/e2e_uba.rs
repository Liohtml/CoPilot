//! End-to-end tests of the SOCFortress UBA port (`copilot-uba`): the
//! production router on a real MySQL, with UBA (and, for setup and rollback,
//! Graylog and the Wazuh manager) replaced by local stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13309/copilot \
//!   cargo test -p copilot --test e2e_uba -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `UBA_E2E_PORT_BASE` (6370) and the ports after
//! it. The connector rows a test points at them are replaced for that test
//! and restored (run single-threaded).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::StatusCode;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

const KEY: &str = "uba_e2e_key_0123456789";

fn port(offset: u16) -> u16 {
    std::env::var("UBA_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6370)
        + offset
}

/// A stand-in on one of this suite's ports.
async fn stand_in(offset: u16) -> MockServer {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port(offset))).unwrap();
    MockServer::builder().listener(listener).start().await
}

/// A saved `connectors` row: name, url, username, password, api key.
type Row = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

struct Saved(String, Vec<Row>);

async fn set_connector(
    h: &Harness,
    name: &str,
    url: &str,
    user: Option<&str>,
    password: Option<&str>,
    key: Option<&str>,
    verified: bool,
) -> Saved {
    let saved: Vec<Row> = sqlx::query_as(
        "SELECT connector_name, connector_url, connector_username, connector_password, \
         connector_api_key FROM connectors WHERE connector_name = ?",
    )
    .bind(name)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
        .bind(name)
        .execute(h.db.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, \
         connector_last_updated, connector_username, connector_password, connector_api_key, \
         connector_description, connector_supports, connector_configured, connector_verified, \
         connector_accepts_host_only, connector_accepts_api_key, \
         connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         (?, '3', ?, UTC_TIMESTAMP(), ?, ?, ?, 'e2e', 'e2e', 1, ?, 0, 1, 0, 0, 0, NULL, 1)",
    )
    .bind(name)
    .bind(url)
    .bind(user)
    .bind(password)
    .bind(key)
    .bind(verified)
    .execute(h.db.pool())
    .await
    .unwrap();
    Saved(name.to_string(), saved)
}

async fn restore(h: &Harness, saved: Saved) {
    sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
        .bind(&saved.0)
        .execute(h.db.pool())
        .await
        .unwrap();
    for (name, url, user, pw, key) in saved.1 {
        sqlx::query(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, \
             connector_last_updated, connector_username, connector_password, connector_api_key, \
             connector_description, connector_supports, connector_configured, \
             connector_verified, connector_accepts_host_only, connector_accepts_api_key, \
             connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_enabled) VALUES (?, '3', ?, \
             UTC_TIMESTAMP(), ?, ?, ?, 'restored', 'restored', 1, 1, 0, 1, 0, 0, 0, 1)",
        )
        .bind(name)
        .bind(url)
        .bind(user)
        .bind(pw)
        .bind(key)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

async fn uba_connector(h: &Harness, uba: &MockServer) -> Saved {
    set_connector(
        h,
        "SOCFortress UBA",
        &format!(" {}/v1/ ", uba.uri()),
        None,
        None,
        Some(KEY),
        true,
    )
    .await
}

fn tokens(h: &Harness) -> (String, String) {
    let s = &h.suffix;
    (
        h.token(&format!("admin{s}"), "admin"),
        h.token(&format!("analyst{s}"), "analyst"),
    )
}

/// The one request the stand-in received: method, path, query, headers, body.
async fn last(
    uba: &MockServer,
) -> (
    String,
    String,
    Option<String>,
    Vec<(String, String)>,
    Vec<u8>,
) {
    let reqs = uba.received_requests().await.unwrap();
    let r = reqs.last().unwrap();
    let mut headers: Vec<(String, String)> = r
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
        .collect();
    headers.sort();
    (
        r.method.to_string(),
        r.url.path().to_string(),
        r.url.query().map(str::to_string),
        headers,
        r.body.clone(),
    )
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn availability_reads_the_connector_row_only() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let (_, analyst) = tokens(&h);
    let saved = set_connector(&h, "SOCFortress UBA", "", None, None, Some(" "), true).await;
    let (status, body) = h
        .call("GET", "/api/uba/availability", Some(&analyst), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"success": true, "message": "SOCFortress UBA connector is not verified",
               "configured": false, "verified": false})
    );
    sqlx::query("DELETE FROM connectors WHERE connector_name = 'SOCFortress UBA'")
        .execute(h.db.pool())
        .await
        .unwrap();
    let (_, body) = h
        .call("GET", "/api/uba/availability", Some(&analyst), None)
        .await;
    assert_eq!(
        body["message"], "SOCFortress UBA connector is not installed",
        "{body}"
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/uba/{}/status", h.code("acme")),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({"detail": "No SOCFortress UBA connector found in the database",
               "reason": "not_configured", "success": false})
    );
    restore(&h, saved).await;
}

#[tokio::test]
async fn proxies_pass_uba_through_with_tenancy_and_validation() {
    if std::env::var("COPILOT_TEST_DATABASE_URL").is_err() {
        return;
    }
    let uba = stand_in(0).await;
    let h = harness_or_skip!(None);
    h.seed().await;
    let saved = uba_connector(&h, &uba).await;
    let (admin, analyst) = tokens(&h);
    let acme = h.code("acme");
    Mock::given(method("GET"))
        .and(path(format!("/v1/tenants/{acme}/entities")))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"total": 1, "entities": [{"key": "upn:jane", "risk": 1.5e16}], "success": "yes"}),
        ))
        .mount(&uba)
        .await;
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/uba/{acme}/entities?q=jane&min_risk=1&native=OFF&page_size=7"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "", "total": 1,
               "entities": [{"key": "upn:jane", "risk": 1.5e16}]})
    );
    let (m, p, q, headers, _) = last(&uba).await;
    assert_eq!(
        (m.as_str(), p.as_str()),
        ("GET", format!("/v1/tenants/{acme}/entities").as_str())
    );
    assert_eq!(
        q.as_deref(),
        Some("q=jane&min_risk=1.0&native=false&page=1&page_size=7")
    );
    assert_eq!(header(&headers, "x-api-key"), Some(KEY));
    assert_eq!(header(&headers, "accept"), Some("application/json"));
    assert_eq!(header(&headers, "user-agent"), Some("python-httpx/0.28.1"));
    assert_eq!(
        header(&headers, "x-uba-actor"),
        None,
        "reads carry no actor"
    );

    // Another tenant's customer: refused before UBA is asked.
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/uba/{}/entities", h.code("beta")),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // Query validation, in the parameters' order.
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/uba/{acme}/entities?min_risk=-1&native=maybe&page=0"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let fields: Vec<&str> = body["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, ["min_risk", "native", "page"]);
    assert_eq!(
        body["details"][1]["message"],
        "native: Input should be a valid boolean, unable to interpret input"
    );

    // Writes carry the analyst, and the body as httpx encodes it.
    Mock::given(method("POST"))
        .and(path(format!("/v1/tenants/{acme}/suppressions")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"message": "ok", "added": 2})),
        )
        .mount(&uba)
        .await;
    let (status, body) = h
        .call(
            "POST",
            &format!("/api/uba/{acme}/suppressions"),
            Some(&analyst),
            Some(
                json!({"entity_key": "windows-demo\\jdoe", "rule_ids": ["r1", "r2"], "days": "7"}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"success": true, "message": "ok", "added": 2}));
    let (_, _, _, headers, sent) = last(&uba).await;
    assert_eq!(
        String::from_utf8(sent).unwrap(),
        r#"{"entity_key":"windows-demo\\jdoe","rule_ids":["r1","r2"],"days":7,"reason":null}"#
    );
    assert_eq!(
        header(&headers, "x-uba-actor"),
        Some(format!("analyst{}", h.suffix).as_str())
    );
    assert_eq!(header(&headers, "content-type"), Some("application/json"));

    // Admin-only routes refuse an analyst.
    let (status, _) = h
        .call(
            "PUT",
            &format!("/api/uba/{acme}/risk-policy"),
            Some(&analyst),
            Some(json!({"alert_threshold": 50})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/tenants/{acme}/identity-candidates/7/dismiss"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .mount(&uba)
        .await;
    let (status, body) = h
        .call(
            "POST",
            &format!("/api/uba/{acme}/identity-candidates/007/dismiss"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, _, _, headers, sent) = last(&uba).await;
    assert!(sent.is_empty());
    assert_eq!(header(&headers, "content-length"), Some("0"));
    restore(&h, saved).await;
}

#[tokio::test]
async fn upstream_failures_are_never_a_copilot_401_or_403() {
    if std::env::var("COPILOT_TEST_DATABASE_URL").is_err() {
        return;
    }
    let uba = stand_in(1).await;
    let h = harness_or_skip!(None);
    h.seed().await;
    let saved = uba_connector(&h, &uba).await;
    let (_, analyst) = tokens(&h);
    let acme = h.code("acme");
    let cases: Vec<(&str, ResponseTemplate, u16, Value)> = vec![
        (
            "a",
            ResponseTemplate::new(401),
            502,
            json!({"detail": "SOCFortress UBA rejected the API key (revoked or wrong). Create one with `uba-admin api-keys create --name copilot --scope write` and update the connector.",
                   "reason": "key_rejected", "success": false}),
        ),
        (
            "b",
            ResponseTemplate::new(403).set_body_json(json!({"detail": "tenant not in key"})),
            502,
            json!({"detail": "The UBA API key's scope does not allow this (tenant not in key). CoPilot needs a key with scope write; setting UBA up for a customer needs scope admin for that customer (or all: `--scope admin --tenants '*'`).",
                   "reason": "insufficient_scope", "success": false}),
        ),
        (
            "c",
            ResponseTemplate::new(404).set_body_json(
                json!({"detail": [{"loc": ["path", 1, null], "msg": "unknown alert"}]}),
            ),
            404,
            json!({"detail": "path.1.None: unknown alert", "reason": "not_found", "success": false}),
        ),
        (
            "d",
            ResponseTemplate::new(422).set_body_string("nope"),
            422,
            json!({"detail": "SOCFortress UBA rejected the request", "reason": "invalid_request",
                   "success": false}),
        ),
        (
            "e",
            ResponseTemplate::new(503),
            502,
            json!({"detail": "SOCFortress UBA returned HTTP 503", "reason": "upstream_error",
                   "success": false}),
        ),
        (
            "f",
            ResponseTemplate::new(200).set_body_string("<html>"),
            502,
            json!({"detail": format!("SOCFortress UBA returned a non-JSON response for /v1/tenants/{acme}/alerts/f: check the connector URL"),
                   "reason": "bad_response", "success": false}),
        ),
    ];
    for (id, template, want_status, want) in cases {
        Mock::given(method("GET"))
            .and(path(format!("/v1/tenants/{acme}/alerts/{id}")))
            .respond_with(template)
            .mount(&uba)
            .await;
        let (status, body) = h
            .call(
                "GET",
                &format!("/api/uba/{acme}/alerts/{id}"),
                Some(&analyst),
                None,
            )
            .await;
        assert_eq!(status.as_u16(), want_status, "{id}: {body}");
        assert_eq!(body, want, "{id}");
    }
    // A detail list whose first entry is not a dict: Python's AttributeError.
    Mock::given(method("GET"))
        .and(path(format!("/v1/tenants/{acme}/alerts/g")))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"detail": ["x"]})))
        .mount(&uba)
        .await;
    let (status, _) = h
        .call(
            "GET",
            &format!("/api/uba/{acme}/alerts/g"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    // Nothing listens: unreachable.
    let dead = set_connector(
        &h,
        "SOCFortress UBA",
        &format!("http://127.0.0.1:{}", port(9)),
        None,
        None,
        Some(KEY),
        true,
    )
    .await;
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/uba/{acme}/about"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        body["detail"],
        format!(
            "Could not reach SOCFortress UBA at http://127.0.0.1:{}: ConnectError",
            port(9)
        )
    );
    drop(dead);
    restore(&h, saved).await;
}

#[tokio::test]
async fn status_and_the_connector_check_read_ubas_status() {
    if std::env::var("COPILOT_TEST_DATABASE_URL").is_err() {
        return;
    }
    let uba = stand_in(2).await;
    let h = harness_or_skip!(None);
    h.seed().await;
    let saved = uba_connector(&h, &uba).await;
    let (admin, analyst) = tokens(&h);
    let acme = h.code("acme");
    Mock::given(method("GET"))
        .and(path("/v1/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": "1.4.6",
            "tenants": [
                {"tenant": "other"},
                {"tenant": acme, "processed_until": "2026-10-17T10:00:00+00:00", "lag_seconds": 3,
                 "alerts_24h": "2", "extra": [1]},
                "never looked at",
            ],
        })))
        .mount(&uba)
        .await;
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/uba/{acme}/status"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "UBA status", "version": "1.4.6", "status": {
            "tenant": acme, "processed_until": "2026-10-17T10:00:00Z", "lag_seconds": 3.0,
            "alerts_24h": 2, "open_alerts": 0, "signals_24h": 0, "onboarding": null,
            "extra": [1]}})
    );
    let id: (i32,) =
        sqlx::query_as("SELECT id FROM connectors WHERE connector_name = 'SOCFortress UBA'")
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    // The connector check reads every tenant: a non-dict entry is Python's
    // exception, which `verify_connector_by_id` turns into its 404.
    let verify = format!("/api/connectors/verify/{}", id.0);
    let (status, _) = h.call("POST", &verify, Some(&admin), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    uba.reset().await;
    Mock::given(method("GET"))
        .and(path("/v1/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": "1.4.6", "tenants": [{"tenant": "other"}, {"tenant": acme}]})))
        .mount(&uba)
        .await;
    let (status, body) = h.call("POST", &verify, Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"connectionSuccessful": true,
               "message": format!("Connected to SOCFortress UBA 1.4.6; tenants: other, {acme}")})
    );
    let (_, _, _, headers, _) = last(&uba).await;
    assert_eq!(header(&headers, "x-api-key"), Some(KEY));
    restore(&h, saved).await;
}

#[tokio::test]
async fn a_uba_verdict_is_written_back_to_its_incident_alert() {
    if std::env::var("COPILOT_TEST_DATABASE_URL").is_err() {
        return;
    }
    let uba = stand_in(3).await;
    let h = harness_or_skip!(None);
    let (acme_alert, beta_alert) = h.seed().await;
    let saved = uba_connector(&h, &uba).await;
    let (_, analyst) = tokens(&h);
    let acme = h.code("acme");
    let alerts = format!("/v1/tenants/{acme}/alerts");
    for (id, linked) in [
        ("u1", json!(acme_alert)),
        ("u2", json!(beta_alert)),
        ("u3", json!(null)),
        ("u4", json!(format!("{acme_alert}"))),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("{alerts}/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"alert": {"id": id, "copilot_alert_id": linked, "entity_key": "upn:j"}}),
            ))
            .mount(&uba)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{alerts}/{id}/feedback")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "saved"})))
            .mount(&uba)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(alerts.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"alerts": [
            {"id": "u1", "copilot_alert_id": acme_alert},
            {"id": "u9", "copilot_alert_id": acme_alert},
        ]})))
        .mount(&uba)
        .await;
    let feedback = |id: &str| format!("/api/uba/{acme}/alerts/{id}/feedback");

    // An unsuppressed false positive while a sibling is open: left alone.
    let (status, body) = h
        .call(
            "POST",
            &feedback("u1"),
            Some(&analyst),
            Some(json!({"verdict": "FALSE_POSITIVE", "suppress": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["incident"]["status"], "skipped", "{body}");
    assert_eq!(
        body["incident"]["message"],
        format!(
            "Incident alert #{acme_alert} also holds 1 other open UBA alert(s) for this entity; a \
             false positive there would suppress their rules, so it was left untriaged."
        )
    );
    // Recorded, with CoPilot's reason vocabulary, audited.
    let (status, body) = h
        .call(
            "POST",
            &feedback("u1"),
            Some(&analyst),
            Some(json!({"verdict": "FALSE_POSITIVE", "reason": "noise", "note": "n"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "saved", "incident": {
            "status": "recorded", "incident_alert_id": acme_alert,
            "verdict": "FALSE_POSITIVE",
            "message": format!("Also recorded on incident alert #{acme_alert}.")}})
    );
    let row: (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT verdict, verdict_reason, verdict_note, verdict_by FROM \
         incident_management_alert WHERE id = ?",
    )
    .bind(acme_alert)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            Some("FALSE_POSITIVE".into()),
            Some("OTHER".into()),
            Some("n".into()),
            Some(format!("analyst{}", h.suffix))
        )
    );
    let audit: (String, String) = sqlx::query_as(
        "SELECT entity_id, CAST(JSON_UNQUOTE(JSON_EXTRACT(new_value, '$.via')) AS CHAR) FROM audit_log \
         WHERE action = 'alert.verdict_set' AND actor_username = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(format!("analyst{}", h.suffix))
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(audit, (acme_alert.to_string(), "uba".to_string()));
    // Never overwritten; another customer's is skipped; none is not linked.
    for (id, status) in [
        ("u4", "already_set"),
        ("u2", "skipped"),
        ("u3", "not_linked"),
    ] {
        let (code, body) = h
            .call(
                "POST",
                &feedback(id),
                Some(&analyst),
                Some(json!({"verdict": "TRUE_POSITIVE"})),
            )
            .await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert_eq!(body["incident"]["status"], status, "{id}: {body}");
    }
    restore(&h, saved).await;
}
