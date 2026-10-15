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

use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use copilot::app::App;
use copilot_auth::JwtCodec;
use copilot_core::config::{CopilotConfig, Secret};
use copilot_core::env::EnvFile;
use copilot_db::Db;

const SECRET: &str = "e2e-secret-not-for-production-0123456789";

struct Harness {
    router: Router,
    db: Db,
    jwt: JwtCodec,
    suffix: String,
    app: App,
}

impl Harness {
    fn code(&self, base: &str) -> String {
        format!("{base}{}", self.suffix)
    }

    fn token(&self, username: &str, role: &str) -> String {
        self.jwt
            .encode_session(username, role, Duration::from_secs(600), None)
            .unwrap()
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(uri);
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
        let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, value)
    }

    /// Run a statement; returns its `LAST_INSERT_ID()`.
    async fn exec(&self, sql: &str) -> i64 {
        let res = sqlx::query(sql).execute(self.db.pool()).await.unwrap();
        i64::try_from(res.last_insert_id()).unwrap()
    }

    async fn scalar_i64(&self, sql: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }

    /// Customers `acme<sfx>` and `beta<sfx>`; users admin/analyst(acme)/
    /// responder(acme)/portal(acme); one alert per customer with an asset.
    /// Returns `(acme_alert, beta_alert)`.
    async fn seed(&self) -> (i64, i64) {
        let s = &self.suffix;
        for c in ["acme", "beta"] {
            self.exec(&format!(
                "INSERT INTO customers (customer_code, customer_name, created_at) \
                 VALUES ('{c}{s}', '{c} corp', UTC_TIMESTAMP())"
            ))
            .await;
        }
        for (name, role) in [
            ("admin", 1),
            ("analyst", 2),
            ("responder", 5),
            ("portal", 4),
        ] {
            self.exec(&format!(
                "INSERT INTO `user` (username, password, email, created_at, role_id) \
                 VALUES ('{name}{s}', 'x', '{name}@example.com', UTC_TIMESTAMP(), {role})"
            ))
            .await;
        }
        for name in ["analyst", "responder", "portal"] {
            self.exec(&format!(
                "INSERT INTO user_customer_access (user_id, customer_code, created_at) \
                 SELECT id, 'acme{s}', UTC_TIMESTAMP() FROM `user` WHERE username = '{name}{s}'"
            ))
            .await;
        }
        let mut alerts = Vec::new();
        for c in ["acme", "beta"] {
            let id = self
                .exec(&format!(
                    "INSERT INTO incident_management_alert (alert_name, alert_description, status, \
                     alert_creation_time, customer_code, source, escalated) VALUES \
                     ('Mimikatz {c}', 'd', 'OPEN', UTC_TIMESTAMP(), '{c}{s}', 'wazuh', 0)"
                ))
                .await;
            let ctx = self
                .exec("INSERT INTO incident_management_alertcontext (source, context) VALUES ('wazuh', '{}')")
                .await;
            self.exec(&format!(
                "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, \
                 customer_code, index_name, index_id) VALUES ({id}, 'dc01-{c}', {ctx}, '{c}{s}', 'idx', 'doc')"
            ))
            .await;
            alerts.push(id);
        }
        (alerts[0], alerts[1])
    }
}

async fn harness(legacy: Option<&MockServer>) -> Option<Harness> {
    let url = std::env::var("COPILOT_TEST_DATABASE_URL").ok()?;
    let mut env = format!(
        "JWT_SECRET={SECRET}\nCOPILOT_DATABASE_URL={url}\nCONNECTOR_CACHE_TTL_SECONDS=0\n\
         COPILOT_URL=https://copilot.example.com\n"
    );
    if let Some(l) = legacy {
        env.push_str(&format!("COPILOT_LEGACY_URL={}\n", l.uri()));
    }
    let cfg = CopilotConfig::from_env(Path::new("."), &EnvFile::isolated(&env)).unwrap();
    let db = Db::connect(&cfg.database).await.unwrap();
    let app = App::new(&cfg, db.clone()).unwrap();
    let router = app.router(cfg.max_body_bytes);
    let suffix = format!("{:06x}", rand_suffix());
    Some(Harness {
        router,
        db,
        jwt: JwtCodec::new(&Secret::new(SECRET)),
        suffix,
        app,
    })
}

fn rand_suffix() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (nanos ^ std::process::id()).wrapping_mul(2_654_435_761) & 0xff_ffff
}

macro_rules! harness_or_skip {
    ($legacy:expr) => {
        match harness($legacy).await {
            Some(h) => h,
            None => {
                eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
                return;
            }
        }
    };
}

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
            json!({"alert_id": acme_alert, "customer_code": acme, "sender": "copilot-analyst"}),
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

    // The bridge receives the investigation_complete event.
    Mock::given(method("POST"))
        .and(path("/api/notifications/events"))
        .and(header("authorization", format!("Bearer {admin}").as_str()))
        .respond_with(
            ResponseTemplate::new(202)
                .set_body_json(json!({"success": true, "message": "Notification event queued"})),
        )
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

    // --- Notifications reached the bridge: report + first review only -------
    let mut bridged = Vec::new();
    for _ in 0..30 {
        bridged = legacy
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.url.path() == "/api/notifications/events")
            .map(|r| serde_json::from_slice::<Value>(&r.body).unwrap())
            .collect();
        if bridged.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let triggers: Vec<&str> = bridged
        .iter()
        .map(|e| e["trigger"].as_str().unwrap())
        .collect();
    assert_eq!(
        triggers,
        vec!["investigation_complete", "ai_report_reviewed"]
    );
    assert_eq!(bridged[0]["subject"], format!("Mimikatz acme"));
    assert_eq!(bridged[0]["context"]["asset_name"], "dc01-acme");
    assert_eq!(bridged[0]["severity"], "Critical");
    assert_eq!(bridged[1]["actor_username"], format!("analyst{s}"));
    assert_eq!(
        bridged[1]["link_url"],
        format!("https://copilot.example.com/alerts/{acme_alert}")
    );

    // --- Replay goes to Talon with the forced template -----------------------
    Mock::given(method("POST"))
        .and(path("/investigate"))
        .and(body_json(
            json!({"alert_id": acme_alert, "customer_code": acme,
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
    Mock::given(method("GET"))
        .and(path("/api/agents"))
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
        .call("GET", "/api/agents?customer_code=x", Some("abc"), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body, json!({"success": true, "agents": []}));
    let req = &legacy.received_requests().await.unwrap()[0];
    assert_eq!(req.url.query(), Some("customer_code=x"));

    // A method the Rust router does not serve on a ported path goes to Python too.
    Mock::given(method("DELETE"))
        .and(path("/api/ai_analyst/jobs/x"))
        .respond_with(
            ResponseTemplate::new(405).set_body_json(json!({"detail": "Method Not Allowed"})),
        )
        .mount(&legacy)
        .await;
    let (st, _) = h
        .call("DELETE", "/api/ai_analyst/jobs/x", Some("abc"), None)
        .await;
    assert_eq!(st, 405);

    // Ported routes are not proxied.
    let before = legacy.received_requests().await.unwrap().len();
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
                json!({"alert_id": id, "customer_code": acme, "sender": "customer-portal"}),
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

    // --- Unported portal paths and methods still reach Python -----------------------
    Mock::given(method("GET"))
        .and(path("/api/customer_portal/overview"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"from": "python"})))
        .expect(1)
        .mount(&legacy)
        .await;
    let (st, body) = h
        .call("GET", "/api/customer_portal/overview", Some(&portal), None)
        .await;
    assert_eq!((st.as_u16(), body), (200, json!({"from": "python"})));
    Mock::given(method("DELETE"))
        .and(path(settings_url(&acme)))
        .respond_with(
            ResponseTemplate::new(405).set_body_json(json!({"detail": "Method Not Allowed"})),
        )
        .expect(1)
        .mount(&legacy)
        .await;
    let (st, _) = h
        .call("DELETE", &settings_url(&acme), Some(&admin), None)
        .await;
    assert_eq!(st, 405);
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
