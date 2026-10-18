//! End-to-end tests of the GitHub organization audit and the Nuclei scans
//! (`copilot-assessments`) against a real MySQL, GitHub's API and the
//! `copilot-nuclei-module` container replaced by stand-ins.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13306/copilot \
//!   cargo test -p copilot --test e2e_github_audit -- --test-threads=1
//! ```
//!
//! The stand-ins listen on `GITHUB_AUDIT_E2E_PORT_BASE` (6236) and the next
//! port. Seeded rows use ids 7843000-7843999 (no other suite uses them);
//! every row of the test's customers is deleted again at the end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// The fixture builds the harness itself (its stand-ins first), so the
// shared `harness_or_skip!` goes unused here.
#[allow(unused_macros)]
mod common;
use common::*;

const GITHUB: u16 = 0;
const NUCLEI: u16 = 1;

fn port(offset: u16) -> u16 {
    std::env::var("GITHUB_AUDIT_E2E_PORT_BASE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(6236)
        + offset
}

/// Whether the suite runs at all; checked before a stand-in binds a port, so
/// that `cargo test --workspace` (parallel, no database) never races for one.
fn configured() -> bool {
    std::env::var("COPILOT_TEST_DATABASE_URL").is_ok()
}

/// A stand-in on its port, retried while the previous test's server lets
/// the port go.
async fn stand_in(offset: u16) -> MockServer {
    let mut tries = 0;
    let listener = loop {
        match std::net::TcpListener::bind(("127.0.0.1", port(offset))) {
            Ok(l) => break l,
            Err(_) if tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("cannot bind the stand-in on {}: {e}", port(offset)),
        }
    };
    MockServer::builder().listener(listener).start().await
}

const CFG_A: i64 = 7843001;
const CFG_B: i64 = 7843002;
const CFG_OFF: i64 = 7843003;
const REP_A: i64 = 7843101;
const REP_B: i64 = 7843102;
const EXC_A: i64 = 7843201;
const EXC_B: i64 = 7843202;
const BAS_A: i64 = 7843301;
const ORG: &str = "e2e-org";

struct Fixture {
    h: Harness,
    admin: String,
    analyst: String,
    portal: String,
    acme: String,
    beta: String,
    github: MockServer,
    nuclei: MockServer,
}

impl Fixture {
    async fn wipe(&self) {
        for table in [
            "github_audit_baseline",
            "github_audit_check_exclusion",
            "github_audit_report",
            "github_audit_config",
        ] {
            self.h
                .exec(&format!(
                    "DELETE FROM {table} WHERE id BETWEEN 7843000 AND 7843999 \
                     OR customer_code IN ('{}', '{}')",
                    self.acme, self.beta
                ))
                .await;
        }
    }

    async fn config(&self, id: i64, customer: &str, org: &str, enabled: bool) {
        self.h
            .exec(&format!(
                "INSERT INTO github_audit_config (id, customer_code, github_token, organization, \
                 token_type, enabled, auto_audit_enabled, include_repos, include_workflows, \
                 include_members, include_archived_repos, repo_filter_mode, notify_on_critical, \
                 notify_on_high, minimum_passing_score, created_at, updated_at, created_by) VALUES \
                 ({id}, '{customer}', 'ghp_e2e_{id}', '{org}', 'pat', {}, 0, 1, 1, 1, 0, 'all', \
                 1, 0, 70.0, '2026-01-02 03:04:05', '2026-01-02 03:04:05', 'seed')",
                i32::from(enabled)
            ))
            .await;
    }

    async fn report(&self, id: i64, config: i64, customer: &str, started: &str) {
        let full = json!({
            "organization_results": {"checks": [
                {"check_id": "org-2fa-required", "status": "fail"},
                {"check_id": "org-sso-enforcement", "status": "pass"},
            ]},
            "repository_results": [
                {"repo_name": "web", "checks": [{"check_id": "repo-license", "status": "warning"}]},
            ],
        });
        sqlx::query(
            "INSERT INTO github_audit_report (id, config_id, customer_code, report_name, \
             organization, audit_started_at, audit_completed_at, audit_duration_seconds, \
             total_repos_audited, total_checks, passed_checks, failed_checks, warning_checks, \
             critical_findings, high_findings, medium_findings, low_findings, score, grade, \
             status, full_report, top_findings, triggered_by) VALUES \
             (?, ?, ?, ?, ?, ?, ?, 1.5, 3, 12, 6, 3, 3, 1, 1, 2, 2, 61.1, 'D', 'completed', ?, \
             '[]', 'manual')",
        )
        .bind(id)
        .bind(config)
        .bind(customer)
        .bind(format!("Audit-{ORG}-seed-{id}"))
        .bind(ORG)
        .bind(started)
        .bind(started)
        .bind(full.to_string())
        .execute(self.h.db.pool())
        .await
        .unwrap();
    }

    async fn exclusion(&self, id: i64, config: i64, customer: &str, check: &str, res: &str) {
        self.h
            .exec(&format!(
                "INSERT INTO github_audit_check_exclusion (id, config_id, customer_code, check_id, \
                 resource_name, reason, enabled, created_at, created_by) VALUES \
                 ({id}, {config}, '{customer}', '{check}', {res}, 'accepted risk', 1, \
                 '2026-01-02 03:04:05', 'seed')"
            ))
            .await;
    }

    async fn seed_rows(&self) {
        self.wipe().await;
        self.config(CFG_A, &self.acme, ORG, true).await;
        self.config(CFG_B, &self.beta, "beta-org", true).await;
        self.config(CFG_OFF, &self.acme, "off-org", false).await;
        self.report(REP_A, CFG_A, &self.acme, "2026-03-01 10:00:00")
            .await;
        self.report(REP_B, CFG_B, &self.beta, "2026-03-02 10:00:00")
            .await;
        self.exclusion(EXC_A, CFG_A, &self.acme, "repo-license", "NULL")
            .await;
        self.exclusion(EXC_B, CFG_B, &self.beta, "repo-license", "NULL")
            .await;
        self.h
            .exec(&format!(
                "INSERT INTO github_audit_baseline (id, config_id, customer_code, name, \
                 expected_checks, is_active, created_at, created_by) VALUES \
                 ({BAS_A}, {CFG_A}, '{}', 'first', '{{\"org-2fa-required\": \"pass\"}}', 1, \
                 '2026-01-02 03:04:05', 'seed')",
                self.acme
            ))
            .await;
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: &str,
        body: Option<Value>,
    ) -> (http::StatusCode, Value) {
        self.h.call(method, uri, Some(token), body).await
    }
}

/// The fixture, or `None` (skipped) without a database.
async fn fixture() -> Option<Fixture> {
    if !configured() {
        eprintln!("COPILOT_TEST_DATABASE_URL not set; skipping");
        return None;
    }
    let github = stand_in(GITHUB).await;
    let nuclei = stand_in(NUCLEI).await;
    let extra = format!(
        "COPILOT_GITHUB_AUDIT_API_URL={}\nCOPILOT_NUCLEI_MODULE_URL={}\n",
        github.uri(),
        nuclei.uri()
    );
    let h = harness_env(None, &extra).await?;
    h.seed().await;
    let s = h.suffix.clone();
    Some(Fixture {
        admin: h.token(&format!("admin{s}"), "admin"),
        analyst: h.token(&format!("analyst{s}"), "analyst"),
        portal: h.token(&format!("portal{s}"), "customer_user"),
        acme: format!("acme{s}"),
        beta: format!("beta{s}"),
        h,
        github,
        nuclei,
    })
}

const G: &str = "/api/github-audit";

#[tokio::test]
async fn configurations_reports_exclusions_and_baselines() {
    let Some(f) = fixture().await else { return };
    f.seed_rows().await;

    // The catalog.
    let (st, body) = f
        .call("GET", &format!("{G}/checks"), &f.analyst, None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["checks"].as_array().unwrap().len(), 15);
    assert_eq!(
        body["checks"][0],
        json!({"id": "org-2fa-required", "name": "Two-Factor Authentication Required",
               "category": "organization", "severity": "critical",
               "description": "Checks if 2FA is required for all organization members"})
    );
    let (st, _) = f.call("GET", &format!("{G}/checks"), &f.portal, None).await;
    assert_eq!(st, 403);

    // Create: the body's customer must be the caller's (§4).
    let new = json!({"customer_code": f.acme, "github_token": "ghp_secret_abcd", "organization": "new-org"});
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config"),
            &f.analyst,
            Some(new.clone()),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let created = &body["config"];
    // §4: the token is masked as every other answer masks it (Python
    // echoed it in clear); the row keeps it.
    assert_eq!(created["github_token"], "***abcd");
    assert!(!body.to_string().contains("ghp_secret"));
    let stored: String = sqlx::query_scalar(&format!(
        "SELECT github_token FROM github_audit_config WHERE id = {}",
        created["id"]
    ))
    .fetch_one(f.h.db.pool())
    .await
    .unwrap();
    assert_eq!(stored, "ghp_secret_abcd");
    assert_eq!(created["minimum_passing_score"], json!(70.0));
    assert_eq!(created["repo_filter_mode"], "all");
    let keys: Vec<&String> = created.as_object().unwrap().keys().collect();
    assert_eq!(
        keys[..4],
        ["id", "customer_code", "github_token", "organization"]
    );
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config"),
            &f.analyst,
            Some(new.clone()),
        )
        .await;
    assert_eq!(st, 400);
    assert_eq!(
        body["message"],
        format!(
            "Configuration already exists for customer '{}' and organization 'new-org'",
            f.acme
        )
    );
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config"),
            &f.analyst,
            Some(json!({"customer_code": f.beta, "github_token": "t", "organization": "o"})),
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        format!("Access denied to customer {}", f.beta)
    );
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config"),
            &f.admin,
            Some(json!({"customer_code": f.acme, "minimum_passing_score": 101})),
        )
        .await;
    assert_eq!(st, 422, "{body}");

    // The list: an analyst sees their customers' only, tokens masked.
    let (st, body) = f
        .call("GET", &format!("{G}/config"), &f.analyst, None)
        .await;
    assert_eq!(st, 200);
    let configs = body["configs"].as_array().unwrap();
    assert!(
        configs
            .iter()
            .all(|c| c["customer_code"] == f.acme.as_str())
    );
    assert!(configs.iter().any(|c| c["id"] == CFG_A));
    assert!(
        configs
            .iter()
            .all(|c| c["github_token"].as_str().unwrap().starts_with("***"))
    );
    let (_, body) = f
        .call(
            "GET",
            &format!("{G}/config?customer_codes={}", f.beta),
            &f.admin,
            None,
        )
        .await;
    assert_eq!(body["configs"].as_array().unwrap().len(), 1);
    assert_eq!(body["configs"][0]["github_token"], "***3002");

    // One configuration: the owner is checked, an unknown id fails closed.
    let (st, body) = f
        .call("GET", &format!("{G}/config/{CFG_A}"), &f.analyst, None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["config"]["github_token"], "***3001");
    assert_eq!(body["config"]["created_at"], "2026-01-02T03:04:05");
    let (st, body) = f
        .call("GET", &format!("{G}/config/{CFG_B}"), &f.analyst, None)
        .await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        format!("Access denied to GitHub audit configuration {CFG_B}")
    );
    let (st, _) = f
        .call("GET", &format!("{G}/config/7843999"), &f.analyst, None)
        .await;
    assert_eq!(st, 403);
    let (st, body) = f
        .call("GET", &format!("{G}/config/7843999"), &f.admin, None)
        .await;
    assert_eq!(st, 404);
    assert_eq!(body["message"], "Configuration not found");
    let (st, _) = f
        .call("GET", &format!("{G}/config/abc"), &f.admin, None)
        .await;
    assert_eq!(st, 422);

    // Update and delete.
    let (st, body) = f
        .call(
            "PUT",
            &format!("{G}/config/{CFG_A}"),
            &f.analyst,
            Some(
                json!({"include_members": false, "repo_filter_list": ["web"], "updated_by": "bob"}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["config"]["include_members"], false);
    assert_eq!(body["config"]["repo_filter_list"], json!(["web"]));
    assert_eq!(body["config"]["updated_by"], "bob");
    let (st, _) = f
        .call(
            "PUT",
            &format!("{G}/config/{CFG_B}"),
            &f.analyst,
            Some(json!({"organization": "x"})),
        )
        .await;
    assert_eq!(st, 403);
    let org: String =
        sqlx::query_scalar("SELECT organization FROM github_audit_config WHERE id = ?")
            .bind(CFG_B)
            .fetch_one(f.h.db.pool())
            .await
            .unwrap();
    assert_eq!(org, "beta-org");
    let (st, _) = f
        .call("DELETE", &format!("{G}/config/{CFG_OFF}"), &f.analyst, None)
        .await;
    assert_eq!(st, 403);
    let (st, body) = f
        .call("DELETE", &format!("{G}/config/{CFG_OFF}"), &f.admin, None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"success": true, "message": "Configuration deleted successfully"})
    );
    // Python's cascade is a no-op: a configuration with reports is the
    // foreign key's bare 500.
    let (st, _) = f
        .call("DELETE", &format!("{G}/config/{CFG_A}"), &f.admin, None)
        .await;
    assert_eq!(st, 500);

    // Reports: the page and its total are the caller's customers'.
    let (st, body) = f
        .call(
            "GET",
            &format!("{G}/reports?organization={ORG}"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["total_count"], 1);
    assert_eq!(body["reports"][0]["id"], REP_A);
    assert!(body["reports"][0].get("full_report").is_none());
    let (st, body) = f
        .call(
            "GET",
            &format!("{G}/reports?customer_code={}", f.beta),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 403, "{body}");
    let (st, body) = f
        .call("GET", &format!("{G}/reports?limit=0"), &f.admin, None)
        .await;
    assert_eq!(st, 422);
    assert_eq!(body["details"][0]["field"], "limit");
    let (st, body) = f
        .call("GET", &format!("{G}/reports/{REP_A}"), &f.analyst, None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body["report"]["full_report"]["repository_results"][0]["repo_name"],
        "web"
    );
    let (st, _) = f
        .call("GET", &format!("{G}/reports/{REP_B}"), &f.analyst, None)
        .await;
    assert_eq!(st, 403);

    // Exclusions.
    let (st, body) = f
        .call(
            "GET",
            &format!("{G}/config/{CFG_A}/exclusions"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["message"], "Found 1 exclusion(s)");
    // An encoded `/` is routed on the decoded path, here (Starlette's
    // routing), with the same tenant check.
    let (st, body) = f
        .call(
            "GET",
            &format!("{G}/config/{CFG_A}%2Fexclusions"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["message"], "Found 1 exclusion(s)");
    let (st, _) = f
        .call(
            "GET",
            &format!("{G}/config/{CFG_B}%2fexclusions"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 403);
    let (st, _) = f
        .call("GET", &format!("{G}/reports%2F{REP_A}%2Fx"), &f.admin, None)
        .await;
    assert_eq!(st, 404);
    let (st, _) = f
        .call(
            "GET",
            &format!("{G}/config/{CFG_B}/exclusions"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 403);
    let (st, body) = f
        .call(
            "GET",
            &format!("{G}/config/7843999/exclusions"),
            &f.admin,
            None,
        )
        .await;
    assert_eq!((st.as_u16(), body["exclusions"].clone()), (200, json!([])));
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config/{CFG_A}/exclusions"),
            &f.analyst,
            Some(
                json!({"check_id": "repo-branch-protection", "resource_name": "web",
                        "reason": "mirror", "approved_by": "lead", "created_by": "alice"}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let exclusion = &body["exclusion"];
    assert_eq!(exclusion["customer_code"], f.acme.as_str());
    assert!(exclusion["approved_at"].is_string());
    let (st, body) = f
        .call(
            "PUT",
            &format!("{G}/exclusions/{EXC_A}"),
            &f.analyst,
            Some(json!({"enabled": false, "reason": "later"})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["exclusion"]["enabled"], false);
    assert_eq!(body["exclusion"]["reason"], "later");
    let (st, _) = f
        .call(
            "PUT",
            &format!("{G}/exclusions/{EXC_B}"),
            &f.analyst,
            Some(json!({})),
        )
        .await;
    assert_eq!(st, 403);
    let (st, _) = f
        .call("DELETE", &format!("{G}/exclusions/{EXC_B}"), &f.admin, None)
        .await;
    assert_eq!(st, 200);

    // Baselines: one from a report, the active one deactivated.
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config/{CFG_A}/baselines"),
            &f.analyst,
            Some(
                json!({"name": "from report", "baseline_report_id": REP_A, "created_by": "alice"}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["baseline"]["expected_checks"],
        json!({"org-2fa-required": "fail", "org-sso-enforcement": "pass", "repo-license:web": "warning"})
    );
    assert_eq!(body["baseline"]["baseline_report_id"], REP_A);
    let active: i64 =
        f.h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM github_audit_baseline WHERE config_id = {CFG_A} AND is_active = 1"
        ))
        .await;
    assert_eq!(active, 1);
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config/{CFG_A}/baselines"),
            &f.analyst,
            Some(json!({"name": "x", "baseline_report_id": REP_B, "created_by": "alice"})),
        )
        .await;
    assert_eq!(st, 403, "{body}");
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config/{CFG_A}/baselines"),
            &f.admin,
            Some(json!({"name": "x", "baseline_report_id": 7843999, "created_by": "alice"})),
        )
        .await;
    assert_eq!(st, 404);
    assert_eq!(body["message"], "Baseline report not found");
    let (st, body) = f
        .call(
            "GET",
            &format!("{G}/config/{CFG_A}/baselines?active_only=true"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["baselines"].as_array().unwrap().len(), 1);
    assert_eq!(body["baselines"][0]["name"], "from report");
    let (st, _) = f
        .call("DELETE", &format!("{G}/baselines/{BAS_A}"), &f.admin, None)
        .await;
    assert_eq!(st, 200);

    // A report a baseline names: the foreign key's bare 500.
    let (st, _) = f
        .call("DELETE", &format!("{G}/reports/{REP_A}"), &f.admin, None)
        .await;
    assert_eq!(st, 500);
    let (st, _) = f
        .call("DELETE", &format!("{G}/reports/{REP_B}"), &f.admin, None)
        .await;
    assert_eq!(st, 200);

    f.wipe().await;
}

/// GitHub's API: `path?query` → `(status, body)`; anything else is a 404.
struct GitHub(Vec<(String, u16, Option<Value>)>);

impl Respond for GitHub {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let target = match req.url.query() {
            Some(q) => format!("{}?{q}", req.url.path()),
            None => req.url.path().to_string(),
        };
        match self.0.iter().find(|(t, _, _)| *t == target) {
            Some((_, status, Some(body))) => ResponseTemplate::new(*status).set_body_json(body),
            Some((_, status, None)) => ResponseTemplate::new(*status),
            None => ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})),
        }
    }
}

fn org_answers() -> GitHub {
    let r = |t: &str, status: u16, body: Option<Value>| (t.to_string(), status, body);
    GitHub(vec![
        r(
            &format!("/orgs/{ORG}"),
            200,
            Some(
                json!({"login": ORG, "html_url": "https://github.com/e2e-org",
                        "two_factor_requirement_enabled": true,
                        "default_repository_permission": "read",
                        "members_can_create_repositories": false,
                        "members_can_create_public_repositories": false}),
            ),
        ),
        r(
            &format!("/orgs/{ORG}/domains"),
            200,
            Some(json!([{"domain": "e2e.example", "is_verified": true}])),
        ),
        r(
            &format!("/orgs/{ORG}/repos?per_page=100&page=1"),
            200,
            Some(json!([
                {"name": "web", "full_name": "e2e-org/web", "html_url": "https://github.com/e2e-org/web",
                 "private": false, "archived": false, "default_branch": "main",
                 "license": {"spdx_id": "MIT", "name": "MIT License"}},
                {"name": "old", "full_name": "e2e-org/old", "private": true, "archived": true},
            ])),
        ),
        r(
            "/repos/e2e-org/web",
            200,
            Some(json!({"security_and_analysis": {"secret_scanning": {"status": "enabled"}}})),
        ),
        r("/repos/e2e-org/web/vulnerability-alerts", 204, None),
        r(
            "/repos/e2e-org/web/code-scanning/alerts?per_page=1",
            200,
            Some(json!([])),
        ),
        r(
            "/repos/e2e-org/web/branches/main",
            200,
            Some(json!({"protected": false})),
        ),
        r(
            &format!("/orgs/{ORG}/actions/permissions"),
            200,
            Some(json!({"allowed_actions": "selected"})),
        ),
        r(
            &format!("/orgs/{ORG}/actions/permissions/workflow"),
            200,
            Some(json!({"default_workflow_permissions": "read"})),
        ),
        r(
            &format!("/orgs/{ORG}/members?per_page=100&page=1"),
            200,
            Some(json!([{"login": "alice"}, {"login": "bob"}])),
        ),
        r(
            &format!("/orgs/{ORG}/members?role=admin&per_page=100&page=1"),
            200,
            Some(json!([{"login": "alice"}])),
        ),
    ])
}

fn targets(reqs: &[Request]) -> Vec<String> {
    let mut out: Vec<String> = reqs
        .iter()
        .map(|r| match r.url.query() {
            Some(q) => format!("{} {}?{q}", r.method, r.url.path()),
            None => format!("{} {}", r.method, r.url.path()),
        })
        .collect();
    out.sort();
    out
}

fn findings(body: &Value) -> Vec<(String, Value)> {
    body["top_findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["check_id"].as_str().unwrap().to_string(),
                c["resource_name"].clone(),
            )
        })
        .collect()
}

#[tokio::test]
async fn audits() {
    let Some(f) = fixture().await else { return };
    f.seed_rows().await;
    Mock::given(method("GET"))
        .respond_with(org_answers())
        .mount(&f.github)
        .await;

    // From a configuration: the exclusion of the branch protection on `web`
    // keeps that failure out of the findings (the summary, below, keeps it).
    f.exclusion(7843203, CFG_A, &f.acme, "repo-branch-protection", "'web'")
        .await;
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config/{CFG_A}/audit"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["summary"]["organization"], ORG);
    let repos: Vec<&str> = body["repository_results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["repo_name"].as_str().unwrap())
        .collect();
    assert_eq!(repos, ["web", "old"]);
    assert!(
        !findings(&body)
            .iter()
            .any(|(id, _)| id == "repo-branch-protection")
    );
    let score = body["summary"]["score"].as_f64().unwrap();

    let reqs = f.github.received_requests().await.unwrap();
    assert_eq!(
        targets(&reqs),
        [
            "GET /orgs/e2e-org",
            "GET /orgs/e2e-org/actions/permissions",
            "GET /orgs/e2e-org/actions/permissions/workflow",
            "GET /orgs/e2e-org/domains",
            "GET /orgs/e2e-org/members?per_page=100&page=1",
            "GET /orgs/e2e-org/members?role=admin&per_page=100&page=1",
            "GET /orgs/e2e-org/repos?per_page=100&page=1",
            "GET /orgs/e2e-org/saml",
            "GET /repos/e2e-org/web",
            "GET /repos/e2e-org/web/branches/main",
            "GET /repos/e2e-org/web/branches/main/protection",
            "GET /repos/e2e-org/web/code-scanning/alerts?per_page=1",
            "GET /repos/e2e-org/web/vulnerability-alerts",
        ]
    );
    // httpx's order: the client's defaults, then the request's own headers
    // (`Headers.update` pops a default it replaces and appends).
    let names: Vec<(String, String)> = reqs[0]
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
        .collect();
    let addr = f.github.address().to_string();
    assert_eq!(
        names,
        [
            ("host", addr.as_str()),
            ("accept-encoding", "gzip, deflate"),
            ("connection", "keep-alive"),
            ("user-agent", "python-httpx/0.28.1"),
            ("authorization", "Bearer ghp_e2e_7843001"),
            ("accept", "application/vnd.github+json"),
            ("x-github-api-version", "2022-11-28"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
    );

    // The report row and the configuration's last audit.
    let (status, stored_score, top): (String, f64, String) = sqlx::query_as(
        "SELECT status, CAST(score AS DOUBLE), CAST(top_findings AS CHAR) FROM github_audit_report \
         WHERE config_id = ? AND id <> ? ORDER BY id DESC LIMIT 1",
    )
    .bind(CFG_A)
    .bind(REP_A)
    .fetch_one(f.h.db.pool())
    .await
    .unwrap();
    assert_eq!(status, "completed");
    assert!((stored_score - score).abs() < 1e-3);
    assert!(!top.contains("repo-branch-protection"));
    let last: f64 = sqlx::query_scalar(
        "SELECT CAST(last_audit_score AS DOUBLE) FROM github_audit_config WHERE id = ?",
    )
    .bind(CFG_A)
    .fetch_one(f.h.db.pool())
    .await
    .unwrap();
    assert!((last - score).abs() < 1e-3);

    // The summary: no report written, the exclusions not applied.
    let before =
        f.h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM github_audit_report WHERE config_id = {CFG_A}"
        ))
        .await;
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config/{CFG_A}/audit/summary"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert!(body.get("repository_results").is_none());
    assert!(findings(&body).len() <= 10);
    assert!(findings(&body).contains(&("repo-branch-protection".into(), json!("web"))));
    let after =
        f.h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM github_audit_report WHERE config_id = {CFG_A}"
        ))
        .await;
    assert_eq!(before, after);

    // Refusals: another tenant's configuration, a disabled one.
    let (st, _) = f
        .call(
            "POST",
            &format!("{G}/config/{CFG_B}/audit"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 403);
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config/{CFG_OFF}/audit"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 400);
    assert_eq!(body["message"], "This configuration is disabled");

    // Ad hoc: the token from the query.
    f.github.reset().await;
    Mock::given(method("GET"))
        .respond_with(org_answers())
        .mount(&f.github)
        .await;
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/audit?github_token=ghp_adhoc"),
            &f.analyst,
            Some(
                json!({"organization": ORG, "include_repos": false, "include_members": false,
                        "include_workflows": false}),
            ),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["repository_results"], json!([]));
    let reqs = f.github.received_requests().await.unwrap();
    assert_eq!(
        targets(&reqs),
        [
            "GET /orgs/e2e-org",
            "GET /orgs/e2e-org/domains",
            "GET /orgs/e2e-org/saml"
        ]
    );
    assert_eq!(
        reqs[0].headers.get("authorization").unwrap(),
        "Bearer ghp_adhoc"
    );
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/audit"),
            &f.analyst,
            Some(json!({"organization": ORG})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(body["details"][0]["field"], "github_token");

    // An answer a check chokes on (`enforce_admins: null`, then `.get`): the
    // audit fails, and so does its report.
    f.github.reset().await;
    let mut odd = org_answers();
    odd.0.insert(
        0,
        (
            "/repos/e2e-org/web/branches/main/protection".into(),
            200,
            Some(json!({"enforce_admins": null})),
        ),
    );
    Mock::given(method("GET"))
        .respond_with(odd)
        .mount(&f.github)
        .await;
    let (st, body) = f
        .call(
            "POST",
            &format!("{G}/config/{CFG_A}/audit"),
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["success"], false);
    assert_eq!(
        body["message"],
        "Audit failed: 'NoneType' object has no attribute 'get'"
    );
    let status: String = sqlx::query_scalar(
        "SELECT status FROM github_audit_report WHERE config_id = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(CFG_A)
    .fetch_one(f.h.db.pool())
    .await
    .unwrap();
    assert_eq!(status, "failed");

    f.wipe().await;
}

#[tokio::test]
async fn nuclei() {
    let Some(f) = fixture().await else { return };
    let n = &f.nuclei;
    Mock::given(method("GET"))
        .and(path("/copilot-nuclei-module/all_reports"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"reports": ["a.example"], "success": true, "message": "Reports found"}),
        ))
        .mount(n)
        .await;
    Mock::given(method("GET"))
        .and(path("/copilot-nuclei-module/report/a.example/index.md"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"markdown": "# a", "success": true, "message": "ok"})),
        )
        .mount(n)
        .await;
    Mock::given(method("POST"))
        .and(path("/copilot-nuclei-module/scan"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "Scan started", "success": true})),
        )
        .mount(n)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/copilot-nuclei-module/report/a.example"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "deleted", "success": true})),
        )
        .mount(n)
        .await;

    let (st, body) = f
        .call("GET", "/api/nuclei/all_reports", &f.analyst, None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"reports": ["a.example"], "success": true, "message": "Reports found"})
    );
    let (st, body) = f
        .call(
            "GET",
            "/api/nuclei/report/a.example/index.md",
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["markdown"], "# a");
    let (st, body) = f
        .call(
            "GET",
            "/api/nuclei/report/b.example/index.md",
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 404);
    assert_eq!(body["message"], "Nuclei report not found");
    let (st, body) = f
        .call(
            "POST",
            "/api/nuclei/scan",
            &f.analyst,
            Some(json!({"host": "a.example"})),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body, json!({"message": "Scan started", "success": true}));
    let (st, _) = f
        .call("POST", "/api/nuclei/scan", &f.analyst, Some(json!({})))
        .await;
    assert_eq!(st, 422);
    let (st, body) = f
        .call(
            "DELETE",
            "/api/nuclei/delete_report/a.example",
            &f.analyst,
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["message"], "deleted");
    let (st, _) = f
        .call("GET", "/api/nuclei/all_reports", &f.portal, None)
        .await;
    assert_eq!(st, 403);

    let reqs = n.received_requests().await.unwrap();
    let scan = reqs.iter().find(|r| r.method.as_str() == "POST").unwrap();
    assert_eq!(
        String::from_utf8_lossy(&scan.body),
        r#"{"host":"a.example"}"#
    );
    assert_eq!(
        scan.headers.get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(
        scan.headers.get("user-agent").unwrap(),
        "python-httpx/0.28.1"
    );

    // The module down: list and report are the bare 500 of the exception.
    n.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(n)
        .await;
    let (st, _) = f
        .call("GET", "/api/nuclei/all_reports", &f.analyst, None)
        .await;
    assert_eq!(st, 500);
}
