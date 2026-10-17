//! End-to-end tests of the external-tool modules of wave 6 on the production
//! router against a real MySQL, every upstream replaced by a mock:
//! Microsoft Patch Tuesday (`copilot-patch-tuesday`), CoPilot MCP (`copilot-mcp`)
//! and the Sublime connector (`copilot-sublime`).
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13309/copilot \
//!   cargo test -p copilot --test e2e_ext_tools -- --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

// --- /api/patch-tuesday ---------------------------------------------------------------

const PT: &str = "/api/patch-tuesday";

/// The Patch Tuesday routes with the three feeds on `upstream` (the parity
/// harness's `COPILOT_*_URL` overrides, set here without touching the
/// process environment).
fn pt_router(h: &Harness, upstream: &str) -> axum::Router {
    let mut st = h.app.patch_tuesday.clone();
    st.urls = Arc::new(copilot_patch_tuesday::urls::Urls {
        msrc: format!("{upstream}/cvrf/v3.0/cvrf"),
        epss: format!("{upstream}/data/v1/epss"),
        kev: format!("{upstream}/kev.json"),
    });
    copilot_patch_tuesday::router(st)
}

fn cvrf_doc() -> Value {
    json!({
        "ProductTree": {"FullProductName": [
            {"ProductID": "1", "Value": "Windows 11 Version 24H2"},
            {"ProductID": "2", "Value": "Microsoft Exchange Server 2019"},
        ]},
        "Vulnerability": [
            {
                "Title": {"Value": "Windows Kernel EoP"},
                "CVE": "CVE-2026-1001",
                "Threats": [{"Type": 3, "Description": {"Value": "Important"}}],
                "CVSSScoreSets": [{"BaseScore": 7.8, "Vector": "CVSS:3.1/AV:L"}],
                "ProductStatuses": [{"ProductID": ["1"]}],
                "Remediations": [{"URL": "https://catalog.update.microsoft.com/?q=KB5034441"}],
            },
            {
                "Title": "Exchange Spoofing",
                "CVE": "CVE-2026-1002",
                "Severity": "critical",
                "ProductStatuses": [{"ProductID": ["2"]}],
            },
        ],
    })
}

async fn feeds() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cvrf/v3.0/cvrf/2026-Jan"))
        .respond_with(ResponseTemplate::new(200).set_body_json(cvrf_doc()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cvrf/v3.0/cvrf/2026-Feb"))
        .respond_with(ResponseTemplate::new(404).set_body_string("no such document"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cvrf/v3.0/cvrf/2026-Mar"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("  <cvrf/>", "text/xml"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/data/v1/epss"))
        .and(query_param("cve", "CVE-2026-1001,CVE-2026-1002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [
            {"cve": "CVE-2026-1001", "epss": "0.95", "percentile": "0.99", "date": "2026-01-14"},
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"vulnerabilities": [
                {"cveID": "CVE-2026-1002", "vendorProject": "Microsoft", "dueDate": "2026-02-03"},
            ]})),
        )
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn patch_tuesday_routes_are_for_analysts() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");
    for uri in [
        "",
        "/summary",
        "/cycles",
        "/search?cve_ids=x",
        "/priority/P0",
        "/kev",
    ] {
        let (status, _) = h.call("GET", &format!("{PT}{uri}"), None, None).await;
        assert_eq!(status, 401, "{uri}");
        let (status, _) = h
            .call("GET", &format!("{PT}{uri}"), Some(&portal), None)
            .await;
        assert_eq!(status, 403, "{uri}");
    }
}

#[tokio::test]
async fn patch_tuesday_reads_the_three_feeds() {
    let mut h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let server = feeds().await;
    h.router = pt_router(&h, &server.uri());

    let (status, body) = h
        .call("GET", &format!("{PT}?cycle=2026-Jan"), Some(&analyst), None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["success"], true);
    assert_eq!(
        body["message"],
        "Successfully retrieved 2 CVEs for cycle 2026-Jan"
    );
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    // Both P0: the very high EPSS sorts before the KEV entry without one.
    assert_eq!(items[0]["cve"], "CVE-2026-1001");
    assert_eq!(
        items[0]["epss"],
        json!({"score": 0.95, "percentile": 0.99, "date": "2026-01-14"})
    );
    assert_eq!(items[0]["remediation"]["kbs"], json!(["KB5034441"]));
    assert_eq!(items[0]["affected"]["family"], "Windows");
    assert_eq!(items[1]["cve"], "CVE-2026-1002");
    assert_eq!(items[1]["kev"]["in_kev"], true);
    assert_eq!(
        items[1]["prioritization"]["reason"],
        json!(["CISA KEV (known exploited)"])
    );
    assert_eq!(body["summary"]["patch_tuesday_date"], "2026-01-13");
    assert_eq!(
        body["summary"]["by_priority"],
        json!({"P0": 2, "P1": 0, "P2": 0, "P3": 0})
    );

    // What `fetch_json` sends: httpx's headers with the module's two.
    let received = server.received_requests().await.unwrap();
    let first = &received[0];
    assert_eq!(first.url.path(), "/cvrf/v3.0/cvrf/2026-Jan");
    let header = |name: &str| {
        first
            .headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };
    assert_eq!(header("accept").as_deref(), Some("application/json"));
    assert_eq!(
        header("user-agent").as_deref(),
        Some("CoPilot-PatchTuesday/1.0")
    );
    assert_eq!(header("accept-encoding").as_deref(), Some("gzip, deflate"));
    assert_eq!(
        received[1].url.query(),
        Some("cve=CVE-2026-1001%2CCVE-2026-1002")
    );

    let (_, body) = h
        .call(
            "GET",
            &format!("{PT}/summary?cycle=2026-Jan&top_n=1&include_epss=no"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["top_items"].as_array().unwrap().len(), 1);
    assert_eq!(body["top_items"][0]["epss"]["score"], Value::Null);

    let (_, body) = h
        .call(
            "GET",
            &format!("{PT}/search?cve_ids=cve-2026-1001&cycle=2026-Jan"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["message"], "Found 1 items matching 1 CVE(s)");
    let (_, body) = h
        .call(
            "GET",
            &format!("{PT}/priority/p1?cycle=2026-Jan"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["message"], "Found 0 P1 priority items");
    assert_eq!(
        body["summary"]["by_priority"],
        json!({"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("{PT}/kev?cycle=2026-Jan"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["message"], "Found 1 known exploited vulnerabilities");
}

#[tokio::test]
async fn patch_tuesday_failures_and_validation() {
    let mut h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let server = feeds().await;
    h.router = pt_router(&h, &server.uri());
    let base = server.uri();

    let (status, body) = h
        .call("GET", &format!("{PT}?cycle=2026-Feb"), Some(&analyst), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["message"],
        format!(
            "Failed to fetch Patch Tuesday data: GET {base}/cvrf/v3.0/cvrf/2026-Feb failed: \
             HTTP 404 - no such document"
        )
    );
    let (_, body) = h
        .call(
            "GET",
            &format!("{PT}/summary?cycle=2026-Mar"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        body["message"],
        "Failed to fetch Patch Tuesday summary: Endpoint returned non-JSON (Content-Type: \
         text/xml). The MSRC API may have returned XML instead of JSON."
    );
    assert_eq!(body["top_items"], json!([]));

    let before = server.received_requests().await.unwrap().len();
    let (_, body) = h
        .call("GET", &format!("{PT}/priority/p9"), Some(&analyst), None)
        .await;
    assert_eq!(
        body["message"],
        "Invalid priority level 'P9'. Valid values: P0, P1, P2, P3"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), before);

    let (status, body) = h
        .call(
            "GET",
            &format!("{PT}/summary?cycle=2026-jan&include_kev=maybe&top_n=0"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 422, "{body}");
    let fields: Vec<&str> = body["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, ["cycle", "include_kev", "top_n"]);
    let (status, body) = h
        .call("GET", &format!("{PT}/search"), Some(&analyst), None)
        .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["details"][0]["field"], "cve_ids");

    let (status, body) = h
        .call("GET", &format!("{PT}/cycles"), Some(&analyst), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["success"], true);
    // Twelve steps of 30 days back: eleven or twelve distinct months.
    let n = body["cycles"].as_array().unwrap().len();
    assert!((11..=12).contains(&n), "{body}");
}

// --- /api/copilot_mcp -----------------------------------------------------------------

const MCP: &str = "/api/copilot_mcp";

/// The MCP routes with the local servers and SOCFortress's cloud (its MCP
/// base and licence server) on `upstream`.
fn mcp_router(h: &Harness, upstream: &str) -> axum::Router {
    let mut st = h.app.mcp.clone();
    let mut urls = (*st.threat_intel.urls).clone();
    urls.mcp = format!("{upstream}/query");
    urls.license = format!("{upstream}/");
    st.threat_intel.urls = Arc::new(urls);
    st.local_base = format!("{upstream}/mcp");
    copilot_mcp::router(st)
}

type LicenceRow = (i64, String, String, String, String);

/// The test's own licence (the first row `get_license` reads) with a fresh
/// cached `SOCFORTRESS AI` feature; the saved rows go back in [`mcp_restore`].
async fn mcp_licence(h: &Harness, key: &str, enabled: bool) -> Vec<LicenceRow> {
    let saved = sqlx::query_as::<_, LicenceRow>(
        "SELECT id, license_key, customer_name, customer_email, company_name FROM license",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    h.exec("DELETE FROM license").await;
    h.exec(&format!(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) \
         VALUES ('{key}', 'e2e', 'e2e@example.com', 'e2e')"
    ))
    .await;
    h.exec(&format!(
        "INSERT INTO license_cache (license_key, feature_name, is_enabled, cached_at, \
         expires_at, license_data) VALUES ('{key}', 'SOCFORTRESS AI', {}, UTC_TIMESTAMP(), \
         UTC_TIMESTAMP() + INTERVAL 1 HOUR, '{{}}')",
        i32::from(enabled)
    ))
    .await;
    saved
}

async fn mcp_restore(h: &Harness, key: &str, saved: Vec<LicenceRow>) {
    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key = '{key}'"
    ))
    .await;
    h.exec(&format!("DELETE FROM license WHERE license_key = '{key}'"))
        .await;
    for (id, k, name, email, company) in saved {
        sqlx::query(
            "INSERT INTO license (id, license_key, customer_name, customer_email, company_name) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(k)
        .bind(name)
        .bind(email)
        .bind(company)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn mcp_routes_are_for_analysts() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");
    for (method, uri) in [
        ("GET", "/servers"),
        ("GET", "/servers/copilot"),
        ("GET", "/example-questions?mcp_server=copilot"),
        ("GET", "/categories?mcp_server=copilot"),
        ("POST", "/query"),
    ] {
        let body = (method == "POST").then(|| json!({"input": "x", "mcp_server": "copilot"}));
        let (status, _) = h
            .call(method, &format!("{MCP}{uri}"), None, body.clone())
            .await;
        assert_eq!(status, 401, "{uri}");
        let (status, _) = h
            .call(method, &format!("{MCP}{uri}"), Some(&portal), body)
            .await;
        assert_eq!(status, 403, "{uri}");
    }
}

#[tokio::test]
async fn mcp_servers_and_questions() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let (status, body) = h
        .call("GET", &format!("{MCP}/servers"), Some(&analyst), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["total_servers"], 8);
    assert_eq!(body["servers"][0]["value"], "copilot");
    let (_, body) = h
        .call(
            "GET",
            &format!("{MCP}/servers/velociraptor"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["server"]["name"], "Velociraptor");
    assert_eq!(
        body["available_categories"],
        json!(["artifacts", "hunting", "network", "persistence", "users"])
    );
    assert_eq!(body["total_example_questions"], 7);
    let (status, body) = h
        .call("GET", &format!("{MCP}/servers/nope"), Some(&analyst), None)
        .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["details"][0]["error_type"], "enum");
    let (_, body) = h
        .call(
            "GET",
            &format!("{MCP}/example-questions?mcp_server=copilot&category=alerts"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["total_questions"], 3);
    assert_eq!(body["mcp_server"], "copilot");
    let (status, _) = h
        .call(
            "GET",
            &format!("{MCP}/example-questions"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 422);
    let (_, body) = h
        .call(
            "GET",
            &format!("{MCP}/categories?mcp_server=cyber-news"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(body["categories"], json!(["cyber_news"]));
    assert_eq!(body["total_categories"], 1);
}

#[tokio::test]
async fn mcp_queries_go_local_or_to_the_cloud() {
    let mut h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let upstream = MockServer::start().await;
    h.router = mcp_router(&h, &upstream.uri());
    let answer =
        json!({"message": "done", "success": true, "result": {"rows": 3}, "execution_time": 2});
    Mock::given(method("POST"))
        .and(path("/mcp/mysql-query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(answer.clone()))
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/query/attack_surface"))
        .respond_with(ResponseTemplate::new(200).set_body_json(answer))
        .mount(&upstream)
        .await;

    let (status, body) = h
        .call(
            "POST",
            &format!("{MCP}/query"),
            Some(&analyst),
            Some(json!({"input": "How many alerts?", "mcp_server": "copilot", "verbose": "no"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"message": "done", "success": true, "result": {"rows": 3},
               "structured_result": null, "execution_time": 2.0})
    );
    let sent = &upstream.received_requests().await.unwrap()[0];
    assert_eq!(
        sent.body,
        br#"{"input":"How many alerts?","mcp_server":"copilot","verbose":false}"#
    );
    assert!(sent.headers.get("x-api-key").is_none());

    let (status, body) = h
        .call(
            "POST",
            &format!("{MCP}/query"),
            Some(&analyst),
            Some(json!({"input": 5, "mcp_server": "nope"})),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid MCP server type: 'nope'.")
    );

    let key = format!("e2e-mcp-{}", h.suffix);
    let saved = mcp_licence(&h, &key, true).await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{MCP}/query"),
            Some(&analyst),
            Some(json!({"input": "breaches?", "mcp_server": "attack-surface"})),
        )
        .await;
    let received = upstream.received_requests().await.unwrap();
    mcp_restore(&h, &key, saved).await;
    assert_eq!(status, 200, "{body}");
    let cloud = received.last().unwrap();
    assert_eq!(cloud.url.path(), "/query/attack_surface");
    assert_eq!(
        cloud.headers.get("x-api-key").unwrap().to_str().unwrap(),
        key
    );

    let saved = mcp_licence(&h, &key, false).await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{MCP}/query"),
            Some(&analyst),
            Some(json!({"input": "news?", "mcp_server": "cyber-news"})),
        )
        .await;
    mcp_restore(&h, &key, saved).await;
    assert_ne!(status, 200, "{body}");
}

// --- /api/sublime ----------------------------------------------------------------------

const SB: &str = "/api/sublime";

/// The `Sublime` connector row on `url` (none for `None`).
async fn sublime_connector(h: &Harness, url: Option<&str>) {
    h.exec("DELETE FROM connectors WHERE connector_name = 'Sublime'")
        .await;
    if let Some(url) = url {
        sqlx::query(
            "INSERT INTO connectors (connector_name, connector_type, connector_url, \
             connector_last_updated, connector_username, connector_password, connector_api_key, \
             connector_description, connector_supports, connector_configured, connector_verified, \
             connector_accepts_host_only, connector_accepts_api_key, \
             connector_accepts_username_password, connector_accepts_file, \
             connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
             ('Sublime', '3', ?, '2026-01-02 03:04:05', NULL, NULL, 'sb-key', 'desc', \
             'supports', 1, 0, 0, 1, 0, 0, 0, NULL, 1)",
        )
        .bind(url)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

/// The test's alerts and their child rows, gone.
async fn sublime_cleanup(h: &Harness) {
    let like = format!("e2e-sb-{}%", h.suffix);
    for child in [
        "flaggedrule",
        "mailbox",
        "recipient",
        "sender",
        "triggeredaction",
    ] {
        sqlx::query(&format!(
            "DELETE FROM {child} WHERE sublime_alert_id IN \
             (SELECT id FROM sublimealerts WHERE event_id LIKE ?)"
        ))
        .bind(&like)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
    sqlx::query("DELETE FROM sublimealerts WHERE event_id LIKE ?")
        .bind(&like)
        .execute(h.db.pool())
        .await
        .unwrap();
    sublime_connector(h, None).await;
}

fn sublime_body(h: &Harness, event: &str, message_id: &str) -> Value {
    json!({
        "api_version": "v0",
        "created_at": "2026-10-17T10:00:00Z",
        "data": {
            "flagged_rules": [
                {"id": "r1", "name": "Impersonation", "severity": "high", "tags": ["bec", "ü"]},
                {"id": "r2", "name": "Link", "tags": []},
            ],
            "message": {
                "canonical_id": "canon-1",
                "external_id": "ext-1",
                "id": message_id,
                "mailbox": {"id": "mbx-1"},
                "message_source_id": "src-1",
            },
            "triggered_actions": [{"id": "a1", "name": "Notify", "type": "webhook"}],
        },
        "id": format!("e2e-sb-{}-{event}", h.suffix),
        "type": "message.flagged",
    })
}

/// Sublime's message lookup, one answer per message id.
async fn sublime_server() -> MockServer {
    let server = MockServer::start().await;
    let message = |id: &str, body: Value| {
        Mock::given(method("GET"))
            .and(path(format!("/v0/messages/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
    };
    message(
        "msg-ok",
        json!({"sender": {"email": "boss@example.com"},
               "recipients": [{"email": "victim@example.com"}, {"email": "cc@example.com"}]}),
    )
    .mount(&server)
    .await;
    message(
        "msg-norcpt",
        json!({"sender": {"email": "a@b"}, "recipients": []}),
    )
    .mount(&server)
    .await;
    message(
        "msg-list",
        json!({"sender": {"email": []}, "recipients": [{"email": "x"}]}),
    )
    .mount(&server)
    .await;
    message(
        "msg-dict",
        json!({"sender": {"email": {"a": 1}}, "recipients": [{"email": "x"}]}),
    )
    .mount(&server)
    .await;
    message(
        "msg-num",
        json!({"sender": {"email": 5}, "recipients": [{"email": ["only"]}]}),
    )
    .mount(&server)
    .await;
    Mock::given(method("GET"))
        .and(path("/v0/messages/msg-html"))
        .respond_with(ResponseTemplate::new(502).set_body_raw("<h1>bad gateway</h1>", "text/html"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v0/rules"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn sublime_routes_are_for_analysts() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");
    for (m, uri) in [("POST", "/alert"), ("GET", "/alerts")] {
        let body = (m == "POST").then(|| json!({}));
        let (status, _) = h.call(m, &format!("{SB}{uri}"), None, body.clone()).await;
        assert_eq!(status, 401, "{uri}");
        let (status, _) = h.call(m, &format!("{SB}{uri}"), Some(&portal), body).await;
        assert_eq!(status, 403, "{uri}");
    }
    // FastAPI reads the body first: malformed JSON is a 422 without a token.
    let (status, _) = h
        .call_raw(
            "POST",
            &format!("{SB}/alert"),
            None,
            Some("application/json"),
            "{",
        )
        .await;
    assert_eq!(status, 422);
}

#[tokio::test]
async fn sublime_stores_and_lists_alerts() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let server = sublime_server().await;
    sublime_connector(&h, Some(&server.uri())).await;

    let before = h.scalar_i64("SELECT UNIX_TIMESTAMP(NOW())").await;
    let (status, body) = h
        .call(
            "POST",
            &format!("{SB}/alert"),
            Some(&analyst),
            Some(sublime_body(&h, "ok", "msg-ok")),
        )
        .await;
    let event = format!("e2e-sb-{}-ok", h.suffix);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": format!("Alert {event} stored in the database")})
    );
    let sent = server.received_requests().await.unwrap();
    assert_eq!(sent.len(), 2);
    for req in &sent {
        assert_eq!(req.url.path(), "/v0/messages/msg-ok");
        assert_eq!(req.headers["authorization"], "Bearer sb-key");
        assert_eq!(req.headers["content-type"], "application/json");
    }
    let stamped = h
        .scalar_i64(&format!(
            "SELECT UNIX_TIMESTAMP(timestamp) FROM sublimealerts WHERE event_id = '{event}'"
        ))
        .await;
    assert!((before - 1..=before + 60).contains(&stamped), "{stamped}");
    let tags: String = sqlx::query_scalar(
        "SELECT f.tags FROM flaggedrule f JOIN sublimealerts a ON a.id = f.sublime_alert_id \
         WHERE a.event_id = ? AND f.rule_id = 'r1'",
    )
    .bind(&event)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(tags, r#"["bec", "\u00fc"]"#);

    let (status, body) = h
        .call("GET", &format!("{SB}/alerts"), Some(&analyst), None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "Successfully retrieved all Sublime Alerts");
    let alert = body["sublime_alerts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["event_id"] == event.as_str())
        .unwrap()
        .clone();
    let mut alert = alert;
    alert["timestamp"] = json!("<ts>");
    assert_eq!(
        alert,
        json!({
            "api_version": "v0", "created_at": "2026-10-17T10:00:00Z", "event_id": event,
            "type": "message.flagged", "message_id": "msg-ok", "canonical_id": "canon-1",
            "external_id": "ext-1", "message_source_id": "src-1", "timestamp": "<ts>",
            "flagged_rules": [
                {"rule_id": "r1", "name": "Impersonation", "severity": "high", "tags": r#"["bec", "\u00fc"]"#},
                {"rule_id": "r2", "name": "Link", "severity": null, "tags": "[]"},
            ],
            "mailbox": [{"external_id": null, "mailbox_id": "mbx-1"}],
            "triggered_actions": [{"action_id": "a1", "name": "Notify", "type": "webhook"}],
            "sender": [{"email": "boss@example.com", "name": "n/a"}],
            "recipients": [{"email": "victim@example.com", "name": "n/a"}],
        })
    );

    // A stored sender without a name fails the listing's schema.
    let id = h
        .scalar_i64(&format!(
            "SELECT id FROM sublimealerts WHERE event_id = '{event}'"
        ))
        .await;
    h.exec(&format!(
        "UPDATE sender SET name = NULL WHERE sublime_alert_id = {id}"
    ))
    .await;
    let (status, body) = h
        .call("GET", &format!("{SB}/alerts"), Some(&analyst), None)
        .await;
    sublime_cleanup(&h).await;
    assert_eq!(status, 500, "{body}");
    assert!(
        body["message"].as_str().unwrap().starts_with(
            "Failed to get all Sublime Alerts with error: 1 validation error for \
             SublimeAlertsSchema\nsender.0.name\n  Input should be a valid string"
        ),
        "{body}"
    );
}

#[tokio::test]
async fn sublime_failures_are_pythons() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let server = sublime_server().await;
    sublime_connector(&h, Some(&server.uri())).await;
    let post = |body: Value| {
        let h = &h;
        let analyst = analyst.clone();
        async move {
            h.call("POST", &format!("{SB}/alert"), Some(&analyst), Some(body))
                .await
        }
    };
    let failed = |event: &str| {
        format!(
            "Failed to store alert e2e-sb-{}-{event} in the database: ",
            h.suffix
        )
    };
    let count = || async {
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM sublimealerts WHERE event_id LIKE 'e2e-sb-{}%'",
            h.suffix
        ))
        .await
    };

    // No external id: the alert's own INSERT fails, nothing is asked of Sublime.
    let mut body = sublime_body(&h, "noext", "msg-ok");
    body["data"]["message"]
        .as_object_mut()
        .unwrap()
        .remove("external_id");
    let (status, out) = post(body).await;
    assert_eq!(status, 500, "{out}");
    let text = out["message"].as_str().unwrap();
    assert!(
        text.starts_with(&format!(
            "{}(pymysql.err.IntegrityError) (1048, \"Column 'external_id' cannot be null\")\n\
             [SQL: INSERT INTO sublimealerts (api_version, created_at, event_id, type, \
             message_id, canonical_id, external_id, message_source_id, timestamp) VALUES (%s, \
             %s, %s, %s, %s, %s, %s, %s, %s)]\n[parameters: ('v0', '2026-10-17T10:00:00Z', \
             'e2e-sb-{}-noext', 'message.flagged', 'msg-ok', 'canon-1', None, 'src-1', \
             datetime.datetime(",
            failed("noext"),
            h.suffix
        )),
        "{text}"
    );
    assert!(text.ends_with("(Background on this error at: https://sqlalche.me/e/20/gkpj)"));
    assert!(server.received_requests().await.unwrap().is_empty());

    let cases = [
        (
            "html",
            "msg-html",
            "500: Failed to get Sublime Alert with message_id msg-html: Failed to send GET \
             request to /v0/messages/msg-html with error: Expecting value: line 1 column 1 \
             (char 0)"
                .to_string(),
        ),
        (
            "norcpt",
            "msg-norcpt",
            "list index out of range".to_string(),
        ),
        (
            "dict",
            "msg-dict",
            "dict can not be used as parameter".to_string(),
        ),
    ];
    for (event, message_id, want) in cases {
        let (status, out) = post(sublime_body(&h, event, message_id)).await;
        assert_eq!(status, 500, "{out}");
        assert_eq!(out["message"], format!("{}{want}", failed(event)));
    }
    // An empty list is written as `()`: MySQL's syntax error quotes the rest.
    let (status, out) = post(sublime_body(&h, "list", "msg-list")).await;
    assert_eq!(status, 500, "{out}");
    let text = out["message"].as_str().unwrap();
    assert!(
        text.starts_with(&format!(
            "{}(pymysql.err.ProgrammingError) (1064, \"You have an error in your SQL syntax; \
             check the manual that corresponds to your MySQL server version for the right \
             syntax to use near '), 'n/a', ",
            failed("list")
        )),
        "{text}"
    );
    assert!(text.contains("[SQL: INSERT INTO sender (email, name, sublime_alert_id) VALUES (%s, %s, %s)]\n[parameters: ([], 'n/a', "));
    // Every failure rolled the alert back.
    assert_eq!(count().await, 0);

    // A number is stored as its digits, a one-item list as its item.
    let (status, out) = post(sublime_body(&h, "num", "msg-num")).await;
    assert_eq!(status, 200, "{out}");
    let (sender, recipient): (String, String) = sqlx::query_as(
        "SELECT s.email, r.email FROM sublimealerts a JOIN sender s ON s.sublime_alert_id = a.id \
         JOIN recipient r ON r.sublime_alert_id = a.id WHERE a.event_id = ?",
    )
    .bind(format!("e2e-sb-{}-num", h.suffix))
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!((sender.as_str(), recipient.as_str()), ("5", "only"));

    // No connector row.
    sublime_connector(&h, None).await;
    let (status, out) = post(sublime_body(&h, "none", "msg-ok")).await;
    assert_eq!(status, 500, "{out}");
    assert_eq!(
        out["message"],
        format!("{}'NoneType' object is not subscriptable", failed("none"))
    );

    // The connector check.
    sublime_connector(&h, Some(&server.uri())).await;
    let id = h
        .scalar_i64("SELECT id FROM connectors WHERE connector_name = 'Sublime'")
        .await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let (status, out) = h
        .call(
            "POST",
            &format!("/api/connectors/verify/{id}"),
            Some(&admin),
            None,
        )
        .await;
    let verified = h
        .scalar_i64("SELECT connector_verified FROM connectors WHERE connector_name = 'Sublime'")
        .await;
    sublime_cleanup(&h).await;
    assert_eq!(status, 200, "{out}");
    assert_eq!(verified, 1);
    let rules = server.received_requests().await.unwrap();
    let check = rules.last().unwrap();
    assert_eq!(check.url.path(), "/v0/rules");
    assert_eq!(check.url.query(), Some("limit=1"));
}

// --- /api/scoutsuite -------------------------------------------------------------------

const SC: &str = "/api/scoutsuite";

/// A `scout` stand-in: records its working directory and arguments (and,
/// for GCP, the credential and its directory's mode) in `log`, then writes
/// the three report files under `scoutsuite-report/` as ScoutSuite does.
fn scout_stub(dir: &std::path::Path, log: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("scout");
    let script = format!(
        r#"#!/bin/sh
out="{log}/$$"
printf '%s\n' "$PWD" > "$out.tmp"
prev=""
name=""
for a in "$@"; do
  printf '%s\n' "$a" >> "$out.tmp"
  if [ "$prev" = "--service-account" ]; then
    cat "$a" > "$out.cred"
    stat -c %a "$(dirname "$a")" > "$out.mode"
  fi
  if [ "$prev" = "--report-name" ]; then name="$a"; fi
  prev="$a"
done
mkdir -p scoutsuite-report/scoutsuite-results
echo report > "scoutsuite-report/$name.html"
echo results > "scoutsuite-report/scoutsuite-results/scoutsuite_results_$name.js"
echo exceptions > "scoutsuite-report/scoutsuite-results/scoutsuite_exceptions_$name.js"
mv "$out.tmp" "$out.done"
"#,
        log = log.display()
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn scout_router(h: &Harness, work: &std::path::Path, program: &std::path::Path) -> axum::Router {
    let mut st = h.app.scoutsuite.clone();
    st.dir = Arc::new(work.to_path_buf());
    st.program = Arc::from(program.to_str().unwrap());
    copilot_scoutsuite::router(st)
}

/// The stand-in's runs, waited for: (working directory, arguments, the
/// credential's contents and directory mode, if any).
async fn scout_runs(
    log: &std::path::Path,
    n: usize,
) -> Vec<(String, Vec<String>, Option<(String, String)>)> {
    for _ in 0..100 {
        let done: Vec<_> = std::fs::read_dir(log)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".done"))
            .collect();
        if done.len() >= n {
            let mut out = Vec::new();
            for e in done {
                let text = std::fs::read_to_string(e.path()).unwrap();
                let mut lines = text.lines().map(str::to_string);
                let cwd = lines.next().unwrap();
                let stem = e.path().with_extension("");
                let cred = std::fs::read_to_string(stem.with_extension("cred"))
                    .ok()
                    .map(|c| {
                        let mode = std::fs::read_to_string(stem.with_extension("mode")).unwrap();
                        (c, mode.trim().to_string())
                    });
                out.push((cwd, lines.collect(), cred));
                std::fs::remove_file(e.path()).unwrap();
            }
            return out;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("scout did not run");
}

#[tokio::test]
async fn scoutsuite_routes_are_for_analysts() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");
    for (m, uri) in [
        ("GET", "/report-generation-options"),
        ("GET", "/available-reports"),
        ("POST", "/generate-aws-report"),
        ("POST", "/generate-azure-report"),
        ("DELETE", "/delete-report/x.html"),
    ] {
        let body = (m == "POST").then(|| json!({}));
        let (status, _) = h.call(m, &format!("{SC}{uri}"), None, body.clone()).await;
        assert_eq!(status, 401, "{uri}");
        let (status, _) = h.call(m, &format!("{SC}{uri}"), Some(&portal), body).await;
        assert_eq!(status, 403, "{uri}");
    }
    let (status, _) = h
        .call_raw(
            "POST",
            &format!("{SC}/generate-gcp-report"),
            Some(&portal),
            Some("multipart/form-data; boundary=b"),
            "--b--\r\n",
        )
        .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn scoutsuite_scans_and_reports() {
    let mut h = harness_or_skip!(None);
    h.seed().await;
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let work = tempfile::tempdir().unwrap();
    let log = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let stub = scout_stub(bin.path(), log.path());
    h.router = scout_router(&h, work.path(), &stub);

    let (status, body) = h
        .call(
            "GET",
            &format!("{SC}/report-generation-options"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["options"], json!(["aws", "azure", "gcp"]));
    // No `scoutsuite-report` yet.
    let (status, body) = h
        .call(
            "GET",
            &format!("{SC}/available-reports"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["message"], "Directory does not exist");

    let (status, body) = h
        .call(
            "POST",
            &format!("{SC}/generate-aws-report"),
            Some(&analyst),
            Some(json!({"report_type": "aws", "access_key_id": "AKIA", "secret_access_key": "s 3", "report_name": "aws-one"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["message"],
        "AWS ScoutSuite report generation started successfully. This will take a few minutes \
         to complete. Check back in shortly."
    );
    let runs = scout_runs(log.path(), 1).await;
    let cwd = std::fs::canonicalize(work.path()).unwrap();
    assert_eq!(runs[0].0, cwd.to_str().unwrap());
    assert_eq!(
        runs[0].1,
        [
            "aws",
            "--access-key-id",
            "AKIA",
            "--secret-access-key",
            "s 3",
            "--report-name",
            "aws-one",
            "--force",
            "--no-browser"
        ]
    );

    let (status, body) = h
        .call(
            "POST",
            &format!("{SC}/generate-azure-report"),
            Some(&analyst),
            Some(json!({"report_type": "aws", "username": "u", "password": "p", "tenant_id": "t", "report_name": "r"})),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["message"], "Invalid report type.");
    let (status, _) = h
        .call(
            "POST",
            &format!("{SC}/generate-azure-report"),
            Some(&analyst),
            Some(json!({"report_type": "azure", "username": "u"})),
        )
        .await;
    assert_eq!(status, 422);

    // GCP: the key in a private directory, removed after the scan.
    let key = json!({
        "type": "service_account", "project_id": "p", "private_key_id": "k", "private_key": "pk",
        "client_email": "e", "client_id": "1", "auth_uri": "a", "token_uri": "t",
        "auth_provider_x509_cert_url": "c", "client_x509_cert_url": "x", "universe_domain": "g",
    })
    .to_string();
    let multipart = |content: &str| {
        format!(
            "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"key.json\"\r\n\
             Content-Type: application/json\r\n\r\n{content}\r\n--b--\r\n"
        )
    };
    let (status, body) = h
        .call_raw(
            "POST",
            &format!("{SC}/generate-gcp-report?report_name=gcp-one"),
            Some(&analyst),
            Some("multipart/form-data; boundary=b"),
            multipart(&key),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let runs = scout_runs(log.path(), 1).await;
    let args = &runs[0].1;
    assert_eq!(args[..2], ["gcp", "--service-account"]);
    assert_eq!(
        args[3..],
        [
            "--all-projects",
            "--report-name",
            "gcp-one",
            "--force",
            "--no-browser"
        ]
    );
    let cred = std::path::Path::new(&args[2]);
    assert!(cred.ends_with("gcp-service-account.json"), "{args:?}");
    assert!(
        cred.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("scoutsuite-gcp-cred-")
    );
    assert_eq!(runs[0].2, Some((key.clone(), "700".to_string())));
    for _ in 0..50 {
        if !cred.parent().unwrap().exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(!cred.parent().unwrap().exists());

    for (content, want) in [
        (
            "{bad",
            "Invalid JSON file - Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
        ),
        (
            "[1]",
            "JSON file does not have the correct format and fields - app.integrations.scoutsuite.schema.scoutsuite.GCPScoutSuiteJSON() argument after ** must be a mapping, not list",
        ),
    ] {
        let (status, body) = h
            .call_raw(
                "POST",
                &format!("{SC}/generate-gcp-report"),
                Some(&analyst),
                Some("multipart/form-data; boundary=b"),
                multipart(content),
            )
            .await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["message"], want);
    }
    let (status, _) = h
        .call_raw(
            "POST",
            &format!("{SC}/generate-gcp-report"),
            Some(&analyst),
            Some("multipart/form-data; boundary=b"),
            "--b--\r\n",
        )
        .await;
    assert_eq!(status, 422);

    // The reports the scans wrote, then a delete.
    let (status, body) = h
        .call(
            "GET",
            &format!("{SC}/available-reports"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let mut reports: Vec<String> =
        serde_json::from_value(body["available_reports"].clone()).unwrap();
    reports.sort();
    assert_eq!(reports, ["aws-one.html", "gcp-one.html"]);
    let (status, body) = h
        .call(
            "DELETE",
            &format!("{SC}/delete-report/aws-one.html"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["message"],
        "Report aws-one.html and associated files deleted successfully"
    );
    let reports_dir = work.path().join("scoutsuite-report");
    assert!(!reports_dir.join("aws-one.html").exists());
    assert!(
        !reports_dir
            .join("scoutsuite-results/scoutsuite_results_aws-one.js")
            .exists()
    );
    assert!(
        reports_dir
            .join("scoutsuite-results/scoutsuite_results_gcp-one.js")
            .exists()
    );
    // A directory of that name is `os.remove`'s error: a bare 500.
    std::fs::create_dir(reports_dir.join("dir.html")).unwrap();
    let (status, _) = h
        .call(
            "DELETE",
            &format!("{SC}/delete-report/dir.html"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(status, 500);
}
