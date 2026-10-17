//! End-to-end tests of the external-tool modules of wave 6 on the production
//! router against a real MySQL, every upstream replaced by a mock:
//! Microsoft Patch Tuesday (`copilot-patch-tuesday`).
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
