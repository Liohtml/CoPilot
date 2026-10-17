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
