//! End-to-end tests of the OpenCTI and Cortex connectors
//! (`copilot-intel-connectors`) against a real MySQL, OpenCTI and Cortex
//! replaced by mocks.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13310/copilot \
//!   cargo test -p copilot --test e2e_intel_connectors -- --test-threads=1
//! ```
//!
//! Each test creates the connector rows it needs, points them at its mock
//! and deletes them again (the harness runs with the connector cache off).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[macro_use]
mod common;
use common::*;

async fn connector(h: &Harness, name: &str, url: &str, key: Option<&str>, extra: Option<&str>) {
    sqlx::query("DELETE FROM connectors WHERE connector_name = ?")
        .bind(name)
        .execute(h.db.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_username, connector_password, connector_api_key, connector_description, \
         connector_supports, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         (?, '1', ?, '2026-01-02 03:04:05', NULL, NULL, ?, 'desc', 'supports', 1, 1, 0, 1, 0, 0, 1, ?, 1)",
    )
    .bind(name)
    .bind(url)
    .bind(key)
    .bind(extra)
    .execute(h.db.pool())
    .await
    .unwrap();
}

async fn cleanup(h: &Harness) {
    h.exec("DELETE FROM connectors WHERE connector_name IN ('OpenCTI', 'Cortex')")
        .await;
}

async fn tokens(h: &Harness) -> (String, String) {
    h.seed().await;
    (
        h.token(&format!("admin{}", h.suffix), "admin"),
        h.token(&format!("analyst{}", h.suffix), "analyst"),
    )
}

/// OpenCTI's GraphQL endpoint, answering by operation name.
struct OpenCti;

fn indicator(n: u32) -> Value {
    json!({
        "id": format!("ind-{n}"), "standard_id": format!("indicator--{n}"), "entity_type": "Indicator",
        "objectLabel": [{"value": "malware", "color": "#f00"}, {"value": ""}],
        "objectMarking": [{"definition": "TLP:CLEAR"}, {}],
        "x_opencti_score": 80, "revoked": false,
    })
}

impl Respond for OpenCti {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let query = body["query"].as_str().unwrap();
        let vars = &body["variables"];
        if req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some("Bearer octi-key")
        {
            return ResponseTemplate::new(200).set_body_json(json!({
                "errors": [{"message": "You must be logged in", "extensions": {"code": "AUTH_REQUIRED"}}],
                "data": {"about": null},
            }));
        }
        let data = if query.contains("CoPilotAbout") || query.contains("CoPilotVerify") {
            json!({"about": {"version": "6.4", "dependencies": [{"name": "ES"}]}, "me": {"name": "copilot"}})
        } else if query.contains("CoPilotObservableLookup") {
            let found: Vec<Value> = vars["filters"]["filters"][0]["values"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v.as_str().unwrap().eq_ignore_ascii_case("bad.example"))
                .map(|_| {
                    json!({"node": {
                        "id": "obs-1", "entity_type": "Domain-Name", "observable_value": "bad.example",
                        "indicators": {"pageInfo": {"globalCount": 1}, "edges": [{"node": indicator(1)}]},
                        "hashes": [{"algorithm": "SHA-256", "hash": "AB12"}],
                    }})
                })
                .collect();
            json!({"stixCyberObservables": {"pageInfo": {"globalCount": found.len()}, "edges": found}})
        } else if query.contains("CoPilotIndicators") {
            let start: u32 = vars["after"]
                .as_str()
                .map_or(0, |c| c[1..].parse().unwrap());
            let edges: Vec<Value> = (start + 1..=(start + 2).min(3))
                .map(|n| json!({"node": indicator(n)}))
                .collect();
            let end = start + u32::try_from(edges.len()).unwrap();
            json!({"indicators": {
                "pageInfo": {"globalCount": 3, "hasNextPage": end < 3, "endCursor": format!("c{end}")},
                "edges": edges,
            }})
        } else {
            json!({"stixCoreObject": null})
        };
        ResponseTemplate::new(200).set_body_json(json!({"data": data}))
    }
}

async fn opencti() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(OpenCti)
        .mount(&server)
        .await;
    server
}

fn header(req: &Request, name: &str) -> String {
    req.headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn opencti_routes() {
    let h = harness_or_skip!(None);
    let (_admin, analyst) = tokens(&h).await;
    let server = opencti().await;

    cleanup(&h).await;
    let (st, body) = h
        .call("GET", "/api/opencti/availability", Some(&analyst), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"success": true, "message": "OpenCTI connector is not installed",
               "configured": false, "verified": false, "platform_url": null})
    );
    let (st, body) = h
        .call("GET", "/api/opencti/about", Some(&analyst), None)
        .await;
    assert_eq!(st, 500);
    assert_eq!(
        body["message"],
        "No OpenCTI connector found in the database"
    );

    connector(
        &h,
        "OpenCTI",
        &format!("{}/graphql/", server.uri()),
        Some("octi-key"),
        Some("https://cti.example/"),
    )
    .await;
    let (_, body) = h
        .call("GET", "/api/opencti/availability", Some(&analyst), None)
        .await;
    assert_eq!(body["platform_url"], "https://cti.example");

    let (st, body) = h
        .call("GET", "/api/opencti/about", Some(&analyst), None)
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["about"],
        json!({"version": "6.4", "dependencies": [{"name": "ES", "version": null}],
               "user_name": "copilot", "user_email": null})
    );
    let reqs = server.received_requests().await.unwrap();
    let about = reqs.last().unwrap();
    assert_eq!(about.url.path(), "/graphql");
    assert_eq!(header(about, "content-type"), "application/json");
    assert_eq!(header(about, "accept"), "application/json");
    assert_eq!(header(about, "user-agent"), "python-httpx/0.28.1");
    assert_eq!(
        String::from_utf8_lossy(&about.body),
        r#"{"query":"\nquery CoPilotAbout {\n    about {\n        version\n        dependencies { name version }\n    }\n    me { name user_email }\n}\n","variables":{}}"#
    );

    let (st, body) = h
        .call(
            "GET",
            "/api/opencti/observables/search?value=%20BAD.example%20",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["value"], "BAD.example");
    assert_eq!(body["total"], 1);
    let obs = &body["observables"][0];
    assert_eq!(obs["indicators_count"], 1);
    assert_eq!(obs["labels"], json!([]));
    assert_eq!(
        obs["indicators"][0]["labels"],
        json!([{"value": "malware", "color": "#f00"}])
    );
    assert_eq!(obs["indicators"][0]["markings"], json!(["TLP:CLEAR"]));
    let sent: Value = serde_json::from_slice(
        &server
            .received_requests()
            .await
            .unwrap()
            .last()
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(
        sent["variables"],
        json!({"filters": {"mode": "and", "filters": [{
                   "key": ["value", "hashes.MD5", "hashes.SHA-1", "hashes.SHA-256", "hashes.SHA-512"],
                   "values": ["BAD.example"], "operator": "eq", "mode": "or"}], "filterGroups": []},
               "first": 10, "indicators": 10, "reports": 5})
    );

    let (st, body) = h
        .call(
            "POST",
            "/api/opencti/observables/lookup",
            Some(&analyst),
            Some(json!({"values": ["bad.example", "ab12", "BAD.EXAMPLE", "nothing"]})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["message"], "2 of 3 values found in OpenCTI");
    assert_eq!(body["results"][1]["found"], true);
    assert_eq!(body["results"][2]["found"], false);
    assert_eq!(body["truncated"], false);
    let sent: Value = serde_json::from_slice(
        &server
            .received_requests()
            .await
            .unwrap()
            .last()
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(sent["variables"]["first"], 50);

    let (st, body) = h
        .call(
            "POST",
            "/api/opencti/observables/lookup",
            Some(&analyst),
            Some(json!({"values": ["  "]})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["message"],
        "values: At least one non-blank value is required"
    );

    let (st, page1) = h
        .call(
            "GET",
            "/api/opencti/indicators?first=2&min_score=50",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200, "{page1}");
    assert_eq!(
        page1["page_info"],
        json!({"global_count": 3, "has_next_page": true, "end_cursor": "c2"})
    );
    let sent: Value = serde_json::from_slice(
        &server
            .received_requests()
            .await
            .unwrap()
            .last()
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(
        sent["variables"],
        json!({"search": null, "filters": {"mode": "and", "filters": [{"key": ["x_opencti_score"],
               "values": ["50"], "operator": "gte", "mode": "or"}], "filterGroups": []},
               "first": 2, "after": null})
    );
    let (_, page2) = h
        .call(
            "GET",
            "/api/opencti/indicators?first=2&after=c2",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(page2["indicators"].as_array().unwrap().len(), 1);
    assert_eq!(page2["page_info"]["has_next_page"], false);

    let (st, body) = h
        .call(
            "GET",
            "/api/opencti/entities/report--1",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 404);
    assert_eq!(body["message"], "No OpenCTI entity found with id report--1");
    let (st, _) = h
        .call(
            "GET",
            "/api/opencti/indicators?first=0",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 422);

    // A revoked token: HTTP 200 with `errors` is a failure.
    connector(&h, "OpenCTI", &server.uri(), Some("revoked"), None).await;
    let (st, body) = h
        .call("GET", "/api/opencti/about", Some(&analyst), None)
        .await;
    assert_eq!(st, 500);
    assert_eq!(
        body["message"],
        "OpenCTI GraphQL error: You must be logged in (AUTH_REQUIRED)"
    );
    cleanup(&h).await;
}

#[tokio::test]
async fn opencti_verification() {
    let h = harness_or_skip!(None);
    let (admin, _) = tokens(&h).await;
    let server = opencti().await;
    connector(&h, "OpenCTI", &server.uri(), Some("octi-key"), None).await;
    let id = h
        .scalar_i64("SELECT id FROM connectors WHERE connector_name = 'OpenCTI'")
        .await;
    h.exec("UPDATE connectors SET connector_verified = 0 WHERE connector_name = 'OpenCTI'")
        .await;
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/connectors/verify/{id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"connectionSuccessful": true,
               "message": "OpenCTI connection successful (version 6.4, authenticated as copilot)"})
    );
    assert_eq!(
        h.scalar_i64("SELECT connector_verified FROM connectors WHERE connector_name = 'OpenCTI'")
            .await,
        1
    );
    let verify = server.received_requests().await.unwrap();
    assert!(String::from_utf8_lossy(&verify.last().unwrap().body).contains("CoPilotVerify"));

    h.exec("UPDATE connectors SET connector_api_key = 'revoked' WHERE connector_name = 'OpenCTI'")
        .await;
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/connectors/verify/{id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 500);
    assert_eq!(
        body["message"],
        format!(
            "Failed to verify connector: Connection to {}/graphql failed: OpenCTI GraphQL error: \
             You must be logged in (AUTH_REQUIRED)",
            server.uri()
        )
    );
    assert_eq!(
        h.scalar_i64("SELECT connector_verified FROM connectors WHERE connector_name = 'OpenCTI'")
            .await,
        0
    );
    cleanup(&h).await;
}

/// Cortex: the analyzers and one job that succeeds at once.
async fn cortex(job: Value) -> MockServer {
    let server = MockServer::start().await;
    let analyzers = json!([{"id": "an 1", "name": "VirusTotal_GetReport_3_1"}, {"id": "an-2", "name": "Abuse_Finder_3_0"}]);
    Mock::given(method("POST"))
        .and(path("/api/analyzer/_search"))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            if req.url.query() == Some("range=all") {
                ResponseTemplate::new(200).set_body_json(analyzers.clone())
            } else {
                let wanted = body["query"]["_value"].clone();
                let found: Vec<Value> = analyzers
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|a| a["name"] == wanted)
                    .cloned()
                    .collect();
                ResponseTemplate::new(200).set_body_json(found)
            }
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/analyzer/an%201/run"))
        .respond_with(ResponseTemplate::new(200).set_body_json(job))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/job/job-1/report"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"report": {"full": {"taxonomies": [{"level": "malicious"}]}}}),
            ),
        )
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn cortex_routes() {
    let h = harness_or_skip!(None);
    let (admin, analyst) = tokens(&h).await;
    cleanup(&h).await;
    let (st, body) = h.call("GET", "/api/analyzers", Some(&analyst), None).await;
    assert_eq!(st, 500);
    assert_eq!(body["message"], "API initialization failed");

    let server = cortex(json!({"id": "job-1", "status": "Success"})).await;
    connector(&h, "Cortex", &server.uri(), Some("ctx-key"), None).await;
    let (st, body) = h.call("GET", "/api/analyzers", Some(&analyst), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"analyzers": ["VirusTotal_GetReport_3_1", "Abuse_Finder_3_0"],
               "message": "Successfully fetched analyzers", "success": true})
    );
    let list = &server.received_requests().await.unwrap()[0];
    assert_eq!(list.url.query(), Some("range=all"));
    assert_eq!(header(list, "authorization"), "Bearer ctx-key");
    assert_eq!(header(list, "user-agent"), "python-requests/2.33.1");
    assert_eq!(list.body, b"{\"query\": {}}");

    let (st, body) = h
        .call(
            "POST",
            "/api/analyzers/run",
            Some(&analyst),
            Some(json!({"analyzer_name": "VirusTotal_GetReport_3_1", "analyzer_data": "8.8.8.8"})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"report": {"success": true, "message": "Analyzer ran successfully",
                          "report": {"taxonomies": [{"level": "malicious"}]}},
               "message": "Successfully ran analyzer", "success": true})
    );
    let reqs = server.received_requests().await.unwrap();
    let run = reqs
        .iter()
        .find(|r| r.url.path().ends_with("/run"))
        .unwrap();
    assert_eq!(run.url.query(), Some("force=1"));
    assert_eq!(
        String::from_utf8_lossy(&run.body),
        r#"{"dataType": "ip", "tlp": 1, "pap": 2, "message": "custom message sent to analyzer", "data": "8.8.8.8"}"#
    );

    let (st, body) = h
        .call(
            "POST",
            "/api/analyzers/run",
            Some(&analyst),
            Some(json!({"analyzer_name": "Nope", "analyzer_data": "example.com"})),
        )
        .await;
    assert_eq!(st, 400);
    assert_eq!(body["message"], "Analyzer Nope does not exist.");
    let (st, body) = h
        .call(
            "POST",
            "/api/analyzers/run",
            Some(&analyst),
            Some(json!({"analyzer_name": "Nope", "analyzer_data": "no ioc"})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(body["message"], "Invalid data type: Unknown");

    // The connector check: cortex4py never calls Cortex.
    let id = h
        .scalar_i64("SELECT id FROM connectors WHERE connector_name = 'Cortex'")
        .await;
    let before = server.received_requests().await.unwrap().len();
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/connectors/verify/{id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["message"], "Cortex connection successful");
    assert_eq!(server.received_requests().await.unwrap().len(), before);
    h.exec("UPDATE connectors SET connector_api_key = NULL WHERE connector_name = 'Cortex'")
        .await;
    let (st, body) = h
        .call(
            "POST",
            &format!("/api/connectors/verify/{id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(st, 500);
    assert_eq!(
        body["message"],
        format!(
            "Failed to verify connector: Connection to {} failed with error: URL and API key are \
             required and must be of type string.",
            server.uri()
        )
    );
    let (st, _) = h.call("GET", "/api/analyzers", Some(&analyst), None).await;
    assert_eq!(st, 500);
    cleanup(&h).await;
}

#[tokio::test]
async fn cortex_job_failure() {
    let h = harness_or_skip!(None);
    let (_, analyst) = tokens(&h).await;
    let server = cortex(json!({"id": "job-1", "status": "Failure", "errorMessage": "quota"})).await;
    connector(&h, "Cortex", &server.uri(), Some("ctx-key"), None).await;
    let (st, body) = h
        .call(
            "POST",
            "/api/analyzers/run",
            Some(&analyst),
            Some(json!({"analyzer_name": "VirusTotal_GetReport_3_1",
                        "analyzer_data": "d41d8cd98f00b204e9800998ecf8427e"})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["report"],
        json!({"success": false, "message": "Analyzer failed: quota"})
    );
    cleanup(&h).await;
}
