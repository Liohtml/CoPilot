//! End-to-end tests of the connector core (`copilot-connectors`) and its
//! cache's cross-process change check, against a real MySQL.
//!
//! ```text
//! COPILOT_TEST_DATABASE_URL=mysql://copilot:copilot@127.0.0.1:13307/copilot \
//!   cargo test -p copilot --test e2e_connectors -- --test-threads=1
//! ```
//!
//! Connector names carry the run's suffix, except where a test needs the
//! real `Wazuh-Indexer` / `Wazuh-Manager` rows: those it creates, points at a
//! local stand-in and deletes again.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use serde_json::{Value, json};

use copilot_db::connectors::ConnectorCache;

#[macro_use]
mod common;
use common::*;

/// Insert a connector row; returns its id.
async fn connector(
    h: &Harness,
    name: &str,
    url: &str,
    user: Option<&str>,
    pass: Option<&str>,
) -> i64 {
    sqlx::query(
        "INSERT INTO connectors (connector_name, connector_type, connector_url, connector_last_updated, \
         connector_username, connector_password, connector_api_key, connector_description, \
         connector_supports, connector_configured, connector_verified, connector_accepts_host_only, \
         connector_accepts_api_key, connector_accepts_username_password, connector_accepts_file, \
         connector_accepts_extra_data, connector_extra_data, connector_enabled) VALUES \
         (?, '4.8', ?, '2026-01-02 03:04:05', ?, ?, NULL, 'desc', 'supports', 1, 0, 0, 0, 1, 0, 0, NULL, 1)",
    )
    .bind(name)
    .bind(url)
    .bind(user)
    .bind(pass)
    .execute(h.db.pool())
    .await
    .unwrap()
    .last_insert_id()
    .try_into()
    .unwrap()
}

async fn drop_connector(h: &Harness, id: i64) {
    h.exec(&format!(
        "DELETE FROM connectorhistory WHERE connector_id = {id}"
    ))
    .await;
    h.exec(&format!("DELETE FROM connectors WHERE id = {id}"))
        .await;
}

#[tokio::test]
async fn the_change_check_drops_a_row_another_process_wrote() {
    let h = harness_or_skip!(None);
    let name = h.code("CacheProbe-");
    let id = connector(
        &h,
        &name,
        "https://old.example:9200",
        Some("u"),
        Some("one"),
    )
    .await;
    let cache = ConnectorCache::new(h.db.clone(), Duration::from_secs(600))
        .with_check_interval(Duration::from_secs(1));

    let first = cache.get(&name).await.unwrap().unwrap();
    assert_eq!(first.connector_password.as_deref(), Some("one"));
    // The Python backend (or an operator's SQL shell) rotates the password:
    // nothing tells this process.
    h.exec(&format!(
        "UPDATE connectors SET connector_password = 'two' WHERE id = {id}"
    ))
    .await;
    let cached = cache.get(&name).await.unwrap().unwrap();
    assert_eq!(
        cached.connector_password.as_deref(),
        Some("one"),
        "inside the interval the cached row is served without a query"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let after = cache.get(&name).await.unwrap().unwrap();
    assert_eq!(
        after.connector_password.as_deref(),
        Some("two"),
        "the rotated password outlived the check interval"
    );
    let stats = cache.stats();
    assert_eq!(stats.stale_dropped, 1);
    assert!(stats.checks >= 2);

    // An unchanged row survives the next check without a reload.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let misses = cache.stats().misses;
    cache.get(&name).await.unwrap().unwrap();
    assert_eq!(
        cache.stats().misses,
        misses,
        "a confirmed row was loaded again"
    );

    // A deleted row is dropped too.
    drop_connector(&h, id).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(cache.get(&name).await.unwrap().is_none());

    // With the check off, the TTL alone decides (the old behaviour).
    let id = connector(&h, &name, "https://old.example:9200", None, Some("one")).await;
    let unchecked = ConnectorCache::new(h.db.clone(), Duration::from_secs(600))
        .with_check_interval(Duration::ZERO);
    unchecked.get(&name).await.unwrap().unwrap();
    h.exec(&format!(
        "UPDATE connectors SET connector_password = 'two' WHERE id = {id}"
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let stale = unchecked.get(&name).await.unwrap().unwrap();
    assert_eq!(stale.connector_password.as_deref(), Some("one"));
    drop_connector(&h, id).await;
}

#[tokio::test]
async fn connector_reads_are_admin_only_and_carry_history() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = &h.suffix;
    let name = h.code("ReadProbe-");
    let id = connector(
        &h,
        &name,
        "https://read.example:55000",
        Some("wazuh"),
        Some("pw"),
    )
    .await;
    h.exec(&format!(
        "INSERT INTO connectorhistory (connector_id, change_timestamp, change_description) \
         VALUES ({id}, '2026-02-03 04:05:06', 'first'), ({id}, '2026-02-03 04:05:07', 'second')"
    ))
    .await;
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");

    let (status, body) = h
        .call("GET", &format!("/api/connectors/{id}"), Some(&admin), None)
        .await;
    assert_eq!(status, 200, "{body}");
    let c = &body["connector"];
    assert_eq!(c["connector_name"], json!(name));
    assert_eq!(c["connector_password"], json!("pw"));
    assert_eq!(c["connector_last_updated"], json!("2026-01-02T03:04:05"));
    assert_eq!(c["connector_configured"], json!(true));
    assert_eq!(
        c["history_logs"],
        json!([
            {"id": c["history_logs"][0]["id"], "connector_id": id, "change_timestamp": "2026-02-03T04:05:06", "change_description": "first"},
            {"id": c["history_logs"][1]["id"], "connector_id": id, "change_timestamp": "2026-02-03T04:05:07", "change_description": "second"},
        ])
    );
    let keys: Vec<&str> = c.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys.first(), Some(&"id"));
    assert_eq!(keys.last(), Some(&"history_logs"));
    assert_eq!(body["message"], json!("Connector fetched successfully"));

    // The list carries the same row.
    let (status, body) = h.call("GET", "/api/connectors", Some(&admin), None).await;
    assert_eq!(status, 200);
    let listed: Vec<&Value> = body["connectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["id"] == json!(id))
        .collect();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["history_logs"].as_array().unwrap().len(), 2);

    // Guards: the list is `get_current_user(scopes=["admin"])`, one row is
    // `require_any_scope("admin")` — the texts differ.
    let (status, body) = h.call("GET", "/api/connectors", Some(&analyst), None).await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            403,
            json!("Insufficient permissions. Required scope: admin")
        )
    );
    let (status, body) = h
        .call(
            "GET",
            &format!("/api/connectors/{id}"),
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            403,
            json!("Insufficient permissions. Required one of: admin")
        )
    );
    let (status, _) = h.call("GET", "/api/connectors", None, None).await;
    assert_eq!(status, 401);
    let (status, body) = h
        .call("GET", "/api/connectors/abc", Some(&admin), None)
        .await;
    assert_eq!(status, 422, "{body}");
    let (status, body) = h
        .call("GET", "/api/connectors/987654321", Some(&admin), None)
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (404, json!("No connector found for ID: 987654321"))
    );

    drop_connector(&h, id).await;
}

/// Point the deployment's `name` connector at `url` for one test; returns
/// what to put back (`None`: the row did not exist and is deleted again).
async fn borrow_connector(
    h: &Harness,
    name: &str,
    url: &str,
    user: &str,
    pass: &str,
) -> (i64, Option<(String, Option<String>, Option<String>)>) {
    let existing: Option<(i64, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, connector_url, connector_username, connector_password FROM connectors \
         WHERE connector_name = ? ORDER BY id LIMIT 1",
    )
    .bind(name)
    .fetch_optional(h.db.pool())
    .await
    .unwrap();
    match existing {
        Some((id, old_url, old_user, old_pass)) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = ?, \
                 connector_password = ? WHERE id = ?",
            )
            .bind(url)
            .bind(user)
            .bind(pass)
            .bind(id)
            .execute(h.db.pool())
            .await
            .unwrap();
            (id, Some((old_url, old_user, old_pass)))
        }
        None => (connector(h, name, url, Some(user), Some(pass)).await, None),
    }
}

async fn give_back(h: &Harness, id: i64, old: Option<(String, Option<String>, Option<String>)>) {
    match old {
        Some((url, user, pass)) => {
            sqlx::query(
                "UPDATE connectors SET connector_url = ?, connector_username = ?, \
                 connector_password = ? WHERE id = ?",
            )
            .bind(url)
            .bind(user)
            .bind(pass)
            .bind(id)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
        None => drop_connector(h, id).await,
    }
}

const BASIC: &str = "Basic aW5kZXhlcjpwdy1lMmU="; // indexer:pw-e2e

#[tokio::test]
async fn indexer_calls_carry_the_connector_row_and_retry_like_elasticsearch7() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, ResponseTemplate};

    let h = harness_or_skip!(None);
    h.seed().await;
    let s = &h.suffix;
    let es = wiremock::MockServer::start().await;
    let (id, old) = borrow_connector(&h, "Wazuh-Indexer", &es.uri(), "indexer", "pw-e2e").await;
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");

    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .and(header("authorization", BASIC))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cluster_name": "wazuh-cluster", "status": "green", "timed_out": false,
            "number_of_nodes": 3, "number_of_data_nodes": 3, "discovered_master": true,
            "discovered_cluster_manager": true, "active_primary_shards": 10, "active_shards": 20,
            "relocating_shards": 0, "initializing_shards": 0, "unassigned_shards": 1,
            "delayed_unassigned_shards": 0, "number_of_pending_tasks": 0,
            "number_of_in_flight_fetch": 0, "task_max_waiting_in_queue_millis": 0,
            "active_shards_percent_as_number": 95.5
        })))
        .expect(1)
        .mount(&es)
        .await;
    let (status, body) = h
        .call("GET", "/api/wazuh_indexer/health", Some(&analyst), None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["cluster_health"]["cluster_name"],
        json!("wazuh-cluster")
    );
    assert_eq!(
        body["cluster_health"]["active_shards_percent_as_number"],
        json!(95.5)
    );
    assert_eq!(body["success"], json!(true));

    // The portal never reaches the indexer.
    let (status, _) = h
        .call("GET", "/api/wazuh_indexer/health", Some(&portal), None)
        .await;
    assert_eq!(status, 403);

    // 503 is retried ten times (`max_retries=10`); the shards route lets
    // the `TransportError` escape, uvicorn's bare 500.
    Mock::given(method("GET"))
        .and(path("/_cat/shards"))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(json!({"error": "busy", "status": 503})),
        )
        .expect(11)
        .mount(&es)
        .await;
    let (status, body) = h
        .call("GET", "/api/wazuh_indexer/shards", Some(&analyst), None)
        .await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(body, json!("Internal Server Error"));
    es.verify().await;
    give_back(&h, id, old).await;
}

#[tokio::test]
async fn snapshot_schedules_are_rows_of_index_snapshot_schedules() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let s = &h.suffix;
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let name = format!("nightly {s}");

    let (status, body) = h
        .call(
            "POST",
            "/api/snapshots/schedules",
            Some(&admin),
            Some(
                json!({"name": name, "index_pattern": "wazuh-alerts-*", "repository": "backup",
                        "scheduled_hour": 2, "timezone": "Europe/Berlin"}),
            ),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let sid = body["schedule"]["id"].as_i64().unwrap();
    assert_eq!(body["schedule"]["snapshot_prefix"], json!("scheduled"));
    assert_eq!(body["schedule"]["skip_write_indices"], json!(true));
    let stored: (String, String, i64, Option<i64>) = sqlx::query_as(
        "SELECT name, timezone, enabled, scheduled_hour FROM index_snapshot_schedules WHERE id = ?",
    )
    .bind(sid)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(stored, (name.clone(), "Europe/Berlin".into(), 1, Some(2)));

    // Admin only, with `get_current_user(scopes=["admin"])`'s text.
    let (status, body) = h
        .call("GET", "/api/snapshots/schedules", Some(&analyst), None)
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            403,
            json!("Insufficient permissions. Required scope: admin")
        )
    );

    // An update writes only what it is sent; an explicit null clears.
    let (status, body) = h
        .call(
            "PUT",
            &format!("/api/snapshots/schedules/{sid}"),
            Some(&admin),
            Some(json!({"enabled": false, "scheduled_hour": null, "retention_days": 30})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let stored: (String, i64, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT name, enabled, scheduled_hour, retention_days FROM index_snapshot_schedules WHERE id = ?",
    )
    .bind(sid)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(stored, (name.clone(), 0, None, Some(30)));

    let (status, body) = h
        .call(
            "GET",
            "/api/snapshots/schedules?enabled_only=true",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert!(
        body["schedules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["id"] != json!(sid)),
        "a disabled schedule is listed as enabled"
    );

    let (status, _) = h
        .call(
            "DELETE",
            &format!("/api/snapshots/schedules/{sid}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM index_snapshot_schedules WHERE id = {sid}"
        ))
        .await,
        0
    );
    let (status, body) = h
        .call(
            "DELETE",
            &format!("/api/snapshots/schedules/{sid}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn manager_tokens_follow_the_row_and_a_401_is_retried_once() {
    use wiremock::matchers::{body_bytes, header, method, path, query_param};
    use wiremock::{Mock, ResponseTemplate};

    let h = harness_or_skip!(None);
    h.seed().await;
    let s = &h.suffix;
    let mgr = wiremock::MockServer::start().await;
    let (id, old) = borrow_connector(&h, "Wazuh-Manager", &mgr.uri(), "wazuh", "pw-1").await;
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    // wazuh:pw-1 and wazuh:pw-2.
    let (basic1, basic2) = ("Basic d2F6dWg6cHctMQ==", "Basic d2F6dWg6cHctMg==");

    // The first token is refused by the next call (expired server-side).
    Mock::given(method("GET"))
        .and(path("/security/user/authenticate"))
        .and(header("authorization", basic1))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "t1"}})))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&mgr)
        .await;
    Mock::given(method("GET"))
        .and(path("/security/user/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "t2"}})))
        .with_priority(2)
        .mount(&mgr)
        .await;
    Mock::given(method("GET"))
        .and(path("/groups"))
        .and(header("authorization", "Bearer t1"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"title": "Unauthorized"})))
        .mount(&mgr)
        .await;
    Mock::given(method("GET"))
        .and(path("/groups"))
        .and(header("authorization", "Bearer t2"))
        .and(query_param("pretty", "False"))
        .and(query_param("limit", "500"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"affected_items": [{"name": "default", "count": "3"}], "total_affected_items": 1}
        })))
        .mount(&mgr)
        .await;

    let (status, body) = h
        .call("GET", "/api/wazuh_manager/groups", Some(&admin), None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["results"],
        json!([{"name": "default", "count": 3, "mergedSum": null, "configSum": null}])
    );
    let paths: Vec<String> = mgr
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert_eq!(
        paths,
        [
            "/security/user/authenticate",
            "/groups",
            "/security/user/authenticate",
            "/groups"
        ]
    );

    // Admin only, with `get_current_user(scopes=["admin"])`'s text.
    let (status, body) = h
        .call("GET", "/api/wazuh_manager/groups", Some(&analyst), None)
        .await;
    assert_eq!(
        (status.as_u16(), body["message"].clone()),
        (
            403,
            json!("Insufficient permissions. Required scope: admin")
        )
    );

    // The cached token serves the next call; a rotated password fetches a new one.
    mgr.reset().await;
    Mock::given(method("GET"))
        .and(path("/security/user/authenticate"))
        .and(header("authorization", basic2))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "t3"}})))
        .expect(1)
        .mount(&mgr)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rules/files/local_rules.xml"))
        .and(header("authorization", "Bearer t3"))
        .and(header("content-type", "application/octet-stream"))
        .and(query_param("overwrite", "true"))
        .and(query_param("pretty", "false"))
        .and(body_bytes(b"<group/>".to_vec()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"affected_items": ["local_rules.xml"], "total_affected_items": 1}
        })))
        .expect(1)
        .mount(&mgr)
        .await;
    h.exec(&format!(
        "UPDATE connectors SET connector_password = 'pw-2' WHERE id = {id}"
    ))
    .await;
    let boundary = "xBOUNDARYx";
    let multipart = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"local_rules.xml\"\r\n\
         Content-Type: application/xml\r\n\r\n<group/>\r\n--{boundary}--\r\n"
    );
    let req = http::Request::builder()
        .method("PUT")
        .uri("/api/wazuh_manager/rules/files/local_rules.xml")
        .header("authorization", format!("Bearer {admin}"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(axum::body::Body::from(multipart))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(h.router.clone(), req)
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["message"],
        json!("Successfully uploaded/updated rule file: local_rules.xml")
    );
    mgr.verify().await;
    give_back(&h, id, old).await;
}
