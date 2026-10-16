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
