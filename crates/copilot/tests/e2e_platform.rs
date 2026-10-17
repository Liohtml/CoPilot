//! The platform-status modules against a real MySQL at the Alembic head:
//! `/api/logs` and `/api/status/sidebar` (`copilot-status`), `/api/license`
//! (`copilot-license`, its licence server a wiremock stand-in). The sidebar's
//! upstreams — the Wazuh indexer and manager, InfluxDB, MinIO and the
//! release check — are wiremock stand-ins too.
//!
//! `log_entries`, `license`, the tag-access settings and the connector rows
//! are deployment-wide: each test puts the rows it finds aside and restores
//! them, so the suites can share one database.
//!
//! `COPILOT_TEST_DATABASE_URL=mysql://… cargo test -p copilot --test
//! e2e_platform -- --test-threads=1`

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod common;

use std::sync::Arc;

use serde_json::{Value, json};
use wiremock::matchers::{body_json, body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{Harness, harness_env};

// --- shared helpers ---------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
struct SavedLog {
    id: i32,
    timestamp: chrono::NaiveDateTime,
    event_type: String,
    user_id: Option<i32>,
    route: Option<String>,
    method: Option<String>,
    status_code: i32,
    message: Option<String>,
    additional_info: Option<String>,
}

async fn save_logs(h: &Harness) -> Vec<SavedLog> {
    let saved = sqlx::query_as::<_, SavedLog>(
        "SELECT id, timestamp, event_type, user_id, route, method, status_code, message, \
         additional_info FROM log_entries ORDER BY id",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    h.exec("DELETE FROM log_entries").await;
    saved
}

async fn restore_logs(h: &Harness, saved: Vec<SavedLog>) {
    // Rows the handlers write after their answers land late: let them.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    h.exec("DELETE FROM log_entries").await;
    for chunk in saved.chunks(1000) {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(
            "INSERT INTO log_entries (id, timestamp, event_type, user_id, route, method, \
             status_code, message, additional_info) ",
        );
        qb.push_values(chunk, |mut b, r| {
            b.push_bind(r.id)
                .push_bind(r.timestamp)
                .push_bind(r.event_type.clone())
                .push_bind(r.user_id)
                .push_bind(r.route.clone())
                .push_bind(r.method.clone())
                .push_bind(r.status_code)
                .push_bind(r.message.clone())
                .push_bind(r.additional_info.clone());
        });
        qb.build().execute(h.db.pool()).await.unwrap();
    }
}

async fn user_id(h: &Harness, name: &str) -> i64 {
    h.scalar_i64(&format!(
        "SELECT id FROM `user` WHERE username = '{name}{}'",
        h.suffix
    ))
    .await
}

async fn cleanup_users(h: &Harness) {
    let s = &h.suffix;
    let contexts: Vec<i32> = sqlx::query_scalar(&format!(
        "SELECT alert_context_id FROM incident_management_asset WHERE customer_code LIKE '%{s}'"
    ))
    .fetch_all(h.db.pool())
    .await
    .unwrap_or_default();
    for sql in [
        format!(
            "DELETE FROM user_customer_access WHERE user_id IN \
             (SELECT id FROM `user` WHERE username LIKE '%{s}')"
        ),
        format!("DELETE FROM `user` WHERE username LIKE '%{s}'"),
        format!("DELETE FROM incident_management_asset WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM incident_management_alert WHERE customer_code LIKE '%{s}'"),
        format!("DELETE FROM customers WHERE customer_code LIKE '%{s}'"),
    ] {
        let _ = sqlx::query(&sql).execute(h.db.pool()).await;
    }
    for id in contexts {
        let _ = sqlx::query("DELETE FROM incident_management_alertcontext WHERE id = ?")
            .bind(id)
            .execute(h.db.pool())
            .await;
    }
}

// --- /api/logs ----------------------------------------------------------------------------

#[tokio::test]
async fn the_error_log_reads_and_purges_like_python() {
    let h = harness_or_skip!(None);
    h.seed().await;
    let saved = save_logs(&h).await;
    let admin = h.token(&format!("admin{}", h.suffix), "admin");
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let admin_id = user_id(&h, "admin").await;

    // Empty: 404, and the handler logs it.
    let (st, body) = h.call("GET", "/api/logs", Some(&admin), None).await;
    assert_eq!(st, 404);
    assert_eq!(body, json!({"success": false, "message": "No logs found"}));
    // Admin only: `Security(get_current_user, scopes=["admin"])`'s 403.
    let (st, body) = h.call("GET", "/api/logs", Some(&analyst), None).await;
    assert_eq!(st, 403);
    assert_eq!(
        body["message"],
        json!("Insufficient permissions. Required scope: admin")
    );

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    h.exec("DELETE FROM log_entries").await;

    for (event, uid, hours, message) in [
        ("Info", Some(admin_id), 2, "recent"),
        ("Error", None, 30, "yesterday"),
        ("Error", Some(admin_id), 240, "old"),
    ] {
        sqlx::query(
            "INSERT INTO log_entries (timestamp, event_type, user_id, route, method, status_code, \
             message) VALUES (UTC_TIMESTAMP() - INTERVAL ? HOUR, ?, ?, 'http://h/x', 'GET', 200, ?)",
        )
        .bind(hours)
        .bind(event)
        .bind(uid)
        .bind(message)
        .execute(h.db.pool())
        .await
        .unwrap();
    }

    let (st, body) = h.call("GET", "/api/logs", Some(&admin), None).await;
    assert_eq!(st, 200);
    let logs = body["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 3);
    let keys: Vec<&String> = logs[0].as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "event_type",
            "user_id",
            "route",
            "method",
            "status_code",
            "message",
            "additional_info",
            "timestamp"
        ]
    );
    assert_eq!(body["message"], json!("Logs fetched successfully"));

    let (st, body) = h
        .call("GET", &format!("/api/logs/{admin_id}"), Some(&admin), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["logs"].as_array().unwrap().len(), 2);
    // `1h` and `1w` both open one day; an int is days.
    for (range, want) in [
        (json!("1h"), 1),
        (json!("1w"), 1),
        (json!("2d"), 2),
        (json!(7), 2),
        (json!(" 7_0d"), 3),
    ] {
        let (st, body) = h
            .call(
                "POST",
                "/api/logs/timerange",
                Some(&admin),
                Some(json!({"time_range": range})),
            )
            .await;
        assert_eq!(st, 200, "{range}: {body}");
        assert_eq!(body["logs"].as_array().unwrap().len(), want, "{range}");
    }
    let (st, body) = h.call("POST", "/api/logs/Error", Some(&admin), None).await;
    assert_eq!(st, 200);
    assert_eq!(body["logs"].as_array().unwrap().len(), 2);
    let (st, body) = h
        .call("GET", "/api/logs/99999999999999999999", Some(&admin), None)
        .await;
    assert_eq!(st, 404);
    assert_eq!(
        body["message"],
        json!("No logs found for user ID: 99999999999999999999")
    );
    let (st, body) = h.call("GET", "/api/logs/abc", Some(&admin), None).await;
    assert_eq!(st, 422);
    assert_eq!(body["details"][0]["field"], json!("user_id"));

    let (st, body) = h
        .call(
            "POST",
            "/api/logs/timerange",
            Some(&admin),
            Some(json!({"time_range": "2w"})),
        )
        .await;
    assert_eq!(st, 422);
    assert_eq!(
        body,
        json!({"message": "Invalid time range. Use 'h' for hours, 'd' for days, and 'w' for weeks.",
               "details": [{"field": "time_range", "error_type": "value_error.time_range",
                            "message": "Invalid time range. Use 'h' for hours, 'd' for days, and 'w' for weeks."}]})
    );
    let (st, _) = h
        .call(
            "POST",
            "/api/logs/timerange",
            Some(&admin),
            Some(json!({"time_range": ""})),
        )
        .await;
    assert_eq!(st, 500, "value[-1] of an empty string is an IndexError");

    let (st, body) = h
        .call("POST", "/api/logs/Warning", Some(&admin), None)
        .await;
    assert_eq!(st, 422);
    assert_eq!(
        body["details"][0]["message"],
        json!("Value is not a valid enumeration member.")
    );

    // Purge one day's rows, then everything.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let before = h.scalar_i64("SELECT COUNT(*) FROM log_entries").await;
    let (st, body) = h
        .call(
            "DELETE",
            "/api/logs/timerange",
            Some(&admin),
            Some(json!({"time_range": "1d"})),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"logs": [], "success": true, "message": "Logs purged successfully"})
    );
    // Everything inside the last day went, the error rows written meanwhile
    // included; the two older seeds stayed.
    assert!(before > 2);
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM log_entries WHERE message IN ('yesterday', 'old')")
            .await,
        2
    );
    assert_eq!(h.scalar_i64("SELECT COUNT(*) FROM log_entries").await, 2);
    let (st, _) = h.call("DELETE", "/api/logs", Some(&admin), None).await;
    assert_eq!(st, 200);
    assert_eq!(h.scalar_i64("SELECT COUNT(*) FROM log_entries").await, 0);

    restore_logs(&h, saved).await;
    cleanup_users(&h).await;
}

// --- /api/license -------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
struct SavedLicense {
    id: i32,
    license_key: String,
    customer_name: String,
    customer_email: String,
    company_name: String,
}

async fn save_licences(h: &Harness) -> Vec<SavedLicense> {
    let saved = sqlx::query_as::<_, SavedLicense>(
        "SELECT id, license_key, customer_name, customer_email, company_name FROM license",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    h.exec("DELETE FROM license").await;
    saved
}

async fn restore_licences(h: &Harness, saved: Vec<SavedLicense>) {
    h.exec("DELETE FROM license").await;
    for r in saved {
        sqlx::query(
            "INSERT INTO license (id, license_key, customer_name, customer_email, company_name) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(r.id)
        .bind(r.license_key)
        .bind(r.customer_name)
        .bind(r.customer_email)
        .bind(r.company_name)
        .execute(h.db.pool())
        .await
        .unwrap();
    }
}

fn licence_router(h: &Harness, upstream: &str) -> axum::Router {
    copilot_license::router(copilot_license::LicenseState {
        ctx: h.app.ctx.clone(),
        client: copilot_license::LicenseClient::new(
            format!("{upstream}/"),
            Some(copilot_core::config::Secret::new("e2e-api-key")),
        )
        .unwrap(),
    })
}

fn licence_object(key: &str) -> Value {
    json!({
        "productId": 1, "id": 7, "key": key, "created": "2026-01-02T03:04:05.120",
        "expires": "2027-01-02T03:04:05", "period": 365, "f1": true, "f2": false, "f3": false,
        "f4": false, "f5": false, "f6": false, "f7": false, "f8": false, "notes": "",
        "block": false, "globalId": 9,
        "customer": {"id": 3, "name": "E2E", "email": "e2e@example.com", "companyName": "E2E Co",
                     "created": "2025-06-01T00:00:00Z"},
        "activatedMachines": [], "trialActivation": false, "maxNoOfMachines": 0,
        "dataObjects": [{"name": "THREAT INTEL", "intValue": 1}, {"name": "AI", "intValue": 0}],
        "signDate": "2026-01-02T03:04:05+02:00"
    })
}

#[tokio::test]
async fn the_licence_routes_call_the_licence_server_like_python() {
    let mut h = harness_or_skip!(None);
    h.seed().await;
    let saved = save_licences(&h).await;
    let key = format!("E2E-{}", h.suffix);
    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key = '{key}'"
    ))
    .await;
    let upstream = MockServer::start().await;
    h.router = licence_router(&h, &upstream.uri());
    let analyst = h.token(&format!("analyst{}", h.suffix), "analyst");
    let portal = h.token(&format!("portal{}", h.suffix), "customer_user");

    let (st, body) = h.call("GET", "/get_license", Some(&analyst), None).await;
    assert_eq!(st, 404);
    assert_eq!(
        body["message"],
        json!("No license found. A license must be created first.")
    );
    let (st, _) = h.call("GET", "/get_license", Some(&portal), None).await;
    assert_eq!(st, 403);

    // `replace_license_in_db` without a licence verifies the key first.
    Mock::given(method("POST"))
        .and(path("/verify-license"))
        .and(header("x-api-key", "e2e-api-key"))
        .and(header("module-version", "1.0"))
        .and(body_json(json!({"license_key": key})))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data": {"license": licence_object(&key), "success": true, "message": "valid"}}),
        ))
        .mount(&upstream)
        .await;
    let (st, body) = h
        .call(
            "POST",
            "/replace_license_in_db",
            Some(&analyst),
            Some(json!({"license_key": key})),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body,
        json!({"success": true, "message": "License created successfully"})
    );
    let (st, body) = h.call("GET", "/get_license", Some(&analyst), None).await;
    assert_eq!(st, 200);
    assert_eq!(body["license_key"], json!(key));

    // Verification from the server caches every named data object for an hour.
    let (st, body) = h.call("GET", "/verify_license", Some(&analyst), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        body["license"]["created"],
        json!("2026-01-02T03:04:05.120000")
    );
    assert_eq!(
        body["license"]["signDate"],
        json!("2026-01-02T03:04:05+02:00")
    );
    assert_eq!(body["message"], json!("valid"));
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM license_cache WHERE license_key = '{key}'"
        ))
        .await,
        2
    );
    // … then answers from the cache.
    let (st, body) = h.call("GET", "/verify_license", Some(&analyst), None).await;
    assert_eq!(st, 200);
    assert_eq!(
        body["message"],
        json!("License verified successfully (from cache)")
    );
    let (st, body) = h
        .call(
            "GET",
            "/is_feature_enabled/THREAT%20INTEL",
            Some(&analyst),
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        body,
        json!({"enabled": true, "success": true, "message": "Feature 'THREAT INTEL' is enabled"})
    );
    // A disabled feature: `IsFeatureEnabledResponse(status_code=400, …)`
    // misses two fields, and its ValidationError is the 400.
    let (st, body) = h
        .call("GET", "/is_feature_enabled/AI", Some(&analyst), None)
        .await;
    assert_eq!(st, 400);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .starts_with("2 validation errors for IsFeatureEnabledResponse"),
        "{body}"
    );
    let (st, body) = h
        .call("GET", "/get_license_features", Some(&analyst), None)
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["features"], json!(["THREAT INTEL"]));

    // The licence server's 5xx is a 502 naming its message.
    Mock::given(method("POST"))
        .and(path("/retrieve-docker-compose"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"message": "down"})))
        .mount(&upstream)
        .await;
    let (st, body) = h
        .call("POST", "/retrieve-docker-compose", Some(&analyst), None)
        .await;
    assert_eq!(st, 502);
    assert_eq!(body["message"], json!("License server error: down"));

    // Replacing an existing licence clears its cache.
    let (st, _) = h
        .call(
            "POST",
            "/replace_license_in_db",
            Some(&analyst),
            Some(json!({"license_key": format!("{key}-2")})),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        h.scalar_i64(&format!(
            "SELECT COUNT(*) FROM license_cache WHERE license_key = '{key}'"
        ))
        .await,
        0
    );

    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key LIKE '{key}%'"
    ))
    .await;
    restore_licences(&h, saved).await;
    cleanup_users(&h).await;
}

// --- /api/status/sidebar -----------------------------------------------------------------

/// The connector rows a sidebar test points at its stand-ins: the rows it
/// finds are copied aside first and put back after.
struct BorrowedConnectors {
    backup: String,
    names: Vec<&'static str>,
}

impl BorrowedConnectors {
    async fn take(h: &Harness, names: &[&'static str]) -> Self {
        let backup = format!("connectors_e2e_platform_{}", h.suffix);
        h.exec(&format!(
            "CREATE TABLE {backup} AS SELECT * FROM connectors WHERE connector_name IN ({})",
            quoted(names)
        ))
        .await;
        Self {
            backup,
            names: names.to_vec(),
        }
    }

    /// Point `name` at `url` (an existing row keeps its id).
    async fn point(
        &self,
        h: &Harness,
        name: &str,
        url: &str,
        api_key: Option<&str>,
        extra: Option<&str>,
    ) {
        let updated = sqlx::query(
            "UPDATE connectors SET connector_url = ?, connector_username = 'u', \
             connector_password = 'p', connector_api_key = ?, connector_extra_data = ?, \
             connector_configured = 1, connector_verified = 1, connector_enabled = 1 \
             WHERE connector_name = ?",
        )
        .bind(url)
        .bind(api_key)
        .bind(extra)
        .bind(name)
        .execute(h.db.pool())
        .await
        .unwrap()
        .rows_affected();
        if updated == 0 {
            sqlx::query(
                "INSERT INTO connectors (connector_name, connector_type, connector_url, \
                 connector_last_updated, connector_username, connector_password, \
                 connector_api_key, connector_description, connector_supports, \
                 connector_configured, connector_verified, connector_accepts_host_only, \
                 connector_accepts_api_key, connector_accepts_username_password, \
                 connector_accepts_file, connector_accepts_extra_data, connector_extra_data, \
                 connector_enabled) VALUES (?, '4.8', ?, '2026-01-02 03:04:05', 'u', 'p', ?, \
                 'e2e', 'e2e', 1, 1, 0, 0, 1, 0, 1, ?, 1)",
            )
            .bind(name)
            .bind(url)
            .bind(api_key)
            .bind(extra)
            .execute(h.db.pool())
            .await
            .unwrap();
        }
    }

    async fn give_back(self, h: &Harness) {
        let b = &self.backup;
        h.exec(&format!(
            "DELETE FROM connectors WHERE connector_name IN ({}) AND id NOT IN \
             (SELECT id FROM {b})",
            quoted(&self.names)
        ))
        .await;
        h.exec(&format!(
            "UPDATE connectors c JOIN {b} o ON o.id = c.id SET c.connector_url = o.connector_url, \
             c.connector_username = o.connector_username, c.connector_password = \
             o.connector_password, c.connector_api_key = o.connector_api_key, \
             c.connector_extra_data = o.connector_extra_data, c.connector_configured = \
             o.connector_configured, c.connector_verified = o.connector_verified, \
             c.connector_enabled = o.connector_enabled"
        ))
        .await;
        h.exec(&format!("DROP TABLE {b}")).await;
    }
}

fn quoted(names: &[&str]) -> String {
    names
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `last()` per series: one critical check still failing, one recovered.
const INFLUX_STATES: &str = "#group,false,false,false,false,true,true,true,true,true\r\n\
    #datatype,string,long,dateTime:RFC3339,string,string,string,string,string,string\r\n\
    #default,_result,,,,,,,,\r\n\
    ,result,table,_time,_value,_check_id,_check_name,_level,host,active\r\n\
    ,,0,2026-10-15T10:00:00Z,wazuh failed,c1,CRITICAL SERVICES CHECK,crit,h1,failed\r\n\
    ,,1,2026-10-15T10:05:00Z,wazuh running,c1,CRITICAL SERVICES CHECK,ok,h1,active\r\n\
    ,,2,2026-10-15T10:04:00.5Z,graylog failed,c1,CRITICAL SERVICES CHECK,crit,h2,failed\r\n\r\n";

const BUCKETS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListAllMyBucketsResult \
    xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>02d6176db174dc93cb1b899f7c6078f0\
    8654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><Buckets><Bucket>\
    <Name>copilot-cases</Name><CreationDate>2026-01-02T03:04:05.678Z</CreationDate></Bucket>\
    </Buckets></ListAllMyBucketsResult>";

fn ids(body: &Value) -> Vec<String> {
    body["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_string())
        .collect()
}

fn indicator<'a>(body: &'a Value, id: &str) -> &'a Value {
    body["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == json!(id))
        .unwrap_or_else(|| panic!("no {id} in {body}"))
}

const SHARED_IDS: [&str; 14] = [
    "tag_rbac",
    "ai_analyst_jobs",
    "mem_palace",
    "notification_dispatch",
    "scheduler",
    "agent_sync",
    "talon",
    "core_soc_tools",
    "wazuh_indexer",
    "wazuh_catalog",
    "influx_health",
    "connectors",
    "license",
    "platform_storage",
];

#[tokio::test]
async fn the_sidebar_serves_its_indicators_like_python() {
    let release = MockServer::start().await;
    let s3 = MockServer::start().await;
    let extra = format!(
        "COPILOT_VERSION_CHECK_URL={}/latest\nCOPILOT_MINIO_ENDPOINT={}\nENVIRONMENT=E2E\n\
         COPILOT_SIDEBAR_REFRESH=false\n",
        release.uri(),
        s3.address()
    );
    let mut h = harness_or_skip!(None, &extra);
    h.seed().await;
    let s = h.suffix.clone();
    let saved = save_licences(&h).await;
    let borrowed =
        BorrowedConnectors::take(&h, &["Wazuh-Indexer", "Wazuh-Manager", "InfluxDB"]).await;
    let indexer = MockServer::start().await;
    let manager = MockServer::start().await;
    let influx = MockServer::start().await;
    borrowed
        .point(&h, "Wazuh-Indexer", &indexer.uri(), None, None)
        .await;
    borrowed
        .point(&h, "Wazuh-Manager", &manager.uri(), None, None)
        .await;
    borrowed
        .point(
            &h,
            "InfluxDB",
            &influx.uri(),
            Some("tok"),
            Some("SOC FORTRESS,telegraf"),
        )
        .await;

    Mock::given(method("GET"))
        .and(path("/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tag_name": "v99.0.0", "html_url": "https://example.com/release", "name": "v99.0.0"
        })))
        .expect(1)
        .mount(&release)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(BUCKETS))
        .mount(&s3)
        .await;
    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cluster_name": "e2e-cluster", "status": "yellow", "timed_out": false,
            "number_of_nodes": 1, "number_of_data_nodes": 1, "discovered_master": true,
            "discovered_cluster_manager": true, "active_primary_shards": 10, "active_shards": 10,
            "relocating_shards": 0, "initializing_shards": 0, "unassigned_shards": 5,
            "delayed_unassigned_shards": 0, "number_of_pending_tasks": 0,
            "number_of_in_flight_fetch": 0, "task_max_waiting_in_queue_millis": 0,
            "active_shards_percent_as_number": 66.6
        })))
        .mount(&indexer)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v2/query"))
        .and(header("authorization", "Token tok"))
        .and(body_string_contains("|> last()"))
        .respond_with(ResponseTemplate::new(200).set_body_string(INFLUX_STATES))
        .mount(&influx)
        .await;

    // A licence whose cached answer expires in ten days and an hour.
    let key = format!("E2E-SIDEBAR-{s}");
    sqlx::query(
        "INSERT INTO license (license_key, customer_name, customer_email, company_name) \
         VALUES (?, 'n', 'e', 'c')",
    )
    .bind(&key)
    .execute(h.db.pool())
    .await
    .unwrap();
    let expires = (chrono::Utc::now().naive_utc() + chrono::Duration::hours(10 * 24 + 1))
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    sqlx::query(
        "INSERT INTO license_cache (license_key, feature_name, is_enabled, cached_at, \
         expires_at, license_data) VALUES (?, 'THREAT INTEL', 1, UTC_TIMESTAMP(), \
         UTC_TIMESTAMP() + INTERVAL 1 HOUR, ?)",
    )
    .bind(&key)
    .bind(json!({"data": {"license": {"expires": format!("{expires}Z")}}}).to_string())
    .execute(h.db.pool())
    .await
    .unwrap();

    let sidebar = copilot_status::sidebar::SidebarState {
        cache: Arc::default(),
        ..h.app.sidebar.clone()
    };
    h.router = copilot_status::sidebar::router(sidebar.clone());
    let admin = h.token(&format!("admin{s}"), "admin");
    let analyst = h.token(&format!("analyst{s}"), "analyst");
    let portal = h.token(&format!("portal{s}"), "customer_user");

    let (st, _) = h.call("GET", "/sidebar", None, None).await;
    assert_eq!(st, 401);

    // Cold: the per-user indicators only; the shared set is computed for
    // the next caller.
    let (st, body) = h.call("GET", "/sidebar", Some(&analyst), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["message"], json!("Sidebar context loaded"));
    assert_eq!(
        body["current_version"],
        json!(copilot_platform::version::CURRENT_VERSION)
    );
    assert_eq!(body["latest_version"], json!("99.0.0"));
    assert_eq!(body["is_outdated"], json!(true));
    assert_eq!(body["release_url"], json!("https://example.com/release"));
    assert_eq!(body["environment"], json!("E2E"));
    assert_eq!(ids(&body), ["open_alerts", "my_open_cases"]);
    // The analyst sees acme's alert only.
    assert_eq!(
        indicator(&body, "open_alerts"),
        &json!({"id": "open_alerts", "status": "warning", "label": "Open alerts",
                "detail": "1 unassigned \u{2014} other: 1", "count": 1, "category": "triage"})
    );
    assert_eq!(
        indicator(&body, "my_open_cases")["detail"],
        json!("No open cases assigned to you.")
    );
    for _ in 0..100 {
        if sidebar.cache.has_shared() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(sidebar.cache.has_shared());

    // Warm: what the two jobs compute (the InfluxDB value first).
    copilot_status::sidebar::services::refresh_influx(&sidebar).await;
    copilot_status::sidebar::services::refresh_shared(&sidebar).await;
    let (st, body) = h.call("GET", "/sidebar", Some(&admin), None).await;
    assert_eq!(st, 200, "{body}");
    let mut want = vec!["open_alerts".to_string(), "my_open_cases".to_string()];
    want.extend(SHARED_IDS.iter().map(|i| i.to_string()));
    assert_eq!(ids(&body), want);
    assert_eq!(
        indicator(&body, "wazuh_indexer"),
        &json!({"id": "wazuh_indexer", "status": "warning", "label": "Wazuh indexer",
                "detail": "Cluster e2e-cluster is yellow.", "count": 1,
                "category": "infrastructure"})
    );
    assert_eq!(
        indicator(&body, "influx_health"),
        &json!({"id": "influx_health", "status": "error", "label": "Healthchecks",
                "detail": "Active alerts: 1 critical/error.", "count": 1,
                "category": "infrastructure"})
    );
    assert_eq!(
        indicator(&body, "license"),
        &json!({"id": "license", "status": "warning", "label": "License",
                "detail": "Expires in 10 days.", "count": 10, "category": "platform"})
    );
    assert_eq!(
        indicator(&body, "platform_storage"),
        &json!({"id": "platform_storage", "status": "ok", "label": "Platform storage",
                "detail": "Database and MinIO are reachable.", "count": 0,
                "category": "platform"})
    );
    // The audiences: an analyst gets no admin indicator, a portal user only
    // the catalog.
    let (_, body) = h.call("GET", "/sidebar", Some(&analyst), None).await;
    assert_eq!(ids(&body)[2..], SHARED_IDS[..11]);
    let (_, body) = h.call("GET", "/sidebar", Some(&portal), None).await;
    assert_eq!(
        ids(&body),
        ["open_alerts", "my_open_cases", "wazuh_catalog"]
    );

    // The catalog indicator reads the Detections Catalog's own cache.
    Mock::given(path("/security/user/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"token": "tok"}, "error": 0})),
        )
        .mount(&manager)
        .await;
    Mock::given(method("GET"))
        .and(path("/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "affected_items": [
                {"filename": "0095-sshd_rules.xml", "relative_dirname": "ruleset/rules",
                 "id": 5710, "level": 5, "status": "enabled", "description": "sshd",
                 "groups": ["sshd"], "details": {}},
                {"filename": "0095-sshd_rules.xml", "relative_dirname": "ruleset/rules",
                 "id": 5712, "level": 10, "status": "enabled", "description": "brute",
                 "groups": ["sshd"], "details": {}}],
            "total_affected_items": 2}, "error": 0})))
        .up_to_n_times(1)
        .mount(&manager)
        .await;
    copilot_searches::caches::refresh_wazuh(&sidebar.searches).await;
    copilot_status::sidebar::services::refresh_shared(&sidebar).await;
    let (_, body) = h.call("GET", "/sidebar", Some(&portal), None).await;
    assert_eq!(
        indicator(&body, "wazuh_catalog"),
        &json!({"id": "wazuh_catalog", "status": "ok", "label": "Wazuh catalog",
                "detail": "2 rules loaded.", "count": 0, "category": "infrastructure"})
    );
    Mock::given(method("GET"))
        .and(path("/rules"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&manager)
        .await;
    copilot_searches::caches::refresh_wazuh(&sidebar.searches).await;
    copilot_status::sidebar::services::refresh_shared(&sidebar).await;
    let (_, body) = h.call("GET", "/sidebar", Some(&portal), None).await;
    let catalog = indicator(&body, "wazuh_catalog");
    assert_eq!(catalog["status"], json!("error"), "{catalog}");
    assert_eq!(catalog["count"], json!(1));

    // Tag RBAC hides the untagged alert from the analyst (Python counted it:
    // its indicator applied customer scoping only).
    let settings = h
        .exec(
            "INSERT INTO incident_management_tag_access_settings (enabled, \
             untagged_alert_behavior, updated_at) VALUES (1, 'admin_only', UTC_TIMESTAMP())",
        )
        .await;
    let (_, body) = h.call("GET", "/sidebar", Some(&analyst), None).await;
    assert_eq!(
        indicator(&body, "open_alerts")["detail"],
        json!("No unassigned open alerts.")
    );
    copilot_status::sidebar::services::refresh_shared(&sidebar).await;
    let (_, body) = h.call("GET", "/sidebar", Some(&analyst), None).await;
    assert_eq!(
        indicator(&body, "tag_rbac")["detail"],
        json!("Active \u{2014} untagged alerts: admin only.")
    );
    h.exec(&format!(
        "DELETE FROM incident_management_tag_access_settings WHERE id = {settings}"
    ))
    .await;

    // MinIO refusing the credentials: S3Error.
    s3.reset().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(403).set_body_raw(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AccessDenied</Code>\
                 <Message>Access Denied.</Message><Resource>/</Resource><RequestId>1\
                 </RequestId><HostId>2</HostId></Error>",
            "application/xml",
        ))
        .mount(&s3)
        .await;
    copilot_status::sidebar::services::refresh_shared(&sidebar).await;
    let (_, body) = h.call("GET", "/sidebar", Some(&admin), None).await;
    assert_eq!(
        indicator(&body, "platform_storage"),
        &json!({"id": "platform_storage", "status": "error", "label": "Platform storage",
                "detail": "MinIO unreachable (S3Error)", "count": 1, "category": "platform"})
    );

    h.exec(&format!(
        "DELETE FROM license_cache WHERE license_key = '{key}'"
    ))
    .await;
    restore_licences(&h, saved).await;
    borrowed.give_back(&h).await;
    cleanup_users(&h).await;
}
