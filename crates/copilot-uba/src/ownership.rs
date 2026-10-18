//! Which Graylog objects UBA setup made for a customer — port of
//! `services/ownership.py` (`uba_provisioned_resource`, #1241).
//!
//! Setup records every object it creates or finds by title; rollback reads
//! the records to know what the customer owns and marks what it removed. A
//! rollback of a customer set up before the table existed records its
//! objects as `adopted` when it removes them. The statements are
//! SQLAlchemy's, so MySQL returns the rows in the same order.

use std::collections::HashMap;

use copilot_core::time::now_utc_naive;
use copilot_db::Db;
use copilot_db::schema::TableRequirement;
use sqlx::MySqlConnection;

/// A "UBA FEED - <source> - <tenant>" stream.
pub const FEED_STREAM: &str = "feed_stream";
/// A routing rule (`route_to_stream` to a feed stream).
pub const ROUTING_RULE: &str = "routing_rule";
/// A "UBA ROUTING - <source> - <tenant>" pipeline.
pub const ROUTING_PIPELINE: &str = "routing_pipeline";
/// The "UBA GELF - <tenant>" output.
pub const OUTPUT: &str = "output";
/// The "UBA ALERTS - <tenant>" stream.
pub const ALERTS_STREAM: &str = "alerts_stream";
/// The shared "UBA ALERTS" input.
pub const ALERTS_INPUT: &str = "alerts_input";
/// The Wazuh rules file (never removed).
pub const WAZUH_RULES: &str = "wazuh_rules";

/// The kinds, in rollback's removal order (`ORDER`).
pub const ORDER: &[&str] = &[
    ROUTING_PIPELINE,
    OUTPUT,
    ROUTING_RULE,
    FEED_STREAM,
    ALERTS_STREAM,
    ALERTS_INPUT,
    WAZUH_RULES,
];

/// `uba_provisioned_resource`'s columns.
pub const TABLE: TableRequirement = TableRequirement {
    table: "uba_provisioned_resource",
    columns: &[
        "id",
        "customer_code",
        "kind",
        "graylog_id",
        "title",
        "source",
        "shared",
        "origin",
        "created_at",
        "updated_at",
        "removed_at",
        "removed_by_rollback_id",
    ],
};

/// `Owned`: an object to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owned {
    /// One of the kinds above.
    pub kind: &'static str,
    /// The Graylog id (the file name for the Wazuh rules).
    pub graylog_id: String,
    /// Its title.
    pub title: String,
    /// `WAZUH` / `O365` for per-source objects.
    pub source: Option<String>,
    /// Used by every customer.
    pub shared: bool,
    /// `created`, `found` or `adopted`.
    pub origin: &'static str,
}

/// A `uba_provisioned_resource` row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Row {
    /// Primary key.
    pub id: i32,
    /// The customer.
    pub customer_code: String,
    /// The kind.
    pub kind: String,
    /// The Graylog id.
    pub graylog_id: String,
    /// The title when last seen.
    pub title: String,
    /// The source.
    pub source: Option<String>,
    /// Shared.
    pub shared: bool,
}

const COLUMNS: &str = "uba_provisioned_resource.id, uba_provisioned_resource.customer_code, \
     uba_provisioned_resource.kind, uba_provisioned_resource.graylog_id, \
     uba_provisioned_resource.title, uba_provisioned_resource.source, \
     uba_provisioned_resource.shared, uba_provisioned_resource.origin, \
     uba_provisioned_resource.created_at, uba_provisioned_resource.updated_at, \
     uba_provisioned_resource.removed_at, uba_provisioned_resource.removed_by_rollback_id";

async fn customer_rows(
    conn: &mut MySqlConnection,
    customer_code: &str,
) -> Result<Vec<Row>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM uba_provisioned_resource \
         WHERE uba_provisioned_resource.customer_code = ?"
    ))
    .bind(customer_code)
    .fetch_all(conn)
    .await
}

/// `record(session, customer_code, items)`: insert or refresh the
/// customer's records (no commit). A row is keyed by its Graylog id: a
/// title changed since setup keeps pointing at the same object.
pub async fn record(
    conn: &mut MySqlConnection,
    customer_code: &str,
    items: &[Owned],
) -> Result<(), sqlx::Error> {
    if items.is_empty() {
        return Ok(());
    }
    let mut existing: HashMap<(String, String), i64> = customer_rows(&mut *conn, customer_code)
        .await?
        .into_iter()
        .map(|r| ((r.kind, r.graylog_id), i64::from(r.id)))
        .collect();
    let now = now_utc_naive();
    for item in items {
        let key = (item.kind.to_string(), item.graylog_id.clone());
        match existing.get(&key) {
            None => {
                let done = sqlx::query(
                    "INSERT INTO uba_provisioned_resource (customer_code, kind, graylog_id, \
                     title, source, shared, origin, created_at, updated_at, removed_at, \
                     removed_by_rollback_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(customer_code)
                .bind(item.kind)
                .bind(&item.graylog_id)
                .bind(&item.title)
                .bind(&item.source)
                .bind(item.shared)
                .bind(item.origin)
                .bind(now)
                .bind(now)
                .bind(None::<chrono::NaiveDateTime>)
                .bind(None::<i32>)
                .execute(&mut *conn)
                .await?;
                let id = i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX);
                existing.insert(key, id);
            }
            Some(id) => {
                sqlx::query(
                    "UPDATE uba_provisioned_resource SET title=?, source=?, shared=?, \
                     updated_at=?, removed_at=?, removed_by_rollback_id=? \
                     WHERE uba_provisioned_resource.id = ?",
                )
                .bind(&item.title)
                .bind(&item.source)
                .bind(item.shared)
                .bind(now)
                .bind(None::<chrono::NaiveDateTime>)
                .bind(None::<i32>)
                .bind(*id)
                .execute(&mut *conn)
                .await?;
            }
        }
    }
    Ok(())
}

/// `active(session, customer_code)`: the records not removed yet — one
/// customer's, or every customer's.
pub async fn active(db: &Db, customer_code: Option<&str>) -> Result<Vec<Row>, sqlx::Error> {
    match customer_code {
        Some(code) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM uba_provisioned_resource \
                 WHERE uba_provisioned_resource.removed_at IS NULL \
                 AND uba_provisioned_resource.customer_code = ?"
            ))
            .bind(code)
            .fetch_all(db.pool())
            .await
        }
        None => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM uba_provisioned_resource \
                 WHERE uba_provisioned_resource.removed_at IS NULL"
            ))
            .fetch_all(db.pool())
            .await
        }
    }
}

/// `mark_removed(session, customer_code, items, rollback_id)`: mark the
/// removed objects, recording (`adopted`) those setup never recorded (no
/// commit).
pub async fn mark_removed(
    conn: &mut MySqlConnection,
    customer_code: &str,
    items: &[Owned],
    rollback_id: i64,
) -> Result<(), sqlx::Error> {
    let adopted: Vec<Owned> = items
        .iter()
        .filter(|i| i.origin == "adopted")
        .cloned()
        .collect();
    record(&mut *conn, customer_code, &adopted).await?;
    let now = now_utc_naive();
    for row in customer_rows(&mut *conn, customer_code).await? {
        if items
            .iter()
            .any(|i| i.kind == row.kind && i.graylog_id == row.graylog_id)
        {
            sqlx::query(
                "UPDATE uba_provisioned_resource SET removed_at=?, removed_by_rollback_id=? \
                 WHERE uba_provisioned_resource.id = ?",
            )
            .bind(now)
            .bind(rollback_id)
            .bind(row.id)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}
