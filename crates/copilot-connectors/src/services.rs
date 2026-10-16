//! `ConnectorServices` (`app/connectors/services.py`): reads, the update,
//! and the verification bookkeeping. Every write ends with
//! `ConnectorCache::invalidate` after its commit, as in Python; the other
//! process learns of it through the cache's change check.

use std::collections::HashMap;

use chrono::NaiveDateTime;

use copilot_db::connectors::{self as db, ConnectorRow};
use copilot_db::{Db, DbError};

use crate::schema::{ConnectorHistoryOut, ConnectorOut, UpdateConnector};

/// `connectorhistory` rows of `ids`, as `selectinload(history_logs)` reads
/// them: one `IN` query, no `ORDER BY` (MySQL walks its `connector_id`
/// index, so rows come back by connector, then id).
pub async fn history(
    db: &Db,
    ids: &[i32],
) -> Result<HashMap<i32, Vec<ConnectorHistoryOut>>, DbError> {
    let mut out: HashMap<i32, Vec<ConnectorHistoryOut>> = HashMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let marks = vec!["?"; ids.len()].join(", ");
    let sql = format!(
        "SELECT id, connector_id, change_timestamp, change_description FROM connectorhistory \
         WHERE connector_id IN ({marks})"
    );
    let mut q = sqlx::query_as::<_, ConnectorHistoryOut>(&sql);
    for id in ids {
        q = q.bind(id);
    }
    for row in q.fetch_all(db.pool()).await? {
        out.entry(row.connector_id).or_default().push(row);
    }
    Ok(out)
}

/// `fetch_all_connectors`: every row with its history, unordered like
/// `select(Connectors)`.
pub async fn list(db: &Db) -> Result<Vec<ConnectorOut>, DbError> {
    let rows = db::list_unordered(db).await?;
    let ids: Vec<i32> = rows.iter().map(|r| r.id).collect();
    let mut logs = history(db, &ids).await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let h = logs.remove(&r.id).unwrap_or_default();
            ConnectorOut::from_row(r, h)
        })
        .collect())
}

/// `fetch_connector_by_id`.
pub async fn get(db: &Db, id: i64) -> Result<Option<ConnectorOut>, DbError> {
    let Some(row) = db::find_by_id(db, id).await? else {
        return Ok(None);
    };
    let mut logs = history(db, &[row.id]).await?;
    let h = logs.remove(&row.id).unwrap_or_default();
    Ok(Some(ConnectorOut::from_row(row, h)))
}

/// The row and its history, for the write paths.
pub async fn load(
    db: &Db,
    id: i64,
) -> Result<Option<(ConnectorRow, Vec<ConnectorHistoryOut>)>, DbError> {
    let Some(row) = db::find_by_id(db, id).await? else {
        return Ok(None);
    };
    let mut logs = history(db, &[row.id]).await?;
    let h = logs.remove(&row.id).unwrap_or_default();
    Ok(Some((row, h)))
}

/// `update_connector_by_id`'s write: the five fields and the timestamp.
pub async fn write_update(
    db: &Db,
    id: i32,
    body: &UpdateConnector,
    now: NaiveDateTime,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE connectors SET connector_url = ?, connector_username = ?, connector_password = ?, \
         connector_api_key = ?, connector_extra_data = ?, connector_last_updated = ? WHERE id = ?",
    )
    .bind(&body.connector_url)
    .bind(&body.connector_username)
    .bind(&body.connector_password)
    .bind(&body.connector_api_key)
    .bind(&body.connector_extra_data)
    .bind(now)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// `verify_connector_by_id`'s write: the outcome and the timestamp.
pub async fn write_verified(
    db: &Db,
    id: i32,
    verified: bool,
    now: NaiveDateTime,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE connectors SET connector_verified = ?, connector_last_updated = ? WHERE id = ?",
    )
    .bind(verified)
    .bind(now)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}
