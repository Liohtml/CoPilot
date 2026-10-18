//! The scheduler's tables: `scheduled_job_metadata` (CoPilot's sidecar) and
//! `apscheduler_jobs`, APScheduler's own SQLAlchemy job store (read only).
//! APScheduler creates that table itself when the Python scheduler first
//! starts — Alembic does not own it, and the `schedulerjob` table the initial
//! migration created is unused — so the readers here answer `None` while it
//! does not exist rather than requiring it.
//!
//! The Rust service may take over a scheduled job from the Python backend.
//! Ownership is decided by data both processes read (see
//! `backend/app/schedulers/handover.py` and `copilot-scheduler`):
//!
//! - the **deciding row** is the job's `scheduled_job_metadata` row with the
//!   lowest id ([`owner_row`]); APScheduler runs the job while it is enabled
//!   or absent, this service only while it exists and is disabled (and the
//!   operator opted in here);
//! - every run, on either side, holds the MySQL named lock [`JobLock`] and
//!   re-reads the row under it, so a hand-over in the middle of a run never
//!   starts the other side.

use std::time::Duration;

use sqlx::MySql;
use sqlx::pool::PoolConnection;

use crate::{Db, DbError};

/// The lock name, computed by MySQL — the same expression as `handover.py`'s
/// `LOCK_NAME_SQL`: scoped to the database, 52 characters at most.
const LOCK_NAME_SQL: &str = "CONCAT('copilot_job:', SHA1(CONCAT(DATABASE(), '/', ?)))";

/// The deciding row's `(enabled, time_interval)` (minutes), if the job has one.
pub async fn owner_row(db: &Db, job_id: &str) -> Result<Option<(bool, i64)>, DbError> {
    let row = sqlx::query_as::<_, (bool, i32)>(
        "SELECT enabled, time_interval FROM scheduled_job_metadata WHERE job_id = ? \
         ORDER BY id LIMIT 1",
    )
    .bind(job_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.map(|(enabled, minutes)| (enabled, i64::from(minutes))))
}

/// The deciding rows of many jobs at once: `job id → (enabled, interval)`
/// for each id that has a row. One statement, each id compared with the
/// column as [`owner_row`] compares it (its collation decides).
pub async fn owner_rows(
    db: &Db,
    job_ids: &[&str],
) -> Result<std::collections::HashMap<String, (bool, i64)>, DbError> {
    let mut out = std::collections::HashMap::new();
    if job_ids.is_empty() {
        return Ok(out);
    }
    let one = "SELECT ? AS k, m.enabled, m.time_interval FROM scheduled_job_metadata AS m \
               WHERE m.id = (SELECT s.id FROM scheduled_job_metadata AS s WHERE s.job_id = ? \
               ORDER BY s.id LIMIT 1)";
    let sql = vec![one; job_ids.len()].join(" UNION ALL ");
    let mut q = sqlx::query_as::<_, (String, bool, i32)>(&sql);
    for id in job_ids {
        q = q.bind(*id).bind(*id);
    }
    for (k, enabled, minutes) in q.fetch_all(db.pool()).await? {
        out.insert(k, (enabled, i64::from(minutes)));
    }
    Ok(out)
}

/// `manage_job_metadata(session, job_id, "add", …)` (`POST /scheduler/add`):
/// a new row, enabled, whatever rows the job already has.
pub async fn insert_metadata(
    db: &Db,
    job_id: &str,
    minutes: i64,
    extra_data: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, extra_data, \
         enabled, job_description) VALUES (?, NULL, ?, ?, 1, NULL)",
    )
    .bind(job_id)
    .bind(minutes)
    .bind(extra_data)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// `manage_job_metadata(session, job_id, "update", time_interval=…,
/// extra_data=…)`: the first row `filter_by(job_id=…)` reads gets both
/// values; `false` when the job has no row (Python's `setattr(None, …)`).
pub async fn update_metadata_first(
    db: &Db,
    job_id: &str,
    minutes: i64,
    extra_data: Option<&str>,
) -> Result<bool, DbError> {
    let Some(row) = metadata_first(db, job_id).await? else {
        return Ok(false);
    };
    sqlx::query("UPDATE scheduled_job_metadata SET time_interval = ?, extra_data = ? WHERE id = ?")
        .bind(minutes)
        .bind(extra_data)
        .bind(row.id)
        .execute(db.pool())
        .await?;
    Ok(true)
}

/// `manage_job_metadata(session, job_id, "delete")`: the first row
/// `filter_by(job_id=…)` reads; `false` when there is none (Python's
/// `session.delete(None)`).
pub async fn delete_metadata_first(db: &Db, job_id: &str) -> Result<bool, DbError> {
    let Some(row) = metadata_first(db, job_id).await? else {
        return Ok(false);
    };
    sqlx::query("DELETE FROM scheduled_job_metadata WHERE id = ?")
        .bind(row.id)
        .execute(db.pool())
        .await?;
    Ok(true)
}

/// What [`upsert_metadata`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    /// The job had no row: one was inserted, enabled.
    Inserted,
    /// Its one row got the interval and was enabled.
    Updated,
    /// Several rows: `one_or_none()`'s `MultipleResultsFound`, nothing written.
    Multiple,
}

/// `add_job_metadata(request)` (`add_scheduler_jobs`' bookkeeping): the
/// job's one row (`one_or_none()`) gets the interval and is enabled, or a row
/// is inserted.
pub async fn upsert_metadata(db: &Db, job_id: &str, minutes: i64) -> Result<Upsert, DbError> {
    let ids: Vec<i32> = sqlx::query_scalar(
        "SELECT scheduled_job_metadata.id FROM scheduled_job_metadata \
         WHERE scheduled_job_metadata.job_id = ?",
    )
    .bind(job_id)
    .fetch_all(db.pool())
    .await?;
    match ids.as_slice() {
        [] => {
            sqlx::query(
                "INSERT INTO scheduled_job_metadata (job_id, last_success, time_interval, \
                 extra_data, enabled, job_description) VALUES (?, NULL, ?, NULL, 1, NULL)",
            )
            .bind(job_id)
            .bind(minutes)
            .execute(db.pool())
            .await?;
            Ok(Upsert::Inserted)
        }
        [id] => {
            sqlx::query(
                "UPDATE scheduled_job_metadata SET time_interval = ?, enabled = 1 WHERE id = ?",
            )
            .bind(minutes)
            .bind(id)
            .execute(db.pool())
            .await?;
            Ok(Upsert::Updated)
        }
        _ => Ok(Upsert::Multiple),
    }
}

/// Every row's job id, in id order (the ownership's job set: a job with a
/// row is a job).
pub async fn metadata_job_ids(db: &Db) -> Result<Vec<String>, DbError> {
    Ok(
        sqlx::query_scalar("SELECT job_id FROM scheduled_job_metadata ORDER BY id")
            .fetch_all(db.pool())
            .await?,
    )
}

/// `apscheduler_jobs`' `(id, next_run_time)` — what `copilot doctor` watches
/// to tell whether APScheduler is running. `None` without the table.
pub async fn stored_next_run_times(db: &Db) -> Result<Option<Vec<(String, Option<f64>)>>, DbError> {
    match sqlx::query_as::<_, (String, Option<f64>)>(
        "SELECT id, next_run_time FROM apscheduler_jobs ORDER BY id",
    )
    .fetch_all(db.pool())
    .await
    {
        Ok(rows) => Ok(Some(rows)),
        Err(e) if missing_table(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `last_success` of the deciding row (naive UTC), if any.
pub async fn last_success(db: &Db, job_id: &str) -> Result<Option<chrono::NaiveDateTime>, DbError> {
    Ok(sqlx::query_scalar::<_, Option<chrono::NaiveDateTime>>(
        "SELECT last_success FROM scheduled_job_metadata WHERE job_id = ? ORDER BY id LIMIT 1",
    )
    .bind(job_id)
    .fetch_optional(db.pool())
    .await?
    .flatten())
}

/// Stamp `last_success` on the deciding row, as `record_job_success` stamps
/// the first row it finds (the Scheduler UI's "last run").
pub async fn stamp_last_success(db: &Db, job_id: &str) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE scheduled_job_metadata SET last_success = ? WHERE job_id = ? ORDER BY id LIMIT 1",
    )
    .bind(copilot_core::time::now_utc_naive())
    .bind(job_id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Set the hand-over flag (`enabled`) on the deciding row; returns the value
/// it had, or `None` when the job has no row (nothing is written then).
pub async fn set_enabled(db: &Db, job_id: &str, enabled: bool) -> Result<Option<bool>, DbError> {
    let mut tx = db.pool().begin().await?;
    let row = sqlx::query_as::<_, (i32, bool)>(
        "SELECT id, enabled FROM scheduled_job_metadata WHERE job_id = ? ORDER BY id LIMIT 1 \
         FOR UPDATE",
    )
    .bind(job_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, before)) = row else {
        tx.rollback().await?;
        return Ok(None);
    };
    sqlx::query("UPDATE scheduled_job_metadata SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(before))
}

/// A `scheduled_job_metadata` row as the Scheduler routes project it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct JobMetadataRow {
    /// `id`.
    pub id: i32,
    /// `job_id`.
    pub job_id: String,
    /// `last_success` (naive UTC).
    pub last_success: Option<chrono::NaiveDateTime>,
    /// `time_interval` (minutes).
    pub time_interval: i32,
    /// `extra_data`.
    pub extra_data: Option<String>,
    /// `enabled`.
    pub enabled: bool,
    /// `job_description`.
    pub job_description: Option<String>,
}

/// `select(JobMetadata).filter_by(job_id=…)` then `.first()`: the same
/// statement (no `ORDER BY`, the column's collation decides what matches) and
/// its first row.
pub async fn metadata_first(db: &Db, job_id: &str) -> Result<Option<JobMetadataRow>, DbError> {
    Ok(sqlx::query_as::<_, JobMetadataRow>(
        "SELECT scheduled_job_metadata.id, scheduled_job_metadata.job_id, \
         scheduled_job_metadata.last_success, scheduled_job_metadata.time_interval, \
         scheduled_job_metadata.extra_data, scheduled_job_metadata.enabled, \
         scheduled_job_metadata.job_description \
         FROM scheduled_job_metadata WHERE scheduled_job_metadata.job_id = ?",
    )
    .bind(job_id)
    .fetch_optional(db.pool())
    .await?)
}

/// One `apscheduler_jobs` row: the job id and its pickled state.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct StoredJob {
    /// `id`.
    pub id: String,
    /// `job_state` (a pickle of `Job.__getstate__()`).
    pub job_state: Vec<u8>,
}

/// MySQL's "table doesn't exist" (1146).
fn missing_table(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("42S02"))
}

/// `SQLAlchemyJobStore._get_jobs()`: every job, the statement SQLAlchemy
/// emits (so MySQL orders same-time jobs alike), paused jobs not yet moved to
/// the end (the caller does what `_fix_paused_jobs_sorting` does). `None`
/// while APScheduler has not created its table.
pub async fn stored_jobs(db: &Db) -> Result<Option<Vec<StoredJob>>, DbError> {
    match sqlx::query_as::<_, StoredJob>(
        "SELECT apscheduler_jobs.id, apscheduler_jobs.job_state \nFROM apscheduler_jobs \
         ORDER BY apscheduler_jobs.next_run_time",
    )
    .fetch_all(db.pool())
    .await
    {
        Ok(rows) => Ok(Some(rows)),
        Err(e) if missing_table(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `SQLAlchemyJobStore.lookup_job(job_id)`: the column's collation decides,
/// so `PRUNE_AUDIT_LOG` finds `prune_audit_log` (as `scheduler.get_job` does).
/// The outer `None`: APScheduler has not created its table.
pub async fn lookup_stored_job(
    db: &Db,
    job_id: &str,
) -> Result<Option<Option<StoredJob>>, DbError> {
    match sqlx::query_as::<_, StoredJob>(
        "SELECT apscheduler_jobs.id, apscheduler_jobs.job_state \nFROM apscheduler_jobs \
         WHERE apscheduler_jobs.id = ?",
    )
    .bind(job_id)
    .fetch_optional(db.pool())
    .await
    {
        Ok(row) => Ok(Some(row)),
        Err(e) if missing_table(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `find_job_by_id(scheduler, job_id)`: whether a stored job's id equals
/// `job_id` exactly (Python compares the strings, not the column's
/// collation). `None` while APScheduler has not created its table.
pub async fn stored_job_exact(db: &Db, job_id: &str) -> Result<Option<bool>, DbError> {
    match sqlx::query_scalar::<_, String>(
        "SELECT apscheduler_jobs.id FROM apscheduler_jobs WHERE apscheduler_jobs.id = ?",
    )
    .bind(job_id)
    .fetch_all(db.pool())
    .await
    {
        Ok(ids) => Ok(Some(ids.iter().any(|id| id == job_id))),
        Err(e) if missing_table(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The first row's job id whose `job_id` matches `job_id` under the column's
/// collation (the ownership's `scheduler.get_job`: a lookup the store's
/// collation decides, as `SQLAlchemyJobStore.lookup_job` does).
pub async fn metadata_job_id_like(db: &Db, job_id: &str) -> Result<Option<String>, DbError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT job_id FROM scheduled_job_metadata WHERE job_id = ? ORDER BY id LIMIT 1",
    )
    .bind(job_id)
    .fetch_optional(db.pool())
    .await?)
}

/// The cross-process run lock of one job (`GET_LOCK`), held on a pooled
/// connection for as long as the run lasts.
///
/// Release it with [`JobLock::release`]. Dropped without that (a panic, a
/// cancelled run), the connection is closed instead of going back to the
/// pool, and MySQL drops the lock with the session — a pooled connection
/// still holding it would block the other scheduler until it was recycled.
#[derive(Debug)]
pub struct JobLock {
    conn: Option<PoolConnection<MySql>>,
    job_id: String,
}

impl JobLock {
    /// Try to take the lock, waiting up to `wait` (whole seconds; zero = try
    /// once). `None` when another session holds it.
    pub async fn acquire(db: &Db, job_id: &str, wait: Duration) -> Result<Option<Self>, DbError> {
        let mut conn = db.pool().acquire().await?;
        let wait_secs = i64::try_from(wait.as_secs()).unwrap_or(i64::MAX);
        let got: Option<i64> = sqlx::query_scalar(&format!("SELECT GET_LOCK({LOCK_NAME_SQL}, ?)"))
            .bind(job_id)
            .bind(wait_secs)
            .fetch_one(&mut *conn)
            .await?;
        if got == Some(1) {
            Ok(Some(Self {
                conn: Some(conn),
                job_id: job_id.to_string(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Release the lock and hand the connection back to the pool.
    pub async fn release(mut self) {
        let Some(mut conn) = self.conn.take() else {
            return;
        };
        let released: Result<Option<i64>, sqlx::Error> =
            sqlx::query_scalar(&format!("SELECT RELEASE_LOCK({LOCK_NAME_SQL})"))
                .bind(&self.job_id)
                .fetch_one(&mut *conn)
                .await;
        if let Err(e) = released {
            tracing::error!(job_id = %self.job_id, err = %e,
                "cannot release the job's run lock; closing its connection");
            drop(conn.detach());
        }
    }
}

impl Drop for JobLock {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // Not released: never let the lock go back to the pool with it.
            drop(conn.detach());
        }
    }
}

/// Whether some session holds the job's run lock (`IS_USED_LOCK`).
pub async fn lock_in_use(db: &Db, job_id: &str) -> Result<bool, DbError> {
    let holder: Option<u64> = sqlx::query_scalar(&format!("SELECT IS_USED_LOCK({LOCK_NAME_SQL})"))
        .bind(job_id)
        .fetch_one(db.pool())
        .await?;
    Ok(holder.is_some())
}

/// `prune_audit_log`'s statement: `DELETE FROM audit_log WHERE timestamp <
/// :cutoff`; returns the rows deleted.
pub async fn delete_audit_log_before(
    db: &Db,
    cutoff: chrono::NaiveDateTime,
) -> Result<u64, DbError> {
    Ok(
        sqlx::query("DELETE FROM audit_log WHERE audit_log.timestamp < ?")
            .bind(cutoff)
            .execute(db.pool())
            .await?
            .rows_affected(),
    )
}
