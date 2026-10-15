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
