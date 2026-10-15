//! `scheduled_job_metadata` — the CoPilot sidecar of APScheduler's job store.
//!
//! The Rust service may take over a scheduled job from the Python backend.
//! The hand-over is decided by the row the Scheduler UI already edits: a job
//! runs here only when the operator opted in for this service *and* the
//! legacy row is disabled (or absent), so the two schedulers can never both
//! run it.

use crate::{Db, DbError};

/// The legacy row's `(enabled, time_interval)` (minutes), if any.
pub async fn legacy_job(db: &Db, job_id: &str) -> Result<Option<(bool, i64)>, DbError> {
    let row = sqlx::query_as::<_, (bool, i32)>(
        "SELECT enabled, time_interval FROM scheduled_job_metadata WHERE job_id = ? \
         ORDER BY id LIMIT 1",
    )
    .bind(job_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.map(|(enabled, minutes)| (enabled, i64::from(minutes))))
}

/// Stamp `last_success` (the Scheduler UI's "last run").
pub async fn stamp_last_success(db: &Db, job_id: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE scheduled_job_metadata SET last_success = ? WHERE job_id = ?")
        .bind(copilot_core::time::now_utc_naive())
        .bind(job_id)
        .execute(db.pool())
        .await?;
    Ok(())
}
