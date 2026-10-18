//! The Scheduler's writes — `POST /add`, `PUT /update/{id}`, `DELETE /{id}`,
//! `POST /start/{id}`, `POST /pause/{id}`, `add_scheduler_jobs` (the
//! integrations' provisioning, `/provisioning_jobs`, Mimecast's
//! `/invoke/scheduler/*`) — step by step as `routes/scheduler.py` and
//! `scheduler.py` take them.
//!
//! Under the hand-over ([`Mode::Handover`]) APScheduler, in the Python
//! process, owns the schedule: each write hands APScheduler's own call to it
//! ([`crate::handoff`]) at the point the Python route makes it, does the
//! `scheduled_job_metadata` statements itself, and brings this service's grid
//! along (a job handed over here is rescheduled here). Under the ownership
//! ([`Mode::Rust`]) nothing reaches Python: the rows are the job store — a
//! job id with a row is a job, its flag says whether it is paused — and the
//! write edits them and this service's grid.
//!
//! Differences by design (§4): a negative interval is refused (APScheduler
//! accepts it and its scheduler then loops for ever); under the ownership a
//! job's id must be its function's key, since the rows have no function
//! column to remember another one by.

use copilot_db::scheduler::{self as db, Upsert};
use copilot_web::{ApiError, CurrentUser};

use crate::functions;
use crate::handoff::{self, ApsOp};
use crate::job::Mode;
use crate::runner::Scheduler;
use crate::trigger::{IntervalError, IntervalTrigger, now_us};

/// The refusal of a job whose id is not its function under the ownership.
pub const ID_IS_NOT_THE_FUNCTION: &str = "With COPILOT_SCHEDULER_OWNER=rust a job is scheduled under its function's name: \
     scheduled_job_metadata has no column to keep another function for it";

/// What a write that finds its job first answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// The job existed; the write was made.
    Done,
    /// `{"success": False, "message": "Job not found"}`.
    NotFound,
}

/// `time_interval` as a trigger takes it: a negative one is refused (400), an
/// `OverflowError` is the bare 500 it is in Python.
pub fn checked_minutes(minutes: i128) -> Result<i64, ApiError> {
    match IntervalTrigger::new(minutes, now_us()) {
        Ok(_) => i64::try_from(minutes).map_err(|_| ApiError::internal("OverflowError")),
        Err(IntervalError::Negative) => {
            Err(ApiError::bad_request(crate::trigger::NEGATIVE_INTERVAL))
        }
        Err(e @ IntervalError::Overflow(_)) => Err(ApiError::internal(e)),
    }
}

/// `get_function_by_name(name)`: its key, or the `ValueError`'s 400.
pub fn function_key(name: &str) -> Result<&'static str, ApiError> {
    functions::by_key(name)
        .map(|f| f.key)
        .ok_or_else(|| ApiError::bad_request(functions::unknown_function(name)))
}

fn missing_row(what: &str) -> ApiError {
    ApiError::internal(format!(
        "{what}: the job has no scheduled_job_metadata row (Python's AttributeError / \
         UnmappedInstanceError)"
    ))
}

/// `POST /scheduler/add`.
pub async fn add(
    s: &Scheduler,
    user: &CurrentUser,
    job_id: &str,
    function_name: &str,
    minutes: i128,
    extra_data: Option<&str>,
) -> Result<(), ApiError> {
    function_key(function_name)?;
    let minutes = checked_minutes(minutes)?;
    match s.mode() {
        Mode::Handover => {
            handoff::apscheduler_ops(
                s.legacy(),
                &user.bearer,
                &[ApsOp::add(job_id, function_name, minutes, true)],
            )
            .await?;
        }
        Mode::Rust if job_id != function_name => {
            return Err(ApiError::bad_request(ID_IS_NOT_THE_FUNCTION));
        }
        Mode::Rust => {}
    }
    let _schedule = s.lock_schedule().await;
    db::insert_metadata(s.db(), job_id, minutes, extra_data).await?;
    s.refresh(job_id, true).await?;
    tracing::info!(job_id, "Job added successfully");
    Ok(())
}

/// Whether the job exists, the way the route asks: APScheduler's
/// `find_job_by_id` under the hand-over (the stored ids, exactly), this
/// service's job set under the ownership.
async fn exists(s: &Scheduler, job_id: &str) -> Result<bool, ApiError> {
    match s.mode() {
        Mode::Handover => Ok(db::stored_job_exact(s.db(), job_id).await?.unwrap_or(false)),
        Mode::Rust => {
            s.ensure_loaded().await?;
            Ok(s.scheduled(job_id))
        }
    }
}

/// `PUT /scheduler/update/{job_id}`: the job found, rescheduled, then
/// `manage_job_metadata(update)` (twice in Python: the same values).
pub async fn update(
    s: &Scheduler,
    user: &CurrentUser,
    job_id: &str,
    minutes: i128,
    extra_data: Option<&str>,
) -> Result<Found, ApiError> {
    if !exists(s, job_id).await? {
        tracing::error!(job_id, "Job not found for updating");
        return Ok(Found::NotFound);
    }
    let minutes = checked_minutes(minutes)?;
    if s.mode() == Mode::Handover {
        let found = handoff::apscheduler_ops(
            s.legacy(),
            &user.bearer,
            &[ApsOp::reschedule(job_id, minutes)],
        )
        .await?;
        if found.first() != Some(&true) {
            return Ok(Found::NotFound);
        }
    }
    let _schedule = s.lock_schedule().await;
    if !db::update_metadata_first(s.db(), job_id, minutes, extra_data).await? {
        return Err(missing_row("update"));
    }
    s.refresh(job_id, true).await?;
    tracing::info!(job_id, "Job updated successfully");
    Ok(Found::Done)
}

/// `DELETE /scheduler/{job_id}`: the job removed, then its first row.
///
/// Under the ownership the rows are the job store: a job `/add` gave several
/// rows keeps being a job (on its next row) until each is deleted.
pub async fn delete(s: &Scheduler, user: &CurrentUser, job_id: &str) -> Result<Found, ApiError> {
    match s.mode() {
        Mode::Handover => {
            let found = handoff::apscheduler_ops(
                s.legacy(),
                &user.bearer,
                &[ApsOp::simple("remove", job_id)],
            )
            .await?;
            if found.first() != Some(&true) {
                tracing::error!(job_id, "Job not found for deletion");
                return Ok(Found::NotFound);
            }
        }
        Mode::Rust => {
            if !exists(s, job_id).await? {
                tracing::error!(job_id, "Job not found for deletion");
                return Ok(Found::NotFound);
            }
        }
    }
    let _schedule = s.lock_schedule().await;
    if !db::delete_metadata_first(s.db(), job_id).await? {
        return Err(missing_row("delete"));
    }
    s.refresh(job_id, false).await?;
    tracing::info!(job_id, "Job deleted successfully");
    Ok(Found::Done)
}

/// `POST /scheduler/pause/{job_id}`. Under the hand-over APScheduler pauses
/// its job and, for a job this build can run, the deciding row is disabled
/// — the hand-over switch; under the ownership the row alone pauses it.
pub async fn pause(s: &Scheduler, user: &CurrentUser, job_id: &str) -> Result<Found, ApiError> {
    match s.mode() {
        Mode::Handover => {
            let found = handoff::apscheduler_ops(
                s.legacy(),
                &user.bearer,
                &[ApsOp::simple("pause", job_id)],
            )
            .await?;
            if found.first() != Some(&true) {
                tracing::error!(job_id, "Job not found for pausing");
                return Ok(Found::NotFound);
            }
            if s.knows(job_id) {
                let _schedule = s.lock_schedule().await;
                if db::set_enabled(s.db(), job_id, false).await? == Some(true) {
                    let to = if s.opted_in(job_id) {
                        "this service"
                    } else {
                        "nobody (not opted in here)"
                    };
                    tracing::info!(job_id, to, "scheduled job disabled in APScheduler");
                }
                s.refresh(job_id, false).await?;
            }
        }
        Mode::Rust => {
            if !exists(s, job_id).await? {
                tracing::error!(job_id, "Job not found for pausing");
                return Ok(Found::NotFound);
            }
            let _schedule = s.lock_schedule().await;
            db::set_enabled(s.db(), job_id, false).await?;
            s.refresh(job_id, false).await?;
        }
    }
    tracing::info!(job_id, "Job paused successfully");
    Ok(Found::Done)
}

/// `POST /scheduler/start/{job_id}`. Under the hand-over the row of a job
/// this build can run is enabled first (this service stops before
/// APScheduler resumes) and restored when APScheduler has no such job.
pub async fn start(s: &Scheduler, user: &CurrentUser, job_id: &str) -> Result<Found, ApiError> {
    match s.mode() {
        Mode::Handover => {
            let before = if s.knows(job_id) {
                let _schedule = s.lock_schedule().await;
                let before = db::set_enabled(s.db(), job_id, true).await?;
                s.refresh(job_id, false).await?;
                before
            } else {
                None
            };
            let found = handoff::apscheduler_ops(
                s.legacy(),
                &user.bearer,
                &[ApsOp::simple("resume", job_id)],
            )
            .await;
            let found = match found {
                Ok(f) => f.first() == Some(&true),
                Err(e) => {
                    restore(s, job_id, before).await?;
                    return Err(e);
                }
            };
            if !found {
                restore(s, job_id, before).await?;
                tracing::error!(job_id, "Job not found for starting");
                return Ok(Found::NotFound);
            }
            if before == Some(false) {
                tracing::info!(job_id, "scheduled job handed back to APScheduler");
            }
        }
        Mode::Rust => {
            if !exists(s, job_id).await? {
                tracing::error!(job_id, "Job not found for starting");
                return Ok(Found::NotFound);
            }
            let _schedule = s.lock_schedule().await;
            db::set_enabled(s.db(), job_id, true).await?;
            s.refresh(job_id, false).await?;
        }
    }
    tracing::info!(job_id, "Job started successfully");
    Ok(Found::Done)
}

async fn restore(s: &Scheduler, job_id: &str, before: Option<bool>) -> Result<(), ApiError> {
    if before == Some(false) {
        let _schedule = s.lock_schedule().await;
        db::set_enabled(s.db(), job_id, false).await?;
        s.refresh(job_id, false).await?;
    }
    Ok(())
}

/// One job of `add_scheduler_jobs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRequest {
    /// `function_name`.
    pub function_name: String,
    /// `job_id`.
    pub job_id: String,
    /// `time_interval` (minutes; Pydantic's `int`, unbounded).
    pub time_interval: i128,
}

/// `add_scheduler_jobs(CreateSchedulerRequest(...))`: the function, the job
/// (`coalesce=True, max_instances=1`), then `add_job_metadata` — the job's
/// one row updated and enabled, or inserted (several rows:
/// `MultipleResultsFound`, a bare 500 after the job was added). Enabling the
/// row hands a handed-over job back to APScheduler, as in Python.
pub async fn add_scheduler_job(
    s: &Scheduler,
    user: &CurrentUser,
    job: &JobRequest,
) -> Result<(), ApiError> {
    function_key(&job.function_name)?;
    let minutes = checked_minutes(job.time_interval)?;
    match s.mode() {
        Mode::Handover => {
            handoff::apscheduler_ops(
                s.legacy(),
                &user.bearer,
                &[ApsOp::add(&job.job_id, &job.function_name, minutes, false)],
            )
            .await?;
        }
        Mode::Rust if job.job_id != job.function_name => {
            return Err(ApiError::bad_request(ID_IS_NOT_THE_FUNCTION));
        }
        Mode::Rust => {}
    }
    let _schedule = s.lock_schedule().await;
    match db::upsert_metadata(s.db(), &job.job_id, minutes).await? {
        Upsert::Multiple => {
            return Err(ApiError::internal(format!(
                "MultipleResultsFound: several scheduled_job_metadata rows for {}",
                job.job_id
            )));
        }
        Upsert::Inserted | Upsert::Updated => {}
    }
    s.refresh(&job.job_id, true).await?;
    Ok(())
}

/// `add_scheduler_jobs` for each job, in order (the first failure stops).
pub async fn add_scheduler_jobs(
    s: &Scheduler,
    user: &CurrentUser,
    jobs: &[JobRequest],
) -> Result<(), ApiError> {
    for job in jobs {
        add_scheduler_job(s, user, job).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_are_checked_as_the_trigger_builds_them() {
        assert_eq!(checked_minutes(0).ok(), Some(0));
        assert_eq!(checked_minutes(1440).ok(), Some(1440));
        assert_eq!(
            checked_minutes(-1).map_err(|e| e.status().as_u16()),
            Err(400)
        );
        assert_eq!(
            checked_minutes(1_440_000_000_000).map_err(|e| e.status().as_u16()),
            Err(500)
        );
    }

    #[test]
    fn an_unknown_function_is_the_value_error() {
        let e = function_key("nope").unwrap_err();
        assert_eq!(e.status(), 400);
        assert!(
            e.to_string()
                .contains("has no entry in get_function_by_name")
        );
    }
}
