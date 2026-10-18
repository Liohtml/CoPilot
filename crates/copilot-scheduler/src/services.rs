//! What the Scheduler routes read, composed as `routes/scheduler.py` does.
//!
//! `scheduler.get_jobs()` is APScheduler's store under the hand-over
//! ([`all_jobs`] decodes `apscheduler_jobs`), and this service's grid under
//! the ownership (the jobs with a row, paused when it is disabled).

use copilot_db::scheduler as db;
use copilot_web::ApiError;

use crate::functions;
use crate::job::Mode;
use crate::jobstore::{ApsJob, NextRun, decode_job};
use crate::runner::Scheduler;
use crate::schema::{JobOut, PAUSED_NEXT_RUN_ERROR, pydantic_utc};
use crate::trigger;

fn undecodable(id: &str, e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(format!("apscheduler_jobs row {id:?}: {e}"))
}

/// A job of this service's grid as the routes need it.
fn grid_job(id: &str, next_run: Option<trigger::Micros>) -> ApsJob {
    ApsJob {
        id: id.to_string(),
        name: functions::by_key(id).map_or(id, |f| f.name).to_string(),
        func: String::new(),
        next_run: match next_run.and_then(trigger::to_utc) {
            Some(t) => NextRun::At(pydantic_utc(t)),
            None => NextRun::Paused,
        },
    }
}

/// `scheduler.get_jobs()`: under the hand-over every job in the store, in
/// `SQLAlchemyJobStore.get_all_jobs()` order — by `next_run_time` (MySQL puts
/// the paused jobs' NULLs first), then the paused ones moved to the end
/// (`_fix_paused_jobs_sorting`); no store yet is no job. Under the ownership
/// the grid, in the same order.
pub async fn all_jobs(s: &Scheduler) -> Result<Vec<ApsJob>, ApiError> {
    if s.mode() == Mode::Rust {
        s.ensure_loaded().await?;
        return Ok(s
            .listed()
            .into_iter()
            .map(|l| grid_job(l.id, l.next_run))
            .collect());
    }
    let Some(rows) = db::stored_jobs(s.db()).await? else {
        return Ok(Vec::new());
    };
    let mut jobs = Vec::with_capacity(rows.len());
    for row in rows {
        jobs.push(decode_job(&row.job_state).map_err(|e| undecodable(&row.id, e))?);
    }
    fix_paused_jobs_sorting(&mut jobs);
    Ok(jobs)
}

/// `_fix_paused_jobs_sorting`: the paused jobs ahead of the first scheduled
/// one go to the end, in their order.
pub fn fix_paused_jobs_sorting(jobs: &mut Vec<ApsJob>) {
    if let Some(i) = jobs.iter().position(|j| j.next_run.is_scheduled()) {
        if i > 0 {
            let paused: Vec<ApsJob> = jobs.drain(..i).collect();
            jobs.extend(paused);
        }
    }
}

/// `filter_and_limit(jobs, params, key=lambda job: f"{job.id or ''} {job.name or ''}")`.
pub fn filter_and_limit(
    jobs: Vec<ApsJob>,
    search: Option<&str>,
    limit: Option<i64>,
) -> Vec<ApsJob> {
    let mut jobs = jobs;
    if let Some(needle) = search.filter(|s| !s.is_empty()) {
        let needle = needle.to_lowercase();
        jobs.retain(|j| {
            format!("{} {}", j.id, j.name)
                .to_lowercase()
                .contains(&needle)
        });
    }
    if let Some(n) = limit {
        jobs.truncate(usize::try_from(n.max(0)).unwrap_or(usize::MAX));
    }
    jobs
}

/// `GET /scheduler` payloads, one metadata lookup per job like the route.
pub async fn list(
    s: &Scheduler,
    search: Option<&str>,
    limit: Option<i64>,
) -> Result<Vec<JobOut>, ApiError> {
    let jobs = filter_and_limit(all_jobs(s).await?, search, limit);
    let mut out = Vec::with_capacity(jobs.len());
    for job in &jobs {
        let meta = db::metadata_first(s.db(), &job.id).await?;
        out.push(JobOut::build(job, meta.as_ref()));
    }
    Ok(out)
}

/// `find_job_by_id`: the first job whose id equals `job_id` exactly.
pub async fn find_job(s: &Scheduler, job_id: &str) -> Result<ApsJob, ApiError> {
    all_jobs(s)
        .await?
        .into_iter()
        .find(|j| j.id == job_id)
        .ok_or_else(|| ApiError::not_found("Job not found"))
}

/// `get_job_payload`.
pub async fn detail(s: &Scheduler, job_id: &str) -> Result<JobOut, ApiError> {
    let job = find_job(s, job_id).await?;
    let meta = db::metadata_first(s.db(), job_id).await?;
    Ok(JobOut::build(&job, meta.as_ref()))
}

/// `job.next_run_time` as the route answers it.
pub fn stored_next_run(job: &ApsJob) -> Result<String, ApiError> {
    match &job.next_run {
        NextRun::At(s) => Ok(s.clone()),
        // `JobsNextRunResponse(next_run_time=None)` raises a ValidationError,
        // which the ValueError handler turns into a 400.
        NextRun::Paused => Err(ApiError::bad_request(PAUSED_NEXT_RUN_ERROR)),
        NextRun::Unconvertible => Err(ApiError::internal(format!(
            "job {:?}: a next run time in no time zone this service knows",
            job.id
        ))),
    }
}

/// `scheduler.get_job(job_id)` (the store's lookup, so the column's collation
/// decides; under the ownership the rows') — `None` when there is no such
/// job.
pub async fn lookup(s: &Scheduler, job_id: &str) -> Result<Option<ApsJob>, ApiError> {
    if s.mode() == Mode::Rust {
        s.ensure_loaded().await?;
        let Some(id) = db::metadata_job_id_like(s.db(), job_id).await? else {
            return Ok(None);
        };
        return Ok(s
            .listed()
            .into_iter()
            .find(|l| l.id == id)
            .map(|l| grid_job(l.id, l.next_run)));
    }
    let Some(row) = db::lookup_stored_job(s.db(), job_id).await?.flatten() else {
        return Ok(None);
    };
    decode_job(&row.job_state)
        .map(Some)
        .map_err(|e| undecodable(&row.id, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: &str, scheduled: bool) -> ApsJob {
        ApsJob {
            id: id.into(),
            name: format!("fn_{id}"),
            func: format!("m:fn_{id}"),
            next_run: if scheduled {
                NextRun::At("x".into())
            } else {
                NextRun::Paused
            },
        }
    }

    fn ids(jobs: &[ApsJob]) -> Vec<&str> {
        jobs.iter().map(|j| j.id.as_str()).collect()
    }

    #[test]
    fn paused_jobs_go_last() {
        let mut jobs = vec![
            job("p1", false),
            job("p2", false),
            job("a", true),
            job("b", true),
        ];
        fix_paused_jobs_sorting(&mut jobs);
        assert_eq!(ids(&jobs), ["a", "b", "p1", "p2"]);
        let mut all_paused = vec![job("p1", false), job("p2", false)];
        fix_paused_jobs_sorting(&mut all_paused);
        assert_eq!(ids(&all_paused), ["p1", "p2"]);
    }

    #[test]
    fn search_matches_id_or_name_case_insensitively() {
        let jobs = vec![
            job("Agent_Sync", true),
            job("prune", true),
            job("other", true),
        ];
        assert_eq!(
            ids(&filter_and_limit(jobs.clone(), Some("AGENT"), None)),
            ["Agent_Sync"]
        );
        assert_eq!(
            ids(&filter_and_limit(jobs.clone(), Some("fn_pr"), None)),
            ["prune"]
        );
        // Matches across the separating space: "<id> <name>".
        assert_eq!(
            ids(&filter_and_limit(jobs.clone(), Some("prune fn"), None)),
            ["prune"]
        );
        assert_eq!(
            ids(&filter_and_limit(jobs.clone(), Some(""), Some(2))).len(),
            2
        );
    }

    #[test]
    fn a_grid_job_is_listed_under_its_callable() {
        let j = grid_job("invoke_carbonblack_integration_collection", None);
        assert_eq!(j.name, "invoke_carbonblack_integration_collect");
        assert_eq!(j.next_run, NextRun::Paused);
    }
}
