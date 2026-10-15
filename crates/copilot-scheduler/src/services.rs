//! What the Scheduler routes read, composed as `routes/scheduler.py` does.

use copilot_db::Db;
use copilot_db::scheduler as db;
use copilot_web::ApiError;

use crate::jobstore::{ApsJob, NextRun, decode_job};
use crate::schema::{JobOut, PAUSED_NEXT_RUN_ERROR};

/// Why the Rust side cannot answer a request itself.
#[derive(Debug)]
pub enum Unanswerable {
    /// A handled error, answered here.
    Api(ApiError),
    /// Only the Python backend can answer exactly (a job state this reader
    /// cannot decode, a timezone it cannot convert).
    Delegate(String),
}

impl From<ApiError> for Unanswerable {
    fn from(e: ApiError) -> Self {
        Unanswerable::Api(e)
    }
}

impl From<copilot_db::DbError> for Unanswerable {
    fn from(e: copilot_db::DbError) -> Self {
        Unanswerable::Api(e.into())
    }
}

/// APScheduler creates its table on its first start: until then only the
/// Python backend (which creates it) can answer.
fn no_store() -> Unanswerable {
    Unanswerable::Delegate("APScheduler's job store (apscheduler_jobs) does not exist yet".into())
}

/// `scheduler.get_jobs()`: every job in the store, in
/// `SQLAlchemyJobStore.get_all_jobs()` order — by `next_run_time` (MySQL puts
/// the paused jobs' NULLs first), then the paused ones moved to the end
/// (`_fix_paused_jobs_sorting`).
pub async fn all_jobs(db: &Db) -> Result<Vec<ApsJob>, Unanswerable> {
    let rows = db::stored_jobs(db).await?.ok_or_else(no_store)?;
    let mut jobs = Vec::with_capacity(rows.len());
    for row in rows {
        let job = decode_job(&row.job_state)
            .map_err(|e| Unanswerable::Delegate(format!("job {:?}: {e}", row.id)))?;
        jobs.push(job);
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
    db: &Db,
    search: Option<&str>,
    limit: Option<i64>,
) -> Result<Vec<JobOut>, Unanswerable> {
    let jobs = filter_and_limit(all_jobs(db).await?, search, limit);
    let mut out = Vec::with_capacity(jobs.len());
    for job in &jobs {
        let meta = db::metadata_first(db, &job.id).await?;
        out.push(JobOut::build(job, meta.as_ref()));
    }
    Ok(out)
}

/// `find_job_by_id`: the first job whose id equals `job_id` exactly.
pub async fn find_job(db: &Db, job_id: &str) -> Result<ApsJob, Unanswerable> {
    all_jobs(db)
        .await?
        .into_iter()
        .find(|j| j.id == job_id)
        .ok_or_else(|| Unanswerable::Api(ApiError::not_found("Job not found")))
}

/// `get_job_payload`.
pub async fn detail(db: &Db, job_id: &str) -> Result<JobOut, Unanswerable> {
    let job = find_job(db, job_id).await?;
    let meta = db::metadata_first(db, job_id).await?;
    Ok(JobOut::build(&job, meta.as_ref()))
}

/// `job.next_run_time` as the route answers it from APScheduler's store.
pub fn stored_next_run(job: &ApsJob) -> Result<String, Unanswerable> {
    match &job.next_run {
        NextRun::At(s) => Ok(s.clone()),
        // `JobsNextRunResponse(next_run_time=None)` raises a ValidationError,
        // which the ValueError handler turns into a 400.
        NextRun::Paused => Err(Unanswerable::Api(ApiError::bad_request(
            PAUSED_NEXT_RUN_ERROR,
        ))),
        NextRun::Unconvertible => Err(Unanswerable::Delegate(format!(
            "job {:?}: next run time in a timezone this service does not convert",
            job.id
        ))),
    }
}

/// `scheduler.get_job(job_id)` (the store's lookup, so the column's
/// collation decides) — `None` when there is no such job.
pub async fn lookup(db: &Db, job_id: &str) -> Result<Option<ApsJob>, Unanswerable> {
    let Some(row) = db::lookup_stored_job(db, job_id)
        .await?
        .ok_or_else(no_store)?
    else {
        return Ok(None);
    };
    decode_job(&row.job_state)
        .map(Some)
        .map_err(|e| Unanswerable::Delegate(format!("job {:?}: {e}", row.id)))
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
}
