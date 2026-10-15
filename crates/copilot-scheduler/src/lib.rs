//! # copilot-scheduler — scheduled jobs
//!
//! Port of `app/schedulers/`. CoPilot's jobs run in APScheduler inside the
//! Python process; this crate takes them over **one at a time, by explicit
//! hand-over**.
//!
//! ## The hand-over (no job ever runs in both schedulers)
//!
//! A job runs here only when the operator opted in (`COPILOT_RS_JOBS`, or
//! `COPILOT_RS_PALACE_JOBS=true` for the two palace jobs) **and** the job's
//! deciding `scheduled_job_metadata` row (lowest id) exists and is
//! **disabled**. APScheduler runs it only while that row is enabled or
//! absent — enforced at every run by the guard on the Python function itself
//! (`backend/app/schedulers/handover.py`), not only when jobs are scheduled.
//! The two conditions are disjoint ([`job::Owner::decide`]), and both sides
//! re-read the row under one MySQL named lock held for the whole run
//! (`copilot_db::scheduler::JobLock`), so a hand-over in the middle of a run
//! never starts the other side. Hand over by disabling the row, hand back by
//! enabling it.
//!
//! - [`job`]      — [`JobSpec`], the opt-in, ownership
//! - [`trigger`]  — APScheduler's interval trigger (grid, coalesce, one
//!   instance, misfire grace)
//! - [`runner`]   — [`Scheduler`]: one task per opted-in job, ticks,
//!   manual runs, shutdown
//! - [`jobs`]     — jobs that need only the database (`prune_audit_log`)

#![warn(missing_docs)]

pub mod job;
pub mod jobs;
pub mod runner;
pub mod trigger;

pub use job::{JobError, JobSpec, OptIn, Owner};
pub use runner::Scheduler;

#[cfg(test)]
mod tests {
    /// `RUST_CAPABLE_JOBS` of `backend/app/schedulers/handover.py`, read from
    /// the source (tests only: the Docker build has no `backend/`).
    fn python_rust_capable_jobs() -> Vec<String> {
        let src = include_str!("../../../backend/app/schedulers/handover.py");
        let Some(start) = src.find("RUST_CAPABLE_JOBS = (") else {
            return Vec::new();
        };
        let rest = &src[start..];
        let end = rest.find(')').unwrap_or(rest.len());
        rest[..end]
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn python_guards_exactly_the_jobs_this_crate_can_run() {
        let mut python = python_rust_capable_jobs();
        python.sort();
        let mut rust: Vec<String> = crate::job::PALACE_JOB_IDS
            .iter()
            .chain([crate::jobs::PRUNE_AUDIT_LOG].iter())
            .map(|s| (*s).to_string())
            .collect();
        rust.sort();
        assert_eq!(python, rust);
    }
}
