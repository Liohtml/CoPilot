//! `copilot doctor`'s scheduler checks: who owns the schedule here, and
//! whether the Python backend's APScheduler agrees.
//!
//! The Python switch (`COPILOT_PY_SCHEDULER`) is not visible from here, but
//! its effect is: a running APScheduler keeps every scheduled job's
//! `apscheduler_jobs.next_run_time` ahead of the clock (it moves each one on
//! as it comes due, a skipped tick included), a stopped one leaves them to
//! fall behind. So the store is watched:
//!
//! - a scheduled job more than [`OVERDUE`] behind → APScheduler is not
//!   running;
//! - else, when the earliest next run time is within [`WATCH_LIMIT`], wait
//!   for it (plus [`SETTLE`]) and read it again: moved on → running, still
//!   there → not running;
//! - else (every next run further away) → not observable now.
//!
//! A mismatch is a failure: APScheduler running while this service owns the
//! schedule (both would run every enabled job, serialized only by the run
//! lock), or not running under the hand-over (the jobs with an enabled row
//! would run nowhere).

use std::time::Duration;

use copilot_db::Db;
use copilot_db::scheduler as db;

use crate::functions;
use crate::job::Mode;
use crate::runner::Scheduler;
use crate::trigger;

/// How far behind the clock a scheduled job proves APScheduler idle.
pub const OVERDUE: Duration = Duration::from_secs(90);
/// How long the check waits for the earliest next run time, at most.
pub const WATCH_LIMIT: Duration = Duration::from_secs(75);
/// How long after that run time it reads again.
pub const SETTLE: Duration = Duration::from_secs(10);

/// What APScheduler's store says about APScheduler.
#[derive(Debug, Clone, PartialEq)]
pub enum Liveness {
    /// No `apscheduler_jobs` table: APScheduler never started on this
    /// database.
    NoStore,
    /// No job is scheduled in the store (none, or all paused).
    NothingScheduled,
    /// A scheduled job's next run time moved on while watched.
    Running,
    /// A scheduled job's next run time is behind the clock (the job id and
    /// by how many seconds).
    Idle(String, i64),
    /// Every next run time is further away than the check waits.
    Unknown(i64),
}

fn now_secs() -> f64 {
    trigger::timestamp(trigger::now_us())
}

/// Watch APScheduler's store (`wait`: whether the check may wait for the
/// earliest next run time).
pub async fn apscheduler_liveness(db: &Db, wait: bool) -> Result<Liveness, copilot_db::DbError> {
    let Some(rows) = db::stored_next_run_times(db).await? else {
        return Ok(Liveness::NoStore);
    };
    let scheduled: Vec<(String, f64)> = rows
        .into_iter()
        .filter_map(|(id, at)| at.map(|t| (id, t)))
        .collect();
    let now = now_secs();
    if let Some((id, at)) = scheduled
        .iter()
        .filter(|(_, at)| *at < now - OVERDUE.as_secs_f64())
        .min_by(|a, b| a.1.total_cmp(&b.1))
    {
        #[allow(clippy::cast_possible_truncation)]
        return Ok(Liveness::Idle(id.clone(), (now - at) as i64));
    }
    let Some((id, earliest)) = scheduled.iter().min_by(|a, b| a.1.total_cmp(&b.1)).cloned() else {
        return Ok(Liveness::NothingScheduled);
    };
    let ahead = earliest - now;
    #[allow(clippy::cast_possible_truncation)]
    let ahead_secs = ahead as i64;
    if !wait || ahead > WATCH_LIMIT.as_secs_f64() {
        return Ok(Liveness::Unknown(ahead_secs));
    }
    let sleep = Duration::from_secs_f64(ahead.max(0.0)) + SETTLE;
    tokio::time::sleep(sleep).await;
    let again = db::stored_next_run_times(db)
        .await?
        .unwrap_or_default()
        .into_iter()
        .find(|(i, _)| *i == id)
        .and_then(|(_, at)| at);
    Ok(match again {
        Some(at) if at > earliest => Liveness::Running,
        // Removed or paused meanwhile: someone ran a write against it.
        None => Liveness::Running,
        Some(at) => {
            #[allow(clippy::cast_possible_truncation)]
            let behind = (now_secs() - at) as i64;
            Liveness::Idle(id, behind)
        }
    })
}

/// The job releases before this one disabled at every Python start while
/// APScheduler kept running it (`schedule_enabled_jobs`' list).
pub const CATO_JOB: &str = "invoke_cato_integration_collect";

/// The warning for a Cato row still disabled that way: the Python start that
/// repairs it (`_repair_cato_row`) runs only while APScheduler is on, and the
/// ownership cannot tell that disabling from a pause of its own.
pub const CATO_WARNING: &str = "warn invoke_cato_integration_collect's row is disabled while \
     APScheduler's stored job is scheduled: releases before this one disabled it at every Python \
     start while APScheduler kept running it — Start it in the Scheduler UI unless it was paused \
     here on purpose";

/// One line of the report and whether it is a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The text after `scheduler   `.
    pub text: String,
    /// A mismatch.
    pub failure: bool,
}

fn line(text: impl Into<String>, failure: bool) -> Line {
    Line {
        text: text.into(),
        failure,
    }
}

/// The verdict for `mode` on what the store shows.
pub fn verdict(mode: Mode, live: &Liveness) -> Line {
    match (mode, live) {
        (Mode::Rust, Liveness::Running) => line(
            "FAIL APScheduler is running in the Python backend while this service owns the \
             schedule: set COPILOT_PY_SCHEDULER=false there (both would run every enabled job)",
            true,
        ),
        (Mode::Rust, Liveness::Idle(id, behind)) => line(
            format!("ok   APScheduler is idle ({id} is {behind}s behind in its store)"),
            false,
        ),
        (Mode::Rust, Liveness::NoStore | Liveness::NothingScheduled) => {
            line("ok   APScheduler has no scheduled job", false)
        }
        (Mode::Handover, Liveness::Running) => line("ok   APScheduler is running", false),
        (Mode::Handover, Liveness::Idle(id, behind)) => line(
            format!(
                "FAIL APScheduler is not running ({id} is {behind}s behind in its store) while it \
                 owns the schedule: set COPILOT_SCHEDULER_OWNER=rust here (with \
                 COPILOT_PY_SCHEDULER=false on the Python backend), or start its scheduler — the \
                 jobs with an enabled row run nowhere"
            ),
            true,
        ),
        (Mode::Handover, Liveness::NoStore) => line(
            "FAIL APScheduler never started on this database (no apscheduler_jobs): the jobs it \
             owns run nowhere",
            true,
        ),
        (Mode::Handover, Liveness::NothingScheduled) => {
            line("ok   APScheduler has no scheduled job", false)
        }
        (_, Liveness::Unknown(ahead)) => line(
            format!(
                "?    APScheduler's next run is {ahead}s away: whether it runs is not observable \
                 now"
            ),
            false,
        ),
    }
}

/// The report: the owner, what this service schedules, APScheduler's state,
/// and under the ownership the stored jobs it will not run (and a Cato row an
/// older release left disabled).
pub async fn report(s: &Scheduler, wait: bool) -> Vec<Line> {
    let mut out = vec![line(
        format!(
            "owner={} ({})",
            s.mode().as_str(),
            match s.mode() {
                Mode::Rust => "every job with an enabled row runs here",
                Mode::Handover => "APScheduler owns the schedule; jobs run here once handed over",
            }
        ),
        false,
    )];
    match apscheduler_liveness(s.db(), wait).await {
        Ok(live) => out.push(verdict(s.mode(), &live)),
        Err(e) => out.push(line(
            format!("FAIL cannot read apscheduler_jobs: {e}"),
            true,
        )),
    }
    if s.mode() == Mode::Rust {
        if let Ok(Some(rows)) = db::stored_next_run_times(s.db()).await {
            let cato_scheduled = rows.iter().any(|(id, at)| id == CATO_JOB && at.is_some());
            if cato_scheduled {
                if let Ok(Some((false, _))) = db::owner_row(s.db(), CATO_JOB).await {
                    out.push(line(CATO_WARNING, false));
                }
            }
            let orphans: Vec<String> = rows
                .into_iter()
                .map(|(id, _)| id)
                .filter(|id| functions::by_key(id).is_none())
                .collect();
            if !orphans.is_empty() {
                out.push(line(
                    format!(
                        "warn APScheduler's store holds {} job(s) whose id names no function, \
                         which only APScheduler could run: {}",
                        orphans.len(),
                        orphans.join(", ")
                    ),
                    false,
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mismatch_is_a_failure() {
        assert!(verdict(Mode::Rust, &Liveness::Running).failure);
        assert!(!verdict(Mode::Rust, &Liveness::Idle("x".into(), 100)).failure);
        assert!(verdict(Mode::Handover, &Liveness::Idle("x".into(), 100)).failure);
        assert!(!verdict(Mode::Handover, &Liveness::Running).failure);
        assert!(verdict(Mode::Handover, &Liveness::NoStore).failure);
        assert!(!verdict(Mode::Rust, &Liveness::Unknown(500)).failure);
    }
}
