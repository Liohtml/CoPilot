//! The job runner: one tokio task per opted-in job, APScheduler's interval
//! semantics ([`crate::trigger`]), the hand-over rule ([`Owner`]) checked at
//! every tick under the cross-process lock, `last_success` stamped only when
//! a run returned.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use copilot_db::Db;
use copilot_db::scheduler::{self as db, JobLock};

use crate::job::{JobError, JobSpec, OptIn, Owner};
use crate::trigger;

/// How long a run started by hand waits for a run in progress (the same as
/// `handover.MANUAL_LOCK_WAIT_SECONDS`).
pub const MANUAL_LOCK_WAIT: Duration = Duration::from_secs(10);

/// How often a waiting job re-reads its interval (an operator may change it
/// in the Scheduler UI).
pub const INTERVAL_POLL: Duration = Duration::from_secs(30);

/// How long shutdown waits for a run in progress before dropping it.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// What a scheduled tick did.
#[derive(Debug)]
pub enum Tick {
    /// The job ran (its result).
    Ran(Result<(), JobError>),
    /// The lock was held elsewhere: the other scheduler (or a manual run) is
    /// running the job. Skipped.
    Busy,
    /// Not this service's to run now.
    NotOwned(Owner),
    /// The database could not be asked; skipped.
    Error(copilot_db::DbError),
}

/// What a run started by hand did.
#[derive(Debug)]
pub enum ManualRun {
    /// It ran (what it returned, or its failure).
    Ran(Result<Option<serde_json::Value>, JobError>),
    /// Still running elsewhere after [`MANUAL_LOCK_WAIT`].
    Busy,
    /// This service does not own the job (any more): let APScheduler's
    /// process run it.
    NotOwned(Owner),
}

#[derive(Debug, Default)]
struct RunState {
    next_run: Option<DateTime<Utc>>,
    running: bool,
}

#[derive(Debug)]
struct Registered {
    spec: JobSpec,
    state: Mutex<RunState>,
}

#[derive(Debug)]
struct Inner {
    db: Db,
    opt_in: OptIn,
    jobs: BTreeMap<&'static str, Registered>,
}

/// The registry of jobs this build can run, and their runner. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Scheduler {
    inner: Arc<Inner>,
}

/// Clears `running` however a run ends (returned, failed, cancelled).
struct RunningFlag<'a>(&'a Registered);

impl<'a> RunningFlag<'a> {
    fn set(job: &'a Registered) -> Self {
        if let Ok(mut s) = job.state.lock() {
            s.running = true;
        }
        Self(job)
    }
}

impl Drop for RunningFlag<'_> {
    fn drop(&mut self) {
        if let Ok(mut s) = self.0.state.lock() {
            s.running = false;
        }
    }
}

/// One job's state as `copilot jobs` and the routes show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobStatus {
    /// Job id.
    pub id: &'static str,
    /// Opted in here.
    pub opted_in: bool,
    /// Who runs it now (`None` when the database could not be read).
    pub owner: Option<Owner>,
    /// The deciding row's interval (minutes), if there is a row.
    pub interval_minutes: Option<i64>,
    /// When this service runs it next (its loop is running).
    pub next_run: Option<DateTime<Utc>>,
    /// A run is in progress here.
    pub running: bool,
}

impl Scheduler {
    /// A scheduler over `jobs` with the operator's opt-in.
    pub fn new(db: Db, opt_in: OptIn, jobs: Vec<JobSpec>) -> Self {
        let jobs = jobs
            .into_iter()
            .map(|spec| {
                (
                    spec.id,
                    Registered {
                        spec,
                        state: Mutex::new(RunState::default()),
                    },
                )
            })
            .collect();
        Self {
            inner: Arc::new(Inner { db, opt_in, jobs }),
        }
    }

    /// Ids of every job this build can run.
    pub fn job_ids(&self) -> Vec<&'static str> {
        self.inner.jobs.keys().copied().collect()
    }

    /// Whether this build can run `job_id`.
    pub fn knows(&self, job_id: &str) -> bool {
        self.inner.jobs.contains_key(job_id)
    }

    /// Whether the operator opted `job_id` in here (and this build knows it).
    pub fn opted_in(&self, job_id: &str) -> bool {
        self.knows(job_id) && self.inner.opt_in.contains(job_id)
    }

    /// The opt-in as configured.
    pub fn opt_in(&self) -> &OptIn {
        &self.inner.opt_in
    }

    /// Who runs `job_id` now, from the deciding row.
    pub async fn owner(&self, job_id: &str) -> Result<Owner, copilot_db::DbError> {
        let row = db::owner_row(&self.inner.db, job_id).await?;
        Ok(Owner::decide(
            self.opted_in(job_id),
            row.map(|(enabled, _)| enabled),
        ))
    }

    /// When this service will run `job_id` next, if its loop is running.
    pub fn next_run(&self, job_id: &str) -> Option<DateTime<Utc>> {
        let job = self.inner.jobs.get(job_id)?;
        job.state.lock().ok().and_then(|s| s.next_run)
    }

    /// Status of every job this build knows.
    pub async fn status(&self) -> Vec<JobStatus> {
        let mut out = Vec::new();
        for (id, job) in &self.inner.jobs {
            let row = db::owner_row(&self.inner.db, id).await;
            let (next_run, running) = job
                .state
                .lock()
                .map(|s| (s.next_run, s.running))
                .unwrap_or((None, false));
            out.push(JobStatus {
                id,
                opted_in: self.opted_in(id),
                owner: row
                    .as_ref()
                    .ok()
                    .map(|r| Owner::decide(self.opted_in(id), r.map(|(e, _)| e))),
                interval_minutes: row.ok().flatten().map(|(_, m)| m),
                next_run,
                running,
            });
        }
        out
    }

    /// One scheduled tick of `job_id`: take the lock without waiting, check
    /// ownership under it, run, stamp `last_success` if the run returned.
    pub async fn tick(&self, job_id: &str) -> Tick {
        let Some(job) = self.inner.jobs.get(job_id) else {
            return Tick::NotOwned(Owner::Legacy);
        };
        let db = &self.inner.db;
        let lock = match JobLock::acquire(db, job_id, Duration::ZERO).await {
            Ok(Some(lock)) => lock,
            Ok(None) => return Tick::Busy,
            Err(e) => return Tick::Error(e),
        };
        let owner = match db::owner_row(db, job_id).await {
            Ok(row) => Owner::decide(self.opted_in(job_id), row.map(|(e, _)| e)),
            Err(e) => {
                lock.release().await;
                return Tick::Error(e);
            }
        };
        if owner != Owner::Rust {
            lock.release().await;
            return Tick::NotOwned(owner);
        }
        let result = {
            let _running = RunningFlag::set(job);
            (job.spec.run)().await.map(|_| ())
        };
        if result.is_ok() {
            if let Err(e) = db::stamp_last_success(db, job_id).await {
                tracing::warn!(job_id, err = %e, "cannot stamp last_success");
            }
        }
        lock.release().await;
        Tick::Ran(result)
    }

    /// `POST /scheduler/jobs/run/{id}` for a job this service owns: wait up
    /// to [`MANUAL_LOCK_WAIT`] for a run in progress, re-check ownership
    /// under the lock, run. `last_success` is stamped only where the Python
    /// function stamps it on a manual run.
    pub async fn run_now(&self, job_id: &str) -> Result<ManualRun, copilot_db::DbError> {
        let Some(job) = self.inner.jobs.get(job_id) else {
            return Ok(ManualRun::NotOwned(Owner::Legacy));
        };
        let db = &self.inner.db;
        let Some(lock) = JobLock::acquire(db, job_id, MANUAL_LOCK_WAIT).await? else {
            return Ok(ManualRun::Busy);
        };
        let owner = match db::owner_row(db, job_id).await {
            Ok(row) => Owner::decide(self.opted_in(job_id), row.map(|(e, _)| e)),
            Err(e) => {
                lock.release().await;
                return Err(e);
            }
        };
        if owner != Owner::Rust {
            lock.release().await;
            return Ok(ManualRun::NotOwned(owner));
        }
        let result = {
            let _running = RunningFlag::set(job);
            (job.spec.run)().await
        };
        if result.is_ok() && job.spec.manual_run_stamps {
            if let Err(e) = db::stamp_last_success(db, job_id).await {
                tracing::warn!(job_id, err = %e, "cannot stamp last_success");
            }
        }
        lock.release().await;
        Ok(ManualRun::Ran(result))
    }

    /// Run `job_id` once now, whoever owns it, serialized with every other
    /// run by the lock (the `copilot palace drain|sweep` commands: an
    /// operator's explicit request, like a manual run in Python).
    pub async fn run_exclusive(&self, job_id: &str) -> Result<ManualRun, copilot_db::DbError> {
        let Some(job) = self.inner.jobs.get(job_id) else {
            return Ok(ManualRun::NotOwned(Owner::Legacy));
        };
        let Some(lock) = JobLock::acquire(&self.inner.db, job_id, MANUAL_LOCK_WAIT).await? else {
            return Ok(ManualRun::Busy);
        };
        let result = {
            let _running = RunningFlag::set(job);
            (job.spec.run)().await
        };
        lock.release().await;
        Ok(ManualRun::Ran(result))
    }

    /// The deciding row's interval, or the job's default.
    async fn interval(&self, job: &Registered) -> Option<i64> {
        match db::owner_row(&self.inner.db, job.spec.id).await {
            Ok(Some((_, minutes))) => Some(minutes),
            Ok(None) => Some(job.spec.default_minutes),
            Err(e) => {
                tracing::warn!(job_id = job.spec.id, err = %e, "cannot read the job's interval");
                None
            }
        }
    }

    fn set_next(job: &Registered, next: Option<DateTime<Utc>>) {
        if let Ok(mut s) = job.state.lock() {
            s.next_run = next;
        }
    }

    /// Start a loop for every opted-in job; the handle completes once all
    /// loops have stopped after `cancel` (a run in progress gets
    /// [`SHUTDOWN_GRACE`] to finish).
    pub fn spawn(&self, cancel: CancellationToken) -> JoinHandle<()> {
        let ids: Vec<&'static str> = self
            .inner
            .jobs
            .keys()
            .copied()
            .filter(|id| self.opted_in(id))
            .collect();
        for id in self.inner.opt_in.unknown(&self.job_ids()) {
            tracing::warn!(
                job_id = id,
                "COPILOT_RS_JOBS names a job this build cannot run; ignored"
            );
        }
        let loops: Vec<JoinHandle<()>> = ids
            .into_iter()
            .map(|id| {
                tracing::info!(job_id = id,
                    "scheduled job opted in here; it runs while its scheduled_job_metadata row is disabled");
                let me = self.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move { me.job_loop(id, cancel).await })
            })
            .collect();
        tokio::spawn(async move {
            for l in loops {
                let _ = l.await;
            }
        })
    }

    async fn job_loop(&self, job_id: &'static str, cancel: CancellationToken) {
        let Some(job) = self.inner.jobs.get(job_id) else {
            return;
        };
        let mut minutes = self.interval(job).await.unwrap_or(job.spec.default_minutes);
        let mut every = trigger::interval_minutes(minutes);
        let last = match db::last_success(&self.inner.db, job_id).await {
            Ok(last) => last.map(|t| t.and_utc()),
            Err(e) => {
                tracing::warn!(job_id, err = %e, "cannot read the job's last success");
                None
            }
        };
        let mut anchor = trigger::first_fire(Utc::now(), every, last);
        let mut next = anchor;
        loop {
            Self::set_next(job, Some(next));
            // Wait for the fire time, noticing interval changes on the way.
            loop {
                let now = Utc::now();
                if now >= next {
                    break;
                }
                let wait = (next - now)
                    .to_std()
                    .unwrap_or(Duration::ZERO)
                    .min(INTERVAL_POLL);
                tokio::select! {
                    () = cancel.cancelled() => {
                        Self::set_next(job, None);
                        return;
                    }
                    () = tokio::time::sleep(wait) => {}
                }
                if let Some(m) = self.interval(job).await {
                    if m != minutes {
                        // Rescheduled (the Scheduler UI's update): a new grid
                        // from now, as `job.reschedule()` starts one.
                        tracing::info!(job_id, from = minutes, to = m, "job interval changed");
                        minutes = m;
                        every = trigger::interval_minutes(m);
                        anchor = Utc::now() + every;
                        next = anchor;
                        Self::set_next(job, Some(next));
                    }
                }
            }
            match trigger::due(next, every, Utc::now()) {
                Some(d) if d.missed => {
                    tracing::warn!(job_id, run_time = %d.run_time, "run time of job was missed");
                }
                Some(_) => {
                    let tick = self.tick(job_id);
                    tokio::pin!(tick);
                    let outcome = tokio::select! {
                        t = &mut tick => Some(t),
                        () = cancel.cancelled() => {
                            tracing::info!(job_id, "shutting down; waiting for the run in progress");
                            tokio::time::timeout(SHUTDOWN_GRACE, &mut tick).await.ok()
                        }
                    };
                    match outcome {
                        Some(Tick::Ran(Ok(()))) => tracing::debug!(job_id, "job ran"),
                        Some(Tick::Ran(Err(e))) => tracing::error!(job_id, err = %e, "job crashed"),
                        Some(Tick::Busy) => {
                            tracing::info!(job_id, "job is running elsewhere; skipping this tick");
                        }
                        Some(Tick::NotOwned(owner)) => {
                            tracing::debug!(
                                job_id,
                                owner = owner.as_str(),
                                "not handed over; idle"
                            );
                        }
                        Some(Tick::Error(e)) => {
                            tracing::warn!(job_id, err = %e, "cannot check the job's owner; skipping this tick");
                        }
                        None => tracing::warn!(job_id, "run abandoned at shutdown"),
                    }
                    if cancel.is_cancelled() {
                        Self::set_next(job, None);
                        return;
                    }
                }
                None => {}
            }
            next = trigger::next_after(anchor, every, Utc::now());
        }
    }
}
