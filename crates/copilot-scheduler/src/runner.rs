//! The job runner: APScheduler's scheduler loop on tokio.
//!
//! One dispatcher task holds the grid — per job its [`IntervalTrigger`] and
//! next run time — wakes at the earliest next run time (or when a write
//! route changed the grid, or every [`INTERVAL_POLL`] to re-read the rows),
//! and starts each due job as `_process_jobs` does ([`crate::trigger`]:
//! coalesce, one instance, the misfire grace). A started run is a [`tick`]:
//! the job's cross-process lock without waiting, the deciding row read
//! under it ([`Owner::decide_in`]), the run, `last_success` stamped if it
//! returned.
//!
//! Which jobs have a grid entry depends on the [`Mode`]:
//!
//! - **hand-over**: every opted-in job, from this process's start, on the
//!   row's interval (the job's default without a row); its ticks run only
//!   while the job is handed over;
//! - **ownership**: every job whose deciding row exists — enabled, it is
//!   scheduled; disabled, it is paused (no next run time) and a resume lands
//!   on its trigger's grid, as APScheduler's `resume_job` does.
//!
//! The rows are re-read every [`INTERVAL_POLL`]: a changed interval is a new
//! trigger from now (`job.reschedule()`), a flipped flag a pause or resume, a
//! new row a new job. The write routes change the grid at once
//! ([`Scheduler::refresh`]), under the same lock as that re-read.
//!
//! [`tick`]: Scheduler::tick

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use copilot_db::Db;
use copilot_db::scheduler::{self as db, JobLock};
use copilot_gateway::LegacyProxy;

use crate::job::{JobError, JobSpec, Mode, OptIn, Owner};
use crate::trigger::{self, IntervalError, IntervalTrigger, Micros};

/// How long a run started by hand waits for a run in progress (the same as
/// `handover.MANUAL_LOCK_WAIT_SECONDS`).
pub const MANUAL_LOCK_WAIT: Duration = Duration::from_secs(10);

/// How often the dispatcher re-reads the rows (an operator may change an
/// interval or a flag through the other backend, or by hand).
pub const INTERVAL_POLL: Duration = Duration::from_secs(30);

/// How long shutdown waits for the runs in progress before dropping them.
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
    /// This build has no such job.
    NotOwned(Owner),
}

#[derive(Debug, Default)]
struct RunState {
    running: bool,
}

#[derive(Debug)]
struct Registered {
    spec: JobSpec,
    state: Mutex<RunState>,
}

/// One job on the grid.
#[derive(Debug, Clone)]
struct Entry {
    trigger: IntervalTrigger,
    /// `None`: paused.
    next_run: Option<Micros>,
    /// The interval (minutes) the trigger was built from.
    minutes: i64,
    /// The deciding row's flag when last seen (`None`: no row).
    enabled: Option<bool>,
    /// Scheduled runs in progress (`max_instances=1`).
    instances: usize,
}

#[derive(Debug)]
struct Inner {
    db: Db,
    mode: Mode,
    opt_in: OptIn,
    jobs: BTreeMap<&'static str, Registered>,
    grid: Mutex<BTreeMap<&'static str, Entry>>,
    loaded: AtomicBool,
    changed: Notify,
    /// Serialises the rows' re-read with the write routes' grid changes.
    schedule: tokio::sync::Mutex<()>,
    legacy: Option<LegacyProxy>,
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
    /// Opted in here (always true under [`Mode::Rust`]).
    pub opted_in: bool,
    /// Who runs it now (`None` when the database could not be read).
    pub owner: Option<Owner>,
    /// The deciding row's interval (minutes), if there is a row.
    pub interval_minutes: Option<i64>,
    /// When this service runs it next (it is on the grid and not paused).
    pub next_run: Option<DateTime<Utc>>,
    /// A run is in progress here.
    pub running: bool,
}

/// A job as the ownership's listing shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// The job id.
    pub id: &'static str,
    /// Its next run time (`None`: paused).
    pub next_run: Option<Micros>,
}

/// Options beyond the jobs and the opt-in.
#[derive(Debug, Clone, Default)]
pub struct SchedulerOptions {
    /// Who owns the schedule.
    pub mode: Mode,
    /// The Python backend, which runs APScheduler under the hand-over.
    pub legacy: Option<LegacyProxy>,
}

impl Scheduler {
    /// A hand-over scheduler over `jobs` with the operator's opt-in.
    pub fn new(db: Db, opt_in: OptIn, jobs: Vec<JobSpec>) -> Self {
        Self::with_options(db, opt_in, jobs, SchedulerOptions::default())
    }

    /// A scheduler with its [`SchedulerOptions`].
    pub fn with_options(
        db: Db,
        opt_in: OptIn,
        jobs: Vec<JobSpec>,
        options: SchedulerOptions,
    ) -> Self {
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
            inner: Arc::new(Inner {
                db,
                mode: options.mode,
                opt_in,
                jobs,
                grid: Mutex::new(BTreeMap::new()),
                loaded: AtomicBool::new(false),
                changed: Notify::new(),
                schedule: tokio::sync::Mutex::new(()),
                legacy: options.legacy,
            }),
        }
    }

    /// Who owns the schedule.
    pub fn mode(&self) -> Mode {
        self.inner.mode
    }

    /// The Python backend, if configured.
    pub fn legacy(&self) -> Option<&LegacyProxy> {
        self.inner.legacy.as_ref()
    }

    /// The database.
    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    /// Ids of every job this build can run.
    pub fn job_ids(&self) -> Vec<&'static str> {
        self.inner.jobs.keys().copied().collect()
    }

    /// The registered id equal to `job_id`.
    pub fn key(&self, job_id: &str) -> Option<&'static str> {
        self.inner.jobs.get_key_value(job_id).map(|(k, _)| *k)
    }

    /// Whether this build can run `job_id`.
    pub fn knows(&self, job_id: &str) -> bool {
        self.inner.jobs.contains_key(job_id)
    }

    /// Whether `job_id` may run here: the operator opted it in (hand-over),
    /// or this service owns the schedule (and this build knows it).
    pub fn opted_in(&self, job_id: &str) -> bool {
        self.knows(job_id) && (self.inner.mode == Mode::Rust || self.inner.opt_in.contains(job_id))
    }

    /// The opt-in as configured.
    pub fn opt_in(&self) -> &OptIn {
        &self.inner.opt_in
    }

    /// Who runs `job_id` now, from the deciding row.
    pub async fn owner(&self, job_id: &str) -> Result<Owner, copilot_db::DbError> {
        let row = db::owner_row(&self.inner.db, job_id).await?;
        Ok(self.decide(job_id, row.map(|(enabled, _)| enabled)))
    }

    fn decide(&self, job_id: &str, row_enabled: Option<bool>) -> Owner {
        Owner::decide_in(self.inner.mode, self.opted_in(job_id), row_enabled)
    }

    /// Whether this process's own refresh timer for the cache job `job_id`
    /// should run: only while no scheduler here decides about the job — its
    /// row is enabled or absent under the hand-over (APScheduler runs the
    /// Python job, which refreshes only the Python process's copy), or it has
    /// no row under the ownership. Handed over, owned or paused, the job
    /// decides (and a pause stops the refresh).
    pub async fn timer_runs(&self, job_id: &str) -> bool {
        match db::owner_row(&self.inner.db, job_id).await {
            Ok(None) => true,
            Ok(Some((enabled, _))) => self.inner.mode == Mode::Handover && enabled,
            Err(e) => {
                tracing::warn!(job_id, err = %e, "cannot read the job's row; refreshing as before");
                true
            }
        }
    }

    /// When this service will run `job_id` next, if it is on the grid and
    /// not paused.
    pub fn next_run(&self, job_id: &str) -> Option<DateTime<Utc>> {
        let grid = self.inner.grid.lock().ok()?;
        grid.get(job_id)
            .and_then(|e| e.next_run)
            .and_then(trigger::to_utc)
    }

    /// Whether `job_id` is on the grid (under [`Mode::Rust`]: whether it is a
    /// job at all).
    pub fn scheduled(&self, job_id: &str) -> bool {
        self.inner.grid.lock().is_ok_and(|g| g.contains_key(job_id))
    }

    /// The grid as `scheduler.get_jobs()` lists it: by next run time (ties
    /// by id), the paused jobs last.
    pub fn listed(&self) -> Vec<Listed> {
        let Ok(grid) = self.inner.grid.lock() else {
            return Vec::new();
        };
        let mut scheduled: Vec<Listed> = Vec::new();
        let mut paused: Vec<Listed> = Vec::new();
        for (id, e) in grid.iter() {
            let item = Listed {
                id,
                next_run: e.next_run,
            };
            if e.next_run.is_some() {
                scheduled.push(item);
            } else {
                paused.push(item);
            }
        }
        scheduled.sort_by_key(|l| (l.next_run, l.id));
        scheduled.extend(paused);
        scheduled
    }

    /// Status of every job this build knows.
    pub async fn status(&self) -> Vec<JobStatus> {
        let rows = db::owner_rows(&self.inner.db, &self.job_ids()).await;
        let mut out = Vec::new();
        for (id, job) in &self.inner.jobs {
            let running = job.state.lock().map(|s| s.running).unwrap_or(false);
            let row = rows.as_ref().ok().map(|r| r.get(*id).copied());
            out.push(JobStatus {
                id,
                opted_in: self.opted_in(id),
                owner: row.map(|r| self.decide(id, r.map(|(e, _)| e))),
                interval_minutes: row.flatten().map(|(_, m)| m),
                next_run: self.next_run(id),
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
            Ok(row) => self.decide(job_id, row.map(|(e, _)| e)),
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

    /// `POST /scheduler/jobs/run/{id}`: an operator's run of `job_id`, here,
    /// whoever owns its schedule — as Python's manual run runs "whatever the
    /// row says": wait up to [`MANUAL_LOCK_WAIT`] for a run in progress (here
    /// or in APScheduler), run, stamp `last_success` only where the Python
    /// function stamps it on a manual run.
    pub async fn run_now(&self, job_id: &str) -> Result<ManualRun, copilot_db::DbError> {
        let Some(job) = self.inner.jobs.get(job_id) else {
            return Ok(ManualRun::NotOwned(Owner::Legacy));
        };
        let db = &self.inner.db;
        let Some(lock) = JobLock::acquire(db, job_id, MANUAL_LOCK_WAIT).await? else {
            return Ok(ManualRun::Busy);
        };
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
    /// run by the lock (the `copilot palace drain|sweep` commands), without
    /// any `last_success` stamp.
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

    /// Hold the schedule (the write routes: their row writes and grid
    /// changes against the dispatcher's re-read).
    pub async fn lock_schedule(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.schedule.lock().await
    }

    /// Load the grid from the rows unless the dispatcher already did (a
    /// route served before it, or a process that runs no dispatcher).
    pub async fn ensure_loaded(&self) -> Result<(), copilot_db::DbError> {
        if self.inner.loaded.load(Ordering::Acquire) {
            return Ok(());
        }
        let _schedule = self.lock_schedule().await;
        if self.inner.loaded.load(Ordering::Acquire) {
            return Ok(());
        }
        self.reconcile_locked().await
    }

    /// Re-read every row and bring the grid in line (hold the schedule).
    async fn reconcile_locked(&self) -> Result<(), copilot_db::DbError> {
        let rows = db::owner_rows(&self.inner.db, &self.job_ids()).await?;
        let now = trigger::now_us();
        if let Ok(mut grid) = self.inner.grid.lock() {
            for id in self.inner.jobs.keys() {
                self.apply(&mut grid, id, rows.get(*id).copied(), false, now);
            }
        }
        self.inner.loaded.store(true, Ordering::Release);
        self.inner.changed.notify_one();
        Ok(())
    }

    /// After a write route changed `job_id`'s rows (with the schedule held):
    /// read its deciding row and apply it — `restart` builds a new trigger
    /// from now (an add or a reschedule), else a changed interval does, and a
    /// flipped flag pauses or resumes.
    pub async fn refresh(&self, job_id: &str, restart: bool) -> Result<(), copilot_db::DbError> {
        let Some(id) = self.key(job_id) else {
            return Ok(());
        };
        let row = db::owner_row(&self.inner.db, id).await?;
        let now = trigger::now_us();
        if let Ok(mut grid) = self.inner.grid.lock() {
            self.apply(&mut grid, id, row, restart, now);
        }
        self.inner.changed.notify_one();
        Ok(())
    }

    /// Bring one job's grid entry in line with its deciding row.
    fn apply(
        &self,
        grid: &mut BTreeMap<&'static str, Entry>,
        id: &'static str,
        row: Option<(bool, i64)>,
        restart: bool,
        now: Micros,
    ) {
        let Some(job) = self.inner.jobs.get(id) else {
            return;
        };
        let wanted = match self.inner.mode {
            Mode::Handover => self.inner.opt_in.contains(id),
            Mode::Rust => row.is_some(),
        };
        if !wanted {
            if grid.remove(id).is_some() {
                tracing::info!(job_id = id, "job taken off the schedule");
            }
            return;
        }
        let minutes = row.map_or(job.spec.default_minutes, |(_, m)| m);
        let enabled = row.map(|(e, _)| e);
        // Paused on the grid only under the ownership (the hand-over's ticks
        // ask the row themselves).
        let paused = self.inner.mode == Mode::Rust && enabled != Some(true);
        let fresh = |minutes: i64| -> Option<IntervalTrigger> {
            match IntervalTrigger::new(i128::from(minutes), now) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::warn!(job_id = id, minutes, err = %e,
                        "the job's interval cannot be scheduled; left off the schedule");
                    None
                }
            }
        };
        match grid.get_mut(id) {
            None => {
                let Some(t) = fresh(minutes) else {
                    return;
                };
                grid.insert(
                    id,
                    Entry {
                        trigger: t,
                        next_run: (!paused).then_some(t.start),
                        minutes,
                        enabled,
                        instances: 0,
                    },
                );
                tracing::info!(job_id = id, minutes, paused, "job scheduled");
            }
            Some(e) => {
                if restart || e.minutes != minutes {
                    let Some(t) = fresh(minutes) else {
                        grid.remove(id);
                        return;
                    };
                    e.trigger = t;
                    e.minutes = minutes;
                    e.next_run = (!paused).then_some(t.start);
                    tracing::info!(job_id = id, minutes, "job rescheduled");
                } else if self.inner.mode == Mode::Rust && e.enabled != enabled {
                    e.next_run = if paused {
                        None
                    } else {
                        // `resume_job`: the trigger's next fire, on its grid.
                        e.trigger.next_fire(None, now)
                    };
                    tracing::info!(job_id = id, paused, "job paused or resumed");
                }
                e.enabled = enabled;
            }
        }
    }

    /// Start the dispatcher (until `cancel`); the handle completes once it
    /// has stopped and the runs in progress ended (each gets
    /// [`SHUTDOWN_GRACE`]).
    pub fn spawn(&self, cancel: CancellationToken) -> JoinHandle<()> {
        if self.inner.mode == Mode::Handover {
            for id in self.inner.opt_in.unknown(&self.job_ids()) {
                tracing::warn!(
                    job_id = id,
                    "COPILOT_RS_JOBS names a job this build cannot run; ignored"
                );
            }
            for id in self.job_ids().into_iter().filter(|id| self.opted_in(id)) {
                tracing::info!(
                    job_id = id,
                    "scheduled job opted in here; it runs while its scheduled_job_metadata row is disabled"
                );
            }
        } else {
            tracing::info!(
                "COPILOT_SCHEDULER_OWNER=rust: this service runs every job whose \
                 scheduled_job_metadata row is enabled"
            );
        }
        let me = self.clone();
        tokio::spawn(async move { me.dispatch(cancel).await })
    }

    async fn dispatch(&self, cancel: CancellationToken) {
        let mut runs: JoinSet<()> = JoinSet::new();
        let mut next_poll = tokio::time::Instant::now();
        loop {
            if tokio::time::Instant::now() >= next_poll {
                let _schedule = self.lock_schedule().await;
                if let Err(e) = self.reconcile_locked().await {
                    tracing::warn!(err = %e, "cannot read the jobs' rows; keeping the schedule");
                }
                next_poll = tokio::time::Instant::now() + INTERVAL_POLL;
            }
            let wake = self.process_due(&mut runs);
            while runs.try_join_next().is_some() {}
            let until_poll = next_poll.saturating_duration_since(tokio::time::Instant::now());
            let wait = wake
                .map(|t| {
                    let us = (t - trigger::now_us()).max(0);
                    Duration::from_micros(u64::try_from(us).unwrap_or(0))
                })
                .map_or(until_poll, |d| d.min(until_poll));
            tokio::select! {
                () = cancel.cancelled() => break,
                () = self.inner.changed.notified() => {}
                () = tokio::time::sleep(wait) => {}
                Some(_) = runs.join_next(), if !runs.is_empty() => {}
            }
        }
        if let Ok(mut grid) = self.inner.grid.lock() {
            for e in grid.values_mut() {
                e.next_run = None;
            }
        }
        if !runs.is_empty() {
            tracing::info!(
                running = runs.len(),
                "shutting down; waiting for the runs in progress"
            );
            let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
                while runs.join_next().await.is_some() {}
            })
            .await;
            if drained.is_err() {
                tracing::warn!("runs abandoned at shutdown");
                runs.abort_all();
            }
        }
    }

    /// `_process_jobs`: start every due job, move its next run time on;
    /// returns the next wake-up.
    fn process_due(&self, runs: &mut JoinSet<()>) -> Option<Micros> {
        let now = trigger::now_us();
        let mut start: Vec<(&'static str, Micros)> = Vec::new();
        let mut wake: Option<Micros> = None;
        if let Ok(mut grid) = self.inner.grid.lock() {
            for (id, e) in grid.iter_mut() {
                let Some(next) = e.next_run else {
                    continue;
                };
                if next <= now {
                    if let Some(due) = trigger::due(&e.trigger, next, now) {
                        if e.instances >= 1 {
                            tracing::warn!(
                                job_id = id,
                                "Execution of job skipped: maximum number of running instances reached (1)"
                            );
                        } else {
                            e.instances += 1;
                            start.push((id, due.run_time));
                        }
                        e.next_run = due.next;
                    }
                }
                if let Some(n) = e.next_run {
                    wake = Some(wake.map_or(n, |w: Micros| w.min(n)));
                }
            }
        }
        for (id, run_time) in start {
            let me = self.clone();
            runs.spawn(async move { me.run_scheduled(id, run_time).await });
        }
        wake
    }

    async fn run_scheduled(&self, id: &'static str, run_time: Micros) {
        let started = trigger::now_us();
        if trigger::missed(run_time, started) {
            tracing::warn!(
                job_id = id,
                late_us = started - run_time,
                "Run time of job was missed"
            );
        } else {
            match self.tick(id).await {
                Tick::Ran(Ok(())) => tracing::debug!(job_id = id, "job executed successfully"),
                Tick::Ran(Err(e)) => {
                    tracing::error!(job_id = id, err = %e, "job raised an exception")
                }
                Tick::Busy => {
                    tracing::info!(job_id = id, "job is running elsewhere; skipping this tick");
                }
                Tick::NotOwned(owner) => {
                    tracing::debug!(
                        job_id = id,
                        owner = owner.as_str(),
                        "not this service's; idle"
                    );
                }
                Tick::Error(e) => {
                    tracing::warn!(job_id = id, err = %e, "cannot check the job's owner; skipping this tick");
                }
            }
        }
        if let Ok(mut grid) = self.inner.grid.lock() {
            if let Some(e) = grid.get_mut(id) {
                e.instances = e.instances.saturating_sub(1);
            }
        }
        self.inner.changed.notify_one();
    }
}

/// `time_interval` as a job's interval, or the error building its trigger
/// now would raise (the write routes check before writing anything).
pub fn check_interval(minutes: i128) -> Result<(), IntervalError> {
    IntervalTrigger::new(minutes, trigger::now_us()).map(|_| ())
}

/// The deciding rows of `ids`, for callers outside the runner.
pub async fn deciding_rows(
    db: &Db,
    ids: &[&str],
) -> Result<HashMap<String, (bool, i64)>, copilot_db::DbError> {
    db::owner_rows(db, ids).await
}
