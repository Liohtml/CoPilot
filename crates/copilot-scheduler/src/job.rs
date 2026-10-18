//! A job this service can run, the operator's opt-in, and who owns a job.

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// What a job's run returns: the value the Python function returned (the
/// manual run's `result`; `None` for most jobs), or its failure.
pub type JobFuture =
    Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, JobError>> + Send>>;

/// Starts one run of a job.
pub type JobFn = Arc<dyn Fn() -> JobFuture + Send + Sync>;

/// Why a run failed. The text is what a manual run answers with (Python's
/// `HTTPException(500, str(e))`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobError(pub String);

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JobError {}

impl From<copilot_db::DbError> for JobError {
    fn from(e: copilot_db::DbError) -> Self {
        JobError(e.to_string())
    }
}

/// A job this service can take over from APScheduler.
#[derive(Clone)]
pub struct JobSpec {
    /// The APScheduler job id, which is also the Python function's name and
    /// the `scheduled_job_metadata.job_id` that decides ownership.
    pub id: &'static str,
    /// Interval while the job has no metadata row (minutes), as
    /// `initialize_job_metadata` seeds it.
    pub default_minutes: i64,
    /// Whether a run started by hand stamps `last_success` — true where the
    /// Python function stamps it itself (the palace jobs), false where only
    /// the scheduler's listener does (a manual run bypasses the listener).
    pub manual_run_stamps: bool,
    /// One run.
    pub run: JobFn,
}

impl fmt::Debug for JobSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobSpec")
            .field("id", &self.id)
            .field("default_minutes", &self.default_minutes)
            .field("manual_run_stamps", &self.manual_run_stamps)
            .finish_non_exhaustive()
    }
}

impl JobSpec {
    /// A job from an async closure (its Python function returns `None`).
    pub fn new<F, Fut>(id: &'static str, default_minutes: i64, run: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), JobError>> + Send + 'static,
    {
        Self {
            id,
            default_minutes,
            manual_run_stamps: false,
            run: Arc::new(move || {
                let fut = run();
                Box::pin(async move { fut.await.map(|()| None) })
            }),
        }
    }

    /// A job whose Python function returns a value (a response model): a
    /// manual run answers it as `result`, as `run_job_manually` does.
    pub fn returning<F, Fut>(id: &'static str, default_minutes: i64, run: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<serde_json::Value, JobError>> + Send + 'static,
    {
        Self {
            id,
            default_minutes,
            manual_run_stamps: false,
            run: Arc::new(move || {
                let fut = run();
                Box::pin(async move { fut.await.map(Some) })
            }),
        }
    }

    /// Mark the job as stamping `last_success` on a manual run too.
    pub fn stamps_manual_runs(mut self) -> Self {
        self.manual_run_stamps = true;
        self
    }
}

/// The jobs the operator lets this service run (`COPILOT_RS_JOBS`, plus the
/// palace jobs under the older `COPILOT_RS_PALACE_JOBS=true`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptIn {
    all: bool,
    ids: BTreeSet<String>,
}

/// The palace jobs `COPILOT_RS_PALACE_JOBS=true` opts in.
pub const PALACE_JOB_IDS: &[&str] = &[
    "invoke_palace_lesson_drainer",
    "invoke_palace_lesson_sweeper",
];

impl OptIn {
    /// Parse `COPILOT_RS_JOBS` (job ids separated by commas or spaces, or
    /// `all`) and the palace flag.
    pub fn parse(jobs: Option<&str>, palace_jobs: bool) -> Self {
        let mut out = Self::default();
        for id in jobs
            .unwrap_or("")
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if id.eq_ignore_ascii_case("all") || id == "*" {
                out.all = true;
            } else {
                out.ids.insert(id.to_string());
            }
        }
        if palace_jobs {
            out.ids
                .extend(PALACE_JOB_IDS.iter().map(|s| (*s).to_string()));
        }
        out
    }

    /// Opt in to everything (tests, `all`).
    pub fn all() -> Self {
        Self {
            all: true,
            ids: BTreeSet::new(),
        }
    }

    /// Whether `job_id` may run here.
    pub fn contains(&self, job_id: &str) -> bool {
        self.all || self.ids.contains(job_id)
    }

    /// Ids named that are not among `known` (a typo, or a job this build
    /// does not have).
    pub fn unknown<'a>(&'a self, known: &'a [&str]) -> impl Iterator<Item = &'a str> + 'a {
        self.ids
            .iter()
            .map(String::as_str)
            .filter(move |id| !known.contains(id))
    }

    /// Whether nothing is opted in.
    pub fn is_empty(&self) -> bool {
        !self.all && self.ids.is_empty()
    }
}

/// Who owns the schedule (`COPILOT_SCHEDULER_OWNER`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    /// Unset: the hand-over. APScheduler (in the Python process) owns the
    /// schedule; this service runs a job only once it is handed over — opted
    /// in (`COPILOT_RS_JOBS`) and its deciding row disabled.
    #[default]
    Handover,
    /// `rust`: this service owns the schedule. It runs every job whose
    /// deciding row is enabled, with the row's interval; Pause and Start only
    /// switch rows; nothing needs `COPILOT_RS_JOBS`. The Python backend must
    /// run without APScheduler (`COPILOT_PY_SCHEDULER=false`).
    Rust,
}

/// The variable naming the schedule's owner.
pub const OWNER_ENV: &str = "COPILOT_SCHEDULER_OWNER";

impl Mode {
    /// Parse `COPILOT_SCHEDULER_OWNER`: unset or empty is the hand-over,
    /// `rust` (any case) the ownership; anything else is refused (the binary
    /// does not start on a value it would have to guess at).
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.map(str::trim) {
            None | Some("") => Ok(Mode::Handover),
            Some(v) if v.eq_ignore_ascii_case("rust") => Ok(Mode::Rust),
            Some(v) => Err(format!(
                "{OWNER_ENV}={v:?}: expected `rust`, or unset for the hand-over to APScheduler"
            )),
        }
    }

    /// Short name for logs and `copilot doctor`.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Handover => "handover",
            Mode::Rust => "rust",
        }
    }
}

/// Who runs a job's scheduled ticks right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// This service (hand-over: opted in, row disabled; ownership: row
    /// enabled).
    Rust,
    /// APScheduler (row enabled, or no row: the Python scheduler runs a job
    /// regardless of metadata). Never under [`Mode::Rust`].
    Legacy,
    /// Nobody: the row is disabled and this service is not opted in (or, under
    /// [`Mode::Rust`], the row is disabled or absent).
    Paused,
}

impl Owner {
    /// The rule both schedulers apply (`handover.py` is its Python half):
    /// APScheduler runs the job while the deciding row is enabled or absent,
    /// this service only while it exists, is disabled and the operator opted
    /// in. The two can never hold at once.
    pub fn decide(opted_in: bool, row_enabled: Option<bool>) -> Self {
        match row_enabled {
            None | Some(true) => Owner::Legacy,
            Some(false) if opted_in => Owner::Rust,
            Some(false) => Owner::Paused,
        }
    }

    /// [`Owner::decide`] under `mode`: with [`Mode::Rust`] the row alone
    /// decides — enabled is this service's, anything else nobody's.
    pub fn decide_in(mode: Mode, opted_in: bool, row_enabled: Option<bool>) -> Self {
        match mode {
            Mode::Handover => Self::decide(opted_in, row_enabled),
            Mode::Rust if row_enabled == Some(true) => Owner::Rust,
            Mode::Rust => Owner::Paused,
        }
    }

    /// Short name for logs and `copilot jobs`.
    pub fn as_str(self) -> &'static str {
        match self {
            Owner::Rust => "rust",
            Owner::Legacy => "python",
            Owner::Paused => "paused",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_in_parsing() {
        let o = OptIn::parse(Some(" prune_audit_log, x  y,,"), false);
        assert!(o.contains("prune_audit_log") && o.contains("x") && o.contains("y"));
        assert!(!o.contains("invoke_palace_lesson_drainer"));
        let o = OptIn::parse(None, true);
        assert!(o.contains("invoke_palace_lesson_drainer"));
        assert!(o.contains("invoke_palace_lesson_sweeper"));
        assert!(!o.contains("prune_audit_log"));
        assert!(OptIn::parse(Some("ALL"), false).contains("anything"));
        assert!(OptIn::parse(Some(""), false).is_empty());
        let o = OptIn::parse(Some("prune_audit_log,typo"), false);
        assert_eq!(
            o.unknown(&["prune_audit_log"]).collect::<Vec<_>>(),
            ["typo"]
        );
    }

    #[test]
    fn ownership_is_exclusive() {
        for opted_in in [false, true] {
            for row in [None, Some(true), Some(false)] {
                let owner = Owner::decide(opted_in, row);
                // The Python guard's rule (handover.legacy_scheduler_owns).
                let python_runs = row.is_none_or(|enabled| enabled);
                assert!(!(python_runs && owner == Owner::Rust), "{opted_in} {row:?}");
                assert_eq!(python_runs, owner == Owner::Legacy);
            }
        }
        assert_eq!(Owner::decide(true, Some(false)), Owner::Rust);
        assert_eq!(Owner::decide(false, Some(false)), Owner::Paused);
        assert_eq!(Owner::decide(true, None), Owner::Legacy);
    }

    #[test]
    fn under_rust_ownership_the_row_alone_decides() {
        for opted_in in [false, true] {
            assert_eq!(
                Owner::decide_in(Mode::Rust, opted_in, Some(true)),
                Owner::Rust
            );
            assert_eq!(
                Owner::decide_in(Mode::Rust, opted_in, Some(false)),
                Owner::Paused
            );
            assert_eq!(Owner::decide_in(Mode::Rust, opted_in, None), Owner::Paused);
        }
        assert_eq!(
            Owner::decide_in(Mode::Handover, false, Some(true)),
            Owner::Legacy
        );
    }

    #[test]
    fn the_owner_variable() {
        assert_eq!(Mode::parse(None), Ok(Mode::Handover));
        assert_eq!(Mode::parse(Some(" ")), Ok(Mode::Handover));
        assert_eq!(Mode::parse(Some("Rust")), Ok(Mode::Rust));
        assert!(Mode::parse(Some("python")).is_err());
    }
}
