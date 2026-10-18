//! # copilot-scoutsuite — `/api/scoutsuite`
//!
//! Port of `app/integrations/scoutsuite/` (routes, `services/scoutsuite.py`,
//! schema): the report options, the reports on disk
//! (`GET /available-reports`, `DELETE /delete-report/{report_name}`) and the
//! three scans (`POST /generate-{aws,azure,gcp}-report`), each the `scout`
//! command Python runs — same arguments, the same working directory, this
//! process's environment — started after the answer, as a FastAPI
//! background task is.
//!
//! - [`routes`] — the six routes, every one `require_any_scope("admin",
//!   "analyst")`; [`schema`] — the request models and the answers
//! - [`services`] — the commands, the run, the GCP credential's private
//!   temporary directory (`tempfile.mkdtemp`), the listing and the delete
//!
//! **The working directory.** Python runs `scout` in its own working
//! directory, where ScoutSuite writes `scoutsuite-report/` (the HTML report,
//! `scoutsuite-results/`), and lists and deletes reports relative to it; the
//! static mount `/scoutsuite-report` (`copilot-standalone`'s, as `copilot.py`
//! mounts it) serves that directory. This process uses `COPILOT_SCOUTSUITE_DIR` (default: its
//! own working directory): under Compose the two containers share
//! `scoutsuite-report` as a volume and the Rust one names the backend's
//! working directory (`docker-compose.rust.yml`). The binary creates
//! `scoutsuite-report` there at startup ([`ensure_report_dir`]), as
//! `copilot.py` does.
//!
//! No route is tenant-scoped, as in Python: a scan names no customer and the
//! reports are the deployment's.
//!
//! State kept by the process: none (scans in flight are child processes).

#![warn(missing_docs)]

pub mod routes;
pub mod schema;
pub mod services;

#[cfg(test)]
mod vectors;

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::FromRef;
use copilot_web::AppContext;

pub use routes::router;

/// The directory ScoutSuite writes its reports to, under the working
/// directory.
pub const REPORT_DIR: &str = "scoutsuite-report";

/// State of the ScoutSuite routes.
#[derive(Clone)]
pub struct ScoutState {
    /// Shared dependencies (auth).
    pub ctx: AppContext,
    /// The working directory: `scout` runs in it and the reports are its
    /// `scoutsuite-report/`.
    pub dir: Arc<PathBuf>,
    /// The program run (`scout`, found on `PATH` as `subprocess.Popen`
    /// finds it; the e2e tests name a stand-in).
    pub program: Arc<str>,
}

impl std::fmt::Debug for ScoutState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScoutState")
            .field("dir", &self.dir)
            .field("program", &self.program)
            .finish_non_exhaustive()
    }
}

impl ScoutState {
    /// The state, the working directory from `COPILOT_SCOUTSUITE_DIR` (else
    /// this process's).
    pub fn new(ctx: AppContext) -> Self {
        let dir = std::env::var("COPILOT_SCOUTSUITE_DIR")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            ctx,
            dir: Arc::new(dir),
            program: Arc::from("scout"),
        }
    }

    /// `{dir}/scoutsuite-report`.
    pub fn report_dir(&self) -> PathBuf {
        self.dir.join(REPORT_DIR)
    }
}

impl FromRef<ScoutState> for AppContext {
    fn from_ref(s: &ScoutState) -> AppContext {
        s.ctx.clone()
    }
}

/// `copilot.py`'s startup step: create `scoutsuite-report` when it is
/// missing (a failure is logged; the listing then answers its 404).
pub fn ensure_report_dir(state: &ScoutState) {
    let dir = state.report_dir();
    if !dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!("could not create {}: {e}", dir.display());
        }
    }
}
