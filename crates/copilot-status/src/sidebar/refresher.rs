//! This process's off-request refresh of the sidebar (Python's
//! `refresh_sidebar_indicators` job every 4 minutes and
//! `refresh_sidebar_health` every 6, which refresh the Python process's
//! copies while APScheduler runs them).
//!
//! The two jobs ([`job_specs`]) refresh *this* process's values once this
//! service's scheduler runs them (handed over, or under
//! `COPILOT_SCHEDULER_OWNER=rust`), so the Scheduler UI's *Run* and *Pause*
//! act on the sidebar this process serves. Its own timer ([`spawn`]) is
//! started by the binary unless `COPILOT_SIDEBAR_REFRESH` (by default
//! `COPILOT_CATALOG_REFRESH`) is off: a warm-up — the InfluxDB value first,
//! so the first shared set carries it — then the two loops, each tick only
//! while no scheduler here decides about its job
//! ([`copilot_scheduler::Scheduler::timer_runs`]). Off, the values are
//! computed on demand only, as Python's request path does without its jobs.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use copilot_scheduler::{JobSpec, Scheduler};

use super::SidebarState;
use super::services::{refresh_influx, refresh_shared};

/// `refresh_sidebar_indicators`' job id.
pub const SHARED_JOB: &str = "refresh_sidebar_indicators";
/// `refresh_sidebar_health`'s job id.
pub const INFLUX_JOB: &str = "refresh_sidebar_health";

/// `refresh_sidebar_indicators`' interval.
pub const SHARED_INTERVAL: Duration = Duration::from_secs(4 * 60);
/// `refresh_sidebar_health`'s interval.
pub const INFLUX_INTERVAL: Duration = Duration::from_secs(6 * 60);

/// The two jobs, for `copilot`'s `scheduled_jobs()` (`initialize_job_metadata`
/// seeds them every 4 and 6 minutes). Neither raises, as in Python.
pub fn job_specs(st: &SidebarState) -> Vec<JobSpec> {
    let shared = st.clone();
    let influx = st.clone();
    vec![
        JobSpec::new(SHARED_JOB, 4, move || {
            let st = shared.clone();
            async move {
                refresh_shared(&st).await;
                Ok(())
            }
        }),
        JobSpec::new(INFLUX_JOB, 6, move || {
            let st = influx.clone();
            async move {
                refresh_influx(&st).await;
                Ok(())
            }
        }),
    ]
}

async fn timer_runs(gate: Option<&Scheduler>, job_id: &'static str) -> bool {
    match gate {
        None => true,
        Some(s) => s.timer_runs(job_id).await,
    }
}

/// Start the warm-up and the two loops (until `cancel`); with `gate`, a
/// loop's tick runs only while its job does not refresh the value itself.
pub fn spawn(st: SidebarState, cancel: CancellationToken, gate: Option<Scheduler>) {
    if !st.env.refresh {
        tracing::info!("COPILOT_SIDEBAR_REFRESH is off: the sidebar indicators load on demand");
        return;
    }
    let warm = st.clone();
    let stop = cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            () = stop.cancelled() => {}
            () = async {
                refresh_influx(&warm).await;
                refresh_shared(&warm).await;
            } => {}
        }
    });
    let shared = st.clone();
    let stop = cancel.clone();
    let shared_gate = gate.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(SHARED_INTERVAL) => {
                    if timer_runs(shared_gate.as_ref(), SHARED_JOB).await {
                        refresh_shared(&shared).await;
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(INFLUX_INTERVAL) => {
                    if timer_runs(gate.as_ref(), INFLUX_JOB).await {
                        refresh_influx(&st).await;
                    }
                }
            }
        }
    });
}
