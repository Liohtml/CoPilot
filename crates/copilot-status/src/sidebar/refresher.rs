//! This process's off-request refresh of the sidebar (Python's
//! `refresh_sidebar_indicators` job every 4 minutes and
//! `refresh_sidebar_health` every 6, which keep refreshing the Python
//! process's copies).
//!
//! Started by the binary unless `COPILOT_SIDEBAR_REFRESH` (by default
//! `COPILOT_CATALOG_REFRESH`) is off: a warm-up — the InfluxDB value first,
//! so the first shared set carries it — then the two loops. Off, the values
//! are computed on demand only, as Python's request path does without its
//! jobs. Not a hand-over job: each process serves its own copies (the shared
//! set is deployment-wide data, the same from either process).

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::SidebarState;
use super::services::{refresh_influx, refresh_shared};

/// `refresh_sidebar_indicators`' interval.
pub const SHARED_INTERVAL: Duration = Duration::from_secs(4 * 60);
/// `refresh_sidebar_health`'s interval.
pub const INFLUX_INTERVAL: Duration = Duration::from_secs(6 * 60);

/// Start the warm-up and the two loops (until `cancel`).
pub fn spawn(st: SidebarState, cancel: CancellationToken) {
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
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(SHARED_INTERVAL) => refresh_shared(&shared).await,
            }
        }
    });
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(INFLUX_INTERVAL) => refresh_influx(&st).await,
            }
        }
    });
}
