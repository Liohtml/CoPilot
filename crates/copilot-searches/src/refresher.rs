//! This process's off-request refresh of the catalog caches.
//!
//! Python's caches are module state of the Python process, refreshed there by
//! APScheduler's `refresh_catalog_caches` (every 15 min, TTL-aware) and
//! `refresh_wazuh_rules_cache` (every 30 min) and warmed at startup
//! (`warm_catalog_caches`). Those jobs fill only Python's copies; this
//! process serves `/api/copilot_searches` from its own, so it runs the same
//! three things itself. It is a process-local task, not a hand-over job: a
//! hand-over would let one scheduler run the job, and the other process's
//! caches would go cold — the Python sidebar (`status/context.py`) still
//! reads Python's Wazuh ruleset. Both processes refreshing their own copy of
//! read-only upstream data is what Python's per-process caches already did
//! with several workers.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::SearchesState;
use crate::caches::{self, Kind};

/// `refresh_catalog_caches`' interval.
pub const CATALOG_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// `refresh_wazuh_rules_cache`'s interval.
pub const WAZUH_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// `refresh_catalog_caches()`: each GitHub-backed cache loaded if stale; a
/// failure is logged, never raised.
pub async fn refresh_catalog_caches(st: &SearchesState) {
    for (name, kind) in [
        ("CoPilot Searches rules", Kind::Rules),
        ("MITRE ATT&CK matrix", Kind::Mitre),
    ] {
        if !st.caches.is_stale(kind) {
            tracing::debug!("{name} cache is still fresh, skipping");
            continue;
        }
        tracing::info!("Refreshing the {name} cache (stale)");
        match caches::ensure_loaded(st, kind).await {
            Ok(()) => tracing::info!("{name} cache refreshed"),
            Err(e) => tracing::warn!(
                "Could not refresh the {name} cache: {}. Serving the previous snapshot.",
                e.text()
            ),
        }
    }
}

/// `refresh_wazuh_rules_cache()`.
pub async fn refresh_wazuh_rules_cache(st: &SearchesState) {
    tracing::info!("Scheduled refresh of the Wazuh rules cache starting");
    let count = caches::refresh_wazuh(st).await;
    match st.caches.wazuh.get().unavailable.as_deref() {
        None => {
            tracing::info!("Scheduled refresh of the Wazuh rules cache completed: {count} rules")
        }
        Some(reason) => tracing::warn!(
            "Scheduled refresh of the Wazuh rules cache could not reach Wazuh: {reason}. \
             Serving the previous snapshot ({count} rules)."
        ),
    }
}

/// Start the warm-up and the two loops (until `cancel`), unless
/// `COPILOT_CATALOG_REFRESH` is off: then the caches load on demand only, as
/// Python's would without its startup warm-up and its two jobs (the parity
/// suites start the binary so, since their Python side never runs those; an
/// air-gapped deployment may).
pub fn spawn(st: SearchesState, cancel: CancellationToken) {
    if !st.settings.refresh {
        tracing::info!("COPILOT_CATALOG_REFRESH is off: the catalog caches load on demand");
        return;
    }
    let warm = st.clone();
    let stop = cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            () = stop.cancelled() => {}
            () = async {
                refresh_catalog_caches(&warm).await;
                if let Err(e) = caches::ensure_loaded(&warm, Kind::Wazuh).await {
                    tracing::warn!("Could not warm the Wazuh rules cache at startup: {}", e.text());
                }
            } => {}
        }
    });
    let catalog = st.clone();
    let stop = cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(CATALOG_INTERVAL) => refresh_catalog_caches(&catalog).await,
            }
        }
    });
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(WAZUH_INTERVAL) => refresh_wazuh_rules_cache(&st).await,
            }
        }
    });
}
