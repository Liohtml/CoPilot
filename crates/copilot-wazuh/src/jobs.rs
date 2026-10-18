//! The two Wazuh-indexer jobs APScheduler can hand over
//! (`app/schedulers/services/{invoke_snapshot_and_restore,wazuh_index_resize}.py`):
//!
//! - `invoke_snapshot_schedules` (every 15 minutes): every enabled snapshot
//!   schedule, gated by its hour, minute, weekday and interval
//!   ([`crate::indexer::services::scheduled`]); the Python function stamps
//!   `last_success` itself, a manual run included;
//! - `resize_wazuh_index_fields` (every minute): `index.mapping.total_fields.limit`
//!   on `wazuh*`, only while the `Wazuh-Indexer` connector is verified; the
//!   function stamps `last_success` itself when it got that far, so a manual
//!   run of an unverified connector is not stamped.

use std::sync::Arc;

use copilot_scheduler::{JobError, JobSpec};

use crate::WazuhState;
use crate::es::CONNECTOR;
use crate::indexer::services::{monitoring, scheduled};

/// `invoke_snapshot_schedules`.
pub const INVOKE_SNAPSHOT_SCHEDULES: &str = "invoke_snapshot_schedules";
/// `resize_wazuh_index_fields`.
pub const RESIZE_WAZUH_INDEX_FIELDS: &str = "resize_wazuh_index_fields";
/// Both, for the hand-over pin.
pub const JOB_IDS: &[&str] = &[INVOKE_SNAPSHOT_SCHEDULES, RESIZE_WAZUH_INDEX_FIELDS];

/// `invoke_snapshot_schedules()`.
pub async fn invoke_snapshot_schedules(st: &WazuhState) -> Result<(), JobError> {
    tracing::info!("Starting scheduled snapshot execution");
    let results = scheduled::execute_all_enabled(st).await.map_err(|e| {
        let e = e.py_str();
        tracing::error!("Failed to execute scheduled snapshots: {e}");
        JobError(e)
    })?;
    let ok = results.iter().filter(|r| r.success).count();
    if results.is_empty() {
        tracing::info!("No enabled snapshot schedules to execute");
    } else {
        tracing::info!(
            "Scheduled snapshot execution completed: {ok} successful, {} failed out of {} schedules",
            results.len() - ok,
            results.len()
        );
        for r in &results {
            if r.success {
                tracing::info!(
                    "  - {}: SUCCESS (snapshot: {}, indices: {}, skipped: {}, ",
                    r.schedule_name,
                    r.snapshot_name.as_deref().unwrap_or("None"),
                    r.indices_snapshotted.len(),
                    r.skipped_write_indices.len()
                );
            } else {
                tracing::error!("  - {}: FAILED - {}", r.schedule_name, r.message);
            }
        }
    }
    Ok(())
}

/// `resize_wazuh_index_fields()` (the job).
pub async fn resize_wazuh_index_fields(st: &WazuhState) -> Result<(), JobError> {
    tracing::info!("Resizing Wazuh index fields via scheduler...");
    let verified = st
        .ctx
        .connectors
        .get(CONNECTOR)
        .await
        .map_err(|e| JobError(e.to_string()))?
        .is_some_and(|r| r.connector_verified);
    if !verified {
        tracing::warn!("Wazuh Indexer connector is not verified.");
        return Ok(());
    }
    monitoring::resize_fields(st)
        .await
        .map_err(|e| JobError(e.py_str()))?;
    // The function's own stamp (the listener's comes on top for a scheduled run).
    copilot_db::scheduler::stamp_last_success(&st.ctx.db, RESIZE_WAZUH_INDEX_FIELDS)
        .await
        .map_err(|e| JobError(e.to_string()))?;
    Ok(())
}

/// The two job specs, for `copilot`'s `scheduled_jobs()`.
pub fn job_specs(st: &WazuhState) -> Vec<JobSpec> {
    let snap = Arc::new(st.clone());
    let resize = Arc::new(st.clone());
    vec![
        JobSpec::new(INVOKE_SNAPSHOT_SCHEDULES, 15, move || {
            let st = Arc::clone(&snap);
            async move { invoke_snapshot_schedules(&st).await }
        })
        .stamps_manual_runs(),
        JobSpec::new(RESIZE_WAZUH_INDEX_FIELDS, 1, move || {
            let st = Arc::clone(&resize);
            async move { resize_wazuh_index_fields(&st).await }
        }),
    ]
}
