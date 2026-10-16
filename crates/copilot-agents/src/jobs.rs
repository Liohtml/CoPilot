//! `agent_sync` (`app/schedulers/services/agent_sync.py`), every 15 minutes:
//! `sync_all_agents()`. The Python function stamps `last_success` itself, a
//! manual run included, and not when the sync raised: the runner does the
//! same here (`stamps_manual_runs`).

use std::sync::Arc;

use copilot_scheduler::{JobError, JobSpec};

use crate::AgentsState;
use crate::services::sync;

/// The job id.
pub const AGENT_SYNC: &str = "agent_sync";
/// The ids this crate registers, for the hand-over pin.
pub const JOB_IDS: &[&str] = &[AGENT_SYNC];

/// `agent_sync()`.
pub async fn agent_sync(st: &AgentsState) -> Result<(), JobError> {
    tracing::info!("Synchronizing agents via scheduler...");
    sync::sync_all_agents(&st.ctx.db, &st.wazuh, &st.velociraptor)
        .await
        .map_err(|e| JobError(e.display()))?;
    Ok(())
}

/// The job spec, for `copilot`'s `scheduled_jobs()`.
pub fn job_specs(st: &AgentsState) -> Vec<JobSpec> {
    let st = Arc::new(st.clone());
    vec![
        JobSpec::new(AGENT_SYNC, 15, move || {
            let st = Arc::clone(&st);
            async move { agent_sync(&st).await }
        })
        .stamps_manual_runs(),
    ]
}
