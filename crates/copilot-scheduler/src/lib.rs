//! # copilot-scheduler — scheduled jobs and `/api/scheduler`
//!
//! Port of `app/schedulers/`. CoPilot's jobs ran in APScheduler inside the
//! Python process; this crate runs every one of them and serves every
//! Scheduler route. Two modes ([`Mode`], `COPILOT_SCHEDULER_OWNER`):
//!
//! - **the hand-over** (unset): APScheduler owns the schedule and this
//!   service takes jobs over **one at a time** (below); the write routes are
//!   answered here and hand only APScheduler's own calls to the Python
//!   process ([`handoff`]);
//! - **the ownership** (`rust`): this service runs every job whose deciding
//!   row is enabled, with the row's interval; Pause and Start switch rows, the
//!   writes edit rows and this service's grid, nothing reaches Python — whose
//!   APScheduler is off (`COPILOT_PY_SCHEDULER=false`, which `copilot doctor`
//!   checks as far as it can see).
//!
//! ## The hand-over (no job ever runs in both schedulers)
//!
//! A job runs here only when the operator opted in (`COPILOT_RS_JOBS`, or
//! `COPILOT_RS_PALACE_JOBS=true` for the two palace jobs) **and** the job's
//! deciding `scheduled_job_metadata` row (lowest id) exists and is
//! **disabled**. APScheduler runs it only while that row is enabled or
//! absent — enforced at every run by the guard on the Python function itself
//! (`backend/app/schedulers/handover.py`), not only when jobs are scheduled.
//! The two conditions are disjoint ([`job::Owner::decide`]), and both sides
//! re-read the row under one MySQL named lock held for the whole run
//! (`copilot_db::scheduler::JobLock`), so a hand-over in the middle of a run
//! never starts the other side. Hand over with *Pause* in the Scheduler UI
//! (through this service, which then disables the row), hand back with
//! *Start*.
//!
//! - [`job`]      — [`JobSpec`], the opt-in, the [`Mode`], ownership
//! - [`functions`] — `get_function_by_name`'s table
//! - [`trigger`]  — APScheduler 3.11's interval trigger (float-second grid,
//!   coalesce, one instance, misfire grace), pinned by `scheduler_vectors.json`
//! - [`runner`]   — [`Scheduler`]: the dispatcher, ticks, manual runs, the
//!   grid the write routes change, shutdown
//! - [`jobs`]     — jobs that need only the database (`prune_audit_log`)
//! - [`pickle`], [`jobstore`] — APScheduler's job store, read only
//! - [`writes`], [`handoff`], [`provisioning`] — the writes
//! - [`schema`], [`services`], [`routes`] — `/api/scheduler`, Mimecast's two
//!   scheduler routes

#![warn(missing_docs)]

pub mod doctor;
pub mod functions;
pub mod handoff;
pub mod job;
pub mod jobs;
pub mod jobstore;
pub mod pickle;
pub mod provisioning;
pub mod routes;
pub mod runner;
pub mod schema;
pub mod services;
pub mod trigger;
pub mod writes;

pub use job::{JobError, JobSpec, Mode, OptIn, Owner};
pub use routes::{SchedulerState, mimecast_router, router};
pub use runner::{Scheduler, SchedulerOptions};

#[cfg(test)]
mod tests {
    /// `RUST_CAPABLE_JOBS` of `backend/app/schedulers/handover.py`, read from
    /// the source line by line (tests only: the Docker build has no
    /// `backend/`).
    fn python_rust_capable_jobs() -> Vec<String> {
        let src = include_str!("../../../backend/app/schedulers/handover.py");
        let Some(start) = src.find("RUST_CAPABLE_JOBS = (") else {
            return Vec::new();
        };
        let rest = &src[start..];
        let block = &rest[..rest.find("\n)").unwrap_or(rest.len())];
        block
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"'))
            .filter_map(|l| l.split('"').next())
            .map(str::to_string)
            .collect()
    }

    /// `copilot_integration_modules::jobs::job_ids()`.
    const INTEGRATION_MODULE_JOBS: &[&str] = &[
        "invoke_huntress_integration_collect",
        "invoke_cato_integration_collect",
        "invoke_duo_integration_collect",
        "invoke_darktrace_integration_collect",
        "invoke_carbonblack_integration_collection",
        "invoke_mimecast_integration",
        "invoke_mimecast_integration_ttp",
        "invoke_sap_siem_integration_collection",
        "invoke_sap_siem_integration_suspicious_logins_analysis",
        "invoke_sap_siem_integration_multiple_logins_same_ip_analysis",
        "invoke_sap_siem_integration_successful_user_login_with_different_ip",
        "invoke_sap_siem_integration_same_user_failed_login_from_different_ip",
        "invoke_sap_siem_integration_same_user_failed_login_from_different_geo_location",
        "invoke_sap_siem_integration_same_user_successful_login_from_different_geo_location",
        "invoke_sap_siem_integration_brute_force_failed_logins",
        "invoke_sap_siem_integration_brute_force_failed_logins_same_ip",
        "invoke_sap_siem_integration_successful_login_after_multiple_failed_logins",
    ];

    #[test]
    fn python_guards_exactly_the_jobs_this_crate_can_run() {
        let mut python = python_rust_capable_jobs();
        python.sort();
        // `notify_sla_transitions` registers from `copilot-soc-management`,
        // `invoke_snapshot_schedules` and `resize_wazuh_index_fields` from
        // `copilot-wazuh`, `invoke_alert_creation_collect` from
        // `copilot-ingest`, `agent_sync` from `copilot-agents`, the
        // integrations' collection jobs from `copilot-integration-modules`
        // (its own test pins `job_ids()` to this list), the catalog's two
        // refreshers from `copilot-searches`, the sidebar's from
        // `copilot-status`.
        let mut rust: Vec<String> = crate::job::PALACE_JOB_IDS
            .iter()
            .chain(
                [
                    crate::jobs::PRUNE_AUDIT_LOG,
                    "notify_sla_transitions",
                    "invoke_snapshot_schedules",
                    "resize_wazuh_index_fields",
                    "invoke_alert_creation_collect",
                    "agent_sync",
                    "refresh_catalog_caches",
                    "refresh_wazuh_rules_cache",
                    "refresh_sidebar_health",
                    "refresh_sidebar_indicators",
                ]
                .iter(),
            )
            .chain(INTEGRATION_MODULE_JOBS.iter())
            .map(|s| (*s).to_string())
            .collect();
        rust.sort();
        assert_eq!(python, rust);
        // … which is every job of `get_function_by_name`.
        let mut functions: Vec<String> = crate::functions::FUNCTIONS
            .iter()
            .map(|f| f.key.to_string())
            .collect();
        functions.sort();
        assert_eq!(functions, rust);
    }
}
