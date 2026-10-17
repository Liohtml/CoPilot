//! The integrations' collection jobs (`app/schedulers/services/invoke_*.py`)
//! as hand-over jobs (`copilot-scheduler`): each runs here only while its
//! `scheduled_job_metadata` row is disabled and `COPILOT_RS_JOBS` names it.
//!
//! None is seeded by `initialize_job_metadata`; the provisioning routes (and
//! `POST /api/scheduler/add`) create them, still in Python — they act on
//! APScheduler, and re-enabling the row there hands the job back.
//!
//! Each keeps its Python function's semantics:
//!
//! - `invoke_huntress_integration_collect` calls the collection for every
//!   customer with the integration, collects the failures (a route answers
//!   `success: false` rather than raising) and then fails the run with
//!   Python's `RuntimeError` text, so `last_success` is not stamped; it
//!   stamps nothing itself (a manual run stamps nothing).
//! - The older jobs (Duo, Darktrace, CarbonBlack, Mimecast, SAP SIEM) stamp
//!   `last_success` themselves at the end, a manual run included
//!   (`stamps_manual_runs`). Duo, Darktrace and CarbonBlack ignore a
//!   customer's `success: false`; the Mimecast and SAP SIEM jobs call routes
//!   that raise, so the first customer that fails fails the run (the
//!   Mimecast ones always do once a customer has the integration — see
//!   [`crate::mimecast`]).
//! - `invoke_carbonblack_integration_collection` is the APScheduler id and
//!   metadata row of the function `invoke_carbonblack_integration_collect`:
//!   the hand-over follows the row; a manual run (`/jobs/run` resolves the
//!   function's name) is answered by Python.
//! - The two SAP SIEM jobs whose analyses Python commented out read the
//!   customers and do nothing else.
//!
//! `invoke_cato_integration_collect` is not here: `schedule_enabled_jobs`
//! disables its row at every Python start while APScheduler's stored job
//! keeps running it, so the hand-over rule (a disabled row is not Python's)
//! would stop the collection on a Python-only deployment.

use std::sync::Arc;

use copilot_auth::pyvalue::PyValue;
use copilot_scheduler::{JobError, JobSpec};
use copilot_upstream::model::kwargs;
use copilot_upstream::py::{PyExc, int_of};

use crate::ModulesState;
use crate::collect::{self, Module};
use crate::error::{Fail, FailResult};
use crate::lookups;
use crate::mimecast;
use crate::sap_siem::{self, ANALYSES, Analysis};
use crate::schema;

/// `invoke_huntress_integration_collect`.
pub const HUNTRESS: &str = "invoke_huntress_integration_collect";
/// `invoke_duo_integration_collect`.
pub const DUO: &str = "invoke_duo_integration_collect";
/// `invoke_darktrace_integration_collect`.
pub const DARKTRACE: &str = "invoke_darktrace_integration_collect";
/// `invoke_carbonblack_integration_collection` (the function is
/// `invoke_carbonblack_integration_collect`).
pub const CARBONBLACK: &str = "invoke_carbonblack_integration_collection";
/// `invoke_mimecast_integration`.
pub const MIMECAST: &str = "invoke_mimecast_integration";
/// `invoke_mimecast_integration_ttp`.
pub const MIMECAST_TTP: &str = "invoke_mimecast_integration_ttp";
/// `invoke_sap_siem_integration_collection`.
pub const SAP_COLLECTION: &str = "invoke_sap_siem_integration_collection";
/// `invoke_sap_siem_integration_suspicious_logins_analysis` (a no-op).
pub const SAP_SUSPICIOUS_LOGINS: &str = "invoke_sap_siem_integration_suspicious_logins_analysis";
/// `invoke_sap_siem_integration_multiple_logins_same_ip_analysis` (a no-op).
pub const SAP_MULTIPLE_LOGINS: &str =
    "invoke_sap_siem_integration_multiple_logins_same_ip_analysis";

/// Every job id this crate registers (for the hand-over pin).
pub fn job_ids() -> Vec<&'static str> {
    let mut ids = vec![
        HUNTRESS,
        DUO,
        DARKTRACE,
        CARBONBLACK,
        MIMECAST,
        MIMECAST_TTP,
        SAP_COLLECTION,
        SAP_SUSPICIOUS_LOGINS,
        SAP_MULTIPLE_LOGINS,
    ];
    ids.extend(ANALYSES.iter().map(|a| a.job_id));
    ids
}

fn failed(e: Fail) -> JobError {
    JobError(e.message())
}

/// `invoke_huntress_integration_collect()`.
pub async fn huntress(st: &ModulesState) -> Result<serde_json::Value, JobError> {
    tracing::info!(target: "copilot::integration_modules", "Invoking Huntress integration collection.");
    let codes = lookups::customers_with_integration(&st.ctx.db, "Huntress")
        .await
        .map_err(failed)?;
    if lookups::job_metadata(&st.ctx.db, HUNTRESS)
        .await
        .map_err(failed)?
        .is_none()
    {
        return Err(JobError(format!(
            "No scheduled_job_metadata row for '{HUNTRESS}'; cannot determine the collection \
             interval."
        )));
    }
    let mut failures = Vec::new();
    let mut succeeded = 0usize;
    for code in &codes {
        let response = collect::collect(st, Module::Huntress, code, "Huntress").await;
        if response.get("success") != Some(&PyValue::Bool(true)) {
            let message = response
                .get("message")
                .map(PyValue::py_str)
                .unwrap_or_default();
            tracing::error!(target: "copilot::integration_modules",
                "Huntress collection failed for customer {code}: {message}");
            failures.push(format!("{code}: {message}"));
        } else {
            succeeded += 1;
        }
    }
    if !failures.is_empty() {
        return Err(JobError(format!(
            "Huntress collection failed for {} of {} customer(s): {}",
            failures.len(),
            codes.len(),
            failures.join("; ")
        )));
    }
    Ok(returned(&format!(
        "Huntress integration invoked for {succeeded} customer(s)."
    )))
}

/// The older collections (Duo, Darktrace, CarbonBlack): every customer's
/// answer ignored.
async fn collect_all(
    st: &ModulesState,
    service: &str,
    module: Module,
    integration_name: &str,
) -> Result<(), JobError> {
    let codes = lookups::customers_with_integration(&st.ctx.db, service)
        .await
        .map_err(failed)?;
    for code in &codes {
        collect::collect(st, module, code, integration_name).await;
    }
    Ok(())
}

/// `invoke_mimecast_integration()` / `invoke_mimecast_integration_ttp()`:
/// the first customer whose route raises fails the run.
async fn mimecast_all(st: &ModulesState, ttp: bool) -> Result<(), JobError> {
    let codes = lookups::customers_with_integration(&st.ctx.db, "Mimecast")
        .await
        .map_err(failed)?;
    for code in &codes {
        let outcome = if ttp {
            mimecast::ttp_urls(st, code, "Mimecast", &PyValue::Str("15m".into())).await
        } else {
            mimecast::invoke(st, code, "Mimecast").await
        };
        outcome.map_err(failed)?;
    }
    Ok(())
}

/// `invoke_sap_siem_integration_collection()`: the window is the job's
/// interval in minutes, read per customer.
async fn sap_collection(st: &ModulesState) -> FailResult<()> {
    let codes = lookups::customers_with_integration(&st.ctx.db, "SAP SIEM").await?;
    for code in &codes {
        let Some((minutes, _)) = lookups::job_metadata(&st.ctx.db, SAP_COLLECTION).await? else {
            return Err(PyExc::AttributeError(
                "'NoneType' object has no attribute 'time_interval'".into(),
            )
            .into());
        };
        let request = sap_siem::construct_bounded(
            &schema::INVOKE_SAP,
            &kwargs(vec![
                ("customer_code", PyValue::Str(code.clone())),
                ("integration_name", PyValue::Str("SAP SIEM".into())),
                ("time_range", PyValue::Str(format!("{minutes}m"))),
            ]),
            sap_siem::utcnow(),
        )?;
        sap_siem::collect(st, &request).await?;
    }
    Ok(())
}

/// One of the seven analysis jobs: `extra_data` (`threshold=N,time_range=M`)
/// read per customer, its names kept across customers as Python's locals
/// are, then the analysis route.
async fn sap_analysis(st: &ModulesState, analysis: &Analysis) -> FailResult<()> {
    let codes = lookups::customers_with_integration(&st.ctx.db, "SAP SIEM").await?;
    let mut threshold: Option<PyValue> = None;
    let mut window: Option<PyValue> = None;
    for code in &codes {
        let Some((_, extra)) = lookups::job_metadata(&st.ctx.db, analysis.job_id).await? else {
            return Err(PyExc::AttributeError(
                "'NoneType' object has no attribute 'extra_data'".into(),
            )
            .into());
        };
        match extra {
            Some(extra) => {
                for part in extra.split(',') {
                    let pieces: Vec<&str> = part.split('=').collect();
                    let &[key, value] = pieces.as_slice() else {
                        return Err(PyExc::ValueError(if pieces.len() < 2 {
                            format!(
                                "not enough values to unpack (expected 2, got {})",
                                pieces.len()
                            )
                        } else {
                            "too many values to unpack (expected 2)".into()
                        })
                        .into());
                    };
                    if key == "threshold" {
                        threshold = Some(PyValue::Int(int_of(&PyValue::Str(value.into()))?));
                    } else if key == "time_range" {
                        window = Some(PyValue::Int(int_of(&PyValue::Str(value.into()))?));
                    }
                }
            }
            None => {
                threshold = Some(PyValue::Int("0".into()));
                window = Some(PyValue::Int(analysis.default_window.to_string()));
            }
        }
        let unbound = |name: &str| {
            Fail::other(
                "UnboundLocalError",
                format!(
                    "cannot access local variable '{name}' where it is not associated with a \
                     value"
                ),
            )
        };
        let t = threshold.clone().ok_or_else(|| unbound("threshold"))?;
        let w = window.clone().ok_or_else(|| unbound("time_range"))?;
        let iris = lookups::iris_customer_id(&st.ctx.db, code).await?;
        sap_siem::analyse(st, analysis, t, w, iris).await?;
    }
    Ok(())
}

/// The value the Python function returns (`Invoke*Response(success=True,
/// message=…)`), which a manual run answers as its `result`.
fn returned(message: &str) -> serde_json::Value {
    serde_json::json!({"success": true, "message": message})
}

/// A job's run: its outcome, then what the function returns.
type JobFut = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<serde_json::Value, JobError>> + Send>,
>;

/// A job's body, given the module state.
type JobRun = fn(Arc<ModulesState>) -> JobFut;

/// The analyses' return messages (`… invoked for <rule>.`).
fn analysis_message(job_id: &str) -> &'static str {
    match job_id {
        "invoke_sap_siem_integration_successful_user_login_with_different_ip" => {
            "SAP SIEM integration invoked for successful user login with different IP."
        }
        "invoke_sap_siem_integration_same_user_failed_login_from_different_ip" => {
            "SAP SIEM integration invoked for same user failed login from different IP."
        }
        "invoke_sap_siem_integration_same_user_failed_login_from_different_geo_location" => {
            "SAP SIEM integration invoked for same user failed login from different geo location."
        }
        "invoke_sap_siem_integration_same_user_successful_login_from_different_geo_location" => {
            "SAP SIEM integration invoked for same user successful login from different geo \
             location."
        }
        "invoke_sap_siem_integration_brute_force_failed_logins" => {
            "SAP SIEM integration invoked for brute force failed logins."
        }
        "invoke_sap_siem_integration_brute_force_failed_logins_same_ip" => {
            "SAP SIEM integration invoked for brute force failed logins from the same IP."
        }
        _ => "SAP SIEM integration invoked for successful login after multiple failed logins.",
    }
}

const SAP_SUSPICIOUS_DONE: &str = "SAP SIEM integration invoked for suspicious logins analysis.";
const SAP_MULTIPLE_DONE: &str =
    "SAP SIEM integration invoked for multiple logins from the same IP analysis.";

async fn duo_job(st: Arc<ModulesState>) -> Result<serde_json::Value, JobError> {
    collect_all(&st, "DUO", Module::Duo, "Duo").await?;
    Ok(returned("Duo integration invoked."))
}

async fn darktrace_job(st: Arc<ModulesState>) -> Result<serde_json::Value, JobError> {
    collect_all(&st, "Darktrace", Module::Darktrace, "Darktrace").await?;
    Ok(returned("Darktrace integration invoked."))
}

async fn carbonblack_job(st: Arc<ModulesState>) -> Result<serde_json::Value, JobError> {
    collect_all(&st, "CarbonBlack", Module::CarbonBlack, "CarbonBlack").await?;
    Ok(returned("Carbonblack integration invoked."))
}

async fn mimecast_job(st: Arc<ModulesState>, ttp: bool) -> Result<serde_json::Value, JobError> {
    mimecast_all(&st, ttp).await?;
    Ok(returned("Mimecast integration invoked."))
}

async fn sap_collection_job(st: Arc<ModulesState>) -> Result<serde_json::Value, JobError> {
    sap_collection(&st).await.map_err(failed)?;
    Ok(returned("SAP SIEM integration invoked."))
}

/// The two analyses Python commented out: the customers are read, nothing
/// else.
async fn sap_noop_job(
    st: Arc<ModulesState>,
    message: &'static str,
) -> Result<serde_json::Value, JobError> {
    lookups::customers_with_integration(&st.ctx.db, "SAP SIEM")
        .await
        .map_err(failed)?;
    Ok(returned(message))
}

/// The job specs, for `copilot`'s `scheduled_jobs()`.
pub fn job_specs(st: &ModulesState) -> Vec<JobSpec> {
    let st = Arc::new(st.clone());
    let spec = |id: &'static str, minutes: i64, run: JobRun| {
        let st = Arc::clone(&st);
        JobSpec::returning(id, minutes, move || run(Arc::clone(&st)))
    };
    let mut specs = vec![spec(HUNTRESS, 5, |st| {
        Box::pin(async move { huntress(&st).await })
    })];
    // The older jobs stamp `last_success` themselves, a manual run included.
    let stamping: [(&'static str, i64, JobRun); 8] = [
        (DUO, 5, |st| Box::pin(duo_job(st))),
        (DARKTRACE, 5, |st| Box::pin(darktrace_job(st))),
        (CARBONBLACK, 5, |st| Box::pin(carbonblack_job(st))),
        (MIMECAST, 5, |st| Box::pin(mimecast_job(st, false))),
        (MIMECAST_TTP, 15, |st| Box::pin(mimecast_job(st, true))),
        (SAP_COLLECTION, 5, |st| Box::pin(sap_collection_job(st))),
        (SAP_SUSPICIOUS_LOGINS, 5, |st| {
            Box::pin(sap_noop_job(st, SAP_SUSPICIOUS_DONE))
        }),
        (SAP_MULTIPLE_LOGINS, 5, |st| {
            Box::pin(sap_noop_job(st, SAP_MULTIPLE_DONE))
        }),
    ];
    for (id, minutes, run) in stamping {
        specs.push(spec(id, minutes, run).stamps_manual_runs());
    }
    for analysis in ANALYSES {
        let st = Arc::clone(&st);
        specs.push(
            JobSpec::returning(analysis.job_id, analysis.default_window, move || {
                let st = Arc::clone(&st);
                async move {
                    sap_analysis(&st, analysis).await.map_err(failed)?;
                    Ok(returned(analysis_message(analysis.job_id)))
                }
            })
            .stamps_manual_runs(),
        );
    }
    specs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_job_id_once() {
        let ids = job_ids();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
        assert_eq!(ids.len(), 16);
        assert!(!ids.contains(&"invoke_cato_integration_collect"));
    }

    /// `RUST_CAPABLE_JOBS` of `backend/app/schedulers/handover.py` (tests
    /// only: the Docker build has no `backend/`), as `copilot-scheduler`'s
    /// pin reads it.
    #[test]
    fn python_guards_every_job_here() {
        let src = include_str!("../../../backend/app/schedulers/handover.py");
        let start = src.find("RUST_CAPABLE_JOBS = (").expect("the tuple");
        let rest = &src[start..];
        let block = &rest[..rest.find("\n)").expect("its end")];
        let python: Vec<&str> = block
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"'))
            .filter_map(|l| l.split('"').next())
            .collect();
        for id in job_ids() {
            assert!(python.contains(&id), "{id} has no @rust_handover in Python");
        }
    }
}
