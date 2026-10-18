//! APScheduler's part of a Scheduler write, handed to the Python process
//! while APScheduler owns the schedule ([`crate::Mode::Handover`]).
//!
//! The write routes are answered here — validation, the
//! `scheduled_job_metadata` statements, this service's grid — but the job
//! store APScheduler runs from lives in the Python process, which pickles its
//! jobs (`apscheduler_jobs.job_state`) and wakes on them in memory. Writing
//! that store from here would leave a running APScheduler blind to the change
//! until its next wake-up, so the one step only it can take is handed to it:
//! `POST /api/scheduler/apscheduler_ops` (`app/schedulers/routes/scheduler.py`,
//! admin/analyst, the caller's token), the way the integrations' provisioning
//! reached `/provisioning_jobs` before. Each operation is the call the Python
//! route makes (`add_job` as `POST /add` or as `add_scheduler_jobs` calls it,
//! `job.reschedule`, `remove_job`, `job.pause`, `job.resume`); the answer says,
//! per operation, whether `find_job_by_id` found the job.
//!
//! Anything but a 2xx answer — APScheduler's own failure there, or no Python
//! backend configured — is the bare 500 Python's failure is.

use std::time::Duration;

use serde::Serialize;

use copilot_gateway::LegacyProxy;
use copilot_web::ApiError;

/// The hook's path on the Python backend.
pub const OPS_PATH: &str = "/api/scheduler/apscheduler_ops";

/// How long the hook may take (APScheduler's calls are in-memory and one
/// store write each).
pub const OPS_TIMEOUT: Duration = Duration::from_secs(60);

/// One APScheduler operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApsOp {
    /// `add`, `reschedule`, `remove`, `pause` or `resume`.
    pub op: &'static str,
    /// The job.
    pub job_id: String,
    /// The function an `add` schedules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// The interval (minutes) of an `add` or a `reschedule`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_interval: Option<i64>,
    /// `add` as `POST /add` calls it (APScheduler's job defaults) rather than
    /// as `add_scheduler_jobs` does (`coalesce=True, max_instances=1`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub defaults: bool,
}

impl ApsOp {
    /// `scheduler.add_job(func, "interval", minutes=…, id=…, replace_existing=True, …)`.
    pub fn add(job_id: &str, function_name: &str, minutes: i64, defaults: bool) -> Self {
        Self {
            op: "add",
            job_id: job_id.to_string(),
            function_name: Some(function_name.to_string()),
            time_interval: Some(minutes),
            defaults,
        }
    }

    /// `job.reschedule(trigger="interval", minutes=…)`.
    pub fn reschedule(job_id: &str, minutes: i64) -> Self {
        Self {
            op: "reschedule",
            job_id: job_id.to_string(),
            function_name: None,
            time_interval: Some(minutes),
            defaults: false,
        }
    }

    /// `remove_job`, `job.pause()` or `job.resume()`.
    pub fn simple(op: &'static str, job_id: &str) -> Self {
        Self {
            op,
            job_id: job_id.to_string(),
            function_name: None,
            time_interval: None,
            defaults: false,
        }
    }
}

#[derive(Serialize)]
struct OpsRequest<'a> {
    ops: &'a [ApsOp],
}

/// Run `ops` in the Python process's APScheduler, in order; per operation,
/// whether the job was found.
pub async fn apscheduler_ops(
    legacy: Option<&LegacyProxy>,
    bearer: &str,
    ops: &[ApsOp],
) -> Result<Vec<bool>, ApiError> {
    let Some(legacy) = legacy else {
        return Err(ApiError::internal(
            "APScheduler runs in the Python backend, and none is configured \
             (COPILOT_LEGACY_URL); set COPILOT_SCHEDULER_OWNER=rust to schedule here",
        ));
    };
    let mut req = legacy
        .client()
        .post(legacy.upstream_url(OPS_PATH))
        .timeout(OPS_TIMEOUT)
        .json(&OpsRequest { ops });
    if !bearer.is_empty() {
        req = req.bearer_auth(bearer);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("APScheduler hand-off: {e}")))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        tracing::error!(%status, body = %text, "APScheduler refused the operation");
        return Err(ApiError::internal(format!(
            "APScheduler hand-off answered {status}: {text}"
        )));
    }
    let found: Vec<bool> = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("found")?
                .as_array()?
                .iter()
                .map(serde_json::Value::as_bool)
                .collect()
        })
        .ok_or_else(|| ApiError::internal(format!("APScheduler hand-off answered {text}")))?;
    if found.len() != ops.len() {
        return Err(ApiError::internal(format!(
            "APScheduler hand-off answered {} results for {} operations",
            found.len(),
            ops.len()
        )));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_is_the_hook_s_model() {
        let ops = [
            ApsOp::add("x", "agent_sync", 9, true),
            ApsOp::add("agent_sync", "agent_sync", 15, false),
            ApsOp::reschedule("x", 7),
            ApsOp::simple("pause", "x"),
        ];
        assert_eq!(
            serde_json::to_string(&OpsRequest { ops: &ops }).unwrap_or_default(),
            r#"{"ops":[{"op":"add","job_id":"x","function_name":"agent_sync","time_interval":9,"defaults":true},{"op":"add","job_id":"agent_sync","function_name":"agent_sync","time_interval":15},{"op":"reschedule","job_id":"x","time_interval":7},{"op":"pause","job_id":"x"}]}"#
        );
    }
}
