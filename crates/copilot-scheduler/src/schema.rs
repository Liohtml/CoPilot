//! Response shapes of `app/schedulers/schema/scheduler.py`, field order kept.

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use serde::Serialize;

use copilot_core::time::pydantic;
use copilot_db::scheduler::JobMetadataRow;

use crate::jobstore::ApsJob;

/// `Job`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobOut {
    /// `job.id`.
    pub id: String,
    /// `job.name`.
    pub name: String,
    /// The metadata row's `enabled`, else whether APScheduler has a next run.
    pub enabled: bool,
    /// The metadata row's interval (minutes), else 0.
    pub time_interval: i64,
    /// The metadata row's `last_success`.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub last_success: Option<NaiveDateTime>,
    /// The metadata row's `job_description`.
    pub description: Option<String>,
}

impl JobOut {
    /// `build_job_payload(job, job_metadata)`.
    pub fn build(job: &ApsJob, meta: Option<&JobMetadataRow>) -> Self {
        Self {
            id: job.id.clone(),
            name: job.name.clone(),
            enabled: meta.map_or(job.next_run.is_scheduled(), |m| m.enabled),
            time_interval: meta.map_or(0, |m| i64::from(m.time_interval)),
            last_success: meta.and_then(|m| m.last_success),
            description: meta.and_then(|m| m.job_description.clone()),
        }
    }
}

/// `JobsResponse`.
#[derive(Debug, Serialize)]
pub struct JobsResponse {
    /// The jobs.
    pub jobs: Vec<JobOut>,
    /// Always true.
    pub success: bool,
    /// `Jobs successfully retrieved.`
    pub message: &'static str,
}

/// `JobDetailResponse`.
#[derive(Debug, Serialize)]
pub struct JobDetailResponse {
    /// The job.
    pub job: JobOut,
    /// Always true.
    pub success: bool,
    /// `Job successfully retrieved.`
    pub message: &'static str,
}

/// `JobsNextRunResponse`.
#[derive(Debug, Serialize)]
pub struct JobsNextRunResponse {
    /// Rendered as Pydantic renders an aware `datetime`.
    pub next_run_time: String,
    /// Always true.
    pub success: bool,
    /// `Next run time successfully retrieved.`
    pub message: &'static str,
}

/// The manual run's answer: `{"success", "message", "result"}`, `result`
/// what the job's function returned (`null` for most jobs).
#[derive(Debug, Serialize)]
pub struct RunResponse {
    /// Always true.
    pub success: bool,
    /// `Job executed successfully`.
    pub message: &'static str,
    /// The function's return value, as FastAPI encodes it.
    pub result: Option<serde_json::Value>,
}

/// An aware UTC time as Pydantic renders it (`…Z`, microseconds only when
/// there are some).
pub fn pydantic_utc(t: DateTime<Utc>) -> String {
    let micros = t.timestamp_subsec_micros();
    let whole = t.to_rfc3339_opts(SecondsFormat::Secs, true);
    if micros == 0 {
        whole
    } else {
        // `2026-10-15T18:00:00Z` → `2026-10-15T18:00:00.123456Z`
        format!("{}.{micros:06}Z", whole.trim_end_matches('Z'))
    }
}

/// Pydantic's `ValidationError` text for `JobsNextRunResponse(next_run_time=None)`
/// — what the route answers (400, through the `ValueError` handler) for a
/// paused job. The URL names pydantic's minor version (2.13).
pub const PAUSED_NEXT_RUN_ERROR: &str = "1 validation error for JobsNextRunResponse\n\
next_run_time\n  Input should be a valid datetime [type=datetime_type, input_value=None, \
input_type=NoneType]\n    For further information visit \
https://errors.pydantic.dev/2.13/v/datetime_type";

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn utc_rendering() {
        let t = Utc
            .with_ymd_and_hms(2026, 10, 15, 18, 0, 0)
            .single()
            .unwrap_or_default();
        assert_eq!(pydantic_utc(t), "2026-10-15T18:00:00Z");
        let t = t + chrono::Duration::microseconds(1234);
        assert_eq!(pydantic_utc(t), "2026-10-15T18:00:00.001234Z");
    }

    #[test]
    fn job_payload_field_order() {
        let job = ApsJob {
            id: "a".into(),
            name: "f".into(),
            func: "m:f".into(),
            next_run: crate::jobstore::NextRun::Paused,
        };
        let v = serde_json::to_string(&JobOut::build(&job, None)).unwrap_or_default();
        assert_eq!(
            v,
            r#"{"id":"a","name":"f","enabled":false,"time_interval":0,"last_success":null,"description":null}"#
        );
    }
}
