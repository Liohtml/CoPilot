//! `POST /api/scheduler/provisioning_jobs` — the integrations' jobs, as
//! their `/provision` routes register them — and Mimecast's two
//! `/invoke/scheduler/*` routes, on [`crate::writes::add_scheduler_jobs`].

use serde_json::{Map, Value};

use copilot_web::validate::{Loc, StrRules, Validator};
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::writes::JobRequest;

/// `PROVISIONING_JOBS` of `routes/scheduler.py`: the jobs the integrations'
/// `/provision` routes register (`test_scheduler_provisioning_jobs.py` pins
/// the Python set to those routes; a test here pins this one to it).
pub const PROVISIONING_JOBS: &[&str] = &[
    "invoke_huntress_integration_collect",
    "invoke_darktrace_integration_collect",
    "invoke_duo_integration_collect",
    "invoke_cato_integration_collect",
    "invoke_carbonblack_integration_collection",
    "invoke_mimecast_integration_ttp",
    "invoke_mimecast_integration",
    "invoke_sap_siem_integration_collection",
    "invoke_sap_siem_integration_suspicious_logins_analysis",
    "invoke_sap_siem_integration_multiple_logins_same_ip_analysis",
];

/// One job of the body, with the customer it is registered for (a field
/// Python's `CreateSchedulerRequest` does not declare, so ignores).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningJob {
    /// The job.
    pub job: JobRequest,
    /// `customer_code`, when the job names one.
    pub customer_code: Option<String>,
}

fn int_field(v: &mut Validator, obj: &Map<String, Value>, at: &Loc, name: &str) -> i128 {
    let mut l = at.clone();
    l.push(copilot_web::validate::LocPart::Key(name.into()));
    let invalid = |v: &mut Validator, l: Loc| {
        v.push(
            "int_parsing",
            l,
            "Input should be a valid integer, unable to parse string as an integer",
        );
    };
    match obj.get(name) {
        None => {
            v.missing(l);
            0
        }
        Some(Value::String(s)) => copilot_web::query::pydantic_int(s).unwrap_or_else(|| {
            invalid(v, l);
            0
        }),
        // A big JSON integer reaches serde_json as a float: still an int.
        Some(Value::Number(n))
            if n.as_i64().is_none() && n.as_f64().is_some_and(f64::is_finite) =>
        {
            let f = n.as_f64().unwrap_or_default();
            if f.fract() == 0.0 {
                #[allow(clippy::cast_possible_truncation)]
                let i = f as i128;
                i
            } else {
                v.push(
                    "int_from_float",
                    l,
                    "Input should be a valid integer, got a number with a fractional part",
                );
                0
            }
        }
        Some(other) => i128::from(
            v.check_int(&l, other, copilot_web::validate::IntRules::default())
                .unwrap_or_default(),
        ),
    }
}

/// `ProvisioningJobsRequest` as Pydantic reads it (`jobs:
/// List[CreateSchedulerRequest]`).
pub fn read_body(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Vec<ProvisioningJob> {
    let mut out = Vec::new();
    for (l, item) in v.list(obj, at, "jobs", true) {
        let Some(job) = v.nested(item, &l, "CreateSchedulerRequest") else {
            continue;
        };
        let function_name = v.req_str(job, &l, "function_name", StrRules::any());
        let job_id = v.req_str(job, &l, "job_id", StrRules::any());
        let time_interval = int_field(v, job, &l, "time_interval");
        let customer_code = match job.get("customer_code") {
            Some(Value::String(c)) => Some(c.clone()),
            _ => None,
        };
        out.push(ProvisioningJob {
            job: JobRequest {
                function_name,
                job_id,
                time_interval,
            },
            customer_code,
        });
    }
    out
}

/// Read the body (`body_loc()` at its root).
pub fn read(body: &copilot_web::JsonBody) -> Result<Vec<ProvisioningJob>, ApiError> {
    body.model(read_body)
}

/// The route's own check, before any job is added: each job one of
/// [`PROVISIONING_JOBS`], under its own function name.
pub fn check_allowlist(jobs: &[ProvisioningJob]) -> Result<(), ApiError> {
    for j in jobs {
        if !PROVISIONING_JOBS.contains(&j.job.job_id.as_str())
            || j.job.function_name != j.job.job_id
        {
            return Err(ApiError::bad_request(format!(
                "Job {} is not an integration provisioning job",
                j.job.job_id
            )));
        }
    }
    Ok(())
}

/// The tenancy check Python does not make (§4): a deployment-wide caller
/// registers any job; anyone else only jobs that name one of their
/// customers — a job naming none is refused (fail closed), since every one
/// of these collects for every customer holding the integration.
pub async fn check_tenancy(
    ctx: &AppContext,
    user: &CurrentUser,
    jobs: &[ProvisioningJob],
) -> Result<(), ApiError> {
    let access = user.access(ctx).await?;
    if access.is_all() {
        return Ok(());
    }
    for j in jobs {
        match &j.customer_code {
            Some(code) => access.enforce_customer(code)?,
            None => access.enforce_owned(None, &format!("job {}", j.job.job_id))?,
        }
    }
    Ok(())
}

/// Mimecast's `POST /invoke/scheduler/{siem,ttp}`: the job each registers.
///
/// `/ttp` registers `invoke_mimecast_integration_ttp` under the job id
/// `invoke_mimecast_integration` in Python — it replaces the SIEM job's
/// function with the TTP one (the SIEM collection stops) and leaves the TTP
/// job's row as it was. Here it schedules the TTP job under its own id (§4:
/// Python fails, Rust works).
pub fn mimecast_job(ttp: bool, minutes: i128) -> JobRequest {
    let id = if ttp {
        "invoke_mimecast_integration_ttp"
    } else {
        "invoke_mimecast_integration"
    };
    JobRequest {
        function_name: id.to_string(),
        job_id: id.to_string(),
        time_interval: minutes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowlist_is_python_s() {
        let src = include_str!("../../../backend/app/schedulers/routes/scheduler.py");
        let start = src.find("PROVISIONING_JOBS = frozenset(").unwrap_or(0);
        let rest = &src[start..];
        let block = &rest[..rest.find("},").unwrap_or(rest.len())];
        let python: Vec<&str> = block
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"'))
            .filter_map(|l| l.split('"').next())
            .collect();
        let mut python = python;
        python.sort_unstable();
        let mut ours = PROVISIONING_JOBS.to_vec();
        ours.sort_unstable();
        assert_eq!(python, ours);
    }

    #[test]
    fn the_body_reads_as_pydantic_does() {
        let body = copilot_web::JsonBody::Value(serde_json::json!({"jobs": [
            {"function_name": "a", "job_id": "a", "time_interval": "1_5", "customer_code": "c"},
            {"function_name": "b", "job_id": "b", "time_interval": 5.0}
        ]}));
        let jobs = read(&body).unwrap_or_default();
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].job.time_interval, 15);
        assert_eq!(jobs[0].customer_code.as_deref(), Some("c"));
        assert_eq!(jobs[1].job.time_interval, 5);
        let bad = copilot_web::JsonBody::Value(serde_json::json!({"jobs": [{"job_id": 1}]}));
        let e = read(&bad).unwrap_err();
        assert_eq!(e.status(), 422);
        assert!(check_allowlist(&jobs).is_err());
    }
}
