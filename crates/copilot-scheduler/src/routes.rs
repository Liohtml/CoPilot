//! `/api/scheduler` — `app/schedulers/routes/scheduler.py` — and Mimecast's
//! `POST /api/mimecast/invoke/scheduler/{siem,ttp}`
//! (`app/integrations/mimecast/routes/provision.py`). Every route is
//! answered here; under the hand-over only APScheduler's own calls go to the
//! Python process ([`crate::handoff`]).
//!
//! | Route | Here |
//! |---|---|
//! | `GET /` (list), `GET /{job_id}`, `GET /next_run/{job_id}` | APScheduler's store (read only, [`crate::jobstore`]) under the hand-over — for a job this service runs now, *its* next run —, this service's grid under the ownership |
//! | `POST /jobs/run/{job_id}` | run here (`get_function_by_name(job.name)`: CarbonBlack's callable found too, §4), serialized with APScheduler by the run lock |
//! | `POST /add`, `PUT /update/{job_id}`, `DELETE /{job_id}`, `POST /start/{job_id}`, `POST /pause/{job_id}`, `POST /provisioning_jobs` | [`crate::writes`]: the rows and this service's grid, APScheduler's part handed to it under the hand-over |
//! | `POST /apscheduler_ops` | the hand-off hook itself: Python's, never reachable through this service (404) |
//!
//! Every Scheduler route is `require_any_scope("admin", "analyst")` (router
//! level), so the token is checked before anything else; Mimecast's two
//! routes declare the same dependency each.

use axum::Router;
use axum::extract::{FromRef, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};

use copilot_web::validate::{IntRules, StrRules, Validator, loc};
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs, WithJson,
};

use crate::job::{Mode, Owner};
use crate::provisioning;
use crate::runner::{ManualRun, Scheduler};
use crate::schema::{
    JobDetailResponse, JobsNextRunResponse, JobsResponse, RunResponse, pydantic_utc,
};
use crate::services;
use crate::writes::{self, Found};

/// State of the Scheduler routes.
#[derive(Clone, Debug)]
pub struct SchedulerState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The jobs this service can run, and the schedule.
    pub scheduler: Scheduler,
}

impl FromRef<SchedulerState> for AppContext {
    fn from_ref(s: &SchedulerState) -> AppContext {
        s.ctx.clone()
    }
}

type Auth = Authorized<AdminOrAnalyst>;

/// `search_query`'s `limit`: `Query(None, ge=1, le=1000)`.
const SEARCH_LIMIT: IntRules = IntRules {
    ge: Some(1),
    le: Some(1000),
};

/// The router, to be nested at `/api/scheduler`.
pub fn router(state: SchedulerState) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/add", post(add))
        .route("/provisioning_jobs", post(provisioning_jobs))
        .route("/apscheduler_ops", post(not_found))
        .route("/{job_id}", get(detail).delete(delete))
        .route("/next_run/{job_id}", get(next_run))
        .route("/jobs/run/{job_id}", post(run))
        .route("/start/{job_id}", post(start))
        .route("/pause/{job_id}", post(pause))
        .route("/update/{job_id}", put(update))
        .method_not_allowed_fallback(|| async { ApiError::MethodNotAllowed })
        .with_state(state)
}

/// Mimecast's two scheduler routes, at their full paths.
pub fn mimecast_router(state: SchedulerState) -> Router {
    Router::new()
        .route("/api/mimecast/invoke/scheduler/siem", post(mimecast_siem))
        .route("/api/mimecast/invoke/scheduler/ttp", post(mimecast_ttp))
        .with_state(state)
}

fn json<T: serde::Serialize>(body: T) -> Response {
    axum::Json(body).into_response()
}

fn success(message: &str) -> Response {
    json(serde_json::json!({"success": true, "message": message}))
}

fn not_found_job() -> Response {
    json(serde_json::json!({"success": false, "message": "Job not found"}))
}

async fn not_found() -> ApiError {
    ApiError::RouteNotFound
}

/// A required `str` query parameter (`Field required` when absent).
fn req_str(v: &mut Validator, q: &QueryPairs, name: &str) -> String {
    match q.get(name) {
        Some(s) => s.to_string(),
        None => {
            v.missing(loc("query", name));
            String::new()
        }
    }
}

/// A required `int` query parameter, Pydantic's lax `str` → `int`
/// (unbounded: the interval checks see the value Python would see).
fn req_int(v: &mut Validator, q: &QueryPairs, name: &str) -> i128 {
    let Some(raw) = q.get(name) else {
        v.missing(loc("query", name));
        return 0;
    };
    copilot_web::query::pydantic_int(raw).unwrap_or_else(|| {
        v.push(
            "int_parsing",
            loc("query", name),
            "Input should be a valid integer, unable to parse string as an integer",
        );
        0
    })
}

async fn list(_auth: Auth, State(st): State<SchedulerState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let search = q.opt_str(&mut v, "search", StrRules::any());
    let limit = q.opt_int(&mut v, "limit", SEARCH_LIMIT);
    v.finish()?;
    let jobs = services::list(&st.scheduler, search.as_deref(), limit).await?;
    Ok(json(JobsResponse {
        jobs,
        success: true,
        message: "Jobs successfully retrieved.",
    }))
}

async fn detail(
    _auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    let job = services::detail(&st.scheduler, &job_id).await?;
    Ok(json(JobDetailResponse {
        job,
        success: true,
        message: "Job successfully retrieved.",
    }))
}

/// This service's next run of `job`, when it runs that job now (the
/// hand-over: APScheduler's paused copy has none).
async fn rust_next_run(s: &Scheduler, job_id: &str, name: &str) -> Option<String> {
    if job_id != name || !s.opted_in(job_id) {
        return None;
    }
    match s.owner(job_id).await {
        Ok(Owner::Rust) => s.next_run(job_id).map(pydantic_utc),
        _ => None,
    }
}

async fn next_run(
    _auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    let s = &st.scheduler;
    let job = services::find_job(s, &job_id).await?;
    let at = match s.mode() {
        Mode::Handover => match rust_next_run(s, &job.id, &job.name).await {
            Some(at) => at,
            None => services::stored_next_run(&job)?,
        },
        Mode::Rust => services::stored_next_run(&job)?,
    };
    Ok(json(JobsNextRunResponse {
        next_run_time: at,
        success: true,
        message: "Next run time successfully retrieved.",
    }))
}

async fn run(
    _auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    let s = &st.scheduler;
    let Some(job) = services::lookup(s, &job_id).await? else {
        return Err(ApiError::not_found("Job not found"));
    };
    // `get_function_by_name(job.name)` inside the route's `try`: a failure is
    // `HTTPException(500, str(e))`.
    let Some(key) = crate::functions::run_key(&job.name).filter(|k| s.knows(k)) else {
        return Err(ApiError::server_error(crate::functions::unknown_function(
            &job.name,
        )));
    };
    tracing::info!(job_id = %job.id, function = %job.name, "Running job manually");
    match s.run_now(key).await? {
        ManualRun::Ran(Ok(result)) => Ok(json(RunResponse {
            success: true,
            message: "Job executed successfully",
            result,
        })),
        ManualRun::Ran(Err(e)) => Err(ApiError::server_error(e.0)),
        ManualRun::Busy => Err(ApiError::server_error(format!(
            "Job {key} is already running; try again when it has finished"
        ))),
        ManualRun::NotOwned(_) => Err(ApiError::server_error(crate::functions::unknown_function(
            &job.name,
        ))),
    }
}

async fn start(
    auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    Ok(
        match writes::start(&st.scheduler, &auth.user, &job_id).await? {
            Found::Done => success("Job started successfully"),
            Found::NotFound => not_found_job(),
        },
    )
}

async fn pause(
    auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    Ok(
        match writes::pause(&st.scheduler, &auth.user, &job_id).await? {
            Found::Done => success("Job paused successfully"),
            Found::NotFound => not_found_job(),
        },
    )
}

async fn add(auth: Auth, State(st): State<SchedulerState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let job_id = req_str(&mut v, &q, "job_id");
    let function_name = req_str(&mut v, &q, "function_name");
    let minutes = req_int(&mut v, &q, "time_interval");
    let extra_data = q.opt_str(&mut v, "extra_data", StrRules::any());
    v.finish()?;
    writes::add(
        &st.scheduler,
        &auth.user,
        &job_id,
        &function_name,
        minutes,
        extra_data.as_deref(),
    )
    .await?;
    Ok(success("Job added successfully"))
}

async fn update(
    auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let minutes = req_int(&mut v, &q, "time_interval");
    let extra_data = q.opt_str(&mut v, "extra_data", StrRules::any());
    v.finish()?;
    Ok(
        match writes::update(
            &st.scheduler,
            &auth.user,
            &job_id,
            minutes,
            extra_data.as_deref(),
        )
        .await?
        {
            Found::Done => success("Job updated successfully"),
            Found::NotFound => not_found_job(),
        },
    )
}

async fn delete(
    auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    Ok(
        match writes::delete(&st.scheduler, &auth.user, &job_id).await? {
            Found::Done => success("Job deleted successfully"),
            Found::NotFound => not_found_job(),
        },
    )
}

async fn provisioning_jobs(
    State(st): State<SchedulerState>,
    WithJson(auth, body): WithJson<Auth>,
) -> ApiResult {
    let jobs = provisioning::read(&body)?;
    provisioning::check_allowlist(&jobs)?;
    provisioning::check_tenancy(&st.ctx, &auth.user, &jobs).await?;
    let requests: Vec<writes::JobRequest> = jobs.into_iter().map(|j| j.job).collect();
    writes::add_scheduler_jobs(&st.scheduler, &auth.user, &requests).await?;
    Ok(success("Jobs added successfully"))
}

async fn mimecast(st: &SchedulerState, auth: &Auth, q: &QueryPairs, ttp: bool) -> ApiResult {
    let mut v = Validator::new();
    let minutes = req_int(&mut v, q, "time_interval");
    v.finish()?;
    writes::add_scheduler_job(
        &st.scheduler,
        &auth.user,
        &provisioning::mimecast_job(ttp, minutes),
    )
    .await?;
    Ok(success("Mimecast integration scheduled."))
}

async fn mimecast_siem(auth: Auth, State(st): State<SchedulerState>, q: QueryPairs) -> ApiResult {
    mimecast(&st, &auth, &q, false).await
}

async fn mimecast_ttp(auth: Auth, State(st): State<SchedulerState>, q: QueryPairs) -> ApiResult {
    mimecast(&st, &auth, &q, true).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_ints_are_pydantic_s() {
        let q = QueryPairs::parse(Some("time_interval=+1_0.00&bad=1.5"));
        let mut v = Validator::new();
        assert_eq!(req_int(&mut v, &q, "time_interval"), 10);
        assert!(!v.has_errors());
        req_int(&mut v, &q, "bad");
        req_int(&mut v, &q, "absent");
        assert_eq!(v.errors().len(), 2);
    }
}
