//! `/api/scheduler` — `app/schedulers/routes/scheduler.py`.
//!
//! The routes read and act on APScheduler, which lives in the Python
//! process (jobs pickled in `apscheduler_jobs`). This service answers what it
//! can answer exactly and hands the rest to the Python backend:
//!
//! | Route | Here |
//! |---|---|
//! | `GET /` (list), `GET /{job_id}` | answered from `apscheduler_jobs` (read only, [`crate::jobstore`]) and `scheduled_job_metadata` |
//! | `GET /next_run/{job_id}` | the same; for a job this service runs now, *its* next run |
//! | `POST /jobs/run/{job_id}` | run here when this service owns the job, else forwarded |
//! | `POST /start/{job_id}`, `POST /pause/{job_id}` | forwarded (they resume/pause APScheduler's job); for a job this service can run, the hand-over flag (`enabled`) follows |
//! | `POST /add`, `PUT /update/{job_id}`, `DELETE /{job_id}` | not routes here: the binary forwards them |
//!
//! Every route is `require_any_scope("admin", "analyst")` (router level), so
//! the token is checked before anything else. A job state this reader cannot
//! decode, or a next run in a timezone it does not convert, is answered by
//! the Python backend.

use axum::Router;
use axum::body::Body;
use axum::extract::{FromRef, OriginalUri, Path, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::StatusCode;

use copilot_db::scheduler as db;
use copilot_gateway::LegacyProxy;
use copilot_web::validate::{IntRules, StrRules, Validator};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs};

use crate::job::Owner;
use crate::runner::{ManualRun, Scheduler};
use crate::schema::{
    JobDetailResponse, JobsNextRunResponse, JobsResponse, RunResponse, pydantic_utc,
};
use crate::services::{self, Unanswerable};

/// State of the Scheduler routes.
#[derive(Clone, Debug)]
pub struct SchedulerState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The jobs this service can run.
    pub scheduler: Scheduler,
    /// The Python backend, which owns APScheduler.
    pub legacy: Option<LegacyProxy>,
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

/// Largest forwarded answer read back (start/pause answer a few dozen bytes).
const MAX_FORWARDED_BODY: usize = 1 << 20;

/// The router, to be nested at `/api/scheduler`.
pub fn router(state: SchedulerState) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/{job_id}", get(detail))
        .route("/next_run/{job_id}", get(next_run))
        .route("/jobs/run/{job_id}", post(run))
        .route("/start/{job_id}", post(start))
        .route("/pause/{job_id}", post(pause))
        .with_state(state)
}

fn json<T: serde::Serialize>(body: T) -> Response {
    axum::Json(body).into_response()
}

/// The request as it reached the service: `nest` strips `/api/scheduler`
/// from the URI a handler sees, and the Python backend needs it back.
fn with_original_uri(mut req: Request) -> Request {
    if let Some(OriginalUri(uri)) = req.extensions().get::<OriginalUri>().cloned() {
        *req.uri_mut() = uri;
    }
    req
}

/// Forward to the Python backend, unchanged.
async fn forward(proxy: &LegacyProxy, req: Request) -> Response {
    proxy.forward(with_original_uri(req)).await
}

/// Let the Python backend answer; without one, an unhandled error.
async fn delegate(st: &SchedulerState, req: Request, why: &str) -> ApiResult {
    match &st.legacy {
        Some(proxy) => {
            tracing::debug!(reason = why, path = %req.uri().path(), "answered by the legacy backend");
            Ok(forward(proxy, req).await)
        }
        None => Err(ApiError::internal(format!(
            "{why}, and no legacy backend is configured"
        ))),
    }
}

async fn answer(st: &SchedulerState, req: Request, r: Result<Response, Unanswerable>) -> ApiResult {
    match r {
        Ok(resp) => Ok(resp),
        Err(Unanswerable::Api(e)) => Err(e),
        Err(Unanswerable::Delegate(why)) => delegate(st, req, &why).await,
    }
}

async fn list(
    _auth: Auth,
    State(st): State<SchedulerState>,
    q: QueryPairs,
    req: Request,
) -> ApiResult {
    let mut v = Validator::new();
    let search = q.opt_str(&mut v, "search", StrRules::any());
    let limit = q.opt_int(&mut v, "limit", SEARCH_LIMIT);
    v.finish()?;
    let r = services::list(&st.ctx.db, search.as_deref(), limit)
        .await
        .map(|jobs| {
            json(JobsResponse {
                jobs,
                success: true,
                message: "Jobs successfully retrieved.",
            })
        });
    answer(&st, req, r).await
}

async fn detail(
    _auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
    req: Request,
) -> ApiResult {
    let r = services::detail(&st.ctx.db, &job_id).await.map(|job| {
        json(JobDetailResponse {
            job,
            success: true,
            message: "Job successfully retrieved.",
        })
    });
    answer(&st, req, r).await
}

/// This service's next run of `job`, when it runs that job now.
async fn rust_next_run(st: &SchedulerState, job_id: &str, name: &str) -> Option<String> {
    if job_id != name || !st.scheduler.opted_in(job_id) {
        return None;
    }
    match st.scheduler.owner(job_id).await {
        Ok(Owner::Rust) => st.scheduler.next_run(job_id).map(pydantic_utc),
        _ => None,
    }
}

async fn next_run(
    _auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
    req: Request,
) -> ApiResult {
    let r = async {
        let job = services::find_job(&st.ctx.db, &job_id).await?;
        let at = match rust_next_run(&st, &job.id, &job.name).await {
            Some(at) => at,
            None => services::stored_next_run(&job)?,
        };
        Ok(json(JobsNextRunResponse {
            next_run_time: at,
            success: true,
            message: "Next run time successfully retrieved.",
        }))
    }
    .await;
    answer(&st, req, r).await
}

async fn run(
    _auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
    req: Request,
) -> ApiResult {
    let job = match services::lookup(&st.ctx.db, &job_id).await {
        Ok(Some(job)) => job,
        Ok(None) => return Err(ApiError::not_found("Job not found")),
        Err(Unanswerable::Api(e)) => return Err(e),
        Err(Unanswerable::Delegate(why)) => return delegate(&st, req, &why).await,
    };
    // `get_function_by_name(job.name)`: the job's function decides.
    if !st.scheduler.opted_in(&job.name) {
        return delegate(&st, req, "the job runs in APScheduler").await;
    }
    tracing::info!(job_id = %job.id, function = %job.name, "Running job manually");
    match st.scheduler.run_now(&job.name).await? {
        ManualRun::Ran(Ok(())) => Ok(json(RunResponse {
            success: true,
            message: "Job executed successfully",
            result: None,
        })),
        ManualRun::Ran(Err(e)) => Err(ApiError::server_error(e.0)),
        ManualRun::Busy => Err(ApiError::server_error(format!(
            "Job {} is already running; try again when it has finished",
            job.name
        ))),
        ManualRun::NotOwned(owner) => {
            delegate(&st, req, &format!("the job's owner is {}", owner.as_str())).await
        }
    }
}

/// Forward and read the answer back (it is tiny): `(status, success, response)`.
async fn forward_buffered(proxy: &LegacyProxy, req: Request) -> (StatusCode, bool, Response) {
    let resp = forward(proxy, req).await;
    let (parts, body) = resp.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_FORWARDED_BODY).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(err = %e, "cannot read the legacy backend's answer");
            return (
                StatusCode::BAD_GATEWAY,
                false,
                ApiError::internal(e).into_response(),
            );
        }
    };
    let success = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("success").and_then(serde_json::Value::as_bool))
        .unwrap_or(false);
    let status = parts.status;
    (
        status,
        status == StatusCode::OK && success,
        Response::from_parts(parts, Body::from(bytes)),
    )
}

async fn start(
    _auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
    req: Request,
) -> ApiResult {
    let Some(proxy) = st.legacy.clone() else {
        return Err(ApiError::RouteNotFound);
    };
    if !st.scheduler.knows(&job_id) {
        return Ok(forward(&proxy, req).await);
    }
    // Hand back first, so this service stops before APScheduler resumes; a
    // refusal (no such job) restores the flag.
    let before = db::set_enabled(&st.ctx.db, &job_id, true).await?;
    let (_, ok, resp) = forward_buffered(&proxy, req).await;
    if !ok && before == Some(false) {
        db::set_enabled(&st.ctx.db, &job_id, false).await?;
    } else if ok && before == Some(false) {
        tracing::info!(job_id, "scheduled job handed back to APScheduler");
    }
    Ok(resp)
}

async fn pause(
    _auth: Auth,
    State(st): State<SchedulerState>,
    Path(job_id): Path<String>,
    req: Request,
) -> ApiResult {
    let Some(proxy) = st.legacy.clone() else {
        return Err(ApiError::RouteNotFound);
    };
    if !st.scheduler.knows(&job_id) {
        return Ok(forward(&proxy, req).await);
    }
    let (_, ok, resp) = forward_buffered(&proxy, req).await;
    // Only a job that was running in APScheduler is handed over here.
    if ok && db::set_enabled(&st.ctx.db, &job_id, false).await? == Some(true) {
        let to = if st.scheduler.opted_in(&job_id) {
            "this service"
        } else {
            "nobody (not opted in here)"
        };
        tracing::info!(job_id, to, "scheduled job disabled in APScheduler");
    }
    Ok(resp)
}
