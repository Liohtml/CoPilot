//! `/api/ai_analyst` — port of `app/ai_analyst/routes/ai_analyst.py`.
//!
//! All routes: `require_any_scope("admin", "analyst")`. Each handler checks
//! in FastAPI's order: token → path parameters → object tenancy → query →
//! body. Object tenancy is fail-closed: an id that resolves to no owner
//! (including one that does not exist) is a 403 for scoped callers and a 404
//! from the service for admins — Talon's job auto-create therefore needs an
//! admin token, as before.
//!
//! Differences from the Python routes, both closing a tenant leak:
//! - `GET /alerts_with_reports` intersects `customer_codes` with the caller's
//!   customers (`scoped_customer_codes`); Python passed them through, so a
//!   scoped analyst sending none saw every tenant.
//! - `POST /jobs` re-checks the owner of an *existing* job id before
//!   relabelling it.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, patch, post};
use bytes::Bytes;
use serde_json::json;

use copilot_db::ai_analyst::{self as db, Owned};
use copilot_db::alerts;
use copilot_talon::TalonState;
use copilot_web::respond::envelope;
use copilot_web::validate::{IntRules, StrRules, Validator, parse_body_model, path_int_dep};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs, ok};

use crate::schema::{
    AlertWithReportResponse, CreateJobRequest, IocResponse, JobResponse, PalaceLessonResponse,
    QueuePalaceLessonRequest, ReplayRequest, ReportResponse, ReviewResponse, SubmitIocsRequest,
    SubmitReportRequest, SubmitReviewRequest, UpdateJobRequest,
};
use crate::services;

type Auth = Authorized<AdminOrAnalyst>;

/// The router, to be nested at `/api/ai_analyst`.
pub fn router(state: TalonState) -> Router {
    Router::new()
        .route("/jobs", post(create_job))
        .route("/jobs/{job_id}", patch(update_job).get(get_job))
        .route("/jobs/alert/{alert_id}", get(jobs_by_alert))
        .route("/jobs/customer/{customer_code}", get(jobs_by_customer))
        .route("/reports", post(submit_report))
        .route("/reports/alert/{alert_id}", get(reports_by_alert))
        .route("/reports/{report_id}", get(alert_with_report_by_report))
        .route("/reports/{report_id}/review", post(submit_review))
        .route("/reports/{report_id}/review/mine", get(my_review))
        .route("/reports/{report_id}/replay", post(replay))
        .route("/iocs", post(submit_iocs))
        .route("/iocs/report/{report_id}", get(iocs_by_report))
        .route("/iocs/alert/{alert_id}", get(iocs_by_alert))
        .route("/iocs/customer/{customer_code}", get(iocs_by_customer))
        .route("/iocs/{ioc_id}", get(get_ioc))
        .route("/alerts_with_reports", get(alerts_with_reports))
        .route(
            "/alerts_with_reports/{alert_id}",
            get(alert_with_latest_report),
        )
        .route("/alert/{alert_id}", get(alert_analysis))
        .route("/palace_lessons", post(queue_palace_lesson))
        .route(
            "/palace_lessons/customer/{customer_code}",
            get(search_palace),
        )
        .route(
            "/palace_lessons/customer/{customer_code}/consolidation",
            get(consolidation),
        )
        .route("/reviews/{review_id}", get(get_review))
        .route(
            "/reviews/customer/{customer_code}",
            get(reviews_by_customer),
        )
        .route("/reviews/customer/{customer_code}/stats", get(review_stats))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tenancy dependencies (`verify_*_access`)
// ---------------------------------------------------------------------------

async fn verify_alert(auth: &Auth, ctx: &AppContext, raw: &str) -> Result<i64, ApiError> {
    let id = path_int_dep("alert_id", raw)?;
    let owner = alerts::alert_customer_code(&ctx.db, id).await?;
    auth.enforce_owned(ctx, owner.as_deref(), &format!("alert {id}"))
        .await?;
    Ok(id)
}

async fn verify_owned(
    auth: &Auth,
    ctx: &AppContext,
    kind: Owned,
    param: &str,
    raw: &str,
) -> Result<i64, ApiError> {
    let id = path_int_dep(param, raw)?;
    let owner = db::owner_of(&ctx.db, kind, id).await?;
    let subject = match kind {
        Owned::Report => format!("report {id}"),
        Owned::Ioc => format!("IOC {id}"),
        Owned::Review => format!("review {id}"),
    };
    auth.enforce_owned(ctx, owner.as_deref(), &subject).await?;
    Ok(id)
}

async fn verify_job(auth: &Auth, ctx: &AppContext, job_id: &str) -> Result<(), ApiError> {
    let owner = db::job_owner(&ctx.db, job_id).await?;
    auth.enforce_owned(ctx, owner.as_deref(), &format!("job {job_id}"))
        .await
}

async fn verify_customer(auth: &Auth, ctx: &AppContext, code: &str) -> Result<(), ApiError> {
    auth.enforce_customer(ctx, code).await
}

fn list<T, U: From<T>>(rows: Vec<T>) -> Vec<U> {
    rows.into_iter().map(Into::into).collect()
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

async fn create_job(auth: Auth, State(st): State<TalonState>, body: Bytes) -> ApiResult {
    let req = parse_body_model(&body, CreateJobRequest::read)?;
    tracing::info!(alert_id = req.alert_id, job_id = %req.id, "creating AI analyst job");
    verify_customer(&auth, &st.ctx, &req.customer_code).await?;
    let (message, job) = services::create_job(&st.ctx, &auth, &req).await?;
    Ok(ok(message, json!({ "job": JobResponse::from(job) })))
}

async fn update_job(
    auth: Auth,
    State(st): State<TalonState>,
    Path(job_id): Path<String>,
    body: Bytes,
) -> ApiResult {
    verify_job(&auth, &st.ctx, &job_id).await?;
    let req = parse_body_model(&body, UpdateJobRequest::read)?;
    tracing::info!(job_id = %job_id, status = %req.status, "updating AI analyst job");
    let job = services::update_job(&st.ctx, &job_id, &req).await?;
    Ok(ok("Job updated", json!({ "job": JobResponse::from(job) })))
}

async fn get_job(
    auth: Auth,
    State(st): State<TalonState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    verify_job(&auth, &st.ctx, &job_id).await?;
    let job = services::get_job(&st.ctx, &job_id).await?;
    Ok(ok(
        "Job retrieved",
        json!({ "job": JobResponse::from(job) }),
    ))
}

async fn jobs_by_alert(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let alert_id = verify_alert(&auth, &st.ctx, &raw).await?;
    let jobs: Vec<JobResponse> = list(db::jobs_by_alert(&st.ctx.db, alert_id).await?);
    Ok(ok("Jobs retrieved", json!({ "jobs": jobs })))
}

async fn jobs_by_customer(
    auth: Auth,
    State(st): State<TalonState>,
    Path(code): Path<String>,
) -> ApiResult {
    verify_customer(&auth, &st.ctx, &code).await?;
    let jobs: Vec<JobResponse> = list(db::jobs_by_customer(&st.ctx.db, &code).await?);
    Ok(ok("Jobs retrieved", json!({ "jobs": jobs })))
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

async fn submit_report(auth: Auth, State(st): State<TalonState>, body: Bytes) -> ApiResult {
    let req = parse_body_model(&body, SubmitReportRequest::read)?;
    tracing::info!(job_id = %req.job_id, "submitting AI analyst report");
    verify_customer(&auth, &st.ctx, &req.customer_code).await?;
    let report = services::submit_report(&st.ctx, &auth, &req).await?;
    Ok(ok(
        "Report submitted",
        json!({ "report": ReportResponse::from(report) }),
    ))
}

async fn reports_by_alert(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let alert_id = verify_alert(&auth, &st.ctx, &raw).await?;
    let reports: Vec<ReportResponse> = list(db::reports_by_alert(&st.ctx.db, alert_id).await?);
    Ok(ok("Reports retrieved", json!({ "reports": reports })))
}

async fn alert_with_report_by_report(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let report_id = verify_owned(&auth, &st.ctx, Owned::Report, "report_id", &raw).await?;
    let alert = services::alert_with_report(&st.ctx, report_id).await?;
    Ok(ok(
        "Alert with report retrieved",
        json!({ "alert": AlertWithReportResponse::from(alert) }),
    ))
}

// ---------------------------------------------------------------------------
// IOCs
// ---------------------------------------------------------------------------

async fn submit_iocs(auth: Auth, State(st): State<TalonState>, body: Bytes) -> ApiResult {
    let req = parse_body_model(&body, SubmitIocsRequest::read)?;
    tracing::info!(
        report_id = req.report_id,
        count = req.iocs.len(),
        "submitting IOCs"
    );
    verify_customer(&auth, &st.ctx, &req.customer_code).await?;
    let iocs: Vec<IocResponse> = list(services::submit_iocs(&st.ctx, &req).await?);
    Ok(ok(
        format!("{} IOCs submitted", iocs.len()),
        json!({ "iocs_created": iocs.len(), "iocs": iocs }),
    ))
}

async fn iocs_by_report(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let report_id = verify_owned(&auth, &st.ctx, Owned::Report, "report_id", &raw).await?;
    let iocs: Vec<IocResponse> = list(db::iocs_by_report(&st.ctx.db, report_id).await?);
    Ok(ok("IOCs retrieved", json!({ "iocs": iocs })))
}

async fn iocs_by_alert(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let alert_id = verify_alert(&auth, &st.ctx, &raw).await?;
    let iocs: Vec<IocResponse> = list(db::iocs_by_alert(&st.ctx.db, alert_id).await?);
    Ok(ok("IOCs retrieved", json!({ "iocs": iocs })))
}

async fn iocs_by_customer(
    auth: Auth,
    State(st): State<TalonState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    verify_customer(&auth, &st.ctx, &code).await?;
    let mut v = Validator::new();
    let verdict = q.opt_str(&mut v, "vt_verdict", StrRules::any());
    v.finish()?;
    let verdict = verdict.filter(|s| !s.is_empty());
    let iocs: Vec<IocResponse> =
        list(db::iocs_by_customer(&st.ctx.db, &code, verdict.as_deref()).await?);
    Ok(ok("IOCs retrieved", json!({ "iocs": iocs })))
}

async fn get_ioc(auth: Auth, State(st): State<TalonState>, Path(raw): Path<String>) -> ApiResult {
    let ioc_id = verify_owned(&auth, &st.ctx, Owned::Ioc, "ioc_id", &raw).await?;
    let ioc = services::get_ioc(&st.ctx, ioc_id).await?;
    Ok(ok(
        "IOC retrieved",
        json!({ "ioc": IocResponse::from(ioc) }),
    ))
}

// ---------------------------------------------------------------------------
// Alerts with reports, combined analysis
// ---------------------------------------------------------------------------

async fn alerts_with_reports(auth: Auth, State(st): State<TalonState>, q: QueryPairs) -> ApiResult {
    let requested = q.customer_codes();
    let scope = auth.access(&st.ctx).await?;
    let codes = scope.scoped_customer_codes(requested.as_deref());
    let rows = match &codes {
        Some(c) if c.is_empty() => Vec::new(),
        Some(c) => db::alerts_with_reports(&st.ctx.db, Some(c)).await?,
        None => db::alerts_with_reports(&st.ctx.db, None).await?,
    };
    let alerts: Vec<AlertWithReportResponse> = list(rows);
    Ok(ok(
        format!("{} alerts with reports found", alerts.len()),
        json!({ "alerts": alerts }),
    ))
}

async fn alert_with_latest_report(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let alert_id = verify_alert(&auth, &st.ctx, &raw).await?;
    let alert = services::alert_with_latest_report(&st.ctx, alert_id).await?;
    Ok(ok(
        "Alert with report retrieved",
        json!({ "alert": AlertWithReportResponse::from(alert) }),
    ))
}

async fn alert_analysis(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let alert_id = verify_alert(&auth, &st.ctx, &raw).await?;
    Ok(match services::alert_analysis(&st.ctx, alert_id).await? {
        None => envelope(
            false,
            "No AI analysis found for this alert",
            json!({ "job": null, "report": null, "iocs": null }),
        ),
        Some((job, report, iocs)) => ok(
            "Alert analysis retrieved",
            json!({
                "job": JobResponse::from(job),
                "report": report.map(ReportResponse::from),
                "iocs": list::<_, IocResponse>(iocs),
            }),
        ),
    })
}

// ---------------------------------------------------------------------------
// Reviews, replay
// ---------------------------------------------------------------------------

async fn submit_review(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
    body: Bytes,
) -> ApiResult {
    let report_id = verify_owned(&auth, &st.ctx, Owned::Report, "report_id", &raw).await?;
    let req = parse_body_model(&body, SubmitReviewRequest::read)?;
    tracing::info!(user_id = auth.id, report_id, "submitting review");
    let (message, review) = services::submit_review(&st.ctx, &auth, report_id, &req).await?;
    Ok(ok(
        message,
        json!({ "review": ReviewResponse::from(review) }),
    ))
}

async fn my_review(auth: Auth, State(st): State<TalonState>, Path(raw): Path<String>) -> ApiResult {
    let report_id = verify_owned(&auth, &st.ctx, Owned::Report, "report_id", &raw).await?;
    Ok(
        match services::my_review(&st.ctx, &auth, report_id).await? {
            None => ok(
                "No existing review for this user on this report",
                json!({ "review": null }),
            ),
            Some(r) => ok(
                "Existing review retrieved",
                json!({ "review": ReviewResponse::from(r) }),
            ),
        },
    )
}

async fn replay(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
    body: Bytes,
) -> ApiResult {
    let report_id = verify_owned(&auth, &st.ctx, Owned::Report, "report_id", &raw).await?;
    let req = parse_body_model(&body, ReplayRequest::read)?;
    let report = db::get_report(&st.ctx.db, report_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Report {report_id} not found")))?;
    if req.customer_code != report.customer_code {
        return Err(ApiError::bad_request(format!(
            "customer_code mismatch: report belongs to {}, got {}",
            report.customer_code, req.customer_code
        )));
    }
    tracing::info!(report_id, alert_id = report.alert_id, template = %req.template_override,
        "replaying investigation");
    let data = copilot_talon::services::replay_investigation(
        &st.talon,
        i64::from(report.alert_id),
        &req.customer_code,
        &req.template_override,
        &req.sender,
    )
    .await?;
    let data = if data.is_object() {
        data
    } else {
        serde_json::Value::Null
    };
    Ok(ok("Replay triggered", json!({ "data": data })))
}

async fn get_review(
    auth: Auth,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let review_id = verify_owned(&auth, &st.ctx, Owned::Review, "review_id", &raw).await?;
    let review = services::get_review(&st.ctx, review_id).await?;
    Ok(ok(
        "Review retrieved",
        json!({ "review": ReviewResponse::from(review) }),
    ))
}

async fn reviews_by_customer(
    auth: Auth,
    State(st): State<TalonState>,
    Path(code): Path<String>,
) -> ApiResult {
    verify_customer(&auth, &st.ctx, &code).await?;
    let reviews: Vec<ReviewResponse> =
        list(db::reviews_by_customer(&st.ctx.db, &code, None).await?);
    Ok(ok(
        format!("{} reviews retrieved", reviews.len()),
        json!({ "reviews": reviews }),
    ))
}

async fn review_stats(
    auth: Auth,
    State(st): State<TalonState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    verify_customer(&auth, &st.ctx, &code).await?;
    let mut v = Validator::new();
    let recent = q.int_or(
        &mut v,
        "recent_limit",
        IntRules {
            ge: Some(0),
            le: Some(50),
        },
        10,
    );
    v.finish()?;
    let stats = services::review_stats(&st.ctx, &code, recent).await?;
    Ok(ok(format!("Review stats for {code}"), &stats))
}

// ---------------------------------------------------------------------------
// Palace
// ---------------------------------------------------------------------------

async fn queue_palace_lesson(auth: Auth, State(st): State<TalonState>, body: Bytes) -> ApiResult {
    let req = parse_body_model(&body, QueuePalaceLessonRequest::read)?;
    tracing::info!(customer = %req.customer_code, "queuing palace lesson");
    verify_customer(&auth, &st.ctx, &req.customer_code).await?;
    let lesson = services::queue_palace_lesson(&st.ctx, &req).await?;
    Ok(ok(
        "Palace lesson queued for ingestion",
        json!({ "lesson": PalaceLessonResponse::from(lesson) }),
    ))
}

async fn search_palace(
    auth: Auth,
    State(st): State<TalonState>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    verify_customer(&auth, &st.ctx, &code).await?;
    let mut v = Validator::new();
    let query = match q.get("query") {
        Some(_) => q.opt_str(&mut v, "query", StrRules::any().min(1)),
        None => {
            v.push(
                "missing",
                copilot_web::validate::loc("query", "query"),
                "Field required",
            );
            None
        }
    };
    let room = q.opt_str(&mut v, "room", StrRules::any());
    let limit = q.int_or(
        &mut v,
        "limit",
        IntRules {
            ge: Some(1),
            le: Some(25),
        },
        5,
    );
    v.finish()?;
    let query = query.unwrap_or_default();
    tracing::info!(customer = %code, room = ?room, limit, "searching palace");
    let lessons = services::search_palace(&st.talon, &code, &query, room.as_deref(), limit).await?;
    Ok(ok(
        format!("{} palace lessons matched", lessons.len()),
        json!({ "lessons": lessons }),
    ))
}

async fn consolidation(
    auth: Auth,
    State(st): State<TalonState>,
    Path(code): Path<String>,
) -> ApiResult {
    verify_customer(&auth, &st.ctx, &code).await?;
    let digest = services::consolidation(&st.ctx, &code).await?;
    Ok(ok(digest.message(), &digest))
}
