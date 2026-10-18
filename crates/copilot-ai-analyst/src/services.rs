//! Business logic — port of `app/ai_analyst/services/ai_analyst.py`.
//!
//! Tenancy is checked by the routes before these run (the Python route
//! dependencies); services trust their arguments, as the Python ones do.

use chrono::{NaiveDateTime, Timelike};
use serde_json::Value;

use copilot_core::notify::{
    AlertEventInput, ai_report_reviewed_event, investigation_complete_event,
};
use copilot_core::time::{now_utc_naive, py_round};
use copilot_db::ai_analyst::{
    self as db, AlertWithReport, IocRow, JobRow, NewIoc, NewIocReview, NewReport, ReportRow,
    ReviewAggregate, ReviewFields, ReviewWithIocs, UpsertOutcome,
};
use copilot_db::alerts;
use copilot_talon::TalonConnector;
use copilot_web::{ApiError, AppContext, CurrentUser};
use serde::Serialize;

use crate::consolidation::{self, Digest};
use crate::schema::{
    CreateJobRequest, PalaceSearchHit, QueuePalaceLessonRequest, SubmitIocsRequest,
    SubmitReportRequest, SubmitReviewRequest, UpdateJobRequest,
};

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

/// `create_job`: insert, or — when Talon's status update already
/// auto-created the row — fill in `alert_type` / `template_used` (only when
/// sent) and `triggered_by`. Returns the message and the stored row.
pub async fn create_job(
    ctx: &AppContext,
    user: &CurrentUser,
    req: &CreateJobRequest,
) -> Result<(&'static str, JobRow), ApiError> {
    for attempt in 0..2 {
        if let Some(mut job) = db::get_job(&ctx.db, &req.id).await? {
            // Hardening: the id may name another tenant's job; the body's
            // customer was checked by the route, the stored owner is checked
            // here so a scoped caller cannot relabel it.
            user.enforce_owned(ctx, Some(&job.customer_code), &format!("job {}", job.id))
                .await?;
            if req.alert_type.is_some() {
                job.alert_type.clone_from(&req.alert_type);
            }
            if req.template_used.is_some() {
                job.template_used.clone_from(&req.template_used);
            }
            job.triggered_by.clone_from(&req.triggered_by);
            db::save_job(&ctx.db, &job).await?;
            return Ok(("Job updated", job));
        }
        let job = JobRow {
            id: req.id.clone(),
            alert_id: i32::try_from(req.alert_id).map_err(ApiError::internal)?,
            customer_code: req.customer_code.clone(),
            status: "pending".into(),
            alert_type: req.alert_type.clone(),
            triggered_by: req.triggered_by.clone(),
            template_used: req.template_used.clone(),
            created_at: now_utc_naive(),
            started_at: None,
            completed_at: None,
            error_message: None,
        };
        match db::insert_job(&ctx.db, &job).await {
            Ok(()) => return Ok(("Job created", job)),
            // Lost a race with the PATCH auto-create: take the update path.
            Err(e) if e.is_unique_violation() && attempt == 0 => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::internal("create_job: retry exhausted"))
}

/// `^copilot-inv-(\d+)-\d+$` → alert id.
pub fn alert_id_from_job_id(job_id: &str) -> Option<i64> {
    let rest = job_id.strip_prefix("copilot-inv-")?;
    let (alert, stamp) = rest.split_once('-')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(alert) || !digits(stamp) {
        return None;
    }
    alert.parse().ok()
}

/// `_auto_create_job_from_id`: Talon may report a status before it created
/// the job; recover the alert from the id and create the row.
async fn auto_create_job(ctx: &AppContext, job_id: &str) -> Result<Option<JobRow>, ApiError> {
    let Some(alert_id) = alert_id_from_job_id(job_id) else {
        tracing::warn!(job_id, "cannot parse alert_id from job id");
        return Ok(None);
    };
    let Some(alert) = alerts::find_alert(&ctx.db, alert_id).await? else {
        tracing::warn!(job_id, alert_id, "alert not found, cannot auto-create job");
        return Ok(None);
    };
    let job = JobRow {
        id: job_id.to_string(),
        alert_id: alert.id,
        customer_code: alert.customer_code,
        status: "pending".into(),
        alert_type: None,
        triggered_by: "webhook".into(),
        template_used: None,
        created_at: now_utc_naive(),
        started_at: None,
        completed_at: None,
        error_message: None,
    };
    match db::insert_job(&ctx.db, &job).await {
        Ok(()) => Ok(Some(job)),
        // Created concurrently by `POST /jobs`: use that row.
        Err(e) if e.is_unique_violation() => Ok(db::get_job(&ctx.db, job_id).await?),
        Err(e) => Err(e.into()),
    }
}

/// Apply an update to a job row (pure, for tests): status always, optional
/// fields only when sent (they can never be cleared), `started_at` once,
/// `completed_at` on every terminal update.
pub fn apply_update(job: &mut JobRow, req: &UpdateJobRequest, now: NaiveDateTime) {
    job.status.clone_from(&req.status);
    if req.alert_type.is_some() {
        job.alert_type.clone_from(&req.alert_type);
    }
    if req.template_used.is_some() {
        job.template_used.clone_from(&req.template_used);
    }
    if req.error_message.is_some() {
        job.error_message.clone_from(&req.error_message);
    }
    if req.status == "running" {
        if job.started_at.is_none() {
            job.started_at = Some(now);
        }
    } else if req.status == "completed" || req.status == "failed" {
        job.completed_at = Some(now);
    }
}

/// `update_job`.
pub async fn update_job(
    ctx: &AppContext,
    job_id: &str,
    req: &UpdateJobRequest,
) -> Result<JobRow, ApiError> {
    let job = match db::get_job(&ctx.db, job_id).await? {
        Some(job) => Some(job),
        None => auto_create_job(ctx, job_id).await?,
    };
    let mut job = job.ok_or_else(|| {
        ApiError::not_found(format!(
            "Job {job_id} not found and could not be auto-created"
        ))
    })?;
    apply_update(&mut job, req, now_utc_naive());
    db::save_job(&ctx.db, &job).await?;
    Ok(job)
}

/// `get_job`.
pub async fn get_job(ctx: &AppContext, job_id: &str) -> Result<JobRow, ApiError> {
    db::get_job(&ctx.db, job_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Job {job_id} not found")))
}

// ---------------------------------------------------------------------------
// Reports, IOCs
// ---------------------------------------------------------------------------

/// `_alert_display_fields`: never fails.
async fn alert_display_fields(ctx: &AppContext, alert_id: i64) -> (Option<String>, Option<String>) {
    let alert = match alerts::find_alert(&ctx.db, alert_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return (None, None),
        Err(e) => {
            tracing::warn!(alert_id, err = %e, "could not resolve alert display fields");
            return (None, None);
        }
    };
    let asset = alerts::first_asset_name(&ctx.db, alert_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(alert_id, err = %e, "could not resolve asset name");
            None
        });
    (Some(alert.alert_name), asset)
}

/// `submit_report`: the job must exist; then the `investigation_complete`
/// notification (same dedupe key as Talon's own dispatch, so whichever
/// arrives first wins).
pub async fn submit_report(
    ctx: &AppContext,
    user: &CurrentUser,
    req: &SubmitReportRequest,
) -> Result<ReportRow, ApiError> {
    if db::get_job(&ctx.db, &req.job_id).await?.is_none() {
        return Err(ApiError::not_found(format!("Job {} not found", req.job_id)));
    }
    let report = db::insert_report(
        &ctx.db,
        &NewReport {
            job_id: &req.job_id,
            alert_id: req.alert_id,
            customer_code: &req.customer_code,
            severity_assessment: req.severity_assessment.as_deref(),
            summary: req.summary.as_deref(),
            report_markdown: req.report_markdown.as_deref(),
            recommended_actions: req.recommended_actions.as_deref(),
        },
    )
    .await?;
    tracing::info!(report_id = report.id, job_id = %req.job_id, "AI analyst report stored");
    let (alert_name, asset_name) = alert_display_fields(ctx, i64::from(report.alert_id)).await;
    let event = investigation_complete_event(
        &ctx.notification_defaults,
        &AlertEventInput {
            alert_id: i64::from(report.alert_id),
            customer_code: Some(&report.customer_code),
            severity: report.severity_assessment.as_deref(),
            summary: report
                .summary
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("An AI investigation completed for this alert."),
            alert_name: alert_name.as_deref(),
            asset_name: asset_name.as_deref(),
        },
    );
    ctx.notifications.emit(event, Some(user.bearer.clone()));
    Ok(report)
}

/// `submit_iocs`: the report must exist; all IOCs in one transaction.
pub async fn submit_iocs(
    ctx: &AppContext,
    req: &SubmitIocsRequest,
) -> Result<Vec<IocRow>, ApiError> {
    if db::get_report(&ctx.db, req.report_id).await?.is_none() {
        return Err(ApiError::not_found(format!(
            "Report {} not found",
            req.report_id
        )));
    }
    let new: Vec<NewIoc> = req
        .iocs
        .iter()
        .map(|i| NewIoc {
            ioc_value: i.ioc_value.clone(),
            ioc_type: i.ioc_type.clone(),
            vt_verdict: i.vt_verdict.clone(),
            vt_score: i.vt_score.clone(),
            details: i.details.clone(),
        })
        .collect();
    Ok(db::insert_iocs(
        &ctx.db,
        req.report_id,
        req.alert_id,
        &req.customer_code,
        &new,
    )
    .await?)
}

/// `get_ioc_by_id`.
pub async fn get_ioc(ctx: &AppContext, ioc_id: i64) -> Result<IocRow, ApiError> {
    db::get_ioc(&ctx.db, ioc_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("IOC {ioc_id} not found")))
}

/// `get_alert_with_report_by_alert_id`.
pub async fn alert_with_latest_report(
    ctx: &AppContext,
    alert_id: i64,
) -> Result<AlertWithReport, ApiError> {
    db::alert_with_latest_report(&ctx.db, alert_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Alert {alert_id} not found")))
}

/// `get_alert_with_report_by_report_id`.
pub async fn alert_with_report(
    ctx: &AppContext,
    report_id: i64,
) -> Result<AlertWithReport, ApiError> {
    db::alert_with_report(&ctx.db, report_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Report {report_id} not found")))
}

/// `get_alert_analysis`: latest job, its first report, that report's IOCs.
pub async fn alert_analysis(
    ctx: &AppContext,
    alert_id: i64,
) -> Result<Option<(JobRow, Option<ReportRow>, Vec<IocRow>)>, ApiError> {
    let Some(job) = db::jobs_by_alert(&ctx.db, alert_id)
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let report = db::reports_by_job(&ctx.db, &job.id)
        .await?
        .into_iter()
        .next();
    let iocs = match &report {
        Some(r) => db::iocs_by_report_unordered(&ctx.db, i64::from(r.id)).await?,
        None => Vec::new(),
    };
    Ok(Some((job, report, iocs)))
}

// ---------------------------------------------------------------------------
// Reviews
// ---------------------------------------------------------------------------

async fn report_or_404(ctx: &AppContext, report_id: i64) -> Result<ReportRow, ApiError> {
    db::get_report(&ctx.db, report_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Report {report_id} not found")))
}

/// `submit_review`: upsert on `(report_id, reviewer)`; the
/// `ai_report_reviewed` notification fires on creation only.
pub async fn submit_review(
    ctx: &AppContext,
    user: &CurrentUser,
    report_id: i64,
    req: &SubmitReviewRequest,
) -> Result<(&'static str, ReviewWithIocs), ApiError> {
    let report = report_or_404(ctx, report_id).await?;
    let template_used = match &req.template_used {
        Some(t) => Some(t.clone()),
        None => db::get_job(&ctx.db, &report.job_id)
            .await?
            .and_then(|j| j.template_used),
    };
    for c in &req.ioc_reviews {
        let belongs = db::get_ioc(&ctx.db, c.ioc_id)
            .await?
            .is_some_and(|i| i64::from(i.report_id) == report_id);
        if !belongs {
            return Err(ApiError::bad_request(format!(
                "IOC {} not found or does not belong to report {report_id}",
                c.ioc_id
            )));
        }
    }
    let rating = |r: Option<i64>| r.and_then(|v| i32::try_from(v).ok());
    let fields = ReviewFields {
        overall_verdict: req.overall_verdict.clone(),
        template_choice: req.template_choice.clone(),
        template_used,
        rating_instructions: rating(req.rating_instructions),
        rating_artifacts: rating(req.rating_artifacts),
        rating_severity: rating(req.rating_severity),
        missing_steps: req.missing_steps.clone(),
        suggested_edits: req.suggested_edits.clone(),
    };
    let iocs: Vec<NewIocReview> = req
        .ioc_reviews
        .iter()
        .map(|c| NewIocReview {
            ioc_id: c.ioc_id,
            verdict_correct: c.verdict_correct,
            note: c.note.clone(),
        })
        .collect();
    let (review, outcome) = db::upsert_review(&ctx.db, &report, user.id, &fields, &iocs).await?;
    if outcome == UpsertOutcome::Created {
        let (alert_name, asset_name) = alert_display_fields(ctx, i64::from(report.alert_id)).await;
        let event = ai_report_reviewed_event(
            &ctx.notification_defaults,
            &AlertEventInput {
                alert_id: i64::from(report.alert_id),
                customer_code: Some(&report.customer_code),
                severity: report.severity_assessment.as_deref(),
                summary: report
                    .summary
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("An analyst reviewed the AI investigation for this alert."),
                alert_name: alert_name.as_deref(),
                asset_name: asset_name.as_deref(),
            },
            i64::from(report.id),
            Some(&user.username),
            req.overall_verdict.as_deref(),
        );
        ctx.notifications.emit(event, Some(user.bearer.clone()));
    }
    let message = match outcome {
        UpsertOutcome::Created => "Review created",
        UpsertOutcome::Updated => "Review updated",
    };
    Ok((message, review))
}

/// `get_my_review`.
pub async fn my_review(
    ctx: &AppContext,
    user: &CurrentUser,
    report_id: i64,
) -> Result<Option<ReviewWithIocs>, ApiError> {
    report_or_404(ctx, report_id).await?;
    Ok(db::review_by_reviewer(&ctx.db, report_id, user.id).await?)
}

/// `get_review_by_id`.
pub async fn get_review(ctx: &AppContext, review_id: i64) -> Result<ReviewWithIocs, ApiError> {
    db::get_review(&ctx.db, review_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Review {review_id} not found")))
}

/// `_pct`: `None` for an empty denominator.
pub fn pct(numerator: i64, denominator: i64) -> Option<f64> {
    if denominator <= 0 {
        None
    } else {
        Some(py_round(numerator as f64 / denominator as f64 * 100.0, 2))
    }
}

fn avg(v: Option<String>) -> Option<f64> {
    v.and_then(|s| s.parse::<f64>().ok())
        .map(|f| py_round(f, 2))
}

/// `ReviewStatsTemplate`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemplateStats {
    /// Template.
    pub template_used: Option<String>,
    /// Reviews.
    pub total: i64,
    /// Up.
    pub thumbs_up: i64,
    /// Down.
    pub thumbs_down: i64,
    /// Correct.
    pub correct: i64,
    /// Partial.
    pub partial: i64,
    /// Wrong.
    pub wrong: i64,
    /// Mean.
    pub avg_rating_instructions: Option<f64>,
    /// Mean.
    pub avg_rating_artifacts: Option<f64>,
    /// Mean.
    pub avg_rating_severity: Option<f64>,
}

impl From<ReviewAggregate> for TemplateStats {
    fn from(a: ReviewAggregate) -> Self {
        Self {
            template_used: a.template_used,
            total: a.total,
            thumbs_up: a.thumbs_up,
            thumbs_down: a.thumbs_down,
            correct: a.correct,
            partial: a.partial,
            wrong: a.wrong,
            avg_rating_instructions: avg(a.avg_rating_instructions),
            avg_rating_artifacts: avg(a.avg_rating_artifacts),
            avg_rating_severity: avg(a.avg_rating_severity),
        }
    }
}

/// `ReviewStatsIocAccuracy`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IocAccuracy {
    /// Corrections.
    pub total: i64,
    /// Verdict was right.
    pub correct: i64,
    /// Verdict was wrong.
    pub incorrect: i64,
    /// `correct / total`, %.
    pub accuracy_pct: Option<f64>,
}

/// `ReviewStatsResponse` without the envelope.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReviewStats {
    /// Customer.
    pub customer_code: String,
    /// Reviews.
    pub total_reviews: i64,
    /// Up.
    pub thumbs_up: i64,
    /// Down.
    pub thumbs_down: i64,
    /// `up / (up + down)`, %.
    pub thumbs_up_pct: Option<f64>,
    /// Template correct.
    pub template_choice_correct: i64,
    /// Template partial.
    pub template_choice_partial: i64,
    /// Template wrong.
    pub template_choice_wrong: i64,
    /// Mean.
    pub avg_rating_instructions: Option<f64>,
    /// Mean.
    pub avg_rating_artifacts: Option<f64>,
    /// Mean.
    pub avg_rating_severity: Option<f64>,
    /// IOC verdict accuracy.
    pub ioc_accuracy: IocAccuracy,
    /// Per template, busiest first.
    pub per_template: Vec<TemplateStats>,
    /// Newest reviews.
    pub recent_reviews: Vec<crate::schema::ReviewResponse>,
}

/// `get_review_stats`.
pub async fn review_stats(
    ctx: &AppContext,
    customer_code: &str,
    recent_limit: i64,
) -> Result<ReviewStats, ApiError> {
    let totals = db::review_totals(&ctx.db, customer_code).await?;
    let per_template = db::review_per_template(&ctx.db, customer_code).await?;
    let (ioc_total, ioc_correct, ioc_incorrect) =
        db::ioc_review_accuracy(&ctx.db, customer_code).await?;
    let recent = db::reviews_by_customer(&ctx.db, customer_code, Some(recent_limit)).await?;
    Ok(ReviewStats {
        customer_code: customer_code.to_string(),
        total_reviews: totals.total,
        thumbs_up: totals.thumbs_up,
        thumbs_down: totals.thumbs_down,
        thumbs_up_pct: pct(totals.thumbs_up, totals.thumbs_up + totals.thumbs_down),
        template_choice_correct: totals.correct,
        template_choice_partial: totals.partial,
        template_choice_wrong: totals.wrong,
        avg_rating_instructions: avg(totals.avg_rating_instructions),
        avg_rating_artifacts: avg(totals.avg_rating_artifacts),
        avg_rating_severity: avg(totals.avg_rating_severity),
        ioc_accuracy: IocAccuracy {
            total: ioc_total,
            correct: ioc_correct,
            incorrect: ioc_incorrect,
            accuracy_pct: pct(ioc_correct, ioc_total),
        },
        per_template: per_template.into_iter().map(Into::into).collect(),
        recent_reviews: recent.into_iter().map(Into::into).collect(),
    })
}

// ---------------------------------------------------------------------------
// Palace
// ---------------------------------------------------------------------------

/// `queue_palace_lesson`: only queues; the drainer talks to Talon.
pub async fn queue_palace_lesson(
    ctx: &AppContext,
    req: &QueuePalaceLessonRequest,
) -> Result<db::PalaceLessonRow, ApiError> {
    if let Some(review_id) = req.review_id {
        if !db::review_exists(&ctx.db, review_id).await? {
            return Err(ApiError::not_found(format!("Review {review_id} not found")));
        }
    }
    Ok(db::insert_palace_lesson(
        &ctx.db,
        req.review_id,
        &req.customer_code,
        &req.lesson_type,
        &req.lesson_text,
        &req.durability,
    )
    .await?)
}

/// Unpack Talon's `/palace/search` body: `{"lessons": [...]}` or a bare list.
pub fn palace_hits(data: &Value) -> Vec<PalaceSearchHit> {
    let items = match data {
        Value::Object(o) => o.get("lessons").and_then(Value::as_array).cloned(),
        Value::Array(a) => Some(a.clone()),
        _ => None,
    };
    items
        .unwrap_or_default()
        .iter()
        .map(PalaceSearchHit::from_value)
        .collect()
}

/// `search_palace_lessons` (route 24).
pub async fn search_palace(
    talon: &TalonConnector,
    customer_code: &str,
    query: &str,
    room: Option<&str>,
    limit: i64,
) -> Result<Vec<PalaceSearchHit>, ApiError> {
    let data =
        copilot_talon::services::search_palace(talon, customer_code, query, room, limit).await?;
    Ok(palace_hits(&data))
}

/// `get_palace_consolidation`.
pub async fn consolidation(ctx: &AppContext, customer_code: &str) -> Result<Digest, ApiError> {
    let rows = db::active_lessons(&ctx.db, customer_code).await?;
    // `datetime.utcnow()`: microsecond precision.
    let now = chrono::Utc::now().naive_utc();
    let now = now
        .with_nanosecond(now.nanosecond() / 1000 * 1000)
        .unwrap_or(now);
    Ok(consolidation::build(customer_code, &rows, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn job() -> JobRow {
        JobRow {
            id: "copilot-inv-5-1".into(),
            alert_id: 5,
            customer_code: "acme".into(),
            status: "pending".into(),
            alert_type: Some("sysmon_event_1".into()),
            triggered_by: "webhook".into(),
            template_used: None,
            created_at: now_utc_naive(),
            started_at: None,
            completed_at: None,
            error_message: None,
        }
    }

    fn update(status: &str) -> UpdateJobRequest {
        UpdateJobRequest {
            status: status.into(),
            alert_type: None,
            template_used: None,
            error_message: None,
        }
    }

    #[test]
    fn job_id_parsing() {
        assert_eq!(
            alert_id_from_job_id("copilot-inv-1234-1760000000000"),
            Some(1234)
        );
        assert_eq!(alert_id_from_job_id("copilot-inv-1234"), None);
        assert_eq!(alert_id_from_job_id("copilot-inv-x-1"), None);
        assert_eq!(alert_id_from_job_id("other-1-2"), None);
        assert_eq!(alert_id_from_job_id("copilot-inv-1-2-3"), None);
    }

    #[test]
    fn update_semantics() {
        let t1 = now_utc_naive();
        let mut j = job();
        apply_update(&mut j, &update("running"), t1);
        assert_eq!(j.started_at, Some(t1));
        let t2 = t1 + chrono::Duration::seconds(5);
        apply_update(&mut j, &update("running"), t2);
        assert_eq!(j.started_at, Some(t1), "started_at is set once");
        apply_update(&mut j, &update("failed"), t2);
        assert_eq!(j.completed_at, Some(t2));
        // Optional fields are never cleared by an absent value.
        assert_eq!(j.alert_type.as_deref(), Some("sysmon_event_1"));
    }

    #[test]
    fn percentages() {
        assert_eq!(pct(1, 3), Some(33.33));
        assert_eq!(pct(2, 3), Some(66.67));
        assert_eq!(pct(0, 0), None);
        assert_eq!(avg(Some("3.6667".into())), Some(3.67));
        assert_eq!(avg(None), None);
    }

    #[test]
    fn palace_hit_unpacking() {
        let hits = palace_hits(&json!({"lessons": [{"id": "d1", "score": 0.9, "extra": 1}]}));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id.as_deref(), Some("d1"));
        assert_eq!(
            palace_hits(&json!([{"text": "x"}]))[0].text.as_deref(),
            Some("x")
        );
        assert!(palace_hits(&json!("nope")).is_empty());
    }
}
