//! The `AiAnalyst*` block of `app/db/universal_models.py` and the queries the
//! AI-analyst and Talon services run against it.
//!
//! `ai_analyst_job → ai_analyst_report → ai_analyst_ioc`, the review chain
//! `ai_analyst_review → ai_analyst_ioc_review`, and the queue
//! `ai_analyst_palace_lesson`. Every table carries `customer_code` (hard FK),
//! which is what the routes' object-tenancy checks read. Enum columns hold
//! lowercase strings, except `severity_assessment` (`High`, `Critical`, …).
//!
//! Lists are newest first. Python orders by `created_at` alone; rows written
//! in one commit share a second, so `id` breaks ties here to keep pages
//! stable.

use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::FromRow;

use copilot_core::time::{mysql_datetime, now_utc_micros, now_utc_naive};

use crate::schema::TableRequirement;
use crate::{Db, DbError};

/// `ai_analyst_job`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize)]
pub struct JobRow {
    /// Talon's job id (`copilot-inv-<alert>-<millis>`).
    pub id: String,
    /// Alert (no FK).
    pub alert_id: i32,
    /// Tenant.
    pub customer_code: String,
    /// `pending` | `running` | `completed` | `failed`.
    pub status: String,
    /// Detected alert type.
    pub alert_type: Option<String>,
    /// `scheduled` | `manual` | `webhook`.
    pub triggered_by: String,
    /// Prompt template used.
    pub template_used: Option<String>,
    /// Created (naive UTC).
    pub created_at: NaiveDateTime,
    /// First moved to `running`.
    pub started_at: Option<NaiveDateTime>,
    /// Reached `completed` / `failed`.
    pub completed_at: Option<NaiveDateTime>,
    /// Agent error text.
    pub error_message: Option<String>,
}

/// `ai_analyst_report`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize)]
pub struct ReportRow {
    /// Primary key.
    pub id: i32,
    /// Owning job.
    pub job_id: String,
    /// Alert.
    pub alert_id: i32,
    /// Tenant.
    pub customer_code: String,
    /// `Critical` | `High` | `Medium` | `Low` | `Informational`.
    pub severity_assessment: Option<String>,
    /// One-paragraph summary.
    pub summary: Option<String>,
    /// Full report.
    pub report_markdown: Option<String>,
    /// Recommended actions.
    pub recommended_actions: Option<String>,
    /// Created.
    pub created_at: NaiveDateTime,
}

/// `ai_analyst_ioc`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize)]
pub struct IocRow {
    /// Primary key.
    pub id: i32,
    /// Owning report.
    pub report_id: i32,
    /// Alert.
    pub alert_id: i32,
    /// Tenant.
    pub customer_code: String,
    /// The indicator.
    pub ioc_value: String,
    /// `ip|domain|hash|process|url|user|command`.
    pub ioc_type: String,
    /// `malicious|suspicious|clean|unknown`.
    pub vt_verdict: String,
    /// VirusTotal score text.
    pub vt_score: Option<String>,
    /// Free text.
    pub details: Option<String>,
    /// Created.
    pub created_at: NaiveDateTime,
}

/// `ai_analyst_review`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize)]
pub struct ReviewRow {
    /// Primary key.
    pub id: i32,
    /// Reviewed report.
    pub report_id: i32,
    /// Alert.
    pub alert_id: i32,
    /// Tenant.
    pub customer_code: String,
    /// Reviewer (`user.id`, no FK).
    pub reviewer_user_id: i32,
    /// `up` | `down`.
    pub overall_verdict: Option<String>,
    /// `correct` | `wrong` | `partial`.
    pub template_choice: Option<String>,
    /// Template snapshot at review time.
    pub template_used: Option<String>,
    /// 1–5.
    pub rating_instructions: Option<i32>,
    /// 1–5.
    pub rating_artifacts: Option<i32>,
    /// 1–5.
    pub rating_severity: Option<i32>,
    /// Free text.
    pub missing_steps: Option<String>,
    /// Free text.
    pub suggested_edits: Option<String>,
    /// Created.
    pub created_at: NaiveDateTime,
    /// Last edit.
    pub updated_at: Option<NaiveDateTime>,
}

/// `ai_analyst_ioc_review`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize)]
pub struct IocReviewRow {
    /// Primary key.
    pub id: i32,
    /// Owning review.
    pub review_id: i32,
    /// Reviewed IOC.
    pub ioc_id: i32,
    /// Was the AI's verdict right?
    pub verdict_correct: bool,
    /// Free text.
    pub note: Option<String>,
    /// Created.
    pub created_at: NaiveDateTime,
}

/// `ai_analyst_palace_lesson`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize)]
pub struct PalaceLessonRow {
    /// Primary key.
    pub id: i32,
    /// Source review, if any.
    pub review_id: Option<i32>,
    /// Tenant (the MemPalace wing).
    pub customer_code: String,
    /// The room: `environment|false_positives|assets|threat_intel|alerts`.
    pub lesson_type: String,
    /// The lesson (nullable in the migrated schema).
    pub lesson_text: Option<String>,
    /// `one_off` | `durable`.
    pub durability: String,
    /// `pending` | `ingested` | `failed` | `expired`.
    pub status: String,
    /// When NanoClaw accepted it.
    pub ingested_at: Option<NaiveDateTime>,
    /// Queued.
    pub created_at: NaiveDateTime,
    /// MemPalace drawer id, for expiry.
    pub drawer_id: Option<String>,
    /// When a one-off lesson was forgotten.
    pub expired_at: Option<NaiveDateTime>,
}

/// An alert joined with one of its reports (`AlertWithReportResponse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertWithReport {
    /// Alert id.
    pub alert_id: i32,
    /// Alert title.
    pub alert_name: String,
    /// Alert tenant.
    pub customer_code: String,
    /// Alert status.
    pub status: String,
    /// Alert source.
    pub source: String,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Alert time.
    pub alert_creation_time: NaiveDateTime,
    /// The report.
    pub report: ReportRow,
}

/// Columns this module needs.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "ai_analyst_job",
        columns: &[
            "id",
            "alert_id",
            "customer_code",
            "status",
            "alert_type",
            "triggered_by",
            "template_used",
            "created_at",
            "started_at",
            "completed_at",
            "error_message",
        ],
    },
    TableRequirement {
        table: "ai_analyst_report",
        columns: &[
            "id",
            "job_id",
            "alert_id",
            "customer_code",
            "severity_assessment",
            "summary",
            "report_markdown",
            "recommended_actions",
            "created_at",
        ],
    },
    TableRequirement {
        table: "ai_analyst_ioc",
        columns: &[
            "id",
            "report_id",
            "alert_id",
            "customer_code",
            "ioc_value",
            "ioc_type",
            "vt_verdict",
            "vt_score",
            "details",
            "created_at",
        ],
    },
    TableRequirement {
        table: "ai_analyst_review",
        columns: &[
            "id",
            "report_id",
            "alert_id",
            "customer_code",
            "reviewer_user_id",
            "overall_verdict",
            "template_choice",
            "template_used",
            "rating_instructions",
            "rating_artifacts",
            "rating_severity",
            "missing_steps",
            "suggested_edits",
            "created_at",
            "updated_at",
        ],
    },
    TableRequirement {
        table: "ai_analyst_ioc_review",
        columns: &[
            "id",
            "review_id",
            "ioc_id",
            "verdict_correct",
            "note",
            "created_at",
        ],
    },
    TableRequirement {
        table: "ai_analyst_palace_lesson",
        columns: &[
            "id",
            "review_id",
            "customer_code",
            "lesson_type",
            "lesson_text",
            "durability",
            "status",
            "ingested_at",
            "created_at",
            "drawer_id",
            "expired_at",
        ],
    },
];

const JOB_COLS: &str = "id, alert_id, customer_code, status, alert_type, triggered_by, \
     template_used, created_at, started_at, completed_at, error_message";
const REPORT_COLS: &str = "id, job_id, alert_id, customer_code, severity_assessment, summary, \
     report_markdown, recommended_actions, created_at";
const IOC_COLS: &str = "id, report_id, alert_id, customer_code, ioc_value, ioc_type, vt_verdict, \
     vt_score, details, created_at";
const REVIEW_COLS: &str = "id, report_id, alert_id, customer_code, reviewer_user_id, \
     overall_verdict, template_choice, template_used, rating_instructions, rating_artifacts, \
     rating_severity, missing_steps, suggested_edits, created_at, updated_at";
const LESSON_COLS: &str = "id, review_id, customer_code, lesson_type, lesson_text, durability, \
     status, ingested_at, created_at, drawer_id, expired_at";

// ---------------------------------------------------------------------------
// Ownership (object-tenancy checks)
// ---------------------------------------------------------------------------

/// Which table an owner lookup reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owned {
    /// `ai_analyst_report`.
    Report,
    /// `ai_analyst_ioc`.
    Ioc,
    /// `ai_analyst_review`.
    Review,
}

/// `customer_code` of a report / IOC / review.
pub async fn owner_of(db: &Db, kind: Owned, id: i64) -> Result<Option<String>, DbError> {
    let sql = match kind {
        Owned::Report => "SELECT customer_code FROM ai_analyst_report WHERE id = ?",
        Owned::Ioc => "SELECT customer_code FROM ai_analyst_ioc WHERE id = ?",
        Owned::Review => "SELECT customer_code FROM ai_analyst_review WHERE id = ?",
    };
    Ok(sqlx::query_scalar::<_, String>(sql)
        .bind(id)
        .fetch_optional(db.pool())
        .await?)
}

/// `customer_code` of a job.
pub async fn job_owner(db: &Db, job_id: &str) -> Result<Option<String>, DbError> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT customer_code FROM ai_analyst_job WHERE id = ?")
            .bind(job_id)
            .fetch_optional(db.pool())
            .await?,
    )
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

/// One job.
pub async fn get_job(db: &Db, job_id: &str) -> Result<Option<JobRow>, DbError> {
    Ok(sqlx::query_as::<_, JobRow>(&format!(
        "SELECT {JOB_COLS} FROM ai_analyst_job WHERE id = ?"
    ))
    .bind(job_id)
    .fetch_optional(db.pool())
    .await?)
}

/// Insert a job row as given.
pub async fn insert_job(db: &Db, job: &JobRow) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO ai_analyst_job (id, alert_id, customer_code, status, alert_type, \
         triggered_by, template_used, created_at, started_at, completed_at, error_message) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&job.id)
    .bind(job.alert_id)
    .bind(&job.customer_code)
    .bind(&job.status)
    .bind(&job.alert_type)
    .bind(&job.triggered_by)
    .bind(&job.template_used)
    .bind(job.created_at)
    .bind(job.started_at)
    .bind(job.completed_at)
    .bind(&job.error_message)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Write back every mutable column of a job.
pub async fn save_job(db: &Db, job: &JobRow) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE ai_analyst_job SET status = ?, alert_type = ?, triggered_by = ?, \
         template_used = ?, started_at = ?, completed_at = ?, error_message = ? WHERE id = ?",
    )
    .bind(&job.status)
    .bind(&job.alert_type)
    .bind(&job.triggered_by)
    .bind(&job.template_used)
    .bind(job.started_at)
    .bind(job.completed_at)
    .bind(&job.error_message)
    .bind(&job.id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Jobs for an alert, newest first.
pub async fn jobs_by_alert(db: &Db, alert_id: i64) -> Result<Vec<JobRow>, DbError> {
    Ok(sqlx::query_as::<_, JobRow>(&format!(
        "SELECT {JOB_COLS} FROM ai_analyst_job WHERE alert_id = ? \
         ORDER BY created_at DESC, id ASC"
    ))
    .bind(alert_id)
    .fetch_all(db.pool())
    .await?)
}

/// Jobs for a customer, newest first.
pub async fn jobs_by_customer(db: &Db, customer_code: &str) -> Result<Vec<JobRow>, DbError> {
    Ok(sqlx::query_as::<_, JobRow>(&format!(
        "SELECT {JOB_COLS} FROM ai_analyst_job WHERE customer_code = ? \
         ORDER BY created_at DESC, id ASC"
    ))
    .bind(customer_code)
    .fetch_all(db.pool())
    .await?)
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// One report.
pub async fn get_report(db: &Db, report_id: i64) -> Result<Option<ReportRow>, DbError> {
    Ok(sqlx::query_as::<_, ReportRow>(&format!(
        "SELECT {REPORT_COLS} FROM ai_analyst_report WHERE id = ?"
    ))
    .bind(report_id)
    .fetch_optional(db.pool())
    .await?)
}

/// Fields of a new report.
#[derive(Debug, Clone)]
pub struct NewReport<'a> {
    /// Owning job.
    pub job_id: &'a str,
    /// Alert.
    pub alert_id: i64,
    /// Tenant.
    pub customer_code: &'a str,
    /// Severity string.
    pub severity_assessment: Option<&'a str>,
    /// Summary.
    pub summary: Option<&'a str>,
    /// Markdown body.
    pub report_markdown: Option<&'a str>,
    /// Actions.
    pub recommended_actions: Option<&'a str>,
}

/// Insert a report and return the stored row.
pub async fn insert_report(db: &Db, r: &NewReport<'_>) -> Result<ReportRow, DbError> {
    let created_at = now_utc_naive();
    let res = sqlx::query(
        "INSERT INTO ai_analyst_report (job_id, alert_id, customer_code, severity_assessment, \
         summary, report_markdown, recommended_actions, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(r.job_id)
    .bind(r.alert_id)
    .bind(r.customer_code)
    .bind(r.severity_assessment)
    .bind(r.summary)
    .bind(r.report_markdown)
    .bind(r.recommended_actions)
    .bind(created_at)
    .execute(db.pool())
    .await?;
    let id = i64::try_from(res.last_insert_id()).unwrap_or(i64::MAX);
    get_report(db, id)
        .await?
        .ok_or_else(|| DbError::Config(format!("report {id} vanished after insert")))
}

/// Reports for an alert, newest first.
pub async fn reports_by_alert(db: &Db, alert_id: i64) -> Result<Vec<ReportRow>, DbError> {
    Ok(sqlx::query_as::<_, ReportRow>(&format!(
        "SELECT {REPORT_COLS} FROM ai_analyst_report WHERE alert_id = ? \
         ORDER BY created_at DESC, id ASC"
    ))
    .bind(alert_id)
    .fetch_all(db.pool())
    .await?)
}

/// Reports of several jobs (oldest job first is not implied; ordered by id).
pub async fn reports_by_job(db: &Db, job_id: &str) -> Result<Vec<ReportRow>, DbError> {
    Ok(sqlx::query_as::<_, ReportRow>(&format!(
        "SELECT {REPORT_COLS} FROM ai_analyst_report WHERE job_id = ? ORDER BY id"
    ))
    .bind(job_id)
    .fetch_all(db.pool())
    .await?)
}

// ---------------------------------------------------------------------------
// IOCs
// ---------------------------------------------------------------------------

/// Fields of a new IOC.
#[derive(Debug, Clone)]
pub struct NewIoc {
    /// The indicator.
    pub ioc_value: String,
    /// Type.
    pub ioc_type: String,
    /// Verdict.
    pub vt_verdict: String,
    /// Score.
    pub vt_score: Option<String>,
    /// Details.
    pub details: Option<String>,
}

/// Insert IOCs for one report in one transaction; returns the stored rows in
/// insertion order.
pub async fn insert_iocs(
    db: &Db,
    report_id: i64,
    alert_id: i64,
    customer_code: &str,
    iocs: &[NewIoc],
) -> Result<Vec<IocRow>, DbError> {
    let created_at = now_utc_naive();
    let mut tx = db.pool().begin().await?;
    let mut ids = Vec::with_capacity(iocs.len());
    for ioc in iocs {
        let res = sqlx::query(
            "INSERT INTO ai_analyst_ioc (report_id, alert_id, customer_code, ioc_value, ioc_type, \
             vt_verdict, vt_score, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(report_id)
        .bind(alert_id)
        .bind(customer_code)
        .bind(&ioc.ioc_value)
        .bind(&ioc.ioc_type)
        .bind(&ioc.vt_verdict)
        .bind(&ioc.vt_score)
        .bind(&ioc.details)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;
        ids.push(res.last_insert_id());
    }
    tx.commit().await?;
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(row) = get_ioc(db, i64::try_from(id).unwrap_or(i64::MAX)).await? {
            rows.push(row);
        }
    }
    Ok(rows)
}

/// One IOC.
pub async fn get_ioc(db: &Db, ioc_id: i64) -> Result<Option<IocRow>, DbError> {
    Ok(sqlx::query_as::<_, IocRow>(&format!(
        "SELECT {IOC_COLS} FROM ai_analyst_ioc WHERE id = ?"
    ))
    .bind(ioc_id)
    .fetch_optional(db.pool())
    .await?)
}

/// IOCs of a report, newest first.
pub async fn iocs_by_report(db: &Db, report_id: i64) -> Result<Vec<IocRow>, DbError> {
    Ok(sqlx::query_as::<_, IocRow>(&format!(
        "SELECT {IOC_COLS} FROM ai_analyst_ioc WHERE report_id = ? \
         ORDER BY created_at DESC, id ASC"
    ))
    .bind(report_id)
    .fetch_all(db.pool())
    .await?)
}

/// IOCs of a report in storage order (the combined analysis view).
pub async fn iocs_by_report_unordered(db: &Db, report_id: i64) -> Result<Vec<IocRow>, DbError> {
    Ok(sqlx::query_as::<_, IocRow>(&format!(
        "SELECT {IOC_COLS} FROM ai_analyst_ioc WHERE report_id = ? ORDER BY id"
    ))
    .bind(report_id)
    .fetch_all(db.pool())
    .await?)
}

/// IOCs of an alert, newest first.
pub async fn iocs_by_alert(db: &Db, alert_id: i64) -> Result<Vec<IocRow>, DbError> {
    Ok(sqlx::query_as::<_, IocRow>(&format!(
        "SELECT {IOC_COLS} FROM ai_analyst_ioc WHERE alert_id = ? \
         ORDER BY created_at DESC, id ASC"
    ))
    .bind(alert_id)
    .fetch_all(db.pool())
    .await?)
}

/// IOCs of a customer, optionally one verdict only, newest first.
pub async fn iocs_by_customer(
    db: &Db,
    customer_code: &str,
    vt_verdict: Option<&str>,
) -> Result<Vec<IocRow>, DbError> {
    let rows =
        match vt_verdict {
            Some(v) => sqlx::query_as::<_, IocRow>(&format!(
                "SELECT {IOC_COLS} FROM ai_analyst_ioc WHERE customer_code = ? AND vt_verdict = ? \
                 ORDER BY created_at DESC, id ASC"
            ))
            .bind(customer_code)
            .bind(v)
            .fetch_all(db.pool())
            .await?,
            None => {
                sqlx::query_as::<_, IocRow>(&format!(
                    "SELECT {IOC_COLS} FROM ai_analyst_ioc WHERE customer_code = ? \
                 ORDER BY created_at DESC, id ASC"
                ))
                .bind(customer_code)
                .fetch_all(db.pool())
                .await?
            }
        };
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Alerts with reports
// ---------------------------------------------------------------------------

#[derive(FromRow)]
struct AlertReportJoin {
    a_id: i32,
    a_alert_name: String,
    a_customer_code: String,
    a_status: String,
    a_source: String,
    a_assigned_to: Option<String>,
    a_alert_creation_time: NaiveDateTime,
    #[sqlx(flatten)]
    report: ReportRow,
}

impl From<AlertReportJoin> for AlertWithReport {
    fn from(j: AlertReportJoin) -> Self {
        AlertWithReport {
            alert_id: j.a_id,
            alert_name: j.a_alert_name,
            customer_code: j.a_customer_code,
            status: j.a_status,
            source: j.a_source,
            assigned_to: j.a_assigned_to,
            alert_creation_time: j.a_alert_creation_time,
            report: j.report,
        }
    }
}

const JOIN_SELECT: &str = "SELECT a.id AS a_id, a.alert_name AS a_alert_name, \
     a.customer_code AS a_customer_code, a.status AS a_status, a.source AS a_source, \
     a.assigned_to AS a_assigned_to, a.alert_creation_time AS a_alert_creation_time, \
     r.id, r.job_id, r.alert_id, r.customer_code, r.severity_assessment, r.summary, \
     r.report_markdown, r.recommended_actions, r.created_at \
     FROM incident_management_alert a JOIN ai_analyst_report r ON r.alert_id = a.id";

/// Every (alert, report) pair, newest report first; `codes` filters by the
/// alert's customer (`None` = all). One row per report.
pub async fn alerts_with_reports(
    db: &Db,
    codes: Option<&[String]>,
) -> Result<Vec<AlertWithReport>, DbError> {
    let rows = match codes {
        None => {
            sqlx::query_as::<_, AlertReportJoin>(&format!(
                "{JOIN_SELECT} ORDER BY r.created_at DESC, r.id ASC"
            ))
            .fetch_all(db.pool())
            .await?
        }
        Some([]) => Vec::new(),
        Some(codes) => {
            let placeholders = vec!["?"; codes.len()].join(", ");
            let sql = format!(
                "{JOIN_SELECT} WHERE a.customer_code IN ({placeholders}) \
                 ORDER BY r.created_at DESC, r.id ASC"
            );
            let mut q = sqlx::query_as::<_, AlertReportJoin>(&sql);
            for c in codes {
                q = q.bind(c);
            }
            q.fetch_all(db.pool()).await?
        }
    };
    Ok(rows.into_iter().map(Into::into).collect())
}

/// The alert with its newest report.
pub async fn alert_with_latest_report(
    db: &Db,
    alert_id: i64,
) -> Result<Option<AlertWithReport>, DbError> {
    let row = sqlx::query_as::<_, AlertReportJoin>(&format!(
        // With LIMIT, MySQL's top-N sort hands back the *last* of tied rows,
        // so the newest id wins a same-second tie (observed against the
        // Python service, see rust_parity_e2e.py).
        "{JOIN_SELECT} WHERE a.id = ? ORDER BY r.created_at DESC, r.id DESC LIMIT 1"
    ))
    .bind(alert_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.map(Into::into))
}

/// The alert a report belongs to, with that report.
pub async fn alert_with_report(
    db: &Db,
    report_id: i64,
) -> Result<Option<AlertWithReport>, DbError> {
    let row =
        sqlx::query_as::<_, AlertReportJoin>(&format!("{JOIN_SELECT} WHERE r.id = ? LIMIT 1"))
            .bind(report_id)
            .fetch_optional(db.pool())
            .await?;
    Ok(row.map(Into::into))
}

// ---------------------------------------------------------------------------
// Reviews
// ---------------------------------------------------------------------------

/// A review with its per-IOC rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewWithIocs {
    /// The review.
    pub review: ReviewRow,
    /// Its IOC verdict corrections.
    pub ioc_reviews: Vec<IocReviewRow>,
}

async fn ioc_reviews_for(db: &Db, review_ids: &[i32]) -> Result<Vec<IocReviewRow>, DbError> {
    if review_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; review_ids.len()].join(", ");
    let sql = format!(
        "SELECT id, review_id, ioc_id, verdict_correct, note, created_at \
         FROM ai_analyst_ioc_review WHERE review_id IN ({placeholders}) ORDER BY id"
    );
    let mut q = sqlx::query_as::<_, IocReviewRow>(&sql);
    for id in review_ids {
        q = q.bind(id);
    }
    Ok(q.fetch_all(db.pool()).await?)
}

async fn attach(db: &Db, reviews: Vec<ReviewRow>) -> Result<Vec<ReviewWithIocs>, DbError> {
    let ids: Vec<i32> = reviews.iter().map(|r| r.id).collect();
    let mut children = ioc_reviews_for(db, &ids).await?;
    Ok(reviews
        .into_iter()
        .map(|review| {
            let (mine, rest): (Vec<_>, Vec<_>) =
                children.drain(..).partition(|c| c.review_id == review.id);
            children = rest;
            ReviewWithIocs {
                review,
                ioc_reviews: mine,
            }
        })
        .collect())
}

/// One review with its IOC rows.
pub async fn get_review(db: &Db, review_id: i64) -> Result<Option<ReviewWithIocs>, DbError> {
    let row = sqlx::query_as::<_, ReviewRow>(&format!(
        "SELECT {REVIEW_COLS} FROM ai_analyst_review WHERE id = ?"
    ))
    .bind(review_id)
    .fetch_optional(db.pool())
    .await?;
    match row {
        None => Ok(None),
        Some(r) => Ok(attach(db, vec![r]).await?.into_iter().next()),
    }
}

/// The review a user wrote for a report.
pub async fn review_by_reviewer(
    db: &Db,
    report_id: i64,
    reviewer_user_id: i32,
) -> Result<Option<ReviewWithIocs>, DbError> {
    let row = sqlx::query_as::<_, ReviewRow>(&format!(
        "SELECT {REVIEW_COLS} FROM ai_analyst_review WHERE report_id = ? AND reviewer_user_id = ?"
    ))
    .bind(report_id)
    .bind(reviewer_user_id)
    .fetch_optional(db.pool())
    .await?;
    match row {
        None => Ok(None),
        Some(r) => Ok(attach(db, vec![r]).await?.into_iter().next()),
    }
}

/// A customer's reviews, newest first (optionally only the first `limit`).
pub async fn reviews_by_customer(
    db: &Db,
    customer_code: &str,
    limit: Option<i64>,
) -> Result<Vec<ReviewWithIocs>, DbError> {
    let sql = match limit {
        Some(_) => format!(
            "SELECT {REVIEW_COLS} FROM ai_analyst_review WHERE customer_code = ? \
             ORDER BY created_at DESC, id ASC LIMIT ?"
        ),
        None => format!(
            "SELECT {REVIEW_COLS} FROM ai_analyst_review WHERE customer_code = ? \
             ORDER BY created_at DESC, id ASC"
        ),
    };
    let mut q = sqlx::query_as::<_, ReviewRow>(&sql).bind(customer_code);
    if let Some(l) = limit {
        q = q.bind(l);
    }
    let rows = q.fetch_all(db.pool()).await?;
    attach(db, rows).await
}

/// The rubric part of a review.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReviewFields {
    /// `up` | `down`.
    pub overall_verdict: Option<String>,
    /// `correct` | `wrong` | `partial`.
    pub template_choice: Option<String>,
    /// Template snapshot.
    pub template_used: Option<String>,
    /// 1–5.
    pub rating_instructions: Option<i32>,
    /// 1–5.
    pub rating_artifacts: Option<i32>,
    /// 1–5.
    pub rating_severity: Option<i32>,
    /// Free text.
    pub missing_steps: Option<String>,
    /// Free text.
    pub suggested_edits: Option<String>,
}

/// One per-IOC correction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIocReview {
    /// IOC.
    pub ioc_id: i64,
    /// Right or wrong.
    pub verdict_correct: bool,
    /// Free text.
    pub note: Option<String>,
}

/// Whether [`upsert_review`] created or edited the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// New review.
    Created,
    /// Existing review overwritten.
    Updated,
}

/// `submit_review`'s write: one transaction that either inserts the review or
/// overwrites every rubric field of the reviewer's existing one (unsent
/// fields become NULL), replaces its IOC rows, and returns the result.
///
/// The unique key `(report_id, reviewer_user_id)` makes a concurrent double
/// submit lose its insert; that case is retried once as an update instead of
/// surfacing as a 500 (the Python behaviour).
pub async fn upsert_review(
    db: &Db,
    report: &ReportRow,
    reviewer_user_id: i32,
    fields: &ReviewFields,
    iocs: &[NewIocReview],
) -> Result<(ReviewWithIocs, UpsertOutcome), DbError> {
    match upsert_review_once(db, report, reviewer_user_id, fields, iocs).await {
        Err(e) if e.is_unique_violation() => {
            upsert_review_once(db, report, reviewer_user_id, fields, iocs).await
        }
        other => other,
    }
}

async fn upsert_review_once(
    db: &Db,
    report: &ReportRow,
    reviewer_user_id: i32,
    f: &ReviewFields,
    iocs: &[NewIocReview],
) -> Result<(ReviewWithIocs, UpsertOutcome), DbError> {
    // Python answers this call from the objects it just wrote, so the new
    // `created_at` / `updated_at` carry microseconds while the row holds the
    // rounded second; reproduce both.
    let micros = now_utc_micros();
    let now = mysql_datetime(micros);
    let mut tx = db.pool().begin().await?;
    let existing = sqlx::query_scalar::<_, i32>(
        "SELECT id FROM ai_analyst_review WHERE report_id = ? AND reviewer_user_id = ? FOR UPDATE",
    )
    .bind(report.id)
    .bind(reviewer_user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (review_id, outcome) = match existing {
        Some(id) => {
            sqlx::query(
                "UPDATE ai_analyst_review SET overall_verdict = ?, template_choice = ?, \
                 template_used = ?, rating_instructions = ?, rating_artifacts = ?, \
                 rating_severity = ?, missing_steps = ?, suggested_edits = ?, updated_at = ? \
                 WHERE id = ?",
            )
            .bind(&f.overall_verdict)
            .bind(&f.template_choice)
            .bind(&f.template_used)
            .bind(f.rating_instructions)
            .bind(f.rating_artifacts)
            .bind(f.rating_severity)
            .bind(&f.missing_steps)
            .bind(&f.suggested_edits)
            .bind(now)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM ai_analyst_ioc_review WHERE review_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            (id, UpsertOutcome::Updated)
        }
        None => {
            let res = sqlx::query(
                "INSERT INTO ai_analyst_review (report_id, alert_id, customer_code, \
                 reviewer_user_id, overall_verdict, template_choice, template_used, \
                 rating_instructions, rating_artifacts, rating_severity, missing_steps, \
                 suggested_edits, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            )
            .bind(report.id)
            .bind(report.alert_id)
            .bind(&report.customer_code)
            .bind(reviewer_user_id)
            .bind(&f.overall_verdict)
            .bind(&f.template_choice)
            .bind(&f.template_used)
            .bind(f.rating_instructions)
            .bind(f.rating_artifacts)
            .bind(f.rating_severity)
            .bind(&f.missing_steps)
            .bind(&f.suggested_edits)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            let id = i32::try_from(res.last_insert_id()).unwrap_or(i32::MAX);
            (id, UpsertOutcome::Created)
        }
    };
    for ioc in iocs {
        sqlx::query(
            "INSERT INTO ai_analyst_ioc_review (review_id, ioc_id, verdict_correct, note, \
             created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(review_id)
        .bind(ioc.ioc_id)
        .bind(ioc.verdict_correct)
        .bind(&ioc.note)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let mut stored = get_review(db, i64::from(review_id))
        .await?
        .ok_or_else(|| DbError::Config(format!("review {review_id} vanished after write")))?;
    match outcome {
        UpsertOutcome::Created => stored.review.created_at = micros,
        UpsertOutcome::Updated => stored.review.updated_at = Some(micros),
    }
    Ok((stored, outcome))
}

/// Aggregates for `get_review_stats` (raw; rounding happens in the service).
#[derive(Debug, Clone, Default, PartialEq, FromRow)]
pub struct ReviewAggregate {
    /// Template name (per-template rows only).
    pub template_used: Option<String>,
    /// Number of reviews.
    pub total: i64,
    /// Thumbs up.
    pub thumbs_up: i64,
    /// Thumbs down.
    pub thumbs_down: i64,
    /// Template choice correct.
    pub correct: i64,
    /// Template choice partial.
    pub partial: i64,
    /// Template choice wrong.
    pub wrong: i64,
    /// Mean rating as MySQL's `DECIMAL` text (`3.6667`): parsed by the
    /// caller exactly as Python's `float(Decimal)` would.
    pub avg_rating_instructions: Option<String>,
    /// Mean rating (decimal text).
    pub avg_rating_artifacts: Option<String>,
    /// Mean rating (decimal text).
    pub avg_rating_severity: Option<String>,
}

const AGG_COLS: &str = "COUNT(id) AS total, \
     CAST(COALESCE(SUM(CASE WHEN overall_verdict = 'up' THEN 1 ELSE 0 END), 0) AS SIGNED) AS thumbs_up, \
     CAST(COALESCE(SUM(CASE WHEN overall_verdict = 'down' THEN 1 ELSE 0 END), 0) AS SIGNED) AS thumbs_down, \
     CAST(COALESCE(SUM(CASE WHEN template_choice = 'correct' THEN 1 ELSE 0 END), 0) AS SIGNED) AS correct, \
     CAST(COALESCE(SUM(CASE WHEN template_choice = 'partial' THEN 1 ELSE 0 END), 0) AS SIGNED) AS partial, \
     CAST(COALESCE(SUM(CASE WHEN template_choice = 'wrong' THEN 1 ELSE 0 END), 0) AS SIGNED) AS wrong, \
     CAST(AVG(rating_instructions) AS CHAR) AS avg_rating_instructions, \
     CAST(AVG(rating_artifacts) AS CHAR) AS avg_rating_artifacts, \
     CAST(AVG(rating_severity) AS CHAR) AS avg_rating_severity";

/// Customer-wide review aggregate.
pub async fn review_totals(db: &Db, customer_code: &str) -> Result<ReviewAggregate, DbError> {
    Ok(sqlx::query_as::<_, ReviewAggregate>(&format!(
        "SELECT CAST(NULL AS CHAR) AS template_used, {AGG_COLS} \
         FROM ai_analyst_review WHERE customer_code = ?"
    ))
    .bind(customer_code)
    .fetch_one(db.pool())
    .await?)
}

/// Per-template aggregates, busiest template first.
pub async fn review_per_template(
    db: &Db,
    customer_code: &str,
) -> Result<Vec<ReviewAggregate>, DbError> {
    Ok(sqlx::query_as::<_, ReviewAggregate>(&format!(
        "SELECT template_used, {AGG_COLS} FROM ai_analyst_review WHERE customer_code = ? \
         GROUP BY template_used ORDER BY COUNT(id) DESC, template_used"
    ))
    .bind(customer_code)
    .fetch_all(db.pool())
    .await?)
}

/// `(total, correct, incorrect)` IOC verdict corrections for a customer.
pub async fn ioc_review_accuracy(db: &Db, customer_code: &str) -> Result<(i64, i64, i64), DbError> {
    let row = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT COUNT(ir.id), \
         CAST(COALESCE(SUM(CASE WHEN ir.verdict_correct THEN 1 ELSE 0 END), 0) AS SIGNED), \
         CAST(COALESCE(SUM(CASE WHEN ir.verdict_correct THEN 0 ELSE 1 END), 0) AS SIGNED) \
         FROM ai_analyst_ioc_review ir JOIN ai_analyst_review r ON r.id = ir.review_id \
         WHERE r.customer_code = ?",
    )
    .bind(customer_code)
    .fetch_one(db.pool())
    .await?;
    Ok(row)
}

// ---------------------------------------------------------------------------
// Palace lessons
// ---------------------------------------------------------------------------

/// Whether a review exists.
pub async fn review_exists(db: &Db, review_id: i64) -> Result<bool, DbError> {
    Ok(
        sqlx::query_scalar::<_, i32>("SELECT id FROM ai_analyst_review WHERE id = ?")
            .bind(review_id)
            .fetch_optional(db.pool())
            .await?
            .is_some(),
    )
}

/// Queue a lesson (`status = pending`).
pub async fn insert_palace_lesson(
    db: &Db,
    review_id: Option<i64>,
    customer_code: &str,
    lesson_type: &str,
    lesson_text: &str,
    durability: &str,
) -> Result<PalaceLessonRow, DbError> {
    let res = sqlx::query(
        "INSERT INTO ai_analyst_palace_lesson (review_id, customer_code, lesson_type, \
         lesson_text, durability, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
    )
    .bind(review_id)
    .bind(customer_code)
    .bind(lesson_type)
    .bind(lesson_text)
    .bind(durability)
    .bind(now_utc_naive())
    .execute(db.pool())
    .await?;
    let id = res.last_insert_id();
    sqlx::query_as::<_, PalaceLessonRow>(&format!(
        "SELECT {LESSON_COLS} FROM ai_analyst_palace_lesson WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?
    .ok_or_else(|| DbError::Config(format!("lesson {id} vanished after insert")))
}

/// Active (pending or ingested) lessons, by room then newest first.
pub async fn active_lessons(db: &Db, customer_code: &str) -> Result<Vec<PalaceLessonRow>, DbError> {
    Ok(sqlx::query_as::<_, PalaceLessonRow>(&format!(
        "SELECT {LESSON_COLS} FROM ai_analyst_palace_lesson \
         WHERE customer_code = ? AND status IN ('pending', 'ingested') \
         ORDER BY lesson_type ASC, created_at DESC, id ASC"
    ))
    .bind(customer_code)
    .fetch_all(db.pool())
    .await?)
}

/// Up to `limit` pending lessons, oldest first (the drainer's batch).
pub async fn pending_lessons(db: &Db, limit: i64) -> Result<Vec<PalaceLessonRow>, DbError> {
    Ok(sqlx::query_as::<_, PalaceLessonRow>(&format!(
        "SELECT {LESSON_COLS} FROM ai_analyst_palace_lesson WHERE status = 'pending' \
         ORDER BY created_at ASC, id ASC LIMIT ?"
    ))
    .bind(limit)
    .fetch_all(db.pool())
    .await?)
}

/// Mark a pending lesson ingested. Guarded on `status = 'pending'` so two
/// drainers (Rust and APScheduler) can never both claim it; returns whether
/// this call won.
pub async fn mark_lesson_ingested(
    db: &Db,
    lesson_id: i32,
    drawer_id: Option<&str>,
) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE ai_analyst_palace_lesson SET status = 'ingested', ingested_at = ?, drawer_id = ? \
         WHERE id = ? AND status = 'pending'",
    )
    .bind(now_utc_naive())
    .bind(drawer_id)
    .bind(lesson_id)
    .execute(db.pool())
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Mark a pending lesson failed (no retry, like the Python drainer).
pub async fn mark_lesson_failed(db: &Db, lesson_id: i32) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE ai_analyst_palace_lesson SET status = 'failed' WHERE id = ? AND status = 'pending'",
    )
    .bind(lesson_id)
    .execute(db.pool())
    .await?;
    Ok(res.rows_affected() == 1)
}

/// One-off lessons ingested before `cutoff` that still hold a drawer.
pub async fn expirable_lessons(
    db: &Db,
    cutoff: NaiveDateTime,
    limit: i64,
) -> Result<Vec<PalaceLessonRow>, DbError> {
    Ok(sqlx::query_as::<_, PalaceLessonRow>(&format!(
        "SELECT {LESSON_COLS} FROM ai_analyst_palace_lesson WHERE durability = 'one_off' \
         AND status = 'ingested' AND drawer_id IS NOT NULL AND ingested_at < ? \
         ORDER BY ingested_at ASC, id ASC LIMIT ?"
    ))
    .bind(cutoff)
    .bind(limit)
    .fetch_all(db.pool())
    .await?)
}

/// Mark an ingested lesson expired.
pub async fn mark_lesson_expired(db: &Db, lesson_id: i32) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE ai_analyst_palace_lesson SET status = 'expired', expired_at = ? \
         WHERE id = ? AND status = 'ingested'",
    )
    .bind(now_utc_naive())
    .bind(lesson_id)
    .execute(db.pool())
    .await?;
    Ok(res.rows_affected() == 1)
}
