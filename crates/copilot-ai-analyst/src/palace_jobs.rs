//! Palace lesson jobs — port of `invoke_palace_lesson_drainer` (every 2 min)
//! and `invoke_palace_lesson_sweeper` (hourly).
//!
//! - **Drainer:** up to 25 `pending` lessons, oldest first, each POSTed to
//!   Talon's `/palace/lesson`; success → `ingested` (+ `drawer_id` when Talon
//!   returns one), failure → `failed`, no retry.
//! - **Sweeper:** up to 25 one-off lessons ingested more than 7 days ago that
//!   hold a drawer, each forgotten via `/palace/forget`; the row becomes
//!   `expired` whether or not MemPalace confirmed.
//!
//! Status changes are guarded on the previous status, so a row is never
//! flipped twice. Both run on `copilot-scheduler`'s runner ([`job_specs`]):
//! only while the operator opted in (`COPILOT_RS_PALACE_JOBS=true`, or the
//! ids in `COPILOT_RS_JOBS`) **and** the job's `scheduled_job_metadata` row is
//! disabled — *Pause* in CoPilot's Scheduler UI hands a job over, *Start*
//! hands it back. Like the Python functions, a manual run stamps
//! `last_success` too.

use chrono::Duration as ChronoDuration;
use serde_json::Value;

use copilot_core::time::now_utc_naive;
use copilot_db::ai_analyst as db;
use copilot_scheduler::{JobError, JobSpec};
use copilot_talon::TalonConnector;
use copilot_talon::contract::PalaceLessonRequest;
use copilot_talon::services::{forget_palace_drawer, post_palace_lesson};
use copilot_web::AppContext;

/// APScheduler job id of the drainer.
pub const DRAINER_JOB_ID: &str = "invoke_palace_lesson_drainer";
/// APScheduler job id of the sweeper.
pub const SWEEPER_JOB_ID: &str = "invoke_palace_lesson_sweeper";
/// Rows per tick.
pub const BATCH_SIZE: i64 = 25;
/// One-off lifetime.
pub const ONE_OFF_EXPIRY_DAYS: i64 = 7;

/// Outcome of one drainer tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Lessons Talon accepted.
    pub ingested: usize,
    /// Lessons Talon refused or could not be reached for.
    pub failed: usize,
}

/// Outcome of one sweeper tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Drawers MemPalace confirmed deleting.
    pub forgotten: usize,
    /// Rows expired without confirmation.
    pub forget_failed: usize,
}

/// `drawer_id` from Talon's `/palace/lesson` answer, if it is a non-empty string.
pub fn drawer_id(data: &Value) -> Option<&str> {
    data.get("drawer_id")
        .and_then(Value::as_str)
        .filter(|d| !d.is_empty())
}

/// One drainer tick.
pub async fn drain_once(
    ctx: &AppContext,
    talon: &TalonConnector,
) -> Result<DrainReport, copilot_db::DbError> {
    let lessons = db::pending_lessons(&ctx.db, BATCH_SIZE).await?;
    let mut report = DrainReport::default();
    for lesson in lessons {
        let body = PalaceLessonRequest {
            customer_code: lesson.customer_code.clone(),
            lesson_type: lesson.lesson_type.clone(),
            lesson_text: lesson.lesson_text.clone().unwrap_or_default(),
            durability: lesson.durability.clone(),
        };
        match post_palace_lesson(talon, &body).await {
            Ok(data) => {
                let drawer = drawer_id(&data);
                if drawer.is_none() {
                    tracing::warn!(
                        lesson_id = lesson.id,
                        "palace lesson ingested without drawer_id; the sweeper will skip it"
                    );
                }
                if db::mark_lesson_ingested(&ctx.db, lesson.id, drawer).await? {
                    report.ingested += 1;
                    tracing::info!(lesson_id = lesson.id, customer = %lesson.customer_code,
                        room = %lesson.lesson_type, "palace lesson ingested");
                }
            }
            Err(e) => {
                tracing::warn!(lesson_id = lesson.id, err = %e, "palace lesson failed");
                if db::mark_lesson_failed(&ctx.db, lesson.id).await? {
                    report.failed += 1;
                }
            }
        }
    }
    Ok(report)
}

/// One sweeper tick.
pub async fn sweep_once(
    ctx: &AppContext,
    talon: &TalonConnector,
) -> Result<SweepReport, copilot_db::DbError> {
    let cutoff = now_utc_naive() - ChronoDuration::days(ONE_OFF_EXPIRY_DAYS);
    let lessons = db::expirable_lessons(&ctx.db, cutoff, BATCH_SIZE).await?;
    let mut report = SweepReport::default();
    for lesson in lessons {
        let Some(drawer) = lesson.drawer_id.as_deref() else {
            continue;
        };
        let confirmed = match forget_palace_drawer(talon, drawer).await {
            Ok(data) => data.get("success").is_some_and(truthy),
            Err(e) => {
                tracing::warn!(lesson_id = lesson.id, err = %e, "palace forget failed");
                false
            }
        };
        if !confirmed {
            tracing::warn!(
                lesson_id = lesson.id,
                drawer_id = drawer,
                "palace forget not confirmed; expiring the row anyway"
            );
        }
        if db::mark_lesson_expired(&ctx.db, lesson.id).await? {
            if confirmed {
                report.forgotten += 1;
            } else {
                report.forget_failed += 1;
            }
        }
    }
    Ok(report)
}

/// Python truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// The two jobs, for the scheduler: the drainer every 2 minutes, the sweeper
/// hourly (the intervals `initialize_job_metadata` seeds).
pub fn job_specs(ctx: &AppContext, talon: &TalonConnector) -> Vec<JobSpec> {
    let drainer = {
        let (ctx, talon) = (ctx.clone(), talon.clone());
        JobSpec::new(DRAINER_JOB_ID, 2, move || {
            let (ctx, talon) = (ctx.clone(), talon.clone());
            async move {
                let r = drain_once(&ctx, &talon).await.map_err(JobError::from)?;
                if r != DrainReport::default() {
                    tracing::info!(
                        ingested = r.ingested,
                        failed = r.failed,
                        "palace drainer tick"
                    );
                }
                Ok(())
            }
        })
        .stamps_manual_runs()
    };
    let sweeper = {
        let (ctx, talon) = (ctx.clone(), talon.clone());
        JobSpec::new(SWEEPER_JOB_ID, 60, move || {
            let (ctx, talon) = (ctx.clone(), talon.clone());
            async move {
                let r = sweep_once(&ctx, &talon).await.map_err(JobError::from)?;
                if r != SweepReport::default() {
                    tracing::info!(
                        forgotten = r.forgotten,
                        failed = r.forget_failed,
                        "palace sweeper tick"
                    );
                }
                Ok(())
            }
        })
        .stamps_manual_runs()
    };
    vec![drainer, sweeper]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn drawer_and_truthiness() {
        assert_eq!(drawer_id(&json!({"drawer_id": "abc"})), Some("abc"));
        assert_eq!(drawer_id(&json!({"drawer_id": ""})), None);
        assert_eq!(drawer_id(&json!({"drawer_id": 5})), None);
        assert!(truthy(&json!(true)));
        assert!(truthy(&json!("yes")));
        assert!(!truthy(&json!(0)));
        assert!(!truthy(&json!(null)));
    }
}
