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
//! flipped twice. The loops only act while `COPILOT_RS_PALACE_JOBS=true`
//! **and** the legacy APScheduler row (`scheduled_job_metadata.job_id`) is
//! disabled — disable the job in CoPilot's Scheduler UI to hand it over.

use std::time::Duration;

use chrono::Duration as ChronoDuration;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use copilot_core::time::now_utc_naive;
use copilot_db::ai_analyst as db;
use copilot_db::scheduler;
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

/// Whether this service should run `job_id` now, and how often.
async fn handed_over(ctx: &AppContext, job_id: &str, default_minutes: i64) -> (bool, Duration) {
    match scheduler::legacy_job(&ctx.db, job_id).await {
        Ok(Some((enabled, minutes))) => (
            !enabled,
            Duration::from_secs(u64::try_from(minutes.max(1)).unwrap_or(1) * 60),
        ),
        Ok(None) => (
            true,
            Duration::from_secs(u64::try_from(default_minutes).unwrap_or(1) * 60),
        ),
        Err(e) => {
            tracing::warn!(job_id, err = %e, "cannot read scheduled_job_metadata; skipping tick");
            (false, Duration::from_secs(60))
        }
    }
}

/// Run both jobs until `cancel` fires.
pub async fn run(ctx: AppContext, talon: TalonConnector, cancel: CancellationToken) {
    let drainer = {
        let (ctx, talon, cancel) = (ctx.clone(), talon.clone(), cancel.clone());
        tokio::spawn(async move {
            job_loop(&ctx, DRAINER_JOB_ID, 2, &cancel, || async {
                drain_once(&ctx, &talon).await.map(|r| {
                    if r != DrainReport::default() {
                        tracing::info!(
                            ingested = r.ingested,
                            failed = r.failed,
                            "palace drainer tick"
                        );
                    }
                })
            })
            .await;
        })
    };
    let sweeper = tokio::spawn(async move {
        job_loop(&ctx, SWEEPER_JOB_ID, 60, &cancel, || async {
            sweep_once(&ctx, &talon).await.map(|r| {
                if r != SweepReport::default() {
                    tracing::info!(
                        forgotten = r.forgotten,
                        failed = r.forget_failed,
                        "palace sweeper tick"
                    );
                }
            })
        })
        .await;
    });
    let _ = tokio::join!(drainer, sweeper);
}

async fn job_loop<F, Fut>(
    ctx: &AppContext,
    job_id: &'static str,
    default_minutes: i64,
    cancel: &CancellationToken,
    mut tick: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), copilot_db::DbError>>,
{
    loop {
        let (active, every) = handed_over(ctx, job_id, default_minutes).await;
        if active {
            match tick().await {
                Ok(()) => {
                    if let Err(e) = scheduler::stamp_last_success(&ctx.db, job_id).await {
                        tracing::warn!(job_id, err = %e, "cannot stamp last_success");
                    }
                }
                Err(e) => tracing::error!(job_id, err = %e, "scheduled job failed"),
            }
        } else {
            tracing::debug!(job_id, "legacy scheduler owns this job; idle");
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(every) => {}
        }
    }
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
