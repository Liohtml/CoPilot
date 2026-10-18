//! Port of `app/customer_portal/services/ai_requests.py`: a portal user
//! asking Talon to analyse one of their alerts (#1215).
//!
//! The only portal write on the AI surface, gated twice per customer (the
//! AI report switch *and* `allow_customer_requests`, both operator decisions,
//! both off by default). A request has to clear, in order:
//!
//! 1. the alert is one the caller may see (customer *and* tags);
//! 2. both switches are on for the alert's customer — taken from the alert,
//!    never from a body;
//! 3. no analysis of the alert is still pending or running (one stuck longer
//!    than [`STALE_INVESTIGATION_AFTER_MINUTES`] is dead, not in progress);
//! 4. the alert was not analysed or asked about in the last
//!    [`REQUEST_COOLDOWN_MINUTES`];
//! 5. the customer is under its daily limit, when one is set.
//!
//! Checks 2–5 and the insert run under `SELECT … FOR UPDATE` on the
//! customer's settings row ([`copilot_db::customer_portal::record_request`]),
//! so two clicks cannot both pass. The lock is released before Talon is
//! called; if Talon refuses, the row is deleted again — a failure costs the
//! customer neither a request nor the cooldown. Talon's error text never
//! reaches the customer.

use chrono::{Duration, NaiveDateTime};
use http::StatusCode;

use copilot_core::audit::AuditRecord;
use copilot_core::time::now_utc_micros;
use copilot_db::alerts;
use copilot_db::customer_portal::{self as db, AiRequestRow, NewRequest, RequestSnapshot};
use copilot_talon::TalonState;
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::reports::{ensure_alert_visible, window_start};

/// Minimum gap between two analyses of one alert, whoever started the last.
pub const REQUEST_COOLDOWN_MINUTES: i64 = 30;

/// A job still pending/running after this long is taken as dead (Talon
/// restarted, the agent crashed) rather than in progress.
pub const STALE_INVESTIGATION_AFTER_MINUTES: i64 = 120;

/// How Talon is told the request came from the portal.
pub const PORTAL_SENDER: &str = "customer-portal";

/// `ai_analysis.request`.
pub const AUDIT_ACTION: &str = "ai_analysis.request";

/// The comment left on the alert's timeline.
pub const REQUEST_COMMENT: &str = "AI analysis requested from the Customer Portal.";

const TALON_FAILED_AUDIT: &str = "The AI analyst could not start the analysis";
const TALON_FAILED: &str = "The AI analyst could not start the analysis. Please try again later.";

/// Why a request cannot go ahead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// 403, 409 or 429.
    pub status: StatusCode,
    /// The message the customer sees.
    pub message: String,
}

impl From<Refusal> for ApiError {
    fn from(r: Refusal) -> Self {
        ApiError::http(r.status, r.message)
    }
}

/// `_minutes_until`: whole minutes left, rounded up, at least 1.
fn minutes_until(moment: NaiveDateTime, now: NaiveDateTime) -> i64 {
    // `int(total_seconds)` truncates toward zero; `-(-x // 60)` is ceil.
    let secs = (moment - now)
        .num_microseconds()
        .map_or_else(|| (moment - now).num_seconds(), |us| us / 1_000_000);
    (-((-secs).div_euclid(60))).max(1)
}

/// `refusal`: pure, so the rules test without a database.
pub fn refusal(s: &RequestSnapshot, now: NaiveDateTime) -> Option<Refusal> {
    let Some(settings) = s.settings.as_ref().filter(|s| s.requests_allowed()) else {
        return Some(Refusal {
            status: StatusCode::FORBIDDEN,
            message: "Requesting an AI analysis is not enabled for this customer".into(),
        });
    };
    if let Some((status, created_at)) = &s.latest_job {
        if matches!(status.as_str(), "pending" | "running")
            && now - *created_at < Duration::minutes(STALE_INVESTIGATION_AFTER_MINUTES)
        {
            return Some(Refusal {
                status: StatusCode::CONFLICT,
                message: "An AI analysis of this alert is already in progress".into(),
            });
        }
    }
    let last = [s.latest_job.as_ref().map(|j| j.1), s.latest_request]
        .into_iter()
        .flatten()
        .max();
    let cooldown = Duration::minutes(REQUEST_COOLDOWN_MINUTES);
    if let Some(last) = last.filter(|l| now - *l < cooldown) {
        let minutes = minutes_until(last + cooldown, now);
        let plural = if minutes == 1 { "" } else { "s" };
        return Some(Refusal {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: format!(
                "This alert was analysed recently. You can request a new analysis in \
                 {minutes} minute{plural}."
            ),
        });
    }
    if settings
        .daily_request_limit
        .is_some_and(|limit| s.recent_requests >= i64::from(limit))
    {
        return Some(Refusal {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "Your organization has reached its daily limit of AI analyses. \
                      Please try again later."
                .into(),
        });
    }
    None
}

/// `request_alert_analysis`: ask Talon to analyse `alert_id` for the
/// caller, or return why not.
pub async fn request_alert_analysis(
    st: &TalonState,
    user: &CurrentUser,
    alert_id: i64,
) -> Result<AiRequestRow, ApiError> {
    let ctx = &st.ctx;
    let alert = ensure_alert_visible(ctx, user, alert_id).await?;
    let customer_code = alert.customer_code.as_str();
    let now = now_utc_micros();
    let new = NewRequest {
        customer_code,
        alert_id,
        user_id: Some(user.id),
        username: &user.username,
        now,
        window_start: window_start(now),
    };
    let request = match db::record_request(&ctx.db, &new, |snap| match refusal(snap, now) {
        Some(r) => Err(r),
        None => Ok(()),
    })
    .await?
    {
        Ok(row) => row,
        Err(refused) => {
            audit(ctx, user, customer_code, alert_id, Some(&refused.message));
            return Err(refused.into());
        }
    };

    if let Err(e) = copilot_talon::services::investigate_alert(
        &st.talon,
        alert_id,
        customer_code,
        PORTAL_SENDER,
    )
    .await
    {
        tracing::error!(
            alert_id,
            customer_code,
            err = %e,
            "Talon refused the portal request"
        );
        db::delete_request(&ctx.db, request.id).await?;
        audit(ctx, user, customer_code, alert_id, Some(TALON_FAILED_AUDIT));
        return Err(ApiError::http(StatusCode::BAD_GATEWAY, TALON_FAILED));
    }

    audit(ctx, user, customer_code, alert_id, None);
    // Best-effort courtesy note; the request already went through.
    if let Err(e) =
        alerts::insert_alert_comment(&ctx.db, alert_id, REQUEST_COMMENT, &user.username).await
    {
        tracing::warn!(alert_id, err = %e, "could not note the AI analysis request on the alert");
    }
    tracing::info!(
        user = %user.username,
        alert_id,
        customer_code,
        "portal user requested an AI analysis"
    );
    Ok(request)
}

/// `_audit`: a refusal or failure carries its reason as `details`.
fn audit(
    ctx: &AppContext,
    user: &CurrentUser,
    customer_code: &str,
    alert_id: i64,
    failure: Option<&str>,
) {
    let mut record = AuditRecord::new(AUDIT_ACTION)
        .actor(Some(user.id), Some(&user.username))
        .customer(Some(customer_code))
        .entity("alert", alert_id);
    if let Some(reason) = failure {
        record = record.failed().details(reason);
    }
    ctx.audit.record(record);
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_db::customer_portal::AiReportSettingsRow;

    fn t(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").unwrap()
    }

    fn settings(allow: bool, limit: Option<i32>) -> AiReportSettingsRow {
        AiReportSettingsRow {
            id: 1,
            customer_code: "acme".into(),
            enabled: true,
            allow_customer_requests: allow,
            daily_request_limit: limit,
            updated_at: t("2026-01-01 00:00:00"),
            updated_by: None,
        }
    }

    fn snap(settings: Option<AiReportSettingsRow>) -> RequestSnapshot {
        RequestSnapshot {
            settings,
            latest_job: None,
            latest_request: None,
            recent_requests: 0,
        }
    }

    const NOW: &str = "2026-01-01 12:00:00.250000";

    fn status(s: &RequestSnapshot) -> Option<(u16, String)> {
        refusal(s, t(NOW)).map(|r| (r.status.as_u16(), r.message))
    }

    #[test]
    fn both_switches_are_required() {
        assert_eq!(status(&snap(None)).unwrap().0, 403);
        assert_eq!(status(&snap(Some(settings(false, None)))).unwrap().0, 403);
        let mut off = settings(true, None);
        off.enabled = false;
        assert_eq!(status(&snap(Some(off))).unwrap().0, 403);
        assert_eq!(status(&snap(Some(settings(true, None)))), None);
    }

    #[test]
    fn running_job_blocks_until_stale() {
        let mut s = snap(Some(settings(true, None)));
        s.latest_job = Some(("running".into(), t("2026-01-01 11:00:00")));
        assert_eq!(status(&s).unwrap().0, 409);
        // Dead after two hours: no longer "in progress", and past the cooldown.
        s.latest_job = Some(("pending".into(), t("2026-01-01 09:59:00")));
        assert_eq!(status(&s), None);
        // A finished job only counts for the cooldown (over at 12:29:00).
        s.latest_job = Some(("completed".into(), t("2026-01-01 11:59:00")));
        assert_eq!(
            status(&s).unwrap(),
            (
                429,
                "This alert was analysed recently. You can request a new analysis in 29 minutes."
                    .into()
            )
        );
    }

    #[test]
    fn cooldown_counts_the_later_of_job_and_request_and_rounds_up() {
        let mut s = snap(Some(settings(true, None)));
        s.latest_job = Some(("failed".into(), t("2026-01-01 10:00:00")));
        s.latest_request = Some(t("2026-01-01 11:31:00"));
        // 30 min after 11:31:00 is 12:01:00 → 59.75 s left → int → 59 → 1 minute.
        assert_eq!(
            status(&s).unwrap().1,
            "This alert was analysed recently. You can request a new analysis in 1 minute."
        );
        s.latest_request = Some(t("2026-01-01 11:45:00"));
        // 15 min − 0.25 s → int(899.75) = 899 → ceil(899/60) = 15.
        assert!(status(&s).unwrap().1.ends_with("in 15 minutes."));
        s.latest_request = Some(t("2026-01-01 11:30:00"));
        assert_eq!(
            status(&s),
            None,
            "exactly 30 minutes ago is past the cooldown"
        );
    }

    #[test]
    fn daily_limit_is_checked_last() {
        let mut s = snap(Some(settings(true, Some(3))));
        s.recent_requests = 2;
        assert_eq!(status(&s), None);
        s.recent_requests = 3;
        assert_eq!(
            status(&s).unwrap(),
            (
                429,
                "Your organization has reached its daily limit of AI analyses. Please try again \
                 later."
                    .into()
            )
        );
        s.latest_job = Some(("running".into(), t("2026-01-01 11:50:00")));
        assert_eq!(
            status(&s).unwrap().0,
            409,
            "in progress wins over the limit"
        );
    }

    #[test]
    fn minutes_round_up_from_truncated_seconds() {
        let now = t("2026-01-01 12:00:00");
        assert_eq!(minutes_until(t("2026-01-01 12:00:00.5"), now), 1);
        assert_eq!(minutes_until(t("2026-01-01 12:01:00"), now), 1);
        assert_eq!(minutes_until(t("2026-01-01 12:01:01"), now), 2);
        assert_eq!(minutes_until(t("2026-01-01 12:29:59.9"), now), 30);
    }
}
