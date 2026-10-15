//! Port of `app/customer_portal/services/ai_reports.py`: the per-customer
//! switch and the portal's read paths.
//!
//! The switch is **opt-in** (a missing row is disabled) and every read here
//! goes through it, so turning it off hides the overview card and the alert
//! tab at once. Alert visibility is `copilot_db::visibility` — the one
//! definition of customer scoping *and* tag RBAC — with the switch ANDed on
//! top, so an AI report never surfaces for an alert the user cannot open.

use chrono::{Duration, NaiveDateTime};
use serde_json::{Map, Value};

use copilot_auth::AccessScope;
use copilot_core::time::now_utc_micros;
use copilot_db::alerts::{self, AlertSummary};
use copilot_db::customer_portal as db;
use copilot_db::visibility::{self, AlertVisibility};
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::schema::{PortalAiInsightAlert, PortalAiInvestigation, PortalAiIoc, PortalAiReport};

/// Severity bucket for a report persisted without an assessment.
pub const UNKNOWN_SEVERITY: &str = "Unknown";

/// The daily limit counts over any 24 hours, not a calendar day, so it means
/// the same in every timezone.
pub fn request_limit_window() -> Duration {
    Duration::hours(24)
}

/// Start of the daily-limit window ending at `now`.
pub fn window_start(now: NaiveDateTime) -> NaiveDateTime {
    now - request_limit_window()
}

/// `count_recent_requests`.
pub async fn count_recent_requests(ctx: &AppContext, customer_code: &str) -> Result<i64, ApiError> {
    Ok(db::count_requests_since(&ctx.db, customer_code, window_start(now_utc_micros())).await?)
}

/// `ensure_alert_visible`: the alert, or 404 / 403 (customer) / 403 (tags).
/// Deliberately reads only the alert row — this surface needs nothing more.
pub async fn ensure_alert_visible(
    ctx: &AppContext,
    user: &CurrentUser,
    alert_id: i64,
) -> Result<AlertSummary, ApiError> {
    let alert = alerts::find_alert(&ctx.db, alert_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Alert {alert_id} not found")))?;
    if !user.access(ctx).await?.can_access(&alert.customer_code) {
        return Err(ApiError::forbidden(format!(
            "Access denied to alert {alert_id} - insufficient customer permissions"
        )));
    }
    if !visibility::can_user_access_alert(&ctx.db, user.id, user.role_id, alert_id).await? {
        return Err(ApiError::forbidden(format!(
            "Access denied to alert {alert_id} - insufficient tag permissions"
        )));
    }
    Ok(alert)
}

/// `is_ai_reports_enabled_for_user`: with a customer, the caller must be
/// entitled to it; without one, "enabled for any customer I can see".
pub async fn availability(
    ctx: &AppContext,
    user: &CurrentUser,
    customer_code: Option<&str>,
) -> Result<(Option<String>, bool), ApiError> {
    if let Some(code) = customer_code.filter(|c| !c.is_empty()) {
        user.enforce_customer(ctx, code).await?;
        let enabled = db::settings(&ctx.db, code)
            .await?
            .is_some_and(|s| s.enabled);
        return Ok((Some(code.to_string()), enabled));
    }
    let enabled = match user.access(ctx).await? {
        AccessScope::All => db::any_enabled(&ctx.db, None).await?,
        AccessScope::Customers(codes) if codes.is_empty() => false,
        AccessScope::Customers(codes) => db::any_enabled(&ctx.db, Some(codes.as_slice())).await?,
    };
    Ok((None, enabled))
}

/// What the portal's AI Report tab renders for one alert.
#[derive(Debug, Clone, PartialEq)]
pub struct PortalAlertAnalysis {
    /// The customer's switch.
    pub enabled: bool,
    /// Whether the portal offers to (re)run the analysis.
    pub can_request: bool,
    /// Latest investigation.
    pub investigation: Option<PortalAiInvestigation>,
    /// Its report.
    pub report: Option<PortalAiReport>,
    /// The report's IOCs.
    pub iocs: Vec<PortalAiIoc>,
}

/// `get_portal_alert_analysis`. With the switch off nothing else is read,
/// so "switched off" stays distinguishable from "no investigation ran".
pub async fn alert_analysis(
    ctx: &AppContext,
    user: &CurrentUser,
    alert_id: i64,
) -> Result<PortalAlertAnalysis, ApiError> {
    let alert = ensure_alert_visible(ctx, user, alert_id).await?;
    let settings = db::settings(&ctx.db, &alert.customer_code).await?;
    let Some(settings) = settings.filter(|s| s.enabled) else {
        return Ok(PortalAlertAnalysis {
            enabled: false,
            can_request: false,
            investigation: None,
            report: None,
            iocs: Vec::new(),
        });
    };
    let can_request = settings.requests_allowed();
    let analysis = copilot_ai_analyst::services::alert_analysis(ctx, alert_id).await?;
    Ok(match analysis {
        None => PortalAlertAnalysis {
            enabled: true,
            can_request,
            investigation: None,
            report: None,
            iocs: Vec::new(),
        },
        Some((job, report, iocs)) => PortalAlertAnalysis {
            enabled: true,
            can_request,
            investigation: Some(job.into()),
            report: report.map(Into::into),
            iocs: iocs.into_iter().map(Into::into).collect(),
        },
    })
}

/// `get_portal_ai_insights`: `(total, severity_counts, recent)`.
pub async fn insights(
    ctx: &AppContext,
    user: &CurrentUser,
    customer_codes: Option<&[String]>,
    limit: i64,
) -> Result<(i64, Map<String, Value>, Vec<PortalAiInsightAlert>), ApiError> {
    let access = user.access(ctx).await?;
    let Some(visibility) =
        AlertVisibility::for_user(&ctx.db, user.id, user.role_id, access, customer_codes).await?
    else {
        return Ok((0, Map::new(), Vec::new()));
    };
    let (counts, recent) = db::ai_insights(&ctx.db, &visibility, limit).await?;
    let (total, severity_counts) = severity_breakdown(counts);
    Ok((
        total,
        severity_counts,
        recent.into_iter().map(Into::into).collect(),
    ))
}

/// Fold `(severity, count)` rows the way the Python loop does: a missing or
/// empty severity is `Unknown`, and when two rows land on one key the later
/// count replaces the earlier one in the map (the total still sums both).
pub fn severity_breakdown(rows: Vec<(Option<String>, i64)>) -> (i64, Map<String, Value>) {
    let mut counts = Map::new();
    let mut total = 0;
    for (severity, n) in rows {
        let key = severity
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| UNKNOWN_SEVERITY.to_string());
        counts.insert(key, Value::from(n));
        total += n;
    }
    (total, counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn severity_breakdown_matches_the_python_loop() {
        let (total, counts) = severity_breakdown(vec![
            (Some("High".into()), 2),
            (None, 1),
            (Some("Low".into()), 4),
            (Some(String::new()), 3),
        ]);
        assert_eq!(total, 10);
        assert_eq!(
            Value::Object(counts),
            json!({"High": 2, "Unknown": 3, "Low": 4})
        );
        let keys: Vec<_> = severity_breakdown(vec![(Some("B".into()), 1), (Some("A".into()), 1)])
            .1
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys, ["B", "A"], "row order, not sorted");
    }
}
