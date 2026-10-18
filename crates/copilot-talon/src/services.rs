//! Talon services — port of `app/connectors/talon/services/talon.py`.
//!
//! Every failure Python turned into `HTTPException(500, detail=<helper
//! message>)` is [`ApiError::server_error`] with the same text here.

use std::time::Duration;

use serde::Serialize;
use serde_json::{Map, Value, json};

use copilot_core::time::to_pydantic_iso;
use copilot_db::{ai_analyst, alerts};
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::client::{POST_TIMEOUT, TalonConnector, TalonError};
use crate::contract::{
    InvestigateRequest, Investigation, MessageRequest, PalaceForgetRequest, PalaceLessonRequest,
    SessionResetRequest, StatusResponse, TRIGGERED_MANUAL, TemplateInfo, is_valid_investigation_id,
};

/// `ANALYST_SENDER`: what an analyst-initiated investigation is labelled.
pub const ANALYST_SENDER: &str = "copilot-analyst";

fn server_error(e: TalonError) -> ApiError {
    match e {
        TalonError::Db(db) => ApiError::internal(db),
        other => ApiError::server_error(other.to_string()),
    }
}

/// `_message_payload`: the lane is always the authenticated user's.
pub fn message_payload(message: &str, sender: &str, user: &CurrentUser) -> MessageRequest {
    MessageRequest {
        message: message.to_string(),
        sender: sender.to_string(),
        user_id: Some(user.id.to_string()),
        user_name: Some(user.username.clone()).filter(|n| !n.is_empty()),
    }
}

/// `investigate_alert`: queue an investigation; Talon's JSON comes back as
/// `data`. Every caller is a person (analyst or customer portal), so the job
/// is recorded as `manual`.
pub async fn investigate_alert(
    talon: &TalonConnector,
    alert_id: i64,
    customer_code: &str,
    sender: &str,
) -> Result<Value, ApiError> {
    let body = InvestigateRequest {
        alert_id,
        customer_code: customer_code.to_string(),
        triggered_by: Some(TRIGGERED_MANUAL.to_string()),
        template_override: None,
        sender: sender.to_string(),
    };
    talon
        .post("/investigate", &body, POST_TIMEOUT)
        .await
        .map_err(server_error)
}

/// `investigate_alert_for_user`: the alert must exist, belong to one of the
/// caller's customers, and match the body's `customer_code`.
pub async fn investigate_alert_for_user(
    ctx: &AppContext,
    talon: &TalonConnector,
    user: &CurrentUser,
    alert_id: i64,
    customer_code: &str,
) -> Result<Value, ApiError> {
    let alert = alerts::find_alert(&ctx.db, alert_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Alert {alert_id} not found")))?;
    user.enforce_customer(ctx, &alert.customer_code).await?;
    if customer_code != alert.customer_code {
        return Err(ApiError::bad_request(format!(
            "customer_code mismatch: alert {} belongs to {}, got {customer_code}",
            alert.id, alert.customer_code
        )));
    }
    investigate_alert(talon, alert_id, customer_code, ANALYST_SENDER).await
}

/// `replay_investigation`: re-run with a forced template (`manual`).
pub async fn replay_investigation(
    talon: &TalonConnector,
    alert_id: i64,
    customer_code: &str,
    template_override: &str,
    sender: &str,
) -> Result<Value, ApiError> {
    let body = InvestigateRequest {
        alert_id,
        customer_code: customer_code.to_string(),
        triggered_by: Some(TRIGGERED_MANUAL.to_string()),
        template_override: Some(template_override.to_string()),
        sender: sender.to_string(),
    };
    talon
        .post("/investigate", &body, POST_TIMEOUT)
        .await
        .map_err(server_error)
}

/// `reset_talon_session`: clear the caller's chat lane; returns
/// `lanes_cleared`.
pub async fn reset_session(talon: &TalonConnector, user_id: i32) -> Result<u64, ApiError> {
    let body = SessionResetRequest {
        scope: "chat".into(),
        user_id: Some(user_id.to_string()),
    };
    let data = talon
        .post("/session/reset", &body, POST_TIMEOUT)
        .await
        .map_err(server_error)?;
    Ok(data.get("cleared").and_then(Value::as_u64).unwrap_or(0))
}

/// `get_talon_session_context`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionContext {
    /// Response message.
    #[serde(skip)]
    pub message: &'static str,
    /// Conversation size.
    pub input_tokens: Option<i64>,
    /// When that figure was recorded.
    pub updated_at: Option<String>,
}

/// Only the caller's own lane, and never an error: this decorates a header.
pub async fn session_context(talon: &TalonConnector, user_id: i32) -> SessionContext {
    let unavailable = SessionContext {
        message: "Talon session context unavailable",
        input_tokens: None,
        updated_at: None,
    };
    let Ok(data) = talon.get("/status", &[]).await else {
        return unavailable;
    };
    let status: StatusResponse = serde_json::from_value(data).unwrap_or(StatusResponse {
        sessions: Vec::new(),
    });
    let me = user_id.to_string();
    match status
        .sessions
        .into_iter()
        .find(|s| s.user_id.as_deref().unwrap_or("") == me)
    {
        None => SessionContext {
            message: "No active Talon conversation",
            input_tokens: None,
            updated_at: None,
        },
        Some(lane) => SessionContext {
            message: "Talon session context retrieved",
            input_tokens: lane.input_tokens,
            updated_at: lane.updated_at,
        },
    }
}

/// `get_talon_status`: Talon's `/status` JSON.
pub async fn status(talon: &TalonConnector) -> Result<Value, ApiError> {
    talon.get("/status", &[]).await.map_err(server_error)
}

/// `list_talon_templates`.
pub async fn templates(talon: &TalonConnector) -> Result<Vec<TemplateInfo>, ApiError> {
    let data = talon.get("/templates", &[]).await.map_err(server_error)?;
    let raw = match data.get("templates") {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    raw.into_iter()
        .map(serde_json::from_value::<TemplateInfo>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            ApiError::bad_request(format!("Talon returned malformed template metadata: {e}"))
        })
}

/// `search_palace_lessons`: Talon's `/palace/search` JSON.
pub async fn search_palace(
    talon: &TalonConnector,
    customer_code: &str,
    query: &str,
    room: Option<&str>,
    limit: i64,
) -> Result<Value, ApiError> {
    let mut params = vec![
        ("customer_code", customer_code.to_string()),
        ("query", query.to_string()),
        ("limit", limit.to_string()),
    ];
    if let Some(room) = room {
        params.push(("room", room.to_string()));
    }
    talon
        .get("/palace/search", &params)
        .await
        .map_err(server_error)
}

/// `POST /palace/lesson` (drainer). Returns Talon's JSON.
pub async fn post_palace_lesson(
    talon: &TalonConnector,
    lesson: &PalaceLessonRequest,
) -> Result<Value, TalonError> {
    talon
        .post("/palace/lesson", lesson, Duration::from_secs(60))
        .await
}

/// `POST /palace/forget` (sweeper). Returns Talon's JSON.
pub async fn forget_palace_drawer(
    talon: &TalonConnector,
    drawer_id: &str,
) -> Result<Value, TalonError> {
    let body = PalaceForgetRequest {
        drawer_id: drawer_id.to_string(),
    };
    talon
        .post("/palace/forget", &body, Duration::from_secs(30))
        .await
}

fn iso(t: Option<chrono::NaiveDateTime>) -> Value {
    t.map_or(Value::Null, |t| Value::String(to_pydantic_iso(t)))
}

/// `get_talon_job`: the latest job for an alert plus the reports of *all*
/// its jobs (database only).
pub async fn talon_job(ctx: &AppContext, alert_id: i64) -> Result<Value, ApiError> {
    let jobs = ai_analyst::jobs_by_alert(&ctx.db, alert_id).await?;
    let Some(latest) = jobs.first() else {
        return Err(ApiError::not_found(format!(
            "No job found for alert {alert_id}"
        )));
    };
    let mut reports = Vec::new();
    for job in &jobs {
        for r in ai_analyst::reports_by_job(&ctx.db, &job.id).await? {
            reports.push(json!({
                "id": r.id,
                "job_id": job.id,
                "alert_id": job.alert_id,
                "customer_code": job.customer_code,
                "severity_assessment": r.severity_assessment,
                "summary": r.summary,
                "report_markdown": r.report_markdown,
                "recommended_actions": r.recommended_actions,
                "created_at": to_pydantic_iso(r.created_at),
            }));
        }
    }
    let mut data = Map::new();
    data.insert("id".into(), json!(latest.id));
    data.insert("alert_id".into(), json!(latest.alert_id));
    data.insert("customer_code".into(), json!(latest.customer_code));
    data.insert("status".into(), json!(latest.status));
    data.insert("alert_type".into(), json!(latest.alert_type));
    data.insert("triggered_by".into(), json!(latest.triggered_by));
    data.insert("template_used".into(), json!(latest.template_used));
    data.insert(
        "created_at".into(),
        json!(to_pydantic_iso(latest.created_at)),
    );
    data.insert("started_at".into(), iso(latest.started_at));
    data.insert("completed_at".into(), iso(latest.completed_at));
    data.insert("error_message".into(), json!(latest.error_message));
    data.insert("reports".into(), Value::Array(reports));
    Ok(Value::Object(data))
}

/// How many of an alert's newest jobs are looked up in Talon for a verdict.
const VERDICT_LOOKUP_JOBS: usize = 5;

/// Talon's structured verdict (`GET /investigations/{id}`) for the newest of
/// the alert's jobs that Talon knows. Jobs registered by the scheduled sweep
/// have no Talon investigation and are skipped.
pub async fn talon_verdict(
    ctx: &AppContext,
    talon: &TalonConnector,
    alert_id: i64,
) -> Result<Value, ApiError> {
    let jobs = ai_analyst::jobs_by_alert(&ctx.db, alert_id).await?;
    if jobs.is_empty() {
        return Err(ApiError::not_found(format!(
            "No job found for alert {alert_id}"
        )));
    }
    for job in jobs.iter().take(VERDICT_LOOKUP_JOBS) {
        if !is_valid_investigation_id(&job.id) {
            continue;
        }
        let Some(raw) = talon
            .get_opt(&format!("/investigations/{}", job.id))
            .await
            .map_err(server_error)?
        else {
            continue;
        };
        let inv: Investigation = serde_json::from_value(raw).map_err(|e| {
            ApiError::server_error(format!("Talon returned an invalid investigation: {e}"))
        })?;
        // Defense in depth: never hand out a verdict for another alert or
        // tenant, whatever Talon answers.
        if inv.id != job.id
            || inv.alert_id != alert_id.to_string()
            || inv.customer_code != job.customer_code
        {
            return Err(ApiError::server_error(format!(
                "Talon investigation {} does not match alert {alert_id}",
                job.id
            )));
        }
        return Ok(verdict_view(&inv));
    }
    Err(ApiError::not_found(format!(
        "No Talon verdict found for alert {alert_id}"
    )))
}

/// The fields of a Talon investigation CoPilot hands to its UI.
fn verdict_view(inv: &Investigation) -> Value {
    json!({
        "job_id": inv.id,
        "alert_id": inv.alert_id,
        "customer_code": inv.customer_code,
        "status": inv.status,
        "triggered_by": inv.triggered_by,
        "template": inv.template,
        "verdict": inv.verdict,
        "error": inv.error,
        "created_at": inv.created_at,
        "updated_at": inv.updated_at,
    })
}

#[cfg(test)]
mod verdict_tests {
    use super::*;

    #[test]
    fn verdict_view_keeps_talon_fields() {
        let inv: Investigation = serde_json::from_value(json!({
            "id": "copilot-inv-42-1", "alert_id": "42", "customer_code": "acme",
            "triggered_by": "manual", "status": "completed", "template": null,
            "created_at": "2026-10-15T07:00:00.000Z", "updated_at": "2026-10-15T07:02:00.000Z",
            "verdict": {"verdict": "true_positive", "severity": "high", "confidence": 0.9},
            "error": null
        }))
        .unwrap();
        let v = verdict_view(&inv);
        assert_eq!(v["job_id"], "copilot-inv-42-1");
        assert_eq!(v["triggered_by"], "manual");
        assert_eq!(v["verdict"]["verdict"], "true_positive");
        assert_eq!(v["verdict"]["severity"], "high");
        assert!(v["error"].is_null());
    }
}
