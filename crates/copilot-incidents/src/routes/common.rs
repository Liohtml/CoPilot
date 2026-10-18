//! Helpers shared by the write routes.

use axum::response::Response;
use serde_json::Value;

use copilot_core::notify::NotificationSeverity;
use copilot_sla::{Actor, SlaRecorder};
use copilot_web::validate::{IntRules, Validator, loc};
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::access;
use crate::views::LoadedAlert;

pub use super::reads::json;

/// `default_severity()`: the deployment's `DEFAULT_ALERT_SEVERITY`.
pub fn default_severity(ctx: &AppContext) -> &'static str {
    match ctx.notification_defaults.default_severity {
        NotificationSeverity::Critical => "Critical",
        NotificationSeverity::High => "High",
        NotificationSeverity::Medium => "Medium",
        NotificationSeverity::Low => "Low",
        NotificationSeverity::Informational => "Informational",
    }
}

/// `severity_of(alert)`: the stored severity, else the deployment default.
pub fn severity_of(ctx: &AppContext, stored: Option<&str>) -> &'static str {
    copilot_sla::severity::severity_of(stored, default_severity(ctx))
}

/// The SLA recorder over the request's database, with the deployment's
/// `DEFAULT_ALERT_SEVERITY`.
pub fn sla(ctx: &AppContext) -> SlaRecorder {
    SlaRecorder::new(ctx.db.clone(), default_severity(ctx))
}

/// `Actor.from_user(current_user)`.
pub fn actor(user: &CurrentUser) -> Actor {
    Actor::from_user(&user.username, user.role_id.unwrap_or_default())
}

/// `RoleEnum.customer_user`.
pub const CUSTOMER_USER: i32 = 4;

/// The caller is a portal user.
pub fn is_customer_user(user: &CurrentUser) -> bool {
    user.role_id == Some(CUSTOMER_USER)
}

/// `customer_reply.CUSTOMER_CANNOT_WAIT`.
pub const CUSTOMER_CANNOT_WAIT: &str = "Only the SOC can set an item to Waiting on customer; reply with a comment to hand it back to the SOC";

/// `ensure_customer_may_set_status`: a portal user cannot put an item on
/// hold for themselves.
pub fn ensure_customer_may_set_status(user: &CurrentUser, status: &str) -> Result<(), ApiError> {
    if status == "PENDING_CUSTOMER" && is_customer_user(user) {
        return Err(ApiError::forbidden(CUSTOMER_CANNOT_WAIT));
    }
    Ok(())
}

/// `_ensure_can_modify_comment`: portal users change only their own.
pub fn ensure_can_modify_comment(user: &CurrentUser, author: &str) -> Result<(), ApiError> {
    if is_customer_user(user) && author != user.username {
        return Err(ApiError::forbidden("You can only modify your own comments"));
    }
    Ok(())
}

/// `_ensure_alert_access` for a loop that skips what an `HTTPException`
/// refuses: `Ok(Err(_))` is a skip (missing alert, tags or customer not the
/// caller's), `Err(_)` fails the request (building the response model
/// raised, or the database did).
pub async fn ensure_alert_soft(
    ctx: &AppContext,
    user: &CurrentUser,
    alert_id: i64,
) -> Result<Result<LoadedAlert, ApiError>, ApiError> {
    let alert = match access::alert_for(ctx, user, alert_id).await {
        Ok(a) => a,
        Err(e @ ApiError::Http { .. }) => return Ok(Err(e)),
        Err(e) => return Err(e),
    };
    alert.build()?;
    if !access::can_access(ctx, user, Some(&alert.row.customer_code)).await? {
        return Ok(Err(ApiError::forbidden(format!(
            "Access denied to alert {alert_id} - insufficient customer permissions"
        ))));
    }
    Ok(Ok(alert))
}

/// An `int` path parameter, validated (`int_parsing`).
pub fn path_int(name: &str, raw: &str) -> Result<i64, ApiError> {
    let mut v = Validator::new();
    let n = v
        .check_int(
            &loc("path", name),
            &Value::String(raw.into()),
            IntRules::default(),
        )
        .unwrap_or_default();
    v.finish()?;
    Ok(n)
}

/// `{"message": m, "success": true}` (key order of the dict literals).
pub fn message_success(message: impl Into<String>) -> Response {
    json(serde_json::json!({"message": message.into(), "success": true}))
}

/// The usernames `select_all_users()` returns, for `assigned_to not in`.
pub async fn user_exists(ctx: &AppContext, username: &str) -> Result<bool, ApiError> {
    let users = copilot_db::users::list_users(&ctx.db, None, None).await?;
    Ok(users.iter().any(|u| u.username == username))
}
