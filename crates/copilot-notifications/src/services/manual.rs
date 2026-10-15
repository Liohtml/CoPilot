//! Sending a chosen alert or case to a configured route
//! (`services/manual_send.py`): a data egress control point, so every check
//! runs before anything is rendered or sent — who may send where, the route
//! against the item's tenant, the caller's view of the item, the AI opt-out.

use copilot_core::Role;
use copilot_jinja::{Event, Input};
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::db::{self, RouteRow};
use crate::dispatcher::Dispatcher;
use crate::event::{ctx_set, entity};
use crate::services::ai_report;
use crate::services::dispatch::{self, Outcome};
use crate::services::render::{self, Rendered};

/// The item being sent.
pub enum Item {
    /// An alert.
    Alert(db::AlertRow),
    /// A case.
    Case(db::CaseRow),
}

impl Item {
    fn customer_code(&self) -> Option<&str> {
        match self {
            Item::Alert(a) => Some(a.customer_code.as_str()),
            Item::Case(c) => c.customer_code.as_deref(),
        }
    }
}

/// `severity_of(alert)`: the stored value if it names a level
/// (case-insensitively), else the deployment default.
pub fn severity_of(stored: Option<&str>, default: &str) -> String {
    const LEVELS: [&str; 5] = ["Informational", "Low", "Medium", "High", "Critical"];
    stored
        .filter(|s| !s.is_empty())
        .and_then(|s| {
            let s = crate::event::py_strip(s).to_lowercase();
            LEVELS.iter().find(|l| l.to_lowercase() == s)
        })
        .map_or_else(|| default.to_string(), |l| (*l).to_string())
}

async fn load_entity(d: &Dispatcher, entity_type: &str, id: i64) -> Result<Option<Item>, ApiError> {
    match entity_type {
        "alert" => Ok(db::alert(d.db(), id).await?.map(Item::Alert)),
        "case" => Ok(db::case(d.db(), id).await?.map(Item::Case)),
        other => Err(ApiError::bad_request(format!(
            "Cannot send a {}; expected one of ('alert', 'case').",
            copilot_auth::pyvalue::str_repr(other)
        ))),
    }
}

/// `_require_send_permission`.
fn require_send_permission(user: &CurrentUser, route: &RouteRow) -> Result<(), ApiError> {
    let role = user.role_id.and_then(Role::from_id);
    if role == Some(Role::CustomerUser) {
        return Err(ApiError::forbidden(
            "Portal users cannot send notifications.",
        ));
    }
    if !matches!(role, Some(Role::Admin | Role::Analyst | Role::Responder)) {
        return Err(ApiError::forbidden(
            "You do not have permission to send notifications.",
        ));
    }
    if route.scope == "customer" && role != Some(Role::Admin) {
        return Err(ApiError::forbidden(
            "Sending to a customer-facing route requires admin. An internal route is available \
             for sharing within the SOC.",
        ));
    }
    Ok(())
}

fn py_opt_repr(s: Option<&str>) -> String {
    s.map_or_else(|| "None".to_string(), copilot_auth::pyvalue::str_repr)
}

/// `_require_route_matches_entity`.
fn require_route_matches(route: &RouteRow, item: &Item) -> Result<(), ApiError> {
    if route.scope == "internal" {
        return Ok(());
    }
    if route.customer_code.as_deref() != item.customer_code() {
        return Err(ApiError::bad_request(format!(
            "That route belongs to customer {}, but this item belongs to {}. A customer-facing \
             route can only receive its own customer's data.",
            py_opt_repr(route.customer_code.as_deref()),
            py_opt_repr(item.customer_code())
        )));
    }
    Ok(())
}

/// `_require_object_access`.
async fn require_object_access(
    ctx: &AppContext,
    item: &Item,
    user: &CurrentUser,
) -> Result<(), ApiError> {
    if let Some(code) = item.customer_code().filter(|c| !c.is_empty()) {
        if !user.access(ctx).await?.can_access(code) {
            return Err(ApiError::forbidden(
                "Access denied — insufficient customer permissions for this item.",
            ));
        }
    }
    if let Item::Alert(a) = item {
        if !copilot_db::visibility::can_user_access_alert(
            &ctx.db,
            user.id,
            user.role_id,
            i64::from(a.id),
        )
        .await?
        {
            return Err(ApiError::forbidden(
                "Access denied — this alert is outside your tag access.",
            ));
        }
    }
    Ok(())
}

/// `_require_ai_report_permitted`.
async fn require_ai_report_permitted(
    d: &Dispatcher,
    route: &RouteRow,
    item: &Item,
    include: bool,
) -> Result<(), ApiError> {
    if !include || route.scope != "customer" {
        return Ok(());
    }
    let enabled = match item.customer_code() {
        Some(code) => copilot_db::customer_portal::settings(d.db(), code)
            .await?
            .is_some_and(|s| s.enabled),
        None => false,
    };
    if !enabled {
        return Err(ApiError::bad_request(
            "AI reports are not enabled for this customer, so the AI report cannot be included. \
             Send without it, or enable AI reports for the customer first.",
        ));
    }
    Ok(())
}

/// `build_manual_event`.
fn manual_event(
    d: &Dispatcher,
    entity_type: &str,
    id: i64,
    item: &Item,
    user: &CurrentUser,
) -> Event {
    let (title, severity, trigger) = match item {
        Item::Alert(a) => (
            Some(a.alert_name.clone()).filter(|t| !t.is_empty()),
            severity_of(
                a.severity.as_deref(),
                crate::event::severity_str(d.defaults().default_severity),
            ),
            "alert_created",
        ),
        Item::Case(c) => (
            Some(c.case_name.clone()).filter(|t| !t.is_empty()),
            "Informational".to_string(),
            "case_assigned",
        ),
    };
    let label = title
        .clone()
        .unwrap_or_else(|| format!("{entity_type} #{id}"));
    let raw_title = match item {
        Item::Alert(a) => Input::Str(a.alert_name.clone()),
        Item::Case(c) => Input::Str(c.case_name.clone()),
    };
    Event {
        customer_code: item.customer_code().map(str::to_string),
        trigger: trigger.into(),
        severity,
        subject: label.clone(),
        summary: format!("{label} was sent to this channel by {}.", user.username),
        entity_type: entity_type.into(),
        entity_id: id,
        dedupe_key: format!("{entity_type}:{id}:manual:{}", uuid::Uuid::new_v4()),
        link_url: None,
        assignee_username: None,
        actor_username: Some(user.username.clone()),
        context: vec![
            ("alert_name".into(), raw_title.clone()),
            ("title".into(), raw_title),
            ("manual".into(), Input::Bool(true)),
        ],
    }
}

/// `_attach_ai_report`: only after every check; refused when the alert has
/// no report to attach.
async fn attach_ai_report(
    d: &Dispatcher,
    e: &mut Event,
    entity_type: &str,
    include: bool,
) -> Result<(), ApiError> {
    if !include {
        return Ok(());
    }
    if entity_type != entity::ALERT {
        return Err(ApiError::bad_request(format!(
            "Only an alert can carry an AI investigation report; this is a {entity_type}."
        )));
    }
    let report = ai_report::safe_load(d.db(), e.entity_id).await;
    if report == Input::None {
        return Err(ApiError::bad_request(format!(
            "Alert {} has no AI investigation report to include. Send without it, or run an \
             investigation for this alert first.",
            e.entity_id
        )));
    }
    ctx_set(e, "ai_report", report);
    Ok(())
}

/// The checks shared by send and preview; returns the route and the event.
async fn prepare(
    ctx: &AppContext,
    d: &Dispatcher,
    user: &CurrentUser,
    entity_type: &str,
    entity_id: i64,
    route_id: i64,
    include_ai_report: bool,
) -> Result<(RouteRow, Event), ApiError> {
    let item = load_entity(d, entity_type, entity_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("{entity_type} {entity_id} not found")))?;
    let route = db::route(d.db(), route_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Route {route_id} not found")))?;
    require_send_permission(user, &route)?;
    require_route_matches(&route, &item)?;
    require_object_access(ctx, &item, user).await?;
    require_ai_report_permitted(d, &route, &item, include_ai_report).await?;
    let mut event = manual_event(d, entity_type, entity_id, &item, user);
    attach_ai_report(d, &mut event, entity_type, include_ai_report).await?;
    Ok((route, event))
}

/// `send_manual`.
pub async fn send(
    ctx: &AppContext,
    d: &Dispatcher,
    user: &CurrentUser,
    entity_type: &str,
    entity_id: i64,
    route_id: i64,
    include_ai_report: bool,
) -> Result<Outcome, ApiError> {
    let (route, event) = prepare(
        ctx,
        d,
        user,
        entity_type,
        entity_id,
        route_id,
        include_ai_report,
    )
    .await?;
    tracing::info!(
        "Manual send: {entity_type}#{entity_id} -> route {} ({}, {}) by {}",
        route.id,
        route.channel,
        route.scope,
        user.username
    );
    let result = dispatch::deliver_one(d, &route, event, "manual").await?;
    Ok(Outcome::of(&route, &result))
}

/// `preview_manual`: the message a send would deliver.
pub async fn preview(
    ctx: &AppContext,
    d: &Dispatcher,
    user: &CurrentUser,
    entity_type: &str,
    entity_id: i64,
    route_id: i64,
    include_ai_report: bool,
) -> Result<Rendered, ApiError> {
    let (route, mut event) = prepare(
        ctx,
        d,
        user,
        entity_type,
        entity_id,
        route_id,
        include_ai_report,
    )
    .await?;
    let (message, _error) = render::render_route(d.db(), &route, &mut event, None).await?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_falls_back_to_the_default() {
        assert_eq!(severity_of(Some(" critical "), "High"), "Critical");
        assert_eq!(severity_of(Some("bogus"), "High"), "High");
        assert_eq!(severity_of(None, "Medium"), "Medium");
    }
}
