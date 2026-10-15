//! In-process emission (`services/emit.py`) — what replaced the hand-off
//! to the Python backend (`services/bridge.py`).
//!
//! Every Rust module emits through `copilot_core::notify::NotificationSink`;
//! [`DispatchingSink`] runs the dispatch on a task of its own, bounded by
//! [`EMIT_TIMEOUT`], and never reports back: the dispatch log is the
//! durable record. Events are dispatched exactly as the Python `emit` does —
//! with one exception kept from the bridge. The two AI-analyst triggers
//! ([`BRIDGED_TRIGGERS`]) used to cross an analyst-reachable endpoint, which
//! accepted them only for an existing alert of the event's customer, only
//! from a caller entitled to that customer, and re-derived the dedupe key
//! and the link. The sink keeps those safeguards for those triggers, so a
//! notification goes out exactly when the bridge would have forwarded it.

use std::time::Duration;

use copilot_auth::{AccessScope, JwtCodec};
use copilot_core::notify::{NotificationDefaults, NotificationEvent, NotificationSink};
use copilot_db::users;
use copilot_jinja::{Event, Input};

use crate::db;
use crate::dispatcher::Dispatcher;
use crate::event::{entity, from_notification, input_from_json};
use crate::schema::{DispatchRequest, EventBody};
use crate::services::dispatch::{DispatchResponse, dispatch_event};

/// `_EMIT_TIMEOUT_S`: the ceiling for one whole emission.
pub const EMIT_TIMEOUT: Duration = Duration::from_secs(60);

/// `BRIDGED_TRIGGERS`: what the former hand-off endpoint accepted.
pub const BRIDGED_TRIGGERS: &[&str] = &["investigation_complete", "ai_report_reviewed"];

/// Why a bridged event is not dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// The alert does not exist (`LookupError`, a 404 on the endpoint).
    NotFound(String),
    /// Anything else (`BridgeRejected`, a 400).
    Refused(String),
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejected::NotFound(m) | Rejected::Refused(m) => f.write_str(m),
        }
    }
}

/// `event_from_dispatch_request`: Talon's body as an event.
pub fn event_from_dispatch_request(p: &DispatchRequest) -> Event {
    let alert_name = p.alert_name.clone();
    Event {
        customer_code: Some(p.customer_code.clone()),
        trigger: p.trigger.clone(),
        severity: p.severity_assessment.clone(),
        subject: alert_name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("Alert #{}", p.alert_id)),
        summary: p.summary.clone(),
        entity_type: entity::ALERT.into(),
        entity_id: p.alert_id,
        dedupe_key: format!("{}:{}:{}", entity::ALERT, p.alert_id, p.trigger),
        link_url: p.report_url.clone(),
        assignee_username: None,
        actor_username: None,
        context: vec![(
            "alert_name".into(),
            alert_name.map_or(Input::None, Input::Str),
        )],
    }
}

/// A `NotificationEvent` request body as an event.
pub fn event_from_body(e: &EventBody) -> Event {
    Event {
        customer_code: e.customer_code.clone(),
        trigger: e.trigger.clone(),
        severity: e.severity.clone(),
        subject: e.subject.clone(),
        summary: e.summary.clone(),
        entity_type: e.entity_type.clone(),
        entity_id: e.entity_id,
        dedupe_key: e.dedupe_key.clone(),
        link_url: e.link_url.clone(),
        assignee_username: e.assignee_username.clone(),
        actor_username: e.actor_username.clone(),
        context: e
            .context
            .iter()
            .map(|(k, v)| (k.clone(), input_from_json(v)))
            .collect(),
    }
}

/// `sanitize_bridged_event`: `owner` is the stored customer of the alert
/// `event.entity_id` names (`None`: no such alert).
pub fn sanitize(
    mut event: Event,
    owner: Option<&str>,
    defaults: &NotificationDefaults,
) -> Result<Event, Rejected> {
    if !BRIDGED_TRIGGERS.contains(&event.trigger.as_str()) {
        return Err(Rejected::Refused(format!(
            "Trigger {} cannot be emitted through the bridge",
            event.trigger
        )));
    }
    if event.entity_type != entity::ALERT {
        return Err(Rejected::Refused(
            "Only alert events can be emitted through the bridge".into(),
        ));
    }
    let Some(owner) = owner else {
        return Err(Rejected::NotFound(format!(
            "Alert {} not found",
            event.entity_id
        )));
    };
    if event.customer_code.as_deref() != Some(owner) {
        return Err(Rejected::Refused(format!(
            "customer_code mismatch: alert {} belongs to {owner}, got {}",
            event.entity_id,
            event.customer_code.as_deref().unwrap_or("None")
        )));
    }
    event.dedupe_key = format!("{}:{}:{}", entity::ALERT, event.entity_id, event.trigger);
    event.link_url = defaults.link(&format!("/alerts/{}", event.entity_id));
    Ok(event)
}

/// `_run`: dispatch, log the outcome, swallow everything.
pub async fn run(d: &Dispatcher, event: Event) -> Option<DispatchResponse> {
    let label = format!(
        "Notification emit [{}] {}#{}",
        event.trigger, event.entity_type, event.entity_id
    );
    let trigger = event.trigger.clone();
    match tokio::time::timeout(EMIT_TIMEOUT, dispatch_event(d, event)).await {
        Ok(Ok(response)) => {
            if response.routes_matched > 0 {
                tracing::info!(
                    "{label}: {} sent, {} skipped, {} failed across {} route(s).",
                    response.dispatched,
                    response.skipped,
                    response.failed,
                    response.routes_matched
                );
            } else {
                tracing::info!("{label}: no route is configured for this trigger; nothing sent.");
            }
            Some(response)
        }
        Ok(Err(e)) => {
            tracing::error!("Notification emit [{trigger}] failed: {e}");
            None
        }
        Err(_) => {
            tracing::error!(
                "{label} timed out after {:.1}s; abandoning.",
                EMIT_TIMEOUT.as_secs_f64()
            );
            None
        }
    }
}

/// `emit`: schedule the dispatch and return immediately.
pub fn spawn_dispatch(d: Dispatcher, event: Event) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            "Notification emit [{}] skipped: no running event loop.",
            event.trigger
        );
        return;
    };
    handle.spawn(async move {
        run(&d, event).await;
    });
}

/// The process's notification sink: dispatches in-process.
#[derive(Clone)]
pub struct DispatchingSink {
    dispatcher: Dispatcher,
    jwt: JwtCodec,
}

impl std::fmt::Debug for DispatchingSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchingSink").finish_non_exhaustive()
    }
}

impl DispatchingSink {
    /// A sink over `dispatcher`; `jwt` checks the emitting caller of a
    /// bridged trigger.
    pub fn new(dispatcher: Dispatcher, jwt: JwtCodec) -> Self {
        Self { dispatcher, jwt }
    }

    /// The bridge's caller check: the token's user holds `admin` or
    /// `analyst` and may see `customer_code`.
    async fn caller_may_emit(&self, bearer: &str, customer_code: &str) -> Result<(), String> {
        let claims = self
            .jwt
            .decode_session(bearer)
            .map_err(|e| format!("401: {e}"))?;
        let user = users::find_by_username(self.dispatcher.db(), &claims.subject)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "401: User not found".to_string())?;
        if !claims.scopes.iter().any(|s| s == "admin" || s == "analyst") {
            return Err("403: Insufficient permissions. Required one of: admin, analyst".into());
        }
        let assigned = match user.role_id {
            Some(1) | None => Vec::new(),
            Some(_) => users::assigned_customer_codes(self.dispatcher.db(), user.id)
                .await
                .map_err(|e| e.to_string())?,
        };
        AccessScope::for_user(user.role_id, assigned)
            .enforce_customer(customer_code)
            .map_err(|e| format!("403: {e}"))
    }

    /// Dispatch one event now and return the outcome (`None`: refused,
    /// failed or timed out — all logged). `emit` runs this on a task.
    pub async fn deliver(
        &self,
        event: &NotificationEvent,
        bearer: Option<&str>,
    ) -> Option<DispatchResponse> {
        let event = from_notification(event);
        if !BRIDGED_TRIGGERS.contains(&event.trigger.as_str()) {
            return run(&self.dispatcher, event).await;
        }
        let owner = match db::alert(self.dispatcher.db(), event.entity_id).await {
            Ok(row) => row.map(|a| a.customer_code),
            Err(e) => {
                tracing::error!("Notification emit [{}] failed: {e}", event.trigger);
                return None;
            }
        };
        // A token-less emitter is CoPilot itself acting on its own
        // authority (no request behind it); a request's emit carries the
        // caller's token and is held to what the bridge required of it.
        if let Some(token) = bearer.filter(|t| !t.is_empty()) {
            let code = owner
                .clone()
                .or_else(|| event.customer_code.clone())
                .unwrap_or_default();
            if let Err(e) = self.caller_may_emit(token, &code).await {
                tracing::warn!(dedupe = %event.dedupe_key, err = %e, "notification emit refused");
                return None;
            }
        }
        match sanitize(event, owner.as_deref(), self.dispatcher.defaults()) {
            Ok(event) => run(&self.dispatcher, event).await,
            Err(e) => {
                tracing::warn!(err = %e, "notification emit refused");
                None
            }
        }
    }
}

impl NotificationSink for DispatchingSink {
    fn emit(&self, event: NotificationEvent, bearer: Option<String>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                "Notification emit [{}] skipped: no running event loop.",
                event.trigger.as_str()
            );
            return;
        };
        let sink = self.clone();
        handle.spawn(async move {
            sink.deliver(&event, bearer.as_deref()).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> NotificationDefaults {
        NotificationDefaults {
            copilot_url: Some("https://copilot.example.com/".into()),
            default_severity: copilot_core::notify::NotificationSeverity::High,
        }
    }

    fn event(trigger: &str, code: Option<&str>) -> Event {
        Event {
            customer_code: code.map(str::to_string),
            trigger: trigger.into(),
            severity: "High".into(),
            subject: "s".into(),
            summary: "x".into(),
            entity_type: "alert".into(),
            entity_id: 9,
            dedupe_key: "forged".into(),
            link_url: Some("https://evil.example".into()),
            assignee_username: None,
            actor_username: None,
            context: Vec::new(),
        }
    }

    #[test]
    fn sanitize_rederives_and_refuses_like_the_bridge() {
        let ok = sanitize(
            event("investigation_complete", Some("acme")),
            Some("acme"),
            &defaults(),
        )
        .unwrap();
        assert_eq!(ok.dedupe_key, "alert:9:investigation_complete");
        assert_eq!(
            ok.link_url.as_deref(),
            Some("https://copilot.example.com/alerts/9")
        );
        assert_eq!(
            sanitize(
                event("alert_created", Some("acme")),
                Some("acme"),
                &defaults()
            ),
            Err(Rejected::Refused(
                "Trigger alert_created cannot be emitted through the bridge".into()
            ))
        );
        assert_eq!(
            sanitize(event("ai_report_reviewed", Some("acme")), None, &defaults()),
            Err(Rejected::NotFound("Alert 9 not found".into()))
        );
        assert_eq!(
            sanitize(event("ai_report_reviewed", None), Some("acme"), &defaults()),
            Err(Rejected::Refused(
                "customer_code mismatch: alert 9 belongs to acme, got None".into()
            ))
        );
        let mut case = event("ai_report_reviewed", Some("acme"));
        case.entity_type = "case".into();
        assert_eq!(
            sanitize(case, Some("acme"), &defaults()),
            Err(Rejected::Refused(
                "Only alert events can be emitted through the bridge".into()
            ))
        );
    }
}
