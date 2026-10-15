//! The dispatch loop (`dispatch_event`), the dispatch log with its
//! idempotency rule (`_record_log`), and the one-route deliveries of the test
//! button and manual send (`deliver_one`).
//!
//! **Send, then log.** A provider is called before the log is consulted; a
//! `(route, dedupe_key)` already logged as `sent` makes the *log write* a
//! no-op and the outcome `skipped`, but the message has gone out again. That
//! is the Python behaviour (CLAUDE.md, SLA notifications) and assignment
//! re-notification relies on it, so it is reproduced, not fixed.

use copilot_db::DbError;
use copilot_jinja::{Event, Input};
use serde::Serialize;

use crate::channels::send::{SKIPPED, SendResult};
use crate::channels::{self, Channel};
use crate::db::{self, NewLog, RoutePool, RouteRow};
use crate::dispatcher::Dispatcher;
use crate::event::{
    AI_SOURCED_TRIGGERS, DUAL_SCOPE_TRIGGERS, INTERNAL_TRIGGERS, SEVERITY_ORDER, entity, py_prefix,
    trigger_values,
};
use crate::services::memo::Memo;
use crate::services::render::{self, Fault, Rendered};
use copilot_web::ApiError;

/// `DispatchOutcome`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    /// Route.
    pub route_id: i64,
    /// Route label.
    pub route_name: String,
    /// Channel key.
    pub channel: String,
    /// `sent` | `failed` | `skipped`.
    pub status: String,
    /// Why not sent.
    pub error_message: Option<String>,
    /// Provider round-trip.
    pub latency_ms: Option<i64>,
    /// Vendor id of the delivery.
    pub provider_reference: Option<String>,
}

impl Outcome {
    fn new(route: &RouteRow, status: &str, error: Option<String>, latency: Option<i64>) -> Self {
        Self {
            route_id: i64::from(route.id),
            route_name: route.name.clone(),
            channel: route.channel.clone(),
            status: status.to_string(),
            error_message: error,
            latency_ms: latency,
            provider_reference: None,
        }
    }

    /// The outcome of one delivery.
    pub fn of(route: &RouteRow, r: &SendResult) -> Self {
        Self {
            provider_reference: r.provider_reference.clone(),
            ..Self::new(route, r.status, r.error_message.clone(), r.latency_ms)
        }
    }
}

/// `DispatchResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DispatchResponse {
    /// Always `true`.
    pub success: bool,
    /// `Dispatched N of M matching route(s) for customer C alert A`.
    pub message: String,
    /// Routes that matched.
    pub routes_matched: usize,
    /// Sent.
    pub dispatched: usize,
    /// Skipped.
    pub skipped: usize,
    /// Failed.
    pub failed: usize,
    /// Per route.
    pub outcomes: Vec<Outcome>,
}

impl From<Fault> for ApiError {
    fn from(f: Fault) -> Self {
        ApiError::internal(f)
    }
}

/// `_severity_meets`: inclusive; an unknown severity fails closed.
pub fn severity_meets(report: &str, route_min: &str) -> bool {
    let rank = |s: &str| SEVERITY_ORDER.iter().position(|x| *x == s);
    match (rank(report), rank(route_min)) {
        (Some(a), Some(b)) => a >= b,
        _ => {
            tracing::warn!(
                "Unknown severity in routing comparison (report={report:?}, route_min={route_min:?}); \
                 skipping route."
            );
            false
        }
    }
}

/// `_trigger_applies` (a legacy `severity_critical_or_high` route fires on
/// `investigation_complete`).
pub fn trigger_applies(event_trigger: &str, route_trigger: &str) -> bool {
    if route_trigger == "severity_critical_or_high" {
        return event_trigger == "investigation_complete";
    }
    route_trigger == event_trigger
}

/// `_self_assignment_suppressed`.
pub fn self_assignment_suppressed(route: &RouteRow, e: &Event) -> bool {
    if !INTERNAL_TRIGGERS.contains(&e.trigger.as_str()) {
        return false;
    }
    match (
        e.actor_username.as_deref().filter(|a| !a.is_empty()),
        e.assignee_username.as_deref().filter(|a| !a.is_empty()),
    ) {
        (Some(actor), Some(assignee)) if actor == assignee => !route.notify_on_self_assign,
        _ => false,
    }
}

/// `routes_for_event`: the candidate pool by scope.
pub async fn routes_for_event(d: &Dispatcher, e: &Event) -> Result<Vec<RouteRow>, DbError> {
    let code = e.customer_code.as_deref();
    let pool = if INTERNAL_TRIGGERS.contains(&e.trigger.as_str()) {
        RoutePool::Internal
    } else if DUAL_SCOPE_TRIGGERS.contains(&e.trigger.as_str()) {
        RoutePool::Both(code)
    } else {
        RoutePool::Customer(code)
    };
    db::routes_for_pool(d.db(), pool).await
}

/// `_ai_reports_permitted`.
async fn ai_reports_permitted(d: &Dispatcher, e: &Event) -> Result<bool, DbError> {
    if !AI_SOURCED_TRIGGERS.contains(&e.trigger.as_str()) {
        return Ok(true);
    }
    let Some(code) = e.customer_code.as_deref() else {
        return Ok(false);
    };
    Ok(copilot_db::customer_portal::settings(d.db(), code)
        .await?
        .is_some_and(|s| s.enabled))
}

/// One log write's outcome fields.
pub struct LogWrite<'a> {
    /// `sent` | `failed` | `skipped`.
    pub status: &'a str,
    /// Error text.
    pub error_message: Option<&'a str>,
    /// Latency.
    pub latency_ms: Option<i64>,
    /// Body preview (cut to 500 characters here).
    pub payload_preview: Option<&'a str>,
    /// Vendor id.
    pub provider_reference: Option<&'a str>,
    /// `automatic` | `manual` | `test`.
    pub trigger_source: &'a str,
}

/// `_record_log`: `false` only when the `(route, dedupe_key)` row is already
/// `sent` (or a concurrent writer won); a failed/skipped row is overwritten.
pub async fn record_log(
    d: &Dispatcher,
    e: &Event,
    route_id: i64,
    w: &LogWrite<'_>,
) -> Result<bool, DbError> {
    let preview = w
        .payload_preview
        .filter(|p| !p.is_empty())
        .map(|p| py_prefix(p, 500));
    if let Some(existing) = db::log_entry(d.db(), route_id, &e.dedupe_key).await? {
        if existing.status == "sent" {
            return Ok(false);
        }
        db::overwrite_log(
            d.db(),
            i64::from(existing.id),
            w.status,
            w.error_message,
            w.latency_ms,
            preview.as_deref(),
            w.provider_reference,
            copilot_core::time::now_utc_naive(),
        )
        .await?;
        return Ok(true);
    }
    // A NULL customer (an internal event about a case without one) violates
    // the column's NOT NULL: SQLAlchemy's IntegrityError, read as "already
    // done" exactly like a lost race.
    let Some(code) = e.customer_code.as_deref() else {
        return Ok(false);
    };
    db::insert_log(
        d.db(),
        &NewLog {
            customer_code: code,
            alert_id: (e.entity_type == entity::ALERT).then_some(e.entity_id),
            entity_type: &e.entity_type,
            entity_id: e.entity_id,
            dedupe_key: &e.dedupe_key,
            route_id,
            trigger: &e.trigger,
            dispatched_at: copilot_core::time::now_utc_naive(),
            status: w.status,
            error_message: w.error_message,
            latency_ms: w.latency_ms,
            payload_preview: preview.as_deref(),
            triggered_by: e.actor_username.as_deref(),
            trigger_source: w.trigger_source,
            provider_reference: w.provider_reference,
        },
    )
    .await
}

/// Deliver one message through a route's provider.
async fn send(
    d: &Dispatcher,
    channel: Channel,
    route: &RouteRow,
    e: &Event,
    message: &Rendered,
    memo: &mut Memo,
) -> SendResult {
    match channel {
        Channel::Webhook => channels::webhook::send(d, route, e, message, memo).await,
        Channel::Teams => channels::teams::send(d, route, e, message).await,
        Channel::Resend => channels::resend::send(d, route, e, message, memo).await,
        Channel::Shuffle => channels::shuffle::send(d, route, e, message, memo).await,
    }
}

fn merge_errors(provider: Option<&str>, template: Option<&str>) -> Option<String> {
    match (
        provider.filter(|s| !s.is_empty()),
        template.filter(|s| !s.is_empty()),
    ) {
        (Some(p), Some(t)) => Some(format!("{p}; {t}")),
        (Some(p), None) => Some(p.to_string()),
        (None, Some(t)) => Some(t.to_string()),
        (None, None) => provider.or(template).map(str::to_string),
    }
}

/// `dispatch_event`: match, gate, render, send, log every route.
pub async fn dispatch_event(d: &Dispatcher, mut e: Event) -> Result<DispatchResponse, ApiError> {
    let routes = routes_for_event(d, &e).await?;
    let matched: Vec<RouteRow> = routes
        .into_iter()
        .filter(|r| {
            r.enabled
                && trigger_applies(&e.trigger, &r.trigger)
                && severity_meets(&e.severity, &r.min_severity)
                && !self_assignment_suppressed(r, &e)
        })
        .collect();
    let mut outcomes = Vec::new();
    let (mut sent, mut failed, mut skipped) = (0usize, 0usize, 0usize);

    let gated: Vec<&RouteRow> = matched.iter().filter(|r| r.scope == "customer").collect();
    let mut gated_ids = Vec::new();
    if !gated.is_empty() && !ai_reports_permitted(d, &e).await? {
        tracing::info!(
            "AI reports are not enabled for customer {}; suppressing {} matched notification \
             route(s) for alert {}.",
            e.customer_code.as_deref().unwrap_or("None"),
            gated.len(),
            e.entity_id
        );
        let reason = "AI reports are not enabled for this customer; notification suppressed.";
        for route in &gated {
            record_log(
                d,
                &e,
                i64::from(route.id),
                &LogWrite {
                    status: SKIPPED,
                    error_message: Some(reason),
                    latency_ms: None,
                    payload_preview: None,
                    provider_reference: None,
                    trigger_source: "automatic",
                },
            )
            .await?;
            skipped += 1;
            outcomes.push(Outcome::new(route, SKIPPED, Some(reason.into()), None));
            gated_ids.push(route.id);
        }
    }

    let mut memo = Memo::default();
    for route in matched.iter().filter(|r| !gated_ids.contains(&r.id)) {
        let (message, template_error) =
            render::render_route(d.db(), route, &mut e, Some(&mut memo)).await?;
        let preview = py_prefix(&message.body, 500);
        let channel = Channel::parse(&route.channel);
        let result = match channel {
            None => SendResult {
                status: crate::channels::send::FAILED,
                error_message: Some(format!("Unsupported channel: {}", route.channel)),
                latency_ms: None,
                provider_reference: None,
                raised: false,
            },
            Some(c) => send(d, c, route, &e, &message, &mut memo).await,
        };
        let error = merge_errors(result.error_message.as_deref(), template_error.as_deref());
        let recorded = record_log(
            d,
            &e,
            i64::from(route.id),
            &LogWrite {
                status: result.status,
                error_message: error.as_deref(),
                latency_ms: result.latency_ms,
                payload_preview: Some(&preview),
                provider_reference: result.provider_reference.as_deref(),
                trigger_source: "automatic",
            },
        )
        .await?;
        if !recorded {
            skipped += 1;
            outcomes.push(Outcome::new(
                route,
                SKIPPED,
                Some("Already dispatched (idempotency)".into()),
                None,
            ));
            continue;
        }
        match result.status {
            "sent" => {
                sent += 1;
                let now = copilot_core::time::now_utc_naive();
                db::bump_dispatch_count(d.db(), i64::from(route.id), now).await?;
                if channel == Some(Channel::Shuffle) {
                    if let Some(id) = route.shuffle_integration_id {
                        db::touch_integration(d.db(), i64::from(id), now).await?;
                    }
                }
            }
            "skipped" => skipped += 1,
            _ => failed += 1,
        }
        outcomes.push(Outcome {
            error_message: error,
            ..Outcome::of(route, &result)
        });
    }
    Ok(DispatchResponse {
        success: true,
        message: format!(
            "Dispatched {sent} of {} matching route(s) for customer {} alert {}",
            matched.len(),
            e.customer_code.as_deref().unwrap_or("None"),
            e.entity_id
        ),
        routes_matched: matched.len(),
        dispatched: sent,
        skipped,
        failed,
        outcomes,
    })
}

/// `deliver_one`: one event through one route, logged; never "raises"
/// for a delivery problem.
pub async fn deliver_one(
    d: &Dispatcher,
    route: &RouteRow,
    mut e: Event,
    trigger_source: &str,
) -> Result<SendResult, ApiError> {
    let Some(channel) = Channel::parse(&route.channel) else {
        return Ok(SendResult::failed(format!(
            "Unsupported channel: {}",
            route.channel
        )));
    };
    let mut memo = Memo::default();
    let (message, template_error) =
        render::render_route(d.db(), route, &mut e, Some(&mut memo)).await?;
    let mut result = send(d, channel, route, &e, &message, &mut memo).await;
    if result.raised {
        // `SendResult.failed(f"Dispatcher exception: …")` here, latency 0.
        result.latency_ms = Some(0);
    }
    let error = merge_errors(result.error_message.as_deref(), template_error.as_deref());
    let preview = py_prefix(&message.body, 500);
    record_log(
        d,
        &e,
        i64::from(route.id),
        &LogWrite {
            status: result.status,
            error_message: error.as_deref(),
            latency_ms: result.latency_ms,
            payload_preview: Some(&preview),
            provider_reference: result.provider_reference.as_deref(),
            trigger_source,
        },
    )
    .await?;
    Ok(result)
}

/// `SLA_SAMPLE_CONTEXT[trigger]`.
pub fn sla_sample_context(trigger: &str) -> Vec<(String, Input)> {
    let s = |v: &str| Input::Str(v.into());
    let (remaining, overdue) = match trigger {
        "sla_at_risk" => (Input::Int(45), Input::None),
        "sla_breached" => (Input::None, Input::Int(20)),
        _ => return Vec::new(),
    };
    vec![
        ("clock".into(), s("resolve")),
        ("due_at".into(), s("2026-09-01 12:00")),
        ("opened_at".into(), s("2026-09-01 04:00")),
        ("remaining_minutes".into(), remaining),
        ("overdue_minutes".into(), overdue),
        ("status".into(), s("IN_PROGRESS")),
    ]
}

/// Merge `extra` into `base` like `{**base, **extra}`.
pub fn dict_merge(base: &mut Vec<(String, Input)>, extra: Vec<(String, Input)>) {
    for (k, v) in extra {
        match base.iter_mut().find(|(bk, _)| *bk == k) {
            Some((_, bv)) => *bv = v,
            None => base.push((k, v)),
        }
    }
}

/// `_sample_event_for(route)`: what the test button sends.
pub fn sample_event_for(route: &RouteRow) -> Event {
    let trigger = if trigger_values().contains(&route.trigger.as_str()) {
        route.trigger.clone()
    } else {
        "investigation_complete".into()
    };
    let is_assignment = INTERNAL_TRIGGERS.contains(&trigger.as_str());
    let entity_type = match trigger.as_str() {
        "case_assigned" => entity::CASE,
        "case_task_assigned" => entity::CASE_TASK,
        _ => entity::ALERT,
    };
    let title = "Test notification from CoPilot";
    let mut context: Vec<(String, Input)> = vec![
        ("alert_name".into(), Input::Str(title.into())),
        ("title".into(), Input::Str(title.into())),
    ];
    dict_merge(&mut context, sla_sample_context(&trigger));
    Event {
        customer_code: route.customer_code.clone(),
        trigger,
        severity: "High".into(),
        subject: title.into(),
        summary: "This is a test notification triggered from the CoPilot route form. If you are \
                  reading it, this route is configured correctly."
            .into(),
        entity_type: entity_type.into(),
        entity_id: 0,
        dedupe_key: format!("test:{}:{}", route.id, uuid::Uuid::new_v4()),
        link_url: None,
        assignee_username: if is_assignment {
            route.created_by.clone()
        } else {
            None
        },
        actor_username: route.created_by.clone(),
        context,
    }
}

/// `send_test_notification`.
pub async fn send_test(d: &Dispatcher, route: &RouteRow) -> Result<Outcome, ApiError> {
    let result = deliver_one(d, route, sample_event_for(route), "test").await?;
    Ok(Outcome::of(route, &result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_and_trigger_rules() {
        assert!(severity_meets("Critical", "High"));
        assert!(severity_meets("High", "High"));
        assert!(!severity_meets("Medium", "High"));
        assert!(!severity_meets("Bogus", "Low"));
        assert!(trigger_applies(
            "investigation_complete",
            "severity_critical_or_high"
        ));
        assert!(!trigger_applies(
            "alert_created",
            "severity_critical_or_high"
        ));
        assert!(trigger_applies("alert_created", "alert_created"));
        assert_eq!(merge_errors(Some("a"), Some("b")).as_deref(), Some("a; b"));
        assert_eq!(merge_errors(None, Some("b")).as_deref(), Some("b"));
        assert_eq!(merge_errors(Some(""), None).as_deref(), Some(""));
    }
}
