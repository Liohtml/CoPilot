//! Notification events — port of `app/notifications/schema/events.py`
//! (`NotificationEvent`) and the AI-analyst builders in
//! `app/notifications/services/event_builders.py`.
//!
//! The notification module itself (routes, channel providers, the dispatch
//! log) is still served by the Python backend. Rust code emits through a
//! [`NotificationSink`]; during the migration the sink forwards the *exact*
//! envelope to the legacy service (`copilot-gateway`), so rendered messages,
//! dedupe keys and webhook payloads stay byte-for-byte what they were.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// `NotificationTrigger` values the Rust services emit today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationTrigger {
    /// An AI investigation finished and its report was written back.
    InvestigationComplete,
    /// An analyst signed off on an AI report.
    AiReportReviewed,
}

impl NotificationTrigger {
    /// Wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            NotificationTrigger::InvestigationComplete => "investigation_complete",
            NotificationTrigger::AiReportReviewed => "ai_report_reviewed",
        }
    }
}

/// `NotificationSeverity` (ordered, capitalised like `severity_assessment`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationSeverity {
    /// Critical.
    Critical,
    /// High.
    High,
    /// Medium.
    Medium,
    /// Low.
    Low,
    /// Informational.
    Informational,
}

impl NotificationSeverity {
    /// Parse the stored/wire spelling (exact, like the Python enum).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "Critical" => Some(Self::Critical),
            "High" => Some(Self::High),
            "Medium" => Some(Self::Medium),
            "Low" => Some(Self::Low),
            "Informational" => Some(Self::Informational),
            _ => None,
        }
    }

    /// `_coerce_severity`: the value if it names a tier, else the deployment
    /// default (`DEFAULT_ALERT_SEVERITY`, itself falling back to `High`).
    pub fn coerce(value: Option<&str>, default: NotificationSeverity) -> Self {
        value
            .filter(|v| !v.is_empty())
            .and_then(Self::parse)
            .unwrap_or(default)
    }
}

/// The trigger-agnostic envelope every dispatch flows through.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationEvent {
    /// Tenant; `None` for internal-scope routes.
    pub customer_code: Option<String>,
    /// Event kind.
    pub trigger: NotificationTrigger,
    /// Severity used for `min_severity` filtering.
    pub severity: NotificationSeverity,
    /// One-line title.
    pub subject: String,
    /// Human-readable body.
    pub summary: String,
    /// `alert` for every AI trigger.
    pub entity_type: String,
    /// The alert id for AI triggers.
    pub entity_id: i64,
    /// Idempotency key (`alert:<id>:<trigger>`).
    pub dedupe_key: String,
    /// Deep link back into CoPilot.
    pub link_url: Option<String>,
    /// Assigned user, for assignment triggers.
    pub assignee_username: Option<String>,
    /// Who caused the event.
    pub actor_username: Option<String>,
    /// Trigger-specific extras read by templates and webhook payloads.
    pub context: serde_json::Map<String, serde_json::Value>,
}

/// Deployment settings the builders need.
#[derive(Debug, Clone)]
pub struct NotificationDefaults {
    /// `COPILOT_URL` (public base URL), if configured.
    pub copilot_url: Option<String>,
    /// `DEFAULT_ALERT_SEVERITY`.
    pub default_severity: NotificationSeverity,
}

impl NotificationDefaults {
    /// `_copilot_link(path)`: `None` when `COPILOT_URL` is unset.
    pub fn link(&self, path: &str) -> Option<String> {
        self.copilot_url
            .as_deref()
            .map(str::trim)
            .filter(|base| !base.is_empty())
            .map(|base| format!("{}{}", base.trim_end_matches('/'), path))
    }
}

fn dedupe_key(alert_id: i64, trigger: NotificationTrigger) -> String {
    format!("alert:{alert_id}:{}", trigger.as_str())
}

fn opt(value: Option<&str>) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, |v| {
        serde_json::Value::String(v.into())
    })
}

/// Inputs shared by both AI-analyst builders.
#[derive(Debug, Clone, Default)]
pub struct AlertEventInput<'a> {
    /// Alert id.
    pub alert_id: i64,
    /// Alert's tenant.
    pub customer_code: Option<&'a str>,
    /// Report's `severity_assessment`.
    pub severity: Option<&'a str>,
    /// Message body.
    pub summary: &'a str,
    /// The alert's name, when known.
    pub alert_name: Option<&'a str>,
    /// The alert's first asset name, when known.
    pub asset_name: Option<&'a str>,
}

/// `investigation_complete_event`.
pub fn investigation_complete_event(
    d: &NotificationDefaults,
    input: &AlertEventInput<'_>,
) -> NotificationEvent {
    let trigger = NotificationTrigger::InvestigationComplete;
    let mut context = serde_json::Map::new();
    context.insert("alert_name".into(), opt(input.alert_name));
    context.insert("asset_name".into(), opt(input.asset_name));
    NotificationEvent {
        customer_code: input.customer_code.map(str::to_string),
        trigger,
        severity: NotificationSeverity::coerce(input.severity, d.default_severity),
        subject: input
            .alert_name
            .filter(|n| !n.is_empty())
            .map_or_else(|| format!("Alert #{}", input.alert_id), str::to_string),
        summary: input.summary.to_string(),
        entity_type: "alert".into(),
        entity_id: input.alert_id,
        dedupe_key: dedupe_key(input.alert_id, trigger),
        link_url: d.link(&format!("/alerts/{}", input.alert_id)),
        assignee_username: None,
        actor_username: None,
        context,
    }
}

/// `ai_report_reviewed_event`.
pub fn ai_report_reviewed_event(
    d: &NotificationDefaults,
    input: &AlertEventInput<'_>,
    report_id: i64,
    reviewer: Option<&str>,
    verdict: Option<&str>,
) -> NotificationEvent {
    let trigger = NotificationTrigger::AiReportReviewed;
    let mut context = serde_json::Map::new();
    context.insert("report_id".into(), serde_json::Value::from(report_id));
    context.insert("reviewer".into(), opt(reviewer));
    context.insert("verdict".into(), opt(verdict));
    context.insert("alert_name".into(), opt(input.alert_name));
    context.insert("asset_name".into(), opt(input.asset_name));
    NotificationEvent {
        customer_code: input.customer_code.map(str::to_string),
        trigger,
        severity: NotificationSeverity::coerce(input.severity, d.default_severity),
        subject: match input.alert_name.filter(|n| !n.is_empty()) {
            Some(name) => format!("Reviewed: {name}"),
            None => format!("Reviewed: alert #{}", input.alert_id),
        },
        summary: input.summary.to_string(),
        entity_type: "alert".into(),
        entity_id: input.alert_id,
        dedupe_key: dedupe_key(input.alert_id, trigger),
        link_url: d.link(&format!("/alerts/{}", input.alert_id)),
        assignee_username: None,
        actor_username: reviewer.map(str::to_string),
        context,
    }
}

/// Where notification events go. `emit` must return immediately: a failure
/// to notify never fails the operation that triggered it (`emit.py`).
pub trait NotificationSink: Send + Sync {
    /// Schedule `event` for dispatch. `bearer` is the caller's token, used by
    /// the legacy bridge to authenticate the hand-off.
    fn emit(&self, event: NotificationEvent, bearer: Option<String>);
}

/// Shared handle type.
pub type SharedNotificationSink = Arc<dyn NotificationSink>;

/// Drops every event (notifications disabled / no legacy backend).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopNotificationSink;

impl NotificationSink for NoopNotificationSink {
    fn emit(&self, event: NotificationEvent, _bearer: Option<String>) {
        tracing::debug!(trigger = event.trigger.as_str(), dedupe = %event.dedupe_key,
            "notification emit skipped: no notification backend configured");
    }
}

/// Collects events in memory (tests).
#[derive(Debug, Default, Clone)]
pub struct MemoryNotificationSink {
    /// Everything emitted so far.
    pub events: Arc<Mutex<Vec<NotificationEvent>>>,
}

impl MemoryNotificationSink {
    /// Copy of the emitted events.
    pub fn snapshot(&self) -> Vec<NotificationEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl NotificationSink for MemoryNotificationSink {
    fn emit(&self, event: NotificationEvent, _bearer: Option<String>) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> NotificationDefaults {
        NotificationDefaults {
            copilot_url: Some("https://copilot.example.com/".into()),
            default_severity: NotificationSeverity::High,
        }
    }

    #[test]
    fn investigation_complete_matches_python_builder() {
        let e = investigation_complete_event(
            &defaults(),
            &AlertEventInput {
                alert_id: 14,
                customer_code: Some("acme"),
                severity: Some("Medium"),
                summary: "done",
                alert_name: None,
                asset_name: Some("dc01"),
            },
        );
        assert_eq!(e.subject, "Alert #14");
        assert_eq!(e.dedupe_key, "alert:14:investigation_complete");
        assert_eq!(
            e.link_url.as_deref(),
            Some("https://copilot.example.com/alerts/14")
        );
        assert_eq!(e.severity, NotificationSeverity::Medium);
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["trigger"], "investigation_complete");
        assert_eq!(json["severity"], "Medium");
        assert_eq!(json["context"]["asset_name"], "dc01");
        assert!(json["context"]["alert_name"].is_null());
    }

    #[test]
    fn reviewed_event_and_severity_fallback() {
        let d = NotificationDefaults {
            copilot_url: None,
            default_severity: NotificationSeverity::Low,
        };
        let e = ai_report_reviewed_event(
            &d,
            &AlertEventInput {
                alert_id: 7,
                customer_code: Some("acme"),
                severity: Some("bogus"),
                summary: "s",
                alert_name: Some("Mimikatz"),
                asset_name: None,
            },
            3,
            Some("alice"),
            Some("up"),
        );
        assert_eq!(e.subject, "Reviewed: Mimikatz");
        assert_eq!(e.severity, NotificationSeverity::Low);
        assert_eq!(e.link_url, None);
        assert_eq!(e.actor_username.as_deref(), Some("alice"));
        assert_eq!(e.context["report_id"], 3);
    }
}
