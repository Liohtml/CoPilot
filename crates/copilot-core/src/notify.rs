//! Notification events — port of `app/notifications/schema/events.py`
//! (`NotificationEvent`) and the AI-analyst builders in
//! `app/notifications/services/event_builders.py`.
//!
//! Rust code emits through a [`NotificationSink`]. The binary's sink is
//! `copilot_notifications::DispatchingSink`, which dispatches in-process
//! exactly as `app/notifications/services/emit.py` does (and keeps the
//! former bridge's checks for the two AI-analyst triggers), so rendered
//! messages, dedupe keys and webhook payloads are what the Python pipeline
//! produced. A ported module builds the same envelope its Python builder
//! built; this crate holds the shared shape, `copilot-notifications` the
//! pipeline.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// `NotificationTrigger` (`app/notifications/schema/notifications.py`), every
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationTrigger {
    /// An AI investigation finished and its report was written back.
    InvestigationComplete,
    /// An analyst signed off on an AI report.
    AiReportReviewed,
    /// CoPilot created an alert.
    AlertCreated,
    /// An alert was assigned to someone.
    AlertAssigned,
    /// A case was assigned to someone.
    CaseAssigned,
    /// A case task was assigned to someone.
    CaseTaskAssigned,
    /// An SLA clock entered its last quarter (`notify_sla_transitions`).
    SlaAtRisk,
    /// An SLA clock ran out (`notify_sla_transitions`).
    SlaBreached,
    /// Not a dispatch trigger: the scope of the temporary-password email's
    /// templates (#999). Routes must not accept it ([`Self::DISPATCH`]).
    TempPasswordIssued,
}

impl NotificationTrigger {
    /// Every value, in the Python enum's order.
    pub const ALL: [Self; 9] = [
        Self::InvestigationComplete,
        Self::AiReportReviewed,
        Self::AlertCreated,
        Self::AlertAssigned,
        Self::CaseAssigned,
        Self::CaseTaskAssigned,
        Self::SlaAtRisk,
        Self::SlaBreached,
        Self::TempPasswordIssued,
    ];

    /// `DISPATCH_TRIGGERS`: what a notification route may fire on.
    pub const DISPATCH: [Self; 8] = [
        Self::InvestigationComplete,
        Self::AiReportReviewed,
        Self::AlertCreated,
        Self::AlertAssigned,
        Self::CaseAssigned,
        Self::CaseTaskAssigned,
        Self::SlaAtRisk,
        Self::SlaBreached,
    ];

    /// Wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvestigationComplete => "investigation_complete",
            Self::AiReportReviewed => "ai_report_reviewed",
            Self::AlertCreated => "alert_created",
            Self::AlertAssigned => "alert_assigned",
            Self::CaseAssigned => "case_assigned",
            Self::CaseTaskAssigned => "case_task_assigned",
            Self::SlaAtRisk => "sla_at_risk",
            Self::SlaBreached => "sla_breached",
            Self::TempPasswordIssued => "temp_password_issued",
        }
    }

    /// The value for a wire string (exact, like the Python enum).
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == value)
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

/// Inputs of [`alert_created_event`].
#[derive(Debug, Clone, Default)]
pub struct AlertCreatedInput<'a> {
    /// Alert id.
    pub alert_id: i64,
    /// Alert's tenant.
    pub customer_code: &'a str,
    /// The alert's title, when known.
    pub alert_title: Option<&'a str>,
    /// The alert's stored severity.
    pub severity: Option<&'a str>,
    /// The source rule's level (Wazuh).
    pub rule_level: Option<i64>,
    /// The alert's asset, when known.
    pub asset_name: Option<&'a str>,
    /// A link the caller already has (else the CoPilot alert page).
    pub link_url: Option<&'a str>,
}

/// `alert_created_event`: a genuinely new alert landed (a recurrence never
/// reaches the emit point).
pub fn alert_created_event(
    d: &NotificationDefaults,
    input: &AlertCreatedInput<'_>,
) -> NotificationEvent {
    let trigger = NotificationTrigger::AlertCreated;
    let title = input
        .alert_title
        .filter(|t| !t.is_empty())
        .map_or_else(|| format!("Alert #{}", input.alert_id), str::to_string);
    let mut context = serde_json::Map::new();
    context.insert(
        "alert_name".into(),
        serde_json::Value::String(title.clone()),
    );
    context.insert(
        "rule_level".into(),
        input
            .rule_level
            .map_or(serde_json::Value::Null, serde_json::Value::from),
    );
    context.insert("asset_name".into(), opt(input.asset_name));
    NotificationEvent {
        customer_code: Some(input.customer_code.to_string()),
        trigger,
        severity: NotificationSeverity::coerce(input.severity, d.default_severity),
        subject: title,
        summary: format!("A new alert was created for {}.", input.customer_code),
        entity_type: "alert".into(),
        entity_id: input.alert_id,
        dedupe_key: dedupe_key(input.alert_id, trigger),
        link_url: input
            .link_url
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .or_else(|| d.link(&format!("/alerts/{}", input.alert_id))),
        assignee_username: None,
        actor_username: None,
        context,
    }
}

/// Who an assignment concerns (the three assignment builders).
#[derive(Debug, Clone, Copy, Default)]
pub struct Assignment<'a> {
    /// The item's title.
    pub title: Option<&'a str>,
    /// The new assignee (`None`: unassigned).
    pub assignee: Option<&'a str>,
    /// Who made the change.
    pub actor: Option<&'a str>,
    /// The item's tenant.
    pub customer_code: Option<&'a str>,
}

/// `_assignment_event`: the dedupe key carries the assignee, so A → B → A
/// notifies A again while a no-op write does not; no link.
fn assignment_event(
    trigger: NotificationTrigger,
    severity: NotificationSeverity,
    entity_type: &str,
    entity_id: i64,
    a: &Assignment<'_>,
    summary: String,
    extra: Option<(&str, serde_json::Value)>,
) -> NotificationEvent {
    let mut context = serde_json::Map::new();
    context.insert("title".into(), opt(a.title));
    if let Some((k, v)) = extra {
        context.insert(k.into(), v);
    }
    NotificationEvent {
        customer_code: a.customer_code.map(str::to_string),
        trigger,
        severity,
        subject: a
            .title
            .filter(|t| !t.is_empty())
            .map_or_else(|| format!("{entity_type} #{entity_id}"), str::to_string),
        summary,
        entity_type: entity_type.into(),
        entity_id,
        dedupe_key: format!(
            "{entity_type}:{entity_id}:{}:{}",
            trigger.as_str(),
            a.assignee.filter(|x| !x.is_empty()).unwrap_or("unassigned")
        ),
        link_url: None,
        assignee_username: a.assignee.map(str::to_string),
        actor_username: a.actor.map(str::to_string),
        context,
    }
}

fn assigned_to(what: &str, id: i64, assignee: Option<&str>) -> String {
    match assignee.filter(|x| !x.is_empty()) {
        Some(who) => format!("{what} #{id} was assigned to {who}."),
        None => format!("{what} #{id} was unassigned."),
    }
}

/// `alert_assigned_event`: the alert's own severity when given (an empty one
/// is the assignment default, Informational; an unknown one the deployment
/// default).
pub fn alert_assigned_event(
    d: &NotificationDefaults,
    alert_id: i64,
    a: &Assignment<'_>,
    severity: Option<&str>,
) -> NotificationEvent {
    let severity = match severity.filter(|s| !s.is_empty()) {
        Some(s) => NotificationSeverity::coerce(Some(s), d.default_severity),
        None => NotificationSeverity::Informational,
    };
    assignment_event(
        NotificationTrigger::AlertAssigned,
        severity,
        "alert",
        alert_id,
        a,
        assigned_to("Alert", alert_id, a.assignee),
        None,
    )
}

/// `case_assigned_event`.
pub fn case_assigned_event(case_id: i64, a: &Assignment<'_>) -> NotificationEvent {
    assignment_event(
        NotificationTrigger::CaseAssigned,
        NotificationSeverity::Informational,
        "case",
        case_id,
        a,
        assigned_to("Case", case_id, a.assignee),
        None,
    )
}

/// `case_task_assigned_event` (`str(None)` where the task has no title, as
/// the f-string prints it).
pub fn case_task_assigned_event(
    task_id: i64,
    case_id: i64,
    a: &Assignment<'_>,
) -> NotificationEvent {
    let title = a.title.unwrap_or("None");
    let summary = match a.assignee.filter(|x| !x.is_empty()) {
        Some(who) => format!("Task '{title}' on case #{case_id} was assigned to {who}."),
        None => format!("Task '{title}' was unassigned."),
    };
    assignment_event(
        NotificationTrigger::CaseTaskAssigned,
        NotificationSeverity::Informational,
        "case_task",
        task_id,
        a,
        summary,
        Some(("case_id", serde_json::Value::from(case_id))),
    )
}

/// Where notification events go. `emit` must return immediately: a failure
/// to notify never fails the operation that triggered it (`emit.py`).
pub trait NotificationSink: Send + Sync {
    /// Schedule `event` for dispatch. `bearer` is the caller's token when a
    /// request caused the event (`None` for CoPilot acting on its own).
    fn emit(&self, event: NotificationEvent, bearer: Option<String>);
}

/// Shared handle type.
pub type SharedNotificationSink = Arc<dyn NotificationSink>;

/// Drops every event (tests, tools without a database).
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

    #[test]
    fn incident_builders_match_python() {
        let d = defaults();
        let e = alert_created_event(
            &d,
            &AlertCreatedInput {
                alert_id: 5,
                customer_code: "acme",
                alert_title: Some(""),
                severity: Some("Critical"),
                rule_level: Some(12),
                ..Default::default()
            },
        );
        assert_eq!(e.subject, "Alert #5");
        assert_eq!(e.summary, "A new alert was created for acme.");
        assert_eq!(e.dedupe_key, "alert:5:alert_created");
        assert_eq!(
            e.link_url.as_deref(),
            Some("https://copilot.example.com/alerts/5")
        );
        assert_eq!(
            serde_json::Value::Object(e.context),
            serde_json::json!({"alert_name": "Alert #5", "rule_level": 12, "asset_name": null})
        );
        let a = Assignment {
            title: Some("Mimikatz"),
            assignee: Some("bob"),
            actor: Some("alice"),
            customer_code: Some("acme"),
        };
        let e = alert_assigned_event(&d, 5, &a, Some(""));
        assert_eq!(e.severity, NotificationSeverity::Informational);
        assert_eq!(e.dedupe_key, "alert:5:alert_assigned:bob");
        assert_eq!(e.summary, "Alert #5 was assigned to bob.");
        assert_eq!(e.link_url, None);
        assert_eq!(
            alert_assigned_event(&d, 5, &a, Some("bogus")).severity,
            NotificationSeverity::High
        );
        let unassigned = Assignment {
            assignee: None,
            title: None,
            ..a
        };
        let e = case_assigned_event(9, &unassigned);
        assert_eq!(
            (
                e.subject.as_str(),
                e.summary.as_str(),
                e.dedupe_key.as_str()
            ),
            (
                "case #9",
                "Case #9 was unassigned.",
                "case:9:case_assigned:unassigned"
            )
        );
        let e = case_task_assigned_event(3, 9, &unassigned);
        assert_eq!(e.summary, "Task 'None' was unassigned.");
        assert_eq!(
            serde_json::Value::Object(e.context),
            serde_json::json!({"title": null, "case_id": 9})
        );
        let e = case_task_assigned_event(3, 9, &a);
        assert_eq!(e.summary, "Task 'Mimikatz' on case #9 was assigned to bob.");
        assert_eq!(e.dedupe_key, "case_task:3:case_task_assigned:bob");
    }

    #[test]
    fn triggers_are_the_python_enums() {
        // `class NotificationTrigger(str, Enum)` in the Python schema, in order.
        let source = include_str!("../../../backend/app/notifications/schema/notifications.py");
        let body = source
            .split("class NotificationTrigger(str, Enum):")
            .nth(1)
            .unwrap()
            .split("\n\n\n")
            .next()
            .unwrap();
        let values: Vec<&str> = body
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let (name, value) = l.split_once(" = \"")?;
                (name.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
                    .then(|| value.trim_end_matches('"'))
            })
            .collect();
        let ours: Vec<&str> = NotificationTrigger::ALL
            .iter()
            .map(|t| t.as_str())
            .collect();
        assert_eq!(values, ours);
        for t in NotificationTrigger::ALL {
            assert_eq!(NotificationTrigger::parse(t.as_str()), Some(t));
            assert_eq!(serde_json::to_value(t).unwrap(), t.as_str());
        }
        assert_eq!(NotificationTrigger::parse("Alert_Created"), None);
        assert!(!NotificationTrigger::DISPATCH.contains(&NotificationTrigger::TempPasswordIssued));
    }
}
