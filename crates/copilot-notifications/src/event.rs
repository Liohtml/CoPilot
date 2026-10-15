//! The event a dispatch renders and delivers, and the Python semantics the
//! dispatcher applies to it.
//!
//! Internally an event is `copilot_jinja::Event` — `NotificationEvent`'s
//! fields with the `context` bag already in template values — because the
//! same object feeds the renderer, the default bodies and the providers.
//! [`from_notification`] converts the `copilot_core` envelope other modules
//! emit.

use copilot_auth::pyvalue::{float_repr, str_repr};
use copilot_core::notify::{NotificationEvent, NotificationTrigger};
use copilot_jinja::{Event, Input};
use serde_json::Value;

/// `INTERNAL_TRIGGERS`: who is working on something, never the customer's
/// business — internal routes only.
pub const INTERNAL_TRIGGERS: &[&str] = &[
    "alert_assigned",
    "case_assigned",
    "case_task_assigned",
    "sla_at_risk",
    "sla_breached",
];

/// `SLA_TRIGGERS`.
pub const SLA_TRIGGERS: &[&str] = &["sla_at_risk", "sla_breached"];

/// `DUAL_SCOPE_TRIGGERS`: resolved against internal *and* customer routes.
pub const DUAL_SCOPE_TRIGGERS: &[&str] = &["ai_report_reviewed"];

/// `AI_SOURCED_TRIGGERS`: gated by the customer's AI report switch.
pub const AI_SOURCED_TRIGGERS: &[&str] = &[
    "investigation_complete",
    "ai_report_reviewed",
    "severity_critical_or_high",
];

/// `SEVERITY_ORDER`, least severe first.
pub const SEVERITY_ORDER: &[&str] = &["Informational", "Low", "Medium", "High", "Critical"];

/// The `NotificationSeverity` values, in enum order.
pub const SEVERITIES: &[&str] = &["Critical", "High", "Medium", "Low", "Informational"];

/// The `NotificationTrigger` values, in enum order.
pub fn trigger_values() -> Vec<&'static str> {
    NotificationTrigger::ALL
        .iter()
        .map(|t| t.as_str())
        .collect()
}

/// `EntityType` values.
pub mod entity {
    /// An alert.
    pub const ALERT: &str = "alert";
    /// A case.
    pub const CASE: &str = "case";
    /// A case task.
    pub const CASE_TASK: &str = "case_task";
}

/// A JSON value as a template value (`Dict[str, Any]` after Pydantic).
pub fn input_from_json(v: &Value) -> Input {
    match v {
        Value::Null => Input::None,
        Value::Bool(b) => Input::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Input::Int(i128::from(i))
            } else if let Some(u) = n.as_u64() {
                Input::Int(i128::from(u))
            } else {
                Input::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => Input::Str(s.clone()),
        Value::Array(items) => Input::List(items.iter().map(input_from_json).collect()),
        Value::Object(map) => Input::Dict(
            map.iter()
                .map(|(k, v)| (k.clone(), input_from_json(v)))
                .collect(),
        ),
    }
}

/// The internal event for a `copilot_core` envelope.
pub fn from_notification(e: &NotificationEvent) -> Event {
    Event {
        customer_code: e.customer_code.clone(),
        trigger: e.trigger.as_str().to_string(),
        severity: severity_str(e.severity).to_string(),
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

/// The wire spelling of a severity.
pub fn severity_str(s: copilot_core::notify::NotificationSeverity) -> &'static str {
    use copilot_core::notify::NotificationSeverity as S;
    match s {
        S::Critical => "Critical",
        S::High => "High",
        S::Medium => "Medium",
        S::Low => "Low",
        S::Informational => "Informational",
    }
}

/// `event.context.get(key)`.
pub fn ctx_get<'a>(e: &'a Event, key: &str) -> Option<&'a Input> {
    e.context.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// `event.context[key] = value` (an existing key keeps its position).
pub fn ctx_set(e: &mut Event, key: &str, value: Input) {
    match e.context.iter_mut().find(|(k, _)| k == key) {
        Some((_, v)) => *v = value,
        None => e.context.push((key.to_string(), value)),
    }
}

/// `dict.get(key)` on a template value.
pub fn dict_get<'a>(v: &'a Input, key: &str) -> Option<&'a Input> {
    match v {
        Input::Dict(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

/// Python truthiness.
pub fn truthy(v: &Input) -> bool {
    match v {
        Input::None => false,
        Input::Bool(b) => *b,
        Input::Int(i) => *i != 0,
        Input::Float(f) => *f != 0.0,
        Input::Str(s) | Input::Markup(s) => !s.is_empty(),
        Input::List(l) => !l.is_empty(),
        Input::Dict(d) => !d.is_empty(),
    }
}

/// `x or None` over an optional value: the value when truthy.
pub fn truthy_opt(v: Option<&Input>) -> Option<&Input> {
    v.filter(|v| truthy(v))
}

/// `str(value)`.
pub fn py_str(v: &Input) -> String {
    match v {
        Input::Str(s) | Input::Markup(s) => s.clone(),
        other => py_repr(other),
    }
}

/// `repr(value)`.
pub fn py_repr(v: &Input) -> String {
    match v {
        Input::None => "None".into(),
        Input::Bool(true) => "True".into(),
        Input::Bool(false) => "False".into(),
        Input::Int(i) => i.to_string(),
        Input::Float(f) => float_repr(*f),
        Input::Str(s) => str_repr(s),
        Input::Markup(s) => format!("Markup({})", str_repr(s)),
        Input::List(items) => {
            let inner: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Input::Dict(items) => {
            let inner: Vec<String> = items
                .iter()
                .map(|(k, v)| format!("{}: {}", str_repr(k), py_repr(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Python's `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    copilot_web::form::py_strip(s)
}

/// `" ".join(s.split())`.
pub fn collapse_whitespace(s: &str) -> String {
    s.split(copilot_web::form::is_py_space)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `s[:n]` (code points).
pub fn py_prefix(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_str_and_repr() {
        let v = Input::Dict(vec![
            (
                "a".into(),
                Input::List(vec![Input::Int(1), Input::Float(2.5)]),
            ),
            ("b".into(), Input::None),
            ("c".into(), Input::Str("it's".into())),
        ]);
        assert_eq!(py_str(&v), "{'a': [1, 2.5], 'b': None, 'c': \"it's\"}");
        assert_eq!(py_str(&Input::Bool(true)), "True");
        assert_eq!(py_str(&Input::Str("x".into())), "x");
        assert!(!truthy(&Input::Str(String::new())));
        assert!(truthy(&Input::Int(-1)));
        assert_eq!(collapse_whitespace("  a \n b\tc  "), "a b c");
    }

    #[test]
    fn triggers_mirror_the_python_groups() {
        let source = include_str!("../../../backend/app/notifications/schema/notifications.py");
        for t in INTERNAL_TRIGGERS
            .iter()
            .chain(DUAL_SCOPE_TRIGGERS)
            .chain(AI_SOURCED_TRIGGERS)
        {
            assert!(source.contains(&format!("\"{t}\"")), "{t}");
        }
    }
}
