//! The incidents' notification events — port of the incident builders of
//! `app/notifications/services/event_builders.py` (`alert_created_event`,
//! `alert_assigned_event`, `case_assigned_event`, `case_task_assigned_event`)
//! and of `app/incidents/services/notification_enrichment.py`.
//!
//! Events go out through `ctx.notifications` (fire and forget, like
//! `emit()`); building them here keeps the shapes pinned by the unit tests
//! below against values captured from the Python builders.

use copilot_core::notify::{
    NotificationDefaults, NotificationEvent, NotificationSeverity, NotificationTrigger,
};
use serde_json::{Map, Value, json};

/// `_ASSIGNMENT_SEVERITY`.
pub const ASSIGNMENT_SEVERITY: NotificationSeverity = NotificationSeverity::Informational;

fn opt(v: Option<&str>) -> Value {
    v.map_or(Value::Null, |s| Value::String(s.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn assignment_event(
    trigger: NotificationTrigger,
    entity_type: &str,
    severity: NotificationSeverity,
    entity_id: i64,
    title: Option<&str>,
    assignee: Option<&str>,
    actor: Option<&str>,
    customer_code: Option<&str>,
    summary: String,
    extra: &[(&str, Value)],
) -> NotificationEvent {
    let mut context = Map::new();
    context.insert("title".into(), opt(title));
    for (k, v) in extra {
        context.insert((*k).to_string(), v.clone());
    }
    NotificationEvent {
        customer_code: customer_code.map(str::to_string),
        trigger,
        severity,
        subject: title
            .filter(|t| !t.is_empty())
            .map_or_else(|| format!("{entity_type} #{entity_id}"), str::to_string),
        summary,
        entity_type: entity_type.to_string(),
        entity_id,
        dedupe_key: format!(
            "{entity_type}:{entity_id}:{}:{}",
            trigger.as_str(),
            assignee.filter(|a| !a.is_empty()).unwrap_or("unassigned")
        ),
        link_url: None,
        assignee_username: assignee.map(str::to_string),
        actor_username: actor.map(str::to_string),
        context,
    }
}

/// `alert_assigned_event`: the alert's own severity when known (the caller
/// passes `severity_of(alert)`), else Informational.
pub fn alert_assigned_event(
    alert_id: i64,
    title: Option<&str>,
    assignee: Option<&str>,
    actor: Option<&str>,
    customer_code: Option<&str>,
    severity: Option<&str>,
    defaults: &NotificationDefaults,
) -> NotificationEvent {
    let severity = match severity.filter(|s| !s.is_empty()) {
        Some(s) => NotificationSeverity::coerce(Some(s), defaults.default_severity),
        None => ASSIGNMENT_SEVERITY,
    };
    let summary = match assignee.filter(|a| !a.is_empty()) {
        Some(a) => format!("Alert #{alert_id} was assigned to {a}."),
        None => format!("Alert #{alert_id} was unassigned."),
    };
    assignment_event(
        NotificationTrigger::AlertAssigned,
        "alert",
        severity,
        alert_id,
        title,
        assignee,
        actor,
        customer_code,
        summary,
        &[],
    )
}

/// `case_assigned_event`.
pub fn case_assigned_event(
    case_id: i64,
    title: Option<&str>,
    assignee: Option<&str>,
    actor: Option<&str>,
    customer_code: Option<&str>,
) -> NotificationEvent {
    let summary = match assignee.filter(|a| !a.is_empty()) {
        Some(a) => format!("Case #{case_id} was assigned to {a}."),
        None => format!("Case #{case_id} was unassigned."),
    };
    assignment_event(
        NotificationTrigger::CaseAssigned,
        "case",
        ASSIGNMENT_SEVERITY,
        case_id,
        title,
        assignee,
        actor,
        customer_code,
        summary,
        &[],
    )
}

/// `case_task_assigned_event`.
pub fn case_task_assigned_event(
    task_id: i64,
    case_id: i64,
    title: Option<&str>,
    assignee: Option<&str>,
    actor: Option<&str>,
    customer_code: Option<&str>,
) -> NotificationEvent {
    let shown = title.map_or_else(|| "None".to_string(), str::to_string);
    let summary = match assignee.filter(|a| !a.is_empty()) {
        Some(a) => format!("Task '{shown}' on case #{case_id} was assigned to {a}."),
        None => format!("Task '{shown}' was unassigned."),
    };
    assignment_event(
        NotificationTrigger::CaseTaskAssigned,
        "case_task",
        ASSIGNMENT_SEVERITY,
        task_id,
        title,
        assignee,
        actor,
        customer_code,
        summary,
        &[("case_id", json!(case_id))],
    )
}

/// `alert_created_event`.
#[allow(clippy::too_many_arguments)]
pub fn alert_created_event(
    alert_id: i64,
    customer_code: &str,
    alert_title: Option<&str>,
    severity: Option<&str>,
    rule_level: Option<i64>,
    asset_name: Option<&str>,
    link_url: Option<&str>,
    defaults: &NotificationDefaults,
) -> NotificationEvent {
    let title = alert_title
        .filter(|t| !t.is_empty())
        .map_or_else(|| format!("Alert #{alert_id}"), str::to_string);
    let mut context = Map::new();
    context.insert("alert_name".into(), json!(title));
    context.insert("rule_level".into(), json!(rule_level));
    context.insert("asset_name".into(), opt(asset_name));
    NotificationEvent {
        customer_code: Some(customer_code.to_string()),
        trigger: NotificationTrigger::AlertCreated,
        severity: NotificationSeverity::coerce(severity, defaults.default_severity),
        subject: title,
        summary: format!("A new alert was created for {customer_code}."),
        entity_type: "alert".into(),
        entity_id: alert_id,
        dedupe_key: format!("alert:{alert_id}:alert_created"),
        link_url: link_url
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .or_else(|| defaults.link(&format!("/alerts/{alert_id}"))),
        assignee_username: None,
        actor_username: None,
        context,
    }
}

/// `extract_rule_level`: `rule_level`, else `rule.level`, as an int.
pub fn extract_rule_level(context: Option<&Value>) -> Option<i64> {
    let ctx = context?.as_object().filter(|o| !o.is_empty())?;
    let candidate = match ctx.get("rule_level") {
        Some(v) if !v.is_null() => v,
        _ => ctx.get("rule")?.as_object()?.get("level")?,
    };
    match candidate {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Value::Bool(b) => Some(i64::from(*b)),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// `severity_from_rule_level`.
pub fn severity_from_rule_level(rule_level: Option<i64>) -> Option<&'static str> {
    let level = rule_level?;
    Some(if level >= 12 {
        "Critical"
    } else if level >= 8 {
        "High"
    } else if level >= 4 {
        "Medium"
    } else {
        "Low"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults(url: Option<&str>) -> NotificationDefaults {
        NotificationDefaults {
            copilot_url: url.map(str::to_string),
            default_severity: NotificationSeverity::High,
        }
    }

    // Values captured from the Python builders (event.model_dump_json()).
    #[test]
    fn alert_assigned_matches_python() {
        let e = alert_assigned_event(
            5,
            Some("T"),
            Some("bob"),
            Some("al"),
            Some("acme"),
            Some("High"),
            &defaults(None),
        );
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"customer_code":"acme","trigger":"alert_assigned","severity":"High","subject":"T","summary":"Alert #5 was assigned to bob.","entity_type":"alert","entity_id":5,"dedupe_key":"alert:5:alert_assigned:bob","link_url":null,"assignee_username":"bob","actor_username":"al","context":{"title":"T"}}"#
        );
    }

    #[test]
    fn case_unassigned_matches_python() {
        let e = case_assigned_event(3, None, None, Some("al"), None);
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"customer_code":null,"trigger":"case_assigned","severity":"Informational","subject":"case #3","summary":"Case #3 was unassigned.","entity_type":"case","entity_id":3,"dedupe_key":"case:3:case_assigned:unassigned","link_url":null,"assignee_username":null,"actor_username":"al","context":{"title":null}}"#
        );
    }

    #[test]
    fn case_task_assigned_matches_python() {
        let e = case_task_assigned_event(9, 3, Some("x"), Some("b"), Some("al"), Some("c"));
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"customer_code":"c","trigger":"case_task_assigned","severity":"Informational","subject":"x","summary":"Task 'x' on case #3 was assigned to b.","entity_type":"case_task","entity_id":9,"dedupe_key":"case_task:9:case_task_assigned:b","link_url":null,"assignee_username":"b","actor_username":"al","context":{"title":"x","case_id":3}}"#
        );
    }

    #[test]
    fn alert_created_matches_python() {
        let e = alert_created_event(
            1,
            "c",
            None,
            Some("High"),
            None,
            None,
            None,
            &defaults(Some("https://c.example/")),
        );
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"customer_code":"c","trigger":"alert_created","severity":"High","subject":"Alert #1","summary":"A new alert was created for c.","entity_type":"alert","entity_id":1,"dedupe_key":"alert:1:alert_created","link_url":"https://c.example/alerts/1","assignee_username":null,"actor_username":null,"context":{"alert_name":"Alert #1","rule_level":null,"asset_name":null}}"#
        );
    }

    #[test]
    fn rule_level_enrichment() {
        assert_eq!(
            extract_rule_level(Some(&json!({"rule_level": "12"}))),
            Some(12)
        );
        assert_eq!(
            extract_rule_level(Some(&json!({"rule": {"level": 7}}))),
            Some(7)
        );
        assert_eq!(extract_rule_level(Some(&json!({"rule_level": "x"}))), None);
        assert_eq!(extract_rule_level(Some(&json!({}))), None);
        assert_eq!(severity_from_rule_level(Some(12)), Some("Critical"));
        assert_eq!(severity_from_rule_level(Some(8)), Some("High"));
        assert_eq!(severity_from_rule_level(Some(4)), Some("Medium"));
        assert_eq!(severity_from_rule_level(Some(1)), Some("Low"));
        assert_eq!(severity_from_rule_level(None), None);
    }
}
