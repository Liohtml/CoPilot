//! The incidents' notification events: the builders are
//! `copilot_core::notify`'s (`alert_created_event`, `alert_assigned_event`,
//! `case_assigned_event`, `case_task_assigned_event`); this module keeps the
//! port of `app/incidents/services/notification_enrichment.py` and pins the
//! events the incidents routes emit against values captured from the Python
//! builders.
//!
//! Events go out through `ctx.notifications` (fire and forget, like
//! `emit()`).

use serde_json::Value;

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
    use copilot_core::notify::{
        AlertCreatedInput, Assignment, NotificationDefaults, NotificationSeverity,
        alert_assigned_event, alert_created_event, case_assigned_event, case_task_assigned_event,
    };
    use serde_json::json;

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
            &defaults(None),
            5,
            &Assignment {
                title: Some("T"),
                assignee: Some("bob"),
                actor: Some("al"),
                customer_code: Some("acme"),
            },
            Some("High"),
        );
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"customer_code":"acme","trigger":"alert_assigned","severity":"High","subject":"T","summary":"Alert #5 was assigned to bob.","entity_type":"alert","entity_id":5,"dedupe_key":"alert:5:alert_assigned:bob","link_url":null,"assignee_username":"bob","actor_username":"al","context":{"title":"T"}}"#
        );
    }

    #[test]
    fn case_unassigned_matches_python() {
        let e = case_assigned_event(
            3,
            &Assignment {
                actor: Some("al"),
                ..Assignment::default()
            },
        );
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"customer_code":null,"trigger":"case_assigned","severity":"Informational","subject":"case #3","summary":"Case #3 was unassigned.","entity_type":"case","entity_id":3,"dedupe_key":"case:3:case_assigned:unassigned","link_url":null,"assignee_username":null,"actor_username":"al","context":{"title":null}}"#
        );
    }

    #[test]
    fn case_task_assigned_matches_python() {
        let e = case_task_assigned_event(
            9,
            3,
            &Assignment {
                title: Some("x"),
                assignee: Some("b"),
                actor: Some("al"),
                customer_code: Some("c"),
            },
        );
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"customer_code":"c","trigger":"case_task_assigned","severity":"Informational","subject":"x","summary":"Task 'x' on case #3 was assigned to b.","entity_type":"case_task","entity_id":9,"dedupe_key":"case_task:9:case_task_assigned:b","link_url":null,"assignee_username":"b","actor_username":"al","context":{"title":"x","case_id":3}}"#
        );
    }

    #[test]
    fn alert_created_matches_python() {
        let e = alert_created_event(
            &defaults(Some("https://c.example/")),
            &AlertCreatedInput {
                alert_id: 1,
                customer_code: "c",
                severity: Some("High"),
                ..AlertCreatedInput::default()
            },
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
