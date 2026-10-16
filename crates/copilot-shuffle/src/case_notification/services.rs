//! The case notification's payload and its Shuffle call.

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_incidents::schema::{AlertOut, CaseOut};
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::{PyExc, type_name};

use crate::case_notification::schema::CREATED_ALERT_PAYLOAD;
use crate::client::ShuffleClient;
use crate::integrations::schema::EXECUTE_WORKFLOW_REQUEST;
use crate::integrations::services::{check_customer_code, execute_workflow};

/// `get_alert_context_by_id(id, db).context`: 404 `Alert context not found`.
async fn alert_context(db: &Db, id: i32) -> Result<PyValue, PyExc> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT CAST(context AS CHAR) FROM incident_management_alertcontext WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await
    .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
    let Some((text,)) = row else {
        return Err(PyExc::http(404, "Alert context not found"));
    };
    Ok(match text {
        None => PyValue::None,
        Some(t) => copilot_auth::pyvalue::loads(&t).unwrap_or(PyValue::None),
    })
}

/// `extract_rule_level(context)`; `Err` is the `AttributeError` of a
/// truthy context that is not a dict.
fn rule_level(context: &PyValue) -> Result<Option<i128>, PyExc> {
    if !context.truthy() {
        return Ok(None);
    }
    let PyValue::Dict(_) = context else {
        return Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'get'",
            type_name(context)
        )));
    };
    let mut candidate = context.get("rule_level").cloned().unwrap_or(PyValue::None);
    if matches!(candidate, PyValue::None) {
        if let Some(rule @ PyValue::Dict(_)) = context.get("rule") {
            candidate = rule.get("level").cloned().unwrap_or(PyValue::None);
        }
    }
    // `int(candidate)`, `TypeError`/`ValueError` → `None`.
    Ok(match candidate {
        PyValue::None => None,
        other => other.to_int(),
    })
}

/// `severity_from_rule_level(rule_level)`.
fn severity(rule_level: Option<i128>) -> PyValue {
    match rule_level {
        None => PyValue::None,
        Some(l) if l >= 12 => PyValue::Str("Critical".into()),
        Some(l) if l >= 8 => PyValue::Str("High".into()),
        Some(l) if l >= 4 => PyValue::Str("Medium".into()),
        Some(_) => PyValue::Str("Low".into()),
    }
}

fn opt_str(v: Option<&str>) -> PyValue {
    v.map_or(PyValue::None, |s| PyValue::Str(s.to_string()))
}

/// One alert's `CreatedAlertPayload` dump.
async fn alert_payload(db: &Db, alert: &AlertOut) -> Result<PyValue, PyExc> {
    let asset = alert.assets.first();
    let context = match asset {
        Some(a) => alert_context(db, a.alert_context_id).await?,
        None => PyValue::None,
    };
    let level = rule_level(&context)?;
    let mut iocs: Vec<(String, PyValue)> = Vec::new();
    for ioc in &alert.iocs {
        match iocs.iter_mut().find(|(k, _)| *k == ioc.value) {
            Some(slot) => slot.1 = PyValue::Str(ioc.kind.clone()),
            None => iocs.push((ioc.value.clone(), PyValue::Str(ioc.kind.clone()))),
        }
    }
    construct(
        &CREATED_ALERT_PAYLOAD,
        &kwargs(vec![
            ("alert_context_payload", context),
            (
                "asset_payload",
                PyValue::Str(asset.map(|a| a.asset_name.clone()).unwrap_or_default()),
            ),
            (
                "timefield_payload",
                PyValue::Str(alert.alert_creation_time.clone()),
            ),
            (
                "alert_title_payload",
                PyValue::Str(alert.alert_name.clone()),
            ),
            ("ioc_payload", PyValue::Dict(iocs)),
            ("source", PyValue::Str(alert.source.clone())),
            ("alert_id", PyValue::Int(alert.id.to_string())),
            ("index_name", opt_str(asset.map(|a| a.index_name.as_str()))),
            ("index_id", opt_str(asset.map(|a| a.index_id.as_str()))),
            (
                "rule_level",
                level.map_or(PyValue::None, |l| PyValue::Int(l.to_string())),
            ),
            ("severity", severity(level)),
        ]),
    )
}

/// The case's payloads, then `handle_customer_notifications_case`.
pub async fn notify(db: &Db, client: &ShuffleClient, case: &CaseOut) -> Result<(), PyExc> {
    let mut alerts = Vec::with_capacity(case.alerts.len());
    for alert in &case.alerts {
        alerts.push(alert_payload(db, alert).await?);
    }
    let code = case.customer_code.clone();
    let notifications = match code.as_deref() {
        Some(c) => copilot_incidents::config::notification(db, c)
            .await
            .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?,
        None => Vec::new(),
    };
    let Some(row) = notifications.first().filter(|n| n.enabled) else {
        return Err(PyExc::http(
            400,
            format!(
                "No enabled customer notification workflow is configured for customer '{}'.",
                code.as_deref().unwrap_or("None")
            ),
        ));
    };
    tracing::info!(
        "Executing workflow for customer code {}",
        code.as_deref().unwrap_or("None")
    );
    let primary = alerts.first();
    let from_primary = |key: &str| primary.map_or(PyValue::None, |a| field(a, key).clone());
    let mitre = primary
        .map(|a| field(a, "alert_context_payload"))
        .filter(|c| c.truthy())
        .and_then(|c| c.get("rule_mitre_id").cloned())
        .unwrap_or(PyValue::None);
    let arguments = kwargs(vec![
        ("type", PyValue::Str("case".into())),
        ("customer_code", opt_str(code.as_deref())),
        ("case_name", PyValue::Str(case.case_name.clone())),
        ("primary_asset", from_primary("asset_payload")),
        ("primary_source", from_primary("source")),
        ("primary_alert_title", from_primary("alert_title_payload")),
        ("primary_timefield", from_primary("timefield_payload")),
        ("primary_alert_id", from_primary("alert_id")),
        ("primary_mitre_id", mitre),
        ("rule_level", from_primary("rule_level")),
        ("severity", from_primary("severity")),
        ("alerts", PyValue::List(alerts.clone())),
    ]);
    let request = construct(
        &EXECUTE_WORKFLOW_REQUEST,
        &kwargs(vec![
            ("workflow_id", PyValue::Str(row.shuffle_workflow_id.clone())),
            ("execution_arguments", arguments),
            ("start", PyValue::Str(String::new())),
        ]),
    )?;
    check_customer_code(&request)?;
    execute_workflow(client, request).await?;
    Ok(())
}

/// `increment_case_notification_count(case_id, db)`.
pub async fn increment(db: &Db, case_id: i64) -> Result<(), PyExc> {
    let done = sqlx::query(
        "UPDATE incident_management_case SET notification_invoked_number = \
         COALESCE(notification_invoked_number, 0) + 1 WHERE id = ?",
    )
    .bind(case_id)
    .execute(db.pool())
    .await
    .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
    if done.rows_affected() == 0 {
        return Err(PyExc::http(404, "Case not found"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn rule_levels_follow_the_enrichment_helpers() {
        let level = |t: &str| rule_level(&loads(t).unwrap()).unwrap();
        assert_eq!(level(r#"{"rule_level": "12"}"#), Some(12));
        assert_eq!(level(r#"{"rule_level": 7.9}"#), Some(7));
        assert_eq!(level(r#"{"rule": {"level": " 1_0 "}}"#), Some(10));
        assert_eq!(
            level(r#"{"rule_level": null, "rule": {"level": 3}}"#),
            Some(3)
        );
        assert_eq!(level(r#"{"rule_level": "high"}"#), None);
        assert_eq!(level(r#"{"rule_level": [1]}"#), None);
        assert_eq!(level("{}"), None);
        assert_eq!(level("[]"), None);
        assert!(rule_level(&loads("[1]").unwrap()).is_err());
        assert_eq!(severity(Some(12)), PyValue::Str("Critical".into()));
        assert_eq!(severity(Some(0)), PyValue::Str("Low".into()));
        assert_eq!(severity(None), PyValue::None);
    }
}
