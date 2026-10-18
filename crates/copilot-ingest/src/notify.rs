//! What a new alert sets in motion besides its rows:
//! `handle_customer_notifications` (the customer's legacy Shuffle workflow,
//! then the SOCFortress MDR forward), `handle_talon_investigation`.
//!
//! All three are best effort: nothing they do (an unreachable Shuffle or
//! MDR server, a Talon that refuses) reaches the request that created the
//! alert, and the Talon call is handed to a task so ingest never waits up
//! to its 120 s timeout.
//!
//! The Shuffle call is the one `execute_workflow` makes — `requests.post`
//! of `ExecuteWorkflowRequest(...).model_dump()` with the connector's
//! bearer key; the Shuffle *routes* (`/api/shuffle/*`, the case
//! notification) are `copilot-shuffle`'s.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_talon::client::POST_TIMEOUT;
use copilot_talon::contract::InvestigateRequest;
use copilot_upstream::http::PyRequest;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_wazuh::error::PyErr;
use http::Method;

use crate::IngestState;
use crate::create::AlertPayload;

/// `MDR_INTEGRATION_NAME`.
const MDR_INTEGRATION_NAME: &str = "SOCFortress MDR";

fn opt_int(v: Option<i64>) -> PyValue {
    v.map_or(PyValue::None, |n| PyValue::Int(n.to_string()))
}

fn opt_str(v: Option<&str>) -> PyValue {
    v.map_or(PyValue::None, |s| PyValue::Str(s.to_string()))
}

/// `handle_customer_notifications(customer_code, asset_name, payload,
/// type)`: the workflow when the customer's notification row is enabled,
/// then (alerts only) the MDR forward. Only the notification lookup itself
/// can fail the caller, as in Python.
pub async fn customer_notifications(
    st: &IngestState,
    customer: &str,
    asset_name: &str,
    payload: &AlertPayload,
    kind: &str,
) -> Result<(), PyErr> {
    let rows = copilot_incidents::config::notification(&st.ctx.db, customer).await?;
    if let Some(row) = rows.first().filter(|r| r.enabled) {
        let arguments = PyValue::Dict(vec![
            ("type".into(), PyValue::Str(kind.into())),
            ("customer_code".into(), PyValue::Str(customer.into())),
            ("asset_name".into(), PyValue::Str(asset_name.into())),
            (
                "alert_context_payload".into(),
                PyValue::Dict(payload.context.clone()),
            ),
            ("alert_title".into(), PyValue::Str(payload.title.clone())),
            ("alert_id".into(), opt_int(payload.alert_id)),
            ("rule_level".into(), opt_int(payload.rule_level)),
            ("severity".into(), opt_str(payload.severity.as_deref())),
        ]);
        if let Err(e) = execute_workflow(st, &row.shuffle_workflow_id, arguments).await {
            tracing::error!(
                target: "copilot::ingest",
                "Failed to execute customer notification workflow for customer code {customer}: {e}"
            );
        }
    }
    if kind == "alert" {
        forward_alert_to_mdr(st, customer, payload).await;
    }
    Ok(())
}

/// `execute_workflow(ExecuteWorkflowRequest(...))`: `Err` is the text of
/// what Python raises (and swallows here).
async fn execute_workflow(
    st: &IngestState,
    workflow_id: &str,
    arguments: PyValue,
) -> Result<(), String> {
    let row = st
        .ctx
        .connectors
        .get("Shuffle")
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "502: Failed to execute Shuffle workflow".to_string())?;
    let body = PyValue::Dict(vec![
        ("workflow_id".into(), PyValue::Str(workflow_id.into())),
        ("execution_arguments".into(), arguments),
        ("start".into(), PyValue::Str(String::new())),
    ]);
    // `json.dumps(…, allow_nan=False)` fails before anything is sent.
    py_dumps(&body, Dumps::DEFAULT).map_err(|e| e.to_string())?;
    let url = format!(
        "{}/api/v1/workflows/{workflow_id}/execute",
        row.connector_url
    );
    let key = row.connector_api_key.as_deref().unwrap_or("None");
    let req = PyRequest::new(Method::POST, url)
        .header("Authorization", format!("Bearer {key}"))
        .json(Some(body));
    let resp = st.shuffle.send(req).await.map_err(|e| e.display())?;
    if resp.status() == 204 {
        return Ok(());
    }
    let parsed = resp.json().map_err(|e| e.display())?;
    let body_ok = !matches!(parsed.get("success"), Some(PyValue::Bool(false)));
    if resp.status() < 400 && body_ok && parsed.get("success") == Some(&PyValue::Bool(true)) {
        Ok(())
    } else {
        Err("Shuffle workflow did not execute successfully".into())
    }
}

/// `_mdr_config()["enabled"]`.
fn mdr_enabled(st: &IngestState) -> bool {
    st.env
        .mdr_enabled
        .as_deref()
        .map(|v| v.to_lowercase())
        .is_some_and(|v| matches!(v.as_str(), "true" | "1" | "yes"))
}

/// One row of the integration/subscription/auth-key join.
type KeyRow = (i32, Option<i32>, Option<String>, Option<String>);

/// `get_mdr_collector_uuid(customer_code)`: the deployed MDR integration's
/// `COLLECTOR_UUID` key, else `MDR_COLLECTOR_UUID`.
async fn mdr_collector_uuid(st: &IngestState, customer: &str) -> Result<Option<String>, PyErr> {
    let rows: Vec<KeyRow> = sqlx::query_as(
        "SELECT customer_integrations.id, integration_subscriptions.id, \
         integration_auth_keys.auth_key_name, integration_auth_keys.auth_value \
         FROM customer_integrations \
         LEFT OUTER JOIN integration_subscriptions ON customer_integrations.id = integration_subscriptions.customer_id \
         LEFT OUTER JOIN integration_auth_keys ON integration_subscriptions.id = integration_auth_keys.subscription_id \
         WHERE customer_integrations.customer_code = ? \
         AND customer_integrations.integration_service_name = ? \
         AND customer_integrations.deployed = true",
    )
    .bind(customer)
    .bind(MDR_INTEGRATION_NAME)
    .fetch_all(st.ctx.db.pool())
    .await?;
    let Some(first) = rows.first().map(|r| r.0) else {
        return Ok(None);
    };
    for (_, _, name, value) in rows.iter().filter(|r| r.0 == first) {
        if name.as_deref() == Some("COLLECTOR_UUID") {
            if let Some(v) = value.as_deref().filter(|v| !v.is_empty()) {
                return Ok(Some(v.to_string()));
            }
        }
    }
    Ok(st.env.mdr_collector_uuid.clone().filter(|v| !v.is_empty()))
}

/// `forward_alert_to_mdr`: never raises.
async fn forward_alert_to_mdr(st: &IngestState, customer: &str, payload: &AlertPayload) {
    if !mdr_enabled(st) {
        return;
    }
    let server = st
        .env
        .mdr_server_url
        .clone()
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();
    if server.is_empty() {
        tracing::warn!(
            target: "copilot::ingest",
            "MDR_ENABLED is set but MDR_SERVER_URL is not configured — skipping MDR forward"
        );
        return;
    }
    let (Some(index), Some(id)) = (
        payload.index_name.as_deref().filter(|s| !s.is_empty()),
        payload.index_id.as_deref().filter(|s| !s.is_empty()),
    ) else {
        return;
    };
    let Some(alert_id) = payload.alert_id else {
        return;
    };
    let uuid = match mdr_collector_uuid(st, customer).await {
        Ok(Some(u)) => u,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "MDR forward errored (non-fatal): {e:?}");
            return;
        }
    };
    let body = PyValue::Dict(vec![
        ("collector_uuid".into(), PyValue::Str(uuid)),
        ("index_name".into(), PyValue::Str(index.into())),
        ("index_id".into(), PyValue::Str(id.into())),
        (
            "copilot_alert_id".into(),
            PyValue::Int(alert_id.to_string()),
        ),
    ]);
    let Ok(text) = py_dumps(&body, Dumps::HTTPX) else {
        return;
    };
    let url = format!("{server}/api/v1/alerts/copilot");
    let result = st
        .mdr
        .post(&url)
        .header("content-type", "application/json")
        .body(text)
        .send()
        .await;
    match result {
        Ok(resp) if resp.status().as_u16() >= 400 => tracing::error!(
            target: "copilot::ingest",
            "MDR forward failed for alert {alert_id} (HTTP {})",
            resp.status().as_u16()
        ),
        Ok(_) => {}
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "MDR forward errored (non-fatal): {e}");
        }
    }
}

/// The MDR client: httpx's 30 s timeout.
pub fn mdr_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("python-httpx/0.28.1")
        .build()
}

/// `handle_talon_investigation(alert_id, customer_code)`: when the
/// customer's AI-analyst trigger is enabled, `POST /investigate` on a task
/// of its own (`sender="copilot"`, Talon records it as a webhook).
pub async fn talon_investigation(st: &IngestState, alert_id: i64, customer: &str) {
    let rows = match copilot_incidents::config::ai_trigger(&st.ctx.db, customer).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                target: "copilot::ingest",
                "Failed to trigger Talon investigation for alert {alert_id}: {e}"
            );
            return;
        }
    };
    if !rows.first().is_some_and(|r| r.enabled) {
        tracing::info!(
            target: "copilot::ingest",
            "AI analyst trigger not enabled for customer {customer}, skipping Talon investigation"
        );
        return;
    }
    // `TalonInvestigateRequest.customer_code` is `max_length=64`.
    if customer.chars().count() > 64 {
        tracing::error!(
            target: "copilot::ingest",
            "Failed to trigger Talon investigation for alert {alert_id}: customer code too long"
        );
        return;
    }
    let talon = st.talon.clone();
    // `TalonInvestigateRequest(...).model_dump(exclude_none=True)`, sent by
    // `requests` (`json.dumps`).
    let request = InvestigateRequest {
        alert_id,
        customer_code: customer.to_string(),
        triggered_by: None,
        template_override: None,
        sender: "copilot".into(),
    };
    let body = PyValue::Dict(vec![
        (
            "alert_id".into(),
            PyValue::Int(request.alert_id.to_string()),
        ),
        ("customer_code".into(), PyValue::Str(request.customer_code)),
        ("sender".into(), PyValue::Str(request.sender)),
    ]);
    let Ok(text) = py_dumps(&body, Dumps::DEFAULT) else {
        return;
    };
    tokio::spawn(async move {
        if let Err(e) = talon.post_text("/investigate", text, POST_TIMEOUT).await {
            tracing::error!(
                target: "copilot::ingest",
                "Failed to trigger Talon investigation for alert {alert_id}: {e}"
            );
        }
    });
}
