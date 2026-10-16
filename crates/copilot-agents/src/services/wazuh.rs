//! `app/agents/wazuh/services/agents.py` and the manager-version check of
//! `app/agents/routes/agents.py`.

use std::cmp::Ordering;

use serde_json::{Value, json};

use copilot_auth::pyvalue::PyValue;
use copilot_platform::pep440::Version;
use copilot_upstream::model;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_upstream::respond::from_json;
use copilot_wazuh::WazuhState;
use copilot_wazuh::manager::client::{self as manager, Param, PutKind};
use copilot_wazuh::pyops;

use crate::schema::WAZUH_AGENT;
use crate::services::{attr, wazuh_err};

/// One agent of `collect_wazuh_agents` (a validated `WazuhAgent`).
#[derive(Debug, Clone, PartialEq)]
pub struct WazuhAgent {
    /// `agent_id`.
    pub agent_id: String,
    /// `agent_name`.
    pub agent_name: String,
    /// `agent_ip`.
    pub agent_ip: String,
    /// `agent_os`.
    pub agent_os: String,
    /// `agent_label`.
    pub agent_label: String,
    /// `agent_last_seen`.
    pub agent_last_seen: String,
    /// `wazuh_agent_version`.
    pub wazuh_agent_version: String,
    /// `wazuh_agent_status`.
    pub wazuh_agent_status: Option<String>,
}

fn s(v: &PyValue, key: &str) -> String {
    model::field(v, key).py_str()
}

/// `agent.get(key, default)` as a model input.
fn get_or(agent: &Value, key: &str, default: &str) -> Result<Value, String> {
    pyops::get(agent, key, json!(default))
}

/// `collect_wazuh_agents()`.
pub async fn collect_wazuh_agents(st: &WazuhState) -> PyResult<Vec<WazuhAgent>> {
    tracing::info!("Collecting all agents from Wazuh Manager");
    let params = [("limit".to_string(), Param::Int(500))];
    let mut collected = manager::send_get(st, "/agents", Some(&params))
        .await
        .map_err(wazuh_err)?;
    let inner = |c: &Value| -> PyResult<Value> {
        let d = pyops::get(c, "data", json!({})).map_err(attr)?;
        pyops::get(&d, "data", json!({})).map_err(attr)
    };
    let data = inner(&collected)?;
    let total = pyops::get(&data, "total_affected_items", json!(0)).map_err(attr)?;
    let items = pyops::get(&data, "affected_items", json!([])).map_err(attr)?;
    let n = pyops::len(&items).map_err(PyExc::TypeError)?;
    let total_n = match &total {
        Value::Number(t) => t.as_f64().unwrap_or(0.0),
        Value::Bool(b) => f64::from(u8::from(*b)),
        other => {
            return Err(PyExc::TypeError(format!(
                "'<' not supported between instances of 'int' and '{}'",
                copilot_wazuh::indexer::services::py_type(other)
            )));
        }
    };
    if (n as f64) < total_n {
        tracing::info!("Total items: {total_n}. Collected {n} agents. Making another request.");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let limit = match &total {
            Value::Number(t) => Param::Str(pyops::py_str(&Value::Number(t.clone()))),
            other => Param::Str(pyops::py_str(other)),
        };
        let params = [("limit".to_string(), limit)];
        collected = manager::send_get(st, "/agents", Some(&params))
            .await
            .map_err(wazuh_err)?;
    }
    let success = pyops::get(&collected, "success", Value::Null).map_err(attr)?;
    if success == Value::Bool(false) {
        let message = pyops::get(&collected, "message", json!("Unknown error")).map_err(attr)?;
        return Err(PyExc::http(500, pyops::py_str(&message)));
    }
    let build = || -> PyResult<Vec<WazuhAgent>> {
        let mut out = Vec::new();
        if !pyops::truthy(&success) {
            return Ok(out);
        }
        let data = inner(&collected)?;
        let items = pyops::get(&data, "affected_items", json!([])).map_err(attr)?;
        for agent in pyops::iterate(&items).map_err(PyExc::TypeError)? {
            let os = pyops::get(&agent, "os", json!({})).map_err(attr)?;
            let os_name = pyops::get(&os, "name", json!("Unknown")).map_err(attr)?;
            let last_keep_alive = get_or(&agent, "lastKeepAlive", "Unknown").map_err(attr)?;
            let groups = pyops::get(&agent, "group", json!([])).map_err(attr)?;
            let group = if pyops::truthy(&groups) {
                pyops::first(&groups).map_err(PyExc::IndexError)?
            } else {
                json!("Unknown")
            };
            let kwargs = model::kwargs(vec![
                (
                    "agent_id",
                    from_json(&get_or(&agent, "id", "Unknown").map_err(attr)?),
                ),
                (
                    "agent_name",
                    from_json(&get_or(&agent, "name", "Unknown").map_err(attr)?),
                ),
                (
                    "agent_ip",
                    from_json(&get_or(&agent, "ip", "Unknown").map_err(attr)?),
                ),
                ("agent_os", from_json(&os_name)),
                ("agent_label", from_json(&group)),
                ("agent_last_seen", from_json(&last_keep_alive)),
                (
                    "wazuh_agent_version",
                    from_json(&get_or(&agent, "version", "n/a").map_err(attr)?),
                ),
                (
                    "wazuh_agent_status",
                    from_json(&get_or(&agent, "status", "n/a").map_err(attr)?),
                ),
            ]);
            let v = model::construct(&WAZUH_AGENT, &kwargs)?;
            out.push(WazuhAgent {
                agent_id: s(&v, "agent_id"),
                agent_name: s(&v, "agent_name"),
                agent_ip: s(&v, "agent_ip"),
                agent_os: s(&v, "agent_os"),
                agent_label: s(&v, "agent_label"),
                agent_last_seen: s(&v, "agent_last_seen"),
                wazuh_agent_version: s(&v, "wazuh_agent_version"),
                wazuh_agent_status: match model::field(&v, "wazuh_agent_status") {
                    PyValue::None => None,
                    other => Some(other.py_str()),
                },
            });
        }
        Ok(out)
    };
    build().map_err(|e| {
        let text = e.display();
        tracing::error!("Failed to collect agents: {text}");
        PyExc::http(500, format!("Failed to collect agents: {text}"))
    })
}

/// `delete_agent_wazuh(agent_id)` (the async service).
pub async fn delete_agent_wazuh(st: &WazuhState, agent_id: &str) -> PyResult<()> {
    tracing::info!("Deleting agent {agent_id} from Wazuh Manager");
    let params = [
        ("purge".to_string(), Param::Bool(true)),
        ("agents_list".to_string(), Param::Str(agent_id.to_string())),
        ("status".to_string(), Param::Str("all".into())),
        ("older_than".to_string(), Param::Str("0s".into())),
    ];
    let wrap = |e: String| {
        PyExc::http(
            500,
            format!("Failed to delete agent {agent_id} from Wazuh Manager: {e}"),
        )
    };
    let deleted = match manager::send_delete(st, "/agents", Some(&params)).await {
        Ok(v) => v,
        Err(e) => return Err(wrap(wazuh_err(e).display())),
    };
    // `handle_agent_deletion_response`: `agent_deleted["success"]`.
    let success = pyops::index(&deleted, "success").map_err(wrap)?;
    if pyops::truthy(&success) {
        return Ok(());
    }
    let message = pyops::get(&deleted, "message", json!("Unknown error")).map_err(wrap)?;
    Err(PyExc::http(
        400,
        format!(
            "Failed to delete agent {agent_id} from Wazuh Manager: {}",
            pyops::py_str(&message)
        ),
    ))
}

static UPGRADE_RESPONSE: model::Model = model::Model::new(
    "AgentWazuhUpgradeResponse",
    &[
        model::Field::req("success", model::Ty::Bool),
        model::Field::req("message", model::Ty::Str),
    ],
);

/// Python's `x == 0`.
fn eq_zero(v: &Value) -> bool {
    match v {
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::Bool(b) => !*b,
        _ => false,
    }
}

/// `upgrade_wazuh_agent(agent_id)`: `(success, message)`.
pub async fn upgrade_wazuh_agent(st: &WazuhState, agent_id: &str) -> PyResult<(bool, String)> {
    tracing::info!("Upgrading agent {agent_id} from Wazuh Manager");
    let params = [("agents_list".to_string(), Param::Str(agent_id.to_string()))];
    let wrap = |e: String| {
        PyExc::http(
            500,
            format!("Failed to upgrade agent {agent_id} from Wazuh Manager: {e}"),
        )
    };
    let upgraded = manager::send_put(st, "/agents/upgrade", None, Some(&params), PutKind::Json)
        .await
        .map_err(|e| wrap(wazuh_err(e).display()))?;
    let handle = || -> Result<(PyValue, PyValue), String> {
        let outer = pyops::get(&upgraded, "data", json!({}))?;
        let data = pyops::get(&outer, "data", json!({}))?;
        let failed = pyops::get(&data, "total_failed_items", json!(0))?;
        if eq_zero(&failed) {
            let message = pyops::get(&outer, "message", json!("Unknown error"))?;
            return Ok((PyValue::Bool(true), from_json(&message)));
        }
        let items = pyops::get(&data, "failed_items", json!([{}]))?;
        let first = pyops::first(&items)?;
        let error = pyops::get(&first, "error", json!({}))?;
        let message = pyops::get(&error, "message", json!("Unknown error"))?;
        Ok((PyValue::Bool(false), from_json(&message)))
    };
    let (success, message) = handle().map_err(wrap)?;
    let v = model::construct(
        &UPGRADE_RESPONSE,
        &model::kwargs(vec![("success", success), ("message", message)]),
    )
    .map_err(|e| wrap(e.display()))?;
    Ok((
        model::field(&v, "success").truthy(),
        model::field(&v, "message").py_str(),
    ))
}

/// `check_wazuh_manager_version()`: the manager's `api_version` is 4.8.0 or
/// later; any failure reads as `False`.
pub async fn check_wazuh_manager_version(st: &WazuhState) -> bool {
    let response = match manager::send_get(st, "/", None).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                "Failed to check Wazuh Manager version: {}",
                wazuh_err(e).display()
            );
            return false;
        }
    };
    let version = pyops::index(&response, "data")
        .and_then(|d| pyops::index(&d, "data"))
        .and_then(|d| pyops::index(&d, "api_version"));
    let version = match version {
        Ok(Value::String(v)) => v,
        Ok(_) | Err(_) => {
            tracing::error!("Failed to fetch Wazuh Manager version");
            return false;
        }
    };
    match (Version::parse(&version), Version::parse("4.8.0")) {
        (Some(have), Some(min)) => have.cmp(&min) != Ordering::Less,
        _ => false,
    }
}
