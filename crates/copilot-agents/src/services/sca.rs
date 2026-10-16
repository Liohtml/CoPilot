//! `app/agents/wazuh/services/sca.py`: an agent's SCA policies and a
//! policy's checks, from the manager API.

use serde_json::{Value, json};

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Model};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_upstream::respond::from_json;
use copilot_wazuh::WazuhState;
use copilot_wazuh::manager::client::{self as manager, Param};
use copilot_wazuh::pyops;

use crate::schema::{WAZUH_AGENT_SCA_POLICY_RESULTS, WAZUH_AGENT_SCA_RESULTS};
use crate::services::{attr, wazuh_err};

/// `_is_no_sca_data_error(message)`: Wazuh's 4xx for an agent without SCA
/// data is an empty result, not a fault.
fn no_sca_data(message: &str) -> bool {
    message.contains("400 Client Error") || message.contains("404 Client Error")
}

/// `process_agent_sca(…)` / `process_agent_sca_policy_results(…)`.
fn process(data: &Value, m: &'static Model, qualname: &str) -> PyResult<Vec<PyValue>> {
    let run = || -> PyResult<Vec<PyValue>> {
        let d = pyops::get(data, "data", json!({})).map_err(attr)?;
        let items = pyops::get(&d, "affected_items", json!([])).map_err(attr)?;
        pyops::iterate(&items)
            .map_err(PyExc::TypeError)?
            .iter()
            .map(|item| model::construct_star(m, qualname, &from_json(item)))
            .collect()
    };
    run().map_err(|e| PyExc::http(500, format!("Failed to process agent sca: {}", e.display())))
}

fn wrap(key: &str, items: Vec<PyValue>, message: &str) -> PyValue {
    PyValue::Dict(vec![
        (key.into(), PyValue::List(items)),
        ("success".into(), PyValue::Bool(true)),
        ("message".into(), PyValue::Str(message.into())),
    ])
}

async fn fetch(
    st: &WazuhState,
    endpoint: &str,
    q: Option<String>,
) -> PyResult<Result<Value, String>> {
    let params = q.map(|q| vec![("q".to_string(), Param::Str(q))]);
    let reply = manager::send_get(st, endpoint, params.as_deref())
        .await
        .map_err(wazuh_err)?;
    let success = pyops::index(&reply, "success").map_err(PyExc::KeyError)?;
    if success == Value::Bool(false) {
        let message = pyops::index(&reply, "message").map_err(PyExc::KeyError)?;
        return Ok(Err(pyops::py_str(&message)));
    }
    Ok(Ok(pyops::index(&reply, "data").map_err(PyExc::KeyError)?))
}

/// `collect_agent_sca(agent_id, policy_id)`: the `WazuhAgentScaResponse`
/// dump.
pub async fn collect_agent_sca(
    st: &WazuhState,
    agent_id: &str,
    policy_id: Option<&str>,
) -> PyResult<PyValue> {
    tracing::info!("Collecting agent {agent_id} sca from Wazuh Manager");
    let q = policy_id
        .filter(|p| !p.is_empty())
        .map(|p| format!("policy_id={p}"));
    match fetch(st, &format!("/sca/{agent_id}"), q).await? {
        Err(message) if no_sca_data(&message) => {
            tracing::info!("Agent {agent_id} has no SCA data: {message}");
            Ok(wrap(
                "sca",
                Vec::new(),
                "No SCA results available for this agent",
            ))
        }
        Err(message) => Err(PyExc::http(500, message)),
        Ok(data) => Ok(wrap(
            "sca",
            process(
                &data,
                &WAZUH_AGENT_SCA_RESULTS,
                "app.agents.wazuh.schema.agents.WazuhAgentScaResults",
            )?,
            "SCA collected successfully",
        )),
    }
}

/// `collect_agent_sca_policy_results(agent_id, policy_id, check_id)`: the
/// `WazuhAgentScaPolicyResultsResponse` dump.
pub async fn collect_policy_results(
    st: &WazuhState,
    agent_id: &str,
    policy_id: &str,
    check_id: Option<i64>,
) -> PyResult<PyValue> {
    tracing::info!("Collecting agent {agent_id} sca from Wazuh Manager");
    let q = check_id.map(|c| format!("id={c}"));
    match fetch(st, &format!("/sca/{agent_id}/checks/{policy_id}"), q).await? {
        Err(message) if no_sca_data(&message) => {
            tracing::info!("Agent {agent_id} has no SCA checks for policy {policy_id}: {message}");
            Ok(wrap(
                "sca_policy_results",
                Vec::new(),
                "No SCA checks available for this policy",
            ))
        }
        Err(message) => Err(PyExc::http(500, message)),
        Ok(data) => Ok(wrap(
            "sca_policy_results",
            process(
                &data,
                &WAZUH_AGENT_SCA_POLICY_RESULTS,
                "app.agents.wazuh.schema.agents.WazuhAgentScaPolicyResults",
            )?,
            "SCA Policy results collected successfully",
        )),
    }
}
