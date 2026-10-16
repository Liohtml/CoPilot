//! `invoke_action` and its helpers (`app/integrations/copilot_action/
//! routes/copilot_action.py`): the agents by hostname, the action's
//! details, the parameter checks, one Velociraptor collection per agent.

use copilot_agents::db::AGENT_COLS;
use copilot_agents::schema::AgentRecord;
use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_db::Db;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::PyExc;
use sqlx::{MySql, QueryBuilder};

use crate::ResponseState;
use crate::copilot_action::collect::{CollectBody, run_artifact_collection};
use crate::copilot_action::schema::{COLLECT_ARTIFACT_RESPONSE, INVOKE_RESPONSE};

/// `select(Agents).filter(Agents.hostname.in_(hostnames))` — narrowed to
/// `customers` for a scoped caller (§4: a hostname is no tenant key, and
/// Python ran the action on every agent of that name, another tenant's
/// included).
pub async fn agents_by_hostnames(
    db: &Db,
    hostnames: &[String],
    customers: Option<&[String]>,
) -> Result<Vec<AgentRecord>, PyExc> {
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {AGENT_COLS} FROM agents WHERE agents.hostname IN ("
    ));
    let mut sep = qb.separated(", ");
    for h in hostnames {
        sep.push_bind(h.clone());
    }
    qb.push(")");
    let rows: Vec<AgentRecord> = qb
        .build_query_as::<AgentRecord>()
        .fetch_all(db.pool())
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
    let found: Vec<&str> = rows.iter().map(|a| a.hostname.as_str()).collect();
    let mut missing: Vec<&String> = Vec::new();
    for h in hostnames {
        if !found.contains(&h.as_str()) && !missing.contains(&h) {
            missing.push(h);
        }
    }
    if !missing.is_empty() {
        let list: Vec<String> = missing.iter().map(|h| str_repr(h)).collect();
        return Err(PyExc::http(
            404,
            format!("Agents with hostnames [{}] not found", list.join(", ")),
        ));
    }
    Ok(match customers {
        None => rows,
        Some(codes) => rows
            .into_iter()
            .filter(|a| a.customer_code.as_ref().is_some_and(|c| codes.contains(c)))
            .collect(),
    })
}

/// `determine_artifact_name(os)`.
fn artifact_for(os: &str) -> Result<&'static str, PyExc> {
    if os.contains("Windows") {
        Ok("Windows.Execute.RemotePowerShellScript")
    } else if os.contains("Linux")
        || ["Ubuntu", "Debian", "CentOS", "Red Hat"]
            .iter()
            .any(|d| os.contains(d))
    {
        Ok("Linux.Execute.RemoteBashScript")
    } else {
        Err(PyExc::http(400, format!("Unsupported OS: {os}")))
    }
}

/// `str(param_value)`: a string as it is, a `ParameterKeyValue` list as
/// its `repr`.
fn value_text(v: &PyValue) -> String {
    match v {
        PyValue::Str(s) => s.clone(),
        PyValue::List(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|i| {
                    format!(
                        "ParameterKeyValue(key={}, value={})",
                        str_repr(field(i, "key").as_str().unwrap_or_default()),
                        str_repr(field(i, "value").as_str().unwrap_or_default())
                    )
                })
                .collect();
            format!("[{}]", parts.join(", "))
        }
        other => other.py_str(),
    }
}

/// One `ScriptParameter`'s name, required flag and `arg_position`.
struct ScriptParam {
    name: String,
    required: bool,
    arg_position: Option<String>,
}

fn script_params(action: &PyValue) -> Vec<ScriptParam> {
    match field(action, "script_parameters") {
        PyValue::List(items) => items
            .iter()
            .map(|p| ScriptParam {
                name: field(p, "name").as_str().unwrap_or_default().to_string(),
                required: matches!(field(p, "required"), PyValue::Bool(true)),
                arg_position: field(p, "arg_position").as_str().map(str::to_string),
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Python's `list(set)`: here in a fixed order (§4: Python's follows the
/// strings' hashes).
fn list_repr(names: &[String]) -> String {
    let parts: Vec<String> = names.iter().map(|n| str_repr(n)).collect();
    format!("[{}]", parts.join(", "))
}

/// `validate_parameters(provided, script_params)`.
fn validate_parameters(
    provided: &[(String, PyValue)],
    params: &[ScriptParam],
) -> Result<(), PyExc> {
    let mut valid: Vec<String> = Vec::new();
    for p in params {
        if !valid.contains(&p.name) {
            valid.push(p.name.clone());
        }
    }
    let mut required: Vec<String> = params
        .iter()
        .filter(|p| p.required)
        .map(|p| p.name.clone())
        .collect();
    if !required.iter().any(|r| r == "ScriptURL") {
        required.push("ScriptURL".into());
    }
    if !valid.iter().any(|v| v == "ScriptURL") {
        valid.push("ScriptURL".into());
    }
    let mut invalid: Vec<String> = Vec::new();
    for (k, _) in provided {
        if !valid.contains(k) && !invalid.contains(k) {
            invalid.push(k.clone());
        }
    }
    if !invalid.is_empty() {
        return Err(PyExc::http(
            400,
            format!(
                "Invalid parameters provided: {}. Valid parameters are: {}",
                list_repr(&invalid),
                list_repr(&valid)
            ),
        ));
    }
    let mut missing: Vec<String> = Vec::new();
    for r in required {
        if !provided.iter().any(|(k, _)| *k == r) && !missing.contains(&r) {
            missing.push(r);
        }
    }
    if !missing.is_empty() {
        return Err(PyExc::http(
            400,
            format!("Missing required parameters: {}", list_repr(&missing)),
        ));
    }
    Ok(())
}

/// `build_velociraptor_parameters(params, script_params)["env"]`.
fn env_of(provided: &[(String, PyValue)], params: &[ScriptParam]) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Some((_, url)) = provided.iter().find(|(k, _)| k == "ScriptURL") {
        env.push(("ScriptURL".to_string(), value_text(url)));
    }
    // `param_position_map`: the last parameter of a name wins.
    let position = |name: &str| {
        params
            .iter()
            .rev()
            .find(|p| p.name == name && p.arg_position.is_some())
            .and_then(|p| p.arg_position.clone())
    };
    for (k, v) in provided {
        if let Some(pos) = position(k) {
            env.push((format!("Arg{pos}"), value_text(v)));
        }
    }
    for (k, v) in provided {
        if position(k).is_none() && k != "ScriptURL" {
            env.push((k.clone(), value_text(v)));
        }
    }
    env
}

fn failed_response(message: String) -> PyValue {
    construct(
        &COLLECT_ARTIFACT_RESPONSE,
        &kwargs(vec![
            ("message", PyValue::Str(message)),
            ("success", PyValue::Bool(false)),
            ("results", PyValue::List(Vec::new())),
        ]),
    )
    .unwrap_or(PyValue::None)
}

/// The invoke after its tenant checks and audit row: the
/// `InvokeCopilotActionResponse` dump, or what Python raises.
pub async fn invoke(
    st: &ResponseState,
    action: &PyValue,
    agents: Vec<AgentRecord>,
    parameters: Vec<(String, PyValue)>,
) -> Result<PyValue, PyExc> {
    let item = field(action, "copilot_action");
    let mut provided = parameters;
    if let Some(url) = field(item, "repo_url").as_str().filter(|u| !u.is_empty()) {
        match provided.iter_mut().find(|(k, _)| k == "ScriptURL") {
            Some(slot) => slot.1 = PyValue::Str(url.to_string()),
            None => provided.push(("ScriptURL".into(), PyValue::Str(url.to_string()))),
        }
    }
    let params = script_params(item);
    validate_parameters(&provided, &params)?;
    let mut responses = Vec::new();
    let (mut ok, mut failed) = (0usize, 0usize);
    for agent in &agents {
        let outcome = async {
            let artifact = artifact_for(&agent.os)?;
            let body = CollectBody {
                hostname: agent.hostname.clone(),
                velociraptor_id: agent.velociraptor_id.clone(),
                velociraptor_org: agent.velociraptor_org.clone(),
                artifact_name: artifact.to_string(),
                env: env_of(&provided, &params),
            };
            run_artifact_collection(&st.velociraptor, &st.ctx.db, &st.store, &body).await
        }
        .await
        .map_err(|e| {
            PyExc::http(
                500,
                format!(
                    "Error invoking action on agent {}: {}",
                    agent.hostname,
                    e.display()
                ),
            )
        });
        match outcome {
            Ok(dump) => {
                tracing::info!("Successfully invoked Copilot action on {}", agent.hostname);
                responses.push(dump);
                ok += 1;
            }
            Err(e) => {
                tracing::error!(
                    "Failed to invoke action on agent {}: {}",
                    agent.hostname,
                    e.display()
                );
                responses.push(failed_response(format!(
                    "Failed to invoke action on {}: {}",
                    agent.hostname,
                    e.display()
                )));
                failed += 1;
            }
        }
    }
    let (message, success) = if failed == 0 {
        (
            format!(
                "Successfully invoked action on all {ok} agent(s). Check the appropriate Grafana \
                 dashboard for results."
            ),
            true,
        )
    } else if ok == 0 {
        (
            format!("Failed to invoke action on all {failed} agent(s)"),
            false,
        )
    } else {
        (
            format!("Partially successful: {ok} succeeded, {failed} failed"),
            true,
        )
    };
    construct(
        &INVOKE_RESPONSE,
        &kwargs(vec![
            ("responses", PyValue::List(responses)),
            ("message", PyValue::Str(message)),
            ("success", PyValue::Bool(success)),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(name: &str, required: bool, pos: Option<&str>) -> ScriptParam {
        ScriptParam {
            name: name.into(),
            required,
            arg_position: pos.map(str::to_string),
        }
    }

    fn s(v: &str) -> PyValue {
        PyValue::Str(v.into())
    }

    #[test]
    fn parameters_are_checked_like_python() {
        let params = [param("Target", true, Some("1")), param("Mode", false, None)];
        let url = ("ScriptURL".to_string(), s("https://x/a.sh"));
        assert!(validate_parameters(&[url.clone(), ("Target".into(), s("a"))], &params).is_ok());
        assert_eq!(
            validate_parameters(&[url.clone(), ("Other".into(), s("a"))], &params)
                .unwrap_err()
                .display(),
            "400: Invalid parameters provided: ['Other']. Valid parameters are: ['Target', \
             'Mode', 'ScriptURL']"
        );
        assert_eq!(
            validate_parameters(&[url], &params).unwrap_err().display(),
            "400: Missing required parameters: ['Target']"
        );
    }

    #[test]
    fn the_env_puts_the_url_first_then_positions_then_the_rest() {
        let params = [
            param("Target", true, Some("1")),
            param("Target", true, Some("2")),
            param("Mode", false, None),
        ];
        let provided = vec![
            ("Mode".to_string(), s("fast")),
            ("Target".into(), s("a")),
            ("ScriptURL".into(), s("https://x/a.sh")),
        ];
        assert_eq!(
            env_of(&provided, &params),
            vec![
                ("ScriptURL".to_string(), "https://x/a.sh".to_string()),
                ("Arg2".into(), "a".into()),
                ("Mode".into(), "fast".into()),
            ]
        );
        let pairs = PyValue::List(vec![PyValue::Dict(vec![
            ("key".into(), s("k")),
            ("value".into(), s("it's")),
        ])]);
        assert_eq!(
            value_text(&pairs),
            "[ParameterKeyValue(key='k', value=\"it's\")]"
        );
    }
}
