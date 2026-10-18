//! What the active-response routes send to the Wazuh manager:
//! `send_put_request("/active-response", data=json.dumps(…), params=…)`
//! through the manager client (`copilot_wazuh::manager::client::send_put`).
//!
//! The body is a pre-serialized `json.dumps` string, as the Python routes
//! pass it (the `send_put_request` footgun: a dict would be form-encoded).
//! `requests` encodes a list parameter as one pair per item and drops an
//! empty list entirely, so `agents_list=[]` sends no `agents_list` at all —
//! which Wazuh reads as every agent, the reason the invoke route refuses it
//! to a scoped caller.

use serde_json::Value;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_wazuh::WazuhState;
use copilot_wazuh::error::PyErr;
use copilot_wazuh::manager::client::{Body, Param, PutKind, send_put};

use crate::active_response::schema::{EventFields, InvokeRequest};

/// The Wazuh endpoint both routes call.
pub const ENDPOINT: &str = "/active-response";

fn dumps(value: &PyValue) -> Result<String, PyErr> {
    py_dumps(value, Dumps::DEFAULT).map_err(|e| PyErr::Other(e.to_string()))
}

/// `invoke_active_response_route`'s request: `{"command": f"{command}0",
/// "arguments": …, "alert": …}`, `params` the `ParamsModel` dump (`None`
/// excluded) with `wait_for_complete` as `"true"`/`"false"`.
pub async fn invoke(st: &WazuhState, req: &InvokeRequest) -> Result<Value, PyErr> {
    let data = PyValue::Dict(vec![
        ("command".into(), PyValue::Str(format!("{}0", req.command))),
        (
            "arguments".into(),
            PyValue::List(req.arguments.iter().cloned().map(PyValue::Str).collect()),
        ),
        ("alert".into(), req.alert.clone()),
    ]);
    let mut params = vec![(
        "wait_for_complete".to_string(),
        Param::Str(
            if req.wait_for_complete {
                "true"
            } else {
                "false"
            }
            .into(),
        ),
    )];
    for agent in req.agents_list.iter().flatten() {
        params.push(("agents_list".into(), Param::Str(agent.clone())));
    }
    send_put(
        st,
        ENDPOINT,
        Some(Body::Text(dumps(&data)?)),
        Some(&params),
        PutKind::Json,
    )
    .await
}

/// `invoke_active_response_graylog_route`'s request; its answer is ignored
/// by the route.
pub async fn invoke_from_graylog(st: &WazuhState, fields: &EventFields) -> Result<Value, PyErr> {
    let data = PyValue::Dict(vec![
        (
            "command".into(),
            PyValue::Str(format!("{}0", fields.command)),
        ),
        ("arguments".into(), PyValue::List(Vec::new())),
        (
            "alert".into(),
            PyValue::Dict(vec![
                ("action".into(), PyValue::Str(fields.action.clone())),
                ("value".into(), PyValue::Str(fields.value.clone())),
            ]),
        ),
    ]);
    let params = vec![
        ("wait_for_complete".to_string(), Param::Bool(true)),
        (
            "agents_list".to_string(),
            Param::Str(fields.agent_id.clone()),
        ),
    ];
    send_put(
        st,
        ENDPOINT,
        Some(Body::Text(dumps(&data)?)),
        Some(&params),
        PutKind::Json,
    )
    .await
}
