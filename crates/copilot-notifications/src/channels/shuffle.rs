//! Shuffle's hosted MCP (`channels/shuffle.py`, `dispatch_shuffle`, the app,
//! org and verify lookups). Shuffle is called with `verify=False`, as the
//! legacy Shuffle connector always has (#1087).

use std::time::Instant;

use copilot_auth::pyvalue::PyValue;
use copilot_jinja::Event;

use crate::channels::Channel;
use crate::channels::send::{
    Credentials, FAILED, SENT, SendResult, Unavailable, cfg_str, connector_credentials, elapsed_ms,
    first_200, header_map, parse_config, response_json, response_text, secs, transport_error,
};
use crate::db::{self, RouteRow};
use crate::dispatcher::Dispatcher;
use crate::pydantic;
use crate::pyjson::{self, Dumps};
use crate::services::memo::Memo;
use crate::services::render::Rendered;

const TIMEOUT_S: u64 = 30;

async fn credentials(d: &Dispatcher, memo: &mut Memo) -> Result<Credentials, SendResult> {
    if let Some(c) = &memo.shuffle {
        return Ok(c.clone());
    }
    match connector_credentials(d.connectors(), Channel::Shuffle).await {
        Ok(Ok(c)) => {
            memo.shuffle = Some(c.clone());
            Ok(c)
        }
        Ok(Err(Unavailable(detail))) => {
            tracing::warn!("Shuffle connector unavailable: {detail}");
            Err(SendResult::failed(if detail.is_empty() {
                "Shuffle connector unavailable".to_string()
            } else {
                detail
            }))
        }
        Err(e) => Err(SendResult::raised("OperationalError", e)),
    }
}

/// `ShuffleChannel.send`.
pub async fn send(
    d: &Dispatcher,
    route: &RouteRow,
    e: &Event,
    message: &Rendered,
    memo: &mut Memo,
) -> SendResult {
    let cfg = match parse_config(Channel::Shuffle, route) {
        Ok(c) => c,
        Err(err) => return SendResult::failed(format!("Invalid shuffle config: {err}")),
    };
    let app_id = cfg_str(&cfg, "app_id");
    let creds = match credentials(d, memo).await {
        Ok(c) => c,
        Err(outcome) => return outcome,
    };
    let Some(app_id) = app_id.filter(|a| !a.is_empty()) else {
        return SendResult::failed("Route config has no app_id (data integrity issue)");
    };
    let integration = match route.shuffle_integration_id {
        Some(id) => match db::integration(d.db(), i64::from(id)).await {
            Ok(i) => i,
            Err(err) => {
                return SendResult::raised("OperationalError", err);
            }
        },
        None => None,
    };
    let Some(integration) =
        integration.filter(|i| Some(i.customer_code.as_str()) == e.customer_code.as_deref())
    else {
        return SendResult::failed(
            "Route's shuffle_integration is missing or belongs to a different customer; refusing \
             to dispatch.",
        );
    };
    if !integration.enabled {
        return SendResult::skipped("Shuffle integration is disabled");
    }
    let input_text = match route.destination.as_deref().filter(|d| !d.is_empty()) {
        Some(dest) => format!("Send to {dest}: {}", message.body),
        None => message.body.clone(),
    };
    dispatch(d, &creds, &integration.shuffle_org_id, &app_id, &input_text).await
}

fn headers(api_key: &str, org_id: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Authorization", format!("Bearer {api_key}")),
        ("Org-Id", org_id.to_string()),
        ("Content-Type", "application/json".into()),
        ("Accept", "application/json".into()),
    ]
}

/// `dispatch_shuffle`.
async fn dispatch(
    d: &Dispatcher,
    creds: &Credentials,
    org_id: &str,
    app_id: &str,
    input_text: &str,
) -> SendResult {
    let url = format!(
        "{}/api/v1/apps/{app_id}/mcp",
        creds.base_url.trim_end_matches('/')
    );
    let s = |v: &str| PyValue::Str(v.to_string());
    let body = PyValue::Dict(vec![
        ("jsonrpc".into(), s("2.0")),
        ("id".into(), s("1")),
        ("method".into(), s("tools/call")),
        (
            "params".into(),
            PyValue::Dict(vec![
                ("tool_id".into(), s(app_id)),
                ("tool_name".into(), s(app_id)),
                (
                    "input".into(),
                    PyValue::Dict(vec![("text".into(), s(input_text))]),
                ),
                ("environment".into(), s("Shuffle")),
            ]),
        ),
    ]);
    tracing::info!("Dispatching payload to Shuffle body: {}", body.py_repr());
    let started = Instant::now();
    let header_map = match header_map(&headers(&creds.api_key, org_id)) {
        Ok(h) => h,
        Err(err) => return SendResult::from_parts(FAILED, Some(err), elapsed_ms(started), None),
    };
    let req = d
        .outbound()
        .shuffle
        .post(&url)
        .timeout(secs(TIMEOUT_S))
        .headers(header_map)
        .body(pyjson::dumps(&body, Dumps::HTTPX).unwrap_or_default());
    let resp = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(err = %err, "Shuffle dispatch failed");
            return SendResult::from_parts(
                FAILED,
                Some(transport_error(&err)),
                elapsed_ms(started),
                None,
            );
        }
    };
    let status = resp.status().as_u16();
    let text = response_text(resp).await;
    let latency = elapsed_ms(started);
    if status == 401 || status == 403 {
        return SendResult::from_parts(
            FAILED,
            Some(format!(
                "Shuffle authentication failed ({status}): {}",
                first_200(&text)
            )),
            latency,
            None,
        );
    }
    if status >= 400 {
        return SendResult::from_parts(
            FAILED,
            Some(format!("Shuffle returned {status}: {}", first_200(&text))),
            latency,
            None,
        );
    }
    let Some(data) = response_json(&text) else {
        return SendResult::from_parts(
            FAILED,
            Some("Shuffle returned non-JSON response".into()),
            latency,
            None,
        );
    };
    let execution_id = data
        .get("execution_id")
        .and_then(PyValue::as_str)
        .map(str::to_string);
    if let (PyValue::Dict(_), Some(PyValue::Bool(false))) = (&data, data.get("success")) {
        let why = data
            .get("reason")
            .filter(|v| v.truthy())
            .or_else(|| data.get("error").filter(|v| v.truthy()))
            .map_or_else(|| data.py_str(), PyValue::py_str);
        return SendResult::from_parts(
            FAILED,
            Some(format!("Shuffle reported failure: {why}")),
            latency,
            execution_id,
        );
    }
    SendResult::from_parts(SENT, None, latency, execution_id)
}

/// A Shuffle list lookup (`list_shuffle_apps` / `list_shuffle_orgs`):
/// `Ok(items)` or the error text.
async fn list(
    d: &Dispatcher,
    creds: &Credentials,
    path: &str,
    org_id: Option<&str>,
) -> Result<Vec<PyValue>, String> {
    let url = format!("{}{path}", creds.base_url.trim_end_matches('/'));
    let pairs: Vec<(&str, String)> = match org_id {
        Some(org) => headers(&creds.api_key, org),
        None => vec![
            ("Authorization", format!("Bearer {}", creds.api_key)),
            ("Accept", "application/json".into()),
        ],
    };
    let req = d
        .outbound()
        .shuffle
        .get(&url)
        .timeout(secs(TIMEOUT_S))
        .headers(header_map(&pairs)?);
    let resp = req.send().await.map_err(|e| {
        tracing::warn!(err = %e, "Shuffle list failed");
        transport_error(&e)
    })?;
    let status = resp.status().as_u16();
    let text = response_text(resp).await;
    if status == 401 || status == 403 {
        return Err(format!("Shuffle authentication failed ({status})"));
    }
    if status >= 400 {
        return Err(format!("Shuffle returned {status}: {}", first_200(&text)));
    }
    let mut data = response_json(&text).ok_or("Shuffle returned non-JSON response")?;
    if org_id.is_none() {
        if let PyValue::Dict(items) = &data {
            if let Some((_, orgs)) = items.iter().find(|(k, _)| k == "orgs") {
                data = if orgs.truthy() {
                    orgs.clone()
                } else {
                    PyValue::List(Vec::new())
                };
            }
        }
    }
    match data {
        PyValue::List(items) => Ok(items),
        other => Err(format!(
            "Unexpected Shuffle response shape: {}",
            pydantic::input_type(&other)
        )),
    }
}

/// `list_shuffle_apps`.
pub async fn list_apps(
    d: &Dispatcher,
    creds: &Credentials,
    org_id: &str,
) -> Result<Vec<PyValue>, String> {
    list(d, creds, "/api/v1/apps", Some(org_id)).await
}

/// `list_shuffle_orgs`.
pub async fn list_orgs(d: &Dispatcher, creds: &Credentials) -> Result<Vec<PyValue>, String> {
    list(d, creds, "/api/v1/orgs", None).await
}
