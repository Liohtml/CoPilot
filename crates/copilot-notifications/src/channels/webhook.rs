//! Direct HTTP webhook delivery (`channels/webhook.py`,
//! `dispatchers.dispatch_webhook`). The structured payload is an external
//! contract: its keys, order and `None`-vs-`""` semantics are Python's.

use std::time::Instant;

use copilot_auth::pyvalue::{self, PyValue};
use copilot_jinja::Event;

use crate::channels::Channel;
use crate::channels::send::{
    FAILED, SENT, SendResult, cfg_str, dict_set, elapsed_ms, first_200, header_map, parse_config,
    response_text, secs, transport_error,
};
use crate::db::RouteRow;
use crate::dispatcher::Dispatcher;
use crate::event::ctx_get;
use crate::pyjson::{self, Dumps};
use crate::services::ai_report;
use crate::services::memo::Memo;
use crate::services::render::Rendered;

/// `_WEBHOOK_TIMEOUT_S`.
const TIMEOUT_S: u64 = 15;

/// A template value as the JSON Python would send.
pub fn input_to_py(v: &copilot_jinja::Input) -> PyValue {
    use copilot_jinja::Input;
    match v {
        Input::None => PyValue::None,
        Input::Bool(b) => PyValue::Bool(*b),
        Input::Int(i) => PyValue::Int(i.to_string()),
        Input::Float(f) => PyValue::Float(*f),
        Input::Str(s) | Input::Markup(s) => PyValue::Str(s.clone()),
        Input::List(items) => PyValue::List(items.iter().map(input_to_py).collect()),
        Input::Dict(items) => PyValue::Dict(
            items
                .iter()
                .map(|(k, v)| (k.clone(), input_to_py(v)))
                .collect(),
        ),
    }
}

fn opt(v: Option<&str>) -> PyValue {
    v.map_or(PyValue::None, |s| PyValue::Str(s.to_string()))
}

/// The memoized `build_full_report`.
async fn report(d: &Dispatcher, e: &Event, memo: &mut Memo) -> Result<Option<PyValue>, SendResult> {
    if let Some(r) = memo.full_report.get(&e.entity_id) {
        return Ok(r.clone());
    }
    let r = ai_report::full_report(d.db(), e.entity_id)
        .await
        .map_err(|err| SendResult::raised("OperationalError", err))?;
    memo.full_report.insert(e.entity_id, r.clone());
    Ok(r)
}

/// `WebhookChannel.send`.
pub async fn send(
    d: &Dispatcher,
    route: &RouteRow,
    e: &Event,
    message: &Rendered,
    memo: &mut Memo,
) -> SendResult {
    let has_template = message.is_custom;
    let cfg = match parse_config(Channel::Webhook, route) {
        Ok(c) => c,
        Err(err) => return SendResult::failed(format!("Invalid webhook config: {err}")),
    };
    let Some(url) = cfg_str(&cfg, "url").filter(|u| !u.is_empty()) else {
        return SendResult::failed("Route config has no url (data integrity issue)");
    };
    let method = cfg_str(&cfg, "method").unwrap_or_else(|| "POST".into());
    let headers: Vec<(String, String)> = match cfg.get("headers") {
        Some(PyValue::Dict(items)) => items
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
            .collect(),
        _ => Vec::new(),
    };
    let include_full_report = matches!(cfg.get("include_full_report"), Some(PyValue::Bool(true)));

    let mut payload: Vec<(String, PyValue)> = vec![
        ("customer_code".into(), opt(e.customer_code.as_deref())),
        ("alert_id".into(), PyValue::Int(e.entity_id.to_string())),
        (
            "alert_name".into(),
            ctx_get(e, "alert_name").map_or(PyValue::None, input_to_py),
        ),
        ("severity".into(), PyValue::Str(e.severity.clone())),
        ("summary".into(), PyValue::Str(e.summary.clone())),
        ("report_url".into(), opt(e.link_url.as_deref())),
        ("text".into(), PyValue::Str(message.body.clone())),
    ];
    let mut rendered_template: Option<String> = None;
    if include_full_report {
        match report(d, e, memo).await {
            Ok(Some(PyValue::Dict(fields))) => {
                for (k, v) in fields {
                    match payload.iter_mut().find(|(pk, _)| *pk == k) {
                        Some((_, pv)) => *pv = v,
                        None => payload.push((k, v)),
                    }
                }
            }
            Ok(_) => {}
            Err(raised) => return raised,
        }
    } else if has_template {
        let mut body = message.body.clone();
        if body.contains("{{report}}") {
            let fields = match report(d, e, memo).await {
                Ok(f) => f,
                Err(raised) => return raised,
            };
            let json = match &fields {
                Some(f) => pyjson::dumps(f, Dumps::DEFAULT).unwrap_or_default(),
                None => "null".into(),
            };
            body = body.replace("{{report}}", &json);
        }
        rendered_template = Some(body);
    }
    dispatch(
        d,
        &url,
        &method,
        &headers,
        PyValue::Dict(payload),
        rendered_template,
    )
    .await
}

/// `dispatch_webhook`.
async fn dispatch(
    d: &Dispatcher,
    url: &str,
    method: &str,
    headers: &[(String, String)],
    structured: PyValue,
    rendered_template: Option<String>,
) -> SendResult {
    let method = method.to_uppercase();
    if method != "POST" && method != "PUT" {
        return SendResult::from_parts(
            FAILED,
            Some(format!("Unsupported webhook method: {method}")),
            0,
            None,
        );
    }
    let mut request_headers: Vec<(String, String)> =
        vec![("Accept".into(), "application/json".into())];
    let json_body: Option<PyValue>;
    let mut content: Option<String> = None;
    match rendered_template {
        Some(template) => {
            json_body = match pyvalue::loads(&template) {
                Ok(v @ (PyValue::Dict(_) | PyValue::List(_))) => Some(v),
                _ => None,
            };
            if json_body.is_none() {
                content = Some(template);
                request_headers.push(("Content-Type".into(), "text/plain; charset=utf-8".into()));
            } else {
                request_headers.push(("Content-Type".into(), "application/json".into()));
            }
        }
        None => {
            json_body = Some(structured);
            request_headers.push(("Content-Type".into(), "application/json".into()));
        }
    }
    for (k, v) in headers {
        dict_set(&mut request_headers, k, v);
    }
    let started = Instant::now();
    let body = match (&json_body, content) {
        (Some(json), _) => match pyjson::dumps(json, Dumps::HTTPX) {
            Ok(b) => b,
            Err(err) => {
                return SendResult::from_parts(
                    FAILED,
                    Some(format!("ValueError: {err}")),
                    elapsed_ms(started),
                    None,
                );
            }
        },
        (None, Some(text)) => text,
        (None, None) => String::new(),
    };
    let header_map = match header_map(&request_headers) {
        Ok(h) => h,
        Err(err) => return SendResult::from_parts(FAILED, Some(err), elapsed_ms(started), None),
    };
    let request = d
        .outbound()
        .http
        .request(
            if method == "PUT" {
                reqwest::Method::PUT
            } else {
                reqwest::Method::POST
            },
            url,
        )
        .timeout(secs(TIMEOUT_S))
        .headers(header_map)
        .body(body);
    match request.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = response_text(resp).await;
            let latency = elapsed_ms(started);
            if status >= 400 {
                SendResult::from_parts(
                    FAILED,
                    Some(format!("Webhook returned {status}: {}", first_200(&text))),
                    latency,
                    None,
                )
            } else {
                SendResult::from_parts(SENT, None, latency, None)
            }
        }
        Err(err) => {
            tracing::warn!(err = %err, "Webhook dispatch failed");
            SendResult::from_parts(
                FAILED,
                Some(transport_error(&err)),
                elapsed_ms(started),
                None,
            )
        }
    }
}
