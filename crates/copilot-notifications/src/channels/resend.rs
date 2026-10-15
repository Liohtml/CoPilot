//! Email through Resend (`channels/resend.py`, `dispatch_resend`).

use std::time::Instant;

use copilot_auth::pyvalue::PyValue;
use copilot_jinja::Event;

use crate::channels::Channel;
use crate::channels::send::{
    Credentials, FAILED, SENT, SendResult, Unavailable, cfg_str, connector_credentials, elapsed_ms,
    first_200, header_map, no_get, parse_config, response_json, response_text, secs,
    transport_error,
};
use crate::db::{self, RouteRow};
use crate::dispatcher::Dispatcher;
use crate::event::py_strip;
use crate::pyjson::{self, Dumps};
use crate::services::memo::Memo;
use crate::services::render::Rendered;

/// `FREE_TIER_MONTHLY_LIMIT`.
pub const FREE_TIER_MONTHLY_LIMIT: i64 = 1000;

const TIMEOUT_S: u64 = 15;

fn str_list(cfg: &PyValue, key: &str) -> Vec<String> {
    match cfg.get(key) {
        Some(PyValue::List(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// `_subject(cfg, event, override=…)`.
pub fn subject(prefix: &str, e: &Event, override_subject: Option<&str>) -> String {
    let prefix = py_strip(prefix);
    let composed;
    let core_source = match override_subject.filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => {
            composed = format!("{}: {}", e.severity, e.subject);
            &composed
        }
    };
    let core = py_strip(core_source);
    if prefix.is_empty() {
        core.to_string()
    } else {
        py_strip(&format!("{prefix} {core}")).to_string()
    }
}

async fn credentials(d: &Dispatcher, memo: &mut Memo) -> Result<Credentials, SendResult> {
    if let Some(c) = &memo.resend {
        return Ok(c.clone());
    }
    match connector_credentials(d.connectors(), Channel::Resend).await {
        Ok(Ok(c)) => {
            memo.resend = Some(c.clone());
            Ok(c)
        }
        Ok(Err(Unavailable(detail))) => {
            tracing::warn!("Resend connector unavailable: {detail}");
            Err(SendResult::failed(if detail.is_empty() {
                "Resend connector unavailable".to_string()
            } else {
                detail
            }))
        }
        Err(e) => Err(SendResult::raised("OperationalError", e)),
    }
}

/// `_resolve_recipients`: the addresses, or the outcome that ends the send.
async fn recipients(
    d: &Dispatcher,
    mode: &str,
    cfg: &PyValue,
    e: &Event,
) -> Result<Vec<String>, SendResult> {
    if mode != "assignee" {
        return Ok(str_list(cfg, "to"));
    }
    let Some(username) = e.assignee_username.as_deref().filter(|u| !u.is_empty()) else {
        return Err(SendResult::skipped(
            "Route delivers to the assignee, but this event has no assignee.",
        ));
    };
    // `find_user` swallows a database error and answers None.
    let user = copilot_db::users::find_by_username(d.db(), username)
        .await
        .unwrap_or(None);
    let Some(user) = user else {
        return Err(SendResult::failed(format!(
            "Assignee '{username}' not found; cannot resolve an email address."
        )));
    };
    if user.email.is_empty() {
        return Err(SendResult::failed(format!(
            "Assignee '{username}' has no email address on their account."
        )));
    }
    Ok(vec![user.email])
}

/// `ResendChannel.send`.
pub async fn send(
    d: &Dispatcher,
    route: &RouteRow,
    e: &Event,
    message: &Rendered,
    memo: &mut Memo,
) -> SendResult {
    let cfg = match parse_config(Channel::Resend, route) {
        Ok(c) => c,
        Err(err) => return SendResult::failed(format!("Invalid resend config: {err}")),
    };
    let creds = match credentials(d, memo).await {
        Ok(c) => c,
        Err(outcome) => return outcome,
    };
    let Some(from) = cfg_str(&cfg, "from_address")
        .filter(|f| !f.is_empty())
        .or_else(|| creds.default_from.clone())
    else {
        return SendResult::failed(
            "No From address: set RESEND_FROM_ADDRESS on the connector or from_address on the \
             route.",
        );
    };
    let to = match recipients(d, &route.recipient_mode, &cfg, e).await {
        Ok(to) => to,
        Err(outcome) => return outcome,
    };
    if to.is_empty() {
        return SendResult::failed("No recipients resolved for this route.");
    }
    if let Some(PyValue::Int(max)) = cfg.get("max_per_hour") {
        if max != "0" {
            let since = copilot_core::time::now_utc_micros() - chrono::Duration::hours(1);
            let recent = match db::sends_since(d.db(), i64::from(route.id), since).await {
                Ok(n) => n,
                Err(err) => return SendResult::raised("OperationalError", err),
            };
            let limit: i128 = max.parse().unwrap_or(i128::MAX);
            if i128::from(recent) >= limit {
                return SendResult::skipped(format!(
                    "Rate limit reached for this route ({recent}/{max} in the last hour)."
                ));
            }
        }
    }
    let prefix = cfg_str(&cfg, "subject_prefix").unwrap_or_default();
    let subject = subject(&prefix, e, message.subject.as_deref());
    let html = match message.format.as_str() {
        "html" => Some(message.body.clone()),
        "markdown" => match copilot_markdown::markdown_to_html(&message.body) {
            Ok(h) => Some(h),
            Err(err) => return SendResult::raised(copilot_markdown::Error::TYPE_NAME, err),
        },
        _ => None,
    }
    .filter(|h| !h.is_empty());
    let cc = str_list(&cfg, "cc");
    let reply_to = cfg_str(&cfg, "reply_to").filter(|r| !r.is_empty());
    dispatch(
        &d.outbound().http,
        &creds,
        &from,
        &to,
        &subject,
        &message.body,
        html,
        cc,
        reply_to,
    )
    .await
}

/// `dispatch_resend`.
#[allow(clippy::too_many_arguments)]
async fn dispatch(
    http: &reqwest::Client,
    creds: &Credentials,
    from: &str,
    to: &[String],
    subject: &str,
    text: &str,
    html: Option<String>,
    cc: Vec<String>,
    reply_to: Option<String>,
) -> SendResult {
    let strs = |v: &[String]| PyValue::List(v.iter().map(|s| PyValue::Str(s.clone())).collect());
    let mut payload = vec![
        ("from".to_string(), PyValue::Str(from.to_string())),
        ("to".to_string(), strs(to)),
        ("subject".to_string(), PyValue::Str(subject.to_string())),
        ("text".to_string(), PyValue::Str(text.to_string())),
    ];
    if let Some(h) = html {
        payload.push(("html".into(), PyValue::Str(h)));
    }
    if !cc.is_empty() {
        payload.push(("cc".into(), strs(&cc)));
    }
    if let Some(r) = reply_to {
        payload.push(("reply_to".into(), PyValue::Str(r)));
    }
    let body = pyjson::dumps(&PyValue::Dict(payload), Dumps::HTTPX).unwrap_or_default();
    let started = Instant::now();
    let url = format!("{}/emails", creds.base_url.trim_end_matches('/'));
    let headers = match header_map(&[
        ("Authorization", format!("Bearer {}", creds.api_key)),
        ("Content-Type", "application/json".to_string()),
    ]) {
        Ok(h) => h,
        Err(err) => return SendResult::from_parts(FAILED, Some(err), elapsed_ms(started), None),
    };
    let result = http
        .post(&url)
        .timeout(secs(TIMEOUT_S))
        .headers(headers)
        .body(body)
        .send()
        .await;
    let resp = match result {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(err = %err, "Resend dispatch failed");
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
    if status >= 400 {
        let mut detail = first_200(&text);
        if let Some(parsed) = response_json(&text) {
            let PyValue::Dict(_) = parsed else {
                return SendResult::from_parts(FAILED, Some(no_get(&parsed)), latency, None);
            };
            let pick = |k: &str| parsed.get(k).filter(|v| v.truthy()).map(PyValue::py_str);
            if let Some(d) = pick("message").or_else(|| pick("error")) {
                detail = d;
            }
        }
        return SendResult::from_parts(
            FAILED,
            Some(format!("Resend returned {status}: {detail}")),
            latency,
            None,
        );
    }
    let message_id = match response_json(&text) {
        None => None,
        Some(v @ PyValue::Dict(_)) => v.get("id").and_then(PyValue::as_str).map(str::to_string),
        Some(other) => {
            return SendResult::from_parts(FAILED, Some(no_get(&other)), latency, None);
        }
    };
    SendResult::from_parts(SENT, None, latency, message_id)
}
