//! `verify_resend_connection(name)`: no row is the failure naming it; no
//! key the failure asking for one; else `GET {url or api.resend.com}/domains`
//! as httpx 0.28 sends it (`copilot_threat_intel::httpx`, 15 s) with the
//! bearer key. A 200 reports the verified sending domains (the first three),
//! Resend's `restricted_api_key` refusal is a success (a send-only key), any
//! other answer names its status and message. Python's `AttributeError` on
//! an answer that is not an object (outside its `except ValueError`) is no
//! outcome.

use std::time::Duration;

use async_trait::async_trait;
use http::Method;

use copilot_auth::pyvalue::{PyValue, loads_bytes};
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_threat_intel::httpx;

use crate::outcome;

/// `_VERIFY_TIMEOUT_S`.
const TIMEOUT: Duration = Duration::from_secs(15);

/// The Resend verifier.
#[derive(Debug, Clone, Copy)]
pub struct ResendVerifier;

/// `value.get(key, default)` on a dict; `None` (Python's `AttributeError`)
/// on anything else.
fn get<'a>(value: &'a PyValue, key: &str) -> Option<Option<&'a PyValue>> {
    match value {
        PyValue::Dict(_) => Some(value.get(key)),
        _ => None,
    }
}

/// `str(x or "")` of an optional value.
fn str_or_empty(v: Option<&PyValue>) -> String {
    match v {
        Some(v) if v.truthy() => v.py_str(),
        _ => String::new(),
    }
}

#[async_trait]
impl ConnectorVerifier for ResendVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        tracing::info!("Verifying Resend connection");
        let Some(row) = connectors.get(name).await.ok()? else {
            tracing::error!("No Resend connector found in the database");
            return outcome(false, "No Resend connector found in the database.");
        };
        let raw_url = if row.connector_url.is_empty() {
            "https://api.resend.com"
        } else {
            row.connector_url.as_str()
        };
        let base = raw_url.trim_end_matches('/').to_string();
        let key = row.connector_api_key.clone().unwrap_or_default();
        if key.is_empty() {
            return outcome(false, "No API key set on the Resend connector.");
        }
        tracing::info!("Verifying the Resend connection to {base}");
        let req = httpx::Request::new(Method::GET, format!("{base}/domains"))
            .header("Authorization", Some(&format!("Bearer {key}")))
            .timeout(TIMEOUT);
        let resp = match httpx::send(req).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Connection to {base} failed with error: {}", e.message);
                return outcome(
                    false,
                    format!("Connection to {base} failed: {}: {}", e.class, e.message),
                );
            }
        };
        let body = loads_bytes(&resp.content).ok();
        if resp.status == 200 {
            let domains: Vec<PyValue> = match &body {
                None => Vec::new(),
                Some(b) => match get(b, "data")? {
                    Some(PyValue::List(items)) => items.clone(),
                    Some(v) if v.truthy() => return None,
                    _ => Vec::new(),
                },
            };
            let mut verified = Vec::new();
            for d in &domains {
                let status = match get(d, "status")? {
                    Some(v) => v.py_str(),
                    None => String::new(),
                };
                if copilot_jinja::unicode::lower(&status) == "verified" {
                    verified.push(d);
                }
            }
            if !verified.is_empty() {
                let names: Vec<String> = verified
                    .iter()
                    .take(3)
                    .map(|d| d.get("name").map_or("None".to_string(), PyValue::py_str))
                    .collect();
                return outcome(
                    true,
                    format!(
                        "Resend connection successful. Verified sending domain(s): {}.",
                        names.join(", ")
                    ),
                );
            }
            return outcome(
                true,
                "Resend connection successful, but no verified sending domain was found. Until a \
                 domain is verified, mail can only be sent to the account owner's address.",
            );
        }
        let (error_name, error_message) = match &body {
            Some(b) => (
                str_or_empty(get(b, "name")?),
                str_or_empty(get(b, "message")?),
            ),
            None => (String::new(), resp.text().chars().take(200).collect()),
        };
        if error_name == "restricted_api_key" {
            return outcome(
                true,
                "Resend connection successful (send-only restricted key). Sending works; \
                 management endpoints are not accessible with this key.",
            );
        }
        tracing::error!(
            "Connection to {base} failed with status {}: {error_message}",
            resp.status
        );
        let detail = if error_message.is_empty() {
            "no detail returned".to_string()
        } else {
            error_message
        };
        outcome(
            false,
            format!("Resend rejected the API key ({}): {detail}", resp.status),
        )
    }
}
