//! The SOCFortress AI routes of `app/threat_intel/routes/socfortress.py`:
//! an alert's indexer document sent to `/analyze-alert` or
//! `/wazuh-exclusion-rule`, the answer left as a comment on the CoPilot
//! alert; and the Velociraptor artifact recommendation, which fails before
//! it calls anything (Python reads `alert._source`, a private attribute
//! Pydantic does not have).

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_ingest::source::AlertDetails;
use copilot_upstream::model::construct;
use copilot_upstream::py::{PyExc, PyResult, get};
use http::Method;

use crate::ThreatIntelState;
use crate::httpx::{self, Request};
use crate::py::{dict, s};
use crate::schema::{AI_EXCLUSION_RESPONSE, ai_alert_response};

/// Which analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `/ai/analyze-alert`.
    Analyze,
    /// `/ai/wazuh-exclusion-rule`.
    ExclusionRule,
}

impl Kind {
    fn endpoint(self) -> &'static str {
        match self {
            Kind::Analyze => "/analyze-alert",
            Kind::ExclusionRule => "/wazuh-exclusion-rule",
        }
    }
}

/// The keys `check_syslog_type` drops from the payload.
const DROPPED: &[&str] = &[
    "message",
    "full_log",
    "gl2_processing_error",
    "gl2_accounted_message_size",
    "gl2_source_input",
    "gl2_remote_ip",
    "gl2_message_id",
    "gl2_remote_port",
];

/// `SocfortressAiAlertRequest(integration="SOCFORTRESS AI",
/// alert_payload=alert_details.source.model_dump()).model_dump()`: the
/// `syslog_type` must be one of `SyslogType`'s values (else the validator's
/// 400), and the noisy fields are dropped.
pub fn request_body(details: &AlertDetails) -> PyResult<PyValue> {
    let syslog_type = details
        .source
        .iter()
        .find(|(k, _)| k == "syslog_type")
        .map(|(_, v)| v.clone())
        .unwrap_or(PyValue::None);
    if !matches!(
        syslog_type.as_str(),
        Some("wazuh" | "fortinet" | "sentinelone")
    ) {
        return Err(PyExc::http(
            400,
            "Invalid syslog_type. Only wazuh, fortinet, sentinelone are supported.",
        ));
    }
    let payload: Vec<(String, PyValue)> = details
        .source
        .iter()
        .filter(|(k, _)| !DROPPED.contains(&k.as_str()))
        .cloned()
        .collect();
    Ok(dict(vec![
        ("integration", s("SOCFORTRESS AI")),
        ("alert_payload", PyValue::Dict(payload)),
    ]))
}

/// `invoke_socfortress_ai_alert_api(api_key, url, request)` (60 s), then
/// the `Forbidden` check and the response model of `kind`.
pub async fn ask(
    st: &ThreatIntelState,
    kind: Kind,
    license_key: &str,
    body: PyValue,
) -> PyResult<PyValue> {
    let sent = httpx::send(
        Request::new(Method::POST, format!("{}{}", st.urls.ai, kind.endpoint()))
            .header("module-version", Some("1.0"))
            .header("x-api-key", Some(license_key))
            .json(body)
            .timeout(Duration::from_secs(60)),
    )
    .await;
    let answer = match sent {
        Err(e) if e.is_request_error() => {
            tracing::error!("Request error occurred: {}", e.message);
            return Err(PyExc::http(
                500,
                format!("Request error occurred: {}", e.message),
            ));
        }
        Err(e) => {
            return Err(PyExc::http(
                500,
                format!("An unexpected error occurred: {}", e.message),
            ));
        }
        Ok(response) => {
            if response.raise_for_status().is_err() {
                return Err(if response.status == 429 {
                    PyExc::http(
                        429,
                        "Rate limit reached for the month. Please try again next month.",
                    )
                } else {
                    PyExc::http(
                        response.status,
                        format!(
                            "HTTP error occurred: {} - {}",
                            response.status,
                            response.text()
                        ),
                    )
                });
            }
            response.json().map_err(|e| {
                PyExc::http(500, format!("An unexpected error occurred: {}", e.text()))
            })?
        }
    };
    if get(&answer, "message")?.is_some_and(|m| m.as_str() == Some("Forbidden")) {
        return Err(PyExc::http(
            403,
            "Forbidden access to the Socfortress AI Alert API",
        ));
    }
    match kind {
        Kind::Analyze => ai_alert_response(&answer),
        Kind::ExclusionRule => construct(&AI_EXCLUSION_RESPONSE, &answer),
    }
}

/// The comment Python leaves on the alert.
pub fn comment_text(kind: Kind, lookup: &PyValue) -> String {
    let field = |k: &str| lookup.get(k).cloned().unwrap_or(PyValue::None).py_str();
    match kind {
        Kind::Analyze => format!("SOCFortress AI Analysis: {}", field("analysis")),
        Kind::ExclusionRule => format!(
            "SOCFortress AI Analysis: {}/n/n{}",
            field("wazuh_exclusion_rule"),
            field("wazuh_exclusion_rule_justification")
        ),
    }
}

/// `fetch_agent_os(agent_id, session)`: the agent's OS, normalised; the
/// texts of `get_agent_os_by_id`'s `try` (a missing agent is its own 404
/// wrapped in a 500).
pub async fn agent_os(st: &ThreatIntelState, agent_id: Option<&str>) -> PyResult<&'static str> {
    let shown = agent_id.unwrap_or("None");
    let found = match agent_id {
        Some(id) => sqlx::query_scalar::<_, String>(
            "SELECT agents.os FROM agents WHERE agents.agent_id = ?",
        )
        .bind(id)
        .fetch_optional(st.ctx.db.pool())
        .await
        .map_err(|e| e.to_string()),
        None => Ok(None),
    };
    let os = match found {
        Ok(Some(os)) => os,
        Ok(None) => {
            return Err(PyExc::http(
                500,
                format!(
                    "Failed to fetch agent with agent_id {shown}: 404: Agent with agent_id \
                     {shown} not found."
                ),
            ));
        }
        Err(e) => {
            return Err(PyExc::http(
                500,
                format!("Failed to fetch agent with agent_id {shown}: {e}"),
            ));
        }
    };
    let lower = copilot_jinja::unicode::lower(&os);
    if lower.contains("windows") {
        Ok("Windows")
    } else if lower.contains("linux") || lower.contains("ubuntu") {
        Ok("Linux")
    } else if lower.contains("macos") || lower.contains("mac") {
        Ok("MacOS")
    } else {
        Err(PyExc::http(400, "Unsupported OS type."))
    }
}
