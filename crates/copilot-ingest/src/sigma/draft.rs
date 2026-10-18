//! In-context exclusion creation from a stored alert (#934): the Sigma
//! payload read back from the alert's comments (`parse_sigma_comments`, the
//! reader of the comments the ingest writes), the draft
//! (`build_exclusion_draft`) and the dry-run (`VeloSigmaExclusionService.dry_run`),
//! which runs the ingest's own matcher against the stored event.

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_incidents::schema::AlertOut;
use serde_json::{Value, json};

use super::events::SigmaEvent;
use super::fields::extract_event_fields;
use super::matcher::{Rule, matches};
use super::{
    SIGMA_FALLBACK_COMMENT_PREFIX, SIGMA_META_COMMENT_PREFIX, SIGMA_PAYLOAD_COMMENT_PREFIX,
};
use crate::py::{py_strip, splitlines};

/// `SUGGESTED_FIELD_PRIORITY`.
const SUGGESTED_FIELD_PRIORITY: &[&str] = &[
    "Image",
    "SourceImage",
    "TargetImage",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "TargetFilename",
    "TargetObject",
    "Path",
    "Process Name",
    "HostApplication",
    "ScriptBlockText",
    "DestinationHostname",
    "DestinationIp",
    "QueryName",
    "User",
    "SourceUser",
    "TargetUser",
    "Threat Name",
    "OriginalFileName",
    "Product",
    "Company",
];

/// `MAX_SUGGESTED_FIELDS`.
const MAX_SUGGESTED_FIELDS: usize = 3;

/// What the comments carry: `(title, channel, event)`.
pub type SigmaComments = (
    Option<String>,
    Option<String>,
    Option<Vec<(String, PyValue)>>,
);

/// `parse_sigma_comments(comments)`: `(title, channel, event)`.
pub fn parse_sigma_comments<'a>(comments: impl IntoIterator<Item = &'a str>) -> SigmaComments {
    let mut title: Option<String> = None;
    let mut channel: Option<String> = None;
    let mut event = None;
    for raw in comments {
        let text = py_strip(raw);
        if text.is_empty() {
            continue;
        }
        if title.is_none() {
            if let Some(meta) = text.strip_prefix(SIGMA_META_COMMENT_PREFIX) {
                let meta = py_strip(meta);
                // The channel never contains " | " while a Sigma title might.
                match meta.rsplit_once(" | ") {
                    Some((t, c)) => {
                        title = Some(py_strip(t).to_string());
                        channel = Some(py_strip(c).to_string());
                    }
                    None => title = Some(meta.to_string()),
                }
                continue;
            }
            if text.starts_with(SIGMA_FALLBACK_COMMENT_PREFIX) {
                for line in splitlines(text) {
                    let Some((key, value)) = line.split_once(':') else {
                        continue;
                    };
                    let value = py_strip(value);
                    match py_strip(key).to_lowercase().as_str() {
                        "title" => title = (!value.is_empty()).then(|| value.to_string()),
                        "channel" => channel = (!value.is_empty()).then(|| value.to_string()),
                        _ => {}
                    }
                }
                continue;
            }
        }
        if event.is_none() {
            if let Some(body) = text.strip_prefix(SIGMA_PAYLOAD_COMMENT_PREFIX) {
                let mut body = py_strip(body);
                if let Some(rest) = body.strip_prefix("```") {
                    body = rest.strip_suffix("```").unwrap_or(rest);
                }
                match copilot_upstream::json::py_loads(py_strip(body)) {
                    Ok(PyValue::Dict(d)) => event = Some(d),
                    Ok(_) => {}
                    Err(_) => {
                        tracing::warn!(
                            target: "copilot::ingest",
                            "Sigma payload comment is not valid JSON; ignoring it"
                        );
                    }
                }
            }
        }
    }
    (title, channel, event)
}

/// The parts of a stored alert rebuilt as the inbound Sigma alert
/// (`sigma_alert_from_copilot_alert`): only what the matcher reads is
/// faithful.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSigma {
    /// `computer` (`"unknown"` when nothing names it).
    pub computer: String,
    /// `clientID`: the first asset's Velociraptor id.
    pub client_id: Option<String>,
    /// `channel`.
    pub channel: String,
    /// `title`.
    pub title: String,
    /// `event` (`{}` when the payload comment is gone).
    pub event: Vec<(String, PyValue)>,
}

impl StoredSigma {
    /// `has_event_payload(alert)`.
    pub fn has_payload(&self) -> bool {
        !self.event.is_empty()
    }

    /// The event as `VelociraptorSigmaAlert.event` holds it.
    pub fn sigma_event(&self) -> SigmaEvent {
        SigmaEvent::Dict(self.event.clone())
    }
}

/// `sigma_alert_from_copilot_alert(alert)`, or `None` when the alert never
/// came from the Sigma ingest.
pub fn stored_sigma(alert: &AlertOut) -> Option<StoredSigma> {
    let (title, mut channel, event) =
        parse_sigma_comments(alert.comments.iter().map(|c| c.comment.as_str()));
    if event.is_none() && title.is_none() && channel.is_none() {
        return None;
    }
    let event = event.unwrap_or_default();
    let system = match crate::py::dict_get(&event, "System") {
        Some(PyValue::Dict(s)) => s.clone(),
        _ => Vec::new(),
    };
    if channel.is_none() {
        if let Some(PyValue::Str(c)) = crate::py::dict_get(&system, "Channel") {
            channel = Some(c.clone());
        }
    }
    let asset = alert.assets.first();
    let from_event = match crate::py::dict_get(&system, "Computer") {
        Some(PyValue::Str(c)) if !c.is_empty() => Some(c.clone()),
        _ => None,
    };
    let computer = from_event
        .or_else(|| asset.map(|a| a.asset_name.clone()))
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "unknown".into());
    Some(StoredSigma {
        computer,
        client_id: asset.and_then(|a| a.velociraptor_id.clone()),
        channel: channel.unwrap_or_default(),
        title: title.unwrap_or_default(),
        event,
    })
}

/// `_VOLATILE_FIELD_PATTERN.search(name)`:
/// `(guid|time|record|sequence|^.*id$|^.*ids$|hash|logon|checksum)`, any case.
fn is_volatile(name: &str) -> bool {
    static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)(guid|time|record|sequence|\A.*id\n?\z|\A.*ids\n?\z|hash|logon|checksum)",
        )
        .ok()
    })
    .as_ref()
    .is_some_and(|re| re.is_match(name))
}

/// `build_exclusion_draft(alert)` as the response's `draft`, or `None`.
pub fn build_exclusion_draft(alert: &AlertOut) -> Option<Value> {
    let sigma = stored_sigma(alert)?;
    let mut fields: Vec<(String, String)> = Vec::new();
    if sigma.has_payload() {
        match extract_event_fields(&sigma.channel, &sigma.sigma_event()) {
            Ok(f) => fields = f,
            Err(e) => tracing::warn!(
                target: "copilot::ingest",
                "Could not extract event fields for alert {}: {e}",
                alert.id
            ),
        }
    }
    let rank = |n: &str| {
        SUGGESTED_FIELD_PRIORITY
            .iter()
            .position(|p| *p == n)
            .unwrap_or(SUGGESTED_FIELD_PRIORITY.len())
    };
    let mut order: Vec<&(String, String)> = fields.iter().collect();
    order.sort_by_key(|a| (rank(&a.0), a.0.to_lowercase()));
    let mut suggested_left = MAX_SUGGESTED_FIELDS;
    let mut out = Vec::new();
    for (name, value) in order {
        if value.is_empty() || value == "None" {
            continue;
        }
        let volatile = is_volatile(name);
        let suggested =
            SUGGESTED_FIELD_PRIORITY.contains(&name.as_str()) && !volatile && suggested_left > 0;
        if suggested {
            suggested_left -= 1;
        }
        out.push(
            json!({"name": name, "value": value, "suggested": suggested, "volatile": volatile}),
        );
    }
    let title = Some(sigma.title.clone()).filter(|t| !t.is_empty());
    let channel = Some(sigma.channel.clone()).filter(|c| !c.is_empty());
    let computer = Some(sigma.computer.clone()).filter(|c| c != "unknown");
    let name = match &title {
        Some(t) => format!("Exclude: {t}"),
        None => format!("Exclusion from alert #{}", alert.id),
    };
    let name: String = name.chars().take(255).collect();
    let place = computer
        .as_deref()
        .map(|c| format!(" on {c}"))
        .unwrap_or_default();
    let description = format!(
        "False positive observed on alert #{}{place}. Justification: ",
        alert.id
    );
    Some(json!({
        "alert_id": alert.id,
        "customer_code": Some(alert.customer_code.clone()).filter(|c| !c.is_empty()),
        "channel": channel,
        "title": title,
        "computer": computer,
        "name": name,
        "description": description,
        "payload_available": sigma.has_payload(),
        "fields": out,
    }))
}

/// `VeloSigmaExclusionDryRunRequest`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DryRunRule {
    /// `channel`.
    pub channel: Option<String>,
    /// `title`.
    pub title: Option<String>,
    /// `field_matches`.
    pub field_matches: Option<PyValue>,
    /// `customer_code`.
    pub customer_code: Option<String>,
}

fn opt_repr(v: Option<&str>) -> String {
    v.map_or_else(|| "None".to_string(), str_repr)
}

fn empty_none(v: &Option<String>) -> Option<String> {
    v.clone().filter(|s| !s.is_empty())
}

/// `VeloSigmaExclusionService.dry_run(alert, rule)` as the response body;
/// `Err` is an exception the matcher raised (a bare 500 in Python).
pub fn dry_run(alert: &AlertOut, rule: &DryRunRule) -> Result<Value, String> {
    let respond = |message: &str, matched: bool, reasons: Vec<String>| json!({"success": true, "message": message, "matches": matched, "reasons": reasons});
    let Some(sigma) = stored_sigma(alert) else {
        return Ok(respond(
            "This alert carries no Velociraptor Sigma payload; nothing to test against",
            false,
            vec!["Alert has no Velociraptor Sigma event payload".into()],
        ));
    };
    let mut event_data = Vec::new();
    if sigma.has_payload() {
        match extract_event_fields(&sigma.channel, &sigma.sigma_event()) {
            Ok(d) => event_data = d,
            Err(e) => {
                return Ok(respond(
                    "The stored event payload could not be parsed",
                    false,
                    vec![format!("Event payload could not be parsed: {e}")],
                ));
            }
        }
    }
    let customer_code = Some(alert.customer_code.clone()).filter(|c| !c.is_empty());
    let candidate = Rule {
        channel: empty_none(&rule.channel),
        title: empty_none(&rule.title),
        field_matches: rule.field_matches.clone().filter(PyValue::truthy),
        customer_code: empty_none(&rule.customer_code),
    };
    let run = |r: &Rule| {
        matches(
            r,
            &sigma.channel,
            &sigma.title,
            &event_data,
            customer_code.as_deref(),
        )
        .map_err(|e| e.0)
    };
    if run(&candidate)? {
        return Ok(respond(
            "The rule matches the originating alert",
            true,
            Vec::new(),
        ));
    }
    let mut reasons = Vec::new();
    if let Some(c) = &candidate.customer_code {
        if Some(c) != customer_code.as_ref() {
            reasons.push(format!(
                "Customer mismatch: rule={}, alert={}",
                str_repr(c),
                opt_repr(customer_code.as_deref())
            ));
        }
    }
    if let Some(c) = &candidate.channel {
        if *c != sigma.channel {
            reasons.push(format!(
                "Channel mismatch: rule={}, alert={}",
                str_repr(c),
                str_repr(&sigma.channel)
            ));
        }
    }
    if let Some(t) = &candidate.title {
        if *t != sigma.title {
            reasons.push(format!(
                "Title mismatch: rule={}, alert={}",
                str_repr(t),
                str_repr(&sigma.title)
            ));
        }
    }
    if candidate.field_matches.is_some() && !sigma.has_payload() {
        reasons.push(
            "Alert stores no event payload, so field matches cannot be verified against it".into(),
        );
    }
    if let Some(PyValue::Dict(items)) = &candidate.field_matches {
        for (field_name, field_value) in items {
            if !sigma.has_payload() {
                break;
            }
            let single = Rule {
                field_matches: Some(PyValue::Dict(vec![(
                    field_name.clone(),
                    field_value.clone(),
                )])),
                ..Rule::default()
            };
            if !run(&single)? {
                let present = event_data.iter().find(|(k, _)| k == field_name);
                if present.is_none() && field_name.to_lowercase() != "hostapplication" {
                    reasons.push(format!(
                        "Field {} is not present on the alert event",
                        str_repr(field_name)
                    ));
                } else {
                    reasons.push(format!(
                        "Field {} does not match: rule={}, alert={}",
                        str_repr(field_name),
                        field_value.py_repr(),
                        opt_repr(present.map(|(_, v)| v.as_str()))
                    ));
                }
            }
        }
    }
    if reasons.is_empty() {
        reasons.push("The rule does not match the originating alert".into());
    }
    Ok(respond(
        "The rule would NOT have suppressed the originating alert",
        false,
        reasons,
    ))
}
