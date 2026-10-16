//! `VelociraptorSigmaService.process_alert` — the Velociraptor Sigma
//! webhook (`POST /create/velo-sigma`).
//!
//! An alert is checked against the enabled exclusion rules first (the
//! matcher of [`super::matcher`], over the fields of
//! [`super::fields::extract_event_fields`]); a match counts on the rule and
//! suppresses the alert. Otherwise the Wazuh copy of the event is looked up
//! (agent, `EventRecordID`, last hour): found, it becomes a CoPilot alert
//! the usual way (`create_alert`); not found, the Velociraptor data itself
//! does (the fallback). Either way the alert gets the two comments the
//! exclusion draft reads back and its tags.
//!
//! The answer is built as Python builds it, including where Python's own
//! response model refuses it: `alert_id` is declared `Optional[str]` but is
//! handed an `int`, so a successfully created alert is reported as
//! `success: false` with the `ValidationError` text and the event's
//! `sourceRef` (as the Python backend answers today).

use chrono::Duration;
use serde_json::{Value, json};

use copilot_auth::pyvalue::PyValue;
use copilot_core::time::{mysql_datetime, now_utc_micros};
use copilot_incidents::writes::{self, CommentKind};
use copilot_wazuh::error::PyErr;

use super::events::{EventKind, ParseError, ParsedEvent, SigmaEvent, get_parsed_event};
use super::fields::{extract_event_fields, fields_of};
use super::matcher::{Rule, matches};
use super::{
    SIGMA_FALLBACK_COMMENT_PREFIX, SIGMA_META_COMMENT_PREFIX, SIGMA_PAYLOAD_COMMENT_PREFIX,
};
use crate::IngestState;
use crate::create::{AlertPayload, Origin, PayloadArgs, create_alert, create_alert_full};
use crate::es;
use crate::py::{dict_get, dumps_indent2, fromtimestamp_local, isoformat, strftime_millis};

/// `VelociraptorSigmaAlert` as validated.
#[derive(Debug, Clone, PartialEq)]
pub struct SigmaAlert {
    /// `computer`.
    pub computer: String,
    /// `clientID`.
    pub client_id: Option<String>,
    /// `channel`.
    pub channel: String,
    /// `title`.
    pub title: String,
    /// `level`.
    pub level: String,
    /// `event`.
    pub event: SigmaEvent,
    /// `type` (`sigma-alert`).
    pub kind: String,
    /// `source` (`velociraptor`).
    pub source: String,
    /// `index_pattern`.
    pub index_pattern: String,
    /// `sourceRef`.
    pub source_ref: String,
}

/// An enabled exclusion rule.
#[derive(Debug, Clone, sqlx::FromRow)]
struct StoredRule {
    id: i32,
    name: String,
    channel: Option<String>,
    title: Option<String>,
    field_matches: Option<sqlx::types::Json<Value>>,
    customer_code: Option<String>,
}

impl StoredRule {
    fn rule(&self) -> Rule {
        Rule {
            customer_code: self.customer_code.clone(),
            channel: self.channel.clone(),
            title: self.title.clone(),
            field_matches: self
                .field_matches
                .as_ref()
                .map(|j| crate::py::to_py(&j.0))
                .filter(|v| *v != PyValue::None),
        }
    }
}

/// `VelociraptorSigmaAlertResponse(...)`, validated as Python validates it
/// (an `int` id is not a `str`).
enum AlertRef {
    None,
    Int(i64),
    Str(String),
}

fn response(success: bool, message: String, alert_id: AlertRef, source_ref: &str) -> Value {
    match alert_id {
        AlertRef::Int(id) => {
            let text = format!(
                "Error: 1 validation error for VelociraptorSigmaAlertResponse\nalert_id\n  Input \
                 should be a valid string [type=string_type, input_value={id}, input_type=int]\n    \
                 For further information visit https://errors.pydantic.dev/{}/v/string_type",
                copilot_upstream::model::PYDANTIC_VERSION
            );
            json!({"success": false, "message": text, "alert_id": source_ref})
        }
        AlertRef::Str(s) => json!({"success": success, "message": message, "alert_id": s}),
        AlertRef::None => json!({"success": success, "message": message, "alert_id": null}),
    }
}

/// `resolve_customer_code(alert)`: the agent's customer by Velociraptor
/// client id, else by hostname; `None` (fail closed) otherwise.
async fn resolve_customer_code(st: &IngestState, alert: &SigmaAlert) -> Option<String> {
    let lookup = async {
        if let Some(client) = alert.client_id.as_deref().filter(|c| !c.is_empty()) {
            let codes: Vec<Option<String>> = sqlx::query_scalar(
                "SELECT agents.customer_code FROM agents WHERE agents.velociraptor_id = ?",
            )
            .bind(client)
            .fetch_all(st.ctx.db.pool())
            .await
            .map_err(|e| e.to_string())?;
            if codes.len() > 1 {
                return Err("Multiple rows were found when one or none was required".to_string());
            }
            if let Some(Some(code)) = codes
                .into_iter()
                .next()
                .filter(|c| c.as_deref().is_some_and(|s| !s.is_empty()))
            {
                return Ok(Some(code));
            }
        }
        if !alert.computer.is_empty() {
            let codes: Vec<Option<String>> = sqlx::query_scalar(
                "SELECT agents.customer_code FROM agents WHERE agents.hostname = ?",
            )
            .bind(&alert.computer)
            .fetch_all(st.ctx.db.pool())
            .await
            .map_err(|e| e.to_string())?;
            if let Some(Some(code)) = codes.into_iter().next() {
                if !code.is_empty() {
                    return Ok(Some(code));
                }
            }
        }
        Ok(None)
    };
    match lookup.await {
        Ok(code) => code,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Error resolving customer code for Sigma alert: {e}");
            None
        }
    }
}

/// `check_exclusions(alert)`: the first enabled rule that matches (its
/// statistics counted), or `None`.
async fn check_exclusions(
    st: &IngestState,
    alert: &SigmaAlert,
) -> Result<Option<(i64, String)>, PyErr> {
    let rules: Vec<StoredRule> = sqlx::query_as(
        "SELECT id, name, channel, title, field_matches, customer_code \
         FROM incident_management_velo_sigma_exclusion \
         WHERE incident_management_velo_sigma_exclusion.enabled = true",
    )
    .fetch_all(st.ctx.db.pool())
    .await?;
    if rules.is_empty() {
        return Ok(None);
    }
    let event_data = match extract_event_fields(&alert.channel, &alert.event) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Error parsing event data: {e}");
            return Ok(None);
        }
    };
    let customer = resolve_customer_code(st, alert).await;
    for rule in rules {
        let matched = matches(
            &rule.rule(),
            &alert.channel,
            &alert.title,
            &event_data,
            customer.as_deref(),
        )
        .map_err(|e| PyErr::Other(e.0))?;
        if matched {
            if let Err(e) = sqlx::query(
                "UPDATE incident_management_velo_sigma_exclusion SET last_matched_at = ?, \
                 match_count = (incident_management_velo_sigma_exclusion.match_count + ?) \
                 WHERE incident_management_velo_sigma_exclusion.id = ?",
            )
            .bind(mysql_datetime(now_utc_micros()))
            .bind(1)
            .bind(rule.id)
            .execute(st.ctx.db.pool())
            .await
            {
                tracing::error!(target: "copilot::ingest", "Error updating exclusion stats: {e}");
            }
            return Ok(Some((i64::from(rule.id), rule.name)));
        }
    }
    Ok(None)
}

/// The processing result (`result` of the Python service).
#[derive(Debug, Default)]
struct Outcome {
    success: bool,
    event_record_id: Option<String>,
    wazuh: Option<(String, String)>,
    reason: Option<String>,
    alert_id: Option<i64>,
}

/// The agent registered under the alert's Velociraptor client id
/// (`scalar_one_or_none`: two are an error): `(hostname, customer_code)`.
async fn agent_by_client_id(
    st: &IngestState,
    client_id: &str,
) -> Result<Option<(String, Option<String>)>, PyErr> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT hostname, customer_code FROM agents WHERE agents.velociraptor_id = ?",
    )
    .bind(client_id)
    .fetch_all(st.ctx.db.pool())
    .await?;
    if rows.len() > 1 {
        return Err(PyErr::Other(
            "Multiple rows were found when one or none was required".into(),
        ));
    }
    Ok(rows.into_iter().next())
}

/// The asset name to look the event up by: the alert's computer, or the
/// hostname the agent is enrolled under.
async fn agent_name(st: &IngestState, alert: &SigmaAlert) -> Result<String, PyErr> {
    let mut name = alert.computer.clone();
    if let Some(client) = alert.client_id.as_deref().filter(|c| !c.is_empty()) {
        if let Some((hostname, _)) = agent_by_client_id(st, client).await? {
            if !hostname.is_empty() {
                name = hostname;
            }
        }
    }
    Ok(name)
}

/// `_fetch_wazuh_alert`: `(index, id)` of the Wazuh copy of the event.
async fn fetch_wazuh_alert(
    st: &IngestState,
    agent: &str,
    record_id: &str,
    index_pattern: &str,
) -> Option<(String, String)> {
    let client = match es::async_client(st).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Error fetching alert data: {}", e.py_str());
            return None;
        }
    };
    let since = strftime_millis(now_utc_micros() - Duration::hours(1));
    let query = crate::py::to_py(&json!({
        "query": {
            "bool": {
                "must": [{"term": {"agent_name": agent}}, {"term": {"data_win_system_eventRecordID": record_id}}],
                "filter": [{"range": {"timestamp": {"gte": since}}}],
            },
        },
    }));
    let response = match es::search(&client, index_pattern, &query, Some(1), Some("1m")).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Search operation failed: {e}");
            return None;
        }
    };
    // `_extract_wazuh_results`.
    let hits = response.get("hits")?;
    let PyValue::List(list) = hits.get("hits")? else {
        return None;
    };
    let hit = list.first()?;
    let PyValue::Dict(h) = hit else {
        return None;
    };
    if !matches!(dict_get(h, "_source"), None | Some(PyValue::Dict(_))) {
        return None;
    }
    // `CreateAlertRequest(index_name=hit.get("_index"), alert_id=hit.get("_id"))`
    // needs both as strings; anything else fails the creation, not the lookup.
    let text = |k: &str| match dict_get(h, k) {
        Some(PyValue::Str(s)) => Some(s.clone()),
        _ => None,
    };
    Some((
        text("_index").unwrap_or_default(),
        text("_id").unwrap_or_default(),
    ))
}

/// `len(x)` / `x[:100] + "..."` of the ScriptBlockText preview (only its
/// exceptions matter).
fn script_preview(value: &PyValue) -> Result<(), String> {
    match value {
        PyValue::Str(_) => Ok(()),
        PyValue::List(items) if items.len() > 100 => {
            Err("can only concatenate list (not \"str\") to list".into())
        }
        PyValue::List(_) => Ok(()),
        PyValue::Dict(d) if d.len() > 100 => Err("unhashable type: 'slice'".into()),
        PyValue::Dict(_) => Ok(()),
        other => Err(format!(
            "object of type '{}' has no len()",
            crate::py::type_name(other)
        )),
    }
}

/// `_process_event_by_type`: the event's record id and its Wazuh copy.
async fn process_event(st: &IngestState, alert: &SigmaAlert) -> Result<Outcome, PyErr> {
    let parsed = get_parsed_event(&alert.channel, &alert.event).map_err(|e| PyErr::Other(e.0))?;
    let route = match parsed.kind {
        EventKind::Sysmon => EventKind::Sysmon,
        EventKind::Defender => EventKind::Defender,
        _ if alert.channel.contains("Sysmon") => EventKind::Sysmon,
        _ if alert.channel.contains("Defender") => EventKind::Defender,
        _ if alert.channel.contains("PowerShell") => EventKind::PowerShell,
        _ => EventKind::Generic,
    };
    let record_id = parsed.event_record_id();
    if route == EventKind::Generic {
        // `_process_generic_event` catches everything.
        let attempt = async {
            let name = agent_name(st, alert).await?;
            Ok::<_, PyErr>(fetch_wazuh_alert(st, &name, &record_id, &alert.index_pattern).await)
        }
        .await;
        return Ok(match attempt {
            Ok(wazuh) => Outcome {
                success: wazuh.is_some(),
                event_record_id: Some(record_id),
                wazuh,
                ..Outcome::default()
            },
            Err(e) => Outcome {
                reason: Some(format!("Failed to process generic event: {}", e.py_str())),
                ..Outcome::default()
            },
        });
    }
    let name = agent_name(st, alert).await?;
    let wazuh = fetch_wazuh_alert(st, &name, &record_id, &alert.index_pattern).await;
    if route == EventKind::PowerShell {
        if let Some(text) = parsed.data("ScriptBlockText") {
            script_preview(text).map_err(PyErr::Other)?;
        }
    }
    Ok(Outcome {
        success: wazuh.is_some(),
        event_record_id: Some(record_id),
        wazuh,
        ..Outcome::default()
    })
}

/// The `Full Event Payload:` comment's text (`json.dumps(event, indent=2)`).
fn payload_comment(event: &SigmaEvent) -> String {
    let body = match event {
        SigmaEvent::Str(s) => s.clone(),
        SigmaEvent::Dict(_) => dumps_indent2(&event.to_py()),
    };
    format!("{SIGMA_PAYLOAD_COMMENT_PREFIX}\n```\n{body}\n```")
}

/// `create_comment` signed `admin`, stamped now.
async fn comment(st: &IngestState, alert_id: i64, text: &str) -> Result<(), PyErr> {
    if copilot_incidents::store::alert(&st.ctx.db, alert_id)
        .await?
        .is_none()
    {
        return Err(PyErr::http(404, "Alert not found"));
    }
    writes::create_comment(
        &st.ctx.db,
        CommentKind::Alert,
        alert_id,
        text,
        "admin",
        Some(copilot_incidents::requests::PyDateTime::naive(
            now_utc_micros(),
        )),
    )
    .await
    .map_err(|e| PyErr::Other(e.to_string()))?;
    Ok(())
}

/// `add_alert_tag_if_not_exists`: nothing when *any* alert already carries
/// a tag of that text (as in Python, the existing tag is not linked).
async fn tag_if_new(st: &IngestState, alert_id: i64, tag: &str) -> Result<(), PyErr> {
    let existing: Vec<i32> = sqlx::query_scalar(
        "SELECT id FROM incident_management_alerttag WHERE incident_management_alerttag.tag = ?",
    )
    .bind(tag)
    .fetch_all(st.ctx.db.pool())
    .await?;
    if !existing.is_empty() {
        return Ok(());
    }
    writes::create_alert_tag(&st.ctx.db, alert_id, tag)
        .await
        .map_err(|e| match e {
            copilot_web::ApiError::Http { status, detail } => PyErr::http(
                status.as_u16(),
                detail.as_str().unwrap_or_default().to_string(),
            ),
            other => PyErr::Other(other.to_string()),
        })?;
    Ok(())
}

/// `_create_copilot_alert`: the Wazuh copy becomes the alert; any failure
/// leaves `alert_id` unset (and `success` as it was).
async fn create_from_wazuh(st: &IngestState, alert: &SigmaAlert, out: &mut Outcome) {
    let Some((index, id)) = out.wazuh.clone() else {
        return;
    };
    let attempt: Result<i64, PyErr> = async {
        let created = create_alert(st, &index, &id).await?;
        comment(
            st,
            created,
            &format!("{SIGMA_META_COMMENT_PREFIX}{} | {}", alert.title, alert.channel),
        )
        .await?;
        if let Err(e) = comment(st, created, &payload_comment(&alert.event)).await {
            tracing::error!(target: "copilot::ingest", "Failed to add event payload as comment: {}", e.py_str());
        }
        tag_if_new(st, created, &alert.kind).await?;
        Ok(created)
    }
    .await;
    match attempt {
        Ok(id) => out.alert_id = Some(id),
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Failed to create CoPilot alert: {}", e.py_str());
            out.alert_id = None;
        }
    }
}

/// `_create_fallback_alert`: the Velociraptor data itself becomes the
/// alert, filed under the enrolled agent's customer.
async fn create_fallback(st: &IngestState, alert: &SigmaAlert, out: &mut Outcome) {
    let attempt = async {
        let parsed = get_parsed_event(&alert.channel, &alert.event).map_err(|e| PyErr::Other(e.0))?;
        let timestamp = fromtimestamp_local(parsed.system_time())
            .map(isoformat)
            .map_err(PyErr::Other)?;
        let mut context = parsed.data_dump();
        for (k, v) in [
            ("alert_title", PyValue::Str(alert.title.clone())),
            ("alert_level", PyValue::Str(alert.level.clone())),
            ("alert_channel", PyValue::Str(alert.channel.clone())),
            ("alert_source", PyValue::Str(alert.source.clone())),
            ("computer", PyValue::Str(alert.computer.clone())),
            (
                "clientID",
                alert
                    .client_id
                    .clone()
                    .map_or(PyValue::None, PyValue::Str),
            ),
        ] {
            crate::py::dict_set(&mut context, k, v);
        }
        let mut customer = "not_found".to_string();
        let mut asset: Option<String> = None;
        if let Some(client) = alert.client_id.as_deref().filter(|c| !c.is_empty()) {
            if let Some((hostname, Some(code))) = agent_by_client_id(st, client).await? {
                if !code.is_empty() {
                    customer = code;
                    asset = Some(hostname);
                }
            }
        }
        let Some(asset) = asset else {
            return Err(PyErr::Other(
                "cannot access local variable 'agent_name' where it is not associated with a value"
                    .into(),
            ));
        };
        let mut payload: AlertPayload = PayloadArgs {
            context: PyValue::Dict(context),
            asset: PyValue::Str(asset),
            timefield: PyValue::Str(timestamp),
            title: PyValue::Str(alert.title.clone()),
            ioc: None,
            source: PyValue::Str(alert.source.clone()),
            index_name: PyValue::Str("not_applicable".into()),
            index_id: PyValue::Str("not_applicable".into()),
            rule_level: None,
            severity: None,
        }
        .build()?;
        let id = create_alert_full(st, &mut payload, &customer, Origin::VeloSigma).await?;
        out.alert_id = Some(id);
        let text = format!(
            "{SIGMA_FALLBACK_COMMENT_PREFIX}\nTitle: {}\nChannel: {}\nLevel: {}\nComputer: {}\n\
             Event Type: {}\nEvent Record ID: {}\nCustomer Code: {customer}\n",
            alert.title,
            alert.channel,
            alert.level,
            alert.computer,
            parsed.kind.class_name(),
            out.event_record_id.as_deref().unwrap_or("Unknown"),
        );
        comment(st, id, &text).await?;
        if let Err(e) = comment(st, id, &payload_comment(&alert.event)).await {
            tracing::error!(target: "copilot::ingest", "Failed to add event payload as comment: {}", e.py_str());
        }
        tag_if_new(st, id, &alert.kind).await?;
        tag_if_new(st, id, "velociraptor-direct").await?;
        let event_tag = if alert.channel.contains("Sysmon") {
            "event_type:sysmon"
        } else if alert.channel.contains("Defender") {
            "event_type:defender"
        } else if alert.channel.contains("PowerShell") {
            "event_type:powershell"
        } else {
            "event_type:generic"
        };
        tag_if_new(st, id, event_tag).await?;
        Ok::<i64, PyErr>(id)
    }
    .await;
    match attempt {
        Ok(_) => out.success = true,
        Err(e) => {
            tracing::error!(target: "copilot::ingest", "Failed to create fallback CoPilot alert: {}", e.py_str());
            out.alert_id = None;
            out.success = false;
            out.reason = Some(format!("Failed to create fallback alert: {}", e.py_str()));
        }
    }
}

/// `process_alert(alert)` as the response body.
pub async fn process_alert(st: &IngestState, alert: &SigmaAlert) -> Value {
    let attempt = async {
        if let Some((id, name)) = check_exclusions(st, alert).await? {
            tracing::info!(target: "copilot::ingest", "Skipping alert processing: matched exclusion rule '{name}' (ID: {id})");
            return Ok::<Value, PyErr>(response(
                true,
                format!("Alert excluded by rule: {name}"),
                AlertRef::None,
                &alert.source_ref,
            ));
        }
        let mut out = process_event(st, alert).await?;
        if out.success {
            create_from_wazuh(st, alert, &mut out).await;
        } else {
            create_fallback(st, alert, &mut out).await;
        }
        let (message, success) = if out.success {
            (format!("Successfully processed {} alert", alert.channel), true)
        } else {
            (
                format!(
                    "Failed to process {} alert: {}",
                    alert.channel,
                    out.reason.as_deref().unwrap_or("Unknown error")
                ),
                false,
            )
        };
        let id = out.alert_id.map_or(AlertRef::None, AlertRef::Int);
        Ok(response(success, message, id, &alert.source_ref))
    }
    .await;
    match attempt {
        Ok(v) => v,
        Err(e) => response(
            false,
            format!("Error: {}", e.py_str()),
            AlertRef::Str(alert.source_ref.clone()),
            &alert.source_ref,
        ),
    }
}

/// `extract_event_fields` for a parsed event (re-exported for tests).
pub fn event_fields(parsed: &ParsedEvent) -> Result<Vec<(String, String)>, ParseError> {
    fields_of(parsed)
}
