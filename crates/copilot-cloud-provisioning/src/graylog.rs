//! The pipeline rules and pipelines the Office 365 and AWS flows keep on the
//! default Graylog (`app/connectors/graylog/services/pipelines.py` and the
//! rule creators of `office365/services/provision.py`): every rule and
//! pipeline is a flat `POST` (Graylog 7 wraps none of them), every update a
//! flat `PUT`.

use copilot_auth::pyvalue::PyValue;
use copilot_graylog::GraylogClient;
use copilot_upstream::model::{field, kwargs};
use copilot_upstream::py::{PyExc, PyResult};

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

/// `WAZUH CREATE FIELD SYSLOG LEVEL - INFO`.
pub const WAZUH_INFO: &str = "WAZUH CREATE FIELD SYSLOG LEVEL - INFO";
/// `WAZUH CREATE FIELD SYSLOG LEVEL - WARNING`.
pub const WAZUH_WARNING: &str = "WAZUH CREATE FIELD SYSLOG LEVEL - WARNING";
/// `WAZUH CREATE FIELD SYSLOG LEVEL - NOTICE`.
pub const WAZUH_NOTICE: &str = "WAZUH CREATE FIELD SYSLOG LEVEL - NOTICE";
/// `WAZUH CREATE FIELD SYSLOG LEVEL - ALERT`.
pub const WAZUH_ALERT: &str = "WAZUH CREATE FIELD SYSLOG LEVEL - ALERT";

fn rule(title: &str, when: &str, then: &str) -> String {
    format!("rule \"{title}\"\nwhen\n  {when}\nthen\n  {then}\nend")
}

/// The source of one of the four shared WAZUH SYSLOG LEVEL rules
/// (`create_wazuh_{info,warning,notice,alert}_rule`), `None` for another
/// title.
pub fn wazuh_rule_source(title: &str) -> Option<String> {
    let (when, level) = match title {
        WAZUH_INFO => (
            "to_long($message.rule_level) > 0 AND to_long($message.rule_level) < 4",
            "INFO",
        ),
        WAZUH_WARNING => (
            "to_long($message.rule_level) > 7 AND to_long($message.rule_level) < 12",
            "WARNING",
        ),
        WAZUH_NOTICE => (
            "to_long($message.rule_level) > 3 AND to_long($message.rule_level) < 8",
            "NOTICE",
        ),
        WAZUH_ALERT => ("to_long($message.rule_level) > 11", "ALERT"),
        _ => return None,
    };
    Some(rule(
        title,
        when,
        &format!("set_field(\"syslog_level\", \"{level}\");"),
    ))
}

/// `office365_utc_rule_source(title)`.
pub fn office365_utc_rule_source(title: &str) -> String {
    rule(
        title,
        "has_field(\"data_office365_CreationTime\")",
        "let creation_time = $message.data_office365_CreationTime;\n  set_field(\"timestamp_utc\", creation_time);",
    )
}

/// `create_office365_syslog_type_rule(title)`'s source.
pub fn office365_syslog_type_rule_source(title: &str) -> String {
    rule(
        title,
        "$message.rule_group1 == \"office365\"",
        "set_field(\"syslog_type\", \"office365\");",
    )
}

/// One `PipelineRule` of `get_pipeline_rules()` (the fields the flows read).
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    /// `id`.
    pub id: String,
    /// `title`.
    pub title: String,
    /// `description`.
    pub description: Option<String>,
    /// `source`.
    pub source: String,
}

fn opt_text(v: &PyValue) -> Option<String> {
    match v {
        PyValue::None => None,
        other => Some(other.py_str()),
    }
}

/// `get_pipeline_rules().pipeline_rules`.
pub async fn pipeline_rules(c: &GraylogClient) -> PyResult<Vec<Rule>> {
    let dump = copilot_graylog::services::pipeline_rules(c).await?;
    let mut out = Vec::new();
    if let PyValue::List(items) = field(&dump, "pipeline_rules") {
        for r in items {
            out.push(Rule {
                id: field(r, "id").py_str(),
                title: field(r, "title").py_str(),
                description: opt_text(field(r, "description")),
                source: field(r, "source").py_str(),
            });
        }
    }
    Ok(out)
}

/// One `Pipeline` of `get_pipelines()` (the fields the flows read).
#[derive(Debug, Clone, PartialEq)]
pub struct Pipeline {
    /// `id`.
    pub id: String,
    /// `title`.
    pub title: String,
    /// `description`.
    pub description: Option<String>,
    /// `source`.
    pub source: String,
}

/// `get_pipelines().pipelines`.
pub async fn pipelines(c: &GraylogClient) -> PyResult<Vec<Pipeline>> {
    let dump = copilot_graylog::services::pipelines(c).await?;
    let mut out = Vec::new();
    if let PyValue::List(items) = field(&dump, "pipelines") {
        for p in items {
            out.push(Pipeline {
                id: field(p, "id").py_str(),
                title: field(p, "title").py_str(),
                description: opt_text(field(p, "description")),
                source: field(p, "source").py_str(),
            });
        }
    }
    Ok(out)
}

/// `create_pipeline_rule(CreatePipelineRule(title, description, source))`.
pub async fn create_rule(
    c: &GraylogClient,
    title: &str,
    description: &str,
    source: &str,
) -> PyResult<()> {
    c.post(
        "/api/system/pipelines/rule",
        Some(kwargs(vec![
            ("title", s(title)),
            ("description", s(description)),
            ("source", s(source)),
        ])),
    )
    .await?;
    Ok(())
}

/// `create_pipeline_graylog(CreatePipeline(title, description, source))`.
pub async fn create_pipeline(
    c: &GraylogClient,
    title: &str,
    description: &str,
    source: &str,
) -> PyResult<()> {
    c.post(
        "/api/system/pipelines/pipeline",
        Some(kwargs(vec![
            ("title", s(title)),
            ("description", s(description)),
            ("source", s(source)),
        ])),
    )
    .await?;
    Ok(())
}

/// `send_put_request(endpoint, data={title, description, source})`: whether
/// the answer was a success (`None` — no connector row — is not).
pub async fn put_source(
    c: &GraylogClient,
    endpoint: &str,
    title: &str,
    description: &str,
    source: &str,
) -> PyResult<(bool, Option<String>)> {
    let reply = c
        .put(
            endpoint,
            Some(kwargs(vec![
                ("title", s(title)),
                ("description", s(description)),
                ("source", s(source)),
            ])),
        )
        .await?;
    Ok(match reply {
        Some(r) => (r.success, Some(r.message)),
        None => (false, None),
    })
}

/// `app/connectors/graylog/services/pipelines.py:get_pipeline_id`: `[id]` of
/// the first pipeline whose description holds `subscription`
/// (case-insensitively; a `None` description is the `AttributeError`).
pub async fn pipeline_id(c: &GraylogClient, subscription: &str) -> PyResult<PyValue> {
    let needle = subscription.to_lowercase();
    for p in pipelines(c).await? {
        let Some(description) = &p.description else {
            return Err(PyExc::AttributeError(
                "'NoneType' object has no attribute 'lower'".into(),
            ));
        };
        if description.to_lowercase().contains(&needle) {
            return Ok(PyValue::List(vec![PyValue::Str(p.id)]));
        }
    }
    Err(PyExc::http(
        500,
        format!("Failed to get pipeline ID for subscription {subscription}"),
    ))
}
