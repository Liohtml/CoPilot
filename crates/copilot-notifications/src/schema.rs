//! Request and response shapes (`schema/notifications.py`, `schema/events.py`).
//!
//! Requests are read with Pydantic's lax rules and FastAPI's 422 texts
//! (`copilot_web::validate`), field by field in declaration order, then the
//! model validators. Responses keep the models' field order; the `*Read`
//! models re-validate a stored row the way `from_orm` / `model_validate`
//! does, so a row the API could never have written (an unknown channel, an
//! empty name) is the same 400 the backend's `ValueError` handler gives.

use chrono::NaiveDateTime;
use copilot_auth::pyvalue::{self, PyValue};
use copilot_web::ApiError;
use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::channels::config::{self as channel_config, dict_items};
use crate::channels::{Channel, py_list_repr};
use crate::db::{IntegrationRow, LogRow, RouteRow, TemplateRow};
use crate::event::{SEVERITIES, py_strip, trigger_values};
use crate::pydantic::{self, Loc as PLoc, PyError};
use crate::pyjson::from_json;
use crate::services::render::is_template_error;

/// `NotificationScope`.
pub const SCOPES: &[&str] = &["customer", "internal"];
/// `RecipientMode`.
pub const RECIPIENT_MODES: &[&str] = &["static", "assignee"];
/// `TemplateFormat`.
pub const TEMPLATE_FORMATS: &[&str] = &["text", "markdown", "html", "json"];
/// `DispatchStatus`.
pub const DISPATCH_STATUSES: &[&str] = &["sent", "failed", "skipped"];

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(name.into()));
    l
}

/// `_assert_route_trigger`.
fn route_trigger_error(trigger: &str) -> String {
    format!(
        "Value error, {} is not a route trigger — nothing dispatches it. It exists so a message \
         template can be scoped to it; that delivery path has its own sender.",
        pyvalue::str_repr(trigger)
    )
}

/// A field that may be absent, `null`, or a value (`exclude_unset`).
pub type Patch<T> = Option<Option<T>>;

fn patched<T>(obj: &Map<String, Value>, name: &str, value: Option<T>) -> Patch<T> {
    obj.contains_key(name).then_some(value)
}

/// `_parse_config`: a dict, a JSON string holding one, or `{}`.
fn lenient_config(v: Option<&Value>) -> Vec<(String, PyValue)> {
    let parsed = match v {
        Some(Value::Object(_)) => v.map(from_json),
        Some(Value::String(s)) if !py_strip(s).is_empty() => pyvalue::loads(s).ok(),
        _ => None,
    };
    match parsed {
        Some(PyValue::Dict(items)) => items,
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `NotificationRouteCreate`, validated (the model validator included).
#[derive(Debug, Clone)]
pub struct RouteCreate {
    /// Label.
    pub name: String,
    /// Trigger (legacy value already rewritten).
    pub trigger: String,
    /// Channel.
    pub channel: Channel,
    /// Destination hint (stripped).
    pub destination: Option<String>,
    /// Severity floor.
    pub min_severity: String,
    /// Inline template.
    pub format_template: Option<String>,
    /// Named template.
    pub template_id: Option<i64>,
    /// Enabled.
    pub enabled: bool,
    /// Scope.
    pub scope: String,
    /// Recipient mode.
    pub recipient_mode: String,
    /// Self-assignment flag.
    pub notify_on_self_assign: bool,
    /// Shuffle integration.
    pub shuffle_integration_id: Option<i64>,
    /// The normalized config (`model_dump()` of the channel's model).
    pub config: PyValue,
}

/// A save-time template check that raised something other than a
/// `TemplateError` (Python lets it escape the validator: a bare 500).
#[derive(Debug, Default)]
pub struct Escaped(pub Option<String>);

impl RouteCreate {
    /// Read the body.
    pub fn read(
        v: &mut Validator,
        obj: &Map<String, Value>,
        at: &Loc,
        escaped: &mut Escaped,
    ) -> Option<Self> {
        let name = v.req_str(obj, at, "name", StrRules::max(128).min(1));
        let triggers = trigger_values();
        let trigger = match obj.get("trigger") {
            None => {
                v.missing(child(at, "trigger"));
                None
            }
            Some(raw) => {
                let raw = match raw {
                    Value::String(s) if s == "severity_critical_or_high" => {
                        Value::String("investigation_complete".into())
                    }
                    other => other.clone(),
                };
                let t = v.check_enum(&child(at, "trigger"), &raw, &triggers);
                if t.as_deref() == Some("temp_password_issued") {
                    v.push(
                        "value_error",
                        child(at, "trigger"),
                        route_trigger_error("temp_password_issued"),
                    );
                    None
                } else {
                    t
                }
            }
        };
        let channel = v.req_enum(obj, at, "channel", &Channel::KEYS);
        let destination = v
            .opt_str(obj, at, "destination", StrRules::any())
            .map(|d| py_strip(&d).to_string());
        let min_severity = v.enum_or(obj, at, "min_severity", SEVERITIES, "Medium");
        let format_template = v.opt_str(obj, at, "format_template", StrRules::any());
        if let Some(src) = format_template
            .as_deref()
            .filter(|s| !py_strip(s).is_empty())
        {
            if let Err(e) = copilot_jinja::compile_template(src, false) {
                if is_template_error(e.kind) {
                    v.push(
                        "value_error",
                        child(at, "format_template"),
                        format!(
                            "Value error, format_template is not valid Jinja: {}",
                            e.message
                        ),
                    );
                } else {
                    escaped.0 = Some(format!("{}: {}", e.kind, e.message));
                }
            }
        }
        let template_id = v.opt_int(obj, at, "template_id", IntRules::default());
        let enabled = v.bool_or(obj, at, "enabled", true);
        let scope = v.enum_or(obj, at, "scope", SCOPES, "customer");
        let recipient_mode = v.enum_or(obj, at, "recipient_mode", RECIPIENT_MODES, "static");
        let notify_on_self_assign = v.bool_or(obj, at, "notify_on_self_assign", false);
        let shuffle_integration_id =
            v.opt_int(obj, at, "shuffle_integration_id", IntRules::default());
        let config = lenient_config(obj.get("config"));
        if v.has_errors() {
            return None;
        }
        let channel = Channel::parse(&channel)?;
        let config = match channel_config::validate(channel, &config) {
            Ok(c) => c,
            Err(errors) => {
                v.push(
                    "value_error",
                    at.clone(),
                    format!(
                        "Value error, Invalid config for channel '{}': {}",
                        channel.key(),
                        pydantic::format(channel.model_name(), &errors)
                    ),
                );
                return None;
            }
        };
        let fail = |v: &mut Validator, msg: String| {
            v.push("value_error", at.clone(), format!("Value error, {msg}"));
        };
        if !channel.recipient_modes().contains(&recipient_mode.as_str()) {
            fail(
                v,
                format!(
                    "Channel '{}' does not support recipient_mode '{recipient_mode}' (supported: {})",
                    channel.key(),
                    py_list_repr(channel.recipient_modes())
                ),
            );
            return None;
        }
        let cfg_truthy = |k: &str| config.get(k).is_some_and(PyValue::truthy);
        let problem = match channel {
            Channel::Shuffle => {
                if shuffle_integration_id.unwrap_or(0) == 0 {
                    Some("shuffle_integration_id is required when channel='shuffle'".to_string())
                } else if !cfg_truthy("app_id") {
                    Some("config.app_id is required when channel='shuffle'".into())
                } else if destination.as_deref().is_none_or(str::is_empty) {
                    Some("destination is required when channel='shuffle'".into())
                } else {
                    None
                }
            }
            Channel::Webhook => match config.get("url").filter(|u| u.truthy()) {
                None => Some("config.url is required when channel='webhook'".into()),
                Some(url) => {
                    let lower = url.py_str().to_lowercase();
                    (!lower.starts_with("http://") && !lower.starts_with("https://"))
                        .then(|| "config.url must start with http:// or https://".to_string())
                }
            },
            Channel::Teams => (!cfg_truthy("webhook_url"))
                .then(|| "config.webhook_url is required when channel='teams'".to_string()),
            Channel::Resend => (recipient_mode == "static" && !cfg_truthy("to")).then(|| {
                "config.to is required when channel='resend' and recipient_mode='static'"
                    .to_string()
            }),
        };
        if let Some(msg) = problem {
            fail(v, msg);
            return None;
        }
        Some(Self {
            name,
            trigger: trigger?,
            channel,
            destination,
            min_severity,
            format_template,
            template_id,
            enabled,
            scope,
            recipient_mode,
            notify_on_self_assign,
            shuffle_integration_id,
            config,
        })
    }
}

/// `NotificationRouteUpdate`: only the fields sent.
#[derive(Debug, Clone, Default)]
pub struct RouteUpdate {
    /// Label.
    pub name: Patch<String>,
    /// Trigger.
    pub trigger: Patch<String>,
    /// Channel.
    pub channel: Patch<String>,
    /// Destination (not stripped on update).
    pub destination: Patch<String>,
    /// Severity floor.
    pub min_severity: Patch<String>,
    /// Inline template (not compiled on update).
    pub format_template: Patch<String>,
    /// Named template.
    pub template_id: Patch<i64>,
    /// Enabled.
    pub enabled: Patch<bool>,
    /// Scope.
    pub scope: Patch<String>,
    /// Recipient mode.
    pub recipient_mode: Patch<String>,
    /// Self-assignment flag.
    pub notify_on_self_assign: Patch<bool>,
    /// Shuffle integration.
    pub shuffle_integration_id: Patch<i64>,
    /// Config dict (replaced wholesale).
    pub config: Patch<Vec<(String, PyValue)>>,
}

impl RouteUpdate {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let triggers = trigger_values();
        let name = v.opt_str(obj, at, "name", StrRules::max(128).min(1));
        let trigger = v.opt_enum(obj, at, "trigger", &triggers);
        if trigger.as_deref() == Some("temp_password_issued") {
            v.push(
                "value_error",
                child(at, "trigger"),
                route_trigger_error("temp_password_issued"),
            );
        }
        let channel = v.opt_enum(obj, at, "channel", &Channel::KEYS);
        let destination = v.opt_str(obj, at, "destination", StrRules::any());
        let min_severity = v.opt_enum(obj, at, "min_severity", SEVERITIES);
        let format_template = v.opt_str(obj, at, "format_template", StrRules::any());
        let template_id = v.opt_int(obj, at, "template_id", IntRules::default());
        let enabled = v.opt_bool(obj, at, "enabled");
        let scope = v.opt_enum(obj, at, "scope", SCOPES);
        let recipient_mode = v.opt_enum(obj, at, "recipient_mode", RECIPIENT_MODES);
        let notify_on_self_assign = v.opt_bool(obj, at, "notify_on_self_assign");
        let shuffle_integration_id =
            v.opt_int(obj, at, "shuffle_integration_id", IntRules::default());
        let config = match obj.get("config") {
            None | Some(Value::Null) => None,
            Some(c @ Value::Object(_)) => match from_json(c) {
                PyValue::Dict(items) => Some(items),
                _ => None,
            },
            Some(_) => {
                v.push(
                    "dict_type",
                    child(at, "config"),
                    "Input should be a valid dictionary",
                );
                None
            }
        };
        Self {
            name: patched(obj, "name", name),
            trigger: patched(obj, "trigger", trigger),
            channel: patched(obj, "channel", channel),
            destination: patched(obj, "destination", destination),
            min_severity: patched(obj, "min_severity", min_severity),
            format_template: patched(obj, "format_template", format_template),
            template_id: patched(obj, "template_id", template_id),
            enabled: patched(obj, "enabled", enabled),
            scope: patched(obj, "scope", scope),
            recipient_mode: patched(obj, "recipient_mode", recipient_mode),
            notify_on_self_assign: patched(obj, "notify_on_self_assign", notify_on_self_assign),
            shuffle_integration_id: patched(obj, "shuffle_integration_id", shuffle_integration_id),
            config: patched(obj, "config", config),
        }
    }
}

// ---------------------------------------------------------------------------
// Read models
// ---------------------------------------------------------------------------

fn py_dt(t: Option<NaiveDateTime>) -> Value {
    t.map_or(Value::Null, |t| {
        Value::String(copilot_core::time::to_pydantic_iso(t))
    })
}

fn opt_s(v: &Option<String>) -> Value {
    v.as_ref().map_or(Value::Null, |s| Value::String(s.clone()))
}

fn len_errors(errors: &mut Vec<PyError>, name: &str, value: &str, min: usize, max: usize) {
    let n = value.chars().count();
    let input = PyValue::Str(value.to_string());
    if n < min {
        errors.push(PyError::new(
            vec![PLoc::Key(name.into())],
            "string_too_short",
            format!(
                "String should have at least {min} character{}",
                if min == 1 { "" } else { "s" }
            ),
            input,
        ));
    } else if n > max {
        errors.push(PyError::new(
            vec![PLoc::Key(name.into())],
            "string_too_long",
            format!("String should have at most {max} characters"),
            input,
        ));
    }
}

fn enum_error(errors: &mut Vec<PyError>, name: &str, value: &str, allowed: &[&str]) {
    if allowed.contains(&value) {
        return;
    }
    let quoted: Vec<String> = allowed.iter().map(|a| format!("'{a}'")).collect();
    let expected = match quoted.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => String::new(),
    };
    errors.push(PyError::new(
        vec![PLoc::Key(name.into())],
        "enum",
        format!("Input should be {expected}"),
        PyValue::Str(value.to_string()),
    ));
}

fn read_failed(title: &str, errors: &[PyError]) -> ApiError {
    ApiError::bad_request(pydantic::format(title, errors))
}

/// `NotificationRouteRead.from_orm(row)` as JSON.
pub fn route_read(r: &RouteRow) -> Result<Value, ApiError> {
    let trigger = if r.trigger == "severity_critical_or_high" {
        "investigation_complete"
    } else {
        r.trigger.as_str()
    };
    let mut errors = Vec::new();
    len_errors(&mut errors, "name", &r.name, 1, 128);
    enum_error(&mut errors, "trigger", trigger, &trigger_values());
    enum_error(&mut errors, "channel", &r.channel, &Channel::KEYS);
    enum_error(&mut errors, "min_severity", &r.min_severity, SEVERITIES);
    enum_error(&mut errors, "scope", &r.scope, SCOPES);
    enum_error(
        &mut errors,
        "recipient_mode",
        &r.recipient_mode,
        RECIPIENT_MODES,
    );
    if !errors.is_empty() {
        return Err(read_failed("NotificationRouteRead", &errors));
    }
    let config = r
        .config
        .as_deref()
        .filter(|c| !py_strip(c).is_empty())
        .and_then(|c| pyvalue::loads(c).ok())
        .filter(|c| matches!(c, PyValue::Dict(_)))
        .unwrap_or(PyValue::Dict(Vec::new()));
    let mut m = Map::new();
    m.insert("name".into(), Value::String(r.name.clone()));
    m.insert("trigger".into(), Value::String(trigger.into()));
    m.insert("channel".into(), Value::String(r.channel.clone()));
    m.insert(
        "destination".into(),
        r.destination
            .as_deref()
            .map_or(Value::Null, |d| Value::String(py_strip(d).into())),
    );
    m.insert("min_severity".into(), Value::String(r.min_severity.clone()));
    m.insert("format_template".into(), opt_s(&r.format_template));
    m.insert(
        "template_id".into(),
        r.template_id.map_or(Value::Null, Value::from),
    );
    m.insert("enabled".into(), Value::Bool(r.enabled));
    m.insert("scope".into(), Value::String(r.scope.clone()));
    m.insert(
        "recipient_mode".into(),
        Value::String(r.recipient_mode.clone()),
    );
    m.insert(
        "notify_on_self_assign".into(),
        Value::Bool(r.notify_on_self_assign),
    );
    m.insert(
        "shuffle_integration_id".into(),
        r.shuffle_integration_id.map_or(Value::Null, Value::from),
    );
    m.insert("config".into(), to_json(&config));
    m.insert("id".into(), Value::from(r.id));
    m.insert("customer_code".into(), opt_s(&r.customer_code));
    m.insert("last_dispatched_at".into(), py_dt(r.last_dispatched_at));
    m.insert("dispatch_count".into(), Value::from(r.dispatch_count));
    m.insert("created_by".into(), opt_s(&r.created_by));
    m.insert("created_at".into(), py_dt(Some(r.created_at)));
    m.insert("updated_at".into(), py_dt(r.updated_at));
    Ok(Value::Object(m))
}

/// A Python value as response JSON (FastAPI's `jsonable_encoder`).
pub fn to_json(v: &PyValue) -> Value {
    match v {
        PyValue::None => Value::Null,
        PyValue::Bool(b) => Value::Bool(*b),
        PyValue::Int(i) => i
            .parse::<i64>()
            .map(Value::from)
            .or_else(|_| i.parse::<u64>().map(Value::from))
            .unwrap_or_else(|_| {
                Value::Number(
                    serde_json::Number::from_f64(i.parse().unwrap_or(0.0))
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                )
            }),
        PyValue::Float(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
        PyValue::Str(s) => Value::String(s.clone()),
        PyValue::List(items) => Value::Array(items.iter().map(to_json).collect()),
        PyValue::Dict(items) => {
            Value::Object(items.iter().map(|(k, v)| (k.clone(), to_json(v))).collect())
        }
    }
}

/// `ShuffleIntegrationRead.from_orm(row)`.
pub fn integration_read(r: &IntegrationRow) -> Result<Value, ApiError> {
    let mut errors = Vec::new();
    len_errors(&mut errors, "display_name", &r.display_name, 1, 128);
    len_errors(&mut errors, "shuffle_org_id", &r.shuffle_org_id, 1, 64);
    if !errors.is_empty() {
        return Err(read_failed("ShuffleIntegrationRead", &errors));
    }
    let mut m = Map::new();
    m.insert("display_name".into(), Value::String(r.display_name.clone()));
    m.insert(
        "shuffle_org_id".into(),
        Value::String(py_strip(&r.shuffle_org_id).into()),
    );
    m.insert("enabled".into(), Value::Bool(r.enabled));
    m.insert("id".into(), Value::from(r.id));
    m.insert(
        "customer_code".into(),
        Value::String(r.customer_code.clone()),
    );
    m.insert("last_used_at".into(), py_dt(r.last_used_at));
    m.insert("created_by".into(), opt_s(&r.created_by));
    m.insert("created_at".into(), py_dt(Some(r.created_at)));
    m.insert("updated_at".into(), py_dt(r.updated_at));
    Ok(Value::Object(m))
}

/// `DispatchLogRead.from_orm(row)`.
pub fn log_read(r: &LogRow) -> Result<Value, ApiError> {
    let mut errors = Vec::new();
    enum_error(&mut errors, "status", &r.status, DISPATCH_STATUSES);
    if !errors.is_empty() {
        return Err(read_failed("DispatchLogRead", &errors));
    }
    let mut m = Map::new();
    m.insert("id".into(), Value::from(r.id));
    m.insert(
        "customer_code".into(),
        Value::String(r.customer_code.clone()),
    );
    m.insert(
        "alert_id".into(),
        r.alert_id.map_or(Value::Null, Value::from),
    );
    m.insert("entity_type".into(), Value::String(r.entity_type.clone()));
    m.insert("entity_id".into(), Value::from(r.entity_id));
    m.insert("dedupe_key".into(), Value::String(r.dedupe_key.clone()));
    m.insert("route_id".into(), Value::from(r.route_id));
    m.insert("trigger".into(), Value::String(r.trigger.clone()));
    m.insert("dispatched_at".into(), py_dt(Some(r.dispatched_at)));
    m.insert("status".into(), Value::String(r.status.clone()));
    m.insert("error_message".into(), opt_s(&r.error_message));
    m.insert(
        "latency_ms".into(),
        r.latency_ms.map_or(Value::Null, Value::from),
    );
    m.insert("payload_preview".into(), opt_s(&r.payload_preview));
    m.insert("provider_reference".into(), opt_s(&r.provider_reference));
    m.insert("triggered_by".into(), opt_s(&r.triggered_by));
    m.insert(
        "trigger_source".into(),
        Value::String(r.trigger_source.clone()),
    );
    Ok(Value::Object(m))
}

/// `NotificationTemplateRead.model_validate(row)`.
pub fn template_read(t: &TemplateRow) -> Result<Value, ApiError> {
    let mut errors = Vec::new();
    len_errors(&mut errors, "name", &t.name, 1, 128);
    if let Some(d) = t.description.as_deref() {
        len_errors(&mut errors, "description", d, 0, 512);
    }
    if let Some(tr) = t.trigger.as_deref() {
        enum_error(&mut errors, "trigger", tr, &trigger_values());
    }
    enum_error(&mut errors, "format", &t.format, TEMPLATE_FORMATS);
    len_errors(
        &mut errors,
        "body_template",
        &t.body_template,
        1,
        usize::MAX,
    );
    if let Some(c) = t.customer_code.as_deref() {
        len_errors(&mut errors, "customer_code", c, 0, 64);
    }
    if !errors.is_empty() {
        return Err(read_failed("NotificationTemplateRead", &errors));
    }
    let mut m = Map::new();
    m.insert("name".into(), Value::String(t.name.clone()));
    m.insert("description".into(), opt_s(&t.description));
    m.insert("trigger".into(), opt_s(&t.trigger));
    m.insert("format".into(), Value::String(t.format.clone()));
    m.insert("subject_template".into(), opt_s(&t.subject_template));
    m.insert(
        "body_template".into(),
        Value::String(t.body_template.clone()),
    );
    m.insert("customer_code".into(), opt_s(&t.customer_code));
    m.insert("id".into(), Value::from(t.id));
    m.insert("is_default".into(), Value::Bool(t.is_default));
    m.insert("created_by".into(), opt_s(&t.created_by));
    m.insert("created_at".into(), py_dt(Some(t.created_at)));
    m.insert("updated_at".into(), py_dt(t.updated_at));
    Ok(Value::Object(m))
}

// ---------------------------------------------------------------------------
// Shuffle integrations
// ---------------------------------------------------------------------------

/// `ShuffleIntegrationCreate`.
#[derive(Debug, Clone)]
pub struct IntegrationCreate {
    /// Label.
    pub display_name: String,
    /// Org-Id (stripped after the length checks).
    pub shuffle_org_id: String,
    /// Enabled.
    pub enabled: bool,
}

impl IntegrationCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let display_name = v.req_str(obj, at, "display_name", StrRules::max(128).min(1));
        let org = v.req_str(obj, at, "shuffle_org_id", StrRules::max(64).min(1));
        let enabled = v.bool_or(obj, at, "enabled", true);
        Self {
            display_name,
            shuffle_org_id: py_strip(&org).to_string(),
            enabled,
        }
    }
}

/// `ShuffleIntegrationUpdate`.
#[derive(Debug, Clone, Default)]
pub struct IntegrationUpdate {
    /// Label.
    pub display_name: Patch<String>,
    /// Org-Id (not stripped on update).
    pub shuffle_org_id: Patch<String>,
    /// Enabled.
    pub enabled: Patch<bool>,
}

impl IntegrationUpdate {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let display_name = v.opt_str(obj, at, "display_name", StrRules::max(128).min(1));
        let org = v.opt_str(obj, at, "shuffle_org_id", StrRules::max(64).min(1));
        let enabled = v.opt_bool(obj, at, "enabled");
        Self {
            display_name: patched(obj, "display_name", display_name),
            shuffle_org_id: patched(obj, "shuffle_org_id", org),
            enabled: patched(obj, "enabled", enabled),
        }
    }
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// `NotificationTemplateCreate`.
#[derive(Debug, Clone)]
pub struct TemplateCreate {
    /// Name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Trigger scope.
    pub trigger: Option<String>,
    /// Format.
    pub format: String,
    /// Subject.
    pub subject_template: Option<String>,
    /// Body.
    pub body_template: String,
    /// Customer scope.
    pub customer_code: Option<String>,
}

impl TemplateCreate {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let triggers = trigger_values();
        Self {
            name: v.req_str(obj, at, "name", StrRules::max(128).min(1)),
            description: v.opt_str(obj, at, "description", StrRules::max(512)),
            trigger: v.opt_enum(obj, at, "trigger", &triggers),
            format: v.enum_or(obj, at, "format", TEMPLATE_FORMATS, "text"),
            subject_template: v.opt_str(obj, at, "subject_template", StrRules::any()),
            body_template: v.req_str(obj, at, "body_template", StrRules::any().min(1)),
            customer_code: v.opt_str(obj, at, "customer_code", StrRules::max(64)),
        }
    }
}

/// `NotificationTemplateUpdate`.
#[derive(Debug, Clone, Default)]
pub struct TemplateUpdate {
    /// Name.
    pub name: Patch<String>,
    /// Description.
    pub description: Patch<String>,
    /// Trigger scope.
    pub trigger: Patch<String>,
    /// Format.
    pub format: Patch<String>,
    /// Subject.
    pub subject_template: Patch<String>,
    /// Body.
    pub body_template: Patch<String>,
    /// Customer scope.
    pub customer_code: Patch<String>,
}

impl TemplateUpdate {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let triggers = trigger_values();
        let name = v.opt_str(obj, at, "name", StrRules::max(128).min(1));
        let description = v.opt_str(obj, at, "description", StrRules::any());
        let trigger = v.opt_enum(obj, at, "trigger", &triggers);
        let format = v.opt_enum(obj, at, "format", TEMPLATE_FORMATS);
        let subject = v.opt_str(obj, at, "subject_template", StrRules::any());
        let body = v.opt_str(obj, at, "body_template", StrRules::any().min(1));
        let customer = v.opt_str(obj, at, "customer_code", StrRules::max(64));
        Self {
            name: patched(obj, "name", name),
            description: patched(obj, "description", description),
            trigger: patched(obj, "trigger", trigger),
            format: patched(obj, "format", format),
            subject_template: patched(obj, "subject_template", subject),
            body_template: patched(obj, "body_template", body),
            customer_code: patched(obj, "customer_code", customer),
        }
    }
}

/// `TemplatePreviewRequest`.
#[derive(Debug, Clone)]
pub struct PreviewRequest {
    /// Body source.
    pub body_template: String,
    /// Subject source.
    pub subject_template: Option<String>,
    /// Format.
    pub format: String,
    /// The sample event's trigger.
    pub trigger: String,
    /// Whose branding to preview with.
    pub customer_code: Option<String>,
}

impl PreviewRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let triggers = trigger_values();
        Self {
            body_template: v.req_str(obj, at, "body_template", StrRules::any().min(1)),
            subject_template: v.opt_str(obj, at, "subject_template", StrRules::any()),
            format: v.enum_or(obj, at, "format", TEMPLATE_FORMATS, "text"),
            trigger: v.enum_or(obj, at, "trigger", &triggers, "alert_created"),
            customer_code: v.opt_str(obj, at, "customer_code", StrRules::any()),
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch, manual send, bridged events
// ---------------------------------------------------------------------------

/// `DispatchRequest` (Talon's body).
#[derive(Debug, Clone)]
pub struct DispatchRequest {
    /// Tenant.
    pub customer_code: String,
    /// Alert.
    pub alert_id: i64,
    /// Trigger.
    pub trigger: String,
    /// Severity.
    pub severity_assessment: String,
    /// Summary.
    pub summary: String,
    /// Link.
    pub report_url: Option<String>,
    /// Alert title.
    pub alert_name: Option<String>,
}

impl DispatchRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let triggers = trigger_values();
        Self {
            customer_code: v.req_str(obj, at, "customer_code", StrRules::any()),
            alert_id: v.req_int(obj, at, "alert_id", IntRules::default()),
            trigger: v.req_enum(obj, at, "trigger", &triggers),
            severity_assessment: v.req_enum(obj, at, "severity_assessment", SEVERITIES),
            summary: v.req_str(obj, at, "summary", StrRules::any()),
            report_url: v.opt_str(obj, at, "report_url", StrRules::any()),
            alert_name: v.opt_str(obj, at, "alert_name", StrRules::any()),
        }
    }
}

/// `ManualSendRequest`.
#[derive(Debug, Clone)]
pub struct ManualSendRequest {
    /// `alert` | `case`.
    pub entity_type: String,
    /// Entity.
    pub entity_id: i64,
    /// Route.
    pub route_id: i64,
    /// Attach the AI report.
    pub include_ai_report: bool,
}

impl ManualSendRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            entity_type: v.req_str(obj, at, "entity_type", StrRules::any()),
            entity_id: v.req_int(obj, at, "entity_id", IntRules::default()),
            route_id: v.req_int(obj, at, "route_id", IntRules::default()),
            include_ai_report: v.bool_or(obj, at, "include_ai_report", false),
        }
    }
}

/// `NotificationEvent` as a request body (`POST /notifications/events`).
#[derive(Debug, Clone)]
pub struct EventBody {
    /// Tenant.
    pub customer_code: Option<String>,
    /// Trigger.
    pub trigger: String,
    /// Severity.
    pub severity: String,
    /// Title.
    pub subject: String,
    /// Body.
    pub summary: String,
    /// Entity type.
    pub entity_type: String,
    /// Entity.
    pub entity_id: i64,
    /// Idempotency key.
    pub dedupe_key: String,
    /// Link.
    pub link_url: Option<String>,
    /// Assignee.
    pub assignee_username: Option<String>,
    /// Actor.
    pub actor_username: Option<String>,
    /// Extras.
    pub context: Map<String, Value>,
}

impl EventBody {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let triggers = trigger_values();
        let customer_code = v.opt_str(obj, at, "customer_code", StrRules::any());
        let trigger = v.req_enum(obj, at, "trigger", &triggers);
        let severity = v.req_enum(obj, at, "severity", SEVERITIES);
        let subject = v.req_str(obj, at, "subject", StrRules::any());
        let summary = v.req_str(obj, at, "summary", StrRules::any());
        let entity_type = v.str_or(obj, at, "entity_type", StrRules::any(), "alert");
        let entity_id = v.req_int(obj, at, "entity_id", IntRules::default());
        let dedupe_key = v.req_str(obj, at, "dedupe_key", StrRules::any());
        let link_url = v.opt_str(obj, at, "link_url", StrRules::any());
        let assignee_username = v.opt_str(obj, at, "assignee_username", StrRules::any());
        let actor_username = v.opt_str(obj, at, "actor_username", StrRules::any());
        let context = match obj.get("context") {
            None => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => {
                v.push(
                    "dict_type",
                    child(at, "context"),
                    "Input should be a valid dictionary",
                );
                Map::new()
            }
        };
        Self {
            customer_code,
            trigger,
            severity,
            subject,
            summary,
            entity_type,
            entity_id,
            dedupe_key,
            link_url,
            assignee_username,
            actor_username,
            context,
        }
    }
}

/// `ShuffleApp` / `ShuffleOrg` items as the routes forward them.
#[derive(Debug, Clone, Serialize)]
pub struct ShuffleApp {
    /// Id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Description.
    pub description: Value,
    /// Image.
    pub large_image: Value,
}

/// Config items of a dict value (re-exported for the services).
pub fn config_items(v: &PyValue) -> Vec<(String, PyValue)> {
    dict_items(v).map(<[_]>::to_vec).unwrap_or_default()
}
