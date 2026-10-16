//! `app/active_response/schema/active_response.py` and the event notification
//! of `schema/graylog.py` (`GraylogEventNotification`).
//!
//! **`InvokeActiveResponseRequest`** is read the way Pydantic reads it,
//! including its `create_alert` model validator (`mode="before"`, #960),
//! which runs *before* any field is validated and so decides what a bad
//! body answers:
//!
//! 1. a body that is not an object is FastAPI's `model_attributes_type`;
//! 2. with a `command` (absent and `null` alike skip the validator): an
//!    `alert` that is truthy but not an object is the root `ValueError`
//!    `'alert' must be an object`; a command that is neither a value nor
//!    (case-insensitively) a name of `ActiveResponseCommand` is the
//!    `HTTPException(400)` its `_missing_` raises; the alert validated as
//!    the command's model (`WindowsFirewallAlert`, `LinuxFirewallAlert`,
//!    `SysmonConfigReloadAlert`) fails with that model's errors at the root
//!    (Pydantic re-raises a `ValidationError` from a validator as its own
//!    lines), and passes as its JSON dump;
//! 3. then the fields, in declaration order: `endpoint`
//!    (`Literal["/active-response"]`), `arguments` (`list[str]`), `command`,
//!    `custom` (`Literal[True]`: `true`, `1` and `1.0` match), `alert`
//!    (`Dict[str, Any]`), `params` (`ParamsModel`, whose `agents_list`
//!    turns `["*"]` into `[]`).

use std::sync::LazyLock;

use serde_json::{Map, Value};

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Check, Field, Model, Ty};
use copilot_upstream::respond::from_json;
use copilot_web::validate::{Loc, LocPart, StrRules, Validator, body_loc};
use copilot_web::{ApiError, JsonBody};

/// `ActiveResponsesSupported`: name and description, in declaration order.
pub const SUPPORTED: &[(&str, &str)] = &[(
    "WINDOWS_FIREWALL",
    "Block or unblock any outbound traffic to the defined IP address via the Windows Firewall",
)];

/// `ActiveResponseCommand`'s members (each name is its value).
pub const COMMANDS: &[&str] = &["windows_firewall", "linux_firewall", "sysmon_config_reload"];

/// `AlertAction`'s values.
pub const ALERT_ACTIONS: &[&str] = &["unblock", "block", "sysmon_config_reload"];

/// `SysmonConfigReloadAlert.action`'s `Literal` as Pydantic prints it.
const SYSMON_LITERAL: &str =
    "Input should be <AlertAction.sysmon_config_reload: 'sysmon_config_reload'>";

/// A validated `InvokeActiveResponseRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct InvokeRequest {
    /// `arguments`.
    pub arguments: Vec<String>,
    /// `command.value`.
    pub command: &'static str,
    /// `alert`: the command's alert model, dumped.
    pub alert: PyValue,
    /// `params.wait_for_complete`.
    pub wait_for_complete: bool,
    /// `params.agents_list` (`["*"]` already `[]`).
    pub agents_list: Option<Vec<String>>,
}

fn child(at: &Loc, key: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(key.into()));
    l
}

/// `ActiveResponseCommand(value)`: the member, or `_missing_`'s 400.
pub fn lookup_command(value: &Value) -> Result<&'static str, ApiError> {
    if let Value::String(s) = value {
        if let Some(c) = COMMANDS.iter().find(|c| **c == s.as_str()) {
            return Ok(c);
        }
        let lower = s.to_lowercase();
        if let Some(c) = COMMANDS.iter().find(|c| c.to_lowercase() == lower) {
            return Ok(c);
        }
    }
    let shown = match value {
        Value::String(s) => s.clone(),
        other => from_json(other).py_str(),
    };
    Err(ApiError::bad_request(format!(
        "Invalid command: {shown}, must be one of {}",
        COMMANDS.join(", ")
    )))
}

/// `FirewallAlert.check_ip`: the stripped address, or the `ValueError`.
fn check_ip(v: &str) -> Result<String, String> {
    let stripped = copilot_web::form::py_strip(v);
    if copilot_ingest::py::is_ip_address(stripped) {
        Ok(stripped.to_string())
    } else {
        Err(format!("'{v}' is not a valid IP address"))
    }
}

/// `alert_model(**alert).model_dump(mode="json")`, its errors located at
/// the root.
fn validate_alert(command: &str, alert: &Map<String, Value>, v: &mut Validator) -> Option<PyValue> {
    let root = body_loc();
    if command == "sysmon_config_reload" {
        if let Some(action) = alert.get("action") {
            if action.as_str() != Some("sysmon_config_reload") {
                v.push("literal_error", child(&root, "action"), SYSMON_LITERAL);
                return None;
            }
        }
        return Some(PyValue::Dict(vec![(
            "action".into(),
            PyValue::Str("sysmon_config_reload".into()),
        )]));
    }
    let action = alert
        .get("action")
        .map(|a| v.check_enum(&child(&root, "action"), a, ALERT_ACTIONS));
    if action.is_none() {
        v.missing(child(&root, "action"));
    }
    let ip_loc = child(&root, "ip");
    let ip = match alert.get("ip") {
        None => {
            v.missing(ip_loc);
            None
        }
        Some(Value::String(s)) => match check_ip(s) {
            Ok(ip) => Some(ip),
            Err(e) => {
                v.push("value_error", ip_loc, format!("Value error, {e}"));
                None
            }
        },
        Some(_) => {
            v.push("string_type", ip_loc, "Input should be a valid string");
            None
        }
    };
    match (action.flatten(), ip) {
        (Some(action), Some(ip)) if !v.has_errors() => Some(PyValue::Dict(vec![
            ("action".into(), PyValue::Str(action)),
            ("ip".into(), PyValue::Str(ip)),
        ])),
        _ => None,
    }
}

/// `Literal[True]`: `True == 1 == 1.0` in Python.
fn is_true_literal(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64() == Some(1) || n.as_f64() == Some(1.0),
        _ => false,
    }
}

/// Read `InvokeActiveResponseRequest` from the body.
pub fn read_invoke(body: &JsonBody) -> Result<InvokeRequest, ApiError> {
    let obj = match body {
        JsonBody::Value(Value::Object(obj)) => obj,
        other => {
            // Not an object: the body's own error (`missing`,
            // `model_attributes_type`).
            other.model(|_, _, _| ())?;
            return Err(ApiError::internal("active response body without errors"));
        }
    };
    let root = body_loc();
    // `create_alert`.
    let mut validated: Option<(&'static str, PyValue)> = None;
    if let Some(command) = obj.get("command").filter(|c| !c.is_null()) {
        let alert = match obj.get("alert") {
            Some(a) if from_json(a).truthy() => a,
            _ => &Value::Object(Map::new()),
        };
        let Value::Object(alert) = alert else {
            let mut v = Validator::new();
            v.push(
                "value_error",
                root,
                "Value error, 'alert' must be an object",
            );
            v.finish()?;
            return Err(ApiError::internal("alert check without errors"));
        };
        let command = lookup_command(command)?;
        let mut v = Validator::new();
        let dump = validate_alert(command, alert, &mut v);
        v.finish()?;
        let dump = dump.ok_or_else(|| ApiError::internal("alert model without errors"))?;
        validated = Some((command, dump));
    }
    // The fields.
    let mut v = Validator::new();
    if let Some(endpoint) = obj.get("endpoint") {
        if endpoint.as_str() != Some("/active-response") {
            v.push(
                "literal_error",
                child(&root, "endpoint"),
                "Input should be '/active-response'",
            );
        }
    }
    let arguments = match obj.get("arguments") {
        None => Vec::new(),
        Some(a) => v.str_items(a, &child(&root, "arguments")),
    };
    let command = match &validated {
        Some((c, _)) => Some(*c),
        None => {
            match obj.get("command") {
                None => v.missing(child(&root, "command")),
                Some(_) => v.push(
                    "enum",
                    child(&root, "command"),
                    "Input should be 'windows_firewall', 'linux_firewall' or 'sysmon_config_reload'",
                ),
            }
            None
        }
    };
    if let Some(custom) = obj.get("custom") {
        if !is_true_literal(custom) {
            v.push(
                "literal_error",
                child(&root, "custom"),
                "Input should be True",
            );
        }
    }
    let alert = match &validated {
        Some((_, dump)) => Some(dump.clone()),
        None => match obj.get("alert") {
            None => {
                v.missing(child(&root, "alert"));
                None
            }
            Some(a @ Value::Object(_)) => Some(from_json(a)),
            Some(_) => {
                v.push(
                    "dict_type",
                    child(&root, "alert"),
                    "Input should be a valid dictionary",
                );
                None
            }
        },
    };
    let params_loc = child(&root, "params");
    let mut wait_for_complete = false;
    let mut agents_list = None;
    match obj.get("params") {
        None => v.missing(params_loc),
        Some(Value::Object(p)) => {
            wait_for_complete = v.req_bool(p, &params_loc, "wait_for_complete");
            agents_list = match p.get("agents_list") {
                None | Some(Value::Null) => None,
                Some(Value::Array(items)) if items.len() == 1 && items[0].as_str() == Some("*") => {
                    Some(Vec::new())
                }
                Some(x) => Some(v.str_items(x, &child(&params_loc, "agents_list"))),
            };
        }
        Some(_) => v.push(
            "model_attributes_type",
            params_loc,
            "Input should be a valid dictionary or object to extract fields from",
        ),
    }
    v.finish()?;
    match (command, alert) {
        (Some(command), Some(alert)) => Ok(InvokeRequest {
            arguments,
            command,
            alert,
            wait_for_complete,
            agents_list,
        }),
        _ => Err(ApiError::internal("active response body without errors")),
    }
}

// --- the Graylog event notification -------------------------------------------

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

fn empty_str() -> PyValue {
    PyValue::Str(String::new())
}

/// `COMMAND_NAME_PATTERN.fullmatch(v)`: `[A-Za-z0-9_-]{1,64}`.
pub fn is_command_name(v: &str) -> bool {
    let n = v.chars().count();
    (1..=64).contains(&n)
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn check_command(v: &PyValue) -> Result<PyValue, Check> {
    match v {
        PyValue::Str(s) if is_command_name(s) => Ok(v.clone()),
        _ => Err(Check::ValueError(
            "COMMAND must be a bare active-response script name (letters, digits, '_' or '-', \
             max 64 chars)"
                .into(),
        )),
    }
}

/// `ReplayInfo`.
pub static REPLAY_INFO: Model = Model::new(
    "ReplayInfo",
    &[
        Field::req("timerange_start", Ty::DateTime),
        Field::req("timerange_end", Ty::DateTime),
        Field::req("query", Ty::Str),
        Field::req("streams", Ty::List(&Ty::Str)),
        Field::def("filters", Ty::List(&Ty::Any), empty_list),
    ],
);

/// `GraylogEventFields` with `additional_fields` given by its alias
/// (`__extra__`).
pub static EVENT_FIELDS: Model = Model::allowing_extra(
    "GraylogEventFields",
    &[
        Field::req("COMMAND", Ty::Str).after(check_command),
        Field::req("AGENT_ID", Ty::Str),
        Field::req("ACTION", Ty::Str),
        Field::req("VALUE", Ty::Str),
        Field::def("additional_fields", Ty::Dict(&Ty::Any), empty_dict).alias("__extra__"),
    ],
);

/// The same, `additional_fields` given by name (`populate_by_name=True`,
/// which Pydantic only consults without the alias).
pub static EVENT_FIELDS_BY_NAME: Model = Model::allowing_extra(
    "GraylogEventFields",
    &[
        Field::req("COMMAND", Ty::Str).after(check_command),
        Field::req("AGENT_ID", Ty::Str),
        Field::req("ACTION", Ty::Str),
        Field::req("VALUE", Ty::Str),
        Field::def("additional_fields", Ty::Dict(&Ty::Any), empty_dict),
    ],
);

macro_rules! event_model {
    ($name:ident, $fields:expr) => {
        /// `GraylogEvent` (with one of the two `fields` spellings).
        pub static $name: Model = Model::new(
            "GraylogEvent",
            &[
                Field::req("id", Ty::Str),
                Field::req("event_definition_type", Ty::Str),
                Field::req("event_definition_id", Ty::Str),
                Field::req("origin_context", Ty::Str),
                Field::req("timestamp", Ty::DateTime),
                Field::req("timestamp_processing", Ty::DateTime),
                Field::opt("timerange_start", Ty::Nullable(&Ty::DateTime)),
                Field::opt("timerange_end", Ty::Nullable(&Ty::DateTime)),
                Field::def("streams", Ty::List(&Ty::Str), empty_list),
                Field::req("source_streams", Ty::List(&Ty::Str)),
                Field::req("message", Ty::Str),
                Field::req("source", Ty::Str),
                Field::def("key_tuple", Ty::List(&Ty::Any), empty_list),
                Field::req("key", Ty::Str),
                Field::req("priority", Ty::Int),
                Field::def("scores", Ty::Dict(&Ty::Any), empty_dict),
                Field::def("associated_assets", Ty::List(&Ty::Any), empty_list),
                Field::req("alert", Ty::Bool),
                Field::req("fields", Ty::Model($fields)),
                Field::def("group_by_fields", Ty::Dict(&Ty::Any), empty_dict),
                Field::req("replay_info", Ty::Model(&REPLAY_INFO)),
            ],
        );
    };
}

event_model!(EVENT, &EVENT_FIELDS);
event_model!(EVENT_BY_NAME, &EVENT_FIELDS_BY_NAME);

macro_rules! notification_model {
    ($name:ident, $event:expr) => {
        /// `GraylogEventNotification` (with one of the two event models).
        pub static $name: Model = Model::new(
            "GraylogEventNotification",
            &[
                Field::req("event_definition_id", Ty::Str),
                Field::req("event_definition_type", Ty::Str),
                Field::req("event_definition_title", Ty::Str),
                Field::def("event_definition_description", Ty::Str, empty_str),
                Field::req("job_definition_id", Ty::Str),
                Field::req("job_trigger_id", Ty::Str),
                Field::req("event", Ty::Model($event)),
                Field::def("backlog", Ty::List(&Ty::Any), empty_list),
            ],
        );
    };
}

notification_model!(NOTIFICATION, &EVENT);
notification_model!(NOTIFICATION_BY_NAME, &EVENT_BY_NAME);

/// The four fields the webhook forwards (`event.fields`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFields {
    /// `COMMAND`.
    pub command: String,
    /// `AGENT_ID`.
    pub agent_id: String,
    /// `ACTION`.
    pub action: String,
    /// `VALUE`.
    pub value: String,
}

/// The model to validate `body` with: `additional_fields` is read by its
/// alias, and by its name only when the alias is absent.
fn notification_model(body: &JsonBody) -> &'static Model {
    let by_name = match body {
        JsonBody::Value(v) => v
            .get("event")
            .and_then(|e| e.get("fields"))
            .and_then(Value::as_object)
            .is_some_and(|f| !f.contains_key("__extra__") && f.contains_key("additional_fields")),
        _ => false,
    };
    if by_name {
        &NOTIFICATION_BY_NAME
    } else {
        &NOTIFICATION
    }
}

/// Validate the webhook body; `Ok` holds `event.fields`.
pub fn read_notification(body: &JsonBody) -> Result<EventFields, ApiError> {
    let dump = copilot_upstream::respond::body_model(body, notification_model(body))?;
    let fields =
        copilot_upstream::model::field(copilot_upstream::model::field(&dump, "event"), "fields");
    let text = |key: &str| {
        copilot_upstream::model::field(fields, key)
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    Ok(EventFields {
        command: text("COMMAND"),
        agent_id: text("AGENT_ID"),
        action: text("ACTION"),
        value: text("VALUE"),
    })
}

/// `ActiveResponse` items of `ActiveResponsesSupportedResponse`.
pub static SUPPORTED_ITEMS: LazyLock<Vec<PyValue>> = LazyLock::new(|| {
    SUPPORTED
        .iter()
        .map(|(name, description)| item(name, description))
        .collect()
});

/// One `ActiveResponse`.
pub fn item(name: &str, description: &str) -> PyValue {
    PyValue::Dict(vec![
        ("name".into(), PyValue::Str(name.into())),
        ("description".into(), PyValue::Str(description.into())),
    ])
}

/// `StrRules` for a plain `str`.
pub const ANY_STR: StrRules = StrRules::any();
