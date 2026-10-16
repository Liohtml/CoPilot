//! The Velociraptor event models of `app/incidents/schema/velo_sigma.py`
//! and `VelociraptorSigmaAlert.get_parsed_event`.
//!
//! An event is parsed into one of four Pydantic models (Sysmon, Defender,
//! PowerShell, generic), chosen from the alert's channel, else the event's
//! provider name, else its system channel; a model that does not fit falls
//! back to the generic one, whose own failure is the exception the ingest
//! reports. What the ingest reads afterwards is what Python reads off the
//! model instance:
//!
//! - the declared fields' *validated* values (attribute access, `dir()`),
//! - the extra keys (`extra="allow"`), reachable through `getattr` but not
//!   listed by `dir()`,
//! - `model_dump()`: the declared fields under their names, then the
//!   extras merged in (an extra named like a field overwrites its value in
//!   place — `DefenderEventData` lets a field be given by name or alias, and
//!   the unused key stays an extra).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Field, Invalid, Model, Ty, format_validation_error, validate};

use crate::py::{dict_get, dict_set, py_strip};

static SYSTEM_PROVIDER: Model = Model::new(
    "SystemProvider",
    &[Field::req("Name", Ty::Str), Field::req("Guid", Ty::Str)],
);
static EVENT_ID: Model = Model::new("EventID", &[Field::req("Value", Ty::Int)]);
static TIME_CREATED: Model = Model::new("TimeCreated", &[Field::req("SystemTime", Ty::Float)]);
static EXECUTION: Model = Model::new(
    "Execution",
    &[
        Field::req("ProcessID", Ty::Int),
        Field::req("ThreadID", Ty::Int),
    ],
);
static SECURITY: Model = Model::new("Security", &[Field::req("UserID", Ty::Str)]);

fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

static SYSTEM_DATA: Model = Model::new(
    "SystemData",
    &[
        Field::req("Provider", Ty::Model(&SYSTEM_PROVIDER)),
        Field::req("EventID", Ty::Model(&EVENT_ID)),
        Field::req("Version", Ty::Int),
        Field::req("Level", Ty::Int),
        Field::req("Task", Ty::Int),
        Field::req("Opcode", Ty::Int),
        Field::req("Keywords", Ty::Int),
        Field::req("TimeCreated", Ty::Model(&TIME_CREATED)),
        Field::req("EventRecordID", Ty::Int),
        Field::def("Correlation", Ty::Dict(&Ty::Any), empty_dict),
        Field::req("Execution", Ty::Model(&EXECUTION)),
        Field::req("Channel", Ty::Str),
        Field::req("Computer", Ty::Str),
        Field::req("Security", Ty::Model(&SECURITY)),
    ],
);

static SYSMON_EVENT_DATA: Model = Model::allowing_extra(
    "SysmonEventData",
    &[
        Field::req("RuleName", Ty::Str),
        Field::req("UtcTime", Ty::Str),
        Field::req("SourceProcessGUID", Ty::Str),
        Field::req("SourceProcessId", Ty::Int),
        Field::req("SourceThreadId", Ty::Int),
        Field::req("SourceImage", Ty::Str),
        Field::req("TargetProcessGUID", Ty::Str),
        Field::req("TargetProcessId", Ty::Int),
        Field::req("TargetImage", Ty::Str),
        Field::req("GrantedAccess", Ty::Int),
        Field::req("CallTrace", Ty::Str),
        Field::req("SourceUser", Ty::Str),
        Field::req("TargetUser", Ty::Str),
    ],
);

const OPT_STR: Ty = Ty::Nullable(&Ty::Str);

/// `DefenderEventData`'s fields: attribute name and alias.
pub const DEFENDER_FIELDS: &[(&str, &str)] = &[
    ("product_name", "Product Name"),
    ("product_version", "Product Version"),
    ("detection_id", "Detection ID"),
    ("detection_time", "Detection Time"),
    ("threat_id", "Threat ID"),
    ("threat_name", "Threat Name"),
    ("severity_id", "Severity ID"),
    ("severity_name", "Severity Name"),
    ("category_id", "Category ID"),
    ("category_name", "Category Name"),
    ("fw_link", "FWLink"),
    ("status_code", "Status Code"),
    ("status_description", "Status Description"),
    ("state", "State"),
    ("source_id", "Source ID"),
    ("source_name", "Source Name"),
    ("process_name", "Process Name"),
    ("detection_user", "Detection User"),
    ("path", "Path"),
    ("origin_id", "Origin ID"),
    ("origin_name", "Origin Name"),
    ("execution_id", "Execution ID"),
    ("execution_name", "Execution Name"),
    ("type_id", "Type ID"),
    ("type_name", "Type Name"),
    ("pre_execution_status", "Pre Execution Status"),
    ("action_id", "Action ID"),
    ("action_name", "Action Name"),
    ("error_code", "Error Code"),
    ("error_description", "Error Description"),
    ("post_clean_status", "Post Clean Status"),
    ("additional_actions_id", "Additional Actions ID"),
    ("additional_actions_string", "Additional Actions String"),
    ("remediation_user", "Remediation User"),
    (
        "security_intelligence_version",
        "Security intelligence Version",
    ),
    ("engine_version", "Engine Version"),
];

macro_rules! defender_opt {
    ($name:literal, $alias:literal) => {
        Field::opt($name, OPT_STR).alias($alias)
    };
}

static DEFENDER_EVENT_DATA: Model = Model::allowing_extra(
    "DefenderEventData",
    &[
        Field::req("product_name", Ty::Str).alias("Product Name"),
        Field::req("product_version", Ty::Str).alias("Product Version"),
        defender_opt!("detection_id", "Detection ID"),
        defender_opt!("detection_time", "Detection Time"),
        defender_opt!("threat_id", "Threat ID"),
        defender_opt!("threat_name", "Threat Name"),
        defender_opt!("severity_id", "Severity ID"),
        defender_opt!("severity_name", "Severity Name"),
        defender_opt!("category_id", "Category ID"),
        defender_opt!("category_name", "Category Name"),
        defender_opt!("fw_link", "FWLink"),
        defender_opt!("status_code", "Status Code"),
        defender_opt!("status_description", "Status Description"),
        defender_opt!("state", "State"),
        defender_opt!("source_id", "Source ID"),
        defender_opt!("source_name", "Source Name"),
        defender_opt!("process_name", "Process Name"),
        defender_opt!("detection_user", "Detection User"),
        defender_opt!("path", "Path"),
        defender_opt!("origin_id", "Origin ID"),
        defender_opt!("origin_name", "Origin Name"),
        defender_opt!("execution_id", "Execution ID"),
        defender_opt!("execution_name", "Execution Name"),
        defender_opt!("type_id", "Type ID"),
        defender_opt!("type_name", "Type Name"),
        defender_opt!("pre_execution_status", "Pre Execution Status"),
        defender_opt!("action_id", "Action ID"),
        defender_opt!("action_name", "Action Name"),
        defender_opt!("error_code", "Error Code"),
        defender_opt!("error_description", "Error Description"),
        defender_opt!("post_clean_status", "Post Clean Status"),
        defender_opt!("additional_actions_id", "Additional Actions ID"),
        defender_opt!("additional_actions_string", "Additional Actions String"),
        defender_opt!("remediation_user", "Remediation User"),
        defender_opt!(
            "security_intelligence_version",
            "Security intelligence Version"
        ),
        defender_opt!("engine_version", "Engine Version"),
    ],
);

static POWERSHELL_EVENT_DATA: Model = Model::allowing_extra(
    "PowerShellEventData",
    &[
        Field::req("MessageNumber", Ty::Int),
        Field::req("MessageTotal", Ty::Int),
        Field::req("ScriptBlockText", Ty::Str),
        Field::req("ScriptBlockId", Ty::Str),
        Field::req("Path", Ty::Str),
        Field::opt("HostApplication", OPT_STR),
        Field::opt("HostName", OPT_STR),
        Field::opt("HostVersion", OPT_STR),
        Field::opt("EngineVersion", OPT_STR),
        Field::opt("RunspaceId", OPT_STR),
        Field::opt("PipelineId", Ty::Nullable(&Ty::Int)),
        Field::opt("CommandName", OPT_STR),
        Field::opt("CommandType", OPT_STR),
        Field::opt("ConnectedUser", OPT_STR),
    ],
);

static GENERIC_EVENT_DATA: Model = Model::allowing_extra("GenericEventData", &[]);

macro_rules! event_model {
    ($ident:ident, $name:literal, $data:ident) => {
        static $ident: Model = Model::new(
            $name,
            &[
                Field::req("System", Ty::Model(&SYSTEM_DATA)),
                Field::req("Message", Ty::Str),
                Field::req("EventData", Ty::Model(&$data)),
            ],
        );
    };
}

event_model!(SYSMON_EVENT, "SysmonEvent", SYSMON_EVENT_DATA);
event_model!(DEFENDER_EVENT, "DefenderEvent", DEFENDER_EVENT_DATA);
event_model!(POWERSHELL_EVENT, "PowerShellEvent", POWERSHELL_EVENT_DATA);
event_model!(GENERIC_EVENT, "GenericEvent", GENERIC_EVENT_DATA);

/// The event union of `VelociraptorSigmaAlert.event`, as FastAPI validates
/// a request body (after the `parse_event` before-validator).
pub static EVENT_UNION: Ty = Ty::Union(&[
    Ty::Str,
    Ty::Dict(&Ty::Any),
    Ty::Model(&SYSMON_EVENT),
    Ty::Model(&DEFENDER_EVENT),
    Ty::Model(&GENERIC_EVENT),
]);

/// Which model an event was parsed into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// `SysmonEvent`.
    Sysmon,
    /// `DefenderEvent`.
    Defender,
    /// `PowerShellEvent`.
    PowerShell,
    /// `GenericEvent`.
    Generic,
}

impl EventKind {
    /// `type(parsed_event).__name__`.
    pub fn class_name(self) -> &'static str {
        match self {
            EventKind::Sysmon => "SysmonEvent",
            EventKind::Defender => "DefenderEvent",
            EventKind::PowerShell => "PowerShellEvent",
            EventKind::Generic => "GenericEvent",
        }
    }

    fn model(self) -> &'static Model {
        match self {
            EventKind::Sysmon => &SYSMON_EVENT,
            EventKind::Defender => &DEFENDER_EVENT,
            EventKind::PowerShell => &POWERSHELL_EVENT,
            EventKind::Generic => &GENERIC_EVENT,
        }
    }

    fn data_model(self) -> &'static Model {
        match self {
            EventKind::Sysmon => &SYSMON_EVENT_DATA,
            EventKind::Defender => &DEFENDER_EVENT_DATA,
            EventKind::PowerShell => &POWERSHELL_EVENT_DATA,
            EventKind::Generic => &GENERIC_EVENT_DATA,
        }
    }
}

/// A parsed event: the model and its validated parts.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedEvent {
    /// The model.
    pub kind: EventKind,
    /// The validated `System` (by field name; no aliases there).
    pub system: Vec<(String, PyValue)>,
    /// `EventData`'s declared fields: attribute name and validated value.
    pub fields: Vec<(String, PyValue)>,
    /// `EventData`'s extra keys, in input order.
    pub extras: Vec<(String, PyValue)>,
}

impl ParsedEvent {
    /// `getattr(parsed_event.System, name)`.
    pub fn system(&self, name: &str) -> Option<&PyValue> {
        dict_get(&self.system, name)
    }

    /// `parsed_event.System.EventRecordID` (an `int`).
    pub fn event_record_id(&self) -> String {
        self.system("EventRecordID")
            .map(PyValue::py_str)
            .unwrap_or_default()
    }

    /// `parsed_event.System.TimeCreated.SystemTime` (a `float`).
    pub fn system_time(&self) -> f64 {
        match self.system("TimeCreated").and_then(|t| t.get("SystemTime")) {
            Some(PyValue::Float(f)) => *f,
            _ => 0.0,
        }
    }

    /// `getattr(parsed_event.EventData, name)` — a declared field, else an
    /// extra (`None`: `AttributeError`, i.e. `hasattr` is false).
    pub fn data(&self, name: &str) -> Option<&PyValue> {
        dict_get(&self.fields, name).or_else(|| dict_get(&self.extras, name))
    }

    /// The extra `name`, if the event carried one.
    pub fn extra(&self, name: &str) -> Option<&PyValue> {
        dict_get(&self.extras, name)
    }

    /// `parsed_event.EventData.model_dump()`.
    pub fn data_dump(&self) -> Vec<(String, PyValue)> {
        let mut out = self.fields.clone();
        for (k, v) in &self.extras {
            dict_set(&mut out, k, v.clone());
        }
        out
    }
}

/// A model's failure: the `ValidationError`'s `str()`, or the `TypeError`
/// of `Model(**x)` with something that is not a dict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `DefenderEventData` is `populate_by_name`: a field given under its name
/// (and not under its alias) is read from there, and that key is no extra.
fn defender_input(raw: &[(String, PyValue)]) -> Vec<(String, PyValue)> {
    let has = |k: &str| raw.iter().any(|(key, _)| key == k);
    raw.iter()
        .map(|(k, v)| {
            match DEFENDER_FIELDS
                .iter()
                .find(|(name, alias)| name == k && !has(alias))
            {
                Some((_, alias)) => ((*alias).to_string(), v.clone()),
                None => (k.clone(), v.clone()),
            }
        })
        .collect()
}

/// `Model(**event_data)` for one of the four event models.
pub fn parse_as(kind: EventKind, event: &[(String, PyValue)]) -> Result<ParsedEvent, ParseError> {
    let mut input = event.to_vec();
    if kind == EventKind::Defender {
        if let Some(PyValue::Dict(data)) = dict_get(event, "EventData") {
            let fixed = defender_input(data);
            dict_set(&mut input, "EventData", PyValue::Dict(fixed));
        }
    }
    let model = kind.model();
    let dump = match validate(model, &PyValue::Dict(input)) {
        Ok(d) => d,
        Err(Invalid::Errors(errors)) => {
            return Err(ParseError(format_validation_error(model.name, &errors)));
        }
        Err(Invalid::Abort(_, detail)) => return Err(ParseError(detail)),
    };
    let system = match model::field(&dump, "System") {
        PyValue::Dict(s) => s.clone(),
        _ => Vec::new(),
    };
    let data = match model::field(&dump, "EventData") {
        PyValue::Dict(d) => d.clone(),
        _ => Vec::new(),
    };
    let declared = kind.data_model().fields;
    let mut fields = Vec::new();
    let mut extras = Vec::new();
    for (k, v) in data {
        match declared.iter().find(|f| f.key() == k) {
            Some(f) => fields.push((f.name.to_string(), v)),
            None => extras.push((k, v)),
        }
    }
    Ok(ParsedEvent {
        kind,
        system,
        fields,
        extras,
    })
}

/// `try: Model(**event_data) except: GenericEvent(**event_data)`.
fn parse_or_generic(
    kind: EventKind,
    event: &[(String, PyValue)],
) -> Result<ParsedEvent, ParseError> {
    match parse_as(kind, event) {
        Ok(p) => Ok(p),
        Err(e) => {
            tracing::warn!(
                target: "copilot::ingest",
                "Failed to parse {} event: {e}",
                kind.class_name().trim_end_matches("Event")
            );
            parse_as(EventKind::Generic, event)
        }
    }
}

/// The keyword a channel or provider name selects (`sysmon`, `defender`,
/// `powershell`, in that order).
fn kind_for(lowered: &str) -> Option<EventKind> {
    if lowered.contains("sysmon") {
        Some(EventKind::Sysmon)
    } else if lowered.contains("defender") {
        Some(EventKind::Defender)
    } else if lowered.contains("powershell") {
        Some(EventKind::PowerShell)
    } else {
        None
    }
}

/// `x in y` for the `"Provider" in system` tests (`TypeError` for a `y`
/// that supports no `in`).
fn contains(container: &PyValue, key: &str) -> Result<bool, ParseError> {
    match container {
        PyValue::Dict(d) => Ok(d.iter().any(|(k, _)| k == key)),
        PyValue::Str(s) => Ok(s.contains(key)),
        PyValue::List(items) => Ok(items.iter().any(|i| i.as_str() == Some(key))),
        other => Err(ParseError(format!(
            "argument of type '{}' is not iterable",
            crate::py::type_name(other)
        ))),
    }
}

/// `container[key]` (`KeyError`/`TypeError` texts).
fn getitem<'a>(container: &'a PyValue, key: &str) -> Result<&'a PyValue, ParseError> {
    match container {
        PyValue::Dict(d) => {
            dict_get(d, key).ok_or_else(|| ParseError(copilot_auth::pyvalue::str_repr(key)))
        }
        PyValue::Str(_) => Err(ParseError(
            "string indices must be integers, not 'str'".into(),
        )),
        PyValue::List(_) => Err(ParseError(
            "list indices must be integers or slices, not str".into(),
        )),
        other => Err(ParseError(format!(
            "'{}' object is not subscriptable",
            crate::py::type_name(other)
        ))),
    }
}

/// `value.lower()` (`AttributeError` for anything but a `str`).
fn lower(value: &PyValue) -> Result<String, ParseError> {
    match value {
        PyValue::Str(s) => Ok(s.to_lowercase()),
        other => Err(ParseError(format!(
            "'{}' object has no attribute 'lower'",
            crate::py::type_name(other)
        ))),
    }
}

/// What `VelociraptorSigmaAlert.event` holds after validation.
#[derive(Debug, Clone, PartialEq)]
pub enum SigmaEvent {
    /// A `str` (a JSON string that decoded to a string).
    Str(String),
    /// A `dict`.
    Dict(Vec<(String, PyValue)>),
}

impl SigmaEvent {
    /// `bool(alert.event)`.
    pub fn truthy(&self) -> bool {
        match self {
            SigmaEvent::Str(s) => !s.is_empty(),
            SigmaEvent::Dict(d) => !d.is_empty(),
        }
    }

    /// The value as Python holds it.
    pub fn to_py(&self) -> PyValue {
        match self {
            SigmaEvent::Str(s) => PyValue::Str(s.clone()),
            SigmaEvent::Dict(d) => PyValue::Dict(d.clone()),
        }
    }
}

/// `VelociraptorSigmaAlert.get_parsed_event()`; `Err` is the exception
/// Python raises (`json.loads` of a string event, a broken generic event,
/// a `System` that is not what the lookups expect).
pub fn get_parsed_event(channel: &str, event: &SigmaEvent) -> Result<ParsedEvent, ParseError> {
    let event_data = match event {
        SigmaEvent::Str(s) => match copilot_upstream::json::py_loads(s) {
            Ok(PyValue::Dict(d)) => d,
            Ok(other) => {
                // Neither `SysmonEvent(**x)` nor the channel/provider tests
                // can take a non-dict: `GenericEvent(**x)` raises.
                return Err(ParseError(format!(
                    "app.incidents.schema.velo_sigma.GenericEvent() argument after ** must be a \
                     mapping, not {}",
                    crate::py::type_name(&other)
                )));
            }
            Err(e) => return Err(ParseError(e)),
        },
        SigmaEvent::Dict(d) => d.clone(),
    };
    if !channel.is_empty() {
        if let Some(kind) = kind_for(&channel.to_lowercase()) {
            return parse_or_generic(kind, &event_data);
        }
    }
    if let Some(system) = dict_get(&event_data, "System") {
        if contains(system, "Provider")? {
            let provider = getitem(system, "Provider")?;
            if contains(provider, "Name")? {
                let name = lower(getitem(provider, "Name")?)?;
                if let Some(kind) = kind_for(&name) {
                    return parse_or_generic(kind, &event_data);
                }
            }
        }
        if contains(system, "Channel")? {
            let ch = lower(getitem(system, "Channel")?)?;
            if let Some(kind) = kind_for(&ch) {
                return parse_or_generic(kind, &event_data);
            }
        }
    }
    parse_as(EventKind::Generic, &event_data)
}

/// `VelociraptorSigmaAlert.parse_event` (`mode="before"`): a string is
/// `json.loads`-ed; `Err` is the `ValueError`'s text.
pub fn parse_event_before(value: &PyValue) -> Result<PyValue, String> {
    match value {
        PyValue::Str(s) => copilot_upstream::json::py_loads(s)
            .map_err(|e| format!("Invalid JSON in event field: {e}")),
        other => Ok(other.clone()),
    }
}

/// `str.strip()` of a value that must be a string (`AttributeError`).
pub fn strip_str(value: &PyValue) -> Result<String, ParseError> {
    match value {
        PyValue::Str(s) => Ok(py_strip(s).to_string()),
        other => Err(ParseError(format!(
            "'{}' object has no attribute 'strip'",
            crate::py::type_name(other)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    fn dict(text: &str) -> Vec<(String, PyValue)> {
        match loads(text).unwrap() {
            PyValue::Dict(d) => d,
            _ => panic!("not a dict"),
        }
    }

    const SYSTEM: &str = r#""System":{"Provider":{"Name":"Microsoft-Windows-Sysmon","Guid":"g"},"EventID":{"Value":10},"Version":3,"Level":4,"Task":10,"Opcode":0,"Keywords":9223372036854775808,"TimeCreated":{"SystemTime":1744233485.0778975},"EventRecordID":564617,"Execution":{"ProcessID":2320,"ThreadID":3540},"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"W","Security":{"UserID":"S-1-5-18"}}"#;

    #[test]
    fn a_partial_sysmon_event_falls_back_to_generic() {
        let ev = dict(&format!(
            r#"{{{SYSTEM},"EventData":{{"RuleName":"r","ContextInfo":"x"}},"Message":"m"}}"#
        ));
        let p = get_parsed_event(
            "Microsoft-Windows-Sysmon/Operational",
            &SigmaEvent::Dict(ev),
        )
        .unwrap();
        assert_eq!(p.kind, EventKind::Generic);
        assert!(p.fields.is_empty());
        assert_eq!(p.extra("ContextInfo"), Some(&PyValue::Str("x".into())));
        assert_eq!(p.event_record_id(), "564617");
    }

    #[test]
    fn defender_fields_by_name_or_alias() {
        let ev = dict(&format!(
            r#"{{{SYSTEM},"EventData":{{"Product Name":"A","product_name":"a","Product Version":"v","threat_name":"t"}},"Message":"m"}}"#
        ));
        let p = parse_as(EventKind::Defender, &ev).unwrap();
        assert_eq!(p.data("product_name"), Some(&PyValue::Str("A".into())));
        assert_eq!(p.data("threat_name"), Some(&PyValue::Str("t".into())));
        assert_eq!(
            p.extras,
            vec![("product_name".into(), PyValue::Str("a".into()))]
        );
        let dump = p.data_dump();
        assert_eq!(dump[0], ("product_name".into(), PyValue::Str("a".into())));
    }

    #[test]
    fn a_broken_system_fails_the_generic_model_too() {
        let ev = dict(r#"{"EventData":{},"Message":"m"}"#);
        let err = get_parsed_event("", &SigmaEvent::Dict(ev)).unwrap_err();
        assert!(
            err.0
                .starts_with("1 validation error for GenericEvent\nSystem\n  Field required"),
            "{err}"
        );
    }
}
