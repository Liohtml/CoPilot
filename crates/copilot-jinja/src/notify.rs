//! CoPilot's notification template rendering
//! (`app/notifications/services/rendering.py`): the variables a template
//! sees, the `NotificationEvent` it can reach as `event`, and the output
//! size limit.

use std::any::Any;
use std::rc::Rc;

use num_bigint_dig::BigInt;

use crate::arena;
use crate::compiler;
use crate::error::{Error, Result};
use crate::objects::Method;
use crate::ops;
use crate::pyrepr;
use crate::tables;
use crate::value::{Dict, Object, PyIter, StrEnum, Value};
use crate::vm;

/// `MAX_RENDERED_BYTES`: the largest body a template may render.
pub const MAX_RENDERED_BYTES: usize = 64 * 1024;

/// The stack a render runs on: deep macro recursion is Python's limit to
/// reach, not the thread's.
const STACK_SIZE: usize = 256 << 20;

/// A JSON-like value handed to a template.
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    /// `None`.
    None,
    /// `bool`.
    Bool(bool),
    /// `int`.
    Int(i128),
    /// `float`.
    Float(f64),
    /// `str`.
    Str(String),
    /// `list`.
    List(Vec<Input>),
    /// `dict` with string keys, in insertion order.
    Dict(Vec<(String, Input)>),
}

impl From<&str> for Input {
    fn from(s: &str) -> Self {
        Input::Str(s.to_string())
    }
}

impl From<String> for Input {
    fn from(s: String) -> Self {
        Input::Str(s)
    }
}

impl From<Option<String>> for Input {
    fn from(s: Option<String>) -> Self {
        s.map_or(Input::None, Input::Str)
    }
}

/// `NotificationEvent`, the envelope a template renders against.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// `customer_code`.
    pub customer_code: Option<String>,
    /// `trigger`: a `NotificationTrigger` value.
    pub trigger: String,
    /// `severity`: a `NotificationSeverity` value.
    pub severity: String,
    /// `subject`.
    pub subject: String,
    /// `summary`.
    pub summary: String,
    /// `entity_type`.
    pub entity_type: String,
    /// `entity_id`.
    pub entity_id: i64,
    /// `dedupe_key`.
    pub dedupe_key: String,
    /// `link_url`.
    pub link_url: Option<String>,
    /// `assignee_username`.
    pub assignee_username: Option<String>,
    /// `actor_username`.
    pub actor_username: Option<String>,
    /// `context`.
    pub context: Vec<(String, Input)>,
}

const ENUM_MODULE: &str = "app.notifications.schema.notifications";

/// `NotificationSeverity`'s members.
pub const SEVERITY_MEMBERS: &[(&str, &str)] = &[
    ("CRITICAL", "Critical"),
    ("HIGH", "High"),
    ("MEDIUM", "Medium"),
    ("LOW", "Low"),
    ("INFORMATIONAL", "Informational"),
];

/// `NotificationTrigger`'s members.
pub const TRIGGER_MEMBERS: &[(&str, &str)] = &[
    ("INVESTIGATION_COMPLETE", "investigation_complete"),
    ("AI_REPORT_REVIEWED", "ai_report_reviewed"),
    ("ALERT_CREATED", "alert_created"),
    ("ALERT_ASSIGNED", "alert_assigned"),
    ("CASE_ASSIGNED", "case_assigned"),
    ("CASE_TASK_ASSIGNED", "case_task_assigned"),
    ("SLA_AT_RISK", "sla_at_risk"),
    ("SLA_BREACHED", "sla_breached"),
    ("TEMP_PASSWORD_ISSUED", "temp_password_issued"),
];

fn member(
    class: &'static str,
    members: &'static [(&'static str, &'static str)],
    value: &str,
) -> Result<Value> {
    let (name, v) = members.iter().find(|(_, v)| *v == value).ok_or_else(|| {
        Error::value_error(format!(
            "{} is not a valid {class}",
            pyrepr::str_repr(value)
        ))
    })?;
    Ok(Value::StrEnum(Rc::new(StrEnum {
        class,
        module: ENUM_MODULE,
        name: (*name).to_string(),
        value: (*v).to_string(),
        members,
    })))
}

/// The template value of an [`Input`].
pub fn input_value(i: &Input) -> Value {
    match i {
        Input::None => Value::None,
        Input::Bool(b) => Value::Bool(*b),
        Input::Int(n) => Value::Int(BigInt::from(*n)),
        Input::Float(f) => Value::Float(*f),
        Input::Str(s) => Value::str(s),
        Input::List(items) => Value::list(items.iter().map(input_value).collect()),
        Input::Dict(pairs) => Value::str_dict(
            pairs
                .iter()
                .map(|(k, v)| (k.as_str(), input_value(v)))
                .collect(),
        ),
    }
}

/// `event` in a template: a Pydantic model's fields, `alert_id`, and the
/// dump methods.
#[derive(Debug)]
pub struct EventObject {
    fields: Vec<(&'static str, Value)>,
}

impl EventObject {
    fn field(&self, name: &str) -> Option<Value> {
        self.fields
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
    }

    fn dump(&self) -> Result<Value> {
        let mut d = Dict::default();
        for (k, v) in &self.fields {
            d.entries.push((Value::str(k), v.fresh()));
        }
        Ok(Value::from_dict(d))
    }

    fn dump_json(&self) -> Result<String> {
        let mut out = String::from("{");
        for (i, (k, v)) in self.fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_str(k, &mut out);
            out.push(':');
            json_value(v, &mut out)?;
        }
        out.push('}');
        Ok(out)
    }
}

impl Object for EventObject {
    fn type_name(&self) -> &str {
        "NotificationEvent"
    }

    fn module(&self) -> &str {
        "app.notifications.schema.events"
    }

    fn repr(&self) -> Result<String> {
        let parts = self
            .fields
            .iter()
            .map(|(k, v)| Ok(format!("{k}={}", pyrepr::repr(v)?)))
            .collect::<Result<Vec<_>>>()?;
        Ok(format!("NotificationEvent({})", parts.join(", ")))
    }

    fn str(&self) -> Result<String> {
        let parts = self
            .fields
            .iter()
            .map(|(k, v)| Ok(format!("{k}={}", pyrepr::repr(v)?)))
            .collect::<Result<Vec<_>>>()?;
        Ok(parts.join(" "))
    }

    fn iter(&self, _me: &Value) -> Option<Result<PyIter>> {
        Some(Ok(PyIter::Seq(
            self.fields
                .iter()
                .map(|(k, v)| Value::tuple(vec![Value::str(k), v.clone()]))
                .collect(),
        )))
    }

    fn attrs(&self) -> &'static [&'static str] {
        tables::ATTRS_EVENT
    }

    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        if let Some(v) = self.field(name) {
            return Some(Ok(v));
        }
        match name {
            "alert_id" => self.field("entity_id").map(Ok),
            "model_dump" | "dict" | "model_dump_json" | "json" => Some(Ok(Method::value(me, name))),
            _ => None,
        }
    }

    fn call_method(
        &self,
        _me: &Value,
        name: &str,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        if !args.is_empty() || !kwargs.is_empty() {
            return Some(Err(Error::unsupported(format!(
                "Arguments to NotificationEvent.{name}()"
            ))));
        }
        Some(match name {
            "model_dump" | "dict" => self.dump(),
            "model_dump_json" | "json" => self.dump_json().map(Value::str),
            _ => return None,
        })
    }

    fn eq(&self, other: &Value) -> Option<bool> {
        let o = other.downcast::<EventObject>()?;
        Some(
            self.fields.len() == o.fields.len()
                && self
                    .fields
                    .iter()
                    .zip(&o.fields)
                    .all(|((a, x), (b, y))| a == b && ops::eq(x, y).unwrap_or(false)),
        )
    }

    fn hashable(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Pydantic's JSON for a dumped field.
fn json_value(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::None => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Float(f) => {
            if f.is_finite() {
                out.push_str(&format!("{f:?}"));
            } else {
                out.push_str("null");
            }
        }
        Value::Str(s) | Value::Markup(s) => json_str(s, out),
        Value::StrEnum(e) => json_str(&e.value, out),
        Value::List(_) | Value::Tuple(_) => {
            out.push('[');
            for (i, item) in ops::iterate(v)?.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_value(item, out)?;
            }
            out.push(']');
        }
        Value::Dict(d) => {
            out.push('{');
            for (i, (k, val)) in d.borrow().entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_str(&pyrepr::str(k)?, out);
                out.push(':');
                json_value(val, out)?;
            }
            out.push('}');
        }
        other => {
            return Err(Error::unsupported(format!(
                "Serialising a {} to JSON",
                other.type_name()
            )));
        }
    }
    Ok(())
}

fn opt_str(s: &Option<String>) -> Value {
    s.as_deref().map_or(Value::None, Value::str)
}

fn or_empty(s: &Option<String>) -> Value {
    Value::str(s.as_deref().unwrap_or(""))
}

/// `build_context(event)`: the variables every template can read.
fn build_context(event: &Event) -> Result<Vec<(&'static str, Value)>> {
    let mut context = Dict::default();
    for (k, v) in &event.context {
        context.entries.push((Value::str(k), input_value(v)));
    }
    let shared = Dict {
        entries: context.entries.clone(),
        default_str: true,
    };
    let ctx = Value::from_dict(shared);
    let trigger = member("NotificationTrigger", TRIGGER_MEMBERS, &event.trigger)?;
    let severity = member("NotificationSeverity", SEVERITY_MEMBERS, &event.severity)?;
    let alert_name = {
        let from_ctx = context.get(&Value::str("alert_name"))?;
        match from_ctx {
            Some(v) if ops::truthy(&v)? => v,
            _ if !event.subject.is_empty() => Value::str(&event.subject),
            _ => Value::str(""),
        }
    };
    let event_obj = Value::object(EventObject {
        fields: vec![
            ("customer_code", opt_str(&event.customer_code)),
            ("trigger", trigger),
            ("severity", severity),
            ("subject", Value::str(&event.subject)),
            ("summary", Value::str(&event.summary)),
            ("entity_type", Value::str(&event.entity_type)),
            ("entity_id", Value::int(event.entity_id)),
            ("dedupe_key", Value::str(&event.dedupe_key)),
            ("link_url", opt_str(&event.link_url)),
            ("assignee_username", opt_str(&event.assignee_username)),
            ("actor_username", opt_str(&event.actor_username)),
            ("context", Value::from_dict(context)),
        ],
    });
    Ok(vec![
        ("customer_code", or_empty(&event.customer_code)),
        ("alert_id", Value::int(event.entity_id)),
        ("alert_name", alert_name),
        ("severity", Value::str(&event.severity)),
        ("summary", Value::str(&event.summary)),
        ("report_url", or_empty(&event.link_url)),
        ("assignee", or_empty(&event.assignee_username)),
        ("actor", or_empty(&event.actor_username)),
        ("entity_type", Value::str(&event.entity_type)),
        ("entity_id", Value::int(event.entity_id)),
        ("subject", Value::str(&event.subject)),
        ("trigger", Value::str(&event.trigger)),
        ("link_url", or_empty(&event.link_url)),
        ("context", ctx),
        ("event", event_obj),
    ])
}

fn render_here(
    source: &str,
    event: &Event,
    autoescape: bool,
    extra: &[(String, Input)],
) -> Result<String> {
    let _guard = arena::RenderGuard::new();
    let template = compiler::compile(source, autoescape)?;
    let mut vars: Vec<(Rc<str>, Value)> = Vec::new();
    for (k, v) in extra {
        vars.push((Rc::from(k.as_str()), input_value(v)));
    }
    for (k, v) in build_context(event)? {
        vars.push((Rc::from(k), v));
    }
    let rendered = vm::render(&template, vars, MAX_RENDERED_BYTES)?;
    if rendered.bytes > MAX_RENDERED_BYTES {
        return Err(Error::new(
            "TemplateTooLargeError",
            format!(
                "Rendered body is {} bytes, over the {MAX_RENDERED_BYTES} byte limit. A loop over an \
                 unbounded collection is the usual cause.",
                rendered.bytes
            ),
        ));
    }
    Ok(rendered.text)
}

fn on_large_stack<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    let handle = std::thread::Builder::new()
        .name("copilot-jinja".into())
        .stack_size(STACK_SIZE)
        .spawn(f)
        .map_err(|e| {
            Error::new(
                "RuntimeError",
                format!("could not start the template engine: {e}"),
            )
        })?;
    handle
        .join()
        .unwrap_or_else(|_| Err(Error::new("RuntimeError", "the template engine failed")))
}

/// `render(source, event, autoescape=…, extra_context=…)`: renders an
/// operator's template the way CoPilot's notification renderer does. The
/// error is the Python exception's type name and message.
pub fn render(
    source: &str,
    event: &Event,
    autoescape: bool,
    extra: &[(String, Input)],
) -> Result<String> {
    let source = source.to_string();
    let event = event.clone();
    let extra = extra.to_vec();
    on_large_stack(move || render_here(&source, &event, autoescape, &extra))
}

/// `compile_template(source, autoescape=…)`: the save-time syntax check.
pub fn compile_template(source: &str, autoescape: bool) -> Result<()> {
    let source = source.to_string();
    on_large_stack(move || {
        let _guard = arena::RenderGuard::new();
        compiler::compile(&source, autoescape).map(|_| ())
    })
}
