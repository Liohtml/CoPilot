//! Pydantic 2 (lax mode) over a rule's values: the models the services build
//! from a rule (`RuleSummary(**…)`, `ParameterSchema`, `AggregationConfig`,
//! the catalog rows), the coercions they apply (`b"x"` → `"x"`, `"12"` →
//! 12, `True` → 1, a tuple → a list) and the `ValidationError` text the
//! routes put into their answers (`1 validation error for RuleSummary\nid\n
//! Input should be a valid string [type=string_type, input_value=1,
//! input_type=int]…`).
//!
//! A model validates to its dump (a `dict` in field order), which
//! [`Value::to_pydantic_json`] writes as FastAPI does.

use std::sync::Arc;

use copilot_upstream::model::{PYDANTIC_VERSION, truncate_repr};
use copilot_upstream::py::PyExc;
use copilot_yaml::Value;
use num_bigint_dig::BigInt;

use crate::py::s;

/// A field type.
#[derive(Debug)]
pub enum Ty {
    /// `Any`.
    Any,
    /// `str`.
    Str,
    /// `int`.
    Int,
    /// `bool`.
    Bool,
    /// `float`.
    Float,
    /// `dict` (any keys and values).
    Dict,
    /// `dict[K, V]`.
    DictOf(&'static Ty, &'static Ty),
    /// `list[T]`.
    List(&'static Ty),
    /// `Optional[T]`.
    Opt(&'static Ty),
    /// A nested model.
    Model(&'static Model),
    /// A `str` enum: its values.
    Enum(&'static [&'static str]),
}

/// A field default.
#[derive(Debug, Clone, Copy)]
pub enum Default {
    /// Required.
    Required,
    /// `None`.
    None,
    /// A `str`.
    Str(&'static str),
    /// An `int`.
    Int(i64),
    /// A `bool`.
    Bool(bool),
    /// A `float`.
    Float(f64),
    /// `[]`.
    EmptyList,
    /// `{}`.
    EmptyDict,
}

impl Default {
    fn value(self) -> Option<Value> {
        Some(match self {
            Default::Required => return None,
            Default::None => Value::None,
            Default::Str(t) => s(t),
            Default::Int(n) => Value::Int(BigInt::from(n)),
            Default::Bool(b) => Value::Bool(b),
            Default::Float(f) => Value::Float(f),
            Default::EmptyList => Value::List(Arc::new(Vec::new())),
            Default::EmptyDict => Value::Dict(Arc::new(Vec::new())),
        })
    }
}

/// A model field.
#[derive(Debug)]
pub struct Field {
    /// The name.
    pub name: &'static str,
    /// The type.
    pub ty: Ty,
    /// The default.
    pub default: Default,
    /// `ge=` / `le=` for an `int`.
    pub range: (Option<i64>, Option<i64>),
    /// `max_length=` for a `str` (in characters).
    pub max_len: Option<usize>,
}

impl Field {
    /// A required field.
    pub const fn req(name: &'static str, ty: Ty) -> Self {
        Self {
            name,
            ty,
            default: Default::Required,
            range: (None, None),
            max_len: None,
        }
    }

    /// A field with a default.
    pub const fn def(name: &'static str, ty: Ty, default: Default) -> Self {
        Self {
            name,
            ty,
            default,
            range: (None, None),
            max_len: None,
        }
    }

    /// With `ge=` / `le=`.
    pub const fn range(mut self, ge: Option<i64>, le: Option<i64>) -> Self {
        self.range = (ge, le);
        self
    }

    /// With `max_length=` (a `str`, or the `str` of an `Optional[str]`).
    pub const fn max_len(mut self, n: usize) -> Self {
        self.max_len = Some(n);
        self
    }
}

/// A model-level check run after the fields (`@field_validator`,
/// `@model_validator(mode="after")`): `Err((loc, message))` is a
/// `value_error`.
pub type After = fn(&[(Value, Value)]) -> Result<(), (Vec<Loc>, String, Value)>;

/// A model.
#[derive(Debug)]
pub struct Model {
    /// The class name (the `ValidationError` title).
    pub title: &'static str,
    /// The fields, in declaration order.
    pub fields: &'static [Field],
    /// The validators.
    pub after: Option<After>,
}

/// One location item.
#[derive(Debug, Clone, PartialEq)]
pub enum Loc {
    /// A field name or `str` key.
    Key(String),
    /// A list index or `int` key.
    Index(String),
}

/// One error line.
#[derive(Debug, Clone)]
pub struct Error {
    /// Where.
    pub loc: Vec<Loc>,
    /// The error type.
    pub kind: &'static str,
    /// The message.
    pub msg: String,
    /// The offending input.
    pub input: Value,
}

/// A failed validation: `str(ValidationError)`.
#[derive(Debug, Clone)]
pub struct Invalid {
    /// The model.
    pub title: String,
    /// The errors.
    pub errors: Vec<Error>,
}

impl Invalid {
    /// `str(e)`.
    pub fn text(&self) -> String {
        let n = self.errors.len();
        let mut out = format!(
            "{n} validation error{} for {}",
            if n == 1 { "" } else { "s" },
            self.title
        );
        for e in &self.errors {
            out.push('\n');
            if !e.loc.is_empty() {
                let parts: Vec<String> = e
                    .loc
                    .iter()
                    .map(|l| match l {
                        Loc::Key(k) if k.contains('.') => format!("`{k}`"),
                        Loc::Key(k) | Loc::Index(k) => k.clone(),
                    })
                    .collect();
                out.push_str(&parts.join("."));
                out.push('\n');
            }
            out.push_str(&format!(
                "  {} [type={}, input_value={}, input_type={}]\n    For further information visit \
                 https://errors.pydantic.dev/{PYDANTIC_VERSION}/v/{}",
                e.msg,
                e.kind,
                truncate_repr(e.input.py_repr()),
                e.input.type_name(),
                e.kind
            ));
        }
        out
    }

    /// As the exception the route sees (a `ValueError`).
    pub fn exc(&self) -> PyExc {
        PyExc::Validation(self.text())
    }
}

struct Ctx {
    errors: Vec<Error>,
}

impl Ctx {
    fn push(&mut self, loc: &[Loc], kind: &'static str, msg: impl Into<String>, input: &Value) {
        self.errors.push(Error {
            loc: loc.to_vec(),
            kind,
            msg: msg.into(),
            input: input.clone(),
        });
    }
}

fn child(loc: &[Loc], item: Loc) -> Vec<Loc> {
    let mut out = loc.to_vec();
    out.push(item);
    out
}

/// `Model(**kwargs)`: the dump, or the `ValidationError`.
pub fn validate(model: &'static Model, input: &Value) -> Result<Value, Invalid> {
    let mut ctx = Ctx { errors: Vec::new() };
    let out = check_model(model, input, &[], &mut ctx);
    if ctx.errors.is_empty() {
        out.ok_or_else(|| Invalid {
            title: model.title.into(),
            errors: Vec::new(),
        })
    } else {
        Err(Invalid {
            title: model.title.into(),
            errors: ctx.errors,
        })
    }
}

/// `Model(**kwargs)` as the exception a route sees.
pub fn build(model: &'static Model, input: &Value) -> Result<Value, PyExc> {
    validate(model, input).map_err(|e| e.exc())
}

fn check_model(model: &'static Model, input: &Value, loc: &[Loc], ctx: &mut Ctx) -> Option<Value> {
    let Value::Dict(items) = input else {
        ctx.push(
            loc,
            "model_type",
            format!(
                "Input should be a valid dictionary or instance of {}",
                model.title
            ),
            input,
        );
        return None;
    };
    let before = ctx.errors.len();
    let mut out: Vec<(Value, Value)> = Vec::with_capacity(model.fields.len());
    for f in model.fields {
        let here = child(loc, Loc::Key(f.name.into()));
        match items.iter().find(|(k, _)| k.as_str() == Some(f.name)) {
            Some((_, v)) => {
                if let Some(checked) = check(&f.ty, v, &here, ctx) {
                    if check_range(f, &checked, &here, ctx) && check_len(f, &checked, v, &here, ctx)
                    {
                        out.push((s(f.name), checked));
                    }
                }
            }
            None => match f.default.value() {
                Some(d) => out.push((s(f.name), d)),
                None => ctx.push(&here, "missing", "Field required", input),
            },
        }
    }
    if ctx.errors.len() != before {
        return None;
    }
    if let Some(after) = model.after {
        if let Err((at, msg, value)) = after(&out) {
            let mut l = loc.to_vec();
            l.extend(at);
            ctx.push(&l, "value_error", format!("Value error, {msg}"), &value);
            return None;
        }
    }
    Some(Value::Dict(Arc::new(out)))
}

fn check_range(f: &Field, v: &Value, loc: &[Loc], ctx: &mut Ctx) -> bool {
    let Value::Int(i) = v else {
        return true;
    };
    if let Some(ge) = f.range.0 {
        if *i < BigInt::from(ge) {
            ctx.push(
                loc,
                "greater_than_equal",
                format!("Input should be greater than or equal to {ge}"),
                v,
            );
            return false;
        }
    }
    if let Some(le) = f.range.1 {
        if *i > BigInt::from(le) {
            ctx.push(
                loc,
                "less_than_equal",
                format!("Input should be less than or equal to {le}"),
                v,
            );
            return false;
        }
    }
    true
}

/// `max_length`: pydantic-core's `string_too_long`, on the input as given.
fn check_len(f: &Field, v: &Value, input: &Value, loc: &[Loc], ctx: &mut Ctx) -> bool {
    let (Some(max), Value::Str(t)) = (f.max_len, v) else {
        return true;
    };
    if t.chars().count() > max {
        ctx.push(
            loc,
            "string_too_long",
            format!("String should have at most {max} characters"),
            input,
        );
        return false;
    }
    true
}

fn utf8_of(b: &[u8]) -> Option<String> {
    std::str::from_utf8(b).ok().map(str::to_string)
}

fn check(ty: &Ty, input: &Value, loc: &[Loc], ctx: &mut Ctx) -> Option<Value> {
    match ty {
        Ty::Any => Some(input.clone()),
        Ty::Opt(inner) => match input {
            Value::None => Some(Value::None),
            other => check(inner, other, loc, ctx),
        },
        Ty::Str => match input {
            Value::Str(_) => Some(input.clone()),
            Value::Bytes(b) => match utf8_of(b) {
                Some(t) => Some(s(t)),
                None => {
                    ctx.push(
                        loc,
                        "string_unicode",
                        "Input should be a valid string, unable to parse raw data as a unicode string",
                        input,
                    );
                    None
                }
            },
            _ => {
                ctx.push(loc, "string_type", "Input should be a valid string", input);
                None
            }
        },
        Ty::Int => check_int(input, loc, ctx),
        Ty::Float => match input {
            Value::Float(_) => Some(input.clone()),
            Value::Int(i) => Some(Value::Float(
                num_traits::ToPrimitive::to_f64(i).unwrap_or(f64::INFINITY),
            )),
            Value::Bool(b) => Some(Value::Float(f64::from(u8::from(*b)))),
            _ => {
                ctx.push(loc, "float_type", "Input should be a valid number", input);
                None
            }
        },
        Ty::Bool => check_bool(input, loc, ctx),
        Ty::Dict => match input {
            Value::Dict(_) => Some(input.clone()),
            _ => {
                ctx.push(
                    loc,
                    "dict_type",
                    "Input should be a valid dictionary",
                    input,
                );
                None
            }
        },
        Ty::DictOf(kt, vt) => match input {
            Value::Dict(items) => {
                let mut out = Vec::with_capacity(items.len());
                let before = ctx.errors.len();
                for (k, v) in items.iter() {
                    let key_loc = match k {
                        Value::Str(t) => Loc::Key(t.clone()),
                        Value::Int(i) => Loc::Index(i.to_string()),
                        other => Loc::Key(other.py_str()),
                    };
                    let here = child(loc, key_loc);
                    let key = check(kt, k, &child(&here, Loc::Key("[key]".into())), ctx);
                    let val = check(vt, v, &here, ctx);
                    if let (Some(key), Some(val)) = (key, val) {
                        out.push((key, val));
                    }
                }
                (ctx.errors.len() == before).then(|| Value::Dict(Arc::new(out)))
            }
            _ => {
                ctx.push(
                    loc,
                    "dict_type",
                    "Input should be a valid dictionary",
                    input,
                );
                None
            }
        },
        Ty::List(inner) => match input {
            Value::List(items) | Value::Tuple(items) | Value::Set(items) => {
                let before = ctx.errors.len();
                let mut out = Vec::with_capacity(items.len());
                for (i, item) in items.iter().enumerate() {
                    if let Some(v) = check(inner, item, &child(loc, Loc::Index(i.to_string())), ctx)
                    {
                        out.push(v);
                    }
                }
                (ctx.errors.len() == before).then(|| Value::List(Arc::new(out)))
            }
            _ => {
                ctx.push(loc, "list_type", "Input should be a valid list", input);
                None
            }
        },
        Ty::Model(m) => check_model(m, input, loc, ctx),
        Ty::Enum(values) => match input {
            Value::Str(t) if values.contains(&t.as_str()) => Some(input.clone()),
            _ => {
                ctx.push(
                    loc,
                    "enum",
                    format!("Input should be {}", expected(values)),
                    input,
                );
                None
            }
        },
    }
}

/// `'a', 'b' or 'c'`.
pub fn expected(values: &[&str]) -> String {
    let quoted: Vec<String> = values.iter().map(|v| format!("'{v}'")).collect();
    match quoted.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        Some((last, _)) => last.clone(),
        None => String::new(),
    }
}

fn parse_int_str(t: &str) -> Option<BigInt> {
    let t = t.trim_matches(char::is_whitespace);
    let (neg, digits) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let digits = match digits.split_once('.') {
        Some((int, frac)) if frac.chars().all(|c| c == '0') => int,
        Some(_) => return None,
        None => digits,
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.chars().all(|c| c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    let clean: String = digits.chars().filter(|c| *c != '_').collect();
    let n: BigInt = clean.parse().ok()?;
    Some(if neg { -n } else { n })
}

fn check_int(input: &Value, loc: &[Loc], ctx: &mut Ctx) -> Option<Value> {
    let parse_text = |t: &str, ctx: &mut Ctx| match parse_int_str(t) {
        Some(n) => Some(Value::Int(n)),
        None => {
            ctx.push(
                loc,
                "int_parsing",
                "Input should be a valid integer, unable to parse string as an integer",
                input,
            );
            None
        }
    };
    match input {
        Value::Int(_) => Some(input.clone()),
        Value::Bool(b) => Some(Value::Int(BigInt::from(u8::from(*b)))),
        Value::Float(f) => {
            if !f.is_finite() {
                ctx.push(
                    loc,
                    "finite_number",
                    "Input should be a finite number",
                    input,
                );
                None
            } else if f.fract() != 0.0 {
                ctx.push(
                    loc,
                    "int_from_float",
                    "Input should be a valid integer, got a number with a fractional part",
                    input,
                );
                None
            } else if *f >= 9.223_372_036_854_776e18 || *f < -9.223_372_036_854_776e18 {
                ctx.push(
                    loc,
                    "int_parsing_size",
                    "Unable to parse input string as an integer, exceeded maximum size",
                    input,
                );
                None
            } else {
                Some(Value::Int(BigInt::from(*f as i64)))
            }
        }
        Value::Str(t) => parse_text(t, ctx),
        Value::Bytes(b) => match utf8_of(b) {
            Some(t) => parse_text(&t, ctx),
            None => {
                ctx.push(
                    loc,
                    "int_parsing",
                    "Input should be a valid integer, unable to parse string as an integer",
                    input,
                );
                None
            }
        },
        _ => {
            ctx.push(loc, "int_type", "Input should be a valid integer", input);
            None
        }
    }
}

fn bool_text(t: &str) -> Option<bool> {
    match t.to_ascii_lowercase().as_str() {
        "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
        "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
        _ => None,
    }
}

fn check_bool(input: &Value, loc: &[Loc], ctx: &mut Ctx) -> Option<Value> {
    let parsing = |ctx: &mut Ctx| {
        ctx.push(
            loc,
            "bool_parsing",
            "Input should be a valid boolean, unable to interpret input",
            input,
        );
        None
    };
    match input {
        Value::Bool(_) => Some(input.clone()),
        Value::Int(i) => {
            if *i == BigInt::from(0) {
                Some(Value::Bool(false))
            } else if *i == BigInt::from(1) {
                Some(Value::Bool(true))
            } else {
                parsing(ctx)
            }
        }
        Value::Float(f) if *f == 0.0 => Some(Value::Bool(false)),
        Value::Float(f) if *f == 1.0 => Some(Value::Bool(true)),
        Value::Str(t) => match bool_text(t) {
            Some(b) => Some(Value::Bool(b)),
            None => parsing(ctx),
        },
        Value::Bytes(b) => match utf8_of(b).as_deref().and_then(bool_text) {
            Some(b) => Some(Value::Bool(b)),
            None => parsing(ctx),
        },
        _ => {
            ctx.push(loc, "bool_type", "Input should be a valid boolean", input);
            None
        }
    }
}
