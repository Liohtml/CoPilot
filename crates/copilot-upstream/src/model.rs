//! Pydantic models for a tool's answers (and request bodies), the way
//! Pydantic 2 (lax mode) validates them and FastAPI serializes them.
//!
//! The connector services build Pydantic models from whatever the tool sent
//! (`Stream(**stream_data)`), and the routes answer with those models through
//! `response_model`. Three things follow from that, and all three are part of
//! the wire contract:
//!
//! - **what is kept**: the declared fields, in declaration order, under their
//!   alias (`by_alias=True`); extra keys are dropped unless the model allows
//!   them (`extra="allow"`, appended in input order); a missing optional
//!   field takes its default;
//! - **what is coerced**: Pydantic's lax rules (`"12"` → 12, `1.0` → 1,
//!   `1` → `1.0` for a float, `"yes"` → true, ISO strings and timestamps →
//!   datetimes), smart unions;
//! - **what fails, and how it reads**: a `ValidationError` whose `str()` the
//!   backend puts into its answer (`1 validation error for Stream\nrules.0.id\n
//!   Field required [type=missing, …]`, see [`format_validation_error`]).
//!
//! A model is a `static` [`Model`] (recursion is a static referring to
//! itself). [`validate`] returns the model as its JSON-mode dump — a
//! [`PyValue`] whose datetimes are already strings — which
//! [`crate::json::pydantic_json`] writes byte for byte as FastAPI's
//! `serialize_json` does. `model_vectors.json` (generated from the Python
//! models by `scripts/gen-connector-model-vectors.py`) pins every model of the
//! ported connectors against pydantic.

use copilot_auth::pyvalue::{PyValue, float_repr};
use speedate::{
    Date, DateConfig, DateTime, DateTimeConfig, MicrosecondsPrecisionOverflowBehavior, TimeConfig,
    TimestampUnit,
};

use crate::py::type_name;

/// The `major.minor` of the Pydantic release CoPilot runs (the error links
/// name it).
pub const PYDANTIC_VERSION: &str = "2.13";

/// One element of an error location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loc {
    /// A field (by alias), dict key or union member label.
    Key(String),
    /// A list index.
    Index(usize),
}

/// One Pydantic error line.
#[derive(Debug, Clone, PartialEq)]
pub struct PyError {
    /// Where.
    pub loc: Vec<Loc>,
    /// Pydantic's error type (`missing`, `string_type`, …).
    pub kind: &'static str,
    /// Its message.
    pub msg: String,
    /// The offending input.
    pub input: PyValue,
}

/// A field type.
#[derive(Debug)]
pub enum Ty {
    /// `Any` (and bare annotations Pydantic does not check).
    Any,
    /// `str`.
    Str,
    /// `int`.
    Int,
    /// `float`.
    Float,
    /// `bool`.
    Bool,
    /// `None` (`Optional[None]` with no other member).
    NoneOnly,
    /// `datetime`.
    DateTime,
    /// `List[T]` (`list` is `List(&Ty::Any)`).
    List(&'static Ty),
    /// `Dict[str, T]` (`dict` is `Dict(&Ty::Any)`).
    Dict(&'static Ty),
    /// A nested model.
    Model(&'static Model),
    /// `Optional[T]`.
    Nullable(&'static Ty),
    /// `Union[A, B, …]` in smart mode.
    Union(&'static [Ty]),
    /// A `str`-valued `Enum` (`class E(str, Enum)`): one of its values, as
    /// the value (`use_enum_values` or a JSON-mode dump).
    Enum(&'static EnumTy),
}

/// A `str`-valued `Enum`: its class name and values in declaration order.
#[derive(Debug)]
pub struct EnumTy {
    /// The class name (a union member's label).
    pub name: &'static str,
    /// The values, in declaration order.
    pub values: &'static [&'static str],
}

impl EnumTy {
    /// Pydantic's `Input should be 'a', 'b' or 'c'`.
    pub fn expected(&self) -> String {
        let quoted: Vec<String> = self.values.iter().map(|v| format!("'{v}'")).collect();
        match quoted.split_last() {
            None => String::new(),
            Some((last, [])) => last.clone(),
            Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        }
    }
}

/// A field's default when the key is absent.
#[derive(Debug, Clone, Copy)]
pub enum Default {
    /// Required (`Field required`).
    Required,
    /// `None`.
    None,
    /// Any other default (`= "x"`, `= {…}`, `default_factory`).
    Value(fn() -> PyValue),
}

/// What a field validator can do with the value.
#[derive(Debug, Clone, PartialEq)]
pub enum Check {
    /// `raise ValueError(text)`: a `value_error` line (`Value error, text`).
    ValueError(String),
    /// `raise HTTPException(status, detail)`: not a validation error at
    /// all — it leaves validation and the request as it is.
    Abort(u16, String),
}

/// A `field_validator(mode="after")`.
pub type AfterValidator = fn(&PyValue) -> Result<PyValue, Check>;

/// One declared field.
#[derive(Debug)]
pub struct Field {
    /// The attribute name.
    pub name: &'static str,
    /// `Field(alias=…)`: the input key, the error location and the output key.
    pub alias: Option<&'static str>,
    /// The annotation.
    pub ty: Ty,
    /// The default.
    pub default: Default,
    /// `field_validator(mode="before")`.
    pub before: Option<fn(&PyValue) -> PyValue>,
    /// `field_validator(mode="after")`.
    pub after: Option<AfterValidator>,
}

impl Field {
    /// A required field.
    pub const fn req(name: &'static str, ty: Ty) -> Self {
        Self {
            name,
            alias: None,
            ty,
            default: Default::Required,
            before: None,
            after: None,
        }
    }

    /// An `Optional[…] = None` field (`ty` is wrapped in [`Ty::Nullable`] by
    /// the caller when the annotation is `Optional`).
    pub const fn opt(name: &'static str, ty: Ty) -> Self {
        Self {
            name,
            alias: None,
            ty,
            default: Default::None,
            before: None,
            after: None,
        }
    }

    /// A field with a default value.
    pub const fn def(name: &'static str, ty: Ty, default: fn() -> PyValue) -> Self {
        Self {
            name,
            alias: None,
            ty,
            default: Default::Value(default),
            before: None,
            after: None,
        }
    }

    /// With an alias.
    pub const fn alias(mut self, alias: &'static str) -> Self {
        self.alias = Some(alias);
        self
    }

    /// With a `mode="before"` validator.
    pub const fn before(mut self, f: fn(&PyValue) -> PyValue) -> Self {
        self.before = Some(f);
        self
    }

    /// With a `mode="after"` validator.
    pub const fn after(mut self, f: AfterValidator) -> Self {
        self.after = Some(f);
        self
    }

    /// The key it is read from and written to.
    pub fn key(&self) -> &'static str {
        self.alias.unwrap_or(self.name)
    }
}

/// A Pydantic model.
#[derive(Debug)]
pub struct Model {
    /// The class name (`1 validation error for <name>`).
    pub name: &'static str,
    /// The fields, in declaration order.
    pub fields: &'static [Field],
    /// `extra="allow"`: undeclared keys are kept.
    pub extra_allow: bool,
}

impl Model {
    /// A model ignoring extra keys.
    pub const fn new(name: &'static str, fields: &'static [Field]) -> Self {
        Self {
            name,
            fields,
            extra_allow: false,
        }
    }

    /// A model keeping extra keys (`ConfigDict(extra="allow")`).
    pub const fn allowing_extra(name: &'static str, fields: &'static [Field]) -> Self {
        Self {
            name,
            fields,
            extra_allow: true,
        }
    }
}

/// How exactly an input matched (smart unions prefer the best).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Exactness {
    Lax,
    Strict,
    Exact,
}

/// A validation that did not complete.
#[derive(Debug, Clone, PartialEq)]
pub enum Invalid {
    /// The `ValidationError`'s lines.
    Errors(Vec<PyError>),
    /// A validator raised `HTTPException(status, detail)`.
    Abort(u16, String),
}

struct Ctx {
    errors: Vec<PyError>,
    abort: Option<(u16, String)>,
    exactness: Exactness,
    fields_set: Option<usize>,
    from_attributes: bool,
}

impl Ctx {
    fn new(from_attributes: bool) -> Self {
        Self {
            errors: Vec::new(),
            abort: None,
            exactness: Exactness::Exact,
            fields_set: None,
            from_attributes,
        }
    }

    fn floor(&mut self, e: Exactness) {
        if e < self.exactness {
            self.exactness = e;
        }
    }

    fn push(&mut self, loc: &[Loc], kind: &'static str, msg: impl Into<String>, input: &PyValue) {
        self.errors.push(PyError {
            loc: loc.to_vec(),
            kind,
            msg: msg.into(),
            input: input.clone(),
        });
    }
}

/// Validate `input` as `model` (`Model(**input)` once Python has checked
/// that `input` is a mapping, or `Model.model_validate(input)`). `Ok` is the
/// JSON-mode dump, by alias.
pub fn validate(model: &'static Model, input: &PyValue) -> Result<PyValue, Invalid> {
    validate_ty(&Ty::Model(model), input)
}

/// Validate `input` against any type (a `TypeAdapter`).
pub fn validate_ty(ty: &Ty, input: &PyValue) -> Result<PyValue, Invalid> {
    validate_with(ty, input, false)
}

/// `TypeAdapter.validate_python(input, from_attributes=True)`, which is how
/// FastAPI validates a request body: a nested model given anything but a
/// dict is `model_attributes_type` ("… or object to extract fields from").
pub fn validate_body(ty: &Ty, input: &PyValue) -> Result<PyValue, Invalid> {
    validate_with(ty, input, true)
}

fn validate_with(ty: &Ty, input: &PyValue, from_attributes: bool) -> Result<PyValue, Invalid> {
    let mut ctx = Ctx::new(from_attributes);
    let mut loc = Vec::new();
    let out = check(ty, input, &mut loc, &mut ctx);
    if let Some((status, detail)) = ctx.abort {
        return Err(Invalid::Abort(status, detail));
    }
    match out {
        Some(v) if ctx.errors.is_empty() => Ok(v),
        _ => Err(Invalid::Errors(ctx.errors)),
    }
}

fn check(ty: &Ty, input: &PyValue, loc: &mut Vec<Loc>, ctx: &mut Ctx) -> Option<PyValue> {
    if ctx.abort.is_some() {
        return None;
    }
    match ty {
        Ty::Any => Some(input.clone()),
        Ty::Str => match input {
            PyValue::Str(s) => Some(PyValue::Str(s.clone())),
            _ => {
                ctx.push(loc, "string_type", "Input should be a valid string", input);
                None
            }
        },
        Ty::Int => check_int(input, loc, ctx),
        Ty::Float => check_float(input, loc, ctx),
        Ty::Bool => check_bool(input, loc, ctx),
        Ty::NoneOnly => match input {
            PyValue::None => Some(PyValue::None),
            _ => {
                ctx.push(loc, "none_required", "Input should be None", input);
                None
            }
        },
        Ty::DateTime => check_datetime(input, loc, ctx),
        Ty::List(item) => match input {
            PyValue::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                let mut ok = true;
                for (i, v) in items.iter().enumerate() {
                    loc.push(Loc::Index(i));
                    match check(item, v, loc, ctx) {
                        Some(x) => out.push(x),
                        None => ok = false,
                    }
                    loc.pop();
                }
                ok.then_some(PyValue::List(out))
            }
            _ => {
                ctx.push(loc, "list_type", "Input should be a valid list", input);
                None
            }
        },
        Ty::Dict(value) => match input {
            PyValue::Dict(items) => {
                let mut out = Vec::with_capacity(items.len());
                let mut ok = true;
                for (k, v) in items {
                    loc.push(Loc::Key(k.clone()));
                    match check(value, v, loc, ctx) {
                        Some(x) => out.push((k.clone(), x)),
                        None => ok = false,
                    }
                    loc.pop();
                }
                ok.then_some(PyValue::Dict(out))
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
        Ty::Model(model) => check_model(model, input, loc, ctx),
        Ty::Nullable(inner) => match input {
            PyValue::None => Some(PyValue::None),
            _ => check(inner, input, loc, ctx),
        },
        Ty::Union(members) => check_union(members, input, loc, ctx),
        Ty::Enum(e) => match input {
            PyValue::Str(s) if e.values.contains(&s.as_str()) => {
                ctx.floor(Exactness::Lax);
                Some(PyValue::Str(s.clone()))
            }
            _ => {
                ctx.push(
                    loc,
                    "enum",
                    format!("Input should be {}", e.expected()),
                    input,
                );
                None
            }
        },
    }
}

fn check_model(
    model: &'static Model,
    input: &PyValue,
    loc: &mut Vec<Loc>,
    ctx: &mut Ctx,
) -> Option<PyValue> {
    let PyValue::Dict(items) = input else {
        if ctx.from_attributes {
            ctx.push(
                loc,
                "model_attributes_type",
                "Input should be a valid dictionary or object to extract fields from",
                input,
            );
        } else {
            ctx.push(
                loc,
                "model_type",
                format!(
                    "Input should be a valid dictionary or instance of {}",
                    model.name
                ),
                input,
            );
        }
        return None;
    };
    let mut out = Vec::with_capacity(model.fields.len());
    let mut ok = true;
    let mut set = 0usize;
    for field in model.fields {
        let key = field.key();
        let present = items.iter().find(|(k, _)| k == key).map(|(_, v)| v);
        loc.push(Loc::Key(key.to_string()));
        match present {
            None => match field.default {
                Default::Required => {
                    ctx.push(loc, "missing", "Field required", input);
                    ok = false;
                }
                Default::None => out.push((key.to_string(), PyValue::None)),
                Default::Value(f) => out.push((key.to_string(), f())),
            },
            Some(raw) => {
                set += 1;
                let before;
                let value = match field.before {
                    Some(f) => {
                        before = f(raw);
                        &before
                    }
                    None => raw,
                };
                match check(&field.ty, value, loc, ctx) {
                    Some(v) => match field.after {
                        None => out.push((key.to_string(), v)),
                        Some(after) => match after(&v) {
                            Ok(v) => out.push((key.to_string(), v)),
                            Err(Check::ValueError(text)) => {
                                ctx.push(loc, "value_error", format!("Value error, {text}"), &v);
                                ok = false;
                            }
                            Err(Check::Abort(status, detail)) => {
                                ctx.abort = Some((status, detail));
                                loc.pop();
                                return None;
                            }
                        },
                    },
                    None => ok = false,
                }
            }
        }
        loc.pop();
        if ctx.abort.is_some() {
            return None;
        }
    }
    if model.extra_allow {
        for (k, v) in items {
            if !model.fields.iter().any(|f| f.key() == k) {
                out.push((k.clone(), v.clone()));
            }
        }
    }
    ctx.fields_set = Some(set);
    ctx.floor(Exactness::Strict);
    ok.then_some(PyValue::Dict(out))
}

/// The label of a union member in error locations.
fn label(ty: &Ty) -> String {
    match ty {
        Ty::Any => "any".into(),
        Ty::Str => "str".into(),
        Ty::Int => "int".into(),
        Ty::Float => "float".into(),
        Ty::Bool => "bool".into(),
        Ty::NoneOnly => "none".into(),
        Ty::DateTime => "datetime".into(),
        Ty::List(item) => format!("list[{}]", label(item)),
        Ty::Dict(value) => format!("dict[str,{}]", label(value)),
        Ty::Model(m) => m.name.into(),
        Ty::Nullable(inner) => format!("nullable[{}]", label(inner)),
        Ty::Union(members) => format!(
            "union[{}]",
            members.iter().map(label).collect::<Vec<_>>().join(",")
        ),
        Ty::Enum(e) => e.name.into(),
    }
}

fn check_union(
    members: &'static [Ty],
    input: &PyValue,
    loc: &[Loc],
    ctx: &mut Ctx,
) -> Option<PyValue> {
    let mut best: Option<(PyValue, Exactness, Option<usize>)> = None;
    let mut failures: Vec<(String, Vec<PyError>)> = Vec::new();
    for member in members {
        let mut sub = Ctx::new(ctx.from_attributes);
        let mut sub_loc = Vec::new();
        let out = check(member, input, &mut sub_loc, &mut sub);
        if let Some((status, detail)) = sub.abort {
            ctx.abort = Some((status, detail));
            return None;
        }
        match out {
            Some(v) if sub.errors.is_empty() => {
                if sub.exactness == Exactness::Exact && sub.fields_set.is_none() {
                    return Some(v);
                }
                let better = match &best {
                    None => true,
                    Some((_, cur_exact, cur_set)) => match (*cur_set, sub.fields_set) {
                        (Some(cur), Some(new)) if cur != new => cur < new,
                        _ => *cur_exact < sub.exactness,
                    },
                };
                if better {
                    best = Some((v, sub.exactness, sub.fields_set));
                }
            }
            _ => {
                if best.is_none() {
                    failures.push((label(member), sub.errors));
                }
            }
        }
    }
    if let Some((v, exactness, _)) = best {
        ctx.floor(exactness);
        return Some(v);
    }
    for (tag, errors) in failures {
        for e in errors {
            let mut l = loc.to_vec();
            l.push(Loc::Key(tag.clone()));
            l.extend(e.loc);
            ctx.errors.push(PyError { loc: l, ..e });
        }
    }
    None
}

/// `str_as_int`: whitespace stripped, an optional sign, digits (and the
/// `_` separators Python allows), and a fractional part of zeros only.
fn parse_int_str(s: &str) -> Option<String> {
    let t = s.trim_matches(|c: char| c.is_whitespace());
    let (sign, digits) = match t.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", t.strip_prefix('+').unwrap_or(t)),
    };
    let digits = match digits.split_once('.') {
        Some((int, frac)) if !frac.is_empty() && frac.chars().all(|c| c == '0') => int,
        Some((int, "")) => int,
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
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    let cleaned = cleaned.trim_start_matches('0');
    if cleaned.is_empty() {
        return Some("0".into());
    }
    Some(format!("{sign}{cleaned}"))
}

/// A whole float as Python's `int(f)` text.
fn float_to_int_text(f: f64) -> String {
    if f.abs() < 9.0e15 {
        format!("{}", f as i64)
    } else {
        // `{:.0}` prints the exact integer value of a whole f64.
        format!("{f:.0}")
    }
}

fn check_int(input: &PyValue, loc: &[Loc], ctx: &mut Ctx) -> Option<PyValue> {
    match input {
        PyValue::Int(i) => Some(PyValue::Int(i.clone())),
        PyValue::Bool(b) => {
            ctx.floor(Exactness::Lax);
            Some(PyValue::Int(if *b { "1" } else { "0" }.into()))
        }
        PyValue::Float(f) => {
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
                ctx.floor(Exactness::Lax);
                Some(PyValue::Int(float_to_int_text(*f)))
            }
        }
        PyValue::Str(s) => match parse_int_str(s) {
            Some(i) => {
                ctx.floor(Exactness::Lax);
                Some(PyValue::Int(i))
            }
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

fn check_float(input: &PyValue, loc: &[Loc], ctx: &mut Ctx) -> Option<PyValue> {
    match input {
        PyValue::Float(f) => Some(PyValue::Float(*f)),
        PyValue::Int(i) => {
            ctx.floor(Exactness::Strict);
            Some(PyValue::Float(i.parse::<f64>().unwrap_or(f64::NAN)))
        }
        PyValue::Bool(b) => {
            ctx.floor(Exactness::Lax);
            Some(PyValue::Float(if *b { 1.0 } else { 0.0 }))
        }
        PyValue::Str(s) => match parse_float_str(s) {
            Some(f) => {
                ctx.floor(Exactness::Lax);
                Some(PyValue::Float(f))
            }
            None => {
                ctx.push(
                    loc,
                    "float_parsing",
                    "Input should be a valid number, unable to parse string as a number",
                    input,
                );
                None
            }
        },
        _ => {
            ctx.push(loc, "float_type", "Input should be a valid number", input);
            None
        }
    }
}

/// `str_as_float`: Rust's float grammar on the stripped string, `_`
/// separators allowed between digits.
fn parse_float_str(s: &str) -> Option<f64> {
    let trimmed = s.trim();
    let owned;
    let t = if trimmed.contains('_') {
        let chars: Vec<char> = trimmed.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            if *c == '_' {
                let before = i.checked_sub(1).and_then(|j| chars.get(j));
                let after = chars.get(i + 1);
                if !(before.is_some_and(char::is_ascii_digit)
                    && after.is_some_and(char::is_ascii_digit))
                {
                    return None;
                }
            }
        }
        owned = trimmed.replace('_', "");
        owned.as_str()
    } else {
        trimmed
    };
    let lower = t.to_ascii_lowercase();
    let body = lower.trim_start_matches(['+', '-']);
    if matches!(body, "inf" | "infinity" | "nan") {
        return t.parse::<f64>().ok();
    }
    if t.chars()
        .any(|c| !(c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-')))
    {
        return None;
    }
    t.parse::<f64>().ok()
}

fn check_bool(input: &PyValue, loc: &[Loc], ctx: &mut Ctx) -> Option<PyValue> {
    let parsed = match input {
        PyValue::Bool(b) => return Some(PyValue::Bool(*b)),
        PyValue::Int(i) => match i.as_str() {
            "0" => Some(false),
            "1" => Some(true),
            big if big.parse::<i64>().is_err() => {
                ctx.push(loc, "bool_type", "Input should be a valid boolean", input);
                return None;
            }
            _ => None,
        },
        PyValue::Float(f) => {
            if *f == 0.0 {
                Some(false)
            } else if *f == 1.0 {
                Some(true)
            } else {
                ctx.push(loc, "bool_type", "Input should be a valid boolean", input);
                return None;
            }
        }
        PyValue::Str(s) => match s.to_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            _ => None,
        },
        _ => {
            ctx.push(loc, "bool_type", "Input should be a valid boolean", input);
            return None;
        }
    };
    match parsed {
        Some(b) => {
            ctx.floor(Exactness::Lax);
            Some(PyValue::Bool(b))
        }
        None => {
            ctx.push(
                loc,
                "bool_parsing",
                "Input should be a valid boolean, unable to interpret input",
                input,
            );
            None
        }
    }
}

fn speedate_message(e: &speedate::ParseError) -> &'static str {
    use strum::EnumMessage;
    e.get_documentation().unwrap_or_default()
}

/// A Pydantic `datetime` in JSON mode: `YYYY-MM-DDTHH:MM:SS[.ffffff][Z|±HH:MM]`.
pub fn format_datetime(dt: &DateTime) -> String {
    let d = &dt.date;
    let t = &dt.time;
    let mut out = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        d.year, d.month, d.day, t.hour, t.minute, t.second
    );
    if t.microsecond != 0 {
        out.push_str(&format!(".{:06}", t.microsecond));
    }
    match t.tz_offset {
        None => {}
        Some(0) => out.push('Z'),
        Some(off) => {
            let sign = if off < 0 { '-' } else { '+' };
            let a = off.unsigned_abs();
            out.push_str(&format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60));
            if a % 60 != 0 {
                out.push_str(&format!(":{:02}", a % 60));
            }
        }
    }
    out
}

fn dt_config() -> DateTimeConfig {
    DateTimeConfig {
        timestamp_unit: TimestampUnit::Infer,
        time_config: TimeConfig {
            microseconds_precision_overflow_behavior:
                MicrosecondsPrecisionOverflowBehavior::Truncate,
            unix_timestamp_offset: Some(0),
        },
    }
}

/// Parse like a Pydantic `datetime` field (the string path: datetime, else a
/// date at midnight); the error is Pydantic's `(type, message)`.
pub fn parse_datetime_str(s: &str) -> Result<DateTime, (&'static str, String)> {
    let config = dt_config();
    match DateTime::parse_bytes_with_config(s.as_bytes(), &config) {
        Ok(dt) => Ok(dt),
        Err(_) => {
            let date_config = DateConfig {
                timestamp_unit: TimestampUnit::Infer,
            };
            match Date::parse_bytes_with_config(s.as_bytes(), &date_config) {
                Ok(d) => Ok(DateTime {
                    date: d,
                    time: speedate::Time {
                        hour: 0,
                        minute: 0,
                        second: 0,
                        microsecond: 0,
                        tz_offset: None,
                    },
                }),
                Err(e) => Err((
                    "datetime_from_date_parsing",
                    format!(
                        "Input should be a valid datetime or date, {}",
                        speedate_message(&e)
                    ),
                )),
            }
        }
    }
}

fn check_datetime(input: &PyValue, loc: &[Loc], ctx: &mut Ctx) -> Option<PyValue> {
    let number_error = |e: speedate::ParseError| {
        (
            "datetime_parsing",
            format!("Input should be a valid datetime, {}", speedate_message(&e)),
        )
    };
    let parsed = match input {
        PyValue::Str(s) => parse_datetime_str(s),
        PyValue::Int(i) => match i.parse::<i64>() {
            Ok(n) => DateTime::from_timestamp_with_config(n, 0, &dt_config()).map_err(number_error),
            Err(_) => Err(number_error(speedate::ParseError::DateTooLarge)),
        },
        PyValue::Float(f) if f.is_nan() => Err((
            "datetime_parsing",
            "Input should be a valid datetime, NaN values not permitted".to_string(),
        )),
        PyValue::Float(f) => {
            DateTime::from_float_with_config(*f, &dt_config()).map_err(number_error)
        }
        _ => {
            ctx.push(
                loc,
                "datetime_type",
                "Input should be a valid datetime",
                input,
            );
            return None;
        }
    };
    match parsed {
        Ok(dt) => {
            ctx.floor(Exactness::Lax);
            Some(PyValue::Str(format_datetime(&dt)))
        }
        Err((kind, msg)) => {
            ctx.push(loc, kind, msg, input);
            None
        }
    }
}

/// `input_value=`: the value's `repr()`, cut to its first 25 and last 24
/// characters around `...` when longer than 50 (by UTF-8 bytes, like
/// pydantic-core).
pub fn input_value(v: &PyValue) -> String {
    let repr = v.py_repr();
    let len = repr.len();
    if len <= 50 {
        return repr;
    }
    let mut head = 25;
    while !repr.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = len - 24;
    while !repr.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{}...{}", &repr[..head], &repr[tail..])
}

/// `str(ValidationError)` for the model `title`.
pub fn format_validation_error(title: &str, errors: &[PyError]) -> String {
    let n = errors.len();
    let mut out = format!(
        "{n} validation error{} for {title}",
        if n == 1 { "" } else { "s" }
    );
    for e in errors {
        out.push('\n');
        if !e.loc.is_empty() {
            let parts: Vec<String> = e
                .loc
                .iter()
                .map(|l| match l {
                    Loc::Key(k) => k.clone(),
                    Loc::Index(i) => i.to_string(),
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
            input_value(&e.input),
            type_name(&e.input),
            e.kind
        ));
    }
    out
}

/// `float` as Python prints it (re-exported for messages).
pub fn py_float(f: f64) -> String {
    float_repr(f)
}

/// Field `key` of a validated model dump.
pub fn field<'a>(dump: &'a PyValue, key: &str) -> &'a PyValue {
    static NONE: PyValue = PyValue::None;
    match dump {
        PyValue::Dict(items) => items
            .iter()
            .find(|(k, _)| k == key)
            .map_or(&NONE, |(_, v)| v),
        _ => &NONE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    static LEAF: Model = Model::new(
        "Leaf",
        &[
            Field::req("n", Ty::Int),
            Field::opt("children", Ty::Nullable(&Ty::List(&Ty::Model(&LEAF)))),
        ],
    );

    static COLOR: EnumTy = EnumTy {
        name: "Color",
        values: &["red", "Green", "b"],
    };
    static PAINT: Model = Model::new(
        "M",
        &[
            Field::req("c", Ty::Enum(&COLOR)),
            Field::opt("d", Ty::Nullable(&Ty::Enum(&COLOR))),
        ],
    );

    #[test]
    fn str_enums_take_their_values_only() {
        let Err(Invalid::Errors(errs)) =
            validate(&PAINT, &loads(r#"{"c": "RED", "d": 5}"#).unwrap())
        else {
            panic!("expected errors")
        };
        assert_eq!(
            format_validation_error("M", &errs),
            "2 validation errors for M\nc\n  Input should be 'red', 'Green' or 'b' [type=enum, \
             input_value='RED', input_type=str]\n    For further information visit \
             https://errors.pydantic.dev/2.13/v/enum\nd\n  Input should be 'red', 'Green' or 'b' \
             [type=enum, input_value=5, input_type=int]\n    For further information visit \
             https://errors.pydantic.dev/2.13/v/enum"
        );
        let ok = validate(&PAINT, &loads(r#"{"c": "red"}"#).unwrap()).unwrap();
        assert_eq!(ok.py_repr(), "{'c': 'red', 'd': None}");
    }

    #[test]
    fn recursive_models_and_errors() {
        let v = loads(r#"{"n": "2", "children": [{"n": 1.0}, {"x": 1}]}"#).unwrap();
        let Err(Invalid::Errors(errs)) = validate(&LEAF, &v) else {
            panic!("expected errors")
        };
        assert_eq!(
            format_validation_error("Leaf", &errs),
            "1 validation error for Leaf\nchildren.1.n\n  Field required [type=missing, \
             input_value={'x': 1}, input_type=dict]\n    For further information visit \
             https://errors.pydantic.dev/2.13/v/missing"
        );
        let ok = validate(
            &LEAF,
            &loads(r#"{"n": "2", "children": [{"n": 1.0}]}"#).unwrap(),
        );
        assert_eq!(
            ok.unwrap().py_repr(),
            "{'n': 2, 'children': [{'n': 1, 'children': None}]}"
        );
    }

    #[test]
    fn request_bodies_validate_from_attributes() {
        static OUTER: Model = Model::new("Outer", &[Field::req("leaf", Ty::Model(&LEAF))]);
        let input = loads(r#"{"leaf": null}"#).unwrap();
        let kind = |r: Result<PyValue, Invalid>| match r {
            Err(Invalid::Errors(e)) => (e[0].kind, e[0].msg.clone()),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            kind(validate(&OUTER, &input)),
            (
                "model_type",
                "Input should be a valid dictionary or instance of Leaf".into()
            )
        );
        assert_eq!(
            kind(validate_body(&Ty::Model(&OUTER), &input)),
            (
                "model_attributes_type",
                "Input should be a valid dictionary or object to extract fields from".into()
            )
        );
    }

    #[test]
    fn int_strings() {
        for (s, want) in [
            (" 12 ", Some("12")),
            ("1_000", Some("1000")),
            ("-007", Some("-7")),
            ("1.0", Some("1")),
            ("1.5", None),
            ("", None),
            ("_1", None),
        ] {
            assert_eq!(parse_int_str(s).as_deref(), want, "{s:?}");
        }
    }
}

/// `Model(**kwargs)` / `Model.model_validate(kwargs)`: the dump, or the
/// exception Python raises (`ValidationError`, or the `HTTPException` a
/// validator raised).
pub fn construct(model: &'static Model, kwargs: &PyValue) -> Result<PyValue, crate::py::PyExc> {
    validate(model, kwargs).map_err(|e| match e {
        Invalid::Errors(errors) => {
            crate::py::PyExc::Validation(format_validation_error(model.name, &errors))
        }
        Invalid::Abort(status, detail) => crate::py::PyExc::Http(status, detail),
    })
}

/// `Model(**value)` where `value` came from a tool: a `TypeError` unless it
/// is a dict (`qualname` is the class's module path, which Python names).
pub fn construct_star(
    model: &'static Model,
    qualname: &str,
    value: &PyValue,
) -> Result<PyValue, crate::py::PyExc> {
    if !matches!(value, PyValue::Dict(_)) {
        return Err(crate::py::PyExc::TypeError(format!(
            "{qualname}() argument after ** must be a mapping, not {}",
            type_name(value)
        )));
    }
    construct(model, value)
}

/// A dict from pairs (kwargs for [`construct`]).
pub fn kwargs(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

#[cfg(test)]
mod vectors {
    //! `model_vectors.json`: the lax rules against pydantic
    //! (`scripts/gen-connector-model-vectors.py`).

    use super::*;
    use crate::json::pydantic_json;
    use copilot_auth::pyvalue::loads;

    static SUB: Model = Model::new(
        "Sub",
        &[
            Field::req("x", Ty::Int),
            Field::opt("y", Ty::Nullable(&Ty::Str)),
        ],
    );

    fn zero() -> PyValue {
        PyValue::Int("0".into())
    }
    fn zero_f() -> PyValue {
        PyValue::Float(0.0)
    }
    fn no() -> PyValue {
        PyValue::Bool(false)
    }
    fn empty() -> PyValue {
        PyValue::Str(String::new())
    }
    fn list() -> PyValue {
        PyValue::List(Vec::new())
    }
    fn dict() -> PyValue {
        PyValue::Dict(Vec::new())
    }

    static LAX: Model = Model::new(
        "Lax",
        &[
            Field::def("i", Ty::Int, zero),
            Field::def("f", Ty::Float, zero_f),
            Field::def("b", Ty::Bool, no),
            Field::def("s", Ty::Str, empty),
            Field::opt("n", Ty::NoneOnly),
            Field::opt("oi", Ty::Nullable(&Ty::Int)),
            Field::def("li", Ty::List(&Ty::Int), list),
            Field::def("ld", Ty::List(&Ty::Nullable(&Ty::Str)), list),
            Field::def("ds", Ty::Dict(&Ty::Str), dict),
            Field::def("da", Ty::Dict(&Ty::Any), dict),
            Field::def("la", Ty::List(&Ty::Any), list),
            Field::opt("a", Ty::Any),
            Field::opt("dt", Ty::Nullable(&Ty::DateTime)),
            Field::opt("m", Ty::Nullable(&Ty::Model(&SUB))),
            Field::opt(
                "u_str_model",
                Ty::Nullable(&Ty::Union(&[Ty::Str, Ty::Model(&SUB)])),
            ),
            Field::opt("u_int_str", Ty::Nullable(&Ty::Union(&[Ty::Int, Ty::Str]))),
            Field::opt(
                "u_str_list",
                Ty::Nullable(&Ty::Union(&[Ty::Str, Ty::List(&Ty::Model(&SUB))])),
            ),
            Field::opt(
                "u_dict",
                Ty::Nullable(&Ty::Dict(&Ty::Union(&[Ty::Str, Ty::List(&Ty::Str)]))),
            ),
        ],
    );

    #[test]
    fn lax_rules_match_pydantic() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("model_vectors.json")).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() > 800);
        let mut failures = Vec::new();
        for v in vectors {
            let input = loads(v["input"].as_str().unwrap()).unwrap();
            let got = match validate(&LAX, &input) {
                Ok(dump) => Ok(pydantic_json(&dump)),
                Err(Invalid::Errors(e)) => Err(format_validation_error("Lax", &e)),
                Err(Invalid::Abort(..)) => Err("abort".into()),
            };
            let want = match v.get("ok") {
                Some(ok) => Ok(ok.as_str().unwrap().to_string()),
                None => Err(v["err"].as_str().unwrap().to_string()),
            };
            if got != want {
                failures.push(format!(
                    "{}\n  want {want:?}\n  got  {got:?}",
                    v["input"].as_str().unwrap()
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} vectors differ:\n{}",
            failures.len(),
            vectors.len(),
            failures.join("\n")
        );
    }
}
