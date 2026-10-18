//! Pydantic 2 models over upstream JSON — the Wazuh responses the Python
//! services feed into their models (`ClusterHealth(**data)`,
//! `WazuhRulesResponse(results=…)`, `SnapshotStatus(…)`).
//!
//! A model is a static field list ([`Model`], [`Field`], [`Ty`]); [`validate`]
//! applies Pydantic's lax Python-mode coercions to a `json.loads` value and
//! either returns the model as FastAPI would serialize it (declaration
//! order, aliases, defaults filled in) or the `ValidationError` text, which
//! several routes put into their responses (`Error fetching rules: 1
//! validation error for WazuhRulesResponse …`).
//!
//! Only what these models use is covered: `str`, `int`, `float`, `bool`,
//! `Union[int, float]`, `Union[dict, str]`, `Optional`, `List`, `Dict[str, …]`,
//! nested models, `Any`, defaults and aliases, `extra="ignore"`.

use copilot_auth::pyvalue::PyValue;
use serde_json::{Map, Number, Value};

/// The `major.minor` of the Pydantic release CoPilot runs (the error links
/// name it).
pub const PYDANTIC_VERSION: &str = "2.13";

/// A field type.
#[derive(Debug)]
pub enum Ty {
    /// `str`.
    Str,
    /// `int`.
    Int,
    /// `float`.
    Float,
    /// `bool`.
    Bool,
    /// `Any`.
    Any,
    /// `Union[int, float]` (smart mode).
    IntOrFloat,
    /// `Union[dict, str]` (smart mode).
    DictOrStr,
    /// `Optional[T]`.
    Opt(&'static Ty),
    /// `List[T]`.
    List(&'static Ty),
    /// `Dict[str, T]` (`dict` is `Dict[str, Any]`).
    Dict(&'static Ty),
    /// A nested model.
    Model(&'static Model),
}

/// What an absent field becomes.
#[derive(Debug, Clone, Copy)]
pub enum Default {
    /// Required (`missing` when absent).
    Required,
    /// `None`.
    Null,
    /// `[]`.
    EmptyList,
    /// `{}`.
    EmptyDict,
    /// `False` / `True`.
    Bool(bool),
    /// An int.
    Int(i64),
    /// A string.
    Str(&'static str),
}

impl Default {
    fn value(self) -> Option<Value> {
        match self {
            Default::Required => None,
            Default::Null => Some(Value::Null),
            Default::EmptyList => Some(Value::Array(Vec::new())),
            Default::EmptyDict => Some(Value::Object(Map::new())),
            Default::Bool(b) => Some(Value::Bool(b)),
            Default::Int(i) => Some(Value::from(i)),
            Default::Str(s) => Some(Value::String(s.into())),
        }
    }
}

/// One field.
#[derive(Debug)]
pub struct Field {
    /// Attribute name.
    pub name: &'static str,
    /// `Field(alias=…)`: the input key (and the output key, FastAPI
    /// serializing by alias).
    pub alias: Option<&'static str>,
    /// `populate_by_name`: the attribute name is accepted as input too.
    pub by_name: bool,
    /// Type.
    pub ty: Ty,
    /// Default.
    pub default: Default,
}

impl Field {
    /// A field without alias.
    pub const fn new(name: &'static str, ty: Ty, default: Default) -> Self {
        Self {
            name,
            alias: None,
            by_name: false,
            ty,
            default,
        }
    }

    /// A required field.
    pub const fn req(name: &'static str, ty: Ty) -> Self {
        Self::new(name, ty, Default::Required)
    }

    /// A field read from (and written as) `alias`.
    pub const fn aliased(
        name: &'static str,
        alias: &'static str,
        ty: Ty,
        default: Default,
    ) -> Self {
        Self {
            name,
            alias: Some(alias),
            by_name: false,
            ty,
            default,
        }
    }

    /// With `populate_by_name`.
    pub const fn or_by_name(mut self) -> Self {
        self.by_name = true;
        self
    }

    fn key(&self) -> &'static str {
        self.alias.unwrap_or(self.name)
    }
}

/// A model.
#[derive(Debug)]
pub struct Model {
    /// Class name (the error title).
    pub name: &'static str,
    /// Fields in declaration order.
    pub fields: &'static [Field],
}

/// One location element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loc {
    /// A field, dict key or union member.
    Key(String),
    /// A list index.
    Index(usize),
}

/// One error.
#[derive(Debug, Clone, PartialEq)]
pub struct PyError {
    /// Where.
    pub loc: Vec<Loc>,
    /// Pydantic's type code.
    pub kind: &'static str,
    /// Message.
    pub msg: String,
    /// The offending input.
    pub input: PyValue,
}

/// A failed validation: `str(ValidationError)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError {
    /// Model name.
    pub title: String,
    /// Errors in order.
    pub errors: Vec<PyError>,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format(&self.title, &self.errors))
    }
}

/// A `json.loads` value as Python sees it.
pub fn py(v: &Value) -> PyValue {
    match v {
        Value::Null => PyValue::None,
        Value::Bool(b) => PyValue::Bool(*b),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                PyValue::Int(n.to_string())
            } else {
                PyValue::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => PyValue::Str(s.clone()),
        Value::Array(a) => PyValue::List(a.iter().map(py).collect()),
        Value::Object(o) => PyValue::Dict(o.iter().map(|(k, v)| (k.clone(), py(v))).collect()),
    }
}

fn input_type(v: &PyValue) -> &'static str {
    match v {
        PyValue::None => "NoneType",
        PyValue::Bool(_) => "bool",
        PyValue::Int(_) => "int",
        PyValue::Float(_) => "float",
        PyValue::Str(_) => "str",
        PyValue::List(_) => "list",
        PyValue::Dict(_) => "dict",
    }
}

/// `input_value=`: `repr()`, cut to 25 + `...` + 24 characters' worth of
/// UTF-8 when over 50 bytes.
fn input_value(v: &PyValue) -> String {
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

/// `str(ValidationError)`.
pub fn format(title: &str, errors: &[PyError]) -> String {
    let n = errors.len();
    let mut out = format!(
        "{n} validation error{} for {title}",
        if n == 1 { "" } else { "s" }
    );
    for e in errors {
        out.push('\n');
        if !e.loc.is_empty() {
            let loc: Vec<String> = e
                .loc
                .iter()
                .map(|l| match l {
                    Loc::Key(k) => k.clone(),
                    Loc::Index(i) => i.to_string(),
                })
                .collect();
            out.push_str(&loc.join("."));
            out.push('\n');
        }
        out.push_str(&format!(
            "  {} [type={}, input_value={}, input_type={}]\n    For further information visit \
             https://errors.pydantic.dev/{PYDANTIC_VERSION}/v/{}",
            e.msg,
            e.kind,
            input_value(&e.input),
            input_type(&e.input),
            e.kind
        ));
    }
    out
}

struct Ctx {
    errors: Vec<PyError>,
}

impl Ctx {
    fn err(&mut self, loc: &[Loc], kind: &'static str, msg: &str, input: &Value) {
        self.errors.push(PyError {
            loc: loc.to_vec(),
            kind,
            msg: msg.to_string(),
            input: py(input),
        });
    }
}

fn with(loc: &[Loc], part: Loc) -> Vec<Loc> {
    let mut l = loc.to_vec();
    l.push(part);
    l
}

/// Pydantic's `str` → `int`: surrounding whitespace, a sign, digits with
/// single underscores between them, and an all-zero fraction.
fn int_from_str(s: &str) -> Option<Number> {
    let t = s.trim_matches(|c: char| c.is_whitespace());
    let (neg, body) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let (int_part, frac) = match body.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (body, None),
    };
    if let Some(f) = frac {
        if f.is_empty() || !f.bytes().all(|b| b == b'0') {
            return None;
        }
    }
    let bytes = int_part.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_digit()
        || !bytes[bytes.len() - 1].is_ascii_digit()
        || bytes.windows(2).any(|w| w == b"__")
        || !bytes.iter().all(|b| b.is_ascii_digit() || *b == b'_')
    {
        return None;
    }
    let digits: String = int_part.chars().filter(|c| *c != '_').collect();
    let text = if neg { format!("-{digits}") } else { digits };
    serde_json::from_str::<Number>(&text)
        .ok()
        .or_else(|| text.parse::<f64>().ok().and_then(Number::from_f64))
}

/// Pydantic's `str` → `float`.
fn float_from_str(s: &str) -> Option<f64> {
    let t = s.trim_matches(|c: char| c.is_whitespace());
    let lower = t.to_ascii_lowercase();
    let unsigned = lower.trim_start_matches(['+', '-']);
    if matches!(unsigned, "inf" | "infinity" | "nan") {
        return lower.parse::<f64>().ok().or(match lower.as_str() {
            "-infinity" => Some(f64::NEG_INFINITY),
            "infinity" | "+infinity" => Some(f64::INFINITY),
            _ => None,
        });
    }
    let bytes = t.as_bytes();
    if bytes.windows(2).any(|w| w == b"__") || t.starts_with('_') || t.ends_with('_') {
        return None;
    }
    t.replace('_', "").parse::<f64>().ok()
}

fn check(ty: &Ty, v: &Value, loc: &[Loc], cx: &mut Ctx) -> Option<Value> {
    match ty {
        Ty::Any => Some(v.clone()),
        Ty::Str => match v {
            Value::String(_) => Some(v.clone()),
            _ => {
                cx.err(loc, "string_type", "Input should be a valid string", v);
                None
            }
        },
        Ty::Int => check_int(v, loc, cx),
        Ty::Float => check_float(v, loc, cx),
        Ty::Bool => check_bool(v, loc, cx),
        Ty::IntOrFloat => {
            match v {
                Value::Number(_) => return Some(v.clone()),
                Value::Bool(b) => return Some(Value::from(i64::from(*b))),
                Value::String(s) => {
                    if let Some(n) = int_from_str(s) {
                        return Some(Value::Number(n));
                    }
                    if let Some(f) = float_from_str(s).and_then(Number::from_f64) {
                        return Some(Value::Number(f));
                    }
                }
                _ => {}
            }
            let mut sub = Ctx { errors: Vec::new() };
            check_int(v, &with(loc, Loc::Key("int".into())), &mut sub);
            check_float(v, &with(loc, Loc::Key("float".into())), &mut sub);
            cx.errors.extend(sub.errors);
            None
        }
        Ty::DictOrStr => match v {
            Value::Object(_) | Value::String(_) => Some(v.clone()),
            _ => {
                cx.err(
                    &with(loc, Loc::Key("dict[any,any]".into())),
                    "dict_type",
                    "Input should be a valid dictionary",
                    v,
                );
                cx.err(
                    &with(loc, Loc::Key("str".into())),
                    "string_type",
                    "Input should be a valid string",
                    v,
                );
                None
            }
        },
        Ty::Opt(inner) => match v {
            Value::Null => Some(Value::Null),
            _ => check(inner, v, loc, cx),
        },
        Ty::List(item) => match v {
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                let mut ok = true;
                for (i, it) in items.iter().enumerate() {
                    match check(item, it, &with(loc, Loc::Index(i)), cx) {
                        Some(x) => out.push(x),
                        None => ok = false,
                    }
                }
                ok.then_some(Value::Array(out))
            }
            _ => {
                cx.err(loc, "list_type", "Input should be a valid list", v);
                None
            }
        },
        Ty::Dict(item) => match v {
            Value::Object(map) => {
                let mut out = Map::new();
                let mut ok = true;
                for (k, it) in map {
                    match check(item, it, &with(loc, Loc::Key(k.clone())), cx) {
                        Some(x) => {
                            out.insert(k.clone(), x);
                        }
                        None => ok = false,
                    }
                }
                ok.then_some(Value::Object(out))
            }
            _ => {
                cx.err(loc, "dict_type", "Input should be a valid dictionary", v);
                None
            }
        },
        Ty::Model(m) => match v {
            Value::Object(map) => check_model(m, map, v, loc, cx),
            _ => {
                cx.err(
                    loc,
                    "model_type",
                    &format!(
                        "Input should be a valid dictionary or instance of {}",
                        m.name
                    ),
                    v,
                );
                None
            }
        },
    }
}

fn check_int(v: &Value, loc: &[Loc], cx: &mut Ctx) -> Option<Value> {
    match v {
        Value::Number(n) if n.is_i64() || n.is_u64() => Some(v.clone()),
        Value::Number(n) => {
            let f = n.as_f64().unwrap_or(f64::NAN);
            if f.fract() == 0.0 && f.is_finite() && f.abs() < 9.2e18 {
                Some(Value::from(f as i64))
            } else {
                cx.err(
                    loc,
                    "int_from_float",
                    "Input should be a valid integer, got a number with a fractional part",
                    v,
                );
                None
            }
        }
        Value::Bool(b) => Some(Value::from(i64::from(*b))),
        Value::String(s) => match int_from_str(s) {
            Some(n) => Some(Value::Number(n)),
            None => {
                cx.err(
                    loc,
                    "int_parsing",
                    "Input should be a valid integer, unable to parse string as an integer",
                    v,
                );
                None
            }
        },
        _ => {
            cx.err(loc, "int_type", "Input should be a valid integer", v);
            None
        }
    }
}

fn check_float(v: &Value, loc: &[Loc], cx: &mut Ctx) -> Option<Value> {
    let f = match v {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::String(s) => match float_from_str(s) {
            Some(f) => Some(f),
            None => {
                cx.err(
                    loc,
                    "float_parsing",
                    "Input should be a valid number, unable to parse string as a number",
                    v,
                );
                return None;
            }
        },
        _ => None,
    };
    match f {
        Some(f) => Number::from_f64(f).map(Value::Number).or(Some(Value::Null)),
        None => {
            cx.err(loc, "float_type", "Input should be a valid number", v);
            None
        }
    }
}

fn check_bool(v: &Value, loc: &[Loc], cx: &mut Ctx) -> Option<Value> {
    let parsed = match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => match n.as_f64() {
            Some(0.0) => Some(false),
            Some(1.0) => Some(true),
            _ => None,
        },
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            _ => None,
        },
        _ => {
            cx.err(loc, "bool_type", "Input should be a valid boolean", v);
            return None;
        }
    };
    if parsed.is_none() {
        cx.err(
            loc,
            "bool_parsing",
            "Input should be a valid boolean, unable to interpret input",
            v,
        );
    }
    parsed.map(Value::Bool)
}

fn check_model(
    m: &Model,
    map: &Map<String, Value>,
    whole: &Value,
    loc: &[Loc],
    cx: &mut Ctx,
) -> Option<Value> {
    let mut out = Map::new();
    let mut ok = true;
    for f in m.fields {
        let found = map
            .get(f.key())
            .or_else(|| if f.by_name { map.get(f.name) } else { None });
        let at = with(loc, Loc::Key(f.key().to_string()));
        match found {
            Some(v) => match check(&f.ty, v, &at, cx) {
                Some(x) => {
                    out.insert(f.key().to_string(), x);
                }
                None => ok = false,
            },
            None => match f.default.value() {
                Some(d) => {
                    out.insert(f.key().to_string(), d);
                }
                None => {
                    cx.err(&at, "missing", "Field required", whole);
                    ok = false;
                }
            },
        }
    }
    ok.then_some(Value::Object(out))
}

/// Validate `input` (the model's keyword arguments, or a dict) as `model`:
/// the serialized model, or the `ValidationError`.
pub fn validate(model: &Model, input: &Value) -> Result<Value, ValidationError> {
    let mut cx = Ctx { errors: Vec::new() };
    let out = match input {
        Value::Object(map) => check_model(model, map, input, &[], &mut cx),
        _ => {
            cx.err(
                &[],
                "model_type",
                &format!(
                    "Input should be a valid dictionary or instance of {}",
                    model.name
                ),
                input,
            );
            None
        }
    };
    match out {
        Some(v) if cx.errors.is_empty() => Ok(v),
        _ => Err(ValidationError {
            title: model.name.to_string(),
            errors: cx.errors,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    static M: Model = Model {
        name: "M",
        fields: &[
            Field::req("a", Ty::Int),
            Field::req("b", Ty::Bool),
            Field::req("c", Ty::Str),
            Field::req("d", Ty::IntOrFloat),
            Field::new("e", Ty::Opt(&Ty::Str), Default::Str("x")),
            Field::new("f", Ty::List(&Ty::Str), Default::EmptyList),
            Field::new("g", Ty::Dict(&Ty::Any), Default::EmptyDict),
            Field::new("h", Ty::Float, Default::Int(0)),
        ],
    };

    #[test]
    fn coercions_match_pydantic() {
        // Recorded with pydantic 2.13 (`M(**data).model_dump()`).
        assert_eq!(
            validate(&M, &json!({"a": "1_000", "b": "yes", "c": "s", "d": "1.5"})).unwrap(),
            json!({"a": 1000, "b": true, "c": "s", "d": 1.5, "e": "x", "f": [], "g": {}, "h": 0})
        );
        assert_eq!(
            validate(&M, &json!({"a": " 7 ", "b": 1, "c": "s", "d": true})).unwrap(),
            json!({"a": 7, "b": true, "c": "s", "d": 1, "e": "x", "f": [], "g": {}, "h": 0})
        );
        assert_eq!(
            validate(
                &M,
                &json!({"a": "12.0000", "b": "oN", "c": "s", "d": 3, "h": true})
            )
            .unwrap()["h"],
            json!(1.0)
        );
    }

    #[test]
    fn errors_match_pydantic() {
        let e = validate(
            &M,
            &json!({"a": "1.0", "b": 2, "c": 5, "d": null, "e": null, "f": null, "g": [], "h": "x"}),
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "7 validation errors for M\n\
             b\n  Input should be a valid boolean, unable to interpret input [type=bool_parsing, input_value=2, input_type=int]\n    For further information visit https://errors.pydantic.dev/2.13/v/bool_parsing\n\
             c\n  Input should be a valid string [type=string_type, input_value=5, input_type=int]\n    For further information visit https://errors.pydantic.dev/2.13/v/string_type\n\
             d.int\n  Input should be a valid integer [type=int_type, input_value=None, input_type=NoneType]\n    For further information visit https://errors.pydantic.dev/2.13/v/int_type\n\
             d.float\n  Input should be a valid number [type=float_type, input_value=None, input_type=NoneType]\n    For further information visit https://errors.pydantic.dev/2.13/v/float_type\n\
             f\n  Input should be a valid list [type=list_type, input_value=None, input_type=NoneType]\n    For further information visit https://errors.pydantic.dev/2.13/v/list_type\n\
             g\n  Input should be a valid dictionary [type=dict_type, input_value=[], input_type=list]\n    For further information visit https://errors.pydantic.dev/2.13/v/dict_type\n\
             h\n  Input should be a valid number, unable to parse string as a number [type=float_parsing, input_value='x', input_type=str]\n    For further information visit https://errors.pydantic.dev/2.13/v/float_parsing"
        );
        let e = validate(
            &M,
            &json!({"a": 1.5, "b": 1.0, "c": "s", "d": "abc", "f": [1]}),
        )
        .unwrap_err();
        let kinds: Vec<_> = e.errors.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                "int_from_float",
                "int_parsing",
                "float_parsing",
                "string_type"
            ]
        );
        let missing = validate(&M, &json!({})).unwrap_err();
        assert_eq!(missing.errors.len(), 4);
        assert_eq!(missing.errors[0].kind, "missing");
    }

    #[test]
    fn int_strings() {
        for (s, ok) in [
            ("+5", true),
            ("-0", true),
            (" 12 ", true),
            ("1_0_", false),
            ("_1", false),
            ("1.5", false),
            ("1e3", false),
            ("0x10", false),
            ("1.", false),
            ("１２", false),
        ] {
            assert_eq!(int_from_str(s).is_some(), ok, "{s}");
        }
    }
}
