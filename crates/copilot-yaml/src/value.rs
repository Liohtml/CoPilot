//! The Python objects `yaml.safe_load` returns, as an immutable tree.
//!
//! What PyYAML shares (an alias is the anchored object) stays shared here
//! (`Arc`), so a document that aliases one list a thousand times costs one
//! list. A container that contains itself is cut where it recurs
//! ([`Value::Recursive`]): `repr()` prints `[...]` there, as Python does, and
//! a JSON dump fails as pydantic's does.

use std::sync::Arc;

use num_bigint_dig::BigInt;
use num_traits::{ToPrimitive, Zero};

use crate::constructor::{Obj, int_float_eq};
use crate::repr::{bytes_repr, float_repr, str_repr};

/// A `datetime.date`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Date {
    /// 1..=9999.
    pub year: i32,
    /// 1..=12.
    pub month: u8,
    /// 1..=31.
    pub day: u8,
}

impl Date {
    /// `date.isoformat()`.
    pub fn isoformat(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    fn ordinal(&self) -> i64 {
        // Days since 0001-01-01 (proleptic Gregorian).
        let y = i64::from(self.year) - 1;
        let mut days = y * 365 + y / 4 - y / 100 + y / 400;
        let leap = {
            let y = i64::from(self.year);
            (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        };
        const CUM: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        days += CUM[usize::from(self.month.saturating_sub(1)).min(11)];
        if leap && self.month > 2 {
            days += 1;
        }
        days + i64::from(self.day) - 1
    }
}

/// A `datetime.datetime`, naive or with a fixed offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DateTime {
    /// The date.
    pub date: Date,
    /// 0..=23.
    pub hour: u8,
    /// 0..=59.
    pub minute: u8,
    /// 0..=59.
    pub second: u8,
    /// 0..=999999.
    pub microsecond: u32,
    /// `utcoffset()` in seconds (`None`: naive; `Some(0)`: `timezone.utc`).
    pub offset: Option<i32>,
}

impl DateTime {
    fn utc_micros(&self) -> i128 {
        let seconds = self.date.ordinal() * 86400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
            - i64::from(self.offset.unwrap_or(0));
        i128::from(seconds) * 1_000_000 + i128::from(self.microsecond)
    }

    /// Python's `==`: two aware datetimes at the same instant are equal; a
    /// naive and an aware one never are.
    pub fn py_eq(&self, other: &DateTime) -> bool {
        match (self.offset, other.offset) {
            (None, None) => self == other,
            (Some(_), Some(_)) => self.utc_micros() == other.utc_micros(),
            _ => false,
        }
    }

    fn offset_text(&self, utc_as_z: bool) -> String {
        match self.offset {
            None => String::new(),
            Some(0) if utc_as_z => "Z".into(),
            Some(off) => {
                let sign = if off < 0 { '-' } else { '+' };
                let a = off.unsigned_abs();
                format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60)
            }
        }
    }

    /// `datetime.isoformat()`.
    pub fn isoformat(&self) -> String {
        let mut out = format!(
            "{}T{:02}:{:02}:{:02}",
            self.date.isoformat(),
            self.hour,
            self.minute,
            self.second
        );
        if self.microsecond != 0 {
            out.push_str(&format!(".{:06}", self.microsecond));
        }
        out.push_str(&self.offset_text(false));
        out
    }

    /// `str(datetime)` (`isoformat(sep=' ')`).
    pub fn py_str(&self) -> String {
        self.isoformat().replacen('T', " ", 1)
    }

    /// pydantic's JSON for a `datetime`: `Z` for UTC.
    pub fn pydantic(&self) -> String {
        let mut out = format!(
            "{}T{:02}:{:02}:{:02}",
            self.date.isoformat(),
            self.hour,
            self.minute,
            self.second
        );
        if self.microsecond != 0 {
            out.push_str(&format!(".{:06}", self.microsecond));
        }
        out.push_str(&self.offset_text(true));
        out
    }

    fn repr(&self) -> String {
        let d = &self.date;
        let mut out = format!(
            "datetime.datetime({}, {}, {}, {}, {}",
            d.year, d.month, d.day, self.hour, self.minute
        );
        if self.microsecond != 0 {
            out.push_str(&format!(", {}, {}", self.second, self.microsecond));
        } else if self.second != 0 {
            out.push_str(&format!(", {}", self.second));
        }
        match self.offset {
            None => {}
            Some(0) => out.push_str(", tzinfo=datetime.timezone.utc"),
            Some(off) => out.push_str(&format!(
                ", tzinfo=datetime.timezone({})",
                crate::pyint::timedelta_repr(i64::from(off))
            )),
        }
        out.push(')');
        out
    }
}

/// A Python object from a YAML document.
#[derive(Debug, Clone)]
pub enum Value {
    /// `None`.
    None,
    /// `bool`.
    Bool(bool),
    /// `int`.
    Int(BigInt),
    /// `float`.
    Float(f64),
    /// `str`.
    Str(String),
    /// `bytes` (`!!binary`).
    Bytes(Vec<u8>),
    /// `datetime.date`.
    Date(Date),
    /// `datetime.datetime`.
    DateTime(DateTime),
    /// `list`.
    List(Arc<Vec<Value>>),
    /// `tuple` (the pairs of `!!omap` and `!!pairs`).
    Tuple(Arc<Vec<Value>>),
    /// `dict`, in insertion order (keys unique under Python's `==`).
    Dict(Arc<Vec<(Value, Value)>>),
    /// `set` (`!!set`), in insertion order — Python's order follows the
    /// elements' hashes.
    Set(Arc<Vec<Value>>),
    /// A container met again inside itself: the kind of the enclosing one
    /// (`'['` list, `'('` tuple, `'{'` dict, `'s'` set).
    Recursive(char),
}

/// Rebuild the arena's objects as a tree, sharing what the arena shares.
pub(crate) fn export(objs: &[Obj], root: usize) -> Value {
    let mut done: Vec<Option<Value>> = vec![None; objs.len()];
    let mut stack: Vec<usize> = Vec::new();
    export_obj(objs, root, &mut done, &mut stack)
}

fn export_obj(
    objs: &[Obj],
    id: usize,
    done: &mut Vec<Option<Value>>,
    stack: &mut Vec<usize>,
) -> Value {
    if let Some(v) = &done[id] {
        return v.clone();
    }
    if stack.contains(&id) {
        return Value::Recursive(match objs[id] {
            Obj::Tuple(_) => '(',
            Obj::Dict(_) => '{',
            Obj::Set(_) => 's',
            _ => '[',
        });
    }
    let value = match &objs[id] {
        Obj::None => Value::None,
        Obj::Bool(b) => Value::Bool(*b),
        Obj::Int(i) => Value::Int(i.clone()),
        Obj::Float(f) => Value::Float(*f),
        Obj::Str(s) => Value::Str(s.clone()),
        Obj::Bytes(b) => Value::Bytes(b.clone()),
        Obj::Date(d) => Value::Date(*d),
        Obj::DateTime(d) => Value::DateTime(*d),
        Obj::List(items) | Obj::Tuple(items) | Obj::Set(items) => {
            stack.push(id);
            let out: Vec<Value> = items
                .iter()
                .map(|c| export_obj(objs, *c, done, stack))
                .collect();
            stack.pop();
            match objs[id] {
                Obj::Tuple(_) => Value::Tuple(Arc::new(out)),
                Obj::Set(_) => Value::Set(Arc::new(out)),
                _ => Value::List(Arc::new(out)),
            }
        }
        Obj::Dict(items) => {
            stack.push(id);
            let out: Vec<(Value, Value)> = items
                .iter()
                .map(|(k, v)| {
                    (
                        export_obj(objs, *k, done, stack),
                        export_obj(objs, *v, done, stack),
                    )
                })
                .collect();
            stack.pop();
            Value::Dict(Arc::new(out))
        }
    };
    // A container that holds a `Recursive` marker is only right where it was
    // cut; share only the ones that do not.
    if !contains_recursive(&value) {
        done[id] = Some(value.clone());
    }
    value
}

fn contains_recursive(v: &Value) -> bool {
    match v {
        Value::Recursive(_) => true,
        Value::List(items) | Value::Tuple(items) | Value::Set(items) => {
            items.iter().any(contains_recursive)
        }
        Value::Dict(items) => items
            .iter()
            .any(|(k, v)| contains_recursive(k) || contains_recursive(v)),
        _ => false,
    }
}

/// A pydantic serialization failure (`PydanticSerializationError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError(pub String);

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Value {
    /// A `str`.
    pub fn str(s: impl Into<String>) -> Self {
        Value::Str(s.into())
    }

    /// `type(v).__name__`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::None => "NoneType",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::Bytes(_) => "bytes",
            Value::Date(_) => "date",
            Value::DateTime(_) => "datetime",
            Value::List(_) => "list",
            Value::Tuple(_) => "tuple",
            Value::Dict(_) => "dict",
            Value::Set(_) => "set",
            Value::Recursive('(') => "tuple",
            Value::Recursive('{') => "dict",
            Value::Recursive('s') => "set",
            Value::Recursive(_) => "list",
        }
    }

    /// The `str`, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The items of a `dict`.
    pub fn as_dict(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Dict(items) => Some(items),
            _ => None,
        }
    }

    /// The items of a `list`.
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(items) => Some(items),
            _ => None,
        }
    }

    /// `isinstance(v, dict)`.
    pub fn is_dict(&self) -> bool {
        matches!(self, Value::Dict(_) | Value::Recursive('{'))
    }

    /// `isinstance(v, list)`.
    pub fn is_list(&self) -> bool {
        matches!(self, Value::List(_) | Value::Recursive('['))
    }

    /// `dict.get(key)` for a `str` key (only a `str` key equals one).
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(items) => items
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// `key in dict` for a `str` key.
    pub fn has_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Value::None => false,
            Value::Bool(b) => *b,
            Value::Int(i) => !i.is_zero(),
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Bytes(b) => !b.is_empty(),
            Value::Date(_) | Value::DateTime(_) => true,
            Value::List(items) | Value::Tuple(items) | Value::Set(items) => !items.is_empty(),
            Value::Dict(items) => !items.is_empty(),
            Value::Recursive(_) => true,
        }
    }

    /// Python's `==`.
    pub fn py_eq(&self, other: &Value) -> bool {
        let num = |v: &Value| match v {
            Value::Bool(b) => Some((Some(BigInt::from(u8::from(*b))), 0.0)),
            Value::Int(i) => Some((Some(i.clone()), 0.0)),
            Value::Float(f) => Some((None, *f)),
            _ => None,
        };
        if let (Some(a), Some(b)) = (num(self), num(other)) {
            return match (a, b) {
                ((Some(i), _), (Some(j), _)) => i == j,
                ((Some(i), _), (None, f)) | ((None, f), (Some(i), _)) => int_float_eq(&i, f),
                ((None, f), (None, g)) => f == g,
            };
        }
        match (self, other) {
            (Value::None, Value::None) => true,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::Date(a), Value::Date(b)) => a == b,
            (Value::DateTime(a), Value::DateTime(b)) => a.py_eq(b),
            (Value::List(a), Value::List(b))
            | (Value::Tuple(a), Value::Tuple(b))
            | (Value::Set(a), Value::Set(b)) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.py_eq(y))
            }
            (Value::Dict(a), Value::Dict(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .all(|(k, v)| b.iter().any(|(k2, v2)| k.py_eq(k2) && v.py_eq(v2)))
            }
            _ => false,
        }
    }

    /// `repr(v)`.
    pub fn py_repr(&self) -> String {
        match self {
            Value::None => "None".into(),
            Value::Bool(true) => "True".into(),
            Value::Bool(false) => "False".into(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => float_repr(*f),
            Value::Str(s) => str_repr(s),
            Value::Bytes(b) => bytes_repr(b),
            Value::Date(d) => format!("datetime.date({}, {}, {})", d.year, d.month, d.day),
            Value::DateTime(d) => d.repr(),
            Value::List(items) => {
                let inner: Vec<String> = items.iter().map(Value::py_repr).collect();
                format!("[{}]", inner.join(", "))
            }
            Value::Tuple(items) => {
                let inner: Vec<String> = items.iter().map(Value::py_repr).collect();
                if inner.len() == 1 {
                    format!("({},)", inner[0])
                } else {
                    format!("({})", inner.join(", "))
                }
            }
            Value::Set(items) => {
                if items.is_empty() {
                    "set()".into()
                } else {
                    let inner: Vec<String> = items.iter().map(Value::py_repr).collect();
                    format!("{{{}}}", inner.join(", "))
                }
            }
            Value::Dict(items) => {
                let inner: Vec<String> = items
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k.py_repr(), v.py_repr()))
                    .collect();
                format!("{{{}}}", inner.join(", "))
            }
            Value::Recursive('(') => "(...)".into(),
            Value::Recursive('{') => "{...}".into(),
            Value::Recursive('s') => "set(...)".into(),
            Value::Recursive(_) => "[...]".into(),
        }
    }

    /// `str(v)` (what an f-string prints).
    pub fn py_str(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Date(d) => d.isoformat(),
            Value::DateTime(d) => d.py_str(),
            other => other.py_repr(),
        }
    }

    /// `TypeAdapter(Any).dump_json(v)`: how FastAPI writes a `dict`/`Any`
    /// field holding this value.
    pub fn to_pydantic_json(&self) -> Result<String, JsonError> {
        let mut out = String::new();
        write_json(self, &mut out)?;
        Ok(out)
    }

    /// The integer as an `i64`, if it is one that fits.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => i.to_i64(),
            _ => None,
        }
    }
}

fn json_string(s: &str, out: &mut String) {
    out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()));
}

fn json_float(f: f64, out: &mut String) {
    if f.is_finite() {
        out.push_str(&serde_json::to_string(&f).unwrap_or_else(|_| "null".into()));
    } else {
        out.push_str("null");
    }
}

fn utf8(b: &[u8]) -> Result<&str, JsonError> {
    std::str::from_utf8(b).map_err(|e| JsonError(format!("Error serializing to JSON: {e}")))
}

fn circular() -> JsonError {
    JsonError(
        "Error serializing to JSON: ValueError: Circular reference detected (id repeated)".into(),
    )
}

/// A dict key as pydantic-core's `infer` writes it.
fn json_key(k: &Value) -> Result<String, JsonError> {
    Ok(match k {
        Value::Str(s) => s.clone(),
        Value::None => "None".into(),
        Value::Bool(true) => "true".into(),
        Value::Bool(false) => "false".into(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) if f.is_finite() => float_repr(*f),
        Value::Float(_) => "None".into(),
        Value::Bytes(b) => utf8(b)?.to_string(),
        Value::Date(d) => d.isoformat(),
        Value::DateTime(d) => d.pydantic(),
        Value::Tuple(items) => {
            let parts: Result<Vec<String>, JsonError> = items.iter().map(json_key).collect();
            parts?.join(",")
        }
        other => other.py_repr(),
    })
}

fn write_json(v: &Value, out: &mut String) -> Result<(), JsonError> {
    match v {
        Value::None => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Float(f) => json_float(*f, out),
        Value::Str(s) => json_string(s, out),
        Value::Bytes(b) => json_string(utf8(b)?, out),
        Value::Date(d) => json_string(&d.isoformat(), out),
        Value::DateTime(d) => json_string(&d.pydantic(), out),
        Value::List(items) | Value::Tuple(items) | Value::Set(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out)?;
            }
            out.push(']');
        }
        Value::Dict(items) => {
            out.push('{');
            for (i, (k, val)) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_string(&json_key(k)?, out);
                out.push(':');
                write_json(val, out)?;
            }
            out.push('}');
        }
        Value::Recursive(_) => return Err(circular()),
    }
    Ok(())
}
