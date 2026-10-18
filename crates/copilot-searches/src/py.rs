//! The Python operations the services perform on a rule — a `yaml.safe_load`
//! value — with the exceptions CPython raises when the value is not what the
//! code assumed (`.get` on a list, `.lower()` on an int, iterating an int, an
//! unhashable dict key), so a malformed rule fails where and as Python's does.
//!
//! JSON from an upstream stays a [`PyValue`] (`copilot_upstream::py` has its
//! operations); [`from_py`] turns it into a [`Value`] where it meets a rule.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_yaml::Value;
use num_bigint_dig::BigInt;
use num_traits::{ToPrimitive, Zero};

/// `type(v).__name__` as CPython's own messages print it (`tp_name`): the
/// `datetime` types carry their module.
pub fn tp_name(v: &Value) -> &'static str {
    match v {
        Value::Date(_) => "datetime.date",
        Value::DateTime(_) => "datetime.datetime",
        other => other.type_name(),
    }
}

/// `AttributeError: '<type>' object has no attribute '<attr>'`.
pub fn no_attr(v: &Value, attr: &str) -> PyExc {
    PyExc::AttributeError(format!("'{}' object has no attribute '{attr}'", tp_name(v)))
}

/// A `str`.
pub fn s(text: impl Into<String>) -> Value {
    Value::Str(text.into())
}

/// An `int`.
pub fn int(n: i64) -> Value {
    Value::Int(BigInt::from(n))
}

/// A `list`.
pub fn list(items: Vec<Value>) -> Value {
    Value::List(Arc::new(items))
}

/// A `dict` with `str` keys, in this order.
pub fn dict(items: Vec<(&str, Value)>) -> Value {
    Value::Dict(Arc::new(
        items.into_iter().map(|(k, v)| (s(k), v)).collect(),
    ))
}

/// A list of `str`s.
pub fn str_list<I, T>(items: I) -> Value
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    list(items.into_iter().map(|t| s(t)).collect())
}

/// `None` or the `str`.
pub fn opt_str(v: Option<impl Into<String>>) -> Value {
    v.map_or(Value::None, |t| s(t))
}

/// `value.get(key, default)` (`AttributeError` on anything but a dict).
pub fn get(v: &Value, key: &str, default: Value) -> PyResult<Value> {
    match v {
        Value::Dict(items) => Ok(items
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map_or(default, |(_, v)| v.clone())),
        Value::Recursive('{') => Ok(default),
        other => Err(no_attr(other, "get")),
    }
}

/// `value.get(key)`.
pub fn get_none(v: &Value, key: &str) -> PyResult<Value> {
    get(v, key, Value::None)
}

/// `value[key]` with a `str` key.
pub fn getitem(v: &Value, key: &str) -> PyResult<Value> {
    match v {
        Value::Dict(items) => items
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v.clone())
            .ok_or_else(|| PyExc::key_error(key)),
        Value::List(_) | Value::Recursive('[') => Err(PyExc::TypeError(
            "list indices must be integers or slices, not str".into(),
        )),
        Value::Tuple(_) | Value::Recursive('(') => Err(PyExc::TypeError(
            "tuple indices must be integers or slices, not str".into(),
        )),
        Value::Str(_) => Err(PyExc::TypeError(
            "string indices must be integers, not 'str'".into(),
        )),
        Value::Bytes(_) => Err(PyExc::TypeError(
            "byte indices must be integers or slices, not str".into(),
        )),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            tp_name(other)
        ))),
    }
}

/// `key in value` for a `str` key.
pub fn contains_key(v: &Value, key: &str) -> PyResult<bool> {
    match v {
        Value::Dict(items) => Ok(items.iter().any(|(k, _)| k.as_str() == Some(key))),
        Value::List(items) | Value::Tuple(items) | Value::Set(items) => {
            Ok(items.iter().any(|i| i.as_str() == Some(key)))
        }
        Value::Str(text) => Ok(text.contains(key)),
        Value::Bytes(_) => Err(PyExc::TypeError(
            "a bytes-like object is required, not 'str'".into(),
        )),
        Value::Recursive(_) => Ok(false),
        other => Err(PyExc::TypeError(format!(
            "argument of type '{}' is not iterable",
            tp_name(other)
        ))),
    }
}

/// `value[key] = item` on a dict (an existing key keeps its place).
pub fn dict_set(items: &mut Vec<(Value, Value)>, key: &str, item: Value) {
    match items.iter_mut().find(|(k, _)| k.as_str() == Some(key)) {
        Some(slot) => slot.1 = item,
        None => items.push((s(key), item)),
    }
}

/// `value.lower()`.
pub fn lower(v: &Value) -> PyResult<String> {
    match v {
        Value::Str(t) => Ok(copilot_jinja::unicode::lower(t)),
        other => Err(no_attr(other, "lower")),
    }
}

/// `value.upper()`.
pub fn upper(v: &Value) -> PyResult<String> {
    match v {
        Value::Str(t) => Ok(copilot_jinja::unicode::upper(t)),
        other => Err(no_attr(other, "upper")),
    }
}

/// `value.strip()` (Python's whitespace).
pub fn strip(v: &Value) -> PyResult<String> {
    match v {
        Value::Str(t) => Ok(py_strip(t).to_string()),
        other => Err(no_attr(other, "strip")),
    }
}

/// `str.strip()`.
pub fn py_strip(t: &str) -> &str {
    t.trim_matches(copilot_jinja::unicode::is_space)
}

/// `str.lower()`.
pub fn py_lower(t: &str) -> String {
    copilot_jinja::unicode::lower(t)
}

/// `str.upper()`.
pub fn py_upper(t: &str) -> String {
    copilot_jinja::unicode::upper(t)
}

/// `str.split()` (runs of Python whitespace).
pub fn py_split_ws(t: &str) -> Vec<&str> {
    t.split(copilot_jinja::unicode::is_space)
        .filter(|p| !p.is_empty())
        .collect()
}

/// `str(value)`.
pub fn py_str(v: &Value) -> String {
    v.py_str()
}

/// `for x in value`: a list's, tuple's or set's items, a dict's keys, a
/// string's characters, a bytes object's ints; `TypeError` for the rest.
pub fn iterate(v: &Value) -> PyResult<Vec<Value>> {
    match v {
        Value::List(items) | Value::Tuple(items) | Value::Set(items) => Ok(items.to_vec()),
        Value::Dict(items) => Ok(items.iter().map(|(k, _)| k.clone()).collect()),
        Value::Str(t) => Ok(t.chars().map(|c| s(c.to_string())).collect()),
        Value::Bytes(b) => Ok(b.iter().map(|x| int(i64::from(*x))).collect()),
        Value::Recursive(_) => Ok(Vec::new()),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not iterable",
            tp_name(other)
        ))),
    }
}

/// `value.items()`.
pub fn items(v: &Value) -> PyResult<Vec<(Value, Value)>> {
    match v {
        Value::Dict(items) => Ok(items.to_vec()),
        Value::Recursive('{') => Ok(Vec::new()),
        other => Err(no_attr(other, "items")),
    }
}

/// `len(value)`.
pub fn len(v: &Value) -> PyResult<usize> {
    match v {
        Value::List(items) | Value::Tuple(items) | Value::Set(items) => Ok(items.len()),
        Value::Dict(items) => Ok(items.len()),
        Value::Str(t) => Ok(t.chars().count()),
        Value::Bytes(b) => Ok(b.len()),
        other => Err(PyExc::TypeError(format!(
            "object of type '{}' has no len()",
            tp_name(other)
        ))),
    }
}

/// `sep.join(items)`.
pub fn join(sep: &str, items: &[Value]) -> PyResult<String> {
    let mut parts = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        match item {
            Value::Str(t) => parts.push(t.as_str()),
            other => {
                return Err(PyExc::TypeError(format!(
                    "sequence item {i}: expected str instance, {} found",
                    tp_name(other)
                )));
            }
        }
    }
    Ok(parts.join(sep))
}

/// `isinstance(value, int)` (a `bool` is one).
pub fn is_int(v: &Value) -> bool {
    matches!(v, Value::Int(_) | Value::Bool(_))
}

/// An `int` (or `bool`) as a big integer.
pub fn as_bigint(v: &Value) -> Option<BigInt> {
    match v {
        Value::Int(i) => Some(i.clone()),
        Value::Bool(b) => Some(BigInt::from(u8::from(*b))),
        _ => None,
    }
}

/// `int` arithmetic for the counters (`count += …`).
pub fn bigint_value(n: &BigInt) -> Value {
    Value::Int(n.clone())
}

/// `x < y` between two values Python orders (numbers, `str`s); `TypeError`
/// otherwise.
pub fn lt(a: &Value, b: &Value) -> PyResult<bool> {
    if let (Some(x), Some(y)) = (num(a), num(b)) {
        return Ok(num_lt(&x, &y));
    }
    match (a, b) {
        (Value::Str(x), Value::Str(y)) => Ok(x < y),
        (Value::Bytes(x), Value::Bytes(y)) => Ok(x < y),
        (Value::Date(x), Value::Date(y)) => Ok((x.year, x.month, x.day) < (y.year, y.month, y.day)),
        _ => Err(PyExc::TypeError(format!(
            "'<' not supported between instances of '{}' and '{}'",
            a.type_name(),
            b.type_name()
        ))),
    }
}

#[derive(Debug, Clone)]
enum Num {
    Int(BigInt),
    Float(f64),
}

fn num(v: &Value) -> Option<Num> {
    match v {
        Value::Int(i) => Some(Num::Int(i.clone())),
        Value::Bool(b) => Some(Num::Int(BigInt::from(u8::from(*b)))),
        Value::Float(f) => Some(Num::Float(*f)),
        _ => None,
    }
}

fn num_lt(a: &Num, b: &Num) -> bool {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => x < y,
        (Num::Float(x), Num::Float(y)) => x < y,
        (Num::Int(x), Num::Float(y)) => int_float_cmp(x, *y) == Some(std::cmp::Ordering::Less),
        (Num::Float(x), Num::Int(y)) => int_float_cmp(y, *x) == Some(std::cmp::Ordering::Greater),
    }
}

/// `int <=> float` exactly (`None` for NaN).
fn int_float_cmp(i: &BigInt, f: f64) -> Option<std::cmp::Ordering> {
    if f.is_nan() {
        return None;
    }
    if f.is_infinite() {
        return Some(if f > 0.0 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        });
    }
    let floor = f.floor();
    let fi = copilot_yaml::pyint::float_to_bigint(floor)?;
    match i.cmp(&fi) {
        std::cmp::Ordering::Equal if f > floor => Some(std::cmp::Ordering::Less),
        other => Some(other),
    }
}

/// A canonical text for a hashable value: two values Python's `dict` holds
/// under one key give the same text. `TypeError` for an unhashable one.
pub fn hash_key(v: &Value) -> PyResult<String> {
    static NAN: AtomicU64 = AtomicU64::new(0);
    Ok(match v {
        Value::None => "N".into(),
        Value::Bool(b) => format!("i{}", u8::from(*b)),
        Value::Int(i) => format!("i{i}"),
        Value::Float(f) if f.is_nan() => format!("n{}", NAN.fetch_add(1, Ordering::Relaxed)),
        Value::Float(f) if f.is_finite() && f.fract() == 0.0 => {
            match copilot_yaml::pyint::float_to_bigint(*f) {
                Some(i) => format!("i{i}"),
                None => format!("f{}", f.to_bits()),
            }
        }
        Value::Float(f) => format!("f{}", f.to_bits()),
        Value::Str(t) => format!("s{t}"),
        Value::Bytes(b) => format!("b{}", hex_of(b)),
        Value::Date(d) => format!("d{}", d.isoformat()),
        Value::DateTime(d) if d.offset.is_some() => {
            let off = d.offset.unwrap_or(0);
            let naive = Value::DateTime(copilot_yaml::DateTime { offset: None, ..*d });
            format!("z{}:{off}", naive.py_str())
        }
        Value::DateTime(d) => format!("t{}", d.isoformat()),
        Value::Tuple(items) => {
            let parts: PyResult<Vec<String>> = items.iter().map(hash_key).collect();
            format!("({})", parts?.join("\u{0}"))
        }
        other => {
            return Err(PyExc::TypeError(format!(
                "unhashable type: '{}'",
                other.type_name()
            )));
        }
    })
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A `json.loads` value as a rule-side value.
pub fn from_py(v: &PyValue) -> Value {
    match v {
        PyValue::None => Value::None,
        PyValue::Bool(b) => Value::Bool(*b),
        PyValue::Int(t) => Value::Int(t.parse::<BigInt>().unwrap_or_else(|_| BigInt::zero())),
        PyValue::Float(f) => Value::Float(*f),
        PyValue::Str(t) => Value::Str(t.clone()),
        PyValue::List(items) => list(items.iter().map(from_py).collect()),
        PyValue::Dict(items) => Value::Dict(Arc::new(
            items
                .iter()
                .map(|(k, v)| (s(k.clone()), from_py(v)))
                .collect(),
        )),
    }
}

/// A `serde_json` value as a rule-side value.
pub fn from_json(v: &serde_json::Value) -> Value {
    from_py(&copilot_upstream::respond::from_json(v))
}

/// A rule-side value as JSON for an upstream body (`json.dumps`), where it
/// can be one: `None` for what JSON cannot hold.
pub fn to_py(v: &Value) -> Option<PyValue> {
    Some(match v {
        Value::None => PyValue::None,
        Value::Bool(b) => PyValue::Bool(*b),
        Value::Int(i) => PyValue::Int(i.to_string()),
        Value::Float(f) => PyValue::Float(*f),
        Value::Str(t) => PyValue::Str(t.clone()),
        Value::List(items) | Value::Tuple(items) => {
            PyValue::List(items.iter().map(to_py).collect::<Option<Vec<_>>>()?)
        }
        Value::Dict(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (k, v) in items.iter() {
                let key = match k {
                    Value::Str(t) => t.clone(),
                    _ => return None,
                };
                out.push((key, to_py(v)?));
            }
            PyValue::Dict(out)
        }
        _ => return None,
    })
}

/// `int(value)` for the values the services convert (`int(bucket.get(…) or
/// 0)`): CPython's `ValueError` / `TypeError` / `OverflowError`.
pub fn py_int(v: &Value) -> PyResult<BigInt> {
    match v {
        Value::Int(i) => Ok(i.clone()),
        Value::Bool(b) => Ok(BigInt::from(u8::from(*b))),
        Value::Float(f) if f.is_nan() => Err(PyExc::ValueError(
            "cannot convert float NaN to integer".into(),
        )),
        Value::Float(f) if f.is_infinite() => Err(PyExc::Other(
            "OverflowError",
            "cannot convert float infinity to integer".into(),
        )),
        Value::Float(f) => Ok(copilot_yaml::pyint::float_to_bigint(f.trunc()).unwrap_or_default()),
        Value::Str(t) => copilot_yaml::pyint::parse_int(t, 10).map_err(|e| {
            if e.is_value_error() {
                PyExc::ValueError(e.message)
            } else {
                PyExc::Other(e.class, e.message)
            }
        }),
        other => Err(PyExc::TypeError(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            tp_name(other)
        ))),
    }
}

/// `float(value)`.
pub fn py_float(v: &Value) -> PyResult<f64> {
    match v {
        Value::Float(f) => Ok(*f),
        Value::Int(i) => i.to_f64().ok_or_else(|| {
            PyExc::Other("OverflowError", "int too large to convert to float".into())
        }),
        Value::Bool(b) => Ok(f64::from(u8::from(*b))),
        Value::Str(t) => {
            copilot_yaml::pyint::parse_float(t).map_err(|e| PyExc::ValueError(e.message))
        }
        other => Err(PyExc::TypeError(format!(
            "float() argument must be a string or a real number, not '{}'",
            tp_name(other)
        ))),
    }
}

/// `round(x, ndigits)` for a float: the correctly rounded decimal
/// (half-even on the exact binary value), as CPython's `float.__round__`.
pub fn py_round(x: f64, ndigits: usize) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let text = format!("{x:.ndigits$}");
    text.parse::<f64>().unwrap_or(x)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn rounding_follows_cpython() {
        // round(0.125, 2) == 0.12, round(2.675, 2) == 2.67, round(1.005, 2) == 1.0
        assert_eq!(py_round(0.125, 2), 0.12);
        assert_eq!(py_round(2.675, 2), 2.67);
        assert_eq!(py_round(1.005, 2), 1.0);
        assert_eq!(py_round(0.375, 2), 0.38);
        assert_eq!(py_round(33.33333, 1), 33.3);
        assert_eq!(py_round(12.25, 1), 12.2);
    }

    #[test]
    fn keys_follow_python_equality() {
        let one = hash_key(&Value::Int(BigInt::from(1))).unwrap();
        assert_eq!(one, hash_key(&Value::Bool(true)).unwrap());
        assert_eq!(one, hash_key(&Value::Float(1.0)).unwrap());
        assert_ne!(one, hash_key(&s("1")).unwrap());
        assert!(hash_key(&list(vec![])).is_err());
    }

    #[test]
    fn messages_follow_cpython() {
        assert_eq!(
            get(&list(vec![]), "a", Value::None).unwrap_err().text(),
            "'list' object has no attribute 'get'"
        );
        assert_eq!(
            lower(&int(3)).unwrap_err().text(),
            "'int' object has no attribute 'lower'"
        );
        assert_eq!(
            join(" ", &[s("a"), int(1)]).unwrap_err().text(),
            "sequence item 1: expected str instance, int found"
        );
    }
}
