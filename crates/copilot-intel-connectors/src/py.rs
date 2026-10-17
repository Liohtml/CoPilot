//! The few Python expressions the two connectors' services are built from,
//! over `json.loads` values ([`PyValue`]), raising what CPython raises.
//!
//! Only a `ValueError` (a `pydantic.ValidationError` among them) and an
//! `HTTPException` reach the caller with their text; any other exception
//! these raise is uvicorn's bare 500, so its text only matters where a
//! service puts it into an answer (`f"…: {e}"`).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::{PyExc, PyResult, type_name};

/// `value.get(key)` on a dict (`None` when absent); `AttributeError` on
/// anything else.
pub fn get(value: &PyValue, key: &str) -> PyResult<PyValue> {
    Ok(copilot_upstream::py::get(value, key)?
        .cloned()
        .unwrap_or(PyValue::None))
}

/// `value.get(key, default)`.
pub fn get_or(value: &PyValue, key: &str, default: PyValue) -> PyResult<PyValue> {
    Ok(copilot_upstream::py::get(value, key)?
        .cloned()
        .unwrap_or(default))
}

/// `value or {}`.
pub fn or_dict(value: PyValue) -> PyValue {
    if value.truthy() {
        value
    } else {
        PyValue::Dict(Vec::new())
    }
}

/// `value or []`.
pub fn or_list(value: PyValue) -> PyValue {
    if value.truthy() {
        value
    } else {
        PyValue::List(Vec::new())
    }
}

/// `value or fallback`.
pub fn or(value: PyValue, fallback: PyValue) -> PyValue {
    if value.truthy() { value } else { fallback }
}

/// `str.strip()`.
pub fn strip(s: &str) -> &str {
    copilot_web::form::py_strip(s)
}

/// `str.lower()`.
pub fn lower(s: &str) -> String {
    copilot_jinja::unicode::lower(s)
}

/// `a > b` between two `json.loads` values; `TypeError` where CPython
/// refuses the comparison.
pub fn gt(a: &PyValue, b: &PyValue) -> PyResult<bool> {
    fn num(v: &PyValue) -> Option<f64> {
        match v {
            PyValue::Bool(b) => Some(f64::from(u8::from(*b))),
            PyValue::Int(i) => i.parse::<f64>().ok(),
            PyValue::Float(f) => Some(*f),
            _ => None,
        }
    }
    match (a, b) {
        (PyValue::Int(x), PyValue::Int(y)) => match (x.parse::<i128>(), y.parse::<i128>()) {
            (Ok(x), Ok(y)) => Ok(x > y),
            _ => Ok(num(a) > num(b)),
        },
        (PyValue::Str(x), PyValue::Str(y)) => Ok(x > y),
        _ => match (num(a), num(b)) {
            (Some(x), Some(y)) => Ok(x > y),
            _ => Err(PyExc::TypeError(format!(
                "'>' not supported between instances of '{}' and '{}'",
                type_name(a),
                type_name(b)
            ))),
        },
    }
}

/// `"; ".join(parts)` (a `TypeError` naming the first item that is not a
/// `str`).
pub fn join(sep: &str, parts: &[PyValue]) -> PyResult<String> {
    let mut out = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        match part {
            PyValue::Str(s) => out.push(s.as_str()),
            other => {
                return Err(PyExc::TypeError(format!(
                    "sequence item {i}: expected str instance, {} found",
                    type_name(other)
                )));
            }
        }
    }
    Ok(out.join(sep))
}

/// A dict from pairs.
pub fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// `d[key] = value`: an existing key keeps its place, a new one is appended.
pub fn set(d: &mut Vec<(String, PyValue)>, key: &str, value: PyValue) {
    match d.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => d.push((key.to_string(), value)),
    }
}

/// A `str` value.
pub fn s(text: impl Into<String>) -> PyValue {
    PyValue::Str(text.into())
}

/// An `int` value.
pub fn int(n: impl std::fmt::Display) -> PyValue {
    PyValue::Int(n.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparisons_and_joins_raise_like_cpython() {
        assert!(gt(&int(5), &int(3)).unwrap());
        assert!(gt(&PyValue::Float(2.5), &int(2)).unwrap());
        assert!(!gt(&PyValue::Bool(false), &int(0)).unwrap());
        assert_eq!(
            gt(&s("5"), &int(3)).unwrap_err().text(),
            "'>' not supported between instances of 'str' and 'int'"
        );
        assert_eq!(join("; ", &[s("a"), s("b")]).unwrap(), "a; b");
        assert_eq!(
            join("; ", &[s("a"), int(1)]).unwrap_err().text(),
            "sequence item 1: expected str instance, int found"
        );
        let mut d = vec![("a".to_string(), int(1)), ("b".to_string(), int(2))];
        set(&mut d, "a", int(3));
        set(&mut d, "c", int(4));
        assert_eq!(PyValue::Dict(d).py_repr(), "{'a': 3, 'b': 2, 'c': 4}");
    }
}
