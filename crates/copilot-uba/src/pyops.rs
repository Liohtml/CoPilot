//! The Python operations provisioning and rollback apply to Graylog's and
//! UBA's JSON — `in`, `str.startswith`, `", ".join`, `sorted`, `x or {}` —
//! raising what CPython raises on a value of another type.
//!
//! Graylog objects are kept in insertion-ordered maps keyed by their `id`
//! (or `title`), as Python's dict comprehensions keep them: a later object
//! with the same key replaces the earlier one's value in the earlier one's
//! place. Graylog's ids and titles are strings; a key that is not one
//! cannot be looked up by the strings these modules look for, and an id
//! that is not one is refused as an unsupported answer (see the module
//! notes of [`crate::rollback`]).

use std::collections::HashMap;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::{self, PyExc, PyResult, py_eq, type_name};

/// An insertion-ordered `dict` with `str` keys.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderedMap<V> {
    order: Vec<String>,
    map: HashMap<String, V>,
}

impl<V> Default for OrderedMap<V> {
    fn default() -> Self {
        Self {
            order: Vec::new(),
            map: HashMap::new(),
        }
    }
}

impl<V> OrderedMap<V> {
    /// `d[key] = value`.
    pub fn insert(&mut self, key: String, value: V) {
        if !self.map.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.map.insert(key, value);
    }

    /// `d.get(key)`.
    pub fn get(&self, key: &str) -> Option<&V> {
        self.map.get(key)
    }

    /// `d.get(key)` with a key of any type (only a `str` can match).
    pub fn get_py(&self, key: &PyValue) -> Option<&V> {
        match key {
            PyValue::Str(s) => self.map.get(s),
            _ => None,
        }
    }

    /// Mutable `d[key]`.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    /// `key in d`.
    pub fn contains(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// `d.items()`.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.order
            .iter()
            .filter_map(|k| self.map.get(k).map(|v| (k, v)))
    }

    /// `d.keys()`.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.order.iter()
    }

    /// `d.values()`.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.order.iter().filter_map(|k| self.map.get(k))
    }

    /// `len(d)`.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// `not d`.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// An answer this port does not reproduce (Graylog or UBA sent a value of a
/// type they never send): a bare 500, as the Python operations on it mostly
/// end in.
pub fn unsupported(what: &str, value: &PyValue) -> PyExc {
    PyExc::Other(
        "NotImplementedError",
        format!("{what} is a {}, not a str", type_name(value)),
    )
}

/// `hash(value)`: `TypeError` for a list or a dict.
pub fn hashable(value: &PyValue) -> PyResult<()> {
    match value {
        PyValue::List(_) | PyValue::Dict(_) => Err(PyExc::TypeError(format!(
            "unhashable type: '{}'",
            type_name(value)
        ))),
        _ => Ok(()),
    }
}

/// A dict key that must be a `str` to be looked up: `TypeError` when it is
/// unhashable, `None` when it is another hashable value.
pub fn str_key(value: &PyValue) -> PyResult<Option<&str>> {
    hashable(value)?;
    Ok(value.as_str())
}

/// `x or {}` / `x or []`: the value when truthy.
pub fn or_else(value: Option<&PyValue>, empty: PyValue) -> PyValue {
    match value {
        Some(v) if v.truthy() => v.clone(),
        _ => empty,
    }
}

/// `{}`.
pub fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

/// `[]`.
pub fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

/// `d.get(key)` (`AttributeError` on anything but a dict).
pub fn get<'a>(value: &'a PyValue, key: &str) -> PyResult<Option<&'a PyValue>> {
    py::get(value, key)
}

/// `d.get(key, default)`.
pub fn get_or(value: &PyValue, key: &str, default: PyValue) -> PyResult<PyValue> {
    Ok(py::get(value, key)?.cloned().unwrap_or(default))
}

/// `value.startswith(prefix)`.
pub fn startswith(value: &PyValue, prefix: &str) -> PyResult<bool> {
    match value {
        PyValue::Str(s) => Ok(s.starts_with(prefix)),
        other => Err(attribute(other, "startswith")),
    }
}

/// `AttributeError: '<type>' object has no attribute '<name>'`.
pub fn attribute(value: &PyValue, name: &str) -> PyExc {
    PyExc::AttributeError(format!(
        "'{}' object has no attribute '{name}'",
        type_name(value)
    ))
}

/// `sep.join(items)`.
pub fn join(sep: &str, items: &[PyValue]) -> PyResult<String> {
    let mut parts = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        match item {
            PyValue::Str(s) => parts.push(s.as_str()),
            other => {
                return Err(PyExc::TypeError(format!(
                    "sequence item {i}: expected str instance, {} found",
                    type_name(other)
                )));
            }
        }
    }
    Ok(parts.join(sep))
}

/// `needle in haystack`.
pub fn contains(haystack: &PyValue, needle: &PyValue) -> PyResult<bool> {
    match haystack {
        PyValue::List(items) => Ok(items.iter().any(|i| py_eq(i, needle))),
        PyValue::Dict(items) => {
            hashable(needle)?;
            Ok(items
                .iter()
                .any(|(k, _)| py_eq(&PyValue::Str(k.clone()), needle)))
        }
        PyValue::Str(s) => match needle {
            PyValue::Str(n) => Ok(s.contains(n.as_str())),
            other => Err(PyExc::TypeError(format!(
                "'in <string>' requires string as left operand, not {}",
                type_name(other)
            ))),
        },
        other => Err(PyExc::TypeError(format!(
            "argument of type '{}' is not iterable",
            type_name(other)
        ))),
    }
}

fn number(value: &PyValue) -> Option<f64> {
    match value {
        PyValue::Bool(b) => Some(f64::from(u8::from(*b))),
        PyValue::Int(i) => i.parse().ok(),
        PyValue::Float(f) => Some(*f),
        _ => None,
    }
}

fn type_of_order(value: &PyValue) -> &'static str {
    match value {
        PyValue::Str(_) => "str",
        PyValue::Bool(_) | PyValue::Int(_) | PyValue::Float(_) => "number",
        other => type_name(other),
    }
}

/// `sorted(items)` of strings or of numbers; `TypeError` when two items
/// cannot be compared (a single item is never compared).
pub fn sorted(mut items: Vec<PyValue>) -> PyResult<Vec<PyValue>> {
    if items.len() < 2 {
        return Ok(items);
    }
    let first = type_of_order(&items[0]);
    for item in &items[1..] {
        let kind = type_of_order(item);
        if kind != first || !matches!(kind, "str" | "number") {
            return Err(PyExc::TypeError(format!(
                "'<' not supported between instances of '{}' and '{}'",
                type_name(item),
                type_name(&items[0])
            )));
        }
    }
    if first == "str" {
        items.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    } else {
        items.sort_by(|a, b| {
            number(a)
                .partial_cmp(&number(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    Ok(items)
}

/// `list(a) == list(b)`.
pub fn list_eq(a: &[PyValue], b: &[PyValue]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| py_eq(x, y))
}

/// `str.strip()` (Python's whitespace).
pub fn strip(s: &str) -> &str {
    copilot_web::form::py_strip(s)
}

/// `str(value)`.
pub fn text(value: &PyValue) -> String {
    value.py_str()
}

/// `template.format(**kwargs)` on a value that should be a `str`.
pub fn format(template: &PyValue, kwargs: &[(&str, &str)]) -> PyResult<String> {
    match template {
        PyValue::Str(t) => crate::pyfmt::format(t, kwargs),
        other => Err(attribute(other, "format")),
    }
}

/// `{k: v for …}` keyed by Python values: insertion order, a later equal key
/// replacing the value in place (`1 == 1.0 == True`).
#[derive(Debug, Clone, Default)]
pub struct PyDict(pub Vec<(PyValue, PyValue)>);

impl PyDict {
    /// `d[key] = value`.
    pub fn set(&mut self, key: PyValue, value: PyValue) -> PyResult<()> {
        hashable(&key)?;
        match self.0.iter_mut().find(|(k, _)| py_eq(k, &key)) {
            Some(slot) => slot.1 = value,
            None => self.0.push((key, value)),
        }
        Ok(())
    }

    /// `a == b`.
    pub fn same(&self, other: &PyDict) -> bool {
        self.0.len() == other.0.len()
            && self.0.iter().all(|(k, v)| {
                other
                    .0
                    .iter()
                    .find(|(k2, _)| py_eq(k, k2))
                    .is_some_and(|(_, v2)| py_eq(v, v2))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> PyValue {
        PyValue::Str(v.into())
    }

    #[test]
    fn membership_and_errors_like_cpython() {
        let list = PyValue::List(vec![s("a"), PyValue::Int("1".into())]);
        assert!(contains(&list, &PyValue::Bool(true)).expect("in"));
        assert!(contains(&s("abc"), &s("b")).expect("in"));
        assert_eq!(
            contains(&s("abc"), &PyValue::Int("1".into()))
                .expect_err("str")
                .text(),
            "'in <string>' requires string as left operand, not int"
        );
        assert_eq!(
            contains(&PyValue::None, &s("a")).expect_err("none").text(),
            "argument of type 'NoneType' is not iterable"
        );
        assert_eq!(
            join(", ", &[s("a"), PyValue::Int("2".into())])
                .expect_err("join")
                .text(),
            "sequence item 1: expected str instance, int found"
        );
        assert_eq!(
            startswith(&PyValue::None, "x").expect_err("none").text(),
            "'NoneType' object has no attribute 'startswith'"
        );
    }

    #[test]
    fn sorting_like_cpython() {
        let got = sorted(vec![s("b"), s("a"), s("é"), s("Z")]).expect("sorted");
        assert_eq!(got, vec![s("Z"), s("a"), s("b"), s("é")]);
        assert!(sorted(vec![s("a"), PyValue::Int("1".into())]).is_err());
        assert_eq!(
            sorted(vec![PyValue::None]).expect("one"),
            vec![PyValue::None]
        );
    }

    #[test]
    fn dicts_replace_equal_keys_in_place() {
        let mut d = PyDict::default();
        d.set(PyValue::Int("1".into()), s("a")).expect("set");
        d.set(s("x"), s("b")).expect("set");
        d.set(PyValue::Bool(true), s("c")).expect("set");
        assert_eq!(d.0.len(), 2);
        assert_eq!(d.0[0].1, s("c"));
        assert!(d.set(PyValue::List(vec![]), s("x")).is_err());
    }
}
