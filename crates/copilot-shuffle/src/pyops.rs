//! The Python operations the Shuffle services apply to a JSON answer, with
//! the exceptions CPython 3.11 raises when the value is not what the code
//! expected (`"actions" in workflow`, `workflow["actions"]`, `for … in …`,
//! `action.pop("large_image", None)`, `executions[0]`).

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_upstream::py::{PyExc, type_name};

/// `needle in container` for a `str` needle.
pub fn contains(container: &PyValue, needle: &str) -> Result<bool, PyExc> {
    match container {
        PyValue::Dict(items) => Ok(items.iter().any(|(k, _)| k == needle)),
        PyValue::List(items) => Ok(items
            .iter()
            .any(|i| matches!(i, PyValue::Str(s) if s == needle))),
        PyValue::Str(s) => Ok(s.contains(needle)),
        other => Err(PyExc::TypeError(format!(
            "argument of type '{}' is not iterable",
            type_name(other)
        ))),
    }
}

/// `container[key]` for a `str` key.
pub fn item<'a>(container: &'a PyValue, key: &str) -> Result<&'a PyValue, PyExc> {
    match container {
        PyValue::Dict(items) => items
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .ok_or_else(|| PyExc::KeyError(str_repr(key))),
        PyValue::List(_) => Err(PyExc::TypeError(
            "list indices must be integers or slices, not str".into(),
        )),
        PyValue::Str(_) => Err(PyExc::TypeError(
            "string indices must be integers, not 'str'".into(),
        )),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        ))),
    }
}

/// `container[0]`.
pub fn first(container: &PyValue) -> Result<PyValue, PyExc> {
    match container {
        PyValue::List(items) => items
            .first()
            .cloned()
            .ok_or_else(|| PyExc::IndexError("list index out of range".into())),
        PyValue::Str(s) => s
            .chars()
            .next()
            .map(|c| PyValue::Str(c.to_string()))
            .ok_or_else(|| PyExc::IndexError("string index out of range".into())),
        // `dict[0]`: JSON keys are strings, so never there.
        PyValue::Dict(_) => Err(PyExc::KeyError("0".into())),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        ))),
    }
}

/// The items `for x in value` visits (a dict's keys, a string's characters).
pub fn iterate(value: &PyValue) -> Result<Vec<PyValue>, PyExc> {
    match value {
        PyValue::List(items) => Ok(items.clone()),
        PyValue::Dict(items) => Ok(items.iter().map(|(k, _)| PyValue::Str(k.clone())).collect()),
        PyValue::Str(s) => Ok(s.chars().map(|c| PyValue::Str(c.to_string())).collect()),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not iterable",
            type_name(other)
        ))),
    }
}

/// `value.pop(key, None)` on what should be a dict.
pub fn pop(value: &mut PyValue, key: &str) -> Result<(), PyExc> {
    match value {
        PyValue::Dict(items) => {
            items.retain(|(k, _)| k != key);
            Ok(())
        }
        PyValue::List(_) => Err(PyExc::TypeError(
            "pop expected at most 1 argument, got 2".into(),
        )),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'pop'",
            type_name(other)
        ))),
    }
}

/// `value.get(key, default)` on what should be a dict.
pub fn get(value: &PyValue, key: &str, default: PyValue) -> Result<PyValue, PyExc> {
    match value {
        PyValue::Dict(items) => Ok(items
            .iter()
            .find(|(k, _)| k == key)
            .map_or(default, |(_, v)| v.clone())),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'get'",
            type_name(other)
        ))),
    }
}

/// FastAPI's `jsonable_encoder` on a returned dict: `sqlalchemy_safe` drops
/// every key starting with `_sa`, at any depth.
pub fn jsonable(value: &PyValue) -> PyValue {
    match value {
        PyValue::Dict(items) => PyValue::Dict(
            items
                .iter()
                .filter(|(k, _)| !k.starts_with("_sa"))
                .map(|(k, v)| (k.clone(), jsonable(v)))
                .collect(),
        ),
        PyValue::List(items) => PyValue::List(items.iter().map(jsonable).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn operations_fail_like_cpython() {
        let s = |t: &str| loads(t).unwrap();
        assert!(contains(&s(r#"{"actions": 1}"#), "actions").unwrap());
        assert!(contains(&s(r#"["x", "actions"]"#), "actions").unwrap());
        assert!(contains(&s(r#""my-actions""#), "actions").unwrap());
        assert_eq!(
            contains(&s("5"), "actions").unwrap_err().text(),
            "argument of type 'int' is not iterable"
        );
        assert_eq!(item(&s("{}"), "id").unwrap_err().text(), "'id'");
        assert_eq!(
            item(&s("null"), "id").unwrap_err().text(),
            "'NoneType' object is not subscriptable"
        );
        assert_eq!(first(&s(r#"{"a": 1}"#)).unwrap_err().text(), "0");
        let mut list = s("[1]");
        assert_eq!(
            pop(&mut list, "x").unwrap_err().text(),
            "pop expected at most 1 argument, got 2"
        );
        assert_eq!(
            jsonable(&s(r#"{"_sa_x": 1, "a": [{"_sab": 2, "b": 3}], "_s": 4}"#)),
            s(r#"{"a": [{"b": 3}], "_s": 4}"#)
        );
    }
}
