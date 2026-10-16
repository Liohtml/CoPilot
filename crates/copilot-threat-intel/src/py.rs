//! Python value helpers the threat-intel services share.

use copilot_auth::pyvalue::PyValue;
use copilot_db::DbError;
use copilot_upstream::py::{PyExc, py_eq, type_name};

/// A `dict` in the given order.
pub fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// A `str`.
pub fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

/// A database failure: SQLAlchemy's exception, which nothing catches (a
/// bare 500).
pub fn db(e: impl Into<DbError>) -> PyExc {
    PyExc::Other("DBAPIError", e.into().to_string())
}

/// `key in container` for a `json.loads` value: a dict's keys, a list's
/// items, a string's substrings; `TypeError` for the rest.
pub fn contains(container: &PyValue, key: &str) -> Result<bool, PyExc> {
    match container {
        PyValue::Dict(items) => Ok(items.iter().any(|(k, _)| k == key)),
        PyValue::List(items) => Ok(items.iter().any(|v| py_eq(v, &s(key)))),
        PyValue::Str(text) => Ok(text.contains(key)),
        other => Err(PyExc::TypeError(format!(
            "argument of type '{}' is not iterable",
            type_name(other)
        ))),
    }
}

/// `float(text)` for a `str`, as CPython 3.11 parses it: Unicode digits and
/// spaces made ASCII, surrounding whitespace stripped, `inf` / `infinity` /
/// `nan` in any case with an optional sign, single underscores between
/// digits. `None` is its `ValueError`.
pub fn py_float(text: &str) -> Option<f64> {
    let ascii: String = text
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c
            } else if copilot_jinja::unicode::is_space(c) {
                ' '
            } else if let Some(d) = copilot_jinja::unicode::decimal_value(c) {
                char::from_digit(d, 10).unwrap_or('?')
            } else {
                '?'
            }
        })
        .collect();
    let t = ascii.trim_matches(|c: char| c == ' ' || ('\t'..='\r').contains(&c));
    let unsigned = t.strip_prefix(['+', '-']).unwrap_or(t);
    let lower = unsigned.to_ascii_lowercase();
    if matches!(lower.as_str(), "inf" | "infinity" | "nan") {
        let v = if lower == "nan" {
            f64::NAN
        } else {
            f64::INFINITY
        };
        return Some(if t.starts_with('-') { -v } else { v });
    }
    let bytes = unsigned.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'_' {
            let before = i > 0 && bytes[i - 1].is_ascii_digit();
            let after = i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit();
            if !(before && after) {
                return None;
            }
        } else if !(b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-')) {
            return None;
        }
    }
    let clean: String = t.chars().filter(|c| *c != '_').collect();
    clean.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_parse_like_cpython() {
        // Recorded with CPython 3.11's float().
        assert_eq!(py_float(" 5 "), Some(5.0));
        assert_eq!(py_float("1_0.5"), Some(10.5));
        assert_eq!(py_float("1e3"), Some(1000.0));
        assert_eq!(py_float(".5"), Some(0.5));
        assert_eq!(py_float("5."), Some(5.0));
        assert_eq!(py_float("-Infinity"), Some(f64::NEG_INFINITY));
        assert!(py_float("nan").is_some_and(f64::is_nan));
        assert_eq!(py_float("\u{0665}"), Some(5.0));
        for bad in [
            "", "1__0", "_1", "1_", "1_.5", "0x10", "infin", "1e", "abc", "1 0",
        ] {
            assert_eq!(py_float(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn membership_follows_python() {
        assert!(contains(&s("metadata"), "data").unwrap());
        assert!(contains(&PyValue::List(vec![s("data")]), "data").unwrap());
        assert_eq!(
            contains(&PyValue::Int("1".into()), "data").unwrap_err(),
            PyExc::TypeError("argument of type 'int' is not iterable".into())
        );
    }
}
