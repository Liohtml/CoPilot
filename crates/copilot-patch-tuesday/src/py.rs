//! The Python operations the module runs on MSRC's, FIRST's and CISA's JSON,
//! with CPython 3.11's semantics: `or` chains on truthiness, `str()` of any
//! value, `json.dumps(…, ensure_ascii=False)`, `re.sub(r"\s+", " ", s)`,
//! `str.strip`/`lower`/`upper`/`title` (`copilot_jinja::unicode`'s Unicode
//! tables), `float()` and the `format(x, ".Nf")` the priority reasons print.

use copilot_auth::pyvalue::PyValue;
use copilot_jinja::unicode;
use copilot_upstream::json::{Dumps, py_dumps_allow_nan};
use copilot_upstream::py::{PyExc, PyResult, get};

/// `a.get(k1) or a.get(k2) or …`: the first truthy value, else the last one
/// (`None` for an absent key). `value` must be a dict (`AttributeError`).
pub fn get_or(value: &PyValue, keys: &[&str]) -> PyResult<PyValue> {
    let mut last = PyValue::None;
    for key in keys {
        last = get(value, key)?.cloned().unwrap_or(PyValue::None);
        if last.truthy() {
            return Ok(last);
        }
    }
    Ok(last)
}

/// `value or default`.
pub fn or(value: PyValue, default: PyValue) -> PyValue {
    if value.truthy() { value } else { default }
}

/// `str.isspace()` of one character.
pub fn is_space(c: char) -> bool {
    unicode::is_space(c)
}

/// `s.strip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `s.lstrip()`.
pub fn lstrip(s: &str) -> &str {
    s.trim_start_matches(is_space)
}

/// `re.sub(r"\s+", " ", s)`.
fn collapse_spaces(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_space = false;
    for c in s.chars() {
        if is_space(c) {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    out
}

/// `normalize_text(s)`: a best-effort single-line string, or `None`.
pub fn normalize_text(value: &PyValue) -> Option<String> {
    const KEYS: [&str; 10] = [
        "Value",
        "value",
        "Description",
        "description",
        "Text",
        "text",
        "Title",
        "title",
        "Name",
        "name",
    ];
    let text = match value {
        PyValue::None => return None,
        PyValue::Dict(items) => {
            // `isinstance(s[k], (str, int, float))`: a bool is an int.
            let picked = KEYS.iter().find_map(|k| {
                items.iter().find(|(key, _)| key == k).and_then(|(_, v)| {
                    matches!(
                        v,
                        PyValue::Str(_) | PyValue::Int(_) | PyValue::Float(_) | PyValue::Bool(_)
                    )
                    .then_some(v)
                })
            });
            match picked {
                Some(v) => v.py_str(),
                None => py_dumps_allow_nan(
                    value,
                    Dumps {
                        ensure_ascii: false,
                        compact: false,
                    },
                ),
            }
        }
        PyValue::List(items) => items
            .iter()
            .filter_map(normalize_text)
            .collect::<Vec<_>>()
            .join(" | "),
        other => other.py_str(),
    };
    let collapsed = collapse_spaces(&text);
    let trimmed = collapsed.trim_matches(' ');
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// `s.upper()`.
pub fn upper(s: &str) -> String {
    unicode::upper(s)
}

/// `s.lower()`.
pub fn lower(s: &str) -> String {
    unicode::lower(s)
}

/// `s.title()`.
pub fn title(s: &str) -> String {
    unicode::title(s)
}

/// `float(x)`: `None` for what raises (`ValueError`, `TypeError`,
/// `OverflowError`).
pub fn float(x: &PyValue) -> Option<f64> {
    match x {
        PyValue::Float(f) => Some(*f),
        PyValue::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        // `float(int)` is correctly rounded, and an int beyond the float
        // range is an `OverflowError`.
        PyValue::Int(i) => i.parse::<f64>().ok().filter(|f| f.is_finite()),
        PyValue::Str(s) => copilot_threat_intel::py::py_float(s),
        _ => None,
    }
}

/// `safe_float(x)`.
pub fn safe_float(x: &PyValue) -> Option<f64> {
    match x {
        PyValue::None => None,
        PyValue::Str(s) if s.is_empty() => None,
        other => float(other),
    }
}

/// `format(x, f".{precision}f")`.
pub fn fixed(x: f64, precision: usize) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    format!("{x:.precision$}")
}

/// `for x in value` (a dict wrapped in a list by the caller).
pub fn iterate(value: &PyValue) -> PyResult<Vec<PyValue>> {
    copilot_upstream::py::iterate(value)
}

/// `value if not isinstance(value, dict) else [value]`.
pub fn listed(value: PyValue) -> PyValue {
    match value {
        d @ PyValue::Dict(_) => PyValue::List(vec![d]),
        other => other,
    }
}

/// A `RuntimeError(text)`.
pub fn runtime_error(text: impl Into<String>) -> PyExc {
    PyExc::Other("RuntimeError", text.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_collapse_like_re() {
        assert_eq!(
            normalize_text(&PyValue::Str(" a\t\u{a0}b\u{1c}c  ".into())).as_deref(),
            Some("a b c")
        );
        assert_eq!(normalize_text(&PyValue::Str("  ".into())), None);
    }

    #[test]
    fn fixed_is_round_half_even() {
        assert_eq!(fixed(0.25, 1), "0.2");
        assert_eq!(fixed(0.125, 2), "0.12");
        assert_eq!(fixed(0.0005, 3), "0.001");
        assert_eq!(fixed(-0.04, 1), "-0.0");
        assert_eq!(fixed(f64::INFINITY, 1), "inf");
        assert_eq!(fixed(f64::NAN, 3), "nan");
    }
}
