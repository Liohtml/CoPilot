//! The Python operations the file-analysis services run on `json.loads`
//! values (a CAPE report, an inspector result, a VirusTotal answer, a stored
//! result): `dict.get` with a default, `or` chains, iteration, slicing,
//! `int()` / `float()` / `str()`, `in` against a frozenset or a list, and
//! the format specs the messages use. Each raises what CPython raises, so a
//! service fails where — and with the text — Python fails.

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_upstream::py::{PyExc, PyResult, int_of, py_eq, type_name};
use num_bigint_dig::BigInt;
use num_traits::ToPrimitive as _;

/// `{}`.
pub fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

/// `[]`.
pub fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

/// A `str` value.
pub fn s(text: impl Into<String>) -> PyValue {
    PyValue::Str(text.into())
}

/// An `int` value.
pub fn int(n: i64) -> PyValue {
    PyValue::Int(n.to_string())
}

/// A dict from `(key, value)` pairs, in order.
pub fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// `value.get(key, default)` (`AttributeError` on anything but a dict).
pub fn get_or(value: &PyValue, key: &str, default: PyValue) -> PyResult<PyValue> {
    Ok(copilot_upstream::py::get(value, key)?
        .cloned()
        .unwrap_or(default))
}

/// `value.get(key)`.
pub fn get(value: &PyValue, key: &str) -> PyResult<PyValue> {
    get_or(value, key, PyValue::None)
}

/// `a or b`.
pub fn or(a: PyValue, b: PyValue) -> PyValue {
    if a.truthy() { a } else { b }
}

/// `a or <lazy b>`.
pub fn or_else(a: PyValue, b: impl FnOnce() -> PyResult<PyValue>) -> PyResult<PyValue> {
    if a.truthy() { Ok(a) } else { b() }
}

/// `isinstance(value, dict)`.
pub fn is_dict(value: &PyValue) -> bool {
    matches!(value, PyValue::Dict(_))
}

/// `for x in value`.
pub fn iter(value: &PyValue) -> PyResult<Vec<PyValue>> {
    copilot_upstream::py::iterate(value)
}

/// `value[:n]` (`n` >= 0): a list's or a string's head; `TypeError` for the
/// rest.
pub fn head(value: &PyValue, n: usize) -> PyResult<PyValue> {
    match value {
        PyValue::List(items) => Ok(PyValue::List(items.iter().take(n).cloned().collect())),
        PyValue::Str(text) => Ok(PyValue::Str(text.chars().take(n).collect())),
        PyValue::Dict(_) => Err(PyExc::TypeError("unhashable type: 'slice'".into())),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        ))),
    }
}

/// `list(value)`.
pub fn to_list(value: &PyValue) -> PyResult<Vec<PyValue>> {
    iter(value)
}

/// `hash(value)`: a list or a dict is `TypeError: unhashable type`.
pub fn ensure_hashable(value: &PyValue) -> PyResult<()> {
    match value {
        PyValue::List(_) | PyValue::Dict(_) => Err(PyExc::TypeError(format!(
            "unhashable type: '{}'",
            type_name(value)
        ))),
        _ => Ok(()),
    }
}

/// `value in frozenset_of_str`.
pub fn in_str_set(value: &PyValue, set: &[&str]) -> PyResult<bool> {
    ensure_hashable(value)?;
    Ok(match value {
        PyValue::Str(text) => set.contains(&text.as_str()),
        _ => false,
    })
}

/// `item in items` for a list (Python `==`).
pub fn list_contains(items: &[PyValue], item: &PyValue) -> bool {
    items.iter().any(|x| py_eq(x, item))
}

/// `str(value)`.
pub fn str_of(value: &PyValue) -> String {
    value.py_str()
}

/// `int(value)` as a big integer.
pub fn int_value(value: &PyValue) -> PyResult<BigInt> {
    let text = int_of(value)?;
    text.parse::<BigInt>()
        .map_err(|_| PyExc::ValueError(format!("invalid literal for int(): {text}")))
}

/// `int(value)` of a setting read with `os.getenv(name, default)`.
pub fn int_setting(raw: &str) -> PyResult<i64> {
    let n = int_value(&PyValue::Str(raw.to_string()))?;
    n.to_i64()
        .ok_or_else(|| PyExc::Other("OverflowError", "int too large".into()))
}

/// `float(text)`: CPython's grammar (whitespace, one underscore between
/// digits, `inf`/`infinity`/`nan` in any case), or its `ValueError`.
pub fn float_str(text: &str) -> PyResult<f64> {
    let invalid = || {
        PyExc::ValueError(format!(
            "could not convert string to float: {}",
            str_repr(text)
        ))
    };
    let t = text.trim_matches(|c: char| copilot_jinja::unicode::is_space(c));
    let bytes: Vec<char> = t.chars().collect();
    let mut clean = String::new();
    for (i, c) in bytes.iter().enumerate() {
        if *c == '_' {
            let prev = i.checked_sub(1).and_then(|p| bytes.get(p));
            let next = bytes.get(i + 1);
            if !(prev.is_some_and(char::is_ascii_digit) && next.is_some_and(char::is_ascii_digit)) {
                return Err(invalid());
            }
            continue;
        }
        if !c.is_ascii() {
            return Err(invalid());
        }
        clean.push(*c);
    }
    let lower = clean.to_ascii_lowercase();
    let unsigned = lower.trim_start_matches(['+', '-']);
    if lower.len() - unsigned.len() > 1 {
        return Err(invalid());
    }
    if matches!(unsigned, "inf" | "infinity" | "nan") {
        return lower.parse::<f64>().map_err(|_| invalid());
    }
    if unsigned.is_empty()
        || !unsigned
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | '+' | '-'))
    {
        return Err(invalid());
    }
    lower.parse::<f64>().map_err(|_| invalid())
}

/// `float(value)`.
pub fn float_of(value: &PyValue) -> PyResult<f64> {
    match value {
        PyValue::Float(f) => Ok(*f),
        PyValue::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
        PyValue::Int(i) => {
            let f: f64 = i.parse().unwrap_or(f64::INFINITY);
            if f.is_infinite() {
                Err(PyExc::Other(
                    "OverflowError",
                    "int too large to convert to float".into(),
                ))
            } else {
                Ok(f)
            }
        }
        PyValue::Str(text) => float_str(text),
        other => Err(PyExc::TypeError(format!(
            "float() argument must be a string or a real number, not '{}'",
            type_name(other)
        ))),
    }
}

/// `format(x, "g")` (six significant digits).
pub fn format_g(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.into();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let sci = format!("{:.5e}", f);
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if (-4..6).contains(&exp) {
        let decimals = usize::try_from(5 - exp).unwrap_or(0);
        let fixed = format!("{:.*}", decimals, f);
        let fixed = if fixed.contains('.') {
            fixed
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string()
        } else {
            fixed
        };
        return fixed;
    }
    let mantissa = if mantissa.contains('.') {
        mantissa.trim_end_matches('0').trim_end_matches('.')
    } else {
        mantissa
    };
    let sign = if exp < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exp.unsigned_abs())
}

/// `str.strip()` (Unicode whitespace).
pub fn strip(text: &str) -> &str {
    text.trim_matches(|c: char| copilot_jinja::unicode::is_space(c))
}

/// `str.isdigit()`.
pub fn isdigit(text: &str) -> bool {
    !text.is_empty() && text.chars().all(copilot_jinja::unicode::is_digit)
}

/// `str.lower()`.
pub fn lower(text: &str) -> String {
    copilot_jinja::unicode::lower(text)
}

/// `str.upper()`.
pub fn upper(text: &str) -> String {
    copilot_jinja::unicode::upper(text)
}

/// `value.lower()` of a value that should be a `str`.
pub fn lower_of(value: &PyValue) -> PyResult<String> {
    match value {
        PyValue::Str(text) => Ok(lower(text)),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'lower'",
            type_name(other)
        ))),
    }
}

/// `posixpath.basename(path)`.
pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `", ".join(items)` (each item must be a `str`).
pub fn join(sep: &str, value: &PyValue) -> PyResult<String> {
    let items = iter(value)?;
    let mut parts = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        match item {
            PyValue::Str(text) => parts.push(text.clone()),
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

/// `-x` of a number (`TypeError` for the rest).
pub fn neg_key(value: &PyValue) -> PyResult<f64> {
    match value {
        PyValue::Int(i) => Ok(-i.parse::<f64>().unwrap_or(f64::INFINITY)),
        PyValue::Float(f) => Ok(-f),
        PyValue::Bool(b) => Ok(if *b { -1.0 } else { 0.0 }),
        other => Err(PyExc::TypeError(format!(
            "bad operand type for unary -: '{}'",
            type_name(other)
        ))),
    }
}

/// `str.encode("latin-1", errors="replace")`.
pub fn latin1_replace(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_parse_like_cpython() {
        assert_eq!(float_str(" 1_0.5 ").unwrap(), 10.5);
        assert!(float_str("1__0").is_err());
        assert!(float_str("_1").is_err());
        assert_eq!(float_str("-Infinity").unwrap(), f64::NEG_INFINITY);
        assert!(float_str("nan").unwrap().is_nan());
        assert_eq!(float_str(".5").unwrap(), 0.5);
        assert_eq!(float_str("5.").unwrap(), 5.0);
        assert!(float_str("").is_err());
        assert!(float_str("1e").is_err());
        assert!(float_str("0x10").is_err());
        assert_eq!(
            float_str("abc").unwrap_err().text(),
            "could not convert string to float: 'abc'"
        );
    }

    #[test]
    fn g_format_matches_python() {
        for (f, want) in [
            (10.0, "10"),
            (7.5, "7.5"),
            (1234567.0, "1.23457e+06"),
            (0.00001234, "1.234e-05"),
            (0.0001, "0.0001"),
            (123456.0, "123456"),
            (6.6, "6.6"),
            (0.1 + 0.2, "0.3"),
            (-2.5, "-2.5"),
            (1e100, "1e+100"),
        ] {
            assert_eq!(format_g(f), want, "{f}");
        }
    }

    #[test]
    fn slicing_and_hashing_raise_like_cpython() {
        assert_eq!(head(&s("abc"), 2).unwrap(), s("ab"));
        assert_eq!(
            head(&empty_dict(), 2).unwrap_err().text(),
            "unhashable type: 'slice'"
        );
        assert_eq!(
            head(&int(5), 2).unwrap_err().text(),
            "'int' object is not subscriptable"
        );
        assert_eq!(
            in_str_set(&empty_list(), &["a"]).unwrap_err().text(),
            "unhashable type: 'list'"
        );
        assert!(in_str_set(&s("a"), &["a"]).unwrap());
        assert!(!in_str_set(&int(1), &["1"]).unwrap());
    }
}
