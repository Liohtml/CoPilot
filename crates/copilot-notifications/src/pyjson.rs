//! CPython's `json.dumps`, for the bytes CoPilot writes where Python wrote
//! them: the stored route `config` (`json.dumps(config)`), the `{{report}}`
//! substitution of a webhook template, the size Teams' 28 KB check measures,
//! and the bodies httpx sends (`json=` is `json.dumps(…, ensure_ascii=False,
//! separators=(",", ":"), allow_nan=False)`).
//!
//! Values are [`PyValue`]s (CPython's `json.loads` result), so a body that
//! round-trips through Python's parser — big integers, `NaN` — is written
//! back the way Python writes it.

use copilot_auth::pyvalue::{PyValue, float_repr};
use serde_json::Value;

/// `json.dumps` options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dumps {
    /// `ensure_ascii` (Python's default: `true`).
    pub ensure_ascii: bool,
    /// `separators=(",", ":")` instead of the default `(", ", ": ")`.
    pub compact: bool,
    /// `allow_nan` (Python's default: `true`).
    pub allow_nan: bool,
}

impl Dumps {
    /// `json.dumps(value)`.
    pub const DEFAULT: Self = Self {
        ensure_ascii: true,
        compact: false,
        allow_nan: true,
    };

    /// What httpx sends for `json=value`.
    pub const HTTPX: Self = Self {
        ensure_ascii: false,
        compact: true,
        allow_nan: false,
    };
}

/// `json.dumps` raised (only with `allow_nan=False`): Python's `ValueError`
/// text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpsError(pub String);

impl std::fmt::Display for DumpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A `serde_json` value as Python holds it after `json.loads`.
pub fn from_json(value: &Value) -> PyValue {
    match value {
        Value::Null => PyValue::None,
        Value::Bool(b) => PyValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PyValue::Int(i.to_string())
            } else if let Some(u) = n.as_u64() {
                PyValue::Int(u.to_string())
            } else {
                PyValue::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => PyValue::Str(s.clone()),
        Value::Array(items) => PyValue::List(items.iter().map(from_json).collect()),
        Value::Object(map) => {
            PyValue::Dict(map.iter().map(|(k, v)| (k.clone(), from_json(v))).collect())
        }
    }
}

/// `json.dumps(value, …)` for a `serde_json` value.
pub fn dumps_json(value: &Value, opts: Dumps) -> Result<String, DumpsError> {
    dumps(&from_json(value), opts)
}

/// `json.dumps(value, …)`.
pub fn dumps(value: &PyValue, opts: Dumps) -> Result<String, DumpsError> {
    let mut out = String::new();
    encode(value, opts, &mut out)?;
    Ok(out)
}

fn encode(value: &PyValue, opts: Dumps, out: &mut String) -> Result<(), DumpsError> {
    let (item_sep, key_sep) = if opts.compact {
        (",", ":")
    } else {
        (", ", ": ")
    };
    match value {
        PyValue::None => out.push_str("null"),
        PyValue::Bool(true) => out.push_str("true"),
        PyValue::Bool(false) => out.push_str("false"),
        PyValue::Int(i) => out.push_str(i),
        PyValue::Float(f) => {
            if f.is_finite() {
                out.push_str(&float_repr(*f));
            } else if !opts.allow_nan {
                return Err(DumpsError(format!(
                    "Out of range float values are not JSON compliant: {}",
                    float_repr(*f)
                )));
            } else if f.is_nan() {
                out.push_str("NaN");
            } else if *f > 0.0 {
                out.push_str("Infinity");
            } else {
                out.push_str("-Infinity");
            }
        }
        PyValue::Str(s) => encode_str(s, opts.ensure_ascii, out),
        PyValue::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                encode(item, opts, out)?;
            }
            out.push(']');
        }
        PyValue::Dict(items) => {
            out.push('{');
            for (i, (k, v)) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                encode_str(k, opts.ensure_ascii, out);
                out.push_str(key_sep);
                encode(v, opts, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// `py_encode_basestring_ascii` / `py_encode_basestring`.
fn encode_str(s: &str, ensure_ascii: bool, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if ensure_ascii && (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors_match_cpython() {
        let vectors: Vec<Value> =
            serde_json::from_str(include_str!("pyjson_vectors.json")).unwrap();
        assert!(!vectors.is_empty());
        for v in vectors {
            let input = &v["input"];
            assert_eq!(
                dumps_json(input, Dumps::DEFAULT).unwrap(),
                v["default"].as_str().unwrap(),
                "{input}"
            );
            assert_eq!(
                dumps_json(
                    input,
                    Dumps {
                        allow_nan: true,
                        ..Dumps::HTTPX
                    }
                )
                .unwrap(),
                v["compact"].as_str().unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn nan_is_refused_by_httpx() {
        let err = dumps(&PyValue::Float(f64::NAN), Dumps::HTTPX).unwrap_err();
        assert_eq!(
            err.0,
            "Out of range float values are not JSON compliant: nan"
        );
        assert_eq!(
            dumps(&PyValue::Float(f64::INFINITY), Dumps::DEFAULT).unwrap(),
            "Infinity"
        );
    }
}
