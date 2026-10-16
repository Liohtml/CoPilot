//! Python's dict/list/str operations on `json.loads` results, with the
//! exception texts the services embed when an upstream answer has an
//! unexpected shape (`'list' object has no attribute 'get'`, `argument of
//! type 'int' is not iterable`, …).

use serde_json::Value;

use crate::indexer::services::py_type;
use crate::pymodel::py;

/// `str(value)`.
pub fn py_str(v: &Value) -> String {
    py(v).py_str()
}

/// Python truthiness.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `v.get(key, default)`.
pub fn get(v: &Value, key: &str, default: Value) -> Result<Value, String> {
    match v {
        Value::Object(map) => Ok(map.get(key).cloned().unwrap_or(default)),
        other => Err(format!(
            "'{}' object has no attribute 'get'",
            py_type(other)
        )),
    }
}

/// `key in v` for a `str` key.
pub fn contains(v: &Value, key: &str) -> Result<bool, String> {
    match v {
        Value::Object(map) => Ok(map.contains_key(key)),
        Value::Array(items) => Ok(items.iter().any(|i| i.as_str() == Some(key))),
        Value::String(s) => Ok(s.contains(key)),
        other => Err(format!(
            "argument of type '{}' is not iterable",
            py_type(other)
        )),
    }
}

/// `v[key]` for a `str` key.
pub fn index(v: &Value, key: &str) -> Result<Value, String> {
    match v {
        Value::Object(map) => map
            .get(key)
            .cloned()
            .ok_or_else(|| copilot_auth::pyvalue::str_repr(key)),
        Value::Array(_) => Err("list indices must be integers or slices, not str".into()),
        Value::String(_) => Err("string indices must be integers, not 'str'".into()),
        other => Err(format!("'{}' object is not subscriptable", py_type(other))),
    }
}

/// `v[0]`.
pub fn first(v: &Value) -> Result<Value, String> {
    match v {
        Value::Array(items) => items
            .first()
            .cloned()
            .ok_or_else(|| "list index out of range".into()),
        Value::String(s) => s
            .chars()
            .next()
            .map(|c| Value::String(c.to_string()))
            .ok_or_else(|| "string index out of range".into()),
        // `d[0]`: JSON keys are strings, never the integer 0.
        Value::Object(_) => Err("0".into()),
        other => Err(format!("'{}' object is not subscriptable", py_type(other))),
    }
}

/// `len(v)`.
pub fn len(v: &Value) -> Result<usize, String> {
    match v {
        Value::Array(a) => Ok(a.len()),
        Value::Object(o) => Ok(o.len()),
        Value::String(s) => Ok(s.chars().count()),
        other => Err(format!("object of type '{}' has no len()", py_type(other))),
    }
}

/// `for item in v` (a dict yields its keys, a string its characters).
pub fn iterate(v: &Value) -> Result<Vec<Value>, String> {
    match v {
        Value::Array(a) => Ok(a.clone()),
        Value::Object(o) => Ok(o.keys().map(|k| Value::String(k.clone())).collect()),
        Value::String(s) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        other => Err(format!("'{}' object is not iterable", py_type(other))),
    }
}

/// `.lower()` of a value the services expect to be a `str`.
pub fn lower(v: &Value) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.to_lowercase()),
        other => Err(format!(
            "'{}' object has no attribute 'lower'",
            py_type(other)
        )),
    }
}

/// `bytes.decode("utf-8")`'s `UnicodeDecodeError` text, or `None` when the
/// bytes are valid.
pub fn utf8_decode_error(bytes: &[u8]) -> Option<String> {
    let e = std::str::from_utf8(bytes).err()?;
    let start = e.valid_up_to();
    let (end, reason) = match e.error_len() {
        None => (bytes.len(), "unexpected end of data"),
        Some(n) => {
            let first = bytes[start];
            let bad_start = n == 1 && ((0x80..=0xc1).contains(&first) || first >= 0xf5);
            (
                start + n,
                if bad_start {
                    "invalid start byte"
                } else {
                    "invalid continuation byte"
                },
            )
        }
    };
    Some(if end - start == 1 {
        format!(
            "'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}",
            bytes[start]
        )
    } else {
        format!(
            "'utf-8' codec can't decode bytes in position {start}-{}: {reason}",
            end - 1
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn utf8_errors_read_as_cpython() {
        // Recorded with Python 3.11.
        for (bytes, text) in [
            (
                &b"<a>\xff</a>"[..],
                "byte 0xff in position 3: invalid start byte",
            ),
            (
                b"\xe4A",
                "byte 0xe4 in position 0: invalid continuation byte",
            ),
            (
                b"\xf0\x9fA",
                "bytes in position 0-1: invalid continuation byte",
            ),
            (
                b"\xe0\x80",
                "byte 0xe0 in position 0: invalid continuation byte",
            ),
            (b"ab\xc3", "byte 0xc3 in position 2: unexpected end of data"),
            (
                b"ab\xf0\x9f\x98",
                "bytes in position 2-4: unexpected end of data",
            ),
            (b"\xc0\xaf", "byte 0xc0 in position 0: invalid start byte"),
            (
                b"\xed\xa0\x80",
                "byte 0xed in position 0: invalid continuation byte",
            ),
            (
                b"\xf4\x90\x80\x80",
                "byte 0xf4 in position 0: invalid continuation byte",
            ),
            (b"ok\x80", "byte 0x80 in position 2: invalid start byte"),
            (b"\xf8", "byte 0xf8 in position 0: invalid start byte"),
        ] {
            assert_eq!(
                utf8_decode_error(bytes).as_deref(),
                Some(format!("'utf-8' codec can't decode {text}").as_str())
            );
        }
        assert_eq!(utf8_decode_error("é".as_bytes()), None);
    }

    #[test]
    fn python_texts() {
        assert_eq!(
            get(&json!([1]), "data", json!({})).unwrap_err(),
            "'list' object has no attribute 'get'"
        );
        assert_eq!(
            contains(&json!(3), "data").unwrap_err(),
            "argument of type 'int' is not iterable"
        );
        assert!(contains(&json!("metadata"), "data").unwrap());
        assert_eq!(index(&json!({"a": 1}), "b").unwrap_err(), "'b'");
        assert_eq!(
            index(&json!(null), "b").unwrap_err(),
            "'NoneType' object is not subscriptable"
        );
        assert_eq!(
            len(&json!(1.5)).unwrap_err(),
            "object of type 'float' has no len()"
        );
        assert_eq!(py_str(&json!({"a": [true, null]})), "{'a': [True, None]}");
    }
}
