//! JSON the way the Python side reads and writes it.
//!
//! - [`pydantic_json`]: what FastAPI sends for a route with a
//!   `response_model` (`serialize_json`, pydantic-core's writer): compact,
//!   UTF-8, `NaN`/`inf` as `null`, floats in the shortest round-trip form
//!   pydantic-core prints (`1e+16`, `0.000025`, `1e-7` — the same as
//!   `serde_json`'s, which this uses), integers of any size.
//! - [`py_dumps`]: CPython's `json.dumps`, for request bodies a Python client
//!   library sent (`requests`' `json=` is `json.dumps(obj, allow_nan=False)`:
//!   `", "`/`": "` separators, `ensure_ascii`).
//! - [`decode_error`]: the `JSONDecodeError` text of CPython 3.11's `json`
//!   for a body that is not JSON (`Expecting value: line 1 column 1 (char
//!   0)`), which several helpers put into their answers.

use copilot_auth::pyvalue::{PyValue, float_repr, loads};

/// pydantic-core's JSON for a JSON-mode dump.
pub fn pydantic_json(value: &PyValue) -> String {
    let mut out = String::new();
    write_pydantic(value, &mut out);
    out
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn write_pydantic(value: &PyValue, out: &mut String) {
    match value {
        PyValue::None => out.push_str("null"),
        PyValue::Bool(true) => out.push_str("true"),
        PyValue::Bool(false) => out.push_str("false"),
        PyValue::Int(i) => out.push_str(i),
        PyValue::Float(f) => {
            if f.is_finite() {
                out.push_str(&serde_json::to_string(f).unwrap_or_else(|_| "null".into()));
            } else {
                out.push_str("null");
            }
        }
        PyValue::Str(s) => out.push_str(&json_str(s)),
        PyValue::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_pydantic(item, out);
            }
            out.push(']');
        }
        PyValue::Dict(items) => {
            out.push('{');
            for (i, (k, v)) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&json_str(k));
                out.push(':');
                write_pydantic(v, out);
            }
            out.push('}');
        }
    }
}

/// `json.dumps` options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dumps {
    /// `ensure_ascii`.
    pub ensure_ascii: bool,
    /// `separators=(",", ":")` instead of `(", ", ": ")`.
    pub compact: bool,
}

impl Dumps {
    /// `json.dumps(obj)` (and `requests`' `json=`).
    pub const DEFAULT: Self = Self {
        ensure_ascii: true,
        compact: false,
    };
    /// httpx's `json=`.
    pub const HTTPX: Self = Self {
        ensure_ascii: false,
        compact: true,
    };
}

/// `ValueError("Out of range float values are not JSON compliant")`, which
/// `json.dumps(…, allow_nan=False)` raises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NanError;

impl std::fmt::Display for NanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Out of range float values are not JSON compliant")
    }
}

/// CPython's `json.dumps(value, allow_nan=False, …)`.
pub fn py_dumps(value: &PyValue, opts: Dumps) -> Result<String, NanError> {
    let mut out = String::new();
    encode(value, opts, &mut out)?;
    Ok(out)
}

fn encode(value: &PyValue, opts: Dumps, out: &mut String) -> Result<(), NanError> {
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
            if !f.is_finite() {
                return Err(NanError);
            }
            out.push_str(&float_repr(*f));
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
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `json.loads(text)`: the value, or the `JSONDecodeError`'s `str()`.
pub fn py_loads(text: &str) -> Result<PyValue, String> {
    match loads(text) {
        Ok(v) => Ok(v),
        Err(_) => Err(decode_error(text).unwrap_or_else(|| {
            // Accepted by the scanner but not by the value parser (a lone
            // surrogate, too deep a nesting): never seen from a tool.
            "Expecting value: line 1 column 1 (char 0)".to_string()
        })),
    }
}

/// The `JSONDecodeError` CPython 3.11 raises for `text`, or `None` when it
/// parses.
pub fn decode_error(text: &str) -> Option<String> {
    let s: Vec<char> = text.chars().collect();
    let (msg, pos) = scan_document(&s)?;
    let (line, col) = line_col(&s, pos);
    Some(format!("{msg}: line {line} column {col} (char {pos})"))
}

fn line_col(s: &[char], pos: usize) -> (usize, usize) {
    let before = &s[..pos.min(s.len())];
    let line = before.iter().filter(|c| **c == '\n').count() + 1;
    let col = match before.iter().rposition(|c| *c == '\n') {
        Some(nl) => pos - nl,
        None => pos + 1,
    };
    (line, col)
}

type Scan = Result<usize, (&'static str, usize)>;

fn ws(s: &[char], mut i: usize) -> usize {
    while i < s.len() && matches!(s[i], ' ' | '\t' | '\n' | '\r') {
        i += 1;
    }
    i
}

fn scan_document(s: &[char]) -> Option<(&'static str, usize)> {
    if s.first() == Some(&'\u{feff}') {
        return Some(("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0));
    }
    let start = ws(s, 0);
    match scan_once(s, start) {
        Err(e) => Some(e),
        Ok(end) => {
            let end = ws(s, end);
            (end != s.len()).then_some(("Extra data", end))
        }
    }
}

fn lit(s: &[char], i: usize, word: &str) -> bool {
    (i..).zip(word.chars()).all(|(k, c)| s.get(k) == Some(&c))
}

fn scan_once(s: &[char], idx: usize) -> Scan {
    let Some(&c) = s.get(idx) else {
        return Err(("Expecting value", idx));
    };
    match c {
        '"' => scan_string(s, idx + 1),
        '{' => scan_object(s, idx + 1),
        '[' => scan_array(s, idx + 1),
        'n' if lit(s, idx, "null") => Ok(idx + 4),
        't' if lit(s, idx, "true") => Ok(idx + 4),
        'f' if lit(s, idx, "false") => Ok(idx + 5),
        'N' if lit(s, idx, "NaN") => Ok(idx + 3),
        'I' if lit(s, idx, "Infinity") => Ok(idx + 8),
        '-' if lit(s, idx, "-Infinity") => Ok(idx + 9),
        _ => scan_number(s, idx),
    }
}

fn digit(s: &[char], i: usize) -> bool {
    s.get(i).is_some_and(char::is_ascii_digit)
}

fn scan_number(s: &[char], start: usize) -> Scan {
    let len = s.len();
    let mut idx = start;
    if s.get(idx) == Some(&'-') {
        idx += 1;
        if idx >= len {
            return Err(("Expecting value", start));
        }
    }
    match s.get(idx) {
        Some(c) if ('1'..='9').contains(c) => {
            idx += 1;
            while digit(s, idx) {
                idx += 1;
            }
        }
        Some('0') => idx += 1,
        _ => return Err(("Expecting value", start)),
    }
    if idx + 1 < len && s[idx] == '.' && digit(s, idx + 1) {
        idx += 2;
        while digit(s, idx) {
            idx += 1;
        }
    }
    if idx + 1 < len && (s[idx] == 'e' || s[idx] == 'E') {
        let e_start = idx;
        idx += 1;
        if idx + 1 < len && (s[idx] == '-' || s[idx] == '+') {
            idx += 1;
        }
        let digits_start = idx;
        while digit(s, idx) {
            idx += 1;
        }
        if idx == digits_start {
            idx = e_start;
        }
    }
    Ok(idx)
}

fn is_hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}

/// `scanstring_unicode(s, end, strict=True)`; `end` is just past the quote.
fn scan_string(s: &[char], end: usize) -> Scan {
    let len = s.len();
    let begin = end - 1;
    let mut end = end;
    loop {
        let mut next = end;
        let mut c = '\0';
        while next < len {
            c = s[next];
            if c == '"' || c == '\\' {
                break;
            }
            if (c as u32) <= 0x1f {
                return Err(("Invalid control character at", next));
            }
            next += 1;
        }
        if next >= len {
            return Err(("Unterminated string starting at", begin));
        }
        if c == '"' {
            return Ok(next + 1);
        }
        // A backslash.
        next += 1;
        if next == len {
            return Err(("Unterminated string starting at", begin));
        }
        let esc = s[next];
        if esc != 'u' {
            end = next + 1;
            if !matches!(esc, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') {
                return Err(("Invalid \\escape", end - 2));
            }
        } else {
            next += 1;
            end = next + 4;
            if end >= len {
                return Err(("Invalid \\uXXXX escape", next - 1));
            }
            let mut code: u32 = 0;
            while next < end {
                let d = s[next];
                if !is_hex(d) {
                    return Err(("Invalid \\uXXXX escape", end - 5));
                }
                code = (code << 4) | d.to_digit(16).unwrap_or(0);
                next += 1;
            }
            if (0xd800..=0xdbff).contains(&code) && end + 6 < len && s[next] == '\\' {
                next += 1;
                if s[next] == 'u' {
                    next += 1;
                    end += 6;
                    while next < end {
                        if !is_hex(s[next]) {
                            return Err(("Invalid \\uXXXX escape", end - 5));
                        }
                        next += 1;
                    }
                }
            }
        }
    }
}

fn scan_object(s: &[char], idx: usize) -> Scan {
    let len = s.len();
    let mut idx = ws(s, idx);
    if idx >= len || s[idx] != '}' {
        loop {
            if idx >= len || s[idx] != '"' {
                return Err(("Expecting property name enclosed in double quotes", idx));
            }
            idx = scan_string(s, idx + 1)?;
            idx = ws(s, idx);
            if idx >= len || s[idx] != ':' {
                return Err(("Expecting ':' delimiter", idx));
            }
            idx = ws(s, idx + 1);
            idx = scan_once(s, idx)?;
            idx = ws(s, idx);
            if idx < len && s[idx] == '}' {
                break;
            }
            if idx >= len || s[idx] != ',' {
                return Err(("Expecting ',' delimiter", idx));
            }
            idx = ws(s, idx + 1);
        }
    }
    Ok(idx + 1)
}

fn scan_array(s: &[char], idx: usize) -> Scan {
    let len = s.len();
    let mut idx = ws(s, idx);
    if idx >= len || s[idx] != ']' {
        loop {
            idx = scan_once(s, idx)?;
            idx = ws(s, idx);
            if idx < len && s[idx] == ']' {
                break;
            }
            if idx >= len || s[idx] != ',' {
                return Err(("Expecting ',' delimiter", idx));
            }
            idx = ws(s, idx + 1);
        }
    }
    Ok(idx + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_errors_read_like_cpython() {
        for (text, want) in [
            ("", "Expecting value: line 1 column 1 (char 0)"),
            ("<html>", "Expecting value: line 1 column 1 (char 0)"),
            (
                r#"{"a":1,}"#,
                "Expecting property name enclosed in double quotes: line 1 column 8 (char 7)",
            ),
            ("[1,]", "Expecting value: line 1 column 4 (char 3)"),
            (
                r#"{"a" 1}"#,
                "Expecting ':' delimiter: line 1 column 6 (char 5)",
            ),
            (
                r#""abc"#,
                "Unterminated string starting at: line 1 column 1 (char 0)",
            ),
            ("[1 2]", "Expecting ',' delimiter: line 1 column 4 (char 3)"),
            (r#"{"a":1}x"#, "Extra data: line 1 column 8 (char 7)"),
            (r#""\q""#, "Invalid \\escape: line 1 column 2 (char 1)"),
            (
                "\"\u{1}\"",
                "Invalid control character at: line 1 column 2 (char 1)",
            ),
            ("[", "Expecting value: line 1 column 2 (char 1)"),
            ("\n\n<x", "Expecting value: line 3 column 1 (char 2)"),
        ] {
            assert_eq!(decode_error(text).as_deref(), Some(want), "{text:?}");
        }
        assert_eq!(decode_error(r#"{"a": [1, 2.5e3, null]}"#), None);
    }

    #[test]
    fn dumps_like_requests() {
        let v = loads(r#"{"a": [1, 2.5, "é\n"], "b": {"c": null}}"#).unwrap();
        assert_eq!(
            py_dumps(&v, Dumps::DEFAULT).unwrap(),
            "{\"a\": [1, 2.5, \"\\u00e9\\n\"], \"b\": {\"c\": null}}"
        );
        assert_eq!(
            py_dumps(&v, Dumps::HTTPX).unwrap(),
            "{\"a\":[1,2.5,\"é\\n\"],\"b\":{\"c\":null}}"
        );
    }

    #[test]
    fn pydantic_json_matches_serialize_json() {
        let v = PyValue::Dict(vec![
            ("f".into(), PyValue::Float(1e16)),
            ("g".into(), PyValue::Float(2.5e-5)),
            ("n".into(), PyValue::Float(f64::NAN)),
            (
                "i".into(),
                PyValue::Int("123456789012345678901234567890".into()),
            ),
            ("s".into(), PyValue::Str("é\u{2028}\u{7f}/\u{1}".into())),
        ]);
        assert_eq!(
            pydantic_json(&v),
            "{\"f\":1e+16,\"g\":0.000025,\"n\":null,\"i\":123456789012345678901234567890,\"s\":\"é\u{2028}\u{7f}/\\u0001\"}"
        );
    }
}
