//! Python's `json.loads(bytes)` into Python-shaped values, and the `str()` /
//! `repr()` Python puts into messages.
//!
//! Used where a third-party library reads JSON the request author controls
//! and its error texts embed the values: py_webauthn's `clientDataJSON`
//! (`Unexpected client data origin "…"`) and PyJWT's header and payload.
//! The grammar is CPython 3.11's `json` module: `NaN`/`Infinity`, integers of
//! any size, duplicate keys (the last value wins, at the first key's
//! position), and the byte-level encoding detection of `json.loads(bytes)`
//! (UTF-8 with or without BOM, UTF-16, UTF-32). Lone surrogates, which a Rust
//! string cannot hold, become U+FFFD.

use icu_properties::CodePointMapData;
use icu_properties::props::GeneralCategory;

/// A value `json.loads` returns.
#[derive(Debug, Clone, PartialEq)]
pub enum PyValue {
    /// `None`.
    None,
    /// `True` / `False`.
    Bool(bool),
    /// An `int`, as its canonical decimal text (any size).
    Int(String),
    /// A `float` (`NaN`, `Infinity`, exponents, fractions).
    Float(f64),
    /// A `str`.
    Str(String),
    /// A `list`.
    List(Vec<PyValue>),
    /// A `dict` in insertion order.
    Dict(Vec<(String, PyValue)>),
}

/// `json.loads` failed (a `ValueError`: `JSONDecodeError` or
/// `UnicodeDecodeError`, or a `RecursionError` on deep nesting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid JSON")]
pub struct JsonError;

const MAX_DEPTH: usize = 900;

impl PyValue {
    /// `dict.get(key)`.
    pub fn get(&self, key: &str) -> Option<&PyValue> {
        match self {
            PyValue::Dict(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The `str`, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PyValue::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            PyValue::None => false,
            PyValue::Bool(b) => *b,
            PyValue::Int(i) => i != "0",
            PyValue::Float(f) => *f != 0.0,
            PyValue::Str(s) => !s.is_empty(),
            PyValue::List(l) => !l.is_empty(),
            PyValue::Dict(d) => !d.is_empty(),
        }
    }

    /// `int(value)` for a time claim: `None` where Python raises.
    pub fn to_int(&self) -> Option<i128> {
        match self {
            PyValue::Bool(b) => Some(i128::from(*b)),
            PyValue::Int(i) => i.parse().ok(),
            PyValue::Float(f) if f.is_finite() => Some(f.trunc() as i128),
            PyValue::Str(s) => copilot_core::config::python_int(s).map(i128::from),
            _ => None,
        }
    }

    /// `str(value)` (what an f-string prints).
    pub fn py_str(&self) -> String {
        match self {
            PyValue::Str(s) => s.clone(),
            other => other.py_repr(),
        }
    }

    /// `repr(value)`.
    pub fn py_repr(&self) -> String {
        match self {
            PyValue::None => "None".into(),
            PyValue::Bool(true) => "True".into(),
            PyValue::Bool(false) => "False".into(),
            PyValue::Int(i) => i.clone(),
            PyValue::Float(f) => float_repr(*f),
            PyValue::Str(s) => str_repr(s),
            PyValue::List(items) => {
                let inner: Vec<String> = items.iter().map(PyValue::py_repr).collect();
                format!("[{}]", inner.join(", "))
            }
            PyValue::Dict(items) => {
                let inner: Vec<String> = items
                    .iter()
                    .map(|(k, v)| format!("{}: {}", str_repr(k), v.py_repr()))
                    .collect();
                format!("{{{}}}", inner.join(", "))
            }
        }
    }
}

/// `repr(float)`: the shortest round-trip digits, exponent form outside
/// `1e-4 <= |x| < 1e16`.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.into();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.into();
    }
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if f < 0.0 { "-" } else { "" };
    let decpt = exp + 1;
    if decpt <= -4 || decpt > 16 {
        let (first, rest) = digits.split_at(1);
        let frac = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{first}{frac}e{esign}{:02}", exp.unsigned_abs());
    }
    let len = digits.len() as i32;
    if decpt <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat((-decpt) as usize))
    } else if decpt >= len {
        format!("{sign}{digits}{}.0", "0".repeat((decpt - len) as usize))
    } else {
        let (int, frac) = digits.split_at(decpt as usize);
        format!("{sign}{int}.{frac}")
    }
}

fn printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    !matches!(
        CodePointMapData::<GeneralCategory>::new().get(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::Surrogate
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::SpaceSeparator
    )
}

/// `repr(str)`.
pub fn str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if c.is_ascii() || printable(c) => out.push(c),
            c if (c as u32) <= 0xff => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) <= 0xffff => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(quote);
    out
}

/// `repr(bytes)`.
pub fn bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::from("b");
    out.push(quote as char);
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            q if q == quote => {
                out.push('\\');
                out.push(q as char);
            }
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push(quote as char);
    out
}

/// `json.detect_encoding` + `bytes.decode(…, "surrogatepass")`.
fn decode_text(b: &[u8]) -> Result<String, JsonError> {
    fn utf16(b: &[u8], be: bool) -> Result<String, JsonError> {
        if b.len() % 2 != 0 {
            return Err(JsonError);
        }
        let units = b.chunks_exact(2).map(|c| {
            if be {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        });
        Ok(char::decode_utf16(units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect())
    }
    fn utf32(b: &[u8], be: bool) -> Result<String, JsonError> {
        if b.len() % 4 != 0 {
            return Err(JsonError);
        }
        b.chunks_exact(4)
            .map(|c| {
                let v = if be {
                    u32::from_be_bytes([c[0], c[1], c[2], c[3]])
                } else {
                    u32::from_le_bytes([c[0], c[1], c[2], c[3]])
                };
                match v {
                    0xd800..=0xdfff => Ok(char::REPLACEMENT_CHARACTER),
                    v => char::from_u32(v).ok_or(JsonError),
                }
            })
            .collect()
    }
    if let Some(rest) = b.strip_prefix(&[0x00, 0x00, 0xfe, 0xff]) {
        return utf32(rest, true);
    }
    if let Some(rest) = b.strip_prefix(&[0xff, 0xfe, 0x00, 0x00]) {
        return utf32(rest, false);
    }
    if let Some(rest) = b.strip_prefix(&[0xfe, 0xff]) {
        return utf16(rest, true);
    }
    if let Some(rest) = b.strip_prefix(&[0xff, 0xfe]) {
        return utf16(rest, false);
    }
    if let Some(rest) = b.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return std::str::from_utf8(rest)
            .map(str::to_string)
            .map_err(|_| JsonError);
    }
    if b.len() >= 4 {
        if b[0] == 0 {
            return if b[1] != 0 {
                utf16(b, true)
            } else {
                utf32(b, true)
            };
        }
        if b[1] == 0 {
            return if b[2] != 0 || b[3] != 0 {
                utf16(b, false)
            } else {
                utf32(b, false)
            };
        }
    } else if b.len() == 2 {
        if b[0] == 0 {
            return utf16(b, true);
        }
        if b[1] == 0 {
            return utf16(b, false);
        }
    }
    std::str::from_utf8(b)
        .map(str::to_string)
        .map_err(|_| JsonError)
}

/// `json.loads(data)` for `bytes`.
pub fn loads_bytes(data: &[u8]) -> Result<PyValue, JsonError> {
    loads(&decode_text(data)?)
}

/// `json.loads(text)` for `str`.
pub fn loads(text: &str) -> Result<PyValue, JsonError> {
    if text.starts_with('\u{feff}') {
        return Err(JsonError);
    }
    let chars: Vec<char> = text.chars().collect();
    let mut p = Parser { s: &chars, i: 0 };
    p.ws();
    let value = p.value(0)?;
    p.ws();
    if p.i != chars.len() {
        return Err(JsonError);
    }
    Ok(value)
}

struct Parser<'a> {
    s: &'a [char],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> bool {
        let n = lit.chars().count();
        if self.s.len() >= self.i + n && self.s[self.i..self.i + n].iter().copied().eq(lit.chars())
        {
            self.i += n;
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<PyValue, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError);
        }
        match self.peek().ok_or(JsonError)? {
            '"' => {
                self.i += 1;
                self.string().map(PyValue::Str)
            }
            '{' => {
                self.i += 1;
                self.object(depth)
            }
            '[' => {
                self.i += 1;
                self.array(depth)
            }
            'n' if self.eat("null") => Ok(PyValue::None),
            't' if self.eat("true") => Ok(PyValue::Bool(true)),
            'f' if self.eat("false") => Ok(PyValue::Bool(false)),
            'N' if self.eat("NaN") => Ok(PyValue::Float(f64::NAN)),
            'I' if self.eat("Infinity") => Ok(PyValue::Float(f64::INFINITY)),
            '-' if self.eat("-Infinity") => Ok(PyValue::Float(f64::NEG_INFINITY)),
            '-' | '0'..='9' => self.number(),
            _ => Err(JsonError),
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some('0'..='9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<PyValue, JsonError> {
        let start = self.i;
        if self.peek() == Some('-') {
            self.i += 1;
        }
        match self.peek() {
            Some('0') => self.i += 1,
            Some('1'..='9') => {
                self.digits();
            }
            _ => return Err(JsonError),
        }
        let int_end = self.i;
        let mut is_float = false;
        if self.peek() == Some('.') && matches!(self.s.get(self.i + 1), Some('0'..='9')) {
            self.i += 1;
            self.digits();
            is_float = true;
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            let save = self.i;
            self.i += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                self.i = save;
            } else {
                is_float = true;
            }
        }
        let text: String = self.s[start..self.i].iter().collect();
        if is_float {
            return text
                .parse::<f64>()
                .map(PyValue::Float)
                .map_err(|_| JsonError);
        }
        debug_assert_eq!(int_end, self.i);
        let negative = text.starts_with('-');
        let magnitude = text.trim_start_matches('-');
        Ok(PyValue::Int(if negative && magnitude != "0" {
            format!("-{magnitude}")
        } else {
            magnitude.to_string()
        }))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let digits = self.s.get(self.i..self.i + 4).ok_or(JsonError)?;
        let mut v = 0u32;
        for d in digits {
            v = v * 16 + d.to_digit(16).ok_or(JsonError)?;
        }
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or(JsonError)?;
            self.i += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let e = self.peek().ok_or(JsonError)?;
                    self.i += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let mut code = self.hex4()?;
                            if (0xd800..=0xdbff).contains(&code)
                                && self.s.get(self.i) == Some(&'\\')
                                && self.s.get(self.i + 1) == Some(&'u')
                            {
                                let save = self.i;
                                self.i += 2;
                                let low = self.hex4()?;
                                if (0xdc00..=0xdfff).contains(&low) {
                                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                                } else {
                                    self.i = save;
                                }
                            }
                            out.push(char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
                        }
                        _ => return Err(JsonError),
                    }
                }
                c if (c as u32) < 0x20 => return Err(JsonError),
                c => out.push(c),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<PyValue, JsonError> {
        let mut items: Vec<(String, PyValue)> = Vec::new();
        self.ws();
        if self.peek() == Some('}') {
            self.i += 1;
            return Ok(PyValue::Dict(items));
        }
        loop {
            if self.peek() != Some('"') {
                return Err(JsonError);
            }
            self.i += 1;
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(':') {
                return Err(JsonError);
            }
            self.i += 1;
            self.ws();
            let value = self.value(depth + 1)?;
            match items.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => items.push((key, value)),
            }
            self.ws();
            match self.peek() {
                Some(',') => {
                    self.i += 1;
                    self.ws();
                }
                Some('}') => {
                    self.i += 1;
                    return Ok(PyValue::Dict(items));
                }
                _ => return Err(JsonError),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<PyValue, JsonError> {
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(']') {
            self.i += 1;
            return Ok(PyValue::List(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(',') => {
                    self.i += 1;
                    self.ws();
                }
                Some(']') => {
                    self.i += 1;
                    return Ok(PyValue::List(items));
                }
                _ => return Err(JsonError),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_grammar() {
        assert_eq!(loads("NaN").map(|v| v.py_repr()).unwrap(), "nan");
        assert_eq!(loads(" -0 ").unwrap(), PyValue::Int("0".into()));
        assert_eq!(
            loads("123456789012345678901234567890").unwrap(),
            PyValue::Int("123456789012345678901234567890".into())
        );
        assert!(loads("01").is_err());
        assert!(loads("1.").is_err());
        assert!(loads("[1,]").is_err());
        assert!(loads("\"a\u{1}\"").is_err());
        assert_eq!(
            loads(r#"{"a":1,"b":2,"a":3}"#).unwrap().py_repr(),
            "{'a': 3, 'b': 2}"
        );
        assert_eq!(
            loads_bytes(b"\xef\xbb\xbf{}").unwrap(),
            PyValue::Dict(vec![])
        );
        assert!(loads("\u{feff}{}").is_err());
        let utf16: Vec<u8> = "{\"a\":1}"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(loads_bytes(&utf16).unwrap().py_repr(), "{'a': 1}");
    }

    #[test]
    fn python_reprs() {
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(1e15), "1000000000000000.0");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(0.00001), "1e-05");
        assert_eq!(float_repr(-1.5), "-1.5");
        assert_eq!(float_repr(123.456), "123.456");
        assert_eq!(float_repr(2.5e-300), "2.5e-300");
        assert_eq!(str_repr("b'c"), "\"b'c\"");
        assert_eq!(str_repr("a\"b'c"), "'a\"b\\'c'");
        assert_eq!(str_repr("\u{7f}\u{a0}é\u{200b}"), "'\\x7f\\xa0é\\u200b'");
        assert_eq!(bytes_repr(b"none"), "b'none'");
        assert_eq!(bytes_repr(b"\x00'"), "b\"\\x00'\"");
        let v = loads(r#"["a", 1, null, true, 1.5]"#).unwrap();
        assert_eq!(v.py_str(), "['a', 1, None, True, 1.5]");
    }
}
