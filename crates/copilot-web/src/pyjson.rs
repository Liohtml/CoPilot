//! Where CPython's `json.loads` fails — the position FastAPI reports in a
//! `json_invalid` error (`loc: ["body", <pos>]`, and the 422's `field`).
//!
//! serde_json parses the body; this scanner only locates errors the way the
//! C accelerator (`_json.c`, Python 3.11) does, so a malformed body names the
//! same character from either backend. Positions are character indices into
//! the decoded text. `form_vectors.json` pins it against Python.
//!
//! Python also accepts `NaN`, `Infinity`, `-Infinity` and lone surrogate
//! escapes, which have no `serde_json::Value`; such a body is treated as
//! malformed at its first character (it never reaches a valid model anyway).

/// `json.loads(body)` on bytes: the decoded text, or `None` when the bytes
/// are not UTF-8 (Python's `UnicodeDecodeError` — FastAPI's 400 "There was an
/// error parsing the body"). A UTF-8 BOM is skipped (`utf-8-sig`).
pub fn decode(bytes: &[u8]) -> Option<&str> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    std::str::from_utf8(bytes).ok()
}

/// The error position of `text`, or `None` when CPython accepts it.
pub fn error_position(text: &str) -> Option<usize> {
    let s: Vec<char> = text.chars().collect();
    let start = ws(&s, 0);
    match scan(&s, start) {
        Err(pos) => Some(pos),
        Ok(end) => {
            let end = ws(&s, end);
            (end != s.len()).then_some(end)
        }
    }
}

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

fn ws(s: &[char], mut i: usize) -> usize {
    while i < s.len() && is_ws(s[i]) {
        i += 1;
    }
    i
}

fn starts_with(s: &[char], i: usize, lit: &str) -> bool {
    (i..).zip(lit.chars()).all(|(k, c)| s.get(k) == Some(&c))
}

/// `scan_once`: the end of the value at `i`, or the error position.
fn scan(s: &[char], i: usize) -> Result<usize, usize> {
    let Some(&c) = s.get(i) else {
        return Err(i);
    };
    match c {
        '"' => return scan_string(s, i + 1),
        '{' => return scan_object(s, i + 1),
        '[' => return scan_array(s, i + 1),
        'n' if starts_with(s, i, "null") => return Ok(i + 4),
        't' if starts_with(s, i, "true") => return Ok(i + 4),
        'f' if starts_with(s, i, "false") => return Ok(i + 5),
        'N' if starts_with(s, i, "NaN") => return Ok(i + 3),
        'I' if starts_with(s, i, "Infinity") => return Ok(i + 8),
        '-' if starts_with(s, i, "-Infinity") => return Ok(i + 9),
        _ => {}
    }
    scan_number(s, i)
}

fn digit(s: &[char], i: usize) -> bool {
    s.get(i).is_some_and(char::is_ascii_digit)
}

/// `_match_number_unicode`.
fn scan_number(s: &[char], start: usize) -> Result<usize, usize> {
    let mut i = start;
    if s.get(i) == Some(&'-') {
        i += 1;
        if i >= s.len() {
            return Err(start);
        }
    }
    match s.get(i) {
        Some('1'..='9') => {
            i += 1;
            while digit(s, i) {
                i += 1;
            }
        }
        Some('0') => i += 1,
        _ => return Err(start),
    }
    if s.get(i) == Some(&'.') && digit(s, i + 1) {
        i += 2;
        while digit(s, i) {
            i += 1;
        }
    }
    if i + 1 < s.len() && matches!(s[i], 'e' | 'E') {
        let e_start = i;
        i += 1;
        if i + 1 < s.len() && matches!(s[i], '-' | '+') {
            i += 1;
        }
        while digit(s, i) {
            i += 1;
        }
        if !digit(s, i - 1) {
            i = e_start;
        }
    }
    Ok(i)
}

fn hex4(s: &[char], from: usize) -> Option<u32> {
    let mut v = 0u32;
    for k in from..from + 4 {
        v = (v << 4) | s.get(k)?.to_digit(16)?;
    }
    Some(v)
}

/// `scanstring_unicode` (strict): `begin` is the index after the quote.
fn scan_string(s: &[char], begin: usize) -> Result<usize, usize> {
    let quote = begin - 1;
    let len = s.len();
    let mut end = begin;
    loop {
        let mut next = end;
        let mut c = '\0';
        while next < len {
            c = s[next];
            if c == '"' || c == '\\' {
                break;
            }
            if (c as u32) <= 0x1f {
                return Err(next);
            }
            next += 1;
        }
        if next >= len {
            return Err(quote);
        }
        if c == '"' {
            return Ok(next + 1);
        }
        // Backslash.
        next += 1;
        if next == len {
            return Err(quote);
        }
        let e = s[next];
        if e != 'u' {
            end = next + 1;
            if !matches!(e, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') {
                return Err(end - 2);
            }
            continue;
        }
        next += 1;
        end = next + 4;
        if end >= len {
            return Err(next - 1);
        }
        let Some(high) = hex4(s, next) else {
            return Err(end - 5);
        };
        if (0xd800..0xdc00).contains(&high) && end + 6 < len && s[end] == '\\' && s[end + 1] == 'u'
        {
            if hex4(s, end + 2).is_none() {
                return Err(end + 1);
            }
            end += 6;
        }
    }
}

/// `_parse_object_unicode`: `i` is the index after `{`.
fn scan_object(s: &[char], i: usize) -> Result<usize, usize> {
    let mut i = ws(s, i);
    if s.get(i) == Some(&'}') {
        return Ok(i + 1);
    }
    loop {
        if s.get(i) != Some(&'"') {
            return Err(i);
        }
        i = ws(s, scan_string(s, i + 1)?);
        if s.get(i) != Some(&':') {
            return Err(i);
        }
        i = ws(s, i + 1);
        i = ws(s, scan(s, i)?);
        match s.get(i) {
            Some('}') => return Ok(i + 1),
            Some(',') => i = ws(s, i + 1),
            _ => return Err(i),
        }
    }
}

/// `_parse_array_unicode`: `i` is the index after `[`.
fn scan_array(s: &[char], i: usize) -> Result<usize, usize> {
    let mut i = ws(s, i);
    if s.get(i) == Some(&']') {
        return Ok(i + 1);
    }
    loop {
        i = ws(s, scan(s, i)?);
        match s.get(i) {
            Some(']') => return Ok(i + 1),
            Some(',') => i = ws(s, i + 1),
            _ => return Err(i),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn positions_match_cpython() {
        let doc: Value = serde_json::from_str(include_str!("form_vectors.json")).unwrap();
        for case in doc["json_errors"].as_array().unwrap() {
            let text = case["doc"].as_str().unwrap();
            let bytes = text.as_bytes();
            let decoded = decode(bytes).unwrap();
            let expected = case["pos"].as_u64().map(|p| p as usize);
            assert_eq!(error_position(decoded), expected, "{text:?}");
        }
    }

    #[test]
    fn escapes() {
        assert_eq!(error_position(r#""\u12""#), Some(2));
        assert_eq!(error_position(r#""\u12x4""#), Some(2));
        assert_eq!(error_position(r#""\ud83d\u00""#), Some(8));
        assert_eq!(error_position("[1E+]"), Some(2));
        assert_eq!(error_position("1e5"), None);
        assert_eq!(error_position(r#""😀""#), None);
        assert_eq!(error_position(r#""\ud83d\uzz00" "#), Some(8));
        assert_eq!(error_position(r#""a\"b""#), None);
        assert_eq!(error_position("\"\\"), Some(0));
        assert_eq!(error_position("[1.5e+3, -0.0, 1E9]"), None);
        assert_eq!(error_position("1."), Some(1));
        assert_eq!(error_position("-x"), Some(0));
        assert!(decode(b"\xff").is_none());
    }
}
