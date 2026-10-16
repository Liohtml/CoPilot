//! CPython 3.11's `json.loads` error messages — what `requests`'
//! `Response.json()` and elasticsearch-py's deserializer put into the texts
//! that reach CoPilot's responses (`Expecting value: line 1 column 1 (char 0)`).
//!
//! The scanner follows the C accelerator (`_json.c`) the way
//! `copilot_web::pyjson` does for positions, and adds the message each
//! failure raises; `line`/`column` are computed as `JSONDecodeError` does.

/// `str(JSONDecodeError)` for `text`, or `None` when CPython parses it.
pub fn decode_error(text: &str) -> Option<String> {
    let s: Vec<char> = text.chars().collect();
    let start = ws(&s, 0);
    let (msg, pos) = match scan(&s, start) {
        Err(e) => e,
        Ok(end) => {
            let end = ws(&s, end);
            if end == s.len() {
                return None;
            }
            ("Extra data", end)
        }
    };
    let before = &s[..pos.min(s.len())];
    let line = before.iter().filter(|c| **c == '\n').count() + 1;
    let column = match before.iter().rposition(|c| *c == '\n') {
        Some(nl) => pos - nl,
        None => pos + 1,
    };
    Some(format!("{msg}: line {line} column {column} (char {pos})"))
}

type Scan = Result<usize, (&'static str, usize)>;

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

const EXPECTING_VALUE: &str = "Expecting value";

fn scan(s: &[char], i: usize) -> Scan {
    let Some(&c) = s.get(i) else {
        return Err((EXPECTING_VALUE, i));
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

fn scan_number(s: &[char], start: usize) -> Scan {
    let mut i = start;
    if s.get(i) == Some(&'-') {
        i += 1;
        if i >= s.len() {
            return Err((EXPECTING_VALUE, start));
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
        _ => return Err((EXPECTING_VALUE, start)),
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

const UNTERMINATED: &str = "Unterminated string starting at";
const BAD_UNICODE: &str = "Invalid \\uXXXX escape";

/// `scanstring_unicode` (strict): `begin` is the index after the quote.
fn scan_string(s: &[char], begin: usize) -> Scan {
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
                return Err(("Invalid control character at", next));
            }
            next += 1;
        }
        if next >= len {
            return Err((UNTERMINATED, quote));
        }
        if c == '"' {
            return Ok(next + 1);
        }
        next += 1;
        if next == len {
            return Err((UNTERMINATED, quote));
        }
        let e = s[next];
        if e != 'u' {
            end = next + 1;
            if !matches!(e, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') {
                return Err(("Invalid \\escape", end - 2));
            }
            continue;
        }
        next += 1;
        end = next + 4;
        if end >= len {
            return Err((BAD_UNICODE, next - 1));
        }
        let Some(high) = hex4(s, next) else {
            return Err((BAD_UNICODE, end - 5));
        };
        if (0xd800..0xdc00).contains(&high) && end + 6 < len && s[end] == '\\' && s[end + 1] == 'u'
        {
            if hex4(s, end + 2).is_none() {
                return Err((BAD_UNICODE, end + 1));
            }
            end += 6;
        }
    }
}

const PROPERTY_NAME: &str = "Expecting property name enclosed in double quotes";
const COMMA: &str = "Expecting ',' delimiter";

fn scan_object(s: &[char], i: usize) -> Scan {
    let mut i = ws(s, i);
    if s.get(i) == Some(&'}') {
        return Ok(i + 1);
    }
    loop {
        if s.get(i) != Some(&'"') {
            return Err((PROPERTY_NAME, i));
        }
        i = ws(s, scan_string(s, i + 1)?);
        if s.get(i) != Some(&':') {
            return Err(("Expecting ':' delimiter", i));
        }
        i = ws(s, i + 1);
        i = ws(s, scan(s, i)?);
        match s.get(i) {
            Some('}') => return Ok(i + 1),
            Some(',') => i = ws(s, i + 1),
            _ => return Err((COMMA, i)),
        }
    }
}

fn scan_array(s: &[char], i: usize) -> Scan {
    let mut i = ws(s, i);
    if s.get(i) == Some(&']') {
        return Ok(i + 1);
    }
    loop {
        i = ws(s, scan(s, i)?);
        match s.get(i) {
            Some(']') => return Ok(i + 1),
            Some(',') => i = ws(s, i + 1),
            _ => return Err((COMMA, i)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_match_cpython() {
        // Recorded with CPython 3.11's `json.loads`.
        let cases = [
            ("", "Expecting value: line 1 column 1 (char 0)"),
            ("<html>", "Expecting value: line 1 column 1 (char 0)"),
            ("  \n x", "Expecting value: line 2 column 2 (char 4)"),
            ("{\"a\": 1} x", "Extra data: line 1 column 10 (char 9)"),
            (
                "{a: 1}",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            (
                "{\"a\" 1}",
                "Expecting ':' delimiter: line 1 column 6 (char 5)",
            ),
            (
                "{\"a\": 1 \"b\"}",
                "Expecting ',' delimiter: line 1 column 9 (char 8)",
            ),
            (
                "{\"a\": 1,}",
                "Expecting property name enclosed in double quotes: line 1 column 9 (char 8)",
            ),
            ("[1, 2", "Expecting ',' delimiter: line 1 column 6 (char 5)"),
            ("[1,]", "Expecting value: line 1 column 4 (char 3)"),
            (
                "\"abc",
                "Unterminated string starting at: line 1 column 1 (char 0)",
            ),
            (
                "\"a\tb\"",
                "Invalid control character at: line 1 column 3 (char 2)",
            ),
            ("\"\\x\"", "Invalid \\escape: line 1 column 2 (char 1)"),
            (
                "\"\\u12\"",
                "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
            ),
        ];
        for (text, want) in cases {
            assert_eq!(decode_error(text).as_deref(), Some(want), "{text:?}");
        }
        assert_eq!(decode_error("{\"a\": [1, 2.5e3, null]}"), None);
        assert_eq!(decode_error(" NaN "), None);
    }
}
