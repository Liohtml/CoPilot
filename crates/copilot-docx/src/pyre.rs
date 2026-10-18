//! The handful of `re` operations docxtpl runs, on fancy-regex: `re.sub`
//! with a callable or a template (`\1`, `\g<1>`, Python's escapes, an
//! unmatched group as the empty string) and `re.search`. Patterns are
//! written in Rust's syntax with Python's `\s` spelled out
//! ([`PY_SPACE`]).

use fancy_regex::{Captures, Regex, RegexBuilder};

use crate::DocxError;

/// Python's `\s` for `str` patterns (`str.isspace`).
pub const PY_SPACE: &str = r"[\t\n\x0B\x0C\r\x1C-\x1F \x85\xA0\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]";

/// Compiles a pattern; `dotall` is `re.DOTALL`.
pub fn compile(pattern: &str, dotall: bool) -> Result<Regex, DocxError> {
    let pattern = pattern.replace(r"\s", PY_SPACE);
    let full = if dotall {
        format!("(?s){pattern}")
    } else {
        pattern
    };
    RegexBuilder::new(&full)
        .backtrack_limit(usize::MAX)
        .build()
        .map_err(|e| DocxError::Internal(format!("re.error: {e}")))
}

fn backtrack(e: fancy_regex::Error) -> DocxError {
    DocxError::Internal(format!("re: {e}"))
}

/// `re.sub(pattern, f, text)`.
pub fn sub_fn(
    re: &Regex,
    text: &str,
    mut f: impl FnMut(&Captures<'_, str>) -> Result<String, DocxError>,
) -> Result<String, DocxError> {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for caps in re.captures_iter(text) {
        let caps = caps.map_err(backtrack)?;
        let Some(m) = caps.get(0) else { continue };
        out.push_str(&text[last..m.start()]);
        out.push_str(&f(&caps)?);
        last = m.end();
    }
    out.push_str(&text[last..]);
    Ok(out)
}

/// `re.sub(pattern, f, text, count=1)`.
pub fn sub_fn_once(
    re: &Regex,
    text: &str,
    f: impl FnOnce(&Captures<'_, str>) -> Result<String, DocxError>,
) -> Result<String, DocxError> {
    match re.captures(text).map_err(backtrack)? {
        Some(caps) => {
            let Some(m) = caps.get(0) else {
                return Ok(text.to_string());
            };
            let mut out = String::with_capacity(text.len());
            out.push_str(&text[..m.start()]);
            out.push_str(&f(&caps)?);
            out.push_str(&text[m.end()..]);
            Ok(out)
        }
        None => Ok(text.to_string()),
    }
}

/// `re.sub(pattern, template, text)`.
pub fn sub(re: &Regex, template: &str, text: &str) -> Result<String, DocxError> {
    sub_fn(re, text, |caps| expand(template, caps))
}

/// `re.sub(pattern, template, text, count=1)`.
pub fn sub_once(re: &Regex, template: &str, text: &str) -> Result<String, DocxError> {
    sub_fn_once(re, text, |caps| expand(template, caps))
}

/// `re.search(pattern, text)`: the match's text.
pub fn search<'t>(re: &Regex, text: &'t str) -> Result<Option<&'t str>, DocxError> {
    Ok(re.find(text).map_err(backtrack)?.map(|m| m.as_str()))
}

/// `m.group(i)`: an unmatched group is `None`.
pub fn group<'t>(caps: &Captures<'t, str>, i: usize) -> Option<&'t str> {
    caps.get(i).map(|m| m.as_str())
}

/// `re._expand`: a replacement template as `re` compiles it.
pub fn expand(template: &str, caps: &Captures<'_, str>) -> Result<String, DocxError> {
    let bad = |m: String| DocxError::Internal(format!("re.error: {m}"));
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let Some(&n) = chars.get(i + 1) else {
            return Err(bad("bad escape (end of pattern)".into()));
        };
        i += 2;
        match n {
            '0'..='9' => {
                let mut digits = n.to_string();
                if let Some(&d) = chars.get(i) {
                    if d.is_ascii_digit() && n != '0' {
                        digits.push(d);
                        i += 1;
                    }
                }
                let g: usize = digits.parse().unwrap_or(0);
                if n == '0' {
                    out.push('\0');
                } else {
                    if g >= caps.len() {
                        return Err(bad(format!("invalid group reference {g}")));
                    }
                    out.push_str(group(caps, g).unwrap_or(""));
                }
            }
            'g' => {
                if chars.get(i) != Some(&'<') {
                    return Err(bad("missing <".into()));
                }
                let close = chars[i..].iter().position(|&c| c == '>');
                let Some(close) = close else {
                    return Err(bad("missing >, unterminated name".into()));
                };
                let name: String = chars[i + 1..i + close].iter().collect();
                i += close + 1;
                let g: usize = name
                    .parse()
                    .map_err(|_| bad(format!("bad character in group name '{name}'")))?;
                if g >= caps.len() {
                    return Err(bad(format!("invalid group reference {g}")));
                }
                out.push_str(group(caps, g).unwrap_or(""));
            }
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0c'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'v' => out.push('\x0b'),
            '\\' => out.push('\\'),
            c if c.is_ascii_alphabetic() => return Err(bad(format!("bad escape \\{c}"))),
            c => {
                out.push('\\');
                out.push(c);
            }
        }
    }
    Ok(out)
}
