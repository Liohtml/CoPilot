//! The Python string semantics markdown-it-py leans on: `str.strip()`,
//! `str.isspace()`, `unicodedata` punctuation, and the character classes of
//! `markdown_it.common.utils`.

use crate::tables::{PUNCT_RANGES, PY_SPACE};

/// `ch.isspace()`.
pub(crate) fn is_py_space(c: char) -> bool {
    PY_SPACE.binary_search(&(c as u32)).is_ok()
}

/// `s.strip()`.
pub(crate) fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// `isStrSpace`: a space or a tab.
pub(crate) fn is_str_space(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// `isWhiteSpace`: Zs or `[\t\f\v\r\n]`.
pub(crate) fn is_white_space(c: char) -> bool {
    let code = c as u32;
    if (0x2000..=0x200A).contains(&code) {
        return true;
    }
    matches!(
        code,
        0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x20 | 0xA0 | 0x1680 | 0x202F | 0x205F | 0x3000
    )
}

/// `isPunctChar`: Unicode categories P* and S*.
pub(crate) fn is_punct_char(c: char) -> bool {
    let code = c as u32;
    PUNCT_RANGES
        .binary_search_by(|&(lo, hi)| {
            if hi < code {
                std::cmp::Ordering::Less
            } else if lo > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `isMdAsciiPunct`.
pub(crate) fn is_md_ascii_punct(c: char) -> bool {
    matches!(
        c,
        '!' | '"'
            | '#'
            | '$'
            | '%'
            | '&'
            | '\''
            | '('
            | ')'
            | '*'
            | '+'
            | ','
            | '-'
            | '.'
            | '/'
            | ':'
            | ';'
            | '<'
            | '='
            | '>'
            | '?'
            | '@'
            | '['
            | '\\'
            | ']'
            | '^'
            | '_'
            | '`'
            | '{'
            | '|'
            | '}'
            | '~'
    )
}

/// `normalizeReference`: trim, collapse `\s+` to one space, then
/// `.lower().upper()`.
pub(crate) fn normalize_reference(s: &str) -> String {
    let mut out = String::new();
    let mut in_space = false;
    for c in py_strip(s).chars() {
        if is_py_space(c) {
            in_space = true;
            continue;
        }
        if in_space {
            out.push(' ');
            in_space = false;
        }
        out.push(c);
    }
    out.to_lowercase().to_uppercase()
}

/// `escapeHtml`: `&`, `<`, `>` and `"`.
pub(crate) fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// `chars[a:b]` with Python's clamping.
pub(crate) fn slice(chars: &[char], a: usize, b: usize) -> String {
    let b = b.min(chars.len());
    if a >= b {
        return String::new();
    }
    chars[a..b].iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_classes() {
        assert!(is_py_space('\u{1c}') && is_py_space('\u{85}') && !is_py_space('\u{200b}'));
        assert_eq!(py_strip("\u{3000} a \n"), "a");
        assert!(is_punct_char('$') && is_punct_char('—') && is_punct_char('€'));
        assert!(!is_punct_char('a') && !is_punct_char(' '));
        assert_eq!(normalize_reference("  Foo \t\n bar "), "FOO BAR");
        assert_eq!(normalize_reference("ẞ"), "SS");
        assert_eq!(
            escape_html("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;'"
        );
    }
}
