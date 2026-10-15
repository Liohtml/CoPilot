//! HTML entities and backslash escapes (`common/utils.py`:
//! `replaceEntityPattern`, `unescapeAll`, `isValidEntityCode`).

use crate::tables::ENTITIES;

/// `entities[name]`.
pub(crate) fn lookup(name: &str) -> Option<&'static str> {
    ENTITIES
        .binary_search_by(|(n, _)| (*n).cmp(name))
        .ok()
        .map(|i| ENTITIES[i].1)
}

/// `isValidEntityCode`.
pub(crate) fn is_valid_entity_code(c: u64) -> bool {
    if (0xD800..=0xDFFF).contains(&c) {
        return false;
    }
    if (0xFDD0..=0xFDEF).contains(&c) {
        return false;
    }
    if (c & 0xFFFF) == 0xFFFF || (c & 0xFFFF) == 0xFFFE {
        return false;
    }
    if c <= 0x08 || c == 0x0B || (0x0E..=0x1F).contains(&c) || (0x7F..=0x9F).contains(&c) {
        return false;
    }
    c <= 0x10FFFF
}

/// The characters `UNESCAPE_ALL_RE`'s first alternative unescapes.
fn is_escapable(c: char) -> bool {
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

/// `replaceEntityPattern(match, name)`.
fn replace_entity(matched: &str, name: &str) -> String {
    if let Some(chars) = lookup(name) {
        return chars.to_string();
    }
    let code = if let Some(digits) = name.strip_prefix('#') {
        if let Some(hex) = digits.strip_prefix(['x', 'X']) {
            (!hex.is_empty() && hex.len() <= 8 && hex.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| u64::from_str_radix(hex, 16).ok())
                .flatten()
        } else {
            (!digits.is_empty() && digits.len() <= 8 && digits.chars().all(|c| c.is_ascii_digit()))
                .then(|| digits.parse::<u64>().ok())
                .flatten()
        }
    } else {
        None
    };
    match code {
        Some(c) if is_valid_entity_code(c) => char::from_u32(c as u32)
            .map(String::from)
            .unwrap_or_else(|| matched.to_string()),
        _ => matched.to_string(),
    }
}

/// `unescapeAll`: backslash escapes and entity references.
pub(crate) fn unescape_all(s: &str) -> String {
    if !s.contains('\\') && !s.contains('&') {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            if let Some(&next) = chars.get(i + 1) {
                if is_escapable(next) {
                    out.push(next);
                    i += 2;
                    continue;
                }
            }
        } else if c == '&' {
            // `&([a-z#][a-z0-9]{1,31});` (case-insensitive)
            if let Some(&first) = chars.get(i + 1) {
                if first.is_ascii_alphabetic() || first == '#' {
                    let mut j = i + 2;
                    while j < chars.len() && chars[j].is_ascii_alphanumeric() && j - (i + 2) < 32 {
                        j += 1;
                    }
                    let run = j - (i + 2);
                    if (1..=31).contains(&run) && chars.get(j) == Some(&';') {
                        let matched: String = chars[i..=j].iter().collect();
                        let name: String = chars[i + 1..j].iter().collect();
                        out.push_str(&replace_entity(&matched, &name));
                        i = j + 1;
                        continue;
                    }
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entities_and_escapes() {
        assert_eq!(lookup("amp"), Some("&"));
        assert_eq!(lookup("nope"), None);
        assert_eq!(
            unescape_all(r"a\*b &amp; &#65; &#x42; &bogus; \q"),
            r"a*b & A B &bogus; \q"
        );
        assert_eq!(unescape_all("&#0; &#xD800;"), "&#0; &#xD800;");
    }
}
