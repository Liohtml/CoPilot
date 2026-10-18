//! Python 3.11's character classes and case mappings, from the generated
//! [`crate::tables`].

use crate::tables;

fn in_ranges(table: &[(u32, u32)], c: char) -> bool {
    let n = c as u32;
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < n {
                std::cmp::Ordering::Less
            } else if lo > n {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn mapped(table: &'static [(u32, &'static str)], c: char) -> Option<&'static str> {
    table
        .binary_search_by_key(&(c as u32), |&(k, _)| k)
        .ok()
        .map(|i| table[i].1)
}

/// A character of Jinja's name token.
pub fn is_name_char(c: char) -> bool {
    in_ranges(tables::NAME_CHARS, c)
}

/// `c.isspace()`.
pub fn is_space(c: char) -> bool {
    in_ranges(tables::SPACE, c)
}

/// `c.isalpha()`.
pub fn is_alpha(c: char) -> bool {
    in_ranges(tables::ALPHA, c)
}

/// `c.isdecimal()` (and `\d`).
pub fn is_decimal(c: char) -> bool {
    in_ranges(tables::DECIMAL, c)
}

/// `c.isdigit()`.
pub fn is_digit(c: char) -> bool {
    in_ranges(tables::DIGIT, c)
}

/// `c.isnumeric()`.
pub fn is_numeric(c: char) -> bool {
    in_ranges(tables::NUMERIC, c)
}

/// `c.isalnum()`.
pub fn is_alnum(c: char) -> bool {
    is_alpha(c) || is_decimal(c) || is_digit(c) || is_numeric(c)
}

/// `\w`: alphanumeric or `_`.
pub fn is_word(c: char) -> bool {
    c == '_' || is_alnum(c)
}

/// Python's lowercase flag.
pub fn is_lower(c: char) -> bool {
    in_ranges(tables::LOWER, c)
}

/// Python's uppercase flag.
pub fn is_upper(c: char) -> bool {
    in_ranges(tables::UPPER, c)
}

/// General category Lt.
pub fn is_titlecase(c: char) -> bool {
    in_ranges(tables::TITLECASE, c)
}

/// Cased.
pub fn is_cased(c: char) -> bool {
    in_ranges(tables::CASED, c)
}

/// Case-ignorable.
pub fn is_case_ignorable(c: char) -> bool {
    in_ranges(tables::CASE_IGNORABLE, c)
}

/// `c.isprintable()`.
pub fn is_printable(c: char) -> bool {
    in_ranges(tables::PRINTABLE, c)
}

/// A line boundary of `str.splitlines()`.
pub fn is_linebreak(c: char) -> bool {
    in_ranges(tables::LINEBREAK, c)
}

/// `s.isidentifier()`.
pub fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if in_ranges(tables::XID_START, c) => {}
        _ => return false,
    }
    chars.all(|c| in_ranges(tables::XID_CONTINUE, c))
}

fn push_upper(out: &mut String, c: char) {
    match mapped(tables::UPPER_MAP, c) {
        Some(s) => out.push_str(s),
        None => out.push(c),
    }
}

fn push_title(out: &mut String, c: char) {
    match mapped(tables::TITLE_MAP, c) {
        Some(s) => out.push_str(s),
        None => push_upper(out, c),
    }
}

/// The lowercase of `chars[i]`, sigma's final form included.
fn push_lower(out: &mut String, chars: &[char], i: usize) {
    let c = chars[i];
    if c == '\u{3a3}' {
        out.push(final_sigma(chars, i));
        return;
    }
    match mapped(tables::LOWER_MAP, c) {
        Some(s) => out.push_str(s),
        None => out.push(c),
    }
}

/// CPython's `handle_capital_sigma`.
fn final_sigma(chars: &[char], i: usize) -> char {
    let mut j = i;
    let mut before = None;
    while j > 0 {
        j -= 1;
        if !is_case_ignorable(chars[j]) {
            before = Some(chars[j]);
            break;
        }
    }
    let mut is_final = before.is_some_and(is_cased);
    if is_final && i + 1 < chars.len() {
        let after = chars[i + 1..].iter().find(|c| !is_case_ignorable(**c));
        is_final = after.is_none_or(|c| !is_cased(*c));
    }
    if is_final { '\u{3c2}' } else { '\u{3c3}' }
}

/// `s.upper()`.
pub fn upper(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        push_upper(&mut out, c);
    }
    out
}

/// `s.lower()`.
pub fn lower(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    for i in 0..chars.len() {
        push_lower(&mut out, &chars, i);
    }
    out
}

/// `s.casefold()`.
pub fn casefold(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    for (i, c) in chars.iter().enumerate() {
        match mapped(tables::FOLD_MAP, *c) {
            Some(f) => out.push_str(f),
            // `casefold` has no final sigma: Σ folds to σ.
            None if *c == '\u{3a3}' => out.push('\u{3c3}'),
            None => push_lower(&mut out, &chars, i),
        }
    }
    out
}

/// `s.title()`.
pub fn title(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut previous_is_cased = false;
    for (i, c) in chars.iter().enumerate() {
        if previous_is_cased {
            push_lower(&mut out, &chars, i);
        } else {
            push_title(&mut out, *c);
        }
        previous_is_cased = is_cased(*c);
    }
    out
}

/// `s.capitalize()`.
pub fn capitalize(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    for (i, c) in chars.iter().enumerate() {
        if i == 0 {
            push_title(&mut out, *c);
        } else {
            push_lower(&mut out, &chars, i);
        }
    }
    out
}

/// `s.swapcase()`.
pub fn swapcase(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    for (i, c) in chars.iter().enumerate() {
        if is_upper(*c) {
            push_lower(&mut out, &chars, i);
        } else if is_lower(*c) {
            push_upper(&mut out, *c);
        } else {
            out.push(*c);
        }
    }
    out
}

/// `s.islower()`.
pub fn str_islower(s: &str) -> bool {
    let mut cased = false;
    for c in s.chars() {
        if is_upper(c) || is_titlecase(c) {
            return false;
        }
        if is_lower(c) {
            cased = true;
        }
    }
    cased
}

/// `s.isupper()`.
pub fn str_isupper(s: &str) -> bool {
    let mut cased = false;
    for c in s.chars() {
        if is_lower(c) || is_titlecase(c) {
            return false;
        }
        if is_upper(c) {
            cased = true;
        }
    }
    cased
}

/// `s.istitle()`.
pub fn str_istitle(s: &str) -> bool {
    let mut cased = false;
    let mut previous_is_cased = false;
    for c in s.chars() {
        if is_upper(c) || is_titlecase(c) {
            if previous_is_cased {
                return false;
            }
            previous_is_cased = true;
            cased = true;
        } else if is_lower(c) {
            if !previous_is_cased {
                return false;
            }
            previous_is_cased = true;
            cased = true;
        } else {
            previous_is_cased = false;
        }
    }
    cased
}

/// `s.split()` without arguments.
pub fn split_whitespace(s: &str) -> Vec<&str> {
    s.split(is_space).filter(|p| !p.is_empty()).collect()
}

/// `s.splitlines(keepends)`.
pub fn splitlines(s: &str, keepends: bool) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < chars.len() {
        if is_linebreak(chars[i]) {
            let mut end = i + 1;
            if chars[i] == '\r' && chars.get(i + 1) == Some(&'\n') {
                end += 1;
            }
            let line: String = if keepends {
                chars[start..end].iter().collect()
            } else {
                chars[start..i].iter().collect()
            };
            out.push(line);
            start = end;
            i = end;
        } else {
            i += 1;
        }
    }
    if start < chars.len() {
        out.push(chars[start..].iter().collect());
    }
    out
}

/// The decimal value of a `\d` character.
pub fn decimal_value(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        return Some(c as u32 - '0' as u32);
    }
    if !is_decimal(c) {
        return None;
    }
    let n = c as u32;
    let i = tables::DECIMAL_ZEROS.partition_point(|z| *z <= n);
    i.checked_sub(1).map(|i| n - tables::DECIMAL_ZEROS[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_mappings_follow_python() {
        assert_eq!(upper("ß"), "SS");
        assert_eq!(title("ß"), "Ss");
        assert_eq!(capitalize("ßa"), "Ssa");
        assert_eq!(lower("İ"), "i\u{307}");
        assert_eq!(lower("ΣΑΣ"), "σας");
        assert_eq!(casefold("Straße"), "strasse");
        assert_eq!(title("hello world-foo"), "Hello World-Foo");
        assert_eq!(title("they're"), "They'Re");
        assert_eq!(swapcase("Hello"), "hELLO");
        assert!(str_istitle("Hello World"));
        assert!(!str_istitle("Hello world"));
    }

    #[test]
    fn classes_follow_python() {
        assert!(is_space('\u{1c}'));
        assert!(is_space('\u{a0}'));
        assert!(!is_space('\u{200b}'));
        assert!(is_digit('²'));
        assert!(!is_decimal('²'));
        assert!(is_numeric('一'));
        assert_eq!(decimal_value('٣'), Some(3));
        assert!(is_identifier("_x1"));
        assert!(!is_identifier("1x"));
        assert_eq!(splitlines("a\r\nb\x0bc\n", false), vec!["a", "b", "c"]);
    }
}
