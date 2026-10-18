//! `fnmatch.fnmatchcase(name, pattern)` of CPython 3.11: the pattern is read
//! as `fnmatch.translate` reads it (`*`, `?`, `[seq]`, `[!seq]`, an unclosed
//! `[` taken literally, empty ranges dropped, a class that ends up empty
//! never matching) and the whole name must match. `?` and `*` match any
//! character, line breaks included (`(?s:…)`).

/// One element of a translated pattern.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// `*` (consecutive stars are one).
    Star,
    /// `?` and the negated empty class `[!]`: any one character.
    Any,
    /// A literal character.
    Lit(char),
    /// A class: negated or not, its single characters and ranges.
    Class {
        negate: bool,
        ranges: Vec<(char, char)>,
    },
    /// An empty class (`[z-a]`): never matches.
    Never,
}

/// `fnmatch.translate`'s handling of `pat[i..j]` (the text between `[` and
/// `]`), returning the class's regex body (`stuff`) before negation.
fn class_stuff(pat: &[char], start: usize, j: usize) -> String {
    let mut i = start;
    let stuff: String = pat[i..j].iter().collect();
    let escape = |s: &str, hyphens: bool| -> String {
        let mut out = String::new();
        for c in s.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '-' if hyphens => out.push_str("\\-"),
                c => out.push(c),
            }
        }
        out
    };
    let mut body = if !stuff.contains('-') {
        escape(&stuff, false)
    } else {
        let mut chunks: Vec<String> = Vec::new();
        let mut k = if pat[i] == '!' { i + 2 } else { i + 1 };
        loop {
            let found = (k..j).find(|&x| pat[x] == '-');
            let Some(kk) = found else { break };
            chunks.push(pat[i..kk].iter().collect());
            i = kk + 1;
            k = kk + 3;
        }
        let chunk: String = pat[i..j].iter().collect();
        if !chunk.is_empty() {
            chunks.push(chunk);
        } else if let Some(last) = chunks.last_mut() {
            last.push('-');
        }
        // Remove empty ranges -- invalid in RE.
        let mut k = chunks.len();
        while k > 1 {
            k -= 1;
            let lo = chunks[k - 1].chars().last();
            let hi = chunks[k].chars().next();
            if let (Some(lo), Some(hi)) = (lo, hi) {
                if lo > hi {
                    let mut prev: Vec<char> = chunks[k - 1].chars().collect();
                    prev.pop();
                    let next: String = chunks[k].chars().skip(1).collect();
                    chunks[k - 1] = prev.into_iter().collect::<String>() + &next;
                    chunks.remove(k);
                }
            }
        }
        chunks
            .iter()
            .map(|s| escape(s, true))
            .collect::<Vec<_>>()
            .join("-")
    };
    // Escape set operations (&&, ~~ and ||).
    let mut escaped = String::new();
    for c in body.chars() {
        if matches!(c, '&' | '~' | '|') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    body = escaped;
    body
}

/// Parse a Python regex class body (as `class_stuff` writes it) into ranges.
fn class_token(stuff: &str) -> Token {
    if stuff.is_empty() {
        return Token::Never;
    }
    if stuff == "!" {
        return Token::Any;
    }
    let chars: Vec<char> = stuff.chars().collect();
    let (negate, mut pos) = match chars[0] {
        '!' => (true, 1),
        _ => (false, 0),
    };
    // `^` or `[` first is escaped by translate: a literal.
    let mut atoms: Vec<(char, bool)> = Vec::new(); // (char, is_raw_hyphen)
    while pos < chars.len() {
        match chars[pos] {
            '\\' if pos + 1 < chars.len() => {
                atoms.push((chars[pos + 1], false));
                pos += 2;
            }
            '-' => {
                atoms.push(('-', true));
                pos += 1;
            }
            c => {
                atoms.push((c, false));
                pos += 1;
            }
        }
    }
    let mut ranges = Vec::new();
    let mut idx = 0;
    while idx < atoms.len() {
        let (c, _) = atoms[idx];
        if idx + 2 < atoms.len() && atoms[idx + 1].1 {
            ranges.push((c, atoms[idx + 2].0));
            idx += 3;
        } else {
            ranges.push((c, c));
            idx += 1;
        }
    }
    Token::Class { negate, ranges }
}

fn translate(pattern: &str) -> Vec<Token> {
    let pat: Vec<char> = pattern.chars().collect();
    let n = pat.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let c = pat[i];
        i += 1;
        match c {
            '*' => {
                if out.last() != Some(&Token::Star) {
                    out.push(Token::Star);
                }
            }
            '?' => out.push(Token::Any),
            '[' => {
                let mut j = i;
                if j < n && pat[j] == '!' {
                    j += 1;
                }
                if j < n && pat[j] == ']' {
                    j += 1;
                }
                while j < n && pat[j] != ']' {
                    j += 1;
                }
                if j >= n {
                    out.push(Token::Lit('['));
                } else {
                    let stuff = class_stuff(&pat, i, j);
                    i = j + 1;
                    out.push(class_token(&stuff));
                }
            }
            c => out.push(Token::Lit(c)),
        }
    }
    out
}

fn matches_one(token: &Token, c: char) -> bool {
    match token {
        Token::Any => true,
        Token::Lit(l) => *l == c,
        Token::Class { negate, ranges } => {
            ranges.iter().any(|(lo, hi)| *lo <= c && c <= *hi) != *negate
        }
        Token::Never | Token::Star => false,
    }
}

fn match_from(tokens: &[Token], name: &[char]) -> bool {
    match tokens.split_first() {
        None => name.is_empty(),
        Some((Token::Star, rest)) => (0..=name.len()).any(|k| match_from(rest, &name[k..])),
        Some((t, rest)) => match name.split_first() {
            Some((c, tail)) if matches_one(t, *c) => match_from(rest, tail),
            _ => false,
        },
    }
}

/// `fnmatch.fnmatchcase(name, pattern)`.
pub fn fnmatchcase(name: &str, pattern: &str) -> bool {
    let tokens = translate(pattern);
    let chars: Vec<char> = name.chars().collect();
    match_from(&tokens, &chars)
}

#[cfg(test)]
mod tests {
    use super::fnmatchcase;

    #[test]
    fn matches_like_cpython() {
        // Recorded with CPython 3.11's fnmatch.fnmatchcase.
        let cases = [
            ("wazuh-alerts-4.x-2026.10.16", "wazuh-alerts-*", true),
            ("wazuh-alerts", "wazuh-alerts-*", false),
            ("Wazuh-alerts-1", "wazuh-alerts-*", false),
            ("a,b", "a,b", true),
            ("idx-1", "idx-?", true),
            ("idx-12", "idx-?", false),
            ("idx-1", "idx-[0-9]", true),
            ("idx-a", "idx-[0-9]", false),
            ("idx-a", "idx-[!0-9]", true),
            ("idx-]", "idx-[]]", true),
            ("idx-[", "idx-[", true),
            ("x", "[z-a]", false),
            ("x", "[!]", false),
            ("-", "[a-]", true),
            ("b", "[a-c-e]", true),
            ("-", "[a-c-e]", true),
            ("d", "[a-c-e]", false),
            ("a\nb", "a*b", true),
            ("a\nb", "a?b", true),
            ("\\", "[\\]", true),
            ("^", "[^]", true),
            ("&", "[&]", true),
            ("", "*", true),
            ("abc", "a**c", true),
            ("[!]", "[!]", true),
            ("x", "[!z-a]", true),
            ("b", "[!a-c]", false),
            ("-", "[!-]", false),
            ("a", "[--a]", true),
            ("-", "[--a]", true),
            (",", "[--a]", false),
            ("a]", "[!]]", false),
            ("]", "[!]]", false),
        ];
        for (name, pat, want) in cases {
            assert_eq!(fnmatchcase(name, pat), want, "{name:?} ~ {pat:?}");
        }
    }
}
