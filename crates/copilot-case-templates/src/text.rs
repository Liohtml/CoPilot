//! The text handling of `template_suggestions.py`, as CPython's `re` and
//! `str` methods behave on it: `_tokenize` (`[a-z0-9]+` over `str.lower()`),
//! `_extract_mitre_ids` (`\bT\d{4}(?:\.\d{3})?\b`, `IGNORECASE`),
//! `_contains_phrase` (a token set, else `\b` + `\W+`-joined tokens + `\b`),
//! `_as_string_list` and `_flatten_values`.
//!
//! `\w`, `\d` and `\b` are Python's Unicode classes (`str.isalnum()` or `_`,
//! the decimal digits), not the `regex` crate's, so the patterns are matched
//! by hand.

use std::collections::BTreeSet;

use copilot_auth::pyvalue::PyValue;
use copilot_jinja::unicode::{is_decimal, is_space, is_word, lower, upper};

/// `str.strip()`.
pub fn strip(t: &str) -> &str {
    t.trim_matches(is_space)
}

/// `_tokenize(text)`: the runs of `[a-z0-9]` in `text.lower()`.
pub fn tokenize(text: &str) -> Vec<String> {
    let lowered = lower(text);
    let mut out = Vec::new();
    let mut current = String::new();
    for c in lowered.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            current.push(c);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// `\b` at `at` in `chars` (Python's: false in an empty string).
fn boundary(chars: &[char], at: usize) -> bool {
    if chars.is_empty() {
        return false;
    }
    let before = at > 0 && is_word(chars[at - 1]);
    let after = at < chars.len() && is_word(chars[at]);
    before != after
}

fn digits(chars: &[char], from: usize, n: usize) -> bool {
    from + n <= chars.len() && chars[from..from + n].iter().all(|c| is_decimal(*c))
}

/// `_MITRE_ID_PATTERN.findall(text)`, each match as `_normalize_mitre_id`
/// leaves it (`strip().upper()`), in the order found.
pub fn mitre_matches(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if matches!(chars[i], 'T' | 't') && boundary(&chars, i) && digits(&chars, i + 1, 4) {
            let j = i + 5;
            // The optional `.\d{3}` first, then without it (backtracking).
            let end = if j < chars.len()
                && chars[j] == '.'
                && digits(&chars, j + 1, 3)
                && boundary(&chars, j + 4)
            {
                Some(j + 4)
            } else if boundary(&chars, j) {
                Some(j)
            } else {
                None
            };
            if let Some(end) = end {
                let found: String = chars[i..end].iter().collect();
                out.push(upper(strip(&found)));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// `_extract_mitre_ids(text)`.
pub fn mitre_ids(text: &str) -> BTreeSet<String> {
    mitre_matches(text).into_iter().collect()
}

/// `_mitre_parent`: `T1059.001` → `T1059`.
pub fn mitre_parent(id: &str) -> Option<&str> {
    id.split_once('.').map(|(parent, _)| parent)
}

/// `_contains_phrase(corpus_tokens, corpus_text, phrase)`.
pub fn contains_phrase(tokens: &BTreeSet<String>, text: &str, phrase: &str) -> bool {
    let wanted: Vec<String> = tokenize(phrase)
        .into_iter()
        .filter(|t| t.chars().count() >= crate::suggest::MIN_TOKEN_LENGTH)
        .collect();
    match wanted.as_slice() {
        [] => false,
        [one] => tokens.contains(one),
        many => phrase_search(text, many),
    }
}

/// `re.search(r"\b" + r"\W+".join(map(re.escape, tokens)) + r"\b", text)`:
/// every token starts and ends with a word character, so `\W+` takes the
/// whole run of non-word characters between two of them.
fn phrase_search(text: &str, tokens: &[String]) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let token_chars: Vec<Vec<char>> = tokens.iter().map(|t| t.chars().collect()).collect();
    let starts_at =
        |at: usize, t: &[char]| at + t.len() <= chars.len() && chars[at..at + t.len()] == *t;
    for start in 0..chars.len() {
        if !boundary(&chars, start) || !starts_at(start, &token_chars[0]) {
            continue;
        }
        let mut at = start + token_chars[0].len();
        let mut ok = true;
        for t in &token_chars[1..] {
            let gap = chars[at..].iter().take_while(|c| !is_word(**c)).count();
            if gap == 0 || !starts_at(at + gap, t) {
                ok = false;
                break;
            }
            at += gap + t.len();
        }
        if ok && boundary(&chars, at) {
            return true;
        }
    }
    false
}

/// `_as_string_list(value)`.
pub fn as_string_list(value: &PyValue) -> Vec<String> {
    match value {
        PyValue::None => Vec::new(),
        PyValue::Str(t) => t
            .split([',', ';', '|'])
            .filter(|part| !strip(part).is_empty())
            .map(str::to_string)
            .collect(),
        PyValue::List(items) => items.iter().flat_map(as_string_list).collect(),
        other => vec![other.py_str()],
    }
}

/// `_flatten_values(value, out)`.
pub fn flatten_values(value: &PyValue, out: &mut Vec<String>) {
    match value {
        PyValue::None => {}
        PyValue::Dict(items) => {
            for (_, v) in items {
                flatten_values(v, out);
            }
        }
        PyValue::List(items) => {
            for v in items {
                flatten_values(v, out);
            }
        }
        other => out.push(other.py_str()),
    }
}

/// `list(dict.fromkeys(x.strip() for x in items if x.strip()))`.
pub fn dedupe_stripped(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let t = strip(item);
        if !t.is_empty() && !out.iter().any(|o| o == t) {
            out.push(t.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vectors {
        text: TextVectors,
    }

    #[derive(Deserialize)]
    struct TextVectors {
        texts: Vec<TextCase>,
        phrases: Vec<PhraseCase>,
        values: Vec<ValueCase>,
    }

    #[derive(Deserialize)]
    struct TextCase {
        text: String,
        tokens: Vec<String>,
        mitre: Vec<String>,
    }

    #[derive(Deserialize)]
    struct PhraseCase {
        corpus: String,
        phrase: String,
        matches: bool,
    }

    #[derive(Deserialize)]
    struct ValueCase {
        value: serde_json::Value,
        strings: Vec<String>,
        flat: Vec<String>,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("case_templates_vectors.json")).unwrap()
    }

    #[test]
    fn tokens_and_mitre_ids_are_python_s() {
        for case in vectors().text.texts {
            assert_eq!(tokenize(&case.text), case.tokens, "{:?}", case.text);
            let ids: Vec<String> = mitre_ids(&case.text).into_iter().collect();
            assert_eq!(ids, case.mitre, "{:?}", case.text);
        }
    }

    #[test]
    fn phrases_match_as_re_search_matches() {
        for case in vectors().text.phrases {
            let text = lower(&case.corpus);
            let tokens: BTreeSet<String> = tokenize(&text).into_iter().collect();
            assert_eq!(
                contains_phrase(&tokens, &text, &case.phrase),
                case.matches,
                "{:?} / {:?}",
                case.corpus,
                case.phrase
            );
        }
    }

    #[test]
    fn values_flatten_as_python_s() {
        for case in vectors().text.values {
            let value = copilot_auth::pyvalue::loads(&case.value.to_string()).unwrap();
            assert_eq!(as_string_list(&value), case.strings, "{}", case.value);
            let mut flat = Vec::new();
            flatten_values(&value, &mut flat);
            assert_eq!(flat, case.flat, "{}", case.value);
        }
    }
}
