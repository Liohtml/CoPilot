//! `textwrap.wrap` as the `wordwrap` filter uses it (`expand_tabs=False`,
//! `replace_whitespace=False`, `drop_whitespace=True`).

use crate::error::{Error, Result};
use crate::unicode;

/// `textwrap`'s whitespace: ASCII only.
fn is_ws(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ')
}

/// `[^\d\W]`
fn is_letter(c: char) -> bool {
    unicode::is_word(c) && !unicode::is_decimal(c)
}

/// `[\w!"'&.,?]`
fn is_word_punct(c: char) -> bool {
    unicode::is_word(c) || matches!(c, '!' | '"' | '\'' | '&' | '.' | ',' | '?')
}

/// `-{2,}\w` at `i`.
fn dashes_then_word(c: &[char], i: usize) -> Option<usize> {
    let mut j = i;
    while j < c.len() && c[j] == '-' {
        j += 1;
    }
    (j - i >= 2 && j < c.len() && unicode::is_word(c[j])).then_some(j)
}

/// `TextWrapper.wordsep_re.split(text)` without empty chunks.
fn split_hyphens(text: &str) -> Vec<String> {
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut p = 0;
    while p < c.len() {
        // whitespace run
        if is_ws(c[p]) {
            let s = p;
            while p < c.len() && is_ws(c[p]) {
                p += 1;
            }
            out.push(c[s..p].iter().collect());
            continue;
        }
        // em-dash between words
        if p > 0 && is_word_punct(c[p - 1]) {
            if let Some(end) = dashes_then_word(&c, p) {
                out.push(c[p..end].iter().collect());
                p = end;
                continue;
            }
        }
        // a word, possibly hyphenated: the shortest run of non-whitespace
        // after which one of the endings applies
        let s = p;
        let mut e = p + 1;
        let end = loop {
            // hyphenated word: -(?:(?<=lt{2}-)|(?<=lt-lt-))(?=lt-?lt)
            if e < c.len() && c[e] == '-' {
                let behind_two = e >= 2 && is_letter(c[e - 1]) && is_letter(c[e - 2]);
                let behind_alt =
                    e >= 3 && is_letter(c[e - 1]) && c[e - 2] == '-' && is_letter(c[e - 3]);
                let ahead = {
                    let a = e + 1;
                    match (c.get(a), c.get(a + 1), c.get(a + 2)) {
                        (Some(x), Some('-'), Some(y)) if is_letter(*x) && is_letter(*y) => true,
                        (Some(x), Some(y), _) => is_letter(*x) && is_letter(*y),
                        _ => false,
                    }
                };
                if (behind_two || behind_alt) && ahead {
                    break e + 1;
                }
            }
            // end of word
            if e >= c.len() || is_ws(c[e]) {
                break e;
            }
            // em-dash
            if is_word_punct(c[e - 1]) && dashes_then_word(&c, e).is_some() {
                break e;
            }
            e += 1;
        };
        out.push(c[s..end].iter().collect());
        p = end;
    }
    out
}

/// `wordsep_simple_re.split(text)` without empty chunks.
fn split_simple(text: &str) -> Vec<String> {
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut p = 0;
    while p < c.len() {
        let s = p;
        let ws = is_ws(c[p]);
        while p < c.len() && is_ws(c[p]) == ws {
            p += 1;
        }
        out.push(c[s..p].iter().collect());
    }
    out
}

fn blank(s: &str) -> bool {
    s.chars().all(unicode::is_space)
}

fn len(s: &str) -> usize {
    s.chars().count()
}

/// `textwrap.wrap(text, width, ...)`.
pub fn wrap(
    text: &str,
    width: i64,
    break_long_words: bool,
    break_on_hyphens: bool,
) -> Result<Vec<String>> {
    let chunks = if break_on_hyphens {
        split_hyphens(text)
    } else {
        split_simple(text)
    };
    if width <= 0 {
        return Err(Error::value_error(format!(
            "invalid width {width} (must be > 0)"
        )));
    }
    let width = width as usize;
    let mut chunks: Vec<String> = chunks.into_iter().rev().collect();
    let mut lines: Vec<String> = Vec::new();
    while !chunks.is_empty() {
        let mut cur_line: Vec<String> = Vec::new();
        let mut cur_len = 0;
        if chunks.last().is_some_and(|c| blank(c)) && !lines.is_empty() {
            chunks.pop();
        }
        while let Some(last) = chunks.last() {
            let l = len(last);
            if cur_len + l <= width {
                cur_len += l;
                cur_line.push(chunks.pop().unwrap_or_default());
            } else {
                break;
            }
        }
        if chunks.last().is_some_and(|c| len(c) > width) {
            let space_left = if width < 1 { 1 } else { width - cur_len };
            if break_long_words {
                let chunk: Vec<char> = chunks
                    .last()
                    .map(|c| c.chars().collect())
                    .unwrap_or_default();
                let mut end = space_left;
                if break_on_hyphens && chunk.len() > space_left {
                    let hyphen = chunk[..space_left.min(chunk.len())]
                        .iter()
                        .rposition(|c| *c == '-');
                    if let Some(h) = hyphen {
                        if h > 0 && chunk[..h].iter().any(|c| *c != '-') {
                            end = h + 1;
                        }
                    }
                }
                let end = end.min(chunk.len());
                cur_line.push(chunk[..end].iter().collect());
                if let Some(last) = chunks.last_mut() {
                    *last = chunk[end..].iter().collect();
                }
            } else if cur_line.is_empty() {
                cur_line.push(chunks.pop().unwrap_or_default());
            }
        }
        if cur_line.last().is_some_and(|c| blank(c)) {
            cur_line.pop();
        }
        if !cur_line.is_empty() {
            lines.push(cur_line.concat());
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_like_textwrap() {
        assert_eq!(
            wrap("a b c d e f g", 5, true, true).unwrap(),
            vec!["a b c", "d e f", "g"]
        );
        assert_eq!(
            wrap("hello-world foo", 8, true, true).unwrap(),
            vec!["hello-", "world", "foo"]
        );
        assert_eq!(
            wrap("abcdefghij", 4, true, true).unwrap(),
            vec!["abcd", "efgh", "ij"]
        );
    }
}
