//! `jinja2.utils.urlize`.

use std::sync::OnceLock;

use regex::Regex;

use crate::markup::escape_str;
use crate::unicode;

fn http_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?ix)
            ^
            (
                (https?://|www\.)
                (([\w%-]+\.)+)?
                (
                    [a-z]{2,63}
                |
                    xn--[\w%]{2,59}
                )
            |
                ([\w%-]{2,63}\.)+
                (com|net|int|edu|gov|org|info|mil)
            |
                (https?://)
                (
                    (([0-9]{1,3})(\.[0-9]{1,3}){3})
                |
                    (\[([0-9a-f]{0,4}:){2}([0-9a-f]{0,4}:?){1,6}\])
                )
            )
            (?::[0-9]{1,5})?
            (?:[/?\#]\S*)?
            $",
        )
        .ok()
    })
    .as_ref()
}

fn email_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\S+@\w[\w.-]*\.\w+$").ok())
        .as_ref()
}

fn matches(re: Option<&Regex>, s: &str) -> bool {
    re.is_some_and(|r| r.is_match(s))
}

/// `urlize(text, trim_url_limit, rel, target, extra_schemes)` over the
/// already escaped `escaped` (`str(markupsafe.escape(text))`).
pub fn urlize(
    escaped: &str,
    trim_url_limit: Option<usize>,
    rel: Option<&str>,
    target: Option<&str>,
    extra_schemes: &[String],
) -> String {
    let trim = |x: &str| -> String {
        match trim_url_limit {
            Some(limit) if x.chars().count() > limit => {
                format!("{}...", x.chars().take(limit).collect::<String>())
            }
            _ => x.to_string(),
        }
    };
    // re.split(r"(\s+)", ...)
    let chars: Vec<char> = escaped.chars().collect();
    let mut words: Vec<String> = Vec::new();
    let mut i = 0;
    let mut cur = String::new();
    while i < chars.len() {
        if unicode::is_space(chars[i]) {
            words.push(std::mem::take(&mut cur));
            let mut ws = String::new();
            while i < chars.len() && unicode::is_space(chars[i]) {
                ws.push(chars[i]);
                i += 1;
            }
            words.push(ws);
        } else {
            cur.push(chars[i]);
            i += 1;
        }
    }
    words.push(cur);
    let rel_attr = rel
        .filter(|r| !r.is_empty())
        .map(|r| format!(" rel=\"{}\"", escape_str(r)))
        .unwrap_or_default();
    let target_attr = target
        .filter(|t| !t.is_empty())
        .map(|t| format!(" target=\"{}\"", escape_str(t)))
        .unwrap_or_default();
    for word in words.iter_mut() {
        let mut head = String::new();
        let mut middle = word.clone();
        let mut tail = String::new();
        // ^([(<]|&lt;)+
        loop {
            if middle.starts_with('(') || middle.starts_with('<') {
                head.push_str(&middle[..1]);
                middle = middle[1..].to_string();
            } else if middle.starts_with("&lt;") {
                head.push_str("&lt;");
                middle = middle[4..].to_string();
            } else {
                break;
            }
        }
        if middle.ends_with([')', '>', '.', ',', '\n']) || middle.ends_with("&gt;") {
            // ([)>.,\n]|&gt;)+$ — the leftmost start whose suffix is all tail tokens
            let m: Vec<char> = middle.chars().collect();
            let is_tail = |from: usize| -> bool {
                let mut j = from;
                let mut any = false;
                while j < m.len() {
                    if matches!(m[j], ')' | '>' | '.' | ',' | '\n') {
                        j += 1;
                    } else if m[j..].starts_with(&['&', 'g', 't', ';']) {
                        j += 4;
                    } else {
                        return false;
                    }
                    any = true;
                }
                any
            };
            if let Some(start) = (0..m.len()).find(|s| is_tail(*s)) {
                tail = m[start..].iter().collect();
                middle = m[..start].iter().collect();
            }
        }
        for (start_char, end_char) in [("(", ")"), ("<", ">"), ("&lt;", "&gt;")] {
            let start_count = middle.matches(start_char).count();
            if start_count <= middle.matches(end_char).count() {
                continue;
            }
            for _ in 0..start_count.min(tail.matches(end_char).count()) {
                if let Some(idx) = tail.find(end_char) {
                    let end_index = idx + end_char.len();
                    middle.push_str(&tail[..end_index]);
                    tail = tail[end_index..].to_string();
                }
            }
        }
        if matches(http_re(), &middle) {
            if middle.starts_with("https://") || middle.starts_with("http://") {
                middle = format!(
                    "<a href=\"{middle}\"{rel_attr}{target_attr}>{}</a>",
                    trim(&middle)
                );
            } else {
                middle = format!(
                    "<a href=\"https://{middle}\"{rel_attr}{target_attr}>{}</a>",
                    trim(&middle)
                );
            }
        } else if middle.starts_with("mailto:") && matches(email_re(), &middle[7..]) {
            middle = format!("<a href=\"{middle}\">{}</a>", &middle[7..]);
        } else if middle.contains('@')
            && !middle.starts_with("www.")
            && !middle.starts_with('@')
            && !middle.contains(':')
            && matches(email_re(), &middle)
        {
            middle = format!("<a href=\"mailto:{middle}\">{middle}</a>");
        } else {
            for scheme in extra_schemes {
                if middle != *scheme && middle.starts_with(scheme.as_str()) {
                    middle = format!("<a href=\"{middle}\"{rel_attr}{target_attr}>{middle}</a>");
                }
            }
        }
        *word = format!("{head}{middle}{tail}");
    }
    words.concat()
}
