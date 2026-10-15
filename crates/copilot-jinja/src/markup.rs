//! markupsafe 3.0: `escape`, `Markup.striptags` and `html.unescape`.

use crate::error::Result;
use crate::pyrepr;
use crate::tables;
use crate::value::Value;

/// `_escape_inner`.
pub fn escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '>' => out.push_str("&gt;"),
            '<' => out.push_str("&lt;"),
            '\'' => out.push_str("&#39;"),
            '"' => out.push_str("&#34;"),
            c => out.push(c),
        }
    }
    out
}

/// The text of `escape(v)`.
pub fn escape_value(v: &Value) -> Result<String> {
    match v {
        Value::Markup(s) => Ok(s.to_string()),
        Value::Str(s) => Ok(escape_str(s)),
        other => Ok(escape_str(&pyrepr::str(other)?)),
    }
}

/// `markupsafe.escape(v)`.
pub fn escape(v: &Value) -> Result<Value> {
    Ok(Value::markup(escape_value(v)?))
}

/// `Markup(v)`: an object with `__html__` is taken as is, anything else
/// through `str()`.
pub fn mark_safe(v: &Value) -> Result<Value> {
    match v {
        Value::Markup(_) => Ok(v.clone()),
        other => Ok(Value::markup(pyrepr::str(other)?)),
    }
}

/// `soft_str(v)`: a `str` stays as it is (a `Markup` stays `Markup`).
pub fn soft_str(v: &Value) -> Result<Value> {
    match v {
        Value::Str(_) | Value::Markup(_) => Ok(v.clone()),
        Value::StrEnum(_) => Ok(v.clone()),
        other => Ok(Value::str(pyrepr::str(other)?)),
    }
}

/// `Markup.striptags`.
pub fn striptags(s: &str) -> String {
    let mut value = s.to_string();
    while let Some(start) = value.find("<!--") {
        let Some(end) = value[start..].find("-->").map(|e| start + e) else {
            break;
        };
        value = format!("{}{}", &value[..start], &value[end + 3..]);
    }
    while let Some(start) = value.find('<') {
        let Some(end) = value[start..].find('>').map(|e| start + e) else {
            break;
        };
        value = format!("{}{}", &value[..start], &value[end + 1..]);
    }
    let joined = crate::unicode::split_whitespace(&value).join(" ");
    unescape(&joined)
}

fn html5(name: &str) -> Option<&'static str> {
    tables::HTML5_ENTITIES
        .binary_search_by(|(n, _)| (*n).cmp(name))
        .ok()
        .map(|i| tables::HTML5_ENTITIES[i].1)
}

/// `_replace_charref` for the text after `&`.
fn replace_charref(s: &str) -> String {
    if let Some(num) = s.strip_prefix('#') {
        let (digits, radix) = match num.strip_prefix(['x', 'X']) {
            Some(h) => (h, 16),
            None => (num, 10),
        };
        let digits = digits.trim_end_matches(';');
        let n = num_bigint_dig::BigInt::parse_bytes(digits.as_bytes(), radix)
            .and_then(|b| num_traits::ToPrimitive::to_u64(&b))
            .unwrap_or(u64::MAX);
        if let Ok(small) = u32::try_from(n) {
            if let Ok(i) = tables::INVALID_CHARREFS.binary_search_by_key(&small, |(k, _)| *k) {
                return tables::INVALID_CHARREFS[i].1.to_string();
            }
        }
        if (0xD800..=0xDFFF).contains(&n) || n > 0x10FFFF {
            return "\u{fffd}".into();
        }
        let n = n as u32;
        if tables::INVALID_CODEPOINTS.contains(&n) {
            return String::new();
        }
        return char::from_u32(n).map(String::from).unwrap_or_default();
    }
    if let Some(v) = html5(s) {
        return v.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    for x in (2..chars.len()).rev() {
        let prefix: String = chars[..x].iter().collect();
        if let Some(v) = html5(&prefix) {
            let rest: String = chars[x..].iter().collect();
            return format!("{v}{rest}");
        }
    }
    format!("&{s}")
}

/// `html.unescape`.
pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '&' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        // &(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)
        let j = i + 1;
        let mut end = None;
        if chars.get(j) == Some(&'#') {
            let hex = matches!(chars.get(j + 1), Some('x' | 'X'));
            let mut k = if hex { j + 2 } else { j + 1 };
            let digits_start = k;
            while k < chars.len()
                && (if hex {
                    chars[k].is_ascii_hexdigit()
                } else {
                    chars[k].is_ascii_digit()
                })
            {
                k += 1;
            }
            if k > digits_start {
                if chars.get(k) == Some(&';') {
                    k += 1;
                }
                end = Some(k);
            } else if hex {
                // `#x` without digits: `#` is excluded from the name form.
                end = None;
            }
        } else {
            let mut k = j;
            while k < chars.len()
                && k - j < 32
                && !matches!(
                    chars[k],
                    '\t' | '\n' | '\u{c}' | ' ' | '<' | '&' | '#' | ';'
                )
            {
                k += 1;
            }
            if k > j {
                if chars.get(k) == Some(&';') {
                    k += 1;
                }
                end = Some(k);
            }
        }
        match end {
            Some(e) => {
                let body: String = chars[j..e].iter().collect();
                out.push_str(&replace_charref(&body));
                i = e;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_like_python() {
        assert_eq!(
            unescape("a &amp; b &lt; &#39; &#x41; &copy &notit;"),
            "a & b < ' A © ¬it;"
        );
        assert_eq!(unescape("&#0;&#128;&#xD800;"), "\u{fffd}€\u{fffd}");
        assert_eq!(striptags("<p>a <b>b</b></p>   c &amp;"), "a b c &");
    }
}
