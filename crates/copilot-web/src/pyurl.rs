//! URL and cookie text as Python's standard library and Starlette produce
//! and read it: `urllib.parse.quote` / `quote_plus` / `urlencode`, the
//! `Location` a `RedirectResponse` sends, and Starlette's `cookie_parser`.

/// `urllib.parse.quote(s, safe)`: UTF-8, unreserved characters and `safe`
/// kept, everything else `%XX` (upper case).
pub fn quote(s: &str, safe: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) || safe.as_bytes().contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `urllib.parse.quote_plus(s, safe="")`: spaces become `+`.
pub fn quote_plus(s: &str) -> String {
    quote(s, " ").replace(' ', "+")
}

/// `urllib.parse.urlencode(pairs)` (values already `str()`-ed).
pub fn urlencode(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The `Location` Starlette's `RedirectResponse(url)` sends:
/// `quote(url, safe=":/%#?=@[]!$&'()*+,;")`.
pub fn redirect_location(url: &str) -> String {
    quote(url, ":/%#?=@[]!$&'()*+,;")
}

/// `http.cookies._unquote`: a double-quoted value loses its quotes and its
/// `\ooo` / `\x` escapes.
fn cookie_unquote(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 2 || chars[0] != '"' || chars[chars.len() - 1] != '"' {
        return value.to_string();
    }
    let inner = &chars[1..chars.len() - 1];
    let mut out = String::new();
    let mut i = 0;
    while i < inner.len() {
        if inner[i] == '\\' && i + 1 < inner.len() {
            let octal = inner.get(i + 1..i + 4).filter(|d| {
                ('0'..='3').contains(&d[0]) && d[1..].iter().all(|c| ('0'..='7').contains(c))
            });
            if let Some(d) = octal {
                let code = d
                    .iter()
                    .fold(0u32, |acc, c| acc * 8 + (*c as u32 - '0' as u32));
                out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                i += 4;
            } else {
                out.push(inner[i + 1]);
                i += 2;
            }
        } else {
            out.push(inner[i]);
            i += 1;
        }
    }
    out
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Starlette's `cookie_parser(cookie_header)[name]`: chunks split on `;`, a
/// chunk without `=` is a nameless cookie, the last occurrence wins.
pub fn cookie(header: &str, name: &str) -> Option<String> {
    let mut found = None;
    for chunk in header.split(';') {
        let (key, value) = chunk.split_once('=').unwrap_or(("", chunk));
        let (key, value) = (py_strip(key), py_strip(value));
        if (!key.is_empty() || !value.is_empty()) && key == name {
            found = Some(cookie_unquote(value));
        }
    }
    found
}

/// A request header as Starlette reads it: the first occurrence, latin-1.
pub fn header_latin1(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .map(|v| v.as_bytes().iter().map(|b| char::from(*b)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_quoting() {
        assert_eq!(
            quote("Email a@b.c is not ok", "/"),
            "Email%20a%40b.c%20is%20not%20ok"
        );
        assert_eq!(quote_plus("openid profile email"), "openid+profile+email");
        assert_eq!(
            urlencode(&[("scope", "a b".into()), ("x", "ä/&".into())]),
            "scope=a+b&x=%C3%A4%2F%26"
        );
        assert_eq!(
            redirect_location("https://h/te nant/x?a=b%20c+d"),
            "https://h/te%20nant/x?a=b%20c+d"
        );
    }

    #[test]
    fn starlette_cookies() {
        assert_eq!(
            cookie("a=1; CF_Authorization=tok ; b=2", "CF_Authorization").as_deref(),
            Some("tok")
        );
        assert_eq!(
            cookie("CF_Authorization=1; CF_Authorization=2", "CF_Authorization").as_deref(),
            Some("2")
        );
        assert_eq!(cookie(r#"x="a\"b\101""#, "x").as_deref(), Some("a\"bA"));
        assert_eq!(cookie("nameless", "").as_deref(), Some("nameless"));
        assert_eq!(cookie("a=1", "b"), None);
    }
}
