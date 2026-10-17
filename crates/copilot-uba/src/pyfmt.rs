//! CPython's `str.format(**kwargs)` with `str` values — how provisioning and
//! rollback name the Graylog objects from UBA's templates
//! (`names["feed_stream"].format(source=…, tenant=…)`) — and `str.lower()`.
//!
//! Supported: literal text with `{{`/`}}`, a replacement field naming a
//! keyword, the `!s`/`!r`/`!a` conversions and a string format spec
//! (`[[fill]align][width][.precision][s]`). CPython's errors for a missing
//! keyword (`KeyError`), a positional field (`IndexError`), an unbalanced
//! brace, an unknown conversion or format code (`ValueError`) come with its
//! texts (pinned by `uba_vectors.json`). Attribute and index access in a
//! field name (`{tenant.upper}`, `{tenant[0]}`) — which no UBA template
//! uses — is refused as an unsupported template.

use copilot_auth::pyvalue::str_repr;
use copilot_upstream::py::PyExc;

/// `str.lower()`.
pub fn lower(s: &str) -> String {
    copilot_jinja::unicode::lower(s)
}

/// `ascii(value)` of a `str`.
fn ascii_repr(s: &str) -> String {
    let mut out = String::new();
    for c in str_repr(s).chars() {
        let n = u32::from(c);
        if c.is_ascii() {
            out.push(c);
        } else if n <= 0xff {
            out.push_str(&format!("\\x{n:02x}"));
        } else if n <= 0xffff {
            out.push_str(&format!("\\u{n:04x}"));
        } else {
            out.push_str(&format!("\\U{n:08x}"));
        }
    }
    out
}

/// `format(value, spec)` for a `str`.
fn format_str(value: &str, spec: &str) -> Result<String, PyExc> {
    let chars: Vec<char> = spec.chars().collect();
    let mut i = 0;
    let mut fill = ' ';
    let mut align: Option<char> = None;
    let is_align = |c: char| matches!(c, '<' | '>' | '^' | '=');
    if chars.len() >= 2 && is_align(chars[1]) {
        fill = chars[0];
        align = Some(chars[1]);
        i = 2;
    } else if !chars.is_empty() && is_align(chars[0]) {
        align = Some(chars[0]);
        i = 1;
    }
    if i < chars.len() && matches!(chars[i], '+' | '-' | ' ') {
        return Err(PyExc::ValueError(
            "Sign not allowed in string format specifier".into(),
        ));
    }
    if i < chars.len() && chars[i] == '#' {
        return Err(PyExc::ValueError(
            "Alternate form (#) not allowed in string format specifier".into(),
        ));
    }
    if i < chars.len() && chars[i] == '0' {
        if align.is_none() {
            fill = '0';
            align = Some('=');
        }
        i += 1;
    }
    let mut width = String::new();
    while i < chars.len() && chars[i].is_ascii_digit() {
        width.push(chars[i]);
        i += 1;
    }
    if i < chars.len() && matches!(chars[i], ',' | '_') {
        return Err(PyExc::ValueError(format!(
            "Cannot specify '{}' with 's'.",
            chars[i]
        )));
    }
    let mut precision: Option<usize> = None;
    if i < chars.len() && chars[i] == '.' {
        i += 1;
        let mut digits = String::new();
        while i < chars.len() && chars[i].is_ascii_digit() {
            digits.push(chars[i]);
            i += 1;
        }
        if digits.is_empty() {
            return Err(PyExc::ValueError(
                "Format specifier missing precision".into(),
            ));
        }
        precision = digits.parse().ok();
    }
    if i + 1 < chars.len() {
        return Err(PyExc::ValueError("Invalid format specifier".into()));
    }
    if i < chars.len() && chars[i] != 's' {
        return Err(PyExc::ValueError(format!(
            "Unknown format code '{}' for object of type 'str'",
            chars[i]
        )));
    }
    if align == Some('=') {
        return Err(PyExc::ValueError(
            "'=' alignment not allowed in string format specifier".into(),
        ));
    }
    let mut text: String = match precision {
        Some(p) => value.chars().take(p).collect(),
        None => value.to_string(),
    };
    let width: usize = width.parse().unwrap_or(0);
    let len = text.chars().count();
    if width > len {
        let pad = width - len;
        let fills = |n: usize| std::iter::repeat_n(fill, n).collect::<String>();
        text = match align.unwrap_or('<') {
            '>' => format!("{}{text}", fills(pad)),
            '^' => format!("{}{text}{}", fills(pad / 2), fills(pad - pad / 2)),
            _ => format!("{text}{}", fills(pad)),
        };
    }
    Ok(text)
}

fn index_error(n: usize) -> PyExc {
    PyExc::IndexError(format!(
        "Replacement index {n} out of range for positional args tuple"
    ))
}

/// One replacement field (the text between the braces).
fn field(body: &str, kwargs: &[(&str, &str)], auto: &mut usize) -> Result<String, PyExc> {
    let end = body.find(['!', ':']).unwrap_or(body.len());
    let name = &body[..end];
    let rest = &body[end..];
    let (conversion, spec) = match rest.strip_prefix('!') {
        Some(after) => {
            let mut it = after.chars();
            let conv = it.next().ok_or_else(|| {
                PyExc::ValueError("end of string while looking for conversion specifier".into())
            })?;
            let tail: String = it.collect();
            if !tail.is_empty() && !tail.starts_with(':') {
                return Err(PyExc::ValueError(
                    "expected ':' after conversion specifier".into(),
                ));
            }
            (Some(conv), tail.strip_prefix(':').unwrap_or("").to_string())
        }
        None => (None, rest.strip_prefix(':').unwrap_or("").to_string()),
    };
    let value: String = if name.is_empty() {
        let n = *auto;
        *auto += 1;
        return Err(index_error(n));
    } else if name.chars().all(|c| c.is_ascii_digit()) {
        return Err(index_error(name.parse().unwrap_or(usize::MAX)));
    } else if name.contains(['.', '[']) {
        return Err(PyExc::Other(
            "NotImplementedError",
            format!("unsupported replacement field {{{name}}}"),
        ));
    } else {
        kwargs
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| (*v).to_string())
            .ok_or_else(|| PyExc::key_error(name))?
    };
    let value = match conversion {
        None | Some('s') => value,
        Some('r') => str_repr(&value),
        Some('a') => ascii_repr(&value),
        Some(other) => {
            return Err(PyExc::ValueError(format!(
                "Unknown conversion specifier {other}"
            )));
        }
    };
    format_str(&value, &spec)
}

/// `template.format(**kwargs)`.
pub fn format(template: &str, kwargs: &[(&str, &str)]) -> Result<String, PyExc> {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut auto = 0;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '{' if chars.get(i + 1) == Some(&'{') => {
                out.push('{');
                i += 2;
            }
            '}' if chars.get(i + 1) == Some(&'}') => {
                out.push('}');
                i += 2;
            }
            '}' => {
                return Err(PyExc::ValueError(
                    "Single '}' encountered in format string".into(),
                ));
            }
            '{' => {
                if i + 1 == chars.len() {
                    return Err(PyExc::ValueError(
                        "Single '{' encountered in format string".into(),
                    ));
                }
                // The field runs to the matching '}' (nested braces counted).
                let mut depth = 1;
                let mut j = i + 1;
                while j < chars.len() {
                    match chars[j] {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                if j == chars.len() {
                    return Err(PyExc::ValueError(
                        "expected '}' before end of string".into(),
                    ));
                }
                let body: String = chars[i + 1..j].iter().collect();
                out.push_str(&field(&body, kwargs, &mut auto)?);
                i = j + 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> serde_json::Value {
        serde_json::from_str(include_str!("uba_vectors.json")).expect("vectors")
    }

    #[test]
    fn formats_like_cpython() {
        let doc = doc();
        let mut failures = Vec::new();
        for case in doc["formats"].as_array().expect("formats") {
            let template = case["template"].as_str().expect("template");
            let tenant = case["tenant"].as_str().expect("tenant");
            let got = format(template, &[("source", "WAZUH"), ("tenant", tenant)]);
            let ok = match (&got, case.get("ok"), case.get("error")) {
                (Ok(text), Some(want), _) => text == want.as_str().expect("ok"),
                (Err(e), None, Some(want)) => {
                    let class = match e {
                        PyExc::KeyError(_) => "KeyError",
                        PyExc::IndexError(_) => "IndexError",
                        PyExc::ValueError(_) => "ValueError",
                        _ => "other",
                    };
                    class == want[0] && e.text() == want[1]
                }
                _ => false,
            };
            if !ok {
                failures.push(format!("{template:?} {tenant:?}: {got:?} vs {case}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn lowers_like_cpython() {
        for case in doc()["lowers"].as_array().expect("lowers") {
            assert_eq!(
                lower(case["input"].as_str().expect("input")),
                case["lower"].as_str().expect("lower")
            );
        }
    }
}
