//! `xmltodict.unparse(input, pretty=True)` (xmltodict 1.0.4 over
//! `xml.sax.saxutils.XMLGenerator`) for the JSON the Wazuh API answers a
//! rule file with, as `convert_to_xml` uses it.
//!
//! - an element per key: a list repeats it, `None` is an empty element, a
//!   scalar is its text (`True`/`False` as `true`/`false`, any other value as
//!   `str()`); a dict's `@`-keys are attributes (`None` is `""`), `#text` the
//!   text written after the children, `#comment` comments, an empty list no
//!   element at all, `@xmlns` a dict of namespace declarations;
//! - `_validate_name` on every element and attribute name, and
//!   `_validate_comment`, with their `ValueError` texts;
//! - `XMLGenerator`'s output: `escape` (`&`, `>`, `<`), `quoteattr` (the
//!   three escapes, then `\n`, `\r`, `\t` as character references, and the
//!   quote chosen by what the value holds), no empty-element shorthand, tab
//!   indentation and `\n` line ends (`pretty=True`).
//!
//! Errors are the `ValueError` texts (`convert_to_xml` wraps them).

use serde_json::Value;

/// `str.isspace()` for one character: Unicode whitespace, plus the
/// information separators U+001C–U+001F that Python counts and Rust does
/// not.
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(py_isspace)
}

/// `_convert_value_to_string`: a `str` as it is, a `bool` as `true`/`false`,
/// anything else `str()`.
pub fn convert(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        other => copilot_wazuh::pyops::py_str(other),
    }
}

/// `_validate_name(value, kind)`.
fn validate_name(value: &str, kind: &str) -> Result<(), String> {
    if value.starts_with('?') || value.starts_with('!') {
        return Err(format!(
            "Invalid {kind} name: cannot start with \"?\" or \"!\""
        ));
    }
    if value.contains('<') || value.contains('>') {
        return Err(format!("Invalid {kind} name: \"<\" or \">\" not allowed"));
    }
    if value.contains('/') {
        return Err(format!("Invalid {kind} name: \"/\" not allowed"));
    }
    if value.contains('"') || value.contains('\'') {
        return Err(format!("Invalid {kind} name: quotes not allowed"));
    }
    if value.contains('=') {
        return Err(format!("Invalid {kind} name: \"=\" not allowed"));
    }
    if value.chars().any(py_isspace) {
        return Err(format!("Invalid {kind} name: whitespace not allowed"));
    }
    Ok(())
}

/// `_validate_comment(value)` for a `str`.
fn validate_comment(value: &str) -> Result<(), String> {
    if value.contains("--") {
        return Err("Comment text cannot contain '--'".into());
    }
    if value.ends_with('-') {
        return Err("Comment text cannot end with '-'".into());
    }
    Ok(())
}

/// `xml.sax.saxutils.escape`.
pub fn escape(data: &str) -> String {
    data.replace('&', "&amp;")
        .replace('>', "&gt;")
        .replace('<', "&lt;")
}

/// `xml.sax.saxutils.quoteattr`.
pub fn quoteattr(data: &str) -> String {
    let data = escape(data)
        .replace('\n', "&#10;")
        .replace('\r', "&#13;")
        .replace('\t', "&#9;");
    if data.contains('"') {
        if data.contains('\'') {
            format!("\"{}\"", data.replace('"', "&quot;"))
        } else {
            format!("'{data}'")
        }
    } else {
        format!("\"{data}\"")
    }
}

const INDENT: &str = "\t";
const NEWL: &str = "\n";
const ATTR_PREFIX: &str = "@";
const CDATA_KEY: &str = "#text";
const COMMENT_KEY: &str = "#comment";

/// An insertion-ordered dict assignment (`attrs[name] = value`).
fn set(attrs: &mut Vec<(String, String)>, name: String, value: String) {
    match attrs.iter_mut().find(|(k, _)| *k == name) {
        Some(slot) => slot.1 = value,
        None => attrs.push((name, value)),
    }
}

/// `_emit(key, value, …, pretty=True)`.
fn emit(key: &str, value: &Value, out: &mut String, depth: usize) -> Result<(), String> {
    if key == COMMENT_KEY {
        let comments: Vec<&Value> = match value {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        for comment in comments {
            if comment.is_null() {
                continue;
            }
            let text = convert(comment);
            if text.is_empty() {
                continue;
            }
            out.push_str(&INDENT.repeat(depth));
            validate_comment(&text)?;
            out.push_str(&format!("<!--{}-->", escape(&text)));
            out.push_str(NEWL);
        }
        return Ok(());
    }
    validate_name(key, "element")?;
    // A list is iterated; a str, a dict and every scalar is one item.
    let items: Vec<&Value> = match value {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    for (index, item) in items.into_iter().enumerate() {
        if depth == 0 && index > 0 {
            return Err("document with multiple roots".into());
        }
        let pairs: Vec<(String, Value)> = match item {
            Value::Null => Vec::new(),
            Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            Value::String(s) => vec![(CDATA_KEY.into(), Value::String(s.clone()))],
            other => vec![(CDATA_KEY.into(), Value::String(convert(other)))],
        };
        let mut cdata: Option<String> = None;
        let mut attrs: Vec<(String, String)> = Vec::new();
        let mut children: Vec<(String, Value)> = Vec::new();
        for (ik, iv) in pairs {
            if ik == CDATA_KEY {
                cdata = if iv.is_null() {
                    None
                } else {
                    Some(convert(&iv))
                };
                continue;
            }
            if let Some(stripped) = ik.strip_prefix(ATTR_PREFIX) {
                if ik == "@xmlns" {
                    if let Value::Object(ns) = &iv {
                        for (k, v) in ns {
                            validate_name(k, "attribute")?;
                            let attr = if k.is_empty() {
                                "xmlns".to_string()
                            } else {
                                format!("xmlns:{k}")
                            };
                            let text = if v.is_null() {
                                String::new()
                            } else {
                                convert(v)
                            };
                            set(&mut attrs, attr, text);
                        }
                        continue;
                    }
                }
                let text = if iv.is_null() {
                    String::new()
                } else {
                    convert(&iv)
                };
                let name = stripped.to_string();
                validate_name(&name, "attribute")?;
                set(&mut attrs, name, text);
                continue;
            }
            if matches!(&iv, Value::Array(a) if a.is_empty()) {
                continue;
            }
            children.push((ik, iv));
        }
        out.push_str(&INDENT.repeat(depth));
        out.push('<');
        out.push_str(key);
        for (name, text) in &attrs {
            out.push_str(&format!(" {name}={}", quoteattr(text)));
        }
        out.push('>');
        if !children.is_empty() {
            out.push_str(NEWL);
        }
        for (child_key, child_value) in &children {
            emit(child_key, child_value, out, depth + 1)?;
        }
        if let Some(text) = cdata.filter(|t| !t.is_empty()) {
            out.push_str(&escape(&text));
        }
        if !children.is_empty() {
            out.push_str(&INDENT.repeat(depth));
        }
        out.push_str(&format!("</{key}>"));
        if depth > 0 {
            out.push_str(NEWL);
        }
    }
    Ok(())
}

/// The XML declaration `startDocument` writes (and `convert_to_xml` removes).
pub const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";

/// `xmltodict.unparse({key: value}, pretty=True)`.
pub fn unparse(key: &str, value: &Value) -> Result<String, String> {
    let mut out = format!("{DECLARATION}\n");
    emit(key, value, &mut out, 0)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn escapes_and_quotes_as_saxutils() {
        assert_eq!(escape("a&b<c>"), "a&amp;b&lt;c&gt;");
        assert_eq!(quoteattr("x"), "\"x\"");
        assert_eq!(quoteattr("say \"hi\""), "'say \"hi\"'");
        assert_eq!(quoteattr("both ' and \""), "\"both ' and &quot;\"");
        assert_eq!(quoteattr("a\nb\tc\rd"), "\"a&#10;b&#9;c&#13;d\"");
    }

    #[test]
    fn a_document_has_one_root() {
        assert_eq!(
            unparse("g", &json!([{"a": 1}, {"b": 2}])).unwrap_err(),
            "document with multiple roots"
        );
        assert_eq!(
            unparse("g", &json!({"a": 1})).unwrap(),
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<g>\n\t<a>1</a>\n</g>"
        );
    }

    #[test]
    fn python_whitespace() {
        assert!(py_isspace('\u{1c}') && py_isspace('\u{85}') && py_isspace(' '));
        assert!(!py_isspace('\u{180e}') && !py_isspace('x'));
        assert_eq!(py_strip("\u{1f} x \n"), "x");
    }
}
