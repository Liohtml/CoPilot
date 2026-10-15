//! `json.dumps(obj, sort_keys=True, indent=...)` as `tojson` calls it.

use crate::error::{Error, Result};
use crate::objects;
use crate::ops;
use crate::pyrepr;
use crate::value::Value;

/// How `indent` was given.
pub enum Indent {
    /// `None`: one line, `", "` and `": "`.
    None,
    /// A string (an int `n` is `n` spaces).
    Text(String),
}

fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

fn float_text(f: f64) -> String {
    if f.is_nan() {
        "NaN".into()
    } else if f.is_infinite() {
        if f > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    } else {
        pyrepr::float_repr(f)
    }
}

struct Encoder<'a> {
    indent: &'a Indent,
    stack: Vec<usize>,
}

impl Encoder<'_> {
    fn newline(&self, out: &mut String, level: usize) {
        if let Indent::Text(t) = self.indent {
            out.push('\n');
            for _ in 0..level {
                out.push_str(t);
            }
        }
    }

    fn enter(&mut self, id: usize) -> Result<()> {
        if self.stack.contains(&id) {
            return Err(Error::value_error("Circular reference detected"));
        }
        self.stack.push(id);
        Ok(())
    }

    fn key_text(&self, k: &Value) -> Result<String> {
        Ok(match k {
            Value::Str(_) | Value::Markup(_) | Value::StrEnum(_) => {
                k.as_str().unwrap_or_default().to_string()
            }
            Value::Float(f) => float_text(*f),
            Value::Bool(true) => "true".into(),
            Value::Bool(false) => "false".into(),
            Value::None => "null".into(),
            Value::Int(i) => pyrepr::int_str(i)?,
            other => {
                return Err(Error::type_error(format!(
                    "keys must be str, int, float, bool or None, not {}",
                    other.type_name()
                )));
            }
        })
    }

    fn encode(&mut self, v: &Value, out: &mut String, level: usize) -> Result<()> {
        ops::check_size(out.len())?;
        let item_sep = match self.indent {
            Indent::None => ", ",
            Indent::Text(_) => ",",
        };
        match v {
            Value::None => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Int(i) => out.push_str(&pyrepr::int_str(i)?),
            Value::Float(f) => out.push_str(&float_text(*f)),
            Value::Str(_) | Value::Markup(_) | Value::StrEnum(_) => {
                escape_into(out, v.as_str().unwrap_or_default())
            }
            Value::List(_) | Value::Tuple(_) => {
                self.encode_seq(v, ops::iterate(v)?, out, level, item_sep)?
            }
            Value::Object(_) if objects::as_tuple(v).is_some() => {
                let items = objects::as_tuple(v).unwrap_or_default();
                self.encode_seq(v, items, out, level, item_sep)?;
            }
            Value::Dict(d) => {
                let id = std::rc::Rc::as_ptr(d) as *const u8 as usize;
                let mut entries = d.borrow().entries.clone();
                if entries.is_empty() {
                    out.push_str("{}");
                    return Ok(());
                }
                self.enter(id)?;
                // `sorted(dct.items())`: by key, then value.
                let keys: Vec<Value> = entries
                    .iter()
                    .map(|(k, w)| Value::tuple(vec![k.clone(), w.clone()]))
                    .collect();
                let pairs: Vec<Value> = entries
                    .drain(..)
                    .map(|(k, w)| Value::tuple(vec![k, w]))
                    .collect();
                let sorted = ops::sort_by_keys(pairs, keys, false)?;
                out.push('{');
                self.newline(out, level + 1);
                for (i, pair) in sorted.iter().enumerate() {
                    let Value::Tuple(kv) = pair else { continue };
                    if i > 0 {
                        out.push_str(item_sep);
                        self.newline(out, level + 1);
                    }
                    let key = self.key_text(&kv[0])?;
                    escape_into(out, &key);
                    out.push_str(": ");
                    self.encode(&kv[1], out, level + 1)?;
                }
                self.newline(out, level);
                out.push('}');
                self.stack.pop();
            }
            other => {
                return Err(Error::type_error(format!(
                    "Object of type {} is not JSON serializable",
                    other.type_name()
                )));
            }
        }
        Ok(())
    }

    fn encode_seq(
        &mut self,
        v: &Value,
        items: Vec<Value>,
        out: &mut String,
        level: usize,
        sep: &str,
    ) -> Result<()> {
        if items.is_empty() {
            out.push_str("[]");
            return Ok(());
        }
        let id = match v {
            Value::List(l) => std::rc::Rc::as_ptr(l) as *const u8 as usize,
            Value::Tuple(t) => t.as_ptr() as usize,
            Value::Object(o) => std::rc::Rc::as_ptr(o) as *const u8 as usize,
            _ => 0,
        };
        self.enter(id)?;
        out.push('[');
        self.newline(out, level + 1);
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                out.push_str(sep);
                self.newline(out, level + 1);
            }
            self.encode(item, out, level + 1)?;
        }
        self.newline(out, level);
        out.push(']');
        self.stack.pop();
        Ok(())
    }
}

/// `json.dumps(v, sort_keys=True, indent=indent)`.
pub fn dumps(v: &Value, indent: &Indent) -> Result<String> {
    let mut out = String::new();
    let mut enc = Encoder {
        indent,
        stack: Vec::new(),
    };
    enc.encode(v, &mut out, 0)?;
    Ok(out)
}

/// `htmlsafe_json_dumps`.
pub fn htmlsafe_dumps(v: &Value, indent: &Indent) -> Result<String> {
    Ok(dumps(v, indent)?
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\'', "\\u0027"))
}
