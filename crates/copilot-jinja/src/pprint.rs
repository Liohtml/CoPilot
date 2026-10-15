//! `pprint.pformat(obj)` (width 80, indent 1, sorted dicts).

use std::cmp::Ordering;

use crate::error::Result;
use crate::ops::{self, CmpOp};
use crate::pyrepr;
use crate::unicode;
use crate::value::Value;

const WIDTH: usize = 80;

/// `_safe_key`'s ordering: the values' own `<`, else the types' names.
fn safe_lt(a: &Value, b: &Value) -> bool {
    match ops::compare(CmpOp::Lt, a, b) {
        Ok(r) => r,
        Err(_) => {
            let ta = format!("<class '{}'>", a.type_name());
            let tb = format!("<class '{}'>", b.type_name());
            ta < tb
        }
    }
}

fn sorted_items(entries: &[(Value, Value)]) -> Vec<(Value, Value)> {
    let mut items = entries.to_vec();
    // `sorted(..., key=_safe_tuple)`: stable, by key then value.
    items.sort_by(|(ka, va), (kb, vb)| {
        if safe_lt(ka, kb) {
            Ordering::Less
        } else if safe_lt(kb, ka) {
            Ordering::Greater
        } else if safe_lt(va, vb) {
            Ordering::Less
        } else if safe_lt(vb, va) {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    });
    items
}

fn id_of(v: &Value) -> Option<usize> {
    match v {
        Value::List(l) => Some(std::rc::Rc::as_ptr(l) as *const u8 as usize),
        Value::Dict(d) => Some(std::rc::Rc::as_ptr(d) as *const u8 as usize),
        Value::Tuple(t) => Some(t.as_ptr() as usize),
        _ => None,
    }
}

fn recursion(v: &Value) -> String {
    format!(
        "<Recursion on {} with id={}>",
        v.type_name(),
        id_of(v).unwrap_or(0)
    )
}

/// `PrettyPrinter._safe_repr`.
fn safe_repr(v: &Value, context: &mut Vec<usize>) -> Result<String> {
    match v {
        Value::Dict(d) if !d.borrow().default_str => {
            let entries = d.borrow().entries.clone();
            if entries.is_empty() {
                return Ok("{}".into());
            }
            let id = id_of(v).unwrap_or(0);
            if context.contains(&id) {
                return Ok(recursion(v));
            }
            context.push(id);
            let mut parts = Vec::new();
            for (k, w) in sorted_items(&entries) {
                parts.push(format!(
                    "{}: {}",
                    safe_repr(&k, context)?,
                    safe_repr(&w, context)?
                ));
            }
            context.pop();
            Ok(format!("{{{}}}", parts.join(", ")))
        }
        Value::List(_) | Value::Tuple(_) => {
            let items = ops::iterate(v)?;
            let is_list = matches!(v, Value::List(_));
            if items.is_empty() {
                return Ok(if is_list { "[]".into() } else { "()".into() });
            }
            let id = id_of(v).unwrap_or(0);
            if context.contains(&id) {
                return Ok(recursion(v));
            }
            context.push(id);
            let mut parts = Vec::new();
            for it in &items {
                parts.push(safe_repr(it, context)?);
            }
            context.pop();
            Ok(if is_list {
                format!("[{}]", parts.join(", "))
            } else if parts.len() == 1 {
                format!("({},)", parts[0])
            } else {
                format!("({})", parts.join(", "))
            })
        }
        other => pyrepr::repr(other),
    }
}

struct Printer {
    out: String,
}

impl Printer {
    fn format(
        &mut self,
        v: &Value,
        indent: usize,
        allowance: usize,
        context: &mut Vec<usize>,
        level: usize,
    ) -> Result<()> {
        if let Some(id) = id_of(v) {
            if context.contains(&id) {
                self.out.push_str(&recursion(v));
                return Ok(());
            }
        }
        let rep = safe_repr(v, &mut context.clone())?;
        let max_width = WIDTH as isize - indent as isize - allowance as isize;
        if rep.chars().count() as isize > max_width {
            match v {
                Value::Dict(d) if !d.borrow().default_str => {
                    let id = id_of(v).unwrap_or(0);
                    context.push(id);
                    self.pprint_dict(v, indent, allowance, context, level + 1)?;
                    context.pop();
                    return Ok(());
                }
                Value::Dict(_) => {
                    let id = id_of(v).unwrap_or(0);
                    context.push(id);
                    self.pprint_default_dict(v, indent, allowance, context, level + 1)?;
                    context.pop();
                    return Ok(());
                }
                Value::List(_) | Value::Tuple(_) => {
                    let id = id_of(v).unwrap_or(0);
                    context.push(id);
                    let items = ops::iterate(v)?;
                    if matches!(v, Value::List(_)) {
                        self.out.push('[');
                        self.format_items(&items, indent, allowance + 1, context, level + 1)?;
                        self.out.push(']');
                    } else {
                        self.out.push('(');
                        let endchar = if items.len() == 1 { ",)" } else { ")" };
                        self.format_items(
                            &items,
                            indent,
                            allowance + endchar.len(),
                            context,
                            level + 1,
                        )?;
                        self.out.push_str(endchar);
                    }
                    context.pop();
                    return Ok(());
                }
                Value::Str(s) => {
                    self.pprint_str(s, indent, allowance, level + 1);
                    return Ok(());
                }
                _ => {}
            }
        }
        self.out.push_str(&rep);
        Ok(())
    }

    fn pprint_dict(
        &mut self,
        v: &Value,
        indent: usize,
        allowance: usize,
        context: &mut Vec<usize>,
        level: usize,
    ) -> Result<()> {
        self.out.push('{');
        let Value::Dict(d) = v else { return Ok(()) };
        let entries = d.borrow().entries.clone();
        if !entries.is_empty() {
            let items = sorted_items(&entries);
            self.format_dict_items(&items, indent, allowance + 1, context, level)?;
        }
        self.out.push('}');
        Ok(())
    }

    fn pprint_default_dict(
        &mut self,
        v: &Value,
        indent: usize,
        allowance: usize,
        context: &mut Vec<usize>,
        level: usize,
    ) -> Result<()> {
        let Value::Dict(d) = v else { return Ok(()) };
        if d.borrow().entries.is_empty() {
            self.out.push_str(&pyrepr::repr(v)?);
            return Ok(());
        }
        let indent = indent + "defaultdict".len() + 1;
        self.out.push_str(&format!(
            "defaultdict(<class 'str'>,\n{}",
            " ".repeat(indent)
        ));
        self.pprint_dict(v, indent, allowance + 1, context, level)?;
        self.out.push(')');
        Ok(())
    }

    fn format_dict_items(
        &mut self,
        items: &[(Value, Value)],
        indent: usize,
        allowance: usize,
        context: &mut Vec<usize>,
        level: usize,
    ) -> Result<()> {
        let indent = indent + 1;
        let delimnl = format!(",\n{}", " ".repeat(indent));
        let last_index = items.len().saturating_sub(1);
        for (i, (k, w)) in items.iter().enumerate() {
            let last = i == last_index;
            let rep = safe_repr(k, &mut context.clone())?;
            self.out.push_str(&rep);
            self.out.push_str(": ");
            let width = rep.chars().count();
            self.format(
                w,
                indent + width + 2,
                if last { allowance } else { 1 },
                context,
                level,
            )?;
            if !last {
                self.out.push_str(&delimnl);
            }
        }
        Ok(())
    }

    fn format_items(
        &mut self,
        items: &[Value],
        indent: usize,
        allowance: usize,
        context: &mut Vec<usize>,
        level: usize,
    ) -> Result<()> {
        let indent = indent + 1;
        let delimnl = format!(",\n{}", " ".repeat(indent));
        let n = items.len();
        for (i, it) in items.iter().enumerate() {
            let last = i + 1 == n;
            if i > 0 {
                self.out.push_str(&delimnl);
            }
            self.format(it, indent, if last { allowance } else { 1 }, context, level)?;
        }
        Ok(())
    }

    fn pprint_str(&mut self, s: &str, indent: usize, allowance: usize, level: usize) {
        if s.is_empty() {
            self.out.push_str(&pyrepr::str_repr(s));
            return;
        }
        let mut chunks: Vec<String> = Vec::new();
        let lines = unicode::splitlines(s, true);
        let (mut indent, mut allowance) = (indent, allowance);
        if level == 1 {
            indent += 1;
            allowance += 1;
        }
        let max_width = WIDTH as isize - indent as isize;
        let mut max_width1 = max_width;
        let mut last_rep = String::new();
        for (i, line) in lines.iter().enumerate() {
            let rep = pyrepr::str_repr(line);
            last_rep = rep.clone();
            if i == lines.len() - 1 {
                max_width1 -= allowance as isize;
            }
            if rep.chars().count() as isize <= max_width1 {
                chunks.push(rep);
            } else {
                // re.findall(r'\S*\s*', line), the empty last part dropped
                let mut parts: Vec<String> = Vec::new();
                let cs: Vec<char> = line.chars().collect();
                let mut j = 0;
                while j < cs.len() {
                    let start = j;
                    while j < cs.len() && !unicode::is_space(cs[j]) {
                        j += 1;
                    }
                    while j < cs.len() && unicode::is_space(cs[j]) {
                        j += 1;
                    }
                    parts.push(cs[start..j].iter().collect());
                }
                let mut max_width2 = max_width;
                let mut current = String::new();
                for (k, part) in parts.iter().enumerate() {
                    let candidate = format!("{current}{part}");
                    if k == parts.len() - 1 && i == lines.len() - 1 {
                        max_width2 -= allowance as isize;
                    }
                    if pyrepr::str_repr(&candidate).chars().count() as isize > max_width2 {
                        if !current.is_empty() {
                            chunks.push(pyrepr::str_repr(&current));
                        }
                        current = part.clone();
                    } else {
                        current = candidate;
                    }
                }
                if !current.is_empty() {
                    chunks.push(pyrepr::str_repr(&current));
                }
            }
        }
        if chunks.len() == 1 {
            self.out.push_str(&last_rep);
            return;
        }
        if level == 1 {
            self.out.push('(');
        }
        for (i, rep) in chunks.iter().enumerate() {
            if i > 0 {
                self.out.push('\n');
                self.out.push_str(&" ".repeat(indent));
            }
            self.out.push_str(rep);
        }
        if level == 1 {
            self.out.push(')');
        }
    }
}

/// `pprint.pformat(v)`.
pub fn pformat(v: &Value) -> Result<String> {
    let mut p = Printer { out: String::new() };
    p.format(v, 0, 0, &mut Vec::new(), 0)?;
    Ok(p.out)
}
