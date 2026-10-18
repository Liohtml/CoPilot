//! Attribute and item access the way the sandbox does it
//! (`SandboxedEnvironment.getattr` / `getitem` / `call`), Python's own
//! subscripting, and the sandboxed `str.format`.

use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::error::{Error, Result};
use crate::methods;
use crate::objects::SliceObj;
use crate::ops;
use crate::pyrepr;
use crate::tables;
use crate::value::{StrEnum, Value};

/// What `hasattr` finds on a `StrictUndefined` (its other attributes raise).
const UNDEFINED_ATTRS: &[&str] = &[
    "__add__",
    "__aiter__",
    "__bool__",
    "__call__",
    "__class__",
    "__complex__",
    "__contains__",
    "__delattr__",
    "__dir__",
    "__div__",
    "__doc__",
    "__eq__",
    "__float__",
    "__floordiv__",
    "__format__",
    "__ge__",
    "__getattr__",
    "__getattribute__",
    "__getitem__",
    "__getstate__",
    "__gt__",
    "__hash__",
    "__init__",
    "__init_subclass__",
    "__int__",
    "__iter__",
    "__le__",
    "__len__",
    "__lt__",
    "__mod__",
    "__module__",
    "__mul__",
    "__ne__",
    "__neg__",
    "__new__",
    "__pos__",
    "__pow__",
    "__radd__",
    "__rdiv__",
    "__reduce__",
    "__reduce_ex__",
    "__repr__",
    "__rfloordiv__",
    "__rmod__",
    "__rmul__",
    "__rpow__",
    "__rsub__",
    "__rtruediv__",
    "__setattr__",
    "__sizeof__",
    "__slots__",
    "__str__",
    "__sub__",
    "__subclasshook__",
    "__truediv__",
    "_fail_with_undefined_error",
    "_undefined_exception",
    "_undefined_hint",
    "_undefined_message",
    "_undefined_name",
    "_undefined_obj",
];

fn builtin_attrs(v: &Value) -> &'static [&'static str] {
    match v {
        Value::None => tables::ATTRS_NONE,
        Value::Bool(_) => tables::ATTRS_BOOL,
        Value::Int(_) => tables::ATTRS_INT,
        Value::Float(_) => tables::ATTRS_FLOAT,
        Value::Str(_) => tables::ATTRS_STR,
        Value::Markup(_) => tables::ATTRS_MARKUP,
        Value::StrEnum(_) => tables::ATTRS_SEVERITY,
        Value::List(_) => tables::ATTRS_LIST,
        Value::Tuple(_) => tables::ATTRS_TUPLE,
        Value::Dict(d) => {
            if d.borrow().default_str {
                tables::ATTRS_DEFAULTDICT
            } else {
                tables::ATTRS_DICT
            }
        }
        Value::Undefined(_) => UNDEFINED_ATTRS,
        Value::Object(o) => o.attrs(),
    }
}

/// The outcome of Python's `getattr(obj, name)`.
enum Lookup {
    Found(Value),
    Missing,
}

fn lookup(obj: &Value, name: &str) -> Result<Lookup> {
    if let Value::Undefined(u) = obj {
        if UNDEFINED_ATTRS.contains(&name) {
            // `__class__` and friends exist; only their safety matters.
            return Ok(Lookup::Found(Value::None));
        }
        if name.starts_with("__") && name.ends_with("__") {
            return Ok(Lookup::Missing);
        }
        return Err(u.error());
    }
    if let Value::Object(o) = obj {
        if let Some(r) = o.getattr(obj, name) {
            return r.map(Lookup::Found);
        }
    } else if let Some(r) = methods::builtin_getattr(obj, name) {
        return r.map(Lookup::Found);
    }
    if builtin_attrs(obj).contains(&name) {
        if name.starts_with('_') {
            return Ok(Lookup::Found(Value::None));
        }
        return Err(Error::unsupported(format!(
            "The attribute {} of a {} value",
            pyrepr::str_repr(name),
            obj.type_name()
        )));
    }
    Ok(Lookup::Missing)
}

/// `is_internal_attribute` and the leading-underscore rule.
fn is_safe_attribute(obj: &Value, attr: &str) -> bool {
    if attr.starts_with('_') {
        return false;
    }
    match obj {
        Value::Object(o) => match o.type_name() {
            "type" => attr != "mro",
            "generator" => !matches!(attr, "gi_frame" | "gi_code"),
            _ => true,
        },
        _ => true,
    }
}

fn is_lookup_error(e: &Error) -> bool {
    matches!(
        e.kind,
        "TypeError" | "KeyError" | "IndexError" | "LookupError"
    )
}

/// `getattr_static(obj, name)` or `hasattr(obj, name)` succeeds.
pub fn has_attribute(obj: &Value, name: &str) -> Result<bool> {
    Ok(matches!(lookup(obj, name)?, Lookup::Found(_)))
}

/// `SandboxedEnvironment.getattr(obj, attribute)`.
pub fn getattr(obj: &Value, attribute: &str) -> Result<Value> {
    match lookup(obj, attribute)? {
        Lookup::Found(v) => {
            if is_safe_attribute(obj, attribute) {
                Ok(v)
            } else {
                Ok(Value::unsafe_undefined(obj, attribute))
            }
        }
        Lookup::Missing => match subscript(obj, &Value::str(attribute)) {
            Ok(v) => Ok(v),
            Err(e) if is_lookup_error(&e) => {
                Ok(Value::undefined_member(obj, Value::str(attribute)))
            }
            Err(e) => Err(e),
        },
    }
}

/// `SandboxedEnvironment.getitem(obj, argument)`.
pub fn getitem(obj: &Value, argument: &Value) -> Result<Value> {
    match subscript(obj, argument) {
        Ok(v) => Ok(v),
        Err(e) if is_lookup_error(&e) => {
            if argument.is_str() {
                let attr = pyrepr::str(argument)?;
                if let Lookup::Found(v) = lookup(obj, &attr)? {
                    let original = argument.as_str().unwrap_or_default();
                    return Ok(if is_safe_attribute(obj, original) {
                        v
                    } else {
                        Value::unsafe_undefined(obj, original)
                    });
                }
            }
            Ok(Value::undefined_member(obj, argument.clone()))
        }
        Err(e) => Err(e),
    }
}

fn not_subscriptable(v: &Value) -> Error {
    Error::type_error(format!("'{}' object is not subscriptable", v.type_name()))
}

/// The items `indices` select from a sequence of `len` items.
fn sliced<T: Clone>(items: &[T], sl: &SliceObj) -> Result<Vec<T>> {
    let n = items.len() as isize;
    let (start, stop, step) = ops::slice_indices(&sl.start, &sl.stop, &sl.step, n)?;
    let mut out = Vec::new();
    let mut i = start;
    if step > 0 {
        while i < stop {
            out.push(items[i as usize].clone());
            i += step;
        }
    } else {
        while i > stop {
            out.push(items[i as usize].clone());
            i += step;
        }
    }
    Ok(out)
}

fn seq_index(i: &num_bigint_dig::BigInt, len: usize) -> Option<usize> {
    let n = len as isize;
    let i = i.to_isize()?;
    let i = if i < 0 { i + n } else { i };
    (0..n).contains(&i).then_some(i as usize)
}

/// Python's `obj[key]` (a slice key is a [`SliceObj`]).
pub fn subscript(obj: &Value, key: &Value) -> Result<Value> {
    match obj {
        Value::Str(_) | Value::Markup(_) | Value::StrEnum(_) => {
            let s = obj.as_str().unwrap_or_default();
            let chars: Vec<char> = s.chars().collect();
            let wrap = |t: String| {
                if obj.is_markup() {
                    Value::markup(t)
                } else {
                    Value::str(t)
                }
            };
            if let Some(i) = ops::as_int(key) {
                return match seq_index(&i, chars.len()) {
                    Some(i) => Ok(wrap(chars[i].to_string())),
                    None => Err(Error::index("string index out of range")),
                };
            }
            if let Some(sl) = key.downcast::<SliceObj>() {
                return Ok(wrap(sliced(&chars, sl)?.into_iter().collect()));
            }
            Err(Error::type_error(format!(
                "string indices must be integers, not '{}'",
                key.type_name()
            )))
        }
        Value::List(l) => {
            if let Some(i) = ops::as_int(key) {
                let l = l.borrow();
                return match seq_index(&i, l.len()) {
                    Some(i) => Ok(l[i].clone()),
                    None => Err(Error::index("list index out of range")),
                };
            }
            if let Some(sl) = key.downcast::<SliceObj>() {
                let items = l.borrow().clone();
                return Ok(Value::list(sliced(&items, sl)?));
            }
            Err(Error::type_error(format!(
                "list indices must be integers or slices, not {}",
                key.type_name()
            )))
        }
        Value::Tuple(t) => {
            if let Some(i) = ops::as_int(key) {
                return match seq_index(&i, t.len()) {
                    Some(i) => Ok(t[i].clone()),
                    None => Err(Error::index("tuple index out of range")),
                };
            }
            if let Some(sl) = key.downcast::<SliceObj>() {
                return Ok(Value::tuple(sliced(t, sl)?));
            }
            Err(Error::type_error(format!(
                "tuple indices must be integers or slices, not {}",
                key.type_name()
            )))
        }
        Value::Dict(d) => {
            let found = d.borrow().get(key)?;
            match found {
                Some(v) => Ok(v),
                None => {
                    if d.borrow().default_str {
                        let v = Value::str("");
                        d.borrow_mut().set(key.clone(), v.clone())?;
                        return Ok(v);
                    }
                    Err(Error::key(pyrepr::repr(key)?))
                }
            }
        }
        Value::Undefined(u) => Err(u.error()),
        Value::Object(o) => match o.getitem(key) {
            Some(r) => r,
            None => Err(not_subscriptable(obj)),
        },
        _ => Err(not_subscriptable(obj)),
    }
}

/// The sandbox's `call`: `obj(*args, **kwargs)`.
pub fn call(obj: &Value, args: Vec<Value>, kwargs: Vec<(Rc<str>, Value)>) -> Result<Value> {
    match obj {
        Value::Undefined(u) => Err(u.error()),
        Value::Object(o) => match o.call(obj, args, kwargs) {
            Some(r) => r,
            None => Err(Error::type_error(format!(
                "'{}' object is not callable",
                obj.type_name()
            ))),
        },
        _ => Err(Error::type_error(format!(
            "'{}' object is not callable",
            obj.type_name()
        ))),
    }
}

// --- str.format ---------------------------------------------------------------------

struct Formatter {
    args: Vec<Value>,
    kwargs: FormatKwargs,
    escape: bool,
}

enum FormatKwargs {
    Pairs(Vec<(Rc<str>, Value)>),
    Mapping(Value),
}

fn get_integer(s: &[char]) -> Result<Option<usize>> {
    if s.is_empty() {
        return Ok(None);
    }
    let mut n: usize = 0;
    for c in s {
        let Some(d) = crate::unicode::decimal_value(*c) else {
            return Ok(None);
        };
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(d as usize))
            .ok_or_else(|| Error::value_error("Too many decimal digits in format string"))?;
    }
    Ok(Some(n))
}

impl Formatter {
    fn get_value(&self, key: &Value) -> Result<Value> {
        if let Value::Int(i) = key {
            let idx = i.to_usize();
            return match idx.and_then(|i| self.args.get(i)) {
                Some(v) => Ok(v.clone()),
                None => Err(Error::index("tuple index out of range")),
            };
        }
        let k = key.as_str().unwrap_or_default();
        match &self.kwargs {
            FormatKwargs::Pairs(p) => match p.iter().find(|(n, _)| &**n == k) {
                Some((_, v)) => Ok(v.clone()),
                None => Err(Error::key(pyrepr::str_repr(k))),
            },
            FormatKwargs::Mapping(m) => subscript(m, key),
        }
    }

    /// `get_field`: the object a field name refers to.
    fn get_field(&self, field_name: &str) -> Result<Value> {
        let c: Vec<char> = field_name.chars().collect();
        let first_end = c
            .iter()
            .position(|ch| *ch == '.' || *ch == '[')
            .unwrap_or(c.len());
        let first = &c[..first_end];
        let key = match get_integer(first)? {
            Some(i) => Value::int(i as i64),
            None => Value::str(first.iter().collect::<String>()),
        };
        let mut obj = self.get_value(&key)?;
        let mut i = first_end;
        while i < c.len() {
            let ch = c[i];
            i += 1;
            let (is_attr, name) = match ch {
                '.' => {
                    let start = i;
                    while i < c.len() && c[i] != '.' && c[i] != '[' {
                        i += 1;
                    }
                    (true, &c[start..i])
                }
                '[' => {
                    let start = i;
                    while i < c.len() && c[i] != ']' {
                        i += 1;
                    }
                    if i >= c.len() {
                        return Err(Error::value_error("Missing ']' in format string"));
                    }
                    let name = &c[start..i];
                    i += 1;
                    (false, name)
                }
                _ => {
                    return Err(Error::value_error(
                        "Only '.' or '[' may follow ']' in format field specifier",
                    ));
                }
            };
            if name.is_empty() {
                return Err(Error::value_error("Empty attribute in format string"));
            }
            let text: String = name.iter().collect();
            if is_attr {
                obj = getattr(&obj, &text)?;
            } else {
                let key = match get_integer(name)? {
                    Some(n) => Value::int(n as i64),
                    None => Value::str(text),
                };
                obj = getitem(&obj, &key)?;
            }
        }
        Ok(obj)
    }

    fn format_field(&self, value: &Value, spec: &str) -> Result<String> {
        if !self.escape {
            return crate::format::format_value(value, spec);
        }
        // EscapeFormatter
        let rv = if let Value::Markup(s) = value {
            if !spec.is_empty() {
                return Err(Error::value_error(
                    "Unsupported format specification for Markup.",
                ));
            }
            return Ok(s.to_string());
        } else {
            crate::format::format_value(value, spec)?
        };
        Ok(crate::markup::escape_str(&rv))
    }

    fn convert(&self, v: Value, conversion: Option<char>) -> Result<Value> {
        Ok(match conversion {
            None => v,
            Some('s') => Value::str(pyrepr::str(&v)?),
            Some('r') => Value::str(pyrepr::repr(&v)?),
            Some('a') => Value::str(crate::format::ascii_of(&pyrepr::repr(&v)?)),
            Some(c) => {
                return Err(Error::value_error(format!(
                    "Unknown conversion specifier {c}"
                )));
            }
        })
    }

    /// `Formatter._vformat`.
    fn vformat(&self, fmt: &str, depth: i32, auto: &mut Option<usize>) -> Result<String> {
        if depth < 0 {
            return Err(Error::value_error("Max string recursion exceeded"));
        }
        let c: Vec<char> = fmt.chars().collect();
        let mut out = String::new();
        let mut pos = 0;
        while pos < c.len() {
            // MarkupIterator_next
            let start = pos;
            let mut ch = '\0';
            let mut markup = false;
            while pos < c.len() {
                ch = c[pos];
                pos += 1;
                if ch == '{' || ch == '}' {
                    markup = true;
                    break;
                }
            }
            let at_end = pos >= c.len();
            let mut len = pos - start;
            if ch == '}' && markup && (at_end || c[pos] != '}') {
                return Err(Error::value_error(
                    "Single '}' encountered in format string",
                ));
            }
            if at_end && ch == '{' && markup {
                return Err(Error::value_error(
                    "Single '{' encountered in format string",
                ));
            }
            if markup && !at_end {
                if c[pos] == ch {
                    pos += 1;
                    markup = false;
                } else {
                    len -= 1;
                }
            }
            out.extend(&c[start..start + len]);
            ops::check_size(out.len())?;
            if !markup {
                continue;
            }
            // parse_field
            let name_start = pos;
            let mut term = '\0';
            while pos < c.len() {
                let x = c[pos];
                pos += 1;
                match x {
                    '{' => return Err(Error::value_error("unexpected '{' in field name")),
                    '[' => {
                        while pos < c.len() && c[pos] != ']' {
                            pos += 1;
                        }
                        continue;
                    }
                    '}' | ':' | '!' => {
                        term = x;
                        break;
                    }
                    _ => continue,
                }
            }
            let name_end = if term == '\0' { pos } else { pos - 1 };
            let mut field_name: String = c[name_start..name_end].iter().collect();
            let mut conversion = None;
            let mut spec = String::new();
            if term == '!' || term == ':' {
                let mut parse_spec = true;
                if term == '!' {
                    if pos >= c.len() {
                        return Err(Error::value_error(
                            "end of string while looking for conversion specifier",
                        ));
                    }
                    conversion = Some(c[pos]);
                    pos += 1;
                    if pos < c.len() {
                        let x = c[pos];
                        pos += 1;
                        if x == '}' {
                            parse_spec = false;
                        } else if x != ':' {
                            return Err(Error::value_error(
                                "expected ':' after conversion specifier",
                            ));
                        }
                    }
                }
                if parse_spec {
                    let spec_start = pos;
                    let mut count = 1;
                    let mut closed = false;
                    while pos < c.len() {
                        let x = c[pos];
                        pos += 1;
                        if x == '{' {
                            count += 1;
                        } else if x == '}' {
                            count -= 1;
                            if count == 0 {
                                spec = c[spec_start..pos - 1].iter().collect();
                                closed = true;
                                break;
                            }
                        }
                    }
                    if !closed {
                        return Err(Error::value_error("unmatched '{' in format spec"));
                    }
                }
            } else if term != '}' {
                return Err(Error::value_error("expected '}' before end of string"));
            }
            // Formatter._vformat's numbering.
            if field_name.is_empty() {
                let Some(n) = *auto else {
                    return Err(Error::value_error(
                        "cannot switch from manual field specification to automatic field numbering",
                    ));
                };
                field_name = n.to_string();
                *auto = Some(n + 1);
            } else if field_name.chars().all(crate::unicode::is_digit) {
                if auto.is_some_and(|n| n > 0) {
                    return Err(Error::value_error(
                        "cannot switch from manual field specification to automatic field numbering",
                    ));
                }
                *auto = None;
            }
            let obj = self.get_field(&field_name)?;
            let obj = self.convert(obj, conversion)?;
            let spec = self.vformat(&spec, depth - 1, auto)?;
            out.push_str(&self.format_field(&obj, &spec)?);
            ops::check_size(out.len())?;
        }
        Ok(out)
    }
}

fn run_format(recv: &Value, args: Vec<Value>, kwargs: FormatKwargs) -> Result<Value> {
    let fmt = recv.as_str().unwrap_or_default().to_string();
    let f = Formatter {
        args,
        kwargs,
        escape: recv.is_markup(),
    };
    let mut auto = Some(0);
    let out = f.vformat(&fmt, 2, &mut auto)?;
    Ok(match recv {
        Value::Markup(_) => Value::markup(out),
        Value::StrEnum(e) => str_enum_from_value(e, &out)?,
        _ => Value::str(out),
    })
}

/// `EnumClass(value)`.
fn str_enum_from_value(e: &StrEnum, value: &str) -> Result<Value> {
    match e.members.iter().find(|(_, v)| *v == value) {
        Some((n, v)) => Ok(Value::StrEnum(Rc::new(StrEnum {
            class: e.class,
            module: e.module,
            name: (*n).to_string(),
            value: (*v).to_string(),
            members: e.members,
        }))),
        None => Err(Error::value_error(format!(
            "{} is not a valid {}",
            pyrepr::str_repr(value),
            e.class
        ))),
    }
}

/// The sandbox's `str.format(*args, **kwargs)`.
pub fn str_format(recv: &Value, args: Vec<Value>, kwargs: Vec<(Rc<str>, Value)>) -> Result<Value> {
    run_format(recv, args, FormatKwargs::Pairs(kwargs))
}

/// The sandbox's `str.format_map(mapping)`.
pub fn str_format_map(recv: &Value, mapping: Value) -> Result<Value> {
    run_format(recv, Vec::new(), FormatKwargs::Mapping(mapping))
}

/// `PySlice_Unpack` + `PySlice_AdjustIndices` helper re-exported for
/// objects that slice.
pub fn slice_object(start: Value, stop: Value, step: Value) -> Value {
    Value::object(SliceObj { start, stop, step })
}
