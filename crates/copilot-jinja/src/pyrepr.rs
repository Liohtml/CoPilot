//! `str()` and `repr()` as CPython 3.11 writes them.

use std::cell::RefCell;

use num_bigint_dig::BigInt;

use crate::error::{Error, Result};
use crate::value::Value;

/// `sys.get_int_max_str_digits()`.
pub const INT_MAX_STR_DIGITS: usize = 4300;

/// Nesting depth at which a recursive operation gives up, standing in for
/// Python's recursion limit.
pub const MAX_DEPTH: usize = 400;

thread_local! {
    static REPR_STACK: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// `str(v)`.
pub fn str(v: &Value) -> Result<String> {
    match v {
        Value::Str(s) | Value::Markup(s) => Ok(s.to_string()),
        Value::StrEnum(e) => Ok(format!("{}.{}", e.class, e.name)),
        Value::Undefined(u) => {
            if u.strict {
                Err(u.error())
            } else {
                Ok(String::new())
            }
        }
        Value::Object(o) => o.str(),
        _ => repr(v),
    }
}

/// `repr(v)`.
pub fn repr(v: &Value) -> Result<String> {
    match v {
        Value::None => Ok("None".into()),
        Value::Bool(true) => Ok("True".into()),
        Value::Bool(false) => Ok("False".into()),
        Value::Int(i) => int_str(i),
        Value::Float(f) => Ok(float_repr(*f)),
        Value::Str(s) => Ok(str_repr(s)),
        Value::Markup(s) => Ok(format!("Markup({})", str_repr(s))),
        Value::StrEnum(e) => Ok(format!("<{}.{}: {}>", e.class, e.name, str_repr(&e.value))),
        Value::List(items) => guarded(items.as_ptr() as usize, "[...]", || {
            let items = items.borrow().clone();
            Ok(format!("[{}]", join_reprs(&items)?))
        }),
        Value::Tuple(items) => {
            if items.len() == 1 {
                Ok(format!("({},)", repr(&items[0])?))
            } else {
                Ok(format!("({})", join_reprs(items)?))
            }
        }
        Value::Dict(d) => guarded(d.as_ptr() as usize, "{...}", || {
            let (entries, default_str) = {
                let d = d.borrow();
                (d.entries.clone(), d.default_str)
            };
            let mut parts = Vec::with_capacity(entries.len());
            for (k, v) in &entries {
                parts.push(format!("{}: {}", repr(k)?, repr(v)?));
            }
            let body = format!("{{{}}}", parts.join(", "));
            if default_str {
                Ok(format!("defaultdict(<class 'str'>, {body})"))
            } else {
                Ok(body)
            }
        }),
        Value::Undefined(_) => Ok("Undefined".into()),
        Value::Object(o) => o.repr(),
    }
}

/// `repr()` of each, joined by `", "`.
pub fn join_reprs(items: &[Value]) -> Result<String> {
    let mut parts = Vec::with_capacity(items.len());
    for item in items {
        parts.push(repr(item)?);
    }
    Ok(parts.join(", "))
}

/// Python's `Py_ReprEnter`: a container met again while it is being
/// printed reads `[...]` / `{...}`; nesting too deep is a `RecursionError`.
fn guarded(ptr: usize, cycle: &str, f: impl FnOnce() -> Result<String>) -> Result<String> {
    let entered = REPR_STACK.with(|s| {
        let mut s = s.borrow_mut();
        if s.contains(&ptr) {
            return Err(None);
        }
        if s.len() >= MAX_DEPTH {
            return Err(Some(Error::new(
                "RecursionError",
                "maximum recursion depth exceeded while getting the repr of an object",
            )));
        }
        s.push(ptr);
        Ok(())
    });
    match entered {
        Err(None) => return Ok(cycle.into()),
        Err(Some(e)) => return Err(e),
        Ok(()) => {}
    }
    let out = f();
    REPR_STACK.with(|s| {
        s.borrow_mut().pop();
    });
    out
}

/// `str(int)`, with Python's 4300-digit conversion limit.
pub fn int_str(i: &BigInt) -> Result<String> {
    let s = i.to_str_radix(10);
    let digits = s.trim_start_matches('-').len();
    if digits > INT_MAX_STR_DIGITS {
        return Err(Error::value_error(format!(
            "Exceeds the limit ({INT_MAX_STR_DIGITS} digits) for integer string conversion; \
             use sys.set_int_max_str_digits() to increase the limit"
        )));
    }
    Ok(s)
}

/// `repr(float)`: the shortest round-tripping digits, in exponent form
/// outside `1e-4 <= |f| < 1e16`.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.into();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.into();
    }
    let (digits, exp) = shortest_digits(f.abs());
    let sign = if f < 0.0 { "-" } else { "" };
    let decpt = exp + 1;
    if decpt <= -4 || decpt > 16 {
        let (first, rest) = digits.split_at(1);
        let frac = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{first}{frac}e{esign}{:02}", exp.unsigned_abs());
    }
    let len = digits.len() as i32;
    if decpt <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat((-decpt) as usize))
    } else if decpt >= len {
        format!("{sign}{digits}{}.0", "0".repeat((decpt - len) as usize))
    } else {
        let (int, frac) = digits.split_at(decpt as usize);
        format!("{sign}{int}.{frac}")
    }
}

/// The shortest round-tripping decimal digits of a positive finite float
/// and the exponent of the first digit.
pub fn shortest_digits(f: f64) -> (String, i32) {
    let sci = format!("{f:e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    (digits, exp)
}

/// `str.isprintable()` for one character.
pub fn printable(c: char) -> bool {
    crate::unicode::is_printable(c)
}

/// `repr(str)`.
pub fn str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if c.is_ascii() || printable(c) => out.push(c),
            c if (c as u32) <= 0xff => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) <= 0xffff => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_like_python() {
        for (f, s) in [
            (1e-5, "1e-05"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (123456789012345680.0, "1.2345678901234568e+17"),
            (-0.0, "-0.0"),
            (5e-324, "5e-324"),
            (0.1 + 0.2, "0.30000000000000004"),
            (2.5e-7, "2.5e-07"),
            (100.0, "100.0"),
        ] {
            assert_eq!(float_repr(f), s);
        }
    }

    #[test]
    fn containers() {
        let l = Value::list(vec![Value::int(1), Value::str("a"), Value::None]);
        assert_eq!(repr(&l).unwrap(), "[1, 'a', None]");
        let t = Value::tuple(vec![Value::int(1)]);
        assert_eq!(repr(&t).unwrap(), "(1,)");
        if let Value::List(items) = &l {
            items.borrow_mut().push(l.clone());
        }
        assert_eq!(repr(&l).unwrap(), "[1, 'a', None, [...]]");
    }
}
