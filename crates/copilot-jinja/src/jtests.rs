//! Jinja2 3.1's built-in tests (`jinja2/tests.py`).

use std::rc::Rc;

use crate::callargs::{self, Sig};
use crate::error::{Error, Result};
use crate::filters::{FILTER_NAMES, FilterCx};
use crate::ops::{self, BinOp, CmpOp};
use crate::pyrepr;
use crate::unicode;
use crate::value::Value;

/// The tests' names.
pub const TEST_NAMES: &[&str] = &[
    "odd",
    "even",
    "divisibleby",
    "defined",
    "undefined",
    "filter",
    "test",
    "none",
    "boolean",
    "false",
    "true",
    "integer",
    "float",
    "lower",
    "upper",
    "string",
    "mapping",
    "number",
    "sequence",
    "iterable",
    "callable",
    "sameas",
    "escaped",
    "in",
    "==",
    "eq",
    "equalto",
    "!=",
    "ne",
    ">",
    "gt",
    "greaterthan",
    "ge",
    ">=",
    "<",
    "lt",
    "lessthan",
    "<=",
    "le",
];

/// Whether `name` is a test.
pub fn test_exists(name: &str) -> bool {
    TEST_NAMES.contains(&name)
}

/// Whether the test takes the environment first (never folded? it can be).
pub fn test_passes_env(name: &str) -> bool {
    matches!(name, "filter" | "test")
}

type Kwargs = Vec<(Rc<str>, Value)>;

fn bind(
    name: &str,
    pass: bool,
    params: &[&str],
    value: Value,
    args: Vec<Value>,
    kwargs: Kwargs,
) -> Result<Vec<Value>> {
    let mut all = Vec::with_capacity(args.len() + 2);
    if pass {
        all.push(Value::None);
    }
    all.push(value);
    all.extend(args);
    let sig = Sig {
        name,
        params,
        ..Sig::default()
    };
    let mut b = callargs::bind_sig(&sig, all, kwargs)?.args;
    if pass {
        b.remove(0);
    }
    Ok(b)
}

/// `operator.eq` and friends: two positional arguments, no keywords.
fn operator(name: &str, value: Value, args: Vec<Value>, kwargs: &Kwargs) -> Result<(Value, Value)> {
    if !kwargs.is_empty() {
        return Err(Error::type_error(format!(
            "{name}() takes no keyword arguments"
        )));
    }
    let n = args.len() + 1;
    if n != 2 {
        return Err(Error::type_error(format!(
            "{name} expected 2 arguments, got {n}"
        )));
    }
    Ok((value, args.into_iter().next().unwrap_or(Value::None)))
}

/// `a is b` as far as these values allow: singletons and equal scalars are
/// the same object (Python shares constants and small ints), containers
/// and objects only when they are the same one.
pub fn is_same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::None, Value::None) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Float(x), Value::Float(y)) => x.to_bits() == y.to_bits(),
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::Markup(x), Value::Markup(y)) => Rc::ptr_eq(x, y),
        (Value::StrEnum(x), Value::StrEnum(y)) => x.class == y.class && x.name == y.name,
        (Value::Tuple(x), Value::Tuple(y)) => Rc::ptr_eq(x, y) || (x.is_empty() && y.is_empty()),
        _ => ops::same_object(a, b),
    }
}

fn has_len(v: &Value) -> bool {
    match v {
        Value::Undefined(u) => !u.strict,
        _ => ops::len(v).is_ok(),
    }
}

/// `callable(v)`.
fn is_callable(v: &Value) -> bool {
    match v {
        Value::Undefined(_) => true,
        Value::Object(o) => matches!(
            o.type_name(),
            "Macro"
                | "builtin_function_or_method"
                | "method"
                | "function"
                | "type"
                | "Joiner"
                | "LoopContext"
                | "BlockReference"
        ),
        _ => false,
    }
}

/// Calls the test `name`.
pub fn call_test(
    cx: &FilterCx,
    name: &str,
    value: Value,
    args: Vec<Value>,
    kwargs: Kwargs,
) -> Result<Value> {
    let _ = cx;
    let b = |n: bool| Ok(Value::Bool(n));
    match name {
        "odd" | "even" => {
            let v = bind(
                if name == "odd" {
                    "test_odd"
                } else {
                    "test_even"
                },
                false,
                &["value"],
                value,
                args,
                kwargs,
            )?;
            let r = ops::binop(BinOp::Mod, &v[0], &Value::int(2))?;
            b(ops::eq(&r, &Value::int(if name == "odd" { 1 } else { 0 }))?)
        }
        "divisibleby" => {
            let v = bind(
                "test_divisibleby",
                false,
                &["value", "num"],
                value,
                args,
                kwargs,
            )?;
            let r = ops::binop(BinOp::Mod, &v[0], &v[1])?;
            b(ops::eq(&r, &Value::int(0))?)
        }
        "defined" | "undefined" => {
            let v = bind(
                if name == "defined" {
                    "test_defined"
                } else {
                    "test_undefined"
                },
                false,
                &["value"],
                value,
                args,
                kwargs,
            )?;
            b(v[0].is_undefined() == (name == "undefined"))
        }
        "filter" | "test" => {
            let v = bind(
                if name == "filter" {
                    "test_filter"
                } else {
                    "test_test"
                },
                true,
                &["env", "value"],
                value,
                args,
                kwargs,
            )?;
            ops::check_hashable(&v[0])?;
            let found = match &v[0] {
                Value::Str(s) | Value::Markup(s) => {
                    if name == "filter" {
                        FILTER_NAMES.contains(&&**s)
                    } else {
                        TEST_NAMES.contains(&&**s)
                    }
                }
                _ => false,
            };
            b(found)
        }
        "none" | "boolean" | "false" | "true" | "integer" | "float" | "string" | "mapping"
        | "number" | "sequence" | "iterable" | "escaped" => {
            let fname = format!("test_{name}");
            let v = bind(&fname, false, &["value"], value, args, kwargs)?;
            let x = &v[0];
            b(match name {
                "none" => matches!(x, Value::None),
                "boolean" => matches!(x, Value::Bool(_)),
                "false" => matches!(x, Value::Bool(false)),
                "true" => matches!(x, Value::Bool(true)),
                "integer" => matches!(x, Value::Int(_)),
                "float" => matches!(x, Value::Float(_)),
                "string" => x.is_str(),
                "mapping" => matches!(x, Value::Dict(_)),
                "number" => matches!(x, Value::Int(_) | Value::Float(_) | Value::Bool(_)),
                "sequence" => {
                    has_len(x)
                        && match x {
                            Value::Object(o) => crate::objects::is_subscriptable(o.as_ref()),
                            Value::None | Value::Bool(_) | Value::Int(_) | Value::Float(_) => false,
                            _ => true,
                        }
                }
                "iterable" => match ops::py_iter(x) {
                    Ok(_) => true,
                    Err(e) if e.kind == "TypeError" => false,
                    Err(e) => return Err(e),
                },
                _ => x.is_markup(),
            })
        }
        "lower" | "upper" => {
            let v = bind(
                if name == "lower" {
                    "test_lower"
                } else {
                    "test_upper"
                },
                false,
                &["value"],
                value,
                args,
                kwargs,
            )?;
            let s = pyrepr::str(&v[0])?;
            b(if name == "lower" {
                unicode::str_islower(&s)
            } else {
                unicode::str_isupper(&s)
            })
        }
        "callable" => {
            let mut all = vec![value];
            all.extend(args);
            let v = callargs::exactly_one("callable", all, &kwargs)?;
            b(is_callable(&v))
        }
        "sameas" => {
            let v = bind(
                "test_sameas",
                false,
                &["value", "other"],
                value,
                args,
                kwargs,
            )?;
            b(is_same(&v[0], &v[1]))
        }
        "in" => {
            let v = bind("test_in", false, &["value", "seq"], value, args, kwargs)?;
            b(ops::contains(&v[0], &v[1])?)
        }
        "==" | "eq" | "equalto" => {
            let (x, y) = operator("eq", value, args, &kwargs)?;
            b(ops::eq(&x, &y)?)
        }
        "!=" | "ne" => {
            let (x, y) = operator("ne", value, args, &kwargs)?;
            b(!ops::eq(&x, &y)?)
        }
        ">" | "gt" | "greaterthan" => {
            let (x, y) = operator("gt", value, args, &kwargs)?;
            b(ops::compare(CmpOp::Gt, &x, &y)?)
        }
        ">=" | "ge" => {
            let (x, y) = operator("ge", value, args, &kwargs)?;
            b(ops::compare(CmpOp::Ge, &x, &y)?)
        }
        "<" | "lt" | "lessthan" => {
            let (x, y) = operator("lt", value, args, &kwargs)?;
            b(ops::compare(CmpOp::Lt, &x, &y)?)
        }
        "<=" | "le" => {
            let (x, y) = operator("le", value, args, &kwargs)?;
            b(ops::compare(CmpOp::Le, &x, &y)?)
        }
        other => Err(Error::runtime(format!(
            "No test named {}.",
            pyrepr::str_repr(other)
        ))),
    }
}
