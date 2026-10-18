//! Python's operators on [`Value`]s: truthiness, `==`, ordering, arithmetic,
//! `in`, `len()`, iteration and `sorted()`, with CPython 3.11's errors.

use std::cmp::Ordering;
use std::rc::Rc;

use num_bigint_dig::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};

use crate::error::{Error, Result};
use crate::value::{PyIter, Value};

/// The largest string, list or integer (in bytes, items or bits) an
/// operation may build. Python would try and fail with a `MemoryError`;
/// this engine refuses earlier, with the same exception.
pub const MAX_BUILD: usize = 64 * 1024 * 1024;

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `//`
    FloorDiv,
    /// `%`
    Mod,
    /// `**`
    Pow,
}

impl BinOp {
    /// The operator's spelling.
    pub fn symbol(self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::FloorDiv => "//",
            BinOp::Mod => "%",
            BinOp::Pow => "** or pow()",
        }
    }
}

/// A comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
}

impl CmpOp {
    /// The operator's spelling.
    pub fn symbol(self) -> &'static str {
        match self {
            CmpOp::Eq => "==",
            CmpOp::Ne => "!=",
            CmpOp::Lt => "<",
            CmpOp::Le => "<=",
            CmpOp::Gt => ">",
            CmpOp::Ge => ">=",
        }
    }
}

/// A number: `bool` and `int` are both integers.
#[derive(Debug, Clone)]
pub enum Num {
    /// `int` (or `bool`).
    Int(BigInt),
    /// `float`.
    Float(f64),
}

/// The value as a number, if it is one.
pub fn as_num(v: &Value) -> Option<Num> {
    match v {
        Value::Bool(b) => Some(Num::Int(BigInt::from(u8::from(*b)))),
        Value::Int(i) => Some(Num::Int(i.clone())),
        Value::Float(f) => Some(Num::Float(*f)),
        _ => None,
    }
}

/// The value as an integer (`int` or `bool`).
pub fn as_int(v: &Value) -> Option<BigInt> {
    match v {
        Value::Bool(b) => Some(BigInt::from(u8::from(*b))),
        Value::Int(i) => Some(i.clone()),
        _ => None,
    }
}

/// `bool(v)`.
pub fn truthy(v: &Value) -> Result<bool> {
    Ok(match v {
        Value::None => false,
        Value::Bool(b) => *b,
        Value::Int(i) => !i.is_zero(),
        Value::Float(f) => *f != 0.0,
        Value::Str(s) | Value::Markup(s) => !s.is_empty(),
        Value::StrEnum(e) => !e.value.is_empty(),
        Value::List(l) => !l.borrow().is_empty(),
        Value::Tuple(t) => !t.is_empty(),
        Value::Dict(d) => !d.borrow().entries.is_empty(),
        Value::Undefined(u) => {
            if u.strict {
                return Err(u.error());
            }
            false
        }
        Value::Object(o) => return o.truthy(),
    })
}

/// `float(int)`: correctly rounded, `OverflowError` past the float range.
pub fn int_to_f64(i: &BigInt) -> Result<f64> {
    big_to_f64(i).ok_or_else(|| Error::overflow("int too large to convert to float"))
}

fn big_to_f64(i: &BigInt) -> Option<f64> {
    let bits = i.bits();
    if bits <= 53 {
        return i.to_i64().map(|v| v as f64);
    }
    // Keep 54 significant bits plus a sticky bit, then round half to even.
    let mag = i.abs();
    let shift = bits - 54;
    let top: BigInt = &mag >> shift;
    let sticky = !(&mag - (&top << shift)).is_zero();
    let mut m = top.to_u64()?;
    let round_bit = m & 1;
    m >>= 1;
    if round_bit == 1 && (sticky || m & 1 == 1) {
        m += 1;
    }
    let exp = i32::try_from(shift + 1).ok()?;
    let f = (m as f64) * 2f64.powi(exp.min(1100));
    if !f.is_finite() || exp > 1100 {
        return None;
    }
    Some(if i.is_negative() { -f } else { f })
}

/// The value as a float (`int`, `bool` or `float`).
pub fn num_to_f64(n: &Num) -> Result<f64> {
    match n {
        Num::Int(i) => int_to_f64(i),
        Num::Float(f) => Ok(*f),
    }
}

/// Exact comparison of an int and a float.
fn cmp_int_float(i: &BigInt, f: f64) -> Option<Ordering> {
    if f.is_nan() {
        return None;
    }
    if f.is_infinite() {
        return Some(if f > 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let floor = f.floor();
    let fi = float_to_big(floor)?;
    match i.cmp(&fi) {
        Ordering::Equal if f > floor => Some(Ordering::Less),
        other => Some(other),
    }
}

/// An integral float as an int.
pub fn float_to_big(f: f64) -> Option<BigInt> {
    if !f.is_finite() {
        return None;
    }
    if f.abs() < 9.0e15 {
        return Some(BigInt::from(f as i64));
    }
    let bits = f.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i64 - 1075;
    let mant = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    let mut v = BigInt::from(mant);
    if exp > 0 {
        v <<= exp as usize;
    } else {
        v >>= (-exp) as usize;
    }
    Some(if f < 0.0 { -v } else { v })
}

fn cmp_num(a: &Num, b: &Num) -> Option<Ordering> {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => Some(x.cmp(y)),
        (Num::Float(x), Num::Float(y)) => x.partial_cmp(y),
        (Num::Int(x), Num::Float(y)) => cmp_int_float(x, *y),
        (Num::Float(x), Num::Int(y)) => cmp_int_float(y, *x).map(Ordering::reverse),
    }
}

/// `a is b` for the values whose identity Python can observe.
pub fn same_object(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::List(x), Value::List(y)) => Rc::ptr_eq(x, y),
        (Value::Dict(x), Value::Dict(y)) => Rc::ptr_eq(x, y),
        (Value::Undefined(x), Value::Undefined(y)) => Rc::ptr_eq(x, y),
        (Value::Object(x), Value::Object(y)) => Rc::ptr_eq(x, y),
        (Value::None, Value::None) => true,
        _ => false,
    }
}

/// `a == b`.
pub fn eq(a: &Value, b: &Value) -> Result<bool> {
    eq_depth(a, b, 0)
}

fn eq_depth(a: &Value, b: &Value, depth: usize) -> Result<bool> {
    if depth > crate::pyrepr::MAX_DEPTH {
        return Err(Error::new(
            "RecursionError",
            "maximum recursion depth exceeded in comparison",
        ));
    }
    // `a.__eq__(b)`, then the reflected `b.__eq__(a)`.
    match (a, b) {
        (Value::Undefined(u), _) => {
            if u.strict {
                return Err(u.error());
            }
            return Ok(matches!(b, Value::Undefined(v) if !v.strict));
        }
        (_, Value::Undefined(u)) => {
            if u.strict {
                return Err(u.error());
            }
            return Ok(false);
        }
        _ => {}
    }
    if let (Some(x), Some(y)) = (as_num(a), as_num(b)) {
        return Ok(cmp_num(&x, &y) == Some(Ordering::Equal));
    }
    if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
        return Ok(x == y);
    }
    match (a, b) {
        (Value::None, Value::None) => Ok(true),
        (Value::List(x), Value::List(y)) => {
            if Rc::ptr_eq(x, y) {
                return Ok(true);
            }
            let (x, y) = (x.borrow().clone(), y.borrow().clone());
            seq_eq(&x, &y, depth)
        }
        (Value::Tuple(x), Value::Tuple(y)) => seq_eq(x, y, depth),
        (Value::Dict(x), Value::Dict(y)) => {
            if Rc::ptr_eq(x, y) {
                return Ok(true);
            }
            let (x, y) = (x.borrow().clone(), y.borrow().clone());
            if x.entries.len() != y.entries.len() {
                return Ok(false);
            }
            for (k, v) in &x.entries {
                match y.get(k)? {
                    Some(w) => {
                        if !same_object(v, &w) && !eq_depth(v, &w, depth + 1)? {
                            return Ok(false);
                        }
                    }
                    None => return Ok(false),
                }
            }
            Ok(true)
        }
        (Value::Object(o), other) | (other, Value::Object(o)) => match o.eq(other) {
            Some(r) => Ok(r),
            None => Ok(same_object(a, b)),
        },
        _ => Ok(false),
    }
}

fn seq_eq(x: &[Value], y: &[Value], depth: usize) -> Result<bool> {
    if x.len() != y.len() {
        return Ok(false);
    }
    for (a, b) in x.iter().zip(y) {
        if !same_object(a, b) && !eq_depth(a, b, depth + 1)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn not_supported(op: CmpOp, a: &Value, b: &Value) -> Error {
    Error::type_error(format!(
        "'{}' not supported between instances of '{}' and '{}'",
        op.symbol(),
        a.type_name(),
        b.type_name()
    ))
}

/// `a <op> b`.
pub fn compare(op: CmpOp, a: &Value, b: &Value) -> Result<bool> {
    match op {
        CmpOp::Eq => return eq(a, b),
        CmpOp::Ne => return eq(a, b).map(|r| !r),
        _ => {}
    }
    if let Value::Undefined(u) = a {
        return Err(u.error());
    }
    if let Value::Undefined(u) = b {
        return Err(u.error());
    }
    let ordering = if let (Some(x), Some(y)) = (as_num(a), as_num(b)) {
        cmp_num(&x, &y)
    } else if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
        Some(x.cmp(y))
    } else {
        match (a, b) {
            (Value::List(x), Value::List(y)) => {
                let (x, y) = (x.borrow().clone(), y.borrow().clone());
                return seq_compare(op, &x, &y);
            }
            (Value::Tuple(x), Value::Tuple(y)) => return seq_compare(op, x, y),
            _ => return Err(not_supported(op, a, b)),
        }
    };
    Ok(match ordering {
        None => false,
        Some(o) => match op {
            CmpOp::Lt => o == Ordering::Less,
            CmpOp::Le => o != Ordering::Greater,
            CmpOp::Gt => o == Ordering::Greater,
            CmpOp::Ge => o != Ordering::Less,
            CmpOp::Eq | CmpOp::Ne => false,
        },
    })
}

fn seq_compare(op: CmpOp, x: &[Value], y: &[Value]) -> Result<bool> {
    for (a, b) in x.iter().zip(y) {
        if !same_object(a, b) && !eq(a, b)? {
            return compare(op, a, b);
        }
    }
    let (n, m) = (x.len(), y.len());
    Ok(match op {
        CmpOp::Lt => n < m,
        CmpOp::Le => n <= m,
        CmpOp::Gt => n > m,
        CmpOp::Ge => n >= m,
        CmpOp::Eq => n == m,
        CmpOp::Ne => n != m,
    })
}

/// `hash(v)` succeeds.
pub fn check_hashable(v: &Value) -> Result<()> {
    match v {
        Value::List(_) => Err(Error::type_error("unhashable type: 'list'")),
        Value::Dict(_) => Err(Error::type_error(format!(
            "unhashable type: '{}'",
            v.type_name()
        ))),
        Value::Tuple(items) => items.iter().try_for_each(check_hashable),
        Value::Undefined(u) if u.strict => Err(u.error()),
        Value::Object(o) if !o.hashable() => Err(Error::type_error(format!(
            "unhashable type: '{}'",
            o.type_name()
        ))),
        _ => Ok(()),
    }
}

/// `len(v)`.
pub fn len(v: &Value) -> Result<usize> {
    match v {
        Value::Str(s) | Value::Markup(s) => Ok(s.chars().count()),
        Value::StrEnum(e) => Ok(e.value.chars().count()),
        Value::List(l) => Ok(l.borrow().len()),
        Value::Tuple(t) => Ok(t.len()),
        Value::Dict(d) => Ok(d.borrow().entries.len()),
        Value::Undefined(u) => {
            if u.strict {
                Err(u.error())
            } else {
                Ok(0)
            }
        }
        Value::Object(o) => match o.len() {
            Some(n) => n,
            None => Err(no_len(v)),
        },
        _ => Err(no_len(v)),
    }
}

fn no_len(v: &Value) -> Error {
    Error::type_error(format!("object of type '{}' has no len()", v.type_name()))
}

/// `iter(v)`.
pub fn py_iter(v: &Value) -> Result<PyIter> {
    Ok(match v {
        Value::Str(s) | Value::Markup(s) => {
            PyIter::Seq(s.chars().map(|c| Value::str(c.to_string())).collect())
        }
        Value::StrEnum(e) => {
            PyIter::Seq(e.value.chars().map(|c| Value::str(c.to_string())).collect())
        }
        Value::List(l) => PyIter::List(l.clone(), 0),
        Value::Tuple(t) => PyIter::Seq(t.iter().cloned().collect()),
        Value::Dict(d) => {
            let len = d.borrow().entries.len();
            PyIter::Dict(d.clone(), 0, len)
        }
        Value::Undefined(u) => {
            if u.strict {
                return Err(u.error());
            }
            PyIter::Done
        }
        Value::Object(o) => match o.iter(v) {
            Some(it) => it?,
            None => return Err(not_iterable(v)),
        },
        _ => return Err(not_iterable(v)),
    })
}

/// The items `iter(v)` yields, collected.
pub fn iterate(v: &Value) -> Result<Vec<Value>> {
    py_iter(v)?.collect()
}

/// `TypeError: 'int' object is not iterable`.
pub fn not_iterable(v: &Value) -> Error {
    Error::type_error(format!("'{}' object is not iterable", v.type_name()))
}

/// `item in container`.
pub fn contains(item: &Value, container: &Value) -> Result<bool> {
    match container {
        Value::Str(_) | Value::Markup(_) | Value::StrEnum(_) => {
            let hay = container.as_str().unwrap_or_default();
            match item {
                Value::Undefined(u) if u.strict => Err(u.error()),
                _ => match item.as_str() {
                    Some(needle) => Ok(hay.contains(needle)),
                    None => Err(Error::type_error(format!(
                        "'in <string>' requires string as left operand, not {}",
                        item.type_name()
                    ))),
                },
            }
        }
        Value::Dict(d) => {
            let d = d.borrow().clone();
            Ok(d.position(item)?.is_some())
        }
        Value::Undefined(u) if u.strict => Err(u.error()),
        Value::Object(o) => match o.contains(item) {
            Some(r) => r,
            None => contains_by_iteration(item, container),
        },
        _ => contains_by_iteration(item, container),
    }
}

fn contains_by_iteration(item: &Value, container: &Value) -> Result<bool> {
    let mut it = match py_iter(container) {
        Ok(it) => it,
        Err(e) if e.kind == "TypeError" && e.message.ends_with("is not iterable") => {
            return Err(Error::type_error(format!(
                "argument of type '{}' is not iterable",
                container.type_name()
            )));
        }
        Err(e) => return Err(e),
    };
    while let Some(x) = it.next()? {
        if same_object(&x, item) || eq(&x, item)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn unsupported_operands(op: BinOp, a: &Value, b: &Value) -> Error {
    Error::type_error(format!(
        "unsupported operand type(s) for {}: '{}' and '{}'",
        op.symbol(),
        a.type_name(),
        b.type_name()
    ))
}

/// `a <op> b`.
pub fn binop(op: BinOp, a: &Value, b: &Value) -> Result<Value> {
    if let Value::Undefined(u) = a {
        return Err(u.error());
    }
    if let Value::Undefined(u) = b {
        return Err(u.error());
    }
    if let (Some(x), Some(y)) = (as_num(a), as_num(b)) {
        return num_binop(op, x, y);
    }
    match op {
        BinOp::Add => add(a, b),
        BinOp::Mul => mul(a, b),
        BinOp::Mod => match a {
            // `str % Markup` too: Markup has no `__rmod__`, plain formatting.
            Value::Str(_) | Value::StrEnum(_) => {
                crate::format::percent(a.as_str().unwrap_or_default(), b, None).map(Value::str)
            }
            Value::Markup(s) => crate::format::percent(s, b, Some(())).map(Value::markup),
            _ => Err(unsupported_operands(op, a, b)),
        },
        _ => Err(unsupported_operands(op, a, b)),
    }
}

fn add(a: &Value, b: &Value) -> Result<Value> {
    match (a, b) {
        (Value::Markup(x), _) if b.is_str() => {
            let other = crate::markup::escape_value(b)?;
            Ok(Value::markup(format!("{x}{other}")))
        }
        (_, Value::Markup(y)) if a.is_str() => {
            let other = crate::markup::escape_value(a)?;
            Ok(Value::markup(format!("{other}{y}")))
        }
        _ if a.is_str() => match b.as_str() {
            Some(y) => {
                let x = a.as_str().unwrap_or_default();
                check_size(x.len() + y.len())?;
                Ok(Value::str(format!("{x}{y}")))
            }
            None => Err(Error::type_error(format!(
                "can only concatenate str (not \"{}\") to str",
                b.type_name()
            ))),
        },
        (Value::List(x), Value::List(y)) => {
            let mut out = x.borrow().clone();
            out.extend(y.borrow().iter().cloned());
            check_size(out.len())?;
            Ok(Value::list(out))
        }
        (Value::List(_), _) => Err(Error::type_error(format!(
            "can only concatenate list (not \"{}\") to list",
            b.type_name()
        ))),
        (Value::Tuple(x), Value::Tuple(y)) => {
            let mut out = x.to_vec();
            out.extend(y.iter().cloned());
            check_size(out.len())?;
            Ok(Value::tuple(out))
        }
        (Value::Tuple(_), _) => Err(Error::type_error(format!(
            "can only concatenate tuple (not \"{}\") to tuple",
            b.type_name()
        ))),
        _ => Err(unsupported_operands(BinOp::Add, a, b)),
    }
}

/// Refuse to build something larger than [`MAX_BUILD`].
pub fn check_size(n: usize) -> Result<()> {
    if n > MAX_BUILD {
        Err(Error::memory())
    } else {
        Ok(())
    }
}

fn repeat_count(n: &Value) -> Option<BigInt> {
    as_int(n)
}

fn mul(a: &Value, b: &Value) -> Result<Value> {
    let (seq, count) = if repeat_count(b).is_some() && !matches!(a, Value::Int(_) | Value::Bool(_))
    {
        (a, b)
    } else if repeat_count(a).is_some() {
        (b, a)
    } else {
        (a, b)
    };
    let is_seq = seq.is_str() || matches!(seq, Value::List(_) | Value::Tuple(_));
    if !is_seq {
        return Err(unsupported_operands(BinOp::Mul, a, b));
    }
    let Some(n) = repeat_count(count) else {
        return Err(Error::type_error(format!(
            "can't multiply sequence by non-int of type '{}'",
            count.type_name()
        )));
    };
    let n = if n.is_negative() {
        0
    } else {
        n.to_usize().ok_or_else(|| {
            Error::overflow(format!(
                "cannot fit '{}' into an index-sized integer",
                count.type_name()
            ))
        })?
    };
    match seq {
        Value::Markup(s) => {
            check_size(s.len().saturating_mul(n))?;
            Ok(Value::markup(s.repeat(n)))
        }
        Value::List(l) => {
            let items = l.borrow().clone();
            check_size(items.len().saturating_mul(n))?;
            let mut out = Vec::with_capacity(items.len() * n);
            for _ in 0..n {
                out.extend(items.iter().cloned());
            }
            Ok(Value::list(out))
        }
        Value::Tuple(t) => {
            check_size(t.len().saturating_mul(n))?;
            let mut out = Vec::with_capacity(t.len() * n);
            for _ in 0..n {
                out.extend(t.iter().cloned());
            }
            Ok(Value::tuple(out))
        }
        _ => {
            let s = seq.as_str().unwrap_or_default();
            check_size(s.len().saturating_mul(n))?;
            Ok(Value::str(s.repeat(n)))
        }
    }
}

fn num_binop(op: BinOp, x: Num, y: Num) -> Result<Value> {
    match (x, y) {
        (Num::Int(a), Num::Int(b)) => int_binop(op, a, b),
        (x, y) => {
            let a = num_to_f64(&x)?;
            let b = num_to_f64(&y)?;
            float_binop(op, a, b)
        }
    }
}

fn int_binop(op: BinOp, a: BigInt, b: BigInt) -> Result<Value> {
    Ok(match op {
        BinOp::Add => Value::Int(a + b),
        BinOp::Sub => Value::Int(a - b),
        BinOp::Mul => {
            check_bits(a.bits().saturating_add(b.bits()))?;
            Value::Int(a * b)
        }
        BinOp::Div => Value::Float(int_true_div(&a, &b)?),
        BinOp::FloorDiv => {
            if b.is_zero() {
                return Err(Error::zero_division("integer division or modulo by zero"));
            }
            Value::Int(a.div_floor(&b))
        }
        BinOp::Mod => {
            if b.is_zero() {
                return Err(Error::zero_division("integer modulo by zero"));
            }
            Value::Int(a.mod_floor(&b))
        }
        BinOp::Pow => {
            if b.is_negative() {
                let fa = int_to_f64(&a)?;
                let fb = int_to_f64(&b)?;
                return float_binop(BinOp::Pow, fa, fb);
            }
            let exp = b.to_u64().ok_or_else(Error::memory)?;
            if a.abs() <= BigInt::one() {
                Value::Int(int_pow(&a, exp))
            } else {
                check_bits(
                    a.bits()
                        .saturating_mul(usize::try_from(exp).unwrap_or(usize::MAX)),
                )?;
                Value::Int(int_pow(&a, exp))
            }
        }
    })
}

fn check_bits(bits: usize) -> Result<()> {
    if bits > MAX_BUILD * 8 {
        Err(Error::memory())
    } else {
        Ok(())
    }
}

fn int_pow(base: &BigInt, mut exp: u64) -> BigInt {
    if base.is_zero() {
        return if exp == 0 {
            BigInt::one()
        } else {
            BigInt::zero()
        };
    }
    if base.is_one() {
        return BigInt::one();
    }
    if *base == -BigInt::one() {
        return if exp % 2 == 0 {
            BigInt::one()
        } else {
            -BigInt::one()
        };
    }
    let mut result = BigInt::one();
    let mut b = base.clone();
    while exp > 0 {
        if exp & 1 == 1 {
            result *= &b;
        }
        exp >>= 1;
        if exp > 0 {
            b = &b * &b;
        }
    }
    result
}

/// `a / b` for ints: correctly rounded.
pub fn int_true_div(a: &BigInt, b: &BigInt) -> Result<f64> {
    if b.is_zero() {
        return Err(Error::zero_division("division by zero"));
    }
    let negative = a.is_negative() != b.is_negative();
    if a.is_zero() {
        return Ok(if negative { -0.0 } else { 0.0 });
    }
    if a.bits() <= 53 && b.bits() <= 53 {
        let (x, y) = (
            a.to_i64().unwrap_or(0) as f64,
            b.to_i64().unwrap_or(1) as f64,
        );
        return Ok(x / y);
    }
    let (x, y) = (a.abs(), b.abs());
    // Scale so the integer quotient has at least 55 significant bits.
    let shift: i64 = 55 - (x.bits() as i64 - y.bits() as i64);
    let (num, den) = if shift >= 0 {
        (&x << shift as usize, y.clone())
    } else {
        (x.clone(), &y << (-shift) as usize)
    };
    let (q, r) = num.div_rem(&den);
    let q = if r.is_zero() {
        q
    } else {
        (q << 1usize) | BigInt::one()
    };
    let extra = if r.is_zero() { 0 } else { 1 };
    let f = big_to_f64(&q)
        .ok_or_else(|| Error::overflow("integer division result too large for a float"))?;
    let scale = -(shift + extra);
    let out = if !(-1000..=1000).contains(&scale) {
        let half = scale / 2;
        f * 2f64.powi(half as i32) * 2f64.powi((scale - half) as i32)
    } else {
        f * 2f64.powi(scale as i32)
    };
    if !out.is_finite() {
        return Err(Error::overflow(
            "integer division result too large for a float",
        ));
    }
    Ok(if negative { -out } else { out })
}

fn float_binop(op: BinOp, a: f64, b: f64) -> Result<Value> {
    Ok(Value::Float(match op {
        BinOp::Add => a + b,
        BinOp::Sub => a - b,
        BinOp::Mul => a * b,
        BinOp::Div => {
            if b == 0.0 {
                return Err(Error::zero_division("float division by zero"));
            }
            a / b
        }
        BinOp::FloorDiv => {
            if b == 0.0 {
                return Err(Error::zero_division("float floor division by zero"));
            }
            float_divmod(a, b).0
        }
        BinOp::Mod => {
            if b == 0.0 {
                return Err(Error::zero_division("float modulo"));
            }
            float_divmod(a, b).1
        }
        BinOp::Pow => float_pow(a, b)?,
    }))
}

/// CPython's `float_divmod`.
pub fn float_divmod(vx: f64, wx: f64) -> (f64, f64) {
    let mut m = vx % wx;
    let mut div = (vx - m) / wx;
    if m != 0.0 {
        if (wx < 0.0) != (m < 0.0) {
            m += wx;
            div -= 1.0;
        }
    } else {
        m = 0.0f64.copysign(wx);
    }
    let floordiv = if div != 0.0 {
        let mut f = div.floor();
        if div - f > 0.5 {
            f += 1.0;
        }
        f
    } else {
        0.0f64.copysign(vx / wx)
    };
    (floordiv, m)
}

/// CPython's `float_pow`.
pub fn float_pow(iv: f64, iw: f64) -> Result<f64> {
    if iw == 0.0 {
        return Ok(1.0);
    }
    if iv.is_nan() {
        return Ok(iv);
    }
    if iw.is_nan() {
        return Ok(if iv == 1.0 { 1.0 } else { iw });
    }
    let iw_is_odd = iw.is_finite() && iw.fract() == 0.0 && (iw / 2.0).fract() != 0.0;
    if iw.is_infinite() {
        let a = iv.abs();
        return Ok(if a == 1.0 {
            1.0
        } else if (iw > 0.0) == (a > 1.0) {
            f64::INFINITY
        } else {
            0.0
        });
    }
    if iv.is_infinite() {
        return Ok(if iw > 0.0 {
            if iw_is_odd { iv } else { iv.abs() }
        } else if iw_is_odd {
            0.0f64.copysign(iv)
        } else {
            0.0
        });
    }
    if iv == 0.0 {
        if iw < 0.0 {
            return Err(Error::zero_division(
                "0.0 cannot be raised to a negative power",
            ));
        }
        return Ok(if iw_is_odd { iv } else { 0.0 });
    }
    if iv < 0.0 && iw.fract() != 0.0 {
        return Err(Error::unsupported("a complex power"));
    }
    if iv == 1.0 {
        return Ok(1.0);
    }
    let r = iv.powf(iw);
    if r.is_infinite() {
        return Err(Error::overflow("(34, 'Numerical result out of range')"));
    }
    Ok(r)
}

/// `-v` / `+v`.
pub fn unary(neg: bool, v: &Value) -> Result<Value> {
    if let Value::Undefined(u) = v {
        return Err(u.error());
    }
    match as_num(v) {
        Some(Num::Int(i)) => Ok(Value::Int(if neg { -i } else { i })),
        Some(Num::Float(f)) => Ok(Value::Float(if neg { -f } else { f })),
        None => Err(Error::type_error(format!(
            "bad operand type for unary {}: '{}'",
            if neg { '-' } else { '+' },
            v.type_name()
        ))),
    }
}

/// CPython 3.11's `list.sort` comparison order for lists under 64 items
/// (`count_run`, then binary insertion), so a failing comparison raises the
/// same `TypeError` as in Python; longer lists merge-sort.
pub fn sort_by_keys(items: Vec<Value>, keys: Vec<Value>, reverse: bool) -> Result<Vec<Value>> {
    let mut pairs: Vec<(Value, Value)> = keys.into_iter().zip(items).collect();
    if reverse {
        pairs.reverse();
    }
    let lt = |a: &Value, b: &Value| compare(CmpOp::Lt, a, b);
    let n = pairs.len();
    if n < 2 {
        if reverse {
            pairs.reverse();
        }
        return Ok(pairs.into_iter().map(|(_, v)| v).collect());
    }
    if n < 64 {
        // count_run
        let mut run = 2;
        let descending = lt(&pairs[1].0, &pairs[0].0)?;
        if descending {
            while run < n && lt(&pairs[run].0, &pairs[run - 1].0)? {
                run += 1;
            }
            pairs[..run].reverse();
        } else {
            while run < n && !lt(&pairs[run].0, &pairs[run - 1].0)? {
                run += 1;
            }
        }
        // binarysort
        for start in run..n {
            let pivot = pairs[start].clone();
            let (mut l, mut r) = (0, start);
            while l < r {
                let p = l + ((r - l) >> 1);
                if lt(&pivot.0, &pairs[p].0)? {
                    r = p;
                } else {
                    l = p + 1;
                }
            }
            pairs.remove(start);
            pairs.insert(l, pivot);
        }
    } else {
        pairs = merge_sort(pairs, &lt)?;
    }
    if reverse {
        pairs.reverse();
    }
    Ok(pairs.into_iter().map(|(_, v)| v).collect())
}

type Pair = (Value, Value);

fn merge_sort(v: Vec<Pair>, lt: &dyn Fn(&Value, &Value) -> Result<bool>) -> Result<Vec<Pair>> {
    if v.len() <= 1 {
        return Ok(v);
    }
    let mut v = v;
    let right = v.split_off(v.len() / 2);
    let left = merge_sort(v, lt)?;
    let right = merge_sort(right, lt)?;
    let mut out = Vec::with_capacity(left.len() + right.len());
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        if lt(&right[j].0, &left[i].0)? {
            out.push(right[j].clone());
            j += 1;
        } else {
            out.push(left[i].clone());
            i += 1;
        }
    }
    out.extend_from_slice(&left[i..]);
    out.extend_from_slice(&right[j..]);
    Ok(out)
}

/// `int(f)` for a float: truncation, with Python's errors.
pub fn float_to_int(f: f64) -> Result<BigInt> {
    if f.is_nan() {
        return Err(Error::value_error("cannot convert float NaN to integer"));
    }
    if f.is_infinite() {
        return Err(Error::overflow("cannot convert float infinity to integer"));
    }
    float_to_big(f.trunc())
        .ok_or_else(|| Error::overflow("cannot convert float infinity to integer"))
}

fn slice_index(v: &Value) -> Result<isize> {
    match as_int(v) {
        Some(i) => Ok(i.to_isize().unwrap_or(if i.is_negative() {
            isize::MIN
        } else {
            isize::MAX
        })),
        None => Err(Error::type_error(
            "slice indices must be integers or None or have an __index__ method",
        )),
    }
}

/// `PySlice_Unpack` + `PySlice_AdjustIndices`: `(start, stop, step)` over a
/// sequence of `length` items.
pub fn slice_indices(
    start: &Value,
    stop: &Value,
    step: &Value,
    length: isize,
) -> Result<(isize, isize, isize)> {
    let step = match step {
        Value::None => 1,
        v => {
            let s = slice_index(v)?;
            if s == 0 {
                return Err(Error::value_error("slice step cannot be zero"));
            }
            s.max(-isize::MAX)
        }
    };
    let mut start = match start {
        Value::None => {
            if step < 0 {
                isize::MAX
            } else {
                0
            }
        }
        v => slice_index(v)?,
    };
    let mut stop = match stop {
        Value::None => {
            if step < 0 {
                isize::MIN
            } else {
                isize::MAX
            }
        }
        v => slice_index(v)?,
    };
    let adjust = |x: &mut isize| {
        if *x < 0 {
            *x += length;
            if *x < 0 {
                *x = if step < 0 { -1 } else { 0 };
            }
        } else if *x >= length {
            *x = if step < 0 { length - 1 } else { length };
        }
    };
    adjust(&mut start);
    adjust(&mut stop);
    Ok((start, stop, step))
}

/// Python's unpacking of `v` into `n` targets.
pub fn unpack(v: &Value, n: usize) -> Result<Vec<Value>> {
    let mut it = match py_iter(v) {
        Ok(it) => it,
        Err(e) if e.kind == "TypeError" && e.message.ends_with("is not iterable") => {
            return Err(Error::type_error(format!(
                "cannot unpack non-iterable {} object",
                v.type_name()
            )));
        }
        Err(e) => return Err(e),
    };
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        match it.next()? {
            Some(x) => out.push(x),
            None => {
                return Err(Error::value_error(format!(
                    "not enough values to unpack (expected {n}, got {})",
                    out.len()
                )));
            }
        }
    }
    if it.next()?.is_some() {
        return Err(Error::value_error(format!(
            "too many values to unpack (expected {n})"
        )));
    }
    Ok(out)
}
