//! Python built-ins the filters and globals rely on: `int()`, `float()`,
//! `dict()`, `str()`, `abs()`, `round()`, `sum()`, and Jinja's `lipsum`.

use std::cell::Cell;
use std::rc::Rc;

use num_bigint_dig::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};

use crate::error::{Error, Result};
use crate::ops::{self, BinOp, Num};
use crate::pyrepr;
use crate::unicode;
use crate::value::{Dict, Value};

/// `_PyUnicode_TransformDecimalAndSpaceToASCII`: Unicode digits become ASCII
/// digits, Unicode spaces become ' ', anything else non-ASCII becomes '?'.
fn to_ascii(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii() {
                c
            } else if unicode::is_space(c) {
                ' '
            } else if let Some(d) = unicode::decimal_value(c) {
                char::from_digit(d, 10).unwrap_or('?')
            } else {
                '?'
            }
        })
        .collect()
}

fn digit_value(c: u8) -> Option<u32> {
    (c as char).to_digit(36)
}

/// `int(s, base)` for a string.
pub fn parse_int(original: &str, base: u32) -> Result<BigInt> {
    let invalid = || {
        let mut r = pyrepr::str_repr(original);
        if r.chars().count() > 200 {
            r = r.chars().take(200).collect();
        }
        Error::value_error(format!("invalid literal for int() with base {base}: {r}"))
    };
    let s = to_ascii(original);
    let t = s.trim_matches(|c: char| c == ' ' || ('\t'..='\r').contains(&c));
    let b = t.as_bytes();
    let mut i = 0;
    let negative = match b.first() {
        Some(b'-') => {
            i = 1;
            true
        }
        Some(b'+') => {
            i = 1;
            false
        }
        _ => false,
    };
    let mut base = base;
    let prefix_of = |c: u8| match c.to_ascii_lowercase() {
        b'x' => Some(16),
        b'o' => Some(8),
        b'b' => Some(2),
        _ => None,
    };
    let mut after_prefix = false;
    if b.get(i) == Some(&b'0') {
        if let Some(p) = b.get(i + 1).and_then(|c| prefix_of(*c)) {
            if base == 0 || base == p {
                base = p;
                i += 2;
                after_prefix = true;
            }
        }
    }
    let leading_zero_rule = base == 0;
    if base == 0 {
        base = 10;
    }
    let digits_start = i;
    let mut value = BigInt::zero();
    let mut ndigits = 0usize;
    let mut prev_underscore = after_prefix;
    let mut all_zero = true;
    while i < b.len() {
        let c = b[i];
        if c == b'_' {
            if prev_underscore && !(after_prefix && i == digits_start) {
                return Err(invalid());
            }
            if i == digits_start && !after_prefix {
                return Err(invalid());
            }
            prev_underscore = true;
            i += 1;
            continue;
        }
        let Some(d) = digit_value(c).filter(|d| *d < base) else {
            return Err(invalid());
        };
        if d != 0 {
            all_zero = false;
        }
        value = value * base + d;
        ndigits += 1;
        prev_underscore = false;
        i += 1;
    }
    if ndigits == 0 || (prev_underscore && i > digits_start) {
        return Err(invalid());
    }
    if leading_zero_rule && !after_prefix && b[digits_start] == b'0' && !all_zero {
        return Err(invalid());
    }
    if !base.is_power_of_two() && ndigits > pyrepr::INT_MAX_STR_DIGITS {
        return Err(Error::value_error(format!(
            "Exceeds the limit ({} digits) for integer string conversion: value has {ndigits} digits; use \
             sys.set_int_max_str_digits() to increase the limit",
            pyrepr::INT_MAX_STR_DIGITS
        )));
    }
    Ok(if negative { -value } else { value })
}

/// `int(v)` or `int(v, base)`.
pub fn py_int(v: &Value, base: Option<&Value>) -> Result<BigInt> {
    if let Some(base) = base {
        let b = crate::methods::index_value(base)?;
        let b = b.to_i64().unwrap_or(-1);
        if !(b == 0 || (2..=36).contains(&b)) {
            return Err(Error::value_error(
                "int() base must be >= 2 and <= 36, or 0",
            ));
        }
        return match v.as_str() {
            Some(s) => parse_int(s, b as u32),
            None => Err(Error::type_error(
                "int() can't convert non-string with explicit base",
            )),
        };
    }
    match v {
        Value::Int(i) => Ok(i.clone()),
        Value::Bool(b) => Ok(BigInt::from(u8::from(*b))),
        Value::Float(f) => ops::float_to_int(*f),
        Value::Undefined(u) => Err(u.error()),
        _ => match v.as_str() {
            Some(s) => parse_int(s, 10),
            None => Err(Error::type_error(format!(
                "int() argument must be a string, a bytes-like object or a real number, not '{}'",
                v.type_name()
            ))),
        },
    }
}

/// `float(s)` for a string.
pub fn parse_float(original: &str) -> Result<f64> {
    let invalid = || {
        Error::value_error(format!(
            "could not convert string to float: {}",
            pyrepr::str_repr(original)
        ))
    };
    let s = to_ascii(original);
    let t = s.trim_matches(|c: char| c == ' ' || ('\t'..='\r').contains(&c));
    let lower = t.to_ascii_lowercase();
    let (sign, body) = match lower.as_bytes().first() {
        Some(b'-') => (-1.0, &lower[1..]),
        Some(b'+') => (1.0, &lower[1..]),
        _ => (1.0, lower.as_str()),
    };
    match body {
        "inf" | "infinity" => return Ok(sign * f64::INFINITY),
        "nan" => return Ok(f64::NAN.copysign(sign)),
        _ => {}
    }
    // digits with single underscores between digits
    let b = body.as_bytes();
    let mut clean = String::with_capacity(b.len());
    let mut seen_digit = false;
    for (i, c) in b.iter().enumerate() {
        match c {
            b'_' => {
                let ok = i > 0
                    && b[i - 1].is_ascii_digit()
                    && b.get(i + 1).is_some_and(u8::is_ascii_digit);
                if !ok {
                    return Err(invalid());
                }
            }
            b'0'..=b'9' => {
                seen_digit = true;
                clean.push(*c as char);
            }
            b'.' | b'e' | b'+' | b'-' => clean.push(*c as char),
            _ => return Err(invalid()),
        }
    }
    if !seen_digit {
        return Err(invalid());
    }
    // Python's grammar: digits [. digits] [e [sign] digits] | . digits ...
    let valid = {
        let (mant, exp) = match clean.find('e') {
            Some(i) => (&clean[..i], Some(&clean[i + 1..])),
            None => (clean.as_str(), None),
        };
        let mant_ok = {
            let parts: Vec<&str> = mant.split('.').collect();
            match parts.len() {
                1 => !parts[0].is_empty() && parts[0].bytes().all(|c| c.is_ascii_digit()),
                2 => {
                    (!parts[0].is_empty() || !parts[1].is_empty())
                        && parts.iter().all(|p| p.bytes().all(|c| c.is_ascii_digit()))
                }
                _ => false,
            }
        };
        let exp_ok = match exp {
            None => true,
            Some(e) => {
                let e = e.strip_prefix(['+', '-']).unwrap_or(e);
                !e.is_empty() && e.bytes().all(|c| c.is_ascii_digit())
            }
        };
        mant_ok && exp_ok
    };
    if !valid {
        return Err(invalid());
    }
    let f: f64 = clean.parse().map_err(|_| invalid())?;
    Ok(sign * f)
}

/// `float(v)`.
pub fn py_float(v: &Value) -> Result<f64> {
    match v {
        Value::Float(f) => Ok(*f),
        Value::Int(i) => ops::int_to_f64(i),
        Value::Bool(b) => Ok(f64::from(u8::from(*b))),
        Value::Undefined(u) => Err(u.error()),
        _ => match v.as_str() {
            Some(s) => parse_float(s),
            None => Err(Error::type_error(format!(
                "float() argument must be a string or a real number, not '{}'",
                v.type_name()
            ))),
        },
    }
}

/// `dict(*args, **kwargs)`.
pub fn py_dict(args: Vec<Value>, kwargs: Vec<(Rc<str>, Value)>) -> Result<Value> {
    if args.len() > 1 {
        return Err(Error::type_error(format!(
            "dict expected at most 1 argument, got {}",
            args.len()
        )));
    }
    let mut d = Dict::default();
    crate::methods::dict_update(&mut d, args.first(), kwargs)?;
    Ok(Value::from_dict(d))
}

/// `str(object='')`.
pub fn str_call(args: Vec<Value>, kwargs: Vec<(Rc<str>, Value)>) -> Result<Value> {
    if !kwargs.is_empty() || args.len() > 1 {
        return Err(Error::unsupported("str() with an encoding"));
    }
    match args.first() {
        None => Ok(Value::str("")),
        Some(v) => Ok(Value::str(pyrepr::str(v)?)),
    }
}

/// `abs(v)`.
pub fn py_abs(v: &Value) -> Result<Value> {
    match ops::as_num(v) {
        Some(Num::Int(i)) => Ok(Value::Int(i.abs())),
        Some(Num::Float(f)) => Ok(Value::Float(f.abs())),
        None => {
            if let Value::Undefined(u) = v {
                return Err(u.error());
            }
            Err(Error::type_error(format!(
                "bad operand type for abs(): '{}'",
                v.type_name()
            )))
        }
    }
}

/// `x` as an exact fraction `m / 2^k` (`m` signed, `k` may be negative).
fn float_parts(x: f64) -> (BigInt, i64) {
    let bits = x.to_bits();
    let negative = bits >> 63 == 1;
    let exp = ((bits >> 52) & 0x7ff) as i64;
    let frac = bits & ((1u64 << 52) - 1);
    let (m, e) = if exp == 0 {
        (frac, -1074)
    } else {
        (frac | (1u64 << 52), exp - 1075)
    };
    let m = BigInt::from(m);
    (if negative { -m } else { m }, e)
}

/// Divides and rounds half to even.
fn div_round_half_even(n: &BigInt, d: &BigInt) -> BigInt {
    let (q, r) = n.div_mod_floor(d);
    let twice = &r * 2u32;
    match twice.cmp(d) {
        std::cmp::Ordering::Less => q,
        std::cmp::Ordering::Greater => q + BigInt::one(),
        std::cmp::Ordering::Equal => {
            if q.is_even() {
                q
            } else {
                q + BigInt::one()
            }
        }
    }
}

/// `round(x, ndigits)` for a float: correctly rounded, half to even.
pub fn round_float(x: f64, ndigits: i64) -> Result<f64> {
    if !x.is_finite() || x == 0.0 {
        return Ok(x);
    }
    if ndigits > 323 {
        return Ok(x);
    }
    if ndigits < -308 {
        return Ok(0.0f64.copysign(x));
    }
    let (m, e) = float_parts(x);
    // x * 10^ndigits = m * 2^e * 10^ndigits; round to an integer q, then
    // the result is q / 10^ndigits.
    let ten = BigInt::from(10u32);
    let (num, den) = {
        let mut num = m.clone();
        let mut den = BigInt::one();
        if e >= 0 {
            num <<= e as usize;
        } else {
            den <<= (-e) as usize;
        }
        if ndigits >= 0 {
            num *= num_traits::pow(ten.clone(), ndigits as usize);
        } else {
            den *= num_traits::pow(ten.clone(), (-ndigits) as usize);
        }
        (num, den)
    };
    let q = div_round_half_even(&num, &den);
    let r = if ndigits >= 0 {
        let scale = num_traits::pow(ten, ndigits as usize);
        crate::ops::int_true_div(&q, &scale)?
    } else {
        let scale = num_traits::pow(ten, (-ndigits) as usize);
        ops::int_to_f64(&(q * scale))?
    };
    if r == 0.0 {
        return Ok(0.0f64.copysign(x));
    }
    Ok(r)
}

/// `round(v, ndigits)`.
pub fn py_round(v: &Value, ndigits: &Value) -> Result<Value> {
    let nd = crate::methods::index_value(ndigits)?;
    match v {
        Value::Float(f) => {
            let nd = nd
                .to_i64()
                .unwrap_or(if nd.is_negative() { i64::MIN } else { i64::MAX });
            Ok(Value::Float(round_float(*f, nd)?))
        }
        Value::Int(_) | Value::Bool(_) => {
            let i = ops::as_int(v).unwrap_or_default();
            if !nd.is_negative() {
                return Ok(Value::Int(i));
            }
            let exp = (-nd).to_usize().unwrap_or(usize::MAX);
            if exp > 5000 {
                return Ok(Value::int(0));
            }
            let scale = num_traits::pow(BigInt::from(10u32), exp);
            Ok(Value::Int(div_round_half_even(&i, &scale) * scale))
        }
        Value::Undefined(u) => Err(u.error()),
        other => Err(Error::type_error(format!(
            "type {} doesn't define __round__ method",
            other.type_name()
        ))),
    }
}

/// `sum(map(f, iterable), start)`.
pub fn py_sum_with(
    it: &mut crate::value::PyIter,
    start: Value,
    f: impl Fn(Value) -> Result<Value>,
) -> Result<Value> {
    if start.is_str() {
        return Err(Error::type_error(
            "sum() can't sum strings [use ''.join(seq) instead]",
        ));
    }
    if start.downcast::<crate::objects::Bytes>().is_some() {
        return Err(Error::type_error(
            "sum() can't sum bytes [use b''.join(seq) instead]",
        ));
    }
    let mut acc = start;
    while let Some(item) = it.next()? {
        let item = f(item)?;
        acc = ops::binop(BinOp::Add, &acc, &item)?;
    }
    Ok(acc)
}

const LOREM_IPSUM_WORDS: &str = "a ac accumsan ad adipiscing aenean aliquam aliquet amet ante aptent arcu at \
auctor augue bibendum blandit class commodo condimentum congue consectetuer consequat conubia convallis cras \
cubilia cum curabitur curae cursus dapibus diam dictum dictumst dignissim dis dolor donec dui duis egestas eget \
eleifend elementum elit enim erat eros est et etiam eu euismod facilisi facilisis fames faucibus felis fermentum \
feugiat fringilla fusce gravida habitant habitasse hac hendrerit hymenaeos iaculis id imperdiet in inceptos \
integer interdum ipsum justo lacinia lacus laoreet lectus leo libero ligula litora lobortis lorem luctus \
maecenas magna magnis malesuada massa mattis mauris metus mi molestie mollis montes morbi mus nam nascetur \
natoque nec neque netus nibh nisi nisl non nonummy nostra nulla nullam nunc odio orci ornare parturient pede \
pellentesque penatibus per pharetra phasellus placerat platea porta porttitor posuere potenti praesent pretium \
primis proin pulvinar purus quam quis quisque rhoncus ridiculus risus rutrum sagittis sapien scelerisque sed \
sem semper senectus sit sociis sociosqu sodales sollicitudin suscipit suspendisse taciti tellus tempor tempus \
tincidunt torquent tortor tristique turpis ullamcorper ultrices ultricies urna ut varius vehicula vel velit \
venenatis vestibulum vitae vivamus viverra volutpat vulputate";

thread_local! {
    static RNG: Cell<u64> = const { Cell::new(0) };
}

/// A pseudo-random number below `n` (Python's `random` differs anyway).
pub fn random_below(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    RNG.with(|r| {
        let mut x = r.get();
        if x == 0 {
            x = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x2545_f491_4f6c_dd1d)
                | 1;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        r.set(x);
        x % n
    })
}

fn randrange(a: i64, b: i64) -> i64 {
    if b <= a {
        return a;
    }
    a + random_below((b - a) as u64) as i64
}

/// `generate_lorem_ipsum(n=5, html=True, min=20, max=100)`.
pub fn lipsum(args: Vec<Value>, kwargs: Vec<(Rc<str>, Value)>) -> Result<Value> {
    let bound = crate::callargs::bind_values(
        "generate_lorem_ipsum",
        &["n", "html", "min", "max"],
        &[
            Value::int(5),
            Value::Bool(true),
            Value::int(20),
            Value::int(100),
        ],
        args,
        kwargs,
    )?;
    let int_of = |v: &Value| -> Result<i64> {
        crate::methods::index_value(v)?
            .to_i64()
            .ok_or_else(|| Error::overflow("Python int too large to convert to C ssize_t"))
    };
    let n = int_of(&bound[0])?;
    let html = ops::truthy(&bound[1])?;
    let min = int_of(&bound[2])?;
    let max = int_of(&bound[3])?;
    if max <= min {
        return Err(Error::value_error(format!(
            "empty range for randrange() ({min}, {max}, {})",
            max - min
        )));
    }
    let words: Vec<&str> = LOREM_IPSUM_WORDS.split(' ').collect();
    let mut result = Vec::new();
    for _ in 0..n.max(0) {
        let mut next_capitalized = true;
        let (mut last_comma, mut last_fullstop) = (0i64, 0i64);
        let mut last = "";
        let mut p: Vec<String> = Vec::new();
        let count = randrange(min, max);
        ops::check_size(count.max(0) as usize)?;
        for idx in 0..count {
            let mut word = loop {
                let w = words[random_below(words.len() as u64) as usize];
                if w != last {
                    last = w;
                    break w.to_string();
                }
            };
            if next_capitalized {
                word = unicode::capitalize(&word);
                next_capitalized = false;
            }
            if idx - randrange(3, 8) > last_comma {
                last_comma = idx;
                last_fullstop += 2;
                word.push(',');
            }
            if idx - randrange(10, 20) > last_fullstop {
                last_comma = idx;
                last_fullstop = idx;
                word.push('.');
                next_capitalized = true;
            }
            p.push(word);
        }
        let mut p_str = p.join(" ");
        if p_str.ends_with(',') {
            p_str.pop();
            p_str.push('.');
        } else if !p_str.ends_with('.') {
            p_str.push('.');
        }
        result.push(p_str);
    }
    if !html {
        return Ok(Value::str(result.join("\n\n")));
    }
    Ok(Value::markup(
        result
            .iter()
            .map(|x| format!("<p>{}</p>", crate::markup::escape_str(x)))
            .collect::<Vec<_>>()
            .join("\n"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_python() {
        assert_eq!(parse_int(" 10 ", 10).unwrap(), BigInt::from(10));
        assert_eq!(parse_int("0x10", 0).unwrap(), BigInt::from(16));
        assert_eq!(parse_int("0x1A", 16).unwrap(), BigInt::from(26));
        assert_eq!(parse_int("1_0", 10).unwrap(), BigInt::from(10));
        assert_eq!(parse_int("١٢", 10).unwrap(), BigInt::from(12));
        assert_eq!(parse_int("00", 0).unwrap(), BigInt::from(0));
        assert!(parse_int("010", 0).is_err());
        assert!(parse_int("_10", 10).is_err());
        assert!(parse_int("1 0", 10).is_err());
        assert_eq!(
            parse_int("x", 10).unwrap_err().message,
            "invalid literal for int() with base 10: 'x'"
        );
        assert_eq!(parse_float(" inf ").unwrap(), f64::INFINITY);
        assert_eq!(parse_float("1_0.5").unwrap(), 10.5);
        assert_eq!(parse_float(".5").unwrap(), 0.5);
        assert_eq!(parse_float("5.").unwrap(), 5.0);
        assert!(parse_float("1__0").is_err());
        assert!(parse_float(".").is_err());
    }

    #[test]
    fn rounds_like_python() {
        assert_eq!(round_float(2.675, 2).unwrap(), 2.67);
        assert_eq!(round_float(2.5, 0).unwrap(), 2.0);
        assert_eq!(round_float(3.5, 0).unwrap(), 4.0);
        assert_eq!(round_float(1234.5678, -2).unwrap(), 1200.0);
        assert_eq!(round_float(0.125, 2).unwrap(), 0.12);
    }
}
