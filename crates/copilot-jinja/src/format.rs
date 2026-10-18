//! Python's string formatting: `str % args` (`PyUnicode_Format`) and
//! `format(value, spec)` (the format-spec mini-language), with CPython
//! 3.11's errors.

use num_bigint_dig::BigInt;
use num_traits::{Signed, ToPrimitive};

use crate::error::{Error, Result};
use crate::ops;
use crate::pyrepr;
use crate::value::Value;

/// `ascii(repr)`: non-ASCII characters escaped.
pub fn ascii_of(repr: &str) -> String {
    let mut out = String::with_capacity(repr.len());
    for c in repr.chars() {
        let n = c as u32;
        if n < 0x80 {
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

// --- float digit generation ---------------------------------------------------

/// `'%.{prec}f'` of a finite non-negative float.
fn fixed_digits(x: f64, prec: usize) -> String {
    format!("{x:.prec$}")
}

/// `'%.{prec}e'` of a finite non-negative float, Python's exponent style.
fn exp_digits(x: f64, prec: usize, upper: bool) -> String {
    let s = format!("{x:.prec$e}");
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let sign = if exp < 0 { '-' } else { '+' };
    let e = if upper { 'E' } else { 'e' };
    format!("{mant}{e}{sign}{:02}", exp.unsigned_abs())
}

/// `'%.{prec}g'` of a finite non-negative float.
fn general_digits(x: f64, prec: usize, alt: bool, upper: bool, add_dot_0: bool) -> String {
    let p = prec.max(1);
    // The exponent after rounding to `p` significant digits.
    let probe = format!("{x:.*e}", p - 1);
    let exp: i32 = probe
        .split_once('e')
        .and_then(|(_, e)| e.parse().ok())
        .unwrap_or(0);
    let mut out = if x == 0.0 || (-4..p as i32).contains(&exp) {
        let decimals = (p as i32 - 1 - exp).max(0) as usize;
        let s = fixed_digits(x, decimals);
        if alt { s } else { strip_zeros(&s) }
    } else {
        let s = exp_digits(x, p - 1, upper);
        if alt {
            s
        } else {
            let (m, e) = s.split_at(s.find(['e', 'E']).unwrap_or(s.len()));
            format!("{}{e}", strip_zeros(m))
        }
    };
    if add_dot_0 && !out.contains(['.', 'e', 'E']) {
        out.push_str(".0");
    }
    if alt && !out.contains('.') {
        // `#` keeps the decimal point even with no digits after it.
        match out.find(['e', 'E']) {
            Some(i) => out.insert(i, '.'),
            None => out.push('.'),
        }
    }
    out
}

fn strip_zeros(s: &str) -> String {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s.to_string()
    }
}

/// A finite or special float, formatted by `type` without sign or padding.
fn float_body(x: f64, ty: char, prec: usize, alt: bool) -> String {
    let upper = ty.is_ascii_uppercase();
    if x.is_nan() {
        return if upper { "NAN" } else { "nan" }.into();
    }
    if x.is_infinite() {
        return if upper { "INF" } else { "inf" }.into();
    }
    let a = x.abs();
    let mut s = match ty.to_ascii_lowercase() {
        'f' => fixed_digits(a, prec),
        'e' => exp_digits(a, prec, upper),
        'g' => general_digits(a, prec, alt, upper, false),
        'r' => {
            let r = pyrepr::float_repr(a);
            if upper { r.to_uppercase() } else { r }
        }
        _ => fixed_digits(a, prec),
    };
    if alt && matches!(ty.to_ascii_lowercase(), 'f' | 'e') && !s.contains('.') {
        match s.find(['e', 'E']) {
            Some(i) => s.insert(i, '.'),
            None => s.push('.'),
        }
    }
    s
}

// --- printf-style -------------------------------------------------------------

#[derive(Default)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alt: bool,
    zero: bool,
    width: usize,
    prec: Option<usize>,
}

fn pad(body: String, sign: &str, prefix: &str, spec: &Spec, numeric: bool) -> String {
    let len = sign.chars().count() + prefix.chars().count() + body.chars().count();
    if len >= spec.width {
        return format!("{sign}{prefix}{body}");
    }
    let fill = spec.width - len;
    if spec.left {
        format!("{sign}{prefix}{body}{}", " ".repeat(fill))
    } else if spec.zero && numeric {
        format!("{sign}{prefix}{}{body}", "0".repeat(fill))
    } else {
        format!("{}{sign}{prefix}{body}", " ".repeat(fill))
    }
}

fn sign_of(negative: bool, spec: &Spec) -> &'static str {
    if negative {
        "-"
    } else if spec.plus {
        "+"
    } else if spec.space {
        " "
    } else {
        ""
    }
}

/// `str % args`. With `markup` set the left side is a `Markup`: arguments
/// are escaped (`_MarkupEscapeHelper`).
pub fn percent(fmt: &str, args: &Value, markup: Option<()>) -> Result<String> {
    let markup = markup.is_some();
    let tuple: Option<Vec<Value>> = match args {
        Value::Tuple(t) => Some(t.to_vec()),
        _ => crate::objects::as_tuple(args),
    };
    let (arglen, mut argidx): (isize, isize) = match &tuple {
        Some(t) => (t.len() as isize, 0),
        None => (-1, -2),
    };
    let is_mapping = tuple.is_none() && !args.is_str() && is_subscriptable(args);
    let next_arg = |argidx: &mut isize| -> Result<Value> {
        if *argidx < arglen {
            let i = *argidx;
            *argidx += 1;
            if arglen < 0 {
                Ok(args.clone())
            } else {
                Ok(tuple
                    .as_ref()
                    .map(|t| t[i as usize].clone())
                    .unwrap_or(Value::None))
            }
        } else {
            Err(Error::type_error("not enough arguments for format string"))
        }
    };
    let chars: Vec<char> = fmt.chars().collect();
    let mut out = String::with_capacity(fmt.len());
    let mut i = 0;
    let mut used_mapping = false;
    while i < chars.len() {
        if chars[i] != '%' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        let mut value: Option<Value> = None;
        if i < chars.len() && chars[i] == '(' {
            if !is_mapping {
                return Err(Error::type_error("format requires a mapping"));
            }
            i += 1;
            let key_start = i;
            let mut depth = 1;
            while i < chars.len() {
                match chars[i] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            if i >= chars.len() {
                return Err(Error::value_error("incomplete format key"));
            }
            let key: String = chars[key_start..i].iter().collect();
            i += 1;
            value = Some(crate::attrs::subscript(args, &Value::str(&key))?);
            used_mapping = true;
        }
        let mut spec = Spec::default();
        while i < chars.len() {
            match chars[i] {
                '-' => spec.left = true,
                '+' => spec.plus = true,
                ' ' => spec.space = true,
                '#' => spec.alt = true,
                '0' => spec.zero = true,
                _ => break,
            }
            i += 1;
        }
        if i < chars.len() && chars[i] == '*' {
            let w = if used_mapping && value.is_some() {
                return Err(Error::type_error("* wants int"));
            } else {
                next_arg(&mut argidx)?
            };
            let w = ops::as_int(&w).ok_or_else(|| Error::type_error("* wants int"))?;
            let w = w.to_i64().ok_or_else(|| Error::overflow("width too big"))?;
            if w < 0 {
                spec.left = true;
            }
            spec.width = w.unsigned_abs() as usize;
            i += 1;
        } else {
            let mut w: usize = 0;
            while i < chars.len() && chars[i].is_ascii_digit() {
                w = w
                    .checked_mul(10)
                    .and_then(|w| w.checked_add(chars[i] as usize - '0' as usize))
                    .ok_or_else(|| Error::value_error("width too big"))?;
                i += 1;
            }
            spec.width = w;
        }
        if i < chars.len() && chars[i] == '.' {
            i += 1;
            if i < chars.len() && chars[i] == '*' {
                let p = next_arg(&mut argidx)?;
                let p = ops::as_int(&p).ok_or_else(|| Error::type_error("* wants int"))?;
                spec.prec = Some(p.to_i64().unwrap_or(0).max(0) as usize);
                i += 1;
            } else {
                let mut p: usize = 0;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    p = p
                        .checked_mul(10)
                        .and_then(|p| p.checked_add(chars[i] as usize - '0' as usize))
                        .ok_or_else(|| Error::value_error("precision too big"))?;
                    i += 1;
                }
                spec.prec = Some(p);
            }
        }
        // Length modifiers are accepted and ignored.
        while i < chars.len() && matches!(chars[i], 'h' | 'l' | 'L') {
            i += 1;
        }
        if i >= chars.len() {
            return Err(Error::value_error("incomplete format"));
        }
        let ty = chars[i];
        i += 1;
        if ty == '%' {
            out.push('%');
            continue;
        }
        let v = match value.take() {
            Some(v) => v,
            None => next_arg(&mut argidx)?,
        };
        let piece = format_arg(ty, &v, &spec, markup, start, &chars)?;
        out.push_str(&piece);
    }
    if argidx < arglen && !is_mapping {
        return Err(Error::type_error(
            "not all arguments converted during string formatting",
        ));
    }
    Ok(out)
}

/// `PyMapping_Check`: the type has `__getitem__`.
fn is_subscriptable(v: &Value) -> bool {
    match v {
        Value::List(_) | Value::Dict(_) | Value::Undefined(_) => true,
        Value::Object(o) => crate::objects::is_subscriptable(o.as_ref()),
        _ => false,
    }
}

fn format_arg(
    ty: char,
    v: &Value,
    spec: &Spec,
    markup: bool,
    start: usize,
    chars: &[char],
) -> Result<String> {
    if let Value::Undefined(u) = v {
        if !matches!(ty, 'r' | 'a') {
            return Err(u.error());
        }
    }
    match ty {
        's' | 'r' | 'a' => {
            let mut s = match ty {
                's' => pyrepr::str(v)?,
                'r' => pyrepr::repr(v)?,
                _ => ascii_of(&pyrepr::repr(v)?),
            };
            if markup {
                s = crate::markup::escape_str(&s);
            }
            if let Some(p) = spec.prec {
                s = s.chars().take(p).collect();
            }
            Ok(pad(s, "", "", spec, false))
        }
        'd' | 'i' | 'u' => {
            let i = int_for_percent(v, ty, markup, false)?;
            let mut digits = i.abs().to_str_radix(10);
            if let Some(p) = spec.prec {
                if digits.len() < p {
                    digits = format!("{}{digits}", "0".repeat(p - digits.len()));
                }
            }
            Ok(pad(digits, sign_of(i.is_negative(), spec), "", spec, true))
        }
        'o' | 'x' | 'X' => {
            let i = int_for_percent(v, ty, markup, true)?;
            let radix = if ty == 'o' { 8 } else { 16 };
            let mut digits = i.abs().to_str_radix(radix);
            if ty == 'X' {
                digits = digits.to_uppercase();
            }
            if let Some(p) = spec.prec {
                if digits.len() < p {
                    digits = format!("{}{digits}", "0".repeat(p - digits.len()));
                }
            }
            let prefix = if spec.alt {
                match ty {
                    'o' => "0o",
                    'x' => "0x",
                    _ => "0X",
                }
            } else {
                ""
            };
            Ok(pad(
                digits,
                sign_of(i.is_negative(), spec),
                prefix,
                spec,
                true,
            ))
        }
        'e' | 'E' | 'f' | 'F' | 'g' | 'G' => {
            let f = float_for_percent(v, markup)?;
            let prec = spec.prec.unwrap_or(6);
            let body = float_body(f, ty, prec, spec.alt);
            let numeric = f.is_finite();
            Ok(pad(
                body,
                sign_of(f.is_sign_negative() && !f.is_nan(), spec),
                "",
                spec,
                numeric,
            ))
        }
        'c' => {
            let c = match v {
                Value::Int(_) | Value::Bool(_) if !markup => {
                    let i = ops::as_int(v).unwrap_or_default();
                    let n = i.to_u32().filter(|n| *n < 0x110000);
                    let Some(c) = n.and_then(char::from_u32) else {
                        return Err(Error::overflow("%c arg not in range(0x110000)"));
                    };
                    c.to_string()
                }
                _ if !markup && v.as_str().is_some_and(|s| s.chars().count() == 1) => {
                    v.as_str().unwrap_or_default().to_string()
                }
                _ => return Err(Error::type_error("%c requires int or char")),
            };
            Ok(pad(c, "", "", spec, false))
        }
        other => Err(Error::value_error(format!(
            "unsupported format character {} (0x{:x}) at index {}",
            pyrepr::str_repr(&other.to_string()),
            other as u32,
            chars[..start].len() + {
                // the index of the type character itself
                let rest = &chars[start..];
                rest.iter().position(|c| *c == other).unwrap_or(0)
            }
        ))),
    }
}

fn int_for_percent(v: &Value, ty: char, markup: bool, index_only: bool) -> Result<BigInt> {
    let need = if index_only {
        "an integer"
    } else {
        "a real number"
    };
    let fail = || {
        Error::type_error(format!(
            "%{ty} format: {need} is required, not {}",
            if markup {
                "_MarkupEscapeHelper".to_string()
            } else {
                v.type_name()
            }
        ))
    };
    if markup && index_only {
        return Err(fail());
    }
    match v {
        Value::Int(i) => Ok(i.clone()),
        Value::Bool(b) => Ok(BigInt::from(u8::from(*b))),
        Value::Float(f) if !index_only => ops::float_to_int(*f),
        _ if markup => crate::builtins::py_int(v, None).map_err(|_| fail()),
        _ => Err(fail()),
    }
}

fn float_for_percent(v: &Value, markup: bool) -> Result<f64> {
    match ops::as_num(v) {
        Some(n) => ops::num_to_f64(&n),
        None if markup => crate::builtins::py_float(v),
        None => Err(Error::type_error(format!(
            "must be real number, not {}",
            v.type_name()
        ))),
    }
}

// --- format(value, spec) --------------------------------------------------------

/// A parsed format spec.
#[derive(Debug, Default, Clone)]
pub struct FormatSpec {
    fill: Option<char>,
    align: Option<char>,
    sign: Option<char>,
    no_neg_zero: bool,
    alt: bool,
    width: Option<usize>,
    grouping: Option<char>,
    precision: Option<usize>,
    ty: Option<char>,
}

fn parse_spec(spec: &str, type_name: &str) -> Result<FormatSpec> {
    let c: Vec<char> = spec.chars().collect();
    let mut p = FormatSpec::default();
    let mut i = 0;
    let is_align = |ch: char| matches!(ch, '<' | '>' | '=' | '^');
    if c.len() >= 2 && is_align(c[1]) {
        p.fill = Some(c[0]);
        p.align = Some(c[1]);
        i = 2;
    } else if !c.is_empty() && is_align(c[0]) {
        p.align = Some(c[0]);
        i = 1;
    }
    if i < c.len() && matches!(c[i], '+' | '-' | ' ') {
        p.sign = Some(c[i]);
        i += 1;
    }
    if i < c.len() && c[i] == 'z' {
        p.no_neg_zero = true;
        i += 1;
    }
    if i < c.len() && c[i] == '#' {
        p.alt = true;
        i += 1;
    }
    if i < c.len() && c[i] == '0' {
        if p.fill.is_none() {
            p.fill = Some('0');
        }
        if p.align.is_none() {
            p.align = Some('=');
        }
        i += 1;
    }
    let start = i;
    while i < c.len() && c[i].is_ascii_digit() {
        i += 1;
    }
    if i > start {
        let digits: String = c[start..i].iter().collect();
        p.width = Some(
            digits
                .parse()
                .map_err(|_| Error::value_error("Too many decimal digits in format string"))?,
        );
    }
    if i < c.len() && c[i] == ',' {
        p.grouping = Some(',');
        i += 1;
    }
    if i < c.len() && c[i] == '_' {
        if p.grouping.is_some() {
            return Err(Error::value_error("Cannot specify both ',' and '_'."));
        }
        p.grouping = Some('_');
        i += 1;
    }
    if i < c.len() && c[i] == ',' {
        return Err(Error::value_error("Cannot specify both ',' and '_'."));
    }
    if i < c.len() && c[i] == '.' {
        i += 1;
        let start = i;
        while i < c.len() && c[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err(Error::value_error("Format specifier missing precision"));
        }
        let digits: String = c[start..i].iter().collect();
        p.precision = Some(
            digits
                .parse()
                .map_err(|_| Error::value_error("Too many decimal digits in format string"))?,
        );
    }
    if c.len() - i > 1 {
        return Err(Error::value_error(format!(
            "Invalid format specifier '{spec}' for object of type '{type_name}'"
        )));
    }
    if i < c.len() {
        p.ty = Some(c[i]);
    }
    if let Some(g) = p.grouping {
        let ok = match p.ty {
            None => true,
            Some(t) => {
                matches!(t, 'd' | 'e' | 'f' | 'g' | 'E' | 'F' | 'G' | '%')
                    || (g == '_' && matches!(t, 'b' | 'o' | 'x' | 'X'))
            }
        };
        if !ok {
            return Err(Error::value_error(format!(
                "Cannot specify '{g}' with '{}'.",
                p.ty.unwrap_or('s')
            )));
        }
    }
    Ok(p)
}

fn unknown_code(ty: char, type_name: &str) -> Error {
    Error::value_error(format!(
        "Unknown format code '{ty}' for object of type '{type_name}'"
    ))
}

fn align_text(body: &str, sign_prefix: &str, spec: &FormatSpec, default_align: char) -> String {
    let len = sign_prefix.chars().count() + body.chars().count();
    let width = spec.width.unwrap_or(0);
    if len >= width {
        return format!("{sign_prefix}{body}");
    }
    let fill = spec.fill.unwrap_or(' ');
    let n = width - len;
    let pad = |k: usize| fill.to_string().repeat(k);
    match spec.align.unwrap_or(default_align) {
        '<' => format!("{sign_prefix}{body}{}", pad(n)),
        '>' => format!("{}{sign_prefix}{body}", pad(n)),
        '^' => format!("{}{sign_prefix}{body}{}", pad(n / 2), pad(n - n / 2)),
        _ => format!("{sign_prefix}{}{body}", pad(n)),
    }
}

fn group_digits(digits: &str, sep: char, every: usize) -> String {
    let chars: Vec<char> = digits.chars().collect();
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % every == 0 {
            out.push(sep);
        }
        out.push(*c);
    }
    out
}

/// Zero-padding with `=` alignment and grouping: Python groups the padding
/// too. Pads `digits` (before the decimal part) to `min` characters.
fn grouped_zero_pad(int_part: &str, sep: Option<char>, every: usize, min: usize) -> String {
    let mut digits = int_part.to_string();
    loop {
        let grouped = match sep {
            Some(s) => group_digits(&digits, s, every),
            None => digits.clone(),
        };
        if grouped.chars().count() >= min {
            return grouped;
        }
        digits.insert(0, '0');
    }
}

/// `format(value, spec)`.
pub fn format_value(v: &Value, spec: &str) -> Result<String> {
    match v {
        Value::Undefined(u) => Err(u.error()),
        Value::Str(_) | Value::Markup(_) => format_str(v.as_str().unwrap_or_default(), spec, "str"),
        Value::StrEnum(_) => format_str(&pyrepr::str(v)?, spec, "str"),
        Value::Bool(_) if spec.is_empty() => pyrepr::str(v),
        Value::Int(_) | Value::Bool(_) => format_int(&ops::as_int(v).unwrap_or_default(), spec),
        Value::Float(f) => format_float(*f, spec),
        _ => {
            if spec.is_empty() {
                pyrepr::str(v)
            } else {
                Err(Error::type_error(format!(
                    "unsupported format string passed to {}.__format__",
                    v.type_name()
                )))
            }
        }
    }
}

fn format_str(s: &str, spec: &str, type_name: &str) -> Result<String> {
    if spec.is_empty() {
        return Ok(s.to_string());
    }
    let p = parse_spec(spec, type_name)?;
    if let Some(t) = p.ty {
        if t != 's' {
            return Err(unknown_code(t, type_name));
        }
    }
    if p.sign.is_some() {
        return Err(Error::value_error(
            "Sign not allowed in string format specifier",
        ));
    }
    if p.alt {
        return Err(Error::value_error(
            "Alternate form (#) not allowed in string format specifier",
        ));
    }
    if p.align == Some('=') {
        return Err(Error::value_error(
            "'=' alignment not allowed in string format specifier",
        ));
    }
    let body: String = match p.precision {
        Some(n) => s.chars().take(n).collect(),
        None => s.to_string(),
    };
    Ok(align_text(&body, "", &p, '<'))
}

fn format_int(i: &BigInt, spec: &str) -> Result<String> {
    let p = parse_spec(spec, "int")?;
    let ty = p.ty.unwrap_or('d');
    match ty {
        'e' | 'E' | 'f' | 'F' | 'g' | 'G' | '%' => {
            let f = ops::int_to_f64(i)?;
            return format_float(f, spec);
        }
        'b' | 'c' | 'd' | 'o' | 'x' | 'X' | 'n' => {}
        other => return Err(unknown_code(other, "int")),
    }
    if p.precision.is_some() {
        return Err(Error::value_error(
            "Precision not allowed in integer format specifier",
        ));
    }
    if ty == 'c' {
        if p.sign.is_some() {
            return Err(Error::value_error(
                "Sign not allowed with integer format specifier 'c'",
            ));
        }
        if p.alt {
            return Err(Error::value_error(
                "Alternate form (#) not allowed with integer format specifier 'c'",
            ));
        }
        let c = i
            .to_u32()
            .filter(|n| *n < 0x110000)
            .and_then(char::from_u32)
            .ok_or_else(|| Error::overflow("%c arg not in range(0x110000)"))?;
        return Ok(align_text(&c.to_string(), "", &p, '<'));
    }
    let (radix, prefix) = match ty {
        'b' => (2, "0b"),
        'o' => (8, "0o"),
        'x' => (16, "0x"),
        'X' => (16, "0X"),
        _ => (10, ""),
    };
    let mut digits = i.abs().to_str_radix(radix);
    if ty == 'X' {
        digits = digits.to_uppercase();
    }
    let sign = if i.is_negative() {
        "-"
    } else {
        match p.sign {
            Some('+') => "+",
            Some(' ') => " ",
            _ => "",
        }
    };
    let prefix = if p.alt { prefix } else { "" };
    let every = if radix == 10 { 3 } else { 4 };
    let sign_prefix = format!("{sign}{prefix}");
    if p.align.unwrap_or('>') == '=' && p.fill == Some('0') {
        let min = p
            .width
            .unwrap_or(0)
            .saturating_sub(sign_prefix.chars().count());
        let body = grouped_zero_pad(&digits, p.grouping, every, min);
        return Ok(format!("{sign_prefix}{body}"));
    }
    if let Some(g) = p.grouping {
        digits = group_digits(&digits, g, every);
    }
    Ok(align_text(&digits, &sign_prefix, &p, '>'))
}

fn format_float(x: f64, spec: &str) -> Result<String> {
    if spec.is_empty() {
        return Ok(pyrepr::float_repr(x));
    }
    let p = parse_spec(spec, "float")?;
    let mut ty = p.ty.unwrap_or('\0');
    let mut add_dot_0 = false;
    let mut val = x;
    let mut pct = false;
    match ty {
        '\0' => {
            add_dot_0 = true;
            ty = if p.precision.is_some() { 'g' } else { 'r' };
        }
        'n' => ty = 'g',
        '%' => {
            ty = 'f';
            val *= 100.0;
            pct = true;
        }
        'e' | 'E' | 'f' | 'F' | 'g' | 'G' => {}
        other => return Err(unknown_code(other, "float")),
    }
    let prec = p.precision.unwrap_or(6);
    let mut body = if ty == 'g' || ty == 'G' {
        if val.is_finite() {
            general_digits(val.abs(), prec, p.alt, ty == 'G', add_dot_0)
        } else {
            float_body(val, ty, prec, p.alt)
        }
    } else {
        float_body(val, ty, prec, p.alt)
    };
    let mut negative = val.is_sign_negative() && !val.is_nan();
    if negative
        && p.no_neg_zero
        && body
            .chars()
            .all(|c| matches!(c, '0' | '.' | 'e' | 'E' | '+' | '-'))
    {
        negative = false;
    }
    if pct {
        body.push('%');
    }
    let sign = if negative {
        "-"
    } else {
        match p.sign {
            Some('+') => "+",
            Some(' ') => " ",
            _ => "",
        }
    };
    let (int_part, rest) = match body.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => body.split_at(i),
        None => (body.as_str(), ""),
    };
    if p.align.unwrap_or('>') == '=' && p.fill == Some('0') && val.is_finite() {
        let min = p
            .width
            .unwrap_or(0)
            .saturating_sub(sign.len() + rest.chars().count());
        let ints = grouped_zero_pad(int_part, p.grouping, 3, min);
        return Ok(format!("{sign}{ints}{rest}"));
    }
    let body = match p.grouping {
        Some(g) if val.is_finite() => format!("{}{rest}", group_digits(int_part, g, 3)),
        _ => body.clone(),
    };
    Ok(align_text(&body, sign, &p, '>'))
}
