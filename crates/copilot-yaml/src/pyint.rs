//! The CPython 3.11 built-ins the constructor calls: `int(s, base)`,
//! `float(s)`, `datetime`'s argument checks, `repr(timedelta)`, and the
//! codec errors' texts.
//!
//! `int()` and `float()` follow `copilot-jinja`'s built-ins (the same
//! CPython rules: Unicode digits and spaces mapped to ASCII, single `_`
//! between digits, base prefixes, the 4300-digit limit).

use num_bigint_dig::BigInt;
use num_traits::Zero;

use copilot_jinja::unicode;

use crate::error::PyException;
use crate::repr::str_repr;

/// `sys.get_int_max_str_digits()`.
pub const INT_MAX_STR_DIGITS: usize = 4300;

/// `_PyUnicode_TransformDecimalAndSpaceToASCII`.
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

fn is_ascii_space(c: char) -> bool {
    c == ' ' || ('\t'..='\r').contains(&c)
}

/// `int(original, base)` for a string.
pub fn parse_int(original: &str, base: u32) -> Result<BigInt, PyException> {
    let invalid = || {
        let mut r = str_repr(original);
        if r.chars().count() > 200 {
            r = r.chars().take(200).collect();
        }
        PyException::value_error(format!("invalid literal for int() with base {base}: {r}"))
    };
    let s = to_ascii(original);
    let t = s.trim_matches(is_ascii_space);
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
        let Some(d) = (c as char).to_digit(36).filter(|d| *d < base) else {
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
    if !base.is_power_of_two() && ndigits > INT_MAX_STR_DIGITS {
        return Err(PyException::value_error(format!(
            "Exceeds the limit ({INT_MAX_STR_DIGITS} digits) for integer string conversion: value \
             has {ndigits} digits; use sys.set_int_max_str_digits() to increase the limit"
        )));
    }
    Ok(if negative { -value } else { value })
}

/// `float(original)` for a string.
pub fn parse_float(original: &str) -> Result<f64, PyException> {
    let invalid = || {
        PyException::value_error(format!(
            "could not convert string to float: {}",
            str_repr(original)
        ))
    };
    let s = to_ascii(original);
    let t = s.trim_matches(is_ascii_space);
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

/// A whole float as an exact integer.
pub fn float_to_bigint(f: f64) -> Option<BigInt> {
    if !f.is_finite() || f.fract() != 0.0 {
        return None;
    }
    // `{:.0}` prints the exact integer value of a whole f64.
    BigInt::parse_bytes(format!("{f:.0}").as_bytes(), 10)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// `check_date_args`.
pub fn check_date(year: i64, month: i64, day: i64) -> Result<(), PyException> {
    if !(1..=9999).contains(&year) {
        return Err(PyException::value_error(format!(
            "year {year} is out of range"
        )));
    }
    if !(1..=12).contains(&month) {
        return Err(PyException::value_error("month must be in 1..12"));
    }
    if day < 1 || day > days_in_month(year, month) {
        return Err(PyException::value_error("day is out of range for month"));
    }
    Ok(())
}

/// `check_time_args` (microseconds come from six digits, always valid).
pub fn check_time(hour: i64, minute: i64, second: i64) -> Result<(), PyException> {
    if !(0..=23).contains(&hour) {
        return Err(PyException::value_error("hour must be in 0..23"));
    }
    if !(0..=59).contains(&minute) {
        return Err(PyException::value_error("minute must be in 0..59"));
    }
    if !(0..=59).contains(&second) {
        return Err(PyException::value_error("second must be in 0..59"));
    }
    Ok(())
}

/// `repr(timedelta(seconds=…))` for a whole number of seconds.
pub fn timedelta_repr(seconds: i64) -> String {
    let days = seconds.div_euclid(86400);
    let rest = seconds.rem_euclid(86400);
    let mut parts = Vec::new();
    if days != 0 {
        parts.push(format!("days={days}"));
    }
    if rest != 0 {
        parts.push(format!("seconds={rest}"));
    }
    if parts.is_empty() {
        "datetime.timedelta(0)".to_string()
    } else {
        format!("datetime.timedelta({})", parts.join(", "))
    }
}

fn char_escape(c: char) -> String {
    let n = u32::from(c);
    if n <= 0xff {
        format!("'\\x{n:02x}'")
    } else if n <= 0xffff {
        format!("'\\u{n:04x}'")
    } else {
        format!("'\\U{n:08x}'")
    }
}

/// `str(UnicodeEncodeError)` of `s.encode('ascii')`, if it fails.
pub fn ascii_encode_error(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let first = chars.iter().position(|c| !c.is_ascii())?;
    let mut last = first;
    while last + 1 < chars.len() && !chars[last + 1].is_ascii() {
        last += 1;
    }
    Some(if first == last {
        format!(
            "'ascii' codec can't encode character {} in position {first}: ordinal not in \
             range(128)",
            char_escape(chars[first])
        )
    } else {
        format!(
            "'ascii' codec can't encode characters in position {first}-{last}: ordinal not in \
             range(128)"
        )
    })
}

/// `str(UnicodeDecodeError)` of `bytes(codes).decode('utf-8')` (CPython's
/// decoder: the first error's start, its length and its reason).
pub fn utf8_decode_error(bytes: &[u8]) -> String {
    let (start, len, reason) = utf8_error(bytes);
    if len == 1 {
        format!(
            "'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}",
            bytes[start]
        )
    } else {
        format!(
            "'utf-8' codec can't decode bytes in position {start}-{}: {reason}",
            start + len - 1
        )
    }
}

/// CPython's UTF-8 decoder: where the first invalid sequence starts, how many
/// bytes it covers and why.
fn utf8_error(b: &[u8]) -> (usize, usize, &'static str) {
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c < 0x80 {
            i += 1;
            continue;
        }
        let (need, lo, hi) = match c {
            0xC2..=0xDF => (1, 0x80, 0xBF),
            0xE0 => (2, 0xA0, 0xBF),
            0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF),
            0xED => (2, 0x80, 0x9F),
            0xF0 => (3, 0x90, 0xBF),
            0xF1..=0xF3 => (3, 0x80, 0xBF),
            0xF4 => (3, 0x80, 0x8F),
            _ => return (i, 1, "invalid start byte"),
        };
        // The second byte has the lead-specific range, the rest 0x80..=0xBF.
        let mut j = 1;
        while j <= need {
            let Some(&n) = b.get(i + j) else {
                return (i, j, "unexpected end of data");
            };
            let (l, h) = if j == 1 { (lo, hi) } else { (0x80, 0xBF) };
            if n < l || n > h {
                return (i, j, "invalid continuation byte");
            }
            j += 1;
        }
        i += need + 1;
    }
    (0, 1, "invalid start byte")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_errors_read_like_cpython() {
        assert_eq!(
            utf8_decode_error(&[0xff]),
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
        );
        assert_eq!(
            utf8_decode_error(&[0x41, 0xe2, 0x82]),
            "'utf-8' codec can't decode bytes in position 1-2: unexpected end of data"
        );
        assert_eq!(
            utf8_decode_error(&[0xe2, 0x41]),
            "'utf-8' codec can't decode byte 0xe2 in position 0: invalid continuation byte"
        );
        assert_eq!(
            timedelta_repr(-(25 * 3600)),
            "datetime.timedelta(days=-2, seconds=82800)"
        );
        assert_eq!(timedelta_repr(86400), "datetime.timedelta(days=1)");
    }
}
