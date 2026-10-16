//! `AlertsQueryBuilder` (`wazuh_indexer/utils/universal.py`) as the SIEM
//! services use it: `add_time_range` (`_get_time_range_start`: the unit is
//! checked first, then `int()` of the rest, then `timedelta` and
//! `datetime.utcnow() - delta`), `add_absolute_time_range`, `add_sort`.

use chrono::{Duration, NaiveDate};
use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_wazuh::indexer::services::alerts::{isoformat, time_range_query};
use copilot_wazuh::pymodel::py;

/// `timedelta`'s limit: `|days| <= 999999999`.
const MAX_DAYS: i128 = 999_999_999;

/// `int(text)` for a `str`, base 10, as CPython 3.11 parses it: Unicode
/// decimal digits and spaces become ASCII first
/// (`_PyUnicode_TransformDecimalAndSpaceToASCII`), surrounding whitespace is
/// stripped, one sign, digits with single underscores between them, at most
/// 4300 digits. `Ok(None)`: it parses but does not fit 128 bits (it can
/// only overflow `timedelta` then).
fn py_int(text: &str) -> Result<Option<i128>, PyExc> {
    let invalid = || {
        let mut r = str_repr(text);
        if r.chars().count() > 200 {
            r = r.chars().take(200).collect();
        }
        PyExc::ValueError(format!("invalid literal for int() with base 10: {r}"))
    };
    let ascii: String = text
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c
            } else if copilot_jinja::unicode::is_space(c) {
                ' '
            } else if let Some(d) = copilot_jinja::unicode::decimal_value(c) {
                char::from_digit(d, 10).unwrap_or('?')
            } else {
                '?'
            }
        })
        .collect();
    let t = ascii.trim_matches(|c: char| c == ' ' || ('\t'..='\r').contains(&c));
    let (negative, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let bytes = digits.as_bytes();
    if bytes.is_empty()
        || bytes[0] == b'_'
        || bytes[bytes.len() - 1] == b'_'
        || digits.contains("__")
        || !bytes.iter().all(|b| b.is_ascii_digit() || *b == b'_')
    {
        return Err(invalid());
    }
    let clean = digits.replace('_', "");
    if clean.len() > 4300 {
        return Err(PyExc::ValueError(format!(
            "Exceeds the limit (4300 digits) for integer string conversion: value has {} \
             digits; use sys.set_int_max_str_digits() to increase the limit",
            clean.len()
        )));
    }
    Ok(clean
        .parse::<i128>()
        .ok()
        .map(|n| if negative { -n } else { n }))
}

/// `OverflowError` with its text.
fn overflow(text: impl Into<String>) -> PyExc {
    PyExc::Other("OverflowError", text.into())
}

/// The C `int` conversion of `timedelta`'s normalised days.
const TOO_LARGE: &str = "Python int too large to convert to C int";

/// `_get_time_range_start(timerange)`: `start.isoformat() + "Z"`.
pub fn time_range_start(timerange: &str) -> PyResult<String> {
    let (per_unit, amount) = if let Some(a) = timerange.strip_suffix('h') {
        (3600i128, a)
    } else if let Some(a) = timerange.strip_suffix('d') {
        (86_400, a)
    } else if let Some(a) = timerange.strip_suffix('w') {
        (604_800, a)
    } else {
        return Err(PyExc::ValueError(
            "Invalid timerange format. Expected a string like '24h', '1d', '1w', etc.".into(),
        ));
    };
    let n = py_int(amount)?.ok_or_else(|| overflow(TOO_LARGE))?;
    // `timedelta` normalises to days (floored), then converts them to a C
    // `int` and checks their range.
    let seconds = n.checked_mul(per_unit).ok_or_else(|| overflow(TOO_LARGE))?;
    let days = seconds.div_euclid(86_400);
    if days > i128::from(i32::MAX) || days < i128::from(i32::MIN) {
        return Err(overflow(TOO_LARGE));
    }
    if days.abs() > MAX_DAYS {
        return Err(overflow(format!(
            "days={days}; must have magnitude <= 999999999"
        )));
    }
    let delta = Duration::try_seconds(i64::try_from(seconds).unwrap_or(i64::MAX))
        .ok_or_else(|| overflow("date value out of range"))?;
    let start = copilot_core::time::now_utc_micros()
        .checked_sub_signed(delta)
        .ok_or_else(|| overflow("date value out of range"))?;
    let min = NaiveDate::from_ymd_opt(1, 1, 1)
        .unwrap_or_default()
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default();
    let max = NaiveDate::from_ymd_opt(9999, 12, 31)
        .unwrap_or_default()
        .and_hms_micro_opt(23, 59, 59, 999_999)
        .unwrap_or_default();
    if start < min || start > max {
        return Err(overflow("date value out of range"));
    }
    Ok(format!("{}Z", isoformat(start)))
}

/// `AlertsQueryBuilder().add_time_range(timerange, field)`'s `must` clause.
pub fn relative(timerange: &str, field: &str) -> PyResult<PyValue> {
    let start = time_range_start(timerange)?;
    Ok(py(&time_range_query(field, &start, "now")))
}

/// `add_absolute_time_range(time_from, time_to, field)`'s clause.
pub fn absolute(time_from: &str, time_to: &str, field: &str) -> PyValue {
    py(&time_range_query(field, time_from, time_to))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_is_checked_before_the_amount() {
        assert_eq!(
            time_range_start("abcx").unwrap_err(),
            PyExc::ValueError(
                "Invalid timerange format. Expected a string like '24h', '1d', '1w', etc.".into()
            )
        );
        assert_eq!(
            time_range_start("abch").unwrap_err(),
            PyExc::ValueError("invalid literal for int() with base 10: 'abc'".into())
        );
        assert_eq!(
            time_range_start("h").unwrap_err(),
            PyExc::ValueError("invalid literal for int() with base 10: ''".into())
        );
        assert!(time_range_start(" 2_4h").is_ok());
        assert!(time_range_start("-1d").is_ok());
        assert!(matches!(
            time_range_start("99999999999999999999h"),
            Err(PyExc::Other("OverflowError", _))
        ));
        assert!(time_range_start("24h").unwrap().ends_with('Z'));
        assert!(time_range_start("\u{0663}h").is_ok());
        assert_eq!(
            time_range_start("\u{2003}7d ").unwrap_err(),
            PyExc::ValueError(
                "Invalid timerange format. Expected a string like '24h', '1d', '1w', etc.".into()
            )
        );
        assert_eq!(
            time_range_start("\u{2003}7dh").unwrap_err(),
            PyExc::ValueError("invalid literal for int() with base 10: '\\u20037d'".into())
        );
        assert!(time_range_start("\u{2003}7 d").is_ok());
        // Recorded with CPython 3.11's `timedelta`.
        let over = |t: &str| match time_range_start(t) {
            Err(PyExc::Other("OverflowError", text)) => text,
            other => panic!("{t}: {other:?}"),
        };
        assert_eq!(over("1000000000000h"), TOO_LARGE);
        assert_eq!(over("1000000000000000w"), TOO_LARGE);
        assert_eq!(
            over("1000000000d"),
            "days=1000000000; must have magnitude <= 999999999"
        );
        assert_eq!(over("999999999d"), "date value out of range");
        assert_eq!(over("-10000000000h"), "date value out of range");
        assert!(matches!(
            time_range_start(&format!("{}h", "1".repeat(5000))),
            Err(PyExc::ValueError(t)) if t.starts_with("Exceeds the limit (4300 digits)")
        ));
    }
}
