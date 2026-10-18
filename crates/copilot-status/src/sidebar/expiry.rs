//! `_parse_license_expiry`: the licence's `expires` as a naive datetime.
//!
//! Python tries `datetime.strptime(raw.replace("Z", ""), fmt)` for
//! `%Y-%m-%dT%H:%M:%S.%f` then `%Y-%m-%dT%H:%M:%S` (its regexes: case
//! insensitive, one-digit months, days and times accepted, Unicode digits
//! for `\d`), then `datetime.fromisoformat(raw.replace("Z", "+00:00"))` with
//! the offset dropped, not applied; anything else is `None`.

use std::sync::OnceLock;

use chrono::{NaiveDate, NaiveDateTime};
use copilot_auth::pyvalue::PyValue;
use regex::Regex;

/// `_strptime`'s regex for `%Y-%m-%dT%H:%M:%S` (with `.%f` when `fraction`).
fn strptime_regex(fraction: bool) -> Option<&'static Regex> {
    static PLAIN: OnceLock<Option<Regex>> = OnceLock::new();
    static FRACTION: OnceLock<Option<Regex>> = OnceLock::new();
    let build = |fraction: bool| {
        let f = if fraction { r"\.(?P<f>[0-9]{1,6})" } else { "" };
        Regex::new(&format!(
            r"(?i)^(?P<Y>\d\d\d\d)-(?P<m>1[0-2]|0[1-9]|[1-9])-(?P<d>3[01]|[12]\d|0[1-9]|[1-9]| [1-9])T(?P<H>2[0-3]|[0-1]\d|\d):(?P<M>[0-5]\d|\d):(?P<S>6[0-1]|[0-5]\d|\d){f}$"
        ))
        .ok()
    };
    if fraction {
        FRACTION.get_or_init(|| build(true)).as_ref()
    } else {
        PLAIN.get_or_init(|| build(false)).as_ref()
    }
}

/// `int()` of a run of `\d` (Unicode decimal digits).
fn digits(text: &str) -> Option<u32> {
    let mut n: u32 = 0;
    for c in text.chars() {
        let d = if c == ' ' {
            continue;
        } else if let Some(d) = c.to_digit(10) {
            d
        } else {
            copilot_jinja::unicode::decimal_value(c)?
        };
        n = n.checked_mul(10)?.checked_add(d)?;
    }
    Some(n)
}

/// `datetime.strptime(text, fmt)`, `None` for its `ValueError`.
fn strptime(text: &str, fraction: bool) -> Option<NaiveDateTime> {
    let caps = strptime_regex(fraction)?.captures(text)?;
    let field = |name: &str| caps.name(name).and_then(|m| digits(m.as_str()));
    let year = i32::try_from(field("Y")?).ok()?;
    if year < 1 {
        return None;
    }
    let micros = match caps.name("f") {
        Some(m) => {
            let mut s = m.as_str().to_string();
            while s.chars().count() < 6 {
                s.push('0');
            }
            digits(&s)?
        }
        None => 0,
    };
    NaiveDate::from_ymd_opt(year, field("m")?, field("d")?)?.and_hms_micro_opt(
        field("H")?,
        field("M")?,
        field("S")?,
        micros,
    )
}

/// `_parse_license_expiry(expires_raw)`.
pub fn parse_license_expiry(raw: Option<&PyValue>) -> Option<NaiveDateTime> {
    let PyValue::Str(raw) = raw? else {
        return None;
    };
    let normalized = raw.replace('Z', "");
    for fraction in [true, false] {
        if let Some(t) = strptime(&normalized, fraction) {
            return Some(t);
        }
    }
    copilot_ingest::py::fromisoformat(&raw.replace('Z', "+00:00"))
        .ok()
        .map(|t| t.wall)
}

/// `(expires_at - datetime.utcnow()).days`: whole days, floored.
pub fn days_until(expires: NaiveDateTime, now: NaiveDateTime) -> i64 {
    let micros = (expires - now)
        .num_microseconds()
        .unwrap_or(if expires > now { i64::MAX } else { i64::MIN });
    micros.div_euclid(86_400 * 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn expiries_parse_like_the_backend() {
        let doc = loads(include_str!("../platform_vectors.json")).unwrap();
        let PyValue::List(cases) = doc.get("license_expiry").unwrap().clone() else {
            panic!("license_expiry")
        };
        assert!(!cases.is_empty());
        for case in cases {
            let input = case.get("input").cloned().unwrap_or(PyValue::None);
            let want = case
                .get("parsed")
                .and_then(PyValue::as_str)
                .map(str::to_string);
            let got = parse_license_expiry(Some(&input)).map(|t| {
                if t.and_utc().timestamp_subsec_micros() == 0 {
                    t.format("%Y-%m-%dT%H:%M:%S").to_string()
                } else {
                    t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
                }
            });
            assert_eq!(got, want, "{}", input.py_repr());
        }
        assert_eq!(parse_license_expiry(None), None);
    }

    #[test]
    fn days_floor_like_timedelta() {
        let t = |s: &str| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap();
        let now = t("2026-10-17 12:00:00");
        assert_eq!(days_until(t("2026-10-18 11:59:59"), now), 0);
        assert_eq!(days_until(t("2026-10-18 12:00:00"), now), 1);
        assert_eq!(days_until(t("2026-10-17 11:59:59"), now), -1);
        assert_eq!(days_until(t("2026-10-15 12:00:00"), now), -2);
    }
}
