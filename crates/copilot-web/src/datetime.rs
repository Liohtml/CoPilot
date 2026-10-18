//! Pydantic's lax `datetime` parsing, for request fields typed `datetime`.
//!
//! pydantic-core hands strings to `speedate` and, when that fails, retries
//! them as a date at midnight (`validators/datetime.rs:datetime_from_date`).
//! This module runs the same two steps on the same `speedate` version, so a
//! value parses — or fails with the same `datetime_from_date_parsing`
//! message — exactly as in the Python backend:
//!
//! 1. `DateTime::parse_bytes_with_config` (RFC 3339-ish, or a unix
//!    timestamp: seconds or milliseconds, inferred; UTC);
//! 2. else `Date::parse_bytes_with_config` → midnight;
//! 3. else the *date* parser's error.
//!
//! The result is the **wall clock** the Python backend binds into SQL:
//! `pymysql` formats an aware `datetime` without its offset, so
//! `…T03:04:05+05:00` filters on 03:04:05. `pydantic_datetime_vectors.json`
//! (generated from pydantic) pins all of it.

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use speedate::{
    Date, DateConfig, DateTime, DateTimeConfig, MicrosecondsPrecisionOverflowBehavior, TimeConfig,
    TimestampUnit,
};
use strum::EnumMessage;

/// Pydantic's error type for a string that is neither a datetime nor a date.
pub const PARSE_ERROR_KIND: &str = "datetime_from_date_parsing";

/// Why a value is not a datetime: Pydantic's `type` and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateTimeError {
    /// Pydantic error type.
    pub kind: &'static str,
    /// Pydantic message.
    pub msg: String,
}

/// Parse like a Pydantic `datetime` field; `Ok` is the naive wall clock.
pub fn parse_lax(raw: &str) -> Result<NaiveDateTime, DateTimeError> {
    let bytes = raw.as_bytes();
    let config = DateTimeConfig {
        timestamp_unit: TimestampUnit::Infer,
        time_config: TimeConfig {
            microseconds_precision_overflow_behavior:
                MicrosecondsPrecisionOverflowBehavior::Truncate,
            unix_timestamp_offset: Some(0),
        },
    };
    if let Ok(dt) = DateTime::parse_bytes_with_config(bytes, &config) {
        return wall_clock(
            dt.date.year,
            dt.date.month,
            dt.date.day,
            dt.time.hour,
            dt.time.minute,
            dt.time.second,
            dt.time.microsecond,
        );
    }
    let date_config = DateConfig {
        timestamp_unit: TimestampUnit::Infer,
    };
    match Date::parse_bytes_with_config(bytes, &date_config) {
        Ok(d) => wall_clock(d.year, d.month, d.day, 0, 0, 0, 0),
        Err(e) => Err(DateTimeError {
            kind: PARSE_ERROR_KIND,
            msg: format!(
                "Input should be a valid datetime or date, {}",
                speedate_message(&e)
            ),
        }),
    }
}

/// Parse like a Pydantic `datetime` field and keep the offset: the naive
/// wall clock and the UTC offset in seconds (`None` for a naive value; `Some(0)`
/// for `Z` and for unix timestamps, which Pydantic makes aware UTC values).
pub fn parse_lax_offset(raw: &str) -> Result<(NaiveDateTime, Option<i32>), DateTimeError> {
    let wall = parse_lax(raw)?;
    let config = DateTimeConfig {
        timestamp_unit: TimestampUnit::Infer,
        time_config: TimeConfig {
            microseconds_precision_overflow_behavior:
                MicrosecondsPrecisionOverflowBehavior::Truncate,
            unix_timestamp_offset: Some(0),
        },
    };
    let offset = DateTime::parse_bytes_with_config(raw.as_bytes(), &config)
        .ok()
        .and_then(|dt| dt.time.tz_offset);
    Ok((wall, offset))
}

/// Parse like a Pydantic `datetime` field, then `time_utils.to_naive_utc`:
/// an aware value (an offset, `Z`, or a unix timestamp) is converted to UTC,
/// a naive one is taken to be UTC already.
pub fn parse_lax_utc(raw: &str) -> Result<NaiveDateTime, DateTimeError> {
    let (wall, offset) = parse_lax_offset(raw)?;
    Ok(wall - chrono::Duration::seconds(i64::from(offset.unwrap_or(0))))
}

/// `err.get_documentation()`, as pydantic-core puts it in its message.
fn speedate_message(e: &speedate::ParseError) -> &'static str {
    e.get_documentation().unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn wall_clock(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    micros: u32,
) -> Result<NaiveDateTime, DateTimeError> {
    let date = NaiveDate::from_ymd_opt(i32::from(year), u32::from(month), u32::from(day));
    let time = NaiveTime::from_hms_micro_opt(
        u32::from(hour),
        u32::from(minute),
        u32::from(second),
        micros,
    );
    match (date, time) {
        (Some(d), Some(t)) => Ok(NaiveDateTime::new(d, t)),
        _ => Err(DateTimeError {
            kind: PARSE_ERROR_KIND,
            msg: "Input should be a valid datetime or date, value is outside expected range".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn utc_conversion_follows_to_naive_utc() {
        let iso = |raw: &str| copilot_core::time::to_pydantic_iso(parse_lax_utc(raw).unwrap());
        assert_eq!(iso("2026-01-02T03:04:05+05:00"), "2026-01-01T22:04:05");
        assert_eq!(iso("2026-01-02T03:04:05Z"), "2026-01-02T03:04:05");
        assert_eq!(iso("2026-01-02T03:04:05"), "2026-01-02T03:04:05");
        assert_eq!(iso("2026-01-02"), "2026-01-02T00:00:00");
        assert!(parse_lax_utc("nope").is_err());
        assert_eq!(
            parse_lax_offset("2026-01-02T03:04:05-03:30").unwrap().1,
            Some(-12600)
        );
        assert_eq!(parse_lax_offset("1700000000").unwrap().1, Some(0));
        assert_eq!(parse_lax_offset("2026-01-02").unwrap().1, None);
    }

    #[test]
    fn matches_pydantic_vectors() {
        let raw = include_str!("pydantic_datetime_vectors.json");
        let doc: Value = serde_json::from_str(raw).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() > 40);
        for v in vectors {
            let input = v["input"].as_str().unwrap();
            let got = parse_lax(input);
            match v.get("ok").and_then(Value::as_str) {
                Some(want) => {
                    let got = got.unwrap_or_else(|e| panic!("{input:?}: {e:?}"));
                    let iso = copilot_core::time::to_pydantic_iso(got);
                    assert_eq!(iso, want, "{input:?}");
                }
                None => {
                    let e = got.expect_err(input);
                    assert_eq!(e.kind, v["type"].as_str().unwrap(), "{input:?}");
                    assert_eq!(e.msg, v["msg"].as_str().unwrap(), "{input:?}");
                }
            }
        }
    }
}
