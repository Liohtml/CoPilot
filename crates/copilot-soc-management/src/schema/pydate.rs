//! Pydantic's lax `date` validation (pydantic-core's `date` validator over
//! `speedate`, the version pinned in the workspace):
//!
//! 1. a string parses as a date (`YYYY-MM-DD`, or a unix timestamp that is
//!    an exact day);
//! 2. else — and for numbers — as a datetime, which must be at midnight
//!    (`date_from_datetime_inexact`); a datetime that does not parse is
//!    `date_from_datetime_parsing` with the datetime parser's reason;
//! 3. anything else is `date_type`.

use chrono::NaiveDate;
use serde_json::Value;
use speedate::{
    Date, DateConfig, DateTime, DateTimeConfig, MicrosecondsPrecisionOverflowBehavior, TimeConfig,
    TimestampUnit,
};
use strum::EnumMessage;

/// Why a value is not a date: Pydantic's `type` and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateError {
    /// Pydantic error type.
    pub kind: &'static str,
    /// Pydantic message.
    pub msg: String,
}

fn datetime_config() -> DateTimeConfig {
    DateTimeConfig {
        timestamp_unit: TimestampUnit::Infer,
        time_config: TimeConfig {
            microseconds_precision_overflow_behavior:
                MicrosecondsPrecisionOverflowBehavior::Truncate,
            unix_timestamp_offset: Some(0),
        },
    }
}

fn parsing(e: &speedate::ParseError) -> DateError {
    DateError {
        kind: "date_from_datetime_parsing",
        msg: format!(
            "Input should be a valid date or datetime, {}",
            e.get_documentation().unwrap_or_default()
        ),
    }
}

fn exact(dt: &DateTime) -> Result<NaiveDate, DateError> {
    let t = &dt.time;
    if (t.hour, t.minute, t.second, t.microsecond) != (0, 0, 0, 0) {
        return Err(DateError {
            kind: "date_from_datetime_inexact",
            msg: "Datetimes provided to dates should have zero time - e.g. be exact dates".into(),
        });
    }
    to_date(&dt.date)
}

fn to_date(d: &Date) -> Result<NaiveDate, DateError> {
    NaiveDate::from_ymd_opt(i32::from(d.year), u32::from(d.month), u32::from(d.day)).ok_or(
        DateError {
            kind: "date_from_datetime_parsing",
            msg: "Input should be a valid date or datetime, value is outside expected range".into(),
        },
    )
}

/// Validate one JSON value as a Pydantic `date`.
pub fn parse_date(value: &Value) -> Result<NaiveDate, DateError> {
    match value {
        Value::String(s) => {
            let config = DateConfig {
                timestamp_unit: TimestampUnit::Infer,
            };
            if let Ok(d) = Date::parse_bytes_with_config(s.as_bytes(), &config) {
                return to_date(&d);
            }
            match DateTime::parse_bytes_with_config(s.as_bytes(), &datetime_config()) {
                Ok(dt) => exact(&dt),
                Err(e) => Err(parsing(&e)),
            }
        }
        Value::Number(n) => {
            let parsed = match n.as_i64() {
                Some(i) => DateTime::from_timestamp_with_config(i, 0, &datetime_config()),
                None => DateTime::from_float_with_config(
                    n.as_f64().unwrap_or(f64::NAN),
                    &datetime_config(),
                ),
            };
            match parsed {
                Ok(dt) => exact(&dt),
                Err(e) => Err(parsing(&e)),
            }
        }
        _ => Err(DateError {
            kind: "date_type",
            msg: "Input should be a valid date".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(v: Value) -> String {
        parse_date(&v).unwrap().to_string()
    }

    fn err(v: Value) -> (&'static str, String) {
        let e = parse_date(&v).unwrap_err();
        (e.kind, e.msg)
    }

    /// The pydantic 2.12 / pydantic-core 2.46 answers for the same inputs.
    #[test]
    fn matches_pydantic() {
        assert_eq!(ok(json!(86400)), "1970-01-02");
        assert_eq!(ok(json!(86400.0)), "1970-01-02");
        assert_eq!(ok(json!(-86400)), "1969-12-31");
        assert_eq!(ok(json!("86400")), "1970-01-02");
        assert_eq!(ok(json!("2026-01-01T00:00:00Z")), "2026-01-01");
        assert_eq!(ok(json!("2026-01-01T00:00:00+02:00")), "2026-01-01");
        assert_eq!(ok(json!("2026-01-01T00:00:00.000")), "2026-01-01");
        assert_eq!(ok(json!(172_800_000)), "1975-06-24");
        assert_eq!(err(json!(true)).0, "date_type");
        assert_eq!(err(json!(null)).0, "date_type");
        assert_eq!(err(json!("20260101")).0, "date_from_datetime_inexact");
        assert_eq!(
            err(json!("2026-1-1")).1,
            "Input should be a valid date or datetime, input is too short"
        );
        assert_eq!(
            err(json!(" 2026-01-01")).1,
            "Input should be a valid date or datetime, invalid character in year"
        );
        assert_eq!(
            err(json!("2026-13-01")).1,
            "Input should be a valid date or datetime, month value is outside expected range of 1-12"
        );
        assert_eq!(
            err(json!(1e20)).1,
            "Input should be a valid date or datetime, dates after 9999 are not supported as unix timestamps"
        );
        assert_eq!(err(json!(1.5)).0, "date_from_datetime_inexact");
    }
}
