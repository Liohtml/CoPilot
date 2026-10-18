//! The logs router's reads and purges over `log_entries`, and
//! `TimeRangeModel.validate_time_range`.
//!
//! The reads are SQLAlchemy's `select(LogEntry)` (every column, no `ORDER
//! BY`), so MySQL returns the rows in the same order to either backend. The
//! time-range routes filter in the process as Python does — every row is
//! read, then kept when `log.timestamp >= datetime.now() -
//! timedelta(days=N)`, with `N` the integer before the unit whatever the unit
//! (`1h` and `1w` both mean one day) and `now` the process's *local* time.

use chrono::{Datelike, Duration, NaiveDateTime};
use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_db::{Db, DbError};

use super::schema::LogRow;

const COLUMNS: &str = "log_entries.id, log_entries.timestamp, log_entries.event_type, \
     log_entries.user_id, log_entries.route, log_entries.method, log_entries.status_code, \
     log_entries.message, log_entries.additional_info";

/// `select(LogEntry)`.
pub async fn all_logs(db: &Db) -> Result<Vec<LogRow>, DbError> {
    Ok(
        sqlx::query_as::<_, LogRow>(&format!("SELECT {COLUMNS} FROM log_entries"))
            .fetch_all(db.pool())
            .await?,
    )
}

/// `select(LogEntry).filter(LogEntry.user_id == user_id)`.
pub async fn logs_of_user(db: &Db, user_id: i64) -> Result<Vec<LogRow>, DbError> {
    Ok(sqlx::query_as::<_, LogRow>(&format!(
        "SELECT {COLUMNS} FROM log_entries WHERE log_entries.user_id = ?"
    ))
    .bind(user_id)
    .fetch_all(db.pool())
    .await?)
}

/// `select(LogEntry).filter(LogEntry.event_type == event_type)` (the
/// column's collation decides: `info` rows match `Info`).
pub async fn logs_of_event_type(db: &Db, event_type: &str) -> Result<Vec<LogRow>, DbError> {
    Ok(sqlx::query_as::<_, LogRow>(&format!(
        "SELECT {COLUMNS} FROM log_entries WHERE log_entries.event_type = ?"
    ))
    .bind(event_type)
    .fetch_all(db.pool())
    .await?)
}

/// `for log in logs: await session.delete(log)` then one commit: the rows
/// read, deleted by primary key in one transaction.
pub async fn delete_rows(db: &Db, rows: &[LogRow]) -> Result<(), DbError> {
    let mut tx = db.pool().begin().await?;
    for chunk in rows.chunks(500) {
        let marks = vec!["?"; chunk.len()].join(", ");
        let sql = format!("DELETE FROM log_entries WHERE log_entries.id IN ({marks})");
        let mut q = sqlx::query(&sql);
        for r in chunk {
            q = q.bind(r.id);
        }
        q.execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// `int(text)` for a `str`, base 10, as CPython 3.11 parses it: Unicode
/// decimal digits and spaces become ASCII first, surrounding whitespace is
/// stripped, one sign, digits with single underscores between them, at most
/// 4300 digits. `Err` is its `ValueError`; `Ok(None)`: it parses but does
/// not fit 128 bits.
pub fn py_int(text: &str) -> Result<Option<i128>, String> {
    let invalid = || {
        let mut r = str_repr(text);
        if r.chars().count() > 200 {
            r = r.chars().take(200).collect();
        }
        format!("invalid literal for int() with base 10: {r}")
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
        return Err(format!(
            "Exceeds the limit (4300 digits) for integer string conversion: value has {} \
             digits; use sys.set_int_max_str_digits() to increase the limit",
            clean.len()
        ));
    }
    Ok(clean
        .parse::<i128>()
        .ok()
        .map(|n| if negative { -n } else { n }))
}

/// What `validate_time_range` does with a value it does not accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeRangeError {
    /// `raise RequestValidationError([{"loc": ("time_range",), "msg": …,
    /// "type": "value_error.time_range"}])`.
    Invalid(&'static str),
    /// An exception Pydantic does not catch (`value[-1]` of `""`: an
    /// `IndexError`): a bare 500.
    Crash(&'static str),
}

const BETWEEN: &str = "The integer part should be between 1 and 7.";
const FORMAT: &str =
    "Invalid format. Time range should be an integer followed by a unit (h, d, w).";
const UNIT: &str = "Invalid unit. Use 'h' for hours, 'd' for days, and 'w' for weeks.";
const POSITIVE: &str = "The integer part should be greater than 0.";
const WEEK: &str = "The maximum allowed time range is 1 week.";

/// `TimeRangeModel.validate_time_range` on the union's value (`int` or
/// `str`): the value to keep.
pub fn validate_time_range(value: &PyValue) -> Result<String, TimeRangeError> {
    match value {
        PyValue::Int(digits) => {
            let in_range = !digits.starts_with('-')
                && digits.len() <= 2
                && digits.parse::<i64>().is_ok_and(|n| (1..=7).contains(&n));
            if in_range {
                Ok(format!("{digits}d"))
            } else {
                Err(TimeRangeError::Invalid(BETWEEN))
            }
        }
        PyValue::Str(s) => {
            let Some(unit) = s.chars().last() else {
                return Err(TimeRangeError::Crash(
                    "IndexError: string index out of range",
                ));
            };
            let head: String = s.chars().take(s.chars().count() - 1).collect();
            let int_part = py_int(&head).map_err(|_| TimeRangeError::Invalid(FORMAT))?;
            if !matches!(unit, 'h' | 'd' | 'w') {
                return Err(TimeRangeError::Invalid(UNIT));
            }
            // `None`: more than 128 bits, positive or negative.
            let positive = match int_part {
                Some(n) => n > 0,
                None => !head.trim_start().starts_with('-'),
            };
            if !positive {
                return Err(TimeRangeError::Invalid(POSITIVE));
            }
            if unit == 'w' && int_part != Some(1) {
                return Err(TimeRangeError::Invalid(WEEK));
            }
            Ok(s.clone())
        }
        // The union only yields `str` or `int`.
        _ => Err(TimeRangeError::Invalid(
            "Invalid type. Time range should be either an integer or a string.",
        )),
    }
}

/// `datetime.now() - timedelta(days=int(time_range[:-1]))`, or the
/// `OverflowError` either raises (`timedelta`'s 999999999 days, or a date
/// before year 1).
pub fn window_start(time_range: &str, now: NaiveDateTime) -> Result<NaiveDateTime, String> {
    let head: String = time_range
        .chars()
        .take(time_range.chars().count().saturating_sub(1))
        .collect();
    let days =
        py_int(&head)?.ok_or_else(|| "Python int too large to convert to C int".to_string())?;
    if days.abs() > 999_999_999 {
        return Err(format!("days={days}; must have magnitude <= 999999999"));
    }
    let start = i64::try_from(days)
        .ok()
        .and_then(|d| now.checked_sub_signed(Duration::days(d)))
        .filter(|t| t.year() >= 1 && t.year() <= 9999)
        .ok_or_else(|| "date value out of range".to_string())?;
    Ok(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> PyValue {
        PyValue::Str(v.into())
    }

    #[test]
    fn time_ranges_validate_like_python() {
        // Recorded with the backend's TimeRangeModel.
        let ok = [
            ("1d", "1d"),
            ("1w", "1w"),
            ("+2d", "+2d"),
            (" 2d", " 2d"),
            ("1_0d", "1_0d"),
        ];
        for (input, want) in ok {
            assert_eq!(
                validate_time_range(&s(input)).as_deref(),
                Ok(want),
                "{input}"
            );
        }
        assert_eq!(validate_time_range(&s("\u{0661}d")).unwrap(), "\u{0661}d");
        assert_eq!(
            validate_time_range(&PyValue::Int("3".into())).unwrap(),
            "3d"
        );
        let bad = [
            ("0h", POSITIVE),
            ("-1d", POSITIVE),
            ("2w", WEEK),
            ("x", FORMAT),
            ("5", FORMAT),
            ("1x", UNIT),
            ("1__0d", FORMAT),
        ];
        for (input, want) in bad {
            assert_eq!(
                validate_time_range(&s(input)),
                Err(TimeRangeError::Invalid(want)),
                "{input}"
            );
        }
        for n in ["8", "0", "-3", "100000000000000000000"] {
            assert_eq!(
                validate_time_range(&PyValue::Int(n.into())),
                Err(TimeRangeError::Invalid(BETWEEN))
            );
        }
        assert!(matches!(
            validate_time_range(&s("")),
            Err(TimeRangeError::Crash(_))
        ));
    }

    #[test]
    fn windows_count_days_whatever_the_unit() {
        let now =
            NaiveDateTime::parse_from_str("2026-10-17 10:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let day =
            NaiveDateTime::parse_from_str("2026-10-16 10:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(window_start("1h", now).unwrap(), day);
        assert_eq!(window_start("1w", now).unwrap(), day);
        assert_eq!(window_start("1d", now).unwrap(), day);
        assert!(window_start("1000000000d", now).is_err());
        assert!(window_start("999999999d", now).is_err());
        assert!(window_start("700000d", now).is_ok());
    }
}

#[cfg(test)]
mod vectors {
    //! `platform_vectors.json`'s `time_range` (`scripts/gen-platform-vectors.py`):
    //! `TimeRangeModel.model_validate(body)` against the backend.

    use super::*;
    use copilot_auth::pyvalue::loads;
    use copilot_upstream::model::{Invalid, Loc, Ty, field, validate_body};

    use crate::logs::schema::TIME_RANGE_MODEL;

    #[test]
    fn time_ranges_follow_the_vectors() {
        let doc = loads(include_str!("../platform_vectors.json")).unwrap();
        let PyValue::List(cases) = doc.get("time_range").unwrap().clone() else {
            panic!("time_range")
        };
        for case in cases {
            let body = case.get("body").unwrap();
            let label = body.py_repr();
            let outcome = validate_body(&Ty::Model(&TIME_RANGE_MODEL), body)
                .map(|dump| validate_time_range(field(&dump, "time_range")));
            if let Some(PyValue::Str(want)) = case.get("ok") {
                assert_eq!(outcome, Ok(Ok(want.clone())), "{label}");
            } else if let Some(PyValue::Str(want)) = case.get("invalid") {
                match outcome {
                    Ok(Err(TimeRangeError::Invalid(msg))) => assert_eq!(msg, want, "{label}"),
                    other => panic!("{label}: {other:?}"),
                }
            } else if case.get("crash").is_some() {
                assert!(
                    matches!(outcome, Ok(Err(TimeRangeError::Crash(_)))),
                    "{label}: {outcome:?}"
                );
            } else {
                let Some(PyValue::List(errors)) = case.get("errors") else {
                    panic!("bad vector {label}")
                };
                let Err(Invalid::Errors(ours)) = outcome else {
                    panic!("{label}: {outcome:?}")
                };
                assert_eq!(ours.len(), errors.len(), "{label}");
                for (o, t) in ours.iter().zip(errors) {
                    assert_eq!(
                        Some(o.kind),
                        t.get("type").and_then(PyValue::as_str),
                        "{label}"
                    );
                    assert_eq!(Some(o.msg.as_str()), t.get("msg").and_then(PyValue::as_str));
                    let loc: Vec<String> = o
                        .loc
                        .iter()
                        .map(|l| match l {
                            Loc::Key(k) => k.clone(),
                            Loc::Index(i) => i.to_string(),
                        })
                        .collect();
                    let want: Vec<String> = match t.get("loc") {
                        Some(PyValue::List(items)) => items.iter().map(PyValue::py_str).collect(),
                        _ => Vec::new(),
                    };
                    assert_eq!(loc, want, "{label}");
                }
            }
        }
    }
}
