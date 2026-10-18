//! Timestamp helpers — port of `app/time_utils.py`.
//!
//! CoPilot's MySQL columns are naive `DATETIME` holding UTC wall-clock time
//! (MySQL keeps whole seconds unless the column says otherwise). Everything
//! written to the database goes through [`now_utc_naive`]; API responses
//! render those values the way Pydantic does — ISO-8601 without an offset.

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Timelike, Utc};

/// Current UTC time, timezone-aware.
pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

/// `datetime.utcnow()`: current UTC wall-clock time, microsecond precision.
pub fn now_utc_micros() -> NaiveDateTime {
    let now = Utc::now().naive_utc();
    now.with_nanosecond(now.nanosecond() / 1_000 * 1_000)
        .unwrap_or(now)
}

/// What MySQL stores for a fractional value in a `DATETIME` (scale 0)
/// column: rounded to the nearest second (half up), not truncated.
pub fn mysql_datetime(t: NaiveDateTime) -> NaiveDateTime {
    let whole = t.with_nanosecond(0).unwrap_or(t);
    if t.nanosecond() >= 500_000_000 {
        whole + chrono::Duration::seconds(1)
    } else {
        whole
    }
}

/// Current UTC time as a `DATETIME` column stores `datetime.utcnow()`
/// written by the Python backend at the same instant — so rows written by
/// either service read back identically.
pub fn now_utc_naive() -> NaiveDateTime {
    mysql_datetime(now_utc_micros())
}

/// Convert an aware time to the naive UTC form the columns hold
/// (`time_utils.to_naive_utc`).
pub fn to_naive_utc(t: DateTime<Utc>) -> NaiveDateTime {
    t.naive_utc()
}

/// Render a naive UTC value like Pydantic's `datetime` serializer
/// (`2026-10-14T07:47:00`, fractional seconds only when present).
pub fn to_pydantic_iso(t: NaiveDateTime) -> String {
    if t.nanosecond() == 0 {
        t.format("%Y-%m-%dT%H:%M:%S").to_string()
    } else {
        t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
    }
}

/// Talon's timestamp format (JavaScript `toISOString`), for payloads sent to
/// Talon.
pub fn to_talon_iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse an ISO-8601 timestamp as sent by API clients: an aware value is
/// converted to UTC, a naive one is taken to already be UTC.
pub fn parse_client_datetime(s: &str) -> Option<NaiveDateTime> {
    let s = s.trim();
    if let Ok(aware) = DateTime::parse_from_rfc3339(s) {
        return Some(aware.with_timezone(&Utc).naive_utc());
    }
    [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M",
    ]
    .iter()
    .find_map(|f| NaiveDateTime::parse_from_str(s, f).ok())
}

/// Serde helpers rendering `DATETIME` values the way Pydantic does.
pub mod pydantic {
    use chrono::NaiveDateTime;
    use serde::Serializer;

    /// `#[serde(serialize_with = "pydantic::datetime")]`.
    pub fn datetime<S: Serializer>(t: &NaiveDateTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::to_pydantic_iso(*t))
    }

    /// `#[serde(serialize_with = "pydantic::opt_datetime")]`.
    pub fn opt_datetime<S: Serializer>(t: &Option<NaiveDateTime>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.serialize_str(&super::to_pydantic_iso(*t)),
            None => s.serialize_none(),
        }
    }
}

/// Python's `round(x, ndigits)` for floats: correctly rounded on the exact
/// binary value, ties to even — which is what Rust's float formatting does.
pub fn py_round(x: f64, ndigits: usize) -> f64 {
    format!("{x:.ndigits$}").parse::<f64>().unwrap_or(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pydantic_rendering() {
        let t = NaiveDateTime::parse_from_str("2026-01-02 03:04:05", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(to_pydantic_iso(t), "2026-01-02T03:04:05");
        let frac = t.with_nanosecond(250_000_000).unwrap();
        assert_eq!(to_pydantic_iso(frac), "2026-01-02T03:04:05.250000");
    }

    #[test]
    fn py_round_matches_python() {
        // round(2.125, 2) == 2.12; round(2.675, 2) == 2.67; round(0.857142, 3) == 0.857
        assert_eq!(py_round(2.125, 2), 2.12);
        assert_eq!(py_round(2.675, 2), 2.67);
        assert_eq!(py_round(0.857_142, 3), 0.857);
        assert_eq!(py_round(66.666_666, 2), 66.67);
    }

    #[test]
    fn naive_now_has_whole_seconds() {
        assert_eq!(now_utc_naive().nanosecond(), 0);
        assert_eq!(now_utc_micros().nanosecond() % 1_000, 0);
    }

    #[test]
    fn mysql_rounds_half_up() {
        let t = |s: &str| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").unwrap();
        assert_eq!(
            mysql_datetime(t("2026-01-01 23:59:59.5")),
            t("2026-01-02 00:00:00.0")
        );
        assert_eq!(
            mysql_datetime(t("2026-01-01 10:00:00.499999")),
            t("2026-01-01 10:00:00.0")
        );
    }

    #[test]
    fn client_datetimes() {
        let aware = parse_client_datetime("2026-01-02T05:04:05+02:00").unwrap();
        assert_eq!(to_pydantic_iso(aware), "2026-01-02T03:04:05");
        let naive = parse_client_datetime("2026-01-02T03:04:05").unwrap();
        assert_eq!(aware, naive);
        assert!(parse_client_datetime("yesterday").is_none());
    }
}
