//! Reporting periods and the buckets their trends are drawn in — port of
//! `soc_management/domain/periods.py`.
//!
//! Periods are half-open, `[start, end)`, in naive UTC. A period's *previous*
//! period is the same length immediately before it.
//!
//! Python's `datetime` spans the years 1 to 9999 and raises past them;
//! chrono's range is wider, so every arithmetic step here checks Python's
//! range and reports leaving it as [`OutOfRange`]: `datetime ± timedelta`
//! raises `OverflowError` (a bare 500), `replace(year=10000)` a `ValueError`
//! (the backend's 400 with its text).

use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, Timelike};

/// A computation left Python's `datetime` range (years 1–9999).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutOfRange {
    /// `datetime ± timedelta`: `OverflowError("date value out of range")`.
    Overflow,
    /// `datetime.replace(year=…)`: `ValueError("year N is out of range")`.
    Year(i32),
}

impl std::fmt::Display for OutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overflow => f.write_str("date value out of range"),
            Self::Year(y) => write!(f, "year {y} is out of range"),
        }
    }
}

impl std::error::Error for OutOfRange {}

/// Keep `t` only inside Python's `datetime` range.
pub fn in_range(t: Option<NaiveDateTime>) -> Result<NaiveDateTime, OutOfRange> {
    t.filter(|t| (1..=9999).contains(&t.year()))
        .ok_or(OutOfRange::Overflow)
}

/// `MAX_PERIOD`: a year and a day.
pub fn max_period() -> Duration {
    Duration::days(366)
}

/// `Bucket`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    /// Hourly.
    Hour,
    /// Daily.
    Day,
    /// Weekly (ISO weeks, Monday).
    Week,
    /// Monthly.
    Month,
}

impl Bucket {
    /// Every value, in the Python enum's order.
    pub const ALL: [Self; 4] = [Self::Hour, Self::Day, Self::Week, Self::Month];

    /// Wire values, in order.
    pub const VALUES: [&'static str; 4] = ["hour", "day", "week", "month"];

    /// Wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
        }
    }

    /// The enum for a wire value.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.as_str() == value)
    }
}

/// `Period`: `[start, end)`, naive UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Period {
    /// Inclusive start.
    pub start: NaiveDateTime,
    /// Exclusive end.
    pub end: NaiveDateTime,
}

/// `Period.__post_init__`'s `ValueError`.
pub const START_BEFORE_END: &str = "The period must start before it ends";

/// `requested_period`'s cap.
pub const TOO_LONG: &str = "The period cannot be longer than 366 days";

impl Period {
    /// `Period(start, end)`.
    pub fn new(start: NaiveDateTime, end: NaiveDateTime) -> Result<Self, &'static str> {
        if start >= end {
            return Err(START_BEFORE_END);
        }
        Ok(Self { start, end })
    }

    /// `length`.
    pub fn length(&self) -> Duration {
        self.end - self.start
    }

    /// `previous()`: the same length immediately before.
    pub fn previous(&self) -> Result<Self, OutOfRange> {
        let start = in_range(self.start.checked_sub_signed(self.length()))?;
        Ok(Self {
            start,
            end: self.start,
        })
    }

    /// `contains(moment)`.
    pub fn contains(&self, moment: NaiveDateTime) -> bool {
        self.start <= moment && moment < self.end
    }
}

/// `requested_period(start, end)`: the invariant plus the reporting cap;
/// `Err` is the `ValueError` text.
pub fn requested_period(start: NaiveDateTime, end: NaiveDateTime) -> Result<Period, &'static str> {
    let period = Period::new(start, end)?;
    if period.length() > max_period() {
        return Err(TOO_LONG);
    }
    Ok(period)
}

/// `auto_bucket(period)`: roughly 24–60 points whatever the range.
pub fn auto_bucket(period: &Period) -> Bucket {
    let micros = period.length().num_microseconds().unwrap_or(i64::MAX);
    let days = micros as f64 / 1e6 / 86400.0;
    if days <= 2.0 {
        Bucket::Hour
    } else if days <= 62.0 {
        Bucket::Day
    } else if days <= 182.0 {
        Bucket::Week
    } else {
        Bucket::Month
    }
}

fn midnight(moment: NaiveDateTime) -> NaiveDateTime {
    moment.date().and_hms_opt(0, 0, 0).unwrap_or(moment)
}

/// `floor_to(moment, bucket)`.
pub fn floor_to(moment: NaiveDateTime, bucket: Bucket) -> Result<NaiveDateTime, OutOfRange> {
    match bucket {
        Bucket::Hour => Ok(moment
            .date()
            .and_hms_opt(moment.hour(), 0, 0)
            .unwrap_or(moment)),
        Bucket::Day => Ok(midnight(moment)),
        Bucket::Week => {
            let day = midnight(moment);
            let back = Duration::days(i64::from(day.weekday().num_days_from_monday()));
            in_range(day.checked_sub_signed(back))
        }
        Bucket::Month => {
            let d = moment.date();
            Ok(NaiveDate::from_ymd_opt(d.year(), d.month(), 1)
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .unwrap_or(moment))
        }
    }
}

/// `next_start(moment, bucket)`.
pub fn next_start(moment: NaiveDateTime, bucket: Bucket) -> Result<NaiveDateTime, OutOfRange> {
    let step = match bucket {
        Bucket::Hour => Duration::hours(1),
        Bucket::Day => Duration::days(1),
        Bucket::Week => Duration::weeks(1),
        Bucket::Month => {
            let (y, m) = if moment.month() == 12 {
                (moment.year() + 1, 1)
            } else {
                (moment.year(), moment.month() + 1)
            };
            if y > 9999 {
                return Err(OutOfRange::Year(y));
            }
            return in_range(
                NaiveDate::from_ymd_opt(y, m, moment.day()).map(|d| d.and_time(moment.time())),
            );
        }
    };
    in_range(moment.checked_add_signed(step))
}

/// `bucket_starts(period, bucket)`: the start of every bucket the period
/// touches, oldest first.
pub fn bucket_starts(period: &Period, bucket: Bucket) -> Result<Vec<NaiveDateTime>, OutOfRange> {
    let mut starts = Vec::new();
    let mut cursor = floor_to(period.start, bucket)?;
    while cursor < period.end {
        starts.push(cursor);
        cursor = next_start(cursor, bucket)?;
    }
    Ok(starts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    #[test]
    fn periods_and_caps() {
        assert_eq!(
            requested_period(at("2026-01-02 00:00:00"), at("2026-01-01 00:00:00")),
            Err(START_BEFORE_END)
        );
        assert_eq!(
            requested_period(at("2025-01-01 00:00:00"), at("2026-01-02 00:00:01")),
            Err(TOO_LONG)
        );
        let p = requested_period(at("2025-01-01 00:00:00"), at("2026-01-02 00:00:00")).unwrap();
        assert_eq!(p.previous().unwrap().start, at("2024-01-01 00:00:00"));
        assert!(p.contains(p.start) && !p.contains(p.end));
        assert_eq!(
            Period::new(at("0001-01-01 00:00:00"), at("0001-02-01 00:00:00"))
                .unwrap()
                .previous(),
            Err(OutOfRange::Overflow)
        );
        let end = Period::new(at("9999-11-15 00:00:00"), at("9999-12-31 00:00:00")).unwrap();
        assert_eq!(
            bucket_starts(&end, Bucket::Month),
            Err(OutOfRange::Year(10000))
        );
        assert_eq!(
            OutOfRange::Year(10000).to_string(),
            "year 10000 is out of range"
        );
    }

    #[test]
    fn buckets_follow_the_length() {
        let p = |a: &str, b: &str| Period::new(at(a), at(b)).unwrap();
        assert_eq!(
            auto_bucket(&p("2026-01-01 00:00:00", "2026-01-03 00:00:00")),
            Bucket::Hour
        );
        assert_eq!(
            auto_bucket(&p("2026-01-01 00:00:00", "2026-01-03 00:00:01")),
            Bucket::Day
        );
        assert_eq!(
            auto_bucket(&p("2026-01-01 00:00:00", "2026-04-01 00:00:00")),
            Bucket::Week
        );
        assert_eq!(
            auto_bucket(&p("2025-01-01 00:00:00", "2026-01-01 00:00:00")),
            Bucket::Month
        );
    }

    #[test]
    fn bucket_starts_cover_the_period() {
        let p = Period::new(at("2026-01-28 10:30:00"), at("2026-03-02 00:00:00")).unwrap();
        assert_eq!(
            bucket_starts(&p, Bucket::Month).unwrap(),
            vec![
                at("2026-01-01 00:00:00"),
                at("2026-02-01 00:00:00"),
                at("2026-03-01 00:00:00")
            ]
        );
        // 2026-01-28 is a Wednesday: the week starts on Monday the 26th.
        assert_eq!(
            bucket_starts(&p, Bucket::Week).unwrap()[0],
            at("2026-01-26 00:00:00")
        );
        let dec = Period::new(at("2025-12-15 00:00:00"), at("2026-01-15 00:00:00")).unwrap();
        assert_eq!(
            bucket_starts(&dec, Bucket::Month).unwrap(),
            vec![at("2025-12-01 00:00:00"), at("2026-01-01 00:00:00")]
        );
        assert_eq!(
            floor_to(at("2026-01-28 10:30:59"), Bucket::Hour).unwrap(),
            at("2026-01-28 10:00:00")
        );
    }
}
