//! The time an SLA clock runs on — port of `soc_management/domain/calendar.py`
//! and the reads of `services/calendars.py`.
//!
//! A clock answers two questions: `add(start, seconds)` (when does a target
//! expire?) and `elapsed(start, end)` (how much of a target did an interval
//! use?). [`Clock::Continuous`] is wall-clock time; a [`BusinessCalendar`]
//! counts only the working windows of a week in an IANA timezone, minus
//! holidays. All instants are naive UTC with microsecond precision, and the
//! seconds are `f64` like Python's `timedelta.total_seconds()`.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::LazyLock;

use chrono::{Datelike, Duration, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde_json::Value;
use sqlx::MySqlConnection;

use crate::SlaError;

/// `WEEKDAYS` (0 = Monday).
pub const WEEKDAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// `_MAX_SEARCH_DAYS`.
const MAX_SEARCH_DAYS: usize = 731;

/// A working window of a local day.
pub type Window = (NaiveTime, NaiveTime);

/// `timedelta.total_seconds()` of `b - a`.
pub fn total_seconds(a: NaiveDateTime, b: NaiveDateTime) -> f64 {
    let micros = (b - a).num_microseconds().unwrap_or(i64::MAX);
    micros as f64 / 1e6
}

/// `start + timedelta(seconds=seconds)`: whole seconds plus the fraction
/// rounded half-even to the microsecond (CPython's `timedelta` constructor).
pub fn add_seconds(start: NaiveDateTime, seconds: f64) -> NaiveDateTime {
    let whole = seconds.trunc();
    let micros = ((seconds - whole) * 1e6).round_ties_even();
    start + Duration::seconds(whole as i64) + Duration::microseconds(micros as i64)
}

/// Working windows per weekday in `timezone`, minus `holidays`.
#[derive(Debug, Clone, PartialEq)]
pub struct BusinessCalendar {
    /// IANA name.
    pub timezone: String,
    tz: Tz,
    week: [Vec<Window>; 7],
    holidays: HashSet<NaiveDate>,
}

fn validate_windows(mut windows: Vec<Window>) -> Result<Vec<Window>, SlaError> {
    windows.sort();
    for (start, end) in &windows {
        if start >= end {
            return Err(SlaError::Calendar(format!(
                "A working window must start before it ends ({}–{})",
                start.format("%H:%M"),
                end.format("%H:%M")
            )));
        }
    }
    for pair in windows.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(SlaError::Calendar(
                "Working windows of one day must not overlap".into(),
            ));
        }
    }
    Ok(windows)
}

impl BusinessCalendar {
    /// `BusinessCalendar(timezone, week, holidays)` with its `__post_init__`
    /// checks; `week` is keyed by weekday (0 = Monday).
    pub fn new(
        timezone: &str,
        week: Vec<(usize, Vec<Window>)>,
        holidays: HashSet<NaiveDate>,
    ) -> Result<Self, SlaError> {
        let tz = Tz::from_str(timezone)
            .map_err(|_| SlaError::Calendar(format!("Unknown timezone '{timezone}'")))?;
        let mut normalised: [Vec<Window>; 7] = Default::default();
        let mut any = false;
        for (weekday, windows) in week {
            if weekday > 6 {
                return Err(SlaError::Calendar(
                    "Weekdays are 0 (Monday) to 6 (Sunday)".into(),
                ));
            }
            if !windows.is_empty() {
                normalised[weekday] = validate_windows(windows)?;
                any = true;
            }
        }
        if !any {
            return Err(SlaError::Calendar(
                "A business calendar needs at least one working window".into(),
            ));
        }
        Ok(Self {
            timezone: timezone.to_string(),
            tz,
            week: normalised,
            holidays,
        })
    }

    /// `BusinessCalendar.from_dict` over a `soc_sla_calendar` row.
    pub fn from_row(timezone: &str, week: &Value, holidays: &Value) -> Result<Self, SlaError> {
        let mut days = Vec::new();
        match week {
            Value::Object(map) => {
                for (name, windows) in map {
                    let Some(index) = WEEKDAYS.iter().position(|d| d == name) else {
                        return Err(SlaError::Calendar(format!("Unknown weekday '{name}'")));
                    };
                    let mut parsed = Vec::new();
                    match windows {
                        Value::Null => {}
                        Value::Array(items) => {
                            for item in items {
                                let pair =
                                    item.as_array().filter(|p| p.len() == 2).ok_or_else(|| {
                                        SlaError::Calendar("A window is [start, end]".into())
                                    })?;
                                parsed.push((parse_time(&pair[0])?, parse_time(&pair[1])?));
                            }
                        }
                        _ => return Err(SlaError::Calendar("Windows are a list".into())),
                    }
                    days.push((index, parsed));
                }
            }
            Value::Null => {}
            Value::Array(a) if a.is_empty() => {}
            _ => return Err(SlaError::Calendar("week is an object".into())),
        }
        let mut days_off = HashSet::new();
        match holidays {
            Value::Null => {}
            Value::Array(items) => {
                for item in items {
                    let text = match item {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    let day = NaiveDate::parse_from_str(&text, "%Y-%m-%d").map_err(|_| {
                        SlaError::Calendar(format!("Invalid isoformat string: '{text}'"))
                    })?;
                    days_off.insert(day);
                }
            }
            _ => return Err(SlaError::Calendar("holidays is a list".into())),
        }
        let timezone = if timezone.is_empty() { "UTC" } else { timezone };
        Self::new(timezone, days, days_off)
    }

    /// `office_hours()`: Monday to Friday, 09:00–17:00 in `timezone`.
    pub fn office_hours(timezone: &str) -> Result<Self, SlaError> {
        let window = (time(9, 0), time(17, 0));
        Self::new(
            timezone,
            (0..5).map(|d| (d, vec![window])).collect(),
            HashSet::new(),
        )
    }

    /// `windows_on(day)`: the working windows of a local day, as naive UTC.
    pub fn windows_on(&self, day: NaiveDate) -> Vec<(NaiveDateTime, NaiveDateTime)> {
        if self.holidays.contains(&day) {
            return Vec::new();
        }
        let weekday = day.weekday().num_days_from_monday() as usize;
        self.week[weekday]
            .iter()
            .map(|(start, end)| {
                (
                    self.to_utc(day.and_time(*start)),
                    self.to_utc(day.and_time(*end)),
                )
            })
            .collect()
    }

    /// `_to_utc`: `local.replace(tzinfo=zone)` (fold 0: the first of two
    /// ambiguous instants, the pre-transition offset inside a gap).
    fn to_utc(&self, local: NaiveDateTime) -> NaiveDateTime {
        match self.tz.from_local_datetime(&local) {
            LocalResult::Single(t) => t.naive_utc(),
            LocalResult::Ambiguous(first, _) => first.naive_utc(),
            LocalResult::None => {
                // The offset in force before the gap.
                let before = local - Duration::days(1);
                let offset = match self.tz.from_local_datetime(&before) {
                    LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => {
                        t.naive_local() - t.naive_utc()
                    }
                    LocalResult::None => Duration::zero(),
                };
                local - offset
            }
        }
    }

    fn local_day(&self, moment: NaiveDateTime) -> NaiveDate {
        Utc.from_utc_datetime(&moment)
            .with_timezone(&self.tz)
            .date_naive()
    }

    /// `add(start, seconds)`.
    pub fn add(&self, start: NaiveDateTime, seconds: f64) -> Result<NaiveDateTime, SlaError> {
        let mut remaining = seconds.max(0.0);
        let mut day = self.local_day(start) - Duration::days(1);
        for _ in 0..MAX_SEARCH_DAYS {
            for (window_start, window_end) in self.windows_on(day) {
                let begin = window_start.max(start);
                if begin >= window_end {
                    continue;
                }
                let available = total_seconds(begin, window_end);
                if remaining <= available {
                    return Ok(add_seconds(begin, remaining));
                }
                remaining -= available;
            }
            day += Duration::days(1);
        }
        Err(SlaError::Calendar(
            "The business calendar has no working time within two years".into(),
        ))
    }

    /// `elapsed(start, end)`: working seconds inside `[start, end)`.
    pub fn elapsed(&self, start: NaiveDateTime, end: NaiveDateTime) -> f64 {
        if end <= start {
            return 0.0;
        }
        let mut total = 0.0;
        let mut day = self.local_day(start) - Duration::days(1);
        let last = self.local_day(end);
        while day <= last {
            for (window_start, window_end) in self.windows_on(day) {
                let overlap = total_seconds(window_start.max(start), window_end.min(end));
                if overlap > 0.0 {
                    total += overlap;
                }
            }
            day += Duration::days(1);
        }
        total
    }
}

fn time(h: u32, m: u32) -> NaiveTime {
    NaiveTime::from_hms_opt(h, m, 0).unwrap_or(NaiveTime::MIN)
}

/// `_parse_time`: `HH:MM` through `int()`.
fn parse_time(value: &Value) -> Result<NaiveTime, SlaError> {
    let text = match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let bad = || SlaError::Calendar(format!("Times are HH:MM, got '{text}'"));
    let mut parts = text.split(':');
    let (Some(h), Some(m), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    let h: u32 = h
        .trim()
        .trim_start_matches('+')
        .parse()
        .map_err(|_| bad())?;
    let m: u32 = m
        .trim()
        .trim_start_matches('+')
        .parse()
        .map_err(|_| bad())?;
    NaiveTime::from_hms_opt(h, m, 0).ok_or_else(bad)
}

/// `DEFAULT_CALENDAR`: Monday to Friday, 09:00–17:00 UTC.
pub static DEFAULT_CALENDAR: LazyLock<BusinessCalendar> = LazyLock::new(|| {
    // UTC always parses and the windows are valid, so this never fails.
    BusinessCalendar::office_hours("UTC").unwrap_or_else(|_| BusinessCalendar {
        timezone: "UTC".into(),
        tz: Tz::UTC,
        week: Default::default(),
        holidays: HashSet::new(),
    })
});

/// A clock basis.
#[derive(Debug, Clone, Copy)]
pub enum Clock<'a> {
    /// `CONTINUOUS`: 24/7.
    Continuous,
    /// Business hours of a calendar.
    Business(&'a BusinessCalendar),
}

impl Clock<'_> {
    /// `clock.add(start, seconds)`.
    pub fn add(&self, start: NaiveDateTime, seconds: f64) -> Result<NaiveDateTime, SlaError> {
        match self {
            Clock::Continuous => Ok(add_seconds(start, seconds)),
            Clock::Business(c) => c.add(start, seconds),
        }
    }

    /// `clock.elapsed(start, end)`.
    pub fn elapsed(&self, start: NaiveDateTime, end: NaiveDateTime) -> f64 {
        match self {
            Clock::Continuous => total_seconds(start, end).max(0.0),
            Clock::Business(c) => c.elapsed(start, end),
        }
    }
}

/// `CalendarBook`: the global calendar and the customers' own.
#[derive(Debug, Clone, Default)]
pub struct CalendarBook {
    /// The deployment's calendar, if configured.
    pub global: Option<BusinessCalendar>,
    /// Per-customer calendars.
    pub by_customer: HashMap<String, BusinessCalendar>,
}

impl CalendarBook {
    /// `for_customer`: the customer's, else the global one, else the default.
    pub fn for_customer(&self, customer_code: Option<&str>) -> &BusinessCalendar {
        if let Some(c) = customer_code
            .filter(|c| !c.is_empty())
            .and_then(|c| self.by_customer.get(c))
        {
            return c;
        }
        self.global.as_ref().unwrap_or(&DEFAULT_CALENDAR)
    }

    /// `clock(customer_code, business_hours)`.
    pub fn clock(&self, customer_code: Option<&str>, business_hours: bool) -> Clock<'_> {
        if business_hours {
            Clock::Business(self.for_customer(customer_code))
        } else {
            Clock::Continuous
        }
    }
}

/// `calendars.load_book(session, codes)`: the global calendar plus those of
/// `codes`.
pub async fn load_book(
    conn: &mut MySqlConnection,
    codes: &[&str],
) -> Result<CalendarBook, SlaError> {
    let codes: Vec<&str> = codes.iter().copied().filter(|c| !c.is_empty()).collect();
    let mut sql = String::from(
        "SELECT customer_code, timezone, week, holidays FROM soc_sla_calendar \
         WHERE customer_code IS NULL",
    );
    if !codes.is_empty() {
        sql.push_str(" OR customer_code IN (");
        sql.push_str(&vec!["?"; codes.len()].join(", "));
        sql.push(')');
    }
    sql.push_str(" ORDER BY id");
    let mut query = sqlx::query_as::<_, (Option<String>, String, Value, Value)>(&sql);
    for code in &codes {
        query = query.bind(*code);
    }
    let rows = query.fetch_all(&mut *conn).await?;
    let mut book = CalendarBook::default();
    for (code, timezone, week, holidays) in &rows {
        match code {
            None if book.global.is_none() => {
                book.global = Some(BusinessCalendar::from_row(timezone, week, holidays)?);
            }
            None => {}
            Some(code) => {
                book.by_customer.insert(
                    code.clone(),
                    BusinessCalendar::from_row(timezone, week, holidays)?,
                );
            }
        }
    }
    Ok(book)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").unwrap()
    }

    #[test]
    fn continuous_adds_wall_clock_time() {
        let c = Clock::Continuous;
        assert_eq!(
            c.add(at("2026-01-02 03:04:05"), 90.0).unwrap(),
            at("2026-01-02 03:05:35")
        );
        assert_eq!(
            c.add(at("2026-01-02 03:04:05"), 1.5).unwrap(),
            at("2026-01-02 03:04:06.5")
        );
        assert_eq!(
            c.elapsed(at("2026-01-02 03:00:00"), at("2026-01-02 02:00:00")),
            0.0
        );
    }

    #[test]
    fn office_hours_skip_nights_and_weekends() {
        let cal = BusinessCalendar::office_hours("UTC").unwrap();
        // Friday 16:00 + 4h → Monday 12:00.
        assert_eq!(
            cal.add(at("2026-01-02 16:00:00"), 4.0 * 3600.0).unwrap(),
            at("2026-01-05 12:00:00")
        );
        // Saturday + 0 → Monday's first window.
        assert_eq!(
            cal.add(at("2026-01-03 10:00:00"), 0.0).unwrap(),
            at("2026-01-05 09:00:00")
        );
        assert_eq!(
            cal.elapsed(at("2026-01-02 16:00:00"), at("2026-01-05 10:00:00")),
            7200.0
        );
    }

    #[test]
    fn rome_business_hours_follow_dst() {
        let week = json!({"mon": [["09:00", "17:00"]], "tue": [["09:00", "17:00"]],
            "wed": [["09:00", "17:00"]], "thu": [["09:00", "17:00"]], "fri": [["09:00", "17:00"]]});
        let cal = BusinessCalendar::from_row("Europe/Rome", &week, &json!([])).unwrap();
        // Friday 16:00 Rome (15:00 UTC in winter) + 4 business hours → Monday 12:00 Rome.
        assert_eq!(
            cal.add(at("2026-01-02 15:00:00"), 4.0 * 3600.0).unwrap(),
            at("2026-01-05 11:00:00")
        );
        // Summer: 09:00 Rome is 07:00 UTC.
        assert_eq!(
            cal.add(at("2026-07-06 00:00:00"), 0.0).unwrap(),
            at("2026-07-06 07:00:00")
        );
    }

    #[test]
    fn holidays_and_validation() {
        let week = json!({"mon": [["09:00", "12:00"], ["13:00", "17:00"]]});
        let cal = BusinessCalendar::from_row("UTC", &week, &json!(["2026-01-05"])).unwrap();
        assert_eq!(
            cal.add(at("2026-01-05 08:00:00"), 3600.0).unwrap(),
            at("2026-01-12 10:00:00")
        );
        assert_eq!(
            cal.add(at("2026-01-12 11:30:00"), 3600.0).unwrap(),
            at("2026-01-12 13:30:00")
        );
        assert!(BusinessCalendar::from_row("UTC", &json!({"xyz": []}), &json!([])).is_err());
        assert!(BusinessCalendar::from_row("Mars/Base", &week, &json!([])).is_err());
        assert!(BusinessCalendar::from_row("UTC", &json!({}), &json!([])).is_err());
        let overlap = json!({"mon": [["09:00", "12:00"], ["11:00", "17:00"]]});
        assert!(BusinessCalendar::from_row("UTC", &overlap, &json!([])).is_err());
        let backwards = json!({"mon": [["12:00", "09:00"]]});
        assert!(BusinessCalendar::from_row("UTC", &backwards, &json!([])).is_err());
    }

    #[test]
    fn timedelta_rounding() {
        assert_eq!(
            add_seconds(at("2026-01-01 00:00:00"), 0.0000005),
            at("2026-01-01 00:00:00")
        );
        assert_eq!(
            add_seconds(at("2026-01-01 00:00:00"), 0.0000015),
            at("2026-01-01 00:00:00.000002")
        );
    }
}
