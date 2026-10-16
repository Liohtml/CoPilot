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

use copilot_auth::pyvalue::{PyValue, str_repr};

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
            .map_err(|_| SlaError::Calendar(format!("Unknown timezone {}", str_repr(timezone))))?;
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

    /// `BusinessCalendar.from_dict` over a `soc_sla_calendar` row, with
    /// Python's semantics on stored JSON (falsy values read as empty, a string
    /// iterates over its characters, `str(value)` before parsing) and its
    /// `ValueError` texts; what Python cannot read at all (a `TypeError`) is
    /// [`SlaError::Unreadable`].
    pub fn from_row(timezone: &str, week: &Value, holidays: &Value) -> Result<Self, SlaError> {
        let week = to_py(week);
        let mut days = Vec::new();
        if week.truthy() {
            for (name, windows) in py_dict(&week)? {
                let Some(index) = WEEKDAYS.iter().position(|d| name.as_str() == Some(*d)) else {
                    return Err(SlaError::Calendar(format!(
                        "Unknown weekday {}",
                        name.py_repr()
                    )));
                };
                let mut parsed = Vec::new();
                if windows.truthy() {
                    for item in py_iter(&windows)? {
                        let (start, end) = unpack_pair(&item)?;
                        parsed.push((parse_stored_time(&start)?, parse_stored_time(&end)?));
                    }
                }
                days.push((index, parsed));
            }
        }
        let holidays = to_py(holidays);
        let mut days_off = HashSet::new();
        if holidays.truthy() {
            for day in py_iter(&holidays)? {
                let text = day.py_str();
                days_off.insert(py_fromisoformat(&text).map_err(SlaError::Calendar)?);
            }
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

    /// `BusinessCalendar.from_dict` over a calendar sent to the API
    /// (`CalendarIn.to_domain`): `week` in the request's key order, each window
    /// already checked to be a pair; `Err` is the `ValueError` text.
    pub fn from_request(
        timezone: &str,
        week: &[(String, Vec<(String, String)>)],
        holidays: &[NaiveDate],
    ) -> Result<Self, String> {
        let mut days = Vec::new();
        for (name, windows) in week {
            let Some(index) = WEEKDAYS.iter().position(|d| d == name) else {
                return Err(format!("Unknown weekday {}", str_repr(name)));
            };
            let mut parsed = Vec::new();
            for (start, end) in windows {
                parsed.push((parse_request_time(start)?, parse_request_time(end)?));
            }
            days.push((index, parsed));
        }
        let timezone = if timezone.is_empty() { "UTC" } else { timezone };
        Self::new(timezone, days, holidays.iter().copied().collect()).map_err(|e| match e {
            SlaError::Calendar(text) => text,
            other => other.to_string(),
        })
    }

    /// `to_dict()["week"]`: every weekday, Monday first, with its windows as
    /// `HH:MM` pairs (a closed day is empty).
    pub fn week_out(&self) -> Vec<(&'static str, Vec<[String; 2]>)> {
        WEEKDAYS
            .iter()
            .zip(self.week.iter())
            .map(|(name, windows)| {
                let pairs = windows
                    .iter()
                    .map(|(s, e)| [s.format("%H:%M").to_string(), e.format("%H:%M").to_string()])
                    .collect();
                (*name, pairs)
            })
            .collect()
    }

    /// `to_dict()["holidays"]`: ISO dates, sorted.
    pub fn holidays_out(&self) -> Vec<String> {
        let mut days: Vec<NaiveDate> = self.holidays.iter().copied().collect();
        days.sort();
        days.into_iter()
            .map(|d| d.format("%Y-%m-%d").to_string())
            .collect()
    }

    /// `to_dict()["week"]` as JSON (what `soc_sla_calendar.week` stores).
    pub fn week_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        for (name, pairs) in self.week_out() {
            let list = pairs
                .into_iter()
                .map(|[s, e]| Value::Array(vec![Value::String(s), Value::String(e)]))
                .collect();
            map.insert(name.to_string(), Value::Array(list));
        }
        Value::Object(map)
    }

    /// `to_dict()["holidays"]` as JSON.
    pub fn holidays_json(&self) -> Value {
        Value::Array(self.holidays_out().into_iter().map(Value::String).collect())
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

/// The code points of `0` in every Unicode 14.0 decimal digit run (category
/// `Nd`, ten consecutive values each) — what CPython 3.11's `int()` accepts
/// besides ASCII digits.
const DECIMAL_ZEROS: [u32; 66] = [
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6,
    0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80,
    0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0,
    0xFF10, 0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0,
    0x11650, 0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x16A60, 0x16AC0,
    0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E950, 0x1FBF0,
];

/// A character's decimal value, as `int()` reads it.
fn decimal_value(c: char) -> Option<u32> {
    let cp = u32::from(c);
    DECIMAL_ZEROS
        .iter()
        .find(|zero| (**zero..**zero + 10).contains(&cp))
        .map(|zero| cp - zero)
}

/// Python's `int()` of a string: surrounding whitespace (Rust's `trim` is
/// the same set), an optional sign, decimal digits of any script with
/// single underscores between them.
fn py_int(text: &str) -> Option<i64> {
    let t = text.trim();
    let (negative, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let chars: Vec<char> = digits.chars().collect();
    if chars.is_empty() || chars[0] == '_' || chars[chars.len() - 1] == '_' || digits.contains("__")
    {
        return None;
    }
    let mut n: i64 = 0;
    for c in chars {
        if c == '_' {
            continue;
        }
        n = n
            .checked_mul(10)?
            .checked_add(i64::from(decimal_value(c)?))?;
    }
    Some(if negative { -n } else { n })
}

/// `_parse_time` of a request value: `str(value).split(":")` into exactly two
/// parts, `time(int(h), int(m))`; any failure is `Times are HH:MM, got …`.
fn parse_request_time(value: &str) -> Result<NaiveTime, String> {
    let bad = || format!("Times are HH:MM, got {}", str_repr(value));
    let mut parts = value.split(':');
    let (Some(h), Some(m), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    let (Some(h), Some(m)) = (py_int(h), py_int(m)) else {
        return Err(bad());
    };
    if !(0..=23).contains(&h) || !(0..=59).contains(&m) {
        return Err(bad());
    }
    NaiveTime::from_hms_opt(h as u32, m as u32, 0).ok_or_else(bad)
}

/// A stored JSON value as Python's `json.loads` returns it.
fn to_py(v: &Value) -> PyValue {
    match v {
        Value::Null => PyValue::None,
        Value::Bool(b) => PyValue::Bool(*b),
        Value::Number(n) if n.is_i64() || n.is_u64() => PyValue::Int(n.to_string()),
        Value::Number(n) => PyValue::Float(n.as_f64().unwrap_or(f64::NAN)),
        Value::String(s) => PyValue::Str(s.clone()),
        Value::Array(items) => PyValue::List(items.iter().map(to_py).collect()),
        Value::Object(map) => {
            PyValue::Dict(map.iter().map(|(k, v)| (k.clone(), to_py(v))).collect())
        }
    }
}

fn py_type(v: &PyValue) -> &'static str {
    match v {
        PyValue::None => "NoneType",
        PyValue::Bool(_) => "bool",
        PyValue::Int(_) => "int",
        PyValue::Float(_) => "float",
        PyValue::Str(_) => "str",
        PyValue::List(_) => "list",
        PyValue::Dict(_) => "dict",
    }
}

/// `iter(value)`: a list's items, a string's characters, a dict's keys.
fn py_iter(v: &PyValue) -> Result<Vec<PyValue>, SlaError> {
    match v {
        PyValue::List(items) => Ok(items.clone()),
        PyValue::Str(s) => Ok(s.chars().map(|c| PyValue::Str(c.to_string())).collect()),
        PyValue::Dict(items) => Ok(items.iter().map(|(k, _)| PyValue::Str(k.clone())).collect()),
        other => Err(SlaError::Unreadable(format!(
            "'{}' object is not iterable",
            py_type(other)
        ))),
    }
}

/// `dict(value).items()` of a truthy stored week: a mapping as it is, a
/// sequence of pairs folded in order (a repeated key keeps its first place
/// and takes its last value).
fn py_dict(v: &PyValue) -> Result<Vec<(PyValue, PyValue)>, SlaError> {
    let elements = match v {
        PyValue::Dict(items) => {
            return Ok(items
                .iter()
                .map(|(k, v)| (PyValue::Str(k.clone()), v.clone()))
                .collect());
        }
        other => py_iter(other)?,
    };
    let mut out: Vec<(PyValue, PyValue)> = Vec::new();
    for (i, element) in elements.iter().enumerate() {
        if matches!(
            element,
            PyValue::None | PyValue::Bool(_) | PyValue::Int(_) | PyValue::Float(_)
        ) {
            return Err(SlaError::Unreadable(format!(
                "cannot convert dictionary update sequence element #{i} to a sequence"
            )));
        }
        let pair = py_iter(element)?;
        if pair.len() != 2 {
            return Err(SlaError::Calendar(format!(
                "dictionary update sequence element #{i} has length {}; 2 is required",
                pair.len()
            )));
        }
        let (key, value) = (pair[0].clone(), pair[1].clone());
        if let PyValue::List(_) | PyValue::Dict(_) = key {
            return Err(SlaError::Unreadable(format!(
                "unhashable type: '{}'",
                py_type(&key)
            )));
        }
        // Only a string key can name a weekday, and the first key that does
        // not raises before any value is read: only strings need folding.
        match out
            .iter_mut()
            .find(|(k, _)| key.as_str().is_some() && k.as_str() == key.as_str())
        {
            Some(slot) => slot.1 = value,
            None => out.push((key, value)),
        }
    }
    Ok(out)
}

/// `start, end = item`.
fn unpack_pair(item: &PyValue) -> Result<(PyValue, PyValue), SlaError> {
    let parts = match item {
        PyValue::None | PyValue::Bool(_) | PyValue::Int(_) | PyValue::Float(_) => {
            return Err(SlaError::Unreadable(format!(
                "cannot unpack non-iterable {} object",
                py_type(item)
            )));
        }
        other => py_iter(other)?,
    };
    match parts.len() {
        2 => Ok((parts[0].clone(), parts[1].clone())),
        n if n < 2 => Err(SlaError::Calendar(format!(
            "not enough values to unpack (expected 2, got {n})"
        ))),
        _ => Err(SlaError::Calendar(
            "too many values to unpack (expected 2)".into(),
        )),
    }
}

/// `_parse_time(value)` of a stored value: only a string can parse; the
/// message carries `repr(value)`.
fn parse_stored_time(value: &PyValue) -> Result<NaiveTime, SlaError> {
    match value {
        PyValue::Str(s) => parse_request_time(s).map_err(SlaError::Calendar),
        other => Err(SlaError::Calendar(format!(
            "Times are HH:MM, got {}",
            other.py_repr()
        ))),
    }
}

/// `date.fromisoformat(text)` as CPython 3.11 implements it: 7, 8 or 10
/// UTF-8 bytes; `YYYY-MM-DD`, `YYYYMMDD`, or an ISO week date (`YYYY-Www[-D]`,
/// `YYYYWww[D]`); bytes past what the form reads are ignored. `Err` is the
/// `ValueError` text.
fn py_fromisoformat(text: &str) -> Result<NaiveDate, String> {
    let invalid = || format!("Invalid isoformat string: {}", str_repr(text));
    let b = text.as_bytes();
    if !matches!(b.len(), 7 | 8 | 10) {
        return Err(invalid());
    }
    // C reads a NUL past the end, which is never a digit.
    let at = |i: usize| b.get(i).copied().unwrap_or(0);
    let digits = |from: usize, n: usize| -> Option<u32> {
        (from..from + n).try_fold(0u32, |acc, i| {
            let c = at(i);
            c.is_ascii_digit().then(|| acc * 10 + u32::from(c - b'0'))
        })
    };
    let year = digits(0, 4).ok_or_else(invalid)?;
    let mut p = 4;
    let separated = at(p) == b'-';
    if separated {
        p += 1;
    }
    let (year, month, day) = if at(p) == b'W' {
        p += 1;
        let week = digits(p, 2).ok_or_else(invalid)?;
        p += 2;
        let weekday = if p < b.len() {
            if separated {
                if at(p) != b'-' {
                    return Err(invalid());
                }
                p += 1;
            }
            digits(p, 1).ok_or_else(invalid)?
        } else {
            1
        };
        if !(1..=7).contains(&weekday) {
            return Err(invalid());
        }
        if year == 0 {
            // CPython's ordinal arithmetic has no year 0: week 53 is out of
            // range, any other week lands on month 0.
            return Err(if week == 53 || week == 0 {
                invalid()
            } else {
                "month must be in 1..12".into()
            });
        }
        let weekday = u8::try_from(weekday - 1)
            .ok()
            .and_then(|d| chrono::Weekday::try_from(d).ok())
            .ok_or_else(invalid)?;
        let date = i32::try_from(year)
            .ok()
            .and_then(|y| NaiveDate::from_isoywd_opt(y, week, weekday))
            .ok_or_else(invalid)?;
        if date.year() > 9999 {
            return Err(format!("year {} is out of range", date.year()));
        }
        return Ok(date);
    } else {
        let month = digits(p, 2).ok_or_else(invalid)?;
        p += 2;
        if separated {
            if at(p) != b'-' {
                return Err(invalid());
            }
            p += 1;
        }
        (year, month, digits(p, 2).ok_or_else(invalid)?)
    };
    if year == 0 {
        return Err(format!("year {year} is out of range"));
    }
    if !(1..=12).contains(&month) {
        return Err("month must be in 1..12".into());
    }
    i32::try_from(year)
        .ok()
        .and_then(|y| NaiveDate::from_ymd_opt(y, month, day))
        .ok_or_else(|| "day is out of range for month".into())
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

    /// `source(customer_code)`: `customer`, `global` or `default`.
    pub fn source(&self, customer_code: Option<&str>) -> &'static str {
        if customer_code
            .filter(|c| !c.is_empty())
            .is_some_and(|c| self.by_customer.contains_key(c))
        {
            return "customer";
        }
        if self.global.is_some() {
            "global"
        } else {
            "default"
        }
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

type CalendarRow = (Option<String>, String, Value, Value);

fn to_book(rows: &[CalendarRow]) -> Result<CalendarBook, SlaError> {
    let mut book = CalendarBook::default();
    for (code, timezone, week, holidays) in rows {
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
    let mut query = sqlx::query_as::<_, CalendarRow>(&sql);
    for code in &codes {
        query = query.bind(*code);
    }
    to_book(&query.fetch_all(&mut *conn).await?)
}

/// `calendars.load_book(session)` without a scope: every calendar.
pub async fn load_all_book(conn: &mut MySqlConnection) -> Result<CalendarBook, SlaError> {
    let rows = sqlx::query_as::<_, CalendarRow>(
        "SELECT customer_code, timezone, week, holidays FROM soc_sla_calendar ORDER BY id",
    )
    .fetch_all(&mut *conn)
    .await?;
    to_book(&rows)
}

/// `replace_calendar`: store a scope's calendar, replacing any previous one.
/// Does not commit.
pub async fn replace_calendar(
    conn: &mut MySqlConnection,
    customer_code: Option<&str>,
    calendar: &BusinessCalendar,
    actor: Option<&str>,
    now: NaiveDateTime,
) -> Result<(), SlaError> {
    match customer_code {
        None => {
            sqlx::query(
                "DELETE FROM soc_sla_calendar WHERE soc_sla_calendar.customer_code IS NULL",
            )
            .execute(&mut *conn)
            .await?;
        }
        Some(code) => {
            sqlx::query("DELETE FROM soc_sla_calendar WHERE soc_sla_calendar.customer_code = ?")
                .bind(code)
                .execute(&mut *conn)
                .await?;
        }
    }
    sqlx::query(
        "INSERT INTO soc_sla_calendar (customer_code, timezone, week, holidays, updated_at, \
         updated_by) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(customer_code)
    .bind(&calendar.timezone)
    .bind(calendar.week_json())
    .bind(calendar.holidays_json())
    .bind(copilot_core::time::mysql_datetime(now))
    .bind(actor)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `clear_calendar`: remove a customer's calendar; how many rows went.
pub async fn clear_calendar(
    conn: &mut MySqlConnection,
    customer_code: &str,
) -> Result<u64, SlaError> {
    let done = sqlx::query("DELETE FROM soc_sla_calendar WHERE soc_sla_calendar.customer_code = ?")
        .bind(customer_code)
        .execute(&mut *conn)
        .await?;
    Ok(done.rows_affected())
}

/// `customers_with_calendar(codes)`: sorted (`None`: every customer; an
/// empty list: nobody).
pub async fn customers_with_calendar(
    conn: &mut MySqlConnection,
    customer_codes: Option<&[String]>,
) -> Result<Vec<String>, SlaError> {
    let mut sql = String::from(
        "SELECT soc_sla_calendar.customer_code FROM soc_sla_calendar \
         WHERE soc_sla_calendar.customer_code IS NOT NULL",
    );
    if let Some(codes) = customer_codes {
        if codes.is_empty() {
            return Ok(Vec::new());
        }
        sql.push_str(" AND soc_sla_calendar.customer_code IN (");
        sql.push_str(&vec!["?"; codes.len()].join(", "));
        sql.push(')');
    }
    let mut query = sqlx::query_scalar::<_, String>(&sql);
    for code in customer_codes.unwrap_or_default() {
        query = query.bind(code);
    }
    let mut codes = query.fetch_all(&mut *conn).await?;
    codes.sort();
    Ok(codes)
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
    fn stored_rows_read_like_python() {
        // Expected texts from CPython 3.11.
        for (text, expected) in [
            ("2026-01-05", Ok("2026-01-05")),
            ("20260105", Ok("2026-01-05")),
            ("2026-W02-1", Ok("2026-01-05")),
            ("2026W021", Ok("2026-01-05")),
            ("2026W02", Ok("2026-01-05")),
            ("2026-W53", Ok("2026-12-28")),
            ("20260105xx", Ok("2026-01-05")),
            ("0001-W01-1", Ok("0001-01-01")),
            ("0004-W01-1", Ok("0003-12-29")),
            ("2026-005", Err("Invalid isoformat string: '2026-005'")),
            ("2026-1-5", Err("Invalid isoformat string: '2026-1-5'")),
            ("2026W0210", Err("Invalid isoformat string: '2026W0210'")),
            ("2026-W02-8", Err("Invalid isoformat string: '2026-W02-8'")),
            ("0000-W53", Err("Invalid isoformat string: '0000-W53'")),
            ("0000-W01-1", Err("month must be in 1..12")),
            ("0000-01-01", Err("year 0 is out of range")),
            ("9999-W52-7", Err("year 10000 is out of range")),
            ("2026-13-01", Err("month must be in 1..12")),
            ("2026-02-30", Err("day is out of range for month")),
            (
                "2026\u{e9}0105",
                Err("Invalid isoformat string: '2026\u{e9}0105'"),
            ),
        ] {
            let got = py_fromisoformat(text).map(|d| d.to_string());
            assert_eq!(got.as_deref().map_err(String::as_str), expected, "{text}");
        }
        assert_eq!(py_int("\u{663}"), Some(3));
        assert_eq!(py_int("\u{a0}0\u{3000}"), Some(0));
        assert_eq!(py_int("\u{660}_\u{669}"), Some(9));
        assert_eq!(py_int("\u{1c}5"), None);
        assert_eq!(py_int("+\u{661}"), Some(1));
        assert_eq!(py_int("- 1"), None);
        let msg = |week: Value, holidays: Value| {
            BusinessCalendar::from_row("UTC", &week, &holidays)
                .err()
                .map(|e| e.to_string())
        };
        assert!(msg(json!([["mon", [["09:00", "17:00"]]]]), json!(null)).is_none());
        assert_eq!(
            msg(json!("ab"), json!([])).unwrap(),
            "dictionary update sequence element #0 has length 1; 2 is required"
        );
        assert!(matches!(
            BusinessCalendar::from_row("UTC", &json!([5]), &json!([])),
            Err(SlaError::Unreadable(_))
        ));
        assert_eq!(
            msg(json!([[5, []]]), json!([])).unwrap(),
            "Unknown weekday 5"
        );
        assert_eq!(
            msg(json!({"mon": [["09:00"]]}), json!([])).unwrap(),
            "not enough values to unpack (expected 2, got 1)"
        );
        assert_eq!(
            msg(json!({"mon": [[9, "17:00"]]}), json!([])).unwrap(),
            "Times are HH:MM, got 9"
        );
        assert_eq!(
            msg(json!({"mon": [["09:00", "17:00"]]}), json!(["x"])).unwrap(),
            "Invalid isoformat string: 'x'"
        );
        assert!(
            msg(
                json!({"mon": [["\u{660}9:00", "17:00"]]}),
                json!([20260105])
            )
            .is_none()
        );
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
