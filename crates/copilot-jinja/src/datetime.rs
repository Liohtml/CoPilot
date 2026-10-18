//! `datetime.datetime`, `datetime.date` and `datetime.time` values: what the
//! case report contexts hand a template (the ORM's naive timestamps).
//!
//! `str()`, `repr()`, the public attributes and the methods a template has
//! reason to call (`strftime` in the C locale, `isoformat`, `date`, `time`,
//! `weekday`, `isoweekday`, `ctime`); the other attributes exist (so the
//! sandbox calls them missing or unsafe as CPython would) but raise
//! `NotImplementedError` when read.

use std::any::Any;
use std::rc::Rc;

use chrono::{Datelike, NaiveDate, NaiveDateTime, NaiveTime, Timelike};

use crate::error::{Error, Result};
use crate::objects::Method;
use crate::value::{Object, Value};

const DATETIME_ATTRS: &[&str] = &[
    "__add__",
    "__class__",
    "__delattr__",
    "__dir__",
    "__doc__",
    "__eq__",
    "__format__",
    "__ge__",
    "__getattribute__",
    "__getstate__",
    "__gt__",
    "__hash__",
    "__init__",
    "__init_subclass__",
    "__le__",
    "__lt__",
    "__ne__",
    "__new__",
    "__radd__",
    "__reduce__",
    "__reduce_ex__",
    "__repr__",
    "__rsub__",
    "__setattr__",
    "__sizeof__",
    "__str__",
    "__sub__",
    "__subclasshook__",
    "astimezone",
    "combine",
    "ctime",
    "date",
    "day",
    "dst",
    "fold",
    "fromisocalendar",
    "fromisoformat",
    "fromordinal",
    "fromtimestamp",
    "hour",
    "isocalendar",
    "isoformat",
    "isoweekday",
    "max",
    "microsecond",
    "min",
    "minute",
    "month",
    "now",
    "replace",
    "resolution",
    "second",
    "strftime",
    "strptime",
    "time",
    "timestamp",
    "timetuple",
    "timetz",
    "today",
    "toordinal",
    "tzinfo",
    "tzname",
    "utcfromtimestamp",
    "utcnow",
    "utcoffset",
    "utctimetuple",
    "weekday",
    "year",
];

const DATE_ATTRS: &[&str] = &[
    "__add__",
    "__class__",
    "__delattr__",
    "__dir__",
    "__doc__",
    "__eq__",
    "__format__",
    "__ge__",
    "__getattribute__",
    "__getstate__",
    "__gt__",
    "__hash__",
    "__init__",
    "__init_subclass__",
    "__le__",
    "__lt__",
    "__ne__",
    "__new__",
    "__radd__",
    "__reduce__",
    "__reduce_ex__",
    "__repr__",
    "__rsub__",
    "__setattr__",
    "__sizeof__",
    "__str__",
    "__sub__",
    "__subclasshook__",
    "ctime",
    "day",
    "fromisocalendar",
    "fromisoformat",
    "fromordinal",
    "fromtimestamp",
    "isocalendar",
    "isoformat",
    "isoweekday",
    "max",
    "min",
    "month",
    "replace",
    "resolution",
    "strftime",
    "timetuple",
    "today",
    "toordinal",
    "weekday",
    "year",
];

const TIME_ATTRS: &[&str] = &[
    "__class__",
    "__delattr__",
    "__dir__",
    "__doc__",
    "__eq__",
    "__format__",
    "__ge__",
    "__getattribute__",
    "__getstate__",
    "__gt__",
    "__hash__",
    "__init__",
    "__init_subclass__",
    "__le__",
    "__lt__",
    "__ne__",
    "__new__",
    "__reduce__",
    "__reduce_ex__",
    "__repr__",
    "__setattr__",
    "__sizeof__",
    "__str__",
    "__subclasshook__",
    "dst",
    "fold",
    "fromisoformat",
    "hour",
    "isoformat",
    "max",
    "microsecond",
    "min",
    "minute",
    "replace",
    "resolution",
    "second",
    "strftime",
    "tzinfo",
    "tzname",
    "utcoffset",
];

const DAYS: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// One of the three value kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moment {
    /// `datetime.datetime` (naive).
    DateTime(NaiveDateTime),
    /// `datetime.date`.
    Date(NaiveDate),
    /// `datetime.time` (naive).
    Time(NaiveTime),
}

impl Moment {
    fn date(&self) -> Option<NaiveDate> {
        match self {
            Moment::DateTime(d) => Some(d.date()),
            Moment::Date(d) => Some(*d),
            Moment::Time(_) => None,
        }
    }

    fn time(&self) -> Option<NaiveTime> {
        match self {
            Moment::DateTime(d) => Some(d.time()),
            Moment::Date(_) => None,
            Moment::Time(t) => Some(*t),
        }
    }
}

fn micro(t: &NaiveTime) -> u32 {
    t.nanosecond() / 1000
}

fn date_iso(d: &NaiveDate) -> String {
    format!("{:04}-{:02}-{:02}", d.year(), d.month(), d.day())
}

fn time_iso(t: &NaiveTime, timespec: &str) -> Result<String> {
    let base = format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second());
    let us = micro(t);
    Ok(match timespec {
        "auto" if us == 0 => base,
        "auto" | "microseconds" => format!("{base}.{us:06}"),
        "hours" => format!("{:02}", t.hour()),
        "minutes" => format!("{:02}:{:02}", t.hour(), t.minute()),
        "seconds" => base,
        "milliseconds" => format!("{base}.{:03}", us / 1000),
        _ => return Err(Error::value_error("Unknown timespec value")),
    })
}

/// `time.strftime` in the C locale, with Python's own `%f`.
pub fn strftime(m: &Moment, fmt: &str) -> String {
    let date = m
        .date()
        .unwrap_or_else(|| NaiveDate::from_ymd_opt(1900, 1, 1).unwrap_or_default());
    let time = m.time().unwrap_or_default();
    let wd = date.weekday().num_days_from_monday() as usize;
    let mut out = String::new();
    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let Some(d) = chars.next() else {
            out.push('%');
            break;
        };
        let hour12 = match time.hour() % 12 {
            0 => 12,
            h => h,
        };
        match d {
            'a' => out.push_str(&DAYS[wd][..3]),
            'A' => out.push_str(DAYS[wd]),
            'b' | 'h' => out.push_str(&MONTHS[date.month0() as usize][..3]),
            'B' => out.push_str(MONTHS[date.month0() as usize]),
            'c' => out.push_str(&strftime(m, "%a %b %e %H:%M:%S %Y")),
            'C' => out.push_str(&format!("{:02}", date.year() / 100)),
            'd' => out.push_str(&format!("{:02}", date.day())),
            'D' => out.push_str(&strftime(m, "%m/%d/%y")),
            'e' => out.push_str(&format!("{:>2}", date.day())),
            'f' => out.push_str(&format!("{:06}", micro(&time))),
            'F' => out.push_str(&strftime(m, "%Y-%m-%d")),
            'G' => out.push_str(&date.iso_week().year().to_string()),
            'g' => out.push_str(&format!("{:02}", date.iso_week().year() % 100)),
            'H' => out.push_str(&format!("{:02}", time.hour())),
            'I' => out.push_str(&format!("{hour12:02}")),
            'j' => out.push_str(&format!("{:03}", date.ordinal())),
            'k' => out.push_str(&format!("{:>2}", time.hour())),
            'l' => out.push_str(&format!("{hour12:>2}")),
            'm' => out.push_str(&format!("{:02}", date.month())),
            'M' => out.push_str(&format!("{:02}", time.minute())),
            'n' => out.push('\n'),
            'p' => out.push_str(if time.hour() < 12 { "AM" } else { "PM" }),
            'P' => out.push_str(if time.hour() < 12 { "am" } else { "pm" }),
            'r' => out.push_str(&strftime(m, "%I:%M:%S %p")),
            'R' => out.push_str(&strftime(m, "%H:%M")),
            'S' => out.push_str(&format!("{:02}", time.second())),
            't' => out.push('\t'),
            'T' | 'X' => out.push_str(&strftime(m, "%H:%M:%S")),
            'u' => out.push_str(&(wd + 1).to_string()),
            'U' => {
                let sunday_based =
                    (date.ordinal0() + 7 - date.weekday().num_days_from_sunday()) / 7;
                out.push_str(&format!("{sunday_based:02}"));
            }
            'V' => out.push_str(&format!("{:02}", date.iso_week().week())),
            'w' => out.push_str(&date.weekday().num_days_from_sunday().to_string()),
            'W' => {
                let monday_based =
                    (date.ordinal0() + 7 - date.weekday().num_days_from_monday()) / 7;
                out.push_str(&format!("{monday_based:02}"));
            }
            'x' => out.push_str(&strftime(m, "%m/%d/%y")),
            'y' => out.push_str(&format!("{:02}", date.year() % 100)),
            'Y' => out.push_str(&date.year().to_string()),
            'z' | 'Z' => {}
            '%' => out.push('%'),
            other => {
                out.push('%');
                out.push(other);
            }
        }
    }
    out
}

/// A `datetime` value in a template.
#[derive(Debug)]
pub struct PyMoment(pub Moment);

impl PyMoment {
    /// The template value.
    pub fn value(m: Moment) -> Value {
        Value::object(PyMoment(m))
    }

    fn class(&self) -> &'static str {
        match self.0 {
            Moment::DateTime(_) => "datetime",
            Moment::Date(_) => "date",
            Moment::Time(_) => "time",
        }
    }
}

fn arg_str(args: &[Value], kwargs: &[(Rc<str>, Value)], i: usize, name: &str) -> Option<Value> {
    args.get(i).cloned().or_else(|| {
        kwargs
            .iter()
            .find(|(k, _)| &**k == name)
            .map(|(_, v)| v.clone())
    })
}

impl Object for PyMoment {
    fn type_name(&self) -> &str {
        self.class()
    }

    fn module(&self) -> &str {
        "datetime"
    }

    fn repr(&self) -> Result<String> {
        Ok(match self.0 {
            Moment::DateTime(d) => {
                let mut parts = vec![
                    d.year().to_string(),
                    d.month().to_string(),
                    d.day().to_string(),
                    d.hour().to_string(),
                    d.minute().to_string(),
                    d.second().to_string(),
                    micro(&d.time()).to_string(),
                ];
                if parts.last().is_some_and(|p| p == "0") {
                    parts.pop();
                }
                if parts.last().is_some_and(|p| p == "0") {
                    parts.pop();
                }
                format!("datetime.datetime({})", parts.join(", "))
            }
            Moment::Date(d) => format!("datetime.date({}, {}, {})", d.year(), d.month(), d.day()),
            Moment::Time(t) => {
                let mut parts = vec![
                    t.hour().to_string(),
                    t.minute().to_string(),
                    t.second().to_string(),
                    micro(&t).to_string(),
                ];
                if parts.last().is_some_and(|p| p == "0") {
                    parts.pop();
                }
                if parts.last().is_some_and(|p| p == "0") {
                    parts.pop();
                }
                format!("datetime.time({})", parts.join(", "))
            }
        })
    }

    fn str(&self) -> Result<String> {
        Ok(match self.0 {
            Moment::DateTime(d) => {
                format!("{} {}", date_iso(&d.date()), time_iso(&d.time(), "auto")?)
            }
            Moment::Date(d) => date_iso(&d),
            Moment::Time(t) => time_iso(&t, "auto")?,
        })
    }

    fn attrs(&self) -> &'static [&'static str] {
        match self.0 {
            Moment::DateTime(_) => DATETIME_ATTRS,
            Moment::Date(_) => DATE_ATTRS,
            Moment::Time(_) => TIME_ATTRS,
        }
    }

    fn getattr(&self, me: &Value, name: &str) -> Option<Result<Value>> {
        let d = self.0.date();
        let t = self.0.time();
        let int = |n: u32| Some(Ok(Value::int(i64::from(n))));
        match (name, d, t) {
            ("year", Some(d), _) => Some(Ok(Value::int(i64::from(d.year())))),
            ("month", Some(d), _) => int(d.month()),
            ("day", Some(d), _) => int(d.day()),
            ("hour", _, Some(t)) => int(t.hour()),
            ("minute", _, Some(t)) => int(t.minute()),
            ("second", _, Some(t)) => int(t.second()),
            ("microsecond", _, Some(t)) => int(micro(&t)),
            ("tzinfo", _, Some(_)) => Some(Ok(Value::None)),
            ("fold", _, Some(_)) => int(0),
            ("strftime" | "isoformat", _, _) => Some(Ok(Method::value(me, name))),
            ("date" | "time" | "ctime" | "weekday" | "isoweekday", Some(_), _) => {
                Some(Ok(Method::value(me, name)))
            }
            _ if self.attrs().contains(&name) && !name.starts_with('_') => {
                Some(Err(Error::unsupported(format!(
                    "The attribute '{name}' of a {} value",
                    self.class()
                ))))
            }
            _ => None,
        }
    }

    fn call_method(
        &self,
        _me: &Value,
        name: &str,
        args: Vec<Value>,
        kwargs: Vec<(Rc<str>, Value)>,
    ) -> Option<Result<Value>> {
        Some((|| match name {
            "strftime" => {
                let fmt = arg_str(&args, &kwargs, 0, "format").ok_or_else(|| {
                    Error::type_error("strftime() missing required argument 'format' (pos 1)")
                })?;
                let fmt = fmt.as_str().ok_or_else(|| {
                    Error::type_error(format!(
                        "strftime() argument 1 must be str, not {}",
                        fmt.type_name()
                    ))
                })?;
                Ok(Value::str(strftime(&self.0, fmt)))
            }
            "isoformat" => match self.0 {
                Moment::DateTime(d) => {
                    let sep = arg_str(&args, &kwargs, 0, "sep")
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_else(|| "T".into());
                    let spec = arg_str(&args, &kwargs, 1, "timespec")
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_else(|| "auto".into());
                    Ok(Value::str(format!(
                        "{}{sep}{}",
                        date_iso(&d.date()),
                        time_iso(&d.time(), &spec)?
                    )))
                }
                Moment::Date(d) => Ok(Value::str(date_iso(&d))),
                Moment::Time(t) => {
                    let spec = arg_str(&args, &kwargs, 0, "timespec")
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_else(|| "auto".into());
                    Ok(Value::str(time_iso(&t, &spec)?))
                }
            },
            "date" => Ok(PyMoment::value(Moment::Date(
                self.0
                    .date()
                    .ok_or_else(|| Error::unsupported("date() of a time"))?,
            ))),
            "time" => Ok(PyMoment::value(Moment::Time(
                self.0.time().unwrap_or_default(),
            ))),
            "weekday" => Ok(Value::int(i64::from(
                self.0
                    .date()
                    .map_or(0, |d| d.weekday().num_days_from_monday()),
            ))),
            "isoweekday" => Ok(Value::int(i64::from(
                self.0
                    .date()
                    .map_or(0, |d| d.weekday().number_from_monday()),
            ))),
            "ctime" => Ok(Value::str(strftime(&self.0, "%a %b %e %H:%M:%S %Y"))),
            _ => Err(Error::unsupported(format!("{}.{name}()", self.class()))),
        })())
    }

    fn eq(&self, other: &Value) -> Option<bool> {
        Some(other.downcast::<PyMoment>().is_some_and(|o| o.0 == self.0))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(s: &str) -> Moment {
        Moment::DateTime(NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").unwrap())
    }

    #[test]
    fn str_and_repr_are_cpythons() {
        let a = PyMoment(dt("2024-01-02 03:04:05.000"));
        assert_eq!(a.str().unwrap(), "2024-01-02 03:04:05");
        assert_eq!(a.repr().unwrap(), "datetime.datetime(2024, 1, 2, 3, 4, 5)");
        let b = PyMoment(dt("2024-01-02 03:00:00.000250"));
        assert_eq!(b.str().unwrap(), "2024-01-02 03:00:00.000250");
        assert_eq!(
            b.repr().unwrap(),
            "datetime.datetime(2024, 1, 2, 3, 0, 0, 250)"
        );
        let c = PyMoment(dt("2024-01-02 03:04:00.000"));
        assert_eq!(c.repr().unwrap(), "datetime.datetime(2024, 1, 2, 3, 4)");
    }

    #[test]
    fn strftime_is_the_c_locale() {
        let m = dt("2024-03-05 14:07:09.123456");
        assert_eq!(
            strftime(&m, "%Y-%m-%d %H:%M:%S.%f"),
            "2024-03-05 14:07:09.123456"
        );
        assert_eq!(
            strftime(&m, "%a %A %b %B %j %I%p %y %%"),
            "Tue Tuesday Mar March 065 02PM 24 %"
        );
        assert_eq!(strftime(&m, "%c"), "Tue Mar  5 14:07:09 2024");
        assert_eq!(strftime(&m, "%U %W %u %w"), "09 10 2 2");
    }
}
