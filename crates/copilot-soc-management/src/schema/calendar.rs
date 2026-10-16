//! Business-hours calendar shapes — port of `soc_management/schema/calendar.py`.

use chrono::NaiveDate;
use copilot_sla::calendar::BusinessCalendar;
use copilot_web::validate::{Loc, LocPart, StrRules, Validator};
use serde::Serialize;
use serde::ser::SerializeMap;
use serde_json::{Map, Value};

use crate::schema::pydate::parse_date;

/// `WeekIn` rendered: every weekday, Monday first, as `[[start, end], …]`.
#[derive(Debug, Clone)]
pub struct WeekOut(pub Vec<(&'static str, Vec<[String; 2]>)>);

impl Serialize for WeekOut {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(self.0.len()))?;
        for (day, windows) in &self.0 {
            map.serialize_entry(day, windows)?;
        }
        map.end()
    }
}

/// `CalendarOut`.
#[derive(Debug, Clone, Serialize)]
pub struct CalendarOut {
    /// Scope (`None`: the deployment's).
    pub customer_code: Option<String>,
    /// `customer` | `global` | `default`.
    pub source: &'static str,
    /// IANA zone.
    pub timezone: String,
    /// Windows per weekday.
    pub week: WeekOut,
    /// ISO dates.
    pub holidays: Vec<String>,
}

impl CalendarOut {
    /// `CalendarOut(customer_code, source, **calendar.to_dict())`.
    pub fn new(
        customer_code: Option<String>,
        source: &'static str,
        cal: &BusinessCalendar,
    ) -> Self {
        Self {
            customer_code,
            source,
            timezone: cal.timezone.clone(),
            week: WeekOut(cal.week_out()),
            holidays: cal.holidays_out(),
        }
    }
}

/// `CalendarResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct CalendarResponse {
    /// Always true.
    pub success: bool,
    /// What happened.
    pub message: String,
    /// The calendar in force for the scope.
    pub calendar: CalendarOut,
    /// Customers with a calendar of their own.
    pub customers_with_calendar: Vec<String>,
    /// Open items whose due times moved.
    pub retargeted: i64,
}

/// `CalendarIn` as validated.
#[derive(Debug, Clone)]
pub struct CalendarIn {
    /// `None` edits the deployment's calendar.
    pub customer_code: Option<String>,
    /// Re-target open business-hours items.
    pub apply_to_open: bool,
    /// The calendar (`to_domain()`), once the model is valid.
    pub calendar: Option<BusinessCalendar>,
}

fn child(at: &Loc, part: LocPart) -> Loc {
    let mut l = at.clone();
    l.push(part);
    l
}

fn key(at: &Loc, name: &str) -> Loc {
    child(at, LocPart::Key(name.into()))
}

/// `Dict[str, List[List[str]]]`: the windows in the request's key order.
fn read_week(v: &mut Validator, value: &Value, at: &Loc) -> Vec<(String, Vec<Vec<String>>)> {
    let Value::Object(days) = value else {
        v.push(
            "dict_type",
            at.clone(),
            "Input should be a valid dictionary",
        );
        return Vec::new();
    };
    let mut out = Vec::new();
    for (day, windows) in days {
        let day_at = key(at, day);
        let Value::Array(windows) = windows else {
            v.push("list_type", day_at, "Input should be a valid list");
            continue;
        };
        let mut parsed = Vec::new();
        for (i, window) in windows.iter().enumerate() {
            let w_at = child(&day_at, LocPart::Index(i));
            let Value::Array(parts) = window else {
                v.push("list_type", w_at, "Input should be a valid list");
                continue;
            };
            let mut texts = Vec::new();
            for (j, part) in parts.iter().enumerate() {
                match part {
                    Value::String(s) => texts.push(s.clone()),
                    _ => v.push(
                        "string_type",
                        child(&w_at, LocPart::Index(j)),
                        "Input should be a valid string",
                    ),
                }
            }
            parsed.push(texts);
        }
        out.push((day.clone(), parsed));
    }
    out
}

fn read_holidays(v: &mut Validator, value: &Value, at: &Loc) -> Vec<NaiveDate> {
    let Value::Array(items) = value else {
        v.push("list_type", at.clone(), "Input should be a valid list");
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        match parse_date(item) {
            Ok(d) => out.push(d),
            Err(e) => v.push(e.kind, child(at, LocPart::Index(i)), e.msg),
        }
    }
    out
}

impl CalendarIn {
    /// Read and validate like Pydantic, then `_valid_calendar` (`to_domain`)
    /// once every field is valid.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let before = v.errors().len();
        let customer_code = v.opt_str(obj, at, "customer_code", StrRules::any());
        let timezone = v.str_or(obj, at, "timezone", StrRules::any(), "UTC");
        let week = match obj.get("week") {
            None => Vec::new(),
            Some(value) => read_week(v, value, &key(at, "week")),
        };
        let holidays = match obj.get("holidays") {
            None => Vec::new(),
            Some(value) => read_holidays(v, value, &key(at, "holidays")),
        };
        let apply_to_open = v.bool_or(obj, at, "apply_to_open", false);
        let mut calendar = None;
        if v.errors().len() == before {
            match to_domain(&timezone, &week, &holidays) {
                Ok(c) => calendar = Some(c),
                Err(msg) => v.push("value_error", at.clone(), format!("Value error, {msg}")),
            }
        }
        Self {
            customer_code,
            apply_to_open,
            calendar,
        }
    }
}

/// `CalendarIn.to_domain()`: every window a pair, then `from_dict`.
fn to_domain(
    timezone: &str,
    week: &[(String, Vec<Vec<String>>)],
    holidays: &[NaiveDate],
) -> Result<BusinessCalendar, String> {
    let mut pairs = Vec::with_capacity(week.len());
    for (_, windows) in week {
        for window in windows {
            if window.len() != 2 {
                return Err("A working window is a [start, end] pair of HH:MM times".into());
            }
        }
    }
    for (day, windows) in week {
        let ws = windows
            .iter()
            .map(|w| (w[0].clone(), w[1].clone()))
            .collect();
        pairs.push((day.clone(), ws));
    }
    BusinessCalendar::from_request(timezone, &pairs, holidays)
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_web::validate::body_loc;
    use serde_json::json;

    fn messages(body: Value) -> Vec<String> {
        let mut v = Validator::new();
        CalendarIn::read(&mut v, body.as_object().unwrap(), &body_loc());
        v.errors()
            .iter()
            .map(|e| e.to_item().message.unwrap_or_default())
            .collect()
    }

    #[test]
    fn errors_match_pydantic() {
        let mon = json!([["09:00", "17:00"]]);
        assert_eq!(
            messages(json!({"timezone": "Mars/Base", "week": {"mon": mon}})),
            vec!["Unknown timezone 'Mars/Base'"]
        );
        assert_eq!(
            messages(json!({"timezone": "O'Brien", "week": {"mon": mon}})),
            vec!["Unknown timezone \"O'Brien\""]
        );
        assert_eq!(
            messages(json!({"week": {"xyz": mon}})),
            vec!["Unknown weekday 'xyz'"]
        );
        assert_eq!(
            messages(json!({"week": {"mon": [["9", "17:00"]]}})),
            vec!["Times are HH:MM, got '9'"]
        );
        assert_eq!(
            messages(json!({"week": {"mon": [["24:00", "25:00"]]}})),
            vec!["Times are HH:MM, got '24:00'"]
        );
        assert_eq!(
            messages(json!({"week": {"mon": [["09:00"]]}})),
            vec!["A working window is a [start, end] pair of HH:MM times"]
        );
        assert_eq!(
            messages(json!({"week": {"mon": [["17:00", "09:00"]]}})),
            vec!["A working window must start before it ends (17:00–09:00)"]
        );
        assert_eq!(
            messages(json!({"week": {"mon": [["09:00", "12:00"], ["11:00", "17:00"]]}})),
            vec!["Working windows of one day must not overlap"]
        );
        assert_eq!(
            messages(json!({"week": {}})),
            vec!["A business calendar needs at least one working window"]
        );
        assert_eq!(
            messages(
                json!({"week": {"mon": "x"}, "holidays": ["2026-13-01", "2026-01-01T00:00:00"]})
            ),
            vec![
                "week.mon: Input should be a valid list",
                "holidays.0: Input should be a valid date or datetime, month value is outside expected range of 1-12"
            ]
        );
        assert_eq!(
            messages(json!({"week": {"mon": [[9, 17]]}})),
            vec![
                "week.mon.0.0: Input should be a valid string",
                "week.mon.0.1: Input should be a valid string"
            ]
        );
        assert_eq!(
            messages(json!({"week": {"mon": mon}, "timezone": null})),
            vec!["timezone: Input should be a valid string"]
        );
        assert!(messages(json!({"week": {"mon": mon}, "timezone": ""})).is_empty());
        assert!(messages(json!({"week": {"mon": [["-0:00", "+1:0_0"]]}})).is_empty());
    }
}
