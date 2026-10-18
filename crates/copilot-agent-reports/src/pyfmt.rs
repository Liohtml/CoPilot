//! Python's renderings of the values these services hold: `datetime`s as
//! Pydantic serializes them and as `isoformat()` / `repr()` print them, and
//! the dict reprs that end up in messages.

use chrono::{NaiveDateTime, Timelike};

use copilot_auth::pyvalue::PyValue;
use copilot_ingest::py::IsoDateTime;

/// A naive `datetime` (`datetime.utcnow()`, a `DATETIME` column).
pub fn naive(t: NaiveDateTime) -> IsoDateTime {
    IsoDateTime {
        wall: t,
        offset_us: None,
    }
}

fn micros(t: &NaiveDateTime) -> u32 {
    t.nanosecond() / 1_000
}

fn wall(t: &NaiveDateTime) -> String {
    let mut out = t.format("%Y-%m-%dT%H:%M:%S").to_string();
    let us = micros(t);
    if us != 0 {
        out.push_str(&format!(".{us:06}"));
    }
    out
}

/// `±HH:MM[:SS[.ffffff]]` of an offset in microseconds (`isoformat()`'s).
fn offset_text(offset_us: i64) -> String {
    let sign = if offset_us < 0 { '-' } else { '+' };
    let a = offset_us.unsigned_abs();
    let (secs, us) = (a / 1_000_000, a % 1_000_000);
    let mut out = format!("{sign}{:02}:{:02}", secs / 3600, (secs % 3600) / 60);
    if secs % 60 != 0 || us != 0 {
        out.push_str(&format!(":{:02}", secs % 60));
    }
    if us != 0 {
        out.push_str(&format!(".{us:06}"));
    }
    out
}

/// A `datetime` field in Pydantic's JSON mode: `YYYY-MM-DDTHH:MM:SS[.ffffff]`,
/// then `Z` for UTC or `±HH:MM[:SS]` for another offset.
pub fn pydantic_iso(dt: &IsoDateTime) -> String {
    let mut out = wall(&dt.wall);
    match dt.offset_us {
        None => {}
        Some(0) => out.push('Z'),
        Some(off) => {
            let sign = if off < 0 { '-' } else { '+' };
            let secs = off.unsigned_abs() / 1_000_000;
            out.push_str(&format!(
                "{sign}{:02}:{:02}",
                secs / 3600,
                (secs % 3600) / 60
            ));
            if secs % 60 != 0 {
                out.push_str(&format!(":{:02}", secs % 60));
            }
        }
    }
    out
}

/// `datetime.isoformat()`: an aware value carries its offset (`+00:00`).
pub fn isoformat(dt: &IsoDateTime) -> String {
    let mut out = wall(&dt.wall);
    if let Some(off) = dt.offset_us {
        out.push_str(&offset_text(off));
    }
    out
}

/// `repr(datetime)` of a naive value (`datetime.datetime(2026, 1, 2, 3, 4,
/// 5, 600)`: the second and microsecond only when set).
pub fn datetime_repr(t: NaiveDateTime) -> String {
    use chrono::Datelike;
    let mut out = format!(
        "datetime.datetime({}, {}, {}, {}, {}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute()
    );
    let us = micros(&t);
    if us != 0 {
        out.push_str(&format!(", {}, {us}", t.second()));
    } else if t.second() != 0 {
        out.push_str(&format!(", {}", t.second()));
    }
    out.push(')');
    out
}

/// `json.loads(text)`, a failure being its `JSONDecodeError`.
pub fn json_loads(text: &str) -> Result<PyValue, copilot_upstream::py::PyExc> {
    copilot_upstream::json::py_loads(text).map_err(copilot_upstream::py::PyExc::JsonDecode)
}

/// A dict from pairs.
pub fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// `PyValue::Str`.
pub fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

/// An optional string.
pub fn opt(v: Option<impl Into<String>>) -> PyValue {
    v.map_or(PyValue::None, |v| PyValue::Str(v.into()))
}

/// An int.
pub fn int(v: impl ToString) -> PyValue {
    PyValue::Int(v.to_string())
}

/// A list of strings.
pub fn str_list(items: &[String]) -> PyValue {
    PyValue::List(items.iter().map(|i| PyValue::Str(i.clone())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").unwrap()
    }

    #[test]
    fn datetimes_render_as_python_does() {
        let utc = IsoDateTime {
            wall: at("2026-01-02 03:04:05.5"),
            offset_us: Some(0),
        };
        assert_eq!(pydantic_iso(&utc), "2026-01-02T03:04:05.500000Z");
        assert_eq!(isoformat(&utc), "2026-01-02T03:04:05.500000+00:00");
        let east = IsoDateTime {
            wall: at("2026-01-02 03:04:05"),
            offset_us: Some(-(5 * 3600 + 30 * 60) * 1_000_000),
        };
        assert_eq!(pydantic_iso(&east), "2026-01-02T03:04:05-05:30");
        assert_eq!(isoformat(&east), "2026-01-02T03:04:05-05:30");
        assert_eq!(
            isoformat(&naive(at("2026-01-02 03:04:05"))),
            "2026-01-02T03:04:05"
        );
        assert_eq!(
            datetime_repr(at("2026-10-16 16:17:07.040075")),
            "datetime.datetime(2026, 10, 16, 16, 17, 7, 40075)"
        );
        assert_eq!(
            datetime_repr(at("2026-10-16 16:17:00")),
            "datetime.datetime(2026, 10, 16, 16, 17)"
        );
        assert_eq!(
            datetime_repr(at("2026-10-16 16:17:09")),
            "datetime.datetime(2026, 10, 16, 16, 17, 9)"
        );
    }
}
