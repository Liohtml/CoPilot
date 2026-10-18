//! The Python built-ins the ingest services lean on, with CPython 3.11's
//! semantics: `str.splitlines`, `str.split()`, `str.capitalize`,
//! `str.strip`, `os.path.basename`, `int()`, `json.dumps(indent=2)`,
//! `datetime.fromisoformat`, `datetime.fromtimestamp` and
//! `ipaddress.ip_address`.
//!
//! The values these services handle are Python values (`json.loads` of an
//! indexer document or a webhook body), so they are [`PyValue`]s here.

use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, Timelike};
use serde_json::Value;

use copilot_auth::pyvalue::{PyValue, float_repr, str_repr};
use copilot_wazuh::error::PyErr;

pub use copilot_web::form::{is_py_space, py_strip};

/// A serde value (an indexer answer, a request body) as the Python value
/// `json.loads` would have produced.
pub fn to_py(v: &Value) -> PyValue {
    match v {
        Value::Null => PyValue::None,
        Value::Bool(b) => PyValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PyValue::Int(i.to_string())
            } else if let Some(u) = n.as_u64() {
                PyValue::Int(u.to_string())
            } else {
                PyValue::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => PyValue::Str(s.clone()),
        Value::Array(items) => PyValue::List(items.iter().map(to_py).collect()),
        Value::Object(m) => PyValue::Dict(m.iter().map(|(k, v)| (k.clone(), to_py(v))).collect()),
    }
}

/// A Python value back as JSON (`NaN`/`inf` become `null`, as pydantic's
/// JSON writer prints them; integers beyond 64 bits become floats).
pub fn from_py(v: &PyValue) -> Value {
    match v {
        PyValue::None => Value::Null,
        PyValue::Bool(b) => Value::Bool(*b),
        PyValue::Int(i) => i
            .parse::<i64>()
            .map(Value::from)
            .or_else(|_| i.parse::<u64>().map(Value::from))
            .unwrap_or_else(|_| {
                i.parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(Value::Null, Value::Number)
            }),
        PyValue::Float(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
        PyValue::Str(s) => Value::String(s.clone()),
        PyValue::List(items) => Value::Array(items.iter().map(from_py).collect()),
        PyValue::Dict(items) => {
            Value::Object(items.iter().map(|(k, v)| (k.clone(), from_py(v))).collect())
        }
    }
}

/// `dict[key] = value`: replaced in place, else appended.
pub fn dict_set(d: &mut Vec<(String, PyValue)>, key: &str, value: PyValue) {
    match d.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => d.push((key.to_string(), value)),
    }
}

/// `dict.get(key)` over the pairs of a dict.
pub fn dict_get<'a>(d: &'a [(String, PyValue)], key: &str) -> Option<&'a PyValue> {
    d.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// `dict.pop(key, None)`.
pub fn dict_pop(d: &mut Vec<(String, PyValue)>, key: &str) -> Option<PyValue> {
    let i = d.iter().position(|(k, _)| k == key)?;
    Some(d.remove(i).1)
}

/// `type(v).__name__`.
pub fn type_name(v: &PyValue) -> &'static str {
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

/// `str.splitlines()`: `\n`, `\r`, `\r\n`, `\v`, `\f`, `\x1c`–`\x1e`,
/// `\x85`, U+2028 and U+2029 end a line.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let breaks = matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !breaks {
            continue;
        }
        out.push(&s[start..i]);
        let mut end = i + c.len_utf8();
        if c == '\r' {
            if let Some((j, '\n')) = chars.peek().copied() {
                chars.next();
                end = j + 1;
            }
        }
        start = end;
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `str.split()` (runs of whitespace, no empty parts).
pub fn split_ws(s: &str) -> Vec<&str> {
    s.split(is_py_space).filter(|p| !p.is_empty()).collect()
}

/// `str.capitalize()`: the first character in title case, the rest lower.
pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out = match TITLE_EXCEPTIONS.binary_search_by(|(c, _)| c.cmp(&first)) {
        Ok(i) => TITLE_EXCEPTIONS[i].1.to_string(),
        Err(_) => first.to_uppercase().collect(),
    };
    out.push_str(&chars.as_str().to_lowercase());
    out
}

/// `os.path.basename` (POSIX): what follows the last `/`.
pub fn basename(p: &str) -> &str {
    p.rfind('/').map_or(p, |i| &p[i + 1..])
}

/// `int(value)` for a JSON value: `Ok(None)` where Python raises
/// `TypeError`/`ValueError`, `Err` where it raises something else
/// (`OverflowError` for an infinite float).
pub fn py_int(v: &PyValue) -> Result<Option<i64>, String> {
    Ok(match v {
        PyValue::Bool(b) => Some(i64::from(*b)),
        PyValue::Int(i) => i.parse::<i64>().ok(),
        PyValue::Float(f) if f.is_nan() => None,
        PyValue::Float(f) if f.is_infinite() => {
            return Err("cannot convert float infinity to integer".into());
        }
        PyValue::Float(f) => Some(f.trunc() as i64),
        PyValue::Str(s) => copilot_core::config::python_int(py_strip(s)),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// json.dumps(obj, indent=2)
// ---------------------------------------------------------------------------

/// `json.dumps(obj, indent=2)` (`ensure_ascii`, `NaN` and `Infinity`
/// allowed, `", "`… replaced by `","` and newlines).
pub fn dumps_indent2(v: &PyValue) -> String {
    let mut out = String::new();
    write_indent(v, 0, &mut out);
    out
}

/// `json.dumps(value)` for a JSON column, where only validity matters
/// (MySQL re-serializes what it stores): `NaN`/`Infinity` written as
/// Python writes them, so MySQL refuses them as it refuses Python's.
pub fn dumps_compact_allow_nan(v: &PyValue) -> String {
    let mut out = String::new();
    write_compact(v, &mut out);
    out
}

fn write_compact(v: &PyValue, out: &mut String) {
    match v {
        PyValue::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_compact(item, out);
            }
            out.push(']');
        }
        PyValue::Dict(items) => {
            out.push('{');
            for (i, (k, val)) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_ascii(k, out);
                out.push(':');
                write_compact(val, out);
            }
            out.push('}');
        }
        scalar => write_indent(scalar, 0, out),
    }
}

fn write_indent(v: &PyValue, level: usize, out: &mut String) {
    match v {
        PyValue::None => out.push_str("null"),
        PyValue::Bool(true) => out.push_str("true"),
        PyValue::Bool(false) => out.push_str("false"),
        PyValue::Int(i) => out.push_str(i),
        PyValue::Float(f) => {
            if f.is_nan() {
                out.push_str("NaN");
            } else if f.is_infinite() {
                out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" });
            } else {
                out.push_str(&float_repr(*f));
            }
        }
        PyValue::Str(s) => encode_ascii(s, out),
        PyValue::List(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(level + 1, out);
                write_indent(item, level + 1, out);
            }
            newline(level, out);
            out.push(']');
        }
        PyValue::Dict(items) => {
            if items.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, val)) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(level + 1, out);
                encode_ascii(k, out);
                out.push_str(": ");
                write_indent(val, level + 1, out);
            }
            newline(level, out);
            out.push('}');
        }
    }
}

fn newline(level: usize, out: &mut String) {
    out.push('\n');
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// `py_encode_basestring_ascii`.
fn encode_ascii(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------
// datetime
// ---------------------------------------------------------------------------

/// What `datetime.fromisoformat` returns: the wall time and, when the
/// string named one, its UTC offset in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsoDateTime {
    /// The wall-clock fields.
    pub wall: NaiveDateTime,
    /// `utcoffset()` in microseconds, if aware.
    pub offset_us: Option<i64>,
}

/// The bytes of a C string: past the end reads as NUL.
struct CStr<'a>(&'a [u8]);

impl CStr<'_> {
    fn at(&self, i: usize) -> u8 {
        self.0.get(i).copied().unwrap_or(0)
    }
}

fn digit(b: u8) -> Option<i32> {
    b.is_ascii_digit().then(|| i32::from(b - b'0'))
}

/// `parse_digits`: `n` digits from `pos`; the position after them.
fn parse_digits(s: &CStr<'_>, pos: usize, n: usize, var: &mut i32) -> Option<usize> {
    let mut p = pos;
    for _ in 0..n {
        let d = digit(s.at(p))?;
        *var = *var * 10 + d;
        p += 1;
    }
    Some(p)
}

/// `_find_isoformat_datetime_separator`.
fn find_separator(s: &CStr<'_>, len: usize) -> usize {
    if len == 7 {
        return 7;
    }
    if s.at(4) == b'-' {
        if s.at(5) == b'W' {
            if len < 8 {
                return usize::MAX;
            }
            if len > 8 && s.at(8) == b'-' {
                if len == 9 {
                    return usize::MAX;
                }
                if len > 10 && s.at(10).is_ascii_digit() {
                    return 8;
                }
                return 10;
            }
            return 8;
        }
        return 10;
    }
    if s.at(4) == b'W' {
        let mut idx = 7;
        while idx < len {
            if !s.at(idx).is_ascii_digit() {
                break;
            }
            idx += 1;
        }
        if idx < 9 {
            return idx;
        }
        return if idx % 2 == 0 { 7 } else { 8 };
    }
    8
}

/// `parse_isoformat_date`: `Ok((year, month, day))` or the failure code.
fn parse_date(s: &CStr<'_>, len: usize) -> Result<(i32, i32, i32), i32> {
    let mut year = 0;
    let mut p = parse_digits(s, 0, 4, &mut year).ok_or(-1)?;
    let uses_separator = s.at(p) == b'-';
    if uses_separator {
        p += 1;
    }
    if s.at(p) == b'W' {
        p += 1;
        let mut week = 0;
        let mut day = 0;
        p = parse_digits(s, p, 2, &mut week).ok_or(-3)?;
        if p < len {
            if uses_separator {
                let c = s.at(p);
                p += 1;
                if c != b'-' {
                    return Err(-2);
                }
            }
            parse_digits(s, p, 1, &mut day).ok_or(-4)?;
        } else {
            day = 1;
        }
        return iso_to_ymd(year, week, day).ok_or(-5);
    }
    let mut month = 0;
    p = parse_digits(s, p, 2, &mut month).ok_or(-1)?;
    if uses_separator {
        let c = s.at(p);
        p += 1;
        if c != b'-' {
            return Err(-2);
        }
    }
    let mut day = 0;
    parse_digits(s, p, 2, &mut day).ok_or(-1)?;
    Ok((year, month, day))
}

/// `iso_to_ymd` (`None` for a week or weekday out of range).
fn iso_to_ymd(year: i32, week: i32, day: i32) -> Option<(i32, i32, i32)> {
    if week <= 0 || week >= 53 {
        let mut out_of_range = true;
        if week == 53 {
            let jan1 = NaiveDate::from_ymd_opt(year, 1, 1)?;
            // `(ymd_to_ord(y, 1, 1) + 6) % 7`: Monday = 0.
            let first_weekday = jan1.weekday().num_days_from_monday();
            let leap = NaiveDate::from_ymd_opt(year, 2, 29).is_some();
            if first_weekday == 3 || (first_weekday == 2 && leap) {
                out_of_range = false;
            }
        }
        if out_of_range {
            return None;
        }
    }
    if day <= 0 || day >= 8 {
        return None;
    }
    // `iso_week1_monday(year)`.
    let jan1 = NaiveDate::from_ymd_opt(year, 1, 1)?;
    let first_weekday = i64::from(jan1.weekday().num_days_from_monday());
    let mut week1_monday = jan1 - Duration::days(first_weekday);
    if first_weekday > 3 {
        week1_monday += Duration::days(7);
    }
    let date = week1_monday + Duration::days(i64::from((week - 1) * 7 + day - 1));
    Some((date.year(), date.month() as i32, date.day() as i32))
}

/// `parse_hh_mm_ss_ff(tstr, tstr_end)`: `Ok(rv)` (`1` = something follows)
/// with the fields, or the failure code.
fn parse_hms(s: &CStr<'_>, start: usize, end: usize) -> Result<(i32, [i32; 4]), i32> {
    let mut vals = [0i32; 3];
    let mut micro = 0i32;
    let mut p = start;
    let mut has_separator = true;
    let mut early = None;
    for (i, slot) in vals.iter_mut().enumerate() {
        p = parse_digits(s, p, 2, slot).ok_or(-3)?;
        let c = s.at(p);
        p += 1;
        if i == 0 {
            has_separator = c == b':';
        }
        if p >= end {
            early = Some(i32::from(c != 0));
            break;
        } else if has_separator && c == b':' {
            continue;
        } else if c == b'.' || c == b',' {
            break;
        } else if !has_separator {
            p -= 1;
        } else {
            return Err(-4);
        }
    }
    if let Some(rv) = early {
        return Ok((rv, [vals[0], vals[1], vals[2], 0]));
    }
    let remains = end.saturating_sub(p);
    let to_parse = remains.min(6);
    p = parse_digits(s, p, to_parse, &mut micro).ok_or(-3)?;
    if to_parse > 0 && to_parse < 6 {
        micro *= [100_000, 10_000, 1_000, 100, 10][to_parse - 1];
    }
    while s.at(p).is_ascii_digit() {
        p += 1;
    }
    Ok((i32::from(s.at(p) != 0), [vals[0], vals[1], vals[2], micro]))
}

/// `datetime.fromisoformat(text)` as CPython 3.11 implements it; `Err` is
/// the `ValueError`'s text.
pub fn fromisoformat(text: &str) -> Result<IsoDateTime, String> {
    let invalid = || format!("Invalid isoformat string: {}", str_repr(text));
    if text.chars().count() < 7 {
        return Err(invalid());
    }
    let bytes = text.as_bytes();
    let s = CStr(bytes);
    let len = bytes.len();
    let sep = find_separator(&s, len);
    if sep == usize::MAX {
        return Err(invalid());
    }
    let (year, month, day) = parse_date(&s, sep).map_err(|_| invalid())?;
    let (mut hms, mut tz) = ([0i32; 4], None);
    if len > sep {
        let start = sep + 1;
        let mut tzpos = start;
        loop {
            let c = s.at(tzpos);
            if c == b'Z' || c == b'+' || c == b'-' {
                break;
            }
            tzpos += 1;
            if tzpos >= len {
                break;
            }
        }
        let (rv, fields) = parse_hms(&s, start, tzpos).map_err(|_| invalid())?;
        hms = fields;
        if tzpos >= len {
            if rv == 1 {
                return Err(invalid());
            }
        } else if s.at(tzpos) == b'Z' {
            if s.at(tzpos + 1) != 0 {
                return Err(invalid());
            }
            tz = Some(0i64);
        } else {
            let sign: i64 = if s.at(tzpos) == b'-' { -1 } else { 1 };
            let (rv, f) = parse_hms(&s, tzpos + 1, len).map_err(|_| invalid())?;
            if rv != 0 {
                return Err(invalid());
            }
            let seconds = i64::from(f[0]) * 3600 + i64::from(f[1]) * 60 + i64::from(f[2]);
            tz = Some(sign * (seconds * 1_000_000 + i64::from(f[3])));
        }
    }
    if let Some(offset) = tz {
        let day_us: i64 = 86_400 * 1_000_000;
        if offset <= -day_us || offset >= day_us {
            return Err(format!(
                "offset must be a timedelta strictly between -timedelta(hours=24) and \
                 timedelta(hours=24), not {}.",
                timedelta_repr(offset)
            ));
        }
    }
    if !(1..=9999).contains(&year) {
        return Err(format!("year {year} is out of range"));
    }
    if !(1..=12).contains(&month) {
        return Err("month must be in 1..12".into());
    }
    let Some(date) = NaiveDate::from_ymd_opt(year, month as u32, day as u32) else {
        return Err("day is out of range for month".into());
    };
    let [h, m, sec, us] = hms;
    if !(0..=23).contains(&h) {
        return Err("hour must be in 0..23".into());
    }
    if !(0..=59).contains(&m) {
        return Err("minute must be in 0..59".into());
    }
    if !(0..=59).contains(&sec) {
        return Err("second must be in 0..59".into());
    }
    let wall = date
        .and_hms_micro_opt(h as u32, m as u32, sec as u32, us as u32)
        .ok_or_else(invalid)?;
    Ok(IsoDateTime {
        wall,
        offset_us: tz,
    })
}

/// `repr(timedelta(microseconds=us))` (normalised days/seconds/microseconds).
pub fn timedelta_repr(us: i64) -> String {
    let day_us: i64 = 86_400 * 1_000_000;
    let days = us.div_euclid(day_us);
    let rest = us.rem_euclid(day_us);
    let seconds = rest / 1_000_000;
    let micros = rest % 1_000_000;
    let mut parts = Vec::new();
    if days != 0 {
        parts.push(format!("days={days}"));
    }
    if seconds != 0 {
        parts.push(format!("seconds={seconds}"));
    }
    if micros != 0 {
        parts.push(format!("microseconds={micros}"));
    }
    if parts.is_empty() {
        "datetime.timedelta(0)".into()
    } else {
        format!("datetime.timedelta({})", parts.join(", "))
    }
}

/// `datetime.isoformat()` of a naive value (`T`, microseconds when set).
pub fn isoformat(t: NaiveDateTime) -> String {
    if t.nanosecond() / 1000 == 0 {
        t.format("%Y-%m-%dT%H:%M:%S").to_string()
    } else {
        t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
    }
}

/// `dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]`: milliseconds, truncated.
pub fn strftime_millis(t: NaiveDateTime) -> String {
    let full = t.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
    full[..full.len() - 3].to_string()
}

/// `calculate_day_range(timestamp)`: `fromisoformat`, then the day's start
/// and the next day's, as `%Y-%m-%d %H:%M:%S.%f`[:-3] in the timestamp's own
/// clock (the offset is dropped by `strftime`).
pub fn day_range(timestamp: &str) -> Result<(String, String), PyErr> {
    let dt = fromisoformat(timestamp).map_err(PyErr::Value)?;
    let start = dt
        .wall
        .date()
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| PyErr::Other("date value out of range".into()))?;
    let end = start
        .checked_add_signed(Duration::days(1))
        .filter(|e| e.year() <= 9999)
        .ok_or_else(|| PyErr::Other("date value out of range".into()))?;
    Ok((strftime_millis(start), strftime_millis(end)))
}

/// `datetime.fromtimestamp(t)` (the process's local time, microseconds
/// rounded half to even as CPython does); `Err` is Python's exception text.
pub fn fromtimestamp_local(t: f64) -> Result<NaiveDateTime, String> {
    if !t.is_finite() {
        return Err(if t.is_nan() {
            "Invalid value NaN (not a number)".into()
        } else {
            "cannot convert float infinity to integer".into()
        });
    }
    let mut int_part = t.trunc();
    let mut frac = (t - int_part) * 1e6;
    frac = round_half_even(frac);
    if frac >= 1e6 {
        frac -= 1e6;
        int_part += 1.0;
    } else if frac < 0.0 {
        frac += 1e6;
        int_part -= 1.0;
    }
    if int_part.abs() > 1e15 {
        return Err("timestamp out of range for platform time_t".into());
    }
    let secs = int_part as i64;
    let utc = chrono::DateTime::from_timestamp(secs, (frac as u32) * 1000)
        .ok_or_else(|| "year is out of range".to_string())?;
    let local = utc.with_timezone(&chrono::Local).naive_local();
    if !(1..=9999).contains(&local.year()) {
        return Err(format!("year {} is out of range", local.year()));
    }
    Ok(local)
}

fn round_half_even(x: f64) -> f64 {
    let r = x.round();
    if (x - x.trunc()).abs() == 0.5 {
        2.0 * (x / 2.0).round()
    } else {
        r
    }
}

// ---------------------------------------------------------------------------
// ipaddress.ip_address
// ---------------------------------------------------------------------------

/// `ipaddress.ip_address(text)` succeeds.
pub fn is_ip_address(text: &str) -> bool {
    if is_ipv4(text) {
        return true;
    }
    // `IPv6Address`: a scope id after `%` (non-empty, no second `%`).
    let (addr, scope) = match text.split_once('%') {
        Some((a, s)) => (a, Some(s)),
        None => (text, None),
    };
    if let Some(s) = scope {
        if s.is_empty() || s.contains('%') {
            return false;
        }
    }
    is_ipv6(addr)
}

/// `IPv4Address(text)`: four decimal octets, at most three digits each, no
/// leading zero.
fn is_ipv4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && !(p.len() > 1 && p.starts_with('0'))
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// `IPv6Address._ip_int_from_string`.
fn is_ipv6(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let mut parts: Vec<String> = text.split(':').map(str::to_string).collect();
    const MIN_PARTS: usize = 3;
    if parts.len() < MIN_PARTS {
        return false;
    }
    // An IPv4 tail counts as two hextets.
    if let Some(last) = parts.last().cloned() {
        if last.contains('.') {
            if !is_ipv4(&last) {
                return false;
            }
            parts.pop();
            parts.push("0".into());
            parts.push("0".into());
        }
    }
    const MAX_PARTS: usize = 9;
    if parts.len() > MAX_PARTS {
        return false;
    }
    let mut skip_index = None;
    for (i, p) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if p.is_empty() {
            if skip_index.is_some() {
                return false;
            }
            skip_index = Some(i);
        }
    }
    let n = parts.len();
    let (parts_hi, parts_lo) = match skip_index {
        Some(skip) => {
            let mut hi = skip;
            let mut lo = n - skip - 1;
            if parts[0].is_empty() {
                hi -= 1;
                if hi != 0 {
                    return false;
                }
            }
            if parts[n - 1].is_empty() {
                lo -= 1;
                if lo != 0 {
                    return false;
                }
            }
            if hi + lo >= 8 {
                return false;
            }
            (hi, lo)
        }
        None => {
            if n != 8 {
                return false;
            }
            if parts[0].is_empty() || parts[n - 1].is_empty() {
                return false;
            }
            (n, 0)
        }
    };
    let hextet =
        |p: &str| p.len() <= 4 && !p.is_empty() && p.bytes().all(|b| b.is_ascii_hexdigit());
    parts[..parts_hi].iter().all(|p| hextet(p)) && parts[n - parts_lo..].iter().all(|p| hextet(p))
}

/// Characters whose `str.title()` is not their `str.upper()` (CPython
/// 3.11's Unicode 14 data), for [`capitalize`].
const TITLE_EXCEPTIONS: &[(char, &str)] = &[
    ('\u{df}', "\u{53}\u{73}"),
    ('\u{1c4}', "\u{1c5}"),
    ('\u{1c5}', "\u{1c5}"),
    ('\u{1c6}', "\u{1c5}"),
    ('\u{1c7}', "\u{1c8}"),
    ('\u{1c8}', "\u{1c8}"),
    ('\u{1c9}', "\u{1c8}"),
    ('\u{1ca}', "\u{1cb}"),
    ('\u{1cb}', "\u{1cb}"),
    ('\u{1cc}', "\u{1cb}"),
    ('\u{1f1}', "\u{1f2}"),
    ('\u{1f2}', "\u{1f2}"),
    ('\u{1f3}', "\u{1f2}"),
    ('\u{587}', "\u{535}\u{582}"),
    ('\u{10d0}', "\u{10d0}"),
    ('\u{10d1}', "\u{10d1}"),
    ('\u{10d2}', "\u{10d2}"),
    ('\u{10d3}', "\u{10d3}"),
    ('\u{10d4}', "\u{10d4}"),
    ('\u{10d5}', "\u{10d5}"),
    ('\u{10d6}', "\u{10d6}"),
    ('\u{10d7}', "\u{10d7}"),
    ('\u{10d8}', "\u{10d8}"),
    ('\u{10d9}', "\u{10d9}"),
    ('\u{10da}', "\u{10da}"),
    ('\u{10db}', "\u{10db}"),
    ('\u{10dc}', "\u{10dc}"),
    ('\u{10dd}', "\u{10dd}"),
    ('\u{10de}', "\u{10de}"),
    ('\u{10df}', "\u{10df}"),
    ('\u{10e0}', "\u{10e0}"),
    ('\u{10e1}', "\u{10e1}"),
    ('\u{10e2}', "\u{10e2}"),
    ('\u{10e3}', "\u{10e3}"),
    ('\u{10e4}', "\u{10e4}"),
    ('\u{10e5}', "\u{10e5}"),
    ('\u{10e6}', "\u{10e6}"),
    ('\u{10e7}', "\u{10e7}"),
    ('\u{10e8}', "\u{10e8}"),
    ('\u{10e9}', "\u{10e9}"),
    ('\u{10ea}', "\u{10ea}"),
    ('\u{10eb}', "\u{10eb}"),
    ('\u{10ec}', "\u{10ec}"),
    ('\u{10ed}', "\u{10ed}"),
    ('\u{10ee}', "\u{10ee}"),
    ('\u{10ef}', "\u{10ef}"),
    ('\u{10f0}', "\u{10f0}"),
    ('\u{10f1}', "\u{10f1}"),
    ('\u{10f2}', "\u{10f2}"),
    ('\u{10f3}', "\u{10f3}"),
    ('\u{10f4}', "\u{10f4}"),
    ('\u{10f5}', "\u{10f5}"),
    ('\u{10f6}', "\u{10f6}"),
    ('\u{10f7}', "\u{10f7}"),
    ('\u{10f8}', "\u{10f8}"),
    ('\u{10f9}', "\u{10f9}"),
    ('\u{10fa}', "\u{10fa}"),
    ('\u{10fd}', "\u{10fd}"),
    ('\u{10fe}', "\u{10fe}"),
    ('\u{10ff}', "\u{10ff}"),
    ('\u{1f80}', "\u{1f88}"),
    ('\u{1f81}', "\u{1f89}"),
    ('\u{1f82}', "\u{1f8a}"),
    ('\u{1f83}', "\u{1f8b}"),
    ('\u{1f84}', "\u{1f8c}"),
    ('\u{1f85}', "\u{1f8d}"),
    ('\u{1f86}', "\u{1f8e}"),
    ('\u{1f87}', "\u{1f8f}"),
    ('\u{1f88}', "\u{1f88}"),
    ('\u{1f89}', "\u{1f89}"),
    ('\u{1f8a}', "\u{1f8a}"),
    ('\u{1f8b}', "\u{1f8b}"),
    ('\u{1f8c}', "\u{1f8c}"),
    ('\u{1f8d}', "\u{1f8d}"),
    ('\u{1f8e}', "\u{1f8e}"),
    ('\u{1f8f}', "\u{1f8f}"),
    ('\u{1f90}', "\u{1f98}"),
    ('\u{1f91}', "\u{1f99}"),
    ('\u{1f92}', "\u{1f9a}"),
    ('\u{1f93}', "\u{1f9b}"),
    ('\u{1f94}', "\u{1f9c}"),
    ('\u{1f95}', "\u{1f9d}"),
    ('\u{1f96}', "\u{1f9e}"),
    ('\u{1f97}', "\u{1f9f}"),
    ('\u{1f98}', "\u{1f98}"),
    ('\u{1f99}', "\u{1f99}"),
    ('\u{1f9a}', "\u{1f9a}"),
    ('\u{1f9b}', "\u{1f9b}"),
    ('\u{1f9c}', "\u{1f9c}"),
    ('\u{1f9d}', "\u{1f9d}"),
    ('\u{1f9e}', "\u{1f9e}"),
    ('\u{1f9f}', "\u{1f9f}"),
    ('\u{1fa0}', "\u{1fa8}"),
    ('\u{1fa1}', "\u{1fa9}"),
    ('\u{1fa2}', "\u{1faa}"),
    ('\u{1fa3}', "\u{1fab}"),
    ('\u{1fa4}', "\u{1fac}"),
    ('\u{1fa5}', "\u{1fad}"),
    ('\u{1fa6}', "\u{1fae}"),
    ('\u{1fa7}', "\u{1faf}"),
    ('\u{1fa8}', "\u{1fa8}"),
    ('\u{1fa9}', "\u{1fa9}"),
    ('\u{1faa}', "\u{1faa}"),
    ('\u{1fab}', "\u{1fab}"),
    ('\u{1fac}', "\u{1fac}"),
    ('\u{1fad}', "\u{1fad}"),
    ('\u{1fae}', "\u{1fae}"),
    ('\u{1faf}', "\u{1faf}"),
    ('\u{1fb2}', "\u{1fba}\u{345}"),
    ('\u{1fb3}', "\u{1fbc}"),
    ('\u{1fb4}', "\u{386}\u{345}"),
    ('\u{1fb7}', "\u{391}\u{342}\u{345}"),
    ('\u{1fbc}', "\u{1fbc}"),
    ('\u{1fc2}', "\u{1fca}\u{345}"),
    ('\u{1fc3}', "\u{1fcc}"),
    ('\u{1fc4}', "\u{389}\u{345}"),
    ('\u{1fc7}', "\u{397}\u{342}\u{345}"),
    ('\u{1fcc}', "\u{1fcc}"),
    ('\u{1ff2}', "\u{1ffa}\u{345}"),
    ('\u{1ff3}', "\u{1ffc}"),
    ('\u{1ff4}', "\u{38f}\u{345}"),
    ('\u{1ff7}', "\u{3a9}\u{342}\u{345}"),
    ('\u{1ffc}', "\u{1ffc}"),
    ('\u{fb00}', "\u{46}\u{66}"),
    ('\u{fb01}', "\u{46}\u{69}"),
    ('\u{fb02}', "\u{46}\u{6c}"),
    ('\u{fb03}', "\u{46}\u{66}\u{69}"),
    ('\u{fb04}', "\u{46}\u{66}\u{6c}"),
    ('\u{fb05}', "\u{53}\u{74}"),
    ('\u{fb06}', "\u{53}\u{74}"),
    ('\u{fb13}', "\u{544}\u{576}"),
    ('\u{fb14}', "\u{544}\u{565}"),
    ('\u{fb15}', "\u{544}\u{56b}"),
    ('\u{fb16}', "\u{54e}\u{576}"),
    ('\u{fb17}', "\u{544}\u{56d}"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_and_words() {
        assert_eq!(
            splitlines("a\r\nb\rc\n\nd\u{85}e"),
            vec!["a", "b", "c", "", "d", "e"]
        );
        assert_eq!(splitlines("x\n"), vec!["x"]);
        assert_eq!(
            split_ws("  Host \u{1c} Application "),
            vec!["Host", "Application"]
        );
        assert_eq!(capitalize("hOST"), "Host");
        assert_eq!(capitalize("ßa"), "Ssa");
        assert_eq!(basename("C:\\x\\y.exe"), "C:\\x\\y.exe");
        assert_eq!(basename("/usr/bin/ls"), "ls");
    }

    #[test]
    fn indent_dumps() {
        let v = copilot_auth::pyvalue::loads(r#"{"a": [1, 2.5, {"b": "é"}], "c": {}, "d": []}"#)
            .unwrap();
        assert_eq!(
            dumps_indent2(&v),
            "{\n  \"a\": [\n    1,\n    2.5,\n    {\n      \"b\": \"\\u00e9\"\n    }\n  ],\n  \"c\": {},\n  \"d\": []\n}"
        );
    }

    #[test]
    fn ip_addresses() {
        for ok in [
            "1.2.3.4",
            "::1",
            "fe80::1%eth0",
            "::ffff:1.2.3.4",
            "1::",
            "1:2:3:4:5:6:7:8",
        ] {
            assert!(is_ip_address(ok), "{ok}");
        }
        for bad in [
            "01.2.3.4",
            "1.2.3",
            "1:2",
            ":::",
            "1:2:3:4:5:6:7:8:9",
            "fe80::1%",
            "g::1",
        ] {
            assert!(!is_ip_address(bad), "{bad}");
        }
    }

    #[test]
    fn timedeltas() {
        assert_eq!(timedelta_repr(0), "datetime.timedelta(0)");
        assert_eq!(
            timedelta_repr(90_000_000_000),
            "datetime.timedelta(days=1, seconds=3600)"
        );
        assert_eq!(
            timedelta_repr(-1),
            "datetime.timedelta(days=-1, seconds=86399, microseconds=999999)"
        );
    }

    /// `py_vectors.json` (`scripts/gen-ingest-vectors.py`, CPython 3.11).
    #[test]
    fn python_vectors() {
        let v: Value = serde_json::from_str(include_str!("py_vectors.json")).unwrap();
        for case in v["fromisoformat"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            match fromisoformat(input) {
                Ok(dt) => {
                    assert_eq!(json_str(&case["wall"]), isoformat(dt.wall), "{input}");
                    assert_eq!(case["offset_us"].as_i64(), dt.offset_us, "{input}");
                }
                Err(e) => assert_eq!(json_str(&case["error"]), e, "{input}"),
            }
            match day_range(input) {
                Ok((start, end)) => {
                    assert_eq!(
                        case["day_range"],
                        serde_json::json!([start, end]),
                        "{input}"
                    );
                }
                Err(PyErr::Value(_)) => assert!(case.get("error").is_some(), "{input}"),
                Err(e) => assert_eq!(json_str(&case["day_range_error"]), e.py_str(), "{input}"),
            }
        }
        for case in v["strings"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            assert_eq!(
                json_str(&case["capitalize"]),
                capitalize(input),
                "{input:?}"
            );
            assert_eq!(
                case["splitlines"],
                serde_json::json!(splitlines(input)),
                "{input:?}"
            );
            assert_eq!(
                case["split"],
                serde_json::json!(split_ws(input)),
                "{input:?}"
            );
        }
        for case in v["ip_address"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            assert_eq!(case["ok"].as_bool(), Some(is_ip_address(input)), "{input}");
        }
        for case in v["basename"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            assert_eq!(json_str(&case["out"]), basename(input), "{input}");
        }
        for case in v["dumps_indent2"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let parsed = copilot_auth::pyvalue::loads(input).unwrap();
            assert_eq!(json_str(&case["out"]), dumps_indent2(&parsed), "{input}");
        }
        for case in v["timedelta_repr"].as_array().unwrap() {
            assert_eq!(
                json_str(&case["out"]),
                timedelta_repr(case["us"].as_i64().unwrap())
            );
        }
    }

    fn json_str(v: &Value) -> String {
        v.as_str().unwrap_or_default().to_string()
    }
}
