//! Flux query results — port of `influxdb_client`'s `FluxCsvParser`
//! (tables mode) over the annotated CSV InfluxDB answers `POST
//! /api/v2/query` with.
//!
//! Rows are read with Python's `csv` rules (the default dialect, which
//! `aiocsv` follows); each annotation block starts a table, a change of the
//! `table` column starts another with the same columns, and values are
//! typed by the `#datatype` annotation exactly as `_to_value` types them
//! (`long`/`unsignedLong`/`duration` → `int()`, `double` → `float()`,
//! `boolean` → `== "true"`, `dateTime:RFC3339` → `datetime.fromisoformat`,
//! an empty cell → the `#default`, else `None`). An `error`/`reference`
//! table is the `FluxQueryException` it raises.

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime};
use copilot_auth::pyvalue::{PyValue, bytes_repr, float_repr, str_repr};
use copilot_upstream::py::PyExc;

/// A typed cell.
#[derive(Debug, Clone, PartialEq)]
pub enum FluxValue {
    /// `None`.
    None,
    /// `str`.
    Str(String),
    /// `bool`.
    Bool(bool),
    /// `int`, as its canonical decimal text.
    Int(String),
    /// `float`.
    Float(f64),
    /// An aware `datetime` (microseconds; the offset InfluxDB wrote).
    Time(DateTime<FixedOffset>),
    /// `bytes` (`base64Binary`).
    Bytes(Vec<u8>),
}

impl FluxValue {
    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            FluxValue::None => false,
            FluxValue::Str(s) => !s.is_empty(),
            FluxValue::Bool(b) => *b,
            FluxValue::Int(i) => i != "0",
            FluxValue::Float(f) => *f != 0.0,
            FluxValue::Time(_) => true,
            FluxValue::Bytes(b) => !b.is_empty(),
        }
    }

    /// `str(value)`.
    pub fn py_str(&self) -> String {
        match self {
            FluxValue::Str(s) => s.clone(),
            FluxValue::Time(t) => py_datetime_str(t),
            other => other.py_repr(),
        }
    }

    /// `repr(value)`.
    pub fn py_repr(&self) -> String {
        match self {
            FluxValue::None => "None".into(),
            FluxValue::Str(s) => str_repr(s),
            FluxValue::Bool(true) => "True".into(),
            FluxValue::Bool(false) => "False".into(),
            FluxValue::Int(i) => i.clone(),
            FluxValue::Float(f) => float_repr(*f),
            FluxValue::Time(t) => py_datetime_repr(t),
            FluxValue::Bytes(b) => bytes_repr(b),
        }
    }

    /// `type(value).__name__`.
    pub fn type_name(&self) -> &'static str {
        match self {
            FluxValue::None => "NoneType",
            FluxValue::Str(_) => "str",
            FluxValue::Bool(_) => "bool",
            FluxValue::Int(_) => "int",
            FluxValue::Float(_) => "float",
            FluxValue::Time(_) => "datetime",
            FluxValue::Bytes(_) => "bytes",
        }
    }

    /// The `json.loads`-shaped value for the cases that have one (a
    /// datetime becomes its Pydantic JSON text, bytes their UTF-8 text).
    pub fn to_py(&self) -> PyValue {
        match self {
            FluxValue::None => PyValue::None,
            FluxValue::Str(s) => PyValue::Str(s.clone()),
            FluxValue::Bool(b) => PyValue::Bool(*b),
            FluxValue::Int(i) => PyValue::Int(i.clone()),
            FluxValue::Float(f) => PyValue::Float(*f),
            FluxValue::Time(t) => PyValue::Str(pydantic_datetime(t)),
            FluxValue::Bytes(b) => PyValue::Str(String::from_utf8_lossy(b).into_owned()),
        }
    }
}

impl FluxValue {
    /// `type(value).__name__` as a comparison `TypeError` names it
    /// (`datetime.datetime`).
    fn qualified_type_name(&self) -> &'static str {
        match self {
            FluxValue::Time(_) => "datetime.datetime",
            other => other.type_name(),
        }
    }

    fn number(&self) -> Option<f64> {
        match self {
            FluxValue::Bool(b) => Some(f64::from(u8::from(*b))),
            FluxValue::Int(i) => i.parse::<f64>().ok(),
            FluxValue::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Python `==` (`1 == 1.0 == True`; a datetime equals the same instant).
    pub fn py_eq(&self, other: &FluxValue) -> bool {
        match (self, other) {
            (FluxValue::Int(a), FluxValue::Int(b)) => a == b,
            (FluxValue::Time(a), FluxValue::Time(b)) => a == b,
            (FluxValue::None, FluxValue::None) => true,
            (FluxValue::Str(a), FluxValue::Str(b)) => a == b,
            (FluxValue::Bytes(a), FluxValue::Bytes(b)) => a == b,
            _ => match (self.number(), other.number()) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            },
        }
    }

    /// `value == "text"`.
    pub fn is_str(&self, text: &str) -> bool {
        matches!(self, FluxValue::Str(s) if s == text)
    }

    /// The key pydantic-core writes for this value as a dict key.
    pub fn json_key(&self) -> String {
        match self {
            FluxValue::None => "None".into(),
            FluxValue::Str(s) => s.clone(),
            FluxValue::Bool(true) => "true".into(),
            FluxValue::Bool(false) => "false".into(),
            FluxValue::Int(i) => i.clone(),
            FluxValue::Float(f) => float_repr(*f),
            FluxValue::Time(t) => pydantic_datetime(t),
            FluxValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        }
    }
}

/// `a < b` (`op` is `"<"`) or `a > b` (`">"`), with Python's `TypeError`
/// for values that do not compare.
pub fn py_order(op: &str, a: &FluxValue, b: &FluxValue) -> Result<bool, PyExc> {
    use std::cmp::Ordering;
    let ordering: Option<Ordering> = match (a, b) {
        (FluxValue::Str(x), FluxValue::Str(y)) => Some(x.cmp(y)),
        (FluxValue::Bytes(x), FluxValue::Bytes(y)) => Some(x.cmp(y)),
        (FluxValue::Time(x), FluxValue::Time(y)) => Some(x.cmp(y)),
        (FluxValue::Int(x), FluxValue::Int(y)) => match (x.parse::<i128>(), y.parse::<i128>()) {
            (Ok(p), Ok(q)) => Some(p.cmp(&q)),
            _ => a
                .number()
                .zip(b.number())
                .and_then(|(p, q)| p.partial_cmp(&q)),
        },
        _ => match (a.number(), b.number()) {
            (Some(p), Some(q)) => {
                // NaN compares false both ways.
                return Ok(if op == "<" { p < q } else { p > q });
            }
            _ => {
                return Err(PyExc::TypeError(format!(
                    "'{op}' not supported between instances of '{}' and '{}'",
                    a.qualified_type_name(),
                    b.qualified_type_name()
                )));
            }
        },
    };
    Ok(match ordering {
        Some(o) if op == "<" => o == Ordering::Less,
        Some(o) => o == Ordering::Greater,
        None => false,
    })
}

/// `values.sort(key=…, reverse=True)` on already computed keys: stable, the
/// newest first; Python's `TypeError` when two keys do not compare.
pub fn sort_desc<T>(items: &mut [(FluxValue, T)]) -> Result<(), PyExc> {
    // CPython reverses, sorts ascending with `<`, and reverses again; check
    // that the keys compare at all the way it would meet them first.
    let n = items.len();
    for i in (1..n).rev() {
        py_order("<", &items[i - 1].0, &items[i].0)?;
    }
    let mut failure = None;
    items.sort_by(|x, y| {
        let after = py_order("<", &x.0, &y.0).unwrap_or_else(|e| {
            failure.get_or_insert(e);
            false
        });
        let before = py_order("<", &y.0, &x.0).unwrap_or(false);
        if after {
            std::cmp::Ordering::Greater
        } else if before {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    });
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn offset_text(t: &DateTime<FixedOffset>, utc_as_z: bool) -> String {
    let secs = t.offset().local_minus_utc();
    if secs == 0 && utc_as_z {
        return "Z".into();
    }
    let sign = if secs < 0 { '-' } else { '+' };
    let a = secs.unsigned_abs();
    let mut out = format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60);
    if a % 60 != 0 {
        out.push_str(&format!(":{:02}", a % 60));
    }
    out
}

fn clock(t: &DateTime<FixedOffset>, sep: char) -> String {
    let n = t.naive_local();
    let mut out = format!("{}{sep}{}", n.format("%Y-%m-%d"), n.format("%H:%M:%S"));
    let micros = n.and_utc().timestamp_subsec_micros();
    if micros != 0 {
        out.push_str(&format!(".{micros:06}"));
    }
    out
}

/// `datetime.isoformat()` (`+00:00` for UTC).
pub fn py_isoformat(t: &DateTime<FixedOffset>) -> String {
    format!("{}{}", clock(t, 'T'), offset_text(t, false))
}

/// `str(datetime)` (a space between date and time).
pub fn py_datetime_str(t: &DateTime<FixedOffset>) -> String {
    format!("{}{}", clock(t, ' '), offset_text(t, false))
}

/// Pydantic's JSON text of an aware `datetime` (`Z` for UTC).
pub fn pydantic_datetime(t: &DateTime<FixedOffset>) -> String {
    format!("{}{}", clock(t, 'T'), offset_text(t, true))
}

/// `repr(datetime)`: `datetime.datetime(2026, 10, 15, 10, 0, tzinfo=datetime.timezone.utc)`.
pub fn py_datetime_repr(t: &DateTime<FixedOffset>) -> String {
    use chrono::{Datelike, Timelike};
    let n = t.naive_local();
    let mut parts = vec![
        n.year().to_string(),
        n.month().to_string(),
        n.day().to_string(),
        n.hour().to_string(),
        n.minute().to_string(),
    ];
    let micros = n.and_utc().timestamp_subsec_micros();
    if n.second() != 0 || micros != 0 {
        parts.push(n.second().to_string());
    }
    if micros != 0 {
        parts.push(micros.to_string());
    }
    let secs = t.offset().local_minus_utc();
    let tz = if secs == 0 {
        "datetime.timezone.utc".to_string()
    } else {
        format!("datetime.timezone(datetime.timedelta(seconds={secs}))")
    };
    format!("datetime.datetime({}, tzinfo={tz})", parts.join(", "))
}

/// One record: the cells in column order (a duplicated label keeps its
/// first position and its last value, like a dict).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FluxRecord {
    /// `record.values`.
    pub values: Vec<(String, FluxValue)>,
}

static NONE: FluxValue = FluxValue::None;

impl FluxRecord {
    /// `record.values.get(key)`.
    pub fn get(&self, key: &str) -> Option<&FluxValue> {
        self.values.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// `record.values.get(key, None)`.
    pub fn value_or_none(&self, key: &str) -> &FluxValue {
        self.get(key).unwrap_or(&NONE)
    }

    /// `record["key"]` (`KeyError` when the table has no such column).
    pub fn item(&self, key: &str) -> Result<&FluxValue, PyExc> {
        self.get(key).ok_or_else(|| PyExc::key_error(key))
    }

    /// `record.get_time()` (`record["_time"]`).
    pub fn time(&self) -> Result<&FluxValue, PyExc> {
        self.item("_time")
    }

    /// `record.get_value()` (`record["_value"]`).
    pub fn value(&self) -> Result<&FluxValue, PyExc> {
        self.item("_value")
    }

    fn set(&mut self, key: &str, value: FluxValue) {
        match self.values.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value,
            None => self.values.push((key.to_string(), value)),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Column {
    index: usize,
    data_type: String,
    default_value: String,
    label: String,
}

/// One table.
#[derive(Debug, Clone, Default)]
pub struct FluxTable {
    columns: Vec<Column>,
    /// Its records.
    pub records: Vec<FluxRecord>,
}

/// `csv.reader` over the response text (default dialect).
pub fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let mut rows = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let mut row: Vec<String> = Vec::new();
        let mut field = String::new();
        let mut in_quotes = false;
        let mut quoted_field = false;
        let mut any = false;
        loop {
            let Some(&c) = chars.get(i) else {
                if any || !field.is_empty() || quoted_field {
                    row.push(std::mem::take(&mut field));
                }
                break;
            };
            if in_quotes {
                i += 1;
                if c == '"' {
                    if chars.get(i) == Some(&'"') {
                        field.push('"');
                        i += 1;
                    } else {
                        in_quotes = false;
                    }
                } else {
                    field.push(c);
                }
                continue;
            }
            match c {
                ',' => {
                    row.push(std::mem::take(&mut field));
                    quoted_field = false;
                    any = true;
                    i += 1;
                }
                '"' if field.is_empty() && !quoted_field => {
                    in_quotes = true;
                    quoted_field = true;
                    i += 1;
                }
                '\r' | '\n' => {
                    if any || !field.is_empty() || quoted_field {
                        row.push(std::mem::take(&mut field));
                    }
                    i += 1;
                    if c == '\r' && chars.get(i) == Some(&'\n') {
                        i += 1;
                    }
                    break;
                }
                other => {
                    field.push(other);
                    i += 1;
                }
            }
        }
        rows.push(row);
    }
    rows
}

fn index_error() -> PyExc {
    PyExc::IndexError("list index out of range".into())
}

fn cell(row: &[String], i: usize) -> Result<&str, PyExc> {
    row.get(i).map(String::as_str).ok_or_else(index_error)
}

/// Python's `int(s)`.
pub fn py_int(s: &str) -> Result<String, PyExc> {
    let invalid = || {
        PyExc::ValueError(format!(
            "invalid literal for int() with base 10: {}",
            str_repr(s)
        ))
    };
    let t = s.trim_matches(|c: char| c.is_whitespace());
    let (sign, digits) = match t.strip_prefix('-') {
        Some(d) => ("-", d),
        None => ("", t.strip_prefix('+').unwrap_or(t)),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.chars().all(|c| c.is_ascii_digit() || c == '_')
    {
        return Err(invalid());
    }
    let clean: String = digits.chars().filter(|c| *c != '_').collect();
    let clean = clean.trim_start_matches('0');
    if clean.is_empty() {
        return Ok("0".into());
    }
    Ok(format!("{sign}{clean}"))
}

/// Python's `float(s)`.
pub fn py_float(s: &str) -> Result<f64, PyExc> {
    let invalid = || {
        PyExc::ValueError(format!(
            "could not convert string to float: {}",
            str_repr(s)
        ))
    };
    let t = s.trim_matches(|c: char| c.is_whitespace());
    let lower = t.to_ascii_lowercase();
    let body = lower.strip_prefix(['+', '-']).unwrap_or(&lower);
    let negative = lower.starts_with('-');
    match body {
        "inf" | "infinity" => {
            return Ok(if negative {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            });
        }
        "nan" => return Ok(f64::NAN),
        _ => {}
    }
    if t.is_empty()
        || !t
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-' | '_'))
    {
        return Err(invalid());
    }
    let chars: Vec<char> = t.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c == '_' {
            let ok = i > 0
                && chars[i - 1].is_ascii_digit()
                && chars.get(i + 1).is_some_and(char::is_ascii_digit);
            if !ok {
                return Err(invalid());
            }
        }
    }
    t.replace('_', "").parse::<f64>().map_err(|_| invalid())
}

/// `datetime.fromisoformat(s)` for the RFC 3339 forms InfluxDB writes
/// (fractions beyond microseconds are cut, `Z` and offsets kept).
pub fn py_fromisoformat(s: &str) -> Result<DateTime<FixedOffset>, PyExc> {
    let invalid = || PyExc::ValueError(format!("Invalid isoformat string: {}", str_repr(s)));
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b' ') {
        return Err(invalid());
    }
    let num = |r: std::ops::Range<usize>| -> Result<u32, PyExc> {
        s.get(r)
            .filter(|t| t.chars().all(|c| c.is_ascii_digit()))
            .and_then(|t| t.parse().ok())
            .ok_or_else(invalid)
    };
    let date =
        NaiveDate::from_ymd_opt(num(0..4)? as i32, num(5..7)?, num(8..10)?).ok_or_else(invalid)?;
    if b[13] != b':' || b[16] != b':' {
        return Err(invalid());
    }
    let (h, m, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut rest = &s[19..];
    let mut micros = 0u32;
    if let Some(frac) = rest.strip_prefix(['.', ',']) {
        let digits: String = frac.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return Err(invalid());
        }
        let mut six: String = digits.chars().take(6).collect();
        while six.len() < 6 {
            six.push('0');
        }
        micros = six.parse().map_err(|_| invalid())?;
        rest = &frac[digits.len()..];
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        tz => {
            let sign = match tz.as_bytes().first() {
                Some(b'+') => 1,
                Some(b'-') => -1,
                _ => return Err(invalid()),
            };
            let t = &tz[1..];
            let (oh, om) = match t.len() {
                5 if t.as_bytes()[2] == b':' => (&t[0..2], &t[3..5]),
                4 => (&t[0..2], &t[2..4]),
                2 => (t, "00"),
                _ => return Err(invalid()),
            };
            let oh: i32 = oh.parse().map_err(|_| invalid())?;
            let om: i32 = om.parse().map_err(|_| invalid())?;
            if oh > 23 || om > 59 {
                return Err(invalid());
            }
            sign * (oh * 3600 + om * 60)
        }
    };
    let time = NaiveTime::from_hms_micro_opt(h, m, sec, micros).ok_or_else(invalid)?;
    let tz = FixedOffset::east_opt(offset).ok_or_else(invalid)?;
    NaiveDateTime::new(date, time)
        .and_local_timezone(tz)
        .single()
        .ok_or_else(invalid)
}

fn to_value(raw: &str, column: &Column) -> Result<FluxValue, PyExc> {
    if raw.is_empty() {
        if column.default_value.is_empty() {
            return Ok(FluxValue::None);
        }
        let default = column.default_value.clone();
        return to_value(&default, column);
    }
    Ok(match column.data_type.as_str() {
        "string" => FluxValue::Str(raw.to_string()),
        "boolean" => FluxValue::Bool(raw == "true"),
        "unsignedLong" | "long" | "duration" => FluxValue::Int(py_int(raw)?),
        "double" => FluxValue::Float(py_float(raw)?),
        "base64Binary" => {
            use base64::Engine as _;
            FluxValue::Bytes(
                base64::engine::general_purpose::STANDARD
                    .decode(raw.trim())
                    .map_err(|_| PyExc::Other("Error", "Incorrect padding".into()))?,
            )
        }
        "dateTime:RFC3339" | "dateTime:RFC3339Nano" => FluxValue::Time(py_fromisoformat(raw)?),
        _ => FluxValue::None,
    })
}

/// `FluxCsvParser` in tables mode over the response text.
pub fn parse_tables(text: &str) -> Result<Vec<FluxTable>, PyExc> {
    let mut tables: Vec<FluxTable> = Vec::new();
    let mut start_new_table = false;
    let mut table_id: i128 = -1;
    let mut groups: Vec<String> = Vec::new();
    let mut parsing_error = false;
    for row in csv_rows(text) {
        if row.is_empty() {
            continue;
        }
        if cell(&row, 1)? == "error" && cell(&row, 2)? == "reference" {
            parsing_error = true;
            continue;
        }
        if parsing_error {
            let message = cell(&row, 1)?.to_string();
            let reference = cell(&row, 2)?.to_string();
            return Err(PyExc::Other(
                "FluxQueryException",
                format!("({}, {})", str_repr(&message), str_repr(&reference)),
            ));
        }
        let token = row[0].as_str();
        let annotation = matches!(token, "#default" | "#group" | "#datatype");
        if annotation && !start_new_table {
            start_new_table = true;
            tables.push(FluxTable::default());
            table_id = -1;
        } else if tables.is_empty() {
            return Err(PyExc::Other(
                "FluxCsvParserException",
                "Unable to parse CSV response. FluxTable definition was not found.".into(),
            ));
        }
        let Some(table) = tables.last_mut() else {
            continue;
        };
        match token {
            "#datatype" => {
                for (i, dt) in row.iter().enumerate().skip(1) {
                    table.columns.push(Column {
                        index: i - 1,
                        data_type: dt.clone(),
                        ..Column::default()
                    });
                }
            }
            "#group" => groups = row.clone(),
            "#default" => {
                for (i, column) in table.columns.iter_mut().enumerate() {
                    column.default_value = cell(&row, i + 1)?.to_string();
                }
            }
            _ if start_new_table => {
                for i in 0..table.columns.len() {
                    // `column.group = groups[i] == "true"`: only read.
                    cell(&groups, i + 1)?;
                }
                for (i, column) in table.columns.iter_mut().enumerate() {
                    column.label = cell(&row, i + 1)?.to_string();
                }
                start_new_table = false;
            }
            _ => {
                let current: i128 = py_int(cell(&row, 2)?)?.parse().unwrap_or(0);
                if table_id == -1 {
                    table_id = current;
                }
                if table_id != current {
                    let columns = table.columns.clone();
                    tables.push(FluxTable {
                        columns,
                        records: Vec::new(),
                    });
                    table_id = current;
                }
                let table = tables.last_mut().ok_or_else(index_error)?;
                let mut record = FluxRecord::default();
                for column in &table.columns {
                    let raw = cell(&row, column.index + 1)?;
                    record.set(&column.label, to_value(raw, column)?);
                }
                table.records.push(record);
            }
        }
    }
    Ok(tables)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "#datatype,string,long,dateTime:RFC3339,double,boolean,unsignedLong,string,duration\r\n\
        #group,false,false,false,false,false,false,true,false\r\n\
        #default,_result,,,,,,dflt,\r\n\
        ,result,table,_time,_value,b,u,s,d\r\n\
        ,,0,2026-10-15T10:00:00Z,+Inf,true,18446744073709551615,,100\r\n\
        ,,1,2026-10-15T10:00:00.5+02:00,,false,,x,-5\r\n\
        ,,1,1970-01-01T00:00:00.000000001Z,1e300,,1,\"a,\"\"b\",\r\n\
        \r\n\
        #datatype,string,long,string\r\n#group,false,false,true\r\n#default,_result,,\r\n\
        ,result,table,_check_name\r\n,,0,CPU CHECK\r\n,,1,Disk\r\n\r\n";

    #[test]
    fn tables_and_types_follow_the_python_parser() {
        let tables = parse_tables(CSV).unwrap();
        assert_eq!(tables.len(), 4);
        let r = &tables[0].records[0];
        assert_eq!(r.get("result"), Some(&FluxValue::Str("_result".into())));
        assert_eq!(r.get("_value"), Some(&FluxValue::Float(f64::INFINITY)));
        assert_eq!(
            r.get("u"),
            Some(&FluxValue::Int("18446744073709551615".into()))
        );
        assert_eq!(r.get("s"), Some(&FluxValue::Str("dflt".into())));
        assert_eq!(r.get("d"), Some(&FluxValue::Int("100".into())));
        let r = &tables[1].records[0];
        assert_eq!(r.value().unwrap(), &FluxValue::None);
        let FluxValue::Time(t) = r.time().unwrap() else {
            panic!("not a datetime")
        };
        assert_eq!(py_isoformat(t), "2026-10-15T10:00:00.500000+02:00");
        assert_eq!(tables[3].records[0].time().unwrap_err().text(), "'_time'");
        assert_eq!(
            tables[1].records[1].get("s"),
            Some(&FluxValue::Str("a,\"b".into()))
        );
        assert_eq!(
            tables[1].records[1].time().unwrap().py_repr(),
            "datetime.datetime(1970, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)"
        );
        assert_eq!(
            tables[3].records[0].get("_check_name"),
            Some(&FluxValue::Str("Disk".into()))
        );
    }

    #[test]
    fn errors_read_like_python() {
        let err = "#datatype,string,string\r\n#group,true,true\r\n#default,,\r\n,error,reference\r\n,\"failed to execute query: boom\",897\r\n\r\n";
        assert_eq!(
            parse_tables(err).unwrap_err().text(),
            "('failed to execute query: boom', '897')"
        );
        assert_eq!(
            parse_tables(",result,table\r\n,,0\r\n").unwrap_err().text(),
            "Unable to parse CSV response. FluxTable definition was not found."
        );
        assert!(parse_tables("").unwrap().is_empty());
        assert_eq!(py_int(" 1_0 ").unwrap(), "10");
        assert_eq!(
            py_int("x").unwrap_err().text(),
            "invalid literal for int() with base 10: 'x'"
        );
        assert_eq!(
            py_float("1.5x").unwrap_err().text(),
            "could not convert string to float: '1.5x'"
        );
        assert_eq!(
            py_fromisoformat("garbage").unwrap_err().text(),
            "Invalid isoformat string: 'garbage'"
        );
        let t = py_fromisoformat("2026-10-15T10:00:00.9999999Z").unwrap();
        assert_eq!(pydantic_datetime(&t), "2026-10-15T10:00:00.999999Z");
    }
}
