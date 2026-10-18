//! The ORM's `INSERT`s as aiomysql runs them, and their failures as
//! SQLAlchemy words them.
//!
//! The store adds `SublimeAlerts(...)` and its child rows to the session; at
//! the flush each row is one `INSERT` naming every column of its table but
//! `id` (a `None` value included), and a failure is the `DBAPIError` whose
//! `str()` reaches the answer:
//!
//! ```text
//! (pymysql.err.IntegrityError) (1048, "Column 'external_id' cannot be null")
//! [SQL: INSERT INTO sublimealerts (api_version, …, timestamp) VALUES (%s, …, %s)]
//! [parameters: ('v1', …, None, 's1', datetime.datetime(2026, 10, 17, 16, 59, 2, 756315))]
//! (Background on this error at: https://sqlalche.me/e/20/gkpj)
//! ```
//!
//! (`_repr_params`: each value's `repr()`, cut to 300 characters.) The
//! columns are validated strings, but a message's sender or recipient email
//! is whatever Sublime's JSON holds, and pymysql writes a non-string value
//! into the statement as its own literal ([`literal`]): a number as its
//! digits, `True` as `1`, a list as a parenthesised tuple — which MySQL then
//! stores, refuses (`Operand should contain 1 column(s)`) or cannot parse —
//! and refuses a dict (`TypeError`) or a NaN before anything is sent. The
//! statement is built the same way here, every string a bound parameter.

use chrono::{NaiveDateTime, Timelike};
use copilot_auth::pyvalue::{PyValue, float_repr, str_repr};
use copilot_incidents::datastore::services::sqlalchemy_error;
use copilot_upstream::py::PyExc;
use sqlx::mysql::MySqlArguments;
use sqlx::query::Query;
use sqlx::{MySql, MySqlConnection};

/// SQLAlchemy's `_repr_base.trunc`: a `repr()` longer than 300 characters
/// keeps its first and last 150 around a count of what was cut.
pub fn trunc(rep: &str) -> String {
    const MAX: usize = 300;
    let chars: Vec<char> = rep.chars().collect();
    if chars.len() <= MAX {
        return rep.to_string();
    }
    let half = MAX / 2;
    let head: String = chars[..half].iter().collect();
    let tail: String = chars[chars.len() - half..].iter().collect();
    format!(
        "{head} ... ({} characters truncated) ... {tail}",
        chars.len() - MAX
    )
}

/// `repr(datetime)`: the microsecond, then the second, left out while zero.
pub fn datetime_repr(t: &NaiveDateTime) -> String {
    use chrono::Datelike;
    let mut parts = vec![
        t.year().to_string(),
        t.month().to_string(),
        t.day().to_string(),
        t.hour().to_string(),
        t.minute().to_string(),
        t.second().to_string(),
        (t.nanosecond() / 1000).to_string(),
    ];
    for _ in 0..2 {
        if parts.last().is_some_and(|p| p == "0") {
            parts.pop();
        }
    }
    format!("datetime.datetime({})", parts.join(", "))
}

/// One bound value of an `INSERT`.
#[derive(Debug, Clone)]
pub enum Param {
    /// A string column's value (`None` is `NULL`).
    Text(Option<String>),
    /// A constant string (the sender's and recipient's `name="n/a"`).
    Const(&'static str),
    /// `sublime_alert_id`.
    Id(u64),
    /// `timestamp`.
    Time(NaiveDateTime),
    /// Whatever Sublime's JSON held (the sender and recipient emails).
    Json(PyValue),
}

impl Param {
    fn repr(&self) -> String {
        match self {
            Param::Text(None) => "None".into(),
            Param::Text(Some(s)) => str_repr(s),
            Param::Const(s) => str_repr(s),
            Param::Id(n) => n.to_string(),
            Param::Time(t) => datetime_repr(t),
            Param::Json(v) => v.py_repr(),
        }
    }
}

/// `_repr_params` of one row's tuple.
pub fn params_repr(params: &[Param]) -> String {
    let items: Vec<String> = params.iter().map(|p| trunc(&p.repr())).collect();
    format!(
        "({}{})",
        items.join(", "),
        if items.len() == 1 { "," } else { "" }
    )
}

/// What pymysql refuses before a statement is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// `escape_dict`: `TypeError("dict can not be used as parameter")`.
    Dict,
    /// `escape_float`: `ProgrammingError("nan can not be used with MySQL")`
    /// (`inf`, `-inf` alike).
    Float(String),
}

/// pymysql's `escape_item` of a `json.loads` value, as SQL with every
/// string a `?` (pushed onto `binds`): `NULL`, `1`/`0`, the digits of an
/// int, `repr(float)` with `e0` appended when it has no exponent, a list as
/// `(a,b)` (no space, as `escape_sequence` joins it).
pub fn literal(value: &PyValue, binds: &mut Vec<String>) -> Result<String, Refused> {
    Ok(match value {
        PyValue::None => "NULL".into(),
        PyValue::Bool(b) => if *b { "1" } else { "0" }.into(),
        PyValue::Int(digits) => {
            if digits.chars().all(|c| c.is_ascii_digit() || c == '-') && !digits.is_empty() {
                digits.clone()
            } else {
                binds.push(digits.clone());
                "?".into()
            }
        }
        PyValue::Float(f) => {
            let s = float_repr(*f);
            if !f.is_finite() {
                return Err(Refused::Float(s));
            }
            if s.contains('e') { s } else { format!("{s}e0") }
        }
        PyValue::Str(s) => {
            binds.push(s.clone());
            "?".into()
        }
        PyValue::List(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                parts.push(literal(item, binds)?);
            }
            format!("({})", parts.join(","))
        }
        PyValue::Dict(_) => return Err(Refused::Dict),
    })
}

/// One row's `INSERT` (`id` left to `AUTO_INCREMENT`).
#[derive(Debug, Clone)]
pub struct Insert {
    /// The table.
    pub table: &'static str,
    /// Its columns but `id`, in the table's order.
    pub columns: &'static [&'static str],
    /// One value per column.
    pub params: Vec<Param>,
}

impl Insert {
    /// The statement as SQLAlchemy prints it (`%s` placeholders).
    pub fn statement(&self) -> String {
        format!(
            "INSERT INTO {} ({}) VALUES ({})",
            self.table,
            self.columns.join(", "),
            vec!["%s"; self.columns.len()].join(", ")
        )
    }

    fn failed(&self, e: &sqlx::Error) -> PyExc {
        sqlalchemy_error(e, &self.statement(), &params_repr(&self.params))
    }

    /// Run it on `conn`; the new row's id.
    pub async fn run(&self, conn: &mut MySqlConnection) -> Result<u64, PyExc> {
        // A value pymysql writes as a literal other than a quoted string:
        // the statement is then written as pymysql writes it (the constant
        // and the id inline), so that MySQL stores, refuses or fails to
        // parse the same text — its syntax error quotes the statement's
        // rest. Strings stay bound parameters.
        let literal_mode = self
            .params
            .iter()
            .any(|p| matches!(p, Param::Json(v) if !matches!(v, PyValue::Str(_))));
        let mut values = Vec::with_capacity(self.params.len());
        let mut binds: Vec<Bind> = Vec::new();
        for p in &self.params {
            match p {
                Param::Text(v) => {
                    values.push("?".to_string());
                    binds.push(Bind::Text(v.clone()));
                }
                Param::Const(c) if literal_mode => values.push(format!("'{c}'")),
                Param::Const(c) => {
                    values.push("?".to_string());
                    binds.push(Bind::Text(Some((*c).to_string())));
                }
                Param::Id(n) if literal_mode => values.push(n.to_string()),
                Param::Id(n) => {
                    values.push("?".to_string());
                    binds.push(Bind::Id(*n));
                }
                Param::Time(t) => {
                    values.push("?".to_string());
                    binds.push(Bind::Time(*t));
                }
                Param::Json(v) => {
                    let mut strings = Vec::new();
                    match literal(v, &mut strings) {
                        Ok(sql) => values.push(sql),
                        Err(Refused::Dict) => {
                            return Err(PyExc::TypeError(
                                "dict can not be used as parameter".into(),
                            ));
                        }
                        Err(Refused::Float(s)) => {
                            return Err(PyExc::Other(
                                "DBAPIError",
                                format!(
                                    "(pymysql.err.ProgrammingError) {s} can not be used with \
                                     MySQL\n[SQL: {}]\n[parameters: {}]\n(Background on this \
                                     error at: https://sqlalche.me/e/20/f405)",
                                    self.statement(),
                                    params_repr(&self.params)
                                ),
                            ));
                        }
                    }
                    binds.extend(strings.into_iter().map(|s| Bind::Text(Some(s))));
                }
            }
        }
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            self.table,
            self.columns.join(", "),
            values.join(", ")
        );
        let mut q: Query<'_, MySql, MySqlArguments> = sqlx::query(&sql).persistent(!literal_mode);
        for b in binds {
            q = match b {
                Bind::Text(v) => q.bind(v),
                Bind::Id(n) => q.bind(n),
                Bind::Time(t) => q.bind(t),
            };
        }
        let done = q.execute(&mut *conn).await.map_err(|e| self.failed(&e))?;
        Ok(done.last_insert_id())
    }
}

#[derive(Debug, Clone)]
enum Bind {
    Text(Option<String>),
    Id(u64),
    Time(NaiveDateTime),
}

/// A database error outside an `INSERT` (the transaction itself).
pub fn operational(e: &sqlx::Error) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn reprs_like_python() {
        let t = |s: &str| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").unwrap();
        assert_eq!(
            datetime_repr(&t("2026-10-17 16:59:02.756315")),
            "datetime.datetime(2026, 10, 17, 16, 59, 2, 756315)"
        );
        assert_eq!(
            datetime_repr(&t("2026-10-17 16:59:02.0")),
            "datetime.datetime(2026, 10, 17, 16, 59, 2)"
        );
        assert_eq!(
            datetime_repr(&t("2026-01-07 00:00:00.0")),
            "datetime.datetime(2026, 1, 7, 0, 0)"
        );
        assert_eq!(
            datetime_repr(&t("2026-01-07 00:00:00.000010")),
            "datetime.datetime(2026, 1, 7, 0, 0, 0, 10)"
        );
        assert_eq!(params_repr(&[Param::Id(7)]), "(7,)");
        let long = "x".repeat(400);
        let cut = trunc(&str_repr(&long));
        assert!(cut.starts_with(&format!("'{}", "x".repeat(149))));
        assert!(cut.contains(" ... (102 characters truncated) ... "));
    }

    #[test]
    fn literals_like_pymysql() {
        let lit = |s: &str| {
            let mut binds = Vec::new();
            literal(&loads(s).unwrap(), &mut binds).map(|sql| (sql, binds))
        };
        assert_eq!(lit("[]"), Ok(("()".into(), vec![])));
        assert_eq!(
            lit(r#"["a", [], [1, true, null, 1.5, 1e100]]"#),
            Ok(("(?,(),(1,1,NULL,1.5e0,1e+100))".into(), vec!["a".into()]))
        );
        assert_eq!(lit(r#"[1, {"a": 1}]"#), Err(Refused::Dict));
        assert_eq!(lit("[NaN, {}]"), Err(Refused::Float("nan".into())));
        assert_eq!(lit("-Infinity"), Err(Refused::Float("-inf".into())));
    }
}
