//! Statement helpers shared by the three modules.
//!
//! The listings are issued in SQLAlchemy's statement shapes — a joined
//! eager load is one `LEFT OUTER JOIN`, a sub-query eager load a second
//! statement — because the ORM keeps rows in the order MySQL returns them
//! and that order follows the plan of the statement. The same text gives
//! the same plan.

use copilot_auth::pyvalue::PyValue;
use copilot_web::ApiError;
use copilot_web::form::py_strip;
use sqlx::mysql::MySqlArguments;
use sqlx::query::Query;
use sqlx::{MySql, Row};

/// An unhandled database error: Python's bare 500.
pub fn internal(e: sqlx::Error) -> ApiError {
    ApiError::internal(format!("database error: {e}"))
}

/// `normalize_instance_name`: absent, empty or whitespace-only → `None`.
pub fn normalize_instance_name(name: Option<&str>) -> Option<String> {
    let stripped = py_strip(name?);
    (!stripped.is_empty()).then(|| stripped.to_string())
}

/// A clause and the value it binds (`None`: nothing to bind).
pub type Clause = (String, Option<String>);

/// `instance_name_matches(column, name)`: `IS NULL` for the unnamed
/// instance.
pub fn instance_matches(column: &str, name: Option<&str>) -> Clause {
    match name {
        None => (format!("{column} IS NULL"), None),
        Some(n) => (format!("{column} = ?"), Some(n.to_string())),
    }
}

/// `instance_name_differs(column, name)`: written so the unnamed instance is
/// not swallowed by SQL's `NULL != 'x'`.
pub fn instance_differs(column: &str, name: Option<&str>) -> Clause {
    match name {
        None => (format!("{column} IS NOT NULL"), None),
        Some(n) => (
            format!("({column} IS NULL OR {column} != ?)"),
            Some(n.to_string()),
        ),
    }
}

/// Bind a clause's value, if it has one.
pub fn bind_clause<'q>(
    q: Query<'q, MySql, MySqlArguments>,
    clause: &'q Clause,
) -> Query<'q, MySql, MySqlArguments> {
    match &clause.1 {
        Some(v) => q.bind(v.as_str()),
        None => q,
    }
}

/// A nullable text column.
pub fn opt_text(row: &sqlx::mysql::MySqlRow, column: &str) -> Result<Option<String>, sqlx::Error> {
    row.try_get::<Option<String>, _>(column)
}

/// A text column.
pub fn text(row: &sqlx::mysql::MySqlRow, column: &str) -> Result<String, sqlx::Error> {
    row.try_get::<String, _>(column)
}

/// A nullable integer column (`INT`).
pub fn opt_int(row: &sqlx::mysql::MySqlRow, column: &str) -> Result<Option<i64>, sqlx::Error> {
    row.try_get::<Option<i32>, _>(column)
        .map(|v| v.map(i64::from))
}

/// A `tinyint(1)` column read as SQLAlchemy's `Boolean` (`None` stays).
pub fn opt_bool(row: &sqlx::mysql::MySqlRow, column: &str) -> Result<Option<bool>, sqlx::Error> {
    row.try_get::<Option<i8>, _>(column)
        .map(|v| v.map(|b| b != 0))
}

/// `PyValue` helpers for the response dumps.
pub fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

/// `Optional[str]`.
pub fn opt_s(v: Option<&str>) -> PyValue {
    v.map_or(PyValue::None, |v| PyValue::Str(v.to_string()))
}

/// An `int`.
pub fn int(v: i64) -> PyValue {
    PyValue::Int(v.to_string())
}

/// `Optional[int]`.
pub fn opt_int_v(v: Option<i64>) -> PyValue {
    v.map_or(PyValue::None, int)
}

/// A dict from pairs, in order.
pub fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// The answer of a route: pydantic-core's JSON of the dump.
pub fn ok(dump: &PyValue) -> axum::response::Response {
    copilot_upstream::respond::model_response(dump)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names_normalise_and_compare_null_safely() {
        assert_eq!(normalize_instance_name(None), None);
        assert_eq!(normalize_instance_name(Some("  \u{a0}")), None);
        assert_eq!(normalize_instance_name(Some(" a ")).as_deref(), Some("a"));
        assert_eq!(instance_matches("c", None).0, "c IS NULL");
        assert_eq!(instance_differs("c", Some("x")).0, "(c IS NULL OR c != ?)");
        assert_eq!(instance_differs("c", None).0, "c IS NOT NULL");
    }
}
