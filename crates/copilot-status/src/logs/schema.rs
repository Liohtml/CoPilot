//! The models of `app/utils.py`'s logs router: `LogRetrieveModel` (the
//! answer's rows), `LogsResponse`, `TimeRangeModel` and `EventType`.

use chrono::NaiveDateTime;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};
use serde::Serialize;

/// One `log_entries` row (`select(LogEntry)`).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LogRow {
    /// `id`.
    pub id: i32,
    /// `timestamp` (naive, as written: UTC).
    pub timestamp: NaiveDateTime,
    /// `event_type`.
    pub event_type: String,
    /// `user_id`.
    pub user_id: Option<i32>,
    /// `route`.
    pub route: Option<String>,
    /// `method`.
    pub method: Option<String>,
    /// `status_code`.
    pub status_code: i32,
    /// `message`.
    pub message: Option<String>,
    /// `additional_info`.
    pub additional_info: Option<String>,
}

/// `LogRetrieveModel`, in its field order (the parent's fields, the
/// overridden ones in place, then `timestamp`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogOut {
    /// `event_type`.
    pub event_type: String,
    /// `user_id`.
    pub user_id: Option<i32>,
    /// `route`.
    pub route: Option<String>,
    /// `method`.
    pub method: Option<String>,
    /// `status_code`.
    pub status_code: i32,
    /// `message`.
    pub message: Option<String>,
    /// `additional_info`.
    pub additional_info: Option<String>,
    /// `timestamp`.
    #[serde(serialize_with = "copilot_core::time::pydantic::datetime")]
    pub timestamp: NaiveDateTime,
}

impl From<LogRow> for LogOut {
    fn from(r: LogRow) -> Self {
        Self {
            event_type: r.event_type,
            user_id: r.user_id,
            route: r.route,
            method: r.method,
            status_code: r.status_code,
            message: r.message,
            additional_info: r.additional_info,
            timestamp: r.timestamp,
        }
    }
}

/// `LogsResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogsResponse {
    /// `logs`.
    pub logs: Vec<LogOut>,
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
}

fn one_day() -> PyValue {
    PyValue::Str("1d".into())
}

/// `TimeRangeModel` without its validator (applied by
/// [`crate::logs::services::validate_time_range`]: it raises
/// `RequestValidationError` itself, which ends validation).
pub static TIME_RANGE_MODEL: Model = Model::new(
    "TimeRangeModel",
    &[Field::def(
        "time_range",
        Ty::Union(&[Ty::Str, Ty::Int]),
        one_day,
    )],
);

/// `EventType`'s values.
pub const EVENT_TYPES: &[&str] = &["Info", "Error"];

/// `f"{event_type}"` of an `EventType` member on CPython 3.11 (a mixed-in
/// `str` enum formats as `EventType.NAME`).
pub fn event_type_format(value: &str) -> &'static str {
    match value {
        "Error" => "EventType.ERROR",
        _ => "EventType.INFO",
    }
}
