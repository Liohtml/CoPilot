//! Application services: loading facts, composing the dashboard, the policy
//! and calendar editors, the portal SLA page and the notifier — ports of
//! `soc_management/services/` and `customer_portal/services/sla.py`.

pub mod calendars;
pub mod datasets;
pub mod metrics;
pub mod notifier;
pub mod policy;
pub mod portal;

use copilot_web::ApiError;

/// An unexpected failure (a query): logged, answered as the bare 500
/// Python's unhandled exceptions produce.
pub fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

/// A failure of the SLA domain as the Python backend answers it: a stored
/// calendar or policy cell that does not parse raises `ValueError` there —
/// the 400 with its text (`value_error_handler`); anything else is a 500.
pub fn sla_error(e: copilot_sla::SlaError) -> ApiError {
    match e {
        copilot_sla::SlaError::Calendar(msg) | copilot_sla::SlaError::Policy(msg) => {
            ApiError::bad_request(msg)
        }
        other => ApiError::internal(other),
    }
}

/// A date computation left Python's range: `ValueError` → 400, `OverflowError` → 500.
pub fn period_error(e: crate::domain::periods::OutOfRange) -> ApiError {
    match e {
        crate::domain::periods::OutOfRange::Year(_) => ApiError::bad_request(e.to_string()),
        crate::domain::periods::OutOfRange::Overflow => ApiError::internal(e),
    }
}
