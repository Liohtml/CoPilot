//! # copilot-status — the platform's own status surfaces
//!
//! - [`logs`] — `/api/logs` (`app/utils.py:logs_router`): the `log_entries`
//!   error log, admin only.

#![warn(missing_docs)]

pub mod logs;

use copilot_db::schema::TableRequirement;

/// The columns this crate reads or writes.
pub const REQUIREMENTS: &[TableRequirement] = &[TableRequirement {
    table: "log_entries",
    columns: &[
        "id",
        "timestamp",
        "event_type",
        "user_id",
        "route",
        "method",
        "status_code",
        "message",
        "additional_info",
    ],
}];
