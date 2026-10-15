//! # copilot-sla — SOC Management SLA clocks
//!
//! Port of the parts of `app/soc_management/` the incidents routes call
//! (#1187): every alert and case carries a tracking row with an immutable
//! `opened_at`, targets snapshotted at opening, and write-once milestones.
//!
//! - [`severity`]  — `alert_severity.py` (`severity_of`, `normalize_severity`, …)
//! - [`calendar`]  — 24/7 and business-hours clocks, the calendar book
//! - [`policy`]    — targets per entity × severity: customer → global → built-in
//! - [`lifecycle`] — which actions move which clocks (guarded writes, pauses)
//! - [`recorder`]  — [`SlaRecorder`], the one entry point the incidents crate calls
//!
//! The dashboard, the policy/calendar editors and the notifier
//! (`notify_sla_transitions`) are still served by the Python backend; they
//! read the same rows.

#![warn(missing_docs)]

pub mod calendar;
pub mod lifecycle;
pub mod policy;
pub mod recorder;
pub mod severity;

pub use lifecycle::{Actor, LifecycleAction};
pub use recorder::SlaRecorder;

use copilot_db::schema::TableRequirement;

/// Why recording failed (logged, never returned to a request).
#[derive(Debug, thiserror::Error)]
pub enum SlaError {
    /// Query failure.
    #[error("{0}")]
    Db(#[from] sqlx::Error),
    /// A stored calendar is not valid.
    #[error("{0}")]
    Calendar(String),
    /// A stored policy row is not valid.
    #[error("{0}")]
    Policy(String),
    /// The item does not exist.
    #[error("{0}")]
    Missing(String),
}

const TRACKING_COLUMNS: &[&str] = &[
    "severity",
    "opened_at",
    "ack_due_at",
    "resolve_due_at",
    "first_ack_at",
    "first_ack_by",
    "first_ack_action",
    "first_assigned_at",
    "resolved_at",
    "resolved_by",
    "first_resolved_at",
    "reopen_count",
    "tracked",
    "updated_at",
    "business_hours",
    "paused_at",
    "paused_seconds",
    "pause_credit_seconds",
];

/// Every column this crate reads or writes (Alembic owns the schema).
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "soc_sla_alert_tracking",
        columns: &["alert_id"],
    },
    TableRequirement {
        table: "soc_sla_alert_tracking",
        columns: TRACKING_COLUMNS,
    },
    TableRequirement {
        table: "soc_sla_case_tracking",
        columns: &["case_id"],
    },
    TableRequirement {
        table: "soc_sla_case_tracking",
        columns: TRACKING_COLUMNS,
    },
    TableRequirement {
        table: "soc_sla_policy",
        columns: &[
            "id",
            "customer_code",
            "entity_type",
            "severity",
            "ack_minutes",
            "resolve_minutes",
            "business_hours",
        ],
    },
    TableRequirement {
        table: "soc_sla_calendar",
        columns: &["id", "customer_code", "timezone", "week", "holidays"],
    },
];
