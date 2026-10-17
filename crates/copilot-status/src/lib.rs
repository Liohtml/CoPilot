//! # copilot-status — the platform's own status surfaces
//!
//! - [`logs`] — `/api/logs` (`app/utils.py:logs_router`): the `log_entries`
//!   error log, admin only.
//! - [`sidebar`] — `/api/status/sidebar` (`app/status/`): the sidebar's
//!   version fields and health indicators, the deployment-wide ones held
//!   and refreshed by this process.

#![warn(missing_docs)]

pub mod logs;
pub mod sidebar;

use copilot_db::schema::TableRequirement;

/// The columns this crate reads or writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
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
    },
    TableRequirement {
        table: "incident_management_alert",
        columns: &["id", "status", "assigned_to", "customer_code"],
    },
    TableRequirement {
        table: "incident_management_alerttag",
        columns: &["id", "tag"],
    },
    TableRequirement {
        table: "incident_management_alert_to_tag",
        columns: &["alert_id", "tag_id"],
    },
    TableRequirement {
        table: "incident_management_case",
        columns: &["assigned_to", "case_status", "customer_code"],
    },
    TableRequirement {
        table: "incident_management_tag_access_settings",
        columns: &["enabled", "untagged_alert_behavior"],
    },
    TableRequirement {
        table: "ai_analyst_job",
        columns: &["status"],
    },
    TableRequirement {
        table: "ai_analyst_palace_lesson",
        columns: &["status"],
    },
    TableRequirement {
        table: "notification_dispatch_log",
        columns: &["status", "dispatched_at"],
    },
];
