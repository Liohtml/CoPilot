//! # copilot-incidents — incident management
//!
//! Port of `app/incidents/` (alerts, cases, comments, assets, tags, IoCs,
//! case tasks and the case timeline), mounted under `/api/incidents`.
//!
//! - [`store`]          — rows and reads of the `incident_management_*` tables
//! - [`schema`]         — the response models (`AlertOut`, `CaseOut`, …)
//! - [`views`]          — rows → response models (`build_alert_out`, `get_case_by_id`)
//! - [`access`]         — per-object checks (`_ensure_alert_access`, tag RBAC on one alert, …)
//! - [`lists`], [`cases`], [`options`] — listings, counts, filter options
//! - [`verdict_stats`]  — the false-positive statistics
//! - [`config`], [`files`] — per-customer settings, field dictionaries, case files
//! - [`routes`]         — the HTTP routes
//!
//! Alert visibility is `copilot_db::visibility` (customer scoping *and* tag
//! RBAC), the one definition every listing goes through.

#![warn(missing_docs)]

pub mod access;
pub mod cases;
pub mod config;
pub mod files;
pub mod lists;
pub mod options;
pub mod routes;
pub mod schema;
pub mod store;
pub mod verdict_stats;
pub mod views;

pub use routes::db_operations;

use copilot_db::schema::TableRequirement;

/// Every column this crate reads or writes (Alembic owns the schema).
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "incident_management_alert",
        columns: &[
            "id",
            "alert_name",
            "alert_description",
            "status",
            "alert_creation_time",
            "customer_code",
            "time_closed",
            "source",
            "severity",
            "assigned_to",
            "escalated",
            "verdict",
            "verdict_reason",
            "verdict_note",
            "verdict_by",
            "verdict_at",
        ],
    },
    TableRequirement {
        table: "incident_management_comment",
        columns: &["id", "alert_id", "comment", "user_name", "created_at"],
    },
    TableRequirement {
        table: "incident_management_asset",
        columns: &[
            "id",
            "alert_linked",
            "asset_name",
            "alert_context_id",
            "agent_id",
            "velociraptor_id",
            "customer_code",
            "index_name",
            "index_id",
        ],
    },
    TableRequirement {
        table: "incident_management_alertcontext",
        columns: &["id", "source", "context"],
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
        table: "incident_management_ioc",
        columns: &["id", "value", "type", "description"],
    },
    TableRequirement {
        table: "incident_management_alert_to_ioc",
        columns: &["alert_id", "ioc_id"],
    },
    TableRequirement {
        table: "incident_management_case",
        columns: &[
            "id",
            "case_name",
            "case_description",
            "case_creation_time",
            "case_status",
            "case_closed_time",
            "assigned_to",
            "customer_code",
            "notification_invoked_number",
            "escalated",
            "severity",
        ],
    },
    TableRequirement {
        table: "incident_management_casealertlink",
        columns: &["case_id", "alert_id"],
    },
    TableRequirement {
        table: "incident_management_case_comment",
        columns: &["id", "case_id", "comment", "user_name", "created_at"],
    },
    TableRequirement {
        table: "incident_management_case_task",
        columns: &[
            "id",
            "case_id",
            "alert_id",
            "template_task_id",
            "title",
            "description",
            "guidelines",
            "mandatory",
            "order_index",
            "status",
            "evidence_comment",
            "completed_by",
            "completed_at",
            "assigned_to",
            "created_by",
            "created_at",
            "updated_at",
        ],
    },
    TableRequirement {
        table: "incident_management_case_event",
        columns: &[
            "id",
            "case_id",
            "event_type",
            "actor",
            "timestamp",
            "payload",
        ],
    },
    TableRequirement {
        table: "incident_management_case_datastore",
        columns: &[
            "id",
            "case_id",
            "bucket_name",
            "object_key",
            "file_name",
            "content_type",
            "file_size",
            "upload_time",
            "file_hash",
        ],
    },
    TableRequirement {
        table: "incident_management_case_report_template_datastore",
        columns: &["id", "report_template_name"],
    },
    TableRequirement {
        table: "incident_management_ai_analyst_trigger_enabled",
        columns: &["id", "customer_code", "enabled"],
    },
    TableRequirement {
        table: "incident_management_notification",
        columns: &["id", "customer_code", "shuffle_workflow_id", "enabled"],
    },
    TableRequirement {
        table: "incident_management_fieldname",
        columns: &["id", "source", "field_name"],
    },
    TableRequirement {
        table: "incident_management_assetfieldname",
        columns: &["id", "source", "field_name"],
    },
    TableRequirement {
        table: "incident_management_timestampfieldname",
        columns: &["id", "source", "field_name"],
    },
    TableRequirement {
        table: "incident_management_alerttitlefieldname",
        columns: &["id", "source", "field_name"],
    },
    TableRequirement {
        table: "incident_management_iocfieldname",
        columns: &["id", "source", "field_name"],
    },
];
