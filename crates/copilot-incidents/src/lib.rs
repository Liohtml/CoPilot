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
//! - [`requests`]       — the write routes' request models (Pydantic's lax rules)
//! - [`writes`], [`dictionary`] — the service-layer writes
//! - [`events`]         — the case timeline (`emit_case_event`)
//! - [`templates`]      — case templates applied to cases (selection, snapshot copy)
//! - [`notify`]         — the incidents' notification events
//! - [`routes`]         — the HTTP routes
//! - [`datastore`]      — the MinIO routes (case files, report templates, case deletion,
//!   customer report files) over `copilot-objectstore`
//!
//! SLA bookkeeping (#1187) goes through `copilot_sla::SlaRecorder`, called
//! where the Python routes call `SlaLifecycleRecorder`.
//!
//! Alert visibility is `copilot_db::visibility` (customer scoping *and* tag
//! RBAC), the one definition every listing goes through.

#![warn(missing_docs)]

pub mod access;
pub mod cases;
pub mod config;
pub mod datastore;
pub mod dictionary;
pub mod events;
pub mod files;
pub mod lists;
pub mod notify;
pub mod options;
pub mod requests;
pub mod routes;
pub mod schema;
pub mod store;
pub mod templates;
pub mod verdict_stats;
pub mod views;
pub mod writes;

pub use routes::{alerts, case_templates, customer_reports, db_operations, report, tag_access};

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
        table: "incident_management_case_template",
        columns: &[
            "id",
            "name",
            "customer_code",
            "source",
            "is_default",
            "match_field",
            "match_value",
            "created_at",
        ],
    },
    TableRequirement {
        table: "incident_management_case_template_task",
        columns: &[
            "id",
            "template_id",
            "title",
            "description",
            "guidelines",
            "mandatory",
            "order_index",
        ],
    },
    TableRequirement {
        table: "incident_management_threshold_alert_metadata",
        columns: &["alert_id"],
    },
    TableRequirement {
        table: "incident_management_velo_sigma_exclusion",
        columns: &[
            "id",
            "name",
            "description",
            "channel",
            "title",
            "field_matches",
            "customer_code",
            "created_by",
            "created_at",
            "last_matched_at",
            "match_count",
            "enabled",
            "source_alert_id",
            "source_case_id",
        ],
    },
    TableRequirement {
        table: "incident_management_customer_reports",
        columns: &[
            "id",
            "report_name",
            "customer_code",
            "bucket_name",
            "object_key",
            "file_name",
            "file_size",
            "file_hash",
            "generated_at",
            "generated_by",
            "generated_by_role",
            "date_from",
            "date_to",
            "filters_json",
            "total_alerts",
            "total_cases",
            "open_cases",
            "closed_cases",
            "visible_to_customer",
            "status",
            "error_message",
        ],
    },
    TableRequirement {
        table: "custom_alert_creation_settings",
        columns: &["id", "customer_code"],
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
