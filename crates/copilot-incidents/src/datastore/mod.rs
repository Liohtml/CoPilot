//! The incidents' MinIO routes (case files, case report templates, `DELETE
//! /case/{id}`, customer report download and delete) over
//! `copilot-objectstore`.
//!
//! `POST /case-report-template/default-template` uploads the templates
//! shipped under `backend/app/incidents/templates`, compiled in
//! ([`default_templates`]). Still Python: the case DOCX/PDF reports and the
//! customer report generation (docxtpl, the Jinja report templates,
//! wkhtmltopdf).

use axum::extract::FromRef;

use copilot_objectstore::{LegacyProxy, ObjectStore};
use copilot_web::AppContext;

pub mod default_templates;
pub mod routes;
pub mod services;

pub use routes::router;

/// What the routes need.
#[derive(Clone)]
pub struct DatastoreState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The MinIO store.
    pub store: ObjectStore,
    /// The Python backend (for a path with an encoded `/`).
    pub legacy: Option<LegacyProxy>,
}

impl FromRef<DatastoreState> for AppContext {
    fn from_ref(s: &DatastoreState) -> AppContext {
        s.ctx.clone()
    }
}

/// `incident_management_case_report_template_datastore` (the columns these
/// routes read and write).
pub const REQUIREMENTS: &[copilot_db::schema::TableRequirement] =
    &[copilot_db::schema::TableRequirement {
        table: "incident_management_case_report_template_datastore",
        columns: &[
            "id",
            "report_template_name",
            "bucket_name",
            "object_key",
            "file_name",
            "content_type",
            "file_size",
            "upload_time",
            "file_hash",
        ],
    }];
