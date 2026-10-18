//! # copilot-soc-management — SOC Management & SLA (#1187)
//!
//! Port of `app/soc_management/` and of the Customer Portal SLA page
//! (`app/customer_portal/{routes,services,schema}/sla.py`):
//!
//! - [`domain`]   — periods, duration statistics, the analytics behind every
//!   figure, SLA notices (pure)
//! - [`services`] — fact loading within the caller's visibility, the
//!   dashboard snapshot, the policy and calendar reads, the portal page, the
//!   notifier
//! - [`schema`]   — the Pydantic models, field for field
//! - [`routes`]   — `/api/soc_management/*` (but `GET /report`, the PDF,
//!   which is `copilot-reports`') and `/api/customer_portal/sla/*`
//!
//! The SLA domain itself (evaluation, policy resolution and writes,
//! business-hours calendars, re-targeting) is `copilot-sla`, the one Rust
//! definition shared with the incidents recorder.

#![warn(missing_docs)]

pub mod domain;
pub mod routes;
pub mod schema;
pub mod services;

use std::sync::Arc;

use axum::Router;
use copilot_db::schema::TableRequirement;
use copilot_scheduler::{JobError, JobSpec};
use copilot_web::AppContext;

/// `notify_sla_transitions`' job id (`handover.py`'s `RUST_CAPABLE_JOBS`).
pub const NOTIFY_SLA_TRANSITIONS: &str = "notify_sla_transitions";

/// Every column this crate reads or writes beyond `copilot-sla`'s and the
/// incidents' (the schema is `copilot-migrate`'s).
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "soc_sla_alert_tracking",
        columns: &domain::notices::STAMP_COLUMNS,
    },
    TableRequirement {
        table: "soc_sla_case_tracking",
        columns: &domain::notices::STAMP_COLUMNS,
    },
    TableRequirement {
        table: "customer_portal_sla_settings",
        columns: &["id", "customer_code", "enabled", "updated_at", "updated_by"],
    },
];

/// `/api/soc_management/*`, to be nested at that prefix.
pub fn router(ctx: AppContext) -> Router {
    routes::soc_management::router().with_state(ctx)
}

/// `/api/customer_portal/sla/*`, with full paths (merged).
pub fn portal_router(ctx: AppContext) -> Router {
    routes::portal_sla::router().with_state(ctx)
}

/// The `notify_sla_transitions` job (every two minutes, as
/// `initialize_job_metadata` seeds it).
pub fn notifier_job_spec(ctx: &AppContext) -> JobSpec {
    let ctx = Arc::new(ctx.clone());
    JobSpec::new(NOTIFY_SLA_TRANSITIONS, 2, move || {
        let ctx = Arc::clone(&ctx);
        async move {
            services::notifier::notify_sla_transitions(&ctx)
                .await
                .map(|_| ())
                .map_err(|e| JobError(e.0))
        }
    })
}
