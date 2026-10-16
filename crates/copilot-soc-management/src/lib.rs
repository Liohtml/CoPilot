//! # copilot-soc-management — SOC Management & SLA (#1187)
//!
//! Port of `app/soc_management/` and of the Customer Portal SLA page
//! (`app/customer_portal/{routes,services,schema}/sla.py`):
//!
//! - [`domain`]   — periods, duration statistics, the analytics behind every
//!   figure (pure)
//! - [`services`] — fact loading within the caller's visibility, the
//!   dashboard snapshot, the policy and calendar reads, the portal page
//! - [`schema`]   — the Pydantic models, field for field
//! - [`routes`]   — `/api/soc_management/*` (but `GET /report`, the PDF,
//!   which stays in Python) and `/api/customer_portal/sla/*`
//!
//! The SLA domain itself (evaluation, policy resolution and writes,
//! business-hours calendars, re-targeting) is `copilot-sla`, the one Rust
//! definition shared with the incidents recorder.

#![warn(missing_docs)]

pub mod domain;
pub mod routes;
pub mod schema;
pub mod services;

use axum::Router;
use copilot_db::schema::TableRequirement;
use copilot_web::AppContext;

/// Every column this crate reads or writes beyond `copilot-sla`'s and the
/// incidents' (Alembic owns the schema).
pub const REQUIREMENTS: &[TableRequirement] = &[TableRequirement {
    table: "customer_portal_sla_settings",
    columns: &["id", "customer_code", "enabled", "updated_at", "updated_by"],
}];

/// `/api/soc_management/*`, to be nested at that prefix.
pub fn router(ctx: AppContext) -> Router {
    routes::soc_management::router().with_state(ctx)
}

/// `/api/customer_portal/sla/*`, with full paths (merged).
pub fn portal_router(ctx: AppContext) -> Router {
    routes::portal_sla::router().with_state(ctx)
}
