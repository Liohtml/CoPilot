//! # copilot-siem — `/api/siem/dashboards`, `/api/siem/event_sources`, `/api/siem/events`
//!
//! Port of `app/siem/`:
//!
//! - [`routes`] — the 15 dashboard routes (built-in templates by category,
//!   enabled dashboards per customer, enable / disable, the custom-template
//!   CRUD with import and export, the builder's preview, panel data), the 4
//!   event-source routes and the 3 event routes (search with scroll paging,
//!   one document, the field names)
//! - [`panels`] — `execute_panels`, the one panel executor panel data and
//!   the preview share (the `.keyword` and unsorted fallbacks included)
//! - [`templates`] — the built-in templates compiled in, pinned to the
//!   backend's files by a test, and walked like the directory they come from
//! - [`services`] / [`store`] / [`schema`] — the services, the statements
//!   and the request and response models
//! - [`indexer`], [`timerange`], [`fnmatch`] — the elasticsearch-py calls,
//!   `AlertsQueryBuilder`'s time window, `fnmatch.fnmatchcase`
//!
//! Differences by design (§4 of `RUST_MIGRATION.md`), each closing a tenant
//! leak: enabling a dashboard checks the body's customer and the event
//! source's against the caller's customers; creating, importing and updating
//! a custom template checks the customer it is scoped to, and an import that
//! overwrites checks the template it replaces; creating an event source
//! checks the body's customer, updating one the customer it belongs to.

#![warn(missing_docs)]

pub mod fnmatch;
pub mod indexer;
pub mod panels;
pub mod py;
pub mod routes;
pub mod schema;
pub mod services;
pub mod store;
pub mod templates;
pub mod timerange;

use axum::extract::FromRef;
use copilot_wazuh::es::EsHttp;
use copilot_web::AppContext;

/// State of the SIEM routes.
#[derive(Debug, Clone)]
pub struct SiemState {
    /// Shared dependencies (database, connector cache, auth).
    pub ctx: AppContext,
    /// The indexer's HTTP stack (`copilot_wazuh::es`).
    pub es: EsHttp,
}

impl FromRef<SiemState> for AppContext {
    fn from_ref(s: &SiemState) -> AppContext {
        s.ctx.clone()
    }
}

/// The columns this crate needs.
pub const REQUIREMENTS: &[copilot_db::schema::TableRequirement] = store::REQUIREMENTS;

pub use routes::router;
