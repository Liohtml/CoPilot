//! # copilot-customer-portal — the Customer Portal's API
//!
//! Port of `app/customer_portal/` (`routes / services / schema`), mounted at
//! `/api/customer_portal`: every route of the module. The SLA page
//! (`/sla/*`) is `copilot-soc-management`'s.
//!
//! Two audiences share these routes:
//! - **portal users** read their own data — the Overview, the dashboard
//!   counters, their agents, their profile, their branding, their AI
//!   findings — and, where the customer allows it, ask for an analysis of one
//!   of their alerts (#1215);
//! - **operators** manage the global portal settings, the per-customer
//!   branding overrides and the AI report switch in CoPilot (admin writes).
//!
//! Every read is narrowed to the caller's customers; alerts go through
//! `copilot_db::visibility` (customer scoping and tag RBAC), the AI surfaces
//! through the customer's switch on top. The portal never goes through
//! `/api/ai_analyst` (whose routes trust the caller).
//!
//! - [`schema`], [`reports`], [`requests`], [`routes`] — `/ai_reports/*`
//! - [`branding`]  — `/settings*`, `/branding*`, the logos, the branding cache
//! - [`dashboard`] — `/overview`, `/dashboard/*`
//! - [`agents`]    — `/agents`, `/agents/export`
//! - [`me`]        — `/me`
//! - [`starlette`] — byte responses as Starlette and `GZipMiddleware` send them
//! - [`query`]     — Pydantic's `int` / `bool` query parameters

#![warn(missing_docs)]

pub mod agents;
pub mod branding;
pub mod dashboard;
pub mod errors;
pub mod me;
pub mod query;
pub mod reports;
pub mod requests;
pub mod routes;
pub mod schema;
pub mod starlette;
pub mod state;

#[cfg(test)]
mod vectors;

pub use branding::services::REQUIREMENTS;
pub use routes::router;
pub use state::PortalState;
