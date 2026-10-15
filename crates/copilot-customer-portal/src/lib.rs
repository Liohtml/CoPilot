//! # copilot-customer-portal — the Customer Portal's AI report surfaces
//!
//! Port of the `ai_reports` slice of `app/customer_portal/` (`routes /
//! services / schema`), mounted at `/api/customer_portal`. Every other portal
//! route is still answered by the Python backend through the legacy proxy.
//!
//! Two audiences share these routes:
//! - **portal users** read their own AI findings (overview card, alert tab)
//!   and — where the customer allows it — ask for an analysis of one of their
//!   alerts (#1215), the one portal write on this surface;
//! - **operators** manage the per-customer switch in CoPilot (admin writes).
//!
//! The portal never goes through `/api/ai_analyst` (whose routes trust the
//! caller): it calls the AI analyst *service* layer and applies its own
//! customer + tag visibility, and its schema is a deliberately narrower
//! projection — no job ids, template names or agent errors.
//!
//! - [`schema`]   — response shapes and the settings request
//! - [`reports`]  — settings, availability, insights, one alert's analysis
//! - [`requests`] — a portal user asking Talon for an analysis
//! - [`routes`]   — `/ai_reports/*`

#![warn(missing_docs)]

pub mod reports;
pub mod requests;
pub mod routes;
pub mod schema;

pub use routes::router;
