//! `/api/api/v1/alert_settings` — port of
//! `app/integrations/alert_creation_settings/` (the router's own prefix is
//! `/api/v1/alert_settings`, under the API's `/api`).
//!
//! A customer's settings row (`custom_alert_creation_settings`) carries its
//! event orders and their event configs. Every route but `/create` (whose
//! customer is in the body, checked by Python itself) and
//! `/{customer_code}/event_configs` is keyed by the customer *name*:
//! `verify_customer_name_access` resolves the name to the first row's code
//! and fails closed for a scoped caller.
//!
//! - [`schema`] — the request models and the response dumps
//! - [`store`]  — the joined eager load (`event_orders` → `event_configs`)
//!   in SQLAlchemy's shape, and the writes
//! - [`routes`] — the handlers

pub mod routes;
pub mod schema;
pub mod store;

/// The `nvd_url` default (the model's and the column's).
pub const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId";
