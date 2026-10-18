//! `/api/integrations` — port of `app/integrations/routes.py` and
//! `schema.py`.
//!
//! - [`schema`]   — the request models and the response dumps
//! - [`store`]    — the statements (SQLAlchemy's shapes)
//! - [`services`] — validation, the multi-instance rules, create, update,
//!   delete and its decommission, the metadata routes
//! - [`routes`]   — the handlers
//!
//! **Multi-instance.** A customer's configurations of one integration are
//! told apart by `customer_integrations.instance_name`; `NULL` is the
//! unnamed instance and is always compared with `IS NULL`
//! ([`crate::sql::instance_matches`], [`crate::sql::instance_differs`]).
//! Only [`MULTI_INSTANCE_INTEGRATIONS`] may have several, and a second one
//! must be named; a route given only a customer and an integration resolves
//! the instance and refuses when there are several.

pub mod cleanup;
pub mod routes;
pub mod schema;
pub mod services;
pub mod store;

/// `MULTI_INSTANCE_INTEGRATIONS`.
pub const MULTI_INSTANCE_INTEGRATIONS: &[&str] = &["Office365", "AWS"];

/// `AWS_INTEGRATION_NAME`.
pub const AWS: &str = "AWS";

/// `AWS_IDENTITY_AUTH_KEYS`: what a deployed AWS instance is identified by
/// on the Wazuh manager and in Graylog.
pub const AWS_IDENTITY_AUTH_KEYS: &[&str] = &["AWS_ACCOUNT_ID", "BUCKET_NAME"];

/// `NETWORK_INTEGRATIONS`: integrations whose metadata is a network
/// connector's.
pub const NETWORK_INTEGRATIONS: &[&str] = &[
    "DefenderForEndpoint",
    "BITDEFENDER",
    "CROWDSTRIKE",
    "FORTINET",
    "Fortinet",
    "Sonicwall",
];

/// `REDACTED_AUTH_KEYS`: write-only auth keys.
pub const REDACTED_AUTH_KEYS: &[&str] = &["SECRET_ACCESS_KEY"];

/// `REDACTED_AUTH_VALUE`.
pub const REDACTED_AUTH_VALUE: &str = "********";

/// `MISSING_META_RECOVERY_HINT`.
pub const MISSING_META_RECOVERY_HINT: &str = "This usually means the deployment did not \
     finish. You can record the metadata manually from the Meta Details panel, or delete the \
     integration and deploy it again.";

/// `is_unchanged_secret`: a write-only key sent back blank or as the
/// placeholder keeps its stored value.
pub fn is_unchanged_secret(name: &str, value: &str) -> bool {
    let v = copilot_web::form::py_strip(value);
    REDACTED_AUTH_KEYS.contains(&name) && (v.is_empty() || v == REDACTED_AUTH_VALUE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_only_keys() {
        assert!(is_unchanged_secret("SECRET_ACCESS_KEY", " ********"));
        assert!(is_unchanged_secret("SECRET_ACCESS_KEY", ""));
        assert!(!is_unchanged_secret("SECRET_ACCESS_KEY", "new"));
        assert!(!is_unchanged_secret("TENANT_ID", ""));
    }
}
