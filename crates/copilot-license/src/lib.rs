//! # copilot-license — `/api/license` and the feature check
//!
//! Port of `app/middleware/license.py`: the 12 routes of its `license_router`
//! and the helpers the rest of the backend imports from it (`get_license`,
//! `is_feature_enabled` and the `license_cache` bookkeeping behind it), so
//! every Rust module that needs the licence (the threat-intel routes, the
//! sidebar's licence indicator) calls one definition.
//!
//! - [`client`] — `send_post_request` / `send_get_request`: the SOCFortress
//!   licence server over `requests` (10 s, TLS verified, requests' header
//!   order), with their failure texts
//! - [`services`] — the `license` row, the feature cache, Python's operations
//!   on whatever JSON the licence server answered (`normalize_api_response`,
//!   `extract_license_payload`, `cache_license_features`)
//! - [`schema`] — the request and response models (`copilot_upstream::model`)
//! - [`routes`] — the 12 routes, admin/analyst (`require_any_scope`), as in
//!   Python
//!
//! The licence server is `https://license.socfortress.co/`, a constant in
//! Python; `COPILOT_LICENSE_URL` points it at a stand-in for the parity
//! harness only, never in production.

#![warn(missing_docs)]

pub mod client;
pub mod routes;
pub mod schema;
pub mod services;

use axum::extract::FromRef;
use copilot_db::schema::TableRequirement;
use copilot_web::AppContext;

pub use client::LicenseClient;
pub use routes::router;
pub use services::{is_feature_enabled, license_key};

/// State of the licence routes.
#[derive(Clone, Debug)]
pub struct LicenseState {
    /// Shared dependencies (database, auth).
    pub ctx: AppContext,
    /// The licence server.
    pub client: LicenseClient,
}

impl FromRef<LicenseState> for AppContext {
    fn from_ref(s: &LicenseState) -> AppContext {
        s.ctx.clone()
    }
}

/// The columns this crate reads or writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "license",
        columns: &[
            "id",
            "license_key",
            "customer_name",
            "customer_email",
            "company_name",
        ],
    },
    TableRequirement {
        table: "license_cache",
        columns: &[
            "id",
            "license_key",
            "feature_name",
            "is_enabled",
            "cached_at",
            "expires_at",
            "license_data",
        ],
    },
];
