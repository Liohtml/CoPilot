//! # copilot-integration-modules — the integrations' collection modules
//!
//! Port of `app/integrations/modules/` (mounted by `app/routers/modules.py`
//! under `/api/integrations/modules/<name>`), the Mimecast routes but the
//! provisioning (`app/integrations/mimecast/routes/mimecast.py`), and the
//! collection jobs of `app/schedulers/services/invoke_{huntress,carbonblack,
//! darktrace,duo,mimecast,sap_siem}.py`.
//!
//! Each integration has a *module*: an optional container on the Docker
//! network (`http://copilot-<name>-module`) that pulls the vendor's events
//! and ships them to Graylog. CoPilot only hands it the customer's auth keys
//! and where to ship:
//!
//! - [`collect`] — Huntress, Mimecast, Duo and Cato (mounted), CarbonBlack
//!   and Darktrace (reached only through their jobs): the customer's keys
//!   read as `extract_auth_keys` reads them, the payload model built, one
//!   httpx POST, and the route's `except Exception` folding every failure
//!   into `success: false` with `str(e)`;
//! - [`sap_siem`] — the SAP SIEM collection (one POST per comma-separated API
//!   key; a single key is POSTed the same way, where Python's bare 500 —
//!   `get_customer_meta_attribute` called without its session — stopped it)
//!   and the seven analyses, whose rules run in the module itself;
//! - [`mimecast`] — `POST /api/mimecast/invoke` and `/ttp/urls`: the
//!   discovery call to Mimecast's API, then what Python would do had the
//!   region's URL been a string (it is a Pydantic `HttpUrl`, and `HttpUrl +
//!   str` is the `TypeError` every Python run ends in): the SIEM download
//!   with its checkpoint file and the TTP URL pages, their events shipped to
//!   Graylog (RUST_MIGRATION.md §4, "Python fails, Rust works");
//! - [`jobs`] — the hand-over jobs (`copilot-scheduler`), one call per
//!   customer with the integration, with each Python function's own failure
//!   and `last_success` semantics; `GET /api/carbonblack/test` runs the
//!   CarbonBlack job as Python's route does (its guard's lock and row
//!   check, then the job).
//!
//! The module and Mimecast URLs are Python's constants;
//! `COPILOT_INTEGRATION_MODULES_URL` points them all at one stand-in (tests
//! only, never in production): `{url}/{host}{path}`.
//!
//! Tenancy (RUST_MIGRATION.md §4): a body naming a customer (`customer_code`,
//! or the SAP analyses' `iris_customer_id`) is checked against the caller's
//! customers, which Python does not do.

#![warn(missing_docs)]

pub mod collect;
pub mod error;
pub mod jobs;
pub mod lookups;
pub mod mimecast;
pub mod routes;
pub mod sap_siem;
pub mod schema;
pub mod upstream;
#[cfg(test)]
mod vectors;

use axum::extract::FromRef;
use copilot_db::schema::TableRequirement;
use copilot_web::AppContext;

pub use routes::router;
pub use upstream::Upstream;

/// What the routes and the jobs need.
#[derive(Clone)]
pub struct ModulesState {
    /// The shared context (database, tokens, connector rows).
    pub ctx: AppContext,
    /// Where the module containers and Mimecast's API are reached.
    pub upstream: Upstream,
    /// Where the Mimecast SIEM collection keeps its checkpoint and log
    /// files (`COPILOT_MIMECAST_DIR`).
    pub mimecast_dir: std::path::PathBuf,
}

impl ModulesState {
    /// A state for `ctx`, the upstreams at `base` (`None` = Python's URLs).
    pub fn new(ctx: AppContext, base: Option<String>) -> Self {
        Self {
            ctx,
            upstream: Upstream::new(base),
            mimecast_dir: mimecast::files::DEFAULT_DIR.into(),
        }
    }

    /// The Mimecast files under `dir` (`None`: Python's module directory).
    pub fn with_mimecast_dir(mut self, dir: Option<String>) -> Self {
        if let Some(dir) = dir {
            self.mimecast_dir = dir.into();
        }
        self
    }
}

impl FromRef<ModulesState> for AppContext {
    fn from_ref(s: &ModulesState) -> Self {
        s.ctx.clone()
    }
}

/// The columns this crate reads beyond `copilot-integrations`' (the
/// customer integrations, their subscriptions and keys).
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customersmeta",
        columns: &["customer_code", "customer_meta_iris_customer_id"],
    },
    TableRequirement {
        table: "license",
        columns: &["license_key"],
    },
];
