//! # copilot-wazuh — the Wazuh indexer and manager connectors
//!
//! Port of `app/connectors/wazuh_indexer/` and `app/connectors/wazuh_manager/`:
//!
//! - [`es`] — the indexer client: elasticsearch-py 7.10.1 as CoPilot
//!   configures it (paths, query order, bodies, Basic auth, retries, the
//!   exceptions' texts); TLS unverified as in Python
//! - [`indexer`] — `/api/alerts`, `/api/wazuh_indexer`, `/api/snapshots`
//! - [`pymodel`] — Pydantic models over upstream JSON (lax coercion and the
//!   `ValidationError` texts the routes put into responses)
//! - [`pyjson_error`] — CPython's `json` error messages
//! - [`error`] — the Python exception kinds the services raise
//!
//! The connector rows (`Wazuh-Indexer`, `Wazuh-Manager`) are read through
//! the process's `ConnectorCache`, whose change check bounds how long a
//! credential rotated by the Python backend is still used here.

#![warn(missing_docs)]

pub mod error;
pub mod es;
pub mod indexer;
pub mod pyjson_error;
pub mod pymodel;

use std::sync::OnceLock;

use axum::extract::FromRef;
use regex::Regex;

use copilot_web::AppContext;

/// State of the Wazuh routes.
#[derive(Clone, Debug)]
pub struct WazuhState {
    /// Shared dependencies (connector cache, database, auth).
    pub ctx: AppContext,
    /// The indexer's HTTP stack.
    pub es: es::EsHttp,
}

impl WazuhState {
    /// Build the clients.
    pub fn new(ctx: AppContext) -> Result<Self, reqwest::Error> {
        Ok(Self {
            ctx,
            es: es::EsHttp::new()?,
        })
    }
}

impl FromRef<WazuhState> for AppContext {
    fn from_ref(s: &WazuhState) -> AppContext {
        s.ctx.clone()
    }
}

/// The `index_snapshot_schedules` columns this crate reads and writes.
pub const REQUIREMENTS: &[copilot_db::schema::TableRequirement] =
    &[copilot_db::schema::TableRequirement {
        table: "index_snapshot_schedules",
        columns: indexer::services::snapshots::COLUMNS,
    }];

/// A constant pattern, compiled once (`None` if it does not compile, which
/// a test rules out).
pub(crate) fn regex(
    slot: &'static OnceLock<Option<Regex>>,
    pattern: &str,
) -> Option<&'static Regex> {
    slot.get_or_init(|| Regex::new(pattern).ok()).as_ref()
}
