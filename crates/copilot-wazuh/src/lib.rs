//! # copilot-wazuh — the Wazuh indexer and manager connectors
//!
//! Port of `app/connectors/wazuh_indexer/` and `app/connectors/wazuh_manager/`:
//!
//! - [`es`] — the indexer client: elasticsearch-py 7.10.1 as CoPilot
//!   configures it (paths, query order, bodies, Basic auth, retries, the
//!   exceptions' texts); TLS unverified as in Python
//! - [`indexer`] — `/api/alerts`, `/api/wazuh_indexer`, `/api/snapshots`
//! - [`requests`] — `requests` 2.33's URL preparation, Basic auth and
//!   exception texts, for the manager
//! - [`manager`] — the manager's token flow and `/api/wazuh_manager`
//! - [`pyops`] — Python's dict/list/str operations and their error texts
//! - [`verify`] — the two connectors' verification for `/api/connectors`
//! - [`jobs`] — `invoke_snapshot_schedules` and `resize_wazuh_index_fields`,
//!   taken over from APScheduler by the hand-over
//! - [`pymodel`] — Pydantic models over upstream JSON (lax coercion and the
//!   `ValidationError` texts the routes put into responses)
//! - [`error`] — the Python exception kinds the services raise
//!
//! CPython's `JSONDecodeError` texts and urllib3's object address come from
//! `copilot-upstream`, which the other connector crates share.
//!
//! The connector rows (`Wazuh-Indexer`, `Wazuh-Manager`) are read through
//! the process's `ConnectorCache`, whose change check bounds how long a
//! credential rotated by the Python backend is still used here.

#![warn(missing_docs)]

pub mod error;
pub mod es;
pub mod indexer;
pub mod jobs;
pub mod manager;
pub mod pymodel;
pub mod pyops;
pub mod requests;
pub mod verify;

use std::sync::OnceLock;

use axum::extract::{FromRef, OriginalUri, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use regex::Regex;

use copilot_gateway::LegacyProxy;
use copilot_web::{ApiError, AppContext};

/// State of the Wazuh routes.
#[derive(Clone, Debug)]
pub struct WazuhState {
    /// Shared dependencies (connector cache, database, auth).
    pub ctx: AppContext,
    /// The indexer's HTTP stack.
    pub es: es::EsHttp,
    /// The manager's HTTP stack and token cache.
    pub manager: manager::client::ManagerHttp,
    /// The Python backend, for the requests these routers must not answer.
    pub legacy: Option<LegacyProxy>,
}

impl WazuhState {
    /// Build the clients.
    pub fn new(ctx: AppContext, legacy: Option<LegacyProxy>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            ctx,
            es: es::EsHttp::new()?,
            manager: manager::client::ManagerHttp::new()?,
            legacy,
        })
    }
}

/// Middleware for the Wazuh routers: a path with an encoded `/` (`%2F`)
/// is not theirs. Starlette routes the *decoded* path, so `…/files/a%2Fb`
/// is `…/files/a/b` there — no route of these routers, or another one —
/// whereas axum would hand `a/b` to the `{filename}` route. Such a request
/// goes to the Python backend (FastAPI's 404 without one).
pub async fn decoded_slash_to_legacy(
    State(legacy): State<Option<LegacyProxy>>,
    mut req: Request,
    next: Next,
) -> Response {
    let original = req
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| req.uri().clone(), |o| o.0.clone());
    if !original.path().to_ascii_lowercase().contains("%2f") {
        return next.run(req).await;
    }
    match legacy {
        Some(proxy) => {
            *req.uri_mut() = original;
            proxy.forward(req).await
        }
        None => ApiError::RouteNotFound.into_response(),
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

#[cfg(test)]
mod tests {
    /// The `JSONDecodeError` texts the indexer and manager failures quote
    /// (`copilot_upstream::json`), recorded with CPython 3.11's `json.loads`.
    #[test]
    fn json_decode_errors_read_like_cpython() {
        let cases = [
            ("", "Expecting value: line 1 column 1 (char 0)"),
            ("<html>", "Expecting value: line 1 column 1 (char 0)"),
            ("  \n x", "Expecting value: line 2 column 2 (char 4)"),
            ("{\"a\": 1} x", "Extra data: line 1 column 10 (char 9)"),
            (
                "{a: 1}",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            (
                "{\"a\" 1}",
                "Expecting ':' delimiter: line 1 column 6 (char 5)",
            ),
            (
                "{\"a\": 1 \"b\"}",
                "Expecting ',' delimiter: line 1 column 9 (char 8)",
            ),
            (
                "{\"a\": 1,}",
                "Expecting property name enclosed in double quotes: line 1 column 9 (char 8)",
            ),
            ("[1, 2", "Expecting ',' delimiter: line 1 column 6 (char 5)"),
            ("[1,]", "Expecting value: line 1 column 4 (char 3)"),
            (
                "\"abc",
                "Unterminated string starting at: line 1 column 1 (char 0)",
            ),
            (
                "\"a\tb\"",
                "Invalid control character at: line 1 column 3 (char 2)",
            ),
            ("\"\\x\"", "Invalid \\escape: line 1 column 2 (char 1)"),
            (
                "\"\\u12\"",
                "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
            ),
        ];
        for (text, want) in cases {
            assert_eq!(
                copilot_upstream::json::decode_error(text).as_deref(),
                Some(want),
                "{text:?}"
            );
        }
        assert_eq!(
            copilot_upstream::json::decode_error("{\"a\": [1, 2.5e3, null]}"),
            None
        );
        assert_eq!(copilot_upstream::json::decode_error(" NaN "), None);
    }
}
