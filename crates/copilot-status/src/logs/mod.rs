//! `/api/logs` — port of `app/utils.py`'s `logs_router`: the `log_entries`
//! rows the exception handlers write, read and purged by an admin.
//!
//! - [`routes`] — the six routes (`Security(get_current_user,
//!   scopes=["admin"])`)
//! - [`services`] — the reads, the purges, `TimeRangeModel`'s validator and
//!   the window it opens
//! - [`schema`] — `LogRetrieveModel`, `LogsResponse`, `TimeRangeModel`

pub mod routes;
pub mod schema;
pub mod services;

pub use routes::router;
