//! `/api/vulnerabilities` — `app/agents/vulnerabilities/`.
//!
//! - [`routes`] — the 13 routes
//! - [`sync`] — the indexer → `agent_vulnerabilities` sync (batch and bulk
//!   mode)
//! - [`services`] — statistics, delete, the indexer search, the CSV reports
//!   in MinIO
//! - [`indexer`] — the `wazuh-states-vulnerabilities-*` documents and queries
//! - [`db`], [`schema`] — the statements and the response models

pub mod db;
pub mod indexer;
pub mod routes;
pub mod schema;
pub mod services;
pub mod sync;

pub use routes::router;
