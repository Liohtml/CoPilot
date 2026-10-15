//! # copilot-db — MySQL pool and cross-cutting tables
//!
//! Port of `app/db/db_session.py` plus the reads every module shares: users
//! and their customer assignments, connector credentials (cached), alert
//! ownership, and the `audit_log` / `log_entries` writers.
//!
//! Feature crates own their tables the way Python modules own their
//! `models.py`: they run their own queries against [`Db::pool`] and declare
//! the columns they need as [`schema::TableRequirement`]s.
//!
//! ## Schema ownership
//! Alembic (`backend/alembic/`) remains the single owner of the schema until
//! the Python backend is retired; see [`schema`]. Timestamps are naive UTC
//! `DATETIME`s (`copilot_core::time`).
//!
//! ## Testing
//! Unit tests need no database. The integration suites (`tests/`) run when
//! `COPILOT_TEST_DATABASE_URL` points at a disposable MySQL migrated to the
//! Alembic head (the backend's 13306 convention) and skip otherwise.

#![warn(missing_docs)]

pub mod agents;
pub mod ai_analyst;
pub mod alerts;
pub mod audit;
pub mod connectors;
pub mod customer_portal;
pub mod customers;
pub mod passkeys;
pub mod pool;
pub mod scheduler;
pub mod schema;
pub mod security;
pub mod sso;
pub mod totp;
pub mod users;
pub mod visibility;

pub use pool::Db;

/// Database-layer error.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Bad connection settings.
    #[error("database configuration: {0}")]
    Config(String),
    /// Query or connection failure.
    #[error("database query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
}

impl DbError {
    /// Whether this is a unique-key violation (MySQL 1062).
    pub fn is_unique_violation(&self) -> bool {
        match self {
            DbError::Sqlx(sqlx::Error::Database(e)) => {
                e.code().as_deref() == Some("23000") && e.message().contains("Duplicate entry")
            }
            _ => false,
        }
    }
}

impl From<DbError> for copilot_core::Error {
    fn from(e: DbError) -> Self {
        copilot_core::Error::Db(e.to_string())
    }
}
