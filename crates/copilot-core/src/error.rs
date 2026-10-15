//! Shared error type (same shape as `talon_core::error`). Crates may use
//! `anyhow` internally, but public APIs that cross crate boundaries return
//! [`Result`].

use thiserror::Error;

/// `Result` with the shared [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors shared across the workspace.
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Bad or missing configuration.
    #[error("configuration error: {0}")]
    Config(String),

    /// Rejected input.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Something that should exist doesn't.
    #[error("not found: {0}")]
    NotFound(String),

    /// Database failure.
    #[error("database error: {0}")]
    Db(String),

    /// Outbound HTTP failure (connector, legacy backend).
    #[error("upstream error: {0}")]
    Upstream(String),

    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Shorthand for [`Error::InvalidInput`].
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Shorthand for [`Error::Other`].
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}
