//! # copilot-core — the contract every CoPilot crate builds against
//!
//! See `docs/architecture/RUST_MIGRATION.md`. This crate mirrors `talon-core` (Talon 2.0):
//! no runtime, no I/O beyond reading `.env`, only types and pure helpers that
//! the database layer, the HTTP layer and the binary agree on.
//!
//! Module map:
//! - [`config`] — process-wide configuration from env / `.env`
//! - [`env`](mod@env)    — `.env` reader that never pollutes `std::env` (vendored from Talon)
//! - [`roles`]  — `RoleEnum`, role extension and token scopes
//! - [`audit`]  — `audit_log` records and the sink abstraction
//! - [`notify`] — notification events and the sink the legacy bridge implements
//! - [`time`]   — naive-UTC `DATETIME` helpers and Pydantic-compatible rendering
//! - [`error`]  — the shared error type

#![warn(missing_docs)]

pub mod audit;
pub mod catalog_env;
pub mod cloud_env;
pub mod config;
pub mod env;
pub mod error;
pub mod ingest_env;
pub mod notify;
pub mod response_env;
pub mod roles;
pub mod time;

pub use error::{Error, Result};
pub use roles::Role;
