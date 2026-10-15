//! # copilot-talon — the Talon (AI analyst) connector
//!
//! Port of `app/connectors/talon/` (`routes / services / schema / utils`),
//! and the place where CoPilot and Talon 2.0 meet in code:
//!
//! - [`contract`] — every request/response exchanged with Talon's HTTP
//!   channel (`talon-http`), typed and pinned by tests
//! - [`client`]   — credentials from the `connectors` row, timeouts, error text
//! - [`services`] — investigate, replay, chat, session, status, templates,
//!   palace calls, the database-only job view
//! - [`routes`]   — `/api/talon/*`
//!
//! The other direction — Talon writing results back — goes through
//! `/api/ai_analyst/*` (crate `copilot-ai-analyst`), reached by Talon's agent
//! via the `copilot` MCP server.

#![warn(missing_docs)]

pub mod client;
pub mod contract;
pub mod routes;
pub mod services;

pub use client::{TalonConnector, TalonError};
pub use routes::{TalonState, router};
