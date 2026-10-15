//! # copilot-ai-analyst — the AI analyst write-back and review API
//!
//! Port of `app/ai_analyst/` (`routes / services / schema`): the REST
//! surface Talon's agent writes its results through (via the `copilot` MCP
//! server: `CreateAiAnalystJobTool`, `SubmitAiAnalystReportTool`,
//! `SubmitAiAnalystIocsTool`, …) and the analyst-facing review, replay and
//! MemPalace-lesson features built on it.
//!
//! - [`schema`]        — request validation and response shapes
//! - [`services`]      — jobs, reports, IOCs, reviews, stats, palace
//! - [`routes`]        — `/api/ai_analyst/*` (25 routes)
//! - [`consolidation`] — the palace digest (pure)
//! - [`difflib`]       — CPython's `SequenceMatcher.ratio()`
//! - [`palace_jobs`]   — the lesson drainer and one-off sweeper
//!
//! The tables live in `copilot_db::ai_analyst`.

#![warn(missing_docs)]

pub mod consolidation;
pub mod difflib;
pub mod palace_jobs;
pub mod routes;
pub mod schema;
pub mod services;

pub use routes::router;
