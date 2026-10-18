//! `/api/github-audit/*` — `app/integrations/github_audit/` (model, routes,
//! schema, services): the per-customer GitHub organization audit, its
//! configurations, reports, check exclusions and baselines.
//!
//! The audit runs only when asked (`POST …/config/{id}/audit`,
//! `…/audit/summary`, the ad-hoc `POST /audit`). `auto_audit_enabled` and
//! `audit_schedule_cron` are stored and returned, but nothing in the Python
//! backend schedules an audit (no APScheduler job, no route registers one),
//! so nothing here does either; the same holds for the notification
//! settings, `minimum_passing_score`, `include_archived_repos` and the
//! `exclude` filter mode, which the Python service never reads.

pub mod audit;
pub mod client;
pub mod routes;
pub mod schema;
pub mod services;
pub mod store;
