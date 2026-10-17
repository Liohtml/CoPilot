//! # copilot-sublime — `/api/sublime`
//!
//! Port of `app/connectors/sublime/` (routes, `services/alerts.py`,
//! `utils/universal.py`, schema, model): the webhook Sublime posts a flagged
//! message to (`POST /api/sublime/alert`, stored in `sublimealerts` and its
//! five child tables, with the sender and the first recipient read back from
//! Sublime's `GET /v0/messages/{id}`), the stored alerts
//! (`GET /api/sublime/alerts`) and the `Sublime` connector check
//! (`GET /v0/rules?limit=1`).
//!
//! - [`routes`] — the two routes, both `require_any_scope("admin",
//!   "analyst")`; [`schema`] — the request and response models
//! - [`services`] — the store (the ORM's statements, in its order, and its
//!   errors as SQLAlchemy words them) and the listing (`selectinload`'s
//!   statements)
//! - [`client`] — `send_get_request` (`requests`, bearer key, `verify=False`,
//!   60 s); [`verify`] — the connector check
//!
//! The tables are Alembic's (`d6c01a2b3c4d`, which created them: before it
//! both routes were a 500 on every deployment). No route is tenant-scoped,
//! as in Python: a Sublime alert names no customer.
//!
//! State kept by the process: none beyond the shared connector cache.

#![warn(missing_docs)]

pub mod client;
pub mod routes;
pub mod schema;
pub mod services;
pub mod sql;
pub mod verify;

#[cfg(test)]
mod vectors;

use axum::extract::FromRef;
use copilot_db::schema::TableRequirement;
use copilot_gateway::LegacyProxy;
use copilot_web::AppContext;

pub use client::SublimeClient;
pub use routes::router;
pub use verify::verifiers;

/// The columns the module reads and writes (the model's tables).
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "sublimealerts",
        columns: &[
            "id",
            "api_version",
            "created_at",
            "event_id",
            "type",
            "message_id",
            "canonical_id",
            "external_id",
            "message_source_id",
            "timestamp",
        ],
    },
    TableRequirement {
        table: "flaggedrule",
        columns: &[
            "id",
            "rule_id",
            "name",
            "severity",
            "tags",
            "sublime_alert_id",
        ],
    },
    TableRequirement {
        table: "mailbox",
        columns: &["id", "external_id", "mailbox_id", "sublime_alert_id"],
    },
    TableRequirement {
        table: "triggeredaction",
        columns: &["id", "action_id", "name", "type", "sublime_alert_id"],
    },
    TableRequirement {
        table: "sender",
        columns: &["id", "email", "name", "sublime_alert_id"],
    },
    TableRequirement {
        table: "recipient",
        columns: &["id", "email", "name", "sublime_alert_id"],
    },
];

/// State of the Sublime routes.
#[derive(Clone)]
pub struct SublimeState {
    /// Shared dependencies (auth, MySQL).
    pub ctx: AppContext,
    /// Sublime's API.
    pub client: SublimeClient,
    /// The Python backend, for a path with an encoded `/`.
    pub legacy: Option<LegacyProxy>,
}

impl std::fmt::Debug for SublimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SublimeState").finish_non_exhaustive()
    }
}

impl SublimeState {
    /// The state over the context's connector cache.
    pub fn new(ctx: AppContext, client: SublimeClient, legacy: Option<LegacyProxy>) -> Self {
        Self {
            ctx,
            client,
            legacy,
        }
    }
}

impl FromRef<SublimeState> for AppContext {
    fn from_ref(s: &SublimeState) -> AppContext {
        s.ctx.clone()
    }
}
