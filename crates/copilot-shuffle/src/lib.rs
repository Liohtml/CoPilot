//! # copilot-shuffle — the Shuffle connector
//!
//! Port of `app/connectors/shuffle/` and the one incidents route that calls
//! it:
//!
//! - [`workflows`] — `/api/workflows` (the list, the last run of each, an
//!   execution and its results);
//! - [`integrations`] — `/api/shuffle/integrations` (the connector's URL and
//!   key for the embedded MCP picker, an app-category run, a workflow
//!   invocation);
//! - [`organizations`] — `/api/shuffle/organizations/organizations…`;
//! - [`singul`] — `/api/shuffle/singul/execute`;
//! - [`case_notification`] — `POST /api/incidents/db_operations/case/notification`;
//! - [`verify`] — the connector's verification.
//!
//! Every Shuffle request is the one `requests` sends from
//! `utils/universal.py` ([`client`]). Each module keeps the backend's
//! `routes / services / schema` split.

#![warn(missing_docs)]

use axum::Router;
use axum::extract::FromRef;
use copilot_web::AppContext;

pub mod case_notification;
pub mod client;
pub mod integrations;
pub mod organizations;
pub mod pyops;
pub mod singul;
pub mod uuid4;
pub mod verify;
pub mod workflows;

pub use client::ShuffleClient;
pub use verify::verifiers;

/// State of the Shuffle routes.
#[derive(Debug, Clone)]
pub struct ShuffleState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Shuffle client.
    pub client: ShuffleClient,
}

impl FromRef<ShuffleState> for AppContext {
    fn from_ref(st: &ShuffleState) -> Self {
        st.ctx.clone()
    }
}

/// Every route but the case notification and the organizations (whose
/// path parameters the binary guards), by full path.
pub fn router(state: ShuffleState) -> Router {
    Router::new()
        .merge(workflows::routes::router(state.clone()))
        .merge(integrations::routes::router(state.clone()))
        .merge(singul::routes::router(state))
}

pub use case_notification::routes::router as case_notification_router;
pub use organizations::routes::router as organizations_router;
