//! `/api/incidents/db_operations` — port of
//! `app/incidents/routes/db_operations.py`.

use axum::Router;

use copilot_web::AppContext;

pub mod alert_writes;
pub mod case_templates;
pub mod case_writes;
pub mod common;
pub mod config_writes;
pub mod reads;
pub mod tag_access;
pub mod task_writes;

/// The router, to be nested at `/api/incidents/db_operations`. Paths and
/// methods not routed here (the Wazuh-indexer and MinIO routes, the Shuffle
/// case notification) fall through to the legacy backend.
pub fn db_operations(ctx: AppContext) -> Router {
    Router::new()
        .merge(reads::router())
        .merge(alert_writes::router())
        .merge(case_writes::router())
        .merge(config_writes::router())
        .merge(task_writes::router())
        .with_state(ctx)
}

pub use case_templates::case_templates;
pub use tag_access::tag_access;
