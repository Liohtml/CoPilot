//! `/api/incidents/db_operations` — port of
//! `app/incidents/routes/db_operations.py`.

use axum::Router;

use copilot_web::AppContext;

pub mod reads;

/// The router, to be nested at `/api/incidents/db_operations`. Paths and
/// methods not routed here (writes, the Wazuh-indexer and MinIO routes) fall
/// through to the legacy backend.
pub fn db_operations(ctx: AppContext) -> Router {
    Router::new().merge(reads::router()).with_state(ctx)
}
