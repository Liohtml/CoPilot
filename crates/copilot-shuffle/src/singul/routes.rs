//! `app/connectors/shuffle/routes/singul.py` (admin/analyst): the body is
//! validated, then the handler calls `exit(0)` — a `SystemExit`, which
//! uvicorn answers with its own bare 500 (`Internal Server Error`) without
//! stopping. The Singul integration itself is commented out in Python.

use axum::Router;
use axum::extract::State;
use axum::routing::post;

use copilot_upstream::respond::body_model;
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, WithJson};

use crate::ShuffleState;
use crate::singul::schema::SINGUL_REQUEST;

type Soc = Authorized<AdminOrAnalyst>;

/// The route, by full path.
pub fn router(state: ShuffleState) -> Router {
    Router::new()
        .route("/api/shuffle/singul/execute", post(execute))
        .with_state(state)
}

async fn execute(State(st): State<ShuffleState>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    let _ = (&auth, &st);
    body_model(&body, &SINGUL_REQUEST)?;
    tracing::info!("Executing Singul integration");
    Err(ApiError::internal("exit(0) in execute_integration_route"))
}
