//! `/api/sublime` — port of `routes/alerts.py`: `POST /alert` (the webhook
//! Sublime is configured to call, which takes a CoPilot token like any
//! route) and `GET /alerts`, both `require_any_scope("admin", "analyst")`.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::{AdminOrAnalyst, ApiResult, Authorized, WithJson};

use crate::SublimeState;
use crate::schema::ALERT_REQUEST_BODY;
use crate::services;

type Reader = Authorized<AdminOrAnalyst>;

/// The two routes (full paths), behind the encoded-slash hand-off.
pub fn router(state: SublimeState) -> Router {
    Router::new()
        .route("/api/sublime/alert", post(receive_sublime_alert))
        .route("/api/sublime/alerts", get(get_sublime_alerts))
        .with_state(state)
}

async fn receive_sublime_alert(
    State(st): State<SublimeState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let alert = body_model(&body, &ALERT_REQUEST_BODY)?;
    tracing::info!(
        "Received alert from Sublime: {}",
        alert.get("id").map(|v| v.py_str()).unwrap_or_default()
    );
    let answer = services::store_sublime_alert(&st, &alert)
        .await
        .map_err(PyExc::unhandled)?;
    Ok(model_response(&answer))
}

async fn get_sublime_alerts(_: Reader, State(st): State<SublimeState>) -> ApiResult {
    tracing::info!("Fetching all alerts from Sublime");
    let answer = services::collect_alerts(&st)
        .await
        .map_err(PyExc::unhandled)?;
    Ok(model_response(&answer))
}
