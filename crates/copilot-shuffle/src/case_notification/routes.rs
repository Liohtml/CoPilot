//! `POST /api/incidents/db_operations/case/notification` (admin/analyst):
//! the case (`get_case_by_id`: 404), its customer (403), one
//! `CreatedAlertPayload` per linked alert, the customer's notification
//! workflow (400 when none is enabled), the Shuffle call (502 when Shuffle
//! does not run it), then the case's `notification_invoked_number`.

use axum::Router;
use axum::extract::State;
use axum::routing::post;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, WithJson};

use crate::ShuffleState;
use crate::case_notification::schema::{CASE_NOTIFICATION_CREATE, CASE_NOTIFICATION_RESPONSE};
use crate::case_notification::services;

type Soc = Authorized<AdminOrAnalyst>;

/// The route, by full path.
pub fn router(state: ShuffleState) -> Router {
    Router::new()
        .route(
            "/api/incidents/db_operations/case/notification",
            post(create),
        )
        .with_state(state)
}

async fn create(State(st): State<ShuffleState>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    let body = body_model(&body, &CASE_NOTIFICATION_CREATE)?;
    let raw = field(&body, "case_id").py_str();
    tracing::info!(
        "Creating case notification for case {raw} for user: {}",
        auth.username
    );
    // A case id no column can hold is a case that does not exist.
    let case_id: i64 = raw
        .parse()
        .map_err(|_| ApiError::not_found("Case not found"))?;
    let case = copilot_incidents::access::ensure_case(&st.ctx, &auth, case_id).await?;
    services::notify(&st.ctx.db, &st.client, &case).await?;
    services::increment(&st.ctx.db, case_id).await?;
    let dump = construct(
        &CASE_NOTIFICATION_RESPONSE,
        &kwargs(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("Case notification created successfully".into()),
            ),
        ]),
    )?;
    Ok(model_response(&dump))
}
