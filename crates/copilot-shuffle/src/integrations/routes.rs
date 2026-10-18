//! `app/connectors/shuffle/routes/integrations.py` (admin/analyst).
//!
//! `POST /invoke-workflow` takes its tenant in the body
//! (`execution_arguments.customer_code`, which the model requires): a
//! caller without deployment-wide access may name only one of its own
//! customers (§4 — Python ran any customer's workflow for any analyst).

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, WithJson};

use crate::ShuffleState;
use crate::client::CONNECTOR;
use crate::integrations::schema::{
    CREDENTIALS_RESPONSE, EXECUTE_WORKFLOW_REQUEST, INTEGRATION_REQUEST,
};
use crate::integrations::services;
use crate::pyops::jsonable;

type Soc = Authorized<AdminOrAnalyst>;

/// The routes, by full path.
pub fn router(state: ShuffleState) -> Router {
    Router::new()
        .route("/api/shuffle/integrations/credentials", get(credentials))
        .route("/api/shuffle/integrations/execute", post(execute))
        .route(
            "/api/shuffle/integrations/invoke-workflow",
            post(invoke_workflow),
        )
        .with_state(state)
}

async fn credentials(auth: Soc, State(st): State<ShuffleState>) -> ApiResult {
    let _ = &auth;
    let Some(row) = st.client.row(CONNECTOR).await? else {
        return Err(ApiError::not_found("Shuffle connector is not configured."));
    };
    let api_key = row.connector_api_key.clone().unwrap_or_default();
    if api_key.is_empty() || row.connector_url.is_empty() {
        return Err(ApiError::bad_request(
            "Shuffle connector is missing connector_url or connector_api_key.",
        ));
    }
    let dump = construct(
        &CREDENTIALS_RESPONSE,
        &kwargs(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("Shuffle connector credentials retrieved.".into()),
            ),
            (
                "base_url",
                PyValue::Str(row.connector_url.trim_end_matches('/').to_string()),
            ),
            ("api_key", PyValue::Str(api_key)),
        ]),
    )?;
    Ok(model_response(&dump))
}

async fn execute(State(st): State<ShuffleState>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    let _ = &auth;
    let request = body_model(&body, &INTEGRATION_REQUEST)?;
    tracing::info!("Executing workflow");
    let response = services::execute_integration(&st.client, request).await?;
    Ok(model_response(&jsonable(
        &response.unwrap_or(PyValue::None),
    )))
}

async fn invoke_workflow(
    State(st): State<ShuffleState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let request = body_model(&body, &EXECUTE_WORKFLOW_REQUEST)?;
    services::check_customer_code(&request)?;
    let code = field(&request, "execution_arguments")
        .get("customer_code")
        .cloned()
        .unwrap_or(PyValue::None);
    auth.enforce_owned(
        &st.ctx,
        code.as_str(),
        &format!("customer {}", code.py_str()),
    )
    .await?;
    tracing::info!("Executing workflow");
    let response = services::execute_workflow(&st.client, request).await?;
    Ok(model_response(&jsonable(&response)))
}
