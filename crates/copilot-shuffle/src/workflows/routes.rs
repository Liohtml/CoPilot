//! `app/connectors/shuffle/routes/workflows.py` (admin/analyst).

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, WithJson};

use crate::ShuffleState;
use crate::pyops::item;
use crate::workflows::schema::{
    REQUEST_WORKFLOW_EXECUTION, REQUEST_WORKFLOW_EXECUTION_RESPONSE, WORKFLOW_EXECUTION_BODY,
    WORKFLOW_EXECUTION_RESPONSE,
};
use crate::workflows::services;

type Soc = Authorized<AdminOrAnalyst>;

/// The routes, by full path.
pub fn router(state: ShuffleState) -> Router {
    Router::new()
        .route("/api/workflows", get(all))
        .route("/api/workflows/executions", get(executions))
        .route("/api/workflows/execute", post(execute))
        .with_state(state)
}

async fn all(auth: Soc, State(st): State<ShuffleState>) -> ApiResult {
    let _ = &auth;
    tracing::info!("Fetching all workflows");
    let dump = services::get_workflows(&st.client).await?;
    Ok(model_response(&dump))
}

async fn executions(auth: Soc, State(st): State<ShuffleState>) -> ApiResult {
    let _ = &auth;
    tracing::info!("Fetching all workflow executions");
    let response = services::get_workflows(&st.client).await?;
    let workflows = field(&response, "workflows").clone();
    let PyValue::List(workflows) = workflows else {
        return Err(ApiError::not_found("No workflows found"));
    };
    if workflows.is_empty() {
        return Err(ApiError::not_found("No workflows found"));
    }
    let mut details = Vec::with_capacity(workflows.len());
    for workflow in &workflows {
        let id = item(workflow, "id").map_err(PyExc::unhandled)?.clone();
        let name = item(workflow, "name").map_err(PyExc::unhandled)?.clone();
        let body = construct(
            &WORKFLOW_EXECUTION_BODY,
            &kwargs(vec![("workflow_id", id.clone())]),
        )?;
        let workflow_id = field(&body, "workflow_id")
            .as_str()
            .unwrap_or_default()
            .to_string();
        let status = services::get_workflow_executions(&st.client, &workflow_id).await?;
        details.push(kwargs(vec![
            ("workflow_id", id),
            ("workflow_name", name),
            ("status", status),
        ]));
    }
    let dump = construct(
        &WORKFLOW_EXECUTION_RESPONSE,
        &kwargs(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("Successfully fetched workflow executions".into()),
            ),
            ("workflows", PyValue::List(details)),
        ]),
    )?;
    Ok(model_response(&dump))
}

/// `validate_execution_id(workflow_id)`.
async fn validate_execution_id(st: &ShuffleState, workflow_id: &str) -> Result<(), ApiError> {
    let response = services::get_workflows(&st.client).await?;
    if let PyValue::List(workflows) = field(&response, "workflows") {
        for workflow in workflows {
            let id = item(workflow, "id").map_err(PyExc::unhandled)?;
            tracing::info!("Workflow ID: {}", id.py_str());
            if matches!(id, PyValue::Str(s) if s == workflow_id) {
                tracing::info!("Workflow validation successful");
                return Ok(());
            }
        }
    }
    Err(ApiError::not_found("Workflow not found"))
}

async fn execute(State(st): State<ShuffleState>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    let _ = &auth;
    let body = body_model(&body, &REQUEST_WORKFLOW_EXECUTION)?;
    let workflow_id = field(&body, "workflow_id")
        .as_str()
        .unwrap_or_default()
        .to_string();
    let argument = field(&body, "execution_argument")
        .as_str()
        .unwrap_or_default()
        .to_string();
    tracing::info!("Executing workflow with ID: {workflow_id}");
    validate_execution_id(&st, &workflow_id).await?;
    let data = services::execute_workflow(&st.client, &workflow_id, &argument).await?;
    let dump = construct(
        &REQUEST_WORKFLOW_EXECUTION_RESPONSE,
        &kwargs(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("Successfully executed workflow".into()),
            ),
            ("data", data),
        ]),
    )?;
    Ok(model_response(&dump))
}
