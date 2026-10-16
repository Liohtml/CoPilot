//! `app/connectors/shuffle/services/integrations.py`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::field;
use copilot_upstream::py::PyExc;

use crate::client::{CONNECTOR, ShuffleClient};

/// `ExecuteWorkflowRequest.check_customer_code` (`mode="after"`): the 400
/// unless `execution_arguments` holds a truthy `customer_code`.
pub fn check_customer_code(request: &PyValue) -> Result<(), PyExc> {
    let ok = field(request, "execution_arguments")
        .get("customer_code")
        .is_some_and(PyValue::truthy);
    if ok {
        Ok(())
    } else {
        Err(PyExc::http(400, "customer_code is required"))
    }
}

/// `execute_integration(request)`: `send_post_request`'s answer as it is.
pub async fn execute_integration(
    client: &ShuffleClient,
    request: PyValue,
) -> Result<Option<PyValue>, PyExc> {
    tracing::info!("Executing integration");
    client
        .post("/api/v1/apps/categories/run", request, CONNECTOR)
        .await
}

/// `execute_workflow(request)` (`ExecuteWorkflowRequest`): the answer when
/// Shuffle says it ran, else the 502 naming why.
pub async fn execute_workflow(client: &ShuffleClient, request: PyValue) -> Result<PyValue, PyExc> {
    let workflow_id = field(&request, "workflow_id").py_str();
    let response = match client
        .post(
            &format!("/api/v1/workflows/{workflow_id}/execute"),
            request,
            CONNECTOR,
        )
        .await
    {
        Ok(r) => r,
        Err(e @ PyExc::Http(..)) => return Err(e),
        Err(e) => {
            tracing::error!("Error executing workflow: {}", e.display());
            return Err(PyExc::http(
                502,
                format!(
                    "Failed to reach Shuffle while executing workflow {workflow_id}: {}",
                    e.display()
                ),
            ));
        }
    };
    match response {
        Some(r) if matches!(r.get("success"), Some(PyValue::Bool(true))) => Ok(r),
        other => {
            let detail = other
                .as_ref()
                .and_then(|r| r.get("message"))
                .filter(|m| m.truthy())
                .map_or_else(
                    || "Failed to execute Shuffle workflow".to_string(),
                    PyValue::py_str,
                );
            tracing::error!("Shuffle workflow {workflow_id} did not execute successfully");
            Err(PyExc::http(502, detail))
        }
    }
}
