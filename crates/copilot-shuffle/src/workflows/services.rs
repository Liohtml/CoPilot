//! `app/connectors/shuffle/services/workflows.py`.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{
    Invalid, Loc, PyError, construct, field, format_validation_error, kwargs, validate,
};
use copilot_upstream::py::{PyExc, type_name};

use crate::client::{CONNECTOR, ShuffleClient};
use crate::pyops::{contains, first, get, item, iterate, pop};
use crate::uuid4;
use crate::workflows::schema::{
    EXECUTE_WORKFLOW_SUCCESS, WORKFLOW_EXECUTION_STATUS, WORKFLOWS_RESPONSE,
};

/// `remove_large_images_from_actions(workflows)`, in place.
pub fn remove_large_images(workflows: &mut PyValue) -> Result<(), PyExc> {
    match workflows {
        PyValue::List(items) => {
            for workflow in items.iter_mut() {
                if !contains(workflow, "actions")? {
                    continue;
                }
                match workflow {
                    PyValue::Dict(fields) => {
                        if let Some((_, actions)) = fields.iter_mut().find(|(k, _)| k == "actions")
                        {
                            strip_actions(actions)?;
                        }
                    }
                    other => {
                        item(other, "actions")?;
                    }
                }
            }
            Ok(())
        }
        other => {
            for workflow in iterate(other)? {
                if contains(&workflow, "actions")? {
                    item(&workflow, "actions")?;
                }
            }
            Ok(())
        }
    }
}

fn strip_actions(actions: &mut PyValue) -> Result<(), PyExc> {
    match actions {
        PyValue::List(list) => {
            for action in list.iter_mut() {
                pop(action, "large_image")?;
            }
            Ok(())
        }
        other => {
            for mut action in iterate(other)? {
                pop(&mut action, "large_image")?;
            }
            Ok(())
        }
    }
}

/// `get_workflows()`: the `WorkflowsResponse` dump; every failure is the
/// 500 `Failed to get workflows with error: …`.
pub async fn get_workflows(client: &ShuffleClient) -> Result<PyValue, PyExc> {
    tracing::info!("Getting workflows");
    let wrap = |e: PyExc| {
        let text = format!("Failed to get workflows with error: {}", e.display());
        tracing::error!("{text}");
        PyExc::http(500, text)
    };
    let Some(response) = client
        .get("/api/v1/workflows", Vec::new(), CONNECTOR)
        .await
        .map_err(wrap)?
    else {
        return construct(
            &WORKFLOWS_RESPONSE,
            &kwargs(vec![
                ("success", PyValue::Bool(false)),
                ("message", PyValue::Str("Failed to get workflows".into())),
                ("workflows", PyValue::List(Vec::new())),
            ]),
        )
        .map_err(wrap);
    };
    let mut workflows = response.get("data").cloned().unwrap_or(PyValue::None);
    remove_large_images(&mut workflows).map_err(wrap)?;
    construct(
        &WORKFLOWS_RESPONSE,
        &kwargs(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("Successfully fetched workflows".into()),
            ),
            ("workflows", workflows),
        ]),
    )
    .map_err(wrap)
}

/// `get_workflow_executions(WorkflowExecutionBodyModel(workflow_id=…))`:
/// the `WorkflowExecutionStatusResponseModel` dump. The request's own 500
/// passes through; what follows it is `Failed to get workflow executions
/// with error: …`.
pub async fn get_workflow_executions(
    client: &ShuffleClient,
    workflow_id: &str,
) -> Result<PyValue, PyExc> {
    tracing::info!("Getting workflow executions");
    let response = client
        .get(
            &format!("/api/v1/workflows/{workflow_id}/executions"),
            Vec::new(),
            CONNECTOR,
        )
        .await?
        .unwrap_or(PyValue::None);
    let run = || -> Result<PyValue, PyExc> {
        let executions = item(&response, "data")?;
        let status = if executions.truthy() {
            match item(&first(executions)?, "status")? {
                PyValue::None => PyValue::Str("Never Ran".into()),
                other => other.clone(),
            }
        } else {
            PyValue::Str("No executions found".into())
        };
        construct(
            &WORKFLOW_EXECUTION_STATUS,
            &kwargs(vec![("last_run", status)]),
        )
    };
    run().map_err(|e| {
        let text = format!(
            "Failed to get workflow executions with error: {}",
            e.display()
        );
        tracing::error!("{text}");
        PyExc::http(500, text)
    })
}

/// `ExecuteWorklow(**data)`.
struct Execution {
    success: bool,
    execution_id: String,
    authorization: String,
}

fn execution(data: &PyValue) -> Result<Execution, PyExc> {
    if !matches!(data, PyValue::Dict(_)) {
        return Err(PyExc::TypeError(format!(
            "app.connectors.shuffle.schema.workflows.ExecuteWorklow() argument after ** must be \
             a mapping, not {}",
            type_name(data)
        )));
    }
    let mut errors: Vec<PyError> = Vec::new();
    let success = match validate(&EXECUTE_WORKFLOW_SUCCESS, data) {
        Ok(dump) => matches!(field(&dump, "success"), PyValue::Bool(true)),
        Err(Invalid::Errors(e)) => {
            errors.extend(e);
            false
        }
        Err(Invalid::Abort(status, detail)) => return Err(PyExc::Http(status, detail)),
    };
    let mut uuid = |name: &str| match data.get(name) {
        None => {
            errors.push(PyError {
                loc: vec![Loc::Key(name.to_string())],
                kind: "missing",
                msg: "Field required".into(),
                input: data.clone(),
            });
            String::new()
        }
        Some(v) => uuid4::check(v, name).unwrap_or_else(|e| {
            errors.push(e);
            String::new()
        }),
    };
    let execution_id = uuid("execution_id");
    let authorization = uuid("authorization");
    if !errors.is_empty() {
        return Err(PyExc::Validation(format_validation_error(
            "ExecuteWorklow",
            &errors,
        )));
    }
    Ok(Execution {
        success,
        execution_id,
        authorization,
    })
}

fn results_body(e: &Execution) -> PyValue {
    kwargs(vec![
        ("execution_id", PyValue::Str(e.execution_id.clone())),
        ("authorization", PyValue::Str(e.authorization.clone())),
    ])
}

/// `wait_for_workflow_execution_results(execution)`: ten polls of
/// `/api/v1/streams/results`, `2**i` seconds apart, until `FINISHED`.
async fn wait_for_results(client: &ShuffleClient, e: &Execution) -> Result<(), PyExc> {
    tracing::info!(
        "Retrieving workflow execution results for execution ID: {}",
        e.execution_id
    );
    for i in 0..10u32 {
        let attempt = async {
            let response = client
                .post("/api/v1/streams/results", results_body(e), CONNECTOR)
                .await?
                .unwrap_or(PyValue::None);
            let data = get(&response, "data", PyValue::Dict(Vec::new()))?;
            let status = get(&data, "status", PyValue::None)?;
            Ok::<_, PyExc>(matches!(status, PyValue::Str(s) if s == "FINISHED"))
        }
        .await;
        match attempt {
            Ok(true) => {
                tracing::info!("Workflow execution with ID {} has finished", e.execution_id);
                return Ok(());
            }
            Ok(false) => {}
            Err(err) => tracing::error!(
                "Error retrieving workflow execution results: {}",
                err.display()
            ),
        }
        tokio::time::sleep(Duration::from_secs(1u64 << i)).await;
    }
    Err(PyExc::http(
        500,
        format!(
            "Workflow execution with ID {} did not finish after 5 attempts",
            e.execution_id
        ),
    ))
}

/// `execute_workflow(body)`: the results' `data`, or what Python raises.
pub async fn execute_workflow(
    client: &ShuffleClient,
    workflow_id: &str,
    execution_argument: &str,
) -> Result<PyValue, PyExc> {
    tracing::info!("Executing workflow with ID: {workflow_id}");
    let response = client
        .post(
            &format!("/api/v1/workflows/{workflow_id}/execute"),
            kwargs(vec![(
                "execution_argument",
                PyValue::Str(execution_argument.into()),
            )]),
            CONNECTOR,
        )
        .await?
        .unwrap_or(PyValue::None);
    let e = execution(item(&response, "data")?)?;
    let run = async {
        if !e.success {
            return Err(PyExc::http(404, "Failed to execute workflow"));
        }
        wait_for_results(client, &e).await?;
        tracing::info!("Successfully executed workflow with ID: {workflow_id}");
        let response = client
            .post("/api/v1/streams/results", results_body(&e), CONNECTOR)
            .await?
            .unwrap_or(PyValue::None);
        get(&response, "data", PyValue::Dict(Vec::new()))
    };
    run.await.map_err(|err| {
        let text = format!("Failed to execute workflow with error: {}", err.display());
        tracing::error!("{text}");
        PyExc::http(500, text)
    })
}
