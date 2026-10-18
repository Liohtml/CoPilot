//! `app/connectors/velociraptor/services/flows.py`: a client's flows and one
//! flow's results.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model;
use copilot_upstream::py::{PyExc, PyResult};

use crate::client::VelociraptorClient;
use crate::schema::{COLLECT_ARTIFACT_RESPONSE, FLOW_CLIENT_SESSION, flow_session_fails};
use crate::validation::{validate_client_id, validate_flow_id};

/// `get_flows(velociraptor_id, velociraptor_org)`: the `FlowResponse` dump.
/// A row that is no valid `FlowClientSession` is skipped, as in Python.
pub async fn get_flows(
    client: &VelociraptorClient,
    velociraptor_id: Option<&str>,
    velociraptor_org: Option<&str>,
) -> PyResult<PyValue> {
    tracing::info!("Fetching artifacts from Velociraptor");
    let client_id = validate_client_id(velociraptor_id)?;
    let service = client.service().await?;
    let vql = format!("SELECT * FROM flows(client_id='{client_id}')");
    let rows = service.execute_query(&vql, velociraptor_org, None).await?;
    let mut flows = Vec::with_capacity(rows.len());
    for flow in &rows {
        if flow_session_fails(flow) {
            tracing::warn!("Skipping unparseable flow");
            continue;
        }
        match model::validate(&FLOW_CLIENT_SESSION, flow) {
            Ok(dump) => flows.push(dump),
            Err(_) => tracing::warn!("Skipping unparseable flow"),
        }
    }
    Ok(PyValue::Dict(vec![
        ("results".into(), PyValue::List(flows)),
        ("success".into(), PyValue::Bool(true)),
        (
            "message".into(),
            PyValue::Str("All flows retrieved.".into()),
        ),
    ]))
}

/// `get_flow(request, velociraptor_org)`: the `CollectArtifactResponse`
/// dump of `flow_results()`.
pub async fn get_flow(
    client: &VelociraptorClient,
    client_id: &str,
    session_id: &str,
    velociraptor_org: Option<&str>,
) -> PyResult<PyValue> {
    tracing::info!("Fetching artifacts from Velociraptor");
    validate_client_id(Some(client_id))?;
    validate_flow_id(Some(session_id))?;
    let service = client.service().await?;
    let vql =
        format!("SELECT * FROM flow_results(client_id='{client_id}', flow_id='{session_id}')");
    let rows = service.execute_query(&vql, velociraptor_org, None).await?;
    model::construct(
        &COLLECT_ARTIFACT_RESPONSE,
        &model::kwargs(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("Successfully executed query".into()),
            ),
            ("results", PyValue::List(rows)),
        ]),
    )
    .map_err(|e| {
        let text = format!(
            "Failed to retrieve flow results from Velociraptor: {}",
            e.display()
        );
        tracing::error!("{text}");
        PyExc::http(500, text)
    })
}
