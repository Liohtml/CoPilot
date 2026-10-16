//! `app/agents/velociraptor/services/agents.py`: what the agents module asks
//! Velociraptor (its orgs, each org's clients, deleting a client, the
//! server's version).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_velociraptor::VelociraptorClient;
use copilot_velociraptor::client::ROOT;
use copilot_velociraptor::validation::{validate_client_id, validate_org_id};

/// `collect_velociraptor_organizations()`: the rows of `SELECT * FROM orgs()`.
pub async fn collect_organizations(client: &VelociraptorClient) -> PyResult<Vec<PyValue>> {
    let service = client.service().await?;
    let rows = service
        .execute_query("SELECT * FROM orgs()", ROOT, None)
        .await?;
    tracing::info!(
        "Successfully ran artifact collection on {} rows",
        rows.len()
    );
    Ok(rows)
}

/// `collect_velociraptor_clients(org_id)`: every client of the org, asked
/// through the root org's `query()`.
pub async fn collect_clients(client: &VelociraptorClient, org_id: &str) -> PyResult<Vec<PyValue>> {
    validate_org_id(Some(org_id))?;
    let service = client.service().await?;
    let vql = format!("SELECT * FROM query(org_id='{org_id}', query='SELECT * FROM clients()')");
    let rows = service.execute_query(&vql, ROOT, None).await?;
    tracing::info!(
        "Successfully ran artifact collection on {} rows",
        rows.len()
    );
    Ok(rows)
}

/// `handle_exception(e, client_id)`'s `HTTPException`.
fn delete_failed(client_id: &str, e: &PyExc) -> PyExc {
    tracing::error!("Failed to delete client {client_id}: {}", e.display());
    PyExc::http(
        500,
        format!(
            "Failed to delete Velociraptor client {client_id}: {}",
            e.display()
        ),
    )
}

/// `delete_agent_velociraptor(client_id)`: `delete_client` with its two
/// `handle_exception` wrappers (a failure reads `Failed to delete
/// Velociraptor client C: 500: Failed to delete Velociraptor client C: 500:
/// Failed to execute query: …`, as in Python).
pub async fn delete_agent_velociraptor(
    client: &VelociraptorClient,
    client_id: Option<&str>,
) -> PyResult<()> {
    let label = client_id.unwrap_or("None");
    match delete_client(client, client_id).await {
        Ok(()) => Ok(()),
        Err(e) => Err(delete_failed(label, &e)),
    }
}

async fn delete_client(client: &VelociraptorClient, client_id: Option<&str>) -> PyResult<()> {
    let client_id = validate_client_id(client_id)?;
    let service = client.service().await?;
    let vql = format!(
        "SELECT collect_client(client_id='server', artifacts=['Server.Utils.DeleteClient'], env=dict(ClientIdList='{client_id}',ReallyDoIt='Y')) FROM scope()"
    );
    match service.execute_query(&vql, ROOT, None).await {
        Ok(rows) => {
            tracing::info!(
                "Successfully ran artifact collection on {} rows",
                rows.len()
            );
            tracing::info!("Successfully deleted velociraptor client {client_id}");
            Ok(())
        }
        Err(e) => Err(delete_failed(client_id, &e)),
    }
}
