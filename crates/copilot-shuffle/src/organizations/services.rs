//! `app/connectors/shuffle/services/organizations.py` (`OrganizationsService`).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, construct_star, field, kwargs};
use copilot_upstream::py::PyExc;

use crate::client::ShuffleClient;
use crate::organizations::schema::{
    DETAILED_ORGANIZATION, ORGANIZATION, ORGANIZATIONS_LIST_RESPONSE,
};
use crate::pyops::get;

/// `list_organizations(connector_name)`: the `OrganizationsListResponse`
/// dump; an organization that does not fit `Organization` is skipped.
pub async fn list_organizations(client: &ShuffleClient, connector: &str) -> Result<PyValue, PyExc> {
    tracing::info!("Fetching organizations from Shuffle");
    let response = client.get("/api/v1/orgs", Vec::new(), connector).await;
    let run = || -> Result<PyValue, PyExc> {
        let response = response.clone()?.unwrap_or(PyValue::None);
        if !get(&response, "success", PyValue::Bool(false))?.truthy() {
            let message = get(&response, "message", PyValue::Str("Unknown error".into()))?;
            return Err(PyExc::http(
                500,
                format!("Failed to fetch organizations: {}", message.py_str()),
            ));
        }
        let PyValue::List(data) = get(&response, "data", PyValue::List(Vec::new()))? else {
            tracing::error!("Invalid response format: expected list of organizations");
            return Err(PyExc::http(500, "Invalid response format from Shuffle API"));
        };
        let mut organizations = Vec::new();
        for org in &data {
            match construct_star(
                &ORGANIZATION,
                "app.connectors.shuffle.schema.organizations.Organization",
                org,
            ) {
                Ok(o) => organizations.push(o),
                Err(e) => {
                    tracing::warn!("Failed to parse organization data. Error: {}", e.display())
                }
            }
        }
        let n = organizations.len();
        construct(
            &ORGANIZATIONS_LIST_RESPONSE,
            &kwargs(vec![
                ("success", PyValue::Bool(true)),
                (
                    "message",
                    PyValue::Str(format!("Successfully retrieved {n} organizations")),
                ),
                ("data", PyValue::List(organizations)),
                ("total_count", PyValue::Int(n.to_string())),
            ]),
        )
    };
    run().map_err(|e| match e {
        e @ PyExc::Http(..) => e,
        e => PyExc::http(
            500,
            format!(
                "Unexpected error while fetching organizations: {}",
                e.display()
            ),
        ),
    })
}

/// `get_organization_by_id(org_id, connector_name)`: the
/// `DetailedOrganization` dump.
pub async fn get_organization_by_id(
    client: &ShuffleClient,
    org_id: &str,
    connector: &str,
) -> Result<PyValue, PyExc> {
    tracing::info!("Fetching organization with ID: {org_id}");
    let response = client
        .get(&format!("/api/v1/orgs/{org_id}"), Vec::new(), connector)
        .await;
    let run = || -> Result<PyValue, PyExc> {
        let response = response.clone()?.unwrap_or(PyValue::None);
        if !get(&response, "success", PyValue::Bool(false))?.truthy() {
            let message = get(&response, "message", PyValue::Str("Unknown error".into()))?;
            return Err(PyExc::http(
                500,
                format!(
                    "Failed to fetch organization {org_id}: {}",
                    message.py_str()
                ),
            ));
        }
        let data = get(&response, "data", PyValue::Dict(Vec::new()))?;
        if !data.truthy() {
            return Err(PyExc::http(
                404,
                format!("Organization with ID {org_id} not found"),
            ));
        }
        construct_star(
            &DETAILED_ORGANIZATION,
            "app.connectors.shuffle.schema.organizations.DetailedOrganization",
            &data,
        )
        .map_err(|e| {
            PyExc::http(
                500,
                format!("Failed to parse organization data: {}", e.display()),
            )
        })
    };
    run().map_err(|e| match e {
        e @ PyExc::Http(..) => e,
        e => PyExc::http(
            500,
            format!(
                "Unexpected error while fetching organization {org_id}: {}",
                e.display()
            ),
        ),
    })
}

/// `get_organization_by_name(org_name, connector_name)`: the first
/// organization whose name matches, case folded with `str.lower()`.
pub async fn get_organization_by_name(
    client: &ShuffleClient,
    org_name: &str,
    connector: &str,
) -> Result<PyValue, PyExc> {
    tracing::info!("Fetching organization with name: {org_name}");
    let listing = list_organizations(client, connector).await?;
    let wanted = org_name.to_lowercase();
    if let PyValue::List(orgs) = field(&listing, "data") {
        for org in orgs {
            if field(org, "name").py_str().to_lowercase() == wanted {
                return Ok(org.clone());
            }
        }
    }
    Err(PyExc::http(
        404,
        format!("Organization with name '{org_name}' not found"),
    ))
}
