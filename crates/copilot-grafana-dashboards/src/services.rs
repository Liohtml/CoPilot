//! `provision_dashboards` and `update_dashboard`
//! (`app/connectors/grafana/services/dashboards.py`), line by line.
//!
//! Each dashboard of the request, in order, is loaded and edited
//! ([`crate::edit`]), then uploaded by `update_dashboard`, which builds a
//! fresh client (the connector row read again), switches the service user's
//! organization and `POST`s `/dashboards/db` with
//! `{"dashboard": …, "folderId": …, "overwrite": true}`. Any exception there
//! becomes `HTTPException(500, "Error updating dashboard: {e}")`, which
//! `provision_dashboards` catches and raises again as
//! `HTTPException(500, f"Error updating dashboard: {e}")` — so the detail
//! reads `Error updating dashboard: 500: Error updating dashboard: …` and the
//! dashboards before it stay uploaded. Grafana's answer is
//! `GrafanaDashboard(**answer)` outside that `except`: a `ValidationError` is
//! the `ValueError` handler's 400, a non-mapping the `TypeError`'s bare 500.

use copilot_auth::pyvalue::PyValue;
use copilot_grafana::GrafanaClient;
use copilot_grafana::client::CONNECTOR;
use copilot_upstream::model::{construct, construct_star, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult};

use crate::edit::load_dashboard_json;
use crate::schema::{GRAFANA_DASHBOARD, GRAFANA_DASHBOARD_QUALNAME, GRAFANA_DASHBOARD_RESPONSE};
use crate::templates;

fn text(dump: &PyValue, key: &str) -> String {
    field(dump, key).py_str()
}

/// `update_dashboard(dashboard_json, organization_id, folder_id)`: Grafana's
/// answer, or the `HTTPException(500)` everything inside becomes.
pub async fn update_dashboard(
    grafana: &GrafanaClient,
    dashboard: PyValue,
    organization_id: &str,
    folder_id: &PyValue,
) -> PyResult<PyValue> {
    let result = async {
        let api = grafana.create(CONNECTOR).await?;
        grafana.switch_organization(&api, organization_id).await?;
        let payload = kwargs(vec![
            ("dashboard", dashboard),
            ("folderId", folder_id.clone()),
            ("overwrite", PyValue::Bool(true)),
        ]);
        grafana.update_dashboard(&api, payload).await
    }
    .await;
    result.map_err(|e| PyExc::http(500, format!("Error updating dashboard: {}", e.display())))
}

/// `provision_dashboards(DashboardProvisionRequest)`: `request` is the
/// request model's dump; the answer is `GrafanaDashboardResponse`'s.
pub async fn provision_dashboards(grafana: &GrafanaClient, request: &PyValue) -> PyResult<PyValue> {
    let names: Vec<String> = match field(request, "dashboards") {
        PyValue::List(items) => items.iter().map(PyValue::py_str).collect(),
        _ => Vec::new(),
    };
    let organization_id = text(request, "organizationId");
    let folder_id = field(request, "folderId").clone();
    let uid = text(request, "datasourceUid");
    let url = text(request, "grafana_url");
    let mut provisioned = Vec::with_capacity(names.len());
    for name in &names {
        // `valid_dashboards[dashboard_name]`: the request model only lets
        // known names through.
        let dashboard = templates::find(name).ok_or_else(|| PyExc::key_error(name))?;
        let uploaded = async {
            let json = load_dashboard_json(&dashboard, &uid, &url)?;
            update_dashboard(grafana, json, &organization_id, &folder_id).await
        }
        .await;
        let answer = match uploaded {
            Ok(answer) => answer,
            Err(e @ PyExc::Http(..)) => {
                return Err(PyExc::http(
                    500,
                    format!("Error updating dashboard: {}", e.display()),
                ));
            }
            Err(other) => return Err(other),
        };
        provisioned.push(construct_star(
            &GRAFANA_DASHBOARD,
            GRAFANA_DASHBOARD_QUALNAME,
            &answer,
        )?);
    }
    construct(
        &GRAFANA_DASHBOARD_RESPONSE,
        &kwargs(vec![
            ("provisioned_dashboards", PyValue::List(provisioned)),
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("All dashboards provisioned successfully".into()),
            ),
        ]),
    )
}

/// The customers whose `customersmeta` row names Grafana organization `org`
/// (`customer_meta_grafana_org_id`, a string column, compared as text).
pub async fn organization_owners(
    db: &copilot_db::Db,
    org: &str,
) -> Result<Vec<String>, copilot_db::DbError> {
    // The value comes from the request: never a cached prepared statement.
    let owners = sqlx::query_scalar::<_, String>(
        "SELECT customer_code FROM customersmeta WHERE customer_meta_grafana_org_id = ?",
    )
    .persistent(false)
    .bind(org)
    .fetch_all(db.pool())
    .await?;
    Ok(owners)
}
