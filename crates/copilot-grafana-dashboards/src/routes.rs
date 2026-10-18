//! The two dashboard provisioning routes, both
//! `require_any_scope("admin", "analyst")`:
//!
//! - `POST /api/grafana/dashboards` (`connectors/grafana/routes/dashboards.py`):
//!   `DashboardProvisionRequest` → `GrafanaDashboardResponse`;
//! - `POST /api/customer_provisioning/provision/dashboards`
//!   (`customer_provisioning/routes/provision.py`): `ProvisionDashboardRequest`
//!   → a `DashboardProvisionRequest` built from its top-level organization,
//!   folder, datasource and URL (the nested request's own are ignored, as in
//!   Python) → `ProvisionDashboardResponse`.
//!
//! The body names a Grafana organization and folder, not a customer
//! (`customer_name` is validated and unused). Python let any analyst write
//! dashboards into any tenant's organization; here a caller without
//! deployment-wide access must hold a customer whose `customersmeta` row
//! names that organization (`customer_meta_grafana_org_id`), checked after
//! the body is validated and before Grafana is asked — fail closed: an
//! organization no row names is a 403 (`Access denied to Grafana
//! organization {id}`; RUST_MIGRATION.md §4). Admins stay deployment-wide.

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use copilot_auth::AccessDenied;
use copilot_auth::pyvalue::PyValue;
use copilot_grafana::GrafanaClient;
use copilot_monitoring_alerts::body::WithPyJson;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::model_response;
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, CurrentUser};

use crate::schema::{
    DASHBOARD_PROVISION_REQUEST, PROVISION_DASHBOARD_REQUEST, PROVISION_DASHBOARD_RESPONSE,
};
use crate::services;

/// Route state.
#[derive(Debug, Clone)]
pub struct DashboardsState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Grafana client.
    pub grafana: GrafanaClient,
}

impl axum::extract::FromRef<DashboardsState> for AppContext {
    fn from_ref(s: &DashboardsState) -> AppContext {
        s.ctx.clone()
    }
}

type Reader = Authorized<AdminOrAnalyst>;

/// The router, with full paths.
pub fn router(state: DashboardsState) -> Router {
    Router::new()
        .route("/api/grafana/dashboards", post(provision))
        .route(
            "/api/customer_provisioning/provision/dashboards",
            post(customer_provision),
        )
        .with_state(state)
}

fn answer(result: Result<PyValue, PyExc>) -> ApiResult {
    result
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

/// A scoped caller must hold a customer whose meta row names `org`.
async fn ensure_organization(
    st: &DashboardsState,
    user: &CurrentUser,
    org: &PyValue,
) -> Result<(), ApiError> {
    let access = user.access(&st.ctx).await?;
    if access.is_all() {
        return Ok(());
    }
    let org = org.py_str();
    let owners = services::organization_owners(&st.ctx.db, &org).await?;
    if owners.iter().any(|code| access.can_access(code)) {
        Ok(())
    } else {
        Err(AccessDenied(format!("Grafana organization {org}")).into())
    }
}

async fn provision(
    State(st): State<DashboardsState>,
    WithPyJson(auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let request = body.model(&DASHBOARD_PROVISION_REQUEST)?;
    ensure_organization(&st, &auth, field(&request, "organizationId")).await?;
    answer(services::provision_dashboards(&st.grafana, &request).await)
}

async fn customer_provision(
    State(st): State<DashboardsState>,
    WithPyJson(auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let request = body.model(&PROVISION_DASHBOARD_REQUEST)?;
    ensure_organization(&st, &auth, field(&request, "grafana_org_id")).await?;
    let result = async {
        let included = field(&request, "dashboards_to_include");
        let inner = construct(
            &DASHBOARD_PROVISION_REQUEST,
            &kwargs(vec![
                ("dashboards", field(included, "dashboards").clone()),
                ("organizationId", field(&request, "grafana_org_id").clone()),
                ("folderId", field(&request, "grafana_folder_id").clone()),
                (
                    "datasourceUid",
                    field(&request, "grafana_datasource_uid").clone(),
                ),
                ("grafana_url", field(&request, "grafana_url").clone()),
            ]),
        )?;
        let provisioned = services::provision_dashboards(&st.grafana, &inner).await?;
        construct(&PROVISION_DASHBOARD_RESPONSE, &provisioned)
    }
    .await;
    answer(result)
}
