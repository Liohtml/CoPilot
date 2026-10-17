//! The Pydantic models of `app/connectors/grafana/schema/dashboards.py` and
//! the dashboard request of `app/customer_provisioning/schema/provision.py`
//! as [`copilot_upstream::model`] statics, pinned by
//! `grafana_dashboard_vectors.json`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Check, Field, Model, Ty};

use crate::templates;

fn zero() -> PyValue {
    PyValue::Int("0".into())
}

fn default_uid() -> PyValue {
    PyValue::Str("uid-to-be-replaced".into())
}

fn default_url() -> PyValue {
    PyValue::Str(crate::edit::GRAFANA_URL_PLACEHOLDER.into())
}

/// `check_dashboards_exist`: every identifier must name a member of
/// `valid_dashboards`.
fn check_dashboards_exist(value: &PyValue) -> Result<PyValue, Check> {
    if let PyValue::List(items) = value {
        for item in items {
            let name = item.py_str();
            if templates::find(&name).is_none() {
                return Err(Check::ValueError(format!(
                    "Dashboard identifier \"{name}\" is not recognized."
                )));
            }
        }
    }
    Ok(value.clone())
}

/// `DashboardProvisionRequest`.
pub static DASHBOARD_PROVISION_REQUEST: Model = Model::new(
    "DashboardProvisionRequest",
    &[
        Field::req("dashboards", Ty::List(&Ty::Str)).after(check_dashboards_exist),
        Field::def("organizationId", Ty::Int, zero),
        Field::def("folderId", Ty::Int, zero),
        Field::def("datasourceUid", Ty::Str, default_uid),
        Field::def("grafana_url", Ty::Str, default_url),
    ],
);

/// `GrafanaDashboard` (Grafana's answer to `POST /dashboards/db`).
pub static GRAFANA_DASHBOARD: Model = Model::new(
    "GrafanaDashboard",
    &[
        Field::req("id", Ty::Int),
        Field::req("slug", Ty::Str),
        Field::req("status", Ty::Str),
        Field::req("uid", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("version", Ty::Int),
    ],
);

/// `GrafanaDashboardResponse`.
pub static GRAFANA_DASHBOARD_RESPONSE: Model = Model::new(
    "GrafanaDashboardResponse",
    &[
        Field::req(
            "provisioned_dashboards",
            Ty::List(&Ty::Model(&GRAFANA_DASHBOARD)),
        ),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `ProvisionDashboardRequest` (`POST /customer_provisioning/provision/dashboards`).
pub static PROVISION_DASHBOARD_REQUEST: Model = Model::new(
    "ProvisionDashboardRequest",
    &[
        Field::req("customer_name", Ty::Str),
        Field::req(
            "dashboards_to_include",
            Ty::Model(&DASHBOARD_PROVISION_REQUEST),
        ),
        Field::req("grafana_org_id", Ty::Int),
        Field::req("grafana_datasource_uid", Ty::Str),
        Field::req("grafana_folder_id", Ty::Int),
        Field::req("grafana_url", Ty::Str),
    ],
);

/// `ProvisionDashboardResponse` (that route's `response_model`).
pub static PROVISION_DASHBOARD_RESPONSE: Model = Model::new(
    "ProvisionDashboardResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// The qualified name `GrafanaDashboard(**answer)`'s `TypeError` prints.
pub const GRAFANA_DASHBOARD_QUALNAME: &str =
    "app.connectors.grafana.schema.dashboards.GrafanaDashboard";
