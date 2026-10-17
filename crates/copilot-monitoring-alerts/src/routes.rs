//! `/api/monitoring_alert/*` — port of
//! `app/integrations/monitoring_alert/routes/provision.py`: four routes, all
//! `require_any_scope("admin", "analyst")`, checked in FastAPI's order (the
//! body decoded first, then the token, then the body validated).
//!
//! Graylog event definitions are deployment-wide configuration, so no route
//! is tenant-scoped, as in Python: a custom alert's `custom_fields` (its
//! `CUSTOMER_CODE` included) are validated and then not used, and the test
//! event is always filed under the fixed customer `00002`.

use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::{get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::field;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::model_response;
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized};

use crate::MonitoringAlertState;
use crate::body::WithPyJson;
use crate::catalog::{self, ALERTS};
use crate::schema::{CUSTOM_REQUEST, PROVISION_REQUEST};
use crate::services;

type Reader = Authorized<AdminOrAnalyst>;

/// The router, nested at `/api/monitoring_alert`.
pub fn router(state: MonitoringAlertState) -> Router {
    Router::new()
        .route("/available", get(available))
        .route("/provision", post(provision))
        .route("/provision/custom", post(provision_custom))
        .route("/provision/testing", post(provision_testing))
        .with_state(state)
}

fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

/// `ProvisionWazuhMonitoringAlertResponse(success=True, message=…)`.
fn provisioned(message: String) -> Response {
    model_response(&PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(true)),
        ("message".into(), s(message)),
    ]))
}

/// The `available_monitoring_alerts` of `GET /available`: each member's name
/// with spaces for underscores, and its description.
pub fn available_alerts() -> PyValue {
    PyValue::List(
        ALERTS
            .iter()
            .map(|a| {
                PyValue::Dict(vec![
                    ("name".into(), s(a.name.replace('_', " "))),
                    ("value".into(), s(a.summary)),
                ])
            })
            .collect(),
    )
}

/// `GET /available`.
async fn available(_: Reader) -> Response {
    model_response(&PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(true)),
        ("message".into(), s("Alerts retrieved successfully")),
        ("available_monitoring_alerts".into(), available_alerts()),
    ]))
}

/// `POST /provision`.
async fn provision(
    State(st): State<MonitoringAlertState>,
    WithPyJson(_auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let request = body.model(&PROVISION_REQUEST)?;
    let name = field(&request, "alert_name").py_str();
    let alert = catalog::find(&name);
    let connector = services::connector_for_alert(
        alert,
        field(&request, "graylog_instance")
            .as_str()
            .unwrap_or("default"),
    );
    services::check_if_event_definition_exists(&st.graylog, connector, &name.replace('_', " "))
        .await
        .map_err(PyExc::unhandled)?;
    let Some(alert) = alert else {
        return Err(ApiError::bad_request(format!(
            "No provision function found for alert name {name}"
        )));
    };
    services::provision(&st.graylog, &st.waf, connector, alert, &request).await?;
    Ok(provisioned(format!(
        "Monitoring alert {name} provisioned successfully."
    )))
}

/// `POST /provision/custom`.
async fn provision_custom(
    State(st): State<MonitoringAlertState>,
    WithPyJson(_auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let request = body.model(&CUSTOM_REQUEST)?;
    let name = field(&request, "alert_name").py_str();
    // Not pinned: the instance asked for, whatever the name.
    let connector = services::connector_for_instance(
        field(&request, "graylog_instance")
            .as_str()
            .unwrap_or("default"),
    );
    services::check_if_event_definition_exists(&st.graylog, connector, &name.replace('_', " "))
        .await
        .map_err(PyExc::unhandled)?;
    let entity = services::custom_entity(&request).map_err(PyExc::unhandled)?;
    services::provision_alert_definition(&st.graylog, connector, entity)
        .await
        .map_err(PyExc::unhandled)?;
    Ok(provisioned(format!(
        "Monitoring alert {name} provisioned successfully."
    )))
}

/// `POST /provision/testing`.
async fn provision_testing(
    State(st): State<MonitoringAlertState>,
    WithPyJson(_auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let request = body.dict()?;
    let message = services::testing_message(&request).map_err(PyExc::unhandled)?;
    services::ship(&st.ctx.connectors, &message)
        .await
        .map_err(PyExc::unhandled)?;
    Ok(provisioned(
        "Event sent to log shipper successfully.".to_string(),
    ))
}
