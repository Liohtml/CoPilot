//! The handlers, by full path, all `require_any_scope("admin", "analyst")`.
//!
//! The request models set their `integration_name` in a
//! `model_validator(mode="before")` that assigns into the input: a JSON
//! object gets the key (whatever it held), anything else — a list, a string,
//! a number, a body sent without a JSON content type — raises `TypeError`
//! before any field is validated (uvicorn's bare 500); no body (or `null`)
//! is the 422 `Field required`. FastAPI's order is kept: the body decoded,
//! the token, the body validated, then the handler — whose first step here is
//! the tenant check (a deliberate difference, see [`crate::network`]).

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use copilot_auth::pyvalue::PyValue;
use copilot_monitoring_alerts::body::{PyBody, WithPyJson};
use copilot_upstream::model::{Model, field};
use copilot_upstream::py::{PyExc, type_name};
use copilot_upstream::respond::model_response;
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized};

use crate::ProvisioningState;
use crate::network::{self, NETWORKS, Network, Tools};

type Reader = Authorized<AdminOrAnalyst>;

/// The routes.
pub fn router(state: ProvisioningState) -> Router {
    let mut router = Router::new();
    for network in NETWORKS {
        let path = format!(
            "/api/stack_provisioning/graylog/provision/{}",
            network.route
        );
        router = router.route(
            &path,
            post(
                move |st: State<ProvisioningState>, body: WithPyJson<Reader>| {
                    provision_network(st, body, network)
                },
            ),
        );
    }
    router.with_state(state)
}

/// The body validated as `model` after `values[key] = value`.
pub fn read_forced(
    body: &PyBody,
    model: &'static Model,
    key: &str,
    value: &str,
) -> Result<PyValue, ApiError> {
    let assignment_error = |what: &str| {
        PyExc::TypeError(format!("'{what}' object does not support item assignment")).unhandled()
    };
    match body {
        PyBody::Missing => body.model(model),
        PyBody::NotJson => Err(assignment_error("bytes")),
        PyBody::Value(PyValue::Dict(items)) => {
            let mut items = items.clone();
            match items.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = PyValue::Str(value.into()),
                None => items.push((key.into(), PyValue::Str(value.into()))),
            }
            PyBody::Value(PyValue::Dict(items)).model(model)
        }
        PyBody::Value(PyValue::List(_)) => Err(PyExc::TypeError(
            "list indices must be integers or slices, not str".into(),
        )
        .unhandled()),
        PyBody::Value(other) => Err(assignment_error(type_name(other))),
    }
}

/// The tools of the state.
pub fn tools(st: &ProvisioningState) -> Tools<'_> {
    Tools {
        db: &st.ctx.db,
        graylog: &st.graylog,
        grafana: &st.grafana,
        wazuh: &st.wazuh,
    }
}

async fn provision_network(
    State(st): State<ProvisioningState>,
    WithPyJson(auth, body): WithPyJson<Reader>,
    network: &'static Network,
) -> ApiResult {
    let request = read_forced(&body, network.request, "integration_name", network.service)?;
    auth.enforce_customer(&st.ctx, &field(&request, "customer_code").py_str())
        .await?;
    network::provision(tools(&st), network, &request)
        .await
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}
