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
use copilot_provisioning::rollback::Rollback;
use copilot_upstream::model::{Model, field};
use copilot_upstream::py::{PyExc, type_name};
use copilot_upstream::respond::model_response;
use copilot_web::validate::{FieldError, Validator, loc};
use copilot_web::{AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs};

use crate::ProvisioningState;
use crate::collectors::{self, COLLECTORS, Collector};
use crate::customer::schema::{PROVISION_NEW_CUSTOMER, PROVISION_WORKER_REQUEST};
use crate::customer::{self, Customer};
use crate::integrations::{self, INTEGRATIONS, Integration, PROVISION_MDR_REQUEST};
use crate::network::{self, NETWORKS, Network, Tools};

type Reader = Authorized<AdminOrAnalyst>;
type Admin = Authorized<AdminOnly>;

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
    for integration in INTEGRATIONS {
        let path = format!("/api/{}/provision", integration.route);
        router = router.route(
            &path,
            post(
                move |st: State<ProvisioningState>, body: WithPyJson<Reader>| {
                    provision_integration(st, body, integration)
                },
            ),
        );
    }
    for collector in COLLECTORS {
        let path = format!("/api/{}/provision", collector.route);
        router = router.route(
            &path,
            post(
                move |st: State<ProvisioningState>, body: WithPyJson<Reader>| {
                    provision_collector(st, body, collector)
                },
            ),
        );
    }
    router
        .route("/api/socfortress_mdr/provision", post(provision_mdr))
        .route(
            "/api/customer_provisioning/provision",
            post(provision_customer),
        )
        .route(
            "/api/customer_provisioning/provision/wazuh_worker",
            post(provision_wazuh_worker),
        )
        .route(
            "/api/portainer/create-wazuh-customer-stack",
            post(create_wazuh_customer_stack),
        )
        .with_state(state)
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

async fn provision_integration(
    State(st): State<ProvisioningState>,
    WithPyJson(auth, body): WithPyJson<Reader>,
    integration: &'static Integration,
) -> ApiResult {
    let request = read_forced(
        &body,
        integration.request,
        "integration_name",
        integration.request_name,
    )?;
    let code = field(&request, "customer_code").py_str();
    auth.enforce_customer(&st.ctx, &code).await?;
    integrations::integrations_of(&st.ctx, &code)
        .await
        .map_err(PyExc::unhandled)?;
    // What the run creates is undone when it — or the jobs' hand-off — fails
    // (the jobs Python registered before a failure stay registered).
    let mut rollback = Rollback::default();
    let outcome: Result<(), ApiError> = async {
        integrations::provision(&st.ctx, tools(&st), integration, &code, &mut rollback).await?;
        integrations::hand_jobs(
            st.legacy.as_ref(),
            &auth.user,
            integrations::jobs(integration, &request),
        )
        .await
        .map_err(PyExc::unhandled)
    }
    .await;
    if outcome.is_err() {
        rollback.run(tools(&st).undo()).await;
    }
    outcome?;
    Ok(model_response(&copilot_upstream::model::kwargs(vec![
        ("success", PyValue::Bool(true)),
        ("message", PyValue::Str(integration.message.into())),
    ])))
}

async fn provision_collector(
    State(st): State<ProvisioningState>,
    WithPyJson(auth, body): WithPyJson<Reader>,
    collector: &'static Collector,
) -> ApiResult {
    let request = read_forced(
        &body,
        collector.request,
        "integration_name",
        collector.service,
    )?;
    auth.enforce_customer(&st.ctx, &field(&request, "customer_code").py_str())
        .await?;
    collectors::provision(&st.ctx, tools(&st), &st.env, collector, &request)
        .await
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

/// The customer provisioning's tools.
fn customer_of(st: &ProvisioningState) -> Customer<'_> {
    Customer {
        ctx: &st.ctx,
        tools: tools(st),
        portainer: &st.portainer,
        http: &st.worker_http,
        env: &st.env,
    }
}

/// `POST /api/customer_provisioning/provision`: the body read, the token,
/// then `check_customer_exists`' query (a missing one is reported with the
/// body's errors, as FastAPI collects them), the query's customer checked
/// against the caller (§4) and looked up (404), the body validated, its
/// customer checked against the caller (§4).
async fn provision_customer(
    State(st): State<ProvisioningState>,
    query: QueryPairs,
    WithPyJson(auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let Some(code) = query.get("customer_code").map(str::to_string) else {
        let mut v = Validator::new();
        v.missing(loc("query", "customer_code"));
        let mut items: Vec<_> = v.errors().iter().map(FieldError::to_item).collect();
        if let Err(ApiError::Validation(more)) = body.model(&PROVISION_NEW_CUSTOMER) {
            items.extend(more);
        }
        return Err(ApiError::Validation(items));
    };
    auth.enforce_customer(&st.ctx, &code).await?;
    customer::check_customer_exists(&st.ctx.db, &code)
        .await
        .map_err(PyExc::unhandled)?;
    let request = body.model(&PROVISION_NEW_CUSTOMER)?;
    auth.enforce_customer(&st.ctx, &field(&request, "customer_code").py_str())
        .await?;
    customer::provision(customer_of(&st), &request)
        .await
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

/// `POST /api/customer_provisioning/provision/wazuh_worker`; the body's
/// customer checked against the caller (§4).
async fn provision_wazuh_worker(
    State(st): State<ProvisioningState>,
    WithPyJson(auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let request = body.model(&PROVISION_WORKER_REQUEST)?;
    auth.enforce_customer(&st.ctx, &field(&request, "customer_code").py_str())
        .await?;
    customer::provision_wazuh_worker(customer_of(&st), request)
        .await
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

/// `POST /api/portainer/create-wazuh-customer-stack` (admin only, so
/// deployment-wide).
async fn create_wazuh_customer_stack(
    State(st): State<ProvisioningState>,
    WithPyJson(_auth, body): WithPyJson<Admin>,
) -> ApiResult {
    let request = body.model(&PROVISION_NEW_CUSTOMER)?;
    customer::create_wazuh_customer_stack(customer_of(&st), &request)
        .await
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

async fn provision_mdr(
    State(st): State<ProvisioningState>,
    WithPyJson(auth, body): WithPyJson<Reader>,
) -> ApiResult {
    let request = body.model(&PROVISION_MDR_REQUEST)?;
    auth.enforce_customer(&st.ctx, &field(&request, "customer_code").py_str())
        .await?;
    integrations::provision_mdr(&st.ctx, &request)
        .await
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}
