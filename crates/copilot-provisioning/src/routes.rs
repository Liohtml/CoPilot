//! The stack-provisioning handlers — port of
//! `app/stack_provisioning/{graylog,influxdb}/routes/` but the three
//! network-connector provisioning routes.
//!
//! Full paths, so that every other path under the two prefixes (the
//! Fortinet / SonicWall / SentinelOne provisioning) reaches Python. Every
//! route is admin/analyst but deleting an InfluxDB check (admin). The body is
//! read first, then the token, then the body is validated — the custom
//! `__init__`s answer before any field ([`crate::schema`]).
//!
//! One deliberate difference: decommissioning a network connector checks the
//! body's `customer_code` against the caller's customers, which Python does
//! not (any analyst could tear down another tenant's connector).

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::pydantic_json;
use copilot_upstream::model::kwargs;
use copilot_upstream::py::PyExc;
use copilot_web::{AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, WithJson};
use http::StatusCode;

use crate::StackState;
use crate::graylog;
use crate::influx;
use crate::schema::{self, CONTENT_PACKS_OVERVIEW, CheckRequest, ContentPackRequest};

type Reader = Authorized<AdminOrAnalyst>;
type Admin = Authorized<AdminOnly>;

/// The routes, by full path.
pub fn router(state: StackState) -> Router {
    Router::new()
        .route(
            "/api/stack_provisioning/graylog/available/content_packs",
            get(available_content_packs),
        )
        .route(
            "/api/stack_provisioning/graylog/provision/content_pack",
            post(provision_content_pack),
        )
        .route(
            "/api/stack_provisioning/influxdb/available/checks",
            get(available_checks),
        )
        .route(
            "/api/stack_provisioning/influxdb/provision/check",
            post(provision_check),
        )
        .route(
            "/api/stack_provisioning/influxdb/provision/checks",
            post(provision_all_checks),
        )
        .route(
            "/api/stack_decommissioning/influxdb/check/{check_name}",
            delete(decommission_check),
        )
        .route(
            "/api/stack_decommissioning/graylog/decommission/network_connector",
            post(decommission_network_connector),
        )
        .with_state(state)
}

fn ok(dump: PyValue) -> Response {
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        pydantic_json(&dump),
    )
        .into_response()
}

fn st(s: impl Into<String>) -> PyValue {
    PyValue::Str(s.into())
}

fn py(e: PyExc) -> ApiError {
    e.unhandled()
}

async fn available_content_packs(_auth: Reader) -> ApiResult {
    let packs = CONTENT_PACKS_OVERVIEW
        .iter()
        .map(|(name, description)| {
            kwargs(vec![("name", st(*name)), ("description", st(*description))])
        })
        .collect();
    Ok(ok(kwargs(vec![
        ("available_content_packs", PyValue::List(packs)),
        ("success", PyValue::Bool(true)),
        (
            "message",
            st("Available content packs retrieved successfully"),
        ),
    ])))
}

async fn provision_content_pack(
    State(s): State<StackState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let req = ContentPackRequest::read(&body)?;
    let name = req.content_pack_name;
    graylog::system_version_check(&s.graylog)
        .await
        .map_err(py)?;
    graylog::does_content_pack_exist(&s.graylog, name)
        .await
        .map_err(py)?;
    graylog::provision_content_pack(&s.graylog, name)
        .await
        .map_err(py)?;
    graylog::check_pipeline_rules(&s.graylog)
        .await
        .map_err(py)?;
    Ok(ok(kwargs(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            st(format!("{name} Content Pack provisioned successfully")),
        ),
    ])))
}

async fn available_checks(State(s): State<StackState>, _auth: Reader) -> ApiResult {
    Ok(ok(influx::available_checks(&s.influx).await.map_err(py)?))
}

async fn provision_check(
    State(s): State<StackState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let req = CheckRequest::read(&body)?;
    Ok(ok(influx::provision_check(
        &s.influx,
        req.check_name,
        req.overwrite,
    )
    .await
    .map_err(py)?))
}

async fn provision_all_checks(
    State(s): State<StackState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let overwrite = schema::read_all_checks(&body)?;
    Ok(ok(influx::provision_all(&s.influx, overwrite)
        .await
        .map_err(py)?))
}

async fn decommission_check(
    State(s): State<StackState>,
    _auth: Admin,
    Path(check_name): Path<String>,
) -> ApiResult {
    if !schema::is_check(&check_name) {
        return Err(ApiError::bad_request(format!(
            "Check {check_name} is not available. Please choose from the available checks."
        )));
    }
    Ok(ok(influx::decommission(&s.influx, &check_name)
        .await
        .map_err(py)?))
}

async fn decommission_network_connector(
    State(s): State<StackState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let req = schema::DecommissionRequest::read(&body)?;
    auth.enforce_customer(&s.ctx, &req.customer_code).await?;
    let meta = graylog::find_meta(&s.ctx.db, &req.customer_code, req.network_connector)
        .await
        .map_err(py)?
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "Network Connector {} not found for customer {}",
                req.network_connector, req.customer_code
            ))
        })?;
    Ok(ok(graylog::decommission_network_connector(
        &s.ctx.db, &s.graylog, &s.grafana, &meta,
    )
    .await
    .map_err(py)?))
}
