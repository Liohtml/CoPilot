//! `/api/customer_provisioning/*` but the three provisioning `POST`s, which
//! reach Python through the router's fallback.
//!
//! Every route is admin/analyst. A route keyed by a customer carries
//! `verify_customer_code_access` (the path's, or for `/decommission` the
//! query's), checked before anything is looked up; the default settings
//! are deployment-wide.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::json::pydantic_json;
use copilot_upstream::py::PyExc;
use copilot_web::body::JsonBody;
use copilot_web::validate::{StrRules, Validator, body_loc, loc};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs, WithJson};
use http::StatusCode;
use serde_json::Value;

use super::decommission::{self, Tools};
use super::{SUBSCRIPTIONS, WAZUH_DASHBOARDS, edr, settings, store};

type Reader = Authorized<AdminOrAnalyst>;

/// The routes, by full path.
pub fn router(tools: Tools) -> Router {
    let p = "/api/customer_provisioning";
    Router::new()
        .route(
            &format!("{p}/default_settings"),
            get(settings_get)
                .post(settings_create)
                .put(settings_update)
                .delete(settings_delete),
        )
        .route(&format!("{p}/provision/dashboards"), get(dashboards))
        .route(&format!("{p}/provision/subscriptions"), get(subscriptions))
        .route(
            &format!("{p}/provision/{{customer_code}}"),
            get(customer_meta),
        )
        .route(
            &format!("{p}/update/office365_org_id/{{customer_code}}"),
            put(office365_org_id),
        )
        .route(
            &format!("{p}/edr_install_commands/{{customer_code}}"),
            get(edr_install_commands),
        )
        .route(&format!("{p}/decommission"), post(decommission_customer))
        .with_state(tools)
}

fn ok(dump: PyValue) -> Response {
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        pydantic_json(&dump),
    )
        .into_response()
}

fn py(e: PyExc) -> ApiError {
    e.unhandled()
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn st(s: impl Into<String>) -> PyValue {
    PyValue::Str(s.into())
}

fn names(items: &[&str]) -> PyValue {
    PyValue::List(items.iter().map(|n| st(*n)).collect())
}

fn meta_missing(code: &str) -> ApiError {
    ApiError::not_found(format!(
        "Customer meta not found for customer: {code}. Please provision the customer first."
    ))
}

async fn settings_get(State(t): State<Tools>, _auth: Reader) -> ApiResult {
    Ok(ok(settings::get(&t.ctx.db).await.map_err(py)?))
}

async fn settings_create(
    State(t): State<Tools>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let fields = settings::read(&body)?;
    Ok(ok(settings::create(&t.ctx.db, fields).await.map_err(py)?))
}

async fn settings_update(
    State(t): State<Tools>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let fields = settings::read(&body)?;
    Ok(ok(settings::update(&t.ctx.db, fields).await.map_err(py)?))
}

async fn settings_delete(State(t): State<Tools>, _auth: Reader) -> ApiResult {
    Ok(ok(settings::delete(&t.ctx.db).await.map_err(py)?))
}

async fn dashboards(_auth: Reader) -> ApiResult {
    Ok(ok(dict(vec![
        ("available_dashboards", names(WAZUH_DASHBOARDS)),
        ("message", st("Dashboards retrieved successfully")),
        ("success", PyValue::Bool(true)),
    ])))
}

async fn subscriptions(_auth: Reader) -> ApiResult {
    Ok(ok(dict(vec![
        ("available_subscriptions", names(SUBSCRIPTIONS)),
        ("message", st("Subscriptions retrieved successfully")),
        ("success", PyValue::Bool(true)),
    ])))
}

async fn customer_meta(
    State(t): State<Tools>,
    auth: Reader,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&t.ctx, &code).await?;
    let meta = store::meta_by_code(&t.ctx.db, &code)
        .await
        .map_err(py)?
        .ok_or_else(|| meta_missing(&code))?;
    Ok(ok(dict(vec![
        ("message", st("Customer meta retrieved successfully")),
        ("success", PyValue::Bool(true)),
        ("customer_meta", meta.dump()),
    ])))
}

async fn office365_org_id(
    State(t): State<Tools>,
    Path(code): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    auth.enforce_customer(&t.ctx, &code).await?;
    let mut v = Validator::new();
    let root = body_loc();
    let org = match &body {
        JsonBody::Missing => {
            v.missing(root);
            String::new()
        }
        JsonBody::NotJson => {
            v.object(&Value::Null, &root);
            String::new()
        }
        JsonBody::Value(value) => match v.object(value, &root) {
            Some(obj) => v.req_str(obj, &root, "office365_org_id", StrRules::default()),
            None => String::new(),
        },
    };
    v.finish()?;
    let meta = store::meta_by_code(&t.ctx.db, &code)
        .await
        .map_err(py)?
        .ok_or_else(|| meta_missing(&code))?;
    store::set_office365_org_id(&t.ctx.db, meta.id, &org)
        .await
        .map_err(py)?;
    Ok(ok(dict(vec![
        (
            "message",
            st("Office 365 organization ID updated successfully"),
        ),
        ("success", PyValue::Bool(true)),
    ])))
}

async fn edr_install_commands(
    State(t): State<Tools>,
    auth: Reader,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&t.ctx, &code).await?;
    let commands = edr::commands(&t.ctx.db, &code).await.map_err(py)?;
    Ok(ok(dict(vec![
        ("message", st("EDR install commands generated successfully")),
        ("success", PyValue::Bool(true)),
        ("customer_code", st(code)),
        ("commands", commands),
    ])))
}

async fn decommission_customer(
    State(t): State<Tools>,
    auth: Reader,
    query: QueryPairs,
) -> ApiResult {
    // `verify_customer_code_access` and `check_customermeta_exists` both
    // take `customer_code` from the query.
    let Some(code) = query.get("customer_code").map(str::to_string) else {
        let mut v = Validator::new();
        v.missing(loc("query", "customer_code"));
        v.missing(loc("query", "customer_code"));
        v.finish()?;
        return Err(ApiError::internal("unreachable"));
    };
    auth.enforce_customer(&t.ctx, &code).await?;
    let meta = store::meta_by_code(&t.ctx.db, &code)
        .await
        .map_err(py)?
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "Customer: {code} not found. Please create the customer first."
            ))
        })?;
    Ok(ok(decommission::decommission(&t, &meta)
        .await
        .map_err(py)?))
}
