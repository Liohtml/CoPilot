//! `app/connectors/shuffle/routes/organizations.py` (admin/analyst; the
//! connector named by `?connector_name=`, `Shuffle` by default).

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::model_response;
use copilot_web::validate::{StrRules, Validator};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs};

use crate::ShuffleState;
use crate::organizations::schema::{DETAILED_ORGANIZATION_RESPONSE, ORGANIZATION_RESPONSE};
use crate::organizations::services;

type Soc = Authorized<AdminOrAnalyst>;

/// The routes, by full path.
pub fn router(state: ShuffleState) -> Router {
    Router::new()
        .route("/api/shuffle/organizations/organizations", get(list))
        .route(
            "/api/shuffle/organizations/organizations/{org_id}",
            get(by_id),
        )
        .route(
            "/api/shuffle/organizations/organizations/name/{org_name}",
            get(by_name),
        )
        .with_state(state)
}

/// `connector_name: str = Query("Shuffle")`.
fn connector_name(q: &QueryPairs) -> Result<String, ApiError> {
    let mut v = Validator::new();
    let name = q.opt_str(&mut v, "connector_name", StrRules::any());
    v.finish()?;
    Ok(name.unwrap_or_else(|| "Shuffle".into()))
}

/// The route's `except HTTPException: raise` / `except Exception` → 500.
fn route_error(e: PyExc) -> ApiError {
    match e {
        e @ PyExc::Http(..) => e.into(),
        e => ApiError::server_error(format!("Internal server error: {}", e.display())),
    }
}

async fn list(auth: Soc, State(st): State<ShuffleState>, q: QueryPairs) -> ApiResult {
    let _ = &auth;
    let connector = connector_name(&q)?;
    tracing::info!("Request to list all organizations using connector: {connector}");
    let dump = services::list_organizations(&st.client, &connector)
        .await
        .map_err(route_error)?;
    Ok(model_response(&dump))
}

async fn by_id(
    auth: Soc,
    State(st): State<ShuffleState>,
    Path(org_id): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let _ = &auth;
    let connector = connector_name(&q)?;
    let org = services::get_organization_by_id(&st.client, &org_id, &connector)
        .await
        .map_err(route_error)?;
    let message = format!(
        "Successfully retrieved organization: {}",
        field(&org, "name").py_str()
    );
    let dump = construct(
        &DETAILED_ORGANIZATION_RESPONSE,
        &kwargs(vec![
            ("success", PyValue::Bool(true)),
            ("message", PyValue::Str(message)),
            ("data", org),
        ]),
    )
    .map_err(route_error)?;
    Ok(model_response(&dump))
}

async fn by_name(
    auth: Soc,
    State(st): State<ShuffleState>,
    Path(org_name): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let _ = &auth;
    let connector = connector_name(&q)?;
    let org = services::get_organization_by_name(&st.client, &org_name, &connector)
        .await
        .map_err(route_error)?;
    let message = format!(
        "Successfully retrieved organization: {}",
        field(&org, "name").py_str()
    );
    let dump = construct(
        &ORGANIZATION_RESPONSE,
        &kwargs(vec![
            ("success", PyValue::Bool(true)),
            ("message", PyValue::Str(message)),
            ("data", org),
        ]),
    )
    .map_err(route_error)?;
    Ok(model_response(&dump))
}
