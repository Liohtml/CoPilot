//! The Grafana routes CoPilot mounts from `app/connectors/grafana/routes/`:
//! `reporting.py` under `/api/reporting` (but `POST /generate-report`: a
//! Playwright browser and the licence check, still Python) and `user.py`
//! under `/api/user` (`/user/organization/add`), all
//! `require_any_scope("admin", "analyst")`. `POST /api/grafana/dashboards`
//! (`dashboards.py`) is not ported: it provisions from the 4.6 MB of
//! dashboard templates under `backend/`, which only the Python image holds.
//! Grafana data is deployment-wide: no route is tenant-scoped, as in Python.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, Loc, Ty};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{body_model, model_response, validation_error};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, WithJson};

use crate::client::GrafanaClient;
use crate::schema::{GRAFANA_GENERATE_IFRAME_LINKS_REQUEST, USER_ORGANIZATION_ADD_REQUEST};
use crate::services;

/// Route state.
#[derive(Debug, Clone)]
pub struct GrafanaState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The Grafana client.
    pub client: GrafanaClient,
}

impl axum::extract::FromRef<GrafanaState> for AppContext {
    fn from_ref(s: &GrafanaState) -> AppContext {
        s.ctx.clone()
    }
}

type Reader = Authorized<AdminOrAnalyst>;

/// The router, with full paths (`/api/reporting/…`, `/api/user/…`).
pub fn router(state: GrafanaState) -> Router {
    Router::new()
        .route("/api/reporting/orgs", get(orgs))
        .route("/api/reporting/dashboards/{org_id}", get(dashboards))
        .route("/api/reporting/dashboard/{dashboard_uid}", get(dashboard))
        .route(
            "/api/reporting/dashboard_panels/{dashboard_uid}",
            get(dashboard_panels),
        )
        .route(
            "/api/reporting/generate_iframe_links",
            post(generate_iframe_links),
        )
        .route(
            "/api/user/user/organization/add",
            post(add_user_organization),
        )
        .with_state(state)
}

fn answer(result: Result<PyValue, PyExc>) -> ApiResult {
    result
        .map(|dump| model_response(&dump))
        .map_err(PyExc::unhandled)
}

/// A path parameter as Starlette matches it: decoded, and never spanning a
/// `/` (an encoded slash makes the path match no route).
fn path_segment(raw: &str) -> Result<&str, ApiError> {
    if raw.contains('/') {
        return Err(ApiError::RouteNotFound);
    }
    Ok(raw)
}

/// `org_id: int` (a path parameter): Python's `int` text.
fn path_int(name: &str, raw: &str) -> Result<String, ApiError> {
    let raw = path_segment(raw)?;
    match model::validate_ty(&Ty::Int, &PyValue::Str(raw.to_string())) {
        Ok(v) => Ok(v.py_str()),
        Err(model::Invalid::Errors(errors)) => Err(validation_error(
            errors
                .into_iter()
                .map(|mut e| {
                    e.loc.insert(0, Loc::Key(name.into()));
                    e
                })
                .collect(),
            "path",
        )),
        Err(model::Invalid::Abort(status, detail)) => Err(PyExc::http(status, detail).unhandled()),
    }
}

async fn orgs(_: Reader, State(st): State<GrafanaState>) -> ApiResult {
    answer(services::orgs(&st.client).await)
}

async fn dashboards(
    _: Reader,
    State(st): State<GrafanaState>,
    Path(org_id): Path<String>,
) -> ApiResult {
    let org_id = path_int("org_id", &org_id)?;
    answer(services::dashboards(&st.client, &org_id).await)
}

async fn dashboard(
    _: Reader,
    State(st): State<GrafanaState>,
    Path(uid): Path<String>,
) -> ApiResult {
    let uid = path_segment(&uid)?;
    answer(services::dashboard_details(&st.client, uid).await)
}

async fn dashboard_panels(
    _: Reader,
    State(st): State<GrafanaState>,
    Path(uid): Path<String>,
) -> ApiResult {
    let uid = path_segment(&uid)?;
    answer(services::dashboard_panels(&st.client, uid).await)
}

async fn generate_iframe_links(
    State(st): State<GrafanaState>,
    WithJson(_, body): WithJson<Reader>,
) -> ApiResult {
    let request = body_model(&body, &GRAFANA_GENERATE_IFRAME_LINKS_REQUEST)?;
    answer(services::iframe_links(&st.ctx.db, &request).await)
}

async fn add_user_organization(
    State(st): State<GrafanaState>,
    WithJson(_, body): WithJson<Reader>,
) -> ApiResult {
    let request = body_model(&body, &USER_ORGANIZATION_ADD_REQUEST)?;
    answer(services::add_user(&st.client, &request).await)
}
