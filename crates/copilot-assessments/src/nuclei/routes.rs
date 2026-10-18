//! `app/integrations/nuclei/routes/nuclei.py`: four admin/analyst routes.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use copilot_uba::params::{StrSpec, b_req_str};
use copilot_upstream::respond::model_response;
use copilot_web::validate::Validator;
use copilot_web::{AdminOrAnalyst, ApiResult, Authorized, WithJson};

use super::services;
use crate::AssessmentsState;

type Reader = Authorized<AdminOrAnalyst>;

const PREFIX: &str = "/api/nuclei";

/// The routes, by full path.
pub fn routes(state: AssessmentsState) -> Router {
    let p = |path: &str| format!("{PREFIX}{path}");
    Router::new()
        .route(&p("/all_reports"), get(all_reports))
        .route(&p("/report/{host}/{report}"), get(report))
        .route(&p("/scan"), post(scan))
        .route(&p("/delete_report/{host}"), delete(delete_report))
        .with_state(state)
}

fn answer(result: copilot_upstream::py::PyResult<copilot_auth::pyvalue::PyValue>) -> ApiResult {
    match result {
        Ok(dump) => Ok(model_response(&dump)),
        Err(e) => Err(e.unhandled()),
    }
}

async fn all_reports(State(s): State<AssessmentsState>, _auth: Reader) -> ApiResult {
    tracing::info!("Collecting Nuclei Reports");
    answer(services::reports_available(&s.nuclei).await)
}

async fn report(
    State(s): State<AssessmentsState>,
    Path((host, report)): Path<(String, String)>,
    _auth: Reader,
) -> ApiResult {
    tracing::info!("Getting Nuclei Report for {host} and {report}");
    answer(services::report(&s.nuclei, &host, &report).await)
}

async fn scan(
    State(s): State<AssessmentsState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let host = body.model(|v: &mut Validator, obj, at| {
        crate::github::schema::text(b_req_str(v, obj, at, "host", StrSpec::ANY))
    })?;
    tracing::info!("Running Nuclei Scan for {host}");
    answer(services::scan(&s.nuclei, &host).await)
}

async fn delete_report(
    State(s): State<AssessmentsState>,
    Path(host): Path<String>,
    _auth: Reader,
) -> ApiResult {
    tracing::info!("Deleting Nuclei Report for {host}");
    answer(services::delete_report(&s.nuclei, &host).await)
}
