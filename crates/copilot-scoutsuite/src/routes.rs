//! `/api/scoutsuite` — port of `routes/scoutsuite.py`: six routes, every one
//! `require_any_scope("admin", "analyst")`.

use axum::Router;
use axum::extract::{OriginalUri, State};
use axum::routing::{delete, get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_objectstore::web::{UploadForm, segment_from_end};
use copilot_upstream::model::Model;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::validate::Validator;
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, Authorized, JsonBody, QueryPairs, WithJson,
};

use crate::ScoutState;
use crate::schema::{
    AWS_REQUEST, AZURE_REQUEST, available_response, options_response, report_response, started,
};
use crate::services::{self, GCP_KEY_PREFIX};

type Reader = Authorized<AdminOrAnalyst>;

/// The six routes (full paths), behind the encoded-slash hand-off.
pub fn router(state: ScoutState) -> Router {
    let p = |s: &str| format!("/api/scoutsuite{s}");
    Router::new()
        .route(&p("/report-generation-options"), get(options))
        .route(&p("/available-reports"), get(available_reports))
        .route(&p("/generate-aws-report"), post(generate_aws_report))
        .route(&p("/generate-azure-report"), post(generate_azure_report))
        .route(&p("/generate-gcp-report"), post(generate_gcp_report))
        .route(&p("/delete-report/{report_name}"), delete(delete_report))
        .with_state(state)
}

async fn options(_: Reader) -> ApiResult {
    Ok(model_response(&options_response()))
}

async fn available_reports(_: Reader, State(st): State<ScoutState>) -> ApiResult {
    let reports = services::available_reports(&st).map_err(PyExc::unhandled)?;
    Ok(model_response(&available_response(reports)))
}

/// The request model, then its `model_validator(mode="after")`: a valid
/// request of another `report_type` is the 400 `Invalid report type.`.
fn request(body: &JsonBody, model: &'static Model, report_type: &str) -> Result<PyValue, ApiError> {
    let request = body_model(body, model)?;
    if request.get("report_type").and_then(PyValue::as_str) != Some(report_type) {
        return Err(PyExc::http(400, "Invalid report type.").unhandled());
    }
    Ok(request)
}

async fn generate_aws_report(
    State(st): State<ScoutState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let request = request(&body, &AWS_REQUEST, "aws")?;
    services::spawn_scan(&st, "AWS", services::aws_command(&request), None);
    Ok(model_response(&started("AWS")))
}

async fn generate_azure_report(
    State(st): State<ScoutState>,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let request = request(&body, &AZURE_REQUEST, "azure")?;
    services::spawn_scan(&st, "Azure", services::azure_command(&request), None);
    Ok(model_response(&started("Azure")))
}

async fn generate_gcp_report(
    State(st): State<ScoutState>,
    q: QueryPairs,
    form: UploadForm<Reader>,
) -> ApiResult {
    let mut v = Validator::new();
    let file = form.file(&mut v, "file");
    v.finish()?;
    let Some(file) = file else {
        return Err(ApiError::internal("validated form fields missing"));
    };
    let report_name = q.get("report_name").unwrap_or("gcp-report").to_string();
    services::check_upload(&file.data).map_err(PyExc::unhandled)?;
    // A private directory of its own, never the served `scoutsuite-report`
    // (GHSA-pm2w-mmc3-h8hc), under a fixed name (GHSA-q3g8-3cf7-744f).
    let directory = services::mkdtemp(GCP_KEY_PREFIX)
        .map_err(|e| ApiError::internal(format!("mkdtemp: {e}")))?;
    let path = match services::save_credentials(&file.data, &directory) {
        Ok(path) => path,
        Err(e) => {
            // Python leaves the directory behind; no part of a key stays
            // here (§4).
            let _ = std::fs::remove_dir_all(&directory);
            return Err(e.unhandled());
        }
    };
    tracing::info!("GCP credentials written to private temp path for scan");
    let file_path = path.to_string_lossy().into_owned();
    tracing::info!("Request: report_name={report_name:?} file_path={file_path:?}");
    let cred_dir = path.parent().map(std::path::Path::to_path_buf);
    services::spawn_scan(
        &st,
        "GCP",
        services::gcp_command(&report_name, &file_path),
        cred_dir,
    );
    Ok(model_response(&started("GCP")))
}

async fn delete_report(
    _: Reader,
    State(st): State<ScoutState>,
    OriginalUri(uri): OriginalUri,
) -> ApiResult {
    let report_name = segment_from_end(&uri, 0);
    services::delete_report(&st, &report_name).map_err(PyExc::unhandled)?;
    Ok(model_response(&report_response(format!(
        "Report {report_name} and associated files deleted successfully"
    ))))
}
