//! `/api/threat_intel` — port of `app/threat_intel/routes/{epss,socfortress}.py`.
//!
//! Check order is FastAPI's: the body is read first (malformed JSON, or a
//! form that does not parse, fails before the token), then the token and
//! its scope (`require_any_scope("admin", "analyst")`), then the route's
//! dependency (`ensure_virustotal_connector` of the file routes), the body
//! validation, and the handler.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Local;
use copilot_auth::AccessScope;
use copilot_auth::pyvalue::PyValue;
use copilot_incidents::requests::PyDateTime;
use copilot_incidents::writes::{CommentKind, create_comment};
use copilot_ingest::schema::CreateAlertRequestRoute;
use copilot_objectstore::web::UploadForm;
use copilot_upstream::json::pydantic_json;
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::PyExc;
use copilot_web::form::FormValue;
use copilot_web::validate::{IntRules, Validator, loc};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, WithJson};
use http::StatusCode;

use crate::ThreatIntelState;
use crate::license;
use crate::schema::{
    EpssRequest, IntelRequest, ProcessNameRequest, VT_ROUTE_RESPONSE, VirusTotalRequest,
};
use crate::services::ai::{self, Kind};
use crate::services::virustotal::{self, Upload};
use crate::services::{epss, mcp, socfortress};

type Soc = Authorized<AdminOrAnalyst>;

/// The 11 routes, behind the encoded-slash hand-off to Python.
pub fn router(state: ThreatIntelState) -> Router {
    let p = |s: &str| format!("/api/threat_intel{s}");
    Router::new()
        .route(&p("/epss"), post(epss_route))
        .route(&p("/socfortress"), post(socfortress_route))
        .route(&p("/process_name"), post(process_name))
        .route(&p("/virustotal"), post(virustotal_route))
        // `GET /virustotal/file/{file_id}` also answers for the ids
        // `submit` and `analyze` (Starlette matches by method and path).
        .route(
            &p("/virustotal/file/submit"),
            post(submit).get(|st, auth| report_of(st, auth, "submit")),
        )
        .route(
            &p("/virustotal/file/analyze"),
            post(analyze).get(|st, auth| report_of(st, auth, "analyze")),
        )
        .route(&p("/virustotal/file/{file_id}"), get(report))
        .route(&p("/virustotal/analysis/{analysis_id}"), get(analysis))
        .route(&p("/ai/analyze-alert"), post(ai_analyze))
        .route(&p("/ai/wazuh-exclusion-rule"), post(ai_exclusion))
        .route(
            &p("/ai/velociraptor-artifact-recommendation"),
            post(ai_velociraptor),
        )
        .with_state(state)
}

/// A `response_model` answer.
fn ok(dump: PyValue) -> Response {
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        pydantic_json(&dump),
    )
        .into_response()
}

fn fail(e: PyExc) -> ApiError {
    e.unhandled()
}

// --- EPSS and SOCFortress threat intel --------------------------------------------------

async fn epss_route(
    State(st): State<ThreatIntelState>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(EpssRequest::read)?;
    tracing::info!("Received request for EPSS score: cve={}", req.cve);
    let dump = epss::collect_epss_score(&st, &req.cve)
        .await
        .map_err(fail)?;
    Ok(ok(dump))
}

async fn socfortress_route(
    State(st): State<ThreatIntelState>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(IntelRequest::read)?;
    license::is_feature_enabled(&st, "THREAT INTEL")
        .await
        .map_err(fail)?;
    tracing::info!("Running SOCFortress Threat Intel. Grabbing License");
    let key = license::license_key(&st).await.map_err(fail)?;
    let dump = socfortress::lookup(&st, &key, &req.ioc_value, req.customer_code.as_deref())
        .await
        .map_err(fail)?;
    Ok(ok(dump))
}

async fn process_name(
    State(st): State<ThreatIntelState>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(ProcessNameRequest::read)?;
    if let Some(error) = req.type_error {
        // The field validator's `TypeError` leaves FastAPI's validation.
        return Err(ApiError::internal(format!("TypeError: {error}")));
    }
    tracing::info!("Running SOCFortress Process Name Analysis. Grabbing License");
    let input = format!(
        "Analyze the process name: {}. Provide a risk assessment and any relevant details.",
        req.process_name
    );
    let answer = mcp::query(&st, &input).await.map_err(fail)?;
    Ok(ok(mcp::respond(&answer).map_err(fail)?))
}

// --- VirusTotal ---------------------------------------------------------------------------

async fn virustotal_route(
    State(st): State<ThreatIntelState>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(VirusTotalRequest::read)?;
    tracing::info!("Running VirusTotal Threat Intel.");
    let row = st.ctx.connectors.get("VirusTotal").await?;
    let Some(row) = row.filter(|r| r.connector_verified) else {
        return Err(ApiError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "VirusTotal connector is not verified.",
        ));
    };
    let data = virustotal::lookup(
        &row.connector_url,
        row.connector_api_key.as_deref(),
        &req.ioc_value,
    )
    .await
    .map_err(fail)?;
    let dump = construct(
        &VT_ROUTE_RESPONSE,
        &kwargs(vec![
            ("data", data),
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("VirusTotal threat intelligence lookup was successful.".into()),
            ),
        ]),
    )
    .map_err(fail)?;
    Ok(ok(dump))
}

/// `ensure_virustotal_connector`: the API key of a verified connector.
async fn vt_config(st: &ThreatIntelState) -> Result<String, ApiError> {
    let row = st.ctx.connectors.get("VirusTotal").await?;
    let Some(row) = row.filter(|r| r.connector_verified) else {
        return Err(ApiError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "VirusTotal connector is not verified.",
        ));
    };
    match row.connector_api_key.filter(|k| !k.is_empty()) {
        Some(key) => Ok(key),
        None => Err(ApiError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "VirusTotal API key not found in the database.",
        )),
    }
}

/// `name: str = Form(None)`: absent or empty is `None`; a file part is a
/// `str` error.
fn optional_text(form: &UploadForm<Soc>, v: &mut Validator, name: &str) -> Option<String> {
    match form.form.get(name) {
        Some(FormValue::Text(t)) if !t.is_empty() => Some(t.clone()),
        Some(FormValue::File { .. }) => {
            v.push(
                "string_type",
                loc("body", name),
                "Input should be a valid string",
            );
            None
        }
        _ => None,
    }
}

/// `name: int = Form(default)`.
fn int_field(form: &UploadForm<Soc>, v: &mut Validator, name: &str, default: i64) -> i64 {
    match form.form.get(name) {
        Some(FormValue::Text(t)) if !t.is_empty() => v
            .check_int(
                &loc("body", name),
                &serde_json::Value::String(t.clone()),
                IntRules::default(),
            )
            .unwrap_or(default),
        Some(FormValue::File { .. }) => {
            v.push(
                "int_type",
                loc("body", name),
                "Input should be a valid integer",
            );
            default
        }
        _ => default,
    }
}

const MAX_FILE: usize = 32 * 1024 * 1024;

fn too_large() -> ApiError {
    ApiError::http(
        StatusCode::PAYLOAD_TOO_LARGE,
        "File too large. Maximum file size is 32MB for free API keys.",
    )
}

fn upload_of(part: copilot_web::form::UploadPart) -> Upload {
    Upload {
        filename: part.filename,
        content_type: part.content_type,
        content: part.data,
    }
}

async fn submit(State(st): State<ThreatIntelState>, form: UploadForm<Soc>) -> ApiResult {
    let key = vt_config(&st).await?;
    let mut v = Validator::new();
    let file = form.file(&mut v, "file");
    let password = optional_text(&form, &mut v, "password");
    v.finish()?;
    let Some(file) = file.map(upload_of) else {
        return Err(ApiError::internal("the file part vanished"));
    };
    tracing::info!(
        "Submitting file {} to VirusTotal for analysis",
        file.filename
    );
    if file.content.len() > MAX_FILE {
        return Err(too_large());
    }
    if let Some(pw) = password.as_deref().filter(|p| !p.is_empty()) {
        let _ = pw;
        let filename = &file.filename;
        let lowered = copilot_jinja::unicode::lower(filename);
        let extension = if filename.contains('.') {
            lowered.rsplit('.').next().unwrap_or_default().to_string()
        } else {
            String::new()
        };
        let content_type = file.content_type.clone().unwrap_or_default();
        let zip_extension = matches!(extension.as_str(), "zip" | "zipx");
        let zip_mime = matches!(
            content_type.as_str(),
            "application/zip"
                | "application/x-zip-compressed"
                | "application/x-zip"
                | "multipart/x-zip"
        );
        if !(zip_extension || zip_mime) {
            return Err(ApiError::http(
                StatusCode::BAD_REQUEST,
                format!(
                    "Password can only be provided for zip files. File '{filename}' has extension \
                     '{extension}' and MIME type '{content_type}', which are not recognized as zip \
                     file formats."
                ),
            ));
        }
    }
    let dump = virustotal::submit(&st, &key, &file, password.as_deref())
        .await
        .map_err(fail)?;
    Ok(ok(dump))
}

async fn analyze(State(st): State<ThreatIntelState>, form: UploadForm<Soc>) -> ApiResult {
    let key = vt_config(&st).await?;
    let mut v = Validator::new();
    let file = form.file(&mut v, "file");
    let password = optional_text(&form, &mut v, "password");
    let max_wait_time = int_field(&form, &mut v, "max_wait_time", 300);
    let poll_interval = int_field(&form, &mut v, "poll_interval", 10);
    v.finish()?;
    let Some(file) = file.map(upload_of) else {
        return Err(ApiError::internal("the file part vanished"));
    };
    tracing::info!("Starting complete analysis for file {}", file.filename);
    if file.content.len() > MAX_FILE {
        return Err(too_large());
    }
    if !(30..=600).contains(&max_wait_time) {
        return Err(ApiError::http(
            StatusCode::BAD_REQUEST,
            "max_wait_time must be between 30 and 600 seconds",
        ));
    }
    if !(5..=60).contains(&poll_interval) {
        return Err(ApiError::http(
            StatusCode::BAD_REQUEST,
            "poll_interval must be between 5 and 60 seconds",
        ));
    }
    let dump = virustotal::submit_and_wait(
        &st,
        &key,
        &file,
        password.as_deref(),
        max_wait_time,
        poll_interval,
    )
    .await
    .map_err(fail)?;
    Ok(ok(dump))
}

async fn analysis(
    State(st): State<ThreatIntelState>,
    _auth: Soc,
    Path(analysis_id): Path<String>,
) -> ApiResult {
    let key = vt_config(&st).await?;
    tracing::info!("Getting analysis status for ID: {analysis_id}");
    let dump = virustotal::analysis_status(&st, &key, &analysis_id)
        .await
        .map_err(fail)?;
    Ok(ok(dump))
}

async fn report(
    State(st): State<ThreatIntelState>,
    auth: Soc,
    Path(file_id): Path<String>,
) -> ApiResult {
    report_of(State(st), auth, &file_id).await
}

async fn report_of(State(st): State<ThreatIntelState>, _auth: Soc, file_id: &str) -> ApiResult {
    let key = vt_config(&st).await?;
    tracing::info!("Getting file report for ID: {file_id}");
    let dump = virustotal::file_report(&st, &key, file_id)
        .await
        .map_err(fail)?;
    Ok(ok(dump))
}

// --- SOCFortress AI ------------------------------------------------------------------------

async fn ai_analyze(
    State(st): State<ThreatIntelState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    ai_route(&st, &auth, body, Kind::Analyze).await
}

async fn ai_exclusion(
    State(st): State<ThreatIntelState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    ai_route(&st, &auth, body, Kind::ExclusionRule).await
}

/// The two AI routes that comment on the alert: its indexer document, the
/// SOCFortress AI answer, then the comment.
async fn ai_route(
    st: &ThreatIntelState,
    auth: &Soc,
    body: copilot_web::JsonBody,
    kind: Kind,
) -> ApiResult {
    let req = body.model(CreateAlertRequestRoute::read)?;
    // §4: Python commented on any tenant's alert; a scoped caller must see
    // the alert before anything is sent upstream.
    if let Some(alert_id) = req.alert_id {
        if !matches!(auth.access(&st.ctx).await?, AccessScope::All) {
            copilot_incidents::access::ensure_alert(&st.ctx, auth, alert_id).await?;
        }
    }
    let details =
        copilot_ingest::source::single_alert_details(&st.ingest, &req.index_name, &req.index_id)
            .await?;
    let request = ai::request_body(&details).map_err(fail)?;
    if kind == Kind::ExclusionRule {
        tracing::info!(
            "Sending request: index_name={} index_id={}",
            req.index_name,
            req.index_id
        );
    }
    let key = license::license_key(st).await.map_err(fail)?;
    let lookup = ai::ask(st, kind, &key, request).await.map_err(fail)?;
    let Some(alert_id) = req.alert_id else {
        return Err(ApiError::bad_request(
            "1 validation error for CommentCreate\nalert_id\n  Input should be a valid integer \
             [type=int_type, input_value=None, input_type=NoneType]\n    For further information \
             visit https://errors.pydantic.dev/2.13/v/int_type",
        ));
    };
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT incident_management_alert.id FROM incident_management_alert WHERE \
         incident_management_alert.id = ?",
    )
    .bind(alert_id)
    .fetch_optional(st.ctx.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if exists.is_none() {
        return Err(ApiError::not_found("Alert not found"));
    }
    create_comment(
        &st.ctx.db,
        CommentKind::Alert,
        alert_id,
        &ai::comment_text(kind, &lookup),
        "admin",
        Some(PyDateTime::naive(Local::now().naive_local())),
    )
    .await?;
    Ok(ok(lookup))
}

async fn ai_velociraptor(
    State(st): State<ThreatIntelState>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(CreateAlertRequestRoute::read)?;
    copilot_ingest::source::single_alert_details(&st.ingest, &req.index_name, &req.index_id)
        .await?;
    ai::agent_os(&st, req.agent_id.as_deref())
        .await
        .map_err(fail)?;
    // `alert_payload._source.model_dump()`: `_source` is the alias of
    // `source`, and Pydantic has no private attribute of that name.
    Err(ApiError::internal(
        "AttributeError: 'GenericAlertModel' object has no attribute '_source'",
    ))
}
