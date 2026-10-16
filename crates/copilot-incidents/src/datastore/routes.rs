//! The MinIO-backed routes of `routes/db_operations.py` and
//! `routes/customer_report.py`, registered with their full paths beside the
//! nested database routes (an axum route on the same path merges methods:
//! `DELETE /case/{case_id}` joins `GET /case/{case_id}`).
//!
//! Check order is FastAPI's: the multipart body is read first (Starlette's
//! 400 before any token check), then the token, the path, the case's or
//! report's owner, the query and the body. Path parameters are decoded as
//! uvicorn decodes the path (`%E9` is U+FFFD there, not a 400), and a path
//! holding an encoded `/` is Python's (it routes the decoded path). What the
//! services raise reaches the caller as it does in Python: the
//! `HTTPException` envelope, the `ValueError` handler's 400 (Pydantic's text,
//! a `UnicodeEncodeError` from a header that is not latin-1), else a bare
//! 500.

use axum::Router;
use axum::extract::{OriginalUri, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde_json::{Value, json};

use copilot_core::audit::AuditRecord;
use copilot_objectstore::web::{self, UploadForm};
use copilot_objectstore::{PyExc, ops};
use copilot_web::validate::{IntRules, Validator, loc};
use copilot_web::{AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, Authorized, QueryPairs};

use super::DatastoreState;
use super::services::{self, TemplateFile};
use crate::access;
use crate::files::CaseFile;
use crate::routes::common::CUSTOMER_USER;

type Soc = Authorized<AdminOrAnalyst>;
type Any = Authorized<AnyPortalOrSoc>;

const P: &str = "/api/incidents/db_operations";

/// Static one-segment paths under `/case/` the Rust routers serve for other
/// methods; FastAPI hands a `DELETE` of any of them to `DELETE
/// /case/{case_id}` (and its 422).
const CASE_STATICS: [&str; 12] = [
    "alert-link",
    "alert-links",
    "alert-unlink",
    "assigned-to",
    "comment",
    "create",
    "customer-code",
    "data-store",
    "escalated",
    "from-alert",
    "severity",
    "status",
];

/// The routes, with full paths.
pub fn router(state: DatastoreState) -> Router {
    let mut r = Router::new()
        .route(
            &format!("{P}/case/data-store/download/{{case_id}}/{{file_name}}"),
            get(download_case_file),
        )
        .route(
            &format!("{P}/case/data-store/upload"),
            post(upload_case_file).get(case_files_of_upload),
        )
        .route(
            &format!("{P}/case/data-store/{{case_id}}/{{file_name}}"),
            delete(delete_case_file),
        )
        .route(&format!("{P}/case-report-template"), get(list_templates))
        .route(
            &format!("{P}/case-report-template/download/{{file_name}}"),
            get(download_template),
        )
        .route(
            &format!("{P}/case-report-template/upload"),
            post(upload_template).delete(delete_template),
        )
        .route(
            &format!("{P}/case-report-template/do-default-template-exists"),
            delete(delete_template),
        )
        .route(
            &format!("{P}/case-report-template/{{file_name}}"),
            delete(delete_template),
        )
        .route(&format!("{P}/case/{{case_id}}"), delete(delete_case))
        .route(
            "/api/incidents/customer_reports/{report_id}/download",
            get(download_report),
        )
        .route(
            "/api/incidents/customer_reports/{report_id}",
            delete(delete_report),
        );
    for name in CASE_STATICS {
        r = r.route(&format!("{P}/case/{name}"), delete(delete_case));
    }
    r.layer(axum::middleware::from_fn_with_state(
        state.legacy.clone(),
        web::encoded_slash_to_legacy,
    ))
    .with_state(state)
}

fn json_response(v: Value) -> Response {
    axum::Json(v).into_response()
}

/// What an exception leaving the route becomes.
fn unhandled(e: PyExc) -> ApiError {
    e.unhandled()
}

/// A path segment as an `int` path parameter (422 `int_parsing`).
fn path_int(uri: &http::Uri, from_end: usize, name: &str) -> ApiResult<i64> {
    let raw = web::segment_from_end(uri, from_end);
    let mut v = Validator::new();
    let n = v
        .check_int(&loc("path", name), &Value::String(raw), IntRules::default())
        .unwrap_or_default();
    v.finish()?;
    Ok(n)
}

// --- case files -------------------------------------------------------------------------------

/// `GET /case/data-store/download/{case_id}/{file_name}`.
async fn download_case_file(
    auth: Any,
    State(st): State<DatastoreState>,
    OriginalUri(uri): OriginalUri,
    request: http::HeaderMap,
) -> ApiResult {
    let case_id = path_int(&uri, 1, "case_id")?;
    let file_name = web::segment_from_end(&uri, 0);
    tracing::info!(
        "Downloading file {file_name} from case {case_id} for user: {} with role_id: {:?}",
        auth.username,
        auth.role_id
    );
    access::ensure_case(&st.ctx, &auth, case_id).await?;
    let row = services::file_by_name(&st.ctx.db, case_id, &file_name)
        .await?
        .ok_or_else(|| ApiError::not_found("File not found"))?;
    let data = ops::download_data_store(&st.store, &row.bucket_name, &row.object_key)
        .await
        .map_err(unhandled)?;
    web::streaming_response(
        data,
        row.content_type.as_deref(),
        &[(
            "Content-Disposition",
            format!("attachment; filename={file_name}"),
        )],
        &request,
    )
    .map_err(unhandled)
}

/// `GET /case/data-store/upload`: FastAPI routes it to `GET
/// /case/data-store/{case_id}`, whose `case_id` it is not.
async fn case_files_of_upload(_auth: Any) -> ApiResult {
    let mut v = Validator::new();
    v.check_int(
        &loc("path", "case_id"),
        &Value::String("upload".into()),
        IntRules::default(),
    );
    v.finish()?;
    Err(ApiError::internal("unreachable: `upload` is no integer"))
}

/// `POST /case/data-store/upload?case_id=` (`UploadFile`): portal users too.
async fn upload_case_file(
    State(st): State<DatastoreState>,
    q: QueryPairs,
    form: UploadForm<Any>,
) -> ApiResult {
    let auth = &form.auth;
    let mut v = Validator::new();
    let case_id = match q.get("case_id") {
        Some(raw) => v
            .check_int(
                &loc("query", "case_id"),
                &Value::String(raw.into()),
                IntRules::default(),
            )
            .unwrap_or_default(),
        None => {
            v.missing(loc("query", "case_id"));
            0
        }
    };
    let file = form.file(&mut v, "file");
    v.finish()?;
    let Some(file) = file else {
        return Err(ApiError::internal("validated upload missing"));
    };
    tracing::info!(
        "Uploading file {} to case {case_id} for user: {} with role_id: {:?}",
        file.filename,
        auth.username,
        auth.role_id
    );
    let case = access::ensure_case(&st.ctx, auth, case_id).await?;
    if services::file_by_name(&st.ctx.db, case_id, &file.filename)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request(
            "File name already exists for this case",
        ));
    }
    let row = services::upload_file_to_case(
        &st.ctx.db,
        &st.store,
        case_id,
        &file.filename,
        file.content_type.as_deref(),
        &file.data,
    )
    .await
    .map_err(unhandled)?;
    st.ctx.audit.record(
        AuditRecord::new("datastore.file_create")
            .actor(Some(auth.id), Some(&auth.username))
            .customer(case.customer_code.as_deref())
            .entity("case_file", &file.filename)
            .values(
                None,
                Some(json!({"case_id": case_id, "file_name": file.filename})),
            )
            .source_ip(auth.source_ip.clone()),
    );
    Ok(json_response(json!({
        "case_data_store": services::created_case_file(&row),
        "success": true,
        "message": "File uploaded successfully",
    })))
}

/// `DELETE /case/data-store/{case_id}/{file_name}` (admin/analyst).
async fn delete_case_file(
    auth: Soc,
    State(st): State<DatastoreState>,
    OriginalUri(uri): OriginalUri,
) -> ApiResult {
    let case_id = path_int(&uri, 1, "case_id")?;
    let file_name = web::segment_from_end(&uri, 0);
    tracing::info!(
        "Deleting file {file_name} from case {case_id} for user: {} with role_id: {:?}",
        auth.username,
        auth.role_id
    );
    let case = access::ensure_case(&st.ctx, &auth, case_id).await?;
    let row: CaseFile = services::file_by_name(&st.ctx.db, case_id, &file_name)
        .await?
        .ok_or_else(|| ApiError::not_found("File not found"))?;
    ops::delete_file(&st.store, &row.bucket_name, &row.object_key)
        .await
        .map_err(unhandled)?;
    services::delete_row(&st.ctx.db, "incident_management_case_datastore", row.id)
        .await
        .map_err(unhandled)?;
    st.ctx.audit.record(
        AuditRecord::new("datastore.file_delete")
            .actor(Some(auth.id), Some(&auth.username))
            .customer(case.customer_code.as_deref())
            .entity("case_file", &file_name)
            .values(
                Some(json!({"case_id": case_id, "file_name": file_name})),
                None,
            )
            .source_ip(auth.source_ip.clone()),
    );
    Ok(json_response(json!({
        "message": "File deleted successfully",
        "success": true,
    })))
}

/// `DELETE /case/{case_id}` (admin/analyst): the case with its comments,
/// links, tasks, timeline and files.
async fn delete_case(
    auth: Soc,
    State(st): State<DatastoreState>,
    OriginalUri(uri): OriginalUri,
) -> ApiResult {
    let case_id = path_int(&uri, 0, "case_id")?;
    tracing::info!(
        "Deleting case {case_id} for user: {} with role_id: {:?}",
        auth.username,
        auth.role_id
    );
    access::ensure_case(&st.ctx, &auth, case_id).await?;
    services::delete_case(&st.ctx.db, &st.store, case_id)
        .await
        .map_err(unhandled)?;
    Ok(json_response(json!({
        "message": "Case deleted successfully",
        "success": true,
    })))
}

// --- case report templates --------------------------------------------------------------------

/// `GET /case-report-template`: the bucket's top-level names.
async fn list_templates(_auth: Soc, State(st): State<DatastoreState>) -> ApiResult {
    tracing::info!("Listing all files in the data store");
    let names =
        ops::list_case_report_template_data_store_files(&st.store, ops::REPORT_TEMPLATES_BUCKET)
            .await
            .map_err(unhandled)?;
    Ok(json_response(json!({
        "case_report_template_data_store": names,
        "success": true,
        "message": "Files retrieved successfully",
    })))
}

/// `GET /case-report-template/download/{file_name}`.
async fn download_template(
    _auth: Soc,
    State(st): State<DatastoreState>,
    OriginalUri(uri): OriginalUri,
    request: http::HeaderMap,
) -> ApiResult {
    let file_name = web::segment_from_end(&uri, 0);
    let row: TemplateFile = services::template_by_name(&st.ctx.db, &file_name)
        .await?
        .ok_or_else(|| ApiError::not_found("File not found"))?;
    let data = ops::download_data_store(&st.store, &row.bucket_name, &row.object_key)
        .await
        .map_err(unhandled)?;
    tracing::info!("Streaming file {file_name}");
    web::streaming_response(
        data,
        row.content_type.as_deref(),
        &[(
            "Content-Disposition",
            format!("attachment; filename={file_name}"),
        )],
        &request,
    )
    .map_err(unhandled)
}

const ZIP_MAGIC: [&[u8]; 3] = [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"];

/// `POST /case-report-template/upload`: a `.docx` that is a ZIP archive or a
/// `.html` that is UTF-8 text and not one (GHSA-7q83-228r-wfh5), under a
/// name not yet taken.
async fn upload_template(State(st): State<DatastoreState>, form: UploadForm<Soc>) -> ApiResult {
    let mut v = Validator::new();
    let file = form.file(&mut v, "file");
    v.finish()?;
    let Some(file) = file else {
        return Err(ApiError::internal("validated upload missing"));
    };
    let extension = services::extension(&file.filename);
    if extension != ".docx" && extension != ".html" {
        return Err(ApiError::bad_request(
            "Invalid file type. Only .docx and .html files are allowed.",
        ));
    }
    let header = &file.data[..file.data.len().min(8)];
    let zip = ZIP_MAGIC.iter().any(|m| header.starts_with(m));
    if extension == ".docx" {
        if !zip {
            return Err(ApiError::bad_request(
                "File content does not match a valid .docx document.",
            ));
        }
    } else if zip || std::str::from_utf8(&file.data).is_err() {
        return Err(ApiError::bad_request(
            "File content does not match a valid .html document.",
        ));
    }
    if crate::files::report_template_exists(&st.ctx.db, &file.filename).await? {
        return Err(ApiError::bad_request(
            "File name already exists for this template",
        ));
    }
    let row = services::upload_report_template(
        &st.ctx.db,
        &st.store,
        &file.filename,
        file.content_type.as_deref(),
        &file.data,
    )
    .await
    .map_err(unhandled)?;
    Ok(json_response(json!({
        "case_report_template_data_store": services::created_template(&row),
        "success": true,
        "message": "File uploaded successfully",
    })))
}

/// `DELETE /case-report-template/{file_name}`.
async fn delete_template(
    _auth: Soc,
    State(st): State<DatastoreState>,
    OriginalUri(uri): OriginalUri,
) -> ApiResult {
    let file_name = web::segment_from_end(&uri, 0);
    let row = services::template_by_name(&st.ctx.db, &file_name)
        .await?
        .ok_or_else(|| ApiError::not_found("File not found"))?;
    ops::delete_file(&st.store, &row.bucket_name, &row.object_key)
        .await
        .map_err(unhandled)?;
    services::delete_row(
        &st.ctx.db,
        "incident_management_case_report_template_datastore",
        row.id,
    )
    .await
    .map_err(unhandled)?;
    Ok(json_response(json!({
        "message": "File deleted successfully",
        "success": true,
    })))
}

// --- customer report files ---------------------------------------------------------------------

/// `_require_report` + `_ensure_customer_access`.
async fn report_for(
    st: &DatastoreState,
    auth: &Any,
    report_id: i64,
) -> ApiResult<services::ReportFile> {
    let report = services::report(&st.ctx.db, report_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Report with ID {report_id} not found")))?;
    if !auth
        .access(&st.ctx)
        .await?
        .can_access(&report.customer_code)
    {
        return Err(ApiError::forbidden(format!(
            "Access denied to customer {}",
            report.customer_code
        )));
    }
    Ok(report)
}

/// `GET /api/incidents/customer_reports/{report_id}/download`: a portal user
/// only a shared report or one of their own, and only a completed one.
async fn download_report(
    auth: Any,
    State(st): State<DatastoreState>,
    OriginalUri(uri): OriginalUri,
    request: http::HeaderMap,
) -> ApiResult {
    let report_id = path_int(&uri, 1, "report_id")?;
    let report = report_for(&st, &auth, report_id).await?;
    if auth.role_id == Some(CUSTOMER_USER)
        && !(report.visible_to_customer
            || report.generated_by_role.as_deref() == Some("customer_user"))
    {
        return Err(ApiError::forbidden("This report is not available."));
    }
    if report.status != "completed" {
        return Err(ApiError::http(
            http::StatusCode::CONFLICT,
            format!(
                "Report is not ready to download (status: {})",
                report.status
            ),
        ));
    }
    let retrieval = ops::retrieve_file_from_minio(
        &st.store,
        Some(&report.bucket_name),
        Some(&report.object_key),
    )
    .await
    .map_err(unhandled)?;
    let data = retrieval.map_err(|error| {
        // `RuntimeError(f"Failed to retrieve report file: {error}")`.
        ApiError::internal(format!("Failed to retrieve report file: {error}"))
    })?;
    web::streaming_response(
        data,
        Some("application/pdf"),
        &[(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", report.file_name),
        )],
        &request,
    )
    .map_err(unhandled)
}

/// `DELETE /api/incidents/customer_reports/{report_id}`: an admin or the
/// report's creator; a file that cannot be removed is only logged.
async fn delete_report(
    auth: Any,
    State(st): State<DatastoreState>,
    OriginalUri(uri): OriginalUri,
) -> ApiResult {
    let report_id = path_int(&uri, 0, "report_id")?;
    let report = report_for(&st, &auth, report_id).await?;
    let is_admin = auth.role_id == Some(1);
    let is_creator = report.generated_by == auth.id;
    if !(is_admin || is_creator) {
        return Err(ApiError::forbidden(
            "Only an admin or the report creator can delete this report",
        ));
    }
    let removed = ops::delete_file_from_minio(
        &st.store,
        Some(&report.bucket_name),
        Some(&report.object_key),
    )
    .await
    .map_err(unhandled)?;
    if let Err(error) = removed {
        tracing::warn!(
            "Failed to delete report {} file from MinIO: {error}. Proceeding with database deletion.",
            report.id
        );
    }
    services::delete_row(
        &st.ctx.db,
        "incident_management_customer_reports",
        report.id,
    )
    .await
    .map_err(unhandled)?;
    tracing::info!(
        "Deleted incident report {report_id} ({}) for customer {}",
        report.report_name,
        report.customer_code
    );
    Ok(json_response(json!({
        "success": true,
        "message": format!("Report '{}' deleted successfully", report.report_name),
        "report_id": report_id,
        "report_name": report.report_name,
        "customer_code": report.customer_code,
    })))
}
