//! `/api/agent_data_store` — port of `app/data_store/data_store_routes.py`.
//!
//! - `POST /upload` (admin/analyst): a file to a bucket and object name,
//!   the bucket created if missing; every failure, a missing file name
//!   included, is the 500 `Failed to upload file: …`. Python wrote any bucket
//!   and object for any analyst (the route is closed to portal users for
//!   that reason, GHSA-6j26-wcv6-gp3f). Here a caller without
//!   deployment-wide access may write only under their customers: the
//!   object's first path segment must be one of their customer codes (the
//!   reports', Sysmon configs' and file analysis' layout) or the id of an
//!   agent of theirs (`velociraptor-artifacts/{agent_id}/…`); anything else
//!   — an unknown owner, an empty, `.` or `..` first segment — is the 403
//!   `Access denied to object {object_name}` before anything is sent
//!   (RUST_MIGRATION.md §4). Admins stay deployment-wide.
//! - `GET /agent/{agent_id}/artifacts[?flow_id=]`, `GET …/{artifact_id}`,
//!   `GET …/{artifact_id}/download` (admin/analyst) and `DELETE
//!   …/{artifact_id}` (admin): the agent's owner first
//!   (`verify_agent_id_access`, fail-closed), then the path, then the row.
//!   A download and a delete address the object as
//!   `velociraptor-artifacts/{agent_id}/{flow_id}/{file_name}` (not the
//!   row's `bucket_name`/`object_key`), as Python does.

use axum::Router;
use axum::extract::{OriginalUri, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::StatusCode;

use copilot_db::agents;
use copilot_gateway::LegacyProxy;
use copilot_upstream::py::PyExc;
use copilot_web::validate::{IntRules, Validator, loc};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, CurrentUser, QueryPairs,
};

use crate::ops;
use crate::schema::{
    AgentDataStoreData, AgentDataStoreListResponse, AgentDataStoreResponse, FileUploadResponse,
};
use crate::services;
use crate::store::ObjectStore;
use crate::web::{self, UploadForm};

/// What the routes need.
#[derive(Clone)]
pub struct DataStoreState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The MinIO store.
    pub store: ObjectStore,
    /// The Python backend (for a path with an encoded `/`).
    pub legacy: Option<LegacyProxy>,
}

impl axum::extract::FromRef<DataStoreState> for AppContext {
    fn from_ref(s: &DataStoreState) -> AppContext {
        s.ctx.clone()
    }
}

/// The router, to be nested at `/api/agent_data_store`.
pub fn router(state: DataStoreState) -> Router {
    Router::new()
        .route("/upload", post(upload))
        .route("/agent/{agent_id}/artifacts", get(list))
        .route(
            "/agent/{agent_id}/artifacts/{artifact_id}",
            get(details).delete(delete_artifact),
        )
        .route(
            "/agent/{agent_id}/artifacts/{artifact_id}/download",
            get(download),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.legacy.clone(),
            web::encoded_slash_to_legacy,
        ))
        .with_state(state)
}

fn json<T: serde::Serialize>(body: T) -> Response {
    axum::Json(body).into_response()
}

fn server_error(text: String) -> ApiError {
    ApiError::http(StatusCode::INTERNAL_SERVER_ERROR, text)
}

/// The path is `/api/agent_data_store/agent/{agent_id}/artifacts[/…]`: the
/// agent id is the segment after `agent`.
fn agent_id_of(uri: &http::Uri) -> String {
    let segments = web::raw_segments(uri.path());
    let at = segments.iter().rposition(|s| *s == "artifacts");
    let raw = at
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| segments.get(i))
        .copied()
        .unwrap_or_default();
    web::py_unquote(raw)
}

/// `verify_agent_id_access`: the agent's customer must be the caller's (an
/// unknown agent is a 403 for a scoped caller).
async fn verify_agent(ctx: &AppContext, user: &CurrentUser, agent_id: &str) -> ApiResult<()> {
    let owner = agents::customer_code_for_agent(&ctx.db, agent_id).await?;
    user.enforce_owned(ctx, owner.as_deref(), &format!("agent {agent_id}"))
        .await
}

fn artifact_id_of(uri: &http::Uri, from_end: usize) -> ApiResult<i64> {
    let raw = web::segment_from_end(uri, from_end);
    let mut v = Validator::new();
    let id = v
        .check_int(
            &loc("path", "artifact_id"),
            &serde_json::Value::String(raw),
            IntRules::default(),
        )
        .unwrap_or_default();
    v.finish()?;
    Ok(id)
}

/// A scoped caller writes only under their customers: the object's first
/// segment is one of their customer codes, or an agent id of theirs (fail
/// closed).
async fn verify_object(ctx: &AppContext, user: &CurrentUser, object: &str) -> ApiResult<()> {
    let access = user.access(ctx).await?;
    if access.is_all() {
        return Ok(());
    }
    let subject = format!("object {object}");
    // A `.` or `..` segment further on is refused by the client itself, as
    // miniopy-async refuses it (the 500 of Python's).
    let first = object.split('/').next().unwrap_or_default();
    if first.is_empty() || first == "." || first == ".." {
        return user.enforce_owned(ctx, None, &subject).await;
    }
    if access.can_access(first) {
        return Ok(());
    }
    let owner = agents::customer_code_for_agent(&ctx.db, first).await?;
    user.enforce_owned(ctx, owner.as_deref(), &subject).await
}

async fn upload(
    State(st): State<DataStoreState>,
    form: UploadForm<Authorized<AdminOrAnalyst>>,
) -> ApiResult {
    let mut v = Validator::new();
    let file = form.file(&mut v, "file");
    let bucket = form.text(&mut v, "bucket_name");
    let object = form.text(&mut v, "object_name");
    v.finish()?;
    let (Some(file), Some(bucket), Some(object)) = (file, bucket, object) else {
        return Err(ApiError::internal("validated form fields missing"));
    };
    verify_object(&st.ctx, &form.auth, &object).await?;
    let result: Result<FileUploadResponse, PyExc> = async {
        tracing::info!(
            "Uploading file {} to bucket {bucket} as {object}",
            file.filename
        );
        if file.filename.is_empty() {
            return Err(PyExc::http(400, "File name is required"));
        }
        let up = ops::upload_file_to_datastore(
            &st.store,
            &file.filename,
            file.content_type.as_deref(),
            &file.data,
            &bucket,
            &object,
        )
        .await?;
        Ok(FileUploadResponse {
            success: true,
            message: format!("File {} uploaded successfully", file.filename),
            bucket_name: up.bucket_name,
            object_key: up.object_key,
            file_name: up.file_name,
            file_size: up.file_size,
            file_hash: up.file_hash,
            content_type: Some(up.content_type),
        })
    }
    .await;
    match result {
        Ok(r) => Ok(json(r)),
        Err(e) => {
            tracing::error!("Failed to upload file: {}", e.display());
            Err(server_error(format!(
                "Failed to upload file: {}",
                e.display()
            )))
        }
    }
}

async fn list(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<DataStoreState>,
    OriginalUri(uri): OriginalUri,
    q: QueryPairs,
) -> ApiResult {
    let agent_id = agent_id_of(&uri);
    verify_agent(&st.ctx, &auth, &agent_id).await?;
    let flow_id = q.get("flow_id").map(str::to_string);
    let result: Result<AgentDataStoreListResponse, String> = async {
        let rows = services::list_artifacts(
            &st.ctx.db,
            &agent_id,
            flow_id.as_deref().filter(|f| !f.is_empty()),
        )
        .await
        .map_err(|e| e.to_string())?;
        let ids: Vec<&str> = rows.iter().map(|r| r.agent_id.as_str()).collect();
        let customers = services::agent_customers(&st.ctx.db, &ids)
            .await
            .map_err(|e| e.to_string())?;
        let data: Vec<AgentDataStoreData> = rows
            .into_iter()
            .map(|row| {
                let customer = customers.get(&row.agent_id).cloned().flatten();
                AgentDataStoreData::from_row(row, customer)
            })
            .collect();
        Ok(AgentDataStoreListResponse {
            success: true,
            message: format!("Found {} artifacts for agent {agent_id}", data.len()),
            total: data.len(),
            data,
        })
    }
    .await;
    result.map(json).map_err(|e| {
        tracing::error!("Failed to list agent artifacts: {e}");
        server_error(format!("Failed to list agent artifacts: {e}"))
    })
}

async fn details(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<DataStoreState>,
    OriginalUri(uri): OriginalUri,
) -> ApiResult {
    let agent_id = agent_id_of(&uri);
    verify_agent(&st.ctx, &auth, &agent_id).await?;
    let artifact_id = artifact_id_of(&uri, 0)?;
    let row = services::artifact(&st.ctx.db, artifact_id, &agent_id)
        .await
        .map_err(|e| server_error(format!("Failed to get artifact details: {e}")))?;
    let Some(row) = row else {
        return Err(ApiError::not_found(format!(
            "Artifact {artifact_id} not found for agent {agent_id}"
        )));
    };
    let customers = services::agent_customers(&st.ctx.db, &[row.agent_id.as_str()])
        .await
        .map_err(|e| server_error(format!("Failed to get artifact details: {e}")))?;
    let customer = customers.get(&row.agent_id).cloned().flatten();
    Ok(json(AgentDataStoreResponse {
        success: true,
        message: "Artifact details retrieved successfully".into(),
        data: Some(AgentDataStoreData::from_row(row, customer)),
    }))
}

async fn download(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<DataStoreState>,
    OriginalUri(uri): OriginalUri,
    request: http::HeaderMap,
) -> ApiResult {
    let agent_id = agent_id_of(&uri);
    verify_agent(&st.ctx, &auth, &agent_id).await?;
    let artifact_id = artifact_id_of(&uri, 1)?;
    let result: Result<Response, PyExc> = async {
        let row = services::artifact(&st.ctx.db, artifact_id, &agent_id)
            .await
            .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
        let Some(row) = row else {
            return Err(PyExc::http(
                404,
                format!("Artifact {artifact_id} not found for agent {agent_id}"),
            ));
        };
        let data = ops::download_data_store(
            &st.store,
            ops::ARTIFACTS_BUCKET,
            &format!("{agent_id}/{}/{}", row.flow_id, row.file_name),
        )
        .await?;
        web::streaming_response(
            data,
            Some(&row.content_type),
            &[
                (
                    "Content-Disposition",
                    format!("attachment; filename={}", row.file_name),
                ),
                ("Content-Length", row.file_size.to_string()),
            ],
            &request,
        )
    }
    .await;
    match result {
        Ok(r) => Ok(r),
        Err(PyExc::Http(status, detail)) => Err(ApiError::http(
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            detail,
        )),
        Err(e) => {
            tracing::error!("Failed to download artifact: {}", e.display());
            Err(server_error(format!(
                "Failed to download artifact: {}",
                e.display()
            )))
        }
    }
}

async fn delete_artifact(
    auth: Authorized<AdminOnly>,
    State(st): State<DataStoreState>,
    OriginalUri(uri): OriginalUri,
) -> ApiResult {
    let agent_id = agent_id_of(&uri);
    verify_agent(&st.ctx, &auth, &agent_id).await?;
    let artifact_id = artifact_id_of(&uri, 0)?;
    let result: Result<(), PyExc> = async {
        let row = services::artifact(&st.ctx.db, artifact_id, &agent_id)
            .await
            .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
        let Some(row) = row else {
            return Err(PyExc::http(
                404,
                format!("Artifact {artifact_id} not found for agent {agent_id}"),
            ));
        };
        ops::delete_file(
            &st.store,
            ops::ARTIFACTS_BUCKET,
            &format!("{agent_id}/{}/{}", row.flow_id, row.file_name),
        )
        .await?;
        services::delete_artifact(&st.ctx.db, row.id)
            .await
            .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
        tracing::info!("Deleted artifact {artifact_id} for agent {agent_id}");
        Ok(())
    }
    .await;
    match result {
        Ok(()) => Ok(json(serde_json::json!({
            "success": true,
            "message": format!("Artifact {artifact_id} deleted successfully"),
        }))),
        Err(PyExc::Http(status, detail)) => Err(ApiError::http(
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            detail,
        )),
        Err(e) => {
            tracing::error!("Failed to delete artifact: {}", e.display());
            Err(server_error(format!(
                "Failed to delete artifact: {}",
                e.display()
            )))
        }
    }
}
