//! `/api/sca` — port of `app/agents/sca/routes/sca.py` (12 routes).
//!
//! Check order is FastAPI's: the JSON body first (a malformed one is the 422
//! before any token check), the token, the path, then the query parameters
//! and the body's fields. The caller's scope is resolved in the handler, as
//! Python's `scoped_customer_codes` is.
//!
//! One difference by design (a tenant leak): the package registry's agent
//! lookup counts, in its `message`, only the matches on the caller's agents
//! (Python dropped the other tenants' matches from the list but kept their
//! number in the message).

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde_json::{Map, Value};

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::model_response;
use copilot_web::validate::{IntRules, Loc, StrRules, Validator, path_int};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs, WithJson};

use crate::AgentReportsState;
use crate::agents::{accessible, may_see};
use crate::pyfmt::{dict, s};

use super::db;
use super::schema::{empty_overview, empty_stats};
use super::services::{self, Filters, OverviewParams, ScaReportRequest};
use super::stream::{self, StreamParams};

type Soc = Authorized<AdminOrAnalyst>;

/// The router, to be nested at `/api/sca`.
pub fn router(state: AgentReportsState) -> Router {
    Router::new()
        .route("/overview", get(overview))
        .route("/overview/stream", get(overview_stream))
        .route("/stats", get(stats))
        .route("/reports/generate", post(generate))
        .route("/reports", get(list))
        .route("/reports/{report_id}/download", get(download))
        .route("/reports/{report_id}", delete(delete_report))
        .route("/policies", get(policies))
        .route("/policies/{policy_id}/metadata", get(policy_metadata))
        .route("/policies/{policy_id}", get(policy_content))
        .route("/packages/registry", get(registry))
        .route(
            "/packages/registry/{registry_key}/agents",
            get(registry_agents),
        )
        .with_state(state)
}

const SCORE: IntRules = IntRules {
    ge: Some(0),
    le: Some(100),
};

fn respond(dump: &PyValue) -> ApiResult {
    Ok(model_response(dump))
}

/// The overview's and the stream's shared query parameters.
fn read_filters(q: &QueryPairs, v: &mut Validator) -> (Option<String>, Filters) {
    let agent_name = q.opt_str(v, "agent_name", StrRules::default());
    let policy_id = q.opt_str(v, "policy_id", StrRules::default());
    let policy_name = q.opt_str(v, "policy_name", StrRules::default());
    let min_score = q.opt_int(v, "min_score", SCORE);
    let max_score = q.opt_int(v, "max_score", SCORE);
    (
        agent_name,
        Filters {
            policy_id,
            policy_name,
            min_score,
            max_score,
        },
    )
}

async fn overview(auth: Soc, State(st): State<AgentReportsState>, q: QueryPairs) -> ApiResult {
    let requested = q.customer_codes();
    let mut v = Validator::new();
    let (agent_name, filters) = read_filters(&q, &mut v);
    let page = q.int_or(
        &mut v,
        "page",
        IntRules {
            ge: Some(1),
            le: None,
        },
        1,
    );
    let page_size = q.int_or(
        &mut v,
        "page_size",
        IntRules {
            ge: Some(1),
            le: Some(1000),
        },
        50,
    );
    v.finish()?;
    let codes = auth
        .access(&st.ctx)
        .await?
        .scoped_customer_codes(requested.as_deref());
    if codes.as_ref().is_some_and(Vec::is_empty) {
        return respond(&empty_overview(page, page_size, "No accessible customers"));
    }
    let p = OverviewParams {
        codes,
        agent_name,
        filters,
        page,
        page_size,
    };
    let dump = services::overview(&st, &p).await.map_err(|e| {
        tracing::error!("Error in SCA overview search endpoint: {}", e.display());
        ApiError::server_error(format!("Failed to search SCA results: {}", e.display()))
    })?;
    respond(&dump)
}

async fn overview_stream(
    auth: Soc,
    State(st): State<AgentReportsState>,
    q: QueryPairs,
) -> Result<Response, ApiError> {
    let requested = q.customer_codes();
    let mut v = Validator::new();
    let (agent_name, filters) = read_filters(&q, &mut v);
    v.finish()?;
    let codes = auth
        .access(&st.ctx)
        .await?
        .scoped_customer_codes(requested.as_deref());
    Ok(stream::response(
        st,
        StreamParams {
            codes,
            agent_name,
            filters,
        },
    ))
}

async fn stats(auth: Soc, State(st): State<AgentReportsState>, q: QueryPairs) -> ApiResult {
    let requested = q.customer_codes();
    let codes = auth
        .access(&st.ctx)
        .await?
        .scoped_customer_codes(requested.as_deref());
    if codes.as_ref().is_some_and(Vec::is_empty) {
        return respond(&empty_stats("No accessible customers"));
    }
    let dump = services::statistics(&st, codes.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("Error getting SCA statistics: {}", e.display());
            ApiError::server_error(format!("Failed to get SCA statistics: {}", e.display()))
        })?;
    respond(&dump)
}

/// `SCAReportGenerateRequest`.
fn report_request(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> ScaReportRequest {
    ScaReportRequest {
        customer_code: v.req_str(obj, at, "customer_code", StrRules::default()),
        report_name: v.opt_str(obj, at, "report_name", StrRules::default()),
        agent_name: v.opt_str(obj, at, "agent_name", StrRules::default()),
        policy_id: v.opt_str(obj, at, "policy_id", StrRules::default()),
        min_score: v.opt_int(obj, at, "min_score", SCORE),
        max_score: v.opt_int(obj, at, "max_score", SCORE),
    }
}

async fn generate(
    State(st): State<AgentReportsState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(report_request)?;
    respond(&services::generate(&st, &auth, &req).await)
}

async fn list(auth: Soc, State(st): State<AgentReportsState>, q: QueryPairs) -> ApiResult {
    let codes = q.customer_codes();
    respond(&services::list(&st, &auth, codes.as_deref()).await)
}

async fn download(
    auth: Soc,
    State(st): State<AgentReportsState>,
    Path(report_id): Path<String>,
) -> Result<Response, ApiError> {
    let report_id = path_int("report_id", &report_id)?;
    let failed = |e: String| {
        tracing::error!("Error retrieving SCA report: {e}");
        ApiError::server_error(format!("Failed to retrieve report: {e}"))
    };
    let Some(report) = services::report_of(&st, report_id).await.map_err(failed)? else {
        return Err(ApiError::not_found("Report not found"));
    };
    let scope = accessible(
        auth.access(&st.ctx)
            .await
            .map_err(|e| failed(e.to_string()))?,
    );
    if !may_see(&scope, &report.customer_code) {
        return Err(ApiError::forbidden("Access denied to this report"));
    }
    let data = copilot_objectstore::ops::retrieve_file_from_minio(
        &st.store,
        Some(&report.bucket_name),
        Some(&report.object_key),
    )
    .await
    .map_err(|e| failed(e.text()))?;
    let Ok(data) = data else {
        return Err(ApiError::server_error("Failed to retrieve report file"));
    };
    // `Response(content, media_type="text/csv", headers=…)`: Starlette
    // encodes the header as latin-1.
    let disposition = format!("attachment; filename={}", report.file_name);
    let header = copilot_objectstore::web::latin1(&disposition).map_err(|e: PyExc| {
        tracing::error!("Error downloading SCA report: {}", e.text());
        ApiError::server_error(format!("Failed to download report: {}", e.text()))
    })?;
    let header = http::HeaderValue::from_bytes(&header)
        .map_err(|e| ApiError::server_error(format!("Failed to download report: {e}")))?;
    Ok((
        [
            (http::header::CONTENT_DISPOSITION, header),
            (
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/csv; charset=utf-8"),
            ),
        ],
        data,
    )
        .into_response())
}

async fn delete_report(
    auth: Soc,
    State(st): State<AgentReportsState>,
    Path(report_id): Path<String>,
) -> ApiResult {
    let report_id = path_int("report_id", &report_id)?;
    let failed = |e: String| {
        tracing::error!("Error deleting SCA report: {e}");
        ApiError::server_error(format!("Failed to delete report: {e}"))
    };
    let Some(report) = services::report_of(&st, report_id).await.map_err(failed)? else {
        return Err(ApiError::not_found("Report not found"));
    };
    let scope = accessible(
        auth.access(&st.ctx)
            .await
            .map_err(|e| failed(e.to_string()))?,
    );
    if !may_see(&scope, &report.customer_code) {
        return Err(ApiError::forbidden("Access denied to this report"));
    }
    tracing::info!(
        "Deleting SCA report file from MinIO: {}/{}",
        report.bucket_name,
        report.object_key
    );
    let removed = copilot_objectstore::ops::delete_file_from_minio(
        &st.store,
        Some(&report.bucket_name),
        Some(&report.object_key),
    )
    .await
    .map_err(|e| failed(e.text()))?;
    if let Err(e) = removed {
        tracing::warn!("Failed to delete file from MinIO: {e}");
    }
    db::delete_report(&st.ctx.db, report.id)
        .await
        .map_err(|e| failed(e.to_string()))?;
    tracing::info!(
        "Successfully deleted SCA report: {} (ID: {report_id})",
        report.report_name
    );
    respond(&dict(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            s(format!(
                "Successfully deleted report '{}'",
                report.report_name
            )),
        ),
    ]))
}

async fn policies(_auth: Soc, State(st): State<AgentReportsState>) -> ApiResult {
    respond(&st.sca_repo.index().await?)
}

async fn policy_metadata(
    _auth: Soc,
    State(st): State<AgentReportsState>,
    Path(policy_id): Path<String>,
) -> ApiResult {
    respond(&st.sca_repo.metadata(&policy_id).await?)
}

async fn policy_content(
    _auth: Soc,
    State(st): State<AgentReportsState>,
    Path(policy_id): Path<String>,
) -> ApiResult {
    respond(&st.sca_repo.content(&policy_id).await?)
}

async fn registry(_auth: Soc) -> ApiResult {
    respond(&services::registry_response())
}

async fn registry_agents(
    auth: Soc,
    State(st): State<AgentReportsState>,
    Path(registry_key): Path<String>,
) -> ApiResult {
    let scope = accessible(auth.access(&st.ctx).await?);
    respond(&services::detect_agents(&st, &registry_key, scope.as_deref()).await?)
}
