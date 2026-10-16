//! `/api/vulnerabilities` — port of
//! `app/agents/vulnerabilities/routes/vulnerabilities.py` (13 routes).
//!
//! Check order is FastAPI's: the JSON body is read first (a malformed one is
//! the 422 before any token check), then the token and the tenancy
//! dependencies, then the query parameters and the body's fields (one 422,
//! query errors first).
//!
//! Differences by design (both close tenant leaks): `GET /agent/{agent_id}`
//! lists only the rows of the caller's customers (Python listed any agent's
//! to any analyst), and `POST /sync/agent/{agent_name}` checks the host's
//! tenant (`enforce_hostname_access`) — Python synced any tenant's agent, and
//! with `?customer_code=` filed its vulnerabilities under a customer of the
//! caller's.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post};
use serde_json::{Map, Value};

use copilot_agents::routes::SyncScopes;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::respond::model_response;
use copilot_web::validate::{IntRules, Loc, StrRules, Validator, body_loc, path_int};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, CurrentUser, JsonBody, QueryPairs,
    WithJson,
};

use crate::AgentReportsState;
use crate::agents::{accessible, may_see};
use crate::pyfmt::{dict, int, s};
use crate::query::{bool_or, opt_list};

use super::services::{self, ReportRequest, SearchParams};
use super::sync;

type Soc = Authorized<AdminOrAnalyst>;

/// The router, to be nested at `/api/vulnerabilities`.
pub fn router(state: AgentReportsState) -> Router {
    Router::new()
        .route("/sync", post(sync_all))
        .route("/sync/background", post(sync_background))
        .route("/agent/{agent_id}", get(by_agent))
        .route("/stats", get(stats))
        .route("/sync/customer/{customer_code}", post(sync_customer))
        .route("/sync/agent/{agent_name}", post(sync_agent))
        .route("/delete", delete(delete_vulnerabilities))
        .route("/search", get(search))
        .route("/reports/generate", post(generate))
        .route("/reports/generate/background", post(generate_background))
        .route("/reports", get(list))
        .route("/reports/{report_id}/download", get(download))
        .route("/reports/{report_id}", delete(delete_report))
        .with_state(state)
}

const BATCH: IntRules = IntRules {
    ge: Some(1),
    le: Some(1000),
};

/// `Optional[VulnerabilitySyncRequest] = None`: validated when sent,
/// unused.
fn optional_sync_body(v: &mut Validator, body: &JsonBody) {
    let root = body_loc();
    let obj = match body {
        JsonBody::Missing => return,
        JsonBody::NotJson => v.object(&Value::Null, &root),
        JsonBody::Value(value) => v.object(value, &root),
    };
    if let Some(obj) = obj {
        v.opt_str(obj, &root, "customer_code", StrRules::default());
        v.opt_str(obj, &root, "agent_name", StrRules::default());
        v.bool_or(obj, &root, "force_refresh", false);
    }
}

fn respond(dump: &PyValue) -> ApiResult {
    Ok(model_response(dump))
}

async fn sync_all(
    State(st): State<AgentReportsState>,
    q: QueryPairs,
    WithJson(_auth, body): WithJson<Authorized<SyncScopes>>,
) -> ApiResult {
    let mut v = Validator::new();
    let batch = q.int_or(&mut v, "batch_size", BATCH, 100);
    let bulk = bool_or(&q, &mut v, "use_bulk_mode", false);
    optional_sync_body(&mut v, &body);
    v.finish()?;
    tracing::info!(
        "Starting vulnerability sync for all agents from database (batch_size={batch}, \
         bulk_mode={})",
        if bulk { "True" } else { "False" }
    );
    respond(&sync::sync_all(&st, None, batch, bulk).await.dump())
}

async fn sync_background(
    State(st): State<AgentReportsState>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let mut v = Validator::new();
    optional_sync_body(&mut v, &body);
    v.finish()?;
    tracing::info!("Starting background vulnerability sync for all agents from database");
    tokio::spawn(async move {
        let r = sync::sync_all(&st, None, 100, false).await;
        if !r.success {
            tracing::error!("Background vulnerability sync failed: {}", r.message);
        }
    });
    respond(&dict(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            s("Vulnerability sync started in background for all agents"),
        ),
    ]))
}

async fn by_agent(
    auth: Soc,
    State(st): State<AgentReportsState>,
    Path(agent_id): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let severity = opt_list(&q, "severity");
    tracing::info!("Getting vulnerabilities for agent: {agent_id}");
    let scope = accessible(auth.access(&st.ctx).await?);
    let dump = services::by_agent(&st, &agent_id, severity.as_deref(), scope.as_deref()).await?;
    respond(&dump)
}

/// `verify_optional_customer_code_access`: a non-empty `?customer_code=`
/// must be the caller's.
async fn optional_customer(
    auth: &CurrentUser,
    st: &AgentReportsState,
    q: &QueryPairs,
) -> Result<(), ApiError> {
    if let Some(code) = q.get("customer_code").filter(|c| !c.is_empty()) {
        auth.enforce_customer(&st.ctx, code).await?;
    }
    Ok(())
}

async fn stats(auth: Soc, State(st): State<AgentReportsState>, q: QueryPairs) -> ApiResult {
    optional_customer(&auth, &st, &q).await?;
    let code = q.get("customer_code").map(str::to_string);
    tracing::info!(
        "Getting vulnerability statistics for customer: {}",
        code.as_deref().unwrap_or("None")
    );
    let scope = auth.access(&st.ctx).await.map_err(|e| {
        ApiError::server_error(format!("Failed to get vulnerability statistics: {e}"))
    })?;
    let acc = accessible(scope);
    respond(&services::statistics(&st, code.as_deref(), acc.as_deref()).await?)
}

async fn sync_customer(
    auth: Soc,
    State(st): State<AgentReportsState>,
    Path(customer_code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &customer_code).await?;
    let mut v = Validator::new();
    bool_or(&q, &mut v, "force_refresh", false);
    let batch = q.int_or(&mut v, "batch_size", IntRules::default(), 100);
    let bulk = bool_or(&q, &mut v, "use_bulk_mode", false);
    v.finish()?;
    tracing::info!(
        "Starting vulnerability sync for customer: {customer_code} (batch_size={batch}, \
         bulk_mode={})",
        if bulk { "True" } else { "False" }
    );
    respond(
        &sync::sync_all(&st, Some(&customer_code), batch, bulk)
            .await
            .dump(),
    )
}

async fn sync_agent(
    auth: Soc,
    State(st): State<AgentReportsState>,
    Path(agent_name): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    optional_customer(&auth, &st, &q).await?;
    // The host is no customer code the dependency could check: its tenant
    // is the caller's or the sync is refused (a §4 difference).
    let owner =
        crate::agents::first(&st.ctx.db, &[crate::agents::On::Hostname(&agent_name)]).await?;
    auth.enforce_owned(
        &st.ctx,
        owner.as_ref().and_then(|a| a.customer_code.as_deref()),
        &format!("host {agent_name}"),
    )
    .await?;
    let mut v = Validator::new();
    let code = q.opt_str(&mut v, "customer_code", StrRules::default());
    let batch = q.int_or(&mut v, "batch_size", BATCH, 100);
    let bulk = bool_or(&q, &mut v, "use_bulk_mode", false);
    v.finish()?;
    tracing::info!(
        "Starting vulnerability sync for agent: {agent_name} (batch_size={batch}, bulk_mode={})",
        if bulk { "True" } else { "False" }
    );
    respond(
        &sync::sync_for_agent(&st, &agent_name, code.as_deref(), batch, bulk)
            .await
            .dump(),
    )
}

async fn delete_vulnerabilities(
    _auth: Authorized<AdminOnly>,
    State(st): State<AgentReportsState>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let agent_name = q.opt_str(&mut v, "agent_name", StrRules::default());
    let customer_code = q.opt_str(&mut v, "customer_code", StrRules::default());
    let confirm = bool_or(&q, &mut v, "confirm_delete_all", false);
    v.finish()?;
    let agent_name = agent_name.filter(|a| !a.is_empty());
    let customer_code = customer_code.filter(|c| !c.is_empty());
    if agent_name.is_none() && customer_code.is_none() {
        if !confirm {
            return Err(ApiError::bad_request(
                "To delete ALL vulnerabilities, you must set confirm_delete_all=true",
            ));
        }
        tracing::warn!("Request to delete ALL vulnerabilities received with confirmation");
    }
    if agent_name.is_some() && customer_code.is_some() {
        return Err(ApiError::bad_request(
            "Cannot specify both agent_name and customer_code. Choose one scope.",
        ));
    }
    respond(&services::delete(&st, agent_name.as_deref(), customer_code.as_deref()).await)
}

async fn search(auth: Soc, State(st): State<AgentReportsState>, q: QueryPairs) -> ApiResult {
    let customer_codes = q.customer_codes();
    let mut v = Validator::new();
    let agent_name = q.opt_str(&mut v, "agent_name", StrRules::default());
    let severity = q.opt_str(&mut v, "severity", StrRules::default());
    let cve_id = q.opt_str(&mut v, "cve_id", StrRules::default());
    let package_name = q.opt_str(&mut v, "package_name", StrRules::default());
    let page = q.int_or(
        &mut v,
        "page",
        IntRules {
            ge: Some(1),
            le: None,
        },
        1,
    );
    let page_size = q.int_or(&mut v, "page_size", BATCH, 50);
    let include_epss = bool_or(&q, &mut v, "include_epss", true);
    v.finish()?;
    let params = SearchParams {
        customer_codes,
        agent_name,
        severity,
        cve_id,
        package_name,
        page,
        page_size,
        include_epss,
    };
    let dump = services::search(&st, &auth, &params)
        .await
        .map_err(|e| ApiError::server_error(format!("Failed to search vulnerabilities: {e}")))?;
    respond(&dump)
}

/// `VulnerabilityReportGenerateRequest`.
fn report_request(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> ReportRequest {
    ReportRequest {
        customer_code: v.req_str(obj, at, "customer_code", StrRules::default()),
        report_name: v.opt_str(obj, at, "report_name", StrRules::default()),
        agent_name: v.opt_str(obj, at, "agent_name", StrRules::default()),
        severity: v.opt_str(obj, at, "severity", StrRules::default()),
        cve_id: v.opt_str(obj, at, "cve_id", StrRules::default()),
        package_name: v.opt_str(obj, at, "package_name", StrRules::default()),
        include_epss: v.bool_or(obj, at, "include_epss", false),
    }
}

async fn generate(
    State(st): State<AgentReportsState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(report_request)?;
    respond(&services::generate(&st, &auth, &req, None).await)
}

async fn generate_background(
    State(st): State<AgentReportsState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(report_request)?;
    tracing::info!(
        "Queueing vulnerability report generation for customer: {}",
        req.customer_code
    );
    let name = req.name_or_default("vulnerability_report");
    let id = services::queue(&st, &auth, &req, &name)
        .await
        .map_err(|e| {
            tracing::error!("Error queueing report generation: {e}");
            ApiError::server_error(format!("Failed to queue report generation: {e}"))
        })?;
    let user: CurrentUser = (*auth).clone();
    let task_st = st.clone();
    let task_req = req.clone();
    tokio::spawn(async move {
        let r = services::generate(&task_st, &user, &task_req, Some(id)).await;
        match copilot_upstream::model::field(&r, "success") {
            PyValue::Bool(true) => {
                tracing::info!("Successfully completed background report generation (ID: {id})")
            }
            _ => tracing::error!(
                "Background report generation failed (ID: {id}): {}",
                copilot_upstream::model::field(&r, "error").py_str()
            ),
        }
    });
    respond(&services::queued_response(id, &name, &req.customer_code))
}

async fn list(auth: Soc, State(st): State<AgentReportsState>, q: QueryPairs) -> ApiResult {
    let codes = q.customer_codes();
    respond(&services::list(&st, &auth, codes.as_deref()).await)
}

async fn download(
    auth: Soc,
    State(st): State<AgentReportsState>,
    Path(report_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult {
    let report_id = path_int("report_id", &report_id)?;
    let failed = |e: String| {
        tracing::error!("Error retrieving vulnerability report: {e}");
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
    copilot_objectstore::web::streaming_response(
        data,
        Some("text/csv"),
        &[(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", report.file_name),
        )],
        &headers,
    )
    .map_err(|e| e.unhandled())
}

async fn delete_report(
    auth: Soc,
    State(st): State<AgentReportsState>,
    Path(report_id): Path<String>,
) -> ApiResult {
    let report_id = path_int("report_id", &report_id)?;
    let failed = |e: String| {
        tracing::error!("Error deleting vulnerability report {report_id}: {e}");
        ApiError::server_error(format!("Failed to delete report: {e}"))
    };
    let Some(report) = services::report_of(&st, report_id).await.map_err(failed)? else {
        return Err(ApiError::not_found(format!(
            "Report with ID {report_id} not found"
        )));
    };
    let scope = accessible(
        auth.access(&st.ctx)
            .await
            .map_err(|e| failed(e.to_string()))?,
    );
    if !may_see(&scope, &report.customer_code) {
        return Err(ApiError::forbidden(format!(
            "Access denied to delete report for customer {}",
            report.customer_code
        )));
    }
    tracing::info!(
        "Deleting vulnerability report ID {report_id} for customer {}",
        report.customer_code
    );
    let removed = copilot_objectstore::ops::delete_file_from_minio(
        &st.store,
        Some(&report.bucket_name),
        Some(&report.object_key),
    )
    .await
    .map_err(|e| failed(e.text()))?;
    if let Err(e) = removed {
        tracing::warn!(
            "Failed to delete file from MinIO for report {report_id}: {e}. Proceeding with \
             database deletion."
        );
    }
    super::db::delete_report(&st.ctx.db, report.id)
        .await
        .map_err(|e| failed(e.to_string()))?;
    tracing::info!("Successfully deleted vulnerability report ID {report_id}");
    respond(&dict(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            s(format!(
                "Report '{}' deleted successfully",
                report.report_name
            )),
        ),
        ("report_id", int(report_id)),
        ("report_name", s(&report.report_name)),
        ("customer_code", s(&report.customer_code)),
    ]))
}
