//! `/api/file-analysis` — `app/file_analysis/routes.py`.
//!
//! Every route is `require_any_scope("admin", "analyst")`. The ones that name
//! a job resolve its customer from the stored job first
//! (`verify_job_customer_access`: 404 `job not found`, then
//! `enforce_owned_object_access`, fail closed), then read the job again in
//! the handler, as Python does; `/velociraptor/agents` and `/history` take a
//! required `customer_code` (checked by a dependency *and* the endpoint, so a
//! missing one is reported twice), `/search/{sha256}` an optional one.
//!
//! Differences by design (§4): `/velociraptor/enumerate` checks its body's
//! `customer_code`, and for a caller without deployment-wide access the
//! endpoint `/enumerate` and `/submit` name (a client id, or a hostname) must
//! be one of that customer's agents — Python let any analyst list and
//! collect files on any tenant's endpoints; the agent list shows such a
//! caller no unassigned endpoint.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_objectstore::web::UploadForm;
use copilot_upstream::model::{construct, construct_star, field};
use copilot_upstream::py::{PyExc, PyResult, type_name};
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::form::FormValue;
use copilot_web::validate::{Validator, loc};
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, Authorized, CurrentUser, QueryPairs, WithJson,
};
use http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};

use crate::orchestrator::{self, Refs, RunArgs};
use crate::py::{self, empty_dict, or, str_of};
use crate::schema::{
    AGENT_INFO, ANALYSIS_JOB, ANALYSIS_RESULT, ENUMERATE_REQUEST, HISTORY_ITEM, MATCH_INFO,
    SEARCH_RESPONSE, SUBMIT_REQUEST, answer,
};
use crate::{FileAnalysisState, report, store, velo};

type Soc = Authorized<AdminOrAnalyst>;

const MAX_UPLOAD_MB: usize = 100;

/// The router to nest at `/api/file-analysis`.
pub fn router(st: FileAnalysisState) -> Router {
    let legacy = st.legacy.clone();
    Router::new()
        .route("/velociraptor/agents", get(agents))
        .route("/velociraptor/enumerate", post(enumerate))
        .route("/submit", post(submit))
        .route("/upload", post(upload))
        .route("/job/{job_id}", get(job))
        .route("/result/{job_id}", get(result))
        .route("/result/{job_id}/cape-report", get(cape_report))
        .route("/result/{job_id}/report.pdf", get(report_pdf))
        .route("/analysis/{job_id}", delete(delete_analysis))
        .route("/result/{job_id}/preview/{name}", get(preview))
        .route("/history", get(history))
        .route("/search/{sha256}", get(search))
        .with_state(st)
        .layer(axum::middleware::from_fn_with_state(
            legacy,
            copilot_objectstore::web::encoded_slash_to_legacy,
        ))
}

fn unhandled(e: PyExc) -> ApiError {
    e.unhandled()
}

/// `verify_customer_code_access` plus the endpoint's own `customer_code:
/// str`: the code, after the 403 for a customer the caller may not see.
async fn customer_query(
    st: &FileAnalysisState,
    auth: &CurrentUser,
    q: &QueryPairs,
    v: &mut Validator,
) -> Result<Option<String>, ApiError> {
    match q.get("customer_code") {
        None => {
            v.missing(loc("query", "customer_code"));
            v.missing(loc("query", "customer_code"));
            Ok(None)
        }
        Some(code) => {
            auth.enforce_customer(&st.ctx, code).await?;
            Ok(Some(code.to_string()))
        }
    }
}

/// `job.get("customer_code")` as `enforce_owned_object_access` reads it.
fn owner_of(job: &PyValue) -> PyResult<Option<String>> {
    Ok(py::get(job, "customer_code")?.as_str().map(str::to_string))
}

/// `verify_job_customer_access(job_id)`.
async fn verify_job(
    st: &FileAnalysisState,
    auth: &CurrentUser,
    job_id: &str,
) -> Result<(), ApiError> {
    let Some(job) = store::load_job(st, job_id).await.map_err(unhandled)? else {
        return Err(ApiError::not_found("job not found"));
    };
    let owner = owner_of(&job).map_err(unhandled)?;
    auth.enforce_owned(&st.ctx, owner.as_deref(), &format!("analysis {job_id}"))
        .await?;
    Ok(())
}

/// The handler's own `load_job` (the job vanishing in between is `missing`).
async fn load(st: &FileAnalysisState, job_id: &str, missing: &str) -> Result<PyValue, ApiError> {
    store::load_job(st, job_id)
        .await
        .map_err(unhandled)?
        .ok_or_else(|| ApiError::not_found(missing))
}

/// `job["customer_code"]` and `job.get("sha256", "")`.
fn job_keys(job: &PyValue) -> Result<(String, String), ApiError> {
    let code = copilot_upstream::py::getitem(job, "customer_code").map_err(unhandled)?;
    let sha = py::get_or(job, "sha256", py::s("")).map_err(unhandled)?;
    Ok((str_of(code), str_of(&sha)))
}

// --- Velociraptor ------------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct AgentRow {
    hostname: String,
    os: String,
    velociraptor_id: Option<String>,
    customer_code: Option<String>,
}

const AGENT_COLUMNS: &str = "agents.id, agents.agent_id, agents.ip_address, agents.os, \
    agents.hostname, agents.label, agents.critical_asset, agents.wazuh_last_seen, \
    agents.velociraptor_id, agents.velociraptor_last_seen, agents.wazuh_agent_version, \
    agents.wazuh_agent_status, agents.velociraptor_agent_version, agents.customer_code, \
    agents.quarantined, agents.velociraptor_org, agents.velociraptor_id_pinned";

async fn agents(auth: Soc, State(st): State<FileAnalysisState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let code = customer_query(&st, &auth, &q, &mut v).await?;
    v.finish()?;
    let code = code.unwrap_or_default();
    if code.is_empty() {
        return Err(ApiError::bad_request("customer_code is required"));
    }
    let rows: Vec<AgentRow> = sqlx::query_as(&format!(
        "SELECT {AGENT_COLUMNS} FROM agents WHERE agents.velociraptor_id IS NOT NULL AND \
         (agents.customer_code = ? OR agents.customer_code IS NULL)"
    ))
    .persistent(false)
    .bind(&code)
    .fetch_all(st.ctx.db.pool())
    .await
    .map_err(ApiError::internal)?;
    let scoped = !auth.access(&st.ctx).await?.is_all();
    let live = match velo::live_last_seen_map(&st).await {
        Ok(live) => live,
        Err(e) => {
            tracing::warn!("live agent status unavailable: {}", e.display());
            Vec::new()
        }
    };
    let mut list = Vec::new();
    for a in rows {
        if scoped && a.customer_code.is_none() {
            continue;
        }
        let cid =
            velo::bare_client_id(a.velociraptor_id.as_deref().unwrap_or_default()).to_string();
        let last = live.iter().find(|(k, _)| *k == cid).map_or(0, |(_, s)| *s);
        let online = velo::is_online(last);
        let info = py::dict(vec![
            ("client_id", py::s(cid)),
            ("hostname", py::s(a.hostname)),
            ("os", py::s(a.os)),
            ("online", PyValue::Bool(online)),
            (
                "last_seen",
                if last == 0 {
                    PyValue::None
                } else {
                    PyValue::Int(last.to_string())
                },
            ),
            ("unassigned", PyValue::Bool(a.customer_code.is_none())),
        ]);
        let info = construct(&AGENT_INFO, &info).map_err(unhandled)?;
        let host = py::lower(field(&info, "hostname").as_str().unwrap_or_default());
        list.push(((!online, a.customer_code.is_none(), host), info));
    }
    list.sort_by(|a, b| a.0.cmp(&b.0));
    let agents: Vec<PyValue> = list.into_iter().map(|(_, i)| i).collect();
    Ok(model_response(&answer(
        &format!("{} agents for {code}", agents.len()),
        "agents",
        PyValue::List(agents),
    )))
}

/// For a caller without deployment-wide access: the endpoint must be one of
/// `customer`'s agents (§4).
async fn endpoint_owned(
    st: &FileAnalysisState,
    auth: &CurrentUser,
    customer: &str,
    client_id: Option<&str>,
    hostname: Option<&str>,
) -> Result<bool, ApiError> {
    if auth.access(&st.ctx).await?.is_all() {
        return Ok(false);
    }
    match (client_id.filter(|c| !c.is_empty()), hostname) {
        (Some(cid), _) => {
            if !orchestrator::client_owned_by(st, cid, customer).await {
                return Err(ApiError::forbidden(format!(
                    "Access denied to client {cid}"
                )));
            }
        }
        (None, Some(host)) => {
            let agent = copilot_velociraptor::agents::by_hostname(&st.ctx.db, host).await?;
            if agent.and_then(|a| a.customer_code).as_deref() != Some(customer) {
                return Err(ApiError::forbidden(format!("Access denied to host {host}")));
            }
        }
        (None, None) => {}
    }
    Ok(true)
}

async fn enumerate(
    State(st): State<FileAnalysisState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let dump = body_model(&body, &ENUMERATE_REQUEST)?;
    let text = |k: &str| field(&dump, k).as_str().unwrap_or_default().to_string();
    let (code, client_id, target) = (
        text("customer_code"),
        text("client_id"),
        text("target_path"),
    );
    auth.enforce_customer(&st.ctx, &code).await?;
    if client_id.is_empty() || target.is_empty() {
        return Err(ApiError::bad_request(
            "client_id and target_path are required",
        ));
    }
    endpoint_owned(&st, &auth, &code, Some(&client_id), None).await?;
    let matches = match velo::enumerate_matches(&st, &client_id, &target).await {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("enumerate failed: {}", e.display());
            return Err(ApiError::http(
                StatusCode::BAD_GATEWAY,
                "could not enumerate files on the endpoint",
            ));
        }
    };
    let mut rows = Vec::with_capacity(matches.len());
    for m in &matches {
        rows.push(
            construct_star(
                &MATCH_INFO,
                "app.file_analysis.schema.analysis.MatchInfo",
                m,
            )
            .map_err(unhandled)?,
        );
    }
    let message = if rows.is_empty() {
        "no files matched".to_string()
    } else {
        format!("{} match(es)", rows.len())
    };
    Ok(model_response(&answer(
        &message,
        "matches",
        PyValue::List(rows),
    )))
}

// --- submissions --------------------------------------------------------------------------------

fn submit_response(job_id: PyValue) -> ApiResult {
    let dump = construct(
        &crate::schema::SUBMIT_RESPONSE,
        &py::dict(vec![
            ("job_id", job_id),
            ("message", py::s("analysis queued")),
        ]),
    )
    .map_err(unhandled)?;
    Ok(model_response(&dump))
}

async fn submit(
    State(st): State<FileAnalysisState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let dump = body_model(&body, &SUBMIT_REQUEST)?;
    let text = |k: &str| field(&dump, k).as_str().map(str::to_string);
    let source = text("source").unwrap_or_default();
    let code = text("customer_code").unwrap_or_default();
    let client_id = text("client_id");
    let target_path = text("target_path");
    let hostname = text("hostname");
    auth.enforce_customer(&st.ctx, &code).await?;
    if source != "host_path" {
        return Err(ApiError::bad_request("use /upload for source=upload"));
    }
    let present = |o: &Option<String>| o.as_deref().is_some_and(|s| !s.is_empty());
    if !(present(&hostname) || present(&client_id)) {
        return Err(ApiError::bad_request(
            "host_path source requires hostname or client_id",
        ));
    }
    if !present(&target_path) {
        return Err(ApiError::bad_request(
            "host_path source requires target_path",
        ));
    }
    let owner_check = endpoint_owned(
        &st,
        &auth,
        &code,
        client_id.as_deref(),
        hostname.as_deref().filter(|h| !h.is_empty()),
    )
    .await?;
    let tiers: Vec<String> = match field(&dump, "tiers") {
        PyValue::List(items) => items.iter().map(str_of).collect(),
        _ => vec!["static".into()],
    };
    let (job_id, needs_run) = orchestrator::create_and_dispatch(&st, &source, &code, "sample", "")
        .await
        .map_err(unhandled)?;
    if needs_run {
        orchestrator::spawn(
            &st,
            str_of(&job_id),
            RunArgs {
                sample: None,
                tiers,
                refs: Refs {
                    client_id,
                    target_path,
                    hostname,
                    owner_check,
                },
                reputation_mode: text("reputation_mode").unwrap_or_default(),
            },
        );
    }
    submit_response(job_id)
}

/// `name: bool = Form(default)` as pydantic reads the text.
fn form_bool(form: &UploadForm<Soc>, v: &mut Validator, name: &str, default: bool) -> bool {
    match form.form.get(name) {
        Some(FormValue::Text(t)) if !t.is_empty() => match t.to_ascii_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => false,
            "1" | "on" | "t" | "true" | "y" | "yes" => true,
            _ => {
                v.push(
                    "bool_parsing",
                    loc("body", name),
                    "Input should be a valid boolean, unable to interpret input",
                );
                default
            }
        },
        Some(FormValue::File { .. }) => {
            v.push(
                "bool_type",
                loc("body", name),
                "Input should be a valid boolean",
            );
            default
        }
        _ => default,
    }
}

/// `name: str = Form(default)`.
fn form_text(form: &UploadForm<Soc>, v: &mut Validator, name: &str, default: &str) -> String {
    match form.form.get(name) {
        Some(FormValue::Text(t)) if !t.is_empty() => t.clone(),
        Some(FormValue::File { .. }) => {
            v.push(
                "string_type",
                loc("body", name),
                "Input should be a valid string",
            );
            default.to_string()
        }
        _ => default.to_string(),
    }
}

async fn upload(State(st): State<FileAnalysisState>, form: UploadForm<Soc>) -> ApiResult {
    let mut v = Validator::new();
    let file = form.file(&mut v, "file");
    let code = form.text(&mut v, "customer_code");
    let sandbox = form_bool(&form, &mut v, "sandbox", true);
    let reputation_mode = form_text(&form, &mut v, "reputation_mode", "lookup");
    v.finish()?;
    let (Some(file), Some(code)) = (file, code) else {
        return Err(ApiError::internal("the form vanished"));
    };
    form.auth.enforce_customer(&st.ctx, &code).await?;
    if file.data.len() > MAX_UPLOAD_MB * 1024 * 1024 {
        return Err(ApiError::http(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("file exceeds {MAX_UPLOAD_MB} MB"),
        ));
    }
    if !matches!(reputation_mode.as_str(), "off" | "lookup" | "upload") {
        return Err(ApiError::bad_request(
            "reputation_mode must be off|lookup|upload",
        ));
    }
    let sha256 = hex::encode(Sha256::digest(&file.data));
    let tiers: Vec<String> = if sandbox {
        vec!["static".into(), "dynamic".into()]
    } else {
        vec!["static".into()]
    };
    let filename = if file.filename.is_empty() {
        "sample".to_string()
    } else {
        file.filename.clone()
    };
    let (job_id, needs_run) =
        orchestrator::create_and_dispatch(&st, "upload", &code, &filename, &sha256)
            .await
            .map_err(unhandled)?;
    if needs_run {
        orchestrator::spawn(
            &st,
            str_of(&job_id),
            RunArgs {
                sample: Some(bytes::Bytes::from(file.data)),
                tiers,
                refs: Refs::default(),
                reputation_mode,
            },
        );
    }
    submit_response(job_id)
}

// --- a job ----------------------------------------------------------------------------------------

async fn job(
    auth: Soc,
    State(st): State<FileAnalysisState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    verify_job(&st, &auth, &job_id).await?;
    let stored = load(&st, &job_id, "job not found").await?;
    let dump = construct_star(
        &ANALYSIS_JOB,
        "app.file_analysis.schema.analysis.AnalysisJob",
        &stored,
    )
    .map_err(unhandled)?;
    Ok(model_response(&answer("", "job", dump)))
}

async fn result(
    auth: Soc,
    State(st): State<FileAnalysisState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    verify_job(&st, &auth, &job_id).await?;
    let stored = load(&st, &job_id, "job not found").await?;
    let (code, sha) = job_keys(&stored)?;
    let Some(result) = store::load_result(&st, &code, &sha)
        .await
        .map_err(unhandled)?
        .filter(PyValue::truthy)
    else {
        return Err(ApiError::not_found("result not ready"));
    };
    let dump = construct_star(
        &ANALYSIS_RESULT,
        "app.file_analysis.schema.analysis.AnalysisResult",
        &result,
    )
    .map_err(unhandled)?;
    Ok(model_response(&answer("", "result", dump)))
}

/// `((result or {}).get("sandbox") or {}).get("task_id")`.
fn task_id(result: Option<&PyValue>) -> PyResult<PyValue> {
    let result = or(result.cloned().unwrap_or(PyValue::None), empty_dict());
    let sandbox = or(py::get(&result, "sandbox")?, empty_dict());
    py::get(&sandbox, "task_id")
}

async fn cape_report(
    auth: Soc,
    State(st): State<FileAnalysisState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    verify_job(&st, &auth, &job_id).await?;
    let stored = load(&st, &job_id, "job not found").await?;
    let (code, sha) = job_keys(&stored)?;
    let result = store::load_result(&st, &code, &sha)
        .await
        .map_err(unhandled)?;
    let task = task_id(result.as_ref()).map_err(unhandled)?;
    if !task.truthy() {
        return Err(ApiError::not_found(
            "this analysis has no detonation report",
        ));
    }
    let report = match orchestrator::backend(&st.settings) {
        None => Err("SANDBOX_BACKEND=none: detonation is disabled".to_string()),
        Some(cape) => cape.get_report(&str_of(&task)).await.map_err(|e| e.text()),
    };
    let report = report.map_err(|e| {
        ApiError::http(
            StatusCode::BAD_GATEWAY,
            format!("could not fetch the CAPE report: {e}"),
        )
    })?;
    let body = copilot_upstream::json::py_dumps(&report, copilot_upstream::json::Dumps::HTTPX)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok((
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response())
}

async fn report_pdf(
    auth: Soc,
    State(st): State<FileAnalysisState>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult {
    verify_job(&st, &auth, &job_id).await?;
    let stored = load(&st, &job_id, "job not found").await?;
    let (code, sha) = job_keys(&stored)?;
    let Some(result) = store::load_result(&st, &code, &sha)
        .await
        .map_err(unhandled)?
        .filter(PyValue::truthy)
    else {
        return Err(ApiError::not_found("result not ready"));
    };
    let sandbox = or(
        py::get(&result, "sandbox").map_err(unhandled)?,
        empty_dict(),
    );
    let task = py::get(&sandbox, "task_id").map_err(unhandled)?;
    let mut screenshots = Vec::new();
    if task.truthy() {
        if let Some(cape) = orchestrator::backend(&st.settings) {
            screenshots = cape.get_screenshots(&str_of(&task), 24).await;
        }
    }
    let failed = |e: String| {
        tracing::error!("PDF report generation failed for job {job_id}: {e}");
        ApiError::server_error(format!("could not generate the PDF report: {e}"))
    };
    let context =
        report::build_context(&result, None, &screenshots).map_err(|e| failed(e.display()))?;
    let html = report::render(&context).map_err(failed)?;
    let pdf = crate::pdf::html_to_pdf(
        &html,
        report::PDF_OPTIONS,
        st.settings.wkhtmltopdf.as_deref(),
    )
    .await
    .map_err(failed)?;
    let name = report::file_name(&result).map_err(|e| failed(e.display()))?;
    Ok(crate::starlette::file_response(
        &pdf.data,
        pdf.mtime,
        &name,
        "application/pdf",
        &headers,
        false,
    ))
}

async fn delete_analysis(
    auth: Soc,
    State(st): State<FileAnalysisState>,
    Path(job_id): Path<String>,
) -> ApiResult {
    verify_job(&st, &auth, &job_id).await?;
    let stored = load(&st, &job_id, "analysis not found").await?;
    let (code, sha) = job_keys(&stored)?;
    let removed = store::delete_analysis(&st, &code, &sha, Some(&job_id))
        .await
        .map_err(unhandled)?;
    Ok(model_response(&answer(
        "analysis deleted",
        "removed",
        py::int(removed),
    )))
}

/// `name in container`.
fn contains(container: &PyValue, name: &str) -> PyResult<bool> {
    match container {
        PyValue::List(items) => Ok(items.iter().any(|i| i.as_str() == Some(name))),
        PyValue::Str(s) => Ok(s.contains(name)),
        PyValue::Dict(items) => Ok(items.iter().any(|(k, _)| k == name)),
        other => Err(PyExc::TypeError(format!(
            "argument of type '{}' is not iterable",
            type_name(other)
        ))),
    }
}

async fn preview(
    auth: Soc,
    State(st): State<FileAnalysisState>,
    Path((job_id, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult {
    verify_job(&st, &auth, &job_id).await?;
    let stored = load(&st, &job_id, "job not found").await?;
    let (code, sha) = job_keys(&stored)?;
    let result = store::load_result(&st, &code, &sha)
        .await
        .map_err(unhandled)?;
    let known = match result.as_ref().filter(|r| r.truthy()) {
        None => false,
        Some(r) => {
            let urls = or(
                py::get(r, "preview_urls").map_err(unhandled)?,
                py::empty_list(),
            );
            contains(&urls, &name).map_err(unhandled)?
        }
    };
    if !known {
        return Err(ApiError::not_found("preview not found"));
    }
    let sha = str_of(copilot_upstream::py::getitem(&stored, "sha256").map_err(unhandled)?);
    let Some(data) = store::load_preview(&st, &code, &sha, &name)
        .await
        .map_err(unhandled)?
    else {
        return Err(ApiError::not_found("preview not found"));
    };
    copilot_objectstore::web::streaming_response(data, Some("image/png"), &[], &headers)
        .map_err(unhandled)
}

// --- history and the cache ------------------------------------------------------------------------

async fn history(auth: Soc, State(st): State<FileAnalysisState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let code = customer_query(&st, &auth, &q, &mut v).await?;
    // Pydantic's `int` from the query text (`"1.0"`, `"1_0"`, unbounded): a
    // limit beyond `i64` slices the list as an unbounded one does.
    let limit = copilot_customer_portal::query::int_or(
        &mut v,
        &q,
        "limit",
        copilot_customer_portal::query::Bounds::default(),
        50,
    );
    let limit = i64::try_from(limit).unwrap_or(if limit < 0 { i64::MIN } else { i64::MAX });
    v.finish()?;
    let code = code.unwrap_or_default();
    if code.is_empty() {
        return Err(ApiError::bad_request("customer_code is required"));
    }
    let items = store::list_history(&st, &code, limit)
        .await
        .map_err(unhandled)?;
    let mut rows = Vec::with_capacity(items.len());
    for i in &items {
        rows.push(
            construct_star(
                &HISTORY_ITEM,
                "app.file_analysis.schema.analysis.HistoryItem",
                i,
            )
            .map_err(unhandled)?,
        );
    }
    Ok(model_response(&answer(
        &format!("{} analyses", rows.len()),
        "items",
        PyValue::List(rows),
    )))
}

async fn search(
    auth: Soc,
    State(st): State<FileAnalysisState>,
    Path(sha256): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let code = q.get("customer_code").map(str::to_string);
    if let Some(c) = code.as_deref().filter(|c| !c.is_empty()) {
        auth.enforce_customer(&st.ctx, c).await?;
    }
    let Some(code) = code.filter(|c| !c.is_empty()) else {
        return Ok(model_response(&py::dict(vec![
            ("success", PyValue::Bool(true)),
            ("message", py::s("customer_code required for cache lookup")),
            ("job_id", PyValue::None),
        ])));
    };
    let job_id = store::find_cached_job_id(&st, &code, &sha256)
        .await
        .map_err(unhandled)?;
    let message = if job_id.is_some() {
        "cache hit"
    } else {
        "not analyzed"
    };
    let dump = construct(
        &SEARCH_RESPONSE,
        &py::dict(vec![
            ("job_id", job_id.unwrap_or(PyValue::None)),
            ("message", py::s(message)),
        ]),
    )
    .map_err(unhandled)?;
    Ok(model_response(&dump))
}
