//! `/api/agents` — port of `app/agents/routes/agents.py`.
//!
//! Check order is FastAPI's: token (and scope) → path and query validation
//! → the tenant filter, which these routes apply as Python does: the agent
//! is looked up through `filter_query_by_customer_access`, so another
//! tenant's agent reads as missing. Several handlers wrap their whole body
//! in `try: … except Exception` and so turn their own 404 into a 500 (`GET
//! /{agent_id}`, `/critical`, `/update`, …); that is kept.
//!
//! Differences by design (both close tenant leaks): `/wazuh/outdated` and
//! `/velociraptor/outdated` list the caller's customers' agents only, where
//! Python listed every tenant's to any analyst.

use axum::body::Body;
use axum::extract::{FromRef, Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use http::HeaderValue;
use http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use serde_json::Value;

use copilot_auth::pyvalue::PyValue;
use copilot_core::audit::AuditRecord;
use copilot_incidents::schema::CaseOutResponse;
use copilot_incidents::store::{CASE_COLS, CaseRow, Include};
use copilot_upstream::model;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::model_response;
use copilot_velociraptor::validation::validate_client_id;
use copilot_web::validate::{IntRules, LocPart, StrRules, Validator, loc};
use copilot_web::{
    AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, AppContext, Authorized, QueryPairs,
    ScopeSet, WithJson,
};

use crate::AgentsState;
use crate::db::{self, Change, Cond, Tenancy};
use crate::schema::{
    AgentModifyResponse, AgentRecord, AgentsResponse, BulkDeleteAgentResult,
    BulkDeleteAgentsResponse, OutdatedVelociraptorAgentsResponse, OutdatedWazuhAgentsResponse,
};
use crate::services::{csv, epss, sca, sync, velociraptor, vulnerabilities, wazuh};

/// `require_any_scope("admin", "analyst", "scheduler")`.
#[derive(Debug)]
pub struct SyncScopes;
impl ScopeSet for SyncScopes {
    const SCOPES: &'static [&'static str] = &["admin", "analyst", "scheduler"];
}

type Soc = Authorized<AdminOrAnalyst>;
type Any = Authorized<AnyPortalOrSoc>;

/// `search_query`'s `limit`.
const SEARCH_LIMIT: IntRules = IntRules {
    ge: Some(1),
    le: Some(1000),
};

/// The severities of `VulnSeverity`.
const SEVERITIES: &[&str] = &["Low", "Medium", "High", "Critical", "All"];

/// The router, to be nested at `/api/agents`.
pub fn router(state: AgentsState) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/dashboard/agents", get(dashboard_agents))
        .route("/bulk/delete", post(bulk_delete))
        .route("/bulk/delete/filter", post(bulk_delete_by_filter))
        .route("/{agent_id}", get(get_agent))
        .route("/hostname/{hostname}", get(by_hostname))
        .route("/sync", post(sync_all))
        .route("/{agent_id}/critical", post(mark_critical))
        .route("/{agent_id}/noncritical", post(mark_not_critical))
        .route("/{agent_id}/wazuh/upgrade", post(upgrade))
        .route(
            "/{agent_id}/vulnerabilities/cve/{cve}",
            get(vulnerability_by_cve),
        )
        .route(
            "/{agent_id}/vulnerabilities/{vulnerability_severity}",
            get(agent_vulnerabilities),
        )
        .route(
            "/{agent_id}/csv/vulnerabilities/{vulnerability_severity}",
            get(vulnerabilities_csv),
        )
        .route("/{agent_id}/sca", get(agent_sca))
        .route("/{agent_id}/sca/{policy_id}", get(sca_policy_results))
        .route("/{agent_id}/csv/sca/{policy_id}", get(sca_csv))
        .route("/{agent_hostname}/cases", get(agent_cases))
        .route("/wazuh/outdated", get(outdated_wazuh))
        .route("/velociraptor/outdated", get(outdated_velociraptor))
        .route("/{agent_id}/update", put(update_velociraptor_id))
        .route("/{agent_id}/velociraptor/unpin", put(unpin))
        .route("/{agent_id}/delete", delete(delete_agent))
        .route("/sync/vulnerabilities", get(sync_vulnerabilities_all))
        .route(
            "/sync/vulnerabilities/{customer_code}",
            post(sync_vulnerabilities_customer),
        )
        .with_state(state)
}

impl FromRef<AgentsState> for AppContext {
    fn from_ref(s: &AgentsState) -> AppContext {
        s.ctx.clone()
    }
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

fn modify(message: impl Into<String>) -> Response {
    json(AgentModifyResponse {
        success: true,
        message: message.into(),
    })
}

/// The caller's `filter_query_by_customer_access` (with an optional
/// requested subset).
async fn tenancy(
    auth: &copilot_web::CurrentUser,
    ctx: &AppContext,
    requested: Option<&[String]>,
) -> Result<Tenancy, ApiError> {
    let scope = auth.access(ctx).await?;
    Ok(Tenancy::of(&scope.resolve_effective(requested)))
}

/// `select(Agents).filter(Agents.agent_id == id)` through the caller's
/// customer filter, `.first()`.
async fn visible_agent(
    st: &AgentsState,
    auth: &copilot_web::CurrentUser,
    agent_id: &str,
) -> Result<Option<AgentRecord>, ApiError> {
    let t = tenancy(auth, &st.ctx, None).await?;
    Ok(db::first(&st.ctx.db, &[Cond::AgentId(agent_id)], &t).await?)
}

fn not_found_or_denied(agent_id: &str) -> String {
    format!("Agent with agent_id {agent_id} not found or access denied")
}

// --- reads ------------------------------------------------------------------------

async fn list(auth: Any, State(st): State<AgentsState>, q: QueryPairs) -> ApiResult {
    let requested = q.customer_codes();
    let mut v = Validator::new();
    let search = q.opt_str(&mut v, "search", StrRules::default());
    let limit = q.opt_int(&mut v, "limit", SEARCH_LIMIT);
    v.finish()?;
    tracing::info!(
        "Fetching agents (customer_codes={}, search={})",
        requested
            .as_ref()
            .map_or("all".to_string(), |c| format!("{c:?}")),
        search
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("none")
    );
    let t = tenancy(&auth, &st.ctx, requested.as_deref()).await?;
    let agents = db::select(&st.ctx.db, &[], &t, search.as_deref(), limit)
        .await
        .map_err(|e| ApiError::server_error(format!("Failed to fetch agents: {e}")))?;
    Ok(json(AgentsResponse {
        agents,
        success: true,
        message: "Agents fetched successfully".into(),
    }))
}

/// `verify_grafana_header`, then the customer's agents (no token).
async fn dashboard_agents(State(st): State<AgentsState>, headers: HeaderMap) -> ApiResult {
    let header = |name: &str| {
        headers
            .get(name)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
    };
    let expected = std::env::var("GRAFANA_API_HEADER_VALUE")
        .ok()
        .filter(|v| !v.is_empty());
    let Some(expected) = expected else {
        tracing::error!(
            "GRAFANA_API_HEADER_VALUE is not configured; denying Grafana dashboard request"
        );
        return Err(ApiError::forbidden(
            "Grafana header authentication is not configured",
        ));
    };
    if header("grafana").as_deref() != Some(expected.as_str()) {
        tracing::error!("Invalid or missing Grafana header");
        return Err(ApiError::forbidden("Invalid or missing Grafana header"));
    }
    let Some(code) = header("customer-code").filter(|c| !c.is_empty()) else {
        tracing::warn!("Dashboard agent request made with no customer_code header");
        return Ok(json(AgentsResponse {
            agents: Vec::new(),
            success: false,
            message: "No customer_code header provided".into(),
        }));
    };
    let agents = db::select(
        &st.ctx.db,
        &[Cond::CustomerCode(&code)],
        &Tenancy::All,
        None,
        None,
    )
    .await
    .map_err(|_| ApiError::server_error(format!("Failed to fetch agents for customer {code}")))?;
    tracing::info!("Found {} agents for customer_code: {code}", agents.len());
    Ok(json(AgentsResponse {
        agents,
        success: true,
        message: format!("Agents for customer {code} fetched successfully"),
    }))
}

async fn get_agent(
    auth: Any,
    State(st): State<AgentsState>,
    Path(agent_id): Path<String>,
) -> ApiResult {
    tracing::info!("Fetching agent with agent_id: {agent_id}");
    // The 404 is raised inside the `try` and becomes the 500.
    match visible_agent(&st, &auth, &agent_id).await {
        Ok(Some(agent)) => Ok(json(AgentsResponse {
            agents: vec![agent],
            success: true,
            message: "Agent fetched successfully".into(),
        })),
        _ => Err(ApiError::server_error(format!(
            "Failed to fetch agent: {agent_id}. Does it exist?"
        ))),
    }
}

async fn by_hostname(
    auth: Any,
    State(st): State<AgentsState>,
    Path(hostname): Path<String>,
) -> ApiResult {
    tracing::info!("Fetching agent with hostname: {hostname}");
    let found = async {
        let t = tenancy(&auth, &st.ctx, None).await?;
        Ok::<_, ApiError>(db::first(&st.ctx.db, &[Cond::Hostname(&hostname)], &t).await?)
    }
    .await;
    match found {
        Ok(Some(agent)) => Ok(json(AgentsResponse {
            agents: vec![agent],
            success: true,
            message: "Agent fetched successfully".into(),
        })),
        _ => Err(ApiError::server_error("Failed to fetch agent")),
    }
}

/// `(agent_id, vulnerability_severity)` with the enum's 422.
fn severity(raw: &str) -> Result<String, ApiError> {
    let mut v = Validator::new();
    let out = v.check_enum(
        &loc("path", "vulnerability_severity"),
        &Value::String(raw.to_string()),
        SEVERITIES,
    );
    v.finish()?;
    Ok(out.unwrap_or_default())
}

async fn require_visible(
    st: &AgentsState,
    auth: &copilot_web::CurrentUser,
    agent_id: &str,
) -> Result<AgentRecord, ApiError> {
    visible_agent(st, auth, agent_id)
        .await?
        .ok_or_else(|| ApiError::not_found(not_found_or_denied(agent_id)))
}

async fn vulnerability_by_cve(
    auth: Any,
    State(st): State<AgentsState>,
    Path((agent_id, cve)): Path<(String, String)>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let package = q.opt_str(&mut v, "package", StrRules::default());
    let version = q.opt_str(&mut v, "version", StrRules::default());
    v.finish()?;
    tracing::info!("Fetching agent {agent_id} vulnerability {cve}");
    require_visible(&st, &auth, &agent_id).await?;
    let new = wazuh::check_wazuh_manager_version(&st.wazuh).await;
    let dump = vulnerabilities::collect_by_cve(
        &st.wazuh,
        &agent_id,
        &cve,
        package.as_deref(),
        version.as_deref(),
        new,
    )
    .await?;
    Ok(model_response(&dump))
}

async fn collect_vulnerabilities(
    st: &AgentsState,
    agent_id: &str,
    severity: &str,
) -> Result<vulnerabilities::Vulns, PyExc> {
    if wazuh::check_wazuh_manager_version(&st.wazuh).await {
        tracing::info!(
            "Wazuh Manager version is 4.8.0 or higher. Fetching vulnerabilities using new API"
        );
        vulnerabilities::collect_from_indexer(&st.wazuh, agent_id, severity).await
    } else {
        vulnerabilities::collect_from_manager(&st.wazuh, agent_id, severity).await
    }
}

async fn agent_vulnerabilities(
    auth: Any,
    State(st): State<AgentsState>,
    Path((agent_id, raw_severity)): Path<(String, String)>,
) -> ApiResult {
    let sev = severity(&raw_severity)?;
    tracing::info!("Fetching agent {agent_id} vulnerabilities");
    require_visible(&st, &auth, &agent_id).await?;
    let vulns = collect_vulnerabilities(&st, &agent_id, &sev).await?;
    Ok(model_response(&vulnerabilities::response(
        Some(vulns),
        "Vulnerabilities collected successfully",
    )))
}

/// `StreamingResponse(output, media_type="text/csv", headers=…)`.
fn csv_response(body: String, filename: &str) -> ApiResult {
    let latin1: Option<Vec<u8>> = filename
        .chars()
        .map(|c| u8::try_from(u32::from(c)).ok())
        .collect();
    let disposition = latin1
        .map(|name| [b"attachment; filename=".as_slice(), &name].concat())
        .and_then(|bytes| HeaderValue::from_bytes(&bytes).ok())
        .ok_or_else(|| ApiError::internal("filename is not a Latin-1 header value"))?;
    Response::builder()
        .status(200)
        .header(CONTENT_TYPE, "text/csv; charset=utf-8")
        .header(CONTENT_DISPOSITION, disposition)
        .body(Body::from(body))
        .map_err(ApiError::internal)
}

async fn vulnerabilities_csv(
    auth: Any,
    State(st): State<AgentsState>,
    Path((agent_id, raw_severity)): Path<(String, String)>,
) -> ApiResult {
    let sev = severity(&raw_severity)?;
    tracing::info!("Fetching agent {agent_id} vulnerabilities as CSV");
    require_visible(&st, &auth, &agent_id).await?;
    let vulns = collect_vulnerabilities(&st, &agent_id, &sev).await?;
    tracing::info!(
        "Creating CSV file for agent {agent_id} with {} vulnerabilities",
        vulns.len()
    );
    let cves: Vec<String> = vulns
        .iter()
        .filter_map(|v| model::field(v, "cve").as_str().map(str::to_string))
        .collect();
    let scores = st.epss.scores(&cves).await?;
    let mut out = String::new();
    csv::row(
        &mut out,
        &[
            "Severity",
            "Version",
            "Type",
            "Name",
            "External References",
            "Detection Time",
            "CVSS3 Score",
            "Published",
            "Architecture",
            "CVE",
            "Status",
            "Title",
            "EPSS Score",
        ]
        .map(String::from),
    );
    for v in &vulns {
        let f = |k: &str| csv::cell(model::field(v, k));
        let refs = match model::field(v, "external_references") {
            PyValue::List(items) if !items.is_empty() => items
                .iter()
                .map(PyValue::py_str)
                .collect::<Vec<_>>()
                .join(", "),
            _ => String::new(),
        };
        let cve = model::field(v, "cve")
            .as_str()
            .unwrap_or_default()
            .to_string();
        csv::row(
            &mut out,
            &[
                f("severity"),
                f("version"),
                f("type"),
                f("name"),
                refs,
                f("detection_time"),
                f("cvss3_score"),
                f("published"),
                f("architecture"),
                f("cve"),
                f("status"),
                f("title"),
                epss::score_of(&scores, &cve),
            ],
        );
    }
    csv_response(out, &format!("{agent_id}_vulnerabilities.csv"))
}

async fn agent_sca(
    auth: Any,
    State(st): State<AgentsState>,
    Path(agent_id): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let policy_id = q.opt_str(&mut v, "policy_id", StrRules::default());
    v.finish()?;
    tracing::info!("Fetching agent {agent_id} sca");
    require_visible(&st, &auth, &agent_id).await?;
    let dump = sca::collect_agent_sca(&st.wazuh, &agent_id, policy_id.as_deref()).await?;
    Ok(model_response(&dump))
}

async fn sca_policy_results(
    auth: Any,
    State(st): State<AgentsState>,
    Path((agent_id, policy_id)): Path<(String, String)>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let check_id = q.opt_int(&mut v, "check_id", IntRules::default());
    v.finish()?;
    tracing::info!("Fetching agent {agent_id} sca policy results");
    require_visible(&st, &auth, &agent_id).await?;
    let dump = sca::collect_policy_results(&st.wazuh, &agent_id, &policy_id, check_id).await?;
    Ok(model_response(&dump))
}

async fn sca_csv(
    auth: Any,
    State(st): State<AgentsState>,
    Path((agent_id, policy_id)): Path<(String, String)>,
) -> ApiResult {
    tracing::info!("Fetching agent {agent_id} sca policy results as CSV");
    require_visible(&st, &auth, &agent_id).await?;
    let dump = sca::collect_policy_results(&st.wazuh, &agent_id, &policy_id, None).await?;
    let results = match model::field(&dump, "sca_policy_results") {
        PyValue::List(items) => items.clone(),
        _ => Vec::new(),
    };
    tracing::info!(
        "Creating CSV file for agent {agent_id} with {} sca policy results",
        results.len()
    );
    let mut out = String::new();
    csv::row(
        &mut out,
        &[
            "Description",
            "Policy ID",
            "Reason",
            "Command",
            "Rationale",
            "Condition",
            "Title",
            "Result",
            "Remediation",
            "Compliance",
            "Rules",
        ]
        .map(String::from),
    );
    for r in &results {
        let f = |k: &str| csv::cell(model::field(r, k));
        let joined = |key: &str, a: &str, b: &str| match model::field(r, key) {
            PyValue::List(items) if !items.is_empty() => items
                .iter()
                .map(|i| {
                    format!(
                        "{}: {}",
                        model::field(i, a).py_str(),
                        model::field(i, b).py_str()
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
            _ => String::new(),
        };
        csv::row(
            &mut out,
            &[
                f("description"),
                f("policy_id"),
                f("reason"),
                f("command"),
                f("rationale"),
                f("condition"),
                f("title"),
                f("result"),
                f("remediation"),
                joined("compliance", "key", "value"),
                joined("rules", "type", "rule"),
            ],
        );
    }
    csv_response(out, &format!("{agent_id}_sca_policy_results.csv"))
}

/// `list_cases_by_asset_name(name, customer_codes=…)`: each case once,
/// newest first.
async fn cases_by_asset_in(
    db: &copilot_db::Db,
    asset_name: &str,
    codes: &[Option<String>],
) -> Result<Vec<CaseRow>, copilot_db::DbError> {
    let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!(
        "SELECT {CASE_COLS} FROM incident_management_case c WHERE c.id IN \
         (SELECT l.case_id FROM incident_management_casealertlink l \
         JOIN incident_management_alert a ON a.id = l.alert_id \
         JOIN incident_management_asset s ON s.alert_linked = a.id WHERE s.asset_name = "
    ));
    qb.push_bind(asset_name.to_string());
    qb.push(") AND c.customer_code IN (");
    let mut sep = qb.separated(", ");
    for c in codes {
        sep.push_bind(c.clone());
    }
    qb.push(") ORDER BY c.id DESC");
    Ok(qb.build_query_as::<CaseRow>().fetch_all(db.pool()).await?)
}

async fn agent_cases(
    auth: Any,
    State(st): State<AgentsState>,
    Path(hostname): Path<String>,
) -> ApiResult {
    tracing::info!("Fetching agent {hostname} cases");
    let t = tenancy(&auth, &st.ctx, None).await?;
    let mut codes: Vec<Option<String>> = Vec::new();
    for c in db::customer_codes_of_hostname(&st.ctx.db, &hostname, &t).await? {
        if !codes.contains(&c) {
            codes.push(c);
        }
    }
    if codes.is_empty() {
        return Err(ApiError::not_found(format!(
            "Agent with hostname {hostname} not found or access denied"
        )));
    }
    // `sorted(set(…))`: `None` beside a code cannot be ordered (`TypeError`).
    if codes.len() > 1 && codes.iter().any(Option::is_none) {
        return Err(ApiError::internal(
            "'<' not supported between instances of 'NoneType' and 'str'",
        ));
    }
    codes.sort();
    let rows = cases_by_asset_in(&st.ctx.db, &hostname, &codes).await?;
    let cases = copilot_incidents::views::cases_out(&st.ctx.db, &rows, Include::BASIC).await?;
    Ok(json(CaseOutResponse {
        cases,
        success: true,
        message: "Cases retrieved successfully".into(),
        ..Default::default()
    }))
}

async fn outdated_wazuh(auth: Soc, State(st): State<AgentsState>) -> ApiResult {
    tracing::info!("Fetching all outdated Wazuh agents");
    let t = tenancy(&auth, &st.ctx, None).await?;
    let failed =
        |e: String| ApiError::server_error(format!("Failed to fetch outdated Wazuh agents: {e}"));
    let manager = db::first(&st.ctx.db, &[Cond::AgentId("000")], &Tenancy::All)
        .await
        .map_err(|e| failed(e.to_string()))?;
    let Some(manager) = manager else {
        return Err(failed(
            "404: Wazuh Manager with agent_id '000' not found.".into(),
        ));
    };
    let agents = outdated_agents(&st.ctx.db, &manager.wazuh_agent_version, &t)
        .await
        .map_err(|e| failed(e.to_string()))?;
    Ok(json(OutdatedWazuhAgentsResponse {
        outdated_wazuh_agents: agents,
        message: "Outdated Wazuh agents fetched successfully.".into(),
        success: true,
    }))
}

/// `select(Agents).filter(agent_id != "000", wazuh_agent_version != v)`,
/// narrowed to the caller's customers.
async fn outdated_agents(
    db: &copilot_db::Db,
    version: &str,
    t: &Tenancy,
) -> Result<Vec<AgentRecord>, copilot_db::DbError> {
    if *t == Tenancy::Nothing {
        return Ok(Vec::new());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!(
        "SELECT {} FROM agents WHERE agents.agent_id != ",
        db::AGENT_COLS
    ));
    qb.push_bind("000")
        .push(" AND agents.wazuh_agent_version != ");
    qb.push_bind(version.to_string());
    if let Tenancy::In(codes) = t {
        qb.push(" AND agents.customer_code IN (");
        let mut sep = qb.separated(", ");
        for c in codes {
            sep.push_bind(c.clone());
        }
        qb.push(")");
    }
    Ok(qb
        .build_query_as::<AgentRecord>()
        .fetch_all(db.pool())
        .await?)
}

async fn outdated_velociraptor(auth: Soc, State(st): State<AgentsState>) -> ApiResult {
    tracing::info!("Fetching all outdated Velociraptor agents");
    let t = tenancy(&auth, &st.ctx, None).await?;
    // `UniversalService().create(…)` is outside the `try`.
    let service = st.velociraptor.service().await?;
    let failed = |e: String| {
        ApiError::server_error(format!("Failed to fetch outdated Velociraptor agents: {e}"))
    };
    let version = service
        .get_server_version("select * from config")
        .await
        .map_err(|e| failed(e.display()))?;
    let agents = db::select(&st.ctx.db, &[], &t, None, None)
        .await
        .map_err(|e| failed(e.to_string()))?;
    let outdated = agents
        .into_iter()
        .filter(|a| match (&a.velociraptor_agent_version, &version) {
            (Some(have), PyValue::Str(want)) => have != want,
            (None, PyValue::None) => false,
            _ => true,
        })
        .collect();
    Ok(json(OutdatedVelociraptorAgentsResponse {
        outdated_velociraptor_agents: outdated,
        message: "Outdated Velociraptor agents fetched successfully.".into(),
        success: true,
    }))
}

// --- writes -----------------------------------------------------------------------

async fn mark(
    st: &AgentsState,
    auth: &copilot_web::CurrentUser,
    agent_id: &str,
    critical: bool,
) -> ApiResult {
    let what = if critical { "critical" } else { "not critical" };
    tracing::info!("Marking agent {agent_id} as {what}");
    let outcome: Result<(), String> = async {
        let agent = visible_agent(st, auth, agent_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("404: {}", not_found_or_denied(agent_id)))?;
        db::update(&st.ctx.db, agent.id, Change::Critical(critical))
            .await
            .map_err(|e| e.to_string())
    }
    .await;
    match outcome {
        Ok(()) if critical => Ok(modify(format!("Agent {agent_id} marked as critical: True"))),
        Ok(()) => Ok(modify(format!("Agent {agent_id} marked as not critical"))),
        Err(e) => Err(ApiError::server_error(format!(
            "Failed to mark agent as {what}: {e}"
        ))),
    }
}

async fn mark_critical(
    auth: Any,
    State(st): State<AgentsState>,
    Path(agent_id): Path<String>,
) -> ApiResult {
    mark(&st, &auth, &agent_id, true).await
}

async fn mark_not_critical(
    auth: Any,
    State(st): State<AgentsState>,
    Path(agent_id): Path<String>,
) -> ApiResult {
    mark(&st, &auth, &agent_id, false).await
}

async fn upgrade(
    auth: Soc,
    State(st): State<AgentsState>,
    Path(agent_id): Path<String>,
) -> ApiResult {
    tracing::info!("Upgrading Wazuh agent {agent_id}");
    let outcome: Result<(bool, String), String> = async {
        visible_agent(&st, &auth, &agent_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("404: {}", not_found_or_denied(&agent_id)))?;
        wazuh::upgrade_wazuh_agent(&st.wazuh, &agent_id)
            .await
            .map_err(|e| e.display())
    }
    .await;
    match outcome {
        Ok((success, message)) => Ok(json(AgentModifyResponse { success, message })),
        Err(e) => {
            tracing::error!("Failed to upgrade Wazuh agent {agent_id}: {e}");
            Err(ApiError::server_error(format!(
                "Failed to upgrade Wazuh agent {agent_id}: {e}"
            )))
        }
    }
}

async fn update_velociraptor_id(
    auth: Soc,
    State(st): State<AgentsState>,
    Path(agent_id): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let velociraptor_id = match q.get("velociraptor_id") {
        Some(raw) => raw.to_string(),
        None => {
            v.missing(vec![
                LocPart::Key("query".into()),
                LocPart::Key("velociraptor_id".into()),
            ]);
            String::new()
        }
    };
    v.finish()?;
    tracing::info!("Updating agent {agent_id} with Velociraptor ID: {velociraptor_id}");
    validate_client_id(Some(&velociraptor_id))?;
    let outcome: Result<(), String> = async {
        let agent = visible_agent(&st, &auth, &agent_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("404: {}", not_found_or_denied(&agent_id)))?;
        db::update(
            &st.ctx.db,
            agent.id,
            Change::PinVelociraptorId(&velociraptor_id),
        )
        .await
        .map_err(|e| e.to_string())
    }
    .await;
    match outcome {
        Ok(()) => Ok(modify(format!(
            "Agent {agent_id} updated with Velociraptor ID: {velociraptor_id}"
        ))),
        Err(e) => Err(ApiError::server_error(format!(
            "Failed to update agent {agent_id} with Velociraptor ID: {velociraptor_id}: {e}"
        ))),
    }
}

async fn unpin(
    auth: Soc,
    State(st): State<AgentsState>,
    Path(agent_id): Path<String>,
) -> ApiResult {
    let agent = require_visible(&st, &auth, &agent_id).await?;
    db::update(&st.ctx.db, agent.id, Change::Unpin).await?;
    tracing::info!("Agent {agent_id} Velociraptor ID unpinned");
    Ok(modify(format!("Agent {agent_id} Velociraptor ID unpinned")))
}

/// `delete_agent_from_database`'s `HTTPException`.
async fn delete_from_db(st: &AgentsState, agent_id: &str) -> Result<(), PyExc> {
    db::delete_agent(&st.ctx.db, agent_id).await.map_err(|e| {
        tracing::error!("Failed to delete agent {agent_id} from database: {e}");
        PyExc::http(
            500,
            format!("Failed to delete agent {agent_id} from database: {e}"),
        )
    })
}

/// `delete_single_agent(db, agent_id, agent)`.
async fn delete_single_agent(st: &AgentsState, agent: &AgentRecord) -> BulkDeleteAgentResult {
    let agent_id = agent.agent_id.clone();
    let mut errors: Vec<String> = Vec::new();
    if let Err(e) = wazuh::delete_agent_wazuh(&st.wazuh, &agent_id).await {
        let msg = format!("Failed to delete from Wazuh: {}", e.display());
        tracing::warn!("Agent {agent_id}: {msg}");
        errors.push(msg);
    }
    if let Some(vid) = agent
        .velociraptor_id
        .as_deref()
        .filter(|v| !v.is_empty() && *v != "Unknown")
    {
        if let Err(e) = velociraptor::delete_agent_velociraptor(&st.velociraptor, Some(vid)).await {
            let msg = format!("Failed to delete from Velociraptor: {}", e.display());
            tracing::warn!("Agent {agent_id}: {msg}");
            errors.push(msg);
        }
    }
    if let Err(e) = delete_from_db(st, &agent_id).await {
        errors.push(format!("Failed to delete from database: {}", e.display()));
        return BulkDeleteAgentResult {
            agent_id,
            success: false,
            message: format!("Failed to delete agent: {}", errors.join("; ")),
        };
    }
    if !errors.is_empty() {
        return BulkDeleteAgentResult {
            agent_id,
            success: true,
            message: format!(
                "Agent deleted from database but with warnings: {}",
                errors.join("; ")
            ),
        };
    }
    BulkDeleteAgentResult {
        agent_id,
        success: true,
        message: "Agent deleted successfully".into(),
    }
}

fn bulk_response(results: Vec<BulkDeleteAgentResult>, total: usize) -> Response {
    let ok = results.iter().filter(|r| r.success).count();
    let failed = results.len() - ok;
    json(BulkDeleteAgentsResponse {
        success: failed == 0,
        message: format!("Bulk deletion completed: {ok} successful, {failed} failed"),
        total_requested: total,
        successful_deletions: ok,
        failed_deletions: failed,
        results,
    })
}

async fn bulk_delete(
    State(st): State<AgentsState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let agent_ids = body.model(|v, obj, at| {
        let mut l = at.clone();
        l.push(LocPart::Key("agent_ids".into()));
        match obj.get("agent_ids") {
            None => {
                v.missing(l);
                Vec::new()
            }
            Some(items) => v.str_items(items, &l),
        }
    })?;
    tracing::info!("Bulk deleting {} agents", agent_ids.len());
    let t = tenancy(&auth, &st.ctx, None).await?;
    let mut results = Vec::new();
    for agent_id in &agent_ids {
        let agent = db::first(&st.ctx.db, &[Cond::AgentId(agent_id)], &t).await?;
        let Some(agent) = agent else {
            results.push(BulkDeleteAgentResult {
                agent_id: agent_id.clone(),
                success: false,
                message: "Agent not found or access denied".into(),
            });
            continue;
        };
        let mut r = delete_single_agent(&st, &agent).await;
        r.agent_id = agent_id.clone();
        results.push(r);
    }
    Ok(bulk_response(results, agent_ids.len()))
}

async fn bulk_delete_by_filter(
    State(st): State<AgentsState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let (customer_code, status, days) = body.model(|v, obj, at| {
        let customer_code = v.opt_str(obj, at, "customer_code", StrRules::any());
        let status = match obj.get("status") {
            None | Some(Value::Null) => None,
            Some(Value::String(s))
                if ["disconnected", "never_connected", "active"].contains(&s.as_str()) =>
            {
                Some(s.clone())
            }
            Some(_) => {
                let mut l = at.clone();
                l.push(LocPart::Key("status".into()));
                v.push(
                    "literal_error",
                    l,
                    "Input should be 'disconnected', 'never_connected' or 'active'",
                );
                None
            }
        };
        let days = v.opt_int(
            obj,
            at,
            "disconnected_days",
            IntRules {
                ge: Some(1),
                le: None,
            },
        );
        (customer_code, status, days)
    })?;
    tracing::info!("Bulk deleting agents with filters");
    if customer_code.as_deref().is_none_or(str::is_empty) && status.is_none() && days.is_none() {
        return Err(ApiError::bad_request(
            "At least one filter condition must be specified to prevent accidental bulk deletion of all agents",
        ));
    }
    let cutoff;
    let mut conds = Vec::new();
    if let Some(c) = customer_code.as_deref().filter(|c| !c.is_empty()) {
        conds.push(Cond::CustomerCode(c));
    }
    if let Some(s) = status.as_deref() {
        conds.push(Cond::Status(s));
    }
    if let Some(d) = days {
        cutoff = Utc::now().naive_utc() - ChronoDuration::days(d);
        conds.push(Cond::LastSeenBefore(cutoff));
    }
    let t = tenancy(&auth, &st.ctx, None).await?;
    let agents = db::select(&st.ctx.db, &conds, &t, None, None).await?;
    if agents.is_empty() {
        return Ok(json(BulkDeleteAgentsResponse {
            success: true,
            message: "No agents found matching the filter criteria".into(),
            total_requested: 0,
            successful_deletions: 0,
            failed_deletions: 0,
            results: Vec::new(),
        }));
    }
    tracing::info!("Found {} agents matching filter criteria", agents.len());
    let mut results = Vec::new();
    for agent in &agents {
        results.push(delete_single_agent(&st, agent).await);
    }
    Ok(bulk_response(results, agents.len()))
}

async fn delete_agent(
    auth: Soc,
    State(st): State<AgentsState>,
    Path(agent_id): Path<String>,
) -> ApiResult {
    tracing::info!("Deleting agent {agent_id}");
    let agent = require_visible(&st, &auth, &agent_id).await?;
    let snapshot = serde_json::json!({
        "hostname": agent.hostname,
        "customer_code": agent.customer_code,
        "velociraptor_id": agent.velociraptor_id,
    });
    let mut upstream: Vec<String> = Vec::new();
    if let Err(e) = wazuh::delete_agent_wazuh(&st.wazuh, &agent_id).await {
        tracing::error!("Wazuh delete failed for agent {agent_id}: {}", e.display());
        upstream.push(format!("Wazuh: {}", e.display()));
    }
    // `fetch_velociraptor_id`: the first row with this agent id, unfiltered.
    let velociraptor_result: Result<(), PyExc> = async {
        let row = db::first(&st.ctx.db, &[Cond::AgentId(&agent_id)], &Tenancy::All)
            .await
            .map_err(|e| {
                PyExc::http(
                    500,
                    format!("Failed to fetch agent {agent_id} from database: {e}"),
                )
            })?;
        let Some(row) = row else {
            return Err(PyExc::http(
                500,
                format!(
                    "Failed to fetch agent {agent_id} from database: 404: Agent {agent_id} not found"
                ),
            ));
        };
        let client_id = row.velociraptor_id;
        tracing::info!("Client ID: {}", client_id.as_deref().unwrap_or("None"));
        if client_id.as_deref() != Some("Unknown") {
            velociraptor::delete_agent_velociraptor(&st.velociraptor, client_id.as_deref()).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = velociraptor_result {
        tracing::error!(
            "Velociraptor delete failed for agent {agent_id}: {}",
            e.display()
        );
        upstream.push(format!("Velociraptor: {}", e.display()));
    }
    delete_from_db(&st, &agent_id).await?;
    let mut record = AuditRecord::new("agent.delete")
        .actor(Some(auth.id), Some(&auth.username))
        .customer(agent.customer_code.as_deref())
        .entity("agent", &agent_id)
        .values(Some(snapshot), None)
        .source_ip(auth.source_ip.clone());
    if !upstream.is_empty() {
        record = record.details(upstream.join("; "));
    }
    st.ctx.audit.record(record);
    if !upstream.is_empty() {
        return Ok(modify(format!(
            "Agent {agent_id} deleted from CoPilot; upstream services reported: {}",
            upstream.join("; ")
        )));
    }
    Ok(modify(format!("Agent {agent_id} deleted successfully")))
}

async fn sync_all(_auth: Authorized<SyncScopes>, State(st): State<AgentsState>) -> ApiResult {
    let message = sync::sync_all_agents(&st.ctx.db, &st.wazuh, &st.velociraptor).await?;
    Ok(modify(message))
}

/// `GET /sync/vulnerabilities` calls the `GET /agents` route function with
/// the session as its first argument; logging `search_params.search` of the
/// unresolved `Depends` fails before anything else: always a bare 500.
async fn sync_vulnerabilities_all(_auth: Soc) -> ApiResult {
    Err(ApiError::internal(
        "'Depends' object has no attribute 'search'",
    ))
}

async fn sync_vulnerabilities_customer(
    auth: Soc,
    State(st): State<AgentsState>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&st.ctx, &customer_code).await?;
    tracing::info!("Syncing agent vulnerabilities");
    let agents = db::select(
        &st.ctx.db,
        &[Cond::CustomerCode(&customer_code)],
        &Tenancy::All,
        None,
        None,
    )
    .await
    .map_err(|e| {
        ApiError::server_error(format!(
            "Failed to fetch agents with customer_code {customer_code}: {e}"
        ))
    })?;
    let hostnames: Vec<String> = agents
        .into_iter()
        .filter(|a| a.customer_code.is_some())
        .map(|a| a.hostname)
        .collect();
    // `BackgroundTasks`: after the answer, one after the other; a task that
    // raises ends the rest.
    let wazuh = st.wazuh.clone();
    let connectors = st.ctx.connectors.clone();
    tokio::spawn(async move {
        for hostname in hostnames {
            if let Err(e) = vulnerabilities::sync_agent_vulnerabilities(
                &wazuh,
                &connectors,
                &hostname,
                &customer_code,
            )
            .await
            {
                tracing::error!("Vulnerability sync of {hostname} failed: {}", e.display());
                break;
            }
        }
    });
    Ok(json(serde_json::json!({
        "success": true,
        "message": "Agent vulnerabilities sync initiated successfully",
    })))
}
