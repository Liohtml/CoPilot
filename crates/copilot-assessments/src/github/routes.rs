//! `/api/github-audit/*` — the 19 routes of
//! `app/integrations/github_audit/routes/github_audit.py`.
//!
//! Check order is FastAPI's: the body is read first (malformed JSON is a
//! 422 before anything), then the token, the `verify_optional_customer_code_
//! access` dependency of `GET /reports`, the path, query and body together
//! (one 422), then the handler. Tenancy (§4): Python checked the caller's
//! customers only on the report list; here every route that names a
//! customer (the body of `POST /config`, `?customer_codes` of `GET
//! /config`) or addresses a configuration, report, exclusion or baseline by
//! its id checks the owner, where the object is resolved — fail closed: an
//! unknown id is a 403 for a scoped caller.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use copilot_auth::pyvalue::PyValue;
use copilot_uba::params::{NumSpec, StrSpec, path_int, q_bool_or, q_int_or, q_opt_str, q_req_str};
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::model_response;
use copilot_web::body::JsonBody;
use copilot_web::validate::{Loc, Validator, body_loc};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, Authorized, QueryPairs, WithJson,
};
use serde_json::{Map, Value};

use super::audit::Scope;
use super::schema::{
    AuditRequest, BaselineCreate, ConfigCreate, ConfigUpdate, ExclusionCreate, ExclusionUpdate,
};
use super::services::{self, Object, owned};
use super::store::{self, ReportFilter};
use crate::AssessmentsState;

type Reader = Authorized<AdminOrAnalyst>;
type Admin = Authorized<AdminOnly>;

const PREFIX: &str = "/api/github-audit";

/// The routes, by full path.
pub fn routes(state: AssessmentsState) -> Router {
    let p = |path: &str| format!("{PREFIX}{path}");
    Router::new()
        .route(&p("/config"), post(create_config).get(get_configs))
        .route(
            &p("/config/{config_id}"),
            get(get_config).put(update_config).delete(delete_config),
        )
        .route(&p("/config/{config_id}/audit"), post(audit_from_config))
        .route(&p("/audit"), post(audit_adhoc))
        .route(&p("/config/{config_id}/audit/summary"), post(audit_summary))
        .route(&p("/reports"), get(get_reports))
        .route(
            &p("/reports/{report_id}"),
            get(get_report).delete(delete_report),
        )
        .route(
            &p("/config/{config_id}/exclusions"),
            post(create_exclusion).get(get_exclusions),
        )
        .route(
            &p("/exclusions/{exclusion_id}"),
            put(update_exclusion).delete(delete_exclusion),
        )
        .route(
            &p("/config/{config_id}/baselines"),
            post(create_baseline).get(get_baselines),
        )
        .route(&p("/baselines/{baseline_id}"), delete(delete_baseline))
        .route(&p("/checks"), get(get_checks))
        .with_state(state)
}

// --- helpers ------------------------------------------------------------------------------

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn st(text: impl Into<String>) -> PyValue {
    PyValue::Str(text.into())
}

fn done(message: &str) -> Response {
    model_response(&dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", st(message)),
    ]))
}

fn config_response(message: &str, config: PyValue, configs: PyValue) -> Response {
    model_response(&dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", st(message)),
        ("config", config),
        ("configs", configs),
    ]))
}

fn exclusion_response(message: &str, one: PyValue, many: PyValue) -> Response {
    model_response(&dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", st(message)),
        ("exclusion", one),
        ("exclusions", many),
    ]))
}

fn baseline_response(message: &str, one: PyValue, many: PyValue) -> Response {
    model_response(&dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", st(message)),
        ("baseline", one),
        ("baselines", many),
    ]))
}

/// FastAPI's body parameter, read into the validator that already holds the
/// path and query errors.
fn read_body<T: Default>(
    v: &mut Validator,
    body: &JsonBody,
    read: impl FnOnce(&mut Validator, &Map<String, Value>, &Loc) -> T,
) -> T {
    let root = body_loc();
    match body {
        JsonBody::Missing => {
            v.missing(root);
            T::default()
        }
        JsonBody::NotJson => {
            v.object(&Value::Null, &root);
            T::default()
        }
        JsonBody::Value(value) => match v.object(value, &root) {
            Some(obj) => read(v, obj, &root),
            None => T::default(),
        },
    }
}

/// `int` path parameter on its own.
fn path_id(name: &str, raw: &str) -> Result<String, ApiError> {
    let mut v = Validator::new();
    let id = path_int(&mut v, name, raw);
    v.finish()?;
    Ok(id)
}

async fn config_for(
    s: &AssessmentsState,
    auth: &Reader,
    id: &str,
) -> Result<store::ConfigRow, ApiError> {
    let row = store::config(&s.ctx.db, id).await?;
    owned(s, &auth.user, Object::Config, id, row, |r| &r.customer_code).await
}

fn exc(e: PyExc) -> ApiError {
    e.unhandled()
}

// --- configurations -----------------------------------------------------------------------

async fn create_config(
    State(s): State<AssessmentsState>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let mut v = Validator::new();
    let req: ConfigCreate = read_body(&mut v, &body, ConfigCreate::read);
    v.finish()?;
    tracing::info!(
        "Creating GitHub Audit config for customer: {}",
        req.customer_code
    );
    // §4: the body names the tenant; Python filed a configuration under any
    // customer for any analyst.
    auth.enforce_customer(&s.ctx, &req.customer_code).await?;
    match store::existing_configs(&s.ctx.db, &req.customer_code, &req.organization).await? {
        0 => {}
        1 => {
            return Err(ApiError::bad_request(format!(
                "Configuration already exists for customer '{}' and organization '{}'",
                req.customer_code, req.organization
            )));
        }
        // `scalar_one_or_none()`'s `MultipleResultsFound`.
        _ => return Err(ApiError::internal("MultipleResultsFound")),
    }
    let id = store::insert_config(&s.ctx.db, &req).await?;
    let row = store::config(&s.ctx.db, &id.to_string())
        .await?
        .ok_or_else(|| ApiError::internal("created configuration not found"))?;
    Ok(config_response(
        "GitHub Audit configuration created successfully",
        row.dump(),
        PyValue::None,
    ))
}

async fn get_configs(State(s): State<AssessmentsState>, auth: Reader, q: QueryPairs) -> ApiResult {
    // §4: Python listed every tenant's configurations (tokens masked) to any
    // analyst; here a scoped caller's customers only.
    let codes = auth
        .access(&s.ctx)
        .await?
        .scoped_customer_codes(q.customer_codes().as_deref());
    let rows = match &codes {
        Some(c) if c.is_empty() => Vec::new(),
        other => store::configs(&s.ctx.db, other.as_deref()).await?,
    };
    let configs: Vec<PyValue> = rows.iter().map(|r| r.dump()).collect();
    Ok(config_response(
        &format!("Found {} configuration(s)", configs.len()),
        PyValue::None,
        PyValue::List(configs),
    ))
}

async fn get_config(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Reader,
) -> ApiResult {
    let id = path_id("config_id", &raw)?;
    let row = config_for(&s, &auth, &id).await?;
    Ok(config_response(
        "Configuration retrieved successfully",
        row.dump(),
        PyValue::None,
    ))
}

async fn update_config(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "config_id", &raw);
    let req: ConfigUpdate = read_body(&mut v, &body, ConfigUpdate::read);
    v.finish()?;
    let row = config_for(&s, &auth, &id).await?;
    store::update_config(&s.ctx.db, row.id, &req.set).await?;
    let row = store::config(&s.ctx.db, &id)
        .await?
        .ok_or_else(|| ApiError::internal("updated configuration not found"))?;
    Ok(config_response(
        "Configuration updated successfully",
        row.dump(),
        PyValue::None,
    ))
}

async fn delete_config(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Admin,
) -> ApiResult {
    let id = path_id("config_id", &raw)?;
    let row = store::config(&s.ctx.db, &id).await?;
    let row = owned(&s, &auth.user, Object::Config, &id, row, |r| {
        &r.customer_code
    })
    .await?;
    store::delete_config(&s.ctx.db, row.id).await?;
    Ok(done("Configuration deleted successfully"))
}

// --- audits -------------------------------------------------------------------------------

async fn enabled_config(
    s: &AssessmentsState,
    auth: &Reader,
    raw: &str,
) -> Result<store::ConfigRow, ApiError> {
    let id = path_id("config_id", raw)?;
    let config = config_for(s, auth, &id).await?;
    if !config.enabled {
        return Err(ApiError::bad_request("This configuration is disabled"));
    }
    Ok(config)
}

async fn audit_from_config(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Reader,
) -> ApiResult {
    tracing::info!("Running GitHub audit from config ID: {raw}");
    let config = enabled_config(&s, &auth, &raw).await?;
    let exclusions: Vec<(String, Option<String>)> = store::enabled_exclusions(&s.ctx.db, config.id)
        .await?
        .into_iter()
        .map(|e| (e.check_id, e.resource_name))
        .collect();
    let scope = services::config_scope(&config, true).map_err(exc)?;
    let response = services::audit_from_config(&s, &config, &scope, &exclusions).await?;
    Ok(model_response(&response.dump()))
}

async fn audit_adhoc(
    State(s): State<AssessmentsState>,
    q: QueryPairs,
    WithJson(_auth, body): WithJson<Reader>,
) -> ApiResult {
    let mut v = Validator::new();
    let token = q_req_str(&q, &mut v, "github_token", StrSpec::ANY);
    let req: AuditRequest = read_body(&mut v, &body, AuditRequest::read);
    v.finish()?;
    tracing::info!(
        "Running ad-hoc GitHub audit for organization: {}",
        req.organization
    );
    let scope = Scope {
        organization: req.organization,
        include_repos: req.include_repos,
        include_workflows: req.include_workflows,
        include_members: req.include_members,
        repo_filter: req.repo_filter,
    };
    let response = services::run_audit(&s, &token, &scope).await;
    Ok(model_response(&response.dump()))
}

async fn audit_summary(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Reader,
) -> ApiResult {
    tracing::info!("Running GitHub audit summary from config ID: {raw}");
    let config = enabled_config(&s, &auth, &raw).await?;
    let scope = services::config_scope(&config, false).map_err(exc)?;
    let response = services::run_audit(&s, &config.github_token, &scope).await;
    Ok(model_response(&response.summary_response()))
}

// --- reports ------------------------------------------------------------------------------

async fn get_reports(State(s): State<AssessmentsState>, auth: Reader, q: QueryPairs) -> ApiResult {
    // `verify_optional_customer_code_access`, before the route's own query.
    let code = q.get("customer_code").map(str::to_string);
    if let Some(c) = code.as_deref().filter(|c| !c.is_empty()) {
        auth.enforce_customer(&s.ctx, c).await?;
    }
    let mut v = Validator::new();
    let customer_code = q_opt_str(&q, &mut v, "customer_code", StrSpec::ANY);
    let config_id = q.get("config_id").and_then(|raw| {
        copilot_uba::params::check_int(
            &mut v,
            &copilot_web::validate::loc("query", "config_id"),
            &PyValue::Str(raw.to_string()),
            NumSpec::ANY,
        )
    });
    let organization = q_opt_str(&q, &mut v, "organization", StrSpec::ANY);
    let status = q_opt_str(&q, &mut v, "status", StrSpec::ANY);
    let limit = q_int_or(&q, &mut v, "limit", NumSpec::range(1.0, 200.0), 50);
    let offset = q_int_or(&q, &mut v, "offset", NumSpec::ge(0.0), 0);
    v.finish()?;
    let access = auth.access(&s.ctx).await?.scoped_customer_codes(None);
    let truthy = |o: Option<String>| o.filter(|x| !x.is_empty());
    // `if config_id:` — 0 filters nothing; an id past any `int` matches
    // nothing.
    let (config_filter, impossible) = match config_id.as_deref() {
        None | Some("0") => (None, false),
        Some(text) => match text.parse::<i64>() {
            Ok(n) => (Some(n), false),
            Err(_) => (None, true),
        },
    };
    let filter = ReportFilter {
        access,
        customer_code: truthy(customer_code),
        config_id: config_filter,
        organization: truthy(organization),
        status: truthy(status),
    };
    let sees_nothing = matches!(&filter.access, Some(c) if c.is_empty()) || impossible;
    let (total, rows) = if sees_nothing {
        (0, Vec::new())
    } else {
        let total = store::count_reports(&s.ctx.db, &filter).await?;
        let offset = offset.parse::<i64>().unwrap_or(i64::MAX);
        let limit = limit.parse::<i64>().unwrap_or(50);
        (
            total,
            store::reports(&s.ctx.db, &filter, offset, limit).await?,
        )
    };
    Ok(model_response(&dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", st(format!("Found {total} report(s)"))),
        (
            "reports",
            PyValue::List(rows.iter().map(store::ReportRow::summary_dump).collect()),
        ),
        ("total_count", PyValue::Int(total.to_string())),
    ])))
}

async fn get_report(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Reader,
) -> ApiResult {
    let id = path_id("report_id", &raw)?;
    let row = store::report(&s.ctx.db, &id).await?;
    let row = owned(&s, &auth.user, Object::Report, &id, row, |r| {
        &r.customer_code
    })
    .await?;
    Ok(model_response(&dict(vec![
        ("success", PyValue::Bool(true)),
        ("message", st("Report retrieved successfully")),
        ("report", row.dump()),
    ])))
}

async fn delete_report(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Admin,
) -> ApiResult {
    let id = path_id("report_id", &raw)?;
    let row = store::report(&s.ctx.db, &id).await?;
    let row = owned(&s, &auth.user, Object::Report, &id, row, |r| {
        &r.customer_code
    })
    .await?;
    store::delete_report(&s.ctx.db, row.id).await?;
    Ok(done("Report deleted successfully"))
}

// --- exclusions ---------------------------------------------------------------------------

async fn create_exclusion(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "config_id", &raw);
    let req: ExclusionCreate = read_body(&mut v, &body, ExclusionCreate::read);
    v.finish()?;
    let config = config_for(&s, &auth, &id).await?;
    let new_id = store::insert_exclusion(&s.ctx.db, &config, &req).await?;
    let row = store::exclusion(&s.ctx.db, &new_id.to_string())
        .await?
        .ok_or_else(|| ApiError::internal("created exclusion not found"))?;
    Ok(exclusion_response(
        "Exclusion created successfully",
        row.dump(),
        PyValue::None,
    ))
}

async fn get_exclusions(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Reader,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "config_id", &raw);
    let include_expired = q_bool_or(&q, &mut v, "include_expired", false);
    v.finish()?;
    services::listing_owner(&s, &auth.user, &id).await?;
    let rows = match id.parse::<i64>() {
        Ok(n) => store::exclusions(&s.ctx.db, n, include_expired).await?,
        Err(_) => Vec::new(),
    };
    Ok(exclusion_response(
        &format!("Found {} exclusion(s)", rows.len()),
        PyValue::None,
        PyValue::List(rows.iter().map(store::ExclusionRow::dump).collect()),
    ))
}

async fn update_exclusion(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "exclusion_id", &raw);
    let req: ExclusionUpdate = read_body(&mut v, &body, ExclusionUpdate::read);
    v.finish()?;
    let row = store::exclusion(&s.ctx.db, &id).await?;
    let row = owned(&s, &auth.user, Object::Exclusion, &id, row, |r| {
        &r.customer_code
    })
    .await?;
    store::update_exclusion(&s.ctx.db, row.id, &req.set).await?;
    let row = store::exclusion(&s.ctx.db, &id)
        .await?
        .ok_or_else(|| ApiError::internal("updated exclusion not found"))?;
    Ok(exclusion_response(
        "Exclusion updated successfully",
        row.dump(),
        PyValue::None,
    ))
}

async fn delete_exclusion(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Admin,
) -> ApiResult {
    let id = path_id("exclusion_id", &raw)?;
    let row = store::exclusion(&s.ctx.db, &id).await?;
    let row = owned(&s, &auth.user, Object::Exclusion, &id, row, |r| {
        &r.customer_code
    })
    .await?;
    store::delete_exclusion(&s.ctx.db, row.id).await?;
    Ok(done("Exclusion deleted successfully"))
}

// --- baselines ----------------------------------------------------------------------------

async fn create_baseline(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Reader>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "config_id", &raw);
    let req: BaselineCreate = read_body(&mut v, &body, BaselineCreate::read);
    v.finish()?;
    let config = config_for(&s, &auth, &id).await?;
    let mut expected = req.expected_checks.clone();
    // `if baseline.baseline_report_id:` — 0 names no report.
    let report_id = req.baseline_report_id.as_deref().filter(|r| *r != "0");
    if let Some(rid) = report_id {
        let report = store::report(&s.ctx.db, rid).await?;
        let mut report = owned(&s, &auth.user, Object::Report, rid, report, |r| {
            &r.customer_code
        })
        .await
        .map_err(|e| match e {
            ApiError::Http { status, .. } if status == http::StatusCode::NOT_FOUND => {
                ApiError::not_found("Baseline report not found")
            }
            other => other,
        })?;
        if let Some(full) = report.full_report.take().filter(PyValue::truthy) {
            expected = Some(services::expected_checks(&full).map_err(exc)?);
        }
    }
    let new = store::NewBaseline {
        config: &config,
        name: &req.name,
        description: req.description.as_deref(),
        expected_checks: expected.as_ref().map(|e| {
            copilot_upstream::json::py_dumps_allow_nan(e, copilot_upstream::json::Dumps::DEFAULT)
        }),
        baseline_report_id: report_id
            .or(req.baseline_report_id.as_deref())
            .and_then(|r| r.parse().ok()),
        is_active: req.is_active,
        created_by: &req.created_by,
    };
    let new_id = store::insert_baseline(&s.ctx.db, &new).await?;
    let row = store::baseline(&s.ctx.db, &new_id.to_string())
        .await?
        .ok_or_else(|| ApiError::internal("created baseline not found"))?;
    Ok(baseline_response(
        "Baseline created successfully",
        row.dump(),
        PyValue::None,
    ))
}

async fn get_baselines(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Reader,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "config_id", &raw);
    let active_only = q_bool_or(&q, &mut v, "active_only", false);
    v.finish()?;
    services::listing_owner(&s, &auth.user, &id).await?;
    let rows = match id.parse::<i64>() {
        Ok(n) => store::baselines(&s.ctx.db, n, active_only).await?,
        Err(_) => Vec::new(),
    };
    Ok(baseline_response(
        &format!("Found {} baseline(s)", rows.len()),
        PyValue::None,
        PyValue::List(rows.iter().map(store::BaselineRow::dump).collect()),
    ))
}

async fn delete_baseline(
    State(s): State<AssessmentsState>,
    Path(raw): Path<String>,
    auth: Admin,
) -> ApiResult {
    let id = path_id("baseline_id", &raw)?;
    let row = store::baseline(&s.ctx.db, &id).await?;
    let row = owned(&s, &auth.user, Object::Baseline, &id, row, |r| {
        &r.customer_code
    })
    .await?;
    store::delete_baseline(&s.ctx.db, row.id).await?;
    Ok(done("Baseline deleted successfully"))
}

// --- the check catalog --------------------------------------------------------------------

/// `get_available_checks`' list: `(id, name, category, severity,
/// description)`.
pub const CHECKS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "org-2fa-required",
        "Two-Factor Authentication Required",
        "organization",
        "critical",
        "Checks if 2FA is required for all organization members",
    ),
    (
        "org-default-permission",
        "Default Repository Permission",
        "organization",
        "medium",
        "Checks the default permission level for new repositories",
    ),
    (
        "org-member-repo-creation",
        "Member Repository Creation",
        "organization",
        "low",
        "Checks if members can create repositories",
    ),
    (
        "org-public-repo-creation",
        "Public Repository Creation",
        "organization",
        "high",
        "Checks if members can create public repositories",
    ),
    (
        "org-verified-domains",
        "Verified Domains",
        "organization",
        "medium",
        "Checks if organization has verified domains",
    ),
    (
        "org-sso-enforcement",
        "SAML SSO Enforcement",
        "organization",
        "high",
        "Checks if SAML SSO is enforced",
    ),
    (
        "repo-branch-protection",
        "Default Branch Protection",
        "repository",
        "high",
        "Checks if default branch has protection rules",
    ),
    (
        "repo-secret-scanning",
        "Secret Scanning",
        "repository",
        "high",
        "Checks if secret scanning is enabled",
    ),
    (
        "repo-dependabot-alerts",
        "Dependabot Alerts",
        "repository",
        "high",
        "Checks if Dependabot alerts are enabled",
    ),
    (
        "repo-code-scanning",
        "Code Scanning (GHAS)",
        "repository",
        "medium",
        "Checks if code scanning is enabled",
    ),
    (
        "repo-private-vuln-reporting",
        "Private Vulnerability Reporting",
        "repository",
        "low",
        "Checks if private vulnerability reporting is enabled",
    ),
    (
        "repo-license",
        "Repository License",
        "repository",
        "low",
        "Checks if public repositories have a license",
    ),
    (
        "repo-branch-deletion",
        "Default Branch Deletion Protection",
        "repository",
        "high",
        "Checks if default branch is protected from deletion",
    ),
    (
        "actions-allowed-all",
        "Actions Permission Policy",
        "workflow",
        "medium",
        "Checks which GitHub Actions are allowed to run",
    ),
    (
        "actions-default-token-perms",
        "Default Workflow Token Permissions",
        "workflow",
        "medium",
        "Checks default GITHUB_TOKEN permissions in workflows",
    ),
];

async fn get_checks(_auth: Reader) -> ApiResult {
    let checks = CHECKS
        .iter()
        .map(|(id, name, category, severity, description)| {
            dict(vec![
                ("id", st(*id)),
                ("name", st(*name)),
                ("category", st(*category)),
                ("severity", st(*severity)),
                ("description", st(*description)),
            ])
        })
        .collect();
    Ok(model_response(&dict(vec![
        ("success", PyValue::Bool(true)),
        (
            "message",
            st("Available audit checks retrieved successfully"),
        ),
        ("checks", PyValue::List(checks)),
    ])))
}
