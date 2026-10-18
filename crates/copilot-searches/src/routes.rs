//! The 38 routes of `routes/copilot_searches.py`.
//!
//! The router is one handler for the whole prefix that routes the
//! *decoded* path as Starlette does: the routes in declaration order, each
//! path a regular expression (`{x}` is `[^/]+`, `{x:path}` is `.*`, `$` also
//! before a final newline), the first route whose path and method match
//! answers. The service's front (`copilot-standalone`) has taken the same
//! decision on the app's whole table before (a path no route has is its
//! 404, a method no route of the path has its 405), so a request reaching
//! this router is one of these routes'; anything else is the 404.
//!
//! Each handler keeps FastAPI's order: the body is read first (malformed
//! JSON is a 422 before anything), then the scope check, the path, the
//! tenancy dependency, the query and the body model.

use std::sync::OnceLock;

use axum::Router;
use axum::extract::{FromRequest, FromRequestParts, OriginalUri, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use copilot_auth::AccessScope;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::PyExc;
use copilot_web::auth::{AdminOrAnalyst, AnyPortalOrSoc, Authorized};
use copilot_web::validate::{LocPart, Validator};
use copilot_web::{ApiError, JsonBody, QueryPairs, WithJson};
use copilot_yaml::Value;
use http::{Method, StatusCode};
use num_bigint_dig::BigInt;
use regex::Regex;
use serde_json::{Map, Value as Json};

use crate::caches::{self, Kind};
use crate::catalog::{self, Snapshot};
use crate::py::{self, s};
use crate::rules::{self, Filters};
use crate::services::{self, ExecuteRequest, ProvisionRequest};
use crate::{SearchesState, backtest, custom_repos, linter, mitre, pyd, schema};

/// The prefix the router serves.
pub const PREFIX: &str = "/api/copilot_searches";

/// The router (full paths).
pub fn router(st: SearchesState) -> Router {
    Router::new()
        .route(PREFIX, any(dispatch))
        .route(&format!("{PREFIX}/{{*rest}}"), any(dispatch))
        .with_state(st)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum R {
    List,
    Linux,
    Windows,
    Powershell,
    Cve,
    Stats,
    Categories,
    ById,
    ByName,
    ByIds,
    MitreCoverage,
    MitreRefresh,
    MitreTechnique,
    Refresh,
    Execute,
    Graylog,
    ProvisionCheck,
    ProvisionBulk,
    Provision,
    CatalogStats,
    Stories,
    Story,
    WazuhRules,
    WazuhRule,
    Gaps,
    Gap,
    Frameworks,
    Compliance,
    ComplianceGroup,
    LogTest,
    Validate,
    Backtest,
    CustomRepos,
    CustomRepoGet,
    CustomRepoPut,
    CustomRepoDelete,
    CustomRepoTest,
    Publish,
}

/// The routes, in declaration order.
const ROUTES: &[(&str, &str, R)] = &[
    ("GET", "", R::List),
    ("GET", "/linux", R::Linux),
    ("GET", "/windows", R::Windows),
    ("GET", "/powershell", R::Powershell),
    ("GET", "/cve", R::Cve),
    ("GET", "/stats", R::Stats),
    ("GET", "/categories", R::Categories),
    ("GET", "/id/{rule_id}", R::ById),
    ("GET", "/name/{rule_name:path}", R::ByName),
    ("POST", "/by-ids", R::ByIds),
    ("GET", "/mitre/coverage", R::MitreCoverage),
    ("POST", "/mitre/refresh", R::MitreRefresh),
    ("GET", "/mitre/{technique_id}", R::MitreTechnique),
    ("POST", "/refresh", R::Refresh),
    ("POST", "/execute", R::Execute),
    ("POST", "/graylog", R::Graylog),
    ("POST", "/provision/graylog/check", R::ProvisionCheck),
    ("POST", "/provision/graylog/bulk", R::ProvisionBulk),
    ("POST", "/provision/graylog", R::Provision),
    ("GET", "/catalog/stats", R::CatalogStats),
    ("GET", "/catalog/stories", R::Stories),
    ("GET", "/catalog/stories/{story_name:path}", R::Story),
    ("GET", "/catalog/wazuh-rules", R::WazuhRules),
    ("GET", "/catalog/wazuh-rules/{rule_id}", R::WazuhRule),
    ("GET", "/catalog/coverage-gaps", R::Gaps),
    ("GET", "/catalog/coverage-gaps/{technique_id}", R::Gap),
    ("GET", "/catalog/compliance/frameworks", R::Frameworks),
    ("GET", "/catalog/compliance/{framework}", R::Compliance),
    (
        "GET",
        "/catalog/compliance/{framework}/{control:path}",
        R::ComplianceGroup,
    ),
    ("POST", "/catalog/wazuh-rules/test", R::LogTest),
    ("POST", "/validate", R::Validate),
    ("POST", "/backtest", R::Backtest),
    ("GET", "/custom-repos", R::CustomRepos),
    ("GET", "/custom-repos/{customer_code}", R::CustomRepoGet),
    ("PUT", "/custom-repos/{customer_code}", R::CustomRepoPut),
    (
        "DELETE",
        "/custom-repos/{customer_code}",
        R::CustomRepoDelete,
    ),
    ("POST", "/custom-repos/test", R::CustomRepoTest),
    ("POST", "/publish", R::Publish),
];

/// A route path as Starlette compiles it, `$` included.
fn compile(path: &str) -> Option<Regex> {
    let mut re = String::from("^");
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        re.push_str(&regex::escape(&rest[..open]));
        let close = rest[open..].find('}')? + open;
        let param = &rest[open + 1..close];
        re.push_str(if param.ends_with(":path") {
            "([^\\n]*)"
        } else {
            "([^/]+)"
        });
        rest = &rest[close + 1..];
    }
    re.push_str(&regex::escape(rest));
    re.push_str("\\n?\\z");
    Regex::new(&re).ok()
}

fn compiled() -> &'static [Option<Regex>] {
    static RES: OnceLock<Vec<Option<Regex>>> = OnceLock::new();
    RES.get_or_init(|| ROUTES.iter().map(|(_, p, _)| compile(p)).collect())
}

/// The full match for `method path`, if a route takes it.
fn find(method: &Method, path: &str) -> Option<(R, Vec<String>)> {
    for ((m, _, route), re) in ROUTES.iter().zip(compiled()) {
        let Some(re) = re else {
            continue;
        };
        let Some(caps) = re.captures(path) else {
            continue;
        };
        if method.as_str() != *m {
            continue;
        }
        let params = caps
            .iter()
            .skip(1)
            .map(|c| c.map_or_else(String::new, |m| m.as_str().to_string()))
            .collect();
        return Some((*route, params));
    }
    None
}

/// `urllib.parse.unquote(path)`: `%XX` runs decoded as UTF-8, undecodable
/// bytes replaced.
pub fn unquote(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn dispatch(State(st): State<SearchesState>, req: Request) -> Response {
    let raw = req
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| req.uri().path().to_string(), |o| o.0.path().to_string());
    let decoded = unquote(&raw);
    let found = decoded
        .strip_prefix(PREFIX)
        .and_then(|rel| find(req.method(), rel));
    match found {
        Some((route, params)) => handle(st, route, params, req).await,
        None => ApiError::RouteNotFound.into_response(),
    }
}

type Res = Result<Response, ApiError>;

async fn handle(st: SearchesState, route: R, params: Vec<String>, req: Request) -> Response {
    let p = |i: usize| params.get(i).cloned().unwrap_or_default();
    let out: Res = match route {
        R::List => list_rules(&st, req, None).await,
        R::Linux => list_rules(&st, req, Some("linux")).await,
        R::Windows => list_rules(&st, req, Some("windows")).await,
        R::Powershell => list_rules(&st, req, Some("powershell")).await,
        R::Cve => list_cve(&st, req).await,
        R::Stats => stats(&st, req).await,
        R::Categories => categories(&st, req).await,
        R::ById => rule_by_id(&st, req, &p(0)).await,
        R::ByName => rule_by_name(&st, req, &p(0)).await,
        R::ByIds => by_ids(&st, req).await,
        R::MitreCoverage => mitre_coverage(&st, req).await,
        R::MitreRefresh => mitre_refresh(&st, req).await,
        R::MitreTechnique => mitre_technique(&st, req, &p(0)).await,
        R::Refresh => refresh(&st, req).await,
        R::Execute => execute(&st, req).await,
        R::Graylog => graylog_query(&st, req).await,
        R::ProvisionCheck => provision_check(&st, req).await,
        R::ProvisionBulk => provision_bulk(&st, req).await,
        R::Provision => provision(&st, req).await,
        R::CatalogStats => catalog_stats(&st, req).await,
        R::Stories => stories(&st, req).await,
        R::Story => story(&st, req, &p(0)).await,
        R::WazuhRules => wazuh_rules(&st, req).await,
        R::WazuhRule => wazuh_rule(&st, req, &p(0)).await,
        R::Gaps => gaps(&st, req).await,
        R::Gap => gap(&st, req, &p(0)).await,
        R::Frameworks => frameworks(&st, req).await,
        R::Compliance => compliance(&st, req, &p(0)).await,
        R::ComplianceGroup => compliance_group(&st, req, &p(0), &p(1)).await,
        R::LogTest => log_test(&st, req).await,
        R::Validate => validate(&st, req).await,
        R::Backtest => run_backtest(&st, req).await,
        R::CustomRepos => custom_repos_list(&st, req).await,
        R::CustomRepoGet => custom_repo_get(&st, req, &p(0)).await,
        R::CustomRepoPut => custom_repo_put(&st, req, &p(0)).await,
        R::CustomRepoDelete => custom_repo_delete(&st, req, &p(0)).await,
        R::CustomRepoTest => custom_repo_test(&st, req).await,
        R::Publish => publish(&st, req).await,
    };
    out.unwrap_or_else(IntoResponse::into_response)
}

// --- helpers ------------------------------------------------------------------------------

/// `200` with pydantic-core's JSON of a dump.
fn json(v: &Value) -> Res {
    let text = v
        .to_pydantic_json()
        .map_err(|e| ApiError::internal(format!("PydanticSerializationError: {e}")))?;
    Ok((
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        text,
    )
        .into_response())
}

fn model(m: &'static pyd::Model, v: &Value) -> Res {
    let dump = pyd::build(m, v).map_err(ApiError::from)?;
    json(&dump)
}

fn exc(e: PyExc) -> ApiError {
    e.unhandled()
}

fn http(status: u16, detail: impl Into<String>) -> ApiError {
    PyExc::http(status, detail).unhandled()
}

async fn auth<S: copilot_web::auth::ScopeSet>(
    st: &SearchesState,
    req: Request,
) -> Result<(Authorized<S>, QueryPairs), ApiError> {
    let (mut parts, _body) = req.into_parts();
    let user = Authorized::<S>::from_request_parts(&mut parts, st).await?;
    Ok((user, QueryPairs::parse(parts.uri.query())))
}

async fn auth_json<S: copilot_web::auth::ScopeSet>(
    st: &SearchesState,
    req: Request,
) -> Result<(Authorized<S>, JsonBody), Box<Response>> {
    let WithJson(user, body) = WithJson::<Authorized<S>>::from_request(req, st)
        .await
        .map_err(Box::new)?;
    Ok((user, body))
}

fn qloc(name: &str) -> Vec<LocPart> {
    vec![LocPart::Key("query".into()), LocPart::Key(name.into())]
}

fn q_enum(q: &QueryPairs, v: &mut Validator, name: &str, allowed: &[&str]) -> Option<String> {
    let raw = q.get(name)?;
    v.check_enum(&qloc(name), &Json::String(raw.into()), allowed)
}

fn q_bool(q: &QueryPairs, v: &mut Validator, name: &str) -> Option<bool> {
    let raw = q.get(name)?;
    match raw.to_ascii_lowercase().as_str() {
        "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
        "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
        _ => {
            v.push(
                "bool_parsing",
                qloc(name),
                "Input should be a valid boolean, unable to interpret input",
            );
            None
        }
    }
}

/// Pydantic's `str` → `int` (whitespace, a sign, `_` between digits, a zero
/// fraction).
pub fn parse_int(t: &str) -> Option<BigInt> {
    let t = t.trim_matches(char::is_whitespace);
    let (neg, digits) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let digits = match digits.split_once('.') {
        Some((int, frac)) if frac.chars().all(|c| c == '0') => int,
        Some(_) => return None,
        None => digits,
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.chars().all(|c| c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    let n: BigInt = digits.replace('_', "").parse().ok()?;
    Some(if neg { -n } else { n })
}

fn check_int_text(
    v: &mut Validator,
    loc: Vec<LocPart>,
    raw: &str,
    ge: Option<i64>,
    le: Option<i64>,
) -> Option<i64> {
    let Some(n) = parse_int(raw) else {
        v.push(
            "int_parsing",
            loc,
            "Input should be a valid integer, unable to parse string as an integer",
        );
        return None;
    };
    if let Some(ge) = ge.filter(|g| n < BigInt::from(*g)) {
        v.push(
            "greater_than_equal",
            loc,
            format!("Input should be greater than or equal to {ge}"),
        );
        return None;
    }
    if let Some(le) = le.filter(|l| n > BigInt::from(*l)) {
        v.push(
            "less_than_equal",
            loc,
            format!("Input should be less than or equal to {le}"),
        );
        return None;
    }
    num_traits::ToPrimitive::to_i64(&n)
}

fn q_int(
    q: &QueryPairs,
    v: &mut Validator,
    name: &str,
    ge: Option<i64>,
    le: Option<i64>,
    default: i64,
) -> i64 {
    match q.get(name) {
        None => default,
        Some(raw) => check_int_text(v, qloc(name), raw, ge, le).unwrap_or(default),
    }
}

fn q_opt_int(
    q: &QueryPairs,
    v: &mut Validator,
    name: &str,
    ge: Option<i64>,
    le: Option<i64>,
) -> Option<i64> {
    let raw = q.get(name)?;
    check_int_text(v, qloc(name), raw, ge, le)
}

fn q_str(q: &QueryPairs, name: &str) -> Option<String> {
    q.get(name).map(str::to_string)
}

fn finish(v: Validator) -> Result<(), ApiError> {
    v.finish()
}

fn snapshot_parts(st: &SearchesState, scope: &AccessScope) -> Parts {
    Parts {
        rules: caches::visible_rules(st, scope),
        mitre: st.caches.mitre.get(),
        wazuh: st.caches.wazuh.get(),
        firing: st.caches.firing.get(),
    }
}

/// The caches at the time of a request.
struct Parts {
    rules: std::sync::Arc<rules::RuleSet>,
    mitre: std::sync::Arc<mitre::Matrix>,
    wazuh: std::sync::Arc<caches::WazuhRules>,
    firing: std::sync::Arc<caches::FiringCache>,
}

impl Parts {
    fn snapshot(&self) -> Snapshot<'_> {
        Snapshot {
            rules: self.rules.all(),
            rules_last_refresh: self.rules.last_refresh,
            matrix: &self.mitre,
            wazuh: &self.wazuh.rules,
            wazuh_last_refresh: self.wazuh.last_refresh,
            wazuh_unavailable: self.wazuh.unavailable.as_deref(),
            firing: &self.firing.stats,
            firing_last_refresh: self.firing.last_refresh,
            firing_unavailable: self.firing.unavailable.as_deref(),
        }
    }
}

fn trigger(st: &SearchesState, kinds: &[Kind]) {
    for k in kinds {
        caches::ensure_fresh_nonblocking(st, *k);
    }
}

// --- rule lists ---------------------------------------------------------------------------

/// `get_rules_list(...)` → the `RuleListResponse` dict.
async fn rules_list(
    st: &SearchesState,
    scope: &AccessScope,
    platform: Option<String>,
    f: Filters,
    skip: i64,
    limit: i64,
) -> Result<Value, PyExc> {
    caches::ensure_loaded(st, Kind::Rules).await?;
    let set = caches::visible_rules(st, scope);
    if let Some(category) = &f.category {
        let known: Vec<String> = set
            .categories()
            .iter()
            .map(|c| copilot_jinja::unicode::lower(&c.value))
            .collect();
        if !known.contains(&copilot_jinja::unicode::lower(category)) {
            return Err(PyExc::ValueError(format!(
                "Unknown category '{category}'. See GET /copilot_searches/categories for the \
                 available folders."
            )));
        }
    }
    let mut filters = f.clone();
    filters.platform = platform.clone().filter(|p| p != "all");
    let mut filtered = rules::filter_rules(set.all(), &filters)?;
    rules::sort_by_name(&mut filtered)?;
    let total_filtered = filtered.len();
    let start = usize::try_from(skip).unwrap_or(0).min(filtered.len());
    let end = start
        .saturating_add(usize::try_from(limit).unwrap_or(0))
        .min(filtered.len());
    let mut summaries = Vec::new();
    for rule in &filtered[start..end] {
        summaries.push(rules::to_summary(rule)?);
    }
    Ok(py::dict(vec![
        ("total", py::int(set.rules_count() as i64)),
        ("filtered", py::int(total_filtered as i64)),
        ("platform", s(platform.unwrap_or_else(|| "all".into()))),
        ("category", py::opt_str(f.category)),
        ("rules", py::list(summaries)),
        ("success", Value::Bool(true)),
        ("message", s("Rules fetched successfully")),
    ]))
}

fn read_filters(q: &QueryPairs, v: &mut Validator, with_category: bool) -> Filters {
    let mut f = Filters::default();
    if with_category {
        f.category = q_str(q, "category");
    }
    f.status = q_enum(q, v, "status", schema::STATUSES);
    f.severity = q_enum(q, v, "severity", schema::SEVERITIES);
    f.mitre_id = q_str(q, "mitre_id");
    f.search = q_str(q, "search");
    f.has_graylog = q_bool(q, v, "has_graylog");
    f
}

async fn list_rules(st: &SearchesState, req: Request, fixed: Option<&str>) -> Res {
    let (user, q) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    let mut v = Validator::new();
    let platform = match fixed {
        Some(p) => Some(p.to_string()),
        None => {
            Some(q_enum(&q, &mut v, "platform", schema::PLATFORMS).unwrap_or_else(|| "all".into()))
        }
    };
    let mut f = if fixed.is_none() {
        let mut f = Filters {
            category: q_str(&q, "category"),
            ..Filters::default()
        };
        let rest = read_filters(&q, &mut v, false);
        f.status = rest.status;
        f.severity = rest.severity;
        f.mitre_id = rest.mitre_id;
        f.search = rest.search;
        f.has_graylog = rest.has_graylog;
        f.provenance = q_str(&q, "provenance");
        f
    } else {
        read_filters(&q, &mut v, false)
    };
    let skip = q_int(&q, &mut v, "skip", Some(0), None, 0);
    let limit = q_int(&q, &mut v, "limit", Some(1), Some(500), 100);
    finish(v)?;
    if fixed.is_some() {
        f.category = None;
    }
    let out = rules_list(st, &scope, platform, f, skip, limit)
        .await
        .map_err(exc)?;
    json(&out)
}

async fn list_cve(st: &SearchesState, req: Request) -> Res {
    let (user, q) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    let mut v = Validator::new();
    let f = read_filters(&q, &mut v, false);
    let skip = q_int(&q, &mut v, "skip", Some(0), None, 0);
    let limit = q_int(&q, &mut v, "limit", Some(1), Some(500), 100);
    finish(v)?;
    let full = rules_list(st, &scope, Some("all".into()), f, 0, 500)
        .await
        .map_err(exc)?;
    let cve_only: Vec<Value> = full
        .get("rules")
        .and_then(Value::as_list)
        .unwrap_or_default()
        .iter()
        .filter(|r| r.get("cve").is_some_and(Value::truthy))
        .cloned()
        .collect();
    let start = usize::try_from(skip).unwrap_or(0).min(cve_only.len());
    let end = start
        .saturating_add(usize::try_from(limit).unwrap_or(0))
        .min(cve_only.len());
    json(&py::dict(vec![
        ("total", full.get("total").cloned().unwrap_or(Value::None)),
        ("filtered", py::int(cve_only.len() as i64)),
        ("platform", s("all")),
        ("category", Value::None),
        ("rules", py::list(cve_only[start..end].to_vec())),
        ("success", Value::Bool(true)),
        ("message", s("Rules fetched successfully")),
    ]))
}

async fn stats(st: &SearchesState, req: Request) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    caches::ensure_loaded(st, Kind::Rules).await.map_err(exc)?;
    let set = caches::visible_rules(st, &scope);
    json(&rules::stats(&set).map_err(exc)?)
}

async fn categories(st: &SearchesState, req: Request) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    caches::ensure_loaded(st, Kind::Rules).await.map_err(exc)?;
    let set = caches::visible_rules(st, &scope);
    json(&py::dict(vec![
        (
            "categories",
            py::list(
                set.categories()
                    .iter()
                    .map(rules::Category::to_value)
                    .collect(),
            ),
        ),
        ("success", Value::Bool(true)),
        ("message", s("Categories fetched successfully")),
    ]))
}

fn detail_response(detail: Value) -> Value {
    py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s("Rule fetched successfully")),
        ("rule", detail),
    ])
}

async fn rule_by_id(st: &SearchesState, req: Request, rule_id: &str) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    caches::ensure_loaded(st, Kind::Rules).await.map_err(exc)?;
    let set = caches::visible_rules(st, &scope);
    let Some(rule) = set.by_id(rule_id) else {
        return Err(http(404, format!("Rule with ID '{rule_id}' not found")));
    };
    json(&detail_response(rules::to_detail(rule).map_err(exc)?))
}

async fn rule_by_name(st: &SearchesState, req: Request, name: &str) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    caches::ensure_loaded(st, Kind::Rules).await.map_err(exc)?;
    let set = caches::visible_rules(st, &scope);
    let Some(rule) = set.by_name(name).map_err(exc)? else {
        return Err(http(404, format!("Rule with name '{name}' not found")));
    };
    json(&detail_response(rules::to_detail(rule).map_err(exc)?))
}

/// `list[str]` with `min_length` / `max_length`.
fn str_list_field(
    v: &mut Validator,
    obj: &Map<String, Json>,
    at: &[LocPart],
    name: &str,
    required: bool,
    min: Option<usize>,
    max: Option<usize>,
) -> Vec<String> {
    let mut loc = at.to_vec();
    loc.push(LocPart::Key(name.into()));
    let Some(raw) = obj.get(name) else {
        if required {
            v.missing(loc);
        }
        return Vec::new();
    };
    let before = v.errors().len();
    let items = v.str_items(raw, &loc);
    if v.errors().len() != before {
        return items;
    }
    let n = items.len();
    if let Some(min) = min.filter(|m| n < *m) {
        v.push(
            "too_short",
            loc.clone(),
            format!(
                "List should have at least {min} item{} after validation, not {n}",
                if min == 1 { "" } else { "s" }
            ),
        );
    }
    if let Some(max) = max.filter(|m| n > *m) {
        v.push(
            "too_long",
            loc,
            format!(
                "List should have at most {max} item{} after validation, not {n}",
                if max == 1 { "" } else { "s" }
            ),
        );
    }
    items
}

async fn by_ids(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AnyPortalOrSoc>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let scope = user.access(&st.ctx).await?.clone();
    let ids = body.model(|v, obj, at| str_list_field(v, obj, at, "ids", true, None, Some(500)))?;
    let (found, missing) = if ids.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        caches::ensure_loaded(st, Kind::Rules).await.map_err(exc)?;
        let set = caches::visible_rules(st, &scope);
        let mut found = Vec::new();
        let mut missing = Vec::new();
        for id in &ids {
            match set.by_id(id) {
                Some(rule) => found.push(rules::to_summary(rule).map_err(exc)?),
                None => missing.push(s(id.clone())),
            }
        }
        (found, missing)
    };
    json(&py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s("Rules fetched successfully")),
        ("rules", py::list(found)),
        ("missing", py::list(missing)),
    ]))
}

// --- MITRE --------------------------------------------------------------------------------

async fn mitre_coverage(st: &SearchesState, req: Request) -> Res {
    let (user, q) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    let mut v = Validator::new();
    let platform =
        q_enum(&q, &mut v, "platform", schema::PLATFORMS).unwrap_or_else(|| "all".into());
    let category = q_str(&q, "category");
    let severity = q_enum(&q, &mut v, "severity", schema::SEVERITIES);
    let status = q_enum(&q, &mut v, "status", schema::STATUSES);
    let has_graylog = q_bool(&q, &mut v, "has_graylog");
    let search = q_str(&q, "search");
    finish(v)?;
    let f = Filters {
        platform: Some(platform).filter(|p| p != "all"),
        category,
        status,
        severity,
        mitre_id: None,
        search,
        has_graylog,
        provenance: None,
    };
    let outcome: Result<Value, PyExc> = async {
        caches::ensure_loaded(st, Kind::Mitre).await?;
        caches::ensure_loaded(st, Kind::Rules).await?;
        let matrix = st.caches.mitre.get();
        let set = caches::visible_rules(st, &scope);
        let out = mitre::coverage(&matrix, set.all(), set.last_refresh, &f)?;
        pyd::build(&schema::MITRE_COVERAGE_RESPONSE, &out)
    }
    .await;
    match outcome {
        Ok(v) => json(&v),
        Err(e) => Err(http(
            503,
            format!("Failed to build MITRE coverage: {}", e.display()),
        )),
    }
}

async fn mitre_refresh(st: &SearchesState, req: Request) -> Res {
    let _ = auth::<AdminOrAnalyst>(st, req).await?;
    match caches::refresh_mitre(st).await {
        Ok(()) => {
            let m = st.caches.mitre.get();
            json(&py::dict(vec![
                ("success", Value::Bool(true)),
                ("message", s("MITRE matrix refreshed")),
                ("tactics", py::int(m.tactics.len() as i64)),
                ("techniques", py::int(m.techniques.len() as i64)),
            ]))
        }
        Err(e) => Err(http(
            503,
            format!("Failed to refresh MITRE matrix: {}", e.display()),
        )),
    }
}

async fn mitre_technique(st: &SearchesState, req: Request, technique_id: &str) -> Res {
    let (user, q) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    let mut v = Validator::new();
    let platform =
        q_enum(&q, &mut v, "platform", schema::PLATFORMS).unwrap_or_else(|| "all".into());
    let category = q_str(&q, "category");
    finish(v)?;
    let f = Filters {
        category,
        mitre_id: Some(technique_id.to_string()),
        ..Filters::default()
    };
    let out = rules_list(st, &scope, Some(platform), f, 0, 100)
        .await
        .map_err(exc)?;
    json(&out)
}

async fn refresh(st: &SearchesState, req: Request) -> Res {
    let _ = auth::<AdminOrAnalyst>(st, req).await?;
    match caches::refresh_rules(st).await {
        Ok(n) => json(&py::dict(vec![
            ("success", Value::Bool(true)),
            ("message", s("Rules cache refreshed successfully")),
            ("rules_loaded", py::int(n as i64)),
            ("timestamp", rules::naive_datetime(caches::utcnow())),
        ])),
        Err(e) => Err(http(
            503,
            format!("Failed to refresh rules: {}", e.display()),
        )),
    }
}

// --- search and Graylog -------------------------------------------------------------------

fn params_field(
    v: &mut Validator,
    obj: &Map<String, Json>,
    at: &[LocPart],
) -> Vec<(String, Value)> {
    match obj.get("parameters") {
        None => Vec::new(),
        Some(Json::Object(map)) => map
            .iter()
            .map(|(k, val)| (k.clone(), py::from_json(val)))
            .collect(),
        Some(_) => {
            let mut loc = at.to_vec();
            loc.push(LocPart::Key("parameters".into()));
            v.push("dict_type", loc, "Input should be a valid dictionary");
            Vec::new()
        }
    }
}

async fn execute(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AdminOrAnalyst>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let scope = user.access(&st.ctx).await?.clone();
    let request = body.model(|v, obj, at| {
        let rule_id = v.req_str(obj, at, "rule_id", copilot_web::validate::StrRules::any());
        let index_pattern = v.req_str(
            obj,
            at,
            "index_pattern",
            copilot_web::validate::StrRules::any(),
        );
        let parameters = params_field(v, obj, at);
        let size = v.opt_int(
            obj,
            at,
            "size",
            copilot_web::validate::IntRules {
                ge: Some(1),
                le: Some(10_000),
            },
        );
        ExecuteRequest {
            rule_id,
            index_pattern,
            parameters,
            size,
        }
    })?;
    match services::execute_rule_search(st, &scope, &request).await {
        Ok(v) => json(&v),
        Err(e) if e.is_value_error() => Err(http(400, e.text())),
        Err(e) => Err(http(
            500,
            format!("Search execution failed: {}", e.display()),
        )),
    }
}

async fn graylog_query(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AdminOrAnalyst>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let scope = user.access(&st.ctx).await?.clone();
    let (rule_id, parameters) = body.model(|v, obj, at| {
        (
            v.req_str(obj, at, "rule_id", copilot_web::validate::StrRules::any()),
            params_field(v, obj, at),
        )
    })?;
    match services::generate_graylog_query(st, &scope, &rule_id, &parameters).await {
        Ok(v) => json(&v),
        Err(e) if e.is_value_error() => Err(http(400, e.text())),
        Err(e) => Err(http(
            500,
            format!("Graylog query generation failed: {}", e.display()),
        )),
    }
}

async fn provision_check(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AnyPortalOrSoc>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let scope = user.access(&st.ctx).await?.clone();
    let ids = body.model(|v, obj, at| str_list_field(v, obj, at, "ids", true, None, Some(500)))?;
    let (titles, warning) = match services::event_definition_titles(st).await {
        Ok(t) => (t, None),
        Err(e) => {
            let w = format!("Could not reach Graylog: {}", e.display());
            tracing::warn!("check-provisioning: {w}");
            (Vec::new(), Some(w))
        }
    };
    caches::ensure_loaded(st, Kind::Rules).await.map_err(exc)?;
    let set = caches::visible_rules(st, &scope);
    let mut provisioned: Vec<(Value, Value)> = Vec::new();
    for id in &ids {
        let Some(rule) = set.by_id(id) else {
            continue;
        };
        let value = if warning.is_some() {
            false
        } else {
            let name = py::get(rule, "name", s("")).map_err(exc)?;
            let title = py::upper(&name).map_err(exc)?.replace(' ', " - ");
            titles.contains(&title)
        };
        match provisioned.iter_mut().find(|(k, _)| k.as_str() == Some(id)) {
            Some(slot) => slot.1 = Value::Bool(value),
            None => provisioned.push((s(id.clone()), Value::Bool(value))),
        }
    }
    json(&py::dict(vec![
        ("success", Value::Bool(true)),
        ("provisioned", Value::Dict(std::sync::Arc::new(provisioned))),
        ("warning", py::opt_str(warning)),
    ]))
}

fn int_rule(
    v: &mut Validator,
    obj: &Map<String, Json>,
    at: &[LocPart],
    name: &str,
    ge: i64,
    le: i64,
    default: i64,
) -> i64 {
    match obj.get(name) {
        None => default,
        Some(val) => {
            let mut loc = at.to_vec();
            loc.push(LocPart::Key(name.into()));
            v.check_int(
                &loc,
                val,
                copilot_web::validate::IntRules {
                    ge: Some(ge),
                    le: Some(le),
                },
            )
            .unwrap_or(default)
        }
    }
}

fn streams_field(v: &mut Validator, obj: &Map<String, Json>, at: &[LocPart]) -> Vec<String> {
    match obj.get("streams") {
        None => Vec::new(),
        Some(raw) => {
            let mut loc = at.to_vec();
            loc.push(LocPart::Key("streams".into()));
            v.str_items(raw, &loc)
        }
    }
}

async fn provision_bulk(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AdminOrAnalyst>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let scope = user.access(&st.ctx).await?.clone();
    let (rule_ids, base) = body.model(|v, obj, at| {
        let ids = str_list_field(v, obj, at, "rule_ids", true, Some(1), Some(200));
        let base = ProvisionRequest {
            rule_id: String::new(),
            search_within_seconds: int_rule(v, obj, at, "search_within_seconds", 60, 86400, 300),
            execute_every_seconds: int_rule(v, obj, at, "execute_every_seconds", 60, 86400, 300),
            streams: streams_field(v, obj, at),
            custom_title: None,
            priority: int_rule(v, obj, at, "priority", 1, 3, 2),
            event_limit: int_rule(v, obj, at, "event_limit", 1, 10_000, 1000),
        };
        (ids, base)
    })?;
    let mut titles = match services::event_definition_titles(st).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                "bulk-provision: could not list event definitions: {}",
                e.display()
            );
            Vec::new()
        }
    };
    let mut results: Vec<Value> = Vec::new();
    let result = |rule_id: &str,
                  name: Option<Value>,
                  title: Option<String>,
                  status: &str,
                  reason: Option<String>| {
        py::dict(vec![
            ("rule_id", s(rule_id)),
            ("rule_name", name.unwrap_or(Value::None)),
            ("alert_title", py::opt_str(title)),
            ("status", s(status)),
            ("reason", py::opt_str(reason)),
        ])
    };
    for rule_id in &rule_ids {
        let outcome: Result<Value, PyExc> = async {
            caches::ensure_loaded(st, Kind::Rules).await?;
            let set = caches::visible_rules(st, &scope);
            let Some(raw) = set.by_id(rule_id) else {
                return Ok(result(
                    rule_id,
                    None,
                    None,
                    "failed",
                    Some("Rule not found".into()),
                ));
            };
            let detail = rules::to_detail(raw)?;
            let name = detail.get("name").cloned().unwrap_or(Value::None);
            let has_query = match detail.get("graylog") {
                Some(g @ Value::Dict(_)) => g.get("query").is_some_and(Value::truthy),
                _ => false,
            };
            if !has_query {
                return Ok(result(
                    rule_id,
                    Some(name),
                    None,
                    "skipped",
                    Some("Rule has no Graylog query".into()),
                ));
            }
            let title = py::upper(&name)?.replace(' ', " - ");
            if titles.contains(&title) {
                return Ok(result(
                    rule_id,
                    Some(name),
                    Some(title),
                    "skipped",
                    Some("Event definition with this title already exists in Graylog".into()),
                ));
            }
            let single = ProvisionRequest {
                rule_id: rule_id.clone(),
                ..base.clone()
            };
            services::provision_from_rule(st, &scope, &single).await?;
            titles.push(title.clone());
            Ok(result(
                rule_id,
                Some(name),
                Some(title),
                "provisioned",
                None,
            ))
        }
        .await;
        match outcome {
            Ok(r) => results.push(r),
            Err(e) => {
                tracing::error!("bulk-provision: rule '{rule_id}' failed: {}", e.display());
                results.push(result(rule_id, None, None, "failed", Some(e.display())));
            }
        }
    }
    let count = |status: &str| {
        results
            .iter()
            .filter(|r| r.get("status").and_then(Value::as_str) == Some(status))
            .count() as i64
    };
    let (p, sk, fl) = (count("provisioned"), count("skipped"), count("failed"));
    json(&py::dict(vec![
        ("success", Value::Bool(fl == 0)),
        (
            "message",
            s(format!("Provisioned {p}, skipped {sk}, failed {fl}")),
        ),
        ("provisioned_count", py::int(p)),
        ("skipped_count", py::int(sk)),
        ("failed_count", py::int(fl)),
        ("results", py::list(results)),
    ]))
}

async fn provision(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AdminOrAnalyst>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let scope = user.access(&st.ctx).await?.clone();
    let request = body.model(|v, obj, at| ProvisionRequest {
        rule_id: v.req_str(obj, at, "rule_id", copilot_web::validate::StrRules::any()),
        search_within_seconds: int_rule(v, obj, at, "search_within_seconds", 60, 86400, 300),
        execute_every_seconds: int_rule(v, obj, at, "execute_every_seconds", 60, 86400, 300),
        streams: streams_field(v, obj, at),
        custom_title: v.opt_str(
            obj,
            at,
            "custom_title",
            copilot_web::validate::StrRules::any(),
        ),
        priority: int_rule(v, obj, at, "priority", 1, 3, 2),
        event_limit: int_rule(v, obj, at, "event_limit", 1, 10_000, 1000),
    })?;
    let outcome: Result<Value, PyExc> = async {
        caches::ensure_loaded(st, Kind::Rules).await?;
        let set = caches::visible_rules(st, &scope);
        let Some(raw) = set.by_id(&request.rule_id) else {
            return Err(PyExc::http(
                404,
                format!("Rule with ID '{}' not found", request.rule_id),
            ));
        };
        let detail = rules::to_detail(raw)?;
        drop(set);
        if !matches!(detail.get("graylog"), Some(Value::Dict(_))) {
            return Err(PyExc::http(
                400,
                format!(
                    "Rule '{}' does not contain a Graylog query",
                    request.rule_id
                ),
            ));
        }
        let title = match request.custom_title.as_deref().filter(|t| !t.is_empty()) {
            Some(t) => t.to_string(),
            None => {
                let name = detail.get("name").cloned().unwrap_or(Value::None);
                py::upper(&name)?.replace(' ', " - ")
            }
        };
        let titles = match copilot_graylog::services::event_definitions(&st.graylog).await {
            Ok(dump) => {
                let defs = copilot_upstream::py::get(&dump, "event_definitions")?
                    .cloned()
                    .unwrap_or(PyValue::List(Vec::new()));
                copilot_upstream::py::iterate(&defs)?
                    .iter()
                    .filter_map(|d| d.get("title").map(PyValue::py_str))
                    .collect::<Vec<_>>()
            }
            Err(e) => return Err(e),
        };
        if titles.contains(&title) {
            return Err(PyExc::http(
                400,
                format!("Event definition '{title}' already exists in Graylog"),
            ));
        }
        services::provision_from_rule(st, &scope, &request).await
    }
    .await;
    match outcome {
        Ok(v) => json(&v),
        Err(e @ PyExc::Http(..)) => Err(e.unhandled()),
        Err(e) if e.is_value_error() => Err(http(400, e.text())),
        Err(e) => Err(http(
            500,
            format!("Failed to provision Graylog alert: {}", e.display()),
        )),
    }
}

// --- the catalog --------------------------------------------------------------------------

async fn catalog_stats(st: &SearchesState, req: Request) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    trigger(st, &[Kind::Rules, Kind::Mitre, Kind::Wazuh]);
    let parts = snapshot_parts(st, &scope);
    let outcome = catalog::catalog_stats(&parts.snapshot());
    match outcome {
        Ok(stats) => {
            let mut items: Vec<(Value, Value)> = vec![
                (s("success"), Value::Bool(true)),
                (s("message"), s("Catalog stats retrieved successfully")),
            ];
            let get = |k: &str| stats.get(k).cloned().unwrap_or(Value::None);
            for k in [
                "detection_count",
                "story_count",
                "product_count",
                "data_source_count",
                "tactic_count",
                "last_refresh",
            ] {
                items.push((s(k), get(k)));
            }
            items.push((s("loading"), Value::Bool(st.caches.any_loading())));
            for k in [
                "wazuh_rule_count",
                "wazuh_last_refresh",
                "wazuh_available",
                "wazuh_unavailable_reason",
            ] {
                items.push((s(k), get(k)));
            }
            json(&Value::Dict(std::sync::Arc::new(items)))
        }
        Err(e) => Err(http(
            503,
            format!("Failed to build catalog stats: {}", e.display()),
        )),
    }
}

/// `search_query`: `search`, `limit` (1..=1000).
fn search_params(q: &QueryPairs, v: &mut Validator) -> (Option<String>, Option<i64>) {
    (
        q_str(q, "search"),
        q_opt_int(q, v, "limit", Some(1), Some(1000)),
    )
}

/// `filter_and_limit(rows, params, key)`.
fn filter_and_limit(
    rows: Vec<Value>,
    search: Option<&str>,
    limit: Option<i64>,
    key: impl Fn(&Value) -> String,
) -> Vec<Value> {
    let mut rows = rows;
    if let Some(needle) = search.filter(|t| !t.is_empty()) {
        let needle = copilot_jinja::unicode::lower(needle);
        rows.retain(|r| copilot_jinja::unicode::lower(&key(r)).contains(&needle));
    }
    if let Some(limit) = limit {
        let n = usize::try_from(limit).unwrap_or(0);
        rows.truncate(n);
    }
    rows
}

async fn stories(st: &SearchesState, req: Request) -> Res {
    let (user, q) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    let mut v = Validator::new();
    let (search, limit) = search_params(&q, &mut v);
    finish(v)?;
    trigger(st, &[Kind::Rules, Kind::Mitre]);
    let parts = snapshot_parts(st, &scope);
    match catalog::list_stories(&parts.snapshot()) {
        Ok(list) => {
            let rows = filter_and_limit(list, search.as_deref(), limit, |r| {
                r.get("name").map(Value::py_str).unwrap_or_default()
            });
            let n = rows.len();
            json(&py::dict(vec![
                ("success", Value::Bool(true)),
                ("message", s(format!("Found {n} story(ies)"))),
                ("stories", py::list(rows)),
                ("loading", Value::Bool(st.caches.any_loading())),
            ]))
        }
        Err(e) => Err(http(
            503,
            format!("Failed to list catalog stories: {}", e.display()),
        )),
    }
}

async fn story(st: &SearchesState, req: Request, name: &str) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    trigger(st, &[Kind::Rules, Kind::Mitre]);
    let parts = snapshot_parts(st, &scope);
    let outcome = catalog::story_detail(&parts.snapshot(), name).and_then(|d| match d {
        None => Ok(None),
        Some(d) => pyd::build(&schema::CATALOG_STORY_DETAIL_RESPONSE, &d).map(Some),
    });
    match outcome {
        Ok(Some(v)) => json(&v),
        Ok(None) => Err(http(
            404,
            format!("No detections found for analytic story '{name}'"),
        )),
        Err(e) => Err(http(
            503,
            format!("Failed to load story detail: {}", e.display()),
        )),
    }
}

async fn wazuh_rules(st: &SearchesState, req: Request) -> Res {
    let (user, q) = auth::<AnyPortalOrSoc>(st, req).await?;
    let customer_code = q_str(&q, "customer_code");
    if let Some(code) = customer_code.as_deref().filter(|c| !c.is_empty()) {
        user.enforce_customer(&st.ctx, code).await?;
    }
    let mut v = Validator::new();
    let (search, limit) = search_params(&q, &mut v);
    finish(v)?;
    trigger(st, &[Kind::Wazuh, Kind::Firing]);
    let customer = match customer_code.as_deref().filter(|c| !c.is_empty()) {
        Some(code) => Some(caches::firing_for_customer(st, code).await),
        None => None,
    };
    let scope = user.access(&st.ctx).await?.clone();
    let parts = snapshot_parts(st, &scope);
    let snap = parts.snapshot();
    let mut rows = catalog::wazuh_rows(&snap, customer.as_ref());
    let mut total = rows.len() as i64;
    if search.as_deref().is_some_and(|t| !t.is_empty()) || limit.is_some() {
        rows = filter_and_limit(rows, search.as_deref(), limit, |r| {
            let d = r.get("description").map(Value::py_str).unwrap_or_default();
            let id = r.get("id").map(Value::py_str).unwrap_or_default();
            format!("{d} {id}")
        });
        total = rows.len() as i64;
    }
    let available = snap.wazuh_unavailable.is_none();
    let mut items = vec![
        ("success", Value::Bool(true)),
        (
            "message",
            s(if available {
                format!("Listed {total} Wazuh rule(s)")
            } else {
                "Wazuh Manager not available".to_string()
            }),
        ),
        ("rules", py::list(rows)),
        ("total", py::int(total)),
    ];
    items.extend(catalog::wazuh_envelope(&snap, customer_code.as_deref()));
    match pyd::build(&schema::CATALOG_WAZUH_RULES_RESPONSE, &py::dict(items)) {
        Ok(v) => json(&v),
        Err(e) => Err(http(
            503,
            format!("Failed to list Wazuh rules: {}", e.display()),
        )),
    }
}

async fn wazuh_rule(st: &SearchesState, req: Request, raw_id: &str) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    let mut v = Validator::new();
    let Some(id) = parse_int(raw_id) else {
        v.push(
            "int_parsing",
            vec![LocPart::Key("path".into()), LocPart::Key("rule_id".into())],
            "Input should be a valid integer, unable to parse string as an integer",
        );
        return Err(v.finish().err().unwrap_or(ApiError::RouteNotFound));
    };
    trigger(st, &[Kind::Wazuh, Kind::Mitre, Kind::Firing]);
    let parts = snapshot_parts(st, &scope);
    let outcome = catalog::wazuh_rule_detail(&parts.snapshot(), &id).and_then(|d| match d {
        None => Ok(None),
        Some(d) => pyd::build(&schema::CATALOG_WAZUH_RULE_DETAIL_RESPONSE, &d).map(Some),
    });
    match outcome {
        Ok(Some(v)) => json(&v),
        Ok(None) => Err(http(404, format!("No Wazuh rule found with id {id}"))),
        Err(e) => Err(http(
            503,
            format!("Failed to load Wazuh rule detail: {}", e.display()),
        )),
    }
}

async fn gaps(st: &SearchesState, req: Request) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    trigger(st, &[Kind::Rules, Kind::Mitre, Kind::Wazuh]);
    let parts = snapshot_parts(st, &scope);
    let outcome = catalog::coverage_gaps(&parts.snapshot()).and_then(|payload| {
        let get = |k: &str| payload.get(k).cloned().unwrap_or(Value::None);
        let message = format!(
            "{} gap(s) across {} technique(s)",
            get("gap_count").py_str(),
            get("total_techniques").py_str()
        );
        let mut items = vec![("success", Value::Bool(true)), ("message", s(message))];
        for k in [
            "gaps",
            "gap_count",
            "covered_count",
            "total_techniques",
            "coverage_pct",
        ] {
            items.push((k, get(k)));
        }
        pyd::build(&schema::CATALOG_COVERAGE_GAPS_RESPONSE, &py::dict(items))
    });
    match outcome {
        Ok(v) => json(&v),
        Err(e) => Err(http(
            503,
            format!("Failed to compute coverage gaps: {}", e.display()),
        )),
    }
}

async fn gap(st: &SearchesState, req: Request, technique_id: &str) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    trigger(st, &[Kind::Rules, Kind::Mitre, Kind::Wazuh]);
    let parts = snapshot_parts(st, &scope);
    let Some(gap) = catalog::coverage_gap(&parts.snapshot(), technique_id).map_err(exc)? else {
        return Err(http(404, format!("Coverage gap {technique_id} not found")));
    };
    model(
        &schema::CATALOG_COVERAGE_GAP_DETAIL_RESPONSE,
        &py::dict(vec![
            ("success", Value::Bool(true)),
            ("message", s("Coverage gap retrieved successfully")),
            ("gap", gap),
        ]),
    )
}

async fn frameworks(st: &SearchesState, req: Request) -> Res {
    let _ = auth::<AnyPortalOrSoc>(st, req).await?;
    json(&py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s("Frameworks listed successfully")),
        ("frameworks", py::list(catalog::frameworks())),
    ]))
}

async fn compliance(st: &SearchesState, req: Request, framework: &str) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    if catalog::FRAMEWORKS.iter().any(|(k, _)| *k == framework) {
        trigger(st, &[Kind::Wazuh, Kind::Firing]);
    }
    let parts = snapshot_parts(st, &scope);
    match catalog::compliance_pivot(&parts.snapshot(), framework) {
        Ok(payload) => {
            let get = |k: &str| payload.get(k).cloned().unwrap_or(Value::None);
            let message = format!(
                "{} control(s) across {} rule(s) tagged for {}",
                get("control_count").py_str(),
                get("rules_with_compliance").py_str(),
                get("framework_label").py_str()
            );
            let mut items = vec![("success", Value::Bool(true)), ("message", s(message))];
            for k in [
                "framework",
                "framework_label",
                "groups",
                "control_count",
                "rules_with_compliance",
                "total_rules",
                "firing_stats_available",
            ] {
                items.push((k, get(k)));
            }
            json(&py::dict(items))
        }
        Err(e) if e.is_value_error() => Err(http(400, e.text())),
        Err(e) => Err(http(
            503,
            format!("Failed to compute compliance pivot: {}", e.display()),
        )),
    }
}

async fn compliance_group(st: &SearchesState, req: Request, framework: &str, control: &str) -> Res {
    let (user, _) = auth::<AnyPortalOrSoc>(st, req).await?;
    let scope = user.access(&st.ctx).await?.clone();
    if catalog::FRAMEWORKS.iter().any(|(k, _)| *k == framework) {
        trigger(st, &[Kind::Wazuh, Kind::Firing]);
    }
    let parts = snapshot_parts(st, &scope);
    let payload = match catalog::compliance_group(&parts.snapshot(), framework, control) {
        Ok(p) => p,
        Err(e) if e.is_value_error() => return Err(http(400, e.text())),
        Err(e) => {
            return Err(http(
                503,
                format!("Failed to load compliance group: {}", e.display()),
            ));
        }
    };
    let Some(payload) = payload else {
        return Err(http(
            404,
            format!(
                "Compliance control {} not found for {}",
                copilot_yaml::str_repr(control),
                copilot_yaml::str_repr(framework)
            ),
        ));
    };
    let get = |k: &str| payload.get(k).cloned().unwrap_or(Value::None);
    json(&py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s("Compliance group retrieved successfully")),
        ("framework", get("framework")),
        ("framework_label", get("framework_label")),
        ("group", get("group")),
        ("firing_stats_available", get("firing_stats_available")),
    ]))
}

async fn log_test(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AnyPortalOrSoc>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let scope = user.access(&st.ctx).await?.clone();
    let (event, log_format, location) = body.model(|v, obj, at| {
        let any = copilot_web::validate::StrRules::any();
        (
            v.req_str(obj, at, "event", any),
            v.str_or(obj, at, "log_format", any, "syslog"),
            v.str_or(obj, at, "location", any, "logtest"),
        )
    })?;
    trigger(st, &[Kind::Mitre]);
    let outcome = services::run_logtest(st, &event, &log_format, &location).await;
    if let Err(reason) = &outcome {
        tracing::warn!("Logtest failed: {reason}");
    }
    let parts = snapshot_parts(st, &scope);
    let result = catalog::log_test_result(&parts.snapshot(), outcome);
    let built = result.and_then(|r| {
        let matched = r.get("matched").is_some_and(Value::truthy);
        let rule = r.get("rule").cloned().unwrap_or(Value::None);
        let message = if matched && rule.truthy() {
            format!(
                "Matched rule {}",
                rule.get("id").map(Value::py_str).unwrap_or_default()
            )
        } else if r
            .get("unavailable_reason")
            .is_none_or(|v| matches!(v, Value::None))
        {
            "No rule matched".to_string()
        } else {
            "Logtest unavailable".to_string()
        };
        let mut items = vec![("success", Value::Bool(true)), ("message", s(message))];
        for k in ["matched", "rule", "alert", "tactics", "unavailable_reason"] {
            items.push((k, r.get(k).cloned().unwrap_or(Value::None)));
        }
        pyd::build(&schema::CATALOG_LOG_TEST_RESPONSE, &py::dict(items))
    });
    match built {
        Ok(v) => json(&v),
        Err(e) => Err(http(503, format!("Failed to run logtest: {}", e.display()))),
    }
}

// --- the rule editor ----------------------------------------------------------------------

async fn validate(st: &SearchesState, req: Request) -> Res {
    let (_user, body) = match auth_json::<AdminOrAnalyst>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let yaml = body
        .model(|v, obj, at| v.req_str(obj, at, "yaml", copilot_web::validate::StrRules::any()))?;
    let lint = linter::lint_result(&yaml).map_err(exc)?.to_value();
    let get = |k: &str| lint.get(k).cloned().unwrap_or(Value::None);
    json(&py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s("Validation complete")),
        ("valid", get("valid")),
        ("error_count", get("error_count")),
        ("warning_count", get("warning_count")),
        ("findings", get("findings")),
    ]))
}

async fn run_backtest(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AdminOrAnalyst>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let (yaml, customer_code, range) = body.model(|v, obj, at| {
        let any = copilot_web::validate::StrRules::any();
        (
            v.req_str(obj, at, "yaml", any),
            v.req_str(obj, at, "customer_code", any),
            int_rule(v, obj, at, "range_seconds", 300, 2_592_000, 604_800),
        )
    })?;
    if !customer_code.is_empty() {
        user.enforce_customer(&st.ctx, &customer_code).await?;
    }
    let result = backtest::run_backtest(st, &st.graylog_search, &yaml, &customer_code, range)
        .await
        .map_err(exc)?;
    model(&schema::BACKTEST_RESPONSE, &result)
}

// --- custom repositories ------------------------------------------------------------------

fn repo_config(record: &custom_repos::Record, status: Option<&rules::SourceStatus>) -> Value {
    let mut items: Vec<(&str, Value)> = custom_repos::redact(record)
        .into_iter()
        .map(|(k, v)| (k, py::from_py(&v)))
        .collect();
    let (ok, loaded, error, at) = match status {
        Some(s_) => (
            Value::Bool(s_.ok),
            py::int(s_.rules_loaded as i64),
            py::opt_str(s_.error.clone()),
            s(s_.fetched_at.clone()),
        ),
        None => (Value::None, Value::None, Value::None, Value::None),
    };
    items.push(("last_refresh_ok", ok));
    items.push(("rules_loaded", loaded));
    items.push(("last_refresh_error", error));
    items.push(("last_refresh_at", at));
    py::dict(items)
}

async fn custom_repos_list(st: &SearchesState, req: Request) -> Res {
    let (user, _q) = auth::<AdminOrAnalyst>(st, req).await?;
    let access = user.access(&st.ctx).await?.clone();
    let set = st.caches.rules.get();
    let mut by_owner: Vec<(Option<String>, rules::SourceStatus)> = Vec::new();
    for status in &set.source_status {
        if status.provenance != "custom" {
            continue;
        }
        match by_owner.iter_mut().find(|(o, _)| *o == status.owner) {
            Some(slot) => slot.1 = status.clone(),
            None => by_owner.push((status.owner.clone(), status.clone())),
        }
    }
    let records = custom_repos::list(&st.store).await.map_err(exc)?;
    let repos: Vec<Value> = records
        .iter()
        .filter(|r| access.can_access(&r.customer_code))
        .map(|r| {
            let status = by_owner
                .iter()
                .find(|(o, _)| o.as_deref() == Some(r.customer_code.as_str()))
                .map(|(_, s_)| s_);
            repo_config(r, status)
        })
        .collect();
    let n = repos.len();
    json(&py::dict(vec![
        ("success", Value::Bool(true)),
        ("message", s(format!("{n} custom repositories configured"))),
        ("repos", py::list(repos)),
    ]))
}

async fn custom_repo_get(st: &SearchesState, req: Request, code: &str) -> Res {
    let (user, _q) = auth::<AdminOrAnalyst>(st, req).await?;
    user.enforce_customer(&st.ctx, code).await?;
    match custom_repos::get(&st.store, code).await.map_err(exc)? {
        None => json(&py::dict(vec![
            ("success", Value::Bool(true)),
            ("message", s("No custom repository configured")),
            ("repo", Value::None),
        ])),
        Some(record) => json(&py::dict(vec![
            ("success", Value::Bool(true)),
            ("message", s("")),
            ("repo", repo_config(&record, None)),
        ])),
    }
}

async fn custom_repo_put(st: &SearchesState, req: Request, code: &str) -> Res {
    let (user, body) = match auth_json::<AdminOrAnalyst>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    user.enforce_customer(&st.ctx, code).await?;
    let (repo, branch, token, enabled) = body.model(|v, obj, at| {
        let any = copilot_web::validate::StrRules::any();
        (
            v.req_str(obj, at, "repo", any),
            v.str_or(obj, at, "branch", any, "main"),
            v.opt_str(obj, at, "token", any),
            v.bool_or(obj, at, "enabled", true),
        )
    })?;
    if !repo.contains('/') {
        return Err(http(400, "repo must be in 'owner/name' form"));
    }
    let cfg = PyValue::Dict(vec![
        ("repo".into(), PyValue::Str(repo)),
        ("branch".into(), PyValue::Str(branch)),
        ("token".into(), token.map_or(PyValue::None, PyValue::Str)),
        ("enabled".into(), PyValue::Bool(enabled)),
    ]);
    let record = custom_repos::set(&st.store, code, &cfg)
        .await
        .map_err(exc)?;
    json(&py::dict(vec![
        ("success", Value::Bool(true)),
        (
            "message",
            s("Saved. Refresh the rules cache to pull this repo's rules."),
        ),
        ("repo", repo_config(&record, None)),
    ]))
}

async fn custom_repo_delete(st: &SearchesState, req: Request, code: &str) -> Res {
    let (user, _q) = auth::<AdminOrAnalyst>(st, req).await?;
    user.enforce_customer(&st.ctx, code).await?;
    custom_repos::delete(&st.store, code).await.map_err(exc)?;
    json(&py::dict(vec![
        ("success", Value::Bool(true)),
        (
            "message",
            s("Custom repository pointer removed. Refresh the cache to drop its rules."),
        ),
        ("repo", Value::None),
    ]))
}

async fn custom_repo_test(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AdminOrAnalyst>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let (repo, branch, token, customer_code) = body.model(|v, obj, at| {
        let any = copilot_web::validate::StrRules::any();
        (
            v.req_str(obj, at, "repo", any),
            v.str_or(obj, at, "branch", any, "main"),
            v.opt_str(obj, at, "token", any),
            v.opt_str(obj, at, "customer_code", any),
        )
    })?;
    if let Some(code) = customer_code.as_deref().filter(|c| !c.is_empty()) {
        user.enforce_customer(&st.ctx, code).await?;
    }
    if !repo.contains('/') {
        return Err(http(400, "repo must be in 'owner/name' form"));
    }
    let mut token = token.filter(|t| !t.is_empty());
    if token.is_none() {
        if let Some(code) = customer_code.as_deref().filter(|c| !c.is_empty()) {
            let stored = custom_repos::get(&st.store, code).await.map_err(exc)?;
            token = stored.and_then(|r| r.token_text());
        }
    }
    let branch = if branch.is_empty() {
        "main".to_string()
    } else {
        branch
    };
    let result = services::test_repo_fetch(st, &repo, &branch, token)
        .await
        .map_err(exc)?;
    let ok = result.get("ok").is_some_and(Value::truthy);
    let message = if ok {
        format!(
            "Found {} detection YAML(s).",
            result
                .get("rules_found")
                .map(Value::py_str)
                .unwrap_or_default()
        )
    } else {
        match result.get("error") {
            Some(e) if e.truthy() => e.py_str(),
            _ => "Test failed".to_string(),
        }
    };
    let mut items = vec![("success", Value::Bool(true)), ("message", s(message))];
    for k in ["ok", "rules_found", "error"] {
        items.push((k, result.get(k).cloned().unwrap_or(Value::None)));
    }
    model(&schema::TEST_CUSTOM_REPO_RESPONSE, &py::dict(items))
}

async fn publish(st: &SearchesState, req: Request) -> Res {
    let (user, body) = match auth_json::<AdminOrAnalyst>(st, req).await {
        Ok(x) => x,
        Err(r) => return Ok(*r),
    };
    let (yaml, customer_code, message, path) = body.model(|v, obj, at| {
        let any = copilot_web::validate::StrRules::any();
        (
            v.req_str(obj, at, "yaml", any),
            v.req_str(obj, at, "customer_code", any),
            v.opt_str(obj, at, "message", any),
            v.opt_str(obj, at, "path", any),
        )
    })?;
    if !customer_code.is_empty() {
        user.enforce_customer(&st.ctx, &customer_code).await?;
    }
    let result = services::publish_rule(
        st,
        &yaml,
        &customer_code,
        message.as_deref(),
        path.as_deref(),
    )
    .await
    .map_err(exc)?;
    model(&schema::PUBLISH_RULE_RESPONSE, &result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn route(method: Method, path: &str) -> Option<(R, Vec<String>)> {
        find(&method, path)
    }

    #[test]
    fn routes_match_like_starlette() {
        assert_eq!(route(Method::GET, "").unwrap().0, R::List);
        assert_eq!(route(Method::GET, "\n").unwrap().0, R::List);
        assert!(route(Method::GET, "/").is_none());
        assert_eq!(
            route(Method::GET, "/mitre/refresh").unwrap(),
            (R::MitreTechnique, vec!["refresh".to_string()])
        );
        assert!(route(Method::POST, "/mitre/coverage").is_none());
        assert_eq!(
            route(Method::POST, "/custom-repos/test").unwrap().0,
            R::CustomRepoTest
        );
        assert_eq!(
            route(Method::GET, "/custom-repos/test").unwrap(),
            (R::CustomRepoGet, vec!["test".to_string()])
        );
        assert_eq!(
            route(Method::GET, "/catalog/compliance/pci_dss/10.2.4").unwrap(),
            (
                R::ComplianceGroup,
                vec!["pci_dss".to_string(), "10.2.4".to_string()]
            )
        );
        assert_eq!(
            route(Method::GET, "/name/a/b c").unwrap(),
            (R::ByName, vec!["a/b c".to_string()])
        );
        assert_eq!(
            route(Method::GET, "/name/a\n").unwrap(),
            (R::ByName, vec!["a".to_string()])
        );
        assert_eq!(
            route(Method::GET, "/id/x\n").unwrap(),
            (R::ById, vec!["x\n".to_string()])
        );
        assert!(route(Method::GET, "/id/a/b").is_none());
        assert_eq!(
            route(Method::GET, "/catalog/stories/").unwrap(),
            (R::Story, vec![String::new()])
        );
        assert_eq!(unquote("/a%2Fb%zz%E2%82%AC"), "/a/b%zz€");
        assert_eq!(ROUTES.len(), 38);
    }
}
