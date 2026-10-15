//! The `GET` routes of `/api/incidents/db_operations` — port of the read
//! endpoints of `app/incidents/routes/db_operations.py`.
//!
//! Check order is FastAPI's: the route's scope dependency, then the
//! endpoint's own parameters (path, then query, in declaration order, all
//! reported in one 422), then the handler's lookups and access checks (404
//! before 403, as `get_alert_by_id` / `get_case_by_id` run first).
//!
//! Not here, so still answered by Python: `/available-source/{index_name}`,
//! `/available-indices/{source}` and `/mappings/fields-assets-title-and-timefield`
//! (they read the Wazuh indexer), `/case-report-template` and the two MinIO
//! downloads (`/case/data-store/download/…`, `/case-report-template/download/…`).
//!
//! Differences by design (each closes a leak; see RUST_MIGRATION.md §4):
//! - the scoped branch of the per-key alert listings (`/alerts/status|asset|
//!   source|assigned-to|title/…`, `/alert/ioc|tag/…`) goes through the one
//!   alert visibility (customers *and* tag RBAC); Python filtered on
//!   customers only, and a scope resolving to no customer listed every
//!   tenant's alerts;
//! - `/alert/context/{id}` checks the owner of the context (through the
//!   alert its asset belongs to);
//! - `/case/data-store` lists only the files of the caller's customers.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

use copilot_auth::AccessScope;
use copilot_core::time::now_utc_micros;
use copilot_db::visibility::AlertVisibility;
use copilot_web::validate::{IntRules, LocPart, StrRules, Validator, loc};
use copilot_web::{
    AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, AppContext, Authorized, CurrentUser,
    QueryPairs,
};

use crate::access;
use crate::cases;
use crate::lists::{self, Criteria, Key};
use crate::schema::{
    ALERT_STATUSES, AlertOut, AlertOutResponse, CaseEventOut, CaseOut, CaseOutResponse,
    CaseTaskOut, FALSE_POSITIVE_REASONS, TASK_STATUSES, VERDICT_UNTRIAGED, VERDICTS,
};
use crate::store::{self, CaseRow, Include};
use crate::verdict_stats::{self, VerdictStats};
use crate::views;
use crate::{config, files, options};

type Soc = Authorized<AdminOrAnalyst>;
type Any = Authorized<AnyPortalOrSoc>;

/// The read routes (nested at `/api/incidents/db_operations`).
pub fn router() -> Router<AppContext> {
    Router::new()
        .route("/ai_trigger/{customer_code}", get(ai_trigger))
        .route("/notification/{customer_code}", get(notification))
        .route("/socfortress/recommends/wazuh", get(recommends))
        .route("/configured/sources", get(configured_sources))
        .route("/fields-assets-title-and-timefield", get(source_fields))
        .route("/alert/available-users", get(available_users))
        .route("/alert/context/{alert_context_id}", get(alert_context))
        .route("/alert/ioc/{ioc_value}", get(alerts_by_ioc))
        .route("/alert/tag/{tag}", get(alerts_by_tag))
        .route("/alerts/verdict-stats", get(verdict_stats_route))
        .route("/alerts/filter-options", get(alert_filter_options))
        .route("/alerts/filter-options/assets", get(alert_asset_options))
        .route("/cases/filter-options", get(case_filter_options))
        .route("/alerts", get(list_alerts))
        .route("/alert/{alert_id}", get(get_alert))
        .route("/alerts/status/{status}", get(alerts_by_status))
        .route("/alerts/assigned-to/{assigned_to}", get(alerts_by_assignee))
        .route("/alerts/asset/{asset_name}", get(alerts_by_asset))
        .route("/alerts/title/{title}", get(alerts_by_title))
        .route("/alerts/customer/{customer_code}", get(alerts_by_customer))
        .route("/alerts/source/{source}", get(alerts_by_source))
        .route("/alerts/filter", get(alerts_filter))
        .route("/cases", get(list_cases))
        .route("/case/status/{status}", get(cases_by_status))
        .route("/case/name/{name}", get(cases_by_name))
        .route("/case/assigned-to/{assigned_to}", get(cases_by_assignee))
        .route("/case/asset/{asset_name}", get(cases_by_asset))
        .route("/case/customer/{customer_code}", get(cases_by_customer))
        .route("/case/data-store", get(all_case_files))
        .route("/case/data-store/{case_id}", get(case_files))
        .route("/case/{case_id}", get(get_case))
        .route(
            "/case-report-template/do-default-template-exists",
            get(default_template_exists),
        )
        .route("/case/{case_id}/tasks", get(case_tasks))
        .route("/case/{case_id}/timeline", get(case_timeline))
}

/// A JSON response.
pub fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

/// `page`, `page_size`, `order` (`Query(1, ge=1)`, `Query(25, ge=1)`,
/// `Query("desc", pattern="^(asc|desc)$")`).
#[derive(Debug, Clone)]
pub struct Paging {
    /// Page (1-based).
    pub page: i64,
    /// Rows per page.
    pub page_size: i64,
    /// `asc` | `desc`.
    pub order: String,
}

/// Read [`Paging`] (errors recorded in `v`, in parameter order).
pub fn paging(v: &mut Validator, q: &QueryPairs) -> Paging {
    let ge1 = IntRules {
        ge: Some(1),
        le: None,
    };
    let page = q.int_or(v, "page", ge1, 1);
    let page_size = q.int_or(v, "page_size", ge1, 25);
    let order = match q.get("order") {
        None => "desc".to_string(),
        Some(o) if o == "asc" || o == "desc" => o.to_string(),
        Some(_) => {
            v.push(
                "string_pattern_mismatch",
                loc("query", "order"),
                "String should match pattern '^(asc|desc)$'",
            );
            "desc".to_string()
        }
    };
    Paging {
        page,
        page_size,
        order,
    }
}

/// `List[str] = Query(None)`: every value, `None` when absent.
pub fn list_q(q: &QueryPairs, name: &str) -> Option<Vec<String>> {
    let all = q.get_all(name);
    (!all.is_empty()).then_some(all)
}

/// An `AlertStatus` path parameter.
pub fn path_status(v: &mut Validator, raw: &str) -> String {
    v.check_enum(
        &loc("path", "status"),
        &Value::String(raw.into()),
        ALERT_STATUSES,
    )
    .unwrap_or_default()
}

/// An `int` path parameter into `v`.
pub fn path_int_v(v: &mut Validator, name: &str, raw: &str) -> i64 {
    v.check_int(
        &loc("path", name),
        &Value::String(raw.into()),
        IntRules::default(),
    )
    .unwrap_or_default()
}

async fn visibility(
    ctx: &AppContext,
    user: &CurrentUser,
    requested: Option<&[String]>,
) -> Result<Option<AlertVisibility>, ApiError> {
    let access = user.access(ctx).await?;
    Ok(AlertVisibility::for_user(&ctx.db, user.id, user.role_id, access, requested).await?)
}

fn alerts_response(alerts: Vec<AlertOut>, counts: [i64; 4]) -> Response {
    json(AlertOutResponse {
        alerts,
        total: Some(counts[0]),
        open: Some(counts[1]),
        in_progress: Some(counts[2]),
        closed: Some(counts[3]),
        success: true,
        message: "Alerts retrieved successfully".into(),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Settings rows keyed by customer, and the ingest field dictionaries
// ---------------------------------------------------------------------------

async fn ai_trigger(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&ctx, &code).await?;
    config::ensure_customer_exists(&ctx, &code).await?;
    let rows = config::ai_trigger(&ctx.db, &code).await?;
    Ok(json(json!({
        "ai_triggers": rows,
        "success": true,
        "message": "AI Trigger retrieved successfully",
    })))
}

async fn notification(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&ctx, &code).await?;
    config::ensure_customer_exists(&ctx, &code).await?;
    let rows = config::notification(&ctx.db, &code).await?;
    Ok(json(json!({
        "notifications": rows,
        "success": true,
        "message": "Notification retrieved successfully",
    })))
}

async fn recommends(_auth: Soc) -> ApiResult {
    Ok(json(json!({
        "field_names": config::RECOMMENDED_FIELD_NAMES,
        "asset_name": "agent_name",
        "timefield_name": "timestamp_utc",
        "alert_title_name": "rule_description",
        "ioc_field_names": ["threat_intel_value"],
        "source": "wazuh",
        "success": true,
        "message": "Field names and asset names retrieved successfully",
    })))
}

async fn configured_sources(_auth: Soc, State(ctx): State<AppContext>) -> ApiResult {
    let sources = config::configured_sources(&ctx.db).await?;
    Ok(json(json!({
        "sources": sources,
        "success": true,
        "message": "Configured sources retrieved successfully",
    })))
}

async fn source_fields(_auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let source = match q.get("source") {
        Some(s) => s.to_string(),
        None => {
            v.missing(loc("query", "source"));
            String::new()
        }
    };
    v.finish()?;
    let names = config::source_names(&ctx.db, &source).await?;
    names.validate()?;
    Ok(json(json!({
        "field_names": names.field_names,
        "asset_name": names.asset_name,
        "timefield_name": names.timefield_name,
        "alert_title_name": names.alert_title_name,
        "ioc_field_names": names.ioc_field_names,
        "source": source,
        "success": true,
        "message": "Field names and asset names retrieved successfully",
    })))
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

async fn available_users(_auth: Soc, State(ctx): State<AppContext>) -> ApiResult {
    let users = copilot_db::users::list_users(&ctx.db, None, None).await?;
    let names: Vec<String> = users.into_iter().map(|u| u.username).collect();
    Ok(json(json!({
        "available_users": names,
        "success": true,
        "message": "Available users retrieved successfully",
    })))
}

async fn alert_context(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int_v(&mut v, "alert_context_id", &raw);
    v.finish()?;
    // Not in Python: the context belongs to the tenant of the alert its
    // asset is linked to (fail closed for scoped callers).
    let owner = config::alert_context_owner(&ctx.db, id).await?;
    auth.enforce_owned(&ctx, owner.as_deref(), &format!("alert context {id}"))
        .await?;
    let row = config::alert_context(&ctx.db, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Alert context not found"))?;
    Ok(json(json!({
        "alert_context": row,
        "success": true,
        "message": "Alert context retrieved successfully",
    })))
}

/// The two branches of a per-key listing: deployment-wide callers get the
/// key's own query and counts; everyone else the filtered listing over
/// their visibility and the counts of the customers they see.
#[allow(clippy::too_many_arguments)]
async fn per_key(
    ctx: &AppContext,
    user: &CurrentUser,
    key: Key<'_>,
    criteria: Criteria,
    requested: Option<&[String]>,
    admin_include: Include,
    p: &Paging,
    message: &str,
) -> ApiResult {
    let access = user.access(ctx).await?;
    if access.resolve_effective(requested).is_all() {
        let rows = lists::list_by_key(&ctx.db, key, p.page, p.page_size, &p.order).await?;
        let alerts = views::alerts_out(&ctx.db, &rows, admin_include).await?;
        let counts = lists::key_counts(&ctx.db, key).await?;
        return Ok(json(counted(alerts, counts, message)));
    }
    let vis = AlertVisibility::for_user(&ctx.db, user.id, user.role_id, access, requested).await?;
    let alerts = match &vis {
        Some(vis) => {
            let rows =
                lists::list_multi(&ctx.db, &criteria, Some(vis), p.page, p.page_size, &p.order)
                    .await?;
            views::alerts_out(&ctx.db, &rows, Include::ALL).await?
        }
        None => Vec::new(),
    };
    let counts = lists::visible_counts(&ctx.db, vis.as_ref()).await?;
    Ok(json(counted(alerts, counts, message)))
}

fn counted(alerts: Vec<AlertOut>, counts: [i64; 4], message: &str) -> AlertOutResponse {
    AlertOutResponse {
        alerts,
        total: Some(counts[0]),
        open: Some(counts[1]),
        in_progress: Some(counts[2]),
        closed: Some(counts[3]),
        success: true,
        message: message.into(),
        ..Default::default()
    }
}

async fn alerts_by_ioc(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(value): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let ge1 = IntRules {
        ge: Some(1),
        le: None,
    };
    let page = q.int_or(&mut v, "page", ge1, 1);
    let page_size = q.int_or(&mut v, "page_size", ge1, 25);
    v.finish()?;
    let p = Paging {
        page,
        page_size,
        order: "desc".into(),
    };
    let criteria = Criteria {
        ioc_value: Some(value.clone()),
        ..Default::default()
    };
    per_key(
        &ctx,
        &auth,
        Key::Ioc(&value),
        criteria,
        None,
        Include::IOCS,
        &p,
        "Alerts retrieved successfully",
    )
    .await
}

async fn alerts_by_tag(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(tag): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let ge1 = IntRules {
        ge: Some(1),
        le: None,
    };
    let page = q.int_or(&mut v, "page", ge1, 1);
    let page_size = q.int_or(&mut v, "page_size", ge1, 25);
    let requested = list_q(&q, "customer_codes");
    v.finish()?;
    let p = Paging {
        page,
        page_size,
        order: "desc".into(),
    };
    let criteria = Criteria {
        tags: Some(vec![tag.clone()]),
        ..Default::default()
    };
    per_key(
        &ctx,
        &auth,
        Key::Tag(&tag),
        criteria,
        requested.as_deref(),
        Include::IOCS,
        &p,
        "Alert's tags retrieved successfully",
    )
    .await
}

async fn alerts_by_status(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let status = path_status(&mut v, &raw);
    let p = paging(&mut v, &q);
    let requested = list_q(&q, "customer_codes");
    v.finish()?;
    let criteria = Criteria {
        status: Some(status.clone()),
        ..Default::default()
    };
    per_key(
        &ctx,
        &auth,
        Key::Status(&status),
        criteria,
        requested.as_deref(),
        Include::IOCS,
        &p,
        "Alerts retrieved successfully",
    )
    .await
}

async fn alerts_by_assignee(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(who): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let p = paging(&mut v, &q);
    v.finish()?;
    let criteria = Criteria {
        assigned_to: Some(who.clone()),
        ..Default::default()
    };
    per_key(
        &ctx,
        &auth,
        Key::AssignedTo(&who),
        criteria,
        None,
        Include::BASIC,
        &p,
        "Alerts retrieved successfully",
    )
    .await
}

async fn alerts_by_asset(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(name): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let p = paging(&mut v, &q);
    let requested = list_q(&q, "customer_codes");
    v.finish()?;
    let criteria = Criteria {
        asset_name: Some(name.clone()),
        ..Default::default()
    };
    per_key(
        &ctx,
        &auth,
        Key::Asset(&name),
        criteria,
        requested.as_deref(),
        Include::BASIC,
        &p,
        "Alerts retrieved successfully",
    )
    .await
}

async fn alerts_by_title(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(title): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let p = paging(&mut v, &q);
    v.finish()?;
    let criteria = Criteria {
        alert_title: Some(title.clone()),
        ..Default::default()
    };
    per_key(
        &ctx,
        &auth,
        Key::Title(&title),
        criteria,
        None,
        Include::BASIC,
        &p,
        "Alerts retrieved successfully",
    )
    .await
}

async fn alerts_by_source(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(source): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let p = paging(&mut v, &q);
    let requested = list_q(&q, "customer_codes");
    v.finish()?;
    let criteria = Criteria {
        source: Some(source.clone()),
        ..Default::default()
    };
    per_key(
        &ctx,
        &auth,
        Key::Source(&source),
        criteria,
        requested.as_deref(),
        Include::BASIC,
        &p,
        "Alerts retrieved successfully",
    )
    .await
}

async fn alerts_by_customer(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let p = paging(&mut v, &q);
    v.finish()?;
    if !access::can_access(&ctx, &auth, Some(&code)).await? {
        return Err(ApiError::forbidden("Access denied to this customer"));
    }
    let key = Key::Customer(&code);
    let rows = lists::list_by_key(&ctx.db, key, p.page, p.page_size, &p.order).await?;
    let alerts = views::alerts_out(&ctx.db, &rows, Include::BASIC).await?;
    let counts = lists::key_counts(&ctx.db, key).await?;
    Ok(alerts_response(alerts, counts))
}

async fn list_alerts(auth: Any, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let p = paging(&mut v, &q);
    let requested = list_q(&q, "customer_codes");
    v.finish()?;
    let vis = visibility(&ctx, &auth, requested.as_deref()).await?;
    let alerts = match &vis {
        Some(vis) => {
            let rows = lists::list_for_user(&ctx.db, vis, p.page, p.page_size, &p.order).await?;
            views::alerts_out(&ctx.db, &rows, Include::ALL).await?
        }
        None => Vec::new(),
    };
    let c = lists::alert_status_counts(&ctx.db, vis.as_ref()).await?;
    Ok(json(AlertOutResponse {
        alerts,
        total: Some(c.total),
        open: Some(c.open),
        in_progress: Some(c.in_progress),
        closed: Some(c.closed),
        pending_customer: Some(c.pending_customer),
        success: true,
        message: "Alerts retrieved successfully".into(),
        ..Default::default()
    }))
}

async fn get_alert(auth: Any, State(ctx): State<AppContext>, Path(raw): Path<String>) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int_v(&mut v, "alert_id", &raw);
    v.finish()?;
    let alert = access::ensure_alert(&ctx, &auth, id).await?;
    Ok(json(AlertOutResponse {
        alerts: vec![alert.build()?],
        success: true,
        message: "Alert retrieved successfully".into(),
        ..Default::default()
    }))
}

async fn alerts_filter(auth: Any, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let s = |name: &str| q.get(name).map(str::to_string);
    let mut criteria = Criteria {
        assigned_to: s("assigned_to"),
        alert_title: s("alert_title"),
        source: s("source"),
        asset_name: s("asset_name"),
        status: s("status"),
        tags: list_q(&q, "tags"),
        ioc_value: s("ioc_value"),
        verdict: s("verdict"),
        verdict_reason: s("verdict_reason"),
        ..Default::default()
    };
    let requested = q.customer_codes();
    for name in ["date_from", "date_to"] {
        if let Some(raw) = q.get(name) {
            match copilot_web::datetime::parse_lax_utc(raw) {
                Ok(t) => {
                    if name == "date_from" {
                        criteria.date_from = Some(t);
                    } else {
                        criteria.date_to = Some(t);
                    }
                }
                Err(e) => v.push(e.kind, loc("query", name), e.msg),
            }
        }
    }
    let p = paging(&mut v, &q);
    v.finish()?;
    if let (Some(from), Some(to)) = (criteria.date_from, criteria.date_to) {
        if from > to {
            return Err(ApiError::http(
                http::StatusCode::UNPROCESSABLE_ENTITY,
                "date_from must not be after date_to",
            ));
        }
    }
    let vis = visibility(&ctx, &auth, requested.as_deref()).await?;
    let own = visibility(&ctx, &auth, None).await?;
    let counts = lists::alert_status_counts(&ctx.db, own.as_ref()).await?;
    let Some(vis) = vis else {
        return Ok(json(AlertOutResponse {
            alerts: Vec::new(),
            total: Some(counts.total),
            open: Some(counts.open),
            in_progress: Some(counts.in_progress),
            closed: Some(counts.closed),
            pending_customer: Some(counts.pending_customer),
            total_filtered: Some(0),
            success: true,
            message: "No alerts found for the requested customers".into(),
        }));
    };
    let rows = lists::list_multi(
        &ctx.db,
        &criteria,
        Some(&vis),
        p.page,
        p.page_size,
        &p.order,
    )
    .await?;
    let alerts = views::alerts_out(&ctx.db, &rows, Include::ALL).await?;
    let total_filtered = lists::count_multi(&ctx.db, &criteria, Some(&vis)).await?;
    Ok(json(AlertOutResponse {
        alerts,
        total: Some(counts.total),
        open: Some(counts.open),
        in_progress: Some(counts.in_progress),
        closed: Some(counts.closed),
        pending_customer: Some(counts.pending_customer),
        total_filtered: Some(total_filtered),
        success: true,
        message: "Alerts retrieved successfully".into(),
    }))
}

async fn verdict_stats_route(auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let requested = q.customer_codes();
    let date_from = q.opt_datetime(&mut v, "date_from");
    let date_to = q.opt_datetime(&mut v, "date_to");
    let limit = q.int_or(
        &mut v,
        "alert_name_limit",
        IntRules {
            ge: Some(1),
            le: Some(100),
        },
        15,
    );
    v.finish()?;
    let date_to = date_to.unwrap_or_else(now_utc_micros);
    let date_from = date_from.unwrap_or(date_to - chrono::Duration::days(30));
    if date_from > date_to {
        return Err(ApiError::bad_request("date_from must not be after date_to"));
    }
    let access = auth.access(&ctx).await?;
    let stats = match access.resolve_effective(requested.as_deref()) {
        AccessScope::Customers(codes) if codes.is_empty() => VerdictStats::empty(),
        AccessScope::All => {
            verdict_stats::compute(&ctx.db, None, date_from, date_to, limit).await?
        }
        AccessScope::Customers(codes) => {
            verdict_stats::compute(&ctx.db, Some(&codes), date_from, date_to, limit).await?
        }
    };
    Ok(json(stats))
}

async fn alert_filter_options(
    auth: Any,
    State(ctx): State<AppContext>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let include_assets = match q.get("include_assets") {
        None => true,
        Some(raw) => {
            let mut map = serde_json::Map::new();
            map.insert("include_assets".into(), Value::String(raw.into()));
            v.bool_or(
                &map,
                &vec![LocPart::Key("query".into())],
                "include_assets",
                true,
            )
        }
    };
    v.finish()?;
    let vis = visibility(&ctx, &auth, None).await?;
    let (sources, assets, tags) =
        options::alert_filter_options(&ctx.db, vis.as_ref(), include_assets).await?;
    let mut verdicts: Vec<&str> = VERDICTS.to_vec();
    verdicts.push(VERDICT_UNTRIAGED);
    Ok(json(json!({
        "sources": sources,
        "assets": assets,
        "tags": tags,
        "statuses": ALERT_STATUSES,
        "verdicts": verdicts,
        "false_positive_reasons": FALSE_POSITIVE_REASONS,
        "success": true,
        "message": "Filter options retrieved successfully",
    })))
}

async fn alert_asset_options(auth: Any, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let search = q.opt_str(&mut v, "search", StrRules::any());
    let limit = q.int_or(
        &mut v,
        "limit",
        IntRules {
            ge: Some(1),
            le: Some(100),
        },
        20,
    );
    v.finish()?;
    let vis = visibility(&ctx, &auth, None).await?;
    let assets = match &vis {
        Some(vis) => {
            let term = search
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            options::asset_names(&ctx.db, vis, term.as_deref(), Some(limit)).await?
        }
        None => Vec::new(),
    };
    let n = assets.len();
    Ok(json(json!({
        "assets": assets,
        "success": true,
        "message": format!("{n} assets found"),
    })))
}

async fn case_filter_options(auth: Any, State(ctx): State<AppContext>) -> ApiResult {
    let access = auth.access(&ctx).await?;
    let (statuses, assigned_to) = cases::filter_options(&ctx.db, access).await?;
    Ok(json(json!({
        "statuses": statuses,
        "assigned_to": assigned_to,
        "success": true,
        "message": "Case filter options retrieved successfully",
    })))
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

fn cases_response(cases: Vec<CaseOut>, counts: Option<lists::StatusCounts>) -> Response {
    json(CaseOutResponse {
        cases,
        total: counts.map(|c| c.total),
        open: counts.map(|c| c.open),
        in_progress: counts.map(|c| c.in_progress),
        closed: counts.map(|c| c.closed),
        pending_customer: counts.map(|c| c.pending_customer),
        success: true,
        message: "Cases retrieved successfully".into(),
    })
}

async fn list_cases(auth: Any, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let p = paging(&mut v, &q);
    let requested = list_q(&q, "customer_codes");
    v.finish()?;
    let scope = auth
        .access(&ctx)
        .await?
        .resolve_effective(requested.as_deref());
    let rows = cases::list_for_user(&ctx.db, &scope, p.page, p.page_size, &p.order).await?;
    let out = views::cases_out(&ctx.db, &rows, Include::ALL).await?;
    let counts = cases::status_counts(&ctx.db, &scope).await?;
    Ok(cases_response(out, Some(counts)))
}

async fn cases_by_status(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let status = path_status(&mut v, &raw);
    let p = paging(&mut v, &q);
    let requested = list_q(&q, "customer_codes");
    v.finish()?;
    let access = auth.access(&ctx).await?;
    let out = if access.is_all() {
        let rows = cases::list_by_status(&ctx.db, &status, p.page, p.page_size, &p.order).await?;
        views::cases_out(&ctx.db, &rows, Include::ALL).await?
    } else {
        let scope = access.resolve_effective(requested.as_deref());
        let rows: Vec<CaseRow> =
            cases::list_for_user(&ctx.db, &scope, p.page, p.page_size, &p.order).await?;
        let mut all = views::cases_out(&ctx.db, &rows, Include::ALL).await?;
        all.retain(|c| c.case_status == status);
        all
    };
    let scope = access.resolve_effective(requested.as_deref());
    let counts = cases::status_counts(&ctx.db, &scope).await?;
    Ok(cases_response(out, Some(counts)))
}

async fn cases_by_name(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(name): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let p = paging(&mut v, &q);
    v.finish()?;
    let rows = cases::list_by_name(&ctx.db, &name, p.page, p.page_size, &p.order).await?;
    let mut out = views::cases_out(&ctx.db, &rows, Include::ALL).await?;
    let access = auth.access(&ctx).await?;
    if !access.is_all() {
        out.retain(|c| {
            c.customer_code
                .as_deref()
                .is_some_and(|code| access.can_access(code))
        });
    }
    let count = |s: &str| out.iter().filter(|c| c.case_status == s).count() as i64;
    let counts = lists::StatusCounts {
        total: out.len() as i64,
        open: count("OPEN"),
        in_progress: count("IN_PROGRESS"),
        closed: count("CLOSED"),
        pending_customer: count("PENDING_CUSTOMER"),
    };
    Ok(cases_response(out, Some(counts)))
}

async fn cases_by_assignee(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(who): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let requested = list_q(&q, "customer_codes");
    let access = auth.access(&ctx).await?;
    let out = if access.is_all() {
        let rows = cases::list_by_assigned_to(&ctx.db, &who).await?;
        views::cases_out(&ctx.db, &rows, Include::BASIC).await?
    } else {
        let scope = access.resolve_effective(requested.as_deref());
        let rows = cases::list_for_user(&ctx.db, &scope, 1, 25, "desc").await?;
        let mut all = views::cases_out(&ctx.db, &rows, Include::ALL).await?;
        all.retain(|c| c.assigned_to.as_deref() == Some(who.as_str()));
        all
    };
    Ok(cases_response(out, None))
}

async fn cases_by_asset(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(name): Path<String>,
) -> ApiResult {
    let access = auth.access(&ctx).await?;
    let out = if access.is_all() {
        let rows = cases::list_by_asset_name(&ctx.db, &name).await?;
        views::cases_out(&ctx.db, &rows, Include::BASIC).await?
    } else {
        let rows = cases::list_for_user(&ctx.db, access, 1, 25, "desc").await?;
        let mut all = views::cases_out(&ctx.db, &rows, Include::ALL).await?;
        all.retain(|c| {
            c.alerts
                .iter()
                .any(|a| a.assets.iter().any(|s| s.asset_name == name))
        });
        all
    };
    Ok(cases_response(out, None))
}

async fn cases_by_customer(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
) -> ApiResult {
    if !access::can_access(&ctx, &auth, Some(&code)).await? {
        return Err(ApiError::forbidden("Access denied to this customer"));
    }
    let rows = cases::list_by_customer(&ctx.db, &code).await?;
    let out = views::cases_out(&ctx.db, &rows, Include::BASIC).await?;
    Ok(cases_response(out, None))
}

async fn get_case(auth: Any, State(ctx): State<AppContext>, Path(raw): Path<String>) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int_v(&mut v, "case_id", &raw);
    v.finish()?;
    let case = access::ensure_case(&ctx, &auth, id).await?;
    Ok(json(CaseOutResponse {
        cases: vec![case],
        success: true,
        message: "Case retrieved successfully".into(),
        ..Default::default()
    }))
}

async fn all_case_files(auth: Soc, State(ctx): State<AppContext>) -> ApiResult {
    let access = auth.access(&ctx).await?;
    let rows = files::list_all(&ctx.db, access).await?;
    Ok(json(json!({
        "case_data_store": rows,
        "success": true,
        "message": "Files retrieved successfully",
    })))
}

async fn case_files(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int_v(&mut v, "case_id", &raw);
    v.finish()?;
    access::ensure_case(&ctx, &auth, id).await?;
    let rows = files::list_by_case(&ctx.db, id).await?;
    Ok(json(json!({
        "case_data_store": rows,
        "success": true,
        "message": "Files retrieved successfully",
    })))
}

async fn default_template_exists(_auth: Soc, State(ctx): State<AppContext>) -> ApiResult {
    if files::report_template_exists(&ctx.db, files::DEFAULT_REPORT_TEMPLATE).await? {
        return Ok(json(json!({
            "success": true,
            "message": "Default case report template exists",
            "default_template_exists": true,
        })));
    }
    Ok(json(json!({
        "success": true,
        "message": "No default case report templates exist",
        "default_template_exists": false,
    })))
}

async fn case_tasks(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int_v(&mut v, "case_id", &raw);
    v.finish()?;
    access::ensure_case(&ctx, &auth, id).await?;
    let sql = format!(
        "SELECT {} FROM incident_management_case_task WHERE case_id = ? \
         ORDER BY order_index, id",
        store::TASK_COLS
    );
    let rows: Vec<store::CaseTaskRow> = sqlx::query_as(&sql)
        .bind(id)
        .fetch_all(ctx.db.pool())
        .await
        .map_err(copilot_db::DbError::from)?;
    if let Some(bad) = rows
        .iter()
        .find(|t| !TASK_STATUSES.contains(&t.status.as_str()))
    {
        return Ok(json(json!({
            "tasks": [],
            "success": false,
            "message": format!(
                "Failed to list case tasks: {} is not a valid CaseTaskStatus",
                views::py_str_repr(&bad.status)
            ),
        })));
    }
    let tasks: Vec<CaseTaskOut> = rows.iter().map(CaseTaskOut::from).collect();
    let n = tasks.len();
    Ok(json(json!({
        "tasks": tasks,
        "success": true,
        "message": format!("Retrieved {n} task(s) for case id={id}"),
    })))
}

async fn case_timeline(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int_v(&mut v, "case_id", &raw);
    let limit = q.int_or(
        &mut v,
        "limit",
        IntRules {
            ge: Some(1),
            le: Some(2000),
        },
        500,
    );
    let offset = q.int_or(
        &mut v,
        "offset",
        IntRules {
            ge: Some(0),
            le: None,
        },
        0,
    );
    v.finish()?;
    access::ensure_case(&ctx, &auth, id).await?;
    let rows: Vec<store::CaseEventRow> = sqlx::query_as(
        "SELECT id, case_id, event_type, actor, timestamp, payload \
         FROM incident_management_case_event WHERE case_id = ? \
         ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
    )
    .bind(id)
    .bind(limit)
    .bind(offset)
    .fetch_all(ctx.db.pool())
    .await
    .map_err(copilot_db::DbError::from)?;
    let events: Vec<CaseEventOut> = rows.iter().map(CaseEventOut::from).collect();
    let n = events.len();
    Ok(json(json!({
        "case_id": id,
        "events": events,
        "success": true,
        "message": format!("Retrieved {n} timeline event(s) for case id={id}"),
    })))
}
