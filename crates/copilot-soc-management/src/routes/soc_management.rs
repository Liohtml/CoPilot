//! `/api/soc_management/*` — port of `soc_management/routes/soc_management.py`.
//!
//! | Route | Scope |
//! |---|---|
//! | `GET /dashboard`, `/sources`, `/attention`, `/items/{entity}/{id}/sla` | admin, analyst |
//! | `GET /policies`, `/policies/overrides`, `/calendars` | admin, analyst |
//! | `PUT /policies`, `DELETE /policies/{code}`, `PUT /calendars`, `DELETE /calendars/{code}` | admin |
//!
//! `GET /report` (the PDF operations report) is `copilot-reports`'
//! (`soc_report`), merged at its full path beside this router.
//!
//! Check order is FastAPI's: the scope, then the endpoint's parameters (path,
//! then query, all reported in one 422), then the handler (400 for a bad
//! period, 403 for a customer outside the caller's scope).

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use copilot_auth::AccessScope;
use copilot_core::time::now_utc_micros;
use copilot_sla::calendar::{clear_calendar, replace_calendar};
use copilot_sla::evaluate::SlaState;
use copilot_sla::policy::{SlaEntity, clear_scope, list_overrides, replace_scope};
use copilot_sla::retarget::retarget_open;
use copilot_web::validate::{IntRules, Loc, LocPart, Validator, loc};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, CurrentUser,
    QueryPairs, WithJson,
};
use serde_json::{Map, Value};

use crate::domain::periods::{Bucket, Period, requested_period};
use crate::schema::calendar::CalendarIn;
use crate::schema::metrics::{DashboardResponse, ItemSlaResponse};
use crate::schema::policy::{
    PolicyOverrideOut, PolicyOverridesResponse, PolicyResponse, PolicyUpdateRequest,
};
use crate::services::datasets::FactFilters;
use crate::services::metrics::{self, DashboardQuery, MAX_ATTENTION_LIMIT};
use crate::services::{calendars, internal, policy};

type Soc = Authorized<AdminOrAnalyst>;
type Admin = Authorized<AdminOnly>;

/// The router, nested at `/api/soc_management`.
pub fn router() -> Router<AppContext> {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route("/sources", get(sources))
        .route("/attention", get(attention))
        .route("/items/{entity}/{item_id}/sla", get(item_sla))
        .route("/policies", get(get_policy).put(put_policy))
        .route(
            "/policies/overrides",
            get(get_policy_overrides).delete(delete_overrides_literal),
        )
        .route("/policies/{customer_code}", delete(delete_policy_override))
        .route("/calendars", get(get_calendar).put(put_calendar))
        .route("/calendars/{customer_code}", delete(delete_calendar))
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

fn query_loc() -> Loc {
    vec![LocPart::Key("query".into())]
}

/// `_list_param(request, name)`: `?x=a&x=b` then `?x[]=a`, de-duplicated,
/// empty values dropped, order kept.
fn list_param(q: &QueryPairs, name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in q
        .get_all(name)
        .into_iter()
        .chain(q.get_all(&format!("{name}[]")))
    {
        if !value.is_empty() && !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

/// `fact_filters(request)` (also the SOC report's, `copilot-reports`).
pub fn fact_filters(q: &QueryPairs) -> FactFilters {
    FactFilters {
        severities: list_param(q, "severities"),
        sources: list_param(q, "sources"),
    }
}

/// A required `datetime` query, converted to naive UTC (`_naive_utc`).
pub fn req_datetime(
    v: &mut Validator,
    q: &QueryPairs,
    name: &str,
) -> Option<chrono::NaiveDateTime> {
    match q.get(name) {
        None => {
            v.missing(loc("query", name));
            None
        }
        Some(raw) => match copilot_web::datetime::parse_lax_utc(raw) {
            Ok(t) => Some(t),
            Err(e) => {
                v.push(e.kind, loc("query", name), e.msg);
                None
            }
        },
    }
}

/// An optional enum query (`Optional[Enum] = Query(None)`).
fn opt_enum(v: &mut Validator, q: &QueryPairs, name: &str, allowed: &[&str]) -> Option<String> {
    let raw = q.get(name)?;
    v.check_enum(&loc("query", name), &Value::String(raw.into()), allowed)
}

/// `bool = Query(False)`.
fn bool_query(v: &mut Validator, q: &QueryPairs, name: &str) -> bool {
    let mut map = Map::new();
    if let Some(raw) = q.get(name) {
        map.insert(name.into(), Value::String(raw.into()));
    }
    v.bool_or(&map, &query_loc(), name, false)
}

/// `_period(date_from, date_to)`: the 400 with the `ValueError` text.
pub fn period(from: chrono::NaiveDateTime, to: chrono::NaiveDateTime) -> Result<Period, ApiError> {
    requested_period(from, to).map_err(ApiError::bad_request)
}

const ENTITIES: [&str; 2] = ["alert", "case"];

// ── dashboard ───────────────────────────────────────────────────────────

async fn dashboard(auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let from = req_datetime(&mut v, &q, "date_from");
    let to = req_datetime(&mut v, &q, "date_to");
    let bucket = opt_enum(&mut v, &q, "bucket", &Bucket::VALUES);
    v.finish()?;
    let (Some(from), Some(to)) = (from, to) else {
        return Err(ApiError::internal("dashboard: dates without errors"));
    };
    let query = DashboardQuery {
        period: period(from, to)?,
        customer_codes: q.customer_codes(),
        filters: fact_filters(&q),
        bucket: bucket.as_deref().and_then(Bucket::parse),
    };
    let body: DashboardResponse = metrics::build_dashboard(&ctx, &auth, &query).await?;
    Ok(json(body))
}

async fn sources(auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let codes = q.customer_codes();
    Ok(json(
        metrics::build_sources(&ctx, &auth, codes.as_deref()).await?,
    ))
}

async fn attention(auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let entity = opt_enum(&mut v, &q, "entity", &ENTITIES);
    let states: Vec<&str> = SlaState::ALL.iter().map(|s| s.as_str()).collect();
    let state = opt_enum(&mut v, &q, "state", &states);
    let limit = q.int_or(
        &mut v,
        "limit",
        IntRules {
            ge: Some(1),
            le: Some(MAX_ATTENTION_LIMIT),
        },
        100,
    );
    v.finish()?;
    let state = state.as_deref().and_then(SlaState::parse);
    if state.is_some_and(|s| s != SlaState::Breached && s != SlaState::AtRisk) {
        return Err(ApiError::bad_request("state must be breached or at_risk"));
    }
    let codes = q.customer_codes();
    let body = metrics::build_attention(
        &ctx,
        &auth,
        codes.as_deref(),
        &fact_filters(&q),
        entity.as_deref().and_then(SlaEntity::parse),
        state,
        usize::try_from(limit).unwrap_or(0),
    )
    .await?;
    Ok(json(body))
}

async fn item_sla(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path((raw_entity, raw_id)): Path<(String, String)>,
) -> ApiResult {
    let mut v = Validator::new();
    let entity = v.check_enum(
        &loc("path", "entity"),
        &Value::String(raw_entity),
        &ENTITIES,
    );
    let id = v.check_int(
        &loc("path", "item_id"),
        &Value::String(raw_id),
        IntRules::default(),
    );
    v.finish()?;
    let (Some(entity), Some(id)) = (entity.as_deref().and_then(SlaEntity::parse), id) else {
        return Err(ApiError::internal("item_sla: path without errors"));
    };
    let found: Option<ItemSlaResponse> = metrics::item_sla(&ctx, &auth, entity, id).await?;
    match found {
        Some(body) => Ok(json(body)),
        // 404 whether it does not exist or belongs to another tenant.
        None => Err(ApiError::not_found(match entity {
            SlaEntity::Alert => "Alert not found",
            SlaEntity::Case => "Case not found",
        })),
    }
}

// ── policies ────────────────────────────────────────────────────────────

/// `_check_scope(customer_code, user)`.
async fn check_scope(
    ctx: &AppContext,
    user: &CurrentUser,
    customer_code: Option<&str>,
) -> Result<(), ApiError> {
    match customer_code {
        Some(code) => user.enforce_customer(ctx, code).await,
        None => Ok(()),
    }
}

/// `None if "*" in accessible else accessible`.
async fn accessible_codes(
    ctx: &AppContext,
    user: &CurrentUser,
) -> Result<Option<Vec<String>>, ApiError> {
    Ok(match user.access(ctx).await? {
        AccessScope::All => None,
        AccessScope::Customers(codes) => Some(codes.clone()),
    })
}

async fn get_policy(auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let code = q.get("customer_code").map(str::to_string);
    check_scope(&ctx, &auth, code.as_deref()).await?;
    let matrix = policy::get_matrix(&ctx, code.as_deref()).await?;
    Ok(json(PolicyResponse {
        success: true,
        message: String::new(),
        policy: matrix,
        retargeted: 0,
    }))
}

async fn get_policy_overrides(auth: Soc, State(ctx): State<AppContext>) -> ApiResult {
    let codes = accessible_codes(&ctx, &auth).await?;
    let mut conn = ctx.db.pool().acquire().await.map_err(internal)?;
    let overrides = list_overrides(&mut conn, codes.as_deref())
        .await
        .map_err(internal)?;
    Ok(json(PolicyOverridesResponse {
        success: true,
        message: String::new(),
        overrides: overrides.iter().map(PolicyOverrideOut::from).collect(),
    }))
}

/// "customer X" or "the global policy"/"calendar" (Python's truthiness).
fn scope_word(code: Option<&str>, global: &str) -> String {
    match code.filter(|c| !c.is_empty()) {
        Some(c) => format!("customer {c}"),
        None => global.to_string(),
    }
}

fn saved_message(code: Option<&str>, global: &str, apply: bool, retargeted: i64) -> String {
    let mut message = format!("Saved {}", scope_word(code, global));
    if apply {
        message.push_str(&format!("; {retargeted} open item(s) re-targeted"));
    }
    message
}

async fn put_policy(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    let req = body.model(PolicyUpdateRequest::read)?;
    let code = req.customer_code.as_deref();
    check_scope(&ctx, &auth, code).await?;
    let now = now_utc_micros();
    let saved = async {
        let mut tx = ctx.db.pool().begin().await?;
        replace_scope(
            &mut tx,
            code,
            &req.stored_cells(),
            Some(&auth.username),
            now,
        )
        .await?;
        let matrix = policy::get_matrix_on(&mut tx, code).await?;
        let retargeted = if req.apply_to_open {
            retarget_open(&mut tx, code, now_utc_micros()).await?
        } else {
            0
        };
        tx.commit().await?;
        Ok::<_, copilot_sla::SlaError>((matrix, retargeted))
    }
    .await;
    let (matrix, retargeted) = saved.map_err(|e| {
        tracing::error!(target: "copilot::sla", "Failed to save the SLA policy: {e}");
        ApiError::server_error("Failed to save the SLA policy")
    })?;
    Ok(json(PolicyResponse {
        success: true,
        message: saved_message(code, "the global policy", req.apply_to_open, retargeted),
        policy: matrix,
        retargeted,
    }))
}

async fn remove_override(
    ctx: &AppContext,
    auth: &CurrentUser,
    code: String,
    q: &QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let apply = bool_query(&mut v, q, "apply_to_open");
    v.finish()?;
    check_scope(ctx, auth, Some(&code)).await?;
    let done = async {
        let mut tx = ctx.db.pool().begin().await?;
        let removed = clear_scope(&mut tx, &code).await?;
        let retargeted = if apply {
            retarget_open(&mut tx, Some(&code), now_utc_micros()).await?
        } else {
            0
        };
        tx.commit().await?;
        Ok::<_, copilot_sla::SlaError>((removed, retargeted))
    }
    .await;
    let (removed, retargeted) = done.map_err(|e| {
        tracing::error!(target: "copilot::sla", "Failed to remove the SLA overrides of {code}: {e}");
        ApiError::server_error("Failed to remove the SLA overrides")
    })?;
    let matrix = policy::get_matrix(ctx, Some(&code)).await?;
    Ok(json(PolicyResponse {
        success: true,
        message: format!("Removed {removed} override(s); {code} now follows the global policy"),
        policy: matrix,
        retargeted,
    }))
}

async fn delete_policy_override(
    auth: Admin,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    remove_override(&ctx, &auth, code, &q).await
}

/// `DELETE /policies/overrides`: FastAPI routes it to `/{customer_code}`.
async fn delete_overrides_literal(
    auth: Admin,
    State(ctx): State<AppContext>,
    q: QueryPairs,
) -> ApiResult {
    remove_override(&ctx, &auth, "overrides".into(), &q).await
}

// ── business-hours calendars ────────────────────────────────────────────

async fn get_calendar(auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let code = q.get("customer_code").map(str::to_string);
    check_scope(&ctx, &auth, code.as_deref()).await?;
    Ok(json(
        calendars::calendar_response(&ctx, &auth, code.as_deref(), String::new(), 0).await?,
    ))
}

async fn put_calendar(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Admin>,
) -> ApiResult {
    let req = body.model(CalendarIn::read)?;
    let code = req.customer_code.as_deref();
    check_scope(&ctx, &auth, code).await?;
    let Some(calendar) = &req.calendar else {
        return Err(ApiError::internal(
            "put_calendar: valid body without a calendar",
        ));
    };
    let now = now_utc_micros();
    let saved = async {
        let mut tx = ctx.db.pool().begin().await?;
        replace_calendar(&mut tx, code, calendar, Some(&auth.username), now).await?;
        let retargeted = if req.apply_to_open {
            retarget_open(&mut tx, code, now_utc_micros()).await?
        } else {
            0
        };
        tx.commit().await?;
        Ok::<_, copilot_sla::SlaError>(retargeted)
    }
    .await;
    let retargeted = saved.map_err(|e| {
        tracing::error!(target: "copilot::sla", "Failed to save the business-hours calendar: {e}");
        ApiError::server_error("Failed to save the business-hours calendar")
    })?;
    let message = saved_message(code, "the global calendar", req.apply_to_open, retargeted);
    Ok(json(
        calendars::calendar_response(&ctx, &auth, code, message, retargeted).await?,
    ))
}

async fn delete_calendar(
    auth: Admin,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let apply = bool_query(&mut v, &q, "apply_to_open");
    v.finish()?;
    check_scope(&ctx, &auth, Some(&code)).await?;
    let done = async {
        let mut tx = ctx.db.pool().begin().await?;
        let removed = clear_calendar(&mut tx, &code).await?;
        let retargeted = if apply {
            retarget_open(&mut tx, Some(&code), now_utc_micros()).await?
        } else {
            0
        };
        tx.commit().await?;
        Ok::<_, copilot_sla::SlaError>((removed, retargeted))
    }
    .await;
    let (removed, retargeted) = done.map_err(|e| {
        tracing::error!(target: "copilot::sla", "Failed to remove the calendar of {code}: {e}");
        ApiError::server_error("Failed to remove the business-hours calendar")
    })?;
    let message = if removed > 0 {
        format!("{code} now follows the global calendar")
    } else {
        format!("{code} had no calendar of its own")
    };
    Ok(json(
        calendars::calendar_response(&ctx, &auth, Some(&code), message, retargeted).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_params_follow_python() {
        let q = QueryPairs::parse(Some(
            "severities=High&severities%5B%5D=Low&severities=High&severities=&sources[]=wazuh",
        ));
        let f = fact_filters(&q);
        assert_eq!(f.severities, vec!["High", "Low"]);
        assert_eq!(f.sources, vec!["wazuh"]);
    }

    #[test]
    fn messages() {
        assert_eq!(
            saved_message(None, "the global policy", false, 0),
            "Saved the global policy"
        );
        assert_eq!(
            saved_message(Some(""), "the global policy", true, 2),
            "Saved the global policy; 2 open item(s) re-targeted"
        );
        assert_eq!(
            saved_message(Some("acme"), "the global calendar", false, 0),
            "Saved customer acme"
        );
    }
}
