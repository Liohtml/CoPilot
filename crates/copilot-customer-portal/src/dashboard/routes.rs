//! `/api/customer_portal/overview` and `/dashboard/*` — port of
//! `app/customer_portal/routes/dashboard.py`.
//!
//! Every route is `Depends(get_current_user)` only (any signed-in user;
//! tenancy narrows what they see) and takes the repeated `customer_codes`
//! query parameter. The counters go through the same visibility and scope
//! as the lists, so they always match what the user can open.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use copilot_incidents::{cases, lists};
use copilot_web::validate::Validator;
use copilot_web::{AnyUser, ApiResult, QueryPairs, ScopedUser};

use super::schema::{CustomerDashboardStatsResponse, StatusStatsResponse};
use super::services;
use crate::query::{self, Bounds};
use crate::state::PortalState;

/// `recent_limit` / `ai_limit`: `Query(…, ge=1, le=25)`.
const LIMIT: Bounds = Bounds {
    ge: Some(1),
    le: Some(25),
};

/// The routes, relative to `/api/customer_portal`.
pub fn router() -> Router<PortalState> {
    Router::new()
        .route("/overview", get(overview))
        .route("/dashboard/stats", get(stats))
        .route("/dashboard/alert-stats", get(alert_stats))
        .route("/dashboard/case-stats", get(case_stats))
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

/// `customer_codes: Optional[List[str]] = Query(None)`: the repeated form
/// only.
fn customer_codes(query: &QueryPairs) -> Option<Vec<String>> {
    let codes = query.get_all("customer_codes");
    (!codes.is_empty()).then_some(codes)
}

async fn overview(
    auth: ScopedUser<AnyUser>,
    State(st): State<PortalState>,
    query: QueryPairs,
) -> ApiResult {
    let codes = customer_codes(&query);
    let mut v = Validator::new();
    // Within 1..=25 once validated.
    let recent_limit =
        i64::try_from(query::int_or(&mut v, &query, "recent_limit", LIMIT, 6)).unwrap_or(6);
    let ai_limit = i64::try_from(query::int_or(&mut v, &query, "ai_limit", LIMIT, 3)).unwrap_or(3);
    v.finish()?;
    tracing::info!(user = %auth.username, "fetching portal overview");
    let body = services::overview(&st.ctx, &auth, codes.as_deref(), recent_limit, ai_limit).await?;
    Ok(json(body))
}

async fn stats(
    auth: ScopedUser<AnyUser>,
    State(st): State<PortalState>,
    query: QueryPairs,
) -> ApiResult {
    let codes = customer_codes(&query);
    let scope = services::effective_scope(auth.access(&st.ctx).await?, codes.as_deref());
    let db = &st.ctx.db;
    let vis = services::visibility(db, &auth, &scope).await?;
    let total_alerts = services::alert_total(db, vis.as_ref()).await?;
    let total_cases = services::case_total(db, &scope).await?;
    let total_agents = services::agent_total(db, &scope).await?;
    Ok(json(CustomerDashboardStatsResponse {
        total_alerts,
        total_cases,
        total_agents,
        success: true,
        message: "Dashboard stats retrieved successfully".into(),
    }))
}

async fn alert_stats(
    auth: ScopedUser<AnyUser>,
    State(st): State<PortalState>,
    query: QueryPairs,
) -> ApiResult {
    let codes = customer_codes(&query);
    let scope = services::effective_scope(auth.access(&st.ctx).await?, codes.as_deref());
    let vis = services::visibility(&st.ctx.db, &auth, &scope).await?;
    let counts = lists::alert_status_counts(&st.ctx.db, vis.as_ref()).await?;
    Ok(json(StatusStatsResponse::new(
        counts,
        "Dashboard alert stats retrieved successfully",
    )))
}

async fn case_stats(
    auth: ScopedUser<AnyUser>,
    State(st): State<PortalState>,
    query: QueryPairs,
) -> ApiResult {
    let codes = customer_codes(&query);
    let scope = services::effective_scope(auth.access(&st.ctx).await?, codes.as_deref());
    let counts = cases::status_counts(&st.ctx.db, &scope).await?;
    Ok(json(StatusStatsResponse::new(
        counts,
        "Dashboard case stats retrieved successfully",
    )))
}
