//! `/api/customer_portal/agents` and `/agents/export` — port of
//! `app/customer_portal/routes/agents.py`. Both are
//! `require_any_scope("admin", "analyst", "customer_user")`; the scope is
//! the caller's customers narrowed by `customer_codes_query`.
//!
//! Query errors come in FastAPI's order: the `agent_filters` dependency's
//! (`critical`) before the route's own `page` and `page_size`.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use http::{HeaderMap, StatusCode};

use copilot_core::time::now_utc;
use copilot_web::validate::Validator;
use copilot_web::{AnyPortalOrSoc, ApiResult, Authorized, QueryPairs};

use super::schema::PortalAgentsResponse;
use super::services::{self, AgentFilters};
use crate::dashboard::services::effective_scope;
use crate::query::{self, Bounds};
use crate::starlette;
use crate::state::PortalState;

/// `MAX_PAGE_SIZE`.
pub const MAX_PAGE_SIZE: i128 = 100;

/// The routes, relative to `/api/customer_portal`.
pub fn router() -> Router<PortalState> {
    Router::new()
        .route("/agents/export", get(export))
        .route("/agents", get(page))
}

/// `agent_filters`: an empty string is no filter.
fn filters(v: &mut Validator, q: &QueryPairs) -> AgentFilters {
    let text = |name: &str| q.get(name).filter(|s| !s.is_empty()).map(str::to_string);
    AgentFilters {
        search: text("search"),
        status: text("status"),
        os: text("os"),
        critical: query::bool_or(v, q, "critical", false),
    }
}

async fn export(
    auth: Authorized<AnyPortalOrSoc>,
    State(st): State<PortalState>,
    q: QueryPairs,
    headers: HeaderMap,
) -> ApiResult {
    let mut v = Validator::new();
    let filters = filters(&mut v, &q);
    v.finish()?;
    let scope = effective_scope(auth.access(&st.ctx).await?, q.customer_codes().as_deref());
    let content = services::export_csv(&st.ctx.db, &scope, &filters).await?;
    let stamp = now_utc().format("%Y-%m-%d-%H-%M-%S");
    starlette::response(
        StatusCode::OK,
        content.into_bytes(),
        Some("text/csv"),
        &[(
            "Content-Disposition",
            format!("attachment; filename=\"assets-export-{stamp}.csv\""),
        )],
        &headers,
    )
}

async fn page(
    auth: Authorized<AnyPortalOrSoc>,
    State(st): State<PortalState>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let filters = filters(&mut v, &q);
    let page = query::int_or(
        &mut v,
        &q,
        "page",
        Bounds {
            ge: Some(1),
            le: None,
        },
        1,
    );
    let page_size = query::int_or(
        &mut v,
        &q,
        "page_size",
        Bounds {
            ge: Some(1),
            le: Some(MAX_PAGE_SIZE),
        },
        25,
    );
    v.finish()?;
    tracing::info!(page = %page, user = %auth.username, "fetching portal agents page");
    let scope = effective_scope(auth.access(&st.ctx).await?, q.customer_codes().as_deref());
    // `(page - 1) * page_size`, clamped to the filtered total by the service:
    // past it every page is empty, so a valid request answers as before, and
    // a page whose offset MySQL refuses (beyond 64 bits — Python's bare 500)
    // is that empty page too (RUST_MIGRATION.md §4).
    let offset = u128::try_from(page.saturating_sub(1).saturating_mul(page_size)).unwrap_or(0);
    let page_size = i64::try_from(page_size).unwrap_or(MAX_PAGE_SIZE as i64);
    let result = services::list(&st.ctx.db, &scope, &filters, offset, page_size).await?;
    Ok(Json(PortalAgentsResponse {
        message: format!("{} agents found", result.total),
        agents: result.agents,
        total: result.total,
        stats: result.stats,
        statuses: result.statuses,
        os_list: result.os_list,
        success: true,
    })
    .into_response())
}
