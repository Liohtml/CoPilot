//! `GET /api/customers/*` — port of the read routes of
//! `app/customers/routes/customers.py` (admin/analyst).
//!
//! Check order is FastAPI's: token → customer access (`verify_customer_code_access`,
//! a 403 for a customer the caller is not assigned) → query → the lookups.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use copilot_core::time::now_utc_micros;
use copilot_db::{agents, customers as db};
use copilot_healthchecks::schema::TimeCriteria;
use copilot_healthchecks::services::{self as health, Tool};
use copilot_web::validate::{IntRules, StrRules, Validator};
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs};

use crate::schema::{
    AgentOut, AgentsResponse, CustomerFullResponse, CustomerMetaOut, CustomerMetaResponse,
    CustomerOut, CustomerResponse, CustomersResponse,
};
use crate::services;

type Auth = Authorized<AdminOrAnalyst>;

/// `search_query`'s `limit`: `Query(None, ge=1, le=1000)`.
const SEARCH_LIMIT: IntRules = IntRules {
    ge: Some(1),
    le: Some(1000),
};

/// The router, to be nested at `/api/customers`. Other methods on these
/// paths (create, update, delete) are 405s that the binary forwards to the
/// legacy backend.
pub fn router(ctx: AppContext) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/{customer_code}", get(customer))
        .route("/{customer_code}/meta", get(meta))
        .route("/{customer_code}/full", get(full))
        .route("/{customer_code}/agents", get(customer_agents))
        .route(
            "/{customer_code}/agents/healthcheck/wazuh",
            get(wazuh_health),
        )
        .route(
            "/{customer_code}/agents/healthcheck/velociraptor",
            get(velociraptor_health),
        )
        .with_state(ctx)
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

async fn list(auth: Auth, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let search = q.opt_str(&mut v, "search", StrRules::default());
    let limit = q.opt_int(&mut v, "limit", SEARCH_LIMIT);
    v.finish()?;
    tracing::info!(
        search = search.as_deref().unwrap_or("none"),
        "fetching customers"
    );
    let access = auth.access(&ctx).await?;
    let rows = services::list(&ctx, access, search.as_deref(), limit).await?;
    Ok(json(CustomersResponse {
        customers: rows
            .into_iter()
            .map(|r| CustomerOut::new(r.customer, Some(r.is_provisioned != 0)))
            .collect(),
        success: true,
        message: "Customers fetched successfully".into(),
    }))
}

async fn customer(
    auth: Auth,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&ctx, &code).await?;
    let row = services::customer_or_404(&ctx, &code).await?;
    Ok(json(CustomerResponse {
        customer: Some(CustomerOut::new(row, None)),
        success: true,
        message: "Customer fetched successfully".into(),
    }))
}

async fn meta(auth: Auth, State(ctx): State<AppContext>, Path(code): Path<String>) -> ApiResult {
    auth.enforce_customer(&ctx, &code).await?;
    let row = db::find_customer_meta(&ctx.db, &code)
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!("Customer meta with customer_code {code} not found"))
        })?;
    Ok(json(CustomerMetaResponse {
        customer_meta: Some(row.into()),
        success: true,
        message: "Customer meta fetched successfully".into(),
    }))
}

async fn full(auth: Auth, State(ctx): State<AppContext>, Path(code): Path<String>) -> ApiResult {
    auth.enforce_customer(&ctx, &code).await?;
    let row = services::customer_or_404(&ctx, &code).await?;
    let meta = db::find_customer_meta(&ctx.db, &code).await?;
    let message = match meta {
        Some(_) => "Customer and customer meta fetched successfully",
        None => "Customer fetched successfully but customer meta not found",
    };
    Ok(json(CustomerFullResponse {
        customer: Some(CustomerOut::new(row, None)),
        customer_meta: meta.map(CustomerMetaOut::from),
        success: true,
        message: message.into(),
    }))
}

async fn customer_agents(
    auth: Auth,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&ctx, &code).await?;
    services::customer_or_404(&ctx, &code).await?;
    let rows = agents::agents_of_customer(&ctx.db, &code).await?;
    Ok(json(AgentsResponse {
        agents: rows.into_iter().map(AgentOut::from).collect(),
        success: true,
        message: "Agents fetched successfully".into(),
    }))
}

async fn health(
    auth: &Auth,
    ctx: &AppContext,
    code: &str,
    q: &QueryPairs,
    tool: Tool,
) -> ApiResult {
    auth.enforce_customer(ctx, code).await?;
    let mut v = Validator::new();
    let criteria = TimeCriteria::from_query(&mut v, q);
    v.finish()?;
    services::customer_or_404(ctx, code).await?;
    let rows = agents::agents_of_customer(&ctx.db, code).await?;
    Ok(json(health::fleet(
        tool,
        &rows,
        now_utc_micros(),
        &criteria,
    )?))
}

async fn wazuh_health(
    auth: Auth,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    health(&auth, &ctx, &code, &q, Tool::Wazuh).await
}

async fn velociraptor_health(
    auth: Auth,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    health(&auth, &ctx, &code, &q, Tool::Velociraptor).await
}
