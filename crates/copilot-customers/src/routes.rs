//! `/api/customers/*` — port of `app/customers/routes/customers.py`.
//!
//! The reads are admin/analyst; the list is scoped to the caller's
//! customers and the `{customer_code}` reads check that customer
//! (`verify_customer_code_access`, a 403 for a customer the caller is not
//! assigned). The writes — creating, updating and deleting a customer, and
//! the (deprecated) meta row's create, update and delete — are admin only
//! (`require_any_scope("admin")`), as in Python: admins are deployment-wide,
//! so they carry no tenant check.
//!
//! Check order is FastAPI's: a body that is not JSON → token → path →
//! query → body model → the services.

use axum::extract::{FromRef, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use copilot_core::time::now_utc_micros;
use copilot_db::{agents, customers as db};
use copilot_healthchecks::schema::TimeCriteria;
use copilot_healthchecks::services::{self as health, Tool};
use copilot_license::LicenseClient;
use copilot_web::validate::{IntRules, StrRules, Validator};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs, WithJson,
};

use crate::schema::{
    AgentOut, AgentsResponse, CustomerFullResponse, CustomerMetaOut, CustomerMetaRequest,
    CustomerMetaResponse, CustomerOut, CustomerRequest, CustomerResponse, CustomersResponse,
    DeleteCustomerResponse,
};
use crate::services;

type Auth = Authorized<AdminOrAnalyst>;
type Admin = Authorized<AdminOnly>;

/// What the customer routes need.
#[derive(Clone, Debug)]
pub struct CustomersState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// The licence server (the MSSP seat check on creation).
    pub license: LicenseClient,
}

impl FromRef<CustomersState> for AppContext {
    fn from_ref(s: &CustomersState) -> AppContext {
        s.ctx.clone()
    }
}

/// `search_query`'s `limit`: `Query(None, ge=1, le=1000)`.
const SEARCH_LIMIT: IntRules = IntRules {
    ge: Some(1),
    le: Some(1000),
};

/// The router, to be nested at `/api/customers`.
pub fn router(state: CustomersState) -> Router {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{customer_code}", get(customer).put(update).delete(remove))
        .route(
            "/{customer_code}/meta",
            get(meta)
                .post(create_meta)
                .put(update_meta)
                .delete(delete_meta),
        )
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
        .with_state(state)
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

// --- writes (admin) ---------------------------------------------------------

async fn create(
    State(st): State<CustomersState>,
    WithJson(_admin, body): WithJson<Admin>,
) -> ApiResult {
    let req = body.model(CustomerRequest::read)?;
    services::create_customer(&st.ctx.db, &st.license, &req).await?;
    Ok(json(CustomerResponse {
        customer: Some(CustomerOut::from(&req)),
        success: true,
        message: "Customer created successfully".into(),
    }))
}

async fn update(
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
    WithJson(_admin, body): WithJson<Admin>,
) -> ApiResult {
    let req = body.model(CustomerRequest::read)?;
    tracing::info!("Updating customer with customer_code: {code}");
    services::update_customer(&ctx.db, &code, &req).await?;
    Ok(json(CustomerResponse {
        customer: Some(CustomerOut::from(&req)),
        success: true,
        message: "Customer updated successfully".into(),
    }))
}

async fn remove(
    _admin: Admin,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
) -> ApiResult {
    tracing::info!("Deleting customer with customer_code: {code}");
    let message = services::delete_customer(&ctx.db, &code).await?;
    Ok(json(DeleteCustomerResponse {
        success: true,
        message,
    }))
}

async fn create_meta(
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
    WithJson(_admin, body): WithJson<Admin>,
) -> ApiResult {
    let req = body.model(CustomerMetaRequest::read)?;
    services::add_customer_meta(&ctx.db, &code, &req).await?;
    Ok(json(CustomerMetaResponse {
        customer_meta: Some(CustomerMetaOut::from(&req)),
        success: true,
        message: "Customer meta added successfully".into(),
    }))
}

async fn update_meta(
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
    WithJson(_admin, body): WithJson<Admin>,
) -> ApiResult {
    let req = body.model(CustomerMetaRequest::read)?;
    tracing::info!("Updating customer meta with customer_code: {code}");
    services::update_customer_meta(&ctx.db, &code, &req).await?;
    Ok(json(CustomerMetaResponse {
        customer_meta: Some(CustomerMetaOut::from(&req)),
        success: true,
        message: "Customer meta updated successfully".into(),
    }))
}

async fn delete_meta(
    _admin: Admin,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
) -> ApiResult {
    tracing::info!("Deleting customer meta with customer_code: {code}");
    let meta = services::delete_customer_meta(&ctx.db, &code).await?;
    Ok(json(CustomerMetaResponse {
        customer_meta: Some(meta),
        success: true,
        message: "Customer meta deleted successfully".into(),
    }))
}
