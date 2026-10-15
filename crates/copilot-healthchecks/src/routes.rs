//! `/api/healthcheck/*` — port of the GET routes of
//! `app/healthchecks/agents/routes/agents.py` (admin/analyst).
//!
//! The fleet routes see the caller's customers only (`scoped_customer_codes`:
//! an analyst without customers gets empty lists). The `{agent_id}` routes
//! check the agent's owner first (`verify_agent_id_access`: an unknown agent
//! is a 403 for a scoped caller), then the window, then 404.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use copilot_core::time::now_utc_micros;
use copilot_db::agents;
use copilot_web::validate::Validator;
use copilot_web::{AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs};

use crate::schema::{HealthCheckResponse, TimeCriteria};
use crate::services::{self, Tool};

type Auth = Authorized<AdminOrAnalyst>;

/// The router, to be nested at `/api/healthcheck`. `POST /logs` is not a
/// route here and falls through to the legacy backend.
pub fn router(ctx: AppContext) -> Router {
    Router::new()
        .route("/wazuh", get(wazuh_fleet))
        .route("/wazuh/{agent_id}", get(wazuh_agent))
        .route("/velociraptor", get(velociraptor_fleet))
        .route("/velociraptor/{agent_id}", get(velociraptor_agent))
        .with_state(ctx)
}

fn json(r: HealthCheckResponse) -> Response {
    axum::Json(r).into_response()
}

fn criteria(q: &QueryPairs) -> Result<TimeCriteria, ApiError> {
    let mut v = Validator::new();
    let c = TimeCriteria::from_query(&mut v, q);
    v.finish()?;
    Ok(c)
}

async fn fleet(auth: &Auth, ctx: &AppContext, q: &QueryPairs, tool: Tool) -> ApiResult {
    let criteria = criteria(q)?;
    let codes = auth.access(ctx).await?.scoped_customer_codes(None);
    let rows = agents::list_agents(&ctx.db, codes.as_deref()).await?;
    Ok(json(services::fleet(
        tool,
        &rows,
        now_utc_micros(),
        &criteria,
    )?))
}

async fn one(
    auth: &Auth,
    ctx: &AppContext,
    agent_id: &str,
    q: &QueryPairs,
    tool: Tool,
) -> ApiResult {
    let owner = agents::customer_code_for_agent(&ctx.db, agent_id).await?;
    auth.enforce_owned(ctx, owner.as_deref(), &format!("agent {agent_id}"))
        .await?;
    let criteria = criteria(q)?;
    let agent = agents::find_by_agent_id(&ctx.db, agent_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Agent with agent_id {agent_id} not found")))?;
    Ok(json(services::single(
        tool,
        &agent,
        now_utc_micros(),
        &criteria,
    )?))
}

async fn wazuh_fleet(auth: Auth, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    fleet(&auth, &ctx, &q, Tool::Wazuh).await
}

async fn velociraptor_fleet(auth: Auth, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    fleet(&auth, &ctx, &q, Tool::Velociraptor).await
}

async fn wazuh_agent(
    auth: Auth,
    State(ctx): State<AppContext>,
    Path(agent_id): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    one(&auth, &ctx, &agent_id, &q, Tool::Wazuh).await
}

async fn velociraptor_agent(
    auth: Auth,
    State(ctx): State<AppContext>,
    Path(agent_id): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    one(&auth, &ctx, &agent_id, &q, Tool::Velociraptor).await
}
