//! `/api/syscollector` — port of
//! `app/agents/wazuh/syscollector/routes/packages.py` (2 routes).
//!
//! One difference by design (a tenant leak): `GET /search/packages` searches
//! a scoped caller's agents only — a `terms` filter on the agent ids of the
//! caller's customers, and an empty answer without asking the indexer when
//! they have none. Python searched every tenant's packages for any analyst.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;

use copilot_agents::db::{Cond, Tenancy};
use copilot_upstream::respond::model_response;
use copilot_web::validate::{IntRules, StrRules, Validator};
use copilot_web::{AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, Authorized, QueryPairs};

use crate::AgentReportsState;
use crate::agents::accessible;

use super::services::{self, IndexerFilters, PackagesQuery};

/// The router, to be nested at `/api/syscollector`.
pub fn router(state: AgentReportsState) -> Router {
    Router::new()
        .route("/search/packages", get(search_packages))
        .route("/{agent_id}/packages", get(agent_packages))
        .with_state(state)
}

async fn search_packages(
    auth: Authorized<AdminOrAnalyst>,
    State(st): State<AgentReportsState>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let any = StrRules::default();
    let f = IndexerFilters {
        package_name: q.opt_str(&mut v, "package_name", any),
        agent_name: q.opt_str(&mut v, "agent_name", any),
        agent_id: q.opt_str(&mut v, "agent_id", any),
        architecture: q.opt_str(&mut v, "architecture", any),
        package_type: q.opt_str(&mut v, "package_type", any),
        vendor: q.opt_str(&mut v, "vendor", any),
        package_version: q.opt_str(&mut v, "package_version", any),
        size: q.int_or(
            &mut v,
            "size",
            IntRules {
                ge: Some(1),
                le: Some(10000),
            },
            500,
        ),
    };
    v.finish()?;
    let owned = match accessible(auth.access(&st.ctx).await?) {
        None => None,
        Some(customers) => Some(
            crate::sca::db::agent_ids_of(&st.ctx.db, &customers)
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?,
        ),
    };
    if owned.as_ref().is_some_and(Vec::is_empty) {
        return Ok(model_response(&services::nothing_owned()));
    }
    Ok(model_response(
        &services::search_indexer(&st, &f, owned.as_deref()).await?,
    ))
}

async fn agent_packages(
    auth: Authorized<AnyPortalOrSoc>,
    State(st): State<AgentReportsState>,
    Path(agent_id): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let any = StrRules::default();
    let limit = q.int_or(
        &mut v,
        "limit",
        IntRules {
            ge: Some(1),
            le: Some(100000),
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
    let sort = q.opt_str(&mut v, "sort", any);
    let search = q.opt_str(&mut v, "search", any);
    let select = q.get_all("select");
    let query = PackagesQuery {
        limit,
        offset,
        sort,
        search,
        select: (!select.is_empty()).then_some(select),
        vendor: q.opt_str(&mut v, "vendor", any),
        name: q.opt_str(&mut v, "name", any),
        architecture: q.opt_str(&mut v, "architecture", any),
        format: q.opt_str(&mut v, "format", any),
        version: q.opt_str(&mut v, "version", any),
        q: q.opt_str(&mut v, "q", any),
    };
    v.finish()?;
    tracing::info!("Fetching packages for agent {agent_id}");
    let tenancy = Tenancy::of(auth.access(&st.ctx).await?);
    let agent = copilot_agents::db::select(
        &st.ctx.db,
        &[Cond::AgentId(&agent_id)],
        &tenancy,
        None,
        None,
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if agent.is_empty() {
        return Err(ApiError::not_found(format!(
            "Agent with agent_id {agent_id} not found or access denied"
        )));
    }
    Ok(model_response(
        &services::agent_packages(&st, &agent_id, &query).await?,
    ))
}
