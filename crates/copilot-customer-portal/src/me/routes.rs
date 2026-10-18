//! `GET /api/customer_portal/me` — port of `app/customer_portal/routes/me.py`
//! (`require_any_scope("customer_user")`).

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};

use copilot_web::{ApiResult, Authorized, ScopeSet};

use super::services;
use crate::errors::internal_errors;
use crate::state::PortalState;

/// `require_any_scope("customer_user")`.
#[derive(Debug)]
pub struct PortalUserOnly;
impl ScopeSet for PortalUserOnly {
    const SCOPES: &'static [&'static str] = &["customer_user"];
}

/// The route, relative to `/api/customer_portal`.
pub fn router() -> Router<PortalState> {
    Router::new().route("/me", get(me))
}

async fn me(auth: Authorized<PortalUserOnly>, State(st): State<PortalState>) -> ApiResult {
    let profile = internal_errors(
        "load the portal profile",
        services::profile(&st.ctx, &auth).await,
    )?;
    Ok(Json(profile).into_response())
}
