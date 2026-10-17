//! `GET /api/status/sidebar` (`app/status/routes/context.py`): admins,
//! analysts and portal users (`require_any_scope`), the user resolved again
//! by `get_current_user` (the same token, so the same answer).

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use copilot_web::{AnyPortalOrSoc, ApiResult, Authorized};

use super::SidebarState;
use super::services::build_sidebar_context;

/// The router to nest at `/api/status`.
pub fn router(state: SidebarState) -> Router {
    Router::new()
        .route("/sidebar", get(sidebar))
        .with_state(state)
}

async fn sidebar(auth: Authorized<AnyPortalOrSoc>, State(st): State<SidebarState>) -> ApiResult {
    tracing::debug!("Building sidebar context for user {}", auth.username);
    Ok(Json(build_sidebar_context(&st, &auth).await?).into_response())
}
