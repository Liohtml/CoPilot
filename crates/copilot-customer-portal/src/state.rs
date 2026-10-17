//! The state of the portal routes ported after the AI reports.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRef;

use copilot_web::AppContext;

use crate::branding::cache::BrandingCache;

/// Shared dependencies plus this process's branding cache.
#[derive(Clone, Debug)]
pub struct PortalState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// Resolved branding (`services/branding_cache.py`).
    pub branding: Arc<BrandingCache>,
}

impl PortalState {
    /// The state with a branding cache of `ttl`
    /// (`BRANDING_CACHE_TTL_SECONDS`) checked every `check`
    /// (`BRANDING_CACHE_CHECK_SECONDS`).
    pub fn new(ctx: AppContext, ttl: Duration, check: Duration) -> Self {
        Self {
            ctx,
            branding: Arc::new(BrandingCache::new(ttl, check)),
        }
    }
}

impl FromRef<PortalState> for AppContext {
    fn from_ref(state: &PortalState) -> Self {
        state.ctx.clone()
    }
}
