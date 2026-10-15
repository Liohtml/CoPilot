//! Wiring: configuration → dependencies → router.
//!
//! ```text
//!                      ┌─────────────── copilot (Rust, :5000) ───────────────┐
//! frontend / portal ──►│ /api/ai_analyst/*  → copilot-ai-analyst             │
//!                      │ /api/customer_portal/ai_reports/*                    │
//!                      │                    → copilot-customer-portal         │
//!                      │ GET /api/customers/*   → copilot-customers           │
//!                      │ GET /api/healthcheck/* → copilot-healthchecks        │
//!                      │ /api/version/*, /api/audit/* → copilot-platform      │
//!                      │ /api/auth/token*, /refresh, /2fa/*, users, /login,   │
//!                      │ /register, /reset-password*, /me/customers,          │
//!                      │ /sso/*, /passkey/*, /security/*                      │
//!                      │                    → copilot-identity                │
//!                      │ GET /api/scheduler/*, run/start/pause                │
//!                      │                    → copilot-scheduler (+ its jobs)  │
//! Talon (MCP tools) ──►│ /api/talon/*       → copilot-talon ───────────────────► Talon :3100
//!                      │ /_copilot/health                                     │
//!                      │ anything else      → copilot-gateway ─────────────────► Python backend
//!                      └──────────────────────────────────────────────────────┘
//! ```

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use copilot_auth::{Fernet, JwtCodec};
use copilot_core::config::CopilotConfig;
use copilot_core::notify::{NoopNotificationSink, SharedNotificationSink};
use copilot_db::Db;
use copilot_db::audit::DbAuditSink;
use copilot_db::connectors::ConnectorCache;
use copilot_db::schema::{self, TableRequirement};
use copilot_gateway::{LegacyNotificationSink, LegacyProxy};
use copilot_identity::{IdentityState, SsoClient, TwoFactorLimiter};
use copilot_platform::PlatformState;
use copilot_platform::version::VersionChecker;
use copilot_scheduler::{OptIn, Scheduler, SchedulerState};
use copilot_talon::{TalonConnector, TalonState};
use copilot_web::middleware::{compression, cors, log_handled_errors, security_headers};
use copilot_web::{ApiError, AppContext, AppDeps};
use copilot_webauthn::RelyingParty;

/// Route prefixes this build answers itself. Everything else is proxied.
/// A method prefix (`GET /api/customers`) means only that method is ported;
/// other methods on those paths go to Python.
pub const PORTED_PREFIXES: &[&str] = &[
    "/api/ai_analyst",
    "/api/talon",
    "/api/customer_portal/ai_reports",
    "GET /api/customers",
    "GET /api/healthcheck",
    "/api/version",
    "/api/audit",
    "/api/auth/token",
    "GET /api/auth/refresh",
    "/api/auth/2fa",
    "/api/auth/register",
    "POST /api/auth/login",
    "/api/auth/users",
    "/api/auth/reset-password",
    "DELETE /api/auth/delete",
    "GET /api/auth/me/customers",
    "/api/auth/sso",
    "/api/auth/passkey",
    "/api/auth/security",
    "GET /api/scheduler",
    "POST /api/scheduler/jobs/run",
    "POST /api/scheduler/start",
    "POST /api/scheduler/pause",
];

/// While the Python backend can still write `connectors`, its cache
/// invalidations cannot reach this process; cap how stale a row may get.
pub const CONNECTOR_TTL_WITH_LEGACY: Duration = Duration::from_secs(60);

/// Every column this build reads or writes.
pub fn schema_requirements() -> Vec<TableRequirement> {
    let mut all = schema::CORE_REQUIREMENTS.to_vec();
    all.extend_from_slice(copilot_db::ai_analyst::REQUIREMENTS);
    all.extend_from_slice(copilot_db::customer_portal::REQUIREMENTS);
    all.extend_from_slice(copilot_db::customers::REQUIREMENTS);
    all.extend_from_slice(copilot_db::agents::REQUIREMENTS);
    all.extend_from_slice(copilot_db::totp::REQUIREMENTS);
    all.extend_from_slice(copilot_db::users::REQUIREMENTS);
    all.extend_from_slice(copilot_db::sso::REQUIREMENTS);
    all.extend_from_slice(copilot_db::passkeys::REQUIREMENTS);
    all.extend_from_slice(copilot_db::security::REQUIREMENTS);
    all.extend_from_slice(copilot_db::branding::REQUIREMENTS);
    all.push(TableRequirement {
        table: "audit_log",
        columns: &[
            "id",
            "timestamp",
            "actor_user_id",
            "actor_username",
            "customer_code",
            "action",
            "entity_type",
            "entity_id",
            "result",
            "old_value",
            "new_value",
            "source_ip",
            "details",
        ],
    });
    all.push(TableRequirement {
        table: "scheduled_job_metadata",
        columns: &[
            "id",
            "job_id",
            "last_success",
            "time_interval",
            "extra_data",
            "enabled",
            "job_description",
        ],
    });
    // `apscheduler_jobs` is APScheduler's own table, created by the Python
    // scheduler at its first start rather than by Alembic: the Scheduler
    // routes read it when it exists and let Python answer until then.
    all
}

/// The assembled application.
pub struct App {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// Talon connector (also used by the palace jobs).
    pub talon: TalonConnector,
    /// GitHub release lookup for `/api/version/check`.
    pub version: VersionChecker,
    /// Login and 2FA state (the TOTP key, the brute-force counter).
    pub identity: IdentityState,
    /// Legacy backend, if configured.
    pub legacy: Option<LegacyProxy>,
    /// The scheduled jobs this build can take over from APScheduler.
    pub scheduler: Scheduler,
}

impl App {
    /// Build the dependencies from configuration and a pool.
    pub fn new(cfg: &CopilotConfig, db: Db) -> anyhow::Result<Self> {
        let legacy = cfg
            .legacy_url
            .clone()
            .map(LegacyProxy::new)
            .transpose()
            .context("building the legacy backend client")?;
        let ttl = if legacy.is_some() {
            cfg.connector_cache_ttl.min(CONNECTOR_TTL_WITH_LEGACY)
        } else {
            cfg.connector_cache_ttl
        };
        let connectors = ConnectorCache::new(db.clone(), ttl);
        let notifications: SharedNotificationSink = match &legacy {
            Some(proxy) => Arc::new(LegacyNotificationSink::new(proxy.clone())),
            None => Arc::new(NoopNotificationSink),
        };
        // Verified unless explicitly disabled: the request carries Talon's
        // API key (Python used verify=False).
        let verify_tls = std::env::var("TALON_VERIFY_TLS")
            .map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(true);
        let talon = TalonConnector::new(connectors.clone(), verify_tls)
            .context("building the Talon client")?;
        let version = VersionChecker::new(cfg.version_check_url.clone())
            .context("building the release-check client")?;
        let fernet = Fernet::for_totp(cfg.totp_encryption_key.as_ref(), &cfg.jwt_secret).map_err(
            |e| {
                anyhow::anyhow!(
                    "TOTP_ENCRYPTION_KEY is malformed. Expected a 32-byte url-safe base64 key \
                     (typically 44 characters ending with '='). Generate a valid one with:\n  \
                     python -c \"from cryptography.fernet import Fernet; \
                     print(Fernet.generate_key().decode())\"\nThen paste the value into your \
                     .env without surrounding quotes or trailing whitespace. (underlying error: {e})"
                )
            },
        )?;
        let ctx = AppContext::new(AppDeps {
            db: db.clone(),
            jwt: JwtCodec::new(&cfg.jwt_secret),
            connectors,
            audit: Arc::new(DbAuditSink::new(db)),
            notifications,
            notification_defaults: cfg.notifications.clone(),
            http: reqwest::Client::new(),
            log_handled_errors: true,
        });
        let scheduler = Scheduler::new(
            ctx.db.clone(),
            OptIn::parse(cfg.rust_jobs.as_deref(), cfg.palace_jobs),
            scheduled_jobs(&ctx, &talon, cfg),
        );
        let sso_secret = cfg.sso_state_secret.as_ref().unwrap_or(&cfg.jwt_secret);
        let sso = SsoClient::new(sso_secret, cfg.sso_idp_url.clone())
            .context("building the SSO client")?;
        let webauthn = &cfg.webauthn;
        let relying_party = RelyingParty::from_env(
            webauthn.origins.as_deref(),
            webauthn.origin.as_deref(),
            webauthn.rp_id.as_deref(),
            webauthn.rp_name.as_deref(),
        );
        let identity = IdentityState {
            ctx: ctx.clone(),
            fernet: Arc::new(fernet),
            limiter: Arc::new(TwoFactorLimiter::default()),
            token_ttl_minutes: cfg.access_token_expire_minutes,
            relying_party: Arc::new(relying_party),
            sso: Arc::new(sso),
            smtp: Arc::new(cfg.smtp.clone()),
        };
        Ok(Self {
            ctx,
            talon,
            version,
            identity,
            legacy,
            scheduler,
        })
    }

    /// The full router: ported modules, health, and the legacy fallback.
    pub fn router(&self, max_body_bytes: usize) -> Router {
        let state = TalonState {
            ctx: self.ctx.clone(),
            talon: self.talon.clone(),
        };
        let platform = PlatformState {
            ctx: self.ctx.clone(),
            version: self.version.clone(),
        };
        let ported = Router::new()
            .nest("/api/ai_analyst", copilot_ai_analyst::router(state.clone()))
            .nest("/api/talon", copilot_talon::router(state.clone()))
            // Only `/ai_reports/*` is ported; other portal paths are not
            // routes here and fall through to the legacy proxy.
            .nest(
                "/api/customer_portal",
                copilot_customer_portal::router(state),
            )
            .nest(
                "/api/customers",
                copilot_customers::router(self.ctx.clone()),
            )
            .nest(
                "/api/healthcheck",
                copilot_healthchecks::router(self.ctx.clone()),
            )
            .nest(
                "/api/version",
                copilot_platform::version_router(platform.clone()),
            )
            .nest("/api/audit", copilot_platform::audit_router(platform))
            .nest("/api/auth", copilot_identity::router(self.identity.clone()))
            .nest(
                "/api/scheduler",
                copilot_scheduler::router(SchedulerState {
                    ctx: self.ctx.clone(),
                    scheduler: self.scheduler.clone(),
                    legacy: self.legacy.clone(),
                }),
            )
            .layer(from_fn_with_state(self.ctx.clone(), log_handled_errors))
            .layer(from_fn(security_headers))
            .layer(compression())
            .layer(cors())
            .layer(DefaultBodyLimit::max(max_body_bytes));
        let health = Router::new()
            .route("/_copilot/health", get(health))
            .with_state(HealthState {
                ctx: self.ctx.clone(),
                legacy: self.legacy.is_some(),
            });
        let app = Router::new().merge(ported).merge(health);
        match &self.legacy {
            // Unported paths *and* methods go to Python, which answers its
            // own 404/405 when it does not know them either.
            Some(proxy) => {
                let fallback = Router::new()
                    .fallback(copilot_gateway::proxy_handler)
                    .with_state(proxy.clone());
                app.method_not_allowed_fallback({
                    let proxy = proxy.clone();
                    move |req: Request| async move { proxy.forward(req).await }
                })
                .fallback_service(fallback)
            }
            None => app
                .method_not_allowed_fallback(|| async { ApiError::MethodNotAllowed })
                .fallback(root_or_404),
        }
    }
}

/// Every job this build can take over from APScheduler (`handover.py`'s
/// `RUST_CAPABLE_JOBS`): the palace drainer and sweeper, `prune_audit_log`.
pub fn scheduled_jobs(
    ctx: &AppContext,
    talon: &TalonConnector,
    cfg: &CopilotConfig,
) -> Vec<copilot_scheduler::JobSpec> {
    let mut jobs = copilot_ai_analyst::palace_jobs::job_specs(ctx, talon);
    jobs.push(copilot_scheduler::jobs::prune_audit_log_spec(
        ctx.db.clone(),
        cfg.audit_log_retention_days.clone(),
    ));
    jobs
}

/// Without a legacy backend: the Python root greeting, else FastAPI's 404.
async fn root_or_404(req: Request) -> Response {
    if req.uri().path() == "/" && req.method() == http::Method::GET {
        return axum::Json(json!({"message": "CoPilot - We Made It!"})).into_response();
    }
    ApiError::RouteNotFound.into_response()
}

#[derive(Clone)]
struct HealthState {
    ctx: AppContext,
    legacy: bool,
}

/// Unauthenticated liveness + dependency summary (no secrets).
async fn health(State(s): State<HealthState>) -> Response {
    let database = match tokio::time::timeout(Duration::from_secs(3), s.ctx.db.ping()).await {
        Ok(Ok(())) => "ok",
        Ok(Err(_)) | Err(_) => "unreachable",
    };
    let status = if database == "ok" {
        http::StatusCode::OK
    } else {
        http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        axum::Json(json!({
            "status": if database == "ok" { "ok" } else { "degraded" },
            "service": "copilot",
            "version": env!("CARGO_PKG_VERSION"),
            "database": database,
            "legacy_backend": if s.legacy { "configured" } else { "none" },
            "ported": PORTED_PREFIXES,
        })),
    )
        .into_response()
}
