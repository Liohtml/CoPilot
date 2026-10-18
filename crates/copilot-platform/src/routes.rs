//! `/api/version/*` and `/api/audit/*`.

use axum::extract::{FromRef, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use copilot_db::audit::{self as db, AuditLogFilter};
use copilot_web::validate::{IntRules, StrRules, Validator, path_int};
use copilot_web::{AdminOnly, ApiError, ApiResult, AppContext, QueryPairs, ScopedUser};

use crate::audit::{
    AuditLogDetailResponse, AuditLogEntry, AuditLogResponse, MAX_LIMIT, Pagination, vocabularies,
};
use crate::version::VersionChecker;

/// State of the platform routes.
#[derive(Clone, Debug)]
pub struct PlatformState {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// GitHub release lookup.
    pub version: VersionChecker,
}

impl FromRef<PlatformState> for AppContext {
    fn from_ref(s: &PlatformState) -> AppContext {
        s.ctx.clone()
    }
}

/// `/api/version`: `GET /check`, unauthenticated.
pub fn version_router(state: PlatformState) -> Router {
    Router::new()
        .route("/check", get(version_check))
        .with_state(state)
}

/// `/api/audit`: `GET /`, `/actions`, `/{audit_id}` — admin only.
pub fn audit_router(state: PlatformState) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/actions", get(actions))
        .route("/{audit_id}", get(detail))
        .with_state(state)
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

async fn version_check(State(st): State<PlatformState>) -> ApiResult {
    tracing::info!("checking CoPilot version");
    Ok(json(st.version.check().await?))
}

type Admin = ScopedUser<AdminOnly>;

async fn actions(_admin: Admin) -> ApiResult {
    Ok(json(vocabularies()))
}

/// `skip: int = Query(0, ge=0)`.
const SKIP: IntRules = IntRules {
    ge: Some(0),
    le: None,
};

/// `limit: int = Query(100, ge=1, le=MAX_LIMIT)`.
const LIMIT: IntRules = IntRules {
    ge: Some(1),
    le: Some(MAX_LIMIT),
};

async fn list(_admin: Admin, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    // FastAPI's order: the `customer_codes_query` dependency (which cannot
    // fail), then the query parameters as declared.
    let customer_codes = q.customer_codes();
    let mut v = Validator::new();
    let skip = q.int_or(&mut v, "skip", SKIP, 0);
    let limit = q.int_or(&mut v, "limit", LIMIT, 100);
    let actor_user_id = q.opt_int(&mut v, "actor_user_id", IntRules::default());
    let text = |v: &mut Validator, name: &str| q.opt_str(v, name, StrRules::any());
    let actor_username = text(&mut v, "actor_username");
    let action = text(&mut v, "action");
    let entity_type = text(&mut v, "entity_type");
    let entity_id = text(&mut v, "entity_id");
    let result = text(&mut v, "result");
    let start_time = q.opt_datetime(&mut v, "start_time");
    let end_time = q.opt_datetime(&mut v, "end_time");
    let search = text(&mut v, "search");
    v.finish()?;

    let filter = AuditLogFilter {
        actor_user_id,
        actor_username,
        action,
        entity_type,
        entity_id,
        customer_codes,
        result,
        start_time,
        end_time,
        search,
    };
    let (rows, total) = db::list_audit_logs(&ctx.db, &filter, skip, limit).await?;
    let audit_logs = rows
        .into_iter()
        .map(AuditLogEntry::from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let message = format!(
        "Retrieved {} of {total} audit log entries",
        audit_logs.len()
    );
    Ok(json(AuditLogResponse {
        audit_logs,
        pagination: Pagination { total, skip, limit },
        success: true,
        message,
    }))
}

async fn detail(
    _admin: Admin,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("audit_id", &raw)?;
    let row = db::get_audit_log(&ctx.db, id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Audit log {id} not found")))?;
    Ok(json(AuditLogDetailResponse {
        audit_log: AuditLogEntry::from_row(row)?,
        success: true,
        message: "Audit log entry retrieved successfully".into(),
    }))
}
