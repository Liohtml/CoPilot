//! `/api/customer_portal/sla/*` — port of `customer_portal/routes/sla.py`.
//!
//! | Route | Scope | Notes |
//! |---|---|---|
//! | `GET /sla/settings/{customer_code}` | admin, analyst | + customer access |
//! | `PUT /sla/settings/{customer_code}` | admin | 404 for an unknown customer |
//! | `GET /sla/availability` | portal + SOC | cheap: the switch only |
//! | `GET /sla/overview` | portal + SOC | the enabled customers' figures |
//!
//! Unexpected failures answer `500 Failed to <action>`
//! (`routes/errors.py:internal_errors`): the cause is logged, never sent.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use copilot_core::time::now_utc_micros;
use copilot_web::validate::{Validator, loc};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, AppContext, Authorized,
    QueryPairs, WithJson,
};

use crate::domain::periods::requested_period;
use crate::schema::portal::{
    PortalSlaAvailabilityResponse, PortalSlaSettings, PortalSlaSettingsResponse,
};
use crate::services::internal;
use crate::services::portal::{self, SlaSettingsRow};

/// `INVALID_PERIOD`.
pub const INVALID_PERIOD: &str =
    "Invalid period: it must start before it ends and span at most 366 days";

/// The router with full paths (merged into the binary's router, beside the
/// other `/api/customer_portal` modules).
pub fn router() -> Router<AppContext> {
    Router::new()
        .route(
            "/api/customer_portal/sla/settings/{customer_code}",
            get(get_settings).put(put_settings),
        )
        .route("/api/customer_portal/sla/availability", get(availability))
        .route("/api/customer_portal/sla/overview", get(overview))
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

/// `internal_errors(action)`: refusals pass through; anything unexpected is
/// logged and answered generically.
fn internal_errors<T>(action: &str, result: Result<T, ApiError>) -> Result<T, ApiError> {
    result.map_err(|e| match e {
        ApiError::Internal(cause) => {
            tracing::error!(%cause, "Failed to {action}");
            ApiError::server_error(format!("Failed to {action}"))
        }
        other => other,
    })
}

/// `_settings_schema(customer_code, settings)`.
fn settings_schema(customer_code: &str, row: Option<SlaSettingsRow>) -> PortalSlaSettings {
    match row {
        None => PortalSlaSettings {
            customer_code: customer_code.to_string(),
            enabled: false,
            updated_at: None,
            updated_by: None,
        },
        Some(r) => PortalSlaSettings {
            customer_code: r.customer_code,
            enabled: r.enabled,
            // `datetime.isoformat()` of the stored (whole-second) value.
            updated_at: r
                .updated_at
                .map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
            updated_by: r.updated_by,
        },
    }
}

async fn get_settings(
    auth: Authorized<AdminOrAnalyst>,
    State(ctx): State<AppContext>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&ctx, &customer_code).await?;
    let row = internal_errors(
        "read customer SLA settings",
        portal::get_settings(&ctx, &customer_code).await,
    )?;
    Ok(json(PortalSlaSettingsResponse {
        settings: settings_schema(&customer_code, row),
        success: true,
        message: "Customer SLA settings retrieved successfully".into(),
    }))
}

async fn put_settings(
    State(ctx): State<AppContext>,
    Path(customer_code): Path<String>,
    WithJson(auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let enabled = body.model(|v, obj, at| v.req_bool(obj, at, "enabled"))?;
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT customers.customer_code FROM customers WHERE customers.customer_code = ?",
    )
    .bind(&customer_code)
    .fetch_optional(ctx.db.pool())
    .await
    .map_err(internal)?;
    if exists.is_none() {
        return Err(ApiError::not_found(format!(
            "Customer {customer_code} not found"
        )));
    }
    let row = internal_errors(
        "save customer SLA settings",
        portal::upsert_settings(
            &ctx,
            &customer_code,
            enabled,
            i64::from(auth.id),
            now_utc_micros(),
        )
        .await,
    )?;
    tracing::info!(
        "Customer portal SLA page {} for customer {customer_code}",
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(json(PortalSlaSettingsResponse {
        settings: settings_schema(&customer_code, Some(row)),
        success: true,
        message: "Customer SLA settings saved successfully".into(),
    }))
}

async fn availability(
    auth: Authorized<AnyPortalOrSoc>,
    State(ctx): State<AppContext>,
    q: QueryPairs,
) -> ApiResult {
    let code = q.get("customer_code");
    let (customer_code, enabled) = internal_errors(
        "resolve SLA availability",
        portal::availability(&ctx, &auth, code).await,
    )?;
    Ok(json(PortalSlaAvailabilityResponse {
        customer_code,
        enabled,
        success: true,
        message: if enabled {
            "The SLA page is enabled".into()
        } else {
            "The SLA page is not enabled".into()
        },
    }))
}

async fn overview(
    auth: Authorized<AnyPortalOrSoc>,
    State(ctx): State<AppContext>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let date = |v: &mut Validator, name: &str| match q.get(name) {
        None => {
            v.missing(loc("query", name));
            None
        }
        Some(raw) => match copilot_web::datetime::parse_lax_utc(raw) {
            Ok(t) => Some(t),
            Err(e) => {
                v.push(e.kind, loc("query", name), e.msg);
                None
            }
        },
    };
    let from = date(&mut v, "date_from");
    let to = date(&mut v, "date_to");
    v.finish()?;
    let (Some(from), Some(to)) = (from, to) else {
        return Err(ApiError::internal("overview: dates without errors"));
    };
    // `Optional[List[str]] = Query(None)`: the repeated parameter only.
    let requested = q.get_all("customer_codes");
    let requested = (!requested.is_empty()).then_some(requested);
    let period = requested_period(from, to).map_err(|_| ApiError::bad_request(INVALID_PERIOD))?;
    let body = internal_errors(
        "load the SLA overview",
        portal::overview(&ctx, &auth, period, requested.as_deref()).await,
    )?;
    Ok(json(body))
}
