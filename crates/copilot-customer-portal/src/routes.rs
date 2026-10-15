//! `/api/customer_portal/ai_reports/*` — port of
//! `app/customer_portal/routes/ai_reports.py`.
//!
//! | Route | Scope | Notes |
//! |---|---|---|
//! | `GET /ai_reports/settings/{customer_code}` | admin, analyst | + customer access |
//! | `PUT /ai_reports/settings/{customer_code}` | admin | audited `ai_report.settings_update` |
//! | `GET /ai_reports/availability` | portal + SOC | cheap: the switch only |
//! | `GET /ai_reports/insights` | portal + SOC | visibility + switch |
//! | `GET /ai_reports/alert/{alert_id}` | portal + SOC | 404/403/403 visibility |
//! | `POST /ai_reports/alert/{alert_id}/investigate` | portal + SOC | the one portal write |
//!
//! Unexpected failures of the two writes answer `500 Failed to <action>`
//! (`routes/errors.py:internal_errors`): the cause is logged, never sent.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use copilot_core::audit::AuditRecord;
use copilot_core::time::now_utc_micros;
use copilot_db::alerts;
use copilot_db::customer_portal::{self as db, SettingsUpdate};
use copilot_talon::TalonState;
use copilot_web::validate::{IntRules, Validator, path_int};
use copilot_web::{
    AdminOnly, AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, AppContext, Authorized,
    QueryPairs, WithJson,
};

use crate::reports;
use crate::requests;
use crate::schema::{
    AlertAnalysisResponse, AnalysisRequestResponse, AvailabilityResponse, InsightsResponse,
    PortalAiReportSettings, SettingsResponse, UpdateSettingsRequest, settings_values,
};

/// `insights?limit=`: `Query(5, ge=1, le=25)`.
const INSIGHTS_LIMIT: IntRules = IntRules {
    ge: Some(1),
    le: Some(25),
};

/// The router, to be nested at `/api/customer_portal`. Paths it does not
/// know fall through to the legacy proxy.
pub fn router(state: TalonState) -> Router {
    Router::new()
        .route(
            "/ai_reports/settings/{customer_code}",
            get(get_settings).put(put_settings),
        )
        .route("/ai_reports/availability", get(availability))
        .route("/ai_reports/insights", get(insights))
        .route("/ai_reports/alert/{alert_id}", get(alert_analysis))
        .route(
            "/ai_reports/alert/{alert_id}/investigate",
            post(investigate),
        )
        .with_state(state)
}

/// `internal_errors(action)`: service refusals pass through; anything
/// unexpected is logged and answered generically.
fn internal_errors<T>(action: &str, result: Result<T, ApiError>) -> Result<T, ApiError> {
    result.map_err(|e| match e {
        ApiError::Internal(cause) => {
            tracing::error!(%cause, "Failed to {action}");
            ApiError::server_error(format!("Failed to {action}"))
        }
        other => other,
    })
}

fn json<T: serde::Serialize>(body: T) -> Response {
    Json(body).into_response()
}

// ---------------------------------------------------------------------------
// Operator-facing switch
// ---------------------------------------------------------------------------

async fn get_settings(
    auth: Authorized<AdminOrAnalyst>,
    State(ctx): State<AppContext>,
    Path(customer_code): Path<String>,
) -> ApiResult {
    auth.enforce_customer(&ctx, &customer_code).await?;
    let settings = db::settings(&ctx.db, &customer_code).await?;
    let used = match &settings {
        Some(_) => reports::count_recent_requests(&ctx, &customer_code).await?,
        None => 0,
    };
    Ok(json(SettingsResponse {
        settings: PortalAiReportSettings::project(&customer_code, settings.as_ref(), used),
        success: true,
        message: "Customer AI report settings retrieved successfully".into(),
    }))
}

async fn put_settings(
    State(ctx): State<AppContext>,
    Path(customer_code): Path<String>,
    WithJson(auth, body): WithJson<Authorized<AdminOnly>>,
) -> ApiResult {
    let req = body.model(UpdateSettingsRequest::read)?;
    if !alerts::customer_exists(&ctx.db, &customer_code).await? {
        return Err(ApiError::not_found(format!(
            "Customer {customer_code} not found"
        )));
    }
    let (before, row, used) = internal_errors(
        "save customer AI report settings",
        async {
            let before = settings_values(db::settings(&ctx.db, &customer_code).await?.as_ref());
            let update = SettingsUpdate {
                enabled: req.enabled,
                allow_customer_requests: req.allow_customer_requests,
                daily_request_limit: req.daily_request_limit,
                updated_by: Some(auth.id),
                now: now_utc_micros(),
            };
            let row = db::upsert_settings(&ctx.db, &customer_code, &update).await?;
            let used = reports::count_recent_requests(&ctx, &customer_code).await?;
            Ok::<_, ApiError>((before, row, used))
        }
        .await,
    )?;

    let after = settings_values(Some(&row));
    tracing::info!(
        customer_code = %customer_code,
        settings = %after,
        "customer portal AI report settings saved"
    );
    if after != before {
        ctx.audit.record(
            AuditRecord::new("ai_report.settings_update")
                .actor(Some(auth.id), Some(&auth.username))
                .customer(Some(&customer_code))
                .entity("customer_portal_ai_report_settings", &customer_code)
                .values(Some(before), Some(after)),
        );
    }
    Ok(json(SettingsResponse {
        settings: PortalAiReportSettings::project(&customer_code, Some(&row), used),
        success: true,
        message: "Customer AI report settings saved successfully".into(),
    }))
}

// ---------------------------------------------------------------------------
// Portal-facing reads
// ---------------------------------------------------------------------------

async fn availability(
    auth: Authorized<AnyPortalOrSoc>,
    State(ctx): State<AppContext>,
    query: QueryPairs,
) -> ApiResult {
    let (customer_code, enabled) =
        reports::availability(&ctx, &auth, query.get("customer_code")).await?;
    Ok(json(AvailabilityResponse {
        customer_code,
        enabled,
        success: true,
        message: if enabled {
            "AI reports are enabled"
        } else {
            "AI reports are not enabled"
        }
        .into(),
    }))
}

async fn insights(
    auth: Authorized<AnyPortalOrSoc>,
    State(ctx): State<AppContext>,
    query: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let limit = query.int_or(&mut v, "limit", INSIGHTS_LIMIT, 5);
    v.finish()?;
    // Only the repeated `customer_codes` form (a plain `Optional[List[str]]`).
    let codes = query.get_all("customer_codes");
    let codes = (!codes.is_empty()).then_some(codes);
    tracing::info!(user = %auth.username, "fetching AI analyst insights");
    let (total, severity_counts, recent) =
        reports::insights(&ctx, &auth, codes.as_deref(), limit).await?;
    Ok(json(InsightsResponse {
        total_reports: total,
        severity_counts,
        recent,
        success: true,
        message: format!("{total} alerts with an AI report found"),
    }))
}

async fn alert_analysis(
    auth: Authorized<AnyPortalOrSoc>,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let alert_id = path_int("alert_id", &raw)?;
    tracing::info!(alert_id, user = %auth.username, "fetching AI analyst report");
    let a = reports::alert_analysis(&ctx, &auth, alert_id).await?;
    let message = if !a.enabled {
        "AI analyst findings are not enabled for this customer"
    } else if a.investigation.is_none() {
        "No AI analysis has been performed for this alert"
    } else {
        "AI analysis retrieved successfully"
    };
    Ok(json(AlertAnalysisResponse {
        alert_id,
        enabled: a.enabled,
        can_request: a.can_request,
        has_analysis: a.investigation.is_some(),
        investigation: a.investigation,
        report: a.report,
        iocs: a.iocs,
        success: true,
        message: message.into(),
    }))
}

// ---------------------------------------------------------------------------
// Portal-facing request (#1215)
// ---------------------------------------------------------------------------

async fn investigate(
    auth: Authorized<AnyPortalOrSoc>,
    State(st): State<TalonState>,
    Path(raw): Path<String>,
) -> ApiResult {
    let alert_id = path_int("alert_id", &raw)?;
    let request = internal_errors(
        "request an AI analysis",
        requests::request_alert_analysis(&st, &auth, alert_id).await,
    )?;
    Ok(json(AnalysisRequestResponse {
        alert_id,
        requested_at: request.requested_at,
        success: true,
        message: "AI analysis requested: it will appear here once the AI analyst has finished"
            .into(),
    }))
}
