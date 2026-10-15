//! The settings writes of `/api/incidents/db_operations`: the per-customer
//! AI-analyst trigger and Shuffle notification rows, and the ingest field
//! dictionaries.
//!
//! Difference by design: `PUT /ai_trigger` and `PUT /notification` check
//! that the caller may manage the *body's* customer (the row they write).
//! Python only checked that the `customer_code` *query* parameter named an
//! existing customer, so an analyst scoped to one customer could switch
//! another tenant's AI investigations or Shuffle workflow on or off.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, put};
use serde_json::{Value, json};

use copilot_web::validate::{LocPart, StrRules, Validator};
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs, WithJson,
};

use super::common::{json, message_success};
use crate::access;
use crate::config::{self, FieldTable};
use crate::dictionary;
use crate::requests::{FieldAndAssetNames, PutAiTrigger, PutNotification, merge};

type Soc = Authorized<AdminOrAnalyst>;

/// The settings write routes (nested at `/api/incidents/db_operations`).
pub fn router() -> Router<AppContext> {
    Router::new()
        .route("/ai_trigger", put(put_ai_trigger))
        .route("/notification", put(put_notification))
        .route("/configured/sources/{source}", delete(delete_source))
        .route(
            "/fields-assets-title-and-timefield",
            axum::routing::post(create_names).put(replace_names),
        )
        .route(
            "/delete-fields-assets-title-and-timefield",
            delete(delete_names),
        )
        .route("/field_name/{name}/{source}", delete(deprecated_field))
        .route("/asset_name/{name}/{source}", delete(deprecated_asset))
        .route(
            "/timefield_name/{name}/{source}",
            delete(deprecated_timefield),
        )
        .route(
            "/alert_title_name/{name}/{source}",
            delete(deprecated_title),
        )
}

/// `Depends(check_customer_exists)`: the `customer_code` query parameter is
/// required, and the customer must exist (404) — checked before the body.
async fn customer_query(ctx: &AppContext, q: &QueryPairs) -> Result<Validator, ApiError> {
    let mut v = Validator::new();
    let obj: serde_json::Map<String, Value> = q
        .get("customer_code")
        .map(|c| ("customer_code".to_string(), Value::String(c.into())))
        .into_iter()
        .collect();
    let code = v.req_str(
        &obj,
        &vec![LocPart::Key("query".into())],
        "customer_code",
        StrRules::any(),
    );
    if !v.has_errors() {
        config::ensure_customer_exists(ctx, &code).await?;
    }
    Ok(v)
}

/// `PUT /ai_trigger?customer_code=`.
async fn put_ai_trigger(
    State(ctx): State<AppContext>,
    q: QueryPairs,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let v = customer_query(&ctx, &q).await?;
    let req = merge(v, body.model(PutAiTrigger::read))?;
    access::ensure_customer(&ctx, &auth, Some(&req.customer_code)).await?;
    let existing = config::ai_trigger(&ctx.db, &req.customer_code).await?;
    match existing.first() {
        Some(row) => {
            sqlx::query(
                "UPDATE incident_management_ai_analyst_trigger_enabled SET customer_code = ?, \
                 enabled = ? WHERE id = ?",
            )
            .bind(&req.customer_code)
            .bind(req.enabled)
            .bind(row.id)
            .execute(ctx.db.pool())
            .await
            .map_err(ApiError::internal)?;
        }
        None => {
            sqlx::query(
                "INSERT INTO incident_management_ai_analyst_trigger_enabled (customer_code, enabled) \
                 VALUES (?, ?)",
            )
            .bind(&req.customer_code)
            .bind(req.enabled)
            .execute(ctx.db.pool())
            .await
            .map_err(ApiError::internal)?;
        }
    }
    let rows = config::ai_trigger(&ctx.db, &req.customer_code).await?;
    Ok(json(json!({
        "ai_triggers": rows,
        "success": true,
        "message": "AI Trigger updated successfully",
    })))
}

/// `PUT /notification?customer_code=`.
async fn put_notification(
    State(ctx): State<AppContext>,
    q: QueryPairs,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let v = customer_query(&ctx, &q).await?;
    let req = merge(v, body.model(PutNotification::read))?;
    access::ensure_customer(&ctx, &auth, Some(&req.customer_code)).await?;
    let existing = config::notification(&ctx.db, &req.customer_code).await?;
    match existing.first() {
        Some(row) => {
            sqlx::query(
                "UPDATE incident_management_notification SET customer_code = ?, \
                 shuffle_workflow_id = ?, enabled = ? WHERE id = ?",
            )
            .bind(&req.customer_code)
            .bind(&req.shuffle_workflow_id)
            .bind(req.enabled)
            .bind(row.id)
            .execute(ctx.db.pool())
            .await
            .map_err(ApiError::internal)?;
        }
        None => {
            sqlx::query(
                "INSERT INTO incident_management_notification (customer_code, shuffle_workflow_id, \
                 enabled) VALUES (?, ?, ?)",
            )
            .bind(&req.customer_code)
            .bind(&req.shuffle_workflow_id)
            .bind(req.enabled)
            .execute(ctx.db.pool())
            .await
            .map_err(ApiError::internal)?;
        }
    }
    let rows = config::notification(&ctx.db, &req.customer_code).await?;
    Ok(json(json!({
        "notifications": rows,
        "success": true,
        "message": "Notification updated successfully",
    })))
}

/// `DELETE /configured/sources/{source}`.
async fn delete_source(
    _auth: Soc,
    State(ctx): State<AppContext>,
    Path(source): Path<String>,
) -> ApiResult {
    dictionary::delete_source(&ctx.db, &source).await?;
    Ok(message_success(format!(
        "Configured source {source} deleted successfully"
    )))
}

/// `POST /fields-assets-title-and-timefield`.
async fn create_names(
    State(ctx): State<AppContext>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let names = body.model(FieldAndAssetNames::read)?;
    dictionary::create(&ctx.db, &names).await?;
    Ok(message_success(
        "Field names and asset names created successfully",
    ))
}

/// `PUT /fields-assets-title-and-timefield`.
async fn replace_names(
    State(ctx): State<AppContext>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let names = body.model(FieldAndAssetNames::read)?;
    dictionary::replace(&ctx.db, &names).await?;
    Ok(message_success(
        "Field names and asset names created successfully",
    ))
}

/// `DELETE /delete-fields-assets-title-and-timefield`.
async fn delete_names(
    State(ctx): State<AppContext>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let names = body.model(FieldAndAssetNames::read)?;
    dictionary::delete(&ctx.db, &names).await?;
    Ok(message_success(
        "Field names and asset names deleted successfully",
    ))
}

async fn deprecated(ctx: &AppContext, table: FieldTable, name: &str, source: &str) -> ApiResult {
    dictionary::deprecated_delete(&ctx.db, table, source, name).await?;
    Ok(json(Value::Null))
}

/// `DELETE /field_name/{field_name}/{source}` (deprecated: commits nothing).
async fn deprecated_field(
    _auth: Soc,
    State(ctx): State<AppContext>,
    Path((name, source)): Path<(String, String)>,
) -> ApiResult {
    deprecated(&ctx, FieldTable::Field, &name, &source).await
}

/// `DELETE /asset_name/{asset_name}/{source}` (deprecated).
async fn deprecated_asset(
    _auth: Soc,
    State(ctx): State<AppContext>,
    Path((name, source)): Path<(String, String)>,
) -> ApiResult {
    deprecated(&ctx, FieldTable::Asset, &name, &source).await
}

/// `DELETE /timefield_name/{timefield_name}/{source}` (deprecated).
async fn deprecated_timefield(
    _auth: Soc,
    State(ctx): State<AppContext>,
    Path((name, source)): Path<(String, String)>,
) -> ApiResult {
    deprecated(&ctx, FieldTable::Timestamp, &name, &source).await
}

/// `DELETE /alert_title_name/{alert_title_name}/{source}` (deprecated).
async fn deprecated_title(
    _auth: Soc,
    State(ctx): State<AppContext>,
    Path((name, source)): Path<(String, String)>,
) -> ApiResult {
    deprecated(&ctx, FieldTable::AlertTitle, &name, &source).await
}
