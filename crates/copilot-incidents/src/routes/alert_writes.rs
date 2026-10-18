//! The alert writes of `/api/incidents/db_operations`: creation, status,
//! verdict, escalation, assignment, comments, contexts, assets, IoCs, tags
//! and deletion — with the SLA milestones (#1187), the audit rows and the
//! `alert_assigned` notification Python records next to each.
//!
//! Check order is FastAPI's: the body is decoded first (malformed JSON is a
//! 422 before the token), then the scope, then the body's fields, then the
//! handler's lookups (404 before 403).

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, post, put};
use serde_json::json;

use copilot_core::audit::AuditRecord;
use copilot_db::visibility::AlertVisibility;
use copilot_sla::LifecycleAction;
use copilot_web::{
    AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, AppContext, Authorized, CurrentUser,
    WithJson,
};

use super::common::{
    actor, ensure_alert_soft, ensure_can_modify_comment, ensure_customer_may_set_status,
    is_customer_user, json, message_success, path_int, sla, user_exists,
};
use crate::access;
use crate::requests::{
    self, AlertContextCreate, AlertCreate, AssetCreate, BulkAssign, BulkUpdateAlertStatus,
    CommentCreate, CommentEdit, IdBool, IdText, IocCreate, TwoIds, UpdateAlertVerdict,
    UpdateStatus, VerdictStateRequest,
};
use crate::schema::AlertRecord;
use crate::store::{self, AlertRow};
use crate::writes::{self, CommentKind, VerdictState};
use copilot_core::notify::Assignment;

type Soc = Authorized<AdminOrAnalyst>;
type Any = Authorized<AnyPortalOrSoc>;

/// The alert write routes (nested at `/api/incidents/db_operations`).
pub fn router() -> Router<AppContext> {
    Router::new()
        .route("/alert", post(create_alert))
        .route("/alert/status", put(update_status))
        .route("/alerts/status", put(bulk_status))
        .route("/alert/verdict", put(update_verdict))
        .route("/alerts/verdict-state", post(verdict_states))
        .route("/alert/escalated", put(update_escalated))
        .route("/alert/comment", post(create_comment).put(edit_comment))
        .route("/alert/comment/{comment_id}", delete(delete_comment))
        .route("/alert/assigned-to", put(assign))
        .route("/alerts/assigned-to", put(bulk_assign))
        .route("/alert/context", post(create_context))
        .route("/alert/asset", post(create_asset))
        .route("/alert/ioc", post(create_ioc).delete(delete_ioc))
        .route("/alert/tag", post(create_tag).delete(delete_tag))
        .route("/alert/{alert_id}", delete(delete_alert))
        .route("/alerts", delete(delete_alerts))
        .route("/alerts/by-title/{title_filter}", delete(delete_by_title))
}

fn alert_response(row: &AlertRow, message: &str) -> axum::response::Response {
    json(json!({
        "alert": AlertRecord::from(row),
        "success": true,
        "message": message,
    }))
}

/// `POST /alert` (#1102: the body's customer must be the caller's).
async fn create_alert(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let a = body.model(AlertCreate::read)?;
    access::ensure_customer(&ctx, &auth, Some(&a.customer_code)).await?;
    let id = writes::create_alert(&ctx.db, &a).await?;
    let row = store::alert(&ctx.db, id)
        .await?
        .ok_or_else(|| ApiError::internal("created alert vanished"))?;
    let recorder = sla(&ctx);
    recorder
        .alert_opened(id, row.severity.as_deref(), &row.customer_code)
        .await;
    recorder
        .alert_action(id, LifecycleAction::Created, &actor(&auth), None, None)
        .await;
    Ok(json(AlertRecord::from(&row)))
}

/// `PUT /alert/status`.
async fn update_status(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let req = body.model(|v, o, at| UpdateStatus::read(v, o, at, "alert_id"))?;
    ensure_customer_may_set_status(&auth, &req.status)?;
    access::ensure_alert(&ctx, &auth, req.id).await?;
    let row = writes::update_alert_status(&ctx.db, req.id, &req.status).await?;
    sla(&ctx)
        .alert_action(
            req.id,
            LifecycleAction::StatusChanged,
            &actor(&auth),
            Some(&req.status),
            None,
        )
        .await;
    Ok(alert_response(&row, "Alert status updated successfully"))
}

/// `PUT /alerts/status` (#1098): per alert, a refused one is skipped.
async fn bulk_status(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let req = body.model(BulkUpdateAlertStatus::read)?;
    let mut updated = Vec::new();
    let mut skipped = Vec::new();
    for id in &req.alert_ids {
        if ensure_customer_may_set_status(&auth, &req.status).is_err() {
            skipped.push(*id);
            continue;
        }
        if ensure_alert_soft(&ctx, &auth, *id).await?.is_err() {
            skipped.push(*id);
            continue;
        }
        match writes::update_alert_status(&ctx.db, *id, &req.status).await {
            Ok(_) => updated.push(*id),
            Err(ApiError::Http { .. }) => skipped.push(*id),
            Err(e) => return Err(e),
        }
    }
    sla(&ctx)
        .alerts_action(
            &updated,
            LifecycleAction::StatusChanged,
            &actor(&auth),
            Some(&req.status),
            None,
        )
        .await;
    Ok(json(json!({
        "message": format!("Updated {} alert(s) to {}", updated.len(), req.status),
        "updated_alert_ids": updated,
        "not_updated_alert_ids": skipped,
        "success": true,
    })))
}

/// `PUT /alert/verdict` (#1085), audited.
async fn update_verdict(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(UpdateAlertVerdict::read)?;
    access::ensure_alert(&ctx, &auth, req.alert_id).await?;
    let (row, previous) = writes::update_alert_verdict(
        &ctx.db,
        req.alert_id,
        req.verdict.as_deref(),
        req.verdict_reason.as_deref(),
        req.verdict_note.as_deref(),
        &auth.username,
    )
    .await?;
    let action = if req.verdict.is_none() {
        "alert.verdict_clear"
    } else {
        "alert.verdict_set"
    };
    ctx.audit.record(
        AuditRecord::new(action)
            .actor(Some(auth.id), Some(&auth.username))
            .customer(Some(&row.customer_code))
            .entity("alert", row.id)
            .values(
                Some(previous),
                Some(json!({
                    "verdict": req.verdict,
                    "verdict_reason": req.verdict_reason,
                    "verdict_note": req.verdict_note,
                })),
            )
            .source_ip(auth.source_ip.clone()),
    );
    sla(&ctx)
        .alert_action(
            i64::from(row.id),
            LifecycleAction::VerdictSet,
            &actor(&auth),
            None,
            None,
        )
        .await;
    Ok(alert_response(&row, "Alert verdict updated successfully"))
}

/// `POST /alerts/verdict-state` (#1239): ids not visible are `missing`,
/// like ids that do not exist.
async fn verdict_states(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(VerdictStateRequest::read)?;
    let mut requested: Vec<i64> = Vec::new();
    for id in req.alert_ids {
        if !requested.contains(&id) {
            requested.push(id);
        }
    }
    let access = auth.access(&ctx).await?;
    let vis = AlertVisibility::for_user(&ctx.db, auth.id, auth.role_id, access, None).await?;
    let rows: Vec<VerdictState> = match vis {
        None => Vec::new(),
        Some(vis) => {
            let mut qb = sqlx::QueryBuilder::new(
                "SELECT a.id, a.verdict, a.verdict_reason, a.verdict_note, a.verdict_by, \
                 a.verdict_at FROM incident_management_alert a WHERE a.id IN (",
            );
            store::push_list(&mut qb, requested.iter().copied());
            qb.push(")");
            vis.push_and(&mut qb, "a");
            qb.push(" ORDER BY a.id");
            qb.build_query_as::<VerdictState>()
                .fetch_all(ctx.db.pool())
                .await
                .map_err(ApiError::internal)?
        }
    };
    let missing: Vec<i64> = requested
        .iter()
        .copied()
        .filter(|id| !rows.iter().any(|r| i64::from(r.id) == *id))
        .collect();
    let message = format!("{} alert verdict(s)", rows.len());
    Ok(json(json!({
        "alerts": rows,
        "missing": missing,
        "success": true,
        "message": message,
    })))
}

/// `PUT /alert/escalated`.
async fn update_escalated(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(|v, o, at| IdBool::read(v, o, at, "alert_id", "escalated"))?;
    access::ensure_alert(&ctx, &auth, req.id).await?;
    let row = writes::update_alert_escalated(&ctx.db, req.id, req.value).await?;
    sla(&ctx)
        .alert_action(
            req.id,
            LifecycleAction::Escalated,
            &actor(&auth),
            None,
            None,
        )
        .await;
    Ok(alert_response(
        &row,
        "Alert escalated status updated successfully",
    ))
}

/// `resume_alert_on_reply`: a portal user's comment hands a waiting alert
/// back to the SOC.
async fn resume_alert_on_reply(
    ctx: &AppContext,
    user: &CurrentUser,
    alert_id: i64,
) -> Result<(), ApiError> {
    if !is_customer_user(user) {
        return Ok(());
    }
    let status = store::alert(&ctx.db, alert_id).await?.map(|a| a.status);
    if status.as_deref() != Some("PENDING_CUSTOMER") {
        return Ok(());
    }
    writes::update_alert_status(&ctx.db, alert_id, "IN_PROGRESS").await?;
    sla(ctx)
        .alert_action(
            alert_id,
            LifecycleAction::StatusChanged,
            &actor(user),
            Some("IN_PROGRESS"),
            None,
        )
        .await;
    Ok(())
}

/// `POST /alert/comment`: authorship is the caller's, whatever the body says.
async fn create_comment(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let req = body.model(|v, o, at| CommentCreate::read(v, o, at, "alert_id"))?;
    access::ensure_alert(&ctx, &auth, req.parent).await?;
    let created = writes::create_comment(
        &ctx.db,
        CommentKind::Alert,
        req.parent,
        &req.comment,
        &auth.username,
        req.created_at,
    )
    .await?;
    sla(&ctx)
        .alert_action(
            req.parent,
            LifecycleAction::Commented,
            &actor(&auth),
            None,
            None,
        )
        .await;
    resume_alert_on_reply(&ctx, &auth, req.parent).await?;
    Ok(json(json!({
        "comment": created.to_json("alert_id"),
        "success": true,
        "message": "Comment created successfully",
    })))
}

/// `PUT /alert/comment`: the comment, not the body, decides the alert.
async fn edit_comment(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let req = body.model(|v, o, at| CommentEdit::read(v, o, at, "alert_id"))?;
    let existing = writes::comment(&ctx.db, CommentKind::Alert, req.comment_id)
        .await?
        .filter(|c| c.parent.map(i64::from) == Some(req.parent))
        .ok_or_else(|| ApiError::not_found("Comment not found"))?;
    access::ensure_alert_msg(&ctx, &auth, req.parent, &format!("alert {}", req.parent)).await?;
    ensure_can_modify_comment(&auth, &existing.user_name)?;
    let edited = writes::edit_comment(
        &ctx.db,
        CommentKind::Alert,
        req.comment_id,
        &req.comment,
        &auth.username,
    )
    .await?;
    Ok(json(json!({
        "comment": edited.to_json("alert_id"),
        "success": true,
        "message": "Comment edited successfully",
    })))
}

/// `DELETE /alert/comment/{comment_id}`.
async fn delete_comment(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("comment_id", &raw)?;
    let existing = writes::comment(&ctx.db, CommentKind::Alert, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Comment not found"))?;
    let alert_id = existing.parent.map(i64::from);
    let subject = format!(
        "comment on alert {}",
        alert_id.map_or_else(|| "None".to_string(), |a| a.to_string())
    );
    match alert_id {
        Some(a) => {
            access::ensure_alert_msg(&ctx, &auth, a, &subject).await?;
        }
        None => return Err(ApiError::not_found("Alert not found")),
    }
    ensure_can_modify_comment(&auth, &existing.user_name)?;
    writes::delete_comment(&ctx.db, CommentKind::Alert, id).await?;
    Ok(message_success("Comment deleted successfully"))
}

/// `PUT /alert/assigned-to` (#1099): the assignee must exist; notifies on a
/// change only.
async fn assign(State(ctx): State<AppContext>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    let req = body.model(|v, o, at| IdText::read(v, o, at, "alert_id", "assigned_to"))?;
    if !user_exists(&ctx, &req.value).await? {
        return Err(ApiError::bad_request("User does not exist"));
    }
    access::ensure_alert(&ctx, &auth, req.id).await?;
    let before = store::alert(&ctx.db, req.id).await?;
    let row = writes::update_alert_assigned_to(&ctx.db, req.id, &req.value).await?;
    sla(&ctx)
        .alert_action(
            req.id,
            LifecycleAction::Assigned,
            &actor(&auth),
            None,
            Some(&req.value),
        )
        .await;
    notify_assigned(&ctx, &auth, req.id, before.as_ref(), &req.value);
    Ok(alert_response(&row, "Alert assigned to user successfully"))
}

fn notify_assigned(
    ctx: &AppContext,
    user: &CurrentUser,
    alert_id: i64,
    before: Option<&AlertRow>,
    assignee: &str,
) {
    let previous = before.and_then(|a| a.assigned_to.as_deref());
    if previous == Some(assignee) {
        return;
    }
    let severity = before.map(|a| super::common::severity_of(ctx, a.severity.as_deref()));
    let event = copilot_core::notify::alert_assigned_event(
        &ctx.notification_defaults,
        alert_id,
        &Assignment {
            title: before.map(|a| a.alert_name.as_str()),
            assignee: Some(assignee),
            actor: Some(&user.username),
            customer_code: before.map(|a| a.customer_code.as_str()),
        },
        severity,
    );
    ctx.notifications.emit(event, Some(user.bearer.clone()));
}

/// `PUT /alerts/assigned-to` (#1098).
async fn bulk_assign(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(BulkAssign::read)?;
    if !user_exists(&ctx, &req.assigned_to).await? {
        return Err(ApiError::bad_request("User does not exist"));
    }
    let mut updated = Vec::new();
    let mut skipped = Vec::new();
    for id in &req.alert_ids {
        if ensure_alert_soft(&ctx, &auth, *id).await?.is_err() {
            skipped.push(*id);
            continue;
        }
        let before = store::alert(&ctx.db, *id).await?;
        match writes::update_alert_assigned_to(&ctx.db, *id, &req.assigned_to).await {
            Ok(_) => {
                updated.push(*id);
                notify_assigned(&ctx, &auth, *id, before.as_ref(), &req.assigned_to);
            }
            Err(ApiError::Http { .. }) => skipped.push(*id),
            Err(e) => return Err(e),
        }
    }
    sla(&ctx)
        .alerts_action(
            &updated,
            LifecycleAction::Assigned,
            &actor(&auth),
            None,
            Some(&req.assigned_to),
        )
        .await;
    Ok(json(json!({
        "message": format!("Assigned {} alert(s) to {}", updated.len(), req.assigned_to),
        "updated_alert_ids": updated,
        "not_updated_alert_ids": skipped,
        "success": true,
    })))
}

/// `POST /alert/context`.
async fn create_context(
    State(ctx): State<AppContext>,
    WithJson(_auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(AlertContextCreate::read)?;
    let row = writes::create_alert_context(&ctx.db, &req.source, &req.context).await?;
    Ok(json(json!({
        "alert_context": row,
        "success": true,
        "message": "Alert context created successfully",
    })))
}

/// `POST /alert/asset` (#1102).
async fn create_asset(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(AssetCreate::read)?;
    access::ensure_alert(&ctx, &auth, req.alert_linked).await?;
    let asset = writes::create_asset(&ctx.db, &req).await?;
    Ok(json(json!({
        "asset": asset,
        "success": true,
        "message": "Asset created successfully",
    })))
}

/// `POST /alert/ioc`.
async fn create_ioc(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(IocCreate::read)?;
    access::ensure_alert(&ctx, &auth, req.alert_id).await?;
    let link = writes::create_alert_ioc(&ctx.db, &req).await?;
    Ok(json(json!({
        "alert_ioc": link,
        "success": true,
        "message": "Alert IoC created successfully",
    })))
}

/// `DELETE /alert/ioc`.
async fn delete_ioc(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(|v, o, at| TwoIds::read(v, o, at, "alert_id", "ioc_id"))?;
    access::ensure_alert(&ctx, &auth, req.a).await?;
    let link = writes::delete_alert_ioc(&ctx.db, req.a, req.b).await?;
    Ok(json(json!({
        "alert_ioc": link,
        "success": true,
        "message": "Alert IoC deleted successfully",
    })))
}

/// `POST /alert/tag`.
async fn create_tag(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(|v, o, at| IdText::read(v, o, at, "alert_id", "tag"))?;
    access::ensure_alert(&ctx, &auth, req.id).await?;
    let tag = writes::create_alert_tag(&ctx.db, req.id, &req.value).await?;
    Ok(json(json!({
        "alert_tag": tag,
        "success": true,
        "message": "Alert tag created successfully",
    })))
}

/// `DELETE /alert/tag` (#1102: tags gate visibility, so this is checked).
async fn delete_tag(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(|v, o, at| TwoIds::read(v, o, at, "alert_id", "tag_id"))?;
    access::ensure_alert(&ctx, &auth, req.a).await?;
    let tag = writes::delete_alert_tag(&ctx.db, req.a, req.b).await?;
    Ok(json(json!({
        "alert_tag": tag,
        "success": true,
        "message": "Alert tag deleted successfully",
    })))
}

/// `DELETE /alert/{alert_id}`.
async fn delete_alert(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("alert_id", &raw)?;
    access::ensure_alert(&ctx, &auth, id).await?;
    writes::ensure_not_linked(&ctx.db, id).await?;
    writes::delete_alert(&ctx.db, id).await?;
    Ok(message_success("Alert deleted successfully"))
}

/// `DELETE /alerts` (#1099): per alert; linked, missing or not the caller's
/// is a skip.
async fn delete_alerts(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let ids = body.model(requests::alert_ids)?;
    let mut deleted = Vec::new();
    let mut skipped = Vec::new();
    for id in &ids {
        if ensure_alert_soft(&ctx, &auth, *id).await?.is_err() {
            skipped.push(*id);
            continue;
        }
        let result = match writes::ensure_not_linked(&ctx.db, *id).await {
            Ok(()) => writes::delete_alert(&ctx.db, *id).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => deleted.push(*id),
            Err(e @ ApiError::Http { .. }) if [400, 403, 404].contains(&e.status().as_u16()) => {
                skipped.push(*id);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(json(json!({
        "message": "Alerts processed successfully",
        "deleted_alert_ids": deleted,
        "not_deleted_alert_ids": skipped,
        "success": true,
    })))
}

/// `DELETE /alerts/by-title/{title_filter}`: what the caller may see.
async fn delete_by_title(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(title): Path<String>,
) -> ApiResult {
    let access = auth.access(&ctx).await?;
    let vis = AlertVisibility::for_user(&ctx.db, auth.id, auth.role_id, access, None).await?;
    let matching: Vec<i32> = match vis {
        None => Vec::new(),
        Some(vis) => {
            let mut qb = sqlx::QueryBuilder::new(
                "SELECT a.id FROM incident_management_alert a WHERE lower(a.alert_name) LIKE lower(",
            );
            qb.push_bind(format!("%{title}%"));
            qb.push(")");
            vis.push_and(&mut qb, "a");
            qb.build_query_scalar::<i32>()
                .fetch_all(ctx.db.pool())
                .await
                .map_err(ApiError::internal)?
        }
    };
    if matching.is_empty() {
        return Ok(json(json!({
            "message": format!("No alerts found matching title filter: {title}"),
            "deleted_alert_ids": [],
            "not_deleted_alert_ids": [],
            "success": true,
        })));
    }
    let mut deleted = Vec::new();
    let mut skipped = Vec::new();
    for id in &matching {
        let id = i64::from(*id);
        match writes::ensure_not_linked(&ctx.db, id).await {
            Ok(()) => {}
            Err(e) if e.status().as_u16() == 400 => {
                skipped.push(id);
                continue;
            }
            Err(e) => return Err(e),
        }
        writes::delete_alert(&ctx.db, id).await?;
        deleted.push(id);
    }
    Ok(json(json!({
        "message": format!(
            "Processed {} alerts matching '{title}'. Deleted: {}, Skipped: {}",
            matching.len(),
            deleted.len(),
            skipped.len()
        ),
        "deleted_alert_ids": deleted,
        "not_deleted_alert_ids": skipped,
        "success": true,
    })))
}
