//! The case writes of `/api/incidents/db_operations`: creation (from scratch
//! or from an alert), alert links, comments, status (with the alert cascade
//! and the mandatory-task warning), escalation, severity, assignment and the
//! customer move — with their timeline events, audit rows, SLA milestones
//! and the `case_assigned` notification.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, post, put};
use serde_json::{Value, json};

use copilot_auth::AccessScope;
use copilot_core::audit::AuditRecord;
use copilot_sla::LifecycleAction;
use copilot_web::validate::{IntRules, StrRules, Validator, loc};
use copilot_web::{
    AdminOrAnalyst, AnyPortalOrSoc, ApiError, ApiResult, AppContext, Authorized, CurrentUser,
    QueryPairs, WithJson,
};

use super::common::{
    actor, ensure_can_modify_comment, ensure_customer_may_set_status, is_customer_user, json,
    message_success, path_int, sla, user_exists,
};
use crate::access;
use crate::events::{self, CaseEvent};
use crate::requests::{
    self, CaseCreate, CommentCreate, CommentEdit, IdBool, IdText, TwoIds, UpdateCaseSeverity,
    UpdateStatus, merge,
};
use crate::schema::{CaseOutResponse, CaseTaskOut};
use crate::store::{self, CaseTaskRow, TASK_COLS};
use crate::templates;
use crate::views;
use crate::writes::{self, CommentKind};
use copilot_core::notify::Assignment;

type Soc = Authorized<AdminOrAnalyst>;
type Any = Authorized<AnyPortalOrSoc>;

/// The case write routes (nested at `/api/incidents/db_operations`).
pub fn router() -> Router<AppContext> {
    Router::new()
        .route("/case/comment", post(create_comment).put(edit_comment))
        .route("/case/comment/{comment_id}", delete(delete_comment))
        .route("/case/create", post(create_case))
        .route("/case/alert-link", post(link_alert))
        .route("/case/alert-links", post(link_alerts))
        .route("/case/alert-unlink", post(unlink_alert))
        .route("/case/from-alert", post(case_from_alert))
        .route("/case/status", put(update_status))
        .route("/case/escalated", put(update_escalated))
        .route("/case/severity", put(update_severity))
        .route("/case/assigned-to", put(assign))
        .route("/case/customer-code", put(move_customer))
}

/// `template_id: Optional[int] = Query(None)`.
fn template_id(v: &mut Validator, q: &QueryPairs) -> Option<i64> {
    q.get("template_id").and_then(|raw| {
        v.check_int(
            &loc("query", "template_id"),
            &Value::String(raw.into()),
            IntRules::default(),
        )
    })
}

async fn case_response(ctx: &AppContext, case_id: i64, message: String) -> ApiResult {
    let case = views::case_full(&ctx.db, case_id).await?;
    Ok(json(CaseOutResponse {
        cases: vec![case],
        success: true,
        message,
        ..Default::default()
    }))
}

// ── comments ──────────────────────────────────────────────────────────────

/// `resume_case_on_reply`: a portal user's comment hands a waiting case
/// (and the alerts waiting with it) back to the SOC.
async fn resume_case_on_reply(
    ctx: &AppContext,
    user: &CurrentUser,
    case_id: i64,
) -> Result<(), ApiError> {
    if !is_customer_user(user) {
        return Ok(());
    }
    let status = store::case(&ctx.db, case_id).await?.map(|c| c.case_status);
    if status.as_deref() != Some("PENDING_CUSTOMER") {
        return Ok(());
    }
    let alert_ids: Vec<i64> = writes::linked_alert_statuses(&ctx.db, case_id)
        .await?
        .into_iter()
        .filter(|(_, s)| s == "PENDING_CUSTOMER")
        .map(|(id, _)| id)
        .collect();
    for id in &alert_ids {
        writes::update_alert_status(&ctx.db, *id, "IN_PROGRESS").await?;
    }
    writes::update_case_status(&ctx.db, case_id, "IN_PROGRESS").await?;
    let who = actor(user);
    let recorder = sla(ctx);
    recorder
        .case_action(
            case_id,
            LifecycleAction::StatusChanged,
            &who,
            Some("IN_PROGRESS"),
            None,
        )
        .await;
    recorder
        .alerts_action(
            &alert_ids,
            LifecycleAction::StatusChanged,
            &who,
            Some("IN_PROGRESS"),
            None,
        )
        .await;
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            case_id,
            events::CASE_STATUS_CHANGED,
            &user.username,
            events::status_change(Some("PENDING_CUSTOMER"), "IN_PROGRESS", false),
        )],
    )
    .await;
    Ok(())
}

/// `POST /case/comment`.
async fn create_comment(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let req = body.model(|v, o, at| CommentCreate::read(v, o, at, "case_id"))?;
    access::ensure_case(&ctx, &auth, req.parent).await?;
    let created = writes::create_comment(
        &ctx.db,
        CommentKind::Case,
        req.parent,
        &req.comment,
        &auth.username,
        req.created_at,
    )
    .await?;
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            req.parent,
            events::COMMENT_ADDED,
            &auth.username,
            events::comment(created.id, &created.comment),
        )],
    )
    .await;
    sla(&ctx)
        .case_action(
            req.parent,
            LifecycleAction::Commented,
            &actor(&auth),
            None,
            None,
        )
        .await;
    resume_case_on_reply(&ctx, &auth, req.parent).await?;
    Ok(json(json!({
        "comment": created.to_json("case_id"),
        "success": true,
        "message": "Case comment created successfully",
    })))
}

/// `PUT /case/comment`: the comment decides which case is checked.
async fn edit_comment(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let req = body.model(|v, o, at| CommentEdit::read(v, o, at, "case_id"))?;
    let existing = writes::comment(&ctx.db, CommentKind::Case, req.comment_id)
        .await?
        .filter(|c| c.parent.map(i64::from) == Some(req.parent))
        .ok_or_else(|| ApiError::not_found("Comment not found"))?;
    access::ensure_case(&ctx, &auth, req.parent).await?;
    ensure_can_modify_comment(&auth, &existing.user_name)?;
    let edited = writes::edit_comment(
        &ctx.db,
        CommentKind::Case,
        req.comment_id,
        &req.comment,
        &auth.username,
    )
    .await?;
    Ok(json(json!({
        "comment": edited.to_json("case_id"),
        "success": true,
        "message": "Case comment edited successfully",
    })))
}

/// `DELETE /case/comment/{comment_id}`.
async fn delete_comment(
    auth: Any,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let id = path_int("comment_id", &raw)?;
    let existing = writes::comment(&ctx.db, CommentKind::Case, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Comment not found"))?;
    let Some(case_id) = existing.parent.map(i64::from) else {
        return Err(ApiError::not_found("Case not found"));
    };
    access::ensure_case_msg(&ctx, &auth, case_id, &format!("comment on case {case_id}")).await?;
    ensure_can_modify_comment(&auth, &existing.user_name)?;
    writes::delete_comment(&ctx.db, CommentKind::Case, id).await?;
    Ok(message_success("Case comment deleted successfully"))
}

// ── creation and links ────────────────────────────────────────────────────

/// `POST /case/create`: the body's customer must be the caller's
/// (GHSA-wjpw-xrg8-vmf9); audited; an optional template applied.
async fn create_case(
    State(ctx): State<AppContext>,
    q: QueryPairs,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let mut v = Validator::new();
    let template = template_id(&mut v, &q);
    let req = merge(v, body.model(CaseCreate::read))?;
    access::ensure_customer(&ctx, &auth, req.customer_code.as_deref()).await?;

    let mut tx = ctx.db.pool().begin().await.map_err(ApiError::internal)?;
    let case_id = writes::insert_case(&mut tx, &req).await?;
    if let Some(t) = template {
        templates::apply_template(&mut tx, case_id, t, &auth.username, None)
            .await
            .map_err(|e| writes::integrity_or_internal(e, "Case already exists"))?;
    }
    tx.commit()
        .await
        .map_err(|e| writes::integrity_or_internal(e, "Case already exists"))?;
    let recorder = sla(&ctx);
    recorder.case_opened(case_id).await;

    let created = store::case(&ctx.db, case_id)
        .await?
        .ok_or_else(|| ApiError::internal("created case vanished"))?;
    ctx.audit.record(
        AuditRecord::new("case.create")
            .actor(Some(auth.id), Some(&auth.username))
            .customer(req.customer_code.as_deref())
            .entity("case", case_id)
            .values(
                None,
                Some(json!({"case_name": created.case_name, "customer_code": req.customer_code})),
            )
            .source_ip(auth.source_ip.clone()),
    );
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            case_id,
            events::CASE_CREATED,
            &auth.username,
            json!({"source": "manual", "template_id": template}),
        )],
    )
    .await;
    recorder
        .case_action(case_id, LifecycleAction::Created, &actor(&auth), None, None)
        .await;
    Ok(json(json!({
        "case": writes::case_record(&created),
        "success": true,
        "message": "Case created successfully",
    })))
}

/// Insert one link (`CaseAlertLink`), `IntegrityError` → 400 `detail`.
async fn insert_link(
    conn: &mut sqlx::MySqlConnection,
    case_id: i64,
    alert_id: i64,
    detail: &str,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO incident_management_casealertlink (case_id, alert_id) VALUES (?, ?)")
        .bind(case_id)
        .bind(alert_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| writes::integrity_or_internal(e, detail))?;
    Ok(())
}

/// `auto_apply_template_for_new_case(case, alert)` inside `conn`'s
/// transaction, with the templates already picked.
async fn apply_picked(
    conn: &mut sqlx::MySqlConnection,
    case_id: i64,
    alert_id: i64,
    picked: &[templates::TemplateRow],
    actor: &str,
    detail: &str,
) -> Result<(), ApiError> {
    for t in picked {
        templates::apply_template(conn, case_id, i64::from(t.id), actor, Some(alert_id))
            .await
            .map_err(|e| writes::integrity_or_internal(e, detail))?;
    }
    Ok(())
}

/// `POST /case/alert-link`: both ends checked (GHSA-wjpw-xrg8-vmf9); the
/// per-alert template auto-apply runs.
async fn link_alert(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let req = body.model(|v, o, at| TwoIds::read(v, o, at, "case_id", "alert_id"))?;
    let (case_id, alert_id) = (req.a, req.b);
    let case = access::ensure_case(&ctx, &auth, case_id).await?;
    let alert = access::ensure_alert(&ctx, &auth, alert_id).await?;
    let detail = "Case alert link already exists";
    let picked = templates::pick_templates_for_alert(
        &ctx,
        case.customer_code.as_deref(),
        alert_id,
        &alert.row.source,
    )
    .await
    .map_err(ApiError::internal)?;
    let mut tx = ctx.db.pool().begin().await.map_err(ApiError::internal)?;
    insert_link(&mut tx, case_id, alert_id, detail).await?;
    apply_picked(&mut tx, case_id, alert_id, &picked, &auth.username, detail).await?;
    tx.commit()
        .await
        .map_err(|e| writes::integrity_or_internal(e, detail))?;
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            case_id,
            events::ALERT_LINKED,
            &auth.username,
            events::alert_link(alert_id, &[]),
        )],
    )
    .await;
    let recorder = sla(&ctx);
    recorder
        .alert_action(
            alert_id,
            LifecycleAction::LinkedToCase,
            &actor(&auth),
            None,
            None,
        )
        .await;
    recorder.case_links_changed(case_id).await;
    Ok(json(json!({
        "case_alert_link": {"case_id": case_id, "alert_id": alert_id},
        "success": true,
        "message": "Case alert link created successfully",
    })))
}

/// `POST /case/alert-links` (#1102): a denied alert fails the request.
async fn link_alerts(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let (case_id, alert_ids) = body.model(|v, o, at| {
        (
            requests::one_id(v, o, at, "case_id"),
            requests::alert_ids(v, o, at),
        )
    })?;
    let case = access::ensure_case(&ctx, &auth, case_id).await?;
    for id in &alert_ids {
        access::ensure_alert(&ctx, &auth, *id).await?;
    }
    let detail = "Case alert links already exist";
    // `select(Alert).where(Alert.id.in_(ids))`: each alert once, in id order.
    let mut unique: Vec<i64> = alert_ids.clone();
    unique.sort_unstable();
    unique.dedup();
    let mut picks = Vec::new();
    for id in &unique {
        if let Some(alert) = store::alert(&ctx.db, *id).await? {
            let picked = templates::pick_templates_for_alert(
                &ctx,
                case.customer_code.as_deref(),
                *id,
                &alert.source,
            )
            .await
            .map_err(ApiError::internal)?;
            picks.push((*id, picked));
        }
    }
    let mut tx = ctx.db.pool().begin().await.map_err(ApiError::internal)?;
    for id in &alert_ids {
        insert_link(&mut tx, case_id, *id, detail).await?;
    }
    for (id, picked) in &picks {
        apply_picked(&mut tx, case_id, *id, picked, &auth.username, detail).await?;
    }
    tx.commit()
        .await
        .map_err(|e| writes::integrity_or_internal(e, detail))?;
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            case_id,
            events::ALERT_LINKED,
            &auth.username,
            events::alert_links_bulk(&alert_ids),
        )],
    )
    .await;
    let recorder = sla(&ctx);
    recorder
        .alerts_action(
            &alert_ids,
            LifecycleAction::LinkedToCase,
            &actor(&auth),
            None,
            None,
        )
        .await;
    recorder.case_links_changed(case_id).await;
    let links: Vec<Value> = alert_ids
        .iter()
        .map(|a| json!({"case_id": case_id, "alert_id": a}))
        .collect();
    Ok(json(json!({
        "case_alert_links": links,
        "success": true,
        "message": "Case alert links created successfully",
    })))
}

/// `POST /case/alert-unlink`: tasks stamped with the alert are orphaned,
/// not deleted.
async fn unlink_alert(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let req = body.model(|v, o, at| TwoIds::read(v, o, at, "case_id", "alert_id"))?;
    let (case_id, alert_id) = (req.a, req.b);
    access::ensure_case(&ctx, &auth, case_id).await?;
    let link: Option<(i32,)> = sqlx::query_as(
        "SELECT case_id FROM incident_management_casealertlink WHERE case_id = ? AND alert_id = ?",
    )
    .bind(case_id)
    .bind(alert_id)
    .fetch_optional(ctx.db.pool())
    .await
    .map_err(ApiError::internal)?;
    if link.is_none() {
        return Err(ApiError::not_found("Case alert link not found"));
    }
    let mut tx = ctx.db.pool().begin().await.map_err(ApiError::internal)?;
    sqlx::query("DELETE FROM incident_management_casealertlink WHERE case_id = ? AND alert_id = ?")
        .bind(case_id)
        .bind(alert_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let orphaned = sqlx::query(
        "UPDATE incident_management_case_task SET alert_id = NULL, updated_at = ? \
         WHERE case_id = ? AND alert_id = ?",
    )
    .bind(copilot_core::time::now_utc_naive())
    .bind(case_id)
    .bind(alert_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?
    .rows_affected();
    tx.commit().await.map_err(ApiError::internal)?;
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            case_id,
            events::ALERT_UNLINKED,
            &auth.username,
            events::alert_link(alert_id, &[("tasks_orphaned", json!(orphaned))]),
        )],
    )
    .await;
    sla(&ctx).case_links_changed(case_id).await;
    let message = if orphaned > 0 {
        format!("Case alert link deleted successfully; {orphaned} task(s) orphaned")
    } else {
        "Case alert link deleted successfully".to_string()
    };
    Ok(json(json!({
        "success": true,
        "message": message,
        "tasks_orphaned": orphaned,
    })))
}

/// `POST /case/from-alert`: a case from the alert, the template applied
/// against it, then the link.
async fn case_from_alert(
    State(ctx): State<AppContext>,
    q: QueryPairs,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let mut v = Validator::new();
    let template = template_id(&mut v, &q);
    let alert_id = merge(
        v,
        body.model(|v, o, at| requests::one_id(v, o, at, "alert_id")),
    )?;
    let alert = access::ensure_alert(&ctx, &auth, alert_id).await?;
    let row = alert.row;
    let picked = match template {
        Some(_) => Vec::new(),
        None => templates::pick_templates_for_alert(
            &ctx,
            Some(&row.customer_code),
            alert_id,
            &row.source,
        )
        .await
        .map_err(ApiError::internal)?,
    };
    let detail = "Case already exists";
    let mut tx = ctx.db.pool().begin().await.map_err(ApiError::internal)?;
    let case_id = writes::insert_case_from_alert(&mut tx, &row).await?;
    match template {
        Some(t) => {
            templates::apply_template(&mut tx, case_id, t, &auth.username, Some(alert_id))
                .await
                .map_err(|e| writes::integrity_or_internal(e, detail))?;
        }
        None => apply_picked(&mut tx, case_id, alert_id, &picked, &auth.username, detail).await?,
    }
    tx.commit()
        .await
        .map_err(|e| writes::integrity_or_internal(e, detail))?;
    let recorder = sla(&ctx);
    recorder.case_opened(case_id).await;

    let mut tx = ctx.db.pool().begin().await.map_err(ApiError::internal)?;
    insert_link(&mut tx, case_id, alert_id, "Case alert link already exists").await?;
    tx.commit()
        .await
        .map_err(|e| writes::integrity_or_internal(e, "Case alert link already exists"))?;
    events::emit(
        &ctx.db,
        &[
            CaseEvent::new(
                case_id,
                events::CASE_CREATED,
                &auth.username,
                json!({"source": "from_alert", "alert_id": alert_id, "template_id": template}),
            ),
            CaseEvent::new(
                case_id,
                events::ALERT_LINKED,
                &auth.username,
                events::alert_link(alert_id, &[]),
            ),
        ],
    )
    .await;
    let who = actor(&auth);
    recorder.case_links_changed(case_id).await;
    recorder
        .case_action(case_id, LifecycleAction::Created, &who, None, None)
        .await;
    recorder
        .alert_action(alert_id, LifecycleAction::LinkedToCase, &who, None, None)
        .await;
    Ok(json(json!({
        "case_alert_link": {"case_id": case_id, "alert_id": alert_id},
        "success": true,
        "message": "Case created from alert successfully",
    })))
}

// ── status, escalation, severity, assignment, customer ────────────────────

/// `status_cascade.cascade_for`: the alerts' new status and which alerts
/// move (`None` = all of them).
pub fn cascade_for(
    old: Option<&str>,
    new: &str,
) -> Option<(&'static str, Option<&'static [&'static str]>)> {
    const ACTIVE: &[&str] = &["OPEN", "IN_PROGRESS"];
    if new == "CLOSED" {
        return (old != Some("CLOSED")).then_some(("CLOSED", None));
    }
    if old == Some("CLOSED") {
        let to = if new == "PENDING_CUSTOMER" {
            "PENDING_CUSTOMER"
        } else {
            "IN_PROGRESS"
        };
        return Some((to, None));
    }
    if new == "PENDING_CUSTOMER" && old != Some("PENDING_CUSTOMER") {
        return Some(("PENDING_CUSTOMER", Some(ACTIVE)));
    }
    if old == Some("PENDING_CUSTOMER") && ACTIVE.contains(&new) {
        return Some(("IN_PROGRESS", Some(&["PENDING_CUSTOMER"])));
    }
    None
}

/// `PUT /case/status`: closing with mandatory tasks open is a soft warning
/// unless `force`; the linked alerts follow the cascade.
async fn update_status(
    State(ctx): State<AppContext>,
    q: QueryPairs,
    WithJson(auth, body): WithJson<Any>,
) -> ApiResult {
    let mut v = Validator::new();
    let force = q
        .get("force")
        .and_then(|raw| {
            let obj =
                serde_json::Map::from_iter([("force".to_string(), Value::String(raw.into()))]);
            v.opt_bool(
                &obj,
                &vec![copilot_web::validate::LocPart::Key("query".into())],
                "force",
            )
        })
        .unwrap_or(false);
    let req = merge(
        v,
        body.model(|v, o, at| UpdateStatus::read(v, o, at, "case_id")),
    )?;
    ensure_customer_may_set_status(&auth, &req.status)?;
    let case = access::ensure_case(&ctx, &auth, req.id).await?;
    let old = Some(case.case_status.clone());
    let new = req.status.as_str();

    if new == "CLOSED" && old.as_deref() != Some("CLOSED") && !force {
        let incomplete: Vec<CaseTaskRow> = sqlx::query_as(&format!(
            "SELECT {TASK_COLS} FROM incident_management_case_task WHERE case_id = ? \
             AND mandatory = true AND status != 'DONE' ORDER BY order_index, id"
        ))
        .bind(req.id)
        .fetch_all(ctx.db.pool())
        .await
        .map_err(ApiError::internal)?;
        if !incomplete.is_empty() {
            let tasks: Vec<CaseTaskOut> = incomplete.iter().map(CaseTaskOut::from).collect();
            return Ok(json(json!({
                "success": false,
                "requires_confirmation": true,
                "message": format!(
                    "{} mandatory task(s) are not marked DONE. Re-submit with force=true to close anyway.",
                    incomplete.len()
                ),
                "incomplete_mandatory_tasks": tasks,
            })));
        }
    }

    let linked = writes::linked_alert_statuses(&ctx.db, req.id).await?;
    let cascade = cascade_for(old.as_deref(), new);
    let alert_ids: Vec<i64> = linked
        .iter()
        .filter(|(_, s)| {
            cascade.is_some_and(|(_, from)| from.is_none_or(|f| f.contains(&s.as_str())))
        })
        .map(|(id, _)| *id)
        .collect();
    let mut failed: Vec<i64> = Vec::new();
    if let Some((to, _)) = cascade {
        for id in &alert_ids {
            if writes::update_alert_status(&ctx.db, *id, to).await.is_err() {
                failed.push(*id);
            }
        }
    }
    if let Err(e) = writes::update_case_status(&ctx.db, req.id, new).await {
        return Err(ApiError::server_error(format!(
            "Failed to update case status: {e}"
        )));
    }
    let who = actor(&auth);
    let recorder = sla(&ctx);
    recorder
        .case_action(
            req.id,
            LifecycleAction::StatusChanged,
            &who,
            Some(new),
            None,
        )
        .await;
    if let Some((to, _)) = cascade {
        let moved: Vec<i64> = alert_ids
            .iter()
            .copied()
            .filter(|a| !failed.contains(a))
            .collect();
        recorder
            .alerts_action(&moved, LifecycleAction::StatusChanged, &who, Some(to), None)
            .await;
    }
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            req.id,
            events::CASE_STATUS_CHANGED,
            &auth.username,
            events::status_change(old.as_deref(), new, force && new == "CLOSED"),
        )],
    )
    .await;
    let mut message = "Case status updated successfully".to_string();
    if let (Some((to, _)), false) = (cascade, alert_ids.is_empty()) {
        message.push_str(&format!(
            " and {} linked alerts updated to {to}",
            alert_ids.len()
        ));
    }
    case_response(&ctx, req.id, message).await
}

/// `PUT /case/escalated`.
async fn update_escalated(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(|v, o, at| IdBool::read(v, o, at, "case_id", "escalated"))?;
    access::ensure_case(&ctx, &auth, req.id).await?;
    writes::update_case_column(&ctx.db, req.id, "escalated", Value::Bool(req.value)).await?;
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            req.id,
            events::CASE_ESCALATED,
            &auth.username,
            events::escalation(req.value),
        )],
    )
    .await;
    sla(&ctx)
        .case_action(
            req.id,
            LifecycleAction::Escalated,
            &actor(&auth),
            None,
            None,
        )
        .await;
    case_response(
        &ctx,
        req.id,
        "Case escalated status updated successfully".into(),
    )
    .await
}

/// `PUT /case/severity` (#1187): re-targets the running clocks.
async fn update_severity(
    State(ctx): State<AppContext>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let req = body.model(UpdateCaseSeverity::read)?;
    access::ensure_case(&ctx, &auth, req.case_id).await?;
    let value = req.severity.clone().map_or(Value::Null, Value::String);
    let before = writes::update_case_column(&ctx.db, req.case_id, "severity", value).await?;
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            req.case_id,
            events::CASE_SEVERITY_CHANGED,
            &auth.username,
            json!({"from": before.severity, "to": req.severity}),
        )],
    )
    .await;
    sla(&ctx)
        .case_severity_changed(req.case_id, &actor(&auth))
        .await;
    case_response(
        &ctx,
        req.case_id,
        "Case severity updated successfully".into(),
    )
    .await
}

/// `PUT /case/assigned-to`: the case first, then the user; notifies on a
/// change only.
async fn assign(State(ctx): State<AppContext>, WithJson(auth, body): WithJson<Any>) -> ApiResult {
    let req = body.model(|v, o, at| IdText::read(v, o, at, "case_id", "assigned_to"))?;
    let case = access::ensure_case(&ctx, &auth, req.id).await?;
    if !user_exists(&ctx, &req.value).await? {
        return Err(ApiError::bad_request("User does not exist"));
    }
    let previous = case.assigned_to.clone();
    writes::update_case_column(
        &ctx.db,
        req.id,
        "assigned_to",
        Value::String(req.value.clone()),
    )
    .await?;
    events::emit(
        &ctx.db,
        &[CaseEvent::new(
            req.id,
            events::CASE_ASSIGNED,
            &auth.username,
            events::assignment(previous.as_deref(), Some(&req.value)),
        )],
    )
    .await;
    sla(&ctx)
        .case_action(
            req.id,
            LifecycleAction::Assigned,
            &actor(&auth),
            None,
            Some(&req.value),
        )
        .await;
    if previous.as_deref() != Some(req.value.as_str()) {
        let event = copilot_core::notify::case_assigned_event(
            req.id,
            &Assignment {
                title: Some(&case.case_name),
                assignee: Some(&req.value),
                actor: Some(&auth.username),
                customer_code: case.customer_code.as_deref(),
            },
        );
        ctx.notifications.emit(event, Some(auth.bearer.clone()));
    }
    case_response(&ctx, req.id, "Case assigned to user successfully".into()).await
}

/// `PUT /case/customer-code?case_id=&customer_code=`: both customers must be
/// the caller's, and the new one must have alert creation settings.
async fn move_customer(auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let case_id = match q.get("case_id") {
        Some(raw) => v
            .check_int(
                &loc("query", "case_id"),
                &Value::String(raw.into()),
                IntRules::default(),
            )
            .unwrap_or_default(),
        None => {
            v.missing(loc("query", "case_id"));
            0
        }
    };
    let obj: serde_json::Map<String, Value> = q
        .get("customer_code")
        .map(|c| ("customer_code".to_string(), Value::String(c.into())))
        .into_iter()
        .collect();
    let code = v.req_str(
        &obj,
        &vec![copilot_web::validate::LocPart::Key("query".into())],
        "customer_code",
        StrRules::any(),
    );
    v.finish()?;
    access::ensure_case(&ctx, &auth, case_id).await?;
    if let AccessScope::Customers(codes) = auth.access(&ctx).await? {
        if !codes.contains(&code) {
            return Err(ApiError::forbidden(format!(
                "Access denied - cannot assign case to customer {code}"
            )));
        }
    }
    writes::customer_code_valid(&ctx.db, &code).await?;
    writes::update_case_column(&ctx.db, case_id, "customer_code", Value::String(code)).await?;
    case_response(
        &ctx,
        case_id,
        "Case customer code updated successfully".into(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::cascade_for;

    #[test]
    fn cascade_rules() {
        assert_eq!(cascade_for(Some("OPEN"), "CLOSED"), Some(("CLOSED", None)));
        assert_eq!(cascade_for(Some("CLOSED"), "CLOSED"), None);
        assert_eq!(
            cascade_for(Some("CLOSED"), "OPEN"),
            Some(("IN_PROGRESS", None))
        );
        assert_eq!(
            cascade_for(Some("CLOSED"), "PENDING_CUSTOMER"),
            Some(("PENDING_CUSTOMER", None))
        );
        assert_eq!(
            cascade_for(Some("OPEN"), "PENDING_CUSTOMER"),
            Some(("PENDING_CUSTOMER", Some(&["OPEN", "IN_PROGRESS"][..])))
        );
        assert_eq!(
            cascade_for(Some("PENDING_CUSTOMER"), "OPEN"),
            Some(("IN_PROGRESS", Some(&["PENDING_CUSTOMER"][..])))
        );
        assert_eq!(cascade_for(Some("OPEN"), "IN_PROGRESS"), None);
    }
}
