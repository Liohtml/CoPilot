//! The case-task writes of `/api/incidents/db_operations` — port of
//! `add_case_task`, `update_case_task`, `delete_case_task` and the manual
//! template apply (`app/incidents/services/case_tasks.py`).
//!
//! The services answer 200 with `success: false` for what they refuse
//! (an alert not linked to the case, `NOT_NECESSARY` on a mandatory task, an
//! unknown assignee); the routes' own lookups are 404s.

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{patch, post};
use serde_json::{Map, Value, json};

use copilot_core::time::{mysql_datetime, now_utc_micros};
use copilot_web::validate::{IntRules, Loc, StrRules, Validator, loc};
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs, WithJson,
};

use super::common::{json, user_exists};
use crate::access;
use crate::events::{self, CaseEvent};
use crate::notify;
use crate::requests::merge;
use crate::schema::{CaseTaskOut, TASK_STATUSES};
use crate::store::{CaseTaskRow, TASK_COLS};
use crate::templates;

type Soc = Authorized<AdminOrAnalyst>;
type Obj = Map<String, Value>;

/// The case-task write routes (nested at `/api/incidents/db_operations`).
pub fn router() -> Router<AppContext> {
    Router::new()
        .route("/case/{case_id}/tasks", post(add_task))
        .route(
            "/case/tasks/{task_id}",
            patch(update_task).delete(delete_task),
        )
        .route(
            "/case/{case_id}/apply-template/{template_id}",
            post(apply_template),
        )
}

fn path_int(v: &mut Validator, name: &str, raw: &str) -> i64 {
    v.check_int(
        &loc("path", name),
        &Value::String(raw.into()),
        IntRules::default(),
    )
    .unwrap_or_default()
}

fn int_or(v: &mut Validator, o: &Obj, at: &Loc, name: &str, rules: IntRules, default: i64) -> i64 {
    match o.get(name) {
        None => default,
        Some(value) => {
            let mut l = at.clone();
            l.push(copilot_web::validate::LocPart::Key(name.into()));
            v.check_int(&l, value, rules).unwrap_or(default)
        }
    }
}

/// `CaseTaskCreate`.
struct TaskCreate {
    title: String,
    description: Option<String>,
    guidelines: Option<String>,
    mandatory: bool,
    order_index: i64,
    alert_id: Option<i64>,
}

impl TaskCreate {
    fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            title: v.req_str(
                o,
                at,
                "title",
                StrRules {
                    max_len: Some(500),
                    ..StrRules::any()
                },
            ),
            description: v.opt_str(o, at, "description", StrRules::any()),
            guidelines: v.opt_str(o, at, "guidelines", StrRules::any()),
            mandatory: v.bool_or(o, at, "mandatory", false),
            order_index: int_or(
                v,
                o,
                at,
                "order_index",
                IntRules {
                    ge: Some(0),
                    le: None,
                },
                0,
            ),
            alert_id: v.opt_int(o, at, "alert_id", IntRules::default()),
        }
    }
}

/// `CaseTaskUpdate` with its `__fields_set__`.
struct TaskUpdate {
    status: Option<Option<String>>,
    evidence_comment: Option<Option<String>>,
    assigned_to: Option<Option<String>>,
}

impl TaskUpdate {
    fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        let status = v.opt_enum(o, at, "status", TASK_STATUSES);
        let evidence = v.opt_str(o, at, "evidence_comment", StrRules::any());
        let assigned = v.opt_str(
            o,
            at,
            "assigned_to",
            StrRules {
                max_len: Some(100),
                ..StrRules::any()
            },
        );
        Self {
            status: o.contains_key("status").then_some(status),
            evidence_comment: o.contains_key("evidence_comment").then_some(evidence),
            assigned_to: o.contains_key("assigned_to").then_some(assigned),
        }
    }
}

async fn task_row(ctx: &AppContext, id: i64) -> Result<Option<CaseTaskRow>, ApiError> {
    sqlx::query_as::<_, CaseTaskRow>(&format!(
        "SELECT {TASK_COLS} FROM incident_management_case_task WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(ctx.db.pool())
    .await
    .map_err(ApiError::internal)
}

async fn alert_linked(ctx: &AppContext, case_id: i64, alert_id: i64) -> Result<bool, ApiError> {
    let found: Option<(i32,)> = sqlx::query_as(
        "SELECT alert_id FROM incident_management_casealertlink WHERE case_id = ? AND alert_id = ? \
         LIMIT 1",
    )
    .bind(case_id)
    .bind(alert_id)
    .fetch_optional(ctx.db.pool())
    .await
    .map_err(ApiError::internal)?;
    Ok(found.is_some())
}

fn op(task: Option<&CaseTaskRow>, success: bool, message: String) -> axum::response::Response {
    json(json!({
        "task": task.map(CaseTaskOut::from),
        "success": success,
        "message": message,
    }))
}

/// `POST /case/{case_id}/tasks`: a custom task (`template_task_id` NULL).
async fn add_task(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let mut v = Validator::new();
    let case_id = path_int(&mut v, "case_id", &raw);
    let req = merge(v, body.model(TaskCreate::read))?;
    access::ensure_case(&ctx, &auth, case_id).await?;
    if let Some(alert_id) = req.alert_id {
        if !alert_linked(&ctx, case_id, alert_id).await? {
            return Ok(op(
                None,
                false,
                format!(
                    "Alert id={alert_id} is not linked to case id={case_id}; link the alert first \
                     or omit alert_id for a case-wide task."
                ),
            ));
        }
    }
    let result = async {
        let mut tx = ctx.db.pool().begin().await?;
        let now = mysql_datetime(now_utc_micros());
        let inserted = sqlx::query(
            "INSERT INTO incident_management_case_task (case_id, alert_id, template_task_id, title, \
             description, guidelines, mandatory, order_index, status, evidence_comment, \
             completed_by, completed_at, assigned_to, created_by, created_at, updated_at) \
             VALUES (?, ?, NULL, ?, ?, ?, ?, ?, 'TODO', NULL, NULL, NULL, NULL, ?, ?, ?)",
        )
        .bind(case_id)
        .bind(req.alert_id)
        .bind(&req.title)
        .bind(&req.description)
        .bind(&req.guidelines)
        .bind(req.mandatory)
        .bind(req.order_index)
        .bind(&auth.username)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let task_id = inserted.last_insert_id() as i64;
        let payload = events::task(
            task_id,
            &req.title,
            req.mandatory,
            &[("source", json!("custom")), ("alert_id", json!(req.alert_id))],
        );
        events::insert(
            &mut tx,
            &CaseEvent::new(case_id, events::TASK_ADDED, &auth.username, payload),
        )
        .await?;
        tx.commit().await?;
        Ok::<i64, sqlx::Error>(task_id)
    }
    .await;
    match result {
        Ok(task_id) => {
            let row = task_row(&ctx, task_id).await?;
            Ok(op(
                row.as_ref(),
                true,
                format!("Added task id={task_id} to case id={case_id}"),
            ))
        }
        Err(e) => Ok(op(None, false, format!("Failed to add case task: {e}"))),
    }
}

/// `PATCH /case/tasks/{task_id}`: status, evidence, assignee — each only when
/// its key is sent.
async fn update_task(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let mut v = Validator::new();
    let task_id = path_int(&mut v, "task_id", &raw);
    let req = merge(v, body.model(TaskUpdate::read))?;
    let Some(mut task) = task_row(&ctx, task_id).await? else {
        return Err(ApiError::not_found(format!(
            "Case task {task_id} not found"
        )));
    };
    access::ensure_case(&ctx, &auth, i64::from(task.case_id)).await?;

    let previous_status = task.status.clone();
    let mut status_changed = false;
    if let Some(Some(status)) = &req.status {
        if status == "NOT_NECESSARY" && task.mandatory {
            return Ok(op(
                Some(&task),
                false,
                "Mandatory tasks cannot be marked NOT_NECESSARY.".into(),
            ));
        }
        if *status != task.status {
            task.status = status.clone();
            status_changed = true;
        }
        if status == "DONE" || status == "NOT_NECESSARY" {
            task.completed_by = Some(auth.username.clone());
            task.completed_at = Some(now_utc_micros());
        } else {
            task.completed_by = None;
            task.completed_at = None;
        }
    }
    let comment_sent = req.evidence_comment.is_some();
    if let Some(comment) = &req.evidence_comment {
        task.evidence_comment = comment.clone();
    }
    let previous_assignee = task.assigned_to.clone();
    let mut assignment_changed = false;
    if let Some(assigned) = &req.assigned_to {
        let new = assigned
            .as_deref()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty());
        if let Some(name) = &new {
            if !user_exists(&ctx, name).await? {
                return Ok(op(
                    Some(&task),
                    false,
                    format!("User '{name}' does not exist."),
                ));
            }
        }
        if new != previous_assignee {
            task.assigned_to = new;
            assignment_changed = true;
        }
    }
    task.updated_at = now_utc_micros();

    let case_id = i64::from(task.case_id);
    let mut timeline = Vec::new();
    if status_changed {
        timeline.push(CaseEvent::new(
            case_id,
            events::TASK_STATUS_CHANGED,
            &auth.username,
            events::task(
                task_id,
                &task.title,
                task.mandatory,
                &[
                    ("from_status", json!(previous_status)),
                    ("to_status", json!(task.status)),
                ],
            ),
        ));
    }
    if assignment_changed {
        timeline.push(CaseEvent::new(
            case_id,
            events::TASK_ASSIGNED,
            &auth.username,
            events::task(
                task_id,
                &task.title,
                task.mandatory,
                &[
                    ("from_assignee", json!(previous_assignee)),
                    ("to_assignee", json!(task.assigned_to)),
                ],
            ),
        ));
    }
    if let Some(Some(comment)) = req.evidence_comment.as_ref().filter(|_| comment_sent) {
        if !comment.is_empty() {
            let snippet: String = comment.chars().take(140).collect();
            timeline.push(CaseEvent::new(
                case_id,
                events::TASK_COMMENTED,
                &auth.username,
                events::task(
                    task_id,
                    &task.title,
                    task.mandatory,
                    &[("snippet", json!(snippet))],
                ),
            ));
        }
    }
    let result = async {
        let mut tx = ctx.db.pool().begin().await?;
        sqlx::query(
            "UPDATE incident_management_case_task SET status = ?, completed_by = ?, \
             completed_at = ?, evidence_comment = ?, assigned_to = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&task.status)
        .bind(&task.completed_by)
        .bind(task.completed_at.map(mysql_datetime))
        .bind(&task.evidence_comment)
        .bind(&task.assigned_to)
        .bind(mysql_datetime(task.updated_at))
        .bind(task_id)
        .execute(&mut *tx)
        .await?;
        for event in &timeline {
            events::insert(&mut tx, event).await?;
        }
        tx.commit().await
    }
    .await;
    if let Err(e) = result {
        return Ok(op(None, false, format!("Failed to update case task: {e}")));
    }
    let stored = task_row(&ctx, task_id).await?;
    if assignment_changed {
        let event = notify::case_task_assigned_event(
            task_id,
            case_id,
            Some(&task.title),
            task.assigned_to.as_deref(),
            Some(&auth.username),
            None,
        );
        ctx.notifications.emit(event, Some(auth.bearer.clone()));
    }
    Ok(op(
        stored.as_ref(),
        true,
        format!("Updated case task id={task_id}"),
    ))
}

/// `DELETE /case/tasks/{task_id}`: the snapshot it held.
async fn delete_task(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let mut v = Validator::new();
    let task_id = path_int(&mut v, "task_id", &raw);
    v.finish()?;
    let Some(task) = task_row(&ctx, task_id).await? else {
        return Err(ApiError::not_found(format!(
            "Case task {task_id} not found"
        )));
    };
    access::ensure_case(&ctx, &auth, i64::from(task.case_id)).await?;
    let deleted = sqlx::query("DELETE FROM incident_management_case_task WHERE id = ?")
        .bind(task_id)
        .execute(ctx.db.pool())
        .await;
    match deleted {
        Ok(_) => Ok(op(
            Some(&task),
            true,
            format!("Deleted case task id={task_id}"),
        )),
        Err(e) => Ok(op(None, false, format!("Failed to delete case task: {e}"))),
    }
}

/// `POST /case/{case_id}/apply-template/{template_id}?alert_id=`.
async fn apply_template(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path((raw_case, raw_template)): Path<(String, String)>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let case_id = path_int(&mut v, "case_id", &raw_case);
    let template_id = path_int(&mut v, "template_id", &raw_template);
    let alert_id = q.get("alert_id").and_then(|raw| {
        v.check_int(
            &loc("query", "alert_id"),
            &Value::String(raw.into()),
            IntRules::default(),
        )
    });
    v.finish()?;
    access::ensure_case(&ctx, &auth, case_id).await?;
    if let Some(a) = alert_id {
        if !alert_linked(&ctx, case_id, a).await? {
            return Err(ApiError::bad_request(format!(
                "Alert id={a} is not linked to case id={case_id}; link the alert first or omit \
                 alert_id to apply case-wide."
            )));
        }
    }
    // Another tenant's template is applied like a missing one (difference by
    // design, see `routes::case_templates`): nothing is copied.
    let owner: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT customer_code FROM incident_management_case_template WHERE id = ?",
    )
    .bind(template_id)
    .fetch_optional(ctx.db.pool())
    .await
    .map_err(ApiError::internal)?
    .flatten();
    let visible = match &owner {
        None => true,
        Some(code) => access::can_access(&ctx, &auth, Some(code)).await?,
    };
    let mut added = 0;
    if visible {
        let mut tx = ctx.db.pool().begin().await.map_err(ApiError::internal)?;
        added = templates::apply_template(&mut tx, case_id, template_id, &auth.username, alert_id)
            .await
            .map_err(ApiError::internal)?
            .unwrap_or(0);
        tx.commit().await.map_err(ApiError::internal)?;
    }
    Ok(json(json!({
        "success": true,
        "message": format!(
            "Applied template id={template_id} to case id={case_id}: {added} task(s) added"
        ),
        "tasks_added": added,
    })))
}
