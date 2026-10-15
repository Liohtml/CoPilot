//! `/api/incidents/case_templates` — port of the template CRUD of
//! `app/incidents/routes/case_templates.py` and
//! `app/incidents/services/case_templates.py` (admin/analyst only).
//!
//! The services answer 200 with `success: false` for what they refuse (a
//! missing template, a half-set match pair, foreign task ids). A write
//! answers with the template as the ORM holds it after the commit: the
//! timestamps it just set keep their microseconds.
//!
//! Still Python ([`LEGACY_PATHS`]): the library (fetched from GitHub and
//! cached in that process) and `/suggest` (reads the Wazuh indexer).
//!
//! Difference by design: a template scoped to a customer belongs to that
//! tenant. Python let any analyst list, read, edit, delete and reorder every
//! tenant's templates; here a scoped caller sees only shared templates and
//! their own customers' (another tenant's reads as missing), and cannot name
//! another tenant's customer in a create or an update (403).

use axum::Router;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, patch, post};
use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::{FromRow, MySqlConnection};

use copilot_auth::AccessScope;
use copilot_core::time::{mysql_datetime, now_utc_micros};
use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator, loc};
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, QueryPairs, WithJson,
};

use super::common::json;
use crate::requests::merge;

type Soc = Authorized<AdminOrAnalyst>;
type Obj = Map<String, Value>;

/// Paths under `/api/incidents/case_templates` that Python keeps serving;
/// the binary routes them to the legacy backend so `/{template_id}` does not
/// swallow them.
pub const LEGACY_PATHS: &[&str] = &[
    "/library",
    "/library/refresh",
    "/library/{key}",
    "/library/{key}/import",
    "/suggest",
];

/// The router, to be nested at `/api/incidents/case_templates`.
pub fn case_templates(ctx: AppContext) -> Router {
    Router::new()
        .route("/", get(list).post(create))
        .route(
            "/{template_id}",
            get(get_one).patch(update).delete(delete_one),
        )
        .route("/{template_id}/tasks", post(add_task))
        .route("/tasks/{task_id}", patch(update_task).delete(delete_task))
        .route("/{template_id}/tasks/reorder", post(reorder))
        .with_state(ctx)
}

#[derive(Debug, Clone, FromRow)]
struct Template {
    id: i32,
    name: String,
    description: Option<String>,
    customer_code: Option<String>,
    source: Option<String>,
    is_default: bool,
    match_field: Option<String>,
    match_value: Option<String>,
    created_by: String,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

/// Every column, in the model's order (what `select(CaseTemplate)` lists).
pub const TEMPLATE_COLS: &str = "incident_management_case_template.id, \
    incident_management_case_template.name, incident_management_case_template.description, \
    incident_management_case_template.customer_code, incident_management_case_template.source, \
    incident_management_case_template.is_default, incident_management_case_template.match_field, \
    incident_management_case_template.match_value, incident_management_case_template.created_by, \
    incident_management_case_template.created_at, incident_management_case_template.updated_at";

#[derive(Debug, Clone, FromRow, Serialize)]
struct TemplateTask {
    id: i32,
    template_id: i32,
    title: String,
    description: Option<String>,
    guidelines: Option<String>,
    mandatory: bool,
    order_index: i32,
}

const TASK_COLS: &str = "id, template_id, title, description, guidelines, mandatory, order_index";

/// `_template_to_response`: tasks by `(order_index, id)`.
fn template_json(t: &Template, tasks: &[TemplateTask]) -> Value {
    let mut tasks = tasks.to_vec();
    tasks.sort_by_key(|x| (x.order_index, x.id));
    let iso = copilot_core::time::to_pydantic_iso;
    json!({
        "id": t.id,
        "name": t.name,
        "description": t.description,
        "customer_code": t.customer_code,
        "source": t.source,
        "is_default": t.is_default,
        "match_field": t.match_field,
        "match_value": t.match_value,
        "created_by": t.created_by,
        "created_at": iso(t.created_at),
        "updated_at": iso(t.updated_at),
        "tasks": tasks,
    })
}

fn template_op(template: Option<Value>, success: bool, message: String) -> Response {
    json(json!({"template": template, "success": success, "message": message}))
}

fn task_op(task: Option<&TemplateTask>, success: bool, message: String) -> Response {
    json(json!({"task": task, "success": success, "message": message}))
}

async fn load(
    conn: &mut MySqlConnection,
    id: i64,
) -> Result<Option<(Template, Vec<TemplateTask>)>, sqlx::Error> {
    let Some(t) = sqlx::query_as::<_, Template>(&format!(
        "SELECT {TEMPLATE_COLS} FROM incident_management_case_template WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let tasks = sqlx::query_as::<_, TemplateTask>(&format!(
        "SELECT {TASK_COLS} FROM incident_management_case_template_task WHERE template_id = ?"
    ))
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Some((t, tasks)))
}

fn path_int(v: &mut Validator, name: &str, raw: &str) -> i64 {
    v.check_int(
        &loc("path", name),
        &Value::String(raw.into()),
        IntRules::default(),
    )
    .unwrap_or_default()
}

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(name.into()));
    l
}

fn max(n: usize) -> StrRules {
    StrRules {
        max_len: Some(n),
        ..StrRules::any()
    }
}

/// `MATCH_PAIR`: `_validate_match_pair`'s `ValueError`.
const MATCH_PAIR: &str = "match_field and match_value must both be set or both be null. Set both \
    to enable conditional auto-apply, or both to null for an unconditional template.";

/// `CaseTemplateTaskCreate`.
#[derive(Debug, Clone)]
struct TaskCreate {
    title: String,
    description: Option<String>,
    guidelines: Option<String>,
    mandatory: bool,
    order_index: i64,
}

impl TaskCreate {
    fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        Self {
            title: v.req_str(o, at, "title", max(500)),
            description: v.opt_str(o, at, "description", StrRules::any()),
            guidelines: v.opt_str(o, at, "guidelines", StrRules::any()),
            mandatory: v.bool_or(o, at, "mandatory", false),
            order_index: match o.get("order_index") {
                None => 0,
                Some(x) => v
                    .check_int(
                        &child(at, "order_index"),
                        x,
                        IntRules {
                            ge: Some(0),
                            le: None,
                        },
                    )
                    .unwrap_or(0),
            },
        }
    }
}

/// `CaseTemplateCreate`.
struct TemplateCreate {
    name: String,
    description: Option<String>,
    customer_code: Option<String>,
    source: Option<String>,
    is_default: bool,
    match_field: Option<String>,
    match_value: Option<String>,
    tasks: Vec<TaskCreate>,
}

impl TemplateCreate {
    fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        let name = v.req_str(o, at, "name", max(255));
        let description = v.opt_str(o, at, "description", StrRules::any());
        let customer_code = v.opt_str(o, at, "customer_code", max(50));
        let source = v.opt_str(o, at, "source", max(50));
        let is_default = v.bool_or(o, at, "is_default", false);
        let match_field = v.opt_str(o, at, "match_field", max(255));
        let match_value = v.opt_str(o, at, "match_value", StrRules::any());
        let mut tasks = Vec::new();
        for (l, item) in v.list(o, at, "tasks", false) {
            // FastAPI validates bodies with `from_attributes`: a non-dict item is
            // `model_attributes_type`, not `model_type`.
            if let Some(obj) = v.object(item, &l) {
                tasks.push(TaskCreate::read(v, obj, &l));
            }
        }
        Self {
            name,
            description,
            customer_code,
            source,
            is_default,
            match_field,
            match_value,
            tasks,
        }
    }
}

/// An optional field with its `__fields_set__` presence.
type Sent<T> = Option<Option<T>>;

fn sent_str(v: &mut Validator, o: &Obj, at: &Loc, name: &str, rules: StrRules) -> Sent<String> {
    let value = v.opt_str(o, at, name, rules);
    o.contains_key(name).then_some(value)
}

/// `CaseTemplateUpdate`.
struct TemplateUpdate {
    name: Sent<String>,
    description: Sent<String>,
    customer_code: Sent<String>,
    source: Sent<String>,
    is_default: Sent<bool>,
    match_field: Sent<String>,
    match_value: Sent<String>,
}

impl TemplateUpdate {
    fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        let name = sent_str(v, o, at, "name", max(255));
        let description = sent_str(v, o, at, "description", StrRules::any());
        let customer_code = sent_str(v, o, at, "customer_code", max(50));
        let source = sent_str(v, o, at, "source", max(50));
        let is_default = {
            let value = v.opt_bool(o, at, "is_default");
            o.contains_key("is_default").then_some(value)
        };
        let match_field = sent_str(v, o, at, "match_field", max(255));
        let match_value = sent_str(v, o, at, "match_value", StrRules::any());
        Self {
            name,
            description,
            customer_code,
            source,
            is_default,
            match_field,
            match_value,
        }
    }
}

/// `CaseTemplateTaskUpdate`.
struct TaskUpdate {
    title: Sent<String>,
    description: Sent<String>,
    guidelines: Sent<String>,
    mandatory: Sent<bool>,
    order_index: Sent<i64>,
}

impl TaskUpdate {
    fn read(v: &mut Validator, o: &Obj, at: &Loc) -> Self {
        let title = sent_str(v, o, at, "title", max(500));
        let description = sent_str(v, o, at, "description", StrRules::any());
        let guidelines = sent_str(v, o, at, "guidelines", StrRules::any());
        let mandatory = {
            let value = v.opt_bool(o, at, "mandatory");
            o.contains_key("mandatory").then_some(value)
        };
        let order_index = {
            let value = v.opt_int(
                o,
                at,
                "order_index",
                IntRules {
                    ge: Some(0),
                    le: None,
                },
            );
            o.contains_key("order_index").then_some(value)
        };
        Self {
            title,
            description,
            guidelines,
            mandatory,
            order_index,
        }
    }
}

/// `_enforce_single_default`: demote the other defaults of the scope.
async fn demote_defaults(
    conn: &mut MySqlConnection,
    customer: Option<&str>,
    source: Option<&str>,
    exclude: Option<i64>,
) -> Result<(), sqlx::Error> {
    let mut sql = String::from(
        "UPDATE incident_management_case_template SET is_default = 0, updated_at = ? \
         WHERE is_default = 1",
    );
    sql.push_str(if customer.is_some() {
        " AND customer_code = ?"
    } else {
        " AND customer_code IS NULL"
    });
    sql.push_str(if source.is_some() {
        " AND source = ?"
    } else {
        " AND source IS NULL"
    });
    if exclude.is_some() {
        sql.push_str(" AND id != ?");
    }
    let mut q = sqlx::query(&sql).bind(mysql_datetime(now_utc_micros()));
    if let Some(c) = customer {
        q = q.bind(c);
    }
    if let Some(s) = source {
        q = q.bind(s);
    }
    if let Some(e) = exclude {
        q = q.bind(e);
    }
    q.execute(&mut *conn).await?;
    Ok(())
}

/// `GET /?customer_code=&source=&include_global=`.
async fn list(auth: Soc, State(ctx): State<AppContext>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let customer = q.get("customer_code").map(str::to_string);
    let source = q.get("source").map(str::to_string);
    let include_global = match q.get("include_global") {
        None => true,
        Some(raw) => {
            let obj: Obj = [("include_global".to_string(), Value::String(raw.into()))]
                .into_iter()
                .collect();
            v.opt_bool(&obj, &vec![LocPart::Key("query".into())], "include_global")
                .unwrap_or(true)
        }
    };
    v.finish()?;
    // SQLAlchemy's statement, column list and all: ties on `created_at` come
    // back in whatever order MySQL's sort leaves them, so the query must be the
    // same one.
    let mut sql = format!("SELECT {TEMPLATE_COLS} FROM incident_management_case_template");
    let mut binds: Vec<String> = Vec::new();
    let mut clauses: Vec<String> = Vec::new();
    for (column, value) in [("customer_code", &customer), ("source", &source)] {
        if let Some(value) = value {
            let col = format!("incident_management_case_template.{column}");
            clauses.push(if include_global {
                format!("({col} = ? OR {col} IS NULL)")
            } else {
                format!("{col} = ?")
            });
            binds.push(value.clone());
        }
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY incident_management_case_template.created_at DESC");
    let mut query = sqlx::query_as::<_, Template>(&sql);
    for b in &binds {
        query = query.bind(b);
    }
    let rows = match query.fetch_all(ctx.db.pool()).await {
        Ok(rows) => rows,
        Err(e) => {
            return Ok(json(json!({
                "templates": [],
                "success": false,
                "message": format!("Failed to list case templates: {e}"),
            })));
        }
    };
    let scope = auth.access(&ctx).await?;
    let rows: Vec<Template> = rows
        .into_iter()
        .filter(|t| sees(scope, t.customer_code.as_deref()))
        .collect();
    let ids: Vec<i32> = rows.iter().map(|t| t.id).collect();
    let mut tasks: Vec<TemplateTask> = Vec::new();
    if !ids.is_empty() {
        let mut qb = sqlx::QueryBuilder::new(format!(
            "SELECT {TASK_COLS} FROM incident_management_case_template_task WHERE template_id IN ("
        ));
        crate::store::push_list(&mut qb, ids.iter().copied());
        qb.push(")");
        tasks = qb
            .build_query_as::<TemplateTask>()
            .fetch_all(ctx.db.pool())
            .await
            .map_err(ApiError::internal)?;
    }
    let templates: Vec<Value> = rows
        .iter()
        .map(|t| {
            let own: Vec<TemplateTask> = tasks
                .iter()
                .filter(|x| x.template_id == t.id)
                .cloned()
                .collect();
            template_json(t, &own)
        })
        .collect();
    let message = format!("Retrieved {} template(s)", templates.len());
    Ok(json(
        json!({"templates": templates, "success": true, "message": message}),
    ))
}

/// `POST /`.
async fn create(State(ctx): State<AppContext>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    let req = body.model(TemplateCreate::read)?;
    ensure_customer(auth.access(&ctx).await?, req.customer_code.as_deref())?;
    if req.match_field.is_none() != req.match_value.is_none() {
        return Ok(template_op(
            None,
            false,
            format!("Failed to create case template: {MATCH_PAIR}"),
        ));
    }
    let created_at = now_utc_micros();
    let updated_at = now_utc_micros();
    let result = async {
        let mut tx = ctx.db.pool().begin().await?;
        if req.is_default {
            demote_defaults(
                &mut tx,
                req.customer_code.as_deref(),
                req.source.as_deref(),
                None,
            )
            .await?;
        }
        let inserted = sqlx::query(
            "INSERT INTO incident_management_case_template (name, description, customer_code, \
             source, is_default, match_field, match_value, created_by, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.customer_code)
        .bind(&req.source)
        .bind(req.is_default)
        .bind(&req.match_field)
        .bind(&req.match_value)
        .bind(&auth.username)
        .bind(mysql_datetime(created_at))
        .bind(mysql_datetime(updated_at))
        .execute(&mut *tx)
        .await?;
        let id = inserted.last_insert_id() as i64;
        for t in &req.tasks {
            sqlx::query(
                "INSERT INTO incident_management_case_template_task (template_id, title, \
                 description, guidelines, mandatory, order_index) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(&t.title)
            .bind(&t.description)
            .bind(&t.guidelines)
            .bind(t.mandatory)
            .bind(t.order_index)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok::<i64, sqlx::Error>(id)
    }
    .await;
    let id = match result {
        Ok(id) => id,
        Err(e) => {
            return Ok(template_op(
                None,
                false,
                format!("Failed to create case template: {e}"),
            ));
        }
    };
    let mut conn = ctx.db.pool().acquire().await.map_err(ApiError::internal)?;
    let (mut t, tasks) = load(&mut conn, id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::internal("created template vanished"))?;
    t.created_at = created_at;
    t.updated_at = updated_at;
    Ok(template_op(
        Some(template_json(&t, &tasks)),
        true,
        format!("Created template id={id}"),
    ))
}

fn not_found(id: i64) -> String {
    format!("Template id={id} not found")
}

/// Difference by design: a template scoped to a customer is that customer's
/// (like `custom_dashboard_templates`, #1050). A caller who may not see the
/// customer gets it as missing; NULL is shared with everyone.
fn sees(scope: &AccessScope, customer: Option<&str>) -> bool {
    match (scope, customer) {
        (AccessScope::All, _) | (_, None) => true,
        (scope, Some(code)) => scope.can_access(code),
    }
}

/// A customer named in the body must be the caller's.
fn ensure_customer(scope: &AccessScope, customer: Option<&str>) -> Result<(), ApiError> {
    match customer {
        Some(code) if !sees(scope, Some(code)) => Err(ApiError::forbidden(format!(
            "Access denied to customer {code} - insufficient customer permissions"
        ))),
        _ => Ok(()),
    }
}

/// `GET /{template_id}`.
async fn get_one(auth: Soc, State(ctx): State<AppContext>, Path(raw): Path<String>) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "template_id", &raw);
    v.finish()?;
    let scope = auth.access(&ctx).await?;
    let mut conn = ctx.db.pool().acquire().await.map_err(ApiError::internal)?;
    let found = load(&mut conn, id)
        .await
        .map_err(ApiError::internal)?
        .filter(|(t, _)| sees(scope, t.customer_code.as_deref()));
    match found {
        None => Ok(template_op(None, false, not_found(id))),
        Some((t, tasks)) => Ok(template_op(
            Some(template_json(&t, &tasks)),
            true,
            format!("Retrieved template id={id}"),
        )),
    }
}

/// `PATCH /{template_id}`: each field only when sent.
async fn update(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "template_id", &raw);
    let req = merge(v, body.model(TemplateUpdate::read))?;
    let scope = auth.access(&ctx).await?;
    let mut conn = ctx.db.pool().acquire().await.map_err(ApiError::internal)?;
    let Some((mut t, tasks)) = load(&mut conn, id)
        .await
        .map_err(ApiError::internal)?
        .filter(|(t, _)| sees(scope, t.customer_code.as_deref()))
    else {
        return Ok(template_op(None, false, not_found(id)));
    };
    drop(conn);
    if let Some(Some(code)) = &req.customer_code {
        ensure_customer(scope, Some(code))?;
    }
    if let Some(Some(name)) = &req.name {
        t.name = name.clone();
    }
    if let Some(d) = &req.description {
        t.description = d.clone();
    }
    if let Some(c) = &req.customer_code {
        t.customer_code = c.clone();
    }
    if let Some(s) = &req.source {
        t.source = s.clone();
    }
    let mut demote = false;
    if let Some(Some(flag)) = req.is_default {
        t.is_default = flag;
        demote = flag;
    }
    if req.match_field.is_some() || req.match_value.is_some() {
        let field = req
            .match_field
            .clone()
            .unwrap_or_else(|| t.match_field.clone());
        let value = req
            .match_value
            .clone()
            .unwrap_or_else(|| t.match_value.clone());
        if field.is_none() != value.is_none() {
            return Ok(template_op(
                None,
                false,
                format!("Failed to update case template: {MATCH_PAIR}"),
            ));
        }
        t.match_field = field;
        t.match_value = value;
    }
    t.updated_at = now_utc_micros();
    let result = async {
        let mut tx = ctx.db.pool().begin().await?;
        if demote {
            demote_defaults(
                &mut tx,
                t.customer_code.as_deref(),
                t.source.as_deref(),
                Some(id),
            )
            .await?;
        }
        sqlx::query(
            "UPDATE incident_management_case_template SET name = ?, description = ?, \
             customer_code = ?, source = ?, is_default = ?, match_field = ?, match_value = ?, \
             updated_at = ? WHERE id = ?",
        )
        .bind(&t.name)
        .bind(&t.description)
        .bind(&t.customer_code)
        .bind(&t.source)
        .bind(t.is_default)
        .bind(&t.match_field)
        .bind(&t.match_value)
        .bind(mysql_datetime(t.updated_at))
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await
    }
    .await;
    if let Err(e) = result {
        return Ok(template_op(
            None,
            false,
            format!("Failed to update case template: {e}"),
        ));
    }
    Ok(template_op(
        Some(template_json(&t, &tasks)),
        true,
        format!("Updated template id={id}"),
    ))
}

/// `DELETE /{template_id}`: snapshots on cases keep their data, their soft
/// link is cleared.
async fn delete_one(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "template_id", &raw);
    v.finish()?;
    let scope = auth.access(&ctx).await?;
    let mut conn = ctx.db.pool().acquire().await.map_err(ApiError::internal)?;
    let Some((t, tasks)) = load(&mut conn, id)
        .await
        .map_err(ApiError::internal)?
        .filter(|(t, _)| sees(scope, t.customer_code.as_deref()))
    else {
        return Ok(template_op(None, false, not_found(id)));
    };
    drop(conn);
    let snapshot = template_json(&t, &tasks);
    let result = async {
        let mut tx = ctx.db.pool().begin().await?;
        for task in &tasks {
            sqlx::query(
                "UPDATE incident_management_case_task SET template_task_id = NULL \
                 WHERE template_task_id = ?",
            )
            .bind(task.id)
            .execute(&mut *tx)
            .await?;
        }
        for task in &tasks {
            sqlx::query("DELETE FROM incident_management_case_template_task WHERE id = ?")
                .bind(task.id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM incident_management_case_template WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await
    }
    .await;
    match result {
        Ok(()) => Ok(template_op(
            Some(snapshot),
            true,
            format!("Deleted template id={id}"),
        )),
        Err(e) => Ok(template_op(
            None,
            false,
            format!("Failed to delete case template: {e}"),
        )),
    }
}

async fn task(conn: &mut MySqlConnection, id: i64) -> Result<Option<TemplateTask>, sqlx::Error> {
    sqlx::query_as::<_, TemplateTask>(&format!(
        "SELECT {TASK_COLS} FROM incident_management_case_template_task WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
}

/// The customer of a task's template (`None` for a shared one or a missing
/// template).
async fn task_customer(
    conn: &mut MySqlConnection,
    template_id: i32,
) -> Result<Option<String>, sqlx::Error> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT customer_code FROM incident_management_case_template WHERE id = ?",
    )
    .bind(template_id)
    .fetch_optional(&mut *conn)
    .await?
    .flatten())
}

async fn touch(conn: &mut MySqlConnection, template_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE incident_management_case_template SET updated_at = ? WHERE id = ?")
        .bind(mysql_datetime(now_utc_micros()))
        .bind(template_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `POST /{template_id}/tasks`.
async fn add_task(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "template_id", &raw);
    let req = merge(v, body.model(TaskCreate::read))?;
    let scope = auth.access(&ctx).await?;
    let result = async {
        let mut tx = ctx.db.pool().begin().await?;
        if !load(&mut tx, id)
            .await?
            .is_some_and(|(t, _)| sees(scope, t.customer_code.as_deref()))
        {
            return Ok(None);
        }
        let inserted = sqlx::query(
            "INSERT INTO incident_management_case_template_task (template_id, title, description, \
             guidelines, mandatory, order_index) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(&req.title)
        .bind(&req.description)
        .bind(&req.guidelines)
        .bind(req.mandatory)
        .bind(req.order_index)
        .execute(&mut *tx)
        .await?;
        touch(&mut tx, id).await?;
        let task_id = inserted.last_insert_id() as i64;
        let stored = task(&mut tx, task_id).await?;
        tx.commit().await?;
        Ok::<Option<Option<TemplateTask>>, sqlx::Error>(Some(stored))
    }
    .await;
    match result {
        Ok(None) => Ok(task_op(None, false, not_found(id))),
        Ok(Some(stored)) => {
            let message = format!(
                "Added task id={} to template id={id}",
                stored.as_ref().map_or(0, |t| t.id)
            );
            Ok(task_op(stored.as_ref(), true, message))
        }
        Err(e) => Ok(task_op(
            None,
            false,
            format!("Failed to add template task: {e}"),
        )),
    }
}

/// `PATCH /tasks/{task_id}`.
async fn update_task(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "task_id", &raw);
    let req = merge(v, body.model(TaskUpdate::read))?;
    let scope = auth.access(&ctx).await?;
    let result = async {
        let mut tx = ctx.db.pool().begin().await?;
        let Some(mut t) = task(&mut tx, id).await? else {
            return Ok(None);
        };
        if !sees(
            scope,
            task_customer(&mut tx, t.template_id).await?.as_deref(),
        ) {
            return Ok(None);
        }
        if let Some(Some(title)) = &req.title {
            t.title = title.clone();
        }
        if let Some(d) = &req.description {
            t.description = d.clone();
        }
        if let Some(g) = &req.guidelines {
            t.guidelines = g.clone();
        }
        if let Some(Some(m)) = req.mandatory {
            t.mandatory = m;
        }
        if let Some(Some(o)) = req.order_index {
            t.order_index = i32::try_from(o).unwrap_or(i32::MAX);
        }
        sqlx::query(
            "UPDATE incident_management_case_template_task SET title = ?, description = ?, \
             guidelines = ?, mandatory = ?, order_index = ? WHERE id = ?",
        )
        .bind(&t.title)
        .bind(&t.description)
        .bind(&t.guidelines)
        .bind(t.mandatory)
        .bind(
            req.order_index
                .flatten()
                .unwrap_or(i64::from(t.order_index)),
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        touch(&mut tx, i64::from(t.template_id)).await?;
        let stored = task(&mut tx, id).await?;
        tx.commit().await?;
        Ok::<Option<Option<TemplateTask>>, sqlx::Error>(Some(stored))
    }
    .await;
    match result {
        Ok(None) => Ok(task_op(
            None,
            false,
            format!("Template task id={id} not found"),
        )),
        Ok(Some(stored)) => Ok(task_op(
            stored.as_ref(),
            true,
            format!("Updated template task id={id}"),
        )),
        Err(e) => Ok(task_op(
            None,
            false,
            format!("Failed to update template task: {e}"),
        )),
    }
}

/// `DELETE /tasks/{task_id}`.
async fn delete_task(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "task_id", &raw);
    v.finish()?;
    let scope = auth.access(&ctx).await?;
    let result = async {
        let mut tx = ctx.db.pool().begin().await?;
        let Some(t) = task(&mut tx, id).await? else {
            return Ok(None);
        };
        if !sees(scope, task_customer(&mut tx, t.template_id).await?.as_deref()) {
            return Ok(None);
        }
        sqlx::query(
            "UPDATE incident_management_case_task SET template_task_id = NULL WHERE template_task_id = ?",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM incident_management_case_template_task WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        touch(&mut tx, i64::from(t.template_id)).await?;
        tx.commit().await?;
        Ok::<Option<TemplateTask>, sqlx::Error>(Some(t))
    }
    .await;
    match result {
        Ok(None) => Ok(task_op(
            None,
            false,
            format!("Template task id={id} not found"),
        )),
        Ok(Some(t)) => Ok(task_op(
            Some(&t),
            true,
            format!("Deleted template task id={id}"),
        )),
        Err(e) => Ok(task_op(
            None,
            false,
            format!("Failed to delete template task: {e}"),
        )),
    }
}

/// `POST /{template_id}/tasks/reorder` (the body is the list of task ids).
async fn reorder(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    let mut v = Validator::new();
    let id = path_int(&mut v, "template_id", &raw);
    let ids = merge(
        v,
        body.value(|v, value, at| {
            let Value::Array(items) = value else {
                v.push("list_type", at.clone(), "Input should be a valid list");
                return Vec::new();
            };
            let mut out = Vec::new();
            for (i, item) in items.iter().enumerate() {
                let mut l = at.clone();
                l.push(LocPart::Index(i));
                if let Some(n) = v.check_int(&l, item, IntRules::default()) {
                    out.push(n);
                }
            }
            out
        }),
    )?;
    let scope = auth.access(&ctx).await?;
    let mut conn = ctx.db.pool().acquire().await.map_err(ApiError::internal)?;
    let Some((mut t, mut tasks)) = load(&mut conn, id)
        .await
        .map_err(ApiError::internal)?
        .filter(|(t, _)| sees(scope, t.customer_code.as_deref()))
    else {
        return Ok(template_op(None, false, not_found(id)));
    };
    drop(conn);
    let bad: Vec<String> = ids
        .iter()
        .filter(|x| !tasks.iter().any(|task| i64::from(task.id) == **x))
        .map(ToString::to_string)
        .collect();
    if !bad.is_empty() {
        return Ok(template_op(
            None,
            false,
            format!(
                "Task ids do not belong to template id={id}: [{}]",
                bad.join(", ")
            ),
        ));
    }
    for task in &mut tasks {
        if let Some(pos) = ids.iter().rposition(|x| *x == i64::from(task.id)) {
            task.order_index = i32::try_from(pos).unwrap_or(i32::MAX);
        }
    }
    t.updated_at = now_utc_micros();
    let result = async {
        let mut tx = ctx.db.pool().begin().await?;
        for task in &tasks {
            if ids.contains(&i64::from(task.id)) {
                sqlx::query(
                    "UPDATE incident_management_case_template_task SET order_index = ? WHERE id = ?",
                )
                .bind(task.order_index)
                .bind(task.id)
                .execute(&mut *tx)
                .await?;
            }
        }
        sqlx::query("UPDATE incident_management_case_template SET updated_at = ? WHERE id = ?")
            .bind(mysql_datetime(t.updated_at))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await
    }
    .await;
    if let Err(e) = result {
        return Ok(template_op(
            None,
            false,
            format!("Failed to reorder template tasks: {e}"),
        ));
    }
    Ok(template_op(
        Some(template_json(&t, &tasks)),
        true,
        format!("Reordered {} task(s) on template id={id}", ids.len()),
    ))
}
