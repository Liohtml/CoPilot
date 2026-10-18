//! `/api/incidents/tag_access` — port of `app/incidents/routes/tag_access.py`
//! and `app/incidents/services/tag_access.py`: the global tag-RBAC settings,
//! the tags of a user or a role, and the caller's effective access.
//!
//! Every route takes `Security(get_current_user)` (any signed-in user); the
//! admin-only ones check the role in the handler (`Admin access required`),
//! after the body is validated — so the settings model's own 400 comes first.

use std::collections::BTreeSet;

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use copilot_auth::AccessScope;
use copilot_auth::tags::TagSet;
use serde_json::{Map, Value, json};
use sqlx::{MySql, QueryBuilder};

use copilot_core::time::{mysql_datetime, now_utc_micros};
use copilot_db::visibility;
use copilot_web::validate::{IntRules, Loc, Validator, loc};
use copilot_web::{AnyUser, ApiError, ApiResult, AppContext, CurrentUser, ScopedUser, WithJson};

use super::common::json;
use crate::requests::{int_list, merge};

type User = ScopedUser<AnyUser>;
type Obj = Map<String, Value>;

/// `UntaggedAlertBehavior`.
const BEHAVIORS: &[&str] = &["visible_to_all", "admin_only", "default_tag"];

/// The router, to be nested at `/api/incidents/tag_access`.
pub fn tag_access(ctx: AppContext) -> Router {
    Router::new()
        .route("/settings", get(get_settings).put(put_settings))
        .route("/tags", get(all_tags))
        .route("/user/{user_id}", get(get_user).put(set_user))
        .route("/user/{user_id}/add", post(add_user))
        .route("/user/{user_id}/remove", post(remove_user))
        .route("/role/{role_id}", get(get_role).put(set_role))
        .route("/role/{role_id}/add", post(add_role))
        .route("/role/{role_id}/remove", post(remove_role))
        .route("/me", get(me))
        .with_state(ctx)
}

fn internal(e: sqlx::Error) -> ApiError {
    ApiError::internal(e)
}

/// `_require_admin`.
fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.role_id != Some(1) {
        return Err(ApiError::forbidden("Admin access required"));
    }
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct Settings {
    id: i32,
    enabled: bool,
    untagged_alert_behavior: String,
    default_tag_id: Option<i32>,
}

/// `get_or_create_tag_settings`: the first row, created with the defaults
/// when there is none.
async fn settings_row(ctx: &AppContext) -> Result<Settings, ApiError> {
    let first = || {
        sqlx::query_as::<_, Settings>(
            "SELECT id, enabled, untagged_alert_behavior, default_tag_id \
             FROM incident_management_tag_access_settings LIMIT 1",
        )
        .fetch_optional(ctx.db.pool())
    };
    if let Some(s) = first().await.map_err(internal)? {
        return Ok(s);
    }
    sqlx::query(
        "INSERT INTO incident_management_tag_access_settings (enabled, untagged_alert_behavior, \
         default_tag_id, updated_at, updated_by) VALUES (0, 'visible_to_all', NULL, ?, NULL)",
    )
    .bind(mysql_datetime(now_utc_micros()))
    .execute(ctx.db.pool())
    .await
    .map_err(internal)?;
    first()
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("tag access settings vanished"))
}

async fn tag_name(ctx: &AppContext, id: i32) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, String>("SELECT tag FROM incident_management_alerttag WHERE id = ?")
        .bind(id)
        .fetch_optional(ctx.db.pool())
        .await
        .map_err(internal)
}

async fn settings_response(ctx: &AppContext, s: &Settings, message: &str) -> ApiResult {
    let name = match s.default_tag_id {
        Some(id) if id != 0 => tag_name(ctx, id).await?,
        _ => None,
    };
    Ok(json(json!({
        "settings": {
            "enabled": s.enabled,
            "untagged_alert_behavior": s.untagged_alert_behavior,
            "default_tag_id": s.default_tag_id,
            "default_tag_name": name,
        },
        "success": true,
        "message": message,
    })))
}

/// `GET /settings` (admin): creates the row if there is none.
async fn get_settings(user: User, State(ctx): State<AppContext>) -> ApiResult {
    require_admin(&user)?;
    let s = settings_row(&ctx).await?;
    settings_response(&ctx, &s, "Settings retrieved successfully").await
}

/// `PUT /settings` (admin).
async fn put_settings(
    State(ctx): State<AppContext>,
    WithJson(user, body): WithJson<User>,
) -> ApiResult {
    let (enabled, behavior, default_tag) = body.model(|v, o, at| {
        (
            v.req_bool(o, at, "enabled"),
            v.enum_or(
                o,
                at,
                "untagged_alert_behavior",
                BEHAVIORS,
                "visible_to_all",
            ),
            v.opt_int(o, at, "default_tag_id", IntRules::default()),
        )
    })?;
    // The model validator raises an HTTPException, which Pydantic lets through.
    if behavior == "default_tag" && default_tag.is_none() {
        return Err(ApiError::bad_request(
            "default_tag_id is required when untagged_alert_behavior is 'default_tag'",
        ));
    }
    require_admin(&user)?;
    if let Some(id) = default_tag.filter(|id| *id != 0) {
        if tag_name(&ctx, i32::try_from(id).unwrap_or(i32::MAX))
            .await?
            .is_none()
        {
            return Err(ApiError::not_found(format!("Tag with id {id} not found")));
        }
    }
    let s = settings_row(&ctx).await?;
    sqlx::query(
        "UPDATE incident_management_tag_access_settings SET enabled = ?, \
         untagged_alert_behavior = ?, default_tag_id = ?, updated_by = ?, updated_at = ? WHERE id = ?",
    )
    .bind(enabled)
    .bind(&behavior)
    .bind(default_tag)
    .bind(&user.username)
    .bind(mysql_datetime(now_utc_micros()))
    .bind(s.id)
    .execute(ctx.db.pool())
    .await
    .map_err(internal)?;
    let s = Settings {
        id: s.id,
        enabled,
        untagged_alert_behavior: behavior,
        default_tag_id: default_tag.map(|t| i32::try_from(t).unwrap_or(i32::MAX)),
    };
    settings_response(&ctx, &s, "Settings updated successfully").await
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
struct Tag {
    id: i32,
    tag: String,
}

async fn tags_where_in(ctx: &AppContext, ids: &[i64]) -> Result<Vec<Tag>, ApiError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT incident_management_alerttag.id, incident_management_alerttag.tag \
         FROM incident_management_alerttag WHERE incident_management_alerttag.id IN (",
    );
    crate::store::push_list(&mut qb, ids.iter().copied());
    qb.push(")");
    qb.build_query_as::<Tag>()
        .fetch_all(ctx.db.pool())
        .await
        .map_err(internal)
}

/// `GET /tags` (any user).
async fn all_tags(_user: User, State(ctx): State<AppContext>) -> ApiResult {
    let tags = sqlx::query_as::<_, Tag>(
        "SELECT incident_management_alerttag.id, incident_management_alerttag.tag \
         FROM incident_management_alerttag",
    )
    .fetch_all(ctx.db.pool())
    .await
    .map_err(internal)?;
    let message = format!("Retrieved {} tags", tags.len());
    Ok(json(
        json!({"tags": tags, "success": true, "message": message}),
    ))
}

/// Users or roles.
#[derive(Clone, Copy)]
enum Subject {
    User,
    Role,
}

impl Subject {
    const fn access_table(self) -> &'static str {
        match self {
            Self::User => "user_tag_access",
            Self::Role => "role_tag_access",
        }
    }

    const fn key(self) -> &'static str {
        match self {
            Self::User => "user_id",
            Self::Role => "role_id",
        }
    }

    /// The subject's name (`username` / role `name`), or the 404.
    async fn name(self, ctx: &AppContext, id: i64) -> Result<String, ApiError> {
        let sql = match self {
            Self::User => "SELECT username FROM `user` WHERE id = ?",
            Self::Role => "SELECT name FROM role WHERE id = ?",
        };
        sqlx::query_scalar::<_, String>(sql)
            .bind(id)
            .fetch_optional(ctx.db.pool())
            .await
            .map_err(internal)?
            .ok_or_else(|| {
                ApiError::not_found(match self {
                    Self::User => "User not found",
                    Self::Role => "Role not found",
                })
            })
    }

    /// `get_*_accessible_tags`: the tags joined through the access rows.
    async fn tags(self, ctx: &AppContext, id: i64) -> Result<Vec<Tag>, ApiError> {
        let t = self.access_table();
        sqlx::query_as::<_, Tag>(&format!(
            "SELECT incident_management_alerttag.id, incident_management_alerttag.tag \
             FROM incident_management_alerttag INNER JOIN {t} ON {t}.tag_id = \
             incident_management_alerttag.id WHERE {t}.{} = ?",
            self.key()
        ))
        .bind(id)
        .fetch_all(ctx.db.pool())
        .await
        .map_err(internal)
    }

    fn response(
        self,
        id: i64,
        name: &str,
        tags: Vec<Tag>,
        message: &str,
    ) -> axum::response::Response {
        let mut m = Map::new();
        m.insert(self.key().into(), json!(id));
        m.insert(
            match self {
                Self::User => "username",
                Self::Role => "role_name",
            }
            .into(),
            json!(name),
        );
        m.insert("accessible_tags".into(), json!(tags));
        m.insert("success".into(), json!(true));
        m.insert("message".into(), json!(message));
        json(Value::Object(m))
    }
}

fn path_and_ids(
    name: &str,
    raw: &str,
    body: &copilot_web::JsonBody,
) -> Result<(i64, Vec<i64>), ApiError> {
    let mut v = Validator::new();
    let id = v
        .check_int(
            &loc("path", name),
            &Value::String(raw.into()),
            IntRules::default(),
        )
        .unwrap_or_default();
    let ids = merge(
        v,
        body.model(|v: &mut Validator, o: &Obj, at: &Loc| {
            int_list(v, o, at, "tag_ids", None, None)
        }),
    )?;
    Ok((id, ids))
}

fn path_only(name: &str, raw: &str) -> Result<i64, ApiError> {
    let mut v = Validator::new();
    let id = v
        .check_int(
            &loc("path", name),
            &Value::String(raw.into()),
            IntRules::default(),
        )
        .unwrap_or_default();
    v.finish()?;
    Ok(id)
}

async fn ensure_tags_exist(ctx: &AppContext, ids: &[i64]) -> Result<(), ApiError> {
    for id in ids {
        let found: Option<(i32,)> =
            sqlx::query_as("SELECT id FROM incident_management_alerttag WHERE id = ?")
                .bind(id)
                .fetch_optional(ctx.db.pool())
                .await
                .map_err(internal)?;
        if found.is_none() {
            return Err(ApiError::not_found(format!("Tag with id {id} not found")));
        }
    }
    Ok(())
}

async fn get_access(
    subject: Subject,
    user: &CurrentUser,
    ctx: &AppContext,
    raw: &str,
) -> ApiResult {
    let id = path_only(subject.key(), raw)?;
    require_admin(user)?;
    let name = subject.name(ctx, id).await?;
    let tags = subject.tags(ctx, id).await?;
    let message = match subject {
        Subject::User => "User tag access retrieved successfully",
        Subject::Role => "Role tag access retrieved successfully",
    };
    Ok(subject.response(id, &name, tags, message))
}

/// `set_*_tag_access`: replace, then the tags named (`IN`, each once).
async fn set_access(
    subject: Subject,
    user: &CurrentUser,
    ctx: &AppContext,
    raw: &str,
    body: &copilot_web::JsonBody,
) -> ApiResult {
    let (id, ids) = path_and_ids(subject.key(), raw, body)?;
    require_admin(user)?;
    let name = subject.name(ctx, id).await?;
    ensure_tags_exist(ctx, &ids).await?;
    let t = subject.access_table();
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    sqlx::query(&format!("DELETE FROM {t} WHERE {} = ?", subject.key()))
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    for tag in &ids {
        sqlx::query(&format!(
            "INSERT INTO {t} ({}, tag_id, created_at) VALUES (?, ?, ?)",
            subject.key()
        ))
        .bind(id)
        .bind(tag)
        .bind(local_now())
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    let tags = tags_where_in(ctx, &ids).await?;
    let message = match subject {
        Subject::User => "User tag access updated successfully",
        Subject::Role => "Role tag access updated successfully",
    };
    Ok(subject.response(id, &name, tags, message))
}

/// `UserTagAccess.created_at`'s `datetime.now()`: the process's local time.
fn local_now() -> chrono::NaiveDateTime {
    mysql_datetime(chrono::Local::now().naive_local())
}

/// `add_*_tag_access`: insert the missing ones.
async fn add_access(
    subject: Subject,
    user: &CurrentUser,
    ctx: &AppContext,
    raw: &str,
    body: &copilot_web::JsonBody,
) -> ApiResult {
    let (id, ids) = path_and_ids(subject.key(), raw, body)?;
    require_admin(user)?;
    let name = subject.name(ctx, id).await?;
    ensure_tags_exist(ctx, &ids).await?;
    let t = subject.access_table();
    let mut tx = ctx.db.pool().begin().await.map_err(internal)?;
    for tag in &ids {
        let exists: Option<(i32,)> = sqlx::query_as(&format!(
            "SELECT id FROM {t} WHERE {} = ? AND tag_id = ? LIMIT 1",
            subject.key()
        ))
        .bind(id)
        .bind(tag)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        if exists.is_none() {
            sqlx::query(&format!(
                "INSERT INTO {t} ({}, tag_id, created_at) VALUES (?, ?, ?)",
                subject.key()
            ))
            .bind(id)
            .bind(tag)
            .bind(local_now())
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        }
    }
    tx.commit().await.map_err(internal)?;
    let tags = subject.tags(ctx, id).await?;
    let message = match subject {
        Subject::User => "Tags added to user access successfully",
        Subject::Role => "Tags added to role access successfully",
    };
    Ok(subject.response(id, &name, tags, message))
}

/// `remove_*_tag_access`.
async fn remove_access(
    subject: Subject,
    user: &CurrentUser,
    ctx: &AppContext,
    raw: &str,
    body: &copilot_web::JsonBody,
) -> ApiResult {
    let (id, ids) = path_and_ids(subject.key(), raw, body)?;
    require_admin(user)?;
    let name = subject.name(ctx, id).await?;
    if !ids.is_empty() {
        let mut qb = QueryBuilder::<MySql>::new(format!(
            "DELETE FROM {} WHERE {} = ",
            subject.access_table(),
            subject.key()
        ));
        qb.push_bind(id);
        qb.push(" AND tag_id IN (");
        crate::store::push_list(&mut qb, ids.iter().copied());
        qb.push(")");
        qb.build().execute(ctx.db.pool()).await.map_err(internal)?;
    }
    let tags = subject.tags(ctx, id).await?;
    let message = match subject {
        Subject::User => "Tags removed from user access successfully",
        Subject::Role => "Tags removed from role access successfully",
    };
    Ok(subject.response(id, &name, tags, message))
}

async fn get_user(user: User, State(ctx): State<AppContext>, Path(raw): Path<String>) -> ApiResult {
    get_access(Subject::User, &user, &ctx, &raw).await
}

async fn set_user(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(user, body): WithJson<User>,
) -> ApiResult {
    set_access(Subject::User, &user, &ctx, &raw, &body).await
}

async fn add_user(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(user, body): WithJson<User>,
) -> ApiResult {
    add_access(Subject::User, &user, &ctx, &raw, &body).await
}

async fn remove_user(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(user, body): WithJson<User>,
) -> ApiResult {
    remove_access(Subject::User, &user, &ctx, &raw, &body).await
}

async fn get_role(user: User, State(ctx): State<AppContext>, Path(raw): Path<String>) -> ApiResult {
    get_access(Subject::Role, &user, &ctx, &raw).await
}

async fn set_role(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(user, body): WithJson<User>,
) -> ApiResult {
    set_access(Subject::Role, &user, &ctx, &raw, &body).await
}

async fn add_role(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(user, body): WithJson<User>,
) -> ApiResult {
    add_access(Subject::Role, &user, &ctx, &raw, &body).await
}

async fn remove_role(
    State(ctx): State<AppContext>,
    Path(raw): Path<String>,
    WithJson(user, body): WithJson<User>,
) -> ApiResult {
    remove_access(Subject::Role, &user, &ctx, &raw, &body).await
}

/// `GET /me`: the caller's customers and tags.
async fn me(user: User, State(ctx): State<AppContext>) -> ApiResult {
    let settings = visibility::tag_access_settings(&ctx.db).await?;
    let enabled = settings.as_ref().is_some_and(|s| s.enabled);
    let tags =
        visibility::accessible_tags(&ctx.db, settings.as_ref(), user.id, user.role_id).await?;
    let (unrestricted, tag_list) = match tags {
        TagSet::All => {
            let all = sqlx::query_as::<_, Tag>(
                "SELECT incident_management_alerttag.id, incident_management_alerttag.tag \
                 FROM incident_management_alerttag",
            )
            .fetch_all(ctx.db.pool())
            .await
            .map_err(internal)?;
            (true, all)
        }
        TagSet::Tags(ids) => {
            let ids: Vec<i64> = ids
                .into_iter()
                .map(i64::from)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            (false, tags_where_in(&ctx, &ids).await?)
        }
    };
    let customers: Vec<String> = match user.access(&ctx).await? {
        AccessScope::All => vec!["*".into()],
        AccessScope::Customers(codes) => codes.clone(),
    };
    let role_name = match user.role_id {
        Some(r) if r != 0 => sqlx::query_scalar::<_, String>("SELECT name FROM role WHERE id = ?")
            .bind(r)
            .fetch_optional(ctx.db.pool())
            .await
            .map_err(internal)?,
        _ => None,
    };
    Ok(json(json!({
        "user_id": user.id,
        "username": user.username,
        "role_id": user.role_id,
        "role_name": role_name,
        "accessible_customers": customers,
        "accessible_tags": tag_list,
        "is_tag_unrestricted": unrestricted,
        "tag_rbac_enabled": enabled,
        "success": true,
        "message": "Effective access retrieved successfully",
    })))
}
