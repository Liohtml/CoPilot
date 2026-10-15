//! The writes of `app/incidents/services/db_operations.py` behind the
//! db_operations routes: alerts, comments, assets, tags, IoCs and cases.
//!
//! Each function is one Python service call: it reads the row, changes it,
//! commits, and returns the object the way the ORM holds it after the commit
//! (`expire_on_commit=False`): stored values plus what was just set — with
//! the microseconds of a fresh `datetime.utcnow()`, which MySQL rounds away.
//! `IntegrityError`s that Python turns into a 400 are reported the same way;
//! any other database error is a 500.

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::MySqlConnection;
use sqlx::mysql::MySqlDatabaseError;

use copilot_core::time::{mysql_datetime, now_utc_micros};
use copilot_db::Db;
use copilot_web::ApiError;

use crate::requests::{AlertCreate, AssetCreate, CaseCreate, IocCreate, PyDateTime};
use crate::store::{self, AlertRow, CaseRow};

/// MySQL errors `pymysql` raises as `IntegrityError`.
const INTEGRITY_ERRORS: [u16; 7] = [1062, 1216, 1452, 1217, 1451, 1215, 1048];

/// Whether `e` is what SQLAlchemy reports as an `IntegrityError`.
pub fn is_integrity(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.try_downcast_ref::<MySqlDatabaseError>())
        .is_some_and(|m| INTEGRITY_ERRORS.contains(&m.number()))
}

/// A database error: `IntegrityError` → 400 `detail`, anything else → 500.
pub fn integrity_or_internal(e: sqlx::Error, detail: &str) -> ApiError {
    if is_integrity(&e) {
        ApiError::bad_request(detail)
    } else {
        ApiError::internal(e)
    }
}

fn internal(e: sqlx::Error) -> ApiError {
    ApiError::internal(e)
}

async fn alert_or_404(db: &Db, id: i64) -> Result<AlertRow, ApiError> {
    store::alert(db, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Alert not found"))
}

async fn case_or_404(db: &Db, id: i64) -> Result<CaseRow, ApiError> {
    store::case(db, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Case not found"))
}

fn db_time(t: Option<NaiveDateTime>) -> Option<NaiveDateTime> {
    t.map(mysql_datetime)
}

// ── alerts ────────────────────────────────────────────────────────────────

/// `create_alert`: insert and read back (`refresh`); returns the id.
pub async fn create_alert(db: &Db, a: &AlertCreate) -> Result<i64, ApiError> {
    let result = sqlx::query(
        "INSERT INTO incident_management_alert (alert_name, alert_description, status, \
         alert_creation_time, customer_code, time_closed, source, severity, assigned_to, \
         escalated, verdict, verdict_reason, verdict_note, verdict_by, verdict_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, 0, NULL, NULL, NULL, NULL, NULL)",
    )
    .bind(&a.alert_name)
    .bind(&a.alert_description)
    .bind(&a.status)
    .bind(db_time(a.alert_creation_time.map(|t| t.wall)))
    .bind(&a.customer_code)
    .bind(db_time(a.time_closed.map(|t| t.wall)))
    .bind(&a.source)
    .bind(&a.assigned_to)
    .execute(db.pool())
    .await
    .map_err(|e| integrity_or_internal(e, "Alert already exists"))?;
    Ok(result.last_insert_id() as i64)
}

/// `update_alert_status`: `time_closed` stamped on CLOSED, cleared otherwise.
pub async fn update_alert_status(db: &Db, id: i64, status: &str) -> Result<AlertRow, ApiError> {
    let mut row = alert_or_404(db, id).await?;
    row.status = status.to_string();
    row.time_closed = (status == "CLOSED").then(now_utc_micros);
    sqlx::query("UPDATE incident_management_alert SET status = ?, time_closed = ? WHERE id = ?")
        .bind(&row.status)
        .bind(db_time(row.time_closed))
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(internal)?;
    Ok(row)
}

/// `update_alert_assigned_to`.
pub async fn update_alert_assigned_to(db: &Db, id: i64, user: &str) -> Result<AlertRow, ApiError> {
    let mut row = alert_or_404(db, id).await?;
    row.assigned_to = Some(user.to_string());
    sqlx::query("UPDATE incident_management_alert SET assigned_to = ? WHERE id = ?")
        .bind(user)
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(internal)?;
    Ok(row)
}

/// `update_alert_escalated`.
pub async fn update_alert_escalated(db: &Db, id: i64, flag: bool) -> Result<AlertRow, ApiError> {
    let mut row = alert_or_404(db, id).await?;
    row.escalated = flag;
    sqlx::query("UPDATE incident_management_alert SET escalated = ? WHERE id = ?")
        .bind(flag)
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(internal)?;
    Ok(row)
}

/// `update_alert_verdict`: the alert and the previous verdict snapshot.
pub async fn update_alert_verdict(
    db: &Db,
    id: i64,
    verdict: Option<&str>,
    reason: Option<&str>,
    note: Option<&str>,
    actor: &str,
) -> Result<(AlertRow, Value), ApiError> {
    let mut row = alert_or_404(db, id).await?;
    let previous = json!({
        "verdict": row.verdict,
        "verdict_reason": row.verdict_reason,
        "verdict_note": row.verdict_note,
        "verdict_by": row.verdict_by,
    });
    row.verdict = verdict.map(str::to_string);
    if verdict.is_none() {
        row.verdict_reason = None;
        row.verdict_note = None;
        row.verdict_by = None;
        row.verdict_at = None;
    } else {
        row.verdict_reason = reason.map(str::to_string);
        row.verdict_note = note.map(str::to_string);
        row.verdict_by = Some(actor.to_string());
        row.verdict_at = Some(now_utc_micros());
    }
    sqlx::query(
        "UPDATE incident_management_alert SET verdict = ?, verdict_reason = ?, verdict_note = ?, \
         verdict_by = ?, verdict_at = ? WHERE id = ?",
    )
    .bind(&row.verdict)
    .bind(&row.verdict_reason)
    .bind(&row.verdict_note)
    .bind(&row.verdict_by)
    .bind(db_time(row.verdict_at))
    .bind(id)
    .execute(db.pool())
    .await
    .map_err(internal)?;
    Ok((row, previous))
}

/// `AlertVerdictState`.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct VerdictState {
    /// Alert.
    pub id: i32,
    /// Verdict.
    pub verdict: Option<String>,
    /// Reason.
    pub verdict_reason: Option<String>,
    /// Note.
    pub verdict_note: Option<String>,
    /// Who.
    pub verdict_by: Option<String>,
    /// When.
    #[serde(serialize_with = "copilot_core::time::pydantic::opt_datetime")]
    pub verdict_at: Option<NaiveDateTime>,
}

// ── comments ──────────────────────────────────────────────────────────────

/// The SQLModel `Comment` / `CaseComment` row as a response field.
#[derive(Debug, Clone, Serialize)]
pub struct CommentRecord {
    /// Id.
    pub id: i64,
    /// `alert_id` or `case_id` (renamed by the caller's serializer).
    #[serde(skip)]
    pub parent: Option<i64>,
    /// Text.
    pub comment: String,
    /// Author.
    pub user_name: String,
    /// Created.
    pub created_at: PyDateTime,
}

impl CommentRecord {
    /// `{id, <parent_key>, comment, user_name, created_at}`.
    pub fn to_json(&self, parent_key: &str) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("id".into(), json!(self.id));
        m.insert(parent_key.into(), json!(self.parent));
        m.insert("comment".into(), json!(self.comment));
        m.insert("user_name".into(), json!(self.user_name));
        m.insert(
            "created_at".into(),
            serde_json::to_value(self.created_at).unwrap_or(Value::Null),
        );
        Value::Object(m)
    }
}

/// Which comment table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    /// `incident_management_comment` (on an alert).
    Alert,
    /// `incident_management_case_comment`.
    Case,
}

impl CommentKind {
    /// Table.
    pub const fn table(self) -> &'static str {
        match self {
            Self::Alert => "incident_management_comment",
            Self::Case => "incident_management_case_comment",
        }
    }

    /// Parent column.
    pub const fn parent(self) -> &'static str {
        match self {
            Self::Alert => "alert_id",
            Self::Case => "case_id",
        }
    }
}

/// A stored comment.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredComment {
    /// Id.
    pub id: i32,
    /// Alert or case.
    pub parent: Option<i32>,
    /// Text.
    pub comment: String,
    /// Author.
    pub user_name: String,
    /// Created.
    pub created_at: NaiveDateTime,
}

impl From<StoredComment> for CommentRecord {
    fn from(c: StoredComment) -> Self {
        Self {
            id: i64::from(c.id),
            parent: c.parent.map(i64::from),
            comment: c.comment,
            user_name: c.user_name,
            created_at: PyDateTime::naive(c.created_at),
        }
    }
}

/// One comment by id.
pub async fn comment(
    db: &Db,
    kind: CommentKind,
    id: i64,
) -> Result<Option<StoredComment>, ApiError> {
    sqlx::query_as::<_, StoredComment>(&format!(
        "SELECT id, {} AS parent, comment, user_name, created_at FROM {} WHERE id = ?",
        kind.parent(),
        kind.table()
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await
    .map_err(internal)
}

/// `create_comment` / `create_case_comment` (the parent was checked).
pub async fn create_comment(
    db: &Db,
    kind: CommentKind,
    parent: i64,
    text: &str,
    user_name: &str,
    created_at: Option<PyDateTime>,
) -> Result<CommentRecord, ApiError> {
    let created_at = created_at.unwrap_or_else(|| PyDateTime::naive(now_utc_micros()));
    let result = sqlx::query(&format!(
        "INSERT INTO {} ({}, comment, user_name, created_at) VALUES (?, ?, ?, ?)",
        kind.table(),
        kind.parent()
    ))
    .bind(parent)
    .bind(text)
    .bind(user_name)
    .bind(mysql_datetime(created_at.wall))
    .execute(db.pool())
    .await
    .map_err(|e| integrity_or_internal(e, "Comment already exists"))?;
    Ok(CommentRecord {
        id: result.last_insert_id() as i64,
        parent: Some(parent),
        comment: text.to_string(),
        user_name: user_name.to_string(),
        created_at,
    })
}

/// `edit_comment` / `edit_case_comment`.
pub async fn edit_comment(
    db: &Db,
    kind: CommentKind,
    id: i64,
    text: &str,
    user_name: &str,
) -> Result<CommentRecord, ApiError> {
    let stored = comment(db, kind, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Comment not found"))?;
    sqlx::query(&format!(
        "UPDATE {} SET comment = ?, user_name = ? WHERE id = ?",
        kind.table()
    ))
    .bind(text)
    .bind(user_name)
    .bind(id)
    .execute(db.pool())
    .await
    .map_err(internal)?;
    let mut out = CommentRecord::from(stored);
    out.comment = text.to_string();
    out.user_name = user_name.to_string();
    Ok(out)
}

/// `delete_comment` / `delete_case_comment`.
pub async fn delete_comment(db: &Db, kind: CommentKind, id: i64) -> Result<(), ApiError> {
    if comment(db, kind, id).await?.is_none() {
        return Err(ApiError::not_found("Comment not found"));
    }
    sqlx::query(&format!("DELETE FROM {} WHERE id = ?", kind.table()))
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(internal)?;
    Ok(())
}

// ── alert children ────────────────────────────────────────────────────────

/// `create_alert_context`: insert, then the row as stored (the JSON as MySQL
/// normalised it).
pub async fn create_alert_context(
    db: &Db,
    source: &str,
    context: &Value,
) -> Result<Value, ApiError> {
    let result =
        sqlx::query("INSERT INTO incident_management_alertcontext (source, context) VALUES (?, ?)")
            .bind(source)
            .bind(sqlx::types::Json(context))
            .execute(db.pool())
            .await
            .map_err(|e| integrity_or_internal(e, "Alert context already exists"))?;
    let row = crate::config::alert_context(db, result.last_insert_id() as i64)
        .await?
        .ok_or_else(|| ApiError::internal("alert context vanished"))?;
    Ok(serde_json::to_value(row).unwrap_or(Value::Null))
}

/// `create_asset`: the alert and the context must exist.
pub async fn create_asset(db: &Db, a: &AssetCreate) -> Result<Value, ApiError> {
    alert_or_404(db, a.alert_linked).await?;
    if crate::config::alert_context(db, a.alert_context_id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("Alert context not found"));
    }
    let result = sqlx::query(
        "INSERT INTO incident_management_asset (alert_linked, asset_name, alert_context_id, \
         agent_id, velociraptor_id, customer_code, index_name, index_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(a.alert_linked)
    .bind(&a.asset_name)
    .bind(a.alert_context_id)
    .bind(&a.agent_id)
    .bind(&a.velociraptor_id)
    .bind(&a.customer_code)
    .bind(&a.index_name)
    .bind(&a.index_id)
    .execute(db.pool())
    .await
    .map_err(|e| integrity_or_internal(e, "Asset already exists"))?;
    Ok(json!({
        "id": result.last_insert_id(),
        "alert_linked": a.alert_linked,
        "asset_name": a.asset_name,
        "alert_context_id": a.alert_context_id,
        "agent_id": a.agent_id,
        "velociraptor_id": a.velociraptor_id,
        "customer_code": a.customer_code,
        "index_name": a.index_name,
        "index_id": a.index_id,
    }))
}

/// `create_alert_ioc`: a new IoC row and its link.
pub async fn create_alert_ioc(db: &Db, i: &IocCreate) -> Result<Value, ApiError> {
    let fail = |e| integrity_or_internal(e, "Alert IoC already exists");
    let mut tx = db.pool().begin().await.map_err(internal)?;
    let ioc = sqlx::query(
        "INSERT INTO incident_management_ioc (value, type, description) VALUES (?, ?, ?)",
    )
    .bind(&i.ioc_value)
    .bind(&i.ioc_type)
    .bind(&i.ioc_description)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    let ioc_id = ioc.last_insert_id();
    sqlx::query("INSERT INTO incident_management_alert_to_ioc (alert_id, ioc_id) VALUES (?, ?)")
        .bind(i.alert_id)
        .bind(ioc_id)
        .execute(&mut *tx)
        .await
        .map_err(fail)?;
    tx.commit().await.map_err(fail)?;
    Ok(json!({"alert_id": i.alert_id, "ioc_id": ioc_id}))
}

/// `delete_alert_ioc`: the link, then the IoC itself.
pub async fn delete_alert_ioc(db: &Db, alert_id: i64, ioc_id: i64) -> Result<Value, ApiError> {
    let link: Option<(i32, i32)> = sqlx::query_as(
        "SELECT alert_id, ioc_id FROM incident_management_alert_to_ioc \
         WHERE alert_id = ? AND ioc_id = ?",
    )
    .bind(alert_id)
    .bind(ioc_id)
    .fetch_optional(db.pool())
    .await
    .map_err(internal)?;
    let Some((a, i)) = link else {
        return Err(ApiError::not_found("Alert IoC not found"));
    };
    let mut tx = db.pool().begin().await.map_err(internal)?;
    sqlx::query("DELETE FROM incident_management_alert_to_ioc WHERE alert_id = ? AND ioc_id = ?")
        .bind(alert_id)
        .bind(ioc_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    sqlx::query("DELETE FROM incident_management_ioc WHERE id = ?")
        .bind(ioc_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit()
        .await
        .map_err(|e| integrity_or_internal(e, "Error deleting alert IoC"))?;
    Ok(json!({"alert_id": a, "ioc_id": i}))
}

/// `create_alert_tag`: a new tag row and its link.
pub async fn create_alert_tag(db: &Db, alert_id: i64, tag: &str) -> Result<Value, ApiError> {
    let fail = |e| integrity_or_internal(e, "Alert tag already exists");
    let mut tx = db.pool().begin().await.map_err(internal)?;
    let created = sqlx::query("INSERT INTO incident_management_alerttag (tag) VALUES (?)")
        .bind(tag)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let tag_id = created.last_insert_id();
    sqlx::query("INSERT INTO incident_management_alert_to_tag (alert_id, tag_id) VALUES (?, ?)")
        .bind(alert_id)
        .bind(tag_id)
        .execute(&mut *tx)
        .await
        .map_err(fail)?;
    tx.commit().await.map_err(fail)?;
    Ok(json!({"id": tag_id, "tag": tag}))
}

/// `delete_alert_tag`: the link, then the tag itself.
pub async fn delete_alert_tag(db: &Db, alert_id: i64, tag_id: i64) -> Result<Value, ApiError> {
    let tag: Option<(i32, String)> =
        sqlx::query_as("SELECT id, tag FROM incident_management_alerttag WHERE id = ?")
            .bind(tag_id)
            .fetch_optional(db.pool())
            .await
            .map_err(internal)?;
    let Some((id, name)) = tag else {
        return Err(ApiError::not_found("Alert tag not found"));
    };
    let link: Option<(i32,)> = sqlx::query_as(
        "SELECT alert_id FROM incident_management_alert_to_tag WHERE alert_id = ? AND tag_id = ?",
    )
    .bind(alert_id)
    .bind(tag_id)
    .fetch_optional(db.pool())
    .await
    .map_err(internal)?;
    if link.is_none() {
        return Err(ApiError::not_found("Alert to tag link not found"));
    }
    let mut tx = db.pool().begin().await.map_err(internal)?;
    sqlx::query("DELETE FROM incident_management_alert_to_tag WHERE alert_id = ? AND tag_id = ?")
        .bind(alert_id)
        .bind(tag_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    sqlx::query("DELETE FROM incident_management_alerttag WHERE id = ?")
        .bind(tag_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit()
        .await
        .map_err(|e| integrity_or_internal(e, "Error deleting alert tag"))?;
    Ok(json!({"id": id, "tag": name}))
}

/// `is_alert_linked_to_case`: 400 when the alert belongs to a case.
pub async fn ensure_not_linked(db: &Db, alert_id: i64) -> Result<(), ApiError> {
    let linked: Option<(i32,)> = sqlx::query_as(
        "SELECT case_id FROM incident_management_casealertlink WHERE alert_id = ? LIMIT 1",
    )
    .bind(alert_id)
    .fetch_optional(db.pool())
    .await
    .map_err(internal)?;
    if linked.is_some() {
        return Err(ApiError::bad_request(
            "Alert is linked to a case, and cannot be deleted",
        ));
    }
    Ok(())
}

/// `delete_alert`: comments, assets (and the contexts no other asset uses),
/// tag and IoC links, threshold metadata; case tasks stamped with the alert
/// are orphaned; then the alert.
pub async fn delete_alert(db: &Db, alert_id: i64) -> Result<(), ApiError> {
    alert_or_404(db, alert_id).await?;
    let mut tx = db.pool().begin().await.map_err(internal)?;
    delete_alert_rows(&mut tx, alert_id)
        .await
        .map_err(internal)?;
    tx.commit()
        .await
        .map_err(|e| integrity_or_internal(e, "Error deleting alert"))?;
    Ok(())
}

async fn delete_alert_rows(conn: &mut MySqlConnection, alert_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM incident_management_comment WHERE alert_id = ?")
        .bind(alert_id)
        .execute(&mut *conn)
        .await?;
    let assets: Vec<(i32, Option<i32>)> = sqlx::query_as(
        "SELECT id, alert_context_id FROM incident_management_asset WHERE alert_linked = ?",
    )
    .bind(alert_id)
    .fetch_all(&mut *conn)
    .await?;
    for (id, context) in assets {
        sqlx::query("DELETE FROM incident_management_asset WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;
        let Some(context) = context else {
            continue;
        };
        let users: Option<(i32,)> = sqlx::query_as(
            "SELECT id FROM incident_management_asset WHERE alert_context_id = ? LIMIT 1",
        )
        .bind(context)
        .fetch_optional(&mut *conn)
        .await?;
        if users.is_none() {
            sqlx::query("DELETE FROM incident_management_alertcontext WHERE id = ?")
                .bind(context)
                .execute(&mut *conn)
                .await?;
        }
    }
    sqlx::query("DELETE FROM incident_management_alert_to_tag WHERE alert_id = ?")
        .bind(alert_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM incident_management_alert_to_ioc WHERE alert_id = ?")
        .bind(alert_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM incident_management_threshold_alert_metadata WHERE alert_id = ?")
        .bind(alert_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "UPDATE incident_management_case_task SET alert_id = NULL, updated_at = ? WHERE alert_id = ?",
    )
    .bind(mysql_datetime(now_utc_micros()))
    .bind(alert_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM incident_management_alert WHERE id = ?")
        .bind(alert_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

// ── cases ─────────────────────────────────────────────────────────────────

/// The SQLModel `Case` row as a response field (`CaseResponse.case`).
pub fn case_record(c: &CaseRow) -> Value {
    json!({
        "id": c.id,
        "case_name": c.case_name,
        "case_description": c.case_description,
        "case_creation_time": copilot_core::time::to_pydantic_iso(c.case_creation_time),
        "case_status": c.case_status,
        "case_closed_time": c.case_closed_time.map(copilot_core::time::to_pydantic_iso),
        "assigned_to": c.assigned_to,
        "customer_code": c.customer_code,
        "notification_invoked_number": c.notification_invoked_number,
        "escalated": c.escalated,
        "severity": c.severity,
    })
}

/// `create_case`'s insert, within `conn`'s transaction; returns the id.
pub async fn insert_case(conn: &mut MySqlConnection, c: &CaseCreate) -> Result<i64, ApiError> {
    let result = sqlx::query(
        "INSERT INTO incident_management_case (case_name, case_description, case_creation_time, \
         case_status, case_closed_time, assigned_to, customer_code, notification_invoked_number, \
         escalated, severity) VALUES (?, ?, ?, ?, NULL, ?, ?, 0, 0, ?)",
    )
    .bind(&c.case_name)
    .bind(&c.case_description)
    .bind(db_time(c.case_creation_time.map(|t| t.wall)))
    .bind(&c.case_status)
    .bind(&c.assigned_to)
    .bind(&c.customer_code)
    .bind(&c.severity)
    .execute(&mut *conn)
    .await
    .map_err(|e| integrity_or_internal(e, "Case already exists"))?;
    Ok(result.last_insert_id() as i64)
}

/// `create_case_from_alert`'s insert: the alert's name, description,
/// status, assignee, escalation and customer.
pub async fn insert_case_from_alert(
    conn: &mut MySqlConnection,
    a: &AlertRow,
) -> Result<i64, ApiError> {
    let result = sqlx::query(
        "INSERT INTO incident_management_case (case_name, case_description, case_creation_time, \
         case_status, case_closed_time, assigned_to, customer_code, notification_invoked_number, \
         escalated, severity) VALUES (?, ?, ?, ?, NULL, ?, ?, 0, ?, NULL)",
    )
    .bind(&a.alert_name)
    .bind(&a.alert_description)
    .bind(mysql_datetime(now_utc_micros()))
    .bind(&a.status)
    .bind(&a.assigned_to)
    .bind(&a.customer_code)
    .bind(a.escalated)
    .execute(&mut *conn)
    .await
    .map_err(|e| integrity_or_internal(e, "Case already exists"))?;
    Ok(result.last_insert_id() as i64)
}

/// `update_case_status`: `case_closed_time` stamped on CLOSED, cleared
/// otherwise.
pub async fn update_case_status(db: &Db, id: i64, status: &str) -> Result<(), ApiError> {
    case_or_404(db, id).await?;
    let closed = (status == "CLOSED").then(now_utc_micros);
    sqlx::query(
        "UPDATE incident_management_case SET case_status = ?, case_closed_time = ? WHERE id = ?",
    )
    .bind(status)
    .bind(db_time(closed))
    .bind(id)
    .execute(db.pool())
    .await
    .map_err(internal)?;
    Ok(())
}

/// One column of a case, set (`update_case_assigned_to`, `_escalated`,
/// `_severity`, `_customer_code`); returns the row before the change.
pub async fn update_case_column(
    db: &Db,
    id: i64,
    column: &str,
    value: Value,
) -> Result<CaseRow, ApiError> {
    let before = case_or_404(db, id).await?;
    let sql = format!("UPDATE incident_management_case SET {column} = ? WHERE id = ?");
    let q = sqlx::query(&sql);
    let q = match value {
        Value::Bool(b) => q.bind(b),
        Value::String(s) => q.bind(s),
        _ => q.bind(None::<String>),
    };
    q.bind(id).execute(db.pool()).await.map_err(internal)?;
    Ok(before)
}

/// `customer_code_valid`: the code must have alert creation settings.
pub async fn customer_code_valid(db: &Db, code: &str) -> Result<(), ApiError> {
    let found: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM custom_alert_creation_settings WHERE customer_code = ? LIMIT 1",
    )
    .bind(code)
    .fetch_optional(db.pool())
    .await
    .map_err(internal)?;
    if found.is_none() {
        return Err(ApiError::not_found("Customer code not found"));
    }
    Ok(())
}

/// The linked alerts of a case and their status (`CaseAlertLink` ⋈ `Alert`).
pub async fn linked_alert_statuses(db: &Db, case_id: i64) -> Result<Vec<(i64, String)>, ApiError> {
    let rows: Vec<(i32, String)> = sqlx::query_as(
        "SELECT l.alert_id, a.status FROM incident_management_casealertlink l \
         JOIN incident_management_alert a ON a.id = l.alert_id WHERE l.case_id = ?",
    )
    .bind(case_id)
    .fetch_all(db.pool())
    .await
    .map_err(internal)?;
    Ok(rows.into_iter().map(|(id, s)| (i64::from(id), s)).collect())
}
