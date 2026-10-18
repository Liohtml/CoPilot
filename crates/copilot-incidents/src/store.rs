//! Rows and reads of the `incident_management_*` tables — the queries behind
//! `app/incidents/services/db_operations.py`.
//!
//! `incident_management_*.customer_code` is a plain string (no FK): orphaned
//! codes exist by design, so nothing here joins `customers`.
//!
//! **Order.** Lists keep the Python query's `ORDER BY` (always `id` for
//! alerts and cases, so ties cannot happen). The relationships SQLAlchemy
//! loads with `selectinload` come back in the order MySQL scans them, which
//! for one parent is its primary key (comments, assets) or the link table's
//! (`alert_to_tag` → tag id, `alert_to_ioc` → IoC id, `casealertlink` → case
//! id / alert id); the loaders below order by the same keys. Queries without
//! an `ORDER BY` in Python keep their exact shape here, so MySQL picks the
//! same plan and row order.
//!
//! **Duplicates.** `select(Alert).join(Asset)…` is not de-duplicated by the
//! ORM: an alert with two matching assets is listed (and counted) twice, and
//! so it is here.

use std::collections::HashMap;

use chrono::NaiveDateTime;
use serde_json::Value;
use sqlx::{FromRow, MySql, QueryBuilder};

use copilot_db::{Db, DbError};

/// `incident_management_alert`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AlertRow {
    /// Id.
    pub id: i32,
    /// Title.
    pub alert_name: String,
    /// Description.
    pub alert_description: String,
    /// Status.
    pub status: String,
    /// Creation / last-seen time.
    pub alert_creation_time: NaiveDateTime,
    /// Tenant.
    pub customer_code: String,
    /// Closed at.
    pub time_closed: Option<NaiveDateTime>,
    /// Source.
    pub source: String,
    /// Severity (`NULL` = the source gave none).
    pub severity: Option<String>,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Escalated.
    pub escalated: bool,
    /// Verdict.
    pub verdict: Option<String>,
    /// Reason.
    pub verdict_reason: Option<String>,
    /// Note.
    pub verdict_note: Option<String>,
    /// Who.
    pub verdict_by: Option<String>,
    /// When.
    pub verdict_at: Option<NaiveDateTime>,
}

/// Every alert column, table aliased `a`.
pub const ALERT_COLS: &str = "a.id, a.alert_name, a.alert_description, a.status, \
    a.alert_creation_time, a.customer_code, a.time_closed, a.source, a.severity, a.assigned_to, \
    a.escalated, a.verdict, a.verdict_reason, a.verdict_note, a.verdict_by, a.verdict_at";

/// `incident_management_comment`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CommentRow {
    /// Id.
    pub id: i32,
    /// Alert.
    pub alert_id: Option<i32>,
    /// Text.
    pub comment: String,
    /// Author.
    pub user_name: String,
    /// Created.
    pub created_at: NaiveDateTime,
}

/// `incident_management_asset`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AssetRow {
    /// Id.
    pub id: i32,
    /// Alert.
    pub alert_linked: Option<i32>,
    /// Host.
    pub asset_name: String,
    /// Context row.
    pub alert_context_id: i32,
    /// Wazuh agent id.
    pub agent_id: Option<String>,
    /// Velociraptor client id.
    pub velociraptor_id: Option<String>,
    /// Tenant.
    pub customer_code: String,
    /// Index.
    pub index_name: String,
    /// Document id.
    pub index_id: String,
}

/// A tag of an alert (`alert_to_tag` ⋈ `alerttag`).
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct TagRow {
    /// Alert.
    pub alert_id: i32,
    /// Tag id.
    pub tag_id: i32,
    /// Tag text.
    pub tag: String,
}

/// An IoC of an alert (`alert_to_ioc` ⋈ `ioc`).
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct IocRow {
    /// Alert.
    pub alert_id: i32,
    /// IoC id.
    pub ioc_id: i32,
    /// Value.
    pub value: String,
    /// Type.
    pub kind: String,
    /// Description.
    pub description: Option<String>,
}

/// A case an alert is linked to (`casealertlink` ⋈ `case`).
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct LinkedCaseRow {
    /// Alert.
    pub alert_id: i32,
    /// Case id.
    pub case_id: i32,
    /// Name.
    pub case_name: String,
    /// Description.
    pub case_description: String,
    /// Created.
    pub case_creation_time: NaiveDateTime,
    /// Status.
    pub case_status: String,
    /// Assignee.
    pub assigned_to: Option<String>,
}

/// `incident_management_case`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CaseRow {
    /// Id.
    pub id: i32,
    /// Name.
    pub case_name: String,
    /// Description.
    pub case_description: String,
    /// Created.
    pub case_creation_time: NaiveDateTime,
    /// Status.
    pub case_status: String,
    /// Closed at.
    pub case_closed_time: Option<NaiveDateTime>,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Tenant (nullable!).
    pub customer_code: Option<String>,
    /// Shuffle notifications sent.
    pub notification_invoked_number: Option<i32>,
    /// Escalated.
    pub escalated: bool,
    /// The analyst's severity.
    pub severity: Option<String>,
}

/// Every case column, table aliased `c`.
pub const CASE_COLS: &str = "c.id, c.case_name, c.case_description, c.case_creation_time, \
    c.case_status, c.case_closed_time, c.assigned_to, c.customer_code, \
    c.notification_invoked_number, c.escalated, c.severity";

/// `incident_management_case_comment`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CaseCommentRow {
    /// Id.
    pub id: i32,
    /// Case.
    pub case_id: Option<i32>,
    /// Text.
    pub comment: String,
    /// Author.
    pub user_name: String,
    /// Created.
    pub created_at: NaiveDateTime,
}

/// `incident_management_case_task`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CaseTaskRow {
    /// Id.
    pub id: i32,
    /// Case.
    pub case_id: i32,
    /// Originating alert.
    pub alert_id: Option<i32>,
    /// Template task.
    pub template_task_id: Option<i32>,
    /// Title.
    pub title: String,
    /// Description.
    pub description: Option<String>,
    /// Guidelines.
    pub guidelines: Option<String>,
    /// Mandatory.
    pub mandatory: bool,
    /// Order.
    pub order_index: i32,
    /// Status.
    pub status: String,
    /// Evidence.
    pub evidence_comment: Option<String>,
    /// Completed by.
    pub completed_by: Option<String>,
    /// Completed at.
    pub completed_at: Option<NaiveDateTime>,
    /// Assignee.
    pub assigned_to: Option<String>,
    /// Creator.
    pub created_by: String,
    /// Created.
    pub created_at: NaiveDateTime,
    /// Updated.
    pub updated_at: NaiveDateTime,
}

/// Every task column.
pub const TASK_COLS: &str = "id, case_id, alert_id, template_task_id, title, description, \
    guidelines, mandatory, order_index, status, evidence_comment, completed_by, completed_at, \
    assigned_to, created_by, created_at, updated_at";

/// `incident_management_case_event`.
#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct CaseEventRow {
    /// Id.
    pub id: i32,
    /// Case.
    pub case_id: i32,
    /// Type.
    pub event_type: String,
    /// Who.
    pub actor: String,
    /// When.
    pub timestamp: NaiveDateTime,
    /// Payload (JSON).
    pub payload: Option<Value>,
}

/// `incident_management_case_datastore`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CaseFileRow {
    /// Id.
    pub id: i32,
    /// Case.
    pub case_id: i32,
    /// Bucket.
    pub bucket_name: String,
    /// Key.
    pub object_key: String,
    /// File name.
    pub file_name: String,
    /// MIME type.
    pub content_type: Option<String>,
    /// Bytes.
    pub file_size: Option<i32>,
    /// Uploaded.
    pub upload_time: NaiveDateTime,
    /// SHA-256.
    pub file_hash: String,
}

/// Every datastore column.
pub const FILE_COLS: &str = "id, case_id, bucket_name, object_key, file_name, content_type, \
    file_size, upload_time, file_hash";

/// `push ", "`-separated binds.
pub fn push_list<'a, T>(qb: &mut QueryBuilder<'a, MySql>, values: impl IntoIterator<Item = T>)
where
    T: 'a + Send + sqlx::Encode<'a, MySql> + sqlx::Type<MySql>,
{
    let mut sep = qb.separated(", ");
    for v in values {
        sep.push_bind(v);
    }
}

fn unique(ids: &[i32]) -> Vec<i32> {
    let mut out: Vec<i32> = Vec::with_capacity(ids.len());
    for id in ids {
        if !out.contains(id) {
            out.push(*id);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

/// One alert.
pub async fn alert(db: &Db, id: i64) -> Result<Option<AlertRow>, DbError> {
    let sql = format!("SELECT {ALERT_COLS} FROM incident_management_alert a WHERE a.id = ?");
    Ok(sqlx::query_as::<_, AlertRow>(&sql)
        .bind(id)
        .fetch_optional(db.pool())
        .await?)
}

/// Alerts by id (any order; callers re-order).
pub async fn alerts_by_ids(db: &Db, ids: &[i32]) -> Result<Vec<AlertRow>, DbError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {ALERT_COLS} FROM incident_management_alert a WHERE a.id IN ("
    ));
    push_list(&mut qb, unique(ids));
    qb.push(")");
    Ok(qb.build_query_as::<AlertRow>().fetch_all(db.pool()).await?)
}

/// Which relationships a Python query `selectinload`s besides comments,
/// assets and tags (which every alert listing loads).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Include {
    /// `selectinload(Alert.iocs)` and the IoCs passed to `build_alert_out`.
    pub iocs: bool,
    /// `selectinload(Alert.cases).selectinload(CaseAlertLink.case)` and the
    /// linked cases passed to `build_alert_out`.
    pub cases: bool,
}

impl Include {
    /// Everything.
    pub const ALL: Include = Include {
        iocs: true,
        cases: true,
    };
    /// Comments, assets and tags only.
    pub const BASIC: Include = Include {
        iocs: false,
        cases: false,
    };
    /// Comments, assets, tags and IoCs.
    pub const IOCS: Include = Include {
        iocs: true,
        cases: false,
    };
}

/// The relationships of a set of alerts, by alert id.
#[derive(Debug, Default)]
pub struct AlertChildren {
    /// Comments.
    pub comments: HashMap<i32, Vec<CommentRow>>,
    /// Assets.
    pub assets: HashMap<i32, Vec<AssetRow>>,
    /// Tags.
    pub tags: HashMap<i32, Vec<TagRow>>,
    /// IoCs.
    pub iocs: HashMap<i32, Vec<IocRow>>,
    /// Linked cases.
    pub cases: HashMap<i32, Vec<LinkedCaseRow>>,
}

/// Load comments, assets, tags and (per `inc`) IoCs and linked cases.
pub async fn alert_children(db: &Db, ids: &[i32], inc: Include) -> Result<AlertChildren, DbError> {
    let ids = unique(ids);
    let mut out = AlertChildren::default();
    if ids.is_empty() {
        return Ok(out);
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT id, alert_id, comment, user_name, created_at FROM incident_management_comment \
         WHERE alert_id IN (",
    );
    push_list(&mut qb, ids.iter().copied());
    qb.push(") ORDER BY id");
    for row in qb
        .build_query_as::<CommentRow>()
        .fetch_all(db.pool())
        .await?
    {
        out.comments
            .entry(row.alert_id.unwrap_or_default())
            .or_default()
            .push(row);
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT id, alert_linked, asset_name, alert_context_id, agent_id, velociraptor_id, \
         customer_code, index_name, index_id FROM incident_management_asset WHERE alert_linked IN (",
    );
    push_list(&mut qb, ids.iter().copied());
    qb.push(") ORDER BY id");
    for row in qb.build_query_as::<AssetRow>().fetch_all(db.pool()).await? {
        out.assets
            .entry(row.alert_linked.unwrap_or_default())
            .or_default()
            .push(row);
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT l.alert_id, t.id AS tag_id, t.tag FROM incident_management_alert_to_tag l \
         JOIN incident_management_alerttag t ON t.id = l.tag_id WHERE l.alert_id IN (",
    );
    push_list(&mut qb, ids.iter().copied());
    qb.push(") ORDER BY l.alert_id, l.tag_id");
    for row in qb.build_query_as::<TagRow>().fetch_all(db.pool()).await? {
        out.tags.entry(row.alert_id).or_default().push(row);
    }
    if inc.iocs {
        let mut qb = QueryBuilder::<MySql>::new(
            "SELECT l.alert_id, i.id AS ioc_id, i.value, i.type AS kind, i.description \
             FROM incident_management_alert_to_ioc l JOIN incident_management_ioc i \
             ON i.id = l.ioc_id WHERE l.alert_id IN (",
        );
        push_list(&mut qb, ids.iter().copied());
        qb.push(") ORDER BY l.alert_id, l.ioc_id");
        for row in qb.build_query_as::<IocRow>().fetch_all(db.pool()).await? {
            out.iocs.entry(row.alert_id).or_default().push(row);
        }
    }
    if inc.cases {
        let mut qb = QueryBuilder::<MySql>::new(
            "SELECT l.alert_id, c.id AS case_id, c.case_name, c.case_description, \
             c.case_creation_time, c.case_status, c.assigned_to \
             FROM incident_management_casealertlink l JOIN incident_management_case c \
             ON c.id = l.case_id WHERE l.alert_id IN (",
        );
        push_list(&mut qb, ids.iter().copied());
        qb.push(") ORDER BY l.alert_id, l.case_id");
        for row in qb
            .build_query_as::<LinkedCaseRow>()
            .fetch_all(db.pool())
            .await?
        {
            out.cases.entry(row.alert_id).or_default().push(row);
        }
    }
    Ok(out)
}

/// `SELECT count(*)` over an arbitrary alert query tail (`FROM … WHERE …`).
pub async fn count(qb: &mut QueryBuilder<'_, MySql>, db: &Db) -> Result<i64, DbError> {
    Ok(qb.build_query_scalar::<i64>().fetch_one(db.pool()).await?)
}

/// Run an alert listing.
pub async fn fetch_alerts(
    qb: &mut QueryBuilder<'_, MySql>,
    db: &Db,
) -> Result<Vec<AlertRow>, DbError> {
    Ok(qb.build_query_as::<AlertRow>().fetch_all(db.pool()).await?)
}

/// `ORDER BY a.id <dir> LIMIT ? OFFSET ?` (`order` is `asc`/`desc`).
pub fn push_page(qb: &mut QueryBuilder<'_, MySql>, order: &str, page: i64, page_size: i64) {
    let dir = if order == "asc" { "ASC" } else { "DESC" };
    qb.push(format!(" ORDER BY a.id {dir} LIMIT "));
    qb.push_bind(page_size);
    qb.push(" OFFSET ");
    qb.push_bind((page - 1).saturating_mul(page_size));
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// One case.
pub async fn case(db: &Db, id: i64) -> Result<Option<CaseRow>, DbError> {
    let sql = format!("SELECT {CASE_COLS} FROM incident_management_case c WHERE c.id = ?");
    Ok(sqlx::query_as::<_, CaseRow>(&sql)
        .bind(id)
        .fetch_optional(db.pool())
        .await?)
}

/// Run a case listing.
pub async fn fetch_cases(
    qb: &mut QueryBuilder<'_, MySql>,
    db: &Db,
) -> Result<Vec<CaseRow>, DbError> {
    Ok(qb.build_query_as::<CaseRow>().fetch_all(db.pool()).await?)
}

/// Linked alert ids (by case, ascending alert id) and comments of cases.
pub async fn case_children(
    db: &Db,
    case_ids: &[i32],
) -> Result<(HashMap<i32, Vec<i32>>, HashMap<i32, Vec<CaseCommentRow>>), DbError> {
    let ids = unique(case_ids);
    let mut links: HashMap<i32, Vec<i32>> = HashMap::new();
    let mut comments: HashMap<i32, Vec<CaseCommentRow>> = HashMap::new();
    if ids.is_empty() {
        return Ok((links, comments));
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT case_id, alert_id FROM incident_management_casealertlink WHERE case_id IN (",
    );
    push_list(&mut qb, ids.iter().copied());
    qb.push(") ORDER BY case_id, alert_id");
    for (case_id, alert_id) in qb
        .build_query_as::<(i32, i32)>()
        .fetch_all(db.pool())
        .await?
    {
        links.entry(case_id).or_default().push(alert_id);
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT id, case_id, comment, user_name, created_at FROM incident_management_case_comment \
         WHERE case_id IN (",
    );
    push_list(&mut qb, ids.iter().copied());
    qb.push(") ORDER BY id");
    for row in qb
        .build_query_as::<CaseCommentRow>()
        .fetch_all(db.pool())
        .await?
    {
        comments
            .entry(row.case_id.unwrap_or_default())
            .or_default()
            .push(row);
    }
    Ok((links, comments))
}

/// `SELECT status, count(id) … GROUP BY status` rows.
pub async fn status_rows(
    qb: &mut QueryBuilder<'_, MySql>,
    db: &Db,
) -> Result<Vec<(String, i64)>, DbError> {
    Ok(qb
        .build_query_as::<(String, i64)>()
        .fetch_all(db.pool())
        .await?)
}
