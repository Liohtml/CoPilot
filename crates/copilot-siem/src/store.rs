//! `event_sources`, `enabled_dashboards` and `custom_dashboard_templates` —
//! the rows and the statements the Python services issue, in their shapes
//! (column lists in the models' order, the same `WHERE` and `ORDER BY`), so
//! MySQL answers both backends in the same order.
//!
//! JSON columns are read in the key order MySQL stores and written as JSON
//! text; a Python `None` written through SQLAlchemy's `JSON` type is the JSON
//! `null`, not SQL `NULL`, and so it is here.

use chrono::NaiveDateTime;
use serde_json::Value;
use sqlx::{FromRow, MySql, QueryBuilder};

use copilot_core::time::mysql_datetime;
use copilot_db::schema::TableRequirement;
use copilot_db::{Db, DbError};

/// A MySQL `JSON` column.
pub type Json = sqlx::types::Json<Value>;

/// The `event_sources` columns, in `EventSources`' order.
pub const EVENT_SOURCE_COLUMNS: &[&str] = &[
    "id",
    "customer_code",
    "name",
    "index_pattern",
    "event_type",
    "time_field",
    "enabled",
    "displayed_columns",
    "created_at",
    "updated_at",
];

/// The `enabled_dashboards` columns, in `EnabledDashboards`' order.
pub const ENABLED_COLUMNS: &[&str] = &[
    "id",
    "customer_code",
    "event_source_id",
    "library_card",
    "template_id",
    "display_name",
    "created_at",
];

/// The `custom_dashboard_templates` columns, in `CustomDashboardTemplates`'
/// order.
pub const CUSTOM_COLUMNS: &[&str] = &[
    "id",
    "template_key",
    "customer_code",
    "title",
    "description",
    "vendor",
    "product",
    "event_type",
    "tags",
    "color",
    "icon",
    "default_query",
    "panels",
    "created_by",
    "created_at",
    "updated_at",
];

/// The columns this crate reads and writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "event_sources",
        columns: EVENT_SOURCE_COLUMNS,
    },
    TableRequirement {
        table: "enabled_dashboards",
        columns: ENABLED_COLUMNS,
    },
    TableRequirement {
        table: "custom_dashboard_templates",
        columns: CUSTOM_COLUMNS,
    },
];

/// One `event_sources` row.
#[derive(Debug, Clone, FromRow)]
pub struct EventSourceRow {
    /// `id`.
    pub id: i32,
    /// `customer_code`.
    pub customer_code: String,
    /// `name`.
    pub name: String,
    /// `index_pattern`.
    pub index_pattern: String,
    /// `event_type`.
    pub event_type: String,
    /// `time_field`.
    pub time_field: String,
    /// `enabled`.
    pub enabled: bool,
    /// `displayed_columns` (JSON).
    pub displayed_columns: Option<Json>,
    /// `created_at`.
    pub created_at: NaiveDateTime,
    /// `updated_at`.
    pub updated_at: NaiveDateTime,
}

/// One `enabled_dashboards` row.
#[derive(Debug, Clone, FromRow)]
pub struct EnabledRow {
    /// `id`.
    pub id: i32,
    /// `customer_code`.
    pub customer_code: String,
    /// `event_source_id`.
    pub event_source_id: i32,
    /// `library_card`.
    pub library_card: String,
    /// `template_id`.
    pub template_id: String,
    /// `display_name`.
    pub display_name: String,
    /// `created_at`.
    pub created_at: NaiveDateTime,
}

/// One `custom_dashboard_templates` row.
#[derive(Debug, Clone, FromRow)]
pub struct CustomRow {
    /// `id`.
    pub id: i32,
    /// `template_key`.
    pub template_key: String,
    /// `customer_code` (`NULL` = shared with every customer).
    pub customer_code: Option<String>,
    /// `title`.
    pub title: String,
    /// `description`.
    pub description: String,
    /// `vendor`.
    pub vendor: String,
    /// `product`.
    pub product: String,
    /// `event_type`.
    pub event_type: String,
    /// `tags` (JSON).
    pub tags: Option<Json>,
    /// `color`.
    pub color: String,
    /// `icon`.
    pub icon: String,
    /// `default_query`.
    pub default_query: String,
    /// `panels` (JSON).
    pub panels: Json,
    /// `created_by`.
    pub created_by: Option<String>,
    /// `created_at`.
    pub created_at: NaiveDateTime,
    /// `updated_at`.
    pub updated_at: NaiveDateTime,
}

fn select(table: &str, columns: &[&str]) -> String {
    let cols: Vec<String> = columns.iter().map(|c| format!("{table}.{c}")).collect();
    format!("SELECT {} FROM {table}", cols.join(", "))
}

/// A Python value bound to a SQLAlchemy `JSON` column (`json.dumps`; `None`
/// is the JSON `null`).
fn json_text(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".into())
}

/// `select(Customers).filter(Customers.customer_code == code)`: whether a row
/// exists.
pub async fn customer_exists(db: &Db, code: &str) -> Result<bool, DbError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT customers.customer_code FROM customers WHERE customers.customer_code = ?",
    )
    .bind(code)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.is_some())
}

// --- event_sources ------------------------------------------------------------------

/// `select(EventSources).where(EventSources.id == id)`.
pub async fn event_source(db: &Db, id: i64) -> Result<Option<EventSourceRow>, DbError> {
    Ok(sqlx::query_as::<_, EventSourceRow>(&format!(
        "{} WHERE event_sources.id = ?",
        select("event_sources", EVENT_SOURCE_COLUMNS)
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}

/// A customer's event sources (no `ORDER BY`, as Python).
pub async fn event_sources_of(db: &Db, code: &str) -> Result<Vec<EventSourceRow>, DbError> {
    Ok(sqlx::query_as::<_, EventSourceRow>(&format!(
        "{} WHERE event_sources.customer_code = ?",
        select("event_sources", EVENT_SOURCE_COLUMNS)
    ))
    .bind(code)
    .fetch_all(db.pool())
    .await?)
}

/// The first event source of a customer with this name (MySQL's collation
/// compares the name).
pub async fn event_source_named(
    db: &Db,
    code: &str,
    name: &str,
) -> Result<Option<EventSourceRow>, DbError> {
    Ok(sqlx::query_as::<_, EventSourceRow>(&format!(
        "{} WHERE event_sources.customer_code = ? AND event_sources.name = ?",
        select("event_sources", EVENT_SOURCE_COLUMNS)
    ))
    .bind(code)
    .bind(name)
    .fetch_optional(db.pool())
    .await?)
}

/// What `create_event_source` inserts.
#[derive(Debug, Clone)]
pub struct NewEventSource<'a> {
    /// `customer_code`.
    pub customer_code: &'a str,
    /// `name`.
    pub name: &'a str,
    /// `index_pattern`.
    pub index_pattern: &'a str,
    /// `event_type`.
    pub event_type: &'a str,
    /// `time_field`.
    pub time_field: &'a str,
    /// `enabled`.
    pub enabled: bool,
    /// `displayed_columns` (`Value::Null` for `None`).
    pub displayed_columns: &'a Value,
    /// `created_at` (`utcnow()`).
    pub created_at: NaiveDateTime,
    /// `updated_at` (a second `utcnow()`).
    pub updated_at: NaiveDateTime,
}

/// Insert an event source; its id.
pub async fn insert_event_source(db: &Db, row: &NewEventSource<'_>) -> Result<i64, DbError> {
    let done = sqlx::query(
        "INSERT INTO event_sources (customer_code, name, index_pattern, event_type, time_field, \
         enabled, displayed_columns, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(row.customer_code)
    .bind(row.name)
    .bind(row.index_pattern)
    .bind(row.event_type)
    .bind(row.time_field)
    .bind(row.enabled)
    .bind(json_text(row.displayed_columns))
    .bind(mysql_datetime(row.created_at))
    .bind(mysql_datetime(row.updated_at))
    .execute(db.pool())
    .await?;
    Ok(done.last_insert_id() as i64)
}

/// One column change of an event source update (`None`: an explicit
/// `null`, which `update_from_model` sets too — MySQL refuses it for the
/// `NOT NULL` columns).
#[derive(Debug, Clone)]
pub enum EventSourceChange {
    /// A text column.
    Text(&'static str, Option<String>),
    /// `enabled`.
    Enabled(Option<bool>),
    /// `displayed_columns` (`Value::Null` is the JSON `null`).
    Columns(Value),
}

/// `update_from_model` then commit: the sent columns and `updated_at`.
pub async fn update_event_source(
    db: &Db,
    id: i64,
    changes: &[EventSourceChange],
    updated_at: NaiveDateTime,
) -> Result<(), DbError> {
    let mut qb = QueryBuilder::<MySql>::new("UPDATE event_sources SET ");
    let mut sep = qb.separated(", ");
    for c in changes {
        match c {
            EventSourceChange::Text(col, v) => {
                sep.push(format!("{col} = "));
                sep.push_bind_unseparated(v.clone());
            }
            EventSourceChange::Enabled(b) => {
                sep.push("enabled = ");
                sep.push_bind_unseparated(*b);
            }
            EventSourceChange::Columns(v) => {
                sep.push("displayed_columns = ");
                sep.push_bind_unseparated(json_text(v));
            }
        }
    }
    sep.push("updated_at = ");
    sep.push_bind_unseparated(mysql_datetime(updated_at));
    qb.push(" WHERE id = ");
    qb.push_bind(id);
    qb.build().execute(db.pool()).await?;
    Ok(())
}

/// `db.delete(event_source)`; a foreign key (an enabled dashboard on it) is
/// MySQL's error.
pub async fn delete_event_source(db: &Db, id: i64) -> Result<(), DbError> {
    sqlx::query("DELETE FROM event_sources WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

// --- enabled_dashboards -------------------------------------------------------------

const NEWEST_FIRST: &str =
    " ORDER BY enabled_dashboards.created_at DESC, enabled_dashboards.id DESC";

/// `get_enabled_dashboards(customer_code)`, newest first.
pub async fn enabled_of(db: &Db, code: &str) -> Result<Vec<EnabledRow>, DbError> {
    Ok(sqlx::query_as::<_, EnabledRow>(&format!(
        "{} WHERE enabled_dashboards.customer_code = ?{NEWEST_FIRST}",
        select("enabled_dashboards", ENABLED_COLUMNS)
    ))
    .bind(code)
    .fetch_all(db.pool())
    .await?)
}

/// `get_enabled_dashboards_for_customers(codes)`: `["*"]`-like (`None`) is
/// every customer; an empty list is SQLAlchemy's empty `IN`, which matches
/// nothing.
pub async fn enabled_for(db: &Db, codes: Option<&[String]>) -> Result<Vec<EnabledRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(select("enabled_dashboards", ENABLED_COLUMNS));
    match codes {
        None => {}
        Some([]) => {
            qb.push(" WHERE enabled_dashboards.customer_code IN (NULL) AND (1 != 1)");
        }
        Some(codes) => {
            qb.push(" WHERE enabled_dashboards.customer_code IN (");
            let mut sep = qb.separated(", ");
            for c in codes {
                sep.push_bind(c.clone());
            }
            qb.push(")");
        }
    }
    qb.push(NEWEST_FIRST);
    Ok(qb
        .build_query_as::<EnabledRow>()
        .fetch_all(db.pool())
        .await?)
}

/// One enabled dashboard.
pub async fn enabled(db: &Db, id: i64) -> Result<Option<EnabledRow>, DbError> {
    Ok(sqlx::query_as::<_, EnabledRow>(&format!(
        "{} WHERE enabled_dashboards.id = ?",
        select("enabled_dashboards", ENABLED_COLUMNS)
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}

/// The duplicate check of `enable_dashboard`.
pub async fn enabled_exists(
    db: &Db,
    code: &str,
    event_source_id: i64,
    library_card: &str,
    template_id: &str,
) -> Result<bool, DbError> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT enabled_dashboards.id FROM enabled_dashboards WHERE \
         enabled_dashboards.customer_code = ? AND enabled_dashboards.event_source_id = ? AND \
         enabled_dashboards.library_card = ? AND enabled_dashboards.template_id = ?",
    )
    .bind(code)
    .bind(event_source_id)
    .bind(library_card)
    .bind(template_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.is_some())
}

/// Insert an enabled dashboard; its id.
pub async fn insert_enabled(
    db: &Db,
    code: &str,
    event_source_id: i64,
    library_card: &str,
    template_id: &str,
    display_name: &str,
    created_at: NaiveDateTime,
) -> Result<i64, DbError> {
    let done = sqlx::query(
        "INSERT INTO enabled_dashboards (customer_code, event_source_id, library_card, \
         template_id, display_name, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(code)
    .bind(event_source_id)
    .bind(library_card)
    .bind(template_id)
    .bind(display_name)
    .bind(mysql_datetime(created_at))
    .execute(db.pool())
    .await?;
    Ok(done.last_insert_id() as i64)
}

/// `db.delete(row)` of one enabled dashboard.
pub async fn delete_enabled(db: &Db, id: i64) -> Result<(), DbError> {
    sqlx::query("DELETE FROM enabled_dashboards WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// How many dashboards are enabled from one custom template.
pub async fn enabled_from_custom(db: &Db, key: &str) -> Result<usize, DbError> {
    let rows: Vec<(i32,)> = sqlx::query_as(
        "SELECT enabled_dashboards.id FROM enabled_dashboards WHERE \
         enabled_dashboards.library_card = 'custom' AND enabled_dashboards.template_id = ?",
    )
    .bind(key)
    .fetch_all(db.pool())
    .await?;
    Ok(rows.len())
}

/// Whether a custom template is enabled for a customer other than `code`.
pub async fn enabled_elsewhere(db: &Db, key: &str, code: &str) -> Result<bool, DbError> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT enabled_dashboards.id FROM enabled_dashboards WHERE \
         enabled_dashboards.library_card = 'custom' AND enabled_dashboards.template_id = ? AND \
         enabled_dashboards.customer_code != ?",
    )
    .bind(key)
    .bind(code)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.is_some())
}

// --- custom_dashboard_templates -----------------------------------------------------

/// `get_custom_template(template_key)`.
pub async fn custom(db: &Db, key: &str) -> Result<Option<CustomRow>, DbError> {
    Ok(sqlx::query_as::<_, CustomRow>(&format!(
        "{} WHERE custom_dashboard_templates.template_key = ?",
        select("custom_dashboard_templates", CUSTOM_COLUMNS)
    ))
    .bind(key)
    .fetch_optional(db.pool())
    .await?)
}

/// One custom template by id (the re-read after a write).
pub async fn custom_by_id(db: &Db, id: i64) -> Result<Option<CustomRow>, DbError> {
    Ok(sqlx::query_as::<_, CustomRow>(&format!(
        "{} WHERE custom_dashboard_templates.id = ?",
        select("custom_dashboard_templates", CUSTOM_COLUMNS)
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}

/// The owner of a custom template (`None`: shared, or no such template).
pub async fn custom_owner(db: &Db, key: &str) -> Result<Option<String>, DbError> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT custom_dashboard_templates.customer_code FROM custom_dashboard_templates WHERE \
         custom_dashboard_templates.template_key = ?",
    )
    .bind(key)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.and_then(|(c,)| c))
}

/// Whether a template key is taken.
pub async fn custom_key_taken(db: &Db, key: &str) -> Result<bool, DbError> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT custom_dashboard_templates.id FROM custom_dashboard_templates WHERE \
         custom_dashboard_templates.template_key = ?",
    )
    .bind(key)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.is_some())
}

/// Which templates `list_custom_dashboards` returns.
#[derive(Debug, Clone)]
pub enum CustomScope {
    /// Every template.
    All,
    /// One customer's and the shared ones.
    Customer(String),
    /// These customers' and the shared ones.
    Customers(Vec<String>),
}

/// `list_custom_dashboards`, ordered by title.
pub async fn custom_list(db: &Db, scope: &CustomScope) -> Result<Vec<CustomRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(select("custom_dashboard_templates", CUSTOM_COLUMNS));
    match scope {
        CustomScope::All => {}
        CustomScope::Customer(code) => {
            qb.push(" WHERE (custom_dashboard_templates.customer_code = ");
            qb.push_bind(code.clone());
            qb.push(" OR custom_dashboard_templates.customer_code IS NULL)");
        }
        CustomScope::Customers(codes) if codes.is_empty() => {
            qb.push(
                " WHERE ((custom_dashboard_templates.customer_code IN (NULL) AND (1 != 1)) OR \
                 custom_dashboard_templates.customer_code IS NULL)",
            );
        }
        CustomScope::Customers(codes) => {
            qb.push(" WHERE (custom_dashboard_templates.customer_code IN (");
            let mut sep = qb.separated(", ");
            for c in codes {
                sep.push_bind(c.clone());
            }
            qb.push(") OR custom_dashboard_templates.customer_code IS NULL)");
        }
    }
    qb.push(" ORDER BY custom_dashboard_templates.title");
    Ok(qb
        .build_query_as::<CustomRow>()
        .fetch_all(db.pool())
        .await?)
}

/// What `create_custom_dashboard` inserts.
#[derive(Debug, Clone)]
pub struct NewCustom<'a> {
    /// `template_key`.
    pub template_key: &'a str,
    /// `customer_code`.
    pub customer_code: Option<&'a str>,
    /// `title`.
    pub title: &'a str,
    /// `description`.
    pub description: &'a str,
    /// `vendor`.
    pub vendor: &'a str,
    /// `product`.
    pub product: &'a str,
    /// `event_type`.
    pub event_type: &'a str,
    /// `tags`.
    pub tags: &'a Value,
    /// `color`.
    pub color: &'a str,
    /// `icon`.
    pub icon: &'a str,
    /// `default_query`.
    pub default_query: &'a str,
    /// `panels`.
    pub panels: &'a Value,
    /// `created_by`.
    pub created_by: Option<&'a str>,
    /// `created_at`.
    pub created_at: NaiveDateTime,
    /// `updated_at`.
    pub updated_at: NaiveDateTime,
}

/// Insert a custom template; its id.
pub async fn insert_custom(db: &Db, row: &NewCustom<'_>) -> Result<i64, DbError> {
    let done = sqlx::query(
        "INSERT INTO custom_dashboard_templates (template_key, customer_code, title, description, \
         vendor, product, event_type, tags, color, icon, default_query, panels, created_by, \
         created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(row.template_key)
    .bind(row.customer_code)
    .bind(row.title)
    .bind(row.description)
    .bind(row.vendor)
    .bind(row.product)
    .bind(row.event_type)
    .bind(json_text(row.tags))
    .bind(row.color)
    .bind(row.icon)
    .bind(row.default_query)
    .bind(json_text(row.panels))
    .bind(row.created_by)
    .bind(mysql_datetime(row.created_at))
    .bind(mysql_datetime(row.updated_at))
    .execute(db.pool())
    .await?;
    Ok(done.last_insert_id() as i64)
}

/// One column change of a custom template update.
#[derive(Debug, Clone)]
pub enum CustomChange {
    /// A text column.
    Text(&'static str, String),
    /// `customer_code` (`None` = shared).
    Customer(Option<String>),
    /// A JSON column (`tags`, `panels`).
    Json(&'static str, Value),
}

/// `update_custom_dashboard`'s flush: the changed columns and `updated_at`.
pub async fn update_custom(
    db: &Db,
    id: i64,
    changes: &[CustomChange],
    updated_at: NaiveDateTime,
) -> Result<(), DbError> {
    let mut qb = QueryBuilder::<MySql>::new("UPDATE custom_dashboard_templates SET ");
    let mut sep = qb.separated(", ");
    for c in changes {
        match c {
            CustomChange::Text(col, v) => {
                sep.push(format!("{col} = "));
                sep.push_bind_unseparated(v.clone());
            }
            CustomChange::Customer(v) => {
                sep.push("customer_code = ");
                sep.push_bind_unseparated(v.clone());
            }
            CustomChange::Json(col, v) => {
                sep.push(format!("{col} = "));
                sep.push_bind_unseparated(json_text(v));
            }
        }
    }
    sep.push("updated_at = ");
    sep.push_bind_unseparated(mysql_datetime(updated_at));
    qb.push(" WHERE id = ");
    qb.push_bind(id);
    qb.build().execute(db.pool()).await?;
    Ok(())
}

/// `delete_custom_dashboard`: the enabled dashboards first, then the
/// template, in one transaction (Python commits once).
pub async fn delete_custom(db: &Db, id: i64, key: &str, with_enabled: bool) -> Result<(), DbError> {
    let mut tx = db.pool().begin().await?;
    if with_enabled {
        sqlx::query(
            "DELETE FROM enabled_dashboards WHERE enabled_dashboards.library_card = 'custom' AND \
             enabled_dashboards.template_id = ?",
        )
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM custom_dashboard_templates WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
