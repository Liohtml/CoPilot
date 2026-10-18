//! Per-customer settings rows and the ingest field dictionaries —
//! `get_customer_ai_trigger`, `get_customer_notification`, the
//! `incident_management_*fieldname` reads and `get_alert_context_by_id`.

use serde::Serialize;
use serde_json::Value;
use sqlx::FromRow;

use copilot_db::{Db, DbError};
use copilot_web::{ApiError, AppContext};

/// `SocfortressRecommendsWazuhFieldNames`, in declaration order.
pub const RECOMMENDED_FIELD_NAMES: &[&str] = &[
    "data_win_eventdata_commandLine",
    "data_win_eventdata_parentCommandLine",
    "data_win_eventdata_parentImage",
    "data_win_eventdata_parentUser",
    "data_win_eventdata_image",
    "data_win_eventdata_user",
    "rule_mitre_id",
    "rule_mitre_tactic",
    "rule_mitre_technique",
    "data_win_eventdata_company",
    "data_win_eventdata_hashes",
    "data_win_eventdata_currentDirectory",
    "data_win_eventdata_originalFileName",
    "data_Path",
    "process_id",
    "sha256",
];

/// `check_customer_exists`: 404 unless the customer row exists.
pub async fn ensure_customer_exists(ctx: &AppContext, code: &str) -> Result<(), ApiError> {
    if copilot_db::alerts::customer_exists(&ctx.db, code).await? {
        return Ok(());
    }
    Err(ApiError::not_found(format!(
        "Customer: {code} not found. Please create the customer first."
    )))
}

/// `AITrigger`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, FromRow)]
pub struct AiTrigger {
    /// Id.
    pub id: i32,
    /// Tenant.
    pub customer_code: String,
    /// Auto-trigger on.
    pub enabled: bool,
}

/// `get_customer_ai_trigger`: the first row, as a list.
pub async fn ai_trigger(db: &Db, code: &str) -> Result<Vec<AiTrigger>, DbError> {
    let rows = sqlx::query_as::<_, AiTrigger>(
        "SELECT id, customer_code, enabled FROM incident_management_ai_analyst_trigger_enabled \
         WHERE customer_code = ?",
    )
    .bind(code)
    .fetch_all(db.pool())
    .await?;
    Ok(rows.into_iter().take(1).collect())
}

/// `Notification` (the response model).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, FromRow)]
pub struct NotificationRow {
    /// Id.
    pub id: i32,
    /// Tenant.
    pub customer_code: String,
    /// Shuffle workflow.
    pub shuffle_workflow_id: String,
    /// On.
    pub enabled: bool,
}

/// `get_customer_notification`: the first row, as a list.
pub async fn notification(db: &Db, code: &str) -> Result<Vec<NotificationRow>, DbError> {
    let rows = sqlx::query_as::<_, NotificationRow>(
        "SELECT id, customer_code, shuffle_workflow_id, enabled \
         FROM incident_management_notification WHERE customer_code = ?",
    )
    .bind(code)
    .fetch_all(db.pool())
    .await?;
    Ok(rows.into_iter().take(1).collect())
}

/// `select(FieldName.source).distinct()`.
pub async fn configured_sources(db: &Db) -> Result<Vec<String>, DbError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT incident_management_fieldname.source FROM incident_management_fieldname",
    )
    .fetch_all(db.pool())
    .await?)
}

/// The dictionary tables, by the name `get_*_names` reads.
#[derive(Debug, Clone, Copy)]
pub enum FieldTable {
    /// `incident_management_fieldname`.
    Field,
    /// `incident_management_assetfieldname`.
    Asset,
    /// `incident_management_timestampfieldname`.
    Timestamp,
    /// `incident_management_alerttitlefieldname`.
    AlertTitle,
    /// `incident_management_iocfieldname`.
    Ioc,
}

impl FieldTable {
    /// Table name.
    pub const fn table(self) -> &'static str {
        match self {
            FieldTable::Field => "incident_management_fieldname",
            FieldTable::Asset => "incident_management_assetfieldname",
            FieldTable::Timestamp => "incident_management_timestampfieldname",
            FieldTable::AlertTitle => "incident_management_alerttitlefieldname",
            FieldTable::Ioc => "incident_management_iocfieldname",
        }
    }
}

/// `SELECT DISTINCT field_name FROM <table> WHERE source = ?`.
pub async fn field_names(db: &Db, table: FieldTable, source: &str) -> Result<Vec<String>, DbError> {
    let t = table.table();
    let sql = format!("SELECT DISTINCT {t}.field_name FROM {t} WHERE {t}.source = ?");
    Ok(sqlx::query_scalar::<_, String>(&sql)
        .bind(source)
        .fetch_all(db.pool())
        .await?)
}

/// What `/fields-assets-title-and-timefield` reports for a source.
#[derive(Debug, Clone, Default)]
pub struct SourceNames {
    /// `get_field_names`.
    pub field_names: Vec<String>,
    /// `get_asset_names` (first).
    pub asset_name: Option<String>,
    /// `get_timefield_names` (first).
    pub timefield_name: Option<String>,
    /// `get_alert_title_names` (first).
    pub alert_title_name: Option<String>,
    /// `get_ioc_names`.
    pub ioc_field_names: Vec<String>,
}

impl SourceNames {
    /// `validate_source_exists`: every table but the IoC one needs a value.
    pub fn validate(&self) -> Result<(), ApiError> {
        let blank = |s: &Option<String>| s.as_deref().is_none_or(str::is_empty);
        if self.field_names.is_empty()
            || blank(&self.asset_name)
            || blank(&self.timefield_name)
            || blank(&self.alert_title_name)
        {
            return Err(ApiError::bad_request("Source does not exist"));
        }
        Ok(())
    }
}

/// Every dictionary entry of a source.
pub async fn source_names(db: &Db, source: &str) -> Result<SourceNames, DbError> {
    let first = |v: Vec<String>| v.into_iter().next();
    Ok(SourceNames {
        field_names: field_names(db, FieldTable::Field, source).await?,
        asset_name: first(field_names(db, FieldTable::Asset, source).await?),
        timefield_name: first(field_names(db, FieldTable::Timestamp, source).await?),
        alert_title_name: first(field_names(db, FieldTable::AlertTitle, source).await?),
        ioc_field_names: field_names(db, FieldTable::Ioc, source).await?,
    })
}

/// `AlertContext` (the SQLModel row).
#[derive(Debug, Clone, PartialEq, Serialize, FromRow)]
pub struct AlertContextRow {
    /// Id.
    pub id: i32,
    /// Source.
    pub source: String,
    /// The event (JSON).
    pub context: Option<Value>,
}

/// `get_alert_context_by_id`'s row.
pub async fn alert_context(db: &Db, id: i64) -> Result<Option<AlertContextRow>, DbError> {
    Ok(sqlx::query_as::<_, AlertContextRow>(
        "SELECT id, source, context FROM incident_management_alertcontext WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}

/// The tenant of an alert context: the customer of the alert its first
/// asset belongs to.
pub async fn alert_context_owner(db: &Db, id: i64) -> Result<Option<String>, DbError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT a.customer_code FROM incident_management_asset s \
         JOIN incident_management_alert a ON a.id = s.alert_linked \
         WHERE s.alert_context_id = ? ORDER BY s.id LIMIT 1",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}
