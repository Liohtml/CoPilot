//! Case files and report templates — the database half of the case data
//! store (`list_all_files`, `list_files_by_case_id`, `report_template_exists`).
//! The bytes live in MinIO; those routes stay in Python for now.

use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::{FromRow, MySql, QueryBuilder};

use copilot_auth::AccessScope;
use copilot_core::time::pydantic;
use copilot_db::{Db, DbError};

use crate::store::{FILE_COLS, push_list};

/// `DefaultReportTemplateFileNames.CASE_REPORT_JINJA_TEMPLATE`.
pub const DEFAULT_REPORT_TEMPLATE: &str = "case_report_jinja_template.docx";

/// `CaseDataStore` (the SQLModel row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, FromRow)]
pub struct CaseFile {
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
    #[serde(serialize_with = "pydantic::datetime")]
    pub upload_time: NaiveDateTime,
    /// SHA-256.
    pub file_hash: String,
}

/// `list_all_files` — narrowed to the caller's customers (Python listed
/// every tenant's files to any analyst).
pub async fn list_all(db: &Db, access: &AccessScope) -> Result<Vec<CaseFile>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {FILE_COLS} FROM incident_management_case_datastore"
    ));
    match access {
        AccessScope::All => {}
        AccessScope::Customers(codes) if codes.is_empty() => return Ok(Vec::new()),
        AccessScope::Customers(codes) => {
            qb.push(
                " WHERE case_id IN (SELECT c.id FROM incident_management_case c \
                 WHERE c.customer_code IN (",
            );
            push_list(&mut qb, codes.iter().map(String::as_str));
            qb.push(")) ORDER BY id");
        }
    }
    Ok(qb.build_query_as::<CaseFile>().fetch_all(db.pool()).await?)
}

/// `list_files_by_case_id`.
pub async fn list_by_case(db: &Db, case_id: i64) -> Result<Vec<CaseFile>, DbError> {
    let sql =
        format!("SELECT {FILE_COLS} FROM incident_management_case_datastore WHERE case_id = ?");
    Ok(sqlx::query_as::<_, CaseFile>(&sql)
        .bind(case_id)
        .fetch_all(db.pool())
        .await?)
}

/// `report_template_exists`.
pub async fn report_template_exists(db: &Db, name: &str) -> Result<bool, DbError> {
    let found = sqlx::query_scalar::<_, i32>(
        "SELECT id FROM incident_management_case_report_template_datastore \
         WHERE report_template_name = ?",
    )
    .bind(name)
    .fetch_all(db.pool())
    .await?;
    Ok(!found.is_empty())
}
