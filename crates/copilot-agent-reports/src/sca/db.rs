//! The `sca_reports` statements, in SQLAlchemy's shapes (declaration-order
//! column lists, Python's filter order), and the `agents.agent_id` lookup of
//! the package-registry route.

use chrono::NaiveDateTime;
use sqlx::{FromRow, MySql, QueryBuilder};

use copilot_db::schema::TableRequirement;
use copilot_db::{Db, DbError};

use crate::agents::push_in;

/// The columns these routes read and write.
pub const REQUIREMENTS: &[TableRequirement] = &[TableRequirement {
    table: "sca_reports",
    columns: &[
        "id",
        "report_name",
        "customer_code",
        "bucket_name",
        "object_key",
        "file_name",
        "file_size",
        "file_hash",
        "generated_at",
        "generated_by",
        "filters_json",
        "total_policies",
        "total_checks",
        "passed_count",
        "failed_count",
        "invalid_count",
        "status",
        "error_message",
    ],
}];

const REPORT_COLS: &str = "sca_reports.id, sca_reports.report_name, sca_reports.customer_code, \
    sca_reports.bucket_name, sca_reports.object_key, sca_reports.file_name, \
    sca_reports.file_size, sca_reports.file_hash, sca_reports.generated_at, \
    sca_reports.generated_by, sca_reports.filters_json, sca_reports.total_policies, \
    sca_reports.total_checks, sca_reports.passed_count, sca_reports.failed_count, \
    sca_reports.invalid_count, sca_reports.status, sca_reports.error_message";

/// One `sca_reports` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ScaReportRow {
    /// Primary key.
    pub id: i32,
    /// Name.
    pub report_name: String,
    /// Tenant.
    pub customer_code: String,
    /// MinIO bucket.
    pub bucket_name: String,
    /// MinIO key.
    pub object_key: String,
    /// File name.
    pub file_name: String,
    /// Size in bytes.
    pub file_size: i32,
    /// SHA-256 (`pending` while generating).
    pub file_hash: String,
    /// When it was generated.
    pub generated_at: NaiveDateTime,
    /// Who generated it.
    pub generated_by: i32,
    /// The filters, as JSON text.
    pub filters_json: Option<String>,
    /// Policy results in it.
    pub total_policies: i32,
    /// Checks.
    pub total_checks: i32,
    /// Passed checks.
    pub passed_count: i32,
    /// Failed checks.
    pub failed_count: i32,
    /// Invalid checks.
    pub invalid_count: i32,
    /// `processing`, `completed`, `failed`.
    pub status: String,
    /// Why it failed.
    pub error_message: Option<String>,
}

/// `select(SCAReport).filter(SCAReport.id == …)` → `.first()`.
pub async fn report(db: &Db, id: i64) -> Result<Option<ScaReportRow>, DbError> {
    let sql = format!("SELECT {REPORT_COLS} \nFROM sca_reports \nWHERE sca_reports.id = ?");
    Ok(sqlx::query_as::<_, ScaReportRow>(&sql)
        .bind(id)
        .fetch_optional(db.pool())
        .await?)
}

/// `list_sca_reports`' select: newest first, the caller's customers, then
/// the requested ones.
pub async fn reports(
    db: &Db,
    accessible: Option<&[String]>,
    requested: Option<&[String]>,
) -> Result<Vec<ScaReportRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT {REPORT_COLS} \nFROM sca_reports"));
    let mut first = true;
    for codes in [accessible, requested].into_iter().flatten() {
        qb.push(if first { " \nWHERE " } else { " AND " });
        first = false;
        push_in(&mut qb, "sca_reports.customer_code", codes);
    }
    qb.push(" ORDER BY sca_reports.generated_at DESC");
    Ok(qb
        .build_query_as::<ScaReportRow>()
        .fetch_all(db.pool())
        .await?)
}

/// A report row as `generate_sca_csv_report` creates it.
#[derive(Debug, Clone)]
pub struct NewScaReport {
    /// Name.
    pub report_name: String,
    /// Tenant.
    pub customer_code: String,
    /// Bucket.
    pub bucket_name: String,
    /// Key.
    pub object_key: String,
    /// File name.
    pub file_name: String,
    /// Size.
    pub file_size: i64,
    /// Hash.
    pub file_hash: String,
    /// `datetime.utcnow()` at construction (MySQL rounds it).
    pub generated_at: NaiveDateTime,
    /// User id.
    pub generated_by: i32,
    /// `json.dumps(filters)`.
    pub filters_json: String,
    /// Totals: policies, checks, passed, failed, invalid.
    pub counts: [i64; 5],
    /// Status.
    pub status: String,
}

/// The ORM's `INSERT` of an `SCAReport` (every column but `id`).
pub const INSERT_REPORT_SQL: &str = "INSERT INTO sca_reports (report_name, customer_code, \
    bucket_name, object_key, file_name, file_size, file_hash, generated_at, generated_by, \
    filters_json, total_policies, total_checks, passed_count, failed_count, invalid_count, \
    status, error_message) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, \
    %s, %s)";

/// `session.add(report_record); commit()`: the new id.
pub async fn insert_report(db: &Db, r: &NewScaReport) -> Result<i64, sqlx::Error> {
    let res = sqlx::query(&INSERT_REPORT_SQL.replace("%s", "?"))
        .bind(&r.report_name)
        .bind(&r.customer_code)
        .bind(&r.bucket_name)
        .bind(&r.object_key)
        .bind(&r.file_name)
        .bind(r.file_size)
        .bind(&r.file_hash)
        .bind(r.generated_at)
        .bind(r.generated_by)
        .bind(&r.filters_json)
        .bind(r.counts[0])
        .bind(r.counts[1])
        .bind(r.counts[2])
        .bind(r.counts[3])
        .bind(r.counts[4])
        .bind(&r.status)
        .bind(None::<String>)
        .execute(db.pool())
        .await?;
    Ok(i64::try_from(res.last_insert_id()).unwrap_or_default())
}

/// `session.delete(report); commit()`.
pub async fn delete_report(db: &Db, id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM sca_reports WHERE sca_reports.id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// `select(Agents.agent_id).where(Agents.customer_code.in_(accessible))`.
pub async fn agent_ids_of(db: &Db, customers: &[String]) -> Result<Vec<String>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new("SELECT agents.agent_id \nFROM agents \nWHERE ");
    push_in(&mut qb, "agents.customer_code", customers);
    Ok(qb
        .build_query_scalar::<String>()
        .fetch_all(db.pool())
        .await?)
}
