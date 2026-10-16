//! The MinIO half of the case data store and the customer report files —
//! `services/db_operations.py` (`upload_file_to_case`, `delete_file_from_case`,
//! `download_file_from_case`, the report-template trio, `delete_case`) and
//! `services/customer_report.py` (`get_customer_report_download`,
//! `delete_customer_report`), in Python's order of database and object-store
//! steps.

use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::FromRow;

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_core::time::{now_utc_micros, pydantic};
use copilot_db::{Db, DbError};
use copilot_objectstore::{ObjectStore, PyExc, ops};

use crate::files::CaseFile;

/// `CaseReportTemplateDataStore` (the SQLModel row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, FromRow)]
pub struct TemplateFile {
    /// Id.
    pub id: i32,
    /// `report_template_name`.
    pub report_template_name: String,
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

/// The columns of `incident_management_customer_reports` the file routes
/// read.
#[derive(Debug, Clone, FromRow)]
pub struct ReportFile {
    /// Id.
    pub id: i32,
    /// `report_name`.
    pub report_name: String,
    /// Owner.
    pub customer_code: String,
    /// Bucket.
    pub bucket_name: String,
    /// Key.
    pub object_key: String,
    /// File name.
    pub file_name: String,
    /// Who generated it.
    pub generated_by: i32,
    /// Their role name.
    pub generated_by_role: Option<String>,
    /// Shown in the portal.
    pub visible_to_customer: bool,
    /// `pending` / `completed` / `failed`.
    pub status: String,
}

const FILE_SELECT: &str = "SELECT incident_management_case_datastore.id, \
    incident_management_case_datastore.case_id, incident_management_case_datastore.bucket_name, \
    incident_management_case_datastore.object_key, incident_management_case_datastore.file_name, \
    incident_management_case_datastore.content_type, incident_management_case_datastore.file_size, \
    incident_management_case_datastore.upload_time, incident_management_case_datastore.file_hash \
    \nFROM incident_management_case_datastore \nWHERE incident_management_case_datastore.case_id = ?";

const TEMPLATE_SELECT: &str = "SELECT incident_management_case_report_template_datastore.id, \
    incident_management_case_report_template_datastore.report_template_name, \
    incident_management_case_report_template_datastore.bucket_name, \
    incident_management_case_report_template_datastore.object_key, \
    incident_management_case_report_template_datastore.file_name, \
    incident_management_case_report_template_datastore.content_type, \
    incident_management_case_report_template_datastore.file_size, \
    incident_management_case_report_template_datastore.upload_time, \
    incident_management_case_report_template_datastore.file_hash \
    \nFROM incident_management_case_report_template_datastore \
    \nWHERE incident_management_case_report_template_datastore.report_template_name = ?";

/// `get_file_by_case_id_and_name` (MySQL's collation compares the name).
pub async fn file_by_name(
    db: &Db,
    case_id: i64,
    file_name: &str,
) -> Result<Option<CaseFile>, DbError> {
    let sql = format!("{FILE_SELECT} AND incident_management_case_datastore.file_name = ?");
    Ok(sqlx::query_as::<_, CaseFile>(&sql)
        .bind(case_id)
        .bind(file_name)
        .fetch_optional(db.pool())
        .await?)
}

/// `get_report_template_by_name`.
pub async fn template_by_name(db: &Db, name: &str) -> Result<Option<TemplateFile>, DbError> {
    Ok(sqlx::query_as::<_, TemplateFile>(TEMPLATE_SELECT)
        .bind(name)
        .fetch_optional(db.pool())
        .await?)
}

/// `_require_report`'s row.
pub async fn report(db: &Db, id: i64) -> Result<Option<ReportFile>, DbError> {
    Ok(sqlx::query_as::<_, ReportFile>(
        "SELECT id, report_name, customer_code, bucket_name, object_key, file_name, \
         generated_by, generated_by_role, visible_to_customer, status \
         FROM incident_management_customer_reports WHERE incident_management_customer_reports.id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}

/// A string field over `max_length` (`string_too_long`).
fn too_long(field: &str, value: &str, max: usize) -> Option<copilot_upstream::model::PyError> {
    (value.chars().count() > max).then(|| copilot_upstream::model::PyError {
        loc: vec![copilot_upstream::model::Loc::Key(field.into())],
        kind: "string_too_long",
        msg: format!("String should have at most {max} characters"),
        input: PyValue::Str(value.to_string()),
    })
}

/// `CaseDataStoreCreation(...)` / `CaseReportTemplateDataStoreCreation(...)`:
/// the length limits, as the `ValidationError` (a `ValueError`) Pydantic
/// raises.
fn validate_creation(title: &str, fields: &[(&str, Option<&str>, usize)]) -> Result<(), PyExc> {
    let errors: Vec<_> = fields
        .iter()
        .filter_map(|(name, value, max)| value.and_then(|v| too_long(name, v, *max)))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(PyExc::Validation(
            copilot_upstream::model::format_validation_error(title, &errors),
        ))
    }
}

/// A row the ORM has just inserted, as the response model writes it: the
/// fields the constructor was given in their declaration order, then the
/// two it defaulted (`id`, `upload_time`).
pub fn created_case_file(f: &CaseFile) -> serde_json::Value {
    serde_json::json!({
        "case_id": f.case_id,
        "bucket_name": f.bucket_name,
        "object_key": f.object_key,
        "file_name": f.file_name,
        "content_type": f.content_type,
        "file_size": f.file_size,
        "file_hash": f.file_hash,
        "id": f.id,
        "upload_time": copilot_core::time::to_pydantic_iso(f.upload_time),
    })
}

/// [`created_case_file`] for a report template.
pub fn created_template(f: &TemplateFile) -> serde_json::Value {
    serde_json::json!({
        "report_template_name": f.report_template_name,
        "bucket_name": f.bucket_name,
        "object_key": f.object_key,
        "file_name": f.file_name,
        "content_type": f.content_type,
        "file_size": f.file_size,
        "file_hash": f.file_hash,
        "id": f.id,
        "upload_time": copilot_core::time::to_pydantic_iso(f.upload_time),
    })
}

/// `hashlib.sha256(content).hexdigest()`.
pub fn sha256(data: &[u8]) -> String {
    copilot_objectstore::sigv4::sha256_hex(data)
}

/// `upload_file_to_case`: the upload model checked, the object stored as
/// `{case_id}/{file_name}` in `copilot-cases`, then the row (`add_file_to_db`,
/// committed). The answer is what the ORM holds: `upload_time` with its
/// microseconds.
pub async fn upload_file_to_case(
    db: &Db,
    store: &ObjectStore,
    case_id: i64,
    file_name: &str,
    content_type: Option<&str>,
    data: &[u8],
) -> Result<CaseFile, PyExc> {
    let file_hash = sha256(data);
    validate_creation(
        "CaseDataStoreCreation",
        &[
            ("bucket_name", Some(ops::CASES_BUCKET), 255),
            ("object_key", Some(file_name), 1024),
            ("file_name", Some(file_name), 255),
            ("content_type", content_type, 100),
            ("file_hash", Some(&file_hash), 128),
        ],
    )?;
    ops::upload_case_data_store(store, case_id, file_name, content_type, data).await?;
    let upload_time = now_utc_micros();
    let object_key = format!("{case_id}/{file_name}");
    let file_size = i32::try_from(data.len()).unwrap_or(i32::MAX);
    let id = sqlx::query(
        "INSERT INTO incident_management_case_datastore (case_id, bucket_name, object_key, \
         file_name, content_type, file_size, upload_time, file_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(case_id)
    .bind(ops::CASES_BUCKET)
    .bind(&object_key)
    .bind(file_name)
    .bind(content_type)
    .bind(file_size)
    .bind(upload_time)
    .bind(&file_hash)
    .execute(db.pool())
    .await
    .map_err(|e| sqlalchemy_error(&e, "INSERT INTO incident_management_case_datastore", ""))?
    .last_insert_id();
    Ok(CaseFile {
        id: i32::try_from(id).unwrap_or_default(),
        case_id: i32::try_from(case_id).unwrap_or_default(),
        bucket_name: ops::CASES_BUCKET.into(),
        object_key,
        file_name: file_name.into(),
        content_type: content_type.map(str::to_string),
        file_size: Some(file_size),
        upload_time,
        file_hash,
    })
}

/// `upload_report_template`: the model checked, the object stored under its
/// file name in `copilot-case-report-templates`, then the row.
pub async fn upload_report_template(
    db: &Db,
    store: &ObjectStore,
    file_name: &str,
    content_type: Option<&str>,
    data: &[u8],
) -> Result<TemplateFile, PyExc> {
    let file_hash = sha256(data);
    validate_creation(
        "CaseReportTemplateDataStoreCreation",
        &[
            ("report_template_name", Some(file_name), 255),
            ("bucket_name", Some(ops::REPORT_TEMPLATES_BUCKET), 255),
            ("object_key", Some(file_name), 1024),
            ("file_name", Some(file_name), 255),
            ("content_type", content_type, 100),
            ("file_hash", Some(&file_hash), 128),
        ],
    )?;
    ops::upload_case_report_template_data_store(store, file_name, content_type, data).await?;
    let upload_time = now_utc_micros();
    let file_size = i32::try_from(data.len()).unwrap_or(i32::MAX);
    let id = sqlx::query(
        "INSERT INTO incident_management_case_report_template_datastore (report_template_name, \
         bucket_name, object_key, file_name, content_type, file_size, upload_time, file_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(file_name)
    .bind(ops::REPORT_TEMPLATES_BUCKET)
    .bind(file_name)
    .bind(file_name)
    .bind(content_type)
    .bind(file_size)
    .bind(upload_time)
    .bind(&file_hash)
    .execute(db.pool())
    .await
    .map_err(|e| {
        sqlalchemy_error(
            &e,
            "INSERT INTO incident_management_case_report_template_datastore",
            "",
        )
    })?
    .last_insert_id();
    Ok(TemplateFile {
        id: i32::try_from(id).unwrap_or_default(),
        report_template_name: file_name.into(),
        bucket_name: ops::REPORT_TEMPLATES_BUCKET.into(),
        object_key: file_name.into(),
        file_name: file_name.into(),
        content_type: content_type.map(str::to_string),
        file_size: Some(file_size),
        upload_time,
        file_hash,
    })
}

/// `remove_file_from_db` / `remove_report_template_from_db` / the report's
/// `session.delete` — one statement, committed.
pub async fn delete_row(db: &Db, table: &str, id: i32) -> Result<(), PyExc> {
    let sql = format!("DELETE FROM {table} WHERE {table}.id = ?");
    sqlx::query(&sql)
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(|e| sqlalchemy_error(&e, &sql.replace('?', "%s"), &format!("({id},)")))?;
    Ok(())
}

/// The `str()` of the `sqlalchemy.exc.DBAPIError` aiomysql's error becomes:
/// `({class}) ({code}, '{message}')\n[SQL: …]\n[parameters: …]\n(Background
/// on this error at: …)`.
pub fn sqlalchemy_error(e: &sqlx::Error, sql: &str, parameters: &str) -> PyExc {
    let Some(db) = e.as_database_error() else {
        return PyExc::Other("OperationalError", e.to_string());
    };
    let (number, message) = match db.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>() {
        Some(m) => (m.number(), m.message().to_string()),
        None => (0, db.message().to_string()),
    };
    let (class, code) = match number {
        1022 | 1048 | 1062 | 1169 | 1216 | 1217 | 1451 | 1452 | 1557 | 1586 | 1761 | 1762
        | 1859 => ("IntegrityError", "gkpj"),
        1054 | 1064 | 1146 | 1149 => ("ProgrammingError", "f405"),
        1264 | 1265 | 1292 | 1366 | 1406 => ("DataError", "9h9h"),
        _ => ("OperationalError", "e3q8"),
    };
    let mut text = format!(
        "(pymysql.err.{class}) ({number}, {})\n[SQL: {sql}]",
        str_repr(&message)
    );
    if !parameters.is_empty() {
        text.push_str(&format!("\n[parameters: {parameters}]"));
    }
    text.push_str(&format!(
        "\n(Background on this error at: https://sqlalche.me/e/20/{code})"
    ));
    PyExc::Other("DBAPIError", text)
}

const CASE_DELETES: [&str; 4] = [
    "incident_management_case_comment",
    "incident_management_casealertlink",
    "incident_management_case_task",
    "incident_management_case_event",
];

/// `delete_case`: comments, alert links, tasks and timeline events deleted,
/// then each file — from MinIO first, its row deleted **and committed** when
/// that worked (so the deletes so far are committed with it), a failure only
/// logged — then the case itself and the final commit. A database error rolls
/// back what is not yet committed and is the 500 `Failed to delete case: …`
/// (a file whose object could not be removed keeps its row, and its foreign
/// key then fails the case's delete).
pub async fn delete_case(db: &Db, store: &ObjectStore, case_id: i64) -> Result<(), PyExc> {
    let failed = |e: PyExc| PyExc::http(500, format!("Failed to delete case: {}", e.text()));
    let mut tx = db
        .pool()
        .begin()
        .await
        .map_err(|e| failed(PyExc::Other("OperationalError", e.to_string())))?;
    for table in CASE_DELETES {
        tracing::info!("Deleting {table} rows for case {case_id}");
        let sql = format!("DELETE FROM {table} WHERE {table}.case_id = ?");
        if let Err(e) = sqlx::query(&sql).bind(case_id).execute(&mut *tx).await {
            let _ = tx.rollback().await;
            return Err(failed(sqlalchemy_error(
                &e,
                &sql.replace('?', "%s"),
                &format!("({case_id},)"),
            )));
        }
    }
    tracing::info!("Deleting data store files for case {case_id}");
    let files = match sqlx::query_as::<_, CaseFile>(FILE_SELECT)
        .bind(case_id)
        .fetch_all(&mut *tx)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(failed(sqlalchemy_error(
                &e,
                &FILE_SELECT.replace('?', "%s"),
                &format!("({case_id},)"),
            )));
        }
    };
    for listed in files {
        // `delete_file_from_case(case_id, file.file_name, db)`.
        let sql = format!("{FILE_SELECT} AND incident_management_case_datastore.file_name = ?");
        let row = match sqlx::query_as::<_, CaseFile>(&sql)
            .bind(case_id)
            .bind(&listed.file_name)
            .fetch_optional(&mut *tx)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.rollback().await;
                return Err(failed(sqlalchemy_error(
                    &e,
                    &sql.replace('?', "%s"),
                    &format!("({case_id}, {})", str_repr(&listed.file_name)),
                )));
            }
        };
        let Some(row) = row else {
            tracing::warn!(
                "Failed to delete file {} from case {case_id}: 404: File not found",
                listed.file_name
            );
            continue;
        };
        if let Err(e) = ops::delete_file(store, &row.bucket_name, &row.object_key).await {
            tracing::warn!(
                "Failed to delete file {} from case {case_id}: {}",
                listed.file_name,
                e.display()
            );
            continue;
        }
        let sql = "DELETE FROM incident_management_case_datastore WHERE \
                   incident_management_case_datastore.id = ?";
        if let Err(e) = sqlx::query(sql).bind(row.id).execute(&mut *tx).await {
            let _ = tx.rollback().await;
            return Err(failed(sqlalchemy_error(
                &e,
                &sql.replace('?', "%s"),
                &format!("({},)", row.id),
            )));
        }
        // `remove_file_from_db` commits, and a new transaction begins.
        if let Err(e) = tx.commit().await {
            return Err(failed(PyExc::Other("OperationalError", e.to_string())));
        }
        tx = db
            .pool()
            .begin()
            .await
            .map_err(|e| failed(PyExc::Other("OperationalError", e.to_string())))?;
    }
    tracing::info!("Deleting case {case_id}");
    let sql = "DELETE FROM incident_management_case WHERE incident_management_case.id = ?";
    if let Err(e) = sqlx::query(sql).bind(case_id).execute(&mut *tx).await {
        let _ = tx.rollback().await;
        return Err(failed(sqlalchemy_error(
            &e,
            &sql.replace('?', "%s"),
            &format!("({case_id},)"),
        )));
    }
    tx.commit()
        .await
        .map_err(|e| failed(PyExc::Other("OperationalError", e.to_string())))?;
    tracing::info!("Successfully deleted case {case_id} and all related records");
    Ok(())
}

/// `os.path.splitext(name)[1].lower()`.
pub fn extension(name: &str) -> String {
    let sep = name.rfind('/');
    let Some(dot) = name.rfind('.') else {
        return String::new();
    };
    let start = sep.map_or(0, |s| s + 1);
    if sep.is_some_and(|s| dot < s) {
        return String::new();
    }
    // Leading dots of the file name are not an extension.
    if name[start..dot].chars().all(|c| c == '.') {
        return String::new();
    }
    name[dot..].to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_split_like_posixpath() {
        assert_eq!(extension("a.DOCX"), ".docx");
        assert_eq!(extension("x.tar.html"), ".html");
        assert_eq!(extension(".docx"), "");
        assert_eq!(extension("..docx"), "");
        assert_eq!(extension("dir.d/file"), "");
        assert_eq!(extension("dir/.docx"), "");
        assert_eq!(extension("noext"), "");
        assert_eq!(extension("a."), ".");
    }

    #[test]
    fn creation_limits_read_like_pydantic() {
        let long = "a".repeat(256);
        let e = validate_creation(
            "CaseDataStoreCreation",
            &[
                ("object_key", Some(&long), 1024),
                ("file_name", Some(&long), 255),
            ],
        )
        .unwrap_err();
        assert_eq!(
            e.text(),
            "1 validation error for CaseDataStoreCreation\nfile_name\n  String should have at \
             most 255 characters [type=string_too_long, input_value='aaaaaaaaaaaaaaaaaaaaaaaa\
             ...aaaaaaaaaaaaaaaaaaaaaaa', input_type=str]\n    For further information visit \
             https://errors.pydantic.dev/2.13/v/string_too_long"
        );
        assert!(e.is_value_error());
    }
}
