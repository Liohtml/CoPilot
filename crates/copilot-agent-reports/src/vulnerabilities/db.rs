//! The `agent_vulnerabilities` and `vulnerability_reports` statements, in
//! SQLAlchemy's shapes (declaration-order column lists, Python's filter order,
//! no `ORDER BY` where Python has none).

use chrono::NaiveDateTime;
use sqlx::{FromRow, MySql, QueryBuilder};

use copilot_db::schema::TableRequirement;
use copilot_db::{Db, DbError};

use crate::agents::push_in;

/// The columns these routes read and write.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "agent_vulnerabilities",
        columns: &[
            "id",
            "cve_id",
            "severity",
            "title",
            "references",
            "status",
            "discovered_at",
            "remediated_at",
            "epss_score",
            "epss_percentile",
            "package_name",
            "agent_id",
            "customer_code",
        ],
    },
    TableRequirement {
        table: "vulnerability_reports",
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
            "total_vulnerabilities",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "status",
            "error_message",
        ],
    },
];

const VULN_COLS: &str = "agent_vulnerabilities.id, agent_vulnerabilities.cve_id, \
    agent_vulnerabilities.severity, agent_vulnerabilities.title, \
    agent_vulnerabilities.`references`, agent_vulnerabilities.status, \
    agent_vulnerabilities.discovered_at, agent_vulnerabilities.remediated_at, \
    agent_vulnerabilities.epss_score, agent_vulnerabilities.epss_percentile, \
    agent_vulnerabilities.package_name, agent_vulnerabilities.agent_id, \
    agent_vulnerabilities.customer_code";

/// One `agent_vulnerabilities` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct VulnRow {
    /// Primary key.
    pub id: i32,
    /// CVE.
    pub cve_id: String,
    /// Severity.
    pub severity: String,
    /// Title (the package name).
    pub title: String,
    /// References.
    pub references: Option<String>,
    /// Status.
    pub status: String,
    /// When Wazuh detected it.
    pub discovered_at: NaiveDateTime,
    /// When it was remediated.
    pub remediated_at: Option<NaiveDateTime>,
    /// EPSS score (the sync stores the CVSS base score here).
    pub epss_score: Option<String>,
    /// EPSS percentile.
    pub epss_percentile: Option<String>,
    /// Package.
    pub package_name: Option<String>,
    /// Wazuh agent id.
    pub agent_id: String,
    /// Tenant.
    pub customer_code: Option<String>,
}

/// `select(AgentVulnerabilities).filter(agent_id == …)
/// [.filter(severity.in_(…))]`, then (Rust) the caller's customers.
pub async fn of_agent(
    db: &Db,
    agent_id: &str,
    severities: Option<&[String]>,
    customers: Option<&[String]>,
) -> Result<Vec<VulnRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {VULN_COLS} \nFROM agent_vulnerabilities \nWHERE agent_vulnerabilities.agent_id = "
    ));
    qb.push_bind(agent_id.to_string());
    if let Some(s) = severities.filter(|s| !s.is_empty()) {
        qb.push(" AND ");
        push_in(&mut qb, "agent_vulnerabilities.severity", s);
    }
    if let Some(codes) = customers {
        qb.push(" AND ");
        push_in(&mut qb, "agent_vulnerabilities.customer_code", codes);
    }
    Ok(qb.build_query_as::<VulnRow>().fetch_all(db.pool()).await?)
}

/// `get_vulnerability_statistics`' select: one customer, else the caller's
/// customers (`None`: every row).
pub async fn for_stats(
    db: &Db,
    customer_code: Option<&str>,
    accessible: Option<&[String]>,
) -> Result<Vec<VulnRow>, DbError> {
    let mut qb =
        QueryBuilder::<MySql>::new(format!("SELECT {VULN_COLS} \nFROM agent_vulnerabilities"));
    if let Some(c) = customer_code {
        qb.push(" \nWHERE agent_vulnerabilities.customer_code = ")
            .push_bind(c.to_string());
    } else if let Some(codes) = accessible {
        qb.push(" \nWHERE ");
        push_in(&mut qb, "agent_vulnerabilities.customer_code", codes);
    }
    Ok(qb.build_query_as::<VulnRow>().fetch_all(db.pool()).await?)
}

/// The rows of one agent (`select(AgentVulnerabilities).filter(agent_id ==
/// …)`), the sync's comparison set.
pub async fn existing(db: &Db, agent_id: &str) -> Result<Vec<VulnRow>, DbError> {
    of_agent(db, agent_id, None, None).await
}

/// What `delete_vulnerabilities` removes.
#[derive(Debug, Clone, Copy)]
pub enum DeleteScope<'a> {
    /// `agent_id == …`.
    Agent(&'a str),
    /// `customer_code == …`.
    Customer(&'a str),
    /// Everything.
    All,
}

/// `delete(AgentVulnerabilities).where(…)`, committed: the row count.
pub async fn delete(db: &Db, scope: DeleteScope<'_>) -> Result<u64, DbError> {
    let res =
        match scope {
            DeleteScope::Agent(a) => {
                sqlx::query(
                    "DELETE FROM agent_vulnerabilities WHERE agent_vulnerabilities.agent_id = ?",
                )
                .bind(a)
                .execute(db.pool())
                .await?
            }
            DeleteScope::Customer(c) => sqlx::query(
                "DELETE FROM agent_vulnerabilities WHERE agent_vulnerabilities.customer_code = ?",
            )
            .bind(c)
            .execute(db.pool())
            .await?,
            DeleteScope::All => {
                sqlx::query("DELETE FROM agent_vulnerabilities")
                    .execute(db.pool())
                    .await?
            }
        };
    Ok(res.rows_affected())
}

/// A row the sync inserts (`AgentVulnerabilities.create_from_model`).
#[derive(Debug, Clone, PartialEq)]
pub struct NewVuln {
    /// CVE.
    pub cve_id: String,
    /// Severity.
    pub severity: String,
    /// Title.
    pub title: String,
    /// References.
    pub references: Option<String>,
    /// `discovered_at` as stored (the wall time, whole seconds).
    pub discovered_at: NaiveDateTime,
    /// `epss_score` (set when a later document of the same batch updated the
    /// object before its insert).
    pub epss_score: Option<String>,
    /// Package.
    pub package_name: Option<String>,
    /// Agent.
    pub agent_id: String,
    /// Tenant.
    pub customer_code: Option<String>,
}

/// One `INSERT` of [`NewVuln`] (`status` `Active`); the new id.
pub async fn insert(conn: &mut sqlx::MySqlConnection, row: &NewVuln) -> Result<i64, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO agent_vulnerabilities (cve_id, severity, title, `references`, status, \
         discovered_at, remediated_at, epss_score, epss_percentile, package_name, agent_id, \
         customer_code) VALUES (?, ?, ?, ?, 'Active', ?, NULL, ?, NULL, ?, ?, ?)",
    )
    .bind(&row.cve_id)
    .bind(&row.severity)
    .bind(&row.title)
    .bind(&row.references)
    .bind(row.discovered_at)
    .bind(&row.epss_score)
    .bind(&row.package_name)
    .bind(&row.agent_id)
    .bind(&row.customer_code)
    .execute(conn)
    .await?;
    Ok(i64::try_from(res.last_insert_id()).unwrap_or_default())
}

/// The columns an update of the sync writes.
#[derive(Debug, Clone, PartialEq)]
pub struct VulnUpdate {
    /// Severity.
    pub severity: String,
    /// Title.
    pub title: String,
    /// References.
    pub references: Option<String>,
    /// `discovered_at` as stored.
    pub discovered_at: NaiveDateTime,
    /// `epss_score`, when it is written.
    pub epss_score: Option<Option<String>>,
    /// Package.
    pub package_name: Option<String>,
}

/// `UPDATE agent_vulnerabilities SET … WHERE id = ?`.
pub async fn update(
    conn: &mut sqlx::MySqlConnection,
    id: i64,
    u: &VulnUpdate,
) -> Result<(), sqlx::Error> {
    let mut qb = QueryBuilder::<MySql>::new("UPDATE agent_vulnerabilities SET severity=");
    qb.push_bind(u.severity.clone())
        .push(", title=")
        .push_bind(u.title.clone())
        .push(", `references`=")
        .push_bind(u.references.clone())
        .push(", discovered_at=")
        .push_bind(u.discovered_at);
    if let Some(epss) = &u.epss_score {
        qb.push(", epss_score=").push_bind(epss.clone());
    }
    qb.push(", package_name=")
        .push_bind(u.package_name.clone())
        .push(" WHERE agent_vulnerabilities.id = ")
        .push_bind(id);
    qb.build().execute(conn).await?;
    Ok(())
}

// --- vulnerability_reports ------------------------------------------------------

const REPORT_COLS: &str = "vulnerability_reports.id, vulnerability_reports.report_name, \
    vulnerability_reports.customer_code, vulnerability_reports.bucket_name, \
    vulnerability_reports.object_key, vulnerability_reports.file_name, \
    vulnerability_reports.file_size, vulnerability_reports.file_hash, \
    vulnerability_reports.generated_at, vulnerability_reports.generated_by, \
    vulnerability_reports.filters_json, vulnerability_reports.total_vulnerabilities, \
    vulnerability_reports.critical_count, vulnerability_reports.high_count, \
    vulnerability_reports.medium_count, vulnerability_reports.low_count, \
    vulnerability_reports.status, vulnerability_reports.error_message";

/// One `vulnerability_reports` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ReportRow {
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
    /// Vulnerabilities in it.
    pub total_vulnerabilities: i32,
    /// Critical ones.
    pub critical_count: i32,
    /// High ones.
    pub high_count: i32,
    /// Medium ones.
    pub medium_count: i32,
    /// Low ones.
    pub low_count: i32,
    /// `processing`, `completed`, `failed`.
    pub status: String,
    /// Why it failed.
    pub error_message: Option<String>,
}

/// `select(VulnerabilityReport).filter(id == …)` → `.first()`.
pub async fn report(db: &Db, id: i64) -> Result<Option<ReportRow>, DbError> {
    let sql = format!(
        "SELECT {REPORT_COLS} \nFROM vulnerability_reports \nWHERE vulnerability_reports.id = ?"
    );
    Ok(sqlx::query_as::<_, ReportRow>(&sql)
        .bind(id)
        .fetch_optional(db.pool())
        .await?)
}

/// `list_vulnerability_reports`' select: newest first, the caller's
/// customers, then the requested ones.
pub async fn reports(
    db: &Db,
    accessible: Option<&[String]>,
    requested: Option<&[String]>,
) -> Result<Vec<ReportRow>, DbError> {
    let mut qb =
        QueryBuilder::<MySql>::new(format!("SELECT {REPORT_COLS} \nFROM vulnerability_reports"));
    let mut first = true;
    for codes in [accessible, requested].into_iter().flatten() {
        qb.push(if first { " \nWHERE " } else { " AND " });
        first = false;
        push_in(&mut qb, "vulnerability_reports.customer_code", codes);
    }
    qb.push(" ORDER BY vulnerability_reports.generated_at DESC");
    Ok(qb
        .build_query_as::<ReportRow>()
        .fetch_all(db.pool())
        .await?)
}

/// A report row as the services create it.
#[derive(Debug, Clone)]
pub struct NewReport {
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
    /// Totals: all, critical, high, medium, low.
    pub counts: [i64; 5],
    /// Status.
    pub status: String,
}

/// The ORM's `INSERT` of a `VulnerabilityReport` (every column but `id`).
pub const INSERT_REPORT_SQL: &str = "INSERT INTO vulnerability_reports (report_name, \
    customer_code, bucket_name, object_key, file_name, file_size, file_hash, generated_at, \
    generated_by, filters_json, total_vulnerabilities, critical_count, high_count, medium_count, \
    low_count, status, error_message) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, \
    %s, %s, %s, %s)";

/// `session.add(report); commit()`: the new id.
pub async fn insert_report(db: &Db, r: &NewReport) -> Result<i64, sqlx::Error> {
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

/// `report.status = "failed"; report.error_message = …; commit()`.
pub async fn mark_failed(db: &Db, id: i64, message: &str) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE vulnerability_reports SET status=?, error_message=? WHERE \
         vulnerability_reports.id = ?",
    )
    .bind("failed")
    .bind(message)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// The completed background report's update.
pub async fn complete(
    db: &Db,
    id: i64,
    file_size: i64,
    file_hash: &str,
    counts: [i64; 5],
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE vulnerability_reports SET file_size=?, file_hash=?, total_vulnerabilities=?, \
         critical_count=?, high_count=?, medium_count=?, low_count=?, status=?, \
         error_message=? WHERE vulnerability_reports.id = ?",
    )
    .bind(file_size)
    .bind(file_hash)
    .bind(counts[0])
    .bind(counts[1])
    .bind(counts[2])
    .bind(counts[3])
    .bind(counts[4])
    .bind("completed")
    .bind(None::<String>)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// `session.delete(report); commit()`.
pub async fn delete_report(db: &Db, id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM vulnerability_reports WHERE vulnerability_reports.id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// `select(Customers).filter(customer_code == …)` → exists.
pub async fn customer_exists(db: &Db, code: &str) -> Result<bool, DbError> {
    let n: Option<String> = sqlx::query_scalar(
        "SELECT customers.customer_code FROM customers WHERE customers.customer_code = ?",
    )
    .bind(code)
    .fetch_optional(db.pool())
    .await?;
    Ok(n.is_some())
}
