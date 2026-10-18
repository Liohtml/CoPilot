//! The four tables of `app/integrations/github_audit/model.py` and the
//! statements the routes issue, in SQLAlchemy's shapes (the columns in the
//! table's order, the same `WHERE` and `ORDER BY`), so MySQL picks the same
//! plan and lists rows in the same order.
//!
//! What a row reads back is what the Python side reads: `FLOAT` columns and
//! `JSON` columns go through the text protocol in aiomysql, so they are
//! selected as `CAST(… AS CHAR)` here — MySQL's six significant digits for a
//! `FLOAT` (`72.3`, `0.333333`), its normalised JSON text (keys sorted by
//! length, then bytes) — and read back as `float()` / `json.loads` read them.

use chrono::NaiveDateTime;
use copilot_auth::pyvalue::{PyValue, loads};
use copilot_db::{Db, DbError};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};

// --- shared readers ---------------------------------------------------------------------

fn float_col(row: &MySqlRow, col: &str) -> Result<Option<f64>, sqlx::Error> {
    let text: Option<String> = row.try_get(col)?;
    Ok(text.and_then(|t| t.trim().parse::<f64>().ok()))
}

fn json_col(row: &MySqlRow, col: &str) -> Result<Option<PyValue>, sqlx::Error> {
    let text: Option<String> = row.try_get(col)?;
    Ok(text.map(|t| loads(&t).unwrap_or(PyValue::None)))
}

/// A naive `datetime` as Pydantic writes it in JSON mode.
pub fn iso(t: &NaiveDateTime) -> String {
    let base = t.format("%Y-%m-%dT%H:%M:%S").to_string();
    let micros = t.and_utc().timestamp_subsec_micros();
    if micros == 0 {
        base
    } else {
        format!("{base}.{micros:06}")
    }
}

fn time(t: Option<&NaiveDateTime>) -> PyValue {
    t.map_or(PyValue::None, |t| PyValue::Str(iso(t)))
}

fn text(s: Option<&str>) -> PyValue {
    s.map_or(PyValue::None, |s| PyValue::Str(s.to_string()))
}

fn float(f: Option<f64>) -> PyValue {
    f.map_or(PyValue::None, PyValue::Float)
}

fn int(i: i32) -> PyValue {
    PyValue::Int(i.to_string())
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// `datetime.utcnow()`: what a `default_factory` stamps (MySQL rounds it to
/// the second).
pub fn utcnow() -> NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

fn in_list(qb: &mut QueryBuilder<'_, MySql>, column: &str, codes: &[String]) {
    qb.push(format!("{column} IN ("));
    let mut sep = qb.separated(", ");
    for c in codes {
        sep.push_bind(c.clone());
    }
    qb.push(")");
}

// --- github_audit_config ----------------------------------------------------------------

/// One `github_audit_config` row.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigRow {
    /// `id`.
    pub id: i32,
    /// `customer_code`.
    pub customer_code: String,
    /// `github_token` (stored as given).
    pub github_token: String,
    /// `organization`.
    pub organization: String,
    /// `token_type`.
    pub token_type: String,
    /// `token_expires_at`.
    pub token_expires_at: Option<NaiveDateTime>,
    /// `enabled`.
    pub enabled: bool,
    /// `auto_audit_enabled`.
    pub auto_audit_enabled: bool,
    /// `audit_schedule_cron`.
    pub audit_schedule_cron: Option<String>,
    /// `include_repos`.
    pub include_repos: bool,
    /// `include_workflows`.
    pub include_workflows: bool,
    /// `include_members`.
    pub include_members: bool,
    /// `include_archived_repos`.
    pub include_archived_repos: bool,
    /// `repo_filter_mode`.
    pub repo_filter_mode: String,
    /// `repo_filter_list` (whatever the JSON column holds).
    pub repo_filter_list: Option<PyValue>,
    /// `notify_on_critical`.
    pub notify_on_critical: bool,
    /// `notify_on_high`.
    pub notify_on_high: bool,
    /// `notification_webhook_url`.
    pub notification_webhook_url: Option<String>,
    /// `notification_email`.
    pub notification_email: Option<String>,
    /// `minimum_passing_score`.
    pub minimum_passing_score: f64,
    /// `created_at`.
    pub created_at: NaiveDateTime,
    /// `updated_at`.
    pub updated_at: NaiveDateTime,
    /// `created_by`.
    pub created_by: Option<String>,
    /// `updated_by`.
    pub updated_by: Option<String>,
    /// `last_audit_at`.
    pub last_audit_at: Option<NaiveDateTime>,
    /// `last_audit_score`.
    pub last_audit_score: Option<f64>,
    /// `last_audit_grade`.
    pub last_audit_grade: Option<String>,
}

const CONFIG_SELECT: &str = "SELECT CAST(github_audit_config.repo_filter_list AS CHAR) AS \
     repo_filter_list, github_audit_config.id, github_audit_config.customer_code, \
     github_audit_config.github_token, github_audit_config.organization, \
     github_audit_config.token_type, github_audit_config.token_expires_at, \
     github_audit_config.enabled, github_audit_config.auto_audit_enabled, \
     github_audit_config.audit_schedule_cron, github_audit_config.include_repos, \
     github_audit_config.include_workflows, github_audit_config.include_members, \
     github_audit_config.include_archived_repos, github_audit_config.repo_filter_mode, \
     github_audit_config.notify_on_critical, github_audit_config.notify_on_high, \
     github_audit_config.notification_webhook_url, github_audit_config.notification_email, \
     CAST(github_audit_config.minimum_passing_score AS CHAR) AS minimum_passing_score, \
     github_audit_config.created_at, github_audit_config.updated_at, \
     github_audit_config.created_by, github_audit_config.updated_by, \
     github_audit_config.last_audit_at, \
     CAST(github_audit_config.last_audit_score AS CHAR) AS last_audit_score, \
     github_audit_config.last_audit_grade FROM github_audit_config";

fn config_row(row: &MySqlRow) -> Result<ConfigRow, sqlx::Error> {
    Ok(ConfigRow {
        id: row.try_get("id")?,
        customer_code: row.try_get("customer_code")?,
        github_token: row.try_get("github_token")?,
        organization: row.try_get("organization")?,
        token_type: row.try_get("token_type")?,
        token_expires_at: row.try_get("token_expires_at")?,
        enabled: row.try_get("enabled")?,
        auto_audit_enabled: row.try_get("auto_audit_enabled")?,
        audit_schedule_cron: row.try_get("audit_schedule_cron")?,
        include_repos: row.try_get("include_repos")?,
        include_workflows: row.try_get("include_workflows")?,
        include_members: row.try_get("include_members")?,
        include_archived_repos: row.try_get("include_archived_repos")?,
        repo_filter_mode: row.try_get("repo_filter_mode")?,
        repo_filter_list: json_col(row, "repo_filter_list")?,
        notify_on_critical: row.try_get("notify_on_critical")?,
        notify_on_high: row.try_get("notify_on_high")?,
        notification_webhook_url: row.try_get("notification_webhook_url")?,
        notification_email: row.try_get("notification_email")?,
        minimum_passing_score: float_col(row, "minimum_passing_score")?.unwrap_or_default(),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        created_by: row.try_get("created_by")?,
        updated_by: row.try_get("updated_by")?,
        last_audit_at: row.try_get("last_audit_at")?,
        last_audit_score: float_col(row, "last_audit_score")?,
        last_audit_grade: row.try_get("last_audit_grade")?,
    })
}

/// `"***" + token[-4:] if len(token) > 4 else "***"` for a non-empty token.
pub fn mask_token(token: &str) -> String {
    if token.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = token.chars().collect();
    if chars.len() > 4 {
        format!("***{}", chars[chars.len() - 4..].iter().collect::<String>())
    } else {
        "***".to_string()
    }
}

impl ConfigRow {
    /// The table model's dump, in declaration order, the token masked as the
    /// routes answer it (`***` and its last four characters). Python's
    /// `POST /config` answered the token in clear; every answer masks it
    /// here (RUST_MIGRATION.md §4, a Python response artefact).
    pub fn dump(&self) -> PyValue {
        let token = mask_token(&self.github_token);
        dict(vec![
            ("id", int(self.id)),
            ("customer_code", PyValue::Str(self.customer_code.clone())),
            ("github_token", PyValue::Str(token)),
            ("organization", PyValue::Str(self.organization.clone())),
            ("token_type", PyValue::Str(self.token_type.clone())),
            ("token_expires_at", time(self.token_expires_at.as_ref())),
            ("enabled", PyValue::Bool(self.enabled)),
            ("auto_audit_enabled", PyValue::Bool(self.auto_audit_enabled)),
            (
                "audit_schedule_cron",
                text(self.audit_schedule_cron.as_deref()),
            ),
            ("include_repos", PyValue::Bool(self.include_repos)),
            ("include_workflows", PyValue::Bool(self.include_workflows)),
            ("include_members", PyValue::Bool(self.include_members)),
            (
                "include_archived_repos",
                PyValue::Bool(self.include_archived_repos),
            ),
            (
                "repo_filter_mode",
                PyValue::Str(self.repo_filter_mode.clone()),
            ),
            (
                "repo_filter_list",
                self.repo_filter_list.clone().unwrap_or(PyValue::None),
            ),
            ("notify_on_critical", PyValue::Bool(self.notify_on_critical)),
            ("notify_on_high", PyValue::Bool(self.notify_on_high)),
            (
                "notification_webhook_url",
                text(self.notification_webhook_url.as_deref()),
            ),
            (
                "notification_email",
                text(self.notification_email.as_deref()),
            ),
            (
                "minimum_passing_score",
                PyValue::Float(self.minimum_passing_score),
            ),
            ("created_at", PyValue::Str(iso(&self.created_at))),
            ("updated_at", PyValue::Str(iso(&self.updated_at))),
            ("created_by", text(self.created_by.as_deref())),
            ("updated_by", text(self.updated_by.as_deref())),
            ("last_audit_at", time(self.last_audit_at.as_ref())),
            ("last_audit_score", float(self.last_audit_score)),
            ("last_audit_grade", text(self.last_audit_grade.as_deref())),
        ])
    }
}

/// `select(GitHubAuditConfig).where(GitHubAuditConfig.id == config_id)`.
/// An id no `int` column can hold matches nothing.
pub async fn config(db: &Db, id: &str) -> Result<Option<ConfigRow>, DbError> {
    let Ok(id) = id.parse::<i64>() else {
        return Ok(None);
    };
    let row = sqlx::query(&format!("{CONFIG_SELECT} WHERE github_audit_config.id = ?"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    Ok(row.as_ref().map(config_row).transpose()?)
}

/// `get_configs`: every row, or those of `codes`.
pub async fn configs(db: &Db, codes: Option<&[String]>) -> Result<Vec<ConfigRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(CONFIG_SELECT);
    if let Some(codes) = codes {
        qb.push(" WHERE ");
        in_list(&mut qb, "github_audit_config.customer_code", codes);
    }
    let rows = qb.build().fetch_all(db.pool()).await?;
    Ok(rows.iter().map(config_row).collect::<Result<Vec<_>, _>>()?)
}

/// How many configurations exist for `(customer_code, organization)`
/// (`scalar_one_or_none()` raises past one).
pub async fn existing_configs(db: &Db, code: &str, organization: &str) -> Result<usize, DbError> {
    let rows = sqlx::query(&format!(
        "{CONFIG_SELECT} WHERE github_audit_config.customer_code = ? AND \
         github_audit_config.organization = ?"
    ))
    .bind(code)
    .bind(organization)
    .fetch_all(db.pool())
    .await?;
    Ok(rows.len())
}

/// `GitHubAuditConfig(**create)`, `add`, `commit`: the new id.
pub async fn insert_config(db: &Db, c: &super::schema::ConfigCreate) -> Result<u64, DbError> {
    let list = c.repo_filter_list.as_ref().map(|items| {
        copilot_upstream::json::py_dumps_allow_nan(
            &PyValue::List(items.iter().cloned().map(PyValue::Str).collect()),
            copilot_upstream::json::Dumps::DEFAULT,
        )
    });
    let created_at = utcnow();
    let updated_at = utcnow();
    let res = sqlx::query(
        "INSERT INTO github_audit_config (repo_filter_list, customer_code, github_token, \
         organization, token_type, token_expires_at, enabled, auto_audit_enabled, \
         audit_schedule_cron, include_repos, include_workflows, include_members, \
         include_archived_repos, repo_filter_mode, notify_on_critical, notify_on_high, \
         notification_webhook_url, notification_email, minimum_passing_score, created_at, \
         updated_at, created_by, updated_by, last_audit_at, last_audit_score, last_audit_grade) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, \
         NULL, NULL)",
    )
    .bind(list)
    .bind(&c.customer_code)
    .bind(&c.github_token)
    .bind(&c.organization)
    .bind(&c.token_type)
    .bind(c.token_expires_at)
    .bind(c.enabled)
    .bind(c.auto_audit_enabled)
    .bind(&c.audit_schedule_cron)
    .bind(c.include_repos)
    .bind(c.include_workflows)
    .bind(c.include_members)
    .bind(c.include_archived_repos)
    .bind(&c.repo_filter_mode)
    .bind(c.notify_on_critical)
    .bind(c.notify_on_high)
    .bind(&c.notification_webhook_url)
    .bind(&c.notification_email)
    .bind(c.minimum_passing_score)
    .bind(created_at)
    .bind(updated_at)
    .bind(&c.created_by)
    .execute(db.pool())
    .await?;
    Ok(res.last_insert_id())
}

/// `setattr` of every field sent, `updated_at = now`, `commit`.
pub async fn update_config(
    db: &Db,
    id: i32,
    set: &[(&'static str, super::schema::ConfigValue)],
) -> Result<(), DbError> {
    use super::schema::ConfigValue;
    let mut qb = QueryBuilder::<MySql>::new("UPDATE github_audit_config SET ");
    let mut sep = qb.separated(", ");
    for (column, value) in set {
        sep.push(format!("{column} = "));
        match value {
            ConfigValue::Text(s) => sep.push_bind_unseparated(s.clone()),
            ConfigValue::Flag(b) => sep.push_bind_unseparated(*b),
            ConfigValue::Time(t) => sep.push_bind_unseparated(*t),
            ConfigValue::Number(f) => sep.push_bind_unseparated(*f),
            ConfigValue::List(items) => {
                sep.push_bind_unseparated(copilot_upstream::json::py_dumps_allow_nan(
                    &PyValue::List(items.iter().cloned().map(PyValue::Str).collect()),
                    copilot_upstream::json::Dumps::DEFAULT,
                ))
            }
        };
    }
    sep.push("updated_at = ");
    sep.push_bind_unseparated(utcnow());
    qb.push(" WHERE github_audit_config.id = ");
    qb.push_bind(id);
    qb.build().execute(db.pool()).await?;
    Ok(())
}

/// `session.delete(config)`, `commit`. A configuration that has reports,
/// exclusions or baselines fails as in Python (its foreign keys refuse it:
/// SQLAlchemy first sets the reports' `config_id` to `NULL`, which the
/// `NOT NULL` column refuses); the error is the caller's bare 500.
pub async fn delete_config(db: &Db, id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM github_audit_config WHERE github_audit_config.id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

// --- github_audit_report ----------------------------------------------------------------

/// One `github_audit_report` row.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportRow {
    /// `id`.
    pub id: i32,
    /// `config_id`.
    pub config_id: i32,
    /// `customer_code`.
    pub customer_code: String,
    /// `report_name`.
    pub report_name: String,
    /// `organization`.
    pub organization: String,
    /// `audit_started_at`.
    pub audit_started_at: NaiveDateTime,
    /// `audit_completed_at`.
    pub audit_completed_at: Option<NaiveDateTime>,
    /// `audit_duration_seconds`.
    pub audit_duration_seconds: Option<f64>,
    /// The eight counters, in column order (`total_repos_audited` …
    /// `low_findings`).
    pub counts: [i32; 9],
    /// `score`.
    pub score: f64,
    /// `grade`.
    pub grade: String,
    /// `status`.
    pub status: String,
    /// `error_message`.
    pub error_message: Option<String>,
    /// `full_report`.
    pub full_report: Option<PyValue>,
    /// `top_findings`.
    pub top_findings: Option<PyValue>,
    /// `triggered_by`.
    pub triggered_by: String,
    /// `triggered_by_user`.
    pub triggered_by_user: Option<String>,
}

const COUNT_COLUMNS: [&str; 9] = [
    "total_repos_audited",
    "total_checks",
    "passed_checks",
    "failed_checks",
    "warning_checks",
    "critical_findings",
    "high_findings",
    "medium_findings",
    "low_findings",
];

const REPORT_SELECT: &str = "SELECT CAST(github_audit_report.full_report AS CHAR) AS full_report, \
     CAST(github_audit_report.top_findings AS CHAR) AS top_findings, github_audit_report.id, \
     github_audit_report.config_id, github_audit_report.customer_code, \
     github_audit_report.report_name, github_audit_report.organization, \
     github_audit_report.audit_started_at, github_audit_report.audit_completed_at, \
     CAST(github_audit_report.audit_duration_seconds AS CHAR) AS audit_duration_seconds, \
     github_audit_report.total_repos_audited, github_audit_report.total_checks, \
     github_audit_report.passed_checks, github_audit_report.failed_checks, \
     github_audit_report.warning_checks, github_audit_report.critical_findings, \
     github_audit_report.high_findings, github_audit_report.medium_findings, \
     github_audit_report.low_findings, CAST(github_audit_report.score AS CHAR) AS score, \
     github_audit_report.grade, github_audit_report.status, github_audit_report.error_message, \
     github_audit_report.triggered_by, github_audit_report.triggered_by_user \
     FROM github_audit_report";

fn counts(row: &MySqlRow) -> Result<[i32; 9], sqlx::Error> {
    let mut out = [0; 9];
    for (slot, col) in out.iter_mut().zip(COUNT_COLUMNS) {
        *slot = row.try_get(col)?;
    }
    Ok(out)
}

fn report_row(row: &MySqlRow, full: bool) -> Result<ReportRow, sqlx::Error> {
    Ok(ReportRow {
        id: row.try_get("id")?,
        config_id: row.try_get("config_id")?,
        customer_code: row.try_get("customer_code")?,
        report_name: row.try_get("report_name")?,
        organization: row.try_get("organization")?,
        audit_started_at: row.try_get("audit_started_at")?,
        audit_completed_at: row.try_get("audit_completed_at")?,
        audit_duration_seconds: float_col(row, "audit_duration_seconds")?,
        counts: counts(row)?,
        score: float_col(row, "score")?.unwrap_or_default(),
        grade: row.try_get("grade")?,
        status: row.try_get("status")?,
        error_message: if full {
            row.try_get("error_message")?
        } else {
            None
        },
        full_report: if full {
            json_col(row, "full_report")?
        } else {
            None
        },
        top_findings: if full {
            json_col(row, "top_findings")?
        } else {
            None
        },
        triggered_by: row.try_get("triggered_by")?,
        triggered_by_user: row.try_get("triggered_by_user")?,
    })
}

impl ReportRow {
    fn head(&self) -> Vec<(&'static str, PyValue)> {
        let mut out = vec![
            ("id", int(self.id)),
            ("config_id", int(self.config_id)),
            ("customer_code", PyValue::Str(self.customer_code.clone())),
            ("report_name", PyValue::Str(self.report_name.clone())),
            ("organization", PyValue::Str(self.organization.clone())),
            (
                "audit_started_at",
                PyValue::Str(iso(&self.audit_started_at)),
            ),
            ("audit_completed_at", time(self.audit_completed_at.as_ref())),
            ("audit_duration_seconds", float(self.audit_duration_seconds)),
        ];
        for (col, n) in COUNT_COLUMNS.iter().zip(self.counts) {
            out.push((col, int(n)));
        }
        out.push(("score", PyValue::Float(self.score)));
        out.push(("grade", PyValue::Str(self.grade.clone())));
        out.push(("status", PyValue::Str(self.status.clone())));
        out
    }

    /// The list view's dict (`get_reports`).
    pub fn summary_dump(&self) -> PyValue {
        let mut pairs = self.head();
        pairs.push(("triggered_by", PyValue::Str(self.triggered_by.clone())));
        pairs.push(("triggered_by_user", text(self.triggered_by_user.as_deref())));
        dict(pairs)
    }

    /// The table model's dump, in declaration order.
    pub fn dump(&self) -> PyValue {
        let mut pairs = self.head();
        pairs.push(("error_message", text(self.error_message.as_deref())));
        pairs.push((
            "full_report",
            self.full_report.clone().unwrap_or(PyValue::None),
        ));
        pairs.push((
            "top_findings",
            self.top_findings.clone().unwrap_or(PyValue::None),
        ));
        pairs.push(("triggered_by", PyValue::Str(self.triggered_by.clone())));
        pairs.push(("triggered_by_user", text(self.triggered_by_user.as_deref())));
        dict(pairs)
    }
}

/// `select(GitHubAuditReport).where(GitHubAuditReport.id == report_id)`.
pub async fn report(db: &Db, id: &str) -> Result<Option<ReportRow>, DbError> {
    let Ok(id) = id.parse::<i64>() else {
        return Ok(None);
    };
    let row = sqlx::query(&format!("{REPORT_SELECT} WHERE github_audit_report.id = ?"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    Ok(row.as_ref().map(|r| report_row(r, true)).transpose()?)
}

/// The filters of `get_reports`.
#[derive(Debug, Clone, Default)]
pub struct ReportFilter {
    /// The caller's customers (`None`: every customer).
    pub access: Option<Vec<String>>,
    /// `customer_code` (only when truthy).
    pub customer_code: Option<String>,
    /// `config_id` (only when truthy).
    pub config_id: Option<i64>,
    /// `organization` (only when truthy).
    pub organization: Option<String>,
    /// `status` (only when truthy).
    pub status: Option<String>,
}

fn report_where(qb: &mut QueryBuilder<'_, MySql>, f: &ReportFilter) {
    let mut first = true;
    let mut and = |qb: &mut QueryBuilder<'_, MySql>| {
        qb.push(if first { " WHERE " } else { " AND " });
        first = false;
    };
    if let Some(codes) = &f.access {
        and(qb);
        in_list(qb, "github_audit_report.customer_code", codes);
    }
    if let Some(c) = &f.customer_code {
        and(qb);
        qb.push("github_audit_report.customer_code = ")
            .push_bind(c.clone());
    }
    if let Some(id) = f.config_id {
        and(qb);
        qb.push("github_audit_report.config_id = ").push_bind(id);
    }
    if let Some(o) = &f.organization {
        and(qb);
        qb.push("github_audit_report.organization = ")
            .push_bind(o.clone());
    }
    if let Some(s) = &f.status {
        and(qb);
        qb.push("github_audit_report.status = ")
            .push_bind(s.clone());
    }
}

/// `get_reports`' page: the list columns, newest first.
pub async fn reports(
    db: &Db,
    f: &ReportFilter,
    offset: i64,
    limit: i64,
) -> Result<Vec<ReportRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT github_audit_report.id, github_audit_report.config_id, \
         github_audit_report.customer_code, github_audit_report.report_name, \
         github_audit_report.organization, github_audit_report.audit_started_at, \
         github_audit_report.audit_completed_at, \
         CAST(github_audit_report.audit_duration_seconds AS CHAR) AS audit_duration_seconds, \
         github_audit_report.total_repos_audited, github_audit_report.total_checks, \
         github_audit_report.passed_checks, github_audit_report.failed_checks, \
         github_audit_report.warning_checks, github_audit_report.critical_findings, \
         github_audit_report.high_findings, github_audit_report.medium_findings, \
         github_audit_report.low_findings, CAST(github_audit_report.score AS CHAR) AS score, \
         github_audit_report.grade, github_audit_report.status, \
         github_audit_report.triggered_by, github_audit_report.triggered_by_user \
         FROM github_audit_report",
    );
    report_where(&mut qb, f);
    qb.push(" ORDER BY github_audit_report.audit_started_at DESC LIMIT ");
    qb.push_bind(offset);
    qb.push(", ");
    qb.push_bind(limit);
    let rows = qb.build().fetch_all(db.pool()).await?;
    Ok(rows
        .iter()
        .map(|r| report_row(r, false))
        .collect::<Result<Vec<_>, _>>()?)
}

/// `get_reports`' count (here under the same tenant filter as the page).
pub async fn count_reports(db: &Db, f: &ReportFilter) -> Result<i64, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT count(github_audit_report.id) AS count_1 FROM github_audit_report",
    );
    report_where(&mut qb, f);
    Ok(qb.build_query_scalar::<i64>().fetch_one(db.pool()).await?)
}

/// `session.delete(report)`, `commit` (a baseline that names the report
/// refuses it: the caller's bare 500).
pub async fn delete_report(db: &Db, id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM github_audit_report WHERE github_audit_report.id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// The `running` row `run_audit_from_config` commits before the audit.
pub async fn insert_running_report(
    db: &Db,
    config: &ConfigRow,
    report_name: &str,
) -> Result<u64, DbError> {
    let res = sqlx::query(
        "INSERT INTO github_audit_report (full_report, top_findings, config_id, customer_code, \
         report_name, organization, audit_started_at, audit_completed_at, \
         audit_duration_seconds, total_repos_audited, total_checks, passed_checks, \
         failed_checks, warning_checks, critical_findings, high_findings, medium_findings, \
         low_findings, score, grade, status, error_message, triggered_by, triggered_by_user) \
         VALUES (NULL, NULL, ?, ?, ?, ?, ?, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?, 'F', \
         'running', NULL, 'manual', NULL)",
    )
    .bind(config.id)
    .bind(&config.customer_code)
    .bind(report_name)
    .bind(&config.organization)
    .bind(utcnow())
    .bind(0.0_f64)
    .execute(db.pool())
    .await?;
    Ok(res.last_insert_id())
}

/// What an audit writes back: the report's outcome and the configuration's
/// `last_audit_*` (one commit).
#[derive(Debug, Clone)]
pub struct AuditWriteBack {
    /// `completed` / `failed`.
    pub status: &'static str,
    /// `audit_completed_at` (and the configuration's `last_audit_at`).
    pub completed_at: NaiveDateTime,
    /// `audit_duration_seconds`.
    pub duration: f64,
    /// The summary's counters, score and grade (none for a failed audit).
    pub summary: Option<([i64; 9], f64, String)>,
    /// `json.dumps(audit_response.model_dump())`.
    pub full_report: String,
    /// `json.dumps([f.model_dump() for f in top_findings[:20]])`.
    pub top_findings: String,
}

/// The write-back of `run_audit_from_config`, in one transaction.
pub async fn finish_report(
    db: &Db,
    report_id: u64,
    config_id: i32,
    w: &AuditWriteBack,
) -> Result<(), DbError> {
    let mut tx = db.pool().begin().await?;
    let mut qb = QueryBuilder::<MySql>::new("UPDATE github_audit_config SET last_audit_at = ");
    qb.push_bind(w.completed_at);
    if let Some((_, score, grade)) = &w.summary {
        qb.push(", last_audit_score = ").push_bind(*score);
        qb.push(", last_audit_grade = ").push_bind(grade.clone());
    }
    qb.push(" WHERE github_audit_config.id = ")
        .push_bind(config_id);
    qb.build().execute(&mut *tx).await?;

    let mut qb = QueryBuilder::<MySql>::new("UPDATE github_audit_report SET status = ");
    qb.push_bind(w.status);
    qb.push(", audit_completed_at = ").push_bind(w.completed_at);
    qb.push(", audit_duration_seconds = ").push_bind(w.duration);
    if let Some((counts, score, grade)) = &w.summary {
        for (col, n) in COUNT_COLUMNS.iter().zip(counts) {
            qb.push(format!(", {col} = ")).push_bind(*n);
        }
        qb.push(", score = ").push_bind(*score);
        qb.push(", grade = ").push_bind(grade.clone());
    }
    qb.push(", full_report = ").push_bind(w.full_report.clone());
    qb.push(", top_findings = ")
        .push_bind(w.top_findings.clone());
    qb.push(" WHERE github_audit_report.id = ")
        .push_bind(report_id);
    qb.build().execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

// --- github_audit_check_exclusion -------------------------------------------------------

/// One `github_audit_check_exclusion` row.
#[derive(Debug, Clone, PartialEq)]
pub struct ExclusionRow {
    /// `id`.
    pub id: i32,
    /// `config_id`.
    pub config_id: i32,
    /// `customer_code`.
    pub customer_code: String,
    /// `check_id`.
    pub check_id: String,
    /// `resource_name`.
    pub resource_name: Option<String>,
    /// `resource_type`.
    pub resource_type: Option<String>,
    /// `reason`.
    pub reason: String,
    /// `approved_by`.
    pub approved_by: Option<String>,
    /// `approved_at`.
    pub approved_at: Option<NaiveDateTime>,
    /// `expires_at`.
    pub expires_at: Option<NaiveDateTime>,
    /// `enabled`.
    pub enabled: bool,
    /// `created_at`.
    pub created_at: NaiveDateTime,
    /// `created_by`.
    pub created_by: String,
}

const EXCLUSION_SELECT: &str = "SELECT github_audit_check_exclusion.id, \
     github_audit_check_exclusion.config_id, github_audit_check_exclusion.customer_code, \
     github_audit_check_exclusion.check_id, github_audit_check_exclusion.resource_name, \
     github_audit_check_exclusion.resource_type, github_audit_check_exclusion.reason, \
     github_audit_check_exclusion.approved_by, github_audit_check_exclusion.approved_at, \
     github_audit_check_exclusion.expires_at, github_audit_check_exclusion.enabled, \
     github_audit_check_exclusion.created_at, github_audit_check_exclusion.created_by \
     FROM github_audit_check_exclusion";

fn exclusion_row(row: &MySqlRow) -> Result<ExclusionRow, sqlx::Error> {
    Ok(ExclusionRow {
        id: row.try_get("id")?,
        config_id: row.try_get("config_id")?,
        customer_code: row.try_get("customer_code")?,
        check_id: row.try_get("check_id")?,
        resource_name: row.try_get("resource_name")?,
        resource_type: row.try_get("resource_type")?,
        reason: row.try_get("reason")?,
        approved_by: row.try_get("approved_by")?,
        approved_at: row.try_get("approved_at")?,
        expires_at: row.try_get("expires_at")?,
        enabled: row.try_get("enabled")?,
        created_at: row.try_get("created_at")?,
        created_by: row.try_get("created_by")?,
    })
}

impl ExclusionRow {
    /// The table model's dump, in declaration order.
    pub fn dump(&self) -> PyValue {
        dict(vec![
            ("id", int(self.id)),
            ("config_id", int(self.config_id)),
            ("customer_code", PyValue::Str(self.customer_code.clone())),
            ("check_id", PyValue::Str(self.check_id.clone())),
            ("resource_name", text(self.resource_name.as_deref())),
            ("resource_type", text(self.resource_type.as_deref())),
            ("reason", PyValue::Str(self.reason.clone())),
            ("approved_by", text(self.approved_by.as_deref())),
            ("approved_at", time(self.approved_at.as_ref())),
            ("expires_at", time(self.expires_at.as_ref())),
            ("enabled", PyValue::Bool(self.enabled)),
            ("created_at", PyValue::Str(iso(&self.created_at))),
            ("created_by", PyValue::Str(self.created_by.clone())),
        ])
    }
}

/// One exclusion by id.
pub async fn exclusion(db: &Db, id: &str) -> Result<Option<ExclusionRow>, DbError> {
    let Ok(id) = id.parse::<i64>() else {
        return Ok(None);
    };
    let row = sqlx::query(&format!(
        "{EXCLUSION_SELECT} WHERE github_audit_check_exclusion.id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.as_ref().map(exclusion_row).transpose()?)
}

/// `get_exclusions`: a configuration's rows, unexpired ones only unless
/// `include_expired` (`now` is the bound `datetime.now(timezone.utc)`).
pub async fn exclusions(
    db: &Db,
    config_id: i64,
    include_expired: bool,
) -> Result<Vec<ExclusionRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(EXCLUSION_SELECT);
    qb.push(" WHERE github_audit_check_exclusion.config_id = ")
        .push_bind(config_id);
    if !include_expired {
        qb.push(
            " AND (github_audit_check_exclusion.expires_at IS NULL OR \
             github_audit_check_exclusion.expires_at > ",
        )
        .push_bind(utcnow())
        .push(")");
    }
    let rows = qb.build().fetch_all(db.pool()).await?;
    Ok(rows
        .iter()
        .map(exclusion_row)
        .collect::<Result<Vec<_>, _>>()?)
}

/// The enabled exclusions an audit applies (expired ones included, as in
/// Python).
pub async fn enabled_exclusions(db: &Db, config_id: i32) -> Result<Vec<ExclusionRow>, DbError> {
    let rows = sqlx::query(&format!(
        "{EXCLUSION_SELECT} WHERE github_audit_check_exclusion.config_id = ? AND \
         github_audit_check_exclusion.enabled = true"
    ))
    .bind(config_id)
    .fetch_all(db.pool())
    .await?;
    Ok(rows
        .iter()
        .map(exclusion_row)
        .collect::<Result<Vec<_>, _>>()?)
}

/// `create_exclusion`'s insert: the new id.
pub async fn insert_exclusion(
    db: &Db,
    config: &ConfigRow,
    e: &super::schema::ExclusionCreate,
) -> Result<u64, DbError> {
    // `datetime.now(timezone.utc) if exclusion.approved_by else None`.
    let approved_at = e
        .approved_by
        .as_deref()
        .filter(|a| !a.is_empty())
        .map(|_| utcnow());
    let res = sqlx::query(
        "INSERT INTO github_audit_check_exclusion (config_id, customer_code, check_id, \
         resource_name, resource_type, reason, approved_by, approved_at, expires_at, enabled, \
         created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
    )
    .bind(config.id)
    .bind(&config.customer_code)
    .bind(&e.check_id)
    .bind(&e.resource_name)
    .bind(&e.resource_type)
    .bind(&e.reason)
    .bind(&e.approved_by)
    .bind(approved_at)
    .bind(e.expires_at)
    .bind(utcnow())
    .bind(&e.created_by)
    .execute(db.pool())
    .await?;
    Ok(res.last_insert_id())
}

/// `setattr` of every field sent, `commit` (nothing sent: no statement).
pub async fn update_exclusion(
    db: &Db,
    id: i32,
    set: &[(&'static str, super::schema::ExclusionValue)],
) -> Result<(), DbError> {
    use super::schema::ExclusionValue;
    if set.is_empty() {
        return Ok(());
    }
    let mut qb = QueryBuilder::<MySql>::new("UPDATE github_audit_check_exclusion SET ");
    let mut sep = qb.separated(", ");
    for (column, value) in set {
        sep.push(format!("{column} = "));
        match value {
            ExclusionValue::Text(s) => sep.push_bind_unseparated(s.clone()),
            ExclusionValue::Time(t) => sep.push_bind_unseparated(*t),
            ExclusionValue::Flag(b) => sep.push_bind_unseparated(*b),
        };
    }
    qb.push(" WHERE github_audit_check_exclusion.id = ");
    qb.push_bind(id);
    qb.build().execute(db.pool()).await?;
    Ok(())
}

/// `session.delete(exclusion)`, `commit`.
pub async fn delete_exclusion(db: &Db, id: i32) -> Result<(), DbError> {
    sqlx::query(
        "DELETE FROM github_audit_check_exclusion WHERE github_audit_check_exclusion.id = ?",
    )
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

// --- github_audit_baseline --------------------------------------------------------------

/// One `github_audit_baseline` row.
#[derive(Debug, Clone, PartialEq)]
pub struct BaselineRow {
    /// `id`.
    pub id: i32,
    /// `config_id`.
    pub config_id: i32,
    /// `customer_code`.
    pub customer_code: String,
    /// `name`.
    pub name: String,
    /// `description`.
    pub description: Option<String>,
    /// `expected_checks`.
    pub expected_checks: Option<PyValue>,
    /// `baseline_report_id`.
    pub baseline_report_id: Option<i32>,
    /// `is_active`.
    pub is_active: bool,
    /// `created_at`.
    pub created_at: NaiveDateTime,
    /// `created_by`.
    pub created_by: String,
}

const BASELINE_SELECT: &str = "SELECT CAST(github_audit_baseline.expected_checks AS CHAR) AS \
     expected_checks, github_audit_baseline.id, github_audit_baseline.config_id, \
     github_audit_baseline.customer_code, github_audit_baseline.name, \
     github_audit_baseline.description, github_audit_baseline.baseline_report_id, \
     github_audit_baseline.is_active, github_audit_baseline.created_at, \
     github_audit_baseline.created_by FROM github_audit_baseline";

fn baseline_row(row: &MySqlRow) -> Result<BaselineRow, sqlx::Error> {
    Ok(BaselineRow {
        id: row.try_get("id")?,
        config_id: row.try_get("config_id")?,
        customer_code: row.try_get("customer_code")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        expected_checks: json_col(row, "expected_checks")?,
        baseline_report_id: row.try_get("baseline_report_id")?,
        is_active: row.try_get("is_active")?,
        created_at: row.try_get("created_at")?,
        created_by: row.try_get("created_by")?,
    })
}

impl BaselineRow {
    /// The table model's dump, in declaration order.
    pub fn dump(&self) -> PyValue {
        dict(vec![
            ("id", int(self.id)),
            ("config_id", int(self.config_id)),
            ("customer_code", PyValue::Str(self.customer_code.clone())),
            ("name", PyValue::Str(self.name.clone())),
            ("description", text(self.description.as_deref())),
            (
                "expected_checks",
                self.expected_checks.clone().unwrap_or(PyValue::None),
            ),
            (
                "baseline_report_id",
                self.baseline_report_id.map_or(PyValue::None, int),
            ),
            ("is_active", PyValue::Bool(self.is_active)),
            ("created_at", PyValue::Str(iso(&self.created_at))),
            ("created_by", PyValue::Str(self.created_by.clone())),
        ])
    }
}

/// One baseline by id.
pub async fn baseline(db: &Db, id: &str) -> Result<Option<BaselineRow>, DbError> {
    let Ok(id) = id.parse::<i64>() else {
        return Ok(None);
    };
    let row = sqlx::query(&format!(
        "{BASELINE_SELECT} WHERE github_audit_baseline.id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.as_ref().map(baseline_row).transpose()?)
}

/// `get_baselines`.
pub async fn baselines(
    db: &Db,
    config_id: i64,
    active_only: bool,
) -> Result<Vec<BaselineRow>, DbError> {
    let mut sql = format!("{BASELINE_SELECT} WHERE github_audit_baseline.config_id = ?");
    if active_only {
        sql.push_str(" AND github_audit_baseline.is_active = true");
    }
    let rows = sqlx::query(&sql)
        .bind(config_id)
        .fetch_all(db.pool())
        .await?;
    Ok(rows
        .iter()
        .map(baseline_row)
        .collect::<Result<Vec<_>, _>>()?)
}

/// What `create_baseline` inserts.
#[derive(Debug, Clone)]
pub struct NewBaseline<'a> {
    /// The configuration.
    pub config: &'a ConfigRow,
    /// `name`.
    pub name: &'a str,
    /// `description`.
    pub description: Option<&'a str>,
    /// `json.dumps(expected_checks)`.
    pub expected_checks: Option<String>,
    /// `baseline_report_id`.
    pub baseline_report_id: Option<i64>,
    /// `is_active` (the configuration's other active baselines are
    /// deactivated first).
    pub is_active: bool,
    /// `created_by`.
    pub created_by: &'a str,
}

/// `create_baseline`'s commit: the deactivations and the insert in one
/// transaction; the new id.
pub async fn insert_baseline(db: &Db, b: &NewBaseline<'_>) -> Result<u64, DbError> {
    let mut tx = db.pool().begin().await?;
    if b.is_active {
        sqlx::query(
            "UPDATE github_audit_baseline SET is_active = 0 WHERE \
             github_audit_baseline.config_id = ? AND github_audit_baseline.is_active = true",
        )
        .bind(b.config.id)
        .execute(&mut *tx)
        .await?;
    }
    let res = sqlx::query(
        "INSERT INTO github_audit_baseline (expected_checks, config_id, customer_code, name, \
         description, baseline_report_id, is_active, created_at, created_by) VALUES \
         (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&b.expected_checks)
    .bind(b.config.id)
    .bind(&b.config.customer_code)
    .bind(b.name)
    .bind(b.description)
    .bind(b.baseline_report_id)
    .bind(b.is_active)
    .bind(utcnow())
    .bind(b.created_by)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.last_insert_id())
}

/// `session.delete(baseline)`, `commit`.
pub async fn delete_baseline(db: &Db, id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM github_audit_baseline WHERE github_audit_baseline.id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// The columns this module reads and writes.
pub const REQUIREMENTS: &[copilot_db::schema::TableRequirement] = &[
    copilot_db::schema::TableRequirement {
        table: "github_audit_config",
        columns: &[
            "id",
            "customer_code",
            "github_token",
            "organization",
            "token_type",
            "token_expires_at",
            "enabled",
            "auto_audit_enabled",
            "audit_schedule_cron",
            "include_repos",
            "include_workflows",
            "include_members",
            "include_archived_repos",
            "repo_filter_mode",
            "repo_filter_list",
            "notify_on_critical",
            "notify_on_high",
            "notification_webhook_url",
            "notification_email",
            "minimum_passing_score",
            "created_at",
            "updated_at",
            "created_by",
            "updated_by",
            "last_audit_at",
            "last_audit_score",
            "last_audit_grade",
        ],
    },
    copilot_db::schema::TableRequirement {
        table: "github_audit_report",
        columns: &[
            "id",
            "config_id",
            "customer_code",
            "report_name",
            "organization",
            "audit_started_at",
            "audit_completed_at",
            "audit_duration_seconds",
            "total_repos_audited",
            "total_checks",
            "passed_checks",
            "failed_checks",
            "warning_checks",
            "critical_findings",
            "high_findings",
            "medium_findings",
            "low_findings",
            "score",
            "grade",
            "status",
            "error_message",
            "full_report",
            "top_findings",
            "triggered_by",
            "triggered_by_user",
        ],
    },
    copilot_db::schema::TableRequirement {
        table: "github_audit_check_exclusion",
        columns: &[
            "id",
            "config_id",
            "customer_code",
            "check_id",
            "resource_name",
            "resource_type",
            "reason",
            "approved_by",
            "approved_at",
            "expires_at",
            "enabled",
            "created_at",
            "created_by",
        ],
    },
    copilot_db::schema::TableRequirement {
        table: "github_audit_baseline",
        columns: &[
            "id",
            "config_id",
            "customer_code",
            "name",
            "description",
            "expected_checks",
            "baseline_report_id",
            "is_active",
            "created_at",
            "created_by",
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_masked_like_python() {
        assert_eq!(mask_token(""), "");
        assert_eq!(mask_token("abcd"), "***");
        assert_eq!(mask_token("ghp_1234567890"), "***7890");
        assert_eq!(mask_token("ééééé"), "***éééé");
    }

    #[test]
    fn naive_datetimes_dump_like_pydantic() {
        let t = chrono::NaiveDate::from_ymd_opt(2026, 1, 2)
            .and_then(|d| d.and_hms_micro_opt(3, 4, 5, 0))
            .unwrap();
        assert_eq!(iso(&t), "2026-01-02T03:04:05");
        let t = t + chrono::Duration::microseconds(7);
        assert_eq!(iso(&t), "2026-01-02T03:04:05.000007");
    }
}
