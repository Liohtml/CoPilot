//! `customersmeta` and `customer_provisioning_default_settings`: the rows and
//! the statements the Python routes issue (no `ORDER BY` where they add
//! none, so MySQL returns the same "first" row).

use copilot_auth::pyvalue::PyValue;
use copilot_db::{Db, DbError};
use copilot_upstream::py::PyExc;
use sqlx::mysql::MySqlArguments;
use sqlx::query::Query;
use sqlx::{FromRow, MySql};

/// The table-model fields of `CustomersMeta`, in declaration order.
pub const META_COLUMNS: &[&str] = &[
    "id",
    "customer_code",
    "customer_name",
    "customer_meta_graylog_index",
    "customer_meta_graylog_stream",
    "customer_meta_grafana_org_id",
    "customer_meta_wazuh_group",
    "customer_meta_index_retention",
    "customer_meta_wazuh_registration_port",
    "customer_meta_wazuh_log_ingestion_port",
    "customer_meta_wazuh_api_port",
    "customer_meta_wazuh_auth_password",
    "customer_meta_iris_customer_id",
    "customer_meta_office365_organization_id",
    "customer_meta_portainer_stack_id",
];

/// One `customersmeta` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct MetaRow {
    /// `id`.
    pub id: i32,
    /// `customer_code`.
    pub customer_code: String,
    /// `customer_name`.
    pub customer_name: String,
    /// `customer_meta_graylog_index`.
    pub customer_meta_graylog_index: String,
    /// `customer_meta_graylog_stream`.
    pub customer_meta_graylog_stream: String,
    /// `customer_meta_grafana_org_id`.
    pub customer_meta_grafana_org_id: String,
    /// `customer_meta_wazuh_group`.
    pub customer_meta_wazuh_group: String,
    /// `customer_meta_index_retention`.
    pub customer_meta_index_retention: Option<String>,
    /// `customer_meta_wazuh_registration_port`.
    pub customer_meta_wazuh_registration_port: Option<String>,
    /// `customer_meta_wazuh_log_ingestion_port`.
    pub customer_meta_wazuh_log_ingestion_port: Option<String>,
    /// `customer_meta_wazuh_api_port`.
    pub customer_meta_wazuh_api_port: Option<String>,
    /// `customer_meta_wazuh_auth_password`.
    pub customer_meta_wazuh_auth_password: Option<String>,
    /// `customer_meta_iris_customer_id`.
    pub customer_meta_iris_customer_id: Option<i32>,
    /// `customer_meta_office365_organization_id`.
    pub customer_meta_office365_organization_id: Option<String>,
    /// `customer_meta_portainer_stack_id`.
    pub customer_meta_portainer_stack_id: Option<i32>,
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn opt(v: &Option<String>) -> PyValue {
    v.as_deref().map_or(PyValue::None, s)
}

fn int(v: Option<i32>) -> PyValue {
    v.map_or(PyValue::None, |i| PyValue::Int(i.to_string()))
}

impl MetaRow {
    /// The `CustomersMeta` table model's dump.
    pub fn dump(&self) -> PyValue {
        PyValue::Dict(vec![
            ("id".into(), int(Some(self.id))),
            ("customer_code".into(), s(&self.customer_code)),
            ("customer_name".into(), s(&self.customer_name)),
            (
                "customer_meta_graylog_index".into(),
                s(&self.customer_meta_graylog_index),
            ),
            (
                "customer_meta_graylog_stream".into(),
                s(&self.customer_meta_graylog_stream),
            ),
            (
                "customer_meta_grafana_org_id".into(),
                s(&self.customer_meta_grafana_org_id),
            ),
            (
                "customer_meta_wazuh_group".into(),
                s(&self.customer_meta_wazuh_group),
            ),
            (
                "customer_meta_index_retention".into(),
                opt(&self.customer_meta_index_retention),
            ),
            (
                "customer_meta_wazuh_registration_port".into(),
                opt(&self.customer_meta_wazuh_registration_port),
            ),
            (
                "customer_meta_wazuh_log_ingestion_port".into(),
                opt(&self.customer_meta_wazuh_log_ingestion_port),
            ),
            (
                "customer_meta_wazuh_api_port".into(),
                opt(&self.customer_meta_wazuh_api_port),
            ),
            (
                "customer_meta_wazuh_auth_password".into(),
                opt(&self.customer_meta_wazuh_auth_password),
            ),
            (
                "customer_meta_iris_customer_id".into(),
                int(self.customer_meta_iris_customer_id),
            ),
            (
                "customer_meta_office365_organization_id".into(),
                opt(&self.customer_meta_office365_organization_id),
            ),
            (
                "customer_meta_portainer_stack_id".into(),
                int(self.customer_meta_portainer_stack_id),
            ),
        ])
    }
}

fn db(e: impl Into<DbError>) -> PyExc {
    PyExc::Other("OperationalError", e.into().to_string())
}

/// `select(CustomersMeta).filter(customer_code == code)` → `.first()`.
pub async fn meta_by_code(pool: &Db, code: &str) -> Result<Option<MetaRow>, PyExc> {
    let rows: Vec<MetaRow> = sqlx::query_as(&format!(
        "SELECT {} FROM customersmeta WHERE customersmeta.customer_code = ?",
        META_COLUMNS.join(", ")
    ))
    .bind(code)
    .fetch_all(pool.pool())
    .await
    .map_err(db)?;
    Ok(rows.into_iter().next())
}

/// `select(CustomersMeta).where(customer_name == name)` →
/// `scalar_one_or_none()`.
pub async fn meta_by_name(pool: &Db, name: &str) -> Result<Option<MetaRow>, PyExc> {
    let rows: Vec<MetaRow> = sqlx::query_as(&format!(
        "SELECT {} FROM customersmeta WHERE customersmeta.customer_name = ?",
        META_COLUMNS.join(", ")
    ))
    .bind(name)
    .fetch_all(pool.pool())
    .await
    .map_err(db)?;
    match rows.len() {
        0 | 1 => Ok(rows.into_iter().next()),
        _ => Err(PyExc::Other(
            "MultipleResultsFound",
            "Multiple rows were found when one or none was required".into(),
        )),
    }
}

/// The customer exists (`select(Customers).filter(customer_code == code)`).
pub async fn customer_exists(pool: &Db, code: &str) -> Result<bool, PyExc> {
    let row: Option<(i32,)> =
        sqlx::query_as("SELECT id FROM customers WHERE customers.customer_code = ? LIMIT 1")
            .bind(code)
            .fetch_optional(pool.pool())
            .await
            .map_err(db)?;
    Ok(row.is_some())
}

/// Set `customer_meta_office365_organization_id`.
pub async fn set_office365_org_id(pool: &Db, id: i32, org: &str) -> Result<(), PyExc> {
    sqlx::query(
        "UPDATE customersmeta SET customer_meta_office365_organization_id = ? WHERE \
         customersmeta.id = ?",
    )
    .bind(org)
    .bind(id)
    .execute(pool.pool())
    .await
    .map_err(db)?;
    Ok(())
}

/// `update(CustomersMeta).where(customer_name == name)
/// .values(customer_meta_portainer_stack_id=None)`.
pub async fn clear_stack_id(pool: &Db, name: &str) -> Result<(), PyExc> {
    sqlx::query(
        "UPDATE customersmeta SET customer_meta_portainer_stack_id = NULL WHERE \
         customersmeta.customer_name = ?",
    )
    .bind(name)
    .execute(pool.pool())
    .await
    .map_err(db)?;
    Ok(())
}

/// `session.delete(customer_meta)`.
pub async fn delete_meta(pool: &Db, id: i32) -> Result<(), PyExc> {
    sqlx::query("DELETE FROM customersmeta WHERE customersmeta.id = ?")
        .bind(id)
        .execute(pool.pool())
        .await
        .map_err(db)?;
    Ok(())
}

// --- default settings --------------------------------------------------------

/// `CustomerProvisioningDefaultSettings`' fields, in declaration order.
pub const SETTINGS_COLUMNS: &[&str] = &[
    "id",
    "cluster_name",
    "cluster_key",
    "master_ip",
    "grafana_url",
    "wazuh_worker_hostname",
    "repo_url",
    "repo_username",
    "repo_password",
    "windows_edr_installer",
    "wazuh_domain",
];

/// The fields with a default (`None`): the EDR repo settings.
pub const SETTINGS_DEFAULTED: &[&str] = &[
    "repo_url",
    "repo_username",
    "repo_password",
    "windows_edr_installer",
    "wazuh_domain",
];

/// One `customer_provisioning_default_settings` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct SettingsRow {
    /// `id`.
    pub id: i32,
    /// `cluster_name`.
    pub cluster_name: String,
    /// `cluster_key`.
    pub cluster_key: String,
    /// `master_ip`.
    pub master_ip: String,
    /// `grafana_url`.
    pub grafana_url: String,
    /// `wazuh_worker_hostname`.
    pub wazuh_worker_hostname: String,
    /// `repo_url`.
    pub repo_url: Option<String>,
    /// `repo_username`.
    pub repo_username: Option<String>,
    /// `repo_password`.
    pub repo_password: Option<String>,
    /// `windows_edr_installer`.
    pub windows_edr_installer: Option<String>,
    /// `wazuh_domain`.
    pub wazuh_domain: Option<String>,
}

impl SettingsRow {
    /// The table model's dump.
    pub fn dump(&self) -> PyValue {
        PyValue::Dict(vec![
            ("id".into(), int(Some(self.id))),
            ("cluster_name".into(), s(&self.cluster_name)),
            ("cluster_key".into(), s(&self.cluster_key)),
            ("master_ip".into(), s(&self.master_ip)),
            ("grafana_url".into(), s(&self.grafana_url)),
            (
                "wazuh_worker_hostname".into(),
                s(&self.wazuh_worker_hostname),
            ),
            ("repo_url".into(), opt(&self.repo_url)),
            ("repo_username".into(), opt(&self.repo_username)),
            ("repo_password".into(), opt(&self.repo_password)),
            (
                "windows_edr_installer".into(),
                opt(&self.windows_edr_installer),
            ),
            ("wazuh_domain".into(), opt(&self.wazuh_domain)),
        ])
    }
}

fn settings_select() -> String {
    format!(
        "SELECT {} FROM customer_provisioning_default_settings",
        SETTINGS_COLUMNS.join(", ")
    )
}

/// `select(CustomerProvisioningDefaultSettings)` → `.first()`.
pub async fn first_settings(pool: &Db) -> Result<Option<SettingsRow>, PyExc> {
    let rows: Vec<SettingsRow> = sqlx::query_as(&settings_select())
        .fetch_all(pool.pool())
        .await
        .map_err(db)?;
    Ok(rows.into_iter().next())
}

/// A value as PyMySQL renders it into a statement: `None` is an unrenderable
/// container (a list or a dict, which fail in MySQL).
fn bind_value<'q>(
    q: Query<'q, MySql, MySqlArguments>,
    v: &PyValue,
) -> Option<Query<'q, MySql, MySqlArguments>> {
    Some(match v {
        PyValue::None => q.bind(Option::<String>::None),
        PyValue::Bool(b) => q.bind(*b),
        PyValue::Int(i) => match i.parse::<i64>() {
            Ok(n) => q.bind(n),
            Err(_) => q.bind(i.clone()),
        },
        PyValue::Float(f) => q.bind(*f),
        PyValue::Str(s) => q.bind(s.clone()),
        // `escape_sequence`: `('k')` is a scalar to MySQL; more items (or
        // none) are a row it refuses, and a dict cannot be rendered at all.
        PyValue::List(items) => match items.as_slice() {
            [one] if !matches!(one, PyValue::List(_) | PyValue::Dict(_)) => {
                return bind_value(q, one);
            }
            _ => return None,
        },
        PyValue::Dict(_) => return None,
    })
}

fn unrenderable() -> PyExc {
    PyExc::Other(
        "ProgrammingError",
        "Operand should contain 1 column(s)".into(),
    )
}

/// `select(...).where(id == value)` → `.first()` (`None` is `IS NULL`).
pub async fn settings_by_id(pool: &Db, id: &PyValue) -> Result<Option<SettingsRow>, PyExc> {
    if let PyValue::None = id {
        let rows: Vec<SettingsRow> = sqlx::query_as(&format!(
            "{} WHERE customer_provisioning_default_settings.id IS NULL",
            settings_select()
        ))
        .fetch_all(pool.pool())
        .await
        .map_err(db)?;
        return Ok(rows.into_iter().next());
    }
    let sql = format!(
        "{} WHERE customer_provisioning_default_settings.id = ?",
        settings_select()
    );
    let q = bind_value(sqlx::query(&sql), id).ok_or_else(unrenderable)?;
    let rows = q.fetch_all(pool.pool()).await.map_err(db)?;
    rows.iter()
        .map(SettingsRow::from_row)
        .next()
        .transpose()
        .map_err(db)
}

/// `session.add(settings)` + commit: the `id` MySQL gave (when none was set).
pub async fn insert_settings(pool: &Db, fields: &[(&str, PyValue)]) -> Result<u64, PyExc> {
    let set: Vec<&(&str, PyValue)> = fields
        .iter()
        .filter(|(k, v)| !(*k == "id" && matches!(v, PyValue::None)))
        .collect();
    let sql = format!(
        "INSERT INTO customer_provisioning_default_settings ({}) VALUES ({})",
        set.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", "),
        vec!["?"; set.len()].join(", ")
    );
    let mut q = sqlx::query(&sql);
    for (_, v) in &set {
        q = bind_value(q, v).ok_or_else(unrenderable)?;
    }
    Ok(q.execute(pool.pool()).await.map_err(db)?.last_insert_id())
}

/// The changed fields' `UPDATE` on the row `id`.
pub async fn update_settings(pool: &Db, id: i32, fields: &[(&str, PyValue)]) -> Result<(), PyExc> {
    if fields.is_empty() {
        return Ok(());
    }
    let sql = format!(
        "UPDATE customer_provisioning_default_settings SET {} WHERE \
         customer_provisioning_default_settings.id = ?",
        fields
            .iter()
            .map(|(k, _)| format!("{k} = ?"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut q = sqlx::query(&sql);
    for (_, v) in fields {
        q = bind_value(q, v).ok_or_else(unrenderable)?;
    }
    q.bind(id).execute(pool.pool()).await.map_err(db)?;
    Ok(())
}

/// `session.delete(settings)` + commit.
pub async fn delete_settings(pool: &Db, id: i32) -> Result<(), PyExc> {
    sqlx::query(
        "DELETE FROM customer_provisioning_default_settings WHERE \
         customer_provisioning_default_settings.id = ?",
    )
    .bind(id)
    .execute(pool.pool())
    .await
    .map_err(db)?;
    Ok(())
}
