//! `customer_waf_instances` — the rows and the statements the Python service
//! issues (`CustomerWafInstance` in `app/db/universal_models.py`).

use chrono::NaiveDateTime;
use copilot_db::{Db, DbError};
use sqlx::{FromRow, MySql, QueryBuilder};

/// One `customer_waf_instances` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct WafRow {
    /// `id`.
    pub id: i32,
    /// `customer_code`.
    pub customer_code: String,
    /// `name`.
    pub name: String,
    /// `api_url`.
    pub api_url: String,
    /// `service_token_encrypted` (never returned, never logged).
    pub service_token_encrypted: String,
    /// `token_prefix`.
    pub token_prefix: String,
    /// `verify_tls`.
    pub verify_tls: bool,
    /// `ca_cert_pem`.
    pub ca_cert_pem: Option<String>,
    /// `enabled`.
    pub enabled: bool,
    /// `last_verified_at`.
    pub last_verified_at: Option<NaiveDateTime>,
    /// `last_verified_role`.
    pub last_verified_role: Option<String>,
    /// `created_by`.
    pub created_by: Option<i32>,
    /// `created_at`.
    pub created_at: Option<NaiveDateTime>,
    /// `updated_by`.
    pub updated_by: Option<i32>,
    /// `updated_at`.
    pub updated_at: Option<NaiveDateTime>,
    /// `syslog_host`.
    pub syslog_host: Option<String>,
    /// `syslog_port`.
    pub syslog_port: Option<i32>,
    /// `graylog_input_id`.
    pub graylog_input_id: Option<String>,
    /// `graylog_stream_id`.
    pub graylog_stream_id: Option<String>,
    /// `graylog_index_set_id`.
    pub graylog_index_set_id: Option<String>,
    /// `waf_forwarder_id`.
    pub waf_forwarder_id: Option<String>,
    /// `forwarding_provisioned_at`.
    pub forwarding_provisioned_at: Option<NaiveDateTime>,
}

/// Every column, in the model's order.
pub const COLUMNS: &[&str] = &[
    "id",
    "customer_code",
    "name",
    "api_url",
    "service_token_encrypted",
    "token_prefix",
    "verify_tls",
    "ca_cert_pem",
    "enabled",
    "last_verified_at",
    "last_verified_role",
    "created_by",
    "created_at",
    "updated_by",
    "updated_at",
    "syslog_host",
    "syslog_port",
    "graylog_input_id",
    "graylog_stream_id",
    "graylog_index_set_id",
    "waf_forwarder_id",
    "forwarding_provisioned_at",
];

fn select() -> String {
    format!("SELECT {} FROM customer_waf_instances", COLUMNS.join(", "))
}

/// `session.get(CustomerWafInstance, waf_id)`.
pub async fn get(db: &Db, id: i64) -> Result<Option<WafRow>, DbError> {
    Ok(
        sqlx::query_as::<_, WafRow>(&format!("{} WHERE id = ?", select()))
            .bind(id)
            .fetch_optional(db.pool())
            .await?,
    )
}

/// `list_instances`: one customer's WAFs by name.
pub async fn list_for_customer(db: &Db, code: &str) -> Result<Vec<WafRow>, DbError> {
    Ok(sqlx::query_as::<_, WafRow>(&format!(
        "{} WHERE customer_code = ? ORDER BY name",
        select()
    ))
    .bind(code)
    .fetch_all(db.pool())
    .await?)
}

/// `list_all_instances`: ordered by customer then name; `None` = everyone's.
pub async fn list_all(db: &Db, codes: Option<&[String]>) -> Result<Vec<WafRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(select());
    if let Some(codes) = codes {
        qb.push(" WHERE customer_code IN (");
        let mut sep = qb.separated(", ");
        for c in codes {
            sep.push_bind(c.clone());
        }
        qb.push(")");
    }
    qb.push(" ORDER BY customer_code, name");
    Ok(qb.build_query_as::<WafRow>().fetch_all(db.pool()).await?)
}

/// What `create_instance` inserts.
#[derive(Debug, Clone)]
pub struct NewWaf<'a> {
    /// `customer_code`.
    pub customer_code: &'a str,
    /// `name`.
    pub name: &'a str,
    /// `api_url`.
    pub api_url: &'a str,
    /// `service_token_encrypted`.
    pub service_token_encrypted: &'a str,
    /// `token_prefix`.
    pub token_prefix: &'a str,
    /// `verify_tls`.
    pub verify_tls: bool,
    /// `ca_cert_pem`.
    pub ca_cert_pem: Option<&'a str>,
    /// `enabled`.
    pub enabled: bool,
    /// `created_by`.
    pub created_by: Option<i32>,
    /// `created_at` (`datetime.utcnow()`, MySQL rounds it).
    pub created_at: NaiveDateTime,
}

/// `INSERT` (the unique `(customer_code, name)` violation is the caller's 409).
pub async fn insert(db: &Db, w: &NewWaf<'_>) -> Result<i64, DbError> {
    let res = sqlx::query(
        "INSERT INTO customer_waf_instances (customer_code, name, api_url, \
         service_token_encrypted, token_prefix, verify_tls, ca_cert_pem, enabled, \
         last_verified_at, last_verified_role, created_by, created_at, updated_by, updated_at, \
         syslog_host, syslog_port, graylog_input_id, graylog_stream_id, graylog_index_set_id, \
         waf_forwarder_id, forwarding_provisioned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, \
         ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
    )
    .bind(w.customer_code)
    .bind(w.name)
    .bind(w.api_url)
    .bind(w.service_token_encrypted)
    .bind(w.token_prefix)
    .bind(w.verify_tls)
    .bind(w.ca_cert_pem)
    .bind(w.enabled)
    .bind(w.created_by)
    .bind(w.created_at)
    .execute(db.pool())
    .await?;
    Ok(i64::try_from(res.last_insert_id()).unwrap_or(i64::MAX))
}

/// `update_instance`'s commit: the configuration columns.
pub async fn write_config(db: &Db, r: &WafRow) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE customer_waf_instances SET name = ?, api_url = ?, service_token_encrypted = ?, \
         token_prefix = ?, verify_tls = ?, ca_cert_pem = ?, enabled = ?, last_verified_at = ?, \
         last_verified_role = ?, updated_by = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&r.name)
    .bind(&r.api_url)
    .bind(&r.service_token_encrypted)
    .bind(&r.token_prefix)
    .bind(r.verify_tls)
    .bind(&r.ca_cert_pem)
    .bind(r.enabled)
    .bind(r.last_verified_at)
    .bind(&r.last_verified_role)
    .bind(r.updated_by)
    .bind(r.updated_at)
    .bind(r.id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// `verify_instance`'s commit.
pub async fn write_verified(
    db: &Db,
    id: i32,
    at: NaiveDateTime,
    role: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE customer_waf_instances SET last_verified_at = ?, last_verified_role = ? WHERE \
         id = ?",
    )
    .bind(at)
    .bind(role)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// The forwarding columns (provision and teardown).
pub async fn write_forwarding(db: &Db, r: &WafRow) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE customer_waf_instances SET syslog_host = ?, syslog_port = ?, graylog_input_id = \
         ?, graylog_stream_id = ?, graylog_index_set_id = ?, waf_forwarder_id = ?, \
         forwarding_provisioned_at = ? WHERE id = ?",
    )
    .bind(&r.syslog_host)
    .bind(r.syslog_port)
    .bind(&r.graylog_input_id)
    .bind(&r.graylog_stream_id)
    .bind(&r.graylog_index_set_id)
    .bind(&r.waf_forwarder_id)
    .bind(r.forwarding_provisioned_at)
    .bind(r.id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// `session.delete(row)`.
pub async fn delete(db: &Db, id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM customer_waf_instances WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// `_siblings_forwarding`: another WAF of the customer still forwards.
pub async fn siblings_forwarding(db: &Db, code: &str, id: i32) -> Result<bool, DbError> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM customer_waf_instances WHERE customer_code = ? AND id != ? AND \
         forwarding_provisioned_at IS NOT NULL LIMIT 1",
    )
    .bind(code)
    .bind(id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.is_some())
}

/// `ensure_customer_exists` / `_customer_name`: the first customer row's name.
pub async fn customer_name(db: &Db, code: &str) -> Result<Option<String>, DbError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT customer_name FROM customers WHERE customer_code = ? LIMIT 1")
            .bind(code)
            .fetch_optional(db.pool())
            .await?;
    Ok(row.map(|(n,)| n))
}
