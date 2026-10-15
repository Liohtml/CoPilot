//! `sso_config` (singleton, id 1) and `sso_allowed_email`
//! (`app/auth/models/sso.py`, `app/auth/services/sso.py`).

use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::schema::TableRequirement;
use crate::{Db, DbError};

/// Columns this module needs.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "sso_config",
        columns: &[
            "id",
            "sso_enabled",
            "azure_enabled",
            "azure_tenant_id",
            "azure_client_id",
            "azure_client_secret",
            "azure_redirect_uri",
            "google_enabled",
            "google_client_id",
            "google_client_secret",
            "google_redirect_uri",
            "cf_enabled",
            "cf_team_domain",
            "cf_audience",
            "updated_at",
        ],
    },
    TableRequirement {
        table: "sso_allowed_email",
        columns: &["id", "email", "role_id", "created_at"],
    },
];

/// The `sso_config` row.
#[derive(Debug, Clone, Default, PartialEq, Eq, FromRow)]
pub struct SsoConfigRow {
    /// Global switch.
    pub sso_enabled: bool,
    /// Azure Entra ID.
    pub azure_enabled: bool,
    /// Tenant (directory) id.
    pub azure_tenant_id: Option<String>,
    /// Application (client) id.
    pub azure_client_id: Option<String>,
    /// Client secret.
    pub azure_client_secret: Option<String>,
    /// Registered redirect URI.
    pub azure_redirect_uri: Option<String>,
    /// Google.
    pub google_enabled: bool,
    /// OAuth client id.
    pub google_client_id: Option<String>,
    /// OAuth client secret.
    pub google_client_secret: Option<String>,
    /// Registered redirect URI.
    pub google_redirect_uri: Option<String>,
    /// Cloudflare Access.
    pub cf_enabled: bool,
    /// `<team>.cloudflareaccess.com`.
    pub cf_team_domain: Option<String>,
    /// Application audience (AUD) tag.
    pub cf_audience: Option<String>,
}

const CONFIG_COLS: &str = "sso_enabled, azure_enabled, azure_tenant_id, azure_client_id, \
     azure_client_secret, azure_redirect_uri, google_enabled, google_client_id, \
     google_client_secret, google_redirect_uri, cf_enabled, cf_team_domain, cf_audience";

/// `get_sso_config()`: the row with id 1.
pub async fn config(db: &Db) -> Result<Option<SsoConfigRow>, DbError> {
    let row = sqlx::query_as::<_, SsoConfigRow>(&format!(
        "SELECT {CONFIG_COLS} FROM sso_config WHERE id = 1"
    ))
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// `upsert_sso_config(data)`: every field is written; a secret that is
/// `None` keeps the stored one. Returns the row as stored.
pub async fn upsert_config(db: &Db, new: &SsoConfigRow) -> Result<SsoConfigRow, DbError> {
    let mut tx = db.pool().begin().await?;
    let exists: Option<i32> =
        sqlx::query_scalar("SELECT id FROM sso_config WHERE id = 1 FOR UPDATE")
            .fetch_optional(&mut *tx)
            .await?;
    let now = copilot_core::time::now_utc_naive();
    if exists.is_none() {
        sqlx::query(
            "INSERT INTO sso_config (id, sso_enabled, azure_enabled, google_enabled, cf_enabled, \
             updated_at) VALUES (1, 0, 0, 0, 0, ?)",
        )
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE sso_config SET sso_enabled = ?, azure_enabled = ?, azure_tenant_id = ?, \
         azure_client_id = ?, azure_client_secret = COALESCE(?, azure_client_secret), \
         azure_redirect_uri = ?, google_enabled = ?, google_client_id = ?, \
         google_client_secret = COALESCE(?, google_client_secret), google_redirect_uri = ?, \
         cf_enabled = ?, cf_team_domain = ?, cf_audience = ?, updated_at = ? WHERE id = 1",
    )
    .bind(new.sso_enabled)
    .bind(new.azure_enabled)
    .bind(&new.azure_tenant_id)
    .bind(&new.azure_client_id)
    .bind(&new.azure_client_secret)
    .bind(&new.azure_redirect_uri)
    .bind(new.google_enabled)
    .bind(&new.google_client_id)
    .bind(&new.google_client_secret)
    .bind(&new.google_redirect_uri)
    .bind(new.cf_enabled)
    .bind(&new.cf_team_domain)
    .bind(&new.cf_audience)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query_as::<_, SsoConfigRow>(&format!(
        "SELECT {CONFIG_COLS} FROM sso_config WHERE id = 1"
    ))
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// One `sso_allowed_email` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AllowedEmailRow {
    /// Primary key.
    pub id: i32,
    /// Lower-cased address.
    pub email: String,
    /// Role a new SSO user gets.
    pub role_id: i32,
    /// When it was added (naive UTC).
    pub created_at: NaiveDateTime,
}

/// `list_allowed_emails()`, by id.
pub async fn allowed_emails(db: &Db) -> Result<Vec<AllowedEmailRow>, DbError> {
    let rows = sqlx::query_as::<_, AllowedEmailRow>(
        "SELECT id, email, role_id, created_at FROM sso_allowed_email ORDER BY id",
    )
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// `find_allowed_email(email)` (compared in SQL, under the column's
/// collation).
pub async fn find_allowed_email(db: &Db, email: &str) -> Result<Option<AllowedEmailRow>, DbError> {
    let row = sqlx::query_as::<_, AllowedEmailRow>(
        "SELECT id, email, role_id, created_at FROM sso_allowed_email WHERE email = ? \
         ORDER BY id LIMIT 1",
    )
    .bind(email)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// `add_allowed_email(email, role_id)`; `None` when the address is already
/// listed.
pub async fn add_allowed_email(db: &Db, email: &str, role_id: i64) -> Result<Option<i32>, DbError> {
    if find_allowed_email(db, email).await?.is_some() {
        return Ok(None);
    }
    let res =
        sqlx::query("INSERT INTO sso_allowed_email (email, role_id, created_at) VALUES (?, ?, ?)")
            .bind(email)
            .bind(role_id)
            .bind(copilot_core::time::now_utc_naive())
            .execute(db.pool())
            .await?;
    Ok(i32::try_from(res.last_insert_id()).ok())
}

/// `delete_allowed_email(id)`: `false` when there was no such row.
pub async fn delete_allowed_email(db: &Db, id: i64) -> Result<bool, DbError> {
    let res = sqlx::query("DELETE FROM sso_allowed_email WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(res.rows_affected() > 0)
}
