//! `user_totp` — one row per user who started 2FA enrolment
//! (`app/auth/models/totp.py`, `app/auth/services/totp.py`).
//!
//! `secret_enc` is a Fernet token, `backup_codes` a JSON list of
//! `{"hash": <bcrypt>, "used": bool}`, `last_used_at` the TOTP counter of the
//! last accepted code. The writes Python makes read-then-write are guarded
//! here: a counter is claimed with `last_used_at < ?` so one code cannot log
//! in twice concurrently, and a backup code is spent under a row lock.

use serde_json::Value;
use sqlx::FromRow;

use crate::schema::TableRequirement;
use crate::{Db, DbError};

/// Columns this module needs.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "user_totp",
        columns: &[
            "id",
            "user_id",
            "secret_enc",
            "enabled",
            "backup_codes",
            "last_used_at",
            "created_at",
        ],
    },
    TableRequirement {
        table: "role",
        columns: &["id", "name"],
    },
    TableRequirement {
        table: "user",
        columns: &["password"],
    },
];

/// One `user_totp` row.
#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct UserTotpRow {
    /// Primary key.
    pub id: i32,
    /// The user.
    pub user_id: i32,
    /// Fernet-encrypted base32 secret.
    pub secret_enc: String,
    /// Verified and active.
    pub enabled: bool,
    /// `[{"hash", "used"}]`.
    pub backup_codes: sqlx::types::Json<Value>,
    /// Counter of the last accepted code.
    pub last_used_at: Option<i64>,
}

const COLS: &str = "id, user_id, secret_enc, enabled, backup_codes, last_used_at";

/// `get_user_totp`.
pub async fn find(db: &Db, user_id: i32) -> Result<Option<UserTotpRow>, DbError> {
    let row = sqlx::query_as::<_, UserTotpRow>(&format!(
        "SELECT {COLS} FROM user_totp WHERE user_id = ? LIMIT 1"
    ))
    .bind(user_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// `is_2fa_enabled`.
pub async fn is_enabled(db: &Db, user_id: i32) -> Result<bool, DbError> {
    Ok(find(db, user_id).await?.is_some_and(|r| r.enabled))
}

/// `setup_totp`'s write: a fresh, not yet enabled secret and codes. `false`
/// when 2FA is already enabled (nothing written).
pub async fn save_setup(
    db: &Db,
    user_id: i32,
    secret_enc: &str,
    backup_codes: &Value,
) -> Result<bool, DbError> {
    let mut tx = db.pool().begin().await?;
    let existing = sqlx::query_as::<_, (i32, bool)>(
        "SELECT id, enabled FROM user_totp WHERE user_id = ? FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    match existing {
        Some((_, true)) => {
            tx.rollback().await?;
            return Ok(false);
        }
        Some((id, false)) => {
            sqlx::query(
                "UPDATE user_totp SET secret_enc = ?, backup_codes = ?, enabled = 0, \
                 last_used_at = NULL WHERE id = ?",
            )
            .bind(secret_enc)
            .bind(sqlx::types::Json(backup_codes))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query(
                "INSERT INTO user_totp (user_id, secret_enc, enabled, backup_codes, \
                 last_used_at, created_at) VALUES (?, ?, 0, ?, NULL, ?)",
            )
            .bind(user_id)
            .bind(secret_enc)
            .bind(sqlx::types::Json(backup_codes))
            .bind(copilot_core::time::now_utc_naive())
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

/// `verify_setup`'s write: enable, starting the replay guard at `counter`.
/// `false` when the row is gone or already enabled.
pub async fn enable(db: &Db, id: i32, counter: i64) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE user_totp SET enabled = 1, last_used_at = ? WHERE id = ? AND enabled = 0",
    )
    .bind(counter)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Accept a code for `counter`: `false` when that counter (or a later one)
/// was already used — Python's replay check, without its read-then-write race.
pub async fn claim_counter(db: &Db, id: i32, counter: i64) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE user_totp SET last_used_at = ? \
         WHERE id = ? AND enabled = 1 AND (last_used_at IS NULL OR last_used_at < ?)",
    )
    .bind(counter)
    .bind(id)
    .bind(counter)
    .execute(db.pool())
    .await?;
    Ok(res.rows_affected() == 1)
}

/// The outcome of [`spend_backup_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupSpend<E> {
    /// No row, or 2FA not enabled.
    NotEnabled,
    /// No unused code matched.
    NoMatch,
    /// This index matched and is now marked used.
    Spent(usize),
    /// The matcher failed.
    Failed(E),
}

/// Spend a backup code under a lock on the row: `pick` gets the stored list
/// and returns the index of the code it matched, which is then marked
/// `"used": true` (other keys of the entry are kept).
pub async fn spend_backup_code<E, F, Fut>(
    db: &Db,
    user_id: i32,
    pick: F,
) -> Result<BackupSpend<E>, DbError>
where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = Result<Option<usize>, E>>,
{
    let mut tx = db.pool().begin().await?;
    let row = sqlx::query_as::<_, UserTotpRow>(&format!(
        "SELECT {COLS} FROM user_totp WHERE user_id = ? LIMIT 1 FOR UPDATE"
    ))
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row.filter(|r| r.enabled) else {
        tx.rollback().await?;
        return Ok(BackupSpend::NotEnabled);
    };
    let mut codes = row.backup_codes.0;
    let index = match pick(codes.clone()).await {
        Ok(Some(index)) => index,
        Ok(None) => {
            tx.rollback().await?;
            return Ok(BackupSpend::NoMatch);
        }
        Err(e) => {
            tx.rollback().await?;
            return Ok(BackupSpend::Failed(e));
        }
    };
    if let Some(entry) = codes.get_mut(index).and_then(Value::as_object_mut) {
        entry.insert("used".into(), Value::Bool(true));
    }
    sqlx::query("UPDATE user_totp SET backup_codes = ? WHERE id = ?")
        .bind(sqlx::types::Json(&codes))
        .bind(row.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(BackupSpend::Spent(index))
}

/// `regenerate_backup_codes`'s write.
pub async fn replace_backup_codes(db: &Db, id: i32, codes: &Value) -> Result<(), DbError> {
    sqlx::query("UPDATE user_totp SET backup_codes = ? WHERE id = ?")
        .bind(sqlx::types::Json(codes))
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// `disable_totp`'s write.
pub async fn delete(db: &Db, user_id: i32) -> Result<(), DbError> {
    sqlx::query("DELETE FROM user_totp WHERE user_id = ?")
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(())
}
