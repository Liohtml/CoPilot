//! `user_passkey` and `webauthn_challenge` (`app/auth/models/passkey.py`,
//! `app/auth/services/passkey.py`).
//!
//! A challenge is consumed under a row lock, so two verifications of one
//! challenge cannot both pass (Python reads, checks and deletes in three
//! statements). The comparisons that Python runs in SQL stay in SQL: a
//! credential id matches under the column's collation, as it does there.

use chrono::NaiveDateTime;
use serde_json::Value;
use sqlx::FromRow;

use crate::schema::TableRequirement;
use crate::{Db, DbError};

/// Columns this module needs.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "user_passkey",
        columns: &[
            "id",
            "user_id",
            "credential_id",
            "public_key",
            "sign_count",
            "transports",
            "device_name",
            "created_at",
            "last_used_at",
        ],
    },
    TableRequirement {
        table: "webauthn_challenge",
        columns: &[
            "token",
            "challenge",
            "user_id",
            "flow",
            "expires_at",
            "created_at",
        ],
    },
];

/// One `user_passkey` row.
#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct PasskeyRow {
    /// Primary key.
    pub id: i32,
    /// Owner.
    pub user_id: i32,
    /// base64url credential id.
    pub credential_id: String,
    /// base64url COSE key.
    pub public_key: String,
    /// Last signature counter.
    pub sign_count: i32,
    /// Transports as the browser reported them.
    pub transports: sqlx::types::Json<Value>,
    /// Label.
    pub device_name: String,
    /// Registration time (naive UTC).
    pub created_at: NaiveDateTime,
    /// Last login with it.
    pub last_used_at: Option<NaiveDateTime>,
}

const COLS: &str = "id, user_id, credential_id, public_key, sign_count, transports, device_name, \
                    created_at, last_used_at";

/// `list_user_passkeys`: newest first.
pub async fn list_for_user(db: &Db, user_id: i32) -> Result<Vec<PasskeyRow>, DbError> {
    let rows = sqlx::query_as::<_, PasskeyRow>(&format!(
        "SELECT {COLS} FROM user_passkey WHERE user_id = ? ORDER BY created_at DESC"
    ))
    .bind(user_id)
    .fetch_all(db.pool())
    .await?;
    Ok(rows)
}

/// `get_passkey_by_credential_id`.
pub async fn find_by_credential_id(
    db: &Db,
    credential_id: &str,
) -> Result<Option<PasskeyRow>, DbError> {
    let row = sqlx::query_as::<_, PasskeyRow>(&format!(
        "SELECT {COLS} FROM user_passkey WHERE credential_id = ? LIMIT 1"
    ))
    .bind(credential_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// `delete_user_passkey`: `false` when the user has no such passkey.
pub async fn delete_for_user(db: &Db, user_id: i32, passkey_id: i64) -> Result<bool, DbError> {
    let res = sqlx::query("DELETE FROM user_passkey WHERE id = ? AND user_id = ?")
        .bind(passkey_id)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(res.rows_affected() > 0)
}

/// A new passkey. `None` when the credential id is already registered.
#[allow(clippy::too_many_arguments)]
pub async fn insert(
    db: &Db,
    user_id: i32,
    credential_id: &str,
    public_key: &str,
    sign_count: i64,
    transports: &Value,
    device_name: &str,
) -> Result<Option<i32>, DbError> {
    if find_by_credential_id(db, credential_id).await?.is_some() {
        return Ok(None);
    }
    let res = sqlx::query(
        "INSERT INTO user_passkey \
         (user_id, credential_id, public_key, sign_count, transports, device_name, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(credential_id)
    .bind(public_key)
    .bind(sign_count)
    .bind(sqlx::types::Json(transports))
    .bind(device_name)
    .bind(copilot_core::time::now_utc_naive())
    .execute(db.pool())
    .await?;
    Ok(i32::try_from(res.last_insert_id()).ok())
}

/// After a login: the new counter and `last_used_at`. `false` when the row
/// is gone ("Passkey no longer exists.").
pub async fn record_use(db: &Db, id: i32, sign_count: i64) -> Result<bool, DbError> {
    let res = sqlx::query("UPDATE user_passkey SET sign_count = ?, last_used_at = ? WHERE id = ?")
        .bind(sign_count)
        .bind(copilot_core::time::now_utc_naive())
        .bind(id)
        .execute(db.pool())
        .await?;
    if res.rows_affected() > 0 {
        return Ok(true);
    }
    let exists: Option<i32> = sqlx::query_scalar("SELECT id FROM user_passkey WHERE id = ?")
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    Ok(exists.is_some())
}

/// `_store_challenge`: purge expired challenges, then store this one.
pub async fn store_challenge(
    db: &Db,
    token: &str,
    challenge_b64: &str,
    flow: &str,
    user_id: Option<i32>,
    expires_at: NaiveDateTime,
) -> Result<(), DbError> {
    let now = copilot_core::time::now_utc_micros();
    let mut tx = db.pool().begin().await?;
    sqlx::query("DELETE FROM webauthn_challenge WHERE expires_at < ?")
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO webauthn_challenge (token, challenge, user_id, flow, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(token)
    .bind(challenge_b64)
    .bind(user_id)
    .bind(flow)
    .bind(expires_at)
    .bind(copilot_core::time::now_utc_naive())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Why `_consume_challenge` refused (its `ValueError` texts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    /// No such token (or already used).
    NotFound,
    /// Registration token used for a login, or the reverse.
    WrongFlow,
    /// Past `expires_at` (the row is deleted).
    Expired,
    /// Issued to another user (the row is kept).
    WrongUser,
}

impl ChallengeError {
    /// The message Python raises.
    pub fn message(self) -> &'static str {
        match self {
            ChallengeError::NotFound => "Challenge not found or already used.",
            ChallengeError::WrongFlow => "Invalid challenge flow.",
            ChallengeError::Expired => "Challenge has expired. Please try again.",
            ChallengeError::WrongUser => "Challenge does not match the authenticated user.",
        }
    }
}

/// `_consume_challenge(token, flow, user_id)`: the stored base64url
/// challenge, deleted in the same transaction that read it.
pub async fn consume_challenge(
    db: &Db,
    token: &str,
    flow: &str,
    user_id: Option<i32>,
) -> Result<Result<String, ChallengeError>, DbError> {
    let mut tx = db.pool().begin().await?;
    let row: Option<(String, Option<i32>, String, NaiveDateTime)> = sqlx::query_as(
        "SELECT challenge, user_id, flow, expires_at FROM webauthn_challenge \
         WHERE token = ? FOR UPDATE",
    )
    .bind(token)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((challenge, owner, stored_flow, expires_at)) = row else {
        return Ok(Err(ChallengeError::NotFound));
    };
    if stored_flow != flow {
        return Ok(Err(ChallengeError::WrongFlow));
    }
    let expired = expires_at < copilot_core::time::now_utc_micros();
    if !expired && user_id.is_some() && owner != user_id {
        return Ok(Err(ChallengeError::WrongUser));
    }
    sqlx::query("DELETE FROM webauthn_challenge WHERE token = ?")
        .bind(token)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if expired {
        return Ok(Err(ChallengeError::Expired));
    }
    Ok(Ok(challenge))
}
