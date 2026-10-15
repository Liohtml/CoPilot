//! `user` and `user_customer_access` — the reads the auth layer needs
//! (`app/auth/services/universal.py:find_user`,
//! `CustomerAccessHandler.get_user_accessible_customers`).

use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::{Db, DbError};

/// A `user` row without its password hash.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct UserRow {
    /// Primary key.
    pub id: i32,
    /// Login name (not unique in the schema; the first match wins).
    pub username: String,
    /// Email address.
    pub email: String,
    /// FK to `role.id`; `NULL` for a user without a role.
    pub role_id: Option<i32>,
    /// Creation time (naive UTC).
    pub created_at: NaiveDateTime,
    /// Last successful login (naive UTC).
    pub last_login_at: Option<NaiveDateTime>,
}

/// `find_user(username)`: the comparison runs in SQL, so MySQL's
/// case-insensitive, PAD SPACE collation decides exactly as it does for the
/// Python backend.
pub async fn find_by_username(db: &Db, username: &str) -> Result<Option<UserRow>, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, email, role_id, created_at, last_login_at \
         FROM `user` WHERE username = ? ORDER BY id LIMIT 1",
    )
    .bind(username)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// A user by id.
pub async fn find_by_id(db: &Db, id: i32) -> Result<Option<UserRow>, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, email, role_id, created_at, last_login_at \
         FROM `user` WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await?;
    Ok(row)
}

/// The customer codes assigned to a user, in row order.
pub async fn assigned_customer_codes(db: &Db, user_id: i32) -> Result<Vec<String>, DbError> {
    let codes = sqlx::query_scalar::<_, String>(
        "SELECT customer_code FROM user_customer_access WHERE user_id = ? ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(db.pool())
    .await?;
    Ok(codes)
}
