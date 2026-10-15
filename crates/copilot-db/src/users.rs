//! `user` and `user_customer_access` — the reads the auth layer needs
//! (`app/auth/services/universal.py:find_user`,
//! `CustomerAccessHandler.get_user_accessible_customers`).

use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::schema::TableRequirement;
use crate::{Db, DbError};

/// Columns user management writes beyond `schema::CORE_REQUIREMENTS`.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "user",
        columns: &["password", "created_at"],
    },
    TableRequirement {
        table: "user_customer_access",
        columns: &["created_at"],
    },
];

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

/// `find_user` for a login: the first matching row and its password hash.
pub async fn find_credentials(
    db: &Db,
    username: &str,
) -> Result<Option<(UserRow, String)>, DbError> {
    #[derive(FromRow)]
    struct Row {
        #[sqlx(flatten)]
        user: UserRow,
        password: String,
    }
    let row = sqlx::query_as::<_, Row>(
        "SELECT id, username, email, role_id, created_at, last_login_at, password \
         FROM `user` WHERE username = ? ORDER BY id LIMIT 1",
    )
    .bind(username)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.map(|r| (r.user, r.password)))
}

/// `role.name` for a role id (`get_role`).
pub async fn role_name(db: &Db, role_id: i32) -> Result<Option<String>, DbError> {
    let name = sqlx::query_scalar::<_, String>("SELECT name FROM role WHERE id = ?")
        .bind(role_id)
        .fetch_optional(db.pool())
        .await?;
    Ok(name)
}

/// `update_last_login`: stamp the last successful login (naive UTC).
pub async fn touch_last_login(db: &Db, user_id: i32) -> Result<(), DbError> {
    sqlx::query("UPDATE `user` SET last_login_at = ? WHERE id = ?")
        .bind(copilot_core::time::now_utc_naive())
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// `select_all_users(search, limit)`: no `ORDER BY`, like the Python query,
/// so MySQL returns the rows in the same order; `search` is a case-insensitive
/// `LIKE` over username and email (its `%`/`_` act as wildcards there too).
pub async fn list_users(
    db: &Db,
    search: Option<&str>,
    limit: Option<i64>,
) -> Result<Vec<UserRow>, DbError> {
    let mut sql =
        String::from("SELECT id, username, email, role_id, created_at, last_login_at FROM `user`");
    let search = search.filter(|s| !s.is_empty()).map(|s| format!("%{s}%"));
    if search.is_some() {
        sql.push_str(" WHERE (lower(username) LIKE lower(?) OR lower(email) LIKE lower(?))");
    }
    if limit.is_some() {
        sql.push_str(" LIMIT ?");
    }
    let mut q = sqlx::query_as::<_, UserRow>(&sql);
    if let Some(term) = &search {
        q = q.bind(term).bind(term);
    }
    if let Some(limit) = limit {
        q = q.bind(limit);
    }
    Ok(q.fetch_all(db.pool()).await?)
}

/// Every role's name by id.
pub async fn role_names(db: &Db) -> Result<std::collections::HashMap<i32, String>, DbError> {
    let rows = sqlx::query_as::<_, (i32, String)>("SELECT id, name FROM role")
        .fetch_all(db.pool())
        .await?;
    Ok(rows.into_iter().collect())
}

/// `(user_id, customer_code)` for these users.
pub async fn assignments_of(db: &Db, user_ids: &[i32]) -> Result<Vec<(i32, String)>, DbError> {
    if user_ids.is_empty() {
        return Ok(Vec::new());
    }
    let marks = vec!["?"; user_ids.len()].join(", ");
    let sql = format!(
        "SELECT user_id, customer_code FROM user_customer_access WHERE user_id IN ({marks})"
    );
    let mut q = sqlx::query_as::<_, (i32, String)>(&sql);
    for id in user_ids {
        q = q.bind(id);
    }
    Ok(q.fetch_all(db.pool()).await?)
}

/// Every `(username, email)`: registration compares them exactly, as Python
/// does in memory (MySQL's comparison would ignore case and trailing spaces).
pub async fn usernames_and_emails(db: &Db) -> Result<Vec<(String, String)>, DbError> {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT username, email FROM `user`")
        .fetch_all(db.pool())
        .await?;
    Ok(rows)
}

/// The stored codes among `codes` (`WHERE customer_code IN (…)`: MySQL's
/// collation decides the match, the caller compares exactly).
pub async fn existing_customer_codes(db: &Db, codes: &[String]) -> Result<Vec<String>, DbError> {
    if codes.is_empty() {
        return Ok(Vec::new());
    }
    let marks = vec!["?"; codes.len()].join(", ");
    let sql = format!("SELECT customer_code FROM customers WHERE customer_code IN ({marks})");
    let mut q = sqlx::query_scalar::<_, String>(&sql);
    for code in codes {
        q = q.bind(code);
    }
    Ok(q.fetch_all(db.pool()).await?)
}

async fn replace_assignment_in(
    tx: &mut sqlx::Transaction<'static, sqlx::MySql>,
    user_id: i32,
    codes: &[String],
) -> Result<(), DbError> {
    sqlx::query("DELETE FROM user_customer_access WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    let now = copilot_core::time::now_utc_naive();
    for code in codes {
        sqlx::query(
            "INSERT INTO user_customer_access (user_id, customer_code, created_at) VALUES (?, ?, ?)",
        )
        .bind(user_id)
        .bind(code)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// A new user and their customers, in one transaction; returns the id.
pub async fn create_user(
    db: &Db,
    username: &str,
    password_hash: &str,
    email: &str,
    role_id: i32,
    codes: &[String],
) -> Result<i32, DbError> {
    let mut tx = db.pool().begin().await?;
    let res = sqlx::query(
        "INSERT INTO `user` (username, password, email, created_at, role_id) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(username)
    .bind(password_hash)
    .bind(email)
    .bind(copilot_core::time::now_utc_naive())
    .bind(role_id)
    .execute(&mut *tx)
    .await?;
    let id = i32::try_from(res.last_insert_id())
        .map_err(|_| DbError::Config("user id out of range".into()))?;
    replace_assignment_in(&mut tx, id, codes).await?;
    tx.commit().await?;
    Ok(id)
}

/// Replace a user's customers (`replace_assignment` + commit).
pub async fn replace_assignment(db: &Db, user_id: i32, codes: &[String]) -> Result<(), DbError> {
    let mut tx = db.pool().begin().await?;
    replace_assignment_in(&mut tx, user_id, codes).await?;
    tx.commit().await?;
    Ok(())
}

/// Change a user's role, and their customers when `codes` is given.
pub async fn set_role(
    db: &Db,
    user_id: i32,
    role_id: i32,
    codes: Option<&[String]>,
) -> Result<(), DbError> {
    let mut tx = db.pool().begin().await?;
    sqlx::query("UPDATE `user` SET role_id = ? WHERE id = ?")
        .bind(role_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if let Some(codes) = codes {
        replace_assignment_in(&mut tx, user_id, codes).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Store a new password hash.
pub async fn set_password(db: &Db, user_id: i32, password_hash: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE `user` SET password = ? WHERE id = ?")
        .bind(password_hash)
        .bind(user_id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// `delete_user`: the user's customer rows, then the user, in one
/// transaction (a row elsewhere still pointing at the user fails it whole).
pub async fn delete_user(db: &Db, user_id: i32) -> Result<(), DbError> {
    let mut tx = db.pool().begin().await?;
    sqlx::query("DELETE FROM user_customer_access WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM `user` WHERE id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// The stored password hash of a user.
pub async fn password_hash(db: &Db, user_id: i32) -> Result<Option<String>, DbError> {
    let hash = sqlx::query_scalar::<_, String>("SELECT password FROM `user` WHERE id = ?")
        .bind(user_id)
        .fetch_optional(db.pool())
        .await?;
    Ok(hash)
}
