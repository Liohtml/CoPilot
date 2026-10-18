//! `ensure_admin_user`, `ensure_scheduler_user` and, when the process stops,
//! `ensure_scheduler_user_removed` (`app/auth/services/universal.py`).

use copilot_core::time::now_utc_naive;
use copilot_db::Db;
use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;

use crate::catalog::SystemUser;
use crate::seed::SeedError;

/// `Password.generate(length)`: one lower-case letter, one upper-case, one
/// digit and one of `@$!%*?&#`, the rest from all four, shuffled with the
/// system's randomness.
pub fn generate_password(length: usize) -> String {
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const SPECIAL: &[u8] = b"@$!%*?&#";
    let pick = |set: &[u8]| char::from(set[OsRng.gen_range(0..set.len())]);
    let alphabet: Vec<u8> = [LOWER, UPPER, DIGITS, SPECIAL].concat();
    let mut chars = vec![pick(LOWER), pick(UPPER), pick(DIGITS), pick(SPECIAL)];
    chars.extend((4..length.max(4)).map(|_| pick(&alphabet)));
    chars.shuffle(&mut OsRng);
    chars.into_iter().collect()
}

/// `create_admin_user` / `create_scheduler_user`: the user inserted with a
/// fresh bcrypt password when no user has its name. Returns the password
/// when it was created.
pub async fn ensure_user(db: &Db, user: &SystemUser) -> Result<Option<String>, SeedError> {
    let step = if user.role_id == 1 {
        "ensure_admin_user"
    } else {
        "ensure_scheduler_user"
    };
    let fail = |e: sqlx::Error| SeedError {
        step,
        message: e.to_string(),
    };
    let mut tx = db.pool().begin().await.map_err(fail)?;
    let found: Option<i64> = sqlx::query_scalar("SELECT id FROM `user` WHERE username = ? LIMIT 1")
        .bind(user.username)
        .fetch_optional(&mut *tx)
        .await
        .map_err(fail)?;
    if found.is_some() {
        tracing::info!(
            "{} user already exists.",
            if user.role_id == 1 {
                "Admin"
            } else {
                "Scheduler"
            }
        );
        return Ok(None);
    }
    let plain = generate_password(user.password_length);
    let hashed = copilot_auth::password::hash_password(&plain).map_err(|e| SeedError {
        step,
        message: e.to_string(),
    })?;
    sqlx::query(
        "INSERT INTO `user` (username, password, email, created_at, role_id, last_login_at) \
         VALUES (?, ?, ?, ?, ?, NULL)",
    )
    .bind(user.username)
    .bind(&hashed)
    .bind(user.email)
    .bind(now_utc_naive())
    .bind(user.role_id)
    .execute(&mut *tx)
    .await
    .map_err(fail)?;
    tx.commit().await.map_err(fail)?;
    Ok(Some(plain))
}

/// `remove_scheduler_user`: the first user named `scheduler` deleted.
/// Whether one was.
pub async fn remove_scheduler_user(db: &Db) -> Result<bool, sqlx::Error> {
    let mut tx = db.pool().begin().await?;
    let id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM `user` WHERE username = 'scheduler' LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    let Some(id) = id else {
        tracing::info!("Scheduler user does not exist.");
        return Ok(false);
    };
    sqlx::query("DELETE FROM `user` WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!("Scheduler user removed.");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_have_every_class_and_the_length() {
        for len in [12, 24] {
            for _ in 0..50 {
                let p = generate_password(len);
                assert_eq!(p.len(), len);
                assert!(p.bytes().any(|b| b.is_ascii_lowercase()));
                assert!(p.bytes().any(|b| b.is_ascii_uppercase()));
                assert!(p.bytes().any(|b| b.is_ascii_digit()));
                assert!(p.bytes().any(|b| b"@$!%*?&#".contains(&b)));
                assert!(
                    p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"@$!%*?&#".contains(&b))
                );
            }
        }
    }
}
