//! The startup lock: one MySQL named lock per database that every CoPilot
//! process takes before it changes the schema or seeds the startup rows.
//!
//! The Python backend takes the same lock around `apply_migrations()` and its
//! seeding (`backend/app/db/startup_lock.py`; the name is computed by MySQL on
//! both sides), so two processes starting against one database — Rust and
//! Python next to each other, or two Rust instances — run those steps one
//! after the other: an empty database gets one schema and one set of rows,
//! whichever process is first. MySQL drops the lock with the connection, so a
//! process that dies holding it strands nothing.

use std::time::Duration;

use sqlx::mysql::{MySqlConnectOptions, MySqlConnection};
use sqlx::{ConnectOptions, Connection};

/// The lock's name, computed by MySQL (`copilot_startup:` and the SHA-1 of
/// the database name: 56 characters, MySQL allows 64).
pub const LOCK_NAME_SQL: &str = "CONCAT('copilot_startup:', SHA1(DATABASE()))";

/// How long a process waits for another one's startup (Alembic's run from an
/// empty database takes a minute or two on a slow host).
pub const DEFAULT_WAIT: Duration = Duration::from_secs(600);

/// Why the lock was not taken.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Another process held it for the whole wait.
    #[error(
        "another CoPilot process (Rust or Python) held the startup lock of this database for {0} s: \
         it is migrating or seeding it, or hangs doing so — stop it, or start this one again later"
    )]
    Timeout(u64),
    /// The connection or the statement failed.
    #[error("startup lock: {0}")]
    Db(#[from] sqlx::Error),
}

/// The lock, held by a connection of its own (which the migrations run on).
#[derive(Debug)]
pub struct StartupLock {
    conn: MySqlConnection,
}

impl StartupLock {
    /// Connect and take the lock, waiting up to `wait`.
    pub async fn acquire(options: &MySqlConnectOptions, wait: Duration) -> Result<Self, LockError> {
        let conn = options.connect().await?;
        Self::acquire_on(conn, wait).await
    }

    /// Take the lock on an open connection.
    pub async fn acquire_on(mut conn: MySqlConnection, wait: Duration) -> Result<Self, LockError> {
        let secs = i64::try_from(wait.as_secs()).unwrap_or(i64::MAX);
        let got: Option<i64> = sqlx::query_scalar(&format!("SELECT GET_LOCK({LOCK_NAME_SQL}, ?)"))
            .bind(secs)
            .fetch_one(&mut conn)
            .await?;
        if got == Some(1) {
            Ok(Self { conn })
        } else {
            Err(LockError::Timeout(wait.as_secs()))
        }
    }

    /// The connection holding the lock.
    pub fn conn(&mut self) -> &mut MySqlConnection {
        &mut self.conn
    }

    /// Release the lock and close the connection.
    pub async fn release(mut self) {
        let released: Result<Option<i64>, sqlx::Error> =
            sqlx::query_scalar(&format!("SELECT RELEASE_LOCK({LOCK_NAME_SQL})"))
                .fetch_one(&mut self.conn)
                .await;
        if let Err(e) = released {
            tracing::warn!(err = %e, "cannot release the startup lock; closing its connection");
        }
        let _ = self.conn.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_python_backend_takes_the_same_lock_around_the_same_steps() {
        let lock = include_str!("../../../backend/app/db/startup_lock.py");
        assert!(lock.contains(&format!("LOCK_NAME_SQL = \"{LOCK_NAME_SQL}\"")));
        assert!(lock.contains(&format!(
            "STARTUP_LOCK_WAIT_SECONDS = {}",
            DEFAULT_WAIT.as_secs()
        )));
        // copilot.py: taken before the migrations, released after the
        // scheduler rows (`init_scheduler()`).
        let lifespan = include_str!("../../../backend/copilot.py");
        let at = |needle: &str| lifespan.find(needle).expect(needle);
        assert!(at("StartupLock.acquire()") < at("    apply_migrations()"));
        assert!(at("await init_scheduler()") < at("startup_lock.release()"));
        assert!(at("await ensure_default_portal_settings(") < at("startup_lock.release()"));
    }
}
