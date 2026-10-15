//! Connection pool — port of `app/db/db_session.py`.
//!
//! The Python engine runs `pool_size + max_overflow` connections with a
//! pre-ping on checkout and recycling below MySQL's `wait_timeout`; the same
//! knobs map onto sqlx's `max_connections`, `test_before_acquire` and
//! `max_lifetime`.

use std::str::FromStr;

use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::{MySql, Pool};

use copilot_core::config::DatabaseConfig;

use crate::DbError;

/// Shared MySQL pool. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Db {
    pool: Pool<MySql>,
}

impl Db {
    /// Connect lazily: the pool opens connections on first use, so the
    /// service can start (and answer `/health`) while MySQL is still booting.
    pub fn connect_lazy(cfg: &DatabaseConfig) -> Result<Self, DbError> {
        let options = connect_options(cfg)?;
        let pool = MySqlPoolOptions::new()
            .max_connections(cfg.max_connections.max(1))
            .acquire_timeout(cfg.acquire_timeout)
            .max_lifetime(Some(cfg.max_lifetime))
            .test_before_acquire(true)
            .connect_lazy_with(options);
        Ok(Self { pool })
    }

    /// Connect eagerly (CLI commands, tests).
    pub async fn connect(cfg: &DatabaseConfig) -> Result<Self, DbError> {
        let db = Self::connect_lazy(cfg)?;
        db.ping().await?;
        Ok(db)
    }

    /// Wrap an existing pool.
    pub fn from_pool(pool: Pool<MySql>) -> Self {
        Self { pool }
    }

    /// The underlying pool, for feature crates that own their queries.
    pub fn pool(&self) -> &Pool<MySql> {
        &self.pool
    }

    /// `SELECT 1`.
    pub async fn ping(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Close every connection (shutdown).
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// Build connect options from config. `MYSQL_URL` is a host with an optional
/// `:port`, as `db_session.py` interpolates it into its URL.
pub fn connect_options(cfg: &DatabaseConfig) -> Result<MySqlConnectOptions, DbError> {
    if let Some(url) = &cfg.url_override {
        return MySqlConnectOptions::from_str(url.expose())
            .map_err(|e| DbError::Config(format!("COPILOT_DATABASE_URL: {e}")));
    }
    let (host, port) = split_host_port(&cfg.host)?;
    Ok(MySqlConnectOptions::new()
        .host(host)
        .port(port)
        .username(&cfg.user)
        .password(cfg.password.expose())
        .database(&cfg.database)
        .charset("utf8mb4"))
}

fn split_host_port(raw: &str) -> Result<(&str, u16), DbError> {
    let raw = raw.trim();
    match raw.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port
                .parse::<u16>()
                .map_err(|_| DbError::Config(format!("MYSQL_URL {raw:?}: bad port")))?;
            Ok((host, port))
        }
        _ => Ok((raw, 3306)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_parsing() {
        assert_eq!(
            split_host_port("copilot-mysql").unwrap(),
            ("copilot-mysql", 3306)
        );
        assert_eq!(
            split_host_port("127.0.0.1:13306").unwrap(),
            ("127.0.0.1", 13306)
        );
        assert!(split_host_port("db:notaport").is_err());
    }
}
