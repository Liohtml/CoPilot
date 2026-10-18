//! `create_database_if_not_exists` + `create_copilot_user_if_not_exists`
//! (`app/db/db_setup.py`): with `ENVIRONMENT=PRODUCTION`, before anything
//! connects to the database, root makes sure the database and the user exist.
//!
//! As in Python: root's connection failing stops the start; a statement
//! failing afterwards is only logged; the user is granted every privilege on
//! the database only when it is created; an existing user (on any host) is
//! left alone. Two differences, both where Python cannot work: the names are
//! the ones this service connects with (`MYSQL_DATABASE`, `MYSQL_USER`, or
//! the `COPILOT_DATABASE_URL`'s) — Python hard-codes `copilot` for both,
//! whatever `MYSQL_USER` says (§4) —, and the statements are `IF NOT EXISTS`,
//! so a second process creating them at the same moment is no error. The
//! password is never logged (Python logs it).

use std::time::Duration;

use copilot_core::config::{DatabaseConfig, Secret};
use sqlx::ConnectOptions;
use sqlx::mysql::{MySqlConnectOptions, MySqlConnection};

/// Where and as whom the service connects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// MySQL's host.
    pub host: String,
    /// Its port.
    pub port: u16,
    /// The database.
    pub database: String,
    /// The user.
    pub user: String,
    /// The user's password.
    pub password: String,
}

impl Target {
    /// From the service's database settings.
    pub fn of(cfg: &DatabaseConfig) -> Result<Self, String> {
        if let Some(raw) = &cfg.url_override {
            let url =
                url::Url::parse(raw.expose()).map_err(|e| format!("COPILOT_DATABASE_URL: {e}"))?;
            let decode = |s: &str| {
                url::form_urlencoded::parse(format!("x={s}").as_bytes())
                    .next()
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            };
            return Ok(Self {
                host: url.host_str().unwrap_or("localhost").to_string(),
                port: url.port().unwrap_or(3306),
                database: url.path().trim_start_matches('/').to_string(),
                user: decode(url.username()),
                password: url.password().map(decode).unwrap_or_default(),
            });
        }
        let raw = cfg.host.trim();
        let (host, port) = match raw.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| format!("MYSQL_URL {raw:?}: bad port"))?,
            ),
            _ => (raw.to_string(), 3306),
        };
        Ok(Self {
            host,
            port,
            database: cfg.database.clone(),
            user: cfg.user.clone(),
            password: cfg.password.expose().to_string(),
        })
    }

    /// root's connection to the server (no database).
    pub fn root_options(&self, root_password: &Secret) -> MySqlConnectOptions {
        MySqlConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .username("root")
            .password(root_password.expose())
            .charset("utf8mb4")
    }
}

/// A backtick-quoted identifier.
pub fn quote_ident(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

/// A single-quoted string literal (`'` doubled, `\` escaped).
pub fn quote_str(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

/// Connect as root, waiting for a server that is still starting (an access
/// refusal is final).
pub async fn connect_root(
    target: &Target,
    root_password: &Secret,
    attempts: u32,
) -> Result<MySqlConnection, sqlx::Error> {
    let options = target.root_options(root_password);
    let mut attempt = 0;
    loop {
        match options.connect().await {
            Ok(conn) => return Ok(conn),
            Err(e) if attempt + 1 < attempts && !is_access_denied(&e) => {
                attempt += 1;
                tracing::warn!(attempt, err = %e, "MySQL not reachable as root yet; retrying in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

fn is_access_denied(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("28000"))
}

/// What the bootstrap did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Outcome {
    /// The database was created.
    pub database_created: bool,
    /// The user was created (and granted the database).
    pub user_created: bool,
}

/// Make sure of the database and the user, on root's connection.
pub async fn run(conn: &mut MySqlConnection, target: &Target) -> Outcome {
    let mut out = Outcome::default();
    let exists: Result<i64, sqlx::Error> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?",
    )
    .bind(&target.database)
    .fetch_one(&mut *conn)
    .await;
    match exists {
        Ok(0) => {
            let sql = format!(
                "CREATE DATABASE IF NOT EXISTS {}",
                quote_ident(&target.database)
            );
            match sqlx::raw_sql(&sql).execute(&mut *conn).await {
                Ok(_) => {
                    tracing::info!("Database '{}' created successfully.", target.database);
                    out.database_created = true;
                }
                Err(e) => tracing::error!("An error occurred: {e}"),
            }
        }
        Ok(_) => tracing::info!("Database '{}' already exists.", target.database),
        Err(e) => tracing::error!("An error occurred: {e}"),
    }
    let user: Result<i64, sqlx::Error> =
        sqlx::query_scalar("SELECT COUNT(*) FROM mysql.user WHERE user = ?")
            .bind(&target.user)
            .fetch_one(&mut *conn)
            .await;
    match user {
        Ok(0) => {
            let account = format!("{}@'%'", quote_str(&target.user));
            let create = format!(
                "CREATE USER IF NOT EXISTS {account} IDENTIFIED BY {}",
                quote_str(&target.password)
            );
            let grant = format!(
                "GRANT ALL PRIVILEGES ON {}.* TO {account}",
                quote_ident(&target.database)
            );
            match sqlx::raw_sql(&create).execute(&mut *conn).await {
                Ok(_) => match sqlx::raw_sql(&grant).execute(&mut *conn).await {
                    Ok(_) => {
                        tracing::info!(
                            "User '{}' created successfully and granted all privileges to the '{}' \
                             database.",
                            target.user,
                            target.database
                        );
                        out.user_created = true;
                    }
                    Err(e) => tracing::info!("An error occurred: {e}"),
                },
                Err(e) => tracing::info!("An error occurred: {e}"),
            }
        }
        Ok(_) => tracing::info!("User '{}' already exists.", target.user),
        Err(e) => tracing::info!("An error occurred: {e}"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_core::env::EnvFile;

    fn db(env: &str) -> DatabaseConfig {
        let env = EnvFile::isolated(&format!("JWT_SECRET=bootstrap-test-0123456789\n{env}"));
        copilot_core::config::CopilotConfig::from_env(std::path::Path::new("."), &env)
            .unwrap()
            .database
    }

    #[test]
    fn the_target_is_what_the_service_connects_with() {
        let t = Target::of(&db("MYSQL_URL=db.local:3307\nMYSQL_PASSWORD=p'w\n")).unwrap();
        assert_eq!(
            t,
            Target {
                host: "db.local".into(),
                port: 3307,
                database: "copilot".into(),
                user: "copilot".into(),
                password: "p'w".into(),
            }
        );
        let t = Target::of(&db(
            "COPILOT_DATABASE_URL=mysql://u%40x:p%2Fw@127.0.0.1:13307/other\n",
        ))
        .unwrap();
        assert_eq!((t.host.as_str(), t.port), ("127.0.0.1", 13307));
        assert_eq!((t.user.as_str(), t.password.as_str()), ("u@x", "p/w"));
        assert_eq!(t.database, "other");
    }

    #[test]
    fn quoting() {
        assert_eq!(quote_ident("a`b"), "`a``b`");
        assert_eq!(quote_str("it's a \\ test"), "'it''s a \\\\ test'");
    }
}
