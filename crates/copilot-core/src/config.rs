//! Process-wide configuration resolved from the environment and the repo-root
//! `.env` — the same file `backend/settings.py` and `app/db/db_session.py`
//! load, so the Rust and Python services agree on every value.
//!
//! | Key | Default | Meaning |
//! |---|---|---|
//! | `COPILOT_BIND` | `0.0.0.0` | listen address (`SERVER_IP` is honoured as a fallback) |
//! | `COPILOT_PORT` | `5000` | listen port — the port the frontends already call |
//! | `COPILOT_LEGACY_URL` | *(unset)* | Python backend that serves every route not yet ported; unset = those routes 404 |
//! | `MYSQL_URL` | `copilot-mysql` | MySQL host[:port] |
//! | `MYSQL_USER` | `copilot` | MySQL user |
//! | `MYSQL_PASSWORD` | — | MySQL password (secret) |
//! | `MYSQL_DATABASE` | `copilot` | schema name (Python hard-codes `copilot`) |
//! | `COPILOT_DATABASE_URL` | *(unset)* | full `mysql://` URL, overrides the four above (tests) |
//! | `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `20` / `20` | pool size = their sum |
//! | `DB_POOL_TIMEOUT` | `30` | seconds to wait for a connection |
//! | `DB_POOL_RECYCLE` | `1800` | max connection lifetime, seconds |
//! | `JWT_SECRET` | — | HS256 key shared with the Python backend (secret, required) |
//! | `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` | lifetime of tokens this service issues |
//! | `COPILOT_URL` | *(unset)* | public base URL, for notification deep links |
//! | `DEFAULT_ALERT_SEVERITY` | `High` | notification severity fallback |
//! | `CONNECTOR_CACHE_TTL_SECONDS` | `600` | `connectors` row cache; `0` disables |
//! | `COPILOT_RS_PALACE_JOBS` | `false` | run the palace-lesson drainer/sweeper here instead of in APScheduler |
//! | `COPILOT_MAX_BODY_BYTES` | `268435456` | request body cap (nginx's `client_max_body_size 256m`) |
//! | `COPILOT_LOG_FORMAT` | `text` | `json` for structured logs |

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::env::EnvFile;
use crate::error::{Error, Result};
use crate::notify::{NotificationDefaults, NotificationSeverity};

/// The value published in old `.env.example` files and as a hard-coded
/// fallback (GHSA-4gxj-hw3c-3x2x). Refused at startup wherever it comes from.
pub const KNOWN_COMPROMISED_JWT_SECRET: &str = "bL4unrkoxtFs1MT6A7Ns2yMLkduyuqrkTxDV9CjlbNc=";

/// A secret string: zeroized on drop, never printed by `Debug`.
#[derive(Clone, Default)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap a value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Whether a non-empty value is present.
    pub fn is_set(&self) -> bool {
        !self.0.is_empty()
    }

    /// The raw value. Never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_set() {
            f.write_str("Secret(<redacted>)")
        } else {
            f.write_str("Secret(<unset>)")
        }
    }
}

/// MySQL connection settings.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Host, optionally with `:port`.
    pub host: String,
    /// User name.
    pub user: String,
    /// Password.
    pub password: Secret,
    /// Schema name.
    pub database: String,
    /// Full URL override (contains the password; never log it).
    pub url_override: Option<Secret>,
    /// Maximum pool connections.
    pub max_connections: u32,
    /// Wait for a free connection.
    pub acquire_timeout: Duration,
    /// Recycle connections older than this.
    pub max_lifetime: Duration,
}

/// Process-wide configuration.
#[derive(Debug, Clone)]
pub struct CopilotConfig {
    /// Repository root (where `.env` lives).
    pub project_root: PathBuf,
    /// Listen address.
    pub bind: IpAddr,
    /// Listen port.
    pub port: u16,
    /// Base URL of the Python backend for not-yet-ported routes.
    pub legacy_url: Option<url::Url>,
    /// MySQL.
    pub database: DatabaseConfig,
    /// HS256 key shared with the Python backend.
    pub jwt_secret: Secret,
    /// Lifetime of issued tokens.
    pub access_token_ttl: Duration,
    /// Notification builder defaults.
    pub notifications: NotificationDefaults,
    /// Connector-row cache TTL (`0` = disabled).
    pub connector_cache_ttl: Duration,
    /// Run the palace-lesson jobs in this process.
    pub palace_jobs: bool,
    /// Request body cap.
    pub max_body_bytes: usize,
    /// Emit JSON logs.
    pub json_logs: bool,
}

impl CopilotConfig {
    /// Load `<project_root>/.env` plus the process environment.
    pub fn load(project_root: &Path) -> Result<Self> {
        Self::from_env(project_root, &EnvFile::load(project_root))
    }

    /// Resolve from an [`EnvFile`] (tests pass [`EnvFile::isolated`]).
    pub fn from_env(project_root: &Path, env: &EnvFile) -> Result<Self> {
        let bind_raw = env
            .get("COPILOT_BIND")
            .or_else(|| env.get("SERVER_IP"))
            .unwrap_or_else(|| "0.0.0.0".into());
        let bind = bind_raw.trim().parse::<IpAddr>().map_err(|_| {
            Error::Config(format!("COPILOT_BIND {bind_raw:?} is not an IP address"))
        })?;
        let port_raw = env.get_or("COPILOT_PORT", "5000");
        let port = port_raw
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| {
                Error::Config(format!("COPILOT_PORT {port_raw:?} is not a valid port"))
            })?;

        let legacy_url = match env.get("COPILOT_LEGACY_URL") {
            None => None,
            Some(raw) => {
                let parsed = url::Url::parse(raw.trim()).map_err(|e| {
                    Error::Config(format!("COPILOT_LEGACY_URL {raw:?} is not a URL: {e}"))
                })?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err(Error::Config("COPILOT_LEGACY_URL must be http(s)".into()));
                }
                Some(parsed)
            }
        };

        let pool = env.get_u64("DB_POOL_SIZE", 20, 1) + env.get_u64("DB_MAX_OVERFLOW", 20, 0);
        let database = DatabaseConfig {
            host: env.get_or("MYSQL_URL", "copilot-mysql"),
            user: env.get_or("MYSQL_USER", "copilot"),
            password: Secret::new(env.get("MYSQL_PASSWORD").unwrap_or_default()),
            database: env.get_or("MYSQL_DATABASE", "copilot"),
            url_override: env.get("COPILOT_DATABASE_URL").map(Secret::new),
            max_connections: u32::try_from(pool).unwrap_or(u32::MAX),
            acquire_timeout: Duration::from_secs(env.get_u64("DB_POOL_TIMEOUT", 30, 1)),
            max_lifetime: Duration::from_secs(env.get_u64("DB_POOL_RECYCLE", 1800, 1)),
        };
        if database.url_override.is_none() && !database.password.is_set() {
            return Err(Error::Config(
                "MYSQL_PASSWORD is not set (or set COPILOT_DATABASE_URL)".into(),
            ));
        }

        let jwt_secret = Secret::new(env.get("JWT_SECRET").unwrap_or_default());
        validate_jwt_secret(&jwt_secret)?;

        let default_severity = env
            .get("DEFAULT_ALERT_SEVERITY")
            .and_then(|s| NotificationSeverity::parse(s.trim()))
            .unwrap_or(NotificationSeverity::High);

        let max_body = env.get_u64("COPILOT_MAX_BODY_BYTES", 256 * 1024 * 1024, 1024);

        Ok(Self {
            project_root: project_root.to_path_buf(),
            bind,
            port,
            legacy_url,
            database,
            jwt_secret,
            access_token_ttl: Duration::from_secs(
                env.get_u64("ACCESS_TOKEN_EXPIRE_MINUTES", 1440, 1) * 60,
            ),
            notifications: NotificationDefaults {
                copilot_url: env.get("COPILOT_URL"),
                default_severity,
            },
            connector_cache_ttl: Duration::from_secs(env.get_u64(
                "CONNECTOR_CACHE_TTL_SECONDS",
                600,
                0,
            )),
            palace_jobs: env.get_bool("COPILOT_RS_PALACE_JOBS"),
            max_body_bytes: usize::try_from(max_body).unwrap_or(usize::MAX),
            json_logs: env
                .get("COPILOT_LOG_FORMAT")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("json")),
        })
    }
}

/// `_load_jwt_secret`: refuse an unset or known-compromised secret. The
/// secret is used as raw UTF-8 bytes, exactly like PyJWT.
pub fn validate_jwt_secret(secret: &Secret) -> Result<()> {
    if !secret.is_set() {
        return Err(Error::Config(
            "JWT_SECRET environment variable is not set. Generate a secure value with \
             `openssl rand -base64 32` and set it before starting the application."
                .into(),
        ));
    }
    if secret.expose() == KNOWN_COMPROMISED_JWT_SECRET {
        return Err(Error::Config(
            "JWT_SECRET is set to the known-compromised default value disclosed in \
             GHSA-4gxj-hw3c-3x2x. Generate a new secret with `openssl rand -base64 32` \
             and update your environment."
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(content: &str) -> Result<CopilotConfig> {
        CopilotConfig::from_env(Path::new("/srv"), &EnvFile::isolated(content))
    }

    #[test]
    fn defaults_match_python_backend() {
        let cfg = load("JWT_SECRET=s3cret\nMYSQL_PASSWORD=pw\n").unwrap();
        assert_eq!(cfg.port, 5000);
        assert_eq!(cfg.database.host, "copilot-mysql");
        assert_eq!(cfg.database.user, "copilot");
        assert_eq!(cfg.database.database, "copilot");
        assert_eq!(cfg.database.max_connections, 40);
        assert_eq!(cfg.access_token_ttl, Duration::from_secs(1440 * 60));
        assert_eq!(cfg.connector_cache_ttl, Duration::from_secs(600));
        assert!(cfg.legacy_url.is_none());
        assert!(!cfg.palace_jobs);
        assert_eq!(
            cfg.notifications.default_severity,
            NotificationSeverity::High
        );
    }

    #[test]
    fn refuses_missing_or_compromised_secret() {
        assert!(load("MYSQL_PASSWORD=pw\n").is_err());
        let err = load(&format!(
            "MYSQL_PASSWORD=pw\nJWT_SECRET={KNOWN_COMPROMISED_JWT_SECRET}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("GHSA-4gxj-hw3c-3x2x"));
    }

    #[test]
    fn requires_a_database_password() {
        assert!(load("JWT_SECRET=x\n").is_err());
        assert!(load("JWT_SECRET=x\nCOPILOT_DATABASE_URL=mysql://u:p@h/db\n").is_ok());
    }

    #[test]
    fn legacy_url_and_port_validation() {
        let cfg = load("JWT_SECRET=x\nMYSQL_PASSWORD=p\nCOPILOT_LEGACY_URL=http://copilot-backend-legacy:5000\n")
            .unwrap();
        assert_eq!(
            cfg.legacy_url.unwrap().host_str(),
            Some("copilot-backend-legacy")
        );
        assert!(load("JWT_SECRET=x\nMYSQL_PASSWORD=p\nCOPILOT_LEGACY_URL=ftp://x\n").is_err());
        assert!(load("JWT_SECRET=x\nMYSQL_PASSWORD=p\nCOPILOT_PORT=0\n").is_err());
    }

    #[test]
    fn secrets_never_print() {
        let cfg = load("JWT_SECRET=topsecret\nMYSQL_PASSWORD=pw\n").unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("topsecret"));
        assert!(dbg.contains("Secret(<redacted>)"));
    }
}
