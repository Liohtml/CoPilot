//! Process-wide configuration resolved from the environment and the repo-root
//! `.env` — the same file `backend/settings.py` and `app/db/db_session.py`
//! load, so the Rust and Python services agree on every value.
//!
//! | Key | Default | Meaning |
//! |---|---|---|
//! | `COPILOT_BIND` | `0.0.0.0` | listen address (`SERVER_IP` is honoured as a fallback) |
//! | `COPILOT_PORT` | `5000` | listen port — the port the frontends already call |
//! | `COPILOT_LEGACY_URL` | *(unset)* | Python backend that serves every route not yet ported; unset = those routes 404 |
//! | `MYSQL_URL` | `copilot-mysql` | MySQL `host[:port]` |
//! | `MYSQL_USER` | `copilot` | MySQL user |
//! | `MYSQL_PASSWORD` | — | MySQL password (secret) |
//! | `MYSQL_DATABASE` | `copilot` | schema name (Python hard-codes `copilot`) |
//! | `COPILOT_DATABASE_URL` | *(unset)* | full `mysql://` URL, overrides the four above (tests) |
//! | `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `20` / `20` | pool size = their sum |
//! | `DB_POOL_TIMEOUT` | `30` | seconds to wait for a connection |
//! | `DB_POOL_RECYCLE` | `1800` | max connection lifetime, seconds |
//! | `JWT_SECRET` | — | HS256 key shared with the Python backend (secret, required) |
//! | `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` | lifetime of tokens this service issues (read like Python's `int()`; anything else refuses to start) |
//! | `TOTP_ENCRYPTION_KEY` | *(unset)* | Fernet key of the stored 2FA secrets (secret); unset = derived from `JWT_SECRET` |
//! | `COPILOT_URL` | *(unset)* | public base URL, for notification deep links |
//! | `DEFAULT_ALERT_SEVERITY` | `High` | notification severity fallback |
//! | `CONNECTOR_CACHE_TTL_SECONDS` | `600` | `connectors` row cache; `0` disables |
//! | `CONNECTOR_CACHE_CHECK_SECONDS` | `5` | how stale a cached `connectors` row may get when another process wrote it (the change check, `copilot_db::connectors`); `0` disables the check |
//! | `COPILOT_RS_PALACE_JOBS` | `false` | run the palace-lesson drainer/sweeper here instead of in APScheduler |
//! | `COPILOT_RS_JOBS` | *(unset)* | scheduled jobs this service may take over (ids, comma-separated, or `all`); each runs only while its `scheduled_job_metadata` row is disabled |
//! | `AUDIT_LOG_RETENTION_DAYS` | `90` | `prune_audit_log`'s window, read as Python reads it (`<= 0` keeps everything) |
//! | `COPILOT_MAX_BODY_BYTES` | `268435456` | request body cap (nginx's `client_max_body_size 256m`) |
//! | `COPILOT_LOG_FORMAT` | `text` | `json` for structured logs |
//! | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_USE_TLS` | *(unset)*, `587`, …, `true` | the temporary-password email; read as set, and parsed per request like Python (a bad `SMTP_PORT` is that request's 400) |

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
    /// Lifetime of issued tokens, in minutes (may be zero or negative, as in
    /// Python — such tokens are born expired).
    pub access_token_expire_minutes: i64,
    /// `TOTP_ENCRYPTION_KEY`, when set.
    pub totp_encryption_key: Option<Secret>,
    /// Notification builder defaults.
    pub notifications: NotificationDefaults,
    /// Connector-row cache TTL (`0` = disabled).
    pub connector_cache_ttl: Duration,
    /// Interval of the connector cache's cross-process change check (`0` =
    /// no check).
    pub connector_cache_check: Duration,
    /// Run the palace-lesson jobs in this process.
    pub palace_jobs: bool,
    /// `COPILOT_RS_JOBS`, as set: the scheduled jobs this process may take
    /// over (parsed by `copilot-scheduler`).
    pub rust_jobs: Option<String>,
    /// `AUDIT_LOG_RETENTION_DAYS`, as set (`os.getenv` semantics).
    pub audit_log_retention_days: Option<String>,
    /// Request body cap.
    pub max_body_bytes: usize,
    /// Emit JSON logs.
    pub json_logs: bool,
    /// Where `GET /api/version/check` looks up the latest release
    /// (`COPILOT_VERSION_CHECK_URL`; `None` = GitHub). For tests and mirrors.
    pub version_check_url: Option<String>,
    /// `SSO_STATE_SECRET`: signs the OAuth2 `state` (else `JWT_SECRET`).
    pub sso_state_secret: Option<Secret>,
    /// `COPILOT_SSO_IDP_URL` — tests only: every server-side request to an
    /// identity provider (token endpoint, JWKS, Cloudflare certs) goes to this
    /// base URL instead, path kept. The browser redirects are unchanged.
    pub sso_idp_url: Option<String>,
    /// The `WEBAUTHN_*` settings, as set (an empty value counts as set).
    pub webauthn: WebAuthnEnv,
    /// The `SMTP_*` settings, as set.
    pub smtp: SmtpEnv,
    /// What the WAF and provisioning modules read from the environment.
    pub provisioning: ProvisioningEnv,
}

/// Raw values the WAF and provisioning modules read per call in Python
/// (`os.environ.get`; `None` = unset, an empty value is still a value).
#[derive(Clone, Debug, Default)]
pub struct ProvisioningEnv {
    /// `WAF_TOKEN_ENCRYPTION_KEY` (no fallback key).
    pub waf_token_encryption_key: Option<Secret>,
    /// `WAF_SYSLOG_PORT_RANGE`.
    pub waf_syslog_port_range: Option<String>,
    /// `WAF_SYSLOG_DEFAULT_HOST`.
    pub waf_syslog_default_host: Option<String>,
    /// `ALERT_FORWARDING_IP`.
    pub alert_forwarding_ip: Option<String>,
    /// `GRAYLOG_API_HEADER_VALUE`.
    pub graylog_api_header_value: Option<Secret>,
}

/// Raw `WEBAUTHN_*` values, read like `os.environ.get` (`None` = unset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebAuthnEnv {
    /// `WEBAUTHN_ORIGINS` (comma-separated).
    pub origins: Option<String>,
    /// `WEBAUTHN_ORIGIN`, used when `WEBAUTHN_ORIGINS` is unset.
    pub origin: Option<String>,
    /// `WEBAUTHN_RP_ID`.
    pub rp_id: Option<String>,
    /// `WEBAUTHN_RP_NAME`.
    pub rp_name: Option<String>,
}

/// Raw `SMTP_*` values, read like `os.getenv` (`None` = unset; an empty
/// value is still a value). `security_admin._smtp_config` interprets them on
/// every call, so a malformed `SMTP_PORT` is a request's error, not a
/// startup failure.
#[derive(Clone, Debug, Default)]
pub struct SmtpEnv {
    /// `SMTP_HOST`; unset or empty = SMTP not configured.
    pub host: Option<String>,
    /// `SMTP_PORT` (default `587`).
    pub port: Option<String>,
    /// `SMTP_USERNAME`.
    pub username: Option<String>,
    /// `SMTP_PASSWORD`.
    pub password: Option<Secret>,
    /// `SMTP_FROM`.
    pub from: Option<String>,
    /// `SMTP_USE_TLS` (default `true`).
    pub use_tls: Option<String>,
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

        // `alert_severity.default_severity()`: matched case-insensitively.
        let default_severity = env
            .get("DEFAULT_ALERT_SEVERITY")
            .and_then(|s| {
                let wanted = s.trim().to_lowercase();
                ["Critical", "High", "Medium", "Low", "Informational"]
                    .into_iter()
                    .find(|level| level.to_lowercase() == wanted)
                    .and_then(NotificationSeverity::parse)
            })
            .unwrap_or(NotificationSeverity::High);

        let max_body = env.get_u64("COPILOT_MAX_BODY_BYTES", 256 * 1024 * 1024, 1024);

        let ttl_raw = env.get_or("ACCESS_TOKEN_EXPIRE_MINUTES", "1440");
        let access_token_expire_minutes = python_int(&ttl_raw).ok_or_else(|| {
            Error::Config(format!(
                "ACCESS_TOKEN_EXPIRE_MINUTES {ttl_raw:?} is not an integer"
            ))
        })?;

        Ok(Self {
            project_root: project_root.to_path_buf(),
            bind,
            port,
            legacy_url,
            database,
            jwt_secret,
            access_token_expire_minutes,
            totp_encryption_key: env
                .get("TOTP_ENCRYPTION_KEY")
                .filter(|k| !k.is_empty())
                .map(Secret::new),
            notifications: NotificationDefaults {
                copilot_url: env.get("COPILOT_URL"),
                default_severity,
            },
            connector_cache_ttl: Duration::from_secs(env.get_u64(
                "CONNECTOR_CACHE_TTL_SECONDS",
                600,
                0,
            )),
            connector_cache_check: Duration::from_secs(env.get_u64(
                "CONNECTOR_CACHE_CHECK_SECONDS",
                5,
                0,
            )),
            palace_jobs: env.get_bool("COPILOT_RS_PALACE_JOBS"),
            rust_jobs: env.get("COPILOT_RS_JOBS"),
            audit_log_retention_days: env.get_raw("AUDIT_LOG_RETENTION_DAYS"),
            max_body_bytes: usize::try_from(max_body).unwrap_or(usize::MAX),
            json_logs: env
                .get("COPILOT_LOG_FORMAT")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("json")),
            version_check_url: env
                .get("COPILOT_VERSION_CHECK_URL")
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            sso_state_secret: env.get("SSO_STATE_SECRET").map(Secret::new),
            sso_idp_url: env
                .get("COPILOT_SSO_IDP_URL")
                .map(|v| v.trim().trim_end_matches('/').to_string())
                .filter(|v| !v.is_empty()),
            webauthn: WebAuthnEnv {
                origins: env.get_raw("WEBAUTHN_ORIGINS"),
                origin: env.get_raw("WEBAUTHN_ORIGIN"),
                rp_id: env.get_raw("WEBAUTHN_RP_ID"),
                rp_name: env.get_raw("WEBAUTHN_RP_NAME"),
            },
            smtp: SmtpEnv {
                host: env.get_raw("SMTP_HOST"),
                port: env.get_raw("SMTP_PORT"),
                username: env.get_raw("SMTP_USERNAME"),
                password: env.get_raw("SMTP_PASSWORD").map(Secret::new),
                from: env.get_raw("SMTP_FROM"),
                use_tls: env.get_raw("SMTP_USE_TLS"),
            },
            provisioning: ProvisioningEnv {
                waf_token_encryption_key: env.get_raw("WAF_TOKEN_ENCRYPTION_KEY").map(Secret::new),
                waf_syslog_port_range: env.get_raw("WAF_SYSLOG_PORT_RANGE"),
                waf_syslog_default_host: env.get_raw("WAF_SYSLOG_DEFAULT_HOST"),
                alert_forwarding_ip: env.get_raw("ALERT_FORWARDING_IP"),
                graylog_api_header_value: env.get_raw("GRAYLOG_API_HEADER_VALUE").map(Secret::new),
            },
        })
    }
}

/// Python's `int(text)` for base-10 ASCII input: surrounding whitespace, a
/// sign, and single underscores between digits are allowed.
pub fn python_int(text: &str) -> Option<i64> {
    let t = text.trim();
    let (negative, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let bytes = digits.as_bytes();
    if bytes.is_empty()
        || bytes[0] == b'_'
        || bytes[bytes.len() - 1] == b'_'
        || digits.contains("__")
        || !bytes.iter().all(|b| b.is_ascii_digit() || *b == b'_')
    {
        return None;
    }
    let value: i64 = digits.replace('_', "").parse().ok()?;
    Some(if negative { -value } else { value })
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
        assert_eq!(cfg.access_token_expire_minutes, 1440);
        assert!(cfg.totp_encryption_key.is_none());
        assert_eq!(cfg.connector_cache_ttl, Duration::from_secs(600));
        assert_eq!(cfg.connector_cache_check, Duration::from_secs(5));
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
    fn token_lifetime_reads_like_python_int() {
        let ttl = |v: &str| {
            load(&format!(
                "JWT_SECRET=x\nMYSQL_PASSWORD=p\nACCESS_TOKEN_EXPIRE_MINUTES={v}\n"
            ))
            .map(|c| c.access_token_expire_minutes)
        };
        assert_eq!(ttl("60").unwrap(), 60);
        assert_eq!(ttl(" 1_440 ").unwrap(), 1440);
        assert_eq!(ttl("-5").unwrap(), -5);
        assert_eq!(ttl("+0").unwrap(), 0);
        assert!(ttl("1.5").is_err());
        assert!(ttl("1__0").is_err());
        assert!(ttl("_1").is_err());
        assert!(ttl("ten").is_err());
    }

    #[test]
    fn secrets_never_print() {
        let cfg = load("JWT_SECRET=topsecret\nMYSQL_PASSWORD=pw\n").unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("topsecret"));
        assert!(dbg.contains("Secret(<redacted>)"));
    }
}
