//! What the startup reads from the environment.
//!
//! | Key | Default | Meaning |
//! |---|---|---|
//! | `COPILOT_STARTUP_TASKS` | `true` | run `copilot.py`'s startup tasks at `serve`'s start (the bootstrap, MinIO's buckets, the catalogs, the system users, the templates, the portal settings, the scheduler rows, the Office 365 rule check) and remove the scheduler user at its end. `false` while another process owns them — every parity suite's Rust instance runs so on its shared database |
//! | `COPILOT_RUN_MIGRATIONS` | `true` | bring the schema to this build's last migration at `serve`'s start (`false`: only check it, as before phase 5) |
//! | `ENVIRONMENT` | `PRODUCTION` | `PRODUCTION` (exactly, as `copilot.py` compares it): create the database and its user through root first |
//! | `MYSQL_ROOT_PASSWORD` | — | root's password for that bootstrap (an empty value is a value) |
//!
//! Each connector's `<NAME>_URL`, `_USERNAME`, `_PASSWORD`, `_API_KEY`,
//! `_SUPPORTS`, `_VERIFIED` and extra-data variable are read as
//! `load_connector_data` reads them ([`crate::catalog::ConnectorSpec::row`]).

use copilot_core::config::Secret;
use copilot_core::env::EnvFile;

/// The startup's switches and inputs.
#[derive(Debug, Clone)]
pub struct StartupEnv {
    /// `COPILOT_STARTUP_TASKS`.
    pub tasks: bool,
    /// `COPILOT_RUN_MIGRATIONS`.
    pub migrations: bool,
    /// `ENVIRONMENT`, as `os.getenv("ENVIRONMENT", "PRODUCTION")` reads it.
    pub environment: String,
    /// `MYSQL_ROOT_PASSWORD`, as set.
    pub root_password: Option<Secret>,
    /// The environment the connector rows are built from.
    pub env: EnvFile,
}

impl StartupEnv {
    /// Read the switches (the connectors' variables are read per row).
    pub fn from_env(env: &EnvFile) -> Self {
        Self {
            tasks: env.get_bool_or("COPILOT_STARTUP_TASKS", true),
            migrations: env.get_bool_or("COPILOT_RUN_MIGRATIONS", true),
            environment: env
                .get_raw("ENVIRONMENT")
                .unwrap_or_else(|| "PRODUCTION".to_string()),
            root_password: env.get_raw("MYSQL_ROOT_PASSWORD").map(Secret::new),
            env: env.clone(),
        }
    }

    /// Whether the PRODUCTION bootstrap runs (`environment == "PRODUCTION"`).
    pub fn production(&self) -> bool {
        self.environment == "PRODUCTION"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_on_and_production() {
        let env = EnvFile::isolated("JWT_SECRET=startup-env-test-0123456789\nMYSQL_PASSWORD=x\n");
        let s = StartupEnv::from_env(&env);
        assert!(s.tasks && s.migrations && s.production());
        assert!(s.root_password.is_none());
    }

    #[test]
    fn switches_and_the_exact_environment_compare() {
        let env = EnvFile::isolated(
            "JWT_SECRET=startup-env-test-0123456789\nMYSQL_PASSWORD=x\nCOPILOT_STARTUP_TASKS=false\n\
             COPILOT_RUN_MIGRATIONS=0\nENVIRONMENT=production\nMYSQL_ROOT_PASSWORD=\n",
        );
        let s = StartupEnv::from_env(&env);
        assert!(!s.tasks && !s.migrations);
        assert!(!s.production(), "copilot.py compares `== \"PRODUCTION\"`");
        assert_eq!(
            s.root_password.map(|p| p.expose().to_string()).as_deref(),
            Some("")
        );
    }
}
