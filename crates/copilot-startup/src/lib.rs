//! # copilot-startup — `backend/copilot.py`'s `lifespan`, in Rust
//!
//! What the Python backend does before it serves its first request, in its
//! order, so the binary can run against an empty MySQL with no Python process
//! ever having started:
//!
//! | `lifespan` | here |
//! |---|---|
//! | `run_integrity_check()` | — no counterpart: it re-hashes the Python image's compiled licence-enforcement modules (`app/middleware/integrity.py`); the binary has no such files |
//! | `create_database_if_not_exists` + `create_copilot_user_if_not_exists` (PRODUCTION) | [`bootstrap`] |
//! | `apply_migrations()` | `copilot-migrate` (`COPILOT_RUN_MIGRATIONS`) |
//! | `create_buckets()` | [`run_tasks`], through `copilot-objectstore` |
//! | `add_connectors` / `delete_connectors` | [`seed::add_connectors`], [`seed::delete_connectors`] |
//! | `create_roles`, `create_available_integrations`, `create_available_network_connectors` | [`seed`] |
//! | `ensure_admin_user`, `ensure_scheduler_user` | [`users`] (and [`Startup::shutdown`]: `ensure_scheduler_user_removed`) |
//! | `seed_builtin_templates`, `ensure_default_portal_settings` | [`seed`] |
//! | `init_scheduler()` | its rows: [`seed::initialize_job_metadata`]; the jobs: `copilot-scheduler` |
//! | `warm_catalog_caches()` | the binary's own refreshers (`copilot-searches`, `copilot-status`) |
//! | `ensure_office365_pipeline_rules()` | [`Startup::spawn_office365_check`] (a task, never fatal) |
//!
//! Everything but the bootstrap and the migrations is gated by
//! `COPILOT_STARTUP_TASKS` (default on, [`env`]). Every step is idempotent as
//! Python's is (check-then-insert by key, never a rewrite of a stored row but
//! Python's two updates), and race-free: the migrations and the seeding run
//! under the startup lock (`copilot_migrate::StartupLock`), which the Python
//! backend takes around the same steps — so Rust and Python starting together
//! against one database seed it once.
//!
//! The process keeps no state of its own from these tasks: the scheduler
//! user's password is not kept (Python keeps it in memory for a
//! `scheduler_login` nothing calls), and the admin's is logged once, when it
//! is created, as Python logs it.

#![warn(missing_docs)]

pub mod bootstrap;
pub mod catalog;
pub mod doctor;
pub mod env;
pub mod markdown;
pub mod seed;
pub mod templates;
pub mod users;
#[cfg(test)]
mod vectors;

use copilot_core::config::DatabaseConfig;
use copilot_core::env::EnvFile;
use copilot_db::Db;
use copilot_db::connectors::ConnectorCache;
use copilot_migrate::{Action, MIGRATIONS, MigrateError, StartupLock};
use copilot_objectstore::ObjectStore;
use sqlx::Connection;

pub use env::StartupEnv;
pub use seed::SeedError;

/// Why the start stops.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// PRODUCTION without root's password.
    #[error(
        "ENVIRONMENT is PRODUCTION (its default): the startup creates the database and its user \
         through MySQL's root, but MYSQL_ROOT_PASSWORD is not set. Set it, set ENVIRONMENT to \
         anything else (the database and the user then must exist), or COPILOT_STARTUP_TASKS=false"
    )]
    NoRootPassword,
    /// root could not connect.
    #[error("cannot connect to MySQL as root at {host}:{port} (ENVIRONMENT=PRODUCTION): {source}")]
    RootConnect {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// The failure.
        source: sqlx::Error,
    },
    /// Bad database settings.
    #[error("{0}")]
    Config(String),
    /// The startup lock.
    #[error(transparent)]
    Lock(#[from] copilot_migrate::lock::LockError),
    /// The migrations.
    #[error(transparent)]
    Migrate(#[from] MigrateError),
    /// `create_buckets()`.
    #[error("create_buckets: {0}")]
    Buckets(String),
    /// A seeding step.
    #[error(transparent)]
    Seed(#[from] SeedError),
}

/// What the tasks need from the application.
#[derive(Clone, Copy)]
pub struct SeedDeps<'a> {
    /// The pool.
    pub db: &'a Db,
    /// MinIO.
    pub objectstore: &'a ObjectStore,
    /// This process's connector cache (forgotten after the connector steps,
    /// as Python's `connector_cache.invalidate_all()`).
    pub connectors: Option<&'a ConnectorCache>,
}

/// What [`run_tasks`] did (for the logs and the tests).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// Connectors inserted.
    pub connectors_added: Vec<&'static str>,
    /// Retired connectors deleted.
    pub connectors_deleted: Vec<&'static str>,
    /// Roles inserted.
    pub roles_added: Vec<&'static str>,
    /// The integration catalog.
    pub integrations: seed::CatalogOutcome,
    /// The network-connector catalog.
    pub network_connectors: seed::CatalogOutcome,
    /// The admin user was created.
    pub admin_created: bool,
    /// The scheduler user was created.
    pub scheduler_created: bool,
    /// Built-in templates inserted.
    pub templates_added: usize,
    /// The portal's global settings row was created.
    pub portal_settings_created: bool,
    /// Scheduler rows inserted.
    pub jobs_added: Vec<&'static str>,
}

/// The tasks after the migrations, in `lifespan`'s order. Run them holding
/// the startup lock.
pub async fn run_tasks(deps: SeedDeps<'_>, env: &EnvFile) -> Result<Summary, StartupError> {
    let mut s = Summary::default();
    for bucket in catalog::BUCKETS {
        copilot_objectstore::ops::create_bucket_if_not_exists(deps.objectstore, bucket)
            .await
            .map_err(|e| StartupError::Buckets(e.text()))?;
    }
    tracing::info!("Adding connectors");
    s.connectors_added = seed::add_connectors(deps.db, env).await?;
    if let Some(c) = deps.connectors {
        c.invalidate_all();
    }
    tracing::info!("Deleting connectors");
    s.connectors_deleted = seed::delete_connectors(deps.db).await?;
    if let Some(c) = deps.connectors {
        c.invalidate_all();
    }
    tracing::info!("Creating roles");
    s.roles_added = seed::create_roles(deps.db).await?;
    tracing::info!("Creating available integrations");
    s.integrations = seed::create_available_integrations(deps.db).await?;
    tracing::info!("Creating available network connectors");
    s.network_connectors = seed::create_available_network_connectors(deps.db).await?;
    tracing::info!("Ensuring admin user exists");
    if let Some(password) = users::ensure_user(deps.db, &catalog::ADMIN_USER).await? {
        // The one place an operator learns the first admin's password, as
        // from the Python backend's log.
        tracing::info!("Added new admin user with username: admin");
        tracing::info!("Admin user password: {password}");
        s.admin_created = true;
    }
    tracing::info!("Ensuring scheduler user exists");
    if users::ensure_user(deps.db, &catalog::SCHEDULER_USER)
        .await?
        .is_some()
    {
        tracing::info!("Added new scheduler user with username: scheduler");
        s.scheduler_created = true;
    }
    s.templates_added = seed::seed_builtin_templates(deps.db).await;
    s.portal_settings_created = seed::ensure_default_portal_settings(deps.db).await;
    s.jobs_added = seed::initialize_job_metadata(deps.db).await?;
    Ok(s)
}

/// The startup of one `serve`.
#[derive(Debug, Clone)]
pub struct Startup {
    env: StartupEnv,
}

impl Startup {
    /// Read the switches.
    pub fn new(env: &EnvFile) -> Self {
        Self {
            env: StartupEnv::from_env(env),
        }
    }

    /// What was read.
    pub fn env(&self) -> &StartupEnv {
        &self.env
    }

    /// `COPILOT_STARTUP_TASKS`.
    pub fn tasks_enabled(&self) -> bool {
        self.env.tasks
    }

    /// The PRODUCTION bootstrap, before anything connects to the database.
    pub async fn bootstrap(&self, db: &DatabaseConfig) -> Result<(), StartupError> {
        if !self.env.tasks || !self.env.production() {
            return Ok(());
        }
        let Some(root) = &self.env.root_password else {
            return Err(StartupError::NoRootPassword);
        };
        let target = bootstrap::Target::of(db).map_err(StartupError::Config)?;
        tracing::info!("Initializing database");
        let mut conn = bootstrap::connect_root(&target, root, 30)
            .await
            .map_err(|source| StartupError::RootConnect {
                host: target.host.clone(),
                port: target.port,
                source,
            })?;
        bootstrap::run(&mut conn, &target).await;
        let _ = conn.close().await;
        Ok(())
    }

    /// The startup lock, then the migrations on its connection. The lock is
    /// held until [`Startup::seed`] has run; `None` when both switches are
    /// off.
    pub async fn schema(&self, db: &DatabaseConfig) -> Result<Option<StartupLock>, StartupError> {
        if !self.env.tasks && !self.env.migrations {
            return Ok(None);
        }
        let options = copilot_db::pool::connect_options(db)
            .map_err(|e| StartupError::Config(e.to_string()))?;
        let mut lock = StartupLock::acquire(&options, copilot_migrate::lock::DEFAULT_WAIT).await?;
        if self.env.migrations {
            let report = copilot_migrate::migrate(lock.conn(), MIGRATIONS).await?;
            for action in &report.actions {
                match action {
                    Action::Adopted(m) => tracing::info!(migration = %m, "schema: adopted"),
                    Action::Applied { migration, ms } => {
                        tracing::info!(migration = %migration, ms, "schema: applied");
                    }
                }
            }
            if report.actions.is_empty() {
                tracing::info!("schema: up to date");
            }
        }
        Ok(Some(lock))
    }

    /// The tasks (when on), then the lock released.
    pub async fn seed(
        &self,
        lock: Option<StartupLock>,
        deps: SeedDeps<'_>,
    ) -> Result<(), StartupError> {
        let result = if self.env.tasks {
            run_tasks(deps, &self.env.env).await.map(|_| ())
        } else {
            Ok(())
        };
        if let Some(lock) = lock {
            lock.release().await;
        }
        result
    }

    /// `ensure_office365_pipeline_rules()` on a task of its own (when the
    /// tasks are on).
    pub fn spawn_office365_check(&self, state: copilot_cloud_provisioning::CloudState) {
        if !self.env.tasks {
            return;
        }
        tokio::spawn(async move {
            copilot_cloud_provisioning::office365::ensure_office365_pipeline_rules(state.tools())
                .await;
        });
    }

    /// At the end of `serve`: `ensure_scheduler_user_removed` (when the
    /// tasks are on). A failure is logged.
    pub async fn shutdown(&self, db: &Db) {
        if !self.env.tasks {
            return;
        }
        tracing::info!("Ensuring scheduler user exists");
        if let Err(e) = users::remove_scheduler_user(db).await {
            tracing::error!("could not remove the scheduler user: {e}");
        }
    }
}

/// `copilot migrate`: the lock, the migrations, the report.
pub async fn migrate_now(db: &DatabaseConfig) -> Result<copilot_migrate::Report, StartupError> {
    let options =
        copilot_db::pool::connect_options(db).map_err(|e| StartupError::Config(e.to_string()))?;
    let mut lock = StartupLock::acquire(&options, copilot_migrate::lock::DEFAULT_WAIT).await?;
    let report = copilot_migrate::migrate(lock.conn(), MIGRATIONS).await;
    lock.release().await;
    Ok(report?)
}
