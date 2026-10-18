//! Running the plan on a database.

use std::time::Instant;

use sqlx::MySqlConnection;

use crate::migrations::{BASELINE, Migration};
use crate::plan::{Baseline, Plan, Refusal, plan};
use crate::sql::split_statements;
use crate::state::{HISTORY_DDL, Method, SchemaState, inspect};

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The baseline was recorded for a database at the Alembic head.
    Adopted(String),
    /// A migration's SQL ran.
    Applied {
        /// `0001_baseline`, …
        migration: String,
        /// How long it took.
        ms: u64,
    },
}

/// The outcome of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// What was found.
    pub before: SchemaState,
    /// What was done, in order (empty: nothing to do).
    pub actions: Vec<Action>,
    /// What deserves an operator's look.
    pub warnings: Vec<String>,
}

/// Why a run stopped.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// The database is in a state the runner does not touch.
    #[error("{0}")]
    Refused(Refusal),
    /// A statement of a migration failed; the migration stays recorded as
    /// unfinished.
    #[error(
        "migration {migration} failed at statement {index} ({statement}): {source}. It stays \
         recorded as unfinished in copilot_rs_schema_history: repair the schema, delete that row, \
         then start again"
    )]
    Statement {
        /// The migration.
        migration: String,
        /// The statement's position, from 1.
        index: usize,
        /// Its beginning.
        statement: String,
        /// MySQL's error.
        source: sqlx::Error,
    },
    /// Reading the state or writing the history failed.
    #[error("migrations: {0}")]
    Db(#[from] sqlx::Error),
}

/// The state and the plan, without changing anything (`copilot doctor`).
pub async fn status(
    conn: &mut MySqlConnection,
    migrations: &[Migration],
) -> Result<(SchemaState, Result<Plan, Refusal>), sqlx::Error> {
    let state = inspect(conn).await?;
    let decision = plan(&state, migrations);
    Ok((state, decision))
}

/// Bring the connection's database to the last of `migrations`. Run it on
/// the connection that holds the [`crate::StartupLock`].
pub async fn migrate(
    conn: &mut MySqlConnection,
    migrations: &[Migration],
) -> Result<Report, MigrateError> {
    let before = inspect(conn).await?;
    let plan = plan(&before, migrations).map_err(MigrateError::Refused)?;
    let mut actions = Vec::new();
    if !plan.is_noop() {
        sqlx::raw_sql(HISTORY_DDL).execute(&mut *conn).await?;
    }
    match plan.baseline {
        Baseline::Recorded => {}
        Baseline::Adopt => {
            record(conn, &BASELINE, Method::Adopted, true).await?;
            tracing::info!(
                baseline = %BASELINE.label(),
                "the database is at Alembic {}: recorded as the baseline, no table touched",
                crate::ALEMBIC_HEAD
            );
            actions.push(Action::Adopted(BASELINE.label()));
        }
        Baseline::Create => {
            let ms = apply(conn, &BASELINE).await?;
            actions.push(Action::Applied {
                migration: BASELINE.label(),
                ms,
            });
        }
    }
    for m in &plan.pending {
        let ms = apply(conn, m).await?;
        actions.push(Action::Applied {
            migration: m.label(),
            ms,
        });
    }
    for w in &plan.warnings {
        tracing::warn!("{w}");
    }
    Ok(Report {
        before,
        actions,
        warnings: plan.warnings,
    })
}

async fn record(
    conn: &mut MySqlConnection,
    m: &Migration,
    method: Method,
    success: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO copilot_rs_schema_history \
         (version, name, checksum, method, success, applied_at, execution_ms) \
         VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP(), 0)",
    )
    .bind(m.version)
    .bind(m.name)
    .bind(m.checksum())
    .bind(method.as_str())
    .bind(success)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Record the migration as started, run its statements, mark it done.
async fn apply(conn: &mut MySqlConnection, m: &Migration) -> Result<u64, MigrateError> {
    tracing::info!(migration = %m.label(), "applying migration");
    record(conn, m, Method::Applied, false).await?;
    let started = Instant::now();
    for (i, stmt) in split_statements(m.sql).into_iter().enumerate() {
        if let Err(source) = sqlx::raw_sql(stmt).execute(&mut *conn).await {
            return Err(MigrateError::Statement {
                migration: m.label(),
                index: i + 1,
                statement: stmt.chars().take(120).collect(),
                source,
            });
        }
    }
    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    sqlx::query(
        "UPDATE copilot_rs_schema_history SET success = 1, execution_ms = ? WHERE version = ?",
    )
    .bind(i64::try_from(ms).unwrap_or(i64::MAX))
    .bind(m.version)
    .execute(&mut *conn)
    .await?;
    tracing::info!(migration = %m.label(), ms, "migration applied");
    Ok(ms)
}
