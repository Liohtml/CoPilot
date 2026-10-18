//! What a database holds before the runner acts: its tables, its Alembic
//! revision and the Rust history.

use chrono::NaiveDateTime;
use sqlx::MySqlConnection;

/// The Rust-owned history table. No SQLModel table, Alembic table or
/// `_sqlx_migrations` can collide with the `copilot_rs_` prefix.
pub const HISTORY_TABLE: &str = "copilot_rs_schema_history";

/// Its definition, created before the first migration is recorded.
pub const HISTORY_DDL: &str = "CREATE TABLE IF NOT EXISTS `copilot_rs_schema_history` (\n  \
     `version` int NOT NULL,\n  \
     `name` varchar(255) NOT NULL,\n  \
     `checksum` char(64) NOT NULL,\n  \
     `method` varchar(16) NOT NULL,\n  \
     `success` tinyint(1) NOT NULL,\n  \
     `applied_at` datetime NOT NULL,\n  \
     `execution_ms` int NOT NULL,\n  \
     PRIMARY KEY (`version`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci";

/// How a history row came to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// The runner ran the migration's SQL.
    Applied,
    /// The database was already at the Alembic head: the baseline was
    /// recorded without touching a table.
    Adopted,
}

impl Method {
    /// The stored word.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Adopted => "adopted",
        }
    }
}

/// One row of [`HISTORY_TABLE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    /// The migration's version.
    pub version: i64,
    /// Its name.
    pub name: String,
    /// The checksum of the file that was applied (or adopted).
    pub checksum: String,
    /// `applied` / `adopted`.
    pub method: String,
    /// `false` while the migration runs, and after it failed part-way.
    pub success: bool,
    /// When the row was written (UTC).
    pub applied_at: NaiveDateTime,
}

/// `alembic_version` as found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alembic {
    /// No such table.
    Absent,
    /// The table, without a row.
    Empty,
    /// Its rows (one, unless the history was branched).
    Revisions(Vec<String>),
}

/// A database before the runner acts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaState {
    /// Every table and view, the history table excepted, by name.
    pub tables: Vec<String>,
    /// Whether the history table exists.
    pub history_table: bool,
    /// Its rows, by version.
    pub history: Vec<HistoryRow>,
    /// `alembic_version`.
    pub alembic: Alembic,
}

/// Read the state of the connection's database.
pub async fn inspect(conn: &mut MySqlConnection) -> Result<SchemaState, sqlx::Error> {
    let names: Vec<String> = sqlx::query_scalar(
        // information_schema names are binary-collated: cast to read them.
        "SELECT CAST(table_name AS CHAR CHARACTER SET utf8mb4) FROM information_schema.tables \
         WHERE table_schema = DATABASE() ORDER BY table_name",
    )
    .fetch_all(&mut *conn)
    .await?;
    let history_table = names.iter().any(|n| n == HISTORY_TABLE);
    let alembic = if names.iter().any(|n| n == "alembic_version") {
        let revs: Vec<String> = sqlx::query_scalar("SELECT version_num FROM alembic_version")
            .fetch_all(&mut *conn)
            .await?;
        if revs.is_empty() {
            Alembic::Empty
        } else {
            Alembic::Revisions(revs)
        }
    } else {
        Alembic::Absent
    };
    let history = if history_table {
        sqlx::query_as::<_, (i64, String, String, String, bool, NaiveDateTime)>(
            "SELECT version, name, checksum, method, success, applied_at \
             FROM copilot_rs_schema_history ORDER BY version",
        )
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .map(
            |(version, name, checksum, method, success, applied_at)| HistoryRow {
                version,
                name,
                checksum,
                method,
                success,
                applied_at,
            },
        )
        .collect()
    } else {
        Vec::new()
    };
    Ok(SchemaState {
        tables: names.into_iter().filter(|n| n != HISTORY_TABLE).collect(),
        history_table,
        history,
        alembic,
    })
}
