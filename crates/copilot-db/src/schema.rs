//! Schema compatibility checks.
//!
//! **Alembic owns the schema** for as long as the Python backend runs: it
//! migrates at its own startup, and the Rust service never creates or alters
//! a table. Each feature crate declares the columns it reads and writes
//! ([`TableRequirement`]); `copilot doctor` and the server's startup check
//! verify them against `information_schema` and report the Alembic revision,
//! so a Rust build deployed against an older database fails loudly instead
//! of at the first query.

use crate::{Db, DbError};

/// The Alembic head this Rust tree was written and tested against.
pub const TESTED_ALEMBIC_HEAD: &str = "c1241a1b2c3d";

/// Columns a module needs in one table.
#[derive(Debug, Clone, Copy)]
pub struct TableRequirement {
    /// Table name.
    pub table: &'static str,
    /// Column names.
    pub columns: &'static [&'static str],
}

/// The tables `copilot-db` itself reads or writes.
pub const CORE_REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "user",
        columns: &[
            "id",
            "username",
            "email",
            "role_id",
            "created_at",
            "last_login_at",
        ],
    },
    TableRequirement {
        table: "user_customer_access",
        columns: &["id", "user_id", "customer_code"],
    },
    TableRequirement {
        table: "customers",
        columns: &["id", "customer_code"],
    },
    TableRequirement {
        table: "connectors",
        columns: &[
            "id",
            "connector_name",
            "connector_type",
            "connector_url",
            "connector_last_updated",
            "connector_username",
            "connector_password",
            "connector_api_key",
            "connector_description",
            "connector_supports",
            "connector_configured",
            "connector_verified",
            "connector_accepts_host_only",
            "connector_accepts_api_key",
            "connector_accepts_username_password",
            "connector_accepts_file",
            "connector_accepts_extra_data",
            "connector_extra_data",
            "connector_enabled",
        ],
    },
    TableRequirement {
        table: "audit_log",
        columns: &[
            "timestamp",
            "actor_user_id",
            "actor_username",
            "customer_code",
            "action",
            "entity_type",
            "entity_id",
            "result",
            "old_value",
            "new_value",
            "source_ip",
            "details",
        ],
    },
    TableRequirement {
        table: "log_entries",
        columns: &[
            "timestamp",
            "event_type",
            "user_id",
            "route",
            "method",
            "status_code",
            "message",
            "additional_info",
        ],
    },
    TableRequirement {
        table: "incident_management_alert",
        columns: &[
            "id",
            "alert_name",
            "customer_code",
            "status",
            "source",
            "assigned_to",
            "alert_creation_time",
        ],
    },
    TableRequirement {
        table: "incident_management_asset",
        columns: &["id", "alert_linked", "asset_name"],
    },
];

/// Current `alembic_version.version_num`, `None` for an unmigrated database.
pub async fn alembic_revision(db: &Db) -> Result<Option<String>, DbError> {
    let present = sqlx::query_scalar::<_, String>(
        "SELECT CAST(table_name AS CHAR CHARACTER SET utf8mb4) FROM information_schema.tables \
         WHERE table_schema = DATABASE() AND table_name = 'alembic_version'",
    )
    .fetch_optional(db.pool())
    .await?;
    if present.is_none() {
        return Ok(None);
    }
    let rev = sqlx::query_scalar::<_, String>("SELECT version_num FROM alembic_version LIMIT 1")
        .fetch_optional(db.pool())
        .await?;
    Ok(rev)
}

/// Every `table.column` in `requirements` that the database lacks.
pub async fn missing_columns(
    db: &Db,
    requirements: &[TableRequirement],
) -> Result<Vec<String>, DbError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        // information_schema names are binary-collated: MySQL reports them as
        // VARBINARY, which does not decode into a String without the cast.
        "SELECT CAST(table_name AS CHAR CHARACTER SET utf8mb4), \
         CAST(column_name AS CHAR CHARACTER SET utf8mb4) FROM information_schema.columns \
         WHERE table_schema = DATABASE()",
    )
    .fetch_all(db.pool())
    .await?;
    let present: std::collections::HashSet<(String, String)> = rows.into_iter().collect();
    let mut missing = Vec::new();
    for req in requirements {
        for col in req.columns {
            if !present.contains(&(req.table.to_string(), (*col).to_string())) {
                missing.push(format!("{}.{}", req.table, col));
            }
        }
    }
    Ok(missing)
}
