//! The `agents` rows the Velociraptor routes read: an endpoint is named by
//! its hostname or its client id, and resolved the way the Python routes
//! resolve it — `select(Agents).filter(…).first()`, unfiltered (the tenancy
//! checks run before, on the customer code of that same first row).

use copilot_db::schema::TableRequirement;
use copilot_db::{Db, DbError};

/// The columns these routes read and write.
pub const REQUIREMENTS: &[TableRequirement] = &[TableRequirement {
    table: "agents",
    columns: &[
        "id",
        "hostname",
        "os",
        "velociraptor_id",
        "velociraptor_org",
        "customer_code",
        "quarantined",
    ],
}];

/// What the routes need of an agent.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AgentRow {
    /// `agents.id`.
    pub id: i32,
    /// `os`.
    pub os: String,
    /// `velociraptor_id`.
    pub velociraptor_id: Option<String>,
    /// `velociraptor_org`.
    pub velociraptor_org: Option<String>,
    /// `customer_code`.
    pub customer_code: Option<String>,
}

// Every lookup selects one column the secondary indexes do not cover, so the
// scan is the primary key's: `.first()` is the lowest id, as in Python.
const COLS: &str = "agents.id, agents.os, agents.velociraptor_id, agents.velociraptor_org, \
                    agents.customer_code";

/// The first agent with this hostname.
pub async fn by_hostname(db: &Db, hostname: &str) -> Result<Option<AgentRow>, DbError> {
    Ok(sqlx::query_as::<_, AgentRow>(&format!(
        "SELECT {COLS} FROM agents WHERE agents.hostname = ? LIMIT 1"
    ))
    .bind(hostname)
    .fetch_optional(db.pool())
    .await?)
}

/// The first agent with this Velociraptor client id.
pub async fn by_client_id(db: &Db, client_id: &str) -> Result<Option<AgentRow>, DbError> {
    Ok(sqlx::query_as::<_, AgentRow>(&format!(
        "SELECT {COLS} FROM agents WHERE agents.velociraptor_id = ? LIMIT 1"
    ))
    .bind(client_id)
    .fetch_optional(db.pool())
    .await?)
}

/// `agent.quarantined = …` + commit.
pub async fn set_quarantined(db: &Db, id: i32, quarantined: bool) -> Result<(), DbError> {
    sqlx::query("UPDATE agents SET quarantined = ? WHERE agents.id = ?")
        .bind(quarantined)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
