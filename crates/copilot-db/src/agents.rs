//! `agents` reads: the rows the customer and healthcheck routes return, and
//! the owner lookup behind `verify_agent_id_access`.
//!
//! Like the Python queries these carry no `ORDER BY` (see
//! [`crate::customers`] for why the shape is kept).

use chrono::NaiveDateTime;
use sqlx::{FromRow, MySql, QueryBuilder};

use crate::schema::TableRequirement;
use crate::{Db, DbError};

/// Columns this module needs.
pub const REQUIREMENTS: &[TableRequirement] = &[TableRequirement {
    table: "agents",
    columns: &[
        "id",
        "agent_id",
        "ip_address",
        "os",
        "hostname",
        "label",
        "critical_asset",
        "wazuh_last_seen",
        "velociraptor_id",
        "velociraptor_last_seen",
        "wazuh_agent_version",
        "wazuh_agent_status",
        "velociraptor_agent_version",
        "customer_code",
        "quarantined",
    ],
}];

/// One `agents` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AgentRow {
    /// Primary key.
    pub id: i32,
    /// Operating system.
    pub os: String,
    /// Label.
    pub label: String,
    /// Last check-in seen by Wazuh (naive UTC).
    pub wazuh_last_seen: NaiveDateTime,
    /// Last check-in seen by Velociraptor.
    pub velociraptor_last_seen: Option<NaiveDateTime>,
    /// Velociraptor agent version.
    pub velociraptor_agent_version: Option<String>,
    /// IP address.
    pub ip_address: String,
    /// Wazuh agent id (`000` is the manager).
    pub agent_id: String,
    /// Hostname.
    pub hostname: String,
    /// Critical asset flag.
    pub critical_asset: bool,
    /// Velociraptor client id.
    pub velociraptor_id: Option<String>,
    /// Wazuh agent version.
    pub wazuh_agent_version: String,
    /// Tenant.
    pub customer_code: Option<String>,
    /// Wazuh status (`active`, …).
    pub wazuh_agent_status: String,
    /// Quarantined by Velociraptor.
    pub quarantined: bool,
}

const AGENT_COLS: &str = "agents.id, agents.os, agents.label, agents.wazuh_last_seen, \
     agents.velociraptor_last_seen, agents.velociraptor_agent_version, agents.ip_address, \
     agents.agent_id, agents.hostname, agents.critical_asset, agents.velociraptor_id, \
     agents.wazuh_agent_version, agents.customer_code, agents.wazuh_agent_status, \
     agents.quarantined";

/// Agents of the given customers (`None` = every agent). `Some(&[])` reads
/// nothing.
pub async fn list_agents(db: &Db, codes: Option<&[String]>) -> Result<Vec<AgentRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT {AGENT_COLS} FROM agents"));
    if let Some(codes) = codes {
        if codes.is_empty() {
            return Ok(Vec::new());
        }
        qb.push(" WHERE agents.customer_code IN (");
        let mut sep = qb.separated(", ");
        for c in codes {
            sep.push_bind(c.clone());
        }
        qb.push(")");
    }
    Ok(qb.build_query_as::<AgentRow>().fetch_all(db.pool()).await?)
}

/// Agents of one customer (`= ?`, the customer routes' query).
pub async fn agents_of_customer(db: &Db, code: &str) -> Result<Vec<AgentRow>, DbError> {
    Ok(sqlx::query_as::<_, AgentRow>(&format!(
        "SELECT {AGENT_COLS} FROM agents WHERE agents.customer_code = ?"
    ))
    .bind(code)
    .fetch_all(db.pool())
    .await?)
}

/// The first agent with this Wazuh agent id.
pub async fn find_by_agent_id(db: &Db, agent_id: &str) -> Result<Option<AgentRow>, DbError> {
    Ok(sqlx::query_as::<_, AgentRow>(&format!(
        "SELECT {AGENT_COLS} FROM agents WHERE agents.agent_id = ? LIMIT 1"
    ))
    .bind(agent_id)
    .fetch_optional(db.pool())
    .await?)
}

/// `customer_code_for_agent`: the owning customer (`None` for an unknown
/// agent *or* a NULL code — both fail closed for scoped callers).
pub async fn customer_code_for_agent(db: &Db, agent_id: &str) -> Result<Option<String>, DbError> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT customer_code FROM agents WHERE agent_id = ? LIMIT 1",
    )
    .bind(agent_id)
    .fetch_optional(db.pool())
    .await?
    .flatten())
}
