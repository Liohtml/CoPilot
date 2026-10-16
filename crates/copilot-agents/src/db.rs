//! The `agents` statements of the agents routes and the sync, in the shapes
//! SQLAlchemy issues them: no `ORDER BY` where Python has none (MySQL picks
//! the same plan and row order for the same statement), the customer filter
//! before the search filter, `ilike` as `lower(col) LIKE lower(?)`.

use chrono::NaiveDateTime;
use sqlx::{MySql, QueryBuilder};

use copilot_auth::AccessScope;
use copilot_db::schema::TableRequirement;
use copilot_db::{Db, DbError};

use crate::schema::AgentRecord;

/// Columns this crate reads and writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
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
            "velociraptor_org",
            "velociraptor_id_pinned",
        ],
    },
    TableRequirement {
        table: "agent_datastore",
        columns: &["agent_id"],
    },
    TableRequirement {
        table: "agent_vulnerabilities",
        columns: &["agent_id"],
    },
];

/// Every column of [`AgentRecord`], qualified.
pub const AGENT_COLS: &str = "agents.id, agents.agent_id, agents.ip_address, agents.os, \
     agents.hostname, agents.label, agents.critical_asset, agents.wazuh_last_seen, \
     agents.velociraptor_id, agents.velociraptor_last_seen, agents.wazuh_agent_version, \
     agents.wazuh_agent_status, agents.velociraptor_agent_version, agents.customer_code, \
     agents.quarantined, agents.velociraptor_org, agents.velociraptor_id_pinned";

/// What `filter_query_by_customer_access` adds: nothing (deployment-wide),
/// `customer_code IN (…)`, or `false` (sees nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tenancy {
    /// No filter.
    All,
    /// `IN (…)`; never empty.
    In(Vec<String>),
    /// `WHERE false`.
    Nothing,
}

impl Tenancy {
    /// From an effective scope (`resolve_effective_customers`): a `"*"`
    /// anywhere means everything, as Python's `"*" in accessible` does.
    pub fn of(scope: &AccessScope) -> Self {
        match scope {
            AccessScope::All => Tenancy::All,
            AccessScope::Customers(codes) if codes.iter().any(|c| c == "*") => Tenancy::All,
            AccessScope::Customers(codes) if codes.is_empty() => Tenancy::Nothing,
            AccessScope::Customers(codes) => Tenancy::In(codes.clone()),
        }
    }

    /// Append `AND agents.customer_code IN (…)` (or nothing). `false` is the
    /// caller's to short-circuit.
    fn push(&self, qb: &mut QueryBuilder<'_, MySql>, first: &mut bool) {
        if let Tenancy::In(codes) = self {
            qb.push(if *first { " WHERE " } else { " AND " });
            *first = false;
            qb.push("agents.customer_code IN (");
            let mut sep = qb.separated(", ");
            for c in codes {
                sep.push_bind(c.clone());
            }
            qb.push(")");
        }
    }
}

/// One equality condition of a lookup.
#[derive(Debug, Clone)]
pub enum Cond<'a> {
    /// `agents.agent_id = ?`.
    AgentId(&'a str),
    /// `agents.hostname = ?`.
    Hostname(&'a str),
    /// `agents.customer_code = ?`.
    CustomerCode(&'a str),
    /// `agents.wazuh_agent_status = ?`.
    Status(&'a str),
    /// `agents.wazuh_last_seen < ?`.
    LastSeenBefore(NaiveDateTime),
    /// `agents.velociraptor_id = ?`.
    VelociraptorId(&'a str),
}

fn push_cond(qb: &mut QueryBuilder<'_, MySql>, c: &Cond<'_>) {
    match c {
        Cond::AgentId(v) => qb.push("agents.agent_id = ").push_bind(v.to_string()),
        Cond::Hostname(v) => qb.push("agents.hostname = ").push_bind(v.to_string()),
        Cond::CustomerCode(v) => qb.push("agents.customer_code = ").push_bind(v.to_string()),
        Cond::Status(v) => qb
            .push("agents.wazuh_agent_status = ")
            .push_bind(v.to_string()),
        Cond::LastSeenBefore(t) => qb.push("agents.wazuh_last_seen < ").push_bind(*t),
        Cond::VelociraptorId(v) => qb
            .push("agents.velociraptor_id = ")
            .push_bind(v.to_string()),
    };
}

/// `select(Agents)` with `conds`, then the tenancy filter, then the search
/// (`hostname`, `label`, `ip_address`, `agent_id` ilike `%search%`) and the
/// limit.
pub async fn select(
    db: &Db,
    conds: &[Cond<'_>],
    tenancy: &Tenancy,
    search: Option<&str>,
    limit: Option<i64>,
) -> Result<Vec<AgentRecord>, DbError> {
    if *tenancy == Tenancy::Nothing {
        return Ok(Vec::new());
    }
    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT {AGENT_COLS} FROM agents"));
    let mut first = true;
    for c in conds {
        qb.push(if first { " WHERE " } else { " AND " });
        first = false;
        push_cond(&mut qb, c);
    }
    tenancy.push(&mut qb, &mut first);
    if let Some(s) = search.filter(|s| !s.is_empty()) {
        let term = format!("%{s}%");
        qb.push(if first { " WHERE (" } else { " AND (" });
        for (i, col) in ["hostname", "label", "ip_address", "agent_id"]
            .iter()
            .enumerate()
        {
            if i > 0 {
                qb.push(" OR ");
            }
            qb.push(format!("lower(agents.{col}) LIKE lower("))
                .push_bind(term.clone())
                .push(")");
        }
        qb.push(")");
    }
    if let Some(n) = limit {
        qb.push(" LIMIT ").push_bind(n);
    }
    Ok(qb
        .build_query_as::<AgentRecord>()
        .fetch_all(db.pool())
        .await?)
}

/// `.scalars().first()` of [`select`] without search or limit.
pub async fn first(
    db: &Db,
    conds: &[Cond<'_>],
    tenancy: &Tenancy,
) -> Result<Option<AgentRecord>, DbError> {
    Ok(select(db, conds, tenancy, None, None)
        .await?
        .into_iter()
        .next())
}

/// `select(Agents.customer_code).filter(Agents.hostname == h)` with the
/// tenancy filter.
pub async fn customer_codes_of_hostname(
    db: &Db,
    hostname: &str,
    tenancy: &Tenancy,
) -> Result<Vec<Option<String>>, DbError> {
    if *tenancy == Tenancy::Nothing {
        return Ok(Vec::new());
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT agents.customer_code FROM agents WHERE agents.hostname = ",
    );
    qb.push_bind(hostname.to_string());
    let mut first = false;
    tenancy.push(&mut qb, &mut first);
    Ok(qb.build_query_scalar().fetch_all(db.pool()).await?)
}

/// One column update of a row by primary key.
pub enum Change<'a> {
    /// `critical_asset`.
    Critical(bool),
    /// `velociraptor_id` + `velociraptor_id_pinned = 1`.
    PinVelociraptorId(&'a str),
    /// `velociraptor_id_pinned = 0`.
    Unpin,
}

/// `agent.<field> = …; await session.commit()`.
pub async fn update(db: &Db, id: i32, change: Change<'_>) -> Result<(), DbError> {
    let q = match change {
        Change::Critical(b) => {
            sqlx::query("UPDATE agents SET critical_asset=? WHERE agents.id = ?").bind(b)
        }
        Change::PinVelociraptorId(v) => sqlx::query(
            "UPDATE agents SET velociraptor_id=?, velociraptor_id_pinned=? WHERE agents.id = ?",
        )
        .bind(v.to_string())
        .bind(true),
        Change::Unpin => {
            sqlx::query("UPDATE agents SET velociraptor_id_pinned=? WHERE agents.id = ?")
                .bind(false)
        }
    };
    q.bind(id).execute(db.pool()).await?;
    Ok(())
}

/// `delete_agent_from_database`: the agent's data-store rows, its
/// vulnerabilities, then every row with that agent id, in one transaction.
pub async fn delete_agent(db: &Db, agent_id: &str) -> Result<(), DbError> {
    let mut tx = db.pool().begin().await?;
    for sql in [
        "DELETE FROM agent_datastore WHERE agent_datastore.agent_id = ?",
        "DELETE FROM agent_vulnerabilities WHERE agent_vulnerabilities.agent_id = ?",
        "DELETE FROM agents WHERE agents.agent_id = ?",
    ] {
        sqlx::query(sql).bind(agent_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The Wazuh fields the sync writes.
#[derive(Debug, Clone)]
pub struct WazuhFields {
    /// `agent_id`.
    pub agent_id: String,
    /// `hostname`.
    pub hostname: String,
    /// `ip_address`.
    pub ip_address: String,
    /// `os`.
    pub os: String,
    /// `label`.
    pub label: String,
    /// `wazuh_last_seen`.
    pub wazuh_last_seen: NaiveDateTime,
    /// `wazuh_agent_version`.
    pub wazuh_agent_version: String,
    /// `wazuh_agent_status`.
    pub wazuh_agent_status: String,
    /// `customer_code`.
    pub customer_code: Option<String>,
}

/// `existing_agent.update_wazuh_agent_from_model(…)` + commit.
pub async fn update_wazuh(db: &Db, id: i32, f: &WazuhFields) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE agents SET agent_id=?, ip_address=?, os=?, hostname=?, label=?, wazuh_last_seen=?, \
         wazuh_agent_version=?, wazuh_agent_status=?, customer_code=? WHERE agents.id = ?",
    )
    .bind(&f.agent_id)
    .bind(&f.ip_address)
    .bind(&f.os)
    .bind(&f.hostname)
    .bind(&f.label)
    .bind(f.wazuh_last_seen)
    .bind(&f.wazuh_agent_version)
    .bind(&f.wazuh_agent_status)
    .bind(&f.customer_code)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// `Agents.create_wazuh_agent_from_model(…)` + `session.add` + commit.
pub async fn insert_wazuh(db: &Db, f: &WazuhFields) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO agents (agent_id, ip_address, os, hostname, label, critical_asset, \
         wazuh_last_seen, velociraptor_id, velociraptor_last_seen, wazuh_agent_version, \
         wazuh_agent_status, velociraptor_agent_version, customer_code, quarantined, \
         velociraptor_org, velociraptor_id_pinned) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, \
         NULL, ?, ?, NULL, ?)",
    )
    .bind(&f.agent_id)
    .bind(&f.ip_address)
    .bind(&f.os)
    .bind(&f.hostname)
    .bind(&f.label)
    .bind(false)
    .bind(f.wazuh_last_seen)
    .bind(&f.wazuh_agent_version)
    .bind(&f.wazuh_agent_status)
    .bind(&f.customer_code)
    .bind(false)
    .bind(false)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// The plain snapshot `sync_agents_velociraptor` takes of every row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentRefRow {
    /// `id`.
    pub id: i32,
    /// `hostname`.
    pub hostname: String,
    /// `velociraptor_id`.
    pub velociraptor_id: Option<String>,
    /// `velociraptor_id_pinned`.
    pub velociraptor_id_pinned: bool,
    /// `customer_code`.
    pub customer_code: Option<String>,
}

/// `select(Agents)` (every row, no order).
pub async fn all_refs(db: &Db) -> Result<Vec<AgentRefRow>, DbError> {
    // No covering index holds these columns: the scan is the primary key's,
    // the order of Python's `select(Agents)`.
    Ok(sqlx::query_as::<_, AgentRefRow>(
        "SELECT agents.id, agents.hostname, agents.velociraptor_id, \
         agents.velociraptor_id_pinned, agents.customer_code FROM agents",
    )
    .fetch_all(db.pool())
    .await?)
}

/// `agent.update_velociraptor_details(…)` + commit; `false` when the row
/// is gone (`session.get` returned `None`).
pub async fn update_velociraptor(
    db: &Db,
    id: i32,
    velociraptor_id: Option<&str>,
    last_seen: Option<NaiveDateTime>,
    version: Option<&str>,
    org: Option<&str>,
) -> Result<bool, DbError> {
    let exists: Option<i32> =
        sqlx::query_scalar("SELECT agents.id FROM agents WHERE agents.id = ?")
            .bind(id)
            .fetch_optional(db.pool())
            .await?;
    if exists.is_none() {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE agents SET velociraptor_id=?, velociraptor_last_seen=?, \
         velociraptor_agent_version=?, velociraptor_org=? WHERE agents.id = ?",
    )
    .bind(velociraptor_id)
    .bind(last_seen)
    .bind(version)
    .bind(org)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(true)
}
