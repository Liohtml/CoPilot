//! The `agents` statements of these routers, in the shapes SQLAlchemy issues
//! them (`select(Agents)` with its filters in Python's order, no `ORDER BY`
//! where Python has none, so MySQL reads the rows in the same order), and
//! the tenant scope those routes resolve.

use sqlx::{MySql, QueryBuilder};

use copilot_agents::db::AGENT_COLS;
use copilot_agents::schema::AgentRecord;
use copilot_auth::AccessScope;
use copilot_db::{Db, DbError};

/// One `WHERE` term of an `agents` select.
#[derive(Debug, Clone, Copy)]
pub enum On<'a> {
    /// `agents.customer_code IN (…)` (an empty list matches nothing).
    CustomerIn(&'a [String]),
    /// `agents.customer_code = ?`.
    Customer(&'a str),
    /// `agents.hostname = ?`.
    Hostname(&'a str),
    /// `agents.agent_id = ?`.
    AgentId(&'a str),
    /// `agents.velociraptor_id = ?`.
    VelociraptorId(&'a str),
}

/// `IN (…)`, or SQLAlchemy's always-false rendering of an empty list.
pub fn push_in(qb: &mut QueryBuilder<'_, MySql>, column: &str, values: &[String]) {
    if values.is_empty() {
        qb.push(format!("{column} IN (NULL) AND (1 != 1)"));
        return;
    }
    qb.push(format!("{column} IN ("));
    let mut sep = qb.separated(", ");
    for v in values {
        sep.push_bind(v.clone());
    }
    qb.push(")");
}

/// `select(Agents).filter(…)…` — every term in order.
pub async fn select(db: &Db, terms: &[On<'_>]) -> Result<Vec<AgentRecord>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT {AGENT_COLS} \nFROM agents"));
    for (i, term) in terms.iter().enumerate() {
        qb.push(if i == 0 { " \nWHERE " } else { " AND " });
        match term {
            On::CustomerIn(codes) => push_in(&mut qb, "agents.customer_code", codes),
            On::Customer(c) => {
                qb.push("agents.customer_code = ").push_bind(c.to_string());
            }
            On::Hostname(h) => {
                qb.push("agents.hostname = ").push_bind(h.to_string());
            }
            On::AgentId(a) => {
                qb.push("agents.agent_id = ").push_bind(a.to_string());
            }
            On::VelociraptorId(v) => {
                qb.push("agents.velociraptor_id = ")
                    .push_bind(v.to_string());
            }
        }
    }
    Ok(qb
        .build_query_as::<AgentRecord>()
        .fetch_all(db.pool())
        .await?)
}

/// `.scalars().first()` of [`select`].
pub async fn first(db: &Db, terms: &[On<'_>]) -> Result<Option<AgentRecord>, DbError> {
    Ok(select(db, terms).await?.into_iter().next())
}

/// `{agent.hostname: agent.customer_code for agent in select(Agents) if
/// agent.hostname}`: a later row of a hostname wins, as in the dict.
pub async fn hostname_customers(db: &Db) -> Result<Vec<(String, Option<String>)>, DbError> {
    let mut map: Vec<(String, Option<String>)> = Vec::new();
    for agent in select(db, &[]).await? {
        if agent.hostname.is_empty() {
            continue;
        }
        match map.iter_mut().find(|(h, _)| *h == agent.hostname) {
            Some(slot) => slot.1 = agent.customer_code,
            None => map.push((agent.hostname, agent.customer_code)),
        }
    }
    Ok(map)
}

/// `customer_agent_map.get(hostname)`.
pub fn customer_of<'a>(map: &'a [(String, Option<String>)], hostname: &str) -> Option<&'a str> {
    map.iter()
        .find(|(h, _)| h == hostname)
        .and_then(|(_, c)| c.as_deref())
}

/// `get_user_accessible_customers` as these services test it: `None` for
/// `"*"` (an admin), else the list.
pub fn accessible(scope: &AccessScope) -> Option<Vec<String>> {
    match scope {
        AccessScope::All => None,
        AccessScope::Customers(codes) => Some(codes.clone()),
    }
}

/// `"*" in accessible or code in accessible`.
pub fn may_see(accessible: &Option<Vec<String>>, code: &str) -> bool {
    match accessible {
        None => true,
        Some(codes) => codes.iter().any(|c| c == code),
    }
}
