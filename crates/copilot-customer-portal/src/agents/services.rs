//! Port of `app/customer_portal/services/agents.py`: one page of the agents
//! a user may see, the cards and filter options over the whole scope, and
//! every filtered agent as CSV — all in SQL, with SQLAlchemy's statements
//! (scope first, then the filters; `ilike` as `lower(…) LIKE lower(…)`).

use sqlx::{MySql, QueryBuilder};

use copilot_agents::db::AGENT_COLS;
use copilot_agents::schema::AgentRecord;
use copilot_auth::AccessScope;
use copilot_db::{Db, DbError};
use copilot_incidents::store;
use copilot_web::form::py_strip;

use super::csv;
use super::schema::PortalAgentStats;

/// Wazuh statuses the portal counts as "offline" in its cards.
pub const OFFLINE_STATUSES: [&str; 2] = ["disconnected", "never_connected"];

/// `CSV_HEADERS`.
pub const CSV_HEADERS: [&str; 9] = [
    "Hostname",
    "Agent ID",
    "IP Address",
    "Operating System",
    "Status",
    "Last Seen",
    "Critical Asset",
    "Agent Version",
    "Customer Code",
];

/// `AgentFilters` (empty strings already read as unset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentFilters {
    /// Hostname, IP address or agent id, case-insensitively.
    pub search: Option<String>,
    /// Wazuh status.
    pub status: Option<String>,
    /// Operating system.
    pub os: Option<String>,
    /// Critical assets only.
    pub critical: bool,
}

/// `_scope`: the customers' clause; `None` when the user sees no agent.
/// `Some(None)` is every customer.
fn scope_clause(scope: &AccessScope) -> Option<Option<&[String]>> {
    match scope {
        AccessScope::All => Some(None),
        AccessScope::Customers(codes) if codes.iter().any(|c| c == "*") => Some(None),
        AccessScope::Customers(codes) if codes.is_empty() => None,
        AccessScope::Customers(codes) => Some(Some(codes.as_slice())),
    }
}

/// `WHERE <scope> AND <filters>` (each clause only when it applies).
fn push_where<'a>(
    qb: &mut QueryBuilder<'a, MySql>,
    customers: Option<&'a [String]>,
    filters: Option<&'a AgentFilters>,
) {
    let mut first = true;
    let mut and = |qb: &mut QueryBuilder<'a, MySql>| {
        qb.push(if first { " WHERE " } else { " AND " });
        first = false;
    };
    if let Some(codes) = customers {
        and(qb);
        qb.push("agents.customer_code IN (");
        store::push_list(qb, codes.iter().map(String::as_str));
        qb.push(")");
    }
    let Some(f) = filters else {
        return;
    };
    if let Some(search) = &f.search {
        let term = format!("%{}%", py_strip(search));
        and(qb);
        qb.push("(lower(agents.hostname) LIKE lower(")
            .push_bind(term.clone())
            .push(") OR lower(agents.ip_address) LIKE lower(")
            .push_bind(term.clone())
            .push(") OR lower(agents.agent_id) LIKE lower(")
            .push_bind(term)
            .push("))");
    }
    if let Some(status) = &f.status {
        and(qb);
        qb.push("agents.wazuh_agent_status = ")
            .push_bind(status.as_str());
    }
    if let Some(os) = &f.os {
        and(qb);
        qb.push("agents.os = ").push_bind(os.as_str());
    }
    if f.critical {
        and(qb);
        qb.push("agents.critical_asset IS true");
    }
}

/// `AgentsPage`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentsPage {
    /// The page.
    pub agents: Vec<AgentRecord>,
    /// Agents matching the filters.
    pub total: i64,
    /// The cards.
    pub stats: PortalAgentStats,
    /// Distinct statuses in scope (blank ones dropped).
    pub statuses: Vec<String>,
    /// Distinct operating systems in scope (blank ones dropped).
    pub os_list: Vec<String>,
}

/// `list_portal_agents`. `offset` is `(page - 1) * page_size`, which may not
/// fit MySQL's `OFFSET` (the caller's bare 500, as in Python).
pub async fn list(
    db: &Db,
    scope: &AccessScope,
    filters: &AgentFilters,
    offset: u64,
    page_size: i64,
) -> Result<AgentsPage, DbError> {
    let Some(customers) = scope_clause(scope) else {
        return Ok(AgentsPage::default());
    };
    let mut qb = QueryBuilder::<MySql>::new("SELECT count(agents.id) AS count_1 FROM agents");
    push_where(&mut qb, customers, Some(filters));
    let total = store::count(&mut qb, db).await?;

    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT {AGENT_COLS} FROM agents"));
    push_where(&mut qb, customers, Some(filters));
    qb.push(" ORDER BY agents.id LIMIT ")
        .push_bind(page_size)
        .push(" OFFSET ")
        .push_bind(offset);
    let agents = qb
        .build_query_as::<AgentRecord>()
        .fetch_all(db.pool())
        .await?;

    // Cards and filter options describe the whole scope, not the filtered list.
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT count(agents.id) AS count_1, \
         CAST(coalesce(sum(CASE WHEN (agents.wazuh_agent_status = 'active') THEN 1 ELSE 0 END), 0) \
         AS SIGNED) AS coalesce_1, \
         CAST(coalesce(sum(CASE WHEN (agents.critical_asset IS true) THEN 1 ELSE 0 END), 0) \
         AS SIGNED) AS coalesce_2, \
         CAST(coalesce(sum(CASE WHEN (agents.wazuh_agent_status IN ('disconnected', \
         'never_connected')) THEN 1 ELSE 0 END), 0) AS SIGNED) AS coalesce_3 FROM agents",
    );
    push_where(&mut qb, customers, None);
    let (count, active, critical, offline) = qb
        .build_query_as::<(i64, i64, i64, i64)>()
        .fetch_one(db.pool())
        .await?;
    let statuses = distinct(db, "wazuh_agent_status", customers).await?;
    let os_list = distinct(db, "os", customers).await?;
    Ok(AgentsPage {
        agents,
        total,
        stats: PortalAgentStats {
            total: count,
            active,
            critical,
            offline,
        },
        statuses,
        os_list,
    })
}

/// `select(Agents.<column>).where(*scope).distinct().order_by(Agents.<column>)`,
/// blank values dropped.
async fn distinct(
    db: &Db,
    column: &str,
    customers: Option<&[String]>,
) -> Result<Vec<String>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT DISTINCT agents.{column} FROM agents"));
    push_where(&mut qb, customers, None);
    qb.push(format!(" ORDER BY agents.{column}"));
    let values: Vec<String> = qb.build_query_scalar().fetch_all(db.pool()).await?;
    Ok(values.into_iter().filter(|v| !v.is_empty()).collect())
}

/// `export_portal_agents_csv`: every agent matching the filters, ISO 8601
/// timestamps.
pub async fn export_csv(
    db: &Db,
    scope: &AccessScope,
    filters: &AgentFilters,
) -> Result<String, DbError> {
    let mut out = csv::row(&CSV_HEADERS);
    let Some(customers) = scope_clause(scope) else {
        return Ok(out);
    };
    let mut qb = QueryBuilder::<MySql>::new(format!("SELECT {AGENT_COLS} FROM agents"));
    push_where(&mut qb, customers, Some(filters));
    qb.push(" ORDER BY agents.id");
    let rows = qb
        .build_query_as::<AgentRecord>()
        .fetch_all(db.pool())
        .await?;
    for a in rows {
        out.push_str(&csv::row(&[
            a.hostname,
            a.agent_id,
            a.ip_address,
            a.os,
            a.wazuh_agent_status,
            copilot_core::time::to_pydantic_iso(a.wazuh_last_seen),
            if a.critical_asset { "Yes" } else { "No" }.to_string(),
            a.wazuh_agent_version,
            a.customer_code.unwrap_or_default(),
        ]));
    }
    Ok(out)
}
