//! Port of `app/customer_portal/schema/agents.py`.

use serde::Serialize;

use copilot_agents::schema::AgentRecord;

/// `PortalAgentStats`: over every agent in scope, whatever the filters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PortalAgentStats {
    /// Agents in scope.
    pub total: i64,
    /// `active`.
    pub active: i64,
    /// Critical assets.
    pub critical: i64,
    /// `disconnected` or `never_connected`.
    pub offline: i64,
}

/// `PortalAgentsResponse`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortalAgentsResponse {
    /// The page (rows in `Agents`' declaration order).
    pub agents: Vec<AgentRecord>,
    /// Agents matching the filters.
    pub total: i64,
    /// The cards.
    pub stats: PortalAgentStats,
    /// Distinct statuses in scope.
    pub statuses: Vec<String>,
    /// Distinct operating systems in scope.
    pub os_list: Vec<String>,
    /// Always `true`.
    pub success: bool,
    /// `"{total} agents found"`.
    pub message: String,
}
