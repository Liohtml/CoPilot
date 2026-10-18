//! Port of `app/healthchecks/agents/schema/agents.py` (the database half).

use chrono::NaiveDateTime;
use serde::Serialize;

use copilot_core::time::pydantic;
use copilot_db::agents::AgentRow;
use copilot_web::validate::{IntRules, Validator};
use copilot_web::{ApiError, QueryPairs};

/// `ExtendedAgentModel`: the agent as `healthchecks` sees it (no status or
/// quarantine flag) plus the verdict. Only one of the two `unhealthy_*`
/// flags is ever set; `unhealthy_recent_logs_collected` is always `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtendedAgent {
    /// Primary key.
    pub id: Option<i32>,
    /// Operating system.
    pub os: Option<String>,
    /// Label.
    pub label: Option<String>,
    /// Wazuh last seen.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub wazuh_last_seen: Option<NaiveDateTime>,
    /// Velociraptor last seen.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub velociraptor_last_seen: Option<NaiveDateTime>,
    /// Velociraptor agent version.
    pub velociraptor_agent_version: Option<String>,
    /// IP address.
    pub ip_address: Option<String>,
    /// Wazuh agent id.
    pub agent_id: Option<String>,
    /// Hostname.
    pub hostname: Option<String>,
    /// Critical asset.
    pub critical_asset: Option<bool>,
    /// Velociraptor client id.
    pub velociraptor_id: Option<String>,
    /// Wazuh agent version.
    pub wazuh_agent_version: Option<String>,
    /// Tenant.
    pub customer_code: Option<String>,
    /// Wazuh verdict.
    pub unhealthy_wazuh_agent: Option<bool>,
    /// Velociraptor verdict.
    pub unhealthy_velociraptor_agent: Option<bool>,
    /// Log-collection verdict (the indexer check; never set here).
    pub unhealthy_recent_logs_collected: Option<bool>,
}

impl ExtendedAgent {
    /// The agent with no verdict yet.
    pub fn from_row(a: &AgentRow) -> Self {
        Self {
            id: Some(a.id),
            os: Some(a.os.clone()),
            label: Some(a.label.clone()),
            wazuh_last_seen: Some(a.wazuh_last_seen),
            velociraptor_last_seen: a.velociraptor_last_seen,
            velociraptor_agent_version: a.velociraptor_agent_version.clone(),
            ip_address: Some(a.ip_address.clone()),
            agent_id: Some(a.agent_id.clone()),
            hostname: Some(a.hostname.clone()),
            critical_asset: Some(a.critical_asset),
            velociraptor_id: a.velociraptor_id.clone(),
            wazuh_agent_version: Some(a.wazuh_agent_version.clone()),
            customer_code: a.customer_code.clone(),
            unhealthy_wazuh_agent: None,
            unhealthy_velociraptor_agent: None,
            unhealthy_recent_logs_collected: None,
        }
    }
}

/// `AgentHealthCheckResponse` — every list is `null` unless the check
/// filled it, and `message` comes before `success`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HealthCheckResponse {
    /// Healthy per Wazuh.
    pub healthy_wazuh_agents: Option<Vec<ExtendedAgent>>,
    /// Unhealthy per Wazuh.
    pub unhealthy_wazuh_agents: Option<Vec<ExtendedAgent>>,
    /// Healthy per Velociraptor.
    pub healthy_velociraptor_agents: Option<Vec<ExtendedAgent>>,
    /// Unhealthy per Velociraptor.
    pub unhealthy_velociraptor_agents: Option<Vec<ExtendedAgent>>,
    /// Indexer check (not ported).
    pub healthy_recent_logs_collected: Option<Vec<ExtendedAgent>>,
    /// Indexer check (not ported).
    pub unhealthy_recent_logs_collected: Option<Vec<ExtendedAgent>>,
    /// Human-readable outcome.
    pub message: String,
    /// Always `true`.
    pub success: bool,
}

/// `TimeCriteriaModel`: how recently an agent must have checked in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeCriteria {
    /// Minutes (default 60).
    pub minutes: i64,
    /// Hours (default 0).
    pub hours: i64,
    /// Days (default 0).
    pub days: i64,
}

/// `timedelta`'s range: `|days| <= 999_999_999`.
const MAX_TIMEDELTA_DAYS: i128 = 999_999_999;

impl TimeCriteria {
    /// `?minutes=60&hours=0&days=0` (plain ints, no bounds).
    pub fn from_query(v: &mut Validator, q: &QueryPairs) -> Self {
        let rules = IntRules::default();
        Self {
            minutes: q.int_or(v, "minutes", rules, 60),
            hours: q.int_or(v, "hours", rules, 0),
            days: q.int_or(v, "days", rules, 0),
        }
    }

    /// `timedelta(minutes=minutes + hours * 60 + days * 1440)`. A window
    /// past `timedelta`'s range is Python's `OverflowError`: a bare 500.
    pub fn window(&self) -> Result<chrono::Duration, ApiError> {
        let total = i128::from(self.minutes)
            + i128::from(self.hours) * 60
            + i128::from(self.days) * 24 * 60;
        let days = total.div_euclid(24 * 60);
        if !(-MAX_TIMEDELTA_DAYS..=MAX_TIMEDELTA_DAYS).contains(&days) {
            return Err(ApiError::internal(format!(
                "OverflowError: days={days}; must have magnitude <= 999999999"
            )));
        }
        i64::try_from(total)
            .ok()
            .and_then(chrono::Duration::try_minutes)
            .ok_or_else(|| ApiError::internal("healthcheck window out of range"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_matches_timedelta() {
        let c = |minutes, hours, days| TimeCriteria {
            minutes,
            hours,
            days,
        };
        assert_eq!(c(60, 0, 0).window().unwrap(), chrono::Duration::minutes(60));
        assert_eq!(
            c(5, 2, 1).window().unwrap(),
            chrono::Duration::minutes(5 + 120 + 1440)
        );
        assert_eq!(
            c(-10, 0, 0).window().unwrap(),
            chrono::Duration::minutes(-10)
        );
        assert!(c(0, 0, 999_999_999).window().is_ok());
        assert!(c(0, 0, 1_000_000_000).window().is_err());
        assert!(c(0, 0, -999_999_999).window().is_ok());
        assert!(c(-1, 0, -999_999_999).window().is_err());
    }
}
