//! Port of `app/healthchecks/agents/services/agents.py` (the database half).
//!
//! Pure: the caller supplies the agents, the clock and the window. Python
//! compares with `datetime.now()` — the process's local clock, UTC in the
//! backend image — against naive UTC columns; the port uses UTC outright.
//!
//! The window is built per agent, and only for an agent with a check-in in
//! the past — as in Python, where an out-of-range `timedelta` is an error
//! only once such an agent is reached.

use chrono::NaiveDateTime;

use copilot_db::agents::AgentRow;
use copilot_web::ApiError;

use crate::schema::{ExtendedAgent, HealthCheckResponse, TimeCriteria};

/// The Wazuh manager's own agent id, left out of fleet checks.
pub const WAZUH_MANAGER_AGENT_ID: &str = "000";

const WAZUH_MESSAGE: &str = "Wazuh agent healthcheck fetched successfully";
const VELOCIRAPTOR_MESSAGE: &str = "Velociraptor agent healthcheck fetched successfully";

/// Missing, in the future, or older than the window.
fn stale(
    last_seen: Option<NaiveDateTime>,
    now: NaiveDateTime,
    criteria: &TimeCriteria,
) -> Result<bool, ApiError> {
    Ok(match last_seen {
        None => true,
        Some(t) if t > now => true,
        Some(t) => now - t > criteria.window()?,
    })
}

/// `is_wazuh_agent_unhealthy`.
pub fn wazuh_verdict(
    a: &AgentRow,
    now: NaiveDateTime,
    criteria: &TimeCriteria,
) -> Result<ExtendedAgent, ApiError> {
    let mut e = ExtendedAgent::from_row(a);
    e.unhealthy_wazuh_agent = Some(stale(Some(a.wazuh_last_seen), now, criteria)?);
    Ok(e)
}

/// `is_velociraptor_agent_unhealthy`: no client id counts as unhealthy too.
pub fn velociraptor_verdict(
    a: &AgentRow,
    now: NaiveDateTime,
    criteria: &TimeCriteria,
) -> Result<ExtendedAgent, ApiError> {
    let mut e = ExtendedAgent::from_row(a);
    let last_seen = a.velociraptor_id.as_ref().and(a.velociraptor_last_seen);
    e.unhealthy_velociraptor_agent = Some(stale(last_seen, now, criteria)?);
    Ok(e)
}

/// Which tool a check asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `wazuh_last_seen`.
    Wazuh,
    /// `velociraptor_id` + `velociraptor_last_seen`.
    Velociraptor,
}

impl Tool {
    fn verdict(
        self,
        a: &AgentRow,
        now: NaiveDateTime,
        criteria: &TimeCriteria,
    ) -> Result<(ExtendedAgent, bool), ApiError> {
        Ok(match self {
            Tool::Wazuh => {
                let e = wazuh_verdict(a, now, criteria)?;
                let bad = e.unhealthy_wazuh_agent == Some(true);
                (e, bad)
            }
            Tool::Velociraptor => {
                let e = velociraptor_verdict(a, now, criteria)?;
                let bad = e.unhealthy_velociraptor_agent == Some(true);
                (e, bad)
            }
        })
    }

    fn response(
        self,
        healthy: Vec<ExtendedAgent>,
        unhealthy: Vec<ExtendedAgent>,
    ) -> HealthCheckResponse {
        match self {
            Tool::Wazuh => HealthCheckResponse {
                healthy_wazuh_agents: Some(healthy),
                unhealthy_wazuh_agents: Some(unhealthy),
                message: WAZUH_MESSAGE.into(),
                success: true,
                ..HealthCheckResponse::default()
            },
            Tool::Velociraptor => HealthCheckResponse {
                healthy_velociraptor_agents: Some(healthy),
                unhealthy_velociraptor_agents: Some(unhealthy),
                message: VELOCIRAPTOR_MESSAGE.into(),
                success: true,
                ..HealthCheckResponse::default()
            },
        }
    }
}

/// `wazuh_agents_healthcheck` / `velociraptor_agents_healthcheck`: the
/// fleet, without the Wazuh manager, split in row order.
pub fn fleet(
    tool: Tool,
    agents: &[AgentRow],
    now: NaiveDateTime,
    criteria: &TimeCriteria,
) -> Result<HealthCheckResponse, ApiError> {
    let mut healthy = Vec::new();
    let mut unhealthy = Vec::new();
    for a in agents
        .iter()
        .filter(|a| a.agent_id != WAZUH_MANAGER_AGENT_ID)
    {
        let (e, bad) = tool.verdict(a, now, criteria)?;
        if bad {
            unhealthy.push(e);
        } else {
            healthy.push(e);
        }
    }
    Ok(tool.response(healthy, unhealthy))
}

/// `wazuh_agent_healthcheck` / `velociraptor_agent_healthcheck`: one agent,
/// the manager included.
pub fn single(
    tool: Tool,
    agent: &AgentRow,
    now: NaiveDateTime,
    criteria: &TimeCriteria,
) -> Result<HealthCheckResponse, ApiError> {
    let (e, bad) = tool.verdict(agent, now, criteria)?;
    Ok(if bad {
        tool.response(Vec::new(), vec![e])
    } else {
        tool.response(vec![e], Vec::new())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    fn agent(id: &str, wazuh: &str, velo: Option<(&str, &str)>) -> AgentRow {
        AgentRow {
            id: 1,
            os: "linux".into(),
            label: "l".into(),
            wazuh_last_seen: t(wazuh),
            velociraptor_last_seen: velo.map(|v| t(v.1)),
            velociraptor_agent_version: None,
            ip_address: "10.0.0.1".into(),
            agent_id: id.into(),
            hostname: format!("host-{id}"),
            critical_asset: false,
            velociraptor_id: velo.map(|v| v.0.to_string()),
            wazuh_agent_version: "4.9".into(),
            customer_code: Some("acme".into()),
            wazuh_agent_status: "active".into(),
            quarantined: false,
        }
    }

    const NOW: &str = "2026-01-01 12:00:00";
    const HOUR: TimeCriteria = TimeCriteria {
        minutes: 60,
        hours: 0,
        days: 0,
    };

    #[test]
    fn wazuh_fleet_skips_the_manager_and_splits() {
        let agents = [
            agent("000", "2026-01-01 11:59:00", None),
            agent("001", "2026-01-01 11:30:00", None),
            agent("002", "2026-01-01 10:00:00", None),
            agent("003", "2026-01-02 00:00:00", None),
        ];
        let r = fleet(Tool::Wazuh, &agents, t(NOW), &HOUR).unwrap();
        let ids = |v: &Option<Vec<ExtendedAgent>>| {
            v.as_ref()
                .unwrap()
                .iter()
                .map(|a| a.agent_id.clone().unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&r.healthy_wazuh_agents), ["001"]);
        assert_eq!(
            ids(&r.unhealthy_wazuh_agents),
            ["002", "003"],
            "old, future"
        );
        assert_eq!(r.healthy_velociraptor_agents, None);
        // An agent exactly at the edge of the window is still healthy.
        let edge = single(
            Tool::Wazuh,
            &agent("000", "2026-01-01 11:00:00", None),
            t(NOW),
            &HOUR,
        )
        .unwrap();
        assert_eq!(edge.healthy_wazuh_agents.unwrap().len(), 1);
    }

    #[test]
    fn an_out_of_range_window_fails_only_when_used() {
        let huge = TimeCriteria {
            minutes: 0,
            hours: 0,
            days: 1_000_000_000,
        };
        // Only the manager, or only future check-ins: Python never builds the timedelta.
        let quiet = [
            agent("000", "2026-01-01 11:00:00", None),
            agent("001", "2027-01-01 00:00:00", None),
        ];
        assert!(fleet(Tool::Wazuh, &quiet, t(NOW), &huge).is_ok());
        let past = [agent("002", "2026-01-01 11:00:00", None)];
        assert!(fleet(Tool::Wazuh, &past, t(NOW), &huge).is_err());
    }

    #[test]
    fn velociraptor_needs_an_id_and_a_check_in() {
        let now = t(NOW);
        let w = &HOUR;
        assert_eq!(
            velociraptor_verdict(&agent("001", NOW, None), now, w)
                .unwrap()
                .unhealthy_velociraptor_agent,
            Some(true)
        );
        assert_eq!(
            velociraptor_verdict(
                &agent("001", NOW, Some(("C.1", "2026-01-01 11:30:00"))),
                now,
                w
            )
            .unwrap()
            .unhealthy_velociraptor_agent,
            Some(false)
        );
    }

    #[test]
    fn response_shape_matches_pydantic() {
        let r = single(
            Tool::Velociraptor,
            &agent("001", NOW, Some(("C.1", NOW))),
            t(NOW),
            &HOUR,
        )
        .unwrap();
        let v = serde_json::to_value(&r).unwrap();
        let keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            [
                "healthy_wazuh_agents",
                "unhealthy_wazuh_agents",
                "healthy_velociraptor_agents",
                "unhealthy_velociraptor_agents",
                "healthy_recent_logs_collected",
                "unhealthy_recent_logs_collected",
                "message",
                "success"
            ]
        );
        assert_eq!(
            v["healthy_velociraptor_agents"][0],
            json!({"id": 1, "os": "linux", "label": "l", "wazuh_last_seen": "2026-01-01T12:00:00",
                   "velociraptor_last_seen": "2026-01-01T12:00:00", "velociraptor_agent_version": null,
                   "ip_address": "10.0.0.1", "agent_id": "001", "hostname": "host-001",
                   "critical_asset": false, "velociraptor_id": "C.1", "wazuh_agent_version": "4.9",
                   "customer_code": "acme", "unhealthy_wazuh_agent": null,
                   "unhealthy_velociraptor_agent": false, "unhealthy_recent_logs_collected": null})
        );
    }
}
