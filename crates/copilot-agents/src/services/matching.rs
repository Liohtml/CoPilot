//! `app/agents/velociraptor/utils/matching.py` (#1195): which Velociraptor
//! client belongs to which agent. Pure; the precedence and the iteration
//! orders are Python's (dicts in insertion order), since which agent is
//! settled first decides what the others may still claim:
//!
//! 1. a pinned id resolves by client id only (a missing client: unresolved);
//! 2. an unpinned stored id is kept while its client exists and reports the
//!    agent's hostname, or no client reports it at all;
//! 3. exactly one unclaimed client with the agent's hostname;
//! 4. the stored client, when every hostname candidate is held by another
//!    agent.
//!
//! Two agents claiming the same client at one step resolve neither.

use std::collections::{HashMap, HashSet};

/// A client and the org it was listed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgClient {
    /// The org.
    pub org_id: String,
    /// `client.client_id`.
    pub client_id: String,
    /// `client.os_info.hostname`.
    pub hostname: String,
    /// `client.last_seen_at` (µs since the epoch).
    pub last_seen_at: i64,
    /// `client.agent_information.version`.
    pub version: String,
}

/// The fields of an `agents` row the matching reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRef {
    /// `agents.id`.
    pub key: i32,
    /// Hostname.
    pub hostname: String,
    /// Stored client id.
    pub velociraptor_id: Option<String>,
    /// Entered by hand.
    pub pinned: bool,
    /// Tenant.
    pub customer_code: Option<String>,
}

/// Why an agent got (or did not get) a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// `pinned`.
    Pinned,
    /// `stored_id`.
    StoredId,
    /// `hostname`.
    Hostname,
    /// `stored_id_fallback`.
    StoredIdFallback,
    /// `pinned_client_missing`.
    PinnedClientMissing,
    /// `ambiguous`.
    Ambiguous,
    /// `contested`.
    Contested,
    /// `no_match`.
    NoMatch,
}

/// The outcome for one agent; `client` is `None` when it must stay as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// Why.
    pub reason: Reason,
    /// The client.
    pub client: Option<OrgClient>,
    /// The candidates an unresolved agent had.
    pub candidates: Vec<String>,
}

impl Resolution {
    fn unresolved(reason: Reason, candidates: Vec<String>) -> Self {
        Self {
            reason,
            client: None,
            candidates,
        }
    }
}

/// An insertion-ordered `defaultdict(list)`.
struct Claims<'a> {
    order: Vec<String>,
    owners: HashMap<String, Vec<&'a AgentRef>>,
}

impl<'a> Claims<'a> {
    fn new() -> Self {
        Self {
            order: Vec::new(),
            owners: HashMap::new(),
        }
    }

    fn push(&mut self, client_id: &str, agent: &'a AgentRef) {
        if !self.owners.contains_key(client_id) {
            self.order.push(client_id.to_string());
        }
        self.owners
            .entry(client_id.to_string())
            .or_default()
            .push(agent);
    }

    fn drain(self) -> Vec<(String, Vec<&'a AgentRef>)> {
        let mut owners = self.owners;
        self.order
            .into_iter()
            .map(|id| {
                let o = owners.remove(&id).unwrap_or_default();
                (id, o)
            })
            .collect()
    }
}

/// `resolve_velociraptor_clients(agents, clients)`, keyed by `AgentRef.key`.
pub fn resolve_velociraptor_clients(
    agents: &[AgentRef],
    clients: &[OrgClient],
) -> HashMap<i32, Resolution> {
    let mut by_id: HashMap<&str, &OrgClient> = HashMap::new();
    let mut by_hostname: HashMap<&str, Vec<&OrgClient>> = HashMap::new();
    for c in clients {
        by_id.entry(c.client_id.as_str()).or_insert(c);
        if !c.hostname.is_empty() {
            by_hostname.entry(c.hostname.as_str()).or_default().push(c);
        }
    }
    let mut results: HashMap<i32, Resolution> = HashMap::new();
    let mut claimed: HashSet<String> = HashSet::new();

    let settle = |claims: Claims<'_>,
                  reason: Reason,
                  results: &mut HashMap<i32, Resolution>,
                  claimed: &mut HashSet<String>| {
        for (client_id, owners) in claims.drain() {
            claimed.insert(client_id.clone());
            if owners.len() == 1 {
                results.insert(
                    owners[0].key,
                    Resolution {
                        reason,
                        client: by_id.get(client_id.as_str()).map(|c| (*c).clone()),
                        candidates: Vec::new(),
                    },
                );
            } else {
                for owner in owners {
                    results.insert(
                        owner.key,
                        Resolution::unresolved(Reason::Contested, vec![client_id.clone()]),
                    );
                }
            }
        }
    };

    // 1. Pinned ids.
    let mut pinned = Claims::new();
    for agent in agents.iter().filter(|a| a.pinned) {
        match agent.velociraptor_id.as_deref() {
            Some(id) if by_id.contains_key(id) => pinned.push(id, agent),
            _ => {
                results.insert(
                    agent.key,
                    Resolution::unresolved(Reason::PinnedClientMissing, Vec::new()),
                );
            }
        }
    }
    settle(pinned, Reason::Pinned, &mut results, &mut claimed);

    // 2. Unpinned stored ids that are still trustworthy.
    let mut stored_claims = Claims::new();
    for agent in agents {
        if results.contains_key(&agent.key) {
            continue;
        }
        let Some(stored_id) = agent.velociraptor_id.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        let Some(stored) = by_id.get(stored_id) else {
            continue;
        };
        if claimed.contains(&stored.client_id) {
            continue;
        }
        let nobody_reports_it = by_hostname
            .get(agent.hostname.as_str())
            .is_none_or(Vec::is_empty);
        if stored.hostname == agent.hostname || nobody_reports_it {
            stored_claims.push(&stored.client_id, agent);
        }
    }
    settle(stored_claims, Reason::StoredId, &mut results, &mut claimed);

    // 3 + 4. Hostname, then the stored id as a last resort.
    let mut picks = Claims::new();
    let mut pick_reasons: HashMap<i32, Reason> = HashMap::new();
    for agent in agents {
        if results.contains_key(&agent.key) {
            continue;
        }
        let candidates: Vec<&OrgClient> = by_hostname
            .get(agent.hostname.as_str())
            .map(|v| {
                v.iter()
                    .copied()
                    .filter(|c| !claimed.contains(&c.client_id))
                    .collect()
            })
            .unwrap_or_default();
        if candidates.len() == 1 {
            picks.push(&candidates[0].client_id, agent);
            pick_reasons.insert(agent.key, Reason::Hostname);
        } else if candidates.len() > 1 {
            results.insert(
                agent.key,
                Resolution::unresolved(
                    Reason::Ambiguous,
                    candidates
                        .iter()
                        .map(|c| format!("{} (org {})", c.client_id, c.org_id))
                        .collect(),
                ),
            );
        } else {
            let stored = agent
                .velociraptor_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .and_then(|id| by_id.get(id));
            match stored {
                Some(stored) if !claimed.contains(&stored.client_id) => {
                    picks.push(&stored.client_id, agent);
                    pick_reasons.insert(agent.key, Reason::StoredIdFallback);
                }
                _ => {
                    results.insert(
                        agent.key,
                        Resolution::unresolved(Reason::NoMatch, Vec::new()),
                    );
                }
            }
        }
    }
    for (client_id, owners) in picks.drain() {
        if owners.len() == 1 {
            let reason = pick_reasons
                .get(&owners[0].key)
                .copied()
                .unwrap_or(Reason::Hostname);
            results.insert(
                owners[0].key,
                Resolution {
                    reason,
                    client: by_id.get(client_id.as_str()).map(|c| (*c).clone()),
                    candidates: Vec::new(),
                },
            );
        } else {
            for owner in owners {
                results.insert(
                    owner.key,
                    Resolution::unresolved(Reason::Contested, vec![client_id.clone()]),
                );
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(org: &str, id: &str, host: &str) -> OrgClient {
        OrgClient {
            org_id: org.into(),
            client_id: id.into(),
            hostname: host.into(),
            last_seen_at: 0,
            version: "0.7".into(),
        }
    }

    fn agent(key: i32, host: &str, id: Option<&str>, pinned: bool) -> AgentRef {
        AgentRef {
            key,
            hostname: host.into(),
            velociraptor_id: id.map(str::to_string),
            pinned,
            customer_code: None,
        }
    }

    fn reason(r: &HashMap<i32, Resolution>, k: i32) -> (Reason, Option<String>) {
        let x = &r[&k];
        (x.reason, x.client.as_ref().map(|c| c.client_id.clone()))
    }

    // The cases of `backend/tests/test_velociraptor_client_matching.py`.
    #[test]
    fn precedence() {
        let clients = [
            client("O1", "C.1", "web-01"),
            client("O2", "C.2", "web-01"),
            client("root", "C.3", "db-01"),
            client("root", "C.4", "renamed"),
        ];
        let agents = [
            agent(1, "web-01", Some("C.2"), true),
            agent(2, "web-01", None, false),
            agent(3, "db-01", Some("C.9"), false),
            agent(4, "old-name", Some("C.4"), false),
            agent(5, "gone", Some("C.404"), true),
            agent(6, "nothing", None, false),
        ];
        let r = resolve_velociraptor_clients(&agents, &clients);
        assert_eq!(reason(&r, 1), (Reason::Pinned, Some("C.2".into())));
        assert_eq!(reason(&r, 2), (Reason::Hostname, Some("C.1".into())));
        assert_eq!(reason(&r, 3), (Reason::Hostname, Some("C.3".into())));
        assert_eq!(reason(&r, 4), (Reason::StoredId, Some("C.4".into())));
        assert_eq!(reason(&r, 5), (Reason::PinnedClientMissing, None));
        assert_eq!(reason(&r, 6), (Reason::NoMatch, None));
    }

    #[test]
    fn ambiguity_and_contests() {
        let clients = [client("O1", "C.1", "h"), client("O2", "C.2", "h")];
        let r = resolve_velociraptor_clients(&[agent(1, "h", None, false)], &clients);
        assert_eq!(r[&1].reason, Reason::Ambiguous);
        assert_eq!(r[&1].candidates, ["C.1 (org O1)", "C.2 (org O2)"]);
        let clients = [client("O1", "C.1", "h")];
        let r = resolve_velociraptor_clients(
            &[agent(1, "h", None, false), agent(2, "h", None, false)],
            &clients,
        );
        assert_eq!(r[&1].reason, Reason::Contested);
        assert_eq!(r[&2].reason, Reason::Contested);
        // A stale stored id: the client carries another hostname while one
        // client does carry the agent's.
        let clients = [client("O1", "C.1", "other"), client("O1", "C.2", "h")];
        let r = resolve_velociraptor_clients(&[agent(1, "h", Some("C.1"), false)], &clients);
        assert_eq!(reason(&r, 1), (Reason::Hostname, Some("C.2".into())));
        // The stored id as a fallback when every candidate is held.
        let clients = [client("O1", "C.1", "h"), client("O1", "C.7", "x")];
        let r = resolve_velociraptor_clients(
            &[
                agent(1, "h", Some("C.1"), true),
                agent(2, "h", Some("C.7"), false),
            ],
            &clients,
        );
        assert_eq!(
            reason(&r, 2),
            (Reason::StoredIdFallback, Some("C.7".into()))
        );
    }
}
