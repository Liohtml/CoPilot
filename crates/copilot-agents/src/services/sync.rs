//! `app/agents/services/sync.py` and `sync_all_agents` (the `/sync` route,
//! which the `agent_sync` job calls too).
//!
//! The Wazuh half writes one row per manager agent (matched by hostname,
//! each in its own commit; one failing agent does not stop the others), the
//! Velociraptor half collects every org's clients before it matches any
//! agent, then writes each resolved agent's client details.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_upstream::model;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_velociraptor::VelociraptorClient;
use copilot_wazuh::WazuhState;

use crate::db::{self, Cond, Tenancy, WazuhFields};
use crate::schema::{VELOCIRAPTOR_CLIENTS, VELOCIRAPTOR_ORGANIZATIONS};
use crate::services::matching::{self, AgentRef, OrgClient, Reason};
use crate::services::velociraptor;
use crate::services::wazuh::{self, WazuhAgent};

/// `datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z").replace(tzinfo=None)`: the
/// wall clock, the offset dropped (not applied), as the model's property.
pub fn strptime_iso_z(s: &str) -> Option<NaiveDateTime> {
    let b = s.as_bytes();
    let mut i = 0;
    let num = |min: usize, max: usize, b: &[u8], i: &mut usize| -> Option<u32> {
        let start = *i;
        while *i < b.len() && *i - start < max && b[*i].is_ascii_digit() {
            *i += 1;
        }
        if *i - start < min {
            return None;
        }
        std::str::from_utf8(&b[start..*i]).ok()?.parse().ok()
    };
    let expect =
        |c: u8, b: &[u8], i: &mut usize| -> Option<()> { (b.get(*i) == Some(&c)).then(|| *i += 1) };
    let year = num(4, 4, b, &mut i)?;
    expect(b'-', b, &mut i)?;
    let month = num(1, 2, b, &mut i)?;
    expect(b'-', b, &mut i)?;
    let day = num(1, 2, b, &mut i)?;
    expect(b'T', b, &mut i)?;
    let hour = num(1, 2, b, &mut i)?;
    expect(b':', b, &mut i)?;
    let minute = num(1, 2, b, &mut i)?;
    expect(b':', b, &mut i)?;
    let second = num(1, 2, b, &mut i)?;
    // %z: Z, or ±HH[:]MM[[:]SS[.ffffff]].
    let rest = &s[i..];
    let tz_ok = rest == "Z" || {
        let r = rest.as_bytes();
        let digits = |x: &[u8]| x.iter().all(u8::is_ascii_digit);
        let body = r.get(1..).unwrap_or_default();
        matches!(r.first(), Some(b'+' | b'-'))
            && match body.len() {
                4 => digits(body),
                5 => digits(&body[..2]) && body[2] == b':' && digits(&body[3..]),
                6 => digits(body),
                8 => {
                    digits(&body[..2])
                        && body[2] == b':'
                        && digits(&body[3..5])
                        && body[5] == b':'
                        && digits(&body[6..])
                }
                _ => false,
            }
    };
    if !tz_ok || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)?
        .and_hms_opt(hour, minute, second)
}

/// `1970-01-01 00:00:00`, what `Unknown` and the epoch string are stored as.
fn epoch() -> NaiveDateTime {
    DateTime::<Utc>::UNIX_EPOCH.naive_utc()
}

/// `extract_customer_code(label)`: the part after the first `_`.
pub fn extract_customer_code(label: &str) -> Option<String> {
    label.split('_').nth(1).map(str::to_string)
}

fn wazuh_fields(agent: &WazuhAgent) -> Option<WazuhFields> {
    let last_seen = if agent.agent_last_seen == "Unknown"
        || agent.agent_last_seen == "1970-01-01T00:00:00+00:00"
    {
        epoch()
    } else {
        strptime_iso_z(&agent.agent_last_seen)?
    };
    Some(WazuhFields {
        agent_id: agent.agent_id.clone(),
        hostname: agent.agent_name.clone(),
        ip_address: agent.agent_ip.clone(),
        os: agent.agent_os.clone(),
        label: agent.agent_label.clone(),
        wazuh_last_seen: last_seen,
        wazuh_agent_version: agent.wazuh_agent_version.clone(),
        wazuh_agent_status: agent
            .wazuh_agent_status
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "not found".into()),
        customer_code: extract_customer_code(&agent.agent_label),
    })
}

/// `sync_agents_wazuh()`: its message (the route does not return it).
pub async fn sync_agents_wazuh(db: &Db, st: &WazuhState) -> PyResult<String> {
    let agents = wazuh::collect_wazuh_agents(st).await?;
    tracing::info!("Collected {} Wazuh agents", agents.len());
    let mut added = 0usize;
    let mut failed: Vec<String> = Vec::new();
    for agent in &agents {
        let outcome: Result<(), String> = async {
            let fields = wazuh_fields(agent).ok_or_else(|| {
                format!(
                    "ValueError: time data {:?} does not match format '%Y-%m-%dT%H:%M:%S%z'",
                    agent.agent_last_seen
                )
            })?;
            let existing = db::first(db, &[Cond::Hostname(&agent.agent_name)], &Tenancy::All)
                .await
                .map_err(|e| e.to_string())?;
            match existing {
                Some(row) => db::update_wazuh(db, row.id, &fields).await,
                None => {
                    tracing::info!("Adding agent {} to the database", agent.agent_name);
                    db::insert_wazuh(db, &fields).await
                }
            }
            .map_err(|e| e.to_string())
        }
        .await;
        match outcome {
            Ok(()) => added += 1,
            Err(e) => {
                tracing::error!(
                    "Failed to sync Wazuh agent {} (agent_id {}): {e}",
                    agent.agent_name,
                    agent.agent_id
                );
                failed.push(agent.agent_name.clone());
            }
        }
    }
    let mut message = format!("Agents synced successfully ({added} of {})", agents.len());
    if !failed.is_empty() {
        message.push_str(&format!(
            ". Failed to sync {}: {}",
            failed.len(),
            failed.join(", ")
        ));
    }
    Ok(message)
}

fn field<'a>(v: &'a PyValue, key: &str) -> &'a PyValue {
    model::field(v, key)
}

/// `datetime.fromtimestamp(us / 1e6, tz=timezone.utc).isoformat(timespec=
/// "seconds")` read back through `client_last_seen_as_datetime`: the naive
/// UTC second (CPython rounds the float to the microsecond, half to even).
pub fn last_seen_from_micros(us: i64) -> Option<NaiveDateTime> {
    let t = us as f64 / 1e6;
    let mut secs = t.floor();
    let mut frac_us = ((t - secs) * 1e6).round_ties_even();
    if frac_us >= 1e6 {
        secs += 1.0;
        frac_us -= 1e6;
    }
    let _ = frac_us;
    if !secs.is_finite() || secs.abs() > 1e15 {
        return None;
    }
    let dt = DateTime::<Utc>::from_timestamp(secs as i64, 0)?;
    // `datetime` covers years 1..9999 only.
    if dt.naive_utc().date() > NaiveDate::from_ymd_opt(9999, 12, 31)? {
        return None;
    }
    Some(dt.naive_utc())
}

/// `sync_agents_velociraptor()`: its message.
pub async fn sync_agents_velociraptor(db: &Db, client: &VelociraptorClient) -> PyResult<String> {
    let verified = client
        .connectors()
        .get(copilot_velociraptor::client::CONNECTOR)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .is_some_and(|r| r.connector_verified);
    if !verified {
        tracing::info!("Velociraptor connector is not verified. Skipping Velociraptor agent sync.");
        return Ok(
            "Velociraptor connector is not verified. Skipped Velociraptor agent sync.".into(),
        );
    }
    let orgs = match velociraptor::collect_organizations(client)
        .await
        .and_then(|rows| {
            model::construct(
                &VELOCIRAPTOR_ORGANIZATIONS,
                &model::kwargs(vec![("organizations", PyValue::List(rows))]),
            )
        }) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                "Failed to collect Velociraptor organizations: {}",
                e.display()
            );
            return Ok(format!(
                "Skipped Velociraptor agent sync: failed to collect Velociraptor organizations: {}",
                e.display()
            ));
        }
    };
    let mut all_clients: Vec<OrgClient> = Vec::new();
    let org_list = match field(&orgs, "organizations") {
        PyValue::List(items) => items.clone(),
        _ => Vec::new(),
    };
    for org in &org_list {
        let org_id = field(org, "OrgId").py_str();
        let clients = velociraptor::collect_clients(client, &org_id)
            .await
            .and_then(|rows| {
                model::construct(
                    &VELOCIRAPTOR_CLIENTS,
                    &model::kwargs(vec![("clients", PyValue::List(rows))]),
                )
            });
        let clients = match clients {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    "Failed to collect Velociraptor clients for org {org_id}: {}",
                    e.display()
                );
                return Ok(format!(
                    "Skipped Velociraptor agent sync: failed to collect clients for org {org_id}: {}",
                    e.display()
                ));
            }
        };
        if let PyValue::List(items) = field(&clients, "clients") {
            for c in items {
                all_clients.push(OrgClient {
                    org_id: org_id.clone(),
                    client_id: field(c, "client_id").py_str(),
                    hostname: field(field(c, "os_info"), "hostname").py_str(),
                    last_seen_at: field(c, "last_seen_at")
                        .to_int()
                        .and_then(|v| i64::try_from(v).ok())
                        .unwrap_or(0),
                    version: field(field(c, "agent_information"), "version").py_str(),
                });
            }
        }
    }
    let refs: Vec<AgentRef> = db::all_refs(db)
        .await
        .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?
        .into_iter()
        .map(|r| AgentRef {
            key: r.id,
            hostname: r.hostname,
            velociraptor_id: r.velociraptor_id,
            pinned: r.velociraptor_id_pinned,
            customer_code: r.customer_code,
        })
        .collect();
    let resolutions = matching::resolve_velociraptor_clients(&refs, &all_clients);
    let mut matched = 0usize;
    let mut unresolved: Vec<String> = Vec::new();
    for agent in &refs {
        let Some(resolution) = resolutions.get(&agent.key) else {
            continue;
        };
        let Some(org_client) = &resolution.client else {
            log_unresolved(agent, resolution);
            if resolution.reason != Reason::NoMatch {
                unresolved.push(agent.hostname.clone());
            }
            continue;
        };
        let Some(last_seen) = last_seen_from_micros(org_client.last_seen_at) else {
            tracing::error!(
                "Failed to update Velociraptor details for {}: year is out of range",
                agent.hostname
            );
            continue;
        };
        let written = db::update_velociraptor(
            db,
            agent.key,
            Some(&org_client.client_id)
                .filter(|s| !s.is_empty())
                .map(String::as_str),
            Some(last_seen),
            Some(&org_client.version)
                .filter(|s| !s.is_empty())
                .map(String::as_str),
            Some(&org_client.org_id)
                .filter(|s| !s.is_empty())
                .map(String::as_str),
        )
        .await;
        match written {
            Ok(true) => matched += 1,
            Ok(false) => tracing::error!(
                "Failed to update Velociraptor details for {}: 'NoneType' object has no attribute 'update_velociraptor_details'",
                agent.hostname
            ),
            Err(e) => tracing::error!(
                "Failed to update Velociraptor details for {}: {e}",
                agent.hostname
            ),
        }
    }
    let mut message = format!("Agents synced successfully ({matched} matched)");
    if !unresolved.is_empty() {
        message.push_str(&format!(
            ". Left unchanged, needs review: {}",
            unresolved.join(", ")
        ));
    }
    Ok(message)
}

fn log_unresolved(agent: &AgentRef, r: &matching::Resolution) {
    let subject = format!(
        "Agent {} (customer {}, velociraptor_id {})",
        agent.hostname,
        agent.customer_code.as_deref().unwrap_or("None"),
        agent.velociraptor_id.as_deref().unwrap_or("None")
    );
    match r.reason {
        Reason::PinnedClientMissing => tracing::warn!(
            "{subject}: pinned Velociraptor client no longer exists in any org; left unchanged"
        ),
        Reason::Ambiguous => tracing::warn!(
            "{subject}: hostname matches several Velociraptor clients ({}); left unchanged. Set the Velociraptor ID on the agent to pin it.",
            r.candidates.join(", ")
        ),
        Reason::Contested => tracing::warn!(
            "{subject}: Velociraptor client {} is claimed by more than one agent; left unchanged. Set the Velociraptor ID on the correct agent to pin it.",
            r.candidates.join(", ")
        ),
        _ => tracing::info!("{subject}: no matching Velociraptor client"),
    }
}

/// `sync_all_agents()`: the Wazuh half (whose failure is the route's), then
/// the Velociraptor half (whose failure is reported in the message).
pub async fn sync_all_agents(
    db: &Db,
    st: &WazuhState,
    client: &VelociraptorClient,
) -> PyResult<String> {
    tracing::info!("Syncing agents as part of scheduled job");
    let wazuh_message = sync_agents_wazuh(db, st).await?;
    tracing::info!("{wazuh_message}");
    match sync_agents_velociraptor(db, client).await {
        Ok(message) => {
            tracing::info!("{message}");
            Ok("Agents synced started successfully".into())
        }
        Err(e) => {
            tracing::error!(
                "Failed to sync agents with Velociraptor, continuing without it: {}",
                e.display()
            );
            Ok(format!(
                "Agents synced from Wazuh Manager. Velociraptor sync skipped: {}",
                e.display()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_alive_times_parse_like_strptime() {
        let t = |s| strptime_iso_z(s).map(|d| d.to_string());
        assert_eq!(
            t("2026-10-15T07:39:48+00:00").as_deref(),
            Some("2026-10-15 07:39:48")
        );
        assert_eq!(
            t("2026-10-15T07:39:48+02:00").as_deref(),
            Some("2026-10-15 07:39:48"),
            "the offset is dropped, not applied"
        );
        assert_eq!(
            t("2026-10-15T07:39:48Z").as_deref(),
            Some("2026-10-15 07:39:48")
        );
        assert_eq!(
            t("2026-1-5T7:9:8+0000").as_deref(),
            Some("2026-01-05 07:09:08")
        );
        assert_eq!(
            t("9999-12-31T23:59:59+00:00").as_deref(),
            Some("9999-12-31 23:59:59")
        );
        assert_eq!(t("2026-02-30T00:00:00+00:00"), None);
        assert_eq!(t("2026-10-15T07:39:48.5+00:00"), None);
        assert_eq!(t("2026-10-15T07:39:48"), None);
        assert_eq!(t("Unknown"), None);
    }

    #[test]
    fn labels_and_last_seen() {
        assert_eq!(
            extract_customer_code("customer_acme").as_deref(),
            Some("acme")
        );
        assert_eq!(extract_customer_code("a_b_c").as_deref(), Some("b"));
        assert_eq!(extract_customer_code("default"), None);
        assert_eq!(extract_customer_code("x_").as_deref(), Some(""));
        assert_eq!(
            last_seen_from_micros(1_760_513_988_999_999)
                .map(|d| d.to_string())
                .as_deref(),
            Some("2025-10-15 07:39:48")
        );
        assert_eq!(
            last_seen_from_micros(0).map(|d| d.to_string()).as_deref(),
            Some("1970-01-01 00:00:00")
        );
    }
}
