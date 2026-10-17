//! The sixteen indicator builders of `app/status/services/context.py` and
//! `context_indicators.py`, each the Python function: the same statements,
//! the same thresholds and texts. `Err` is an exception the builder raised,
//! which `safe_build` turns into a missing indicator.

use std::collections::HashMap;

use chrono::{Duration, NaiveDateTime};
use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_db::connectors::{ConnectorRow, list_unordered};
use copilot_db::visibility::AlertVisibility;
use copilot_web::CurrentUser;
use sqlx::{MySql, QueryBuilder};

use super::SidebarState;
use super::expiry::{days_until, parse_license_expiry};
use super::schema::Indicator;

/// `_SEVERITY_TAGS`.
const SEVERITY_TAGS: &[&str] = &["critical", "high", "medium", "low"];
/// `_AGENT_SYNC_JOB_ID`.
const AGENT_SYNC: &str = "agent_sync";
/// `_NOTIFICATION_LOOKBACK_HOURS`.
const LOOKBACK_HOURS: i64 = 24;

/// A builder's exception.
pub type Built = Result<Indicator, String>;

fn db_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// `_preview_items(items, limit)`.
pub fn preview(items: &[String], limit: usize) -> String {
    if items.is_empty() {
        return String::new();
    }
    let shown = items
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > limit {
        format!("{shown}, +{} more", items.len() - limit)
    } else {
        shown
    }
}

/// `_is_scheduler_job_stale`.
pub fn is_stale(
    last_success: Option<NaiveDateTime>,
    interval_minutes: i64,
    now: NaiveDateTime,
) -> bool {
    if interval_minutes <= 0 {
        return false;
    }
    match last_success {
        None => true,
        Some(t) => now - t > Duration::minutes(interval_minutes * 2),
    }
}

/// `datetime.isoformat()` of a naive value (microseconds only when set).
fn isoformat(t: NaiveDateTime) -> String {
    copilot_core::time::to_pydantic_iso(t)
}

fn utcnow() -> NaiveDateTime {
    copilot_core::time::now_utc_micros()
}

// --- per-user ---------------------------------------------------------------------------------

/// `build_open_alerts_indicator`: the caller's unassigned open alerts,
/// through the one definition of alert visibility (customer scoping and tag
/// RBAC; Python applied customer scoping only, §4).
pub async fn open_alerts(st: &SidebarState, user: &CurrentUser) -> Built {
    let ctx = &st.ctx;
    let access = user.access(ctx).await.map_err(|e| e.to_string())?;
    let visibility = AlertVisibility::for_user(&ctx.db, user.id, user.role_id, access, None)
        .await
        .map_err(db_err)?;
    let ok = || {
        Indicator::new(
            "open_alerts",
            "ok",
            "Open alerts",
            "No unassigned open alerts.",
            0,
            "triage",
        )
    };
    let Some(visibility) = visibility else {
        return Ok(ok());
    };
    let filters = |qb: &mut QueryBuilder<'_, MySql>| {
        qb.push(
            " WHERE incident_management_alert.status = 'OPEN' AND \
             (incident_management_alert.assigned_to IS NULL OR \
             incident_management_alert.assigned_to = '')",
        );
        visibility.push_and(qb, "incident_management_alert");
    };
    let mut qb =
        QueryBuilder::<MySql>::new("SELECT count(*) AS count_1 FROM incident_management_alert");
    filters(&mut qb);
    let total: i64 = qb
        .build_query_scalar()
        .fetch_one(ctx.db.pool())
        .await
        .map_err(db_err)?;
    if total == 0 {
        return Ok(ok());
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT incident_management_alerttag.tag, count(DISTINCT incident_management_alert.id) \
         AS count_1 FROM incident_management_alerttag JOIN incident_management_alert_to_tag ON \
         incident_management_alert_to_tag.tag_id = incident_management_alerttag.id JOIN \
         incident_management_alert ON incident_management_alert.id = \
         incident_management_alert_to_tag.alert_id",
    );
    filters(&mut qb);
    qb.push(" GROUP BY incident_management_alerttag.tag");
    let groups: Vec<(String, i64)> = qb
        .build_query_as()
        .fetch_all(ctx.db.pool())
        .await
        .map_err(db_err)?;
    let mut parts = Vec::new();
    let mut other = total;
    for (tag, count) in groups {
        if SEVERITY_TAGS.contains(&tag.to_lowercase().as_str()) {
            parts.push(format!("{tag}: {count}"));
            other -= count;
        }
    }
    if other > 0 {
        parts.push(format!("other: {other}"));
    }
    Ok(Indicator::new(
        "open_alerts",
        if total >= 20 { "error" } else { "warning" },
        "Open alerts",
        format!("{total} unassigned \u{2014} {}", preview(&parts, 4)),
        total,
        "triage",
    ))
}

/// `build_my_open_cases_indicator`.
pub async fn my_open_cases(st: &SidebarState, user: &CurrentUser) -> Built {
    let ctx = &st.ctx;
    let access = user.access(ctx).await.map_err(|e| e.to_string())?;
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT count(*) AS count_1 FROM incident_management_case WHERE \
         incident_management_case.assigned_to = ",
    );
    qb.push_bind(user.username.clone());
    qb.push(" AND incident_management_case.case_status IN ('OPEN', 'IN_PROGRESS')");
    let count: i64 = match access {
        copilot_auth::AccessScope::All => qb
            .build_query_scalar()
            .fetch_one(ctx.db.pool())
            .await
            .map_err(db_err)?,
        // `Case.customer_code.in_([])` matches nothing.
        copilot_auth::AccessScope::Customers(codes) if codes.is_empty() => 0,
        copilot_auth::AccessScope::Customers(codes) => {
            qb.push(" AND incident_management_case.customer_code IN (");
            let mut sep = qb.separated(", ");
            for c in codes {
                sep.push_bind(c.clone());
            }
            qb.push(")");
            qb.build_query_scalar()
                .fetch_one(ctx.db.pool())
                .await
                .map_err(db_err)?
        }
    };
    if count == 0 {
        return Ok(Indicator::new(
            "my_open_cases",
            "ok",
            "My cases",
            "No open cases assigned to you.",
            0,
            "triage",
        ));
    }
    Ok(Indicator::new(
        "my_open_cases",
        if count >= 5 { "warning" } else { "ok" },
        "My cases",
        format!(
            "{count} open case{} assigned to you.",
            if count == 1 { "" } else { "s" }
        ),
        count,
        "triage",
    ))
}

// --- deployment-wide ----------------------------------------------------------------------------

/// `build_tag_rbac_indicator`.
pub async fn tag_rbac(st: &SidebarState) -> Built {
    let row: Option<(bool, String)> = sqlx::query_as(
        "SELECT incident_management_tag_access_settings.enabled, \
         incident_management_tag_access_settings.untagged_alert_behavior \
         FROM incident_management_tag_access_settings LIMIT ?",
    )
    .bind(1_i64)
    .fetch_optional(st.ctx.db.pool())
    .await
    .map_err(db_err)?;
    match row {
        Some((true, behavior)) => Ok(Indicator::new(
            "tag_rbac",
            "warning",
            "Tag RBAC",
            format!(
                "Active \u{2014} untagged alerts: {}.",
                behavior.replace('_', " ")
            ),
            1,
            "triage",
        )),
        _ => Ok(Indicator::new(
            "tag_rbac",
            "ok",
            "Tag RBAC",
            "Tag-based access control is disabled.",
            0,
            "triage",
        )),
    }
}

async fn count_status(db: &Db, table: &str, status: &str) -> Result<i64, String> {
    sqlx::query_scalar::<_, i64>(&format!(
        "SELECT count(*) AS count_1 FROM {table} WHERE {table}.status = ?"
    ))
    .bind(status)
    .fetch_one(db.pool())
    .await
    .map_err(db_err)
}

/// The two queue indicators' shape: nothing, else `N a, M b` with the
/// failures deciding the status.
fn queue(
    id: &'static str,
    label: &'static str,
    quiet: &'static str,
    first: (i64, &str),
    failed: i64,
) -> Indicator {
    if first.0 == 0 && failed == 0 {
        return Indicator::new(id, "ok", label, quiet, 0, "ai");
    }
    let mut parts = Vec::new();
    if first.0 != 0 {
        parts.push(format!("{} {}", first.0, first.1));
    }
    if failed != 0 {
        parts.push(format!("{failed} failed"));
    }
    Indicator::new(
        id,
        if failed != 0 { "error" } else { "warning" },
        label,
        parts.join(", "),
        if failed != 0 { failed } else { first.0 },
        "ai",
    )
}

/// `build_ai_analyst_jobs_indicator`.
pub async fn ai_analyst_jobs(st: &SidebarState) -> Built {
    let running = count_status(&st.ctx.db, "ai_analyst_job", "running").await?;
    let failed = count_status(&st.ctx.db, "ai_analyst_job", "failed").await?;
    Ok(queue(
        "ai_analyst_jobs",
        "AI Analyst",
        "No running or failed investigations.",
        (running, "running"),
        failed,
    ))
}

/// `build_mem_palace_indicator`.
pub async fn mem_palace(st: &SidebarState) -> Built {
    let pending = count_status(&st.ctx.db, "ai_analyst_palace_lesson", "pending").await?;
    let failed = count_status(&st.ctx.db, "ai_analyst_palace_lesson", "failed").await?;
    Ok(queue(
        "mem_palace",
        "MemPalace queue",
        "No pending or failed lessons.",
        (pending, "pending"),
        failed,
    ))
}

/// `build_notification_dispatch_indicator`.
pub async fn notification_dispatch(st: &SidebarState) -> Built {
    let since = utcnow() - Duration::hours(LOOKBACK_HOURS);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) AS count_1 FROM notification_dispatch_log WHERE \
         notification_dispatch_log.status = ? AND notification_dispatch_log.dispatched_at >= ?",
    )
    .bind("failed")
    .bind(since)
    .fetch_one(st.ctx.db.pool())
    .await
    .map_err(db_err)?;
    if count == 0 {
        return Ok(Indicator::new(
            "notification_dispatch",
            "ok",
            "Notifications",
            format!("No failed dispatches in the last {LOOKBACK_HOURS}h."),
            0,
            "operations",
        ));
    }
    Ok(Indicator::new(
        "notification_dispatch",
        if count >= 3 { "error" } else { "warning" },
        "Notifications",
        format!(
            "{count} failed dispatch{} in the last {LOOKBACK_HOURS}h.",
            if count == 1 { "" } else { "es" }
        ),
        count,
        "operations",
    ))
}

/// One `scheduled_job_metadata` row.
#[derive(Debug, Clone, sqlx::FromRow)]
struct MetaRow {
    job_id: String,
    last_success: Option<NaiveDateTime>,
    time_interval: i32,
    enabled: bool,
}

const META_COLUMNS: &str = "scheduled_job_metadata.id, scheduled_job_metadata.job_id, \
     scheduled_job_metadata.last_success, scheduled_job_metadata.time_interval, \
     scheduled_job_metadata.extra_data, scheduled_job_metadata.enabled, \
     scheduled_job_metadata.job_description";

/// `scheduler.get_jobs()`'s ids: APScheduler's store (`apscheduler_jobs`)
/// read as `SQLAlchemyJobStore.get_all_jobs()` reads it — by
/// `next_run_time`, the paused jobs moved to the end. A row whose state this
/// reader cannot decode keeps its place as a scheduled job (APScheduler
/// drops a row it cannot restore). No table yet: no jobs.
async fn scheduled_job_ids(db: &Db) -> Result<Vec<String>, String> {
    let Some(rows) = copilot_db::scheduler::stored_jobs(db)
        .await
        .map_err(db_err)?
    else {
        return Ok(Vec::new());
    };
    let mut scheduled = Vec::new();
    let mut paused = Vec::new();
    let mut seen_scheduled = false;
    for row in rows {
        let is_scheduled = copilot_scheduler::jobstore::decode_job(&row.job_state)
            .map(|j| j.next_run.is_scheduled())
            .unwrap_or(true);
        // `_fix_paused_jobs_sorting`: the paused jobs MySQL sorts ahead of
        // the first scheduled one go to the end, in their order.
        if is_scheduled {
            seen_scheduled = true;
            scheduled.push(row.id);
        } else if seen_scheduled {
            scheduled.push(row.id);
        } else {
            paused.push(row.id);
        }
    }
    scheduled.extend(paused);
    Ok(scheduled)
}

/// `build_scheduler_indicator_excluding_agent_sync`.
pub async fn scheduler(st: &SidebarState) -> Built {
    let db = &st.ctx.db;
    let now = utcnow();
    let job_ids: Vec<String> = scheduled_job_ids(db)
        .await?
        .into_iter()
        .filter(|id| id != AGENT_SYNC)
        .collect();
    // `{metadata.job_id: metadata for metadata in rows}`: a later row of
    // the same id replaces an earlier one; the column's collation matched.
    let mut metadata: HashMap<String, MetaRow> = HashMap::new();
    if !job_ids.is_empty() {
        let mut qb = QueryBuilder::<MySql>::new(format!(
            "SELECT {META_COLUMNS} FROM scheduled_job_metadata WHERE \
             scheduled_job_metadata.job_id IN ("
        ));
        let mut sep = qb.separated(", ");
        for id in &job_ids {
            sep.push_bind(id.clone());
        }
        qb.push(")");
        let rows: Vec<MetaRow> = qb
            .build_query_as()
            .fetch_all(db.pool())
            .await
            .map_err(db_err)?;
        for row in rows {
            metadata.insert(row.job_id.clone(), row);
        }
    }
    let mut stale = Vec::new();
    for id in job_ids {
        let Some(meta) = metadata.get(&id).filter(|m| m.enabled) else {
            continue;
        };
        if is_stale(meta.last_success, i64::from(meta.time_interval), now) {
            stale.push(id);
        }
    }
    let count = i64::try_from(stale.len()).unwrap_or(i64::MAX);
    if count == 0 {
        return Ok(Indicator::new(
            "scheduler",
            "ok",
            "Scheduler",
            "All enabled jobs ran within their expected interval.",
            0,
            "operations",
        ));
    }
    Ok(Indicator::new(
        "scheduler",
        if count == 1 { "warning" } else { "error" },
        "Scheduler",
        preview(&stale, 3),
        count,
        "operations",
    ))
}

/// `build_agent_sync_indicator`.
pub async fn agent_sync(st: &SidebarState) -> Built {
    let db = &st.ctx.db;
    let now = utcnow();
    let meta: Option<MetaRow> = sqlx::query_as(&format!(
        "SELECT {META_COLUMNS} FROM scheduled_job_metadata WHERE scheduled_job_metadata.job_id = ?"
    ))
    .bind(AGENT_SYNC)
    .fetch_optional(db.pool())
    .await
    .map_err(db_err)?;
    let label = "Agent sync";
    let Some(meta) = meta else {
        return Ok(Indicator::new(
            "agent_sync",
            "warning",
            label,
            "Scheduler metadata for agent sync is missing.",
            1,
            "operations",
        ));
    };
    if !meta.enabled {
        return Ok(Indicator::new(
            "agent_sync",
            "warning",
            label,
            "Agent sync job is disabled.",
            0,
            "operations",
        ));
    }
    if !scheduled_job_ids(db)
        .await?
        .iter()
        .any(|id| id == AGENT_SYNC)
    {
        return Ok(Indicator::new(
            "agent_sync",
            "error",
            label,
            "Agent sync is enabled but not scheduled.",
            1,
            "operations",
        ));
    }
    if is_stale(meta.last_success, i64::from(meta.time_interval), now) {
        let last = meta
            .last_success
            .map_or_else(|| "never".to_string(), isoformat);
        return Ok(Indicator::new(
            "agent_sync",
            "error",
            label,
            format!("Last success: {last}."),
            1,
            "operations",
        ));
    }
    let last = meta
        .last_success
        .map_or_else(|| "unknown".to_string(), isoformat);
    Ok(Indicator::new(
        "agent_sync",
        "ok",
        label,
        format!("Last success: {last}."),
        0,
        "operations",
    ))
}

/// `_find_connector(session, name)`: the first row of `select(Connectors)`
/// with that exact name.
async fn find_connector(db: &Db, name: &str) -> Result<Option<ConnectorRow>, String> {
    Ok(list_unordered(db)
        .await
        .map_err(db_err)?
        .into_iter()
        .find(|c| c.connector_name == name))
}

/// `_connector_status_indicator`.
fn connector_status(
    id: &'static str,
    label: &'static str,
    connector: Option<&ConnectorRow>,
    category: &'static str,
) -> Indicator {
    let (status, detail, count) = match connector {
        None => ("warning", "Connector not found in deployment catalog.", 1),
        Some(c) if c.connector_enabled && !c.connector_configured => {
            ("error", "Enabled but not configured.", 1)
        }
        Some(c) if c.connector_configured && !c.connector_verified => {
            ("error", "Configured but verification failed.", 1)
        }
        Some(c) if !c.connector_configured => ("warning", "Not configured.", 0),
        Some(_) => ("ok", "Configured and verified.", 0),
    };
    Indicator::new(id, status, label, detail, count, category)
}

/// `build_talon_indicator`.
pub async fn talon(st: &SidebarState) -> Built {
    let connector = find_connector(&st.ctx.db, "Talon").await?;
    Ok(connector_status(
        "talon",
        "Talon",
        connector.as_ref(),
        "infrastructure",
    ))
}

/// `build_core_soc_tools_indicator`.
pub async fn core_soc_tools(st: &SidebarState) -> Built {
    let mut issues = Vec::new();
    for name in ["Graylog", "Velociraptor"] {
        match find_connector(&st.ctx.db, name).await? {
            None => issues.push(format!("{name} missing")),
            Some(c) if c.connector_enabled && !c.connector_configured => {
                issues.push(format!("{name} not configured"));
            }
            Some(c) if c.connector_configured && !c.connector_verified => {
                issues.push(name.to_string());
            }
            Some(_) => {}
        }
    }
    let count = i64::try_from(issues.len()).unwrap_or(i64::MAX);
    if count == 0 {
        return Ok(Indicator::new(
            "core_soc_tools",
            "ok",
            "Core SOC tools",
            "Graylog and Velociraptor are healthy.",
            0,
            "infrastructure",
        ));
    }
    Ok(Indicator::new(
        "core_soc_tools",
        if count >= 2 { "error" } else { "warning" },
        "Core SOC tools",
        preview(&issues, 3),
        count,
        "infrastructure",
    ))
}

/// `_build_connector_indicator`.
pub async fn connectors(st: &SidebarState) -> Built {
    let mut issues = Vec::new();
    for c in list_unordered(&st.ctx.db).await.map_err(db_err)? {
        let name = c.connector_name.clone();
        if matches!(name.as_str(), "Talon" | "Graylog" | "Velociraptor") {
            continue;
        }
        if c.connector_enabled && !c.connector_configured {
            issues.push(format!("{name} (not configured)"));
        } else if c.connector_configured && !c.connector_verified {
            issues.push(name);
        }
    }
    let count = i64::try_from(issues.len()).unwrap_or(i64::MAX);
    if count == 0 {
        return Ok(Indicator::new(
            "connectors",
            "ok",
            "Connectors",
            "All other enabled connectors are configured and verified.",
            0,
            "infrastructure",
        ));
    }
    Ok(Indicator::new(
        "connectors",
        if count <= 2 { "warning" } else { "error" },
        "Connectors",
        preview(&issues, 3),
        count,
        "infrastructure",
    ))
}

/// `build_wazuh_indexer_indicator`: the cluster health through
/// `copilot-wazuh`'s `cluster_healthcheck`; any failure is "unavailable".
pub async fn wazuh_indexer(st: &SidebarState) -> Built {
    let unavailable = || {
        Indicator::new(
            "wazuh_indexer",
            "error",
            "Wazuh indexer",
            "Indexer cluster health is unavailable.",
            1,
            "infrastructure",
        )
    };
    let response =
        match copilot_wazuh::indexer::services::monitoring::cluster_health(&st.wazuh).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Wazuh indexer health check failed: {e:?}");
                return Ok(unavailable());
            }
        };
    let Some(cluster) = response.get("cluster_health").filter(|c| c.is_object()) else {
        return Ok(Indicator::new(
            "wazuh_indexer",
            "error",
            "Wazuh indexer",
            "Cluster health payload missing.",
            1,
            "infrastructure",
        ));
    };
    let text = |v: Option<&serde_json::Value>| match v {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => "None".into(),
    };
    let status = text(cluster.get("status")).to_lowercase();
    let name = text(cluster.get("cluster_name"));
    Ok(match status.as_str() {
        "green" => Indicator::new(
            "wazuh_indexer",
            "ok",
            "Wazuh indexer",
            format!("Cluster {name} is green."),
            0,
            "infrastructure",
        ),
        "yellow" => Indicator::new(
            "wazuh_indexer",
            "warning",
            "Wazuh indexer",
            format!("Cluster {name} is yellow."),
            1,
            "infrastructure",
        ),
        other => Indicator::new(
            "wazuh_indexer",
            "error",
            "Wazuh indexer",
            format!("Cluster {name} is {other}."),
            1,
            "infrastructure",
        ),
    })
}

/// `_build_wazuh_catalog_indicator`: the Detections Catalog's Wazuh ruleset
/// cache (`copilot-searches`' own), read as it stands, then a background
/// refresh started when it is stale — the state Python reads before its
/// refresh task can run.
pub async fn wazuh_catalog(st: &SidebarState) -> Built {
    let snapshot = st.searches.caches.wazuh.get();
    copilot_searches::caches::ensure_fresh_nonblocking(
        &st.searches,
        copilot_searches::caches::Kind::Wazuh,
    );
    let count = snapshot.rules.len();
    Ok(match &snapshot.unavailable {
        None if count == 0 => Indicator::new(
            "wazuh_catalog",
            "ok",
            "Wazuh catalog",
            "Loading the Wazuh ruleset\u{2026}",
            0,
            "infrastructure",
        ),
        None => Indicator::new(
            "wazuh_catalog",
            "ok",
            "Wazuh catalog",
            format!("{count} rules loaded."),
            0,
            "infrastructure",
        ),
        Some(reason) => Indicator::new(
            "wazuh_catalog",
            "error",
            "Wazuh catalog",
            if reason.is_empty() {
                "Wazuh Manager rules are unavailable.".to_string()
            } else {
                reason.clone()
            },
            1,
            "infrastructure",
        ),
    })
}

/// `_build_influx_health_indicator`: the active alerts of the last day
/// through `copilot-influxdb`'s `get_influxdb_alerts`.
pub async fn compute_influx_health(st: &SidebarState) -> Indicator {
    let params = copilot_influxdb::services::AlertParams {
        days: 1,
        severity: None,
        check_name: None,
        sensor_type: None,
        status: "active".into(),
        latest_only: true,
        exclude_ok: true,
        limit: Some(200),
    };
    let failed = || {
        Indicator::new(
            "influx_health",
            "warning",
            "Healthchecks",
            "Unable to query InfluxDB healthchecks.",
            0,
            "infrastructure",
        )
    };
    let response = match copilot_influxdb::services::alerts(&st.influx, &params).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Influx health indicator failed: {}", e.display());
            return failed();
        }
    };
    let success = response.get("success").is_some_and(PyValue::truthy);
    if !success {
        let message = response
            .get("message")
            .and_then(PyValue::as_str)
            .filter(|m| !m.is_empty())
            .unwrap_or("InfluxDB healthchecks unavailable.")
            .to_string();
        return Indicator::new(
            "influx_health",
            "warning",
            "Healthchecks",
            message,
            0,
            "infrastructure",
        );
    }
    let severities: Vec<String> = match response.get("alerts") {
        Some(PyValue::List(alerts)) => alerts
            .iter()
            .map(|a| {
                a.get("severity")
                    .map_or_else(|| "None".into(), PyValue::py_str)
            })
            .map(|s| s.to_lowercase())
            .collect(),
        _ => Vec::new(),
    };
    let critical = severities
        .iter()
        .filter(|s| matches!(s.as_str(), "critical" | "error"))
        .count();
    let warn = severities
        .iter()
        .filter(|s| matches!(s.as_str(), "warn" | "warning"))
        .count();
    if critical == 0 && warn == 0 {
        return Indicator::new(
            "influx_health",
            "ok",
            "Healthchecks",
            "No active critical InfluxDB alerts.",
            0,
            "infrastructure",
        );
    }
    let mut parts = Vec::new();
    if critical != 0 {
        parts.push(format!("{critical} critical/error"));
    }
    if warn != 0 {
        parts.push(format!("{warn} warning"));
    }
    let n = if critical != 0 { critical } else { warn };
    Indicator::new(
        "influx_health",
        if critical != 0 { "error" } else { "warning" },
        "Healthchecks",
        format!("Active alerts: {}.", parts.join(", ")),
        i64::try_from(n).unwrap_or(i64::MAX),
        "infrastructure",
    )
}

/// `build_license_indicator`.
pub async fn license(st: &SidebarState) -> Built {
    let days = license_days(&st.ctx.db).await?;
    let make = |status, detail: String, count| {
        Indicator::new("license", status, "License", detail, count, "platform")
    };
    Ok(match days {
        None => make("ok", "License expiry not available from cache.".into(), 0),
        Some(d) if d < 0 => make("error", "License has expired.".into(), 1),
        Some(d) if d <= 7 => make(
            "error",
            format!("Expires in {d} day{}.", if d == 1 { "" } else { "s" }),
            d,
        ),
        Some(d) if d <= 30 => make("warning", format!("Expires in {d} days."), d),
        Some(d) => make("ok", format!("Valid for {d} more days."), 0),
    })
}

/// `_get_license_days_until_expiry`: the newest cache row's licence (an
/// answer that is not JSON reads as unknown; one that is JSON but not an
/// object fails the builder, as `payload.get` does).
async fn license_days(db: &Db) -> Result<Option<i64>, String> {
    let Some(license) = copilot_license::services::first_license(db)
        .await
        .map_err(|e| e.text())?
    else {
        return Ok(None);
    };
    let data: Option<Option<String>> = sqlx::query_as::<_, (i32, Option<String>)>(
        "SELECT license_cache.id, license_cache.license_data FROM license_cache WHERE \
         license_cache.license_key = ? ORDER BY license_cache.cached_at DESC LIMIT ?",
    )
    .bind(&license.license_key)
    .bind(1_i64)
    .fetch_optional(db.pool())
    .await
    .map_err(db_err)?
    .map(|(_, d)| d);
    let Some(Some(raw)) = data else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    let Ok(payload) = copilot_upstream::json::py_loads(&raw) else {
        return Ok(None);
    };
    let PyValue::Dict(_) = payload else {
        return Err(format!(
            "'{}' object has no attribute 'get'",
            copilot_upstream::py::type_name(&payload)
        ));
    };
    let from_data = match payload.get("data") {
        Some(data @ PyValue::Dict(_)) => match data.get("license") {
            Some(l @ PyValue::Dict(_)) => Some(l.clone()),
            _ => None,
        },
        _ => None,
    };
    let license_obj = match from_data {
        Some(l) => l,
        None => match payload.get("license") {
            Some(l @ PyValue::Dict(_)) => l.clone(),
            _ => return Ok(None),
        },
    };
    let Some(expires) = parse_license_expiry(license_obj.get("expires")) else {
        return Ok(None);
    };
    Ok(Some(days_until(expires, utcnow())))
}

/// `build_platform_storage_indicator`: the database answers `SELECT 1`, and
/// MinIO lists its buckets within 5 seconds.
pub async fn platform_storage(st: &SidebarState) -> Built {
    let mut issues = Vec::new();
    if sqlx::query("SELECT 1")
        .execute(st.ctx.db.pool())
        .await
        .is_err()
    {
        issues.push("Database unreachable (OperationalError)".to_string());
    }
    let minio = async {
        let client = st.store.session().map_err(|e| class_of(&e))?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.list_buckets()).await {
            Err(_) => Err("TimeoutError".to_string()),
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(class_of(&e.into_py())),
        }
    };
    if let Err(class) = minio.await {
        issues.push(format!("MinIO unreachable ({class})"));
    }
    let count = i64::try_from(issues.len()).unwrap_or(i64::MAX);
    if count == 0 {
        return Ok(Indicator::new(
            "platform_storage",
            "ok",
            "Platform storage",
            "Database and MinIO are reachable.",
            0,
            "platform",
        ));
    }
    Ok(Indicator::new(
        "platform_storage",
        "error",
        "Platform storage",
        preview(&issues, 2),
        count,
        "platform",
    ))
}

/// `exc.__class__.__name__`.
fn class_of(e: &copilot_upstream::py::PyExc) -> String {
    use copilot_upstream::py::PyExc;
    match e {
        PyExc::KeyError(_) => "KeyError",
        PyExc::TypeError(_) => "TypeError",
        PyExc::AttributeError(_) => "AttributeError",
        PyExc::IndexError(_) => "IndexError",
        PyExc::ValueError(_) => "ValueError",
        PyExc::Validation(_) => "ValidationError",
        PyExc::JsonDecode(_) => "JSONDecodeError",
        PyExc::Http(..) => "HTTPException",
        PyExc::Other(class, _) => class,
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previews_and_staleness() {
        let items: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(preview(&items, 3), "a, b, c, +2 more");
        assert_eq!(preview(&items[..2], 3), "a, b");
        assert_eq!(preview(&[], 3), "");
        let t = |s: &str| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap();
        let now = t("2026-10-17 12:00:00");
        assert!(!is_stale(None, 0, now));
        assert!(is_stale(None, 5, now));
        assert!(!is_stale(Some(t("2026-10-17 11:50:00")), 5, now));
        assert!(is_stale(Some(t("2026-10-17 11:49:59")), 5, now));
    }
}
