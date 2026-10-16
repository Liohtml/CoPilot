//! The scheduled half of `services/snapshot_and_restore.py`:
//! `execute_all_enabled_schedules` and what it calls (`_is_schedule_due`,
//! `get_indices_needing_snapshot`, `get_snapshotted_indices_for_schedule`,
//! `execute_snapshot_schedule`), run by the `invoke_snapshot_schedules` job.
//!
//! A schedule's row is written as the ORM writes it: the deferral reason
//! (`DEFERRED: …`), `SKIPPED: …` when nothing is new, `SUCCESS` or
//! `FAILED: …` after the snapshot request, each with `updated_at`.

use std::collections::HashSet;

use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use reqwest::Method;
use serde_json::{Map, Value, json};

use copilot_db::Db;

use crate::WazuhState;
use crate::error::PyErr;
use crate::es::make_path;
use crate::indexer::schema::CreateSnapshotRequest;
use crate::indexer::services::client;
use crate::indexer::services::snapshots::{self, ScheduleRow, pattern_regex};

/// `SCHEDULE_MATCH_TOLERANCE_MINUTES`.
pub const SCHEDULE_MATCH_TOLERANCE_MINUTES: i32 = 15;
const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// `ScheduledSnapshotExecutionResponse`, the fields the job logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execution {
    /// Schedule name.
    pub schedule_name: String,
    /// The snapshot taken, if any.
    pub snapshot_name: Option<String>,
    /// Indices snapshotted.
    pub indices_snapshotted: Vec<String>,
    /// Write indices skipped.
    pub skipped_write_indices: Vec<String>,
    /// Whether the run counts as a success.
    pub success: bool,
    /// What happened.
    pub message: String,
}

/// `ZoneInfo(schedule.timezone or "UTC")`, falling back to UTC for an
/// unknown name; the name is `tz.key` in the messages.
fn zone(name: &str) -> (Tz, String) {
    let name = if name.is_empty() { "UTC" } else { name };
    match name.parse::<Tz>() {
        Ok(tz) => (tz, name.to_string()),
        Err(_) => {
            tracing::warn!("invalid timezone '{name}', falling back to UTC");
            (Tz::UTC, "UTC".to_string())
        }
    }
}

/// `weekday_names[i]` with Python's negative indexing.
fn weekday_name(i: i32) -> Result<&'static str, String> {
    let idx = if i < 0 { i + 7 } else { i };
    usize::try_from(idx)
        .ok()
        .and_then(|i| WEEKDAYS.get(i).copied())
        .ok_or_else(|| "list index out of range".to_string())
}

/// `_is_schedule_due(schedule, now_utc)`: `Ok(None)` when due, else the
/// deferral reason; `Err` is an exception (`IndexError`) Python would raise.
pub fn is_due(s: &ScheduleRow, now_utc: DateTime<Utc>) -> Result<Option<String>, String> {
    let (tz, key) = zone(&s.timezone);
    let now_local = now_utc.with_timezone(&tz);
    let interval_days = if s.interval_days == 0 {
        1
    } else {
        s.interval_days
    };
    if let Some(last) = s.last_execution_time {
        let last_local = Utc.from_utc_datetime(&last).with_timezone(&tz).date_naive();
        let days = (now_local.date_naive() - last_local).num_days();
        if days < i64::from(interval_days) {
            return Ok(Some(format!(
                "DEFERRED: interval_days={interval_days}, last run {days} day(s) ago"
            )));
        }
    }
    let weekday = i32::try_from(now_local.weekday().num_days_from_monday()).unwrap_or(0);
    if let Some(dow) = s.day_of_week {
        if weekday != dow {
            return Ok(Some(format!(
                "DEFERRED: not scheduled day (want={}, today={} {key})",
                weekday_name(dow)?,
                weekday_name(weekday)?
            )));
        }
    }
    if let Some(hour) = s.scheduled_hour {
        if i64::from(now_local.hour()) != i64::from(hour) {
            return Ok(Some(format!(
                "DEFERRED: outside scheduled hour ({hour:02}:xx {key})"
            )));
        }
        if let Some(minute) = s.scheduled_minute {
            let now_minute = i64::from(now_local.minute());
            let start = i64::from(minute);
            let in_window = start <= now_minute
                && now_minute < start + i64::from(SCHEDULE_MATCH_TOLERANCE_MINUTES);
            if !in_window {
                return Ok(Some(format!(
                    "DEFERRED: outside scheduled minute window ({hour:02}:{minute:02} \
                     +{SCHEDULE_MATCH_TOLERANCE_MINUTES}min {key})"
                )));
            }
        }
    }
    Ok(None)
}

/// `f"{schedule.snapshot_prefix}_{schedule.name}_".lower().replace(" ", "_")`.
fn prefix(s: &ScheduleRow) -> String {
    format!("{}_{}_", s.snapshot_prefix, s.name)
        .to_lowercase()
        .replace(' ', "_")
}

/// `get_snapshotted_indices_for_schedule` (any failure: none).
async fn snapshotted_indices(st: &WazuhState, s: &ScheduleRow) -> HashSet<String> {
    let result: Result<HashSet<String>, String> = async {
        let es = client(st).await.map_err(|e| e.py_str())?;
        let response = es
            .perform(
                Method::GET,
                &make_path(&["_snapshot", &s.repository, "_all"]),
                &[("ignore_unavailable", "true".into())],
                None,
            )
            .await
            .map_err(|e| e.to_string())?;
        let prefix = prefix(s);
        let mut out = HashSet::new();
        let snaps = match &response {
            Value::Object(m) => m.get("snapshots").cloned().unwrap_or(json!([])),
            _ => return Err("'str' object has no attribute 'get'".into()),
        };
        for snap in crate::pyops::iterate(&snaps)? {
            let name = crate::pyops::get(&snap, "snapshot", json!(""))?;
            if name.as_str().is_some_and(|n| n.starts_with(&prefix)) {
                let indices = crate::pyops::get(&snap, "indices", json!([]))?;
                for i in crate::pyops::iterate(&indices)? {
                    out.insert(crate::pyops::py_str(&i));
                }
            }
        }
        Ok(out)
    }
    .await;
    result.unwrap_or_else(|e| {
        tracing::error!(
            "Failed to get snapshotted indices for schedule {}: {e}",
            s.name
        );
        HashSet::new()
    })
}

/// `get_indices_needing_snapshot(schedule)`:
/// `(to_snapshot, skipped_write_indices, already_snapshotted)`.
async fn indices_needing_snapshot(
    st: &WazuhState,
    s: &ScheduleRow,
) -> Result<(Vec<String>, Vec<String>, Vec<String>), String> {
    let all = snapshots::all_indices(st).await;
    let mut matching = Vec::new();
    if s.index_pattern.contains('*') {
        let re = pattern_regex(&s.index_pattern)?;
        matching.extend(all.iter().filter(|n| re.is_match(n)).cloned());
    } else if all.contains(&s.index_pattern) {
        matching.push(s.index_pattern.clone());
    }
    let writes = snapshots::write_indices(&all);
    let previously = snapshotted_indices(st, s).await;
    let (mut to_snapshot, mut skipped, mut already) = (Vec::new(), Vec::new(), Vec::new());
    for index in matching {
        if s.skip_write_indices && writes.contains(&index) {
            skipped.push(index);
        } else if previously.contains(&index) {
            already.push(index);
        } else {
            to_snapshot.push(index);
        }
    }
    Ok((to_snapshot, skipped, already))
}

async fn write_status(
    db: &Db,
    id: i32,
    status: &str,
    executed_at: Option<NaiveDateTime>,
    snapshot: Option<Option<&str>>,
) -> Result<(), sqlx::Error> {
    let now = copilot_core::time::now_utc_micros();
    let mut sql = String::from(
        "UPDATE index_snapshot_schedules SET last_execution_status = ?, updated_at = ?",
    );
    if executed_at.is_some() {
        sql.push_str(", last_execution_time = ?");
    }
    if snapshot.is_some() {
        sql.push_str(", last_snapshot_name = ?");
    }
    sql.push_str(" WHERE id = ?");
    let mut q = sqlx::query(&sql).bind(status).bind(now);
    if let Some(at) = executed_at {
        q = q.bind(at);
    }
    if let Some(name) = snapshot {
        q = q.bind(name);
    }
    q.bind(id).execute(db.pool()).await?;
    Ok(())
}

fn done(s: &ScheduleRow, success: bool, message: String) -> Execution {
    Execution {
        schedule_name: s.name.clone(),
        snapshot_name: None,
        indices_snapshotted: Vec::new(),
        skipped_write_indices: Vec::new(),
        success,
        message,
    }
}

/// `execute_snapshot_schedule(schedule, session)`.
pub async fn execute_schedule(st: &WazuhState, s: &ScheduleRow, now: DateTime<Utc>) -> Execution {
    let db = &st.ctx.db;
    let outcome: Result<Execution, String> = async {
        if let Some(reason) = is_due(s, now)? {
            tracing::info!("Schedule {}: {reason}", s.name);
            if let Err(e) = write_status(db, s.id, &reason, None, None).await {
                tracing::warn!("Schedule {}: cannot record the deferral: {e}", s.name);
            }
            return Ok(done(s, true, reason));
        }
        let (to_snapshot, skipped, already) = indices_needing_snapshot(st, s).await?;
        if to_snapshot.is_empty() {
            let mut message = "No new indices to snapshot".to_string();
            if !skipped.is_empty() {
                message.push_str(&format!(" ({} write indices skipped)", skipped.len()));
            }
            if !already.is_empty() {
                message.push_str(&format!(" ({} already snapshotted)", already.len()));
            }
            tracing::info!("Schedule {}: {message}", s.name);
            write_status(
                db,
                s.id,
                &format!("SKIPPED: {message}"),
                Some(copilot_core::time::now_utc_micros()),
                None,
            )
            .await
            .map_err(|e| e.to_string())?;
            let mut e = done(s, true, message);
            e.skipped_write_indices = skipped;
            return Ok(e);
        }
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let snapshot_name = format!("{}_{}_{timestamp}", s.snapshot_prefix, s.name)
            .to_lowercase()
            .replace(' ', "_");
        let mut metadata = Map::new();
        metadata.insert("schedule_id".into(), json!(s.id));
        metadata.insert("schedule_name".into(), json!(s.name));
        metadata.insert("created_by".into(), json!("scheduled_job"));
        metadata.insert("skipped_write_indices".into(), json!(skipped));
        metadata.insert("already_snapshotted_count".into(), json!(already.len()));
        let request = CreateSnapshotRequest {
            repository: s.repository.clone(),
            snapshot: snapshot_name.clone(),
            indices: Some(to_snapshot.clone()),
            ignore_unavailable: Some(true),
            include_global_state: Some(s.include_global_state),
            partial: Some(false),
            wait_for_completion: Some(false),
            metadata: Some(metadata),
            skip_write_indices: Some(false),
        };
        let response = snapshots::create(st, &request).await;
        let success = response.get("success") == Some(&Value::Bool(true));
        let message = response
            .get("message")
            .map(crate::pyops::py_str)
            .unwrap_or_default();
        let status = if success {
            "SUCCESS".to_string()
        } else {
            format!("FAILED: {message}")
        };
        write_status(
            db,
            s.id,
            &status,
            Some(copilot_core::time::now_utc_micros()),
            Some(success.then_some(snapshot_name.as_str())),
        )
        .await
        .map_err(|e| e.to_string())?;
        if success {
            tracing::info!(
                "Successfully executed schedule {}: snapshot={snapshot_name}, indices={}, \
                 skipped_write={}, already_snapshotted={}",
                s.name,
                to_snapshot.len(),
                skipped.len(),
                already.len()
            );
        } else {
            tracing::error!("Failed to execute schedule {}: {message}", s.name);
        }
        Ok(Execution {
            schedule_name: s.name.clone(),
            snapshot_name: success.then_some(snapshot_name),
            indices_snapshotted: if success { to_snapshot } else { Vec::new() },
            skipped_write_indices: skipped,
            success,
            message,
        })
    }
    .await;
    match outcome {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to execute snapshot schedule {}: {e}", s.name);
            let _ = write_status(
                db,
                s.id,
                &format!("FAILED: {e}"),
                Some(copilot_core::time::now_utc_micros()),
                None,
            )
            .await;
            done(
                s,
                false,
                format!("Failed to execute snapshot schedule: {e}"),
            )
        }
    }
}

/// `execute_all_enabled_schedules()`.
pub async fn execute_all_enabled(st: &WazuhState) -> Result<Vec<Execution>, PyErr> {
    tracing::info!("Executing all enabled snapshot schedules");
    let rows = snapshots::schedules(&st.ctx.db, true).await?;
    tracing::info!("Found {} enabled snapshot schedules", rows.len());
    let mut out = Vec::new();
    for s in &rows {
        out.push(execute_schedule(st, s, Utc::now()).await);
    }
    let ok = out.iter().filter(|r| r.success).count();
    tracing::info!(
        "Completed scheduled snapshots: {ok} successful, {} failed",
        out.len() - ok
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule() -> ScheduleRow {
        let t = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        ScheduleRow {
            id: 1,
            name: "Nightly Run".into(),
            index_pattern: "wazuh_*".into(),
            repository: "backup".into(),
            enabled: true,
            snapshot_prefix: "scheduled".into(),
            include_global_state: false,
            skip_write_indices: true,
            retention_days: None,
            last_execution_time: None,
            last_snapshot_name: None,
            last_execution_status: None,
            created_at: t,
            updated_at: t,
            scheduled_hour: None,
            scheduled_minute: None,
            interval_days: 1,
            timezone: "UTC".into(),
            day_of_week: None,
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn due_rules_follow_python() {
        // Recorded with `_is_schedule_due` (Python 3.11, zoneinfo).
        let now = at("2026-10-16T21:20:00Z"); // Fri; 23:20 in Berlin
        let mut s = schedule();
        assert_eq!(is_due(&s, now), Ok(None));
        s.timezone = "Europe/Berlin".into();
        s.scheduled_hour = Some(2);
        assert_eq!(
            is_due(&s, now).unwrap().as_deref(),
            Some("DEFERRED: outside scheduled hour (02:xx Europe/Berlin)")
        );
        s.scheduled_hour = Some(23);
        s.scheduled_minute = Some(0);
        assert_eq!(
            is_due(&s, now).unwrap().as_deref(),
            Some("DEFERRED: outside scheduled minute window (23:00 +15min Europe/Berlin)")
        );
        s.scheduled_minute = Some(10);
        assert_eq!(is_due(&s, now), Ok(None));
        s.day_of_week = Some(6);
        assert_eq!(
            is_due(&s, now).unwrap().as_deref(),
            Some("DEFERRED: not scheduled day (want=Sun, today=Fri Europe/Berlin)")
        );
        s.day_of_week = Some(-1);
        assert_eq!(
            is_due(&s, now).unwrap().as_deref(),
            Some("DEFERRED: not scheduled day (want=Sun, today=Fri Europe/Berlin)")
        );
        s.day_of_week = Some(9);
        assert_eq!(is_due(&s, now), Err("list index out of range".into()));
        s.day_of_week = None;
        // 22:30 UTC on the 15th was the 16th in Berlin: the same local day.
        s.last_execution_time = Some(at("2026-10-15T22:30:00Z").naive_utc());
        assert_eq!(
            is_due(&s, now).unwrap().as_deref(),
            Some("DEFERRED: interval_days=1, last run 0 day(s) ago")
        );
        s.interval_days = 0;
        s.last_execution_time = Some(at("2026-10-15T12:00:00Z").naive_utc());
        assert_eq!(is_due(&s, now), Ok(None));
        s.timezone = "Mars/Olympus".into();
        s.scheduled_hour = Some(23);
        assert_eq!(
            is_due(&s, now).unwrap().as_deref(),
            Some("DEFERRED: outside scheduled hour (23:xx UTC)")
        );
    }

    #[test]
    fn snapshot_prefix_is_lowered_and_underscored() {
        assert_eq!(prefix(&schedule()), "scheduled_nightly_run_");
    }
}
