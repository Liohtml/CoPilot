//! `wazuh_indexer/services/snapshot_and_restore.py`: repositories, snapshot
//! status and lists, create (skipping Graylog's write indices) and restore,
//! and the `index_snapshot_schedules` rows.
//!
//! Every indexer failure becomes the response's `message`
//! (`Failed to …: {e}`) and the route's 500, as in Python.

use chrono::NaiveDateTime;
use regex::Regex;
use reqwest::Method;
use serde_json::{Map, Value, json};

use copilot_db::Db;

use crate::WazuhState;
use crate::error::PyErr;
use crate::es::{flag, make_path, require};
use crate::indexer::schema::{
    CREATE_SNAPSHOT_RESPONSE, CreateSnapshotRequest, RESTORE_SNAPSHOT_RESPONSE,
    RestoreSnapshotRequest, SNAPSHOT_INFO, SNAPSHOT_REPOSITORY, SNAPSHOT_STATUS, ScheduleBody,
};
use crate::indexer::services::alerts::isoformat;
use crate::indexer::services::{client, keys, py_type};
use crate::pymodel;

/// `d.get(key, default)` on a `json.loads` value that must be a dict.
fn dget(d: &Value, key: &str, default: Value) -> Result<Value, String> {
    match d {
        Value::Object(m) => Ok(m.get(key).cloned().unwrap_or(default)),
        other => Err(format!(
            "'{}' object has no attribute 'get'",
            py_type(other)
        )),
    }
}

/// `for x in d.get("snapshots", [])`.
fn snapshots_of(v: &Value) -> Result<Vec<Value>, String> {
    match dget(v, "snapshots", json!([]))? {
        Value::Array(items) => Ok(items),
        Value::Object(m) => Ok(m.keys().map(|k| json!(k)).collect()),
        Value::String(s) => Ok(s.chars().map(|c| json!(c.to_string())).collect()),
        other => Err(format!("'{}' object is not iterable", py_type(&other))),
    }
}

/// Build `model(**kwargs)` from `(name, value)` pairs.
fn build(model: &'static pymodel::Model, pairs: Vec<(&str, Value)>) -> Result<Value, String> {
    let input: Map<String, Value> = pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    pymodel::validate(model, &Value::Object(input)).map_err(|e| e.to_string())
}

/// `list_snapshot_repositories()`.
pub async fn list_repositories(st: &WazuhState) -> Value {
    let result: Result<Vec<Value>, String> = async {
        let es = client(st).await.map_err(|e| e.py_str())?;
        let v = es
            .perform(Method::GET, "/_snapshot", &[], None)
            .await
            .map_err(|e| e.to_string())?;
        let Value::Object(map) = &v else {
            return Err(format!("'{}' object has no attribute 'items'", py_type(&v)));
        };
        let mut out = Vec::new();
        for (name, data) in map {
            out.push(build(
                &SNAPSHOT_REPOSITORY,
                vec![
                    ("name", json!(name)),
                    ("type", dget(data, "type", json!("unknown"))?),
                    ("settings", dget(data, "settings", json!({}))?),
                ],
            )?);
        }
        Ok(out)
    }
    .await;
    match result {
        Ok(repos) => json!({
            "repositories": repos,
            "success": true,
            "message": format!("Successfully retrieved {} snapshot repositories", repos.len()),
        }),
        Err(e) => json!({
            "repositories": [],
            "success": false,
            "message": format!("Failed to list snapshot repositories: {e}"),
        }),
    }
}

/// `get_snapshot_status(repository, snapshot)`.
pub async fn status(st: &WazuhState, repository: Option<&str>, snapshot: Option<&str>) -> Value {
    let result: Result<Vec<Value>, String> = async {
        let es = client(st).await.map_err(|e| e.py_str())?;
        let repo = repository.filter(|r| !r.is_empty()).unwrap_or("_all");
        let snap = snapshot.filter(|s| !s.is_empty()).unwrap_or("_all");
        let v = es
            .perform(
                Method::GET,
                &make_path(&["_snapshot", repo, snap, "_status"]),
                &[("ignore_unavailable", flag(true))],
                None,
            )
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for d in snapshots_of(&v)? {
            out.push(build(
                &SNAPSHOT_STATUS,
                vec![
                    ("snapshot", dget(&d, "snapshot", json!("unknown"))?),
                    ("repository", dget(&d, "repository", json!("unknown"))?),
                    ("uuid", dget(&d, "uuid", Value::Null)?),
                    ("state", dget(&d, "state", json!("unknown"))?),
                    (
                        "include_global_state",
                        dget(&d, "include_global_state", Value::Null)?,
                    ),
                    ("shards_stats", dget(&d, "shards_stats", json!({}))?),
                    ("stats", dget(&d, "stats", json!({}))?),
                    ("indices", dget(&d, "indices", json!({}))?),
                ],
            )?);
        }
        Ok(out)
    }
    .await;
    match result {
        Ok(list) => json!({
            "snapshots": list,
            "success": true,
            "message": format!("Successfully retrieved status for {} snapshots", list.len()),
        }),
        Err(e) => json!({
            "snapshots": [],
            "success": false,
            "message": format!("Failed to get snapshot status: {e}"),
        }),
    }
}

/// `es.snapshot.get(repository, snapshot="_all", ignore_unavailable=True)`.
async fn all_snapshots(st: &WazuhState, repository: &str) -> Result<Value, String> {
    let es = client(st).await.map_err(|e| e.py_str())?;
    require(&[repository, "_all"]).map_err(|e| e.to_string())?;
    es.perform(
        Method::GET,
        &make_path(&["_snapshot", repository, "_all"]),
        &[("ignore_unavailable", flag(true))],
        None,
    )
    .await
    .map_err(|e| e.to_string())
}

/// `list_snapshots(repository)`.
pub async fn list_snapshots(st: &WazuhState, repository: &str) -> Value {
    let result: Result<Vec<Value>, String> = async {
        let v = all_snapshots(st, repository).await?;
        let mut out = Vec::new();
        for d in snapshots_of(&v)? {
            out.push(build(
                &SNAPSHOT_INFO,
                vec![
                    ("snapshot", dget(&d, "snapshot", json!("unknown"))?),
                    ("uuid", dget(&d, "uuid", Value::Null)?),
                    ("version_id", dget(&d, "version_id", Value::Null)?),
                    ("version", dget(&d, "version", Value::Null)?),
                    ("indices", dget(&d, "indices", json!([]))?),
                    (
                        "include_global_state",
                        dget(&d, "include_global_state", Value::Null)?,
                    ),
                    ("state", dget(&d, "state", json!("unknown"))?),
                    ("start_time", dget(&d, "start_time", Value::Null)?),
                    (
                        "start_time_in_millis",
                        dget(&d, "start_time_in_millis", Value::Null)?,
                    ),
                    ("end_time", dget(&d, "end_time", Value::Null)?),
                    (
                        "end_time_in_millis",
                        dget(&d, "end_time_in_millis", Value::Null)?,
                    ),
                    (
                        "duration_in_millis",
                        dget(&d, "duration_in_millis", Value::Null)?,
                    ),
                    ("failures", dget(&d, "failures", json!([]))?),
                    ("shards", dget(&d, "shards", json!({}))?),
                ],
            )?);
        }
        Ok(out)
    }
    .await;
    match result {
        Ok(list) => json!({
            "repository": repository,
            "snapshots": list,
            "success": true,
            "message": format!(
                "Successfully retrieved {} snapshots from repository {repository}",
                list.len()
            ),
        }),
        Err(e) => json!({
            "repository": repository,
            "snapshots": [],
            "success": false,
            "message": format!("Failed to list snapshots: {e}"),
        }),
    }
}

fn shard_info(snapshot_data: &Value) -> Result<Value, String> {
    let shards = dget(snapshot_data, "shards", json!({}))?;
    Ok(json!({
        "total": dget(&shards, "total", json!(0))?,
        "failed": dget(&shards, "failed", json!(0))?,
        "successful": dget(&shards, "successful", json!(0))?,
    }))
}

/// `restore_snapshot(request)`.
pub async fn restore(st: &WazuhState, req: &RestoreSnapshotRequest) -> Value {
    let result: Result<Value, String> = async {
        let es = client(st).await.map_err(|e| e.py_str())?;
        let mut body = Map::new();
        if let Some(i) = req.indices.as_ref().filter(|i| !i.is_empty()) {
            body.insert("indices".into(), json!(i.join(",")));
        }
        if let Some(b) = req.ignore_unavailable {
            body.insert("ignore_unavailable".into(), json!(b));
        }
        if let Some(b) = req.include_global_state {
            body.insert("include_global_state".into(), json!(b));
        }
        if let Some(p) = req.rename_pattern.as_ref().filter(|p| !p.is_empty()) {
            body.insert("rename_pattern".into(), json!(p));
        }
        if let Some(p) = req.rename_replacement.as_ref().filter(|p| !p.is_empty()) {
            body.insert("rename_replacement".into(), json!(p));
        }
        if let Some(b) = req.include_aliases {
            body.insert("include_aliases".into(), json!(b));
        }
        if let Some(b) = req.partial {
            body.insert("partial".into(), json!(b));
        }
        require(&[&req.repository, &req.snapshot]).map_err(|e| e.to_string())?;
        let body = Value::Object(body);
        let response = es
            .perform(
                Method::POST,
                &make_path(&["_snapshot", &req.repository, &req.snapshot, "_restore"]),
                &[("wait_for_completion", flag(false))],
                (!body.as_object().is_some_and(Map::is_empty)).then_some(&body),
            )
            .await
            .map_err(|e| e.to_string())?;
        let snapshot_data = dget(&response, "snapshot", json!({}))?;
        let shards = shard_info(&snapshot_data)?;
        let indices = dget(&snapshot_data, "indices", json!([]))?;
        build(
            &RESTORE_SNAPSHOT_RESPONSE,
            vec![
                ("snapshot", json!(req.snapshot)),
                ("repository", json!(req.repository)),
                ("indices", indices),
                ("shards", shards),
                ("success", json!(true)),
                (
                    "message",
                    json!(format!(
                        "Successfully initiated restore of snapshot {}",
                        req.snapshot
                    )),
                ),
            ],
        )
    }
    .await;
    match result {
        Ok(v) => v,
        Err(e) => json!({
            "snapshot": req.snapshot,
            "repository": req.repository,
            "indices": [],
            "shards": {"total": 0, "failed": 0, "successful": 0},
            "success": false,
            "message": format!("Failed to restore snapshot: {e}"),
        }),
    }
}

/// `parse_graylog_index_name`: `base_number` with an all-digit suffix.
fn graylog_parts(name: &str) -> Option<(&str, u128)> {
    let (base, number) = name.rsplit_once('_')?;
    if base.is_empty() || number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((base, number.parse().unwrap_or(u128::MAX)))
}

/// `identify_write_indices`: the highest-numbered index of each Graylog
/// base name (the first one listed on a tie).
pub fn write_indices(names: &[String]) -> Vec<String> {
    let mut best: Vec<(&str, u128, &str)> = Vec::new();
    for n in names {
        if let Some((base, number)) = graylog_parts(n) {
            match best.iter_mut().find(|(b, ..)| *b == base) {
                Some(entry) => {
                    if number > entry.1 {
                        entry.1 = number;
                        entry.2 = n;
                    }
                }
                None => best.push((base, number, n)),
            }
        }
    }
    best.into_iter().map(|(_, _, n)| n.to_string()).collect()
}

/// `get_all_indices()` (any failure: none).
async fn all_indices(st: &WazuhState) -> Vec<String> {
    let Ok(es) = client(st).await else {
        return Vec::new();
    };
    match es.perform(Method::GET, "/*/_alias", &[], None).await {
        Ok(v) => keys(&v).unwrap_or_default(),
        Err(e) => {
            tracing::error!("Failed to get indices: {e}");
            Vec::new()
        }
    }
}

/// A user index pattern as Python matches it: `re.match(f"^{p}$", name)`
/// with `*` → `.*`, the rest left to the regex engine. `re.match` anchors
/// at the start only, so the outer group keeps an alternation's branches
/// as Python reads them (`a*x|b*` is `^a.*x` *or* `b.*$`).
pub(crate) fn pattern_regex(pattern: &str) -> Result<Regex, String> {
    Regex::new(&format!("^(?:^{}$)", pattern.replace('*', ".*"))).map_err(|e| e.to_string())
}

/// `filter_write_indices(requested)`: `(to_snapshot, skipped)`.
async fn filter_write_indices(
    st: &WazuhState,
    requested: Option<&[String]>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let all = all_indices(st).await;
    let writes = write_indices(&all);
    let to_check: Vec<String> = match requested.filter(|r| !r.is_empty()) {
        Some(patterns) => {
            let mut out = Vec::new();
            for p in patterns {
                if p.contains('*') {
                    let re = pattern_regex(p)?;
                    out.extend(all.iter().filter(|n| re.is_match(n)).cloned());
                } else {
                    out.push(p.clone());
                }
            }
            out
        }
        None => all.clone(),
    };
    let (skipped, keep): (Vec<String>, Vec<String>) =
        to_check.into_iter().partition(|n| writes.contains(n));
    Ok((keep, skipped))
}

/// `create_snapshot(request)`.
pub async fn create(st: &WazuhState, req: &CreateSnapshotRequest) -> Value {
    let failed = |e: String| {
        json!({
            "snapshot": req.snapshot,
            "repository": req.repository,
            "uuid": null,
            "state": null,
            "indices": [],
            "skipped_write_indices": [],
            "shards": null,
            "accepted": false,
            "success": false,
            "message": format!("Failed to create snapshot: {e}"),
        })
    };
    let es = match client(st).await {
        Ok(es) => es,
        Err(e) => return failed(e.py_str()),
    };
    let mut skipped: Vec<String> = Vec::new();
    let mut to_snapshot: Option<Vec<String>> = req.indices.clone();
    if req.skip_write_indices == Some(true) {
        match filter_write_indices(st, req.indices.as_deref()).await {
            Ok((keep, skip)) => {
                to_snapshot = Some(keep);
                skipped = skip;
            }
            Err(e) => return failed(e),
        }
        if to_snapshot.as_ref().is_none_or(Vec::is_empty) {
            return json!({
                "snapshot": req.snapshot,
                "repository": req.repository,
                "uuid": null,
                "state": null,
                "indices": [],
                "skipped_write_indices": skipped,
                "shards": null,
                "accepted": false,
                "success": false,
                "message": "No indices to snapshot - all requested indices are currently being written to",
            });
        }
    }
    let mut body = Map::new();
    if let Some(i) = to_snapshot.as_ref().filter(|i| !i.is_empty()) {
        body.insert("indices".into(), json!(i.join(",")));
    }
    if let Some(b) = req.ignore_unavailable {
        body.insert("ignore_unavailable".into(), json!(b));
    }
    if let Some(b) = req.include_global_state {
        body.insert("include_global_state".into(), json!(b));
    }
    if let Some(b) = req.partial {
        body.insert("partial".into(), json!(b));
    }
    match req.metadata.as_ref().filter(|m| !m.is_empty()) {
        Some(m) => {
            let mut m = m.clone();
            if !skipped.is_empty() {
                m.insert("skipped_write_indices".into(), json!(skipped));
            }
            body.insert("metadata".into(), Value::Object(m));
        }
        None if !skipped.is_empty() => {
            body.insert("metadata".into(), json!({"skipped_write_indices": skipped}));
        }
        None => {}
    }
    if let Err(e) = require(&[&req.repository, &req.snapshot]) {
        return failed(e.to_string());
    }
    let wait = req.wait_for_completion.unwrap_or(false);
    let body = Value::Object(body);
    let response = match es
        .perform(
            Method::PUT,
            &make_path(&["_snapshot", &req.repository, &req.snapshot]),
            &[("wait_for_completion", flag(wait))],
            (!body.as_object().is_some_and(Map::is_empty)).then_some(&body),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => return failed(e.to_string()),
    };
    let suffix = if skipped.is_empty() {
        String::new()
    } else {
        format!(" (skipped {} write indices)", skipped.len())
    };
    let result: Result<Value, String> = (|| {
        if wait {
            let data = dget(&response, "snapshot", json!({}))?;
            let shards = shard_info(&data)?;
            build(
                &CREATE_SNAPSHOT_RESPONSE,
                vec![
                    ("snapshot", dget(&data, "snapshot", json!(req.snapshot))?),
                    ("repository", json!(req.repository)),
                    ("uuid", dget(&data, "uuid", Value::Null)?),
                    ("state", dget(&data, "state", Value::Null)?),
                    ("indices", dget(&data, "indices", json!([]))?),
                    ("skipped_write_indices", json!(skipped)),
                    ("shards", shards),
                    ("accepted", json!(true)),
                    ("success", json!(true)),
                    (
                        "message",
                        json!(format!(
                            "Successfully created snapshot {}{suffix}",
                            req.snapshot
                        )),
                    ),
                ],
            )
        } else {
            let accepted = dget(&response, "accepted", json!(false))?;
            let accepted_ok = crate::indexer::services::alerts::truthy(&accepted);
            let message = if accepted_ok {
                format!("Snapshot {} creation initiated{suffix}", req.snapshot)
            } else {
                "Snapshot request was not accepted".into()
            };
            build(
                &CREATE_SNAPSHOT_RESPONSE,
                vec![
                    ("snapshot", json!(req.snapshot)),
                    ("repository", json!(req.repository)),
                    ("uuid", Value::Null),
                    ("state", json!("IN_PROGRESS")),
                    ("indices", json!(to_snapshot.clone().unwrap_or_default())),
                    ("skipped_write_indices", json!(skipped)),
                    ("shards", Value::Null),
                    ("accepted", accepted.clone()),
                    ("success", accepted),
                    ("message", json!(message)),
                ],
            )
        }
    })();
    result.unwrap_or_else(failed)
}

// ---------------------------------------------------------------------------
// index_snapshot_schedules
// ---------------------------------------------------------------------------

/// The `index_snapshot_schedules` columns.
pub const COLUMNS: &[&str] = &[
    "id",
    "name",
    "index_pattern",
    "repository",
    "enabled",
    "snapshot_prefix",
    "include_global_state",
    "skip_write_indices",
    "retention_days",
    "last_execution_time",
    "last_snapshot_name",
    "last_execution_status",
    "created_at",
    "updated_at",
    "scheduled_hour",
    "scheduled_minute",
    "interval_days",
    "timezone",
    "day_of_week",
];

/// One `index_snapshot_schedules` row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ScheduleRow {
    /// Id.
    pub id: i32,
    /// Friendly name.
    pub name: String,
    /// Index pattern.
    pub index_pattern: String,
    /// Repository.
    pub repository: String,
    /// Active.
    pub enabled: bool,
    /// Snapshot name prefix.
    pub snapshot_prefix: String,
    /// Include the cluster state.
    pub include_global_state: bool,
    /// Skip Graylog's write indices.
    pub skip_write_indices: bool,
    /// Retention.
    pub retention_days: Option<i32>,
    /// Last run.
    pub last_execution_time: Option<NaiveDateTime>,
    /// Last snapshot.
    pub last_snapshot_name: Option<String>,
    /// Last status.
    pub last_execution_status: Option<String>,
    /// Created.
    pub created_at: NaiveDateTime,
    /// Updated.
    pub updated_at: NaiveDateTime,
    /// Hour gate.
    pub scheduled_hour: Option<i32>,
    /// Minute gate.
    pub scheduled_minute: Option<i32>,
    /// Interval.
    pub interval_days: i32,
    /// IANA zone.
    pub timezone: String,
    /// Weekday gate.
    pub day_of_week: Option<i32>,
}

/// `_schedule_to_response`.
pub fn schedule_out(r: &ScheduleRow) -> Value {
    json!({
        "id": r.id,
        "name": r.name,
        "index_pattern": r.index_pattern,
        "repository": r.repository,
        "enabled": r.enabled,
        "snapshot_prefix": r.snapshot_prefix,
        "include_global_state": r.include_global_state,
        "skip_write_indices": r.skip_write_indices,
        "retention_days": r.retention_days,
        "last_execution_time": r.last_execution_time.map(isoformat),
        "last_snapshot_name": r.last_snapshot_name,
        "last_execution_status": r.last_execution_status,
        "scheduled_hour": r.scheduled_hour,
        "scheduled_minute": r.scheduled_minute,
        "interval_days": r.interval_days,
        "day_of_week": r.day_of_week,
        "timezone": r.timezone,
        "created_at": isoformat(r.created_at),
        "updated_at": isoformat(r.updated_at),
    })
}

fn select() -> String {
    format!(
        "SELECT {} FROM index_snapshot_schedules",
        COLUMNS.join(", ")
    )
}

/// One row by id.
pub async fn schedule_by_id(db: &Db, id: i64) -> Result<Option<ScheduleRow>, sqlx::Error> {
    sqlx::query_as::<_, ScheduleRow>(&format!("{} WHERE id = ?", select()))
        .bind(id)
        .fetch_optional(db.pool())
        .await
}

/// `select(SnapshotSchedule)[.where(enabled == True)]` (no `ORDER BY`).
pub async fn schedules(db: &Db, enabled_only: bool) -> Result<Vec<ScheduleRow>, sqlx::Error> {
    let mut sql = select();
    if enabled_only {
        sql.push_str(" WHERE enabled = true");
    }
    sqlx::query_as::<_, ScheduleRow>(&sql)
        .fetch_all(db.pool())
        .await
}

fn op(schedule: Option<Value>, success: bool, message: String) -> Value {
    json!({"schedule": schedule, "success": success, "message": message})
}

/// `create_snapshot_schedule`.
pub async fn create_schedule(db: &Db, b: &ScheduleBody) -> Value {
    let now = copilot_core::time::now_utc_micros();
    let result: Result<ScheduleRow, sqlx::Error> = async {
        let id = sqlx::query(
            "INSERT INTO index_snapshot_schedules (name, index_pattern, repository, enabled, \
             snapshot_prefix, include_global_state, skip_write_indices, retention_days, \
             last_execution_time, last_snapshot_name, last_execution_status, scheduled_hour, \
             scheduled_minute, interval_days, day_of_week, timezone, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&b.name)
        .bind(&b.index_pattern)
        .bind(&b.repository)
        .bind(b.enabled.unwrap_or(true))
        .bind(
            b.snapshot_prefix
                .clone()
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| "scheduled".into()),
        )
        .bind(b.include_global_state.unwrap_or(false))
        .bind(b.skip_write_indices.unwrap_or(true))
        .bind(b.retention_days)
        .bind(b.scheduled_hour.1)
        .bind(b.scheduled_minute.1)
        .bind(b.interval_days.unwrap_or(1))
        .bind(b.day_of_week.1)
        .bind(
            b.timezone
                .clone()
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| "UTC".into()),
        )
        .bind(now)
        .bind(now)
        .execute(db.pool())
        .await?
        .last_insert_id();
        schedule_by_id(db, i64::try_from(id).unwrap_or_default())
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }
    .await;
    match result {
        Ok(row) => op(
            Some(schedule_out(&row)),
            true,
            format!("Successfully created snapshot schedule: {}", row.name),
        ),
        Err(e) => op(
            None,
            false,
            format!("Failed to create snapshot schedule: {e}"),
        ),
    }
}

/// `list_snapshot_schedules`.
pub async fn list_schedules(db: &Db, enabled_only: bool) -> Value {
    match schedules(db, enabled_only).await {
        Ok(rows) => json!({
            "schedules": rows.iter().map(schedule_out).collect::<Vec<_>>(),
            "success": true,
            "message": format!("Successfully retrieved {} snapshot schedules", rows.len()),
        }),
        Err(e) => json!({
            "schedules": [],
            "success": false,
            "message": format!("Failed to list snapshot schedules: {e}"),
        }),
    }
}

fn not_found(id: i64) -> Value {
    op(
        None,
        false,
        format!("Snapshot schedule with ID {id} not found"),
    )
}

/// `get_snapshot_schedule`.
pub async fn get_schedule(db: &Db, id: i64) -> Value {
    match schedule_by_id(db, id).await {
        Ok(Some(row)) => op(
            Some(schedule_out(&row)),
            true,
            format!("Successfully retrieved snapshot schedule: {}", row.name),
        ),
        Ok(None) => not_found(id),
        Err(e) => op(None, false, format!("Failed to get snapshot schedule: {e}")),
    }
}

/// `update_snapshot_schedule`: the fields sent (the time gates even when
/// `null`), and `updated_at`.
pub async fn update_schedule(db: &Db, id: i64, b: &ScheduleBody) -> Value {
    let result: Result<Option<ScheduleRow>, sqlx::Error> = async {
        let Some(mut r) = schedule_by_id(db, id).await? else {
            return Ok(None);
        };
        if let Some(v) = &b.name {
            r.name = v.clone();
        }
        if let Some(v) = &b.index_pattern {
            r.index_pattern = v.clone();
        }
        if let Some(v) = &b.repository {
            r.repository = v.clone();
        }
        if let Some(v) = b.enabled {
            r.enabled = v;
        }
        if let Some(v) = &b.snapshot_prefix {
            r.snapshot_prefix = v.clone();
        }
        if let Some(v) = b.include_global_state {
            r.include_global_state = v;
        }
        if let Some(v) = b.skip_write_indices {
            r.skip_write_indices = v;
        }
        if let Some(v) = b.retention_days {
            r.retention_days = i32::try_from(v).ok();
        }
        if b.scheduled_hour.0 {
            r.scheduled_hour = b.scheduled_hour.1.and_then(|v| i32::try_from(v).ok());
        }
        if b.scheduled_minute.0 {
            r.scheduled_minute = b.scheduled_minute.1.and_then(|v| i32::try_from(v).ok());
        }
        if let Some(v) = b.interval_days {
            r.interval_days = i32::try_from(v).unwrap_or(i32::MAX);
        }
        if b.day_of_week.0 {
            r.day_of_week = b.day_of_week.1.and_then(|v| i32::try_from(v).ok());
        }
        if let Some(v) = &b.timezone {
            r.timezone = v.clone();
        }
        sqlx::query(
            "UPDATE index_snapshot_schedules SET name = ?, index_pattern = ?, repository = ?, \
             enabled = ?, snapshot_prefix = ?, include_global_state = ?, skip_write_indices = ?, \
             retention_days = ?, scheduled_hour = ?, scheduled_minute = ?, interval_days = ?, \
             day_of_week = ?, timezone = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&r.name)
        .bind(&r.index_pattern)
        .bind(&r.repository)
        .bind(r.enabled)
        .bind(&r.snapshot_prefix)
        .bind(r.include_global_state)
        .bind(r.skip_write_indices)
        .bind(r.retention_days)
        .bind(r.scheduled_hour)
        .bind(r.scheduled_minute)
        .bind(r.interval_days)
        .bind(r.day_of_week)
        .bind(&r.timezone)
        .bind(copilot_core::time::now_utc_micros())
        .bind(id)
        .execute(db.pool())
        .await?;
        schedule_by_id(db, id).await
    }
    .await;
    match result {
        Ok(Some(row)) => op(
            Some(schedule_out(&row)),
            true,
            format!("Successfully updated snapshot schedule: {}", row.name),
        ),
        Ok(None) => not_found(id),
        Err(e) => op(
            None,
            false,
            format!("Failed to update snapshot schedule: {e}"),
        ),
    }
}

/// `delete_snapshot_schedule`.
pub async fn delete_schedule(db: &Db, id: i64) -> Value {
    let result: Result<Option<String>, sqlx::Error> = async {
        let Some(r) = schedule_by_id(db, id).await? else {
            return Ok(None);
        };
        sqlx::query("DELETE FROM index_snapshot_schedules WHERE id = ?")
            .bind(id)
            .execute(db.pool())
            .await?;
        Ok(Some(r.name))
    }
    .await;
    match result {
        Ok(Some(name)) => op(
            None,
            true,
            format!("Successfully deleted snapshot schedule: {name}"),
        ),
        Ok(None) => not_found(id),
        Err(e) => op(
            None,
            false,
            format!("Failed to delete snapshot schedule: {e}"),
        ),
    }
}

/// `PyErr` from a failed operation response (`HTTPException(404 if "not
/// found" in message else 500, message)`).
pub fn op_error(response: &Value, lookup: bool) -> Option<PyErr> {
    if response["success"].as_bool() == Some(true) {
        return None;
    }
    let message = response["message"].as_str().unwrap_or_default().to_string();
    let status = if lookup && message.to_lowercase().contains("not found") {
        404
    } else {
        500
    };
    Some(PyErr::http(status, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graylog_write_indices() {
        let names: Vec<String> = [
            "wazuh_acme_1",
            "wazuh_acme_10",
            "wazuh_acme_9",
            "plain",
            "other_x_02",
            "other_x_2",
            "trailing_",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(write_indices(&names), ["wazuh_acme_10", "other_x_02"]);
    }

    #[test]
    fn index_patterns_match_as_re_match_does() {
        // Recorded with Python 3.11: `bool(re.match(f"^{p}$", name))`.
        for (pattern, name, expected) in [
            ("a*x|b*", "aaxyz", true),
            ("a*x|b*", "zb", false),
            ("wazuh-*", "wazuh-alerts", true),
            ("wazuh-*", "xwazuh-a", false),
            ("a*|b", "cb", false),
        ] {
            let re = pattern_regex(pattern).unwrap();
            assert_eq!(re.is_match(name), expected, "{pattern} ~ {name}");
        }
    }
}
