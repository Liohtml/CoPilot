//! `wazuh_indexer/schema/*.py`: the request bodies (read with
//! `copilot_web::validate`, Pydantic's 422 texts) and the models upstream
//! data passes through ([`crate::pymodel`], Pydantic's `ValidationError`
//! texts).

use serde_json::{Map, Value};

use copilot_web::validate::{IntRules, Loc, LocPart, StrRules, Validator};

use crate::pymodel::{Default as D, Field, Model, Ty};

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(name.into()));
    l
}

/// `int = Field(default)` from a JSON body.
fn int_or(v: &mut Validator, obj: &Map<String, Value>, at: &Loc, name: &str, d: i64) -> i64 {
    match obj.get(name) {
        None => d,
        Some(x) => v
            .check_int(&child(at, name), x, IntRules::default())
            .unwrap_or(d),
    }
}

/// `validate_timerange`: ends with `h`, `d` or `w`, digits before it. The
/// validator raises `ValueError`, which FastAPI reports as `value_error`.
fn timerange(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> String {
    let value = v.str_or(obj, at, "timerange", StrRules::any(), "24h");
    if v.errors().iter().any(|e| e.loc == child(at, "timerange")) {
        return value;
    }
    let ok_unit = value.ends_with(['h', 'd', 'w']);
    let digits = &value[..value.len().saturating_sub(1)];
    if !ok_unit {
        v.push(
            "value_error",
            child(at, "timerange"),
            "Value error, Invalid timerange format. The string should end with either 'h', 'd', 'w'.",
        );
    } else if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        v.push(
            "value_error",
            child(at, "timerange"),
            "Value error, Invalid timerange format. The string should start with a number.",
        );
    }
    value
}

/// `AlertsSearchBody` (+ `HostAlertsSearchBody.agent_name`,
/// `IndexAlertsSearchBody.index_name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertsSearchBody {
    /// Hits per index.
    pub size: i64,
    /// `24h`, `7d`, `1w`, …
    pub timerange: String,
    /// The field matched.
    pub alert_field: String,
    /// Its value.
    pub alert_value: String,
    /// Range and sort field (mutated by the `timestamp_utc` fallback).
    pub timestamp_field: String,
    /// `/host` only.
    pub agent_name: Option<String>,
    /// `/index` only.
    pub index_name: Option<String>,
}

/// Which subclass of `AlertsSearchBody` a route takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertsBodyKind {
    /// `AlertsSearchBody`.
    Plain,
    /// `HostAlertsSearchBody`.
    Host,
    /// `IndexAlertsSearchBody`.
    Index,
}

impl AlertsSearchBody {
    /// Read the body in field order.
    pub fn read(
        kind: AlertsBodyKind,
    ) -> impl Fn(&mut Validator, &Map<String, Value>, &Loc) -> Self {
        move |v, obj, at| {
            let any = StrRules::any();
            let size = int_or(v, obj, at, "size", 10);
            let timerange = timerange(v, obj, at);
            let alert_field = v.str_or(obj, at, "alert_field", any, "syslog_level");
            let alert_value = v.str_or(obj, at, "alert_value", any, "ALERT");
            let timestamp_field = v.str_or(obj, at, "timestamp_field", any, "timestamp_utc");
            let agent_name =
                (kind == AlertsBodyKind::Host).then(|| v.req_str(obj, at, "agent_name", any));
            let index_name =
                (kind == AlertsBodyKind::Index).then(|| v.req_str(obj, at, "index_name", any));
            Self {
                size,
                timerange,
                alert_field,
                alert_value,
                timestamp_field,
                agent_name,
                index_name,
            }
        }
    }
}

/// `GraylogAlertsSearchBody` (+ `GraylogIndexAlertsSearchBody.index_name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraylogAlertsSearchBody {
    /// Hits.
    pub size: i64,
    /// Window.
    pub timerange: String,
    /// The Graylog events index pattern.
    pub index_prefix: String,
    /// Optional customer subset.
    pub customer_codes: Option<Vec<String>>,
    /// `/alerts/graylog/index` only.
    pub index_name: Option<String>,
}

impl GraylogAlertsSearchBody {
    /// Read the body in field order.
    pub fn read(with_index: bool) -> impl Fn(&mut Validator, &Map<String, Value>, &Loc) -> Self {
        move |v, obj, at| {
            let any = StrRules::any();
            let size = int_or(v, obj, at, "size", 10);
            let timerange = timerange(v, obj, at);
            let index_prefix = v.str_or(obj, at, "index_prefix", any, "gl-events*");
            let customer_codes = match obj.get("customer_codes") {
                None | Some(Value::Null) => None,
                Some(x) => Some(v.str_items(x, &child(at, "customer_codes"))),
            };
            let index_name = with_index.then(|| v.req_str(obj, at, "index_name", any));
            Self {
                size,
                timerange,
                index_prefix,
                customer_codes,
                index_name,
            }
        }
    }
}

/// `AlertByIdSearchBody`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertByIdSearchBody {
    /// Index.
    pub index_name: String,
    /// Document id.
    pub alert_id: String,
}

impl AlertByIdSearchBody {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let any = StrRules::any();
        Self {
            index_name: v.req_str(obj, at, "index_name", any),
            alert_id: v.req_str(obj, at, "alert_id", any),
        }
    }
}

// ---------------------------------------------------------------------------
// Models upstream data passes through
// ---------------------------------------------------------------------------

/// `ClusterHealth`.
pub static CLUSTER_HEALTH: Model = Model {
    name: "ClusterHealth",
    fields: &[
        Field::req("active_primary_shards", Ty::Int),
        Field::req("active_shards", Ty::Int),
        Field::req("active_shards_percent_as_number", Ty::IntOrFloat),
        Field::req("cluster_name", Ty::Str),
        Field::req("delayed_unassigned_shards", Ty::Int),
        Field::req("discovered_cluster_manager", Ty::Bool),
        Field::req("discovered_master", Ty::Bool),
        Field::req("initializing_shards", Ty::Int),
        Field::req("number_of_data_nodes", Ty::Int),
        Field::req("number_of_in_flight_fetch", Ty::Int),
        Field::req("number_of_nodes", Ty::Int),
        Field::req("number_of_pending_tasks", Ty::Int),
        Field::req("relocating_shards", Ty::Int),
        Field::req("status", Ty::Str),
        Field::req("task_max_waiting_in_queue_millis", Ty::Int),
        Field::req("timed_out", Ty::Bool),
        Field::req("unassigned_shards", Ty::Int),
    ],
};

/// `NodeAllocation`.
pub static NODE_ALLOCATION: Model = Model {
    name: "NodeAllocation",
    fields: &[
        Field::new("disk_available", Ty::Opt(&Ty::Str), D::Null),
        Field::new("disk_percent", Ty::Opt(&Ty::Str), D::Null),
        Field::new("disk_total", Ty::Opt(&Ty::Str), D::Null),
        Field::new("disk_used", Ty::Opt(&Ty::Str), D::Null),
        Field::req("node", Ty::Str),
    ],
};

/// `IndicesStats`.
pub static INDICES_STATS: Model = Model {
    name: "IndicesStats",
    fields: &[
        Field::new(
            "docs_count",
            Ty::Opt(&Ty::Str),
            D::Str("Docs count not found"),
        ),
        Field::req("health", Ty::Str),
        Field::req("index", Ty::Str),
        Field::req("replica_count", Ty::Str),
        Field::new(
            "store_size",
            Ty::Opt(&Ty::Str),
            D::Str("Store size not found"),
        ),
    ],
};

/// `Shards`.
pub static SHARDS: Model = Model {
    name: "Shards",
    fields: &[
        Field::req("index", Ty::Str),
        Field::new("node", Ty::Opt(&Ty::Str), D::Null),
        Field::req("shard", Ty::Int),
        Field::req("state", Ty::Str),
        Field::new("size", Ty::Opt(&Ty::Str), D::Null),
    ],
};

/// `AlertsByHost`.
pub static ALERTS_BY_HOST: Model = Model {
    name: "AlertsByHost",
    fields: &[
        Field::req("agent_name", Ty::Str),
        Field::req("number_of_alerts", Ty::Int),
    ],
};

/// `AlertsByRule`.
pub static ALERTS_BY_RULE: Model = Model {
    name: "AlertsByRule",
    fields: &[
        Field::req("rule", Ty::Str),
        Field::req("number_of_alerts", Ty::Int),
    ],
};

/// `AlertsByRulePerHost` (declared `agent_name`, `number_of_alerts`, `rule`).
pub static ALERTS_BY_RULE_PER_HOST: Model = Model {
    name: "AlertsByRulePerHost",
    fields: &[
        Field::req("agent_name", Ty::Str),
        Field::req("number_of_alerts", Ty::Int),
        Field::req("rule", Ty::Str),
    ],
};

/// `SnapshotRepository`.
pub static SNAPSHOT_REPOSITORY: Model = Model {
    name: "SnapshotRepository",
    fields: &[
        Field::req("name", Ty::Str),
        Field::req("type", Ty::Str),
        Field::new("settings", Ty::Dict(&Ty::Any), D::EmptyDict),
    ],
};

static SNAPSHOT_SHARD_STATUS: Model = Model {
    name: "SnapshotShardStatus",
    fields: &[
        Field::req("stage", Ty::Str),
        Field::aliased(
            "total_files",
            "total_file_count",
            Ty::Opt(&Ty::Int),
            D::Null,
        ),
        Field::new("total_size_in_bytes", Ty::Opt(&Ty::Int), D::Null),
        Field::aliased(
            "processed_files",
            "processed_file_count",
            Ty::Opt(&Ty::Int),
            D::Null,
        ),
        Field::aliased(
            "processed_size_in_bytes",
            "done_size_in_bytes",
            Ty::Opt(&Ty::Int),
            D::Null,
        ),
    ],
};

static SNAPSHOT_INDEX_STATUS: Model = Model {
    name: "SnapshotIndexStatus",
    fields: &[
        Field::new("shards_stats", Ty::Dict(&Ty::Any), D::EmptyDict),
        Field::new("stats", Ty::Dict(&Ty::Any), D::EmptyDict),
        Field::new(
            "shards",
            Ty::Dict(&Ty::Model(&SNAPSHOT_SHARD_STATUS)),
            D::EmptyDict,
        ),
    ],
};

/// `SnapshotStatus`.
pub static SNAPSHOT_STATUS: Model = Model {
    name: "SnapshotStatus",
    fields: &[
        Field::req("snapshot", Ty::Str),
        Field::req("repository", Ty::Str),
        Field::new("uuid", Ty::Opt(&Ty::Str), D::Null),
        Field::req("state", Ty::Str),
        Field::new("include_global_state", Ty::Opt(&Ty::Bool), D::Null),
        Field::new("shards_stats", Ty::Dict(&Ty::Any), D::EmptyDict),
        Field::new("stats", Ty::Dict(&Ty::Any), D::EmptyDict),
        Field::new(
            "indices",
            Ty::Dict(&Ty::Model(&SNAPSHOT_INDEX_STATUS)),
            D::EmptyDict,
        ),
    ],
};

/// `SnapshotInfo`.
pub static SNAPSHOT_INFO: Model = Model {
    name: "SnapshotInfo",
    fields: &[
        Field::req("snapshot", Ty::Str),
        Field::new("uuid", Ty::Opt(&Ty::Str), D::Null),
        Field::new("version_id", Ty::Opt(&Ty::Int), D::Null),
        Field::new("version", Ty::Opt(&Ty::Str), D::Null),
        Field::new("indices", Ty::List(&Ty::Str), D::EmptyList),
        Field::new("include_global_state", Ty::Opt(&Ty::Bool), D::Null),
        Field::req("state", Ty::Str),
        Field::new("start_time", Ty::Opt(&Ty::Str), D::Null),
        Field::new("start_time_in_millis", Ty::Opt(&Ty::Int), D::Null),
        Field::new("end_time", Ty::Opt(&Ty::Str), D::Null),
        Field::new("end_time_in_millis", Ty::Opt(&Ty::Int), D::Null),
        Field::new("duration_in_millis", Ty::Opt(&Ty::Int), D::Null),
        Field::new("failures", Ty::List(&Ty::Dict(&Ty::Any)), D::EmptyList),
        Field::new("shards", Ty::Dict(&Ty::Any), D::EmptyDict),
    ],
};

/// `RestoreShardInfo`.
pub static RESTORE_SHARD_INFO: Model = Model {
    name: "RestoreShardInfo",
    fields: &[
        Field::req("total", Ty::Int),
        Field::req("failed", Ty::Int),
        Field::req("successful", Ty::Int),
    ],
};

/// `RestoreSnapshotResponse` (its `indices` and `shards` come from the
/// indexer).
pub static RESTORE_SNAPSHOT_RESPONSE: Model = Model {
    name: "RestoreSnapshotResponse",
    fields: &[
        Field::req("snapshot", Ty::Str),
        Field::req("repository", Ty::Str),
        Field::new("indices", Ty::List(&Ty::Str), D::EmptyList),
        Field::req("shards", Ty::Model(&RESTORE_SHARD_INFO)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
};

/// `CreateSnapshotResponse`.
pub static CREATE_SNAPSHOT_RESPONSE: Model = Model {
    name: "CreateSnapshotResponse",
    fields: &[
        Field::req("snapshot", Ty::Str),
        Field::req("repository", Ty::Str),
        Field::new("uuid", Ty::Opt(&Ty::Str), D::Null),
        Field::new("state", Ty::Opt(&Ty::Str), D::Null),
        Field::new("indices", Ty::List(&Ty::Str), D::EmptyList),
        Field::new("skipped_write_indices", Ty::List(&Ty::Str), D::EmptyList),
        Field::new("shards", Ty::Opt(&Ty::Model(&RESTORE_SHARD_INFO)), D::Null),
        Field::req("accepted", Ty::Bool),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
};

/// `Alert` of an `AlertsSearchResponse` (`alerts` are documents).
pub static ALERT: Model = Model {
    name: "Alert",
    fields: &[
        Field::req("index_name", Ty::Str),
        Field::req("total_alerts", Ty::Int),
        Field::new(
            "alerts",
            Ty::Opt(&Ty::List(&Ty::Dict(&Ty::Any))),
            D::EmptyList,
        ),
    ],
};

/// `AlertsSearchResponse`.
pub static ALERTS_SEARCH_RESPONSE: Model = Model {
    name: "AlertsSearchResponse",
    fields: SEARCH_RESPONSE_FIELDS,
};

/// `HostAlertsSearchResponse`.
pub static HOST_ALERTS_SEARCH_RESPONSE: Model = Model {
    name: "HostAlertsSearchResponse",
    fields: SEARCH_RESPONSE_FIELDS,
};

/// `IndexAlertsSearchResponse`.
pub static INDEX_ALERTS_SEARCH_RESPONSE: Model = Model {
    name: "IndexAlertsSearchResponse",
    fields: SEARCH_RESPONSE_FIELDS,
};

static SEARCH_RESPONSE_FIELDS: &[Field] = &[
    Field::req("alerts_summary", Ty::List(&Ty::Model(&ALERT))),
    Field::req("success", Ty::Bool),
    Field::req("message", Ty::Str),
];

// ---------------------------------------------------------------------------
// Snapshot schedules
// ---------------------------------------------------------------------------

/// `SnapshotScheduleCreate` / `SnapshotScheduleUpdate`: every field, with
/// whether it was sent (`fields_set`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScheduleBody {
    /// `name`.
    pub name: Option<String>,
    /// `index_pattern`.
    pub index_pattern: Option<String>,
    /// `repository`.
    pub repository: Option<String>,
    /// `enabled`.
    pub enabled: Option<bool>,
    /// `snapshot_prefix`.
    pub snapshot_prefix: Option<String>,
    /// `include_global_state`.
    pub include_global_state: Option<bool>,
    /// `skip_write_indices`.
    pub skip_write_indices: Option<bool>,
    /// `retention_days`.
    pub retention_days: Option<i64>,
    /// `scheduled_hour` (sent?, value).
    pub scheduled_hour: (bool, Option<i64>),
    /// `scheduled_minute`.
    pub scheduled_minute: (bool, Option<i64>),
    /// `interval_days`.
    pub interval_days: Option<i64>,
    /// `day_of_week`.
    pub day_of_week: (bool, Option<i64>),
    /// `timezone`.
    pub timezone: Option<String>,
}

const HOUR: IntRules = IntRules {
    ge: Some(0),
    le: Some(23),
};
const MINUTE: IntRules = IntRules {
    ge: Some(0),
    le: Some(59),
};
const WEEKDAY: IntRules = IntRules {
    ge: Some(0),
    le: Some(6),
};
const INTERVAL: IntRules = IntRules {
    ge: Some(1),
    le: None,
};

impl ScheduleBody {
    /// `SnapshotScheduleCreate`: `name`, `index_pattern` and `repository`
    /// required; the optional fields default as declared.
    pub fn read_create(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let any = StrRules::any();
        let name = Some(v.req_str(obj, at, "name", any));
        let index_pattern = Some(v.req_str(obj, at, "index_pattern", any));
        let repository = Some(v.req_str(obj, at, "repository", any));
        let mut b = Self::read_optional(v, obj, at);
        b.name = name;
        b.index_pattern = index_pattern;
        b.repository = repository;
        // Defaults of the create model (an absent key, not an explicit null).
        if !obj.contains_key("enabled") {
            b.enabled = Some(true);
        }
        if !obj.contains_key("snapshot_prefix") {
            b.snapshot_prefix = Some("scheduled".into());
        }
        if !obj.contains_key("include_global_state") {
            b.include_global_state = Some(false);
        }
        if !obj.contains_key("skip_write_indices") {
            b.skip_write_indices = Some(true);
        }
        if !obj.contains_key("interval_days") {
            b.interval_days = Some(1);
        }
        if !obj.contains_key("timezone") {
            b.timezone = Some("UTC".into());
        }
        b
    }

    /// `SnapshotScheduleUpdate`: every field optional, `None` by default.
    pub fn read_update(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let any = StrRules::any();
        let name = v.opt_str(obj, at, "name", any);
        let index_pattern = v.opt_str(obj, at, "index_pattern", any);
        let repository = v.opt_str(obj, at, "repository", any);
        let mut b = Self::read_optional(v, obj, at);
        b.name = name;
        b.index_pattern = index_pattern;
        b.repository = repository;
        b
    }

    fn read_optional(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let any = StrRules::any();
        let enabled = v.opt_bool(obj, at, "enabled");
        let snapshot_prefix = v.opt_str(obj, at, "snapshot_prefix", any);
        let include_global_state = v.opt_bool(obj, at, "include_global_state");
        let skip_write_indices = v.opt_bool(obj, at, "skip_write_indices");
        let retention_days = v.opt_int(obj, at, "retention_days", IntRules::default());
        let scheduled_hour = (
            obj.contains_key("scheduled_hour"),
            v.opt_int(obj, at, "scheduled_hour", HOUR),
        );
        let scheduled_minute = (
            obj.contains_key("scheduled_minute"),
            v.opt_int(obj, at, "scheduled_minute", MINUTE),
        );
        let interval_days = v.opt_int(obj, at, "interval_days", INTERVAL);
        let day_of_week = (
            obj.contains_key("day_of_week"),
            v.opt_int(obj, at, "day_of_week", WEEKDAY),
        );
        let timezone = v.opt_str(obj, at, "timezone", any);
        Self {
            name: None,
            index_pattern: None,
            repository: None,
            enabled,
            snapshot_prefix,
            include_global_state,
            skip_write_indices,
            retention_days,
            scheduled_hour,
            scheduled_minute,
            interval_days,
            day_of_week,
            timezone,
        }
    }
}

/// `CreateSnapshotRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct CreateSnapshotRequest {
    /// Repository.
    pub repository: String,
    /// Snapshot name.
    pub snapshot: String,
    /// Indices (or patterns).
    pub indices: Option<Vec<String>>,
    /// `ignore_unavailable` (default `False`).
    pub ignore_unavailable: Option<bool>,
    /// `include_global_state` (default `True`).
    pub include_global_state: Option<bool>,
    /// `partial` (default `False`).
    pub partial: Option<bool>,
    /// `wait_for_completion` (default `False`).
    pub wait_for_completion: Option<bool>,
    /// `metadata`.
    pub metadata: Option<Map<String, Value>>,
    /// `skip_write_indices` (default `True`).
    pub skip_write_indices: Option<bool>,
}

fn opt_bool_default(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    d: bool,
) -> Option<bool> {
    if obj.contains_key(name) {
        v.opt_bool(obj, at, name)
    } else {
        Some(d)
    }
}

fn opt_str_list(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
) -> Option<Vec<String>> {
    match obj.get(name) {
        None | Some(Value::Null) => None,
        Some(x) => Some(v.str_items(x, &child(at, name))),
    }
}

impl CreateSnapshotRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let any = StrRules::any();
        let repository = v.req_str(obj, at, "repository", any);
        let snapshot = v.req_str(obj, at, "snapshot", any);
        let indices = opt_str_list(v, obj, at, "indices");
        let ignore_unavailable = opt_bool_default(v, obj, at, "ignore_unavailable", false);
        let include_global_state = opt_bool_default(v, obj, at, "include_global_state", true);
        let partial = opt_bool_default(v, obj, at, "partial", false);
        let wait_for_completion = opt_bool_default(v, obj, at, "wait_for_completion", false);
        let metadata = match obj.get("metadata") {
            None | Some(Value::Null) => None,
            Some(Value::Object(m)) => Some(m.clone()),
            Some(_) => {
                v.push(
                    "dict_type",
                    child(at, "metadata"),
                    "Input should be a valid dictionary",
                );
                None
            }
        };
        let skip_write_indices = opt_bool_default(v, obj, at, "skip_write_indices", true);
        Self {
            repository,
            snapshot,
            indices,
            ignore_unavailable,
            include_global_state,
            partial,
            wait_for_completion,
            metadata,
            skip_write_indices,
        }
    }
}

/// `RestoreSnapshotRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreSnapshotRequest {
    /// Repository.
    pub repository: String,
    /// Snapshot.
    pub snapshot: String,
    /// Indices.
    pub indices: Option<Vec<String>>,
    /// Default `True`.
    pub ignore_unavailable: Option<bool>,
    /// Default `False`.
    pub include_global_state: Option<bool>,
    /// Rename pattern.
    pub rename_pattern: Option<String>,
    /// Rename replacement.
    pub rename_replacement: Option<String>,
    /// Default `True`.
    pub include_aliases: Option<bool>,
    /// Default `False`.
    pub partial: Option<bool>,
}

impl RestoreSnapshotRequest {
    /// Read the body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let any = StrRules::any();
        let repository = v.req_str(obj, at, "repository", any);
        let snapshot = v.req_str(obj, at, "snapshot", any);
        let indices = opt_str_list(v, obj, at, "indices");
        let ignore_unavailable = opt_bool_default(v, obj, at, "ignore_unavailable", true);
        let include_global_state = opt_bool_default(v, obj, at, "include_global_state", false);
        let rename_pattern = v.opt_str(obj, at, "rename_pattern", any);
        let rename_replacement = v.opt_str(obj, at, "rename_replacement", any);
        let include_aliases = opt_bool_default(v, obj, at, "include_aliases", true);
        let partial = opt_bool_default(v, obj, at, "partial", false);
        Self {
            repository,
            snapshot,
            indices,
            ignore_unavailable,
            include_global_state,
            rename_pattern,
            rename_replacement,
            include_aliases,
            partial,
        }
    }
}
