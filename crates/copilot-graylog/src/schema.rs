//! The Pydantic models of `app/connectors/graylog/schema/` (and the Event
//! Shipper payload), field by field: types, defaults, aliases, validators.
//! `model_vectors.json` pins them against the Python classes.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

// --- collector.py --------------------------------------------------------

/// `Document`.
pub static DOCUMENT: Model = Model::new(
    "Document",
    &[Field::req("count", Ty::Int), Field::req("deleted", Ty::Int)],
);

/// `Operation`.
pub static OPERATION: Model = Model::new(
    "Operation",
    &[
        Field::req("time_seconds", Ty::Int),
        Field::req("total", Ty::Int),
    ],
);

/// `ShardInfo`.
pub static SHARD_INFO: Model = Model::new(
    "ShardInfo",
    &[
        Field::req("documents", Ty::Model(&DOCUMENT)),
        Field::req("flush", Ty::Model(&OPERATION)),
        Field::req("get", Ty::Model(&OPERATION)),
        Field::req("index", Ty::Model(&OPERATION)),
        Field::req("merge", Ty::Model(&OPERATION)),
        Field::req("open_search_contexts", Ty::Int),
        Field::req("refresh", Ty::Model(&OPERATION)),
        Field::req("search_fetch", Ty::Model(&OPERATION)),
        Field::req("search_query", Ty::Model(&OPERATION)),
        Field::req("segments", Ty::Int),
        Field::req("store_size_bytes", Ty::Int),
    ],
);

/// `Routing`.
pub static ROUTING: Model = Model::new(
    "Routing",
    &[
        Field::req("active", Ty::Bool),
        Field::req("id", Ty::Int),
        Field::req("node_hostname", Ty::Str),
        Field::req("node_id", Ty::Str),
        Field::req("node_name", Ty::Str),
        Field::req("primary", Ty::Bool),
        Field::opt("relocating_to", Ty::Nullable(&Ty::Str)),
        Field::req("state", Ty::Str),
    ],
);

/// `IndexInfo`.
pub static INDEX_INFO: Model = Model::new(
    "IndexInfo",
    &[
        Field::req("all_shards", Ty::Model(&SHARD_INFO)),
        Field::req("primary_shards", Ty::Model(&SHARD_INFO)),
        Field::opt("reopened", Ty::Nullable(&Ty::Bool)),
        Field::req("routing", Ty::List(&Ty::Model(&ROUTING))),
    ],
);

/// `GraylogIndexItem`.
pub static GRAYLOG_INDEX_ITEM: Model = Model::new(
    "GraylogIndexItem",
    &[
        Field::req("index_name", Ty::Str),
        Field::req("index_info", Ty::Model(&INDEX_INFO)),
    ],
);

/// `GraylogIndicesResponse`.
pub static GRAYLOG_INDICES_RESPONSE: Model = Model::new(
    "GraylogIndicesResponse",
    &[
        Field::req("indices", Ty::List(&Ty::Model(&GRAYLOG_INDEX_ITEM))),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// `_normalize_encrypted_value`: Graylog 7's `{"is_set": true}` for an
/// encrypted attribute becomes `"***"` (or `None` when unset).
pub fn normalize_encrypted_value(value: &PyValue) -> PyValue {
    match value {
        PyValue::Dict(_) => {
            let set = value.get("is_set").is_some_and(PyValue::truthy);
            if set {
                PyValue::Str("***".into())
            } else {
                PyValue::None
            }
        }
        other => other.clone(),
    }
}

/// `ConfiguredInputAttributes`.
pub static CONFIGURED_INPUT_ATTRIBUTES: Model = Model::new(
    "ConfiguredInputAttributes",
    &[
        Field::req("recv_buffer_size", Ty::Int),
        Field::opt("tcp_keepalive", Ty::Nullable(&Ty::Bool)),
        Field::opt("use_null_delimiter", Ty::Nullable(&Ty::Bool)),
        Field::req("number_worker_threads", Ty::Int),
        Field::opt("tls_client_auth_cert_file", Ty::Nullable(&Ty::Str)),
        Field::opt("force_rdns", Ty::Nullable(&Ty::Bool)),
        Field::req("bind_address", Ty::Str),
        Field::opt("tls_cert_file", Ty::Nullable(&Ty::Str)),
        Field::opt("store_full_message", Ty::Nullable(&Ty::Bool)),
        Field::opt("expand_structured_data", Ty::Nullable(&Ty::Bool)),
        Field::req("port", Ty::Int),
        Field::opt("tls_key_file", Ty::Nullable(&Ty::Str)),
        Field::opt("tls_enable", Ty::Nullable(&Ty::Bool)),
        Field::opt("tls_key_password", Ty::Nullable(&Ty::Str)).before(normalize_encrypted_value),
        Field::opt("max_message_size", Ty::Nullable(&Ty::Int)),
        Field::opt("tls_client_auth", Ty::Nullable(&Ty::Str)),
        Field::opt("override_source", Ty::Nullable(&Ty::Str)),
        Field::opt("charset_name", Ty::Nullable(&Ty::Str)),
        Field::opt("allow_override_date", Ty::Nullable(&Ty::Bool)),
    ],
);

/// `ConfiguredInput`.
pub static CONFIGURED_INPUT: Model = Model::new(
    "ConfiguredInput",
    &[
        Field::req("title", Ty::Str),
        Field::req("global_field", Ty::Bool).alias("global"),
        Field::req("name", Ty::Str),
        Field::opt("content_pack", Ty::Nullable(&Ty::Str)),
        Field::req("created_at", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("creator_user_id", Ty::Str),
        Field::req("attributes", Ty::Model(&CONFIGURED_INPUT_ATTRIBUTES)),
        Field::req("static_fields", Ty::Dict(&Ty::Str)),
        Field::opt("node", Ty::Nullable(&Ty::Str)),
        Field::req("id", Ty::Str),
    ],
);

/// `MessageInputAttributes`.
pub static MESSAGE_INPUT_ATTRIBUTES: Model = Model::new(
    "MessageInputAttributes",
    &[
        Field::req("recv_buffer_size", Ty::Int),
        Field::opt("tcp_keepalive", Ty::Nullable(&Ty::Bool)),
        Field::opt("use_null_delimiter", Ty::Nullable(&Ty::Bool)),
        Field::req("number_worker_threads", Ty::Int),
        Field::opt("tls_client_auth_cert_file", Ty::Nullable(&Ty::Str)),
        Field::req("bind_address", Ty::Str),
        Field::opt("tls_cert_file", Ty::Nullable(&Ty::Str)),
        Field::req("port", Ty::Int),
        Field::opt("tls_key_file", Ty::Nullable(&Ty::Str)),
        Field::opt("tls_enable", Ty::Nullable(&Ty::Bool)),
        Field::opt("tls_key_password", Ty::Nullable(&Ty::Str)).before(normalize_encrypted_value),
        Field::opt("max_message_size", Ty::Nullable(&Ty::Int)),
        Field::opt("tls_client_auth", Ty::Nullable(&Ty::Str)),
    ],
);

/// `MessageInput`.
pub static MESSAGE_INPUT: Model = Model::new(
    "MessageInput",
    &[
        Field::req("title", Ty::Str),
        Field::req("global_field", Ty::Bool).alias("global"),
        Field::req("name", Ty::Str),
        Field::opt("content_pack", Ty::Nullable(&Ty::Str)),
        Field::req("created_at", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("creator_user_id", Ty::Str),
        Field::req("attributes", Ty::Model(&MESSAGE_INPUT_ATTRIBUTES)),
        Field::req("static_fields", Ty::Dict(&Ty::Str)),
        Field::opt("node", Ty::Nullable(&Ty::Str)),
        Field::req("id", Ty::Str),
    ],
);

/// `RunningInput`.
pub static RUNNING_INPUT: Model = Model::new(
    "RunningInput",
    &[
        Field::req("id", Ty::Str),
        Field::req("state", Ty::Str),
        Field::req("started_at", Ty::Str),
        Field::opt("detailed_message", Ty::Nullable(&Ty::Str)),
        Field::req("message_input", Ty::Model(&MESSAGE_INPUT)),
    ],
);

/// `ConfiguredInputsResponse`.
pub static CONFIGURED_INPUTS_RESPONSE: Model = Model::new(
    "ConfiguredInputsResponse",
    &[
        Field::req("configured_inputs", Ty::List(&Ty::Model(&CONFIGURED_INPUT))),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// `RunningInputsResponse`.
pub static RUNNING_INPUTS_RESPONSE: Model = Model::new(
    "RunningInputsResponse",
    &[
        Field::req("running_inputs", Ty::List(&Ty::Model(&RUNNING_INPUT))),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// `GraylogInputsResponse`.
pub static GRAYLOG_INPUTS_RESPONSE: Model = Model::new(
    "GraylogInputsResponse",
    &[
        Field::req("configured_inputs", Ty::List(&Ty::Model(&CONFIGURED_INPUT))),
        Field::req("running_inputs", Ty::List(&Ty::Model(&RUNNING_INPUT))),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

// --- events.py -----------------------------------------------------------

/// `Provider`.
pub static PROVIDER: Model = Model::new(
    "Provider",
    &[
        Field::opt("require_values", Ty::Nullable(&Ty::Bool)),
        Field::opt("template", Ty::Nullable(&Ty::Str)),
        Field::req("type", Ty::Str),
    ],
);

/// `FieldSpecItem`.
pub static FIELD_SPEC_ITEM: Model = Model::new(
    "FieldSpecItem",
    &[
        Field::req("data_type", Ty::Str),
        Field::req("providers", Ty::List(&Ty::Model(&PROVIDER))),
    ],
);

/// `ExpressionItem` (recursive).
pub static EXPRESSION_ITEM: Model = Model::new(
    "ExpressionItem",
    &[
        Field::req("expr", Ty::Str),
        Field::opt("ref", Ty::Nullable(&Ty::Str)),
        Field::opt("value", Ty::Nullable(&Ty::Int)),
        Field::opt("left", Ty::Nullable(&Ty::Model(&EXPRESSION_ITEM))),
        Field::opt("right", Ty::Nullable(&Ty::Model(&EXPRESSION_ITEM))),
    ],
);

/// `Conditions`.
pub static CONDITIONS: Model = Model::new(
    "Conditions",
    &[Field::opt(
        "expression",
        Ty::Nullable(&Ty::Union(&[Ty::Str, Ty::Model(&EXPRESSION_ITEM)])),
    )],
);

/// `SeriesItem`.
pub static SERIES_ITEM: Model = Model::new(
    "SeriesItem",
    &[
        Field::opt("type", Ty::Nullable(&Ty::Str)),
        Field::req("id", Ty::Str),
        Field::opt("field", Ty::Nullable(&Ty::Str)),
    ],
);

/// `Config`.
pub static CONFIG: Model = Model::new(
    "Config",
    &[
        Field::opt("conditions", Ty::Nullable(&Ty::Model(&CONDITIONS))),
        Field::opt("execute_every_ms", Ty::Nullable(&Ty::Int)),
        Field::opt("group_by", Ty::Nullable(&Ty::List(&Ty::Str))),
        Field::opt("query", Ty::Nullable(&Ty::Str)),
        Field::opt("query_parameters", Ty::Nullable(&Ty::List(&Ty::Str))),
        Field::opt("search_within_ms", Ty::Nullable(&Ty::Int)),
        Field::opt(
            "series",
            Ty::Nullable(&Ty::Union(&[Ty::Str, Ty::List(&Ty::Model(&SERIES_ITEM))])),
        ),
        Field::opt("streams", Ty::Nullable(&Ty::List(&Ty::Str))),
        Field::opt("type", Ty::Nullable(&Ty::Str)),
    ],
);

/// `NotificationSettings`.
pub static NOTIFICATION_SETTINGS: Model = Model::new(
    "NotificationSettings",
    &[
        Field::req("backlog_size", Ty::Int),
        Field::req("grace_period_ms", Ty::Int),
    ],
);

/// `Storage`.
pub static STORAGE: Model = Model::new(
    "Storage",
    &[
        Field::req("streams", Ty::List(&Ty::Str)),
        Field::req("type", Ty::Str),
    ],
);

/// `EventDefinition` (its `_scope` annotation is a private attribute:
/// Pydantic neither reads nor writes it).
pub static EVENT_DEFINITION: Model = Model::new(
    "EventDefinition",
    &[
        Field::req("alert", Ty::Bool),
        Field::opt("config", Ty::Nullable(&Ty::Model(&CONFIG))),
        Field::req("description", Ty::Str),
        Field::req("field_spec", Ty::Dict(&Ty::Model(&FIELD_SPEC_ITEM))),
        Field::req("id", Ty::Str),
        Field::req("key_spec", Ty::List(&Ty::Str)),
        Field::req("notification_settings", Ty::Model(&NOTIFICATION_SETTINGS)),
        Field::opt(
            "notifications",
            Ty::Nullable(&Ty::List(&Ty::Dict(&Ty::Nullable(&Ty::Str)))),
        ),
        Field::req("priority", Ty::Int),
        Field::req("storage", Ty::List(&Ty::Model(&STORAGE))),
        Field::req("title", Ty::Str),
    ],
);

/// `GraylogEventDefinitionsResponse`.
pub static GRAYLOG_EVENT_DEFINITIONS_RESPONSE: Model = Model::new(
    "GraylogEventDefinitionsResponse",
    &[
        Field::req("event_definitions", Ty::List(&Ty::Model(&EVENT_DEFINITION))),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

fn empty_str() -> PyValue {
    PyValue::Str(String::new())
}

fn one() -> PyValue {
    PyValue::Int("1".into())
}

fn hundred() -> PyValue {
    PyValue::Int("100".into())
}

fn default_filter() -> PyValue {
    PyValue::Dict(vec![
        ("alerts".into(), PyValue::Str("only".into())),
        ("event_definitions".into(), PyValue::List(Vec::new())),
    ])
}

fn default_timerange() -> PyValue {
    PyValue::Dict(vec![
        ("range".into(), PyValue::Int("86400".into())),
        ("type".into(), PyValue::Str("relative".into())),
    ])
}

/// `AlertQuery` (the body of `POST /event/alerts`).
pub static ALERT_QUERY: Model = Model::new(
    "AlertQuery",
    &[
        Field::def("query", Ty::Nullable(&Ty::Str), empty_str),
        Field::def("page", Ty::Int, one),
        Field::def("per_page", Ty::Int, hundred),
        Field::def(
            "filter",
            Ty::Nullable(&Ty::Dict(&Ty::Union(&[Ty::Str, Ty::List(&Ty::Str)]))),
            default_filter,
        ),
        Field::def(
            "timerange",
            Ty::Nullable(&Ty::Dict(&Ty::Union(&[Ty::Int, Ty::Str]))),
            default_timerange,
        ),
    ],
);

/// `SimplifiedEventDefinition`.
pub static SIMPLIFIED_EVENT_DEFINITION: Model = Model::new(
    "SimplifiedEventDefinition",
    &[
        Field::req("description", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("title", Ty::Str),
    ],
);

/// `events.Stream`.
pub static EVENT_STREAM: Model = Model::new(
    "Stream",
    &[
        Field::req("description", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("title", Ty::Str),
    ],
);

/// `Context`.
pub static CONTEXT: Model = Model::new(
    "Context",
    &[
        Field::req(
            "event_definitions",
            Ty::Dict(&Ty::Model(&SIMPLIFIED_EVENT_DEFINITION)),
        ),
        Field::req("streams", Ty::Dict(&Ty::Model(&EVENT_STREAM))),
    ],
);

/// `Event`.
pub static EVENT: Model = Model::new(
    "Event",
    &[
        Field::req("alert", Ty::Bool),
        Field::req("event_definition_id", Ty::Str),
        Field::req("event_definition_type", Ty::Str),
        Field::req("fields", Ty::Dict(&Ty::Str)),
        Field::req("group_by_fields", Ty::Dict(&Ty::Str)),
        Field::req("id", Ty::Str),
        Field::opt("key", Ty::Nullable(&Ty::Str)),
        Field::req("key_tuple", Ty::List(&Ty::Str)),
        Field::req("message", Ty::Str),
        Field::req("origin_context", Ty::Str),
        Field::req("priority", Ty::Int),
        Field::req("source", Ty::Str),
        Field::req("source_streams", Ty::List(&Ty::Str)),
        Field::req("streams", Ty::List(&Ty::Str)),
        Field::opt("timerange_end", Ty::Nullable(&Ty::Str)),
        Field::opt("timerange_start", Ty::Nullable(&Ty::Str)),
        Field::req("timestamp", Ty::Str),
        Field::req("timestamp_processing", Ty::Str),
    ],
);

/// `AlertEvent`.
pub static ALERT_EVENT: Model = Model::new(
    "AlertEvent",
    &[
        Field::req("event", Ty::Model(&EVENT)),
        Field::req("index_name", Ty::Str),
        Field::req("index_type", Ty::Str),
    ],
);

/// `Filter`.
pub static FILTER: Model = Model::new(
    "Filter",
    &[
        Field::req("alerts", Ty::Str),
        Field::req("event_definitions", Ty::List(&Ty::Str)),
    ],
);

/// `Timerange`.
pub static TIMERANGE: Model = Model::new(
    "Timerange",
    &[Field::req("range", Ty::Int), Field::req("type", Ty::Str)],
);

/// `Parameters`.
pub static PARAMETERS: Model = Model::new(
    "Parameters",
    &[
        Field::req("page", Ty::Int),
        Field::req("per_page", Ty::Int),
        Field::req("query", Ty::Str),
        Field::req("sort_by", Ty::Str),
        Field::req("sort_direction", Ty::Str),
        Field::req("timerange", Ty::Model(&TIMERANGE)),
        Field::req("filter", Ty::Model(&FILTER)),
    ],
);

/// `Alerts`.
pub static ALERTS: Model = Model::new(
    "Alerts",
    &[
        Field::req("context", Ty::Model(&CONTEXT)),
        Field::req("duration", Ty::Int),
        Field::req("events", Ty::List(&Ty::Model(&ALERT_EVENT))),
        Field::req("parameters", Ty::Model(&PARAMETERS)),
        Field::req("total_events", Ty::Int),
        Field::req("used_indices", Ty::List(&Ty::Str)),
    ],
);

/// `GraylogAlertsResponse`.
pub static GRAYLOG_ALERTS_RESPONSE: Model = Model::new(
    "GraylogAlertsResponse",
    &[
        Field::req("alerts", Ty::Model(&ALERTS)),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

// --- management.py -------------------------------------------------------

/// `DeletedIndexBody`.
pub static DELETED_INDEX_BODY: Model =
    Model::new("DeletedIndexBody", &[Field::req("index_name", Ty::Str)]);

/// `StopInputBody` (and `StartInputBody`, the same shape).
pub static INPUT_BODY: Model = Model::new("StopInputBody", &[Field::req("input_id", Ty::Str)]);

/// `StopStreamBody` (and `StartStreamBody`).
pub static STREAM_BODY: Model = Model::new("StopStreamBody", &[Field::req("stream_id", Ty::Str)]);

/// `{success, message}` answers (`DeletedIndexResponse`, `Stop…`, `Start…`).
pub static SUCCESS_MESSAGE: Model = Model::new(
    "DeletedIndexResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `UrlWhitelistEntry`.
pub static URL_WHITELIST_ENTRY: Model = Model::new(
    "UrlWhitelistEntry",
    &[
        Field::req("id", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("title", Ty::Str),
        Field::req("value", Ty::Str),
    ],
);

/// `UrlWhitelistEntries`.
pub static URL_WHITELIST_ENTRIES: Model = Model::new(
    "UrlWhitelistEntries",
    &[
        Field::req("entries", Ty::List(&Ty::Model(&URL_WHITELIST_ENTRY))),
        Field::req("disabled", Ty::Bool),
    ],
);

/// `UrlWhitelistEntryResponse`.
pub static URL_WHITELIST_ENTRY_RESPONSE: Model = Model::new(
    "UrlWhitelistEntryResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("url_whitelist_entries", Ty::Model(&URL_WHITELIST_ENTRIES)),
    ],
);

// --- monitoring.py -------------------------------------------------------

/// `GraylogMessages`.
pub static GRAYLOG_MESSAGES: Model = Model::new(
    "GraylogMessages",
    &[
        Field::req("caller", Ty::Str),
        Field::req("content", Ty::Str),
        Field::req("node_id", Ty::Str),
        Field::req("timestamp", Ty::Str),
    ],
);

/// `GraylogMessagesResponse`.
pub static GRAYLOG_MESSAGES_RESPONSE: Model = Model::new(
    "GraylogMessagesResponse",
    &[
        Field::req("graylog_messages", Ty::List(&Ty::Model(&GRAYLOG_MESSAGES))),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("total_messages", Ty::Int),
    ],
);

/// `GraylogThroughputMetrics`.
pub static GRAYLOG_THROUGHPUT_METRICS: Model = Model::new(
    "GraylogThroughputMetrics",
    &[
        Field::req("metric", Ty::Str),
        Field::req("value", Ty::Float),
    ],
);

/// The aliases of `GraylogThroughputMetricsCollection`: the metrics
/// `/metrics` reports, in that model's order.
pub const THROUGHPUT_METRIC_NAMES: &[&str] = &[
    "org.graylog2.buffers.input.usage",
    "org.graylog2.buffers.output.usage",
    "org.graylog2.buffers.process.usage",
    "org.graylog2.throughput.input.1-sec-rate",
    "org.graylog2.throughput.output.1-sec-rate",
    "org.graylog2.throughput.output",
    "org.graylog2.throughput.input",
];

/// `GraylogUncommittedJournalEntries`.
pub static GRAYLOG_UNCOMMITTED_JOURNAL_ENTRIES: Model = Model::new(
    "GraylogUncommittedJournalEntries",
    &[Field::req("uncommitted_journal_entries", Ty::Int)],
);

/// `GraylogMetricsResponse`.
pub static GRAYLOG_METRICS_RESPONSE: Model = Model::new(
    "GraylogMetricsResponse",
    &[
        Field::req(
            "throughput_metrics",
            Ty::List(&Ty::Model(&GRAYLOG_THROUGHPUT_METRICS)),
        ),
        Field::req("uncommitted_journal_entries", Ty::Int),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

/// `GraylogEventNotificationsNotification`.
pub static GRAYLOG_EVENT_NOTIFICATIONS_NOTIFICATION: Model = Model::new(
    "GraylogEventNotificationsNotification",
    &[
        Field::req("id", Ty::Str),
        Field::req("title", Ty::Str),
        Field::req("description", Ty::Str),
        Field::opt("config", Ty::Nullable(&Ty::Dict(&Ty::Any))),
    ],
);

/// `GraylogEventNotifications`.
pub static GRAYLOG_EVENT_NOTIFICATIONS: Model = Model::new(
    "GraylogEventNotifications",
    &[
        Field::req("total", Ty::Int),
        Field::req("page", Ty::Int),
        Field::req("per_page", Ty::Int),
        Field::req("count", Ty::Int),
        Field::req(
            "notifications",
            Ty::List(&Ty::Model(&GRAYLOG_EVENT_NOTIFICATIONS_NOTIFICATION)),
        ),
        Field::req("query", Ty::Str),
        Field::req("grand_total", Ty::Int),
    ],
);

/// `GraylogEventNotificationsResponse`.
pub static GRAYLOG_EVENT_NOTIFICATIONS_RESPONSE: Model = Model::new(
    "GraylogEventNotificationsResponse",
    &[
        Field::opt(
            "event_notifications",
            Ty::Nullable(&Ty::Model(&GRAYLOG_EVENT_NOTIFICATIONS)),
        ),
        Field::req("message", Ty::Str),
        Field::req("success", Ty::Bool),
    ],
);

// --- pipelines.py --------------------------------------------------------

/// `Stage`.
pub static STAGE: Model = Model::new(
    "Stage",
    &[
        Field::req("match", Ty::Str),
        Field::req("rules", Ty::List(&Ty::Str)),
        Field::req("stage", Ty::Int),
    ],
);

/// `StageWithRuleID`.
pub static STAGE_WITH_RULE_ID: Model = Model::new(
    "StageWithRuleID",
    &[
        Field::req("match", Ty::Str),
        Field::req("rules", Ty::List(&Ty::Str)),
        Field::req("stage", Ty::Int),
        Field::req("rule_ids", Ty::List(&Ty::Nullable(&Ty::Str))),
    ],
);

/// `Pipeline`.
pub static PIPELINE: Model = Model::new(
    "Pipeline",
    &[
        Field::req("created_at", Ty::Str),
        Field::opt("description", Ty::Nullable(&Ty::Str)),
        Field::opt("errors", Ty::NoneOnly),
        Field::req("id", Ty::Str),
        Field::opt("modified_at", Ty::Nullable(&Ty::Str)),
        Field::req("source", Ty::Str),
        Field::req("stages", Ty::List(&Ty::Model(&STAGE))),
        Field::req("title", Ty::Str),
    ],
);

/// `PipelineWithRuleID`.
pub static PIPELINE_WITH_RULE_ID: Model = Model::new(
    "PipelineWithRuleID",
    &[
        Field::req("created_at", Ty::Str),
        Field::opt("description", Ty::Nullable(&Ty::Str)),
        Field::opt("errors", Ty::NoneOnly),
        Field::req("id", Ty::Str),
        Field::opt("modified_at", Ty::Nullable(&Ty::Str)),
        Field::req("source", Ty::Str),
        Field::req("stages", Ty::List(&Ty::Model(&STAGE_WITH_RULE_ID))),
        Field::req("title", Ty::Str),
    ],
);

/// `GraylogPipelinesResponse`.
pub static GRAYLOG_PIPELINES_RESPONSE: Model = Model::new(
    "GraylogPipelinesResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("pipelines", Ty::List(&Ty::Model(&PIPELINE))),
        Field::req("success", Ty::Bool),
    ],
);

/// `GraylogPipelinesResponseWithRuleID`.
pub static GRAYLOG_PIPELINES_RESPONSE_WITH_RULE_ID: Model = Model::new(
    "GraylogPipelinesResponseWithRuleID",
    &[
        Field::req("message", Ty::Str),
        Field::req("pipelines", Ty::List(&Ty::Model(&PIPELINE_WITH_RULE_ID))),
        Field::req("success", Ty::Bool),
    ],
);

/// `PipelineRule`.
pub static PIPELINE_RULE: Model = Model::new(
    "PipelineRule",
    &[
        Field::req("created_at", Ty::Str),
        Field::opt("description", Ty::Nullable(&Ty::Str)),
        Field::opt("errors", Ty::NoneOnly),
        Field::req("id", Ty::Str),
        Field::opt("modified_at", Ty::Nullable(&Ty::Str)),
        Field::req("source", Ty::Str),
        Field::req("title", Ty::Str),
    ],
);

/// `PipelineRulesResponse`.
pub static PIPELINE_RULES_RESPONSE: Model = Model::new(
    "PipelineRulesResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("pipeline_rules", Ty::List(&Ty::Model(&PIPELINE_RULE))),
        Field::req("success", Ty::Bool),
    ],
);

// --- streams.py ----------------------------------------------------------

/// `Rule`.
pub static RULE: Model = Model::new(
    "Rule",
    &[
        Field::opt("description", Ty::Nullable(&Ty::Str)),
        Field::req("field", Ty::Str),
        Field::req("id", Ty::Str),
        Field::req("inverted", Ty::Bool),
        Field::req("stream_id", Ty::Str),
        Field::req("type", Ty::Int),
        Field::req("value", Ty::Str),
    ],
);

fn no_description() -> PyValue {
    PyValue::Str("No description provided".into())
}

/// `streams.Stream`.
pub static STREAM: Model = Model::new(
    "Stream",
    &[
        Field::opt("content_pack", Ty::Nullable(&Ty::Str)),
        Field::req("created_at", Ty::Str),
        Field::req("creator_user_id", Ty::Str),
        Field::def("description", Ty::Nullable(&Ty::Str), no_description),
        Field::req("disabled", Ty::Bool),
        Field::req("id", Ty::Str),
        Field::req("index_set_id", Ty::Str),
        Field::req("is_default", Ty::Bool),
        Field::req("is_editable", Ty::Bool),
        Field::req("matching_type", Ty::Str),
        Field::req("outputs", Ty::List(&Ty::Any)),
        Field::req("remove_matches_from_default_stream", Ty::Bool),
        Field::req("rules", Ty::List(&Ty::Model(&RULE))),
        Field::req("title", Ty::Str),
    ],
);

/// `GraylogStreamsResponse`.
pub static GRAYLOG_STREAMS_RESPONSE: Model = Model::new(
    "GraylogStreamsResponse",
    &[
        Field::req("message", Ty::Str),
        Field::req("streams", Ty::List(&Ty::Model(&STREAM))),
        Field::req("total", Ty::Int),
        Field::req("success", Ty::Bool),
    ],
);

// --- app/integrations/utils/schema.py ------------------------------------

/// `EventShipperPayload` (`extra="allow"`): what `/receiver` forwards.
pub static EVENT_SHIPPER_PAYLOAD: Model = Model::allowing_extra(
    "EventShipperPayload",
    &[
        Field::req("integration", Ty::Str),
        Field::req("customer_code", Ty::Str),
    ],
);

/// Every model, by the name `model_vectors.json` uses.
pub fn registry() -> Vec<(&'static str, &'static Model)> {
    vec![
        ("GraylogIndexItem", &GRAYLOG_INDEX_ITEM),
        ("GraylogIndicesResponse", &GRAYLOG_INDICES_RESPONSE),
        ("ConfiguredInput", &CONFIGURED_INPUT),
        ("RunningInput", &RUNNING_INPUT),
        ("ConfiguredInputsResponse", &CONFIGURED_INPUTS_RESPONSE),
        ("RunningInputsResponse", &RUNNING_INPUTS_RESPONSE),
        ("GraylogInputsResponse", &GRAYLOG_INPUTS_RESPONSE),
        ("EventDefinition", &EVENT_DEFINITION),
        ("AlertQuery", &ALERT_QUERY),
        ("AlertEvent", &ALERT_EVENT),
        ("Context", &CONTEXT),
        ("Parameters", &PARAMETERS),
        ("Alerts", &ALERTS),
        ("DeletedIndexBody", &DELETED_INDEX_BODY),
        ("StopInputBody", &INPUT_BODY),
        ("StopStreamBody", &STREAM_BODY),
        ("UrlWhitelistEntryResponse", &URL_WHITELIST_ENTRY_RESPONSE),
        ("GraylogMessages", &GRAYLOG_MESSAGES),
        ("GraylogMessagesResponse", &GRAYLOG_MESSAGES_RESPONSE),
        ("GraylogThroughputMetrics", &GRAYLOG_THROUGHPUT_METRICS),
        (
            "GraylogUncommittedJournalEntries",
            &GRAYLOG_UNCOMMITTED_JOURNAL_ENTRIES,
        ),
        ("GraylogMetricsResponse", &GRAYLOG_METRICS_RESPONSE),
        (
            "GraylogEventNotificationsResponse",
            &GRAYLOG_EVENT_NOTIFICATIONS_RESPONSE,
        ),
        ("Pipeline", &PIPELINE),
        ("StageWithRuleID", &STAGE_WITH_RULE_ID),
        ("PipelineWithRuleID", &PIPELINE_WITH_RULE_ID),
        ("PipelineRule", &PIPELINE_RULE),
        ("Stream", &STREAM),
        ("GraylogStreamsResponse", &GRAYLOG_STREAMS_RESPONSE),
        ("EventShipperPayload", &EVENT_SHIPPER_PAYLOAD),
    ]
}

#[cfg(test)]
mod vectors {
    //! `model_vectors.json`: every model against pydantic, on samples of
    //! Graylog 6.1 and 7.0 answers and their mutations
    //! (`scripts/gen-connector-model-vectors.py`).

    use super::*;
    use copilot_auth::pyvalue::loads;
    use copilot_upstream::json::pydantic_json;
    use copilot_upstream::model::{Invalid, format_validation_error, validate};
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    fn patch(base: &PyValue, path: &[Value], op: &str, value: Option<PyValue>) -> PyValue {
        fn walk(v: &mut PyValue, path: &[Value], op: &str, value: Option<PyValue>) {
            let (head, rest) = path.split_first().unwrap();
            match (v, head) {
                (PyValue::Dict(items), Value::String(k)) => {
                    let pos = items.iter().position(|(key, _)| key == k).unwrap();
                    if rest.is_empty() {
                        if op == "del" {
                            items.remove(pos);
                        } else {
                            items[pos].1 = value.unwrap();
                        }
                    } else {
                        walk(&mut items[pos].1, rest, op, value);
                    }
                }
                (PyValue::List(items), Value::Number(n)) => {
                    let i = usize::try_from(n.as_u64().unwrap()).unwrap();
                    if rest.is_empty() {
                        items[i] = value.unwrap();
                    } else {
                        walk(&mut items[i], rest, op, value);
                    }
                }
                other => panic!("bad path {other:?}"),
            }
        }
        let mut out = base.clone();
        walk(&mut out, path, op, value);
        out
    }

    fn run(model: &'static Model, input: &PyValue) -> Result<String, String> {
        match validate(model, input) {
            Ok(dump) => Ok(pydantic_json(&dump)),
            Err(Invalid::Errors(e)) => Err(format_validation_error(model.name, &e)),
            Err(Invalid::Abort(s, d)) => Err(format!("abort {s} {d}")),
        }
    }

    #[test]
    fn models_match_pydantic() {
        let registry = registry();
        let doc: Value = serde_json::from_str(include_str!("model_vectors.json")).unwrap();
        let bases = doc["bases"].as_array().unwrap();
        let mut inputs = Vec::new();
        let mut failures = Vec::new();
        for b in bases {
            let name = b["model"].as_str().unwrap();
            let model = registry
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("no model {name}"))
                .1;
            let input = loads(b["input"].as_str().unwrap()).unwrap();
            let got = run(model, &input);
            let want = match b.get("ok") {
                Some(ok) => Ok(ok.as_str().unwrap().to_string()),
                None => Err(b["err"].as_str().unwrap().to_string()),
            };
            if got != want {
                failures.push(format!("base {name}\n  want {want:?}\n  got  {got:?}"));
            }
            inputs.push((model, input));
        }
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() > 1000);
        for v in vectors {
            let idx = usize::try_from(v["base"].as_u64().unwrap()).unwrap();
            let (model, base) = &inputs[idx];
            let op = v["op"].as_str().unwrap();
            let value = v.get("value").map(|t| loads(t.as_str().unwrap()).unwrap());
            let input = patch(base, v["path"].as_array().unwrap(), op, value);
            let got = run(model, &input);
            let ok = match (&got, v.get("ok_sha256"), v.get("err")) {
                (Ok(text), Some(sha), _) => {
                    hex::encode(Sha256::digest(text.as_bytes())) == sha.as_str().unwrap()
                }
                (Err(text), _, Some(err)) => text == err.as_str().unwrap(),
                _ => false,
            };
            if !ok {
                failures.push(format!(
                    "{} {:?} {op} {:?}\n  want {:?}\n  got  {got:?}",
                    model.name,
                    v["path"],
                    v.get("value"),
                    v.get("err")
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} vectors differ:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
