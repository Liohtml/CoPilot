//! The Pydantic models the provisioning flows build and read, as
//! [`copilot_upstream::model`] statics: `customer_provisioning/schema/
//! {graylog,grafana}.py` (index sets, streams, pipeline connections, the
//! OpenSearch datasource, folders, node versions) and the request models of
//! `stack_provisioning/graylog/schema/{fortinet,sonicwall,sentinelone}.py`.
//! Pinned by `integration_provisioning_vectors.json`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

fn f() -> PyValue {
    PyValue::Bool(false)
}

fn t() -> PyValue {
    PyValue::Bool(true)
}

fn five() -> PyValue {
    PyValue::Int("5".into())
}

/// `GrafanaJsonData.dataLinks`' default.
fn data_links() -> PyValue {
    PyValue::List(vec![PyValue::Dict(vec![
        (
            "field".into(),
            PyValue::Str("^data_vulnerability_cve$".into()),
        ),
        (
            "url".into(),
            PyValue::Str("https://nvd.nist.gov/vuln/detail".into()),
        ),
    ])])
}

// --- index sets ---------------------------------------------------------

/// `TimeBasedRotationStrategyConfig`.
pub static TIME_BASED_ROTATION: Model = Model::new(
    "TimeBasedRotationStrategyConfig",
    &[
        Field::req("type", Ty::Str),
        Field::opt("rotation_period", Ty::Nullable(&Ty::Str)),
    ],
);

/// `TimeBasedRetentionStrategyConfig`.
pub static TIME_BASED_RETENTION: Model = Model::new(
    "TimeBasedRetentionStrategyConfig",
    &[
        Field::req("type", Ty::Str),
        Field::opt("max_number_of_indices", Ty::Nullable(&Ty::Int)),
    ],
);

/// `TimeBasedIndexSet` (the body of `POST /api/system/indices/index_sets`).
pub static TIME_BASED_INDEX_SET: Model = Model::new(
    "TimeBasedIndexSet",
    &[
        Field::req("title", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("index_prefix", Ty::Str),
        Field::req("rotation_strategy_class", Ty::Str),
        Field::req("rotation_strategy", Ty::Model(&TIME_BASED_ROTATION)),
        Field::req("retention_strategy_class", Ty::Str),
        Field::req("retention_strategy", Ty::Model(&TIME_BASED_RETENTION)),
        Field::req("creation_date", Ty::Str),
        Field::req("index_analyzer", Ty::Str),
        Field::req("shards", Ty::Int),
        Field::req("replicas", Ty::Int),
        Field::req("index_optimization_max_num_segments", Ty::Int),
        Field::req("index_optimization_disabled", Ty::Bool),
        Field::req("writable", Ty::Bool),
        Field::req("field_type_refresh_interval", Ty::Int),
    ],
);

/// `RotationStrategyConfig` (Graylog's answer).
pub static ROTATION_STRATEGY_CONFIG: Model = Model::new(
    "RotationStrategyConfig",
    &[
        Field::req("type", Ty::Str),
        Field::req("rotation_period", Ty::Str),
        Field::opt("max_rotation_period", Ty::Nullable(&Ty::Str)),
        Field::opt("rotate_empty_index_set", Ty::Nullable(&Ty::Bool)),
    ],
);

/// `RetentionStrategyConfig` (Graylog's answer).
pub static RETENTION_STRATEGY_CONFIG: Model = Model::new(
    "RetentionStrategyConfig",
    &[
        Field::req("type", Ty::Str),
        Field::req("max_number_of_indices", Ty::Int),
    ],
);

/// `GraylogIndexSetData`.
pub static GRAYLOG_INDEX_SET_DATA: Model = Model::new(
    "GraylogIndexSetData",
    &[
        Field::req("id", Ty::Str),
        Field::req("title", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("can_be_default", Ty::Bool),
        Field::req("index_prefix", Ty::Str),
        Field::req("shards", Ty::Int),
        Field::req("replicas", Ty::Int),
        Field::req("rotation_strategy_class", Ty::Str),
        Field::req("rotation_strategy", Ty::Model(&ROTATION_STRATEGY_CONFIG)),
        Field::req("retention_strategy_class", Ty::Str),
        Field::req("retention_strategy", Ty::Model(&RETENTION_STRATEGY_CONFIG)),
        Field::req("creation_date", Ty::Str),
        Field::req("index_analyzer", Ty::Str),
        Field::req("index_optimization_max_num_segments", Ty::Int),
        Field::req("index_optimization_disabled", Ty::Bool),
        Field::req("field_type_refresh_interval", Ty::Int),
        Field::opt("index_template_type", Ty::Nullable(&Ty::Str)),
        Field::req("default", Ty::Bool),
        Field::req("writable", Ty::Bool),
    ],
);

/// `GraylogIndexSetCreationResponse`.
pub static GRAYLOG_INDEX_SET_CREATION_RESPONSE: Model = Model::new(
    "GraylogIndexSetCreationResponse",
    &[
        Field::req("data", Ty::Model(&GRAYLOG_INDEX_SET_DATA)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

// --- streams --------------------------------------------------------------

/// `StreamRule`.
pub static STREAM_RULE: Model = Model::new(
    "StreamRule",
    &[
        Field::req("field", Ty::Str),
        Field::req("type", Ty::Int),
        Field::req("inverted", Ty::Bool),
        Field::req("value", Ty::Str),
    ],
);

/// The integrations' `<Name>EventStream` (one shape, eleven names).
pub static EVENT_STREAM: Model = Model::new(
    "EventStream",
    &[
        Field::req("title", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("index_set_id", Ty::Str),
        Field::req("rules", Ty::List(&Ty::Model(&STREAM_RULE))),
        Field::req("matching_type", Ty::Str),
        Field::req("remove_matches_from_default_stream", Ty::Bool),
        Field::opt("content_pack", Ty::Nullable(&Ty::Str)),
    ],
);

/// `StreamData`.
pub static STREAM_DATA: Model = Model::new("StreamData", &[Field::req("stream_id", Ty::Str)]);

/// `StreamCreationResponse`.
pub static STREAM_CREATION_RESPONSE: Model = Model::new(
    "StreamCreationResponse",
    &[
        Field::req("data", Ty::Model(&STREAM_DATA)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

/// `StreamConnectionToPipelineRequest`.
pub static STREAM_CONNECTION_TO_PIPELINE_REQUEST: Model = Model::new(
    "StreamConnectionToPipelineRequest",
    &[
        Field::req("stream_id", Ty::Str),
        Field::req("pipeline_ids", Ty::List(&Ty::Str)),
    ],
);

/// `StreamAndPipelineData`.
pub static STREAM_AND_PIPELINE_DATA: Model = Model::new(
    "StreamAndPipelineData",
    &[
        Field::req("stream_id", Ty::Str),
        Field::req("pipeline_ids", Ty::List(&Ty::Str)),
    ],
);

/// `StreamConnectionToPipelineResponse`.
pub static STREAM_CONNECTION_TO_PIPELINE_RESPONSE: Model = Model::new(
    "StreamConnectionToPipelineResponse",
    &[
        Field::req("data", Ty::Model(&STREAM_AND_PIPELINE_DATA)),
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
    ],
);

// --- Grafana ----------------------------------------------------------------

/// `GrafanaSecureJsonData`.
pub static GRAFANA_SECURE_JSON_DATA: Model = Model::new(
    "GrafanaSecureJsonData",
    &[Field::req("basicAuthPassword", Ty::Str)],
);

/// `GrafanaJsonData`.
pub static GRAFANA_JSON_DATA: Model = Model::new(
    "GrafanaJsonData",
    &[
        Field::req("database", Ty::Str),
        Field::req("flavor", Ty::Str),
        Field::req("version", Ty::Str),
        Field::def("includeFrozen", Ty::Bool, f),
        Field::req("logLevelField", Ty::Str),
        Field::req("logMessageField", Ty::Str),
        Field::def("maxConcurrentShardRequests", Ty::Int, five),
        Field::req("timeField", Ty::Str),
        Field::def("tlsSkipVerify", Ty::Bool, t),
        Field::def("dataLinks", Ty::List(&Ty::Any), data_links),
    ],
);

/// `GrafanaDatasource` (the body of `POST /datasources`).
pub static GRAFANA_DATASOURCE: Model = Model::new(
    "GrafanaDatasource",
    &[
        Field::req("name", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("typeName", Ty::Str),
        Field::req("access", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("database", Ty::Str),
        Field::def("basicAuth", Ty::Bool, t),
        Field::req("basicAuthUser", Ty::Str),
        Field::req("secureJsonData", Ty::Model(&GRAFANA_SECURE_JSON_DATA)),
        Field::def("isDefault", Ty::Bool, f),
        Field::req("jsonData", Ty::Model(&GRAFANA_JSON_DATA)),
        Field::def("readOnly", Ty::Bool, t),
    ],
);

/// `DataSourceCreationJsonData`.
pub static DATASOURCE_CREATION_JSON_DATA: Model = Model::new(
    "DataSourceCreationJsonData",
    &[
        Field::req("database", Ty::Str),
        Field::req("flavor", Ty::Str),
        Field::req("includeFrozen", Ty::Bool),
        Field::req("logLevelField", Ty::Str),
        Field::req("logMessageField", Ty::Str),
        Field::req("maxConcurrentShardRequests", Ty::Int),
        Field::req("timeField", Ty::Str),
        Field::req("tlsSkipVerify", Ty::Bool),
        Field::req("version", Ty::Str),
    ],
);

/// `DataSourceCreationSecureJsonFields`.
pub static DATASOURCE_CREATION_SECURE_JSON_FIELDS: Model = Model::new(
    "DataSourceCreationSecureJsonFields",
    &[Field::req("basicAuthPassword", Ty::Bool)],
);

/// `DataSourceCreationDatasource`.
pub static DATASOURCE_CREATION_DATASOURCE: Model = Model::new(
    "DataSourceCreationDatasource",
    &[
        Field::req("id", Ty::Int),
        Field::req("uid", Ty::Str),
        Field::req("orgId", Ty::Int),
        Field::req("name", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("typeLogoUrl", Ty::Str),
        Field::req("access", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("user", Ty::Str),
        Field::req("database", Ty::Str),
        Field::req("basicAuth", Ty::Bool),
        Field::req("basicAuthUser", Ty::Str),
        Field::req("withCredentials", Ty::Bool),
        Field::req("isDefault", Ty::Bool),
        Field::req("jsonData", Ty::Model(&DATASOURCE_CREATION_JSON_DATA)),
        Field::req(
            "secureJsonFields",
            Ty::Model(&DATASOURCE_CREATION_SECURE_JSON_FIELDS),
        ),
        Field::req("version", Ty::Int),
        Field::req("readOnly", Ty::Bool),
    ],
);

/// `GrafanaDataSourceCreationResponse`.
pub static GRAFANA_DATASOURCE_CREATION_RESPONSE: Model = Model::new(
    "GrafanaDataSourceCreationResponse",
    &[
        Field::req("datasource", Ty::Model(&DATASOURCE_CREATION_DATASOURCE)),
        Field::req("id", Ty::Int),
        Field::req("message", Ty::Str),
        Field::req("name", Ty::Str),
    ],
);

/// `GrafanaFolderCreationResponse`.
pub static GRAFANA_FOLDER_CREATION_RESPONSE: Model = Model::new(
    "GrafanaFolderCreationResponse",
    &[
        Field::req("id", Ty::Int),
        Field::req("uid", Ty::Str),
        Field::req("title", Ty::Str),
        Field::req("url", Ty::Str),
        Field::req("hasAcl", Ty::Bool),
        Field::req("canSave", Ty::Bool),
        Field::req("canEdit", Ty::Bool),
        Field::req("canAdmin", Ty::Bool),
        Field::req("canDelete", Ty::Bool),
        Field::req("createdBy", Ty::Str),
        Field::req("created", Ty::DateTime),
        Field::req("updatedBy", Ty::Str),
        Field::req("updated", Ty::DateTime),
        Field::req("version", Ty::Int),
    ],
);

/// `NodeInfo`.
pub static NODE_INFO: Model = Model::new("NodeInfo", &[Field::req("version", Ty::Str)]);

/// `NodesVersionResponse`.
pub static NODES_VERSION_RESPONSE: Model = Model::new(
    "NodesVersionResponse",
    &[Field::req("nodes", Ty::Dict(&Ty::Model(&NODE_INFO)))],
);

/// Module paths of the models built with `Model(**answer)`, for the
/// `TypeError` a non-mapping answer raises.
pub mod qualname {
    /// `GrafanaDataSourceCreationResponse`.
    pub const DATASOURCE_RESPONSE: &str =
        "app.customer_provisioning.schema.grafana.GrafanaDataSourceCreationResponse";
    /// `GrafanaFolderCreationResponse`.
    pub const FOLDER_RESPONSE: &str =
        "app.customer_provisioning.schema.grafana.GrafanaFolderCreationResponse";
    /// `NodesVersionResponse`.
    pub const NODES_VERSION: &str = "app.customer_provisioning.schema.grafana.NodesVersionResponse";
}

// --- network-connector requests ------------------------------------------

fn fortinet() -> PyValue {
    PyValue::Str("Fortinet".into())
}

fn sonicwall() -> PyValue {
    PyValue::Str("Sonicwall".into())
}

fn sentinelone() -> PyValue {
    PyValue::Str("Sentinelone".into())
}

/// `ProvisionFortinetRequest`.
pub static PROVISION_FORTINET_REQUEST: Model = Model::new(
    "ProvisionFortinetRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, fortinet),
        Field::def("tcp_enabled", Ty::Nullable(&Ty::Bool), f),
        Field::def("udp_enabled", Ty::Nullable(&Ty::Bool), f),
        Field::req("hot_data_retention", Ty::Int),
        Field::req("index_replicas", Ty::Int),
    ],
);

/// `ProvisionSonicwallRequest`.
pub static PROVISION_SONICWALL_REQUEST: Model = Model::new(
    "ProvisionSonicwallRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, sonicwall),
        Field::def("tls_enabled", Ty::Nullable(&Ty::Bool), f),
        Field::req("hot_data_retention", Ty::Int),
        Field::req("index_replicas", Ty::Int),
    ],
);

/// `ProvisionSentinelOneRequest`.
pub static PROVISION_SENTINELONE_REQUEST: Model = Model::new(
    "ProvisionSentinelOneRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, sentinelone),
        Field::def("tls_enabled", Ty::Nullable(&Ty::Bool), t),
        Field::req("hot_data_retention", Ty::Int),
        Field::req("index_replicas", Ty::Int),
    ],
);

/// Every model, by name, for the vectors.
pub fn registry() -> Vec<(&'static str, &'static Model)> {
    vec![
        ("TimeBasedIndexSet", &TIME_BASED_INDEX_SET),
        (
            "GraylogIndexSetCreationResponse",
            &GRAYLOG_INDEX_SET_CREATION_RESPONSE,
        ),
        ("StreamCreationResponse", &STREAM_CREATION_RESPONSE),
        (
            "StreamConnectionToPipelineRequest",
            &STREAM_CONNECTION_TO_PIPELINE_REQUEST,
        ),
        (
            "StreamConnectionToPipelineResponse",
            &STREAM_CONNECTION_TO_PIPELINE_RESPONSE,
        ),
        ("GrafanaDatasource", &GRAFANA_DATASOURCE),
        (
            "GrafanaDataSourceCreationResponse",
            &GRAFANA_DATASOURCE_CREATION_RESPONSE,
        ),
        (
            "GrafanaFolderCreationResponse",
            &GRAFANA_FOLDER_CREATION_RESPONSE,
        ),
        ("NodesVersionResponse", &NODES_VERSION_RESPONSE),
        ("ProvisionFortinetRequest", &PROVISION_FORTINET_REQUEST),
        ("ProvisionSonicwallRequest", &PROVISION_SONICWALL_REQUEST),
        (
            "ProvisionSentinelOneRequest",
            &PROVISION_SENTINELONE_REQUEST,
        ),
    ]
}
