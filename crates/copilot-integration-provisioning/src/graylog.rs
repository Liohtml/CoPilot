//! The Graylog steps of the provisioning flows, on a connector (the default
//! `Graylog`, or `Graylog-Network` under `GraylogContext.NETWORK`):
//!
//! - the id lookups of `connectors/graylog/services/collector.py`
//!   (`get_stream_id_by_stream_name`, `get_input_id_by_input_name`,
//!   `get_content_pack_id_by_content_pack_name`): the first match's `id`, or
//!   `None`, a `KeyError` becoming `500 Failed to collect … ID key: …`;
//! - the index set (`build_index_set_config` +
//!   `send_index_set_creation_request`), flat;
//! - the event stream (`send_post_request_create_entity("/api/streams")`,
//!   wrapped for Graylog 7);
//! - `assign_stream_to_index`, `get_pipeline_id`,
//!   `connect_stream_to_pipeline` (`customer_provisioning/services/graylog.py`);
//! - the network connectors' content packs
//!   (`provision_content_pack_network_connector`): the templates of
//!   `copilot-provisioning`, keywords replaced, inserted and installed through
//!   its connector-aware functions.

use copilot_auth::pyvalue::PyValue;
use copilot_graylog::GraylogClient;
use copilot_graylog::client::{EntityKind, Reply};
use copilot_provisioning::graylog::{does_content_pack_exist_on, insert_and_install_on};
use copilot_provisioning::rollback::Rollback;
use copilot_provisioning::templates;
use copilot_upstream::model::{construct, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, getitem, int_of, iterate};

use crate::schema::{
    EVENT_STREAM, GRAYLOG_INDEX_SET_CREATION_RESPONSE, STREAM_CONNECTION_TO_PIPELINE_REQUEST,
    STREAM_CONNECTION_TO_PIPELINE_RESPONSE, STREAM_CREATION_RESPONSE, TIME_BASED_INDEX_SET,
};

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

/// A helper's return value as the dict Python indexes
/// (`{"data", "success", "message"}`).
pub fn reply_dict(reply: &Reply) -> PyValue {
    kwargs(vec![
        ("data", reply.data.clone()),
        ("success", PyValue::Bool(reply.success)),
        ("message", PyValue::Str(reply.message.clone())),
    ])
}

/// `get_*_id_by_*_name`: `GET endpoint`, then the first item of
/// `data[list_key]` whose `match_key` equals `name`.
async fn id_by_name(
    c: &GraylogClient,
    connector: &str,
    endpoint: &str,
    list_key: &str,
    match_key: &str,
    name: &str,
    what: &str,
) -> PyResult<PyValue> {
    let reply = c.get_on(connector, endpoint, &[]).await?;
    let wrap = |e: PyExc| match e {
        PyExc::KeyError(k) => PyExc::http(500, format!("Failed to collect {what} ID key: {k}")),
        other => other,
    };
    let found = (|| -> PyResult<PyValue> {
        for item in iterate(getitem(&reply.data, list_key)?)? {
            if getitem(&item, match_key)? == &s(name) {
                return Ok(getitem(&item, "id")?.clone());
            }
        }
        Ok(PyValue::None)
    })();
    found.map_err(wrap)
}

/// `get_stream_id_by_stream_name(name)`.
pub async fn stream_id_by_name(
    c: &GraylogClient,
    connector: &str,
    name: &str,
) -> PyResult<PyValue> {
    id_by_name(
        c,
        connector,
        "/api/streams",
        "streams",
        "title",
        name,
        "stream",
    )
    .await
}

/// `get_input_id_by_input_name(name)`.
pub async fn input_id_by_name(c: &GraylogClient, connector: &str, name: &str) -> PyResult<PyValue> {
    id_by_name(
        c,
        connector,
        "/api/system/inputs",
        "inputs",
        "title",
        name,
        "input",
    )
    .await
}

/// `get_content_pack_id_by_content_pack_name(name)`.
pub async fn content_pack_id_by_name(
    c: &GraylogClient,
    connector: &str,
    name: &str,
) -> PyResult<PyValue> {
    id_by_name(
        c,
        connector,
        "/api/system/content_packs",
        "content_packs",
        "name",
        name,
        "content pack",
    )
    .await
}

/// `datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")`.
pub fn creation_date() -> String {
    chrono::Utc::now()
        .naive_utc()
        .format("%Y-%m-%dT%H:%M:%S.%6fZ")
        .to_string()
}

/// The parts of a `TimeBasedIndexSet` the flows vary.
#[derive(Debug, Clone)]
pub struct IndexSet {
    /// `title`.
    pub title: String,
    /// `description`.
    pub description: String,
    /// `index_prefix`.
    pub index_prefix: String,
    /// `retention_strategy.max_number_of_indices`.
    pub max_indices: PyValue,
    /// `shards`.
    pub shards: PyValue,
    /// `replicas`.
    pub replicas: PyValue,
    /// `creation_date` (taken before the shard count is asked for, as the
    /// keyword arguments are evaluated in order).
    pub creation_date: String,
}

/// `TimeBasedIndexSet(...)`: daily rotation, deletion retention.
pub fn index_set_config(spec: &IndexSet) -> PyResult<PyValue> {
    construct(
        &TIME_BASED_INDEX_SET,
        &kwargs(vec![
            ("title", s(&spec.title)),
            ("description", s(&spec.description)),
            ("index_prefix", s(&spec.index_prefix)),
            (
                "rotation_strategy_class",
                s("org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy"),
            ),
            (
                "rotation_strategy",
                kwargs(vec![
                    (
                        "type",
                        s(
                            "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig",
                        ),
                    ),
                    ("rotation_period", s("P1D")),
                    ("rotate_empty_index_set", PyValue::Bool(false)),
                    ("max_rotation_period", PyValue::None),
                ]),
            ),
            (
                "retention_strategy_class",
                s("org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy"),
            ),
            (
                "retention_strategy",
                kwargs(vec![
                    (
                        "type",
                        s(
                            "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
                        ),
                    ),
                    ("max_number_of_indices", spec.max_indices.clone()),
                ]),
            ),
            ("creation_date", s(&spec.creation_date)),
            ("index_analyzer", s("standard")),
            ("shards", spec.shards.clone()),
            ("replicas", spec.replicas.clone()),
            (
                "index_optimization_max_num_segments",
                PyValue::Int("1".into()),
            ),
            ("index_optimization_disabled", PyValue::Bool(false)),
            ("writable", PyValue::Bool(true)),
            ("field_type_refresh_interval", PyValue::Int("5000".into())),
        ]),
    )
}

/// `send_index_set_creation_request(index_set)`: `data.id` of
/// `GraylogIndexSetCreationResponse(**response_json)`.
pub async fn create_index_set(
    c: &GraylogClient,
    connector: &str,
    index_set: PyValue,
) -> PyResult<PyValue> {
    let reply = c
        .post_on(connector, "/api/system/indices/index_sets", Some(index_set))
        .await?;
    let response = construct(&GRAYLOG_INDEX_SET_CREATION_RESPONSE, &reply_dict(&reply))?;
    Ok(field(field(&response, "data"), "id").clone())
}

/// The event stream of an integration: `{title, description, index_set_id,
/// rules, matching_type: AND, remove_matches_from_default_stream: true,
/// content_pack: None}`.
pub fn event_stream_config(
    title: &str,
    description: &str,
    index_set_id: &PyValue,
    rules: Vec<(&str, String)>,
) -> PyResult<PyValue> {
    event_stream_config_matching(title, description, index_set_id, rules, "AND")
}

/// [`event_stream_config`] with its `matching_type` (the customer's Wazuh
/// stream matches either rule: `OR`).
pub fn event_stream_config_matching(
    title: &str,
    description: &str,
    index_set_id: &PyValue,
    rules: Vec<(&str, String)>,
    matching_type: &str,
) -> PyResult<PyValue> {
    let rules = rules
        .into_iter()
        .map(|(f, v)| {
            kwargs(vec![
                ("field", s(f)),
                ("type", PyValue::Int("1".into())),
                ("inverted", PyValue::Bool(false)),
                ("value", PyValue::Str(v)),
            ])
        })
        .collect();
    construct(
        &EVENT_STREAM,
        &kwargs(vec![
            ("title", s(title)),
            ("description", s(description)),
            ("index_set_id", index_set_id.clone()),
            ("rules", PyValue::List(rules)),
            ("matching_type", s(matching_type)),
            ("remove_matches_from_default_stream", PyValue::Bool(true)),
            ("content_pack", PyValue::None),
        ]),
    )
}

/// `send_event_stream_creation_request(stream)`: `data.stream_id` of
/// `StreamCreationResponse(**response_json)`.
pub async fn create_event_stream(
    c: &GraylogClient,
    connector: &str,
    stream: PyValue,
) -> PyResult<PyValue> {
    let reply = c
        .create_entity(connector, &EntityKind::Stream, stream, None)
        .await?;
    let response = construct(&STREAM_CREATION_RESPONSE, &reply_dict(&reply))?;
    Ok(field(field(&response, "data"), "stream_id").clone())
}

/// `assign_stream_to_index(stream_id, index_id)`.
pub async fn assign_stream_to_index(
    c: &GraylogClient,
    connector: &str,
    stream_id: &PyValue,
    index_id: &PyValue,
) -> PyResult<()> {
    let reply = c
        .put_on(
            connector,
            &format!("/api/streams/{}", stream_id.py_str()),
            Some(kwargs(vec![("index_set_id", index_id.clone())])),
        )
        .await?;
    match reply {
        // `send_put_request` returned `None`: `None["success"]`.
        None => Err(PyExc::TypeError(
            "'NoneType' object is not subscriptable".into(),
        )),
        Some(r) if r.success => Ok(()),
        Some(_) => Err(PyExc::http(
            500,
            format!(
                "Failed to assign stream {} to index {}",
                stream_id.py_str(),
                index_id.py_str()
            ),
        )),
    }
}

/// `get_pipeline_id(subscription)`: `[id]` of the first pipeline whose
/// description holds the subscription, case-insensitively.
pub async fn pipeline_id(
    c: &GraylogClient,
    connector: &str,
    subscription: &str,
) -> PyResult<PyValue> {
    let response = copilot_graylog::services::pipelines_on(c, connector).await?;
    let needle = subscription.to_lowercase();
    if let PyValue::List(pipelines) = field(&response, "pipelines") {
        for pipeline in pipelines {
            let description = match field(pipeline, "description") {
                PyValue::Str(d) => d.to_lowercase(),
                _ => {
                    return Err(PyExc::AttributeError(
                        "'NoneType' object has no attribute 'lower'".into(),
                    ));
                }
            };
            if description.contains(&needle) {
                return Ok(PyValue::List(vec![field(pipeline, "id").clone()]));
            }
        }
    }
    Err(PyExc::http(
        500,
        format!(
            "Failed to get pipeline ID for subscription {subscription}. Please ensure you have \
             installed the SOCFortress Wazuh Content Pack. See more at: \
             https://youtu.be/euFrHP0VkD8?si=ajqjNobHvBjrTzAH"
        ),
    ))
}

/// `connect_stream_to_pipeline(StreamConnectionToPipelineRequest(...))`.
pub async fn connect_stream_to_pipeline(
    c: &GraylogClient,
    connector: &str,
    stream_id: &PyValue,
    pipeline_ids: &PyValue,
) -> PyResult<()> {
    let request = construct(
        &STREAM_CONNECTION_TO_PIPELINE_REQUEST,
        &kwargs(vec![
            ("stream_id", stream_id.clone()),
            ("pipeline_ids", pipeline_ids.clone()),
        ]),
    )?;
    let reply = c
        .post_on(
            connector,
            "/api/system/pipelines/connections/to_stream",
            Some(request),
        )
        .await?;
    construct(&STREAM_CONNECTION_TO_PIPELINE_RESPONSE, &reply_dict(&reply))?;
    Ok(())
}

// --- network connectors' content packs ------------------------------------

/// `ContentPackKeywords` as the network flows fill it.
#[derive(Debug, Clone)]
pub struct Keywords {
    /// `customer_name`.
    pub customer_name: String,
    /// `customer_code`.
    pub customer_code: String,
    /// `protocol_type` (`TCP` / `UDP` for Fortinet, else `None`).
    pub protocol_type: Option<&'static str>,
    /// `syslog_port` (an `int`'s text).
    pub syslog_port: String,
    /// `tls_cert_file`.
    pub tls_cert_file: Option<String>,
    /// `tls_key_file`.
    pub tls_key_file: Option<String>,
}

/// `retrieve_valid_content_packs(name)` then `filter_content_packs(…,
/// protocol)`: the `AvailableContentPacks` members naming `name`, in
/// declaration order, without the other protocol's input.
pub fn network_content_packs(name: &str, protocol: Option<&str>) -> Vec<&'static str> {
    templates::GRAYLOG
        .iter()
        .map(|(member, _)| *member)
        .filter(|member| member.contains(name))
        .filter(|member| match protocol {
            Some("TCP") => !member.contains("UDP"),
            Some("UDP") => !member.contains("TCP"),
            _ => true,
        })
        .collect()
}

/// `replace_keywords_in_json_complex(data, replacements)`: every string
/// value (never a key) has each keyword replaced in turn by `str(value)`.
pub fn replace_keywords(data: &PyValue, replacements: &[(&str, String)]) -> PyValue {
    match data {
        PyValue::Dict(items) => PyValue::Dict(
            items
                .iter()
                .map(|(k, v)| (k.clone(), replace_keywords(v, replacements)))
                .collect(),
        ),
        PyValue::List(items) => PyValue::List(
            items
                .iter()
                .map(|v| replace_keywords(v, replacements))
                .collect(),
        ),
        PyValue::Str(text) => {
            let mut text = text.clone();
            for (key, value) in replacements {
                text = text.replace(key, value);
            }
            PyValue::Str(text)
        }
        other => other.clone(),
    }
}

/// `convert_port_value_to_int(data)`: a `"port": {"@value": "<str>"}` takes
/// `int()` of it where `int()` accepts it.
pub fn convert_port_value_to_int(data: &mut PyValue) {
    match data {
        PyValue::Dict(items) => {
            for (key, value) in items.iter_mut() {
                let port = key == "port"
                    && matches!(value, PyValue::Dict(inner)
                        if inner.iter().any(|(k, v)| k == "@value" && matches!(v, PyValue::Str(_))));
                if port {
                    if let PyValue::Dict(inner) = value {
                        for (k, v) in inner.iter_mut() {
                            if k == "@value" {
                                if let Ok(n) = int_of(v) {
                                    *v = PyValue::Int(n);
                                }
                                break;
                            }
                        }
                    }
                } else {
                    convert_port_value_to_int(value);
                }
            }
        }
        PyValue::List(items) => {
            for item in items {
                convert_port_value_to_int(item);
            }
        }
        _ => {}
    }
}

/// `ReplaceContentPackKeywords(...).model_dump()` as `str()` values, in
/// declaration order, with two fresh `uuid4()`s.
pub fn replacements(keywords: &Keywords) -> Vec<(&'static str, String)> {
    replacements_with(
        keywords,
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    )
}

/// [`replacements`] with the two UUIDs given.
pub fn replacements_with(
    keywords: &Keywords,
    uuid_global: String,
    uuid_specific: String,
) -> Vec<(&'static str, String)> {
    let none = || "None".to_string();
    vec![
        ("REPLACE_UUID_GLOBAL", uuid_global),
        ("REPLACE_UUID_SPECIFIC", uuid_specific),
        ("customer_name", keywords.customer_name.clone()),
        ("customer_code", keywords.customer_code.clone()),
        ("SYSLOG_PORT", keywords.syslog_port.clone()),
        (
            "TLS_CERT_FILE",
            keywords.tls_cert_file.clone().unwrap_or_else(none),
        ),
        (
            "TLS_KEY_FILE",
            keywords.tls_key_file.clone().unwrap_or_else(none),
        ),
    ]
}

/// `render_content_pack(template, replacements)`: the template with its
/// keywords replaced and its port turned into an `int`.
pub fn render_content_pack(template: &PyValue, replacements: &[(&str, String)]) -> PyValue {
    // `"PROCESSING_PIPELINE" not in content_pack` tests the dict's keys: true
    // for every template, so every pack is rendered.
    let mut pack = replace_keywords(template, replacements);
    convert_port_value_to_int(&mut pack);
    pack
}

/// `provision_content_pack_network_connector(request)`: each pack is
/// skipped when a content pack named after the *customer* exists (a 400 when
/// it is not a processing pipeline), else rendered, inserted and — when
/// Graylog took it — installed.
///
/// Each pack this run inserts is registered in `rollback` (its installation
/// with it); the answer is whether the stream pack was among them — the
/// stream it made is then this run's too.
pub async fn provision_network_content_packs(
    c: &GraylogClient,
    connector: &'static str,
    name: &str,
    keywords: &Keywords,
    rollback: &mut Rollback,
) -> PyResult<bool> {
    let mut stream_pack_installed = false;
    for member in network_content_packs(name, keywords.protocol_type) {
        if does_content_pack_exist_on(c, connector, &keywords.customer_name).await? {
            continue;
        }
        let template = templates::content_pack(member)
            .ok_or_else(|| PyExc::http(404, "Content pack JSON file not found"))?;
        let pack = render_content_pack(&template, &replacements(keywords));
        let before = rollback.descriptions().len();
        insert_and_install_on(c, connector, &pack, false, rollback).await?;
        if member.ends_with("_STREAM") && rollback.descriptions().len() > before {
            stream_pack_installed = true;
        }
    }
    Ok(stream_pack_installed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn packs_follow_the_enum_and_the_protocol() {
        assert_eq!(
            network_content_packs("FORTINET", Some("TCP")),
            vec![
                "SOCFORTRESS_FORTINET_INPUT_SYSLOG_TCP",
                "SOCFORTRESS_FORTINET_PROCESSING_PIPELINE",
                "SOCFORTRESS_FORTINET_STREAM",
            ]
        );
        assert_eq!(
            network_content_packs("FORTINET", Some("UDP")),
            vec![
                "SOCFORTRESS_FORTINET_INPUT_SYSLOG_UDP",
                "SOCFORTRESS_FORTINET_PROCESSING_PIPELINE",
                "SOCFORTRESS_FORTINET_STREAM",
            ]
        );
        assert_eq!(network_content_packs("SONICWALL", None).len(), 3);
        assert!(network_content_packs("SENTINELONE", None).is_empty());
    }

    #[test]
    fn keywords_are_replaced_in_values_in_turn() {
        let data = loads(
            r#"{"customer_name": ["customer_name x", {"port": {"@value": "SYSLOG_PORT"}}],
                "n": 1, "port": {"@value": "abc"}}"#,
        )
        .unwrap();
        let replacements = vec![
            ("customer_name", "A customer_code".to_string()),
            ("customer_code", "C1".to_string()),
            ("SYSLOG_PORT", "0514".to_string()),
        ];
        let out = render_content_pack(&data, &replacements);
        assert_eq!(
            out.py_repr(),
            "{'customer_name': ['A C1 x', {'port': {'@value': 514}}], 'n': 1, \
             'port': {'@value': 'abc'}}"
        );
    }
}
