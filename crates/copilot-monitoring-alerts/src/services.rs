//! Port of `app/integrations/monitoring_alert/services/provision.py` (the
//! provisioning functions and `provision_alert_definition`), the route's
//! `check_if_event_definition_exists`, and the Event Shipper test.
//!
//! Every Graylog call of a request goes to one connector — `Graylog`, or
//! `Graylog-Network` for the network instance — as `set_graylog_context`
//! routes them in Python: the existence check, `get_system_info`, the
//! 6.x/7.x version probe and the creation.
//!
//! `provision_alert_definition` reads the server's version (`GET
//! /api/system` into `GraylogServerInfo`) and compares it **as a string**
//! with `"5.2"`: a smaller one (`"5.1.9"`, but also `"10.0.0"`) has
//! `event_limit` deleted from the config before the dump. Then the
//! definition goes through `send_post_request_create_entity`, wrapped in a
//! `CreateEntityRequest` for Graylog 7.

use copilot_auth::pyvalue::PyValue;
use copilot_db::connectors::ConnectorCache;
use copilot_graylog::GraylogClient;
use copilot_graylog::client::{DEFAULT_CONNECTOR, EntityKind, NETWORK_CONNECTOR};
use copilot_upstream::model::{construct, construct_star, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult};
use copilot_waf::WafState;
use copilot_waf::alerts::{self as waf_alerts, AlertError};
use copilot_web::ApiError;

use crate::catalog::{Alert, Definition, Kind};
use crate::schema::{PROVISION_CONFIG, PROVISION_MODEL};

/// `graylog_context_for_instance(instance).value`: the connector a Graylog
/// instance name (`default`, `network`) routes to.
pub fn connector_for_instance(instance: &str) -> &'static str {
    if instance == "network" {
        NETWORK_CONNECTOR
    } else {
        DEFAULT_CONNECTOR
    }
}

/// `effective_graylog_instance(alert_name, requested)` then
/// `graylog_context_for_instance`: a pinned alert (the WAF's) always goes to
/// the default Graylog.
pub fn connector_for_alert(alert: Option<&Alert>, requested: &str) -> &'static str {
    match alert {
        Some(a) if a.pinned_to_default_graylog() => DEFAULT_CONNECTOR,
        _ => connector_for_instance(requested),
    }
}

/// `check_if_event_definition_exists(title)` on `connector`: 400 when a
/// definition has that title.
pub async fn check_if_event_definition_exists(
    c: &GraylogClient,
    connector: &str,
    title: &str,
) -> PyResult<()> {
    let dump = copilot_graylog::services::event_definitions_on(c, connector).await?;
    // `GraylogEventDefinitionsResponse(**response.model_dump())` validates a
    // dump of itself again, which cannot fail.
    if let PyValue::List(definitions) = field(&dump, "event_definitions") {
        if definitions
            .iter()
            .any(|d| field(d, "title").as_str() == Some(title))
        {
            return Err(PyExc::http(
                400,
                format!("Event definition {title} already exists"),
            ));
        }
    }
    Ok(())
}

/// `get_graylog_version()`: `get_system_info().version` on `connector`.
pub async fn graylog_version(c: &GraylogClient, connector: &str) -> PyResult<String> {
    let reply = c.get_on(connector, "/api/system", &[]).await?;
    let info = construct_star(
        &copilot_provisioning::schema::GRAYLOG_SERVER_INFO,
        "app.connectors.graylog.schema.management.GraylogServerInfo",
        &reply.data,
    )?;
    Ok(field(&info, "version").py_str())
}

/// `delattr(model.config, "event_limit")` before `model_dump()`.
pub(crate) fn without_event_limit(entity: PyValue) -> PyValue {
    match entity {
        PyValue::Dict(items) => PyValue::Dict(
            items
                .into_iter()
                .map(|(k, v)| match (k.as_str(), v) {
                    ("config", PyValue::Dict(config)) => (
                        k,
                        PyValue::Dict(
                            config
                                .into_iter()
                                .filter(|(key, _)| key != "event_limit")
                                .collect(),
                        ),
                    ),
                    (_, v) => (k, v),
                })
                .collect(),
        ),
        other => other,
    }
}

/// `provision_alert_definition(model)`, `entity` being the model's dump.
pub async fn provision_alert_definition(
    c: &GraylogClient,
    connector: &str,
    entity: PyValue,
) -> PyResult<()> {
    let version = graylog_version(c, connector).await?;
    let entity = if version.as_str() < "5.2" {
        without_event_limit(entity)
    } else {
        entity
    };
    c.create_entity(connector, &EntityKind::EventDefinition, entity, None)
        .await?;
    Ok(())
}

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

fn template_field(template: &str) -> PyValue {
    kwargs(vec![
        ("data_type", s("string")),
        (
            "providers",
            PyValue::List(vec![kwargs(vec![
                ("type", s("template-v1")),
                ("template", s(template)),
                ("require_values", PyValue::Bool(true)),
            ])]),
        ),
    ])
}

/// The `GraylogAlertProvisionModel` dump a provisioning function builds:
/// `GraylogAlertProvisionConfig(...)` first (where a custom alert's `null`
/// streams fail), then the model around it.
#[allow(clippy::too_many_arguments)]
fn provision_model(
    title: PyValue,
    description: PyValue,
    priority: PyValue,
    query: PyValue,
    streams: PyValue,
    search_within_ms: PyValue,
    execute_every_ms: PyValue,
    field_spec: Vec<(&str, PyValue)>,
) -> PyResult<PyValue> {
    let config = construct(
        &PROVISION_CONFIG,
        &kwargs(vec![
            ("type", s("aggregation-v1")),
            ("query", query),
            ("query_parameters", PyValue::List(Vec::new())),
            ("streams", streams),
            ("group_by", PyValue::List(Vec::new())),
            ("series", PyValue::List(Vec::new())),
            ("conditions", kwargs(vec![("expression", PyValue::None)])),
            ("search_within_ms", search_within_ms),
            ("execute_every_ms", execute_every_ms),
            ("event_limit", PyValue::Int("1000".into())),
        ]),
    )?;
    construct(
        &PROVISION_MODEL,
        &kwargs(vec![
            ("title", title),
            ("description", description),
            ("priority", priority),
            ("config", config),
            ("field_spec", kwargs(field_spec)),
            ("key_spec", PyValue::List(Vec::new())),
            (
                "notification_settings",
                kwargs(vec![
                    ("grace_period_ms", PyValue::Int("0".into())),
                    ("backlog_size", PyValue::None),
                ]),
            ),
            ("alert", PyValue::Bool(true)),
        ]),
    )
}

/// `seconds * 1000` of a Python `int` given as its decimal text.
fn ms(seconds: &PyValue) -> PyValue {
    copilot_waf::alerts::ms_of_seconds(&seconds.py_str())
}

/// The event definition a catalog function provisions for a request's
/// window and interval (both in seconds, Python `int`s).
pub fn definition_entity(
    d: &Definition,
    search_within_last: &PyValue,
    execute_every: &PyValue,
) -> PyResult<PyValue> {
    provision_model(
        s(d.title),
        s(d.description),
        PyValue::Int(d.priority.to_string()),
        s(d.query),
        PyValue::List(Vec::new()),
        ms(search_within_last),
        ms(execute_every),
        vec![
            ("ALERT_ID", template_field("${source._id}")),
            ("CUSTOMER_CODE", template_field(d.customer_code)),
            ("ALERT_SOURCE", template_field(d.source)),
            ("COPILOT_ALERT_ID", template_field("NONE")),
        ],
    )
}

/// The event definition `provision_custom_alert` provisions for a validated
/// `CustomMonitoringAlertProvisionModel`.
pub fn custom_entity(request: &PyValue) -> PyResult<PyValue> {
    provision_model(
        field(request, "alert_name").clone(),
        field(request, "alert_description").clone(),
        field(request, "alert_priority").clone(),
        // `f"{request.search_query}"` of a `str`.
        field(request, "search_query").clone(),
        field(request, "streams").clone(),
        field(request, "search_within_ms").clone(),
        field(request, "execute_every_ms").clone(),
        vec![("COPILOT_ALERT_ID", template_field("NONE"))],
    )
}

/// Provision catalog alert `alert` for a validated
/// `ProvisionMonitoringAlertRequest` (`request`) on `connector`: the WAF's
/// two alerts through `copilot-waf`, every other one as its event
/// definition.
pub async fn provision(
    graylog: &GraylogClient,
    waf: &WafState,
    connector: &str,
    alert: &Alert,
    request: &PyValue,
) -> Result<(), ApiError> {
    let search_within_last = field(request, "search_within_last");
    let execute_every = field(request, "execute_every");
    let waf_result = match &alert.kind {
        Kind::Definition(d) => {
            let entity = definition_entity(d, search_within_last, execute_every)
                .map_err(PyExc::unhandled)?;
            return provision_alert_definition(graylog, connector, entity)
                .await
                .map_err(PyExc::unhandled);
        }
        Kind::WafBlocked => {
            waf_alerts::provision_blocked_alert(
                waf,
                &execute_every.py_str(),
                &search_within_last.py_str(),
            )
            .await
        }
        Kind::WafBruteForce => waf_alerts::provision_brute_force_alert(waf).await,
    };
    match waf_result {
        Ok(()) => Ok(()),
        Err(AlertError::Py(e)) => Err(e.unhandled()),
        Err(AlertError::Api(e)) => Err(e),
    }
}

/// The keyword arguments the testing route passes before `**request`.
pub const TESTING_FIELDS: [(&str, &str); 3] = [
    ("customer_code", "00002"),
    ("integration", "testing"),
    ("version", "1.0"),
];

/// `EventShipperPayload(customer_code="00002", integration="testing",
/// version="1.0", **request).to_dict()`: the message the testing route
/// ships, or the `TypeError` of a key passed twice.
pub fn testing_message(request: &[(String, PyValue)]) -> PyResult<PyValue> {
    if let Some((key, _)) = request
        .iter()
        .find(|(k, _)| TESTING_FIELDS.iter().any(|(name, _)| name == k))
    {
        return Err(PyExc::TypeError(format!(
            "app.integrations.utils.schema.EventShipperPayload() got multiple values for \
             keyword argument '{key}'"
        )));
    }
    let mut pairs: Vec<(String, PyValue)> = TESTING_FIELDS
        .iter()
        .map(|(k, v)| ((*k).to_string(), s(v)))
        .collect();
    pairs.extend(request.iter().cloned());
    let message = construct(
        &copilot_graylog::schema::EVENT_SHIPPER_PAYLOAD,
        &PyValue::Dict(pairs),
    )?;
    // `to_dict()`: `model_dump(exclude_none=True)`, top level only.
    Ok(match message {
        PyValue::Dict(items) => PyValue::Dict(
            items
                .into_iter()
                .filter(|(_, v)| !matches!(v, PyValue::None))
                .collect(),
        ),
        other => other,
    })
}

/// `event_shipper(message)`: one GELF frame to the `Event Shipper`.
pub async fn ship(connectors: &ConnectorCache, message: &PyValue) -> PyResult<()> {
    copilot_graylog::gelf::ship(connectors, message).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog;
    use copilot_upstream::json::{Dumps, py_dumps};

    #[test]
    fn version_strings_compare_as_python_strings() {
        for (version, dropped) in [
            ("6.1.4", false),
            ("5.2", false),
            ("5.2.0", false),
            ("5.1.9", true),
            ("5.10.0", true),
            ("10.0.0", true),
            ("7.0.1+abc", false),
            ("", true),
        ] {
            let Some(catalog::Alert {
                kind: Kind::Definition(d),
                ..
            }) = catalog::find("SURICATA_ALERT_SEVERITY_1")
            else {
                panic!("no Suricata alert")
            };
            let one = PyValue::Int("1".into());
            let entity = definition_entity(d, &one, &one).unwrap();
            let entity = if version < "5.2" {
                without_event_limit(entity)
            } else {
                entity
            };
            let text = py_dumps(&entity, Dumps::DEFAULT).unwrap();
            assert_eq!(!text.contains("event_limit"), dropped, "{version}");
        }
    }

    #[test]
    fn the_testing_payload() {
        let request = vec![
            ("a".to_string(), PyValue::None),
            ("b".to_string(), PyValue::Int("1".into())),
        ];
        let message = testing_message(&request).unwrap();
        assert_eq!(
            message.py_repr(),
            "{'integration': 'testing', 'customer_code': '00002', 'version': '1.0', 'b': 1}"
        );
        let twice = vec![("version".to_string(), s("2"))];
        assert!(matches!(
            testing_message(&twice),
            Err(PyExc::TypeError(m)) if m.ends_with("keyword argument 'version'")
        ));
    }
}
