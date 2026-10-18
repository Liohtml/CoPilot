//! The models of `app/integrations/schema.py` as
//! [`copilot_upstream::model`] statics (the request bodies), and the
//! response dumps in their field order.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

use super::REDACTED_AUTH_KEYS;
use super::REDACTED_AUTH_VALUE;
use super::store::{Catalog, CustomerIntegration, Meta, NetworkMeta, Subscription};
use crate::sql::{dict, int, opt_int_v, opt_s, s};

/// `CreateIntegrationService`.
pub static CREATE_INTEGRATION_SERVICE: Model = Model::new(
    "CreateIntegrationService",
    &[
        Field::req("auth_type", Ty::Str),
        Field::req("config_key", Ty::Str),
        Field::req("config_value", Ty::Str),
    ],
);

/// `CreateIntegrationAuthKeys`.
pub static CREATE_INTEGRATION_AUTH_KEYS: Model = Model::new(
    "CreateIntegrationAuthKeys",
    &[
        Field::req("auth_key_name", Ty::Str),
        Field::req("auth_value", Ty::Str),
    ],
);

/// `CustomerIntegrationCreate`.
pub static CUSTOMER_INTEGRATION_CREATE: Model = Model::new(
    "CustomerIntegrationCreate",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("customer_name", Ty::Str),
        Field::req("integration_name", Ty::Str),
        Field::opt("instance_name", Ty::Nullable(&Ty::Str)),
        Field::req("integration_config", Ty::Model(&CREATE_INTEGRATION_SERVICE)),
        Field::req(
            "integration_auth_keys",
            Ty::List(&Ty::Model(&CREATE_INTEGRATION_AUTH_KEYS)),
        ),
    ],
);

/// `UpdateCustomerIntegration`.
pub static UPDATE_CUSTOMER_INTEGRATION: Model = Model::new(
    "UpdateCustomerIntegration",
    &[
        Field::req("integration_name", Ty::Str),
        Field::opt("instance_name", Ty::Nullable(&Ty::Str)),
        Field::req(
            "integration_auth_keys",
            Ty::List(&Ty::Model(&CREATE_INTEGRATION_AUTH_KEYS)),
        ),
    ],
);

/// `DeleteCustomerIntegration`.
pub static DELETE_CUSTOMER_INTEGRATION: Model = Model::new(
    "DeleteCustomerIntegration",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("integration_name", Ty::Str),
        Field::opt("instance_name", Ty::Nullable(&Ty::Str)),
    ],
);

/// `coerce_external_ids_to_str`: an `int` (not a `bool`) becomes its text.
pub fn ids_to_str(v: &PyValue) -> PyValue {
    match v {
        PyValue::Int(i) => PyValue::Str(i.clone()),
        other => other.clone(),
    }
}

/// `CustomerIntegrationsMetaSchema`.
pub static CUSTOMER_INTEGRATIONS_META_SCHEMA: Model = Model::new(
    "CustomerIntegrationsMetaSchema",
    &[
        Field::opt("id", Ty::Nullable(&Ty::Int)),
        Field::req("customer_code", Ty::Str),
        Field::req("integration_name", Ty::Str),
        Field::opt("instance_name", Ty::Nullable(&Ty::Str)),
        Field::opt("graylog_input_id", Ty::Nullable(&Ty::Str)).before(ids_to_str),
        Field::req("graylog_index_id", Ty::Str).before(ids_to_str),
        Field::req("graylog_stream_id", Ty::Str).before(ids_to_str),
        Field::req("grafana_org_id", Ty::Str).before(ids_to_str),
        Field::req("grafana_dashboard_folder_id", Ty::Str).before(ids_to_str),
        Field::opt("grafana_datasource_uid", Ty::Nullable(&Ty::Str)).before(ids_to_str),
    ],
);

/// `UpdateMetaAutoRequest`.
pub static UPDATE_META_AUTO_REQUEST: Model = Model::new(
    "UpdateMetaAutoRequest",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("integration_name", Ty::Str),
        Field::opt("instance_name", Ty::Nullable(&Ty::Str)),
        Field::opt("graylog_input_id", Ty::Nullable(&Ty::Str)),
        Field::opt("graylog_index_id", Ty::Nullable(&Ty::Str)),
        Field::opt("graylog_stream_id", Ty::Nullable(&Ty::Str)),
        Field::opt("graylog_pipeline_id", Ty::Nullable(&Ty::Str)),
        Field::opt("graylog_content_pack_input_id", Ty::Nullable(&Ty::Str)),
        Field::opt("graylog_content_pack_stream_id", Ty::Nullable(&Ty::Str)),
        Field::opt("grafana_org_id", Ty::Nullable(&Ty::Str)),
        Field::opt("grafana_dashboard_folder_id", Ty::Nullable(&Ty::Str)),
        Field::opt("grafana_datasource_uid", Ty::Nullable(&Ty::Str)),
    ],
);

/// `IntegrationWithAuthKeys`.
pub fn catalog_dump(c: &Catalog) -> PyValue {
    dict(vec![
        ("id", int(c.id)),
        ("integration_name", s(&c.name)),
        ("description", s(&c.description)),
        ("integration_details", s(&c.details)),
        (
            "auth_keys",
            PyValue::List(
                c.keys
                    .iter()
                    .map(|k| dict(vec![("auth_key_name", s(k))]))
                    .collect(),
            ),
        ),
    ])
}

/// `IntegrationAuthKeys`' serializer: a write-only key's value is the
/// placeholder.
fn auth_value(name: &str, value: &str) -> PyValue {
    if REDACTED_AUTH_KEYS.contains(&name) && !value.is_empty() {
        s(REDACTED_AUTH_VALUE)
    } else {
        s(value)
    }
}

fn subscription_dump(sub: &Subscription) -> Result<PyValue, &'static str> {
    let service = sub
        .service
        .as_ref()
        .ok_or("a subscription without a service")?;
    Ok(dict(vec![
        ("id", int(sub.id)),
        ("customer_id", opt_int_v(sub.customer_id)),
        ("integration_service_id", opt_int_v(sub.service_id)),
        (
            "integration_service",
            dict(vec![
                ("auth_type", s(&service.auth_type)),
                ("service_name", s(&service.service_name)),
                ("id", int(service.id)),
            ]),
        ),
        (
            "integration_auth_keys",
            PyValue::List(
                sub.keys
                    .iter()
                    .map(|k| {
                        dict(vec![
                            ("id", int(k.id)),
                            ("auth_key_name", s(&k.auth_key_name)),
                            ("auth_value", auth_value(&k.auth_key_name, &k.auth_value)),
                            ("subscription_id", opt_int_v(k.subscription_id)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]))
}

/// `CustomerIntegrations` (the response schema). `processed`: the listing
/// of every customer, whose rows `process_customer_integrations` rebuilds
/// with the *first subscription's* service id and name.
pub fn customer_integration_dump(
    ci: &CustomerIntegration,
    processed: bool,
) -> Result<PyValue, &'static str> {
    let subs = ci
        .subscriptions
        .iter()
        .map(subscription_dump)
        .collect::<Result<Vec<_>, _>>()?;
    let (service_id, service_name) = if processed {
        match ci.subscriptions.first() {
            Some(first) => (
                opt_int_v(first.service_id),
                s(&first
                    .service
                    .as_ref()
                    .ok_or("a subscription without a service")?
                    .service_name),
            ),
            None => (PyValue::None, PyValue::None),
        }
    } else {
        (
            int(ci.integration_service_id),
            s(&ci.integration_service_name),
        )
    };
    Ok(dict(vec![
        ("customer_code", s(&ci.customer_code)),
        ("id", int(ci.id)),
        ("customer_name", s(&ci.customer_name)),
        ("integration_subscriptions", PyValue::List(subs)),
        ("integration_service_id", service_id),
        ("integration_service_name", service_name),
        ("instance_name", opt_s(ci.instance_name.as_deref())),
        ("deployed", ci.deployed.map_or(PyValue::None, PyValue::Bool)),
    ]))
}

/// `CustomerIntegrationsMetaSchema` of a stored row.
pub fn meta_dump(m: &Meta) -> PyValue {
    dict(vec![
        ("id", int(m.id)),
        ("customer_code", s(&m.customer_code)),
        ("integration_name", s(&m.integration_name)),
        ("instance_name", opt_s(m.instance_name.as_deref())),
        ("graylog_input_id", opt_s(m.graylog_input_id.as_deref())),
        ("graylog_index_id", s(&m.graylog_index_id)),
        ("graylog_stream_id", s(&m.graylog_stream_id)),
        ("grafana_org_id", s(&m.grafana_org_id)),
        (
            "grafana_dashboard_folder_id",
            s(&m.grafana_dashboard_folder_id),
        ),
        (
            "grafana_datasource_uid",
            opt_s(m.grafana_datasource_uid.as_deref()),
        ),
    ])
}

/// `CustomerIntegrationsMeta.model_dump()` (the table model, in its
/// declaration order).
pub fn meta_table_dump(m: &Meta) -> PyValue {
    meta_dump(m)
}

/// `CustomerNetworkConnectorsMeta.model_dump()` (the table model, in its
/// declaration order).
pub fn network_meta_table_dump(m: &NetworkMeta) -> PyValue {
    dict(vec![
        ("id", int(m.id)),
        ("customer_code", s(&m.customer_code)),
        ("network_connector_name", s(&m.network_connector_name)),
        ("graylog_input_id", opt_s(m.graylog_input_id.as_deref())),
        ("graylog_index_id", s(&m.graylog_index_id)),
        ("graylog_stream_id", s(&m.graylog_stream_id)),
        ("graylog_pipeline_id", s(&m.graylog_pipeline_id)),
        (
            "graylog_content_pack_input_id",
            s(&m.graylog_content_pack_input_id),
        ),
        (
            "graylog_content_pack_stream_id",
            s(&m.graylog_content_pack_stream_id),
        ),
        ("grafana_org_id", s(&m.grafana_org_id)),
        (
            "grafana_dashboard_folder_id",
            s(&m.grafana_dashboard_folder_id),
        ),
        ("grafana_datasource_uid", s(&m.grafana_datasource_uid)),
    ])
}

/// `{message, success, additional_info}` (`CustomerIntegrationCreateResponse`
/// and `…DeleteResponse`).
pub fn message_response(message: String, additional_info: Option<String>) -> PyValue {
    dict(vec![
        ("message", s(message)),
        ("success", PyValue::Bool(true)),
        ("additional_info", opt_s(additional_info.as_deref())),
    ])
}

/// `CustomerIntegrationsMetaResponse`.
pub fn meta_response(message: &str, success: bool, metas: Option<Vec<PyValue>>) -> PyValue {
    dict(vec![
        ("message", s(message)),
        ("success", PyValue::Bool(success)),
        (
            "customer_integrations_meta",
            metas.map_or(PyValue::None, PyValue::List),
        ),
    ])
}
