//! `app/network_connectors/schema.py` as model statics, and the dumps.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

use super::store::{Catalog, CustomerConnector, Meta, Subscription};
use crate::integrations::schema::ids_to_str;
use crate::sql::{dict, int, opt_int_v, opt_s, s};

/// `CreateNetworkConnectorsService`.
pub static CREATE_SERVICE: Model = Model::new(
    "CreateNetworkConnectorsService",
    &[
        Field::req("auth_type", Ty::Str),
        Field::req("config_key", Ty::Str),
        Field::req("config_value", Ty::Str),
    ],
);

/// `CreateNetworkConnectorsAuthKeys`.
pub static CREATE_AUTH_KEYS: Model = Model::new(
    "CreateNetworkConnectorsAuthKeys",
    &[
        Field::req("auth_key_name", Ty::Str),
        Field::req("auth_value", Ty::Str),
    ],
);

/// `CustomerNetworkConnectorsCreate`.
pub static CREATE: Model = Model::new(
    "CustomerNetworkConnectorsCreate",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("customer_name", Ty::Str),
        Field::req("network_connector_name", Ty::Str),
        Field::req("network_connector_config", Ty::Model(&CREATE_SERVICE)),
        Field::req(
            "network_connector_auth_keys",
            Ty::List(&Ty::Model(&CREATE_AUTH_KEYS)),
        ),
    ],
);

/// `UpdateCustomerNetworkConnectors`.
pub static UPDATE: Model = Model::new(
    "UpdateCustomerNetworkConnectors",
    &[
        Field::req("network_connector_name", Ty::Str),
        Field::req(
            "network_connector_auth_keys",
            Ty::List(&Ty::Model(&CREATE_AUTH_KEYS)),
        ),
    ],
);

/// `DeleteCustomerNetworkConnectors`.
pub static DELETE: Model = Model::new(
    "DeleteCustomerNetworkConnectors",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("network_connector_name", Ty::Str),
    ],
);

/// `CustomerNetworkConnectorsMetaSchema`.
pub static META_SCHEMA: Model = Model::new(
    "CustomerNetworkConnectorsMetaSchema",
    &[
        Field::opt("id", Ty::Nullable(&Ty::Int)),
        Field::req("customer_code", Ty::Str),
        Field::req("network_connector_name", Ty::Str),
        Field::opt("graylog_input_id", Ty::Nullable(&Ty::Str)).before(ids_to_str),
        Field::req("graylog_index_id", Ty::Str).before(ids_to_str),
        Field::req("graylog_stream_id", Ty::Str).before(ids_to_str),
        Field::req("grafana_org_id", Ty::Str).before(ids_to_str),
        Field::req("grafana_dashboard_folder_id", Ty::Str).before(ids_to_str),
    ],
);

/// `NetworkConnectorsWithAuthKeys`.
pub fn catalog_dump(c: &Catalog) -> PyValue {
    dict(vec![
        ("id", int(c.id)),
        ("network_connector_name", s(&c.name)),
        ("description", s(&c.description)),
        ("network_connector_details", s(&c.details)),
        (
            "network_connector_keys",
            PyValue::List(
                c.keys
                    .iter()
                    .map(|k| dict(vec![("auth_key_name", s(k))]))
                    .collect(),
            ),
        ),
    ])
}

fn subscription_dump(sub: &Subscription) -> Result<PyValue, &'static str> {
    let service = sub
        .service
        .as_ref()
        .ok_or("a subscription without a service")?;
    Ok(dict(vec![
        ("id", int(sub.id)),
        ("customer_id", opt_int_v(sub.customer_id)),
        ("network_connectors_service_id", int(sub.service_id)),
        (
            "network_connectors_service",
            dict(vec![
                ("auth_type", s(&service.auth_type)),
                ("service_name", s(&service.service_name)),
                ("id", int(service.id)),
            ]),
        ),
        (
            "network_connectors_keys",
            PyValue::List(
                sub.keys
                    .iter()
                    .map(|k| {
                        dict(vec![
                            ("id", int(k.id)),
                            ("auth_key_name", s(&k.auth_key_name)),
                            ("auth_value", s(&k.auth_value)),
                            ("subscription_id", opt_int_v(k.subscription_id)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]))
}

/// `CustomerNetworkConnectors` (the response schema); `processed` as for
/// the integrations.
pub fn connector_dump(c: &CustomerConnector, processed: bool) -> Result<PyValue, &'static str> {
    let subs = c
        .subscriptions
        .iter()
        .map(subscription_dump)
        .collect::<Result<Vec<_>, _>>()?;
    let (service_id, service_name) = if processed {
        match c.subscriptions.first() {
            Some(first) => (
                int(first.service_id),
                s(&first
                    .service
                    .as_ref()
                    .ok_or("a subscription without a service")?
                    .service_name),
            ),
            None => (PyValue::None, PyValue::None),
        }
    } else {
        (int(c.service_id), s(&c.service_name))
    };
    Ok(dict(vec![
        ("customer_code", s(&c.customer_code)),
        ("id", int(c.id)),
        ("customer_name", s(&c.customer_name)),
        ("network_connectors_subscriptions", PyValue::List(subs)),
        ("network_connector_service_id", service_id),
        ("network_connector_service_name", service_name),
        ("deployed", c.deployed.map_or(PyValue::None, PyValue::Bool)),
    ]))
}

/// `CustomerNetworkConnectorsMetaSchema` of a stored row.
pub fn meta_dump(m: &Meta) -> PyValue {
    dict(vec![
        ("id", int(m.id)),
        ("customer_code", s(&m.customer_code)),
        ("network_connector_name", s(&m.network_connector_name)),
        ("graylog_input_id", opt_s(m.graylog_input_id.as_deref())),
        ("graylog_index_id", s(&m.graylog_index_id)),
        ("graylog_stream_id", s(&m.graylog_stream_id)),
        ("grafana_org_id", s(&m.grafana_org_id)),
        (
            "grafana_dashboard_folder_id",
            s(&m.grafana_dashboard_folder_id),
        ),
    ])
}

/// `CustomerNetworkConnectorsMetaResponse`.
pub fn meta_response(message: &str, success: bool, metas: Option<Vec<PyValue>>) -> PyValue {
    dict(vec![
        ("message", s(message)),
        ("success", PyValue::Bool(success)),
        (
            "customer_network_connectors_meta",
            metas.map_or(PyValue::None, PyValue::List),
        ),
    ])
}
