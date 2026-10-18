//! `alert_creation_settings/schema/alert_creation_settings.py` as model
//! statics, and the response dumps.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

use super::NVD_URL;
use super::store::{EventOrder, Settings};
use crate::sql::{dict, int, opt_int_v, opt_s, s};

fn nvd_url() -> PyValue {
    PyValue::Str(NVD_URL.into())
}

/// `AlertCreationEventConfigCreate`.
pub static EVENT_CONFIG_CREATE: Model = Model::new(
    "AlertCreationEventConfigCreate",
    &[
        Field::req("event_id", Ty::Str),
        Field::req("field", Ty::Str),
        Field::req("value", Ty::Str),
    ],
);

/// `EventOrderCreate`.
pub static EVENT_ORDER_CREATE: Model = Model::new(
    "EventOrderCreate",
    &[
        Field::req("order_label", Ty::Str),
        Field::req("event_configs", Ty::List(&Ty::Model(&EVENT_CONFIG_CREATE))),
    ],
);

/// `AlertCreationSettingsCreate`.
pub static SETTINGS_CREATE: Model = Model::new(
    "AlertCreationSettingsCreate",
    &[
        Field::req("customer_code", Ty::Str),
        Field::req("customer_name", Ty::Str),
        Field::opt("excluded_wazuh_rules", Ty::Nullable(&Ty::Str)),
        Field::opt("excluded_suricata_rules", Ty::Nullable(&Ty::Str)),
        Field::opt("timefield", Ty::Nullable(&Ty::Str)),
        Field::opt("office365_organization_id", Ty::Nullable(&Ty::Str)),
        Field::opt("iris_customer_id", Ty::Nullable(&Ty::Int)),
        Field::opt("iris_customer_name", Ty::Nullable(&Ty::Str)),
        Field::opt("iris_index", Ty::Nullable(&Ty::Str)),
        Field::opt("grafana_url", Ty::Nullable(&Ty::Str)),
        Field::opt("misp_url", Ty::Nullable(&Ty::Str)),
        Field::opt("opencti_url", Ty::Nullable(&Ty::Str)),
        Field::opt("custom_message", Ty::Nullable(&Ty::Str)),
        Field::opt("shuffle_endpoint", Ty::Nullable(&Ty::Str)),
        Field::def("nvd_url", Ty::Nullable(&Ty::Str), nvd_url),
        Field::opt(
            "event_orders",
            Ty::Nullable(&Ty::List(&Ty::Model(&EVENT_ORDER_CREATE))),
        ),
    ],
);

/// The text columns of the settings, in declaration order (between the
/// name and `nvd_url`; `iris_customer_id` is the one integer among them).
pub const TEXT_FIELDS: &[&str] = &[
    "excluded_wazuh_rules",
    "excluded_suricata_rules",
    "timefield",
    "office365_organization_id",
    "iris_customer_id",
    "iris_customer_name",
    "iris_index",
    "grafana_url",
    "misp_url",
    "opencti_url",
    "custom_message",
    "shuffle_endpoint",
];

fn columns(row: &Settings) -> Vec<(&'static str, PyValue)> {
    vec![
        ("customer_code", s(&row.customer_code)),
        ("customer_name", s(&row.customer_name)),
        (
            "excluded_wazuh_rules",
            opt_s(row.excluded_wazuh_rules.as_deref()),
        ),
        (
            "excluded_suricata_rules",
            opt_s(row.excluded_suricata_rules.as_deref()),
        ),
        ("timefield", opt_s(row.timefield.as_deref())),
        (
            "office365_organization_id",
            opt_s(row.office365_organization_id.as_deref()),
        ),
        ("iris_customer_id", opt_int_v(row.iris_customer_id)),
        (
            "iris_customer_name",
            opt_s(row.iris_customer_name.as_deref()),
        ),
        ("iris_index", opt_s(row.iris_index.as_deref())),
        ("grafana_url", opt_s(row.grafana_url.as_deref())),
        ("misp_url", opt_s(row.misp_url.as_deref())),
        ("opencti_url", opt_s(row.opencti_url.as_deref())),
        ("custom_message", opt_s(row.custom_message.as_deref())),
        ("shuffle_endpoint", opt_s(row.shuffle_endpoint.as_deref())),
        ("nvd_url", opt_s(row.nvd_url.as_deref())),
    ]
}

/// `AlertCreationEventConfigResponse`s of one order.
pub fn configs_dump(order: &EventOrder) -> PyValue {
    PyValue::List(
        order
            .configs
            .iter()
            .map(|c| {
                dict(vec![
                    ("event_id", s(&c.event_id)),
                    ("field", s(&c.field)),
                    ("value", s(&c.value)),
                ])
            })
            .collect(),
    )
}

/// `EventOrderResponse`.
pub fn order_dump(order: &EventOrder) -> PyValue {
    dict(vec![
        ("order_label", s(&order.order_label)),
        ("event_configs", configs_dump(order)),
    ])
}

/// `AlertCreationSettingsResponse` of a loaded row and its orders.
pub fn settings_dump(row: &Settings) -> PyValue {
    let mut fields = columns(row);
    fields.push((
        "event_orders",
        PyValue::List(row.orders.iter().map(order_dump).collect()),
    ));
    dict(fields)
}

/// `AlertCreationSettings` (the table model `/create` answers with), in
/// its declaration order — Python's follows the order the refresh loaded
/// the attributes in, which changes between processes (RUST_MIGRATION.md
/// §4).
pub fn table_dump(row: &Settings) -> PyValue {
    let mut fields = vec![("id", int(row.id))];
    fields.extend(columns(row));
    dict(fields)
}
