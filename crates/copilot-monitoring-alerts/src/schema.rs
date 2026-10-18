//! Port of `app/integrations/monitoring_alert/schema/provision.py`: the two
//! request bodies with their validators, and the `GraylogAlertProvision*`
//! models the provisioning functions build an event definition from.
//!
//! The validators raise `HTTPException`, not `ValueError`: a value they
//! refuse ends validation on the spot as a 400 (`Check::Abort`), whatever
//! the fields before it failed — `search_within_last` and `execute_every`
//! refuse `0` (negative windows pass), `alert_name` is normalized
//! (`replace(" ", "_").upper()`, CPython 3.11's `str.upper`) and must name a
//! catalog member.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Check, EnumTy, Field, IntEnumTy, Model, Ty};

use crate::catalog;

/// `GraylogInstance`.
pub static GRAYLOG_INSTANCE: EnumTy = EnumTy {
    name: "GraylogInstance",
    values: &["default", "network"],
};

/// `AlertPriority` (a plain `Enum` of ints).
pub static ALERT_PRIORITY: IntEnumTy = IntEnumTy {
    name: "AlertPriority",
    values: &[1, 2, 3],
};

/// The default `alert_name`.
pub const DEFAULT_ALERT_NAME: &str = "WAZUH_SYSLOG_LEVEL_ALERT";

fn default_alert_name() -> PyValue {
    PyValue::Str(DEFAULT_ALERT_NAME.into())
}

fn default_instance() -> PyValue {
    PyValue::Str("default".into())
}

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

fn thousand() -> PyValue {
    PyValue::Int("1000".into())
}

/// `validate_non_zero`.
fn validate_non_zero(v: &PyValue) -> Result<PyValue, Check> {
    if matches!(v, PyValue::Int(i) if i == "0") {
        return Err(Check::Abort(
            400,
            format!("Invalid value: {}. Must be greater than 0.", v.py_str()),
        ));
    }
    Ok(v.clone())
}

/// `validate_alert_name`: the normalized name, or the 400.
pub fn normalize_alert_name(raw: &str) -> Result<String, Check> {
    let name = copilot_jinja::unicode::upper(&raw.replace(' ', "_"));
    if catalog::find(&name).is_none() {
        return Err(Check::Abort(
            400,
            format!(
                "Invalid alert name: {name}. Must be one of: {}",
                catalog::names().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    Ok(name)
}

fn validate_alert_name(v: &PyValue) -> Result<PyValue, Check> {
    match v {
        PyValue::Str(s) => normalize_alert_name(s).map(PyValue::Str),
        other => Ok(other.clone()),
    }
}

/// `CustomFields.replace_spaces_with_underscores`.
fn spaces_to_underscores(v: &PyValue) -> Result<PyValue, Check> {
    match v {
        PyValue::Str(s) => Ok(PyValue::Str(s.replace(' ', "_"))),
        other => Ok(other.clone()),
    }
}

/// `ProvisionMonitoringAlertRequest`.
pub static PROVISION_REQUEST: Model = Model::new(
    "ProvisionMonitoringAlertRequest",
    &[
        Field::req("search_within_last", Ty::Int).after(validate_non_zero),
        Field::req("execute_every", Ty::Int).after(validate_non_zero),
        Field::def("alert_name", Ty::Str, default_alert_name).after(validate_alert_name),
        Field::def(
            "graylog_instance",
            Ty::Enum(&GRAYLOG_INSTANCE),
            default_instance,
        ),
    ],
);

/// `CustomFields`.
pub static CUSTOM_FIELDS: Model = Model::new(
    "CustomFields",
    &[
        Field::req("name", Ty::Str).after(spaces_to_underscores),
        Field::req("value", Ty::Str),
    ],
);

/// `CustomMonitoringAlertProvisionModel`.
pub static CUSTOM_REQUEST: Model = Model::new(
    "CustomMonitoringAlertProvisionModel",
    &[
        Field::req("alert_name", Ty::Str),
        Field::req("alert_description", Ty::Str),
        Field::req("alert_priority", Ty::IntEnum(&ALERT_PRIORITY)),
        Field::req("search_query", Ty::Str),
        Field::def("streams", Ty::Nullable(&Ty::List(&Ty::Str)), empty_list),
        Field::opt(
            "custom_fields",
            Ty::Nullable(&Ty::List(&Ty::Model(&CUSTOM_FIELDS))),
        ),
        Field::req("search_within_ms", Ty::Int),
        Field::req("execute_every_ms", Ty::Int),
        Field::def(
            "graylog_instance",
            Ty::Enum(&GRAYLOG_INSTANCE),
            default_instance,
        ),
    ],
);

/// `GraylogAlertProvisionProvider`.
pub static PROVIDER: Model = Model::new(
    "GraylogAlertProvisionProvider",
    &[
        Field::req("template", Ty::Str),
        Field::req("type", Ty::Str),
        Field::req("require_values", Ty::Bool),
    ],
);

/// `GraylogAlertProvisionFieldSpecItem`.
pub static FIELD_SPEC_ITEM: Model = Model::new(
    "GraylogAlertProvisionFieldSpecItem",
    &[
        Field::req("data_type", Ty::Str),
        Field::req("providers", Ty::List(&Ty::Model(&PROVIDER))),
    ],
);

/// `GraylogAlertProvisionConfig`.
pub static PROVISION_CONFIG: Model = Model::new(
    "GraylogAlertProvisionConfig",
    &[
        Field::req("query", Ty::Str),
        Field::req("query_parameters", Ty::List(&Ty::Any)),
        Field::req("streams", Ty::List(&Ty::Any)),
        Field::req("search_within_ms", Ty::Int),
        Field::req("execute_every_ms", Ty::Int),
        Field::req("group_by", Ty::List(&Ty::Any)),
        Field::req("series", Ty::List(&Ty::Any)),
        Field::req("conditions", Ty::Dict(&Ty::Any)),
        Field::req("type", Ty::Str),
        Field::def("event_limit", Ty::Int, thousand),
    ],
);

/// `GraylogAlertProvisionNotificationSettings`.
pub static NOTIFICATION_SETTINGS: Model = Model::new(
    "GraylogAlertProvisionNotificationSettings",
    &[
        Field::req("grace_period_ms", Ty::Int),
        Field::opt("backlog_size", Ty::Nullable(&Ty::Int)),
    ],
);

/// `GraylogAlertProvisionNotification`.
pub static NOTIFICATION: Model = Model::new(
    "GraylogAlertProvisionNotification",
    &[Field::req("notification_id", Ty::Str)],
);

/// `GraylogAlertProvisionModel`.
pub static PROVISION_MODEL: Model = Model::new(
    "GraylogAlertProvisionModel",
    &[
        Field::req("title", Ty::Str),
        Field::req("description", Ty::Str),
        Field::req("priority", Ty::Int),
        Field::req("config", Ty::Model(&PROVISION_CONFIG)),
        Field::req("field_spec", Ty::Dict(&Ty::Model(&FIELD_SPEC_ITEM))),
        Field::req("key_spec", Ty::List(&Ty::Any)),
        Field::req("notification_settings", Ty::Model(&NOTIFICATION_SETTINGS)),
        Field::def(
            "notifications",
            Ty::Nullable(&Ty::List(&Ty::Model(&NOTIFICATION))),
            empty_list,
        ),
        Field::req("alert", Ty::Bool),
    ],
);
