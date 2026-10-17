//! `app/integrations/office365/schema/provision.py`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

fn office365() -> PyValue {
    PyValue::Str("Office365".into())
}

/// `ProvisionOffice365Request` (its `integration_name` forced by the
/// `mode="before"` validator).
pub static PROVISION_OFFICE365_REQUEST: Model = Model::new(
    "ProvisionOffice365Request",
    &[
        Field::req("customer_code", Ty::Str),
        Field::def("integration_name", Ty::Str, office365),
        Field::opt("instance_name", Ty::Nullable(&Ty::Str)),
    ],
);

/// `ProvisionOffice365AuthKeys`.
pub static PROVISION_OFFICE365_AUTH_KEYS: Model = Model::new(
    "ProvisionOffice365AuthKeys",
    &[
        Field::req("TENANT_ID", Ty::Str),
        Field::req("CLIENT_ID", Ty::Str),
        Field::req("CLIENT_SECRET", Ty::Str),
        Field::req("API_TYPE", Ty::Str),
    ],
);

/// `PipelineRuleTitles`, in declaration order.
pub const PIPELINE_RULE_TITLES: [&str; 6] = [
    crate::graylog::WAZUH_INFO,
    crate::graylog::WAZUH_WARNING,
    crate::graylog::WAZUH_NOTICE,
    crate::graylog::WAZUH_ALERT,
    OFFICE365_TIMESTAMP,
    OFFICE365_SYSLOG_TYPE,
];

/// `PipelineRuleTitles.OFFICE365_TIMESTAMP`.
pub const OFFICE365_TIMESTAMP: &str = "Office365 Timestamp - UTC";
/// `PipelineRuleTitles.OFFICE365_SYSLOG_TYPE`.
pub const OFFICE365_SYSLOG_TYPE: &str = "SYSLOG TYPE OFFICE365";
/// `PipelineTitles.OFFICE365`.
pub const PIPELINE_TITLE: &str = "OFFICE365 PROCESSING PIPELINE";
