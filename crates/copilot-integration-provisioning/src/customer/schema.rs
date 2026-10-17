//! The customer provisioning's Pydantic models —
//! `customer_provisioning/schema/{provision,wazuh_worker,grafana}.py` — as
//! the flow builds and validates them.

use copilot_auth::pyvalue::PyValue;
use copilot_grafana_dashboards::schema::DASHBOARD_PROVISION_REQUEST;
use copilot_upstream::model::{Check, EnumTy, Field, Model, Ty};

/// `CustomerSubsctipion` (a plain `Enum`, `WAZUH = "Wazuh"`).
pub static CUSTOMER_SUBSCRIPTION: EnumTy = EnumTy {
    name: "CustomerSubsctipion",
    values: &["Wazuh"],
};

fn na() -> PyValue {
    PyValue::Str("n/a".into())
}

fn zero_text() -> PyValue {
    PyValue::Str("0".into())
}

fn no() -> PyValue {
    PyValue::Bool(false)
}

fn one_text() -> PyValue {
    PyValue::Str("1".into())
}

/// The message of `validate_customer_index_name`'s `ValueError`.
pub const INDEX_NAME_MESSAGE: &str = "customer_index_name must start with a lowercase letter or \
                                      number and can only contain lowercase letters, numbers, \
                                      underscores, plus signs, and hyphens.";

/// `re.match(r"^[a-z0-9][a-z0-9_+-]*$", v)`: `$` also matches before one
/// trailing newline.
pub fn index_name_matches(v: &str) -> bool {
    let body = v.strip_suffix('\n').unwrap_or(v);
    let mut chars = body.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '+' | '-'))
}

fn validate_customer_index_name(v: &PyValue) -> Result<PyValue, Check> {
    match v {
        PyValue::Str(s) if index_name_matches(s) => Ok(v.clone()),
        _ => Err(Check::ValueError(INDEX_NAME_MESSAGE.into())),
    }
}

/// `ProvisionNewCustomer` (the body of `POST /customer_provisioning/provision`
/// and `POST /portainer/create-wazuh-customer-stack`).
pub static PROVISION_NEW_CUSTOMER: Model = Model::new(
    "ProvisionNewCustomer",
    &[
        Field::req("customer_name", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("customer_index_name", Ty::Str).after(validate_customer_index_name),
        Field::req("customer_grafana_org_name", Ty::Str),
        Field::req("hot_data_retention", Ty::Int),
        Field::req("index_replicas", Ty::Int),
        Field::req("index_shards", Ty::Int),
        Field::req(
            "customer_subscription",
            Ty::List(&Ty::Enum(&CUSTOMER_SUBSCRIPTION)),
        ),
        Field::req(
            "dashboards_to_include",
            Ty::Model(&DASHBOARD_PROVISION_REQUEST),
        ),
        Field::def("wazuh_auth_password", Ty::Nullable(&Ty::Str), na),
        Field::def("wazuh_registration_port", Ty::Nullable(&Ty::Str), na),
        Field::def("wazuh_logs_port", Ty::Nullable(&Ty::Str), na),
        Field::def("wazuh_api_port", Ty::Nullable(&Ty::Str), na),
        Field::def("wazuh_cluster_name", Ty::Nullable(&Ty::Str), na),
        Field::def("wazuh_cluster_key", Ty::Nullable(&Ty::Str), na),
        Field::def("wazuh_master_ip", Ty::Nullable(&Ty::Str), na),
        Field::req("grafana_url", Ty::Str),
        Field::def("grafana_org_id", Ty::Nullable(&Ty::Str), zero_text),
        Field::def("only_insert_into_db", Ty::Nullable(&Ty::Bool), no),
        Field::opt("graylog_index_id", Ty::Nullable(&Ty::Str)),
        Field::opt("graylog_stream_id", Ty::Nullable(&Ty::Str)),
        Field::opt("wazuh_worker_hostname", Ty::Nullable(&Ty::Str)),
        Field::def("provision_wazuh_worker", Ty::Bool, no),
        Field::def("provision_ha_proxy", Ty::Bool, no),
        Field::opt("portainer_deployment", Ty::Nullable(&Ty::Bool)),
    ],
);

/// `ProvisionWorkerRequest`.
pub static PROVISION_WORKER_REQUEST: Model = Model::new(
    "ProvisionWorkerRequest",
    &[
        Field::req("customer_name", Ty::Str),
        Field::req("customer_code", Ty::Str),
        Field::req("wazuh_auth_password", Ty::Str),
        Field::req("wazuh_registration_port", Ty::Str),
        Field::req("wazuh_logs_port", Ty::Str),
        Field::req("wazuh_api_port", Ty::Str),
        Field::req("wazuh_cluster_name", Ty::Str),
        Field::req("wazuh_cluster_key", Ty::Str),
        Field::req("wazuh_master_ip", Ty::Str),
        Field::opt("wazuh_worker_hostname", Ty::Nullable(&Ty::Str)),
        Field::opt("portainer_deployment", Ty::Nullable(&Ty::Bool)),
        Field::opt("swarm_nodes", Ty::Nullable(&Ty::List(&Ty::Str))),
        Field::opt("wazuh_manager_version", Ty::Nullable(&Ty::Str)),
        Field::def("node_id", Ty::Nullable(&Ty::Str), one_text),
    ],
);

/// `ProvisionHaProxyRequest`.
pub static PROVISION_HAPROXY_REQUEST: Model = Model::new(
    "ProvisionHaProxyRequest",
    &[
        Field::req("customer_name", Ty::Str),
        Field::req("wazuh_registration_port", Ty::Str),
        Field::req("wazuh_logs_port", Ty::Str),
        Field::opt("wazuh_worker_hostname", Ty::Nullable(&Ty::Str)),
        Field::opt("portainer_deployment", Ty::Nullable(&Ty::Bool)),
        Field::opt("swarm_nodes", Ty::Nullable(&Ty::List(&Ty::Str))),
    ],
);

/// `CustomerProvisionMeta`.
pub static CUSTOMER_PROVISION_META: Model = Model::new(
    "CustomerProvisionMeta",
    &[
        Field::req("index_set_id", Ty::Str),
        Field::req("stream_id", Ty::Str),
        Field::req("pipeline_ids", Ty::List(&Ty::Str)),
        Field::req("grafana_organization_id", Ty::Int),
        Field::req("wazuh_datasource_uid", Ty::Str),
        Field::req("grafana_edr_folder_id", Ty::Int),
        Field::opt("iris_customer_id", Ty::Nullable(&Ty::Int)),
    ],
);

/// `GrafanaOrganizationCreation`.
pub static GRAFANA_ORGANIZATION_CREATION: Model = Model::new(
    "GrafanaOrganizationCreation",
    &[Field::req("message", Ty::Str), Field::req("orgId", Ty::Int)],
);

/// The qualified name `GrafanaOrganizationCreation(**results)`'s `TypeError`
/// prints.
pub const GRAFANA_ORGANIZATION_CREATION_QUALNAME: &str =
    "app.customer_provisioning.schema.grafana.GrafanaOrganizationCreation";

/// The models, by name (the vectors).
pub fn registry() -> Vec<(&'static str, &'static Model)> {
    vec![
        ("ProvisionNewCustomer", &PROVISION_NEW_CUSTOMER),
        ("ProvisionWorkerRequest", &PROVISION_WORKER_REQUEST),
        ("ProvisionHaProxyRequest", &PROVISION_HAPROXY_REQUEST),
        ("CustomerProvisionMeta", &CUSTOMER_PROVISION_META),
        (
            "GrafanaOrganizationCreation",
            &GRAFANA_ORGANIZATION_CREATION,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_name_is_re_match_s() {
        for ok in ["a", "0", "socf", "a-b_c+d", "abc\n", "9z"] {
            assert!(index_name_matches(ok), "{ok:?}");
        }
        for bad in [
            "", "A", "-a", "_a", "ab c", "abc\n\n", "\n", "é", "a.b", "aB",
        ] {
            assert!(!index_name_matches(bad), "{bad:?}");
        }
    }
}
