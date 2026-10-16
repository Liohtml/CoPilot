//! `app/connectors/shuffle/schema/organizations.py`.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Field, Model, Ty};

fn s(v: &str) -> PyValue {
    PyValue::Str(v.into())
}

fn empty_str() -> PyValue {
    s("")
}

fn empty_list() -> PyValue {
    PyValue::List(Vec::new())
}

fn empty_dict() -> PyValue {
    PyValue::Dict(Vec::new())
}

fn no() -> PyValue {
    PyValue::Bool(false)
}

fn yes() -> PyValue {
    PyValue::Bool(true)
}

fn zero() -> PyValue {
    PyValue::Int("0".into())
}

fn dict(pairs: &[(&str, PyValue)]) -> PyValue {
    PyValue::Dict(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect(),
    )
}

/// `OrgAuth()`.
fn org_auth_default() -> PyValue {
    dict(&[("token", s("")), ("expires", PyValue::None)])
}

/// `SyncConfig()`.
fn sync_config_default() -> PyValue {
    dict(&[("interval", zero()), ("api_key", s("")), ("source", s(""))])
}

/// `PartnerInfo()`.
fn partner_info_default() -> PyValue {
    dict(&[("reseller", no()), ("reseller_level", s(""))])
}

/// `SSOConfig()`.
fn sso_config_default() -> PyValue {
    dict(&[
        ("sso_entrypoint", s("")),
        ("sso_certificate", s("")),
        ("client_id", s("")),
        ("client_secret", s("")),
        ("openid_authorization", s("")),
        ("openid_token", s("")),
    ])
}

/// `SyncConfig`.
pub static SYNC_CONFIG: Model = Model::new(
    "SyncConfig",
    &[
        Field::def("interval", Ty::Int, zero),
        Field::def("api_key", Ty::Str, empty_str),
        Field::def("source", Ty::Str, empty_str),
    ],
);

/// `PartnerInfo`.
pub static PARTNER_INFO: Model = Model::new(
    "PartnerInfo",
    &[
        Field::def("reseller", Ty::Bool, no),
        Field::def("reseller_level", Ty::Str, empty_str),
    ],
);

/// `SSOConfig`.
pub static SSO_CONFIG: Model = Model::new(
    "SSOConfig",
    &[
        Field::def("sso_entrypoint", Ty::Str, empty_str),
        Field::def("sso_certificate", Ty::Str, empty_str),
        Field::def("client_id", Ty::Str, empty_str),
        Field::def("client_secret", Ty::Str, empty_str),
        Field::def("openid_authorization", Ty::Str, empty_str),
        Field::def("openid_token", Ty::Str, empty_str),
    ],
);

/// `OrgAuth`.
pub static ORG_AUTH: Model = Model::new(
    "OrgAuth",
    &[
        Field::def("token", Ty::Str, empty_str),
        Field::opt("expires", Ty::Nullable(&Ty::DateTime)),
    ],
);

/// `Organization`.
pub static ORGANIZATION: Model = Model::new(
    "Organization",
    &[
        Field::req("name", Ty::Str),
        Field::opt("description", Ty::Nullable(&Ty::Str)),
        Field::def("company_type", Ty::Str, empty_str),
        Field::req("id", Ty::Str),
        Field::opt("org", Ty::Nullable(&Ty::Str)),
        Field::def("org_auth", Ty::Model(&ORG_AUTH), org_auth_default),
        Field::def("users", Ty::Nullable(&Ty::List(&Ty::Str)), empty_list),
        Field::def("role", Ty::Str, empty_str),
        Field::def("roles", Ty::List(&Ty::Str), empty_list),
        Field::def("active_apps", Ty::List(&Ty::Str), empty_list),
        Field::def("cloud_sync", Ty::Bool, no),
        Field::def("cloud_sync_active", Ty::Bool, yes),
        Field::def("sync_config", Ty::Model(&SYNC_CONFIG), sync_config_default),
        Field::def("sync_features", Ty::Dict(&Ty::Any), empty_dict),
        Field::opt("invites", Ty::Any),
        Field::opt("child_orgs", Ty::Nullable(&Ty::List(&Ty::Str))),
        Field::opt("manager_orgs", Ty::Nullable(&Ty::List(&Ty::Str))),
        Field::opt("creator_org", Ty::Nullable(&Ty::Str)),
        Field::def("disabled", Ty::Bool, no),
        Field::def(
            "partner_info",
            Ty::Model(&PARTNER_INFO),
            partner_info_default,
        ),
        Field::def("sso_config", Ty::Model(&SSO_CONFIG), sso_config_default),
        Field::def("main_priority", Ty::Str, empty_str),
        Field::def("region", Ty::Str, empty_str),
        Field::def("region_url", Ty::Str, empty_str),
        Field::def("tutorials", Ty::List(&Ty::Any), empty_list),
    ],
);

/// `DetailedOrganization.validate_manager_orgs` (`mode="before"`).
fn manager_orgs(v: &PyValue) -> PyValue {
    match v {
        PyValue::None => PyValue::None,
        PyValue::List(items) => PyValue::List(
            items
                .iter()
                .filter(|i| !matches!(i, PyValue::None))
                .map(|i| PyValue::Str(i.py_str()))
                .collect(),
        ),
        // `isinstance(v, (str, int))`: a bool is an int.
        PyValue::Str(_) | PyValue::Int(_) | PyValue::Bool(_) => {
            PyValue::List(vec![PyValue::Str(v.py_str())])
        }
        _ => PyValue::None,
    }
}

/// `DetailedOrganization`.
pub static DETAILED_ORGANIZATION: Model = Model::new(
    "DetailedOrganization",
    &[
        Field::req("name", Ty::Str),
        Field::def("description", Ty::Str, empty_str),
        Field::def("company_type", Ty::Str, empty_str),
        Field::def("image", Ty::Str, empty_str),
        Field::req("id", Ty::Str),
        Field::def("org", Ty::Str, empty_str),
        Field::def("org_auth", Ty::Model(&ORG_AUTH), org_auth_default),
        Field::def("users", Ty::List(&Ty::Any), empty_list),
        Field::def("role", Ty::Str, empty_str),
        Field::def("roles", Ty::List(&Ty::Str), empty_list),
        Field::def("active_apps", Ty::List(&Ty::Str), empty_list),
        Field::def("cloud_sync", Ty::Bool, no),
        Field::def("cloud_sync_active", Ty::Bool, yes),
        Field::def("sync_config", Ty::Model(&SYNC_CONFIG), sync_config_default),
        Field::def("sync_features", Ty::Dict(&Ty::Any), empty_dict),
        Field::opt("invites", Ty::Any),
        Field::opt("manager_orgs", Ty::Nullable(&Ty::List(&Ty::Str))).before(manager_orgs),
        Field::opt("creator_org", Ty::Nullable(&Ty::Str)),
        Field::def("disabled", Ty::Bool, no),
        Field::def(
            "partner_info",
            Ty::Model(&PARTNER_INFO),
            partner_info_default,
        ),
        Field::def("sso_config", Ty::Model(&SSO_CONFIG), sso_config_default),
        Field::def("main_priority", Ty::Str, empty_str),
        Field::def("region", Ty::Str, empty_str),
        Field::def("region_url", Ty::Str, empty_str),
        Field::def("tutorials", Ty::List(&Ty::Any), empty_list),
    ],
);

/// `OrganizationsListResponse`.
pub static ORGANIZATIONS_LIST_RESPONSE: Model = Model::new(
    "OrganizationsListResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::req("data", Ty::List(&Ty::Model(&ORGANIZATION))),
        Field::req("total_count", Ty::Int),
    ],
);

/// `OrganizationResponse`.
pub static ORGANIZATION_RESPONSE: Model = Model::new(
    "OrganizationResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::opt("data", Ty::Nullable(&Ty::Model(&ORGANIZATION))),
    ],
);

/// `DetailedOrganizationResponse`.
pub static DETAILED_ORGANIZATION_RESPONSE: Model = Model::new(
    "DetailedOrganizationResponse",
    &[
        Field::req("success", Ty::Bool),
        Field::req("message", Ty::Str),
        Field::opt("data", Ty::Nullable(&Ty::Model(&DETAILED_ORGANIZATION))),
    ],
);
