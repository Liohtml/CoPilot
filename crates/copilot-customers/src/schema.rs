//! Port of `app/customers/schema/customers.py` (response side).
//!
//! These are the *response* models (`CustomerOut`, `CustomerMetaOut`): they
//! show whatever a stored row holds, nullable where the table is.

use chrono::NaiveDateTime;
use serde::Serialize;
use serde_json::{Map, Value};

use copilot_web::validate::{IntRules, Loc, StrRules, Validator};

use copilot_core::time::pydantic;
use copilot_db::agents::AgentRow;
use copilot_db::customers::{CustomerMetaRow, CustomerRow};

/// `CustomerOut`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerOut {
    /// Tenant key.
    pub customer_code: String,
    /// Display name.
    pub customer_name: String,
    /// Contact last name.
    pub contact_last_name: Option<String>,
    /// Contact first name.
    pub contact_first_name: Option<String>,
    /// Parent customer.
    pub parent_customer_code: Option<String>,
    /// Phone.
    pub phone: Option<String>,
    /// Address line 1.
    pub address_line1: Option<String>,
    /// Address line 2.
    pub address_line2: Option<String>,
    /// City.
    pub city: Option<String>,
    /// State.
    pub state: Option<String>,
    /// Postal code.
    pub postal_code: Option<String>,
    /// Country.
    pub country: Option<String>,
    /// Customer type.
    pub customer_type: Option<String>,
    /// Logo file name.
    pub logo_file: Option<String>,
    /// Set by the list only (a meta row exists); `null` elsewhere.
    pub is_provisioned: Option<bool>,
}

impl CustomerOut {
    /// Project a row; `is_provisioned` as the route knows it.
    pub fn new(r: CustomerRow, is_provisioned: Option<bool>) -> Self {
        Self {
            customer_code: r.customer_code,
            customer_name: r.customer_name,
            contact_last_name: r.contact_last_name,
            contact_first_name: r.contact_first_name,
            parent_customer_code: r.parent_customer_code,
            phone: r.phone,
            address_line1: r.address_line1,
            address_line2: r.address_line2,
            city: r.city,
            state: r.state,
            postal_code: r.postal_code,
            country: r.country,
            customer_type: r.customer_type,
            logo_file: r.logo_file,
            is_provisioned,
        }
    }
}

/// `CustomerMetaOut`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerMetaOut {
    /// Graylog index set.
    pub customer_meta_graylog_index: String,
    /// Graylog stream.
    pub customer_meta_graylog_stream: String,
    /// Grafana organisation.
    pub customer_meta_grafana_org_id: String,
    /// Wazuh group.
    pub customer_meta_wazuh_group: String,
    /// Index retention.
    pub customer_meta_index_retention: Option<String>,
    /// Wazuh registration port.
    pub customer_meta_wazuh_registration_port: Option<String>,
    /// Wazuh log ingestion port.
    pub customer_meta_wazuh_log_ingestion_port: Option<String>,
    /// Wazuh API port.
    pub customer_meta_wazuh_api_port: Option<String>,
    /// Wazuh auth password (returned as stored, as in Python).
    pub customer_meta_wazuh_auth_password: Option<String>,
    /// Portainer stack.
    pub customer_meta_portainer_stack_id: Option<i64>,
}

impl From<CustomerMetaRow> for CustomerMetaOut {
    fn from(r: CustomerMetaRow) -> Self {
        Self {
            customer_meta_graylog_index: r.customer_meta_graylog_index,
            customer_meta_graylog_stream: r.customer_meta_graylog_stream,
            customer_meta_grafana_org_id: r.customer_meta_grafana_org_id,
            customer_meta_wazuh_group: r.customer_meta_wazuh_group,
            customer_meta_index_retention: r.customer_meta_index_retention,
            customer_meta_wazuh_registration_port: r.customer_meta_wazuh_registration_port,
            customer_meta_wazuh_log_ingestion_port: r.customer_meta_wazuh_log_ingestion_port,
            customer_meta_wazuh_api_port: r.customer_meta_wazuh_api_port,
            customer_meta_wazuh_auth_password: r.customer_meta_wazuh_auth_password,
            customer_meta_portainer_stack_id: r.customer_meta_portainer_stack_id.map(i64::from),
        }
    }
}

/// `AgentModel` of the customer routes (with Wazuh status and quarantine,
/// which drive the UI's ONLINE / Quarantined badges, #956).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentOut {
    /// Primary key.
    pub id: i32,
    /// Operating system.
    pub os: String,
    /// Label.
    pub label: String,
    /// Wazuh last seen.
    #[serde(serialize_with = "pydantic::datetime")]
    pub wazuh_last_seen: NaiveDateTime,
    /// Velociraptor last seen.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub velociraptor_last_seen: Option<NaiveDateTime>,
    /// Velociraptor agent version.
    pub velociraptor_agent_version: Option<String>,
    /// IP address.
    pub ip_address: String,
    /// Wazuh agent id.
    pub agent_id: String,
    /// Hostname.
    pub hostname: String,
    /// Critical asset.
    pub critical_asset: bool,
    /// Velociraptor client id.
    pub velociraptor_id: Option<String>,
    /// Wazuh agent version.
    pub wazuh_agent_version: String,
    /// Tenant.
    pub customer_code: Option<String>,
    /// Wazuh status.
    pub wazuh_agent_status: String,
    /// Quarantined.
    pub quarantined: bool,
}

impl From<AgentRow> for AgentOut {
    fn from(a: AgentRow) -> Self {
        Self {
            id: a.id,
            os: a.os,
            label: a.label,
            wazuh_last_seen: a.wazuh_last_seen,
            velociraptor_last_seen: a.velociraptor_last_seen,
            velociraptor_agent_version: a.velociraptor_agent_version,
            ip_address: a.ip_address,
            agent_id: a.agent_id,
            hostname: a.hostname,
            critical_asset: a.critical_asset,
            velociraptor_id: a.velociraptor_id,
            wazuh_agent_version: a.wazuh_agent_version,
            customer_code: a.customer_code,
            wazuh_agent_status: a.wazuh_agent_status,
            quarantined: a.quarantined,
        }
    }
}

/// `CustomersResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomersResponse {
    /// The customers.
    pub customers: Vec<CustomerOut>,
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
}

/// `CustomerResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerResponse {
    /// The customer.
    pub customer: Option<CustomerOut>,
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
}

/// `CustomerMetaResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerMetaResponse {
    /// The meta row.
    pub customer_meta: Option<CustomerMetaOut>,
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
}

/// `CustomerFullResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerFullResponse {
    /// The customer.
    pub customer: Option<CustomerOut>,
    /// Its meta row, if any.
    pub customer_meta: Option<CustomerMetaOut>,
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
}

/// `AgentsResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentsResponse {
    /// The customer's agents.
    pub agents: Vec<AgentOut>,
    /// Always `true`.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
}

// --- request side ---------------------------------------------------------

/// `CustomerRequestBody`: what creating or updating a customer must send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerRequest {
    /// Tenant key.
    pub customer_code: String,
    /// Display name.
    pub customer_name: String,
    /// Contact last name.
    pub contact_last_name: String,
    /// Contact first name.
    pub contact_first_name: String,
    /// Parent customer.
    pub parent_customer_code: Option<String>,
    /// Phone.
    pub phone: Option<String>,
    /// Address line 1.
    pub address_line1: Option<String>,
    /// Address line 2.
    pub address_line2: Option<String>,
    /// City.
    pub city: Option<String>,
    /// State.
    pub state: Option<String>,
    /// Postal code.
    pub postal_code: Option<String>,
    /// Country.
    pub country: Option<String>,
    /// Customer type.
    pub customer_type: Option<String>,
    /// Logo file name.
    pub logo_file: Option<String>,
    /// Not a column: echoed back in the answer.
    pub is_provisioned: Option<bool>,
}

impl CustomerRequest {
    /// Read the body as Pydantic validates `CustomerRequestBody` (field
    /// order, lax `str` and `bool`).
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let any = StrRules::any();
        Self {
            customer_code: v.req_str(obj, at, "customer_code", any),
            customer_name: v.req_str(obj, at, "customer_name", any),
            contact_last_name: v.req_str(obj, at, "contact_last_name", any),
            contact_first_name: v.req_str(obj, at, "contact_first_name", any),
            parent_customer_code: v.opt_str(obj, at, "parent_customer_code", any),
            phone: v.opt_str(obj, at, "phone", any),
            address_line1: v.opt_str(obj, at, "address_line1", any),
            address_line2: v.opt_str(obj, at, "address_line2", any),
            city: v.opt_str(obj, at, "city", any),
            state: v.opt_str(obj, at, "state", any),
            postal_code: v.opt_str(obj, at, "postal_code", any),
            country: v.opt_str(obj, at, "country", any),
            customer_type: v.opt_str(obj, at, "customer_type", any),
            logo_file: v.opt_str(obj, at, "logo_file", any),
            is_provisioned: v.opt_bool(obj, at, "is_provisioned"),
        }
    }

    /// The fourteen columns `model_dump(exclude={"is_provisioned"})` sets,
    /// in the model's order.
    pub fn columns(&self) -> [(&'static str, Option<&str>); 14] {
        [
            ("customer_code", Some(self.customer_code.as_str())),
            ("customer_name", Some(self.customer_name.as_str())),
            ("contact_last_name", Some(self.contact_last_name.as_str())),
            ("contact_first_name", Some(self.contact_first_name.as_str())),
            ("parent_customer_code", self.parent_customer_code.as_deref()),
            ("phone", self.phone.as_deref()),
            ("address_line1", self.address_line1.as_deref()),
            ("address_line2", self.address_line2.as_deref()),
            ("city", self.city.as_deref()),
            ("state", self.state.as_deref()),
            ("postal_code", self.postal_code.as_deref()),
            ("country", self.country.as_deref()),
            ("customer_type", self.customer_type.as_deref()),
            ("logo_file", self.logo_file.as_deref()),
        ]
    }
}

impl From<&CustomerRequest> for CustomerOut {
    /// `CustomerOut.model_validate(customer)`: the request as sent.
    fn from(r: &CustomerRequest) -> Self {
        Self {
            customer_code: r.customer_code.clone(),
            customer_name: r.customer_name.clone(),
            contact_last_name: Some(r.contact_last_name.clone()),
            contact_first_name: Some(r.contact_first_name.clone()),
            parent_customer_code: r.parent_customer_code.clone(),
            phone: r.phone.clone(),
            address_line1: r.address_line1.clone(),
            address_line2: r.address_line2.clone(),
            city: r.city.clone(),
            state: r.state.clone(),
            postal_code: r.postal_code.clone(),
            country: r.country.clone(),
            customer_type: r.customer_type.clone(),
            logo_file: r.logo_file.clone(),
            is_provisioned: r.is_provisioned,
        }
    }
}

/// `CustomerMetaRequestBody`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerMetaRequest {
    /// The nine required strings, in the model's order.
    pub strings: [(&'static str, String); 9],
    /// `customer_meta_portainer_stack_id`: `None` when absent, `Some(None)`
    /// for an explicit `null` (`exclude_unset` tells them apart).
    pub portainer_stack_id: Option<Option<i64>>,
}

/// The nine required string fields of `CustomerMetaRequestBody`.
pub const META_STRING_FIELDS: [&str; 9] = [
    "customer_meta_graylog_index",
    "customer_meta_graylog_stream",
    "customer_meta_grafana_org_id",
    "customer_meta_wazuh_group",
    "customer_meta_index_retention",
    "customer_meta_wazuh_registration_port",
    "customer_meta_wazuh_log_ingestion_port",
    "customer_meta_wazuh_api_port",
    "customer_meta_wazuh_auth_password",
];

impl CustomerMetaRequest {
    /// Read the body as Pydantic validates `CustomerMetaRequestBody`.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let strings = META_STRING_FIELDS.map(|f| (f, v.req_str(obj, at, f, StrRules::any())));
        let portainer_stack_id = obj
            .contains_key("customer_meta_portainer_stack_id")
            .then(|| {
                v.opt_int(
                    obj,
                    at,
                    "customer_meta_portainer_stack_id",
                    IntRules::default(),
                )
            });
        Self {
            strings,
            portainer_stack_id,
        }
    }

    fn string(&self, i: usize) -> String {
        self.strings[i].1.clone()
    }

    /// `customer_meta_portainer_stack_id` (`None` when absent or `null`).
    pub fn stack_id(&self) -> Option<i64> {
        self.portainer_stack_id.flatten()
    }
}

impl From<&CustomerMetaRequest> for CustomerMetaOut {
    /// `CustomerMetaOut.model_validate(customer_meta)`: the request as sent.
    fn from(r: &CustomerMetaRequest) -> Self {
        Self {
            customer_meta_graylog_index: r.string(0),
            customer_meta_graylog_stream: r.string(1),
            customer_meta_grafana_org_id: r.string(2),
            customer_meta_wazuh_group: r.string(3),
            customer_meta_index_retention: Some(r.string(4)),
            customer_meta_wazuh_registration_port: Some(r.string(5)),
            customer_meta_wazuh_log_ingestion_port: Some(r.string(6)),
            customer_meta_wazuh_api_port: Some(r.string(7)),
            customer_meta_wazuh_auth_password: Some(r.string(8)),
            customer_meta_portainer_stack_id: r.stack_id(),
        }
    }
}

/// `DeleteCustomerResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteCustomerResponse {
    /// Always `true`.
    pub success: bool,
    /// `Customer '…' deleted successfully`.
    pub message: String,
}
