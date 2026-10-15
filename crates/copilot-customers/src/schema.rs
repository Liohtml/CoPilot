//! Port of `app/customers/schema/customers.py` (response side).
//!
//! These are the *response* models (`CustomerOut`, `CustomerMetaOut`): they
//! show whatever a stored row holds, nullable where the table is.

use chrono::NaiveDateTime;
use serde::Serialize;

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
    pub customer_meta_portainer_stack_id: Option<i32>,
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
            customer_meta_portainer_stack_id: r.customer_meta_portainer_stack_id,
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
