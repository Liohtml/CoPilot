//! Customer provisioning — port of `app/customer_provisioning/` but the
//! provisioning itself.
//!
//! - [`store`]        — `customersmeta` and the default settings
//! - [`settings`]     — the default-settings CRUD
//! - [`edr`]          — the EDR agent install commands
//! - [`decommission`] — tearing a customer down (Wazuh agents and groups,
//!   the Graylog stream and index set, the Grafana organization, the Wazuh
//!   worker and HAProxy, the row)
//! - [`routes`]       — the handlers
//!
//! `POST /provision`, `POST /provision/dashboards` and
//! `POST /provision/wazuh_worker` stay in Python: in the same request they
//! create Grafana dashboards from the dashboard templates under `backend/`
//! (any of the deployment's dashboard families) or the Portainer worker stack
//! from its template, which the Rust image does not carry — the reason
//! `POST /api/grafana/dashboards` and `POST /api/portainer/
//! create-wazuh-customer-stack` stayed there too.

pub mod decommission;
pub mod edr;
pub mod routes;
pub mod settings;
pub mod store;

/// `WazuhDashboard`'s members (what `GET /provision/dashboards` lists).
pub const WAZUH_DASHBOARDS: &[&str] = &[
    "WAZUH_SUMMARY",
    "EDR_WINDOWS_EVENT_LOGS",
    "EDR_USERS_AND_GROUPS",
    "EDR_SYSTEM_SECURITY_AUDIT",
    "EDR_SYSTEM_PROCESSES",
    "EDR_PROCESS_INJECTION",
    "EDR_OPEN_AUDIT",
    "EDR_NETWORK_SCAN",
    "EDR_NETWORK_CONNECTIONS",
    "EDR_MITRE",
    "EDR_FIM",
    "EDR_DOCKER_MONITORING",
    "EDR_DNS_REQUESTS",
    "EDR_DLL_SIDE_LOADING",
    "EDR_COMPLIANCE",
    "EDR_AV_MALWARE_IOC",
    "EDR_AGENT_INVENTORY",
    "EDR_AD_INVENTORY",
];

/// `CustomerSubsctipion`'s values.
pub const SUBSCRIPTIONS: &[&str] = &["Wazuh"];
