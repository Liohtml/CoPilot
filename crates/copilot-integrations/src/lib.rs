//! The integrations core — ports of three Python modules that share one
//! shape (a catalog, a customer's activations, their auth keys and the
//! provisioned resources' metadata):
//!
//! - [`integrations`] — `app/integrations/routes.py` (`/api/integrations`):
//!   the catalog, a customer's integrations and their metadata, creation,
//!   key updates, the metadata repair routes, the auth-key lookup and the
//!   delete with its decommission (the Graylog stream and index set, the
//!   Grafana folder and datasource, an Office365 tenant's `<api_auth>` block
//!   on the Wazuh manager, [`office365`]), multi-instance included;
//! - [`alert_settings`] — `app/integrations/alert_creation_settings/`
//!   (mounted under `/api/api/v1/alert_settings`: the router's prefix is
//!   itself `/api/v1/...`), keyed by customer *name* and code;
//! - [`network_connectors`] — `app/network_connectors/`
//!   (`/api/network_connectors`), the integrations' twin on the
//!   `network_connectors_*` tables.
//!
//! [`etree`] is the part of ElementTree the Office365 decommission edits
//! `ossec.conf` with; [`table_model`] the catalog `PUT`s' SQLModel table
//! bodies; [`sql`] the statement helpers the three share.
//!
//! What stays in Python: the delete of a *deployed* AWS instance (its
//! `ossec.conf` edit reconciles buckets under an in-process lock that AWS
//! provisioning, still Python, takes too — two processes could interleave),
//! handed over whole; the Office365 and AWS provisioning. The network
//! connectors' and the other integrations' provisioning routes are
//! `copilot-integration-provisioning`'s.

#![warn(missing_docs)]

pub mod alert_settings;
pub mod etree;
pub mod integrations;
pub mod network_connectors;
pub mod office365;
pub mod sql;
pub mod table_model;

use axum::Router;
use axum::extract::FromRef;
use copilot_db::schema::TableRequirement;
use copilot_gateway::LegacyProxy;
use copilot_grafana::GrafanaClient;
use copilot_graylog::GraylogClient;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

/// What the three routers need.
#[derive(Clone)]
pub struct IntegrationsState {
    /// The shared context (database, tokens, connector rows).
    pub ctx: AppContext,
    /// The Graylog client (the default connector, as the delete uses it).
    pub graylog: GraylogClient,
    /// The Grafana client (the folder and datasource of a deployed
    /// integration).
    pub grafana: GrafanaClient,
    /// The Wazuh manager client (an Office365 tenant's `<api_auth>` block).
    pub wazuh: WazuhState,
    /// The Python backend, which deletes a deployed AWS instance.
    pub legacy: Option<LegacyProxy>,
}

impl FromRef<IntegrationsState> for AppContext {
    fn from_ref(s: &IntegrationsState) -> Self {
        s.ctx.clone()
    }
}

/// Every route of the three modules, by full path.
pub fn router(state: IntegrationsState) -> Router {
    let legacy = state.legacy.clone();
    Router::new()
        .merge(integrations::routes::router(state.clone()))
        .merge(alert_settings::routes::router(state.clone()))
        .merge(network_connectors::routes::router(state))
        .route_layer(axum::middleware::from_fn_with_state(
            legacy,
            copilot_wazuh::decoded_slash_to_legacy,
        ))
}

/// The columns this crate reads and writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "available_integrations",
        columns: &[
            "id",
            "integration_name",
            "description",
            "integration_details",
        ],
    },
    TableRequirement {
        table: "available_integrations_auth_keys",
        columns: &["id", "integration_id", "integration_name", "auth_key_name"],
    },
    TableRequirement {
        table: "customer_integrations",
        columns: &[
            "id",
            "customer_code",
            "customer_name",
            "integration_service_id",
            "integration_service_name",
            "instance_name",
            "deployed",
        ],
    },
    TableRequirement {
        table: "integration_services",
        columns: &["id", "service_name", "auth_type"],
    },
    TableRequirement {
        table: "integration_subscriptions",
        columns: &["id", "customer_id", "integration_service_id"],
    },
    TableRequirement {
        table: "integration_configs",
        columns: &["id", "integration_service_id", "config_key", "config_value"],
    },
    TableRequirement {
        table: "integration_auth_keys",
        columns: &["id", "subscription_id", "auth_key_name", "auth_value"],
    },
    TableRequirement {
        table: "customer_integrations_meta",
        columns: integrations::store::META_COLUMNS,
    },
    TableRequirement {
        table: "custom_alert_creation_settings",
        columns: alert_settings::store::SETTINGS_COLUMNS,
    },
    TableRequirement {
        table: "custom_alert_creation_event_order",
        columns: &["id", "alert_creation_settings_id", "order_label"],
    },
    TableRequirement {
        table: "custom_alert_creation_event_config",
        columns: &["id", "event_order_id", "event_id", "field", "value"],
    },
    TableRequirement {
        table: "custom_alert_creation_condition",
        columns: &["id", "event_order_id"],
    },
    TableRequirement {
        table: "available_network_connectors",
        columns: &[
            "id",
            "network_connector_name",
            "description",
            "network_connector_details",
        ],
    },
    TableRequirement {
        table: "available_network_connectors_keys",
        columns: &[
            "id",
            "network_connector_id",
            "network_connector_name",
            "auth_key_name",
        ],
    },
    TableRequirement {
        table: "customer_network_connectors",
        columns: &[
            "id",
            "customer_code",
            "customer_name",
            "network_connector_service_id",
            "network_connector_service_name",
            "deployed",
        ],
    },
    TableRequirement {
        table: "network_connectors_services",
        columns: &["id", "service_name", "auth_type"],
    },
    TableRequirement {
        table: "network_connectors_subscriptions",
        columns: &["id", "customer_id", "network_connectors_service_id"],
    },
    TableRequirement {
        table: "network_connectors_configs",
        columns: &[
            "id",
            "network_connector_service_id",
            "config_key",
            "config_value",
        ],
    },
    TableRequirement {
        table: "network_connectors_keys",
        columns: &["id", "subscription_id", "auth_key_name", "auth_value"],
    },
    TableRequirement {
        table: "customer_network_connectors_meta",
        columns: network_connectors::store::META_COLUMNS,
    },
    TableRequirement {
        table: "customersmeta",
        columns: &[
            "id",
            "customer_code",
            "customer_meta_office365_organization_id",
        ],
    },
    TableRequirement {
        table: "customers",
        columns: &["id", "customer_code"],
    },
];
