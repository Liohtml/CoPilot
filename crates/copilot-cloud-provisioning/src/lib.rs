//! The provisioning of the two cloud integrations that edit the Wazuh
//! manager's `ossec.conf` — ports of `app/integrations/office365/` and
//! `app/integrations/aws/` (`routes`, `services`, `schema`, `utils`).
//!
//! - [`office365`] — `POST /api/office365/provision`: one Microsoft 365
//!   tenant (its `<api_auth>` block on the manager, its Graylog stream; the
//!   customer's index set and Grafana objects shared with its other tenants);
//! - [`graylog`] — the pipeline rules and pipelines both flows keep up to
//!   date on the default Graylog;
//! - [`rollback`] — `_ProvisioningRollback`: what a failed deployment
//!   created, undone newest-first, each failure reported, never fatal.
//!
//! Python hands `ossec.conf` from step to step through a file next to its
//! module; this service keeps it in memory and writes no file (§4).

#![warn(missing_docs)]

pub mod graylog;
pub mod office365;
pub mod rollback;
pub mod routes;

use axum::extract::FromRef;
use copilot_db::schema::TableRequirement;
use copilot_grafana::GrafanaClient;
use copilot_graylog::GraylogClient;
use copilot_wazuh::WazuhState;
use copilot_web::AppContext;

pub use routes::router;

/// What the routes need.
#[derive(Clone)]
pub struct CloudState {
    /// The shared context (database, tokens, connector rows).
    pub ctx: AppContext,
    /// The Graylog client (the default connector).
    pub graylog: GraylogClient,
    /// The Grafana client.
    pub grafana: GrafanaClient,
    /// The Wazuh manager (ossec.conf) and indexer (shards, version).
    pub wazuh: WazuhState,
}

impl FromRef<CloudState> for AppContext {
    fn from_ref(s: &CloudState) -> Self {
        s.ctx.clone()
    }
}

/// The tools a flow uses.
#[derive(Clone, Copy)]
pub struct Tools<'a> {
    /// The shared context.
    pub ctx: &'a AppContext,
    /// Graylog.
    pub graylog: &'a GraylogClient,
    /// Grafana.
    pub grafana: &'a GrafanaClient,
    /// The Wazuh manager and indexer.
    pub wazuh: &'a WazuhState,
}

impl CloudState {
    /// The tools of this state.
    pub fn tools(&self) -> Tools<'_> {
        Tools {
            ctx: &self.ctx,
            graylog: &self.graylog,
            grafana: &self.grafana,
            wazuh: &self.wazuh,
        }
    }
}

/// The columns this crate reads and writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customer_integrations",
        columns: &[
            "customer_code",
            "integration_service_name",
            "instance_name",
            "deployed",
        ],
    },
    TableRequirement {
        table: "customersmeta",
        columns: &[
            "customer_code",
            "customer_meta_grafana_org_id",
            "customer_meta_office365_organization_id",
        ],
    },
    TableRequirement {
        table: "customer_provisioning_default_settings",
        columns: &["grafana_url"],
    },
];

#[cfg(test)]
mod vectors;
