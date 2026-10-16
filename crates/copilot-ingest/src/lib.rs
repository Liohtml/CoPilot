//! # copilot-ingest — alert creation and ingest
//!
//! Port of what `app/incidents/routes/incident_alert.py`
//! (`/api/incidents/alerts`) does besides the exclusion-rule CRUD
//! (`copilot-incidents`), and of the Wazuh-indexer reads of
//! `/api/incidents/db_operations`:
//!
//! | Route | Guard | What |
//! |---|---|---|
//! | `GET /index/names` | admin/analyst | the `gl-events*` indices |
//! | `GET /alerts/not-created` | admin/analyst | Graylog events without a CoPilot alert (Python's answer is a 500: its handler returns a tuple) |
//! | `POST /alert/details`, `/alert/timeline` | admin/analyst | one document, its process timeline (a threshold alert's replay) |
//! | `POST /create/manual` | admin/analyst | an alert from one document ([`create`]) |
//! | `POST /create/auto` | admin/analyst | the Graylog-event collector ([`collect`]) |
//! | `POST /create/threshold` | `graylog` header | a Graylog threshold event ([`threshold`]) |
//! | `POST /create/velo-sigma` | `velociraptor` header | the Velociraptor Sigma ingest ([`sigma::ingest`]) |
//! | `GET /alert/{id}/velo-sigma/exclusion-draft`, `POST …/exclusion-dry-run` | admin/analyst, the alert's tags and customer | in-context exclusion rules ([`sigma::draft`]) |
//! | `GET /db_operations/available-source/{index}`, `/available-indices/{source}`, `/mappings/fields-assets-title-and-timefield` | admin/analyst | the source dictionary's indexer lookups ([`indices`]) |
//!
//! and the `invoke_alert_creation_collect` job (hand-over, [`job_spec`]).
//!
//! The indexer is `copilot_wazuh::es` (elasticsearch-py 7.10.1's requests);
//! Talon is `copilot-talon`'s client; the SLA clocks are `copilot-sla`'s
//! recorder; `alert_created` goes out through `ctx.notifications`.

#![warn(missing_docs)]

pub mod collect;
pub mod create;
pub mod es;
pub mod indices;
pub mod notify;
pub mod py;
pub mod routes;
pub mod schema;
pub mod sigma;
pub mod source;
pub mod threshold;

use std::sync::Arc;
use std::time::Duration;

use copilot_core::ingest_env::IngestEnv;
use copilot_db::schema::TableRequirement;
use copilot_gateway::LegacyProxy;
use copilot_scheduler::{JobError, JobSpec};
use copilot_talon::TalonConnector;
use copilot_upstream::http::PyHttp;
use copilot_wazuh::es::EsHttp;
use copilot_web::AppContext;

pub use routes::router;

/// `invoke_alert_creation_collect`'s job id (`handover.py`'s
/// `RUST_CAPABLE_JOBS`).
pub const INVOKE_ALERT_CREATION_COLLECT: &str = "invoke_alert_creation_collect";

/// The ingest's dependencies.
#[derive(Clone)]
pub struct IngestState {
    /// Database, connectors, notifications.
    pub ctx: AppContext,
    /// The Wazuh indexer's HTTP stack.
    pub es: EsHttp,
    /// Talon (the AI-analyst auto-trigger).
    pub talon: TalonConnector,
    /// `requests` towards Shuffle (`verify=False`, 60 s).
    pub shuffle: PyHttp,
    /// httpx towards the MDR server (30 s).
    pub mdr: reqwest::Client,
    /// The environment the ingest reads.
    pub env: Arc<IngestEnv>,
    /// The Python backend (a path with an encoded `/` is its).
    pub legacy: Option<LegacyProxy>,
}

impl std::fmt::Debug for IngestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestState").finish_non_exhaustive()
    }
}

impl IngestState {
    /// Build the clients.
    pub fn new(
        ctx: AppContext,
        es: EsHttp,
        talon: TalonConnector,
        env: IngestEnv,
        legacy: Option<LegacyProxy>,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            ctx,
            es,
            talon,
            shuffle: PyHttp::new(Duration::from_secs(60), false)?,
            mdr: notify::mdr_client()?,
            env: Arc::new(env),
            legacy,
        })
    }
}

impl axum::extract::FromRef<IngestState> for AppContext {
    fn from_ref(s: &IngestState) -> AppContext {
        s.ctx.clone()
    }
}

/// The `invoke_alert_creation_collect` job: `create_alert_auto_route`, then
/// the function's own `last_success` stamp (a manual run included; the
/// runner adds its own for a scheduled run, as Python's listener does).
pub fn job_spec(st: &IngestState) -> JobSpec {
    let st = Arc::new(st.clone());
    JobSpec::new(INVOKE_ALERT_CREATION_COLLECT, 5, move || {
        let st = Arc::clone(&st);
        async move {
            tracing::info!(target: "copilot::ingest", "Invoking alert creation collection via scheduler...");
            collect::create_alerts_auto(&st)
                .await
                .map_err(|e| JobError(e.py_str()))?;
            copilot_db::scheduler::stamp_last_success(&st.ctx.db, INVOKE_ALERT_CREATION_COLLECT)
                .await
                .map_err(|e| JobError(e.to_string()))?;
            Ok(())
        }
    })
}

/// The columns this crate reads or writes beyond `copilot-incidents`'.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "incident_management_threshold_alert_metadata",
        columns: &[
            "id",
            "alert_id",
            "event_definition_id",
            "replay_query",
            "timerange_start",
            "timerange_end",
            "group_by_fields",
            "source_streams",
            "source",
            "resolved_index_name",
            "resolved_index_id",
        ],
    },
    TableRequirement {
        table: "custom_alert_creation_settings",
        columns: &[
            "id",
            "customer_code",
            "customer_name",
            "office365_organization_id",
        ],
    },
    TableRequirement {
        table: "agents",
        columns: &["agent_id", "hostname", "velociraptor_id", "customer_code"],
    },
    TableRequirement {
        table: "customer_integrations",
        columns: &[
            "id",
            "customer_code",
            "customer_name",
            "integration_service_name",
            "deployed",
        ],
    },
    TableRequirement {
        table: "integration_subscriptions",
        columns: &["id", "customer_id", "integration_service_id"],
    },
    TableRequirement {
        table: "integration_services",
        columns: &["id", "service_name"],
    },
    TableRequirement {
        table: "integration_auth_keys",
        columns: &["id", "subscription_id", "auth_key_name", "auth_value"],
    },
];
