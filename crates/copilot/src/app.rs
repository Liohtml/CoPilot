//! Wiring: configuration → dependencies → router.
//!
//! ```text
//!                      ┌─────────────── copilot (Rust, :5000) ───────────────┐
//! frontend / portal ──►│ /api/ai_analyst/*  → copilot-ai-analyst             │
//!                      │ /api/customer_portal/* (but /sla)                    │
//!                      │                    → copilot-customer-portal         │
//!                      │ GET /api/customers/*   → copilot-customers           │
//!                      │ GET /api/healthcheck/* → copilot-healthchecks        │
//!                      │ /api/version/*, /api/audit/* → copilot-platform      │
//!                      │ /api/auth/token*, /refresh, /2fa/*, users, /login,   │
//!                      │ /register, /reset-password*, /me/customers,          │
//!                      │ /sso/*, /passkey/*, /security/*                      │
//!                      │                    → copilot-identity                │
//!                      │ GET /api/scheduler/*, run/start/pause                │
//!                      │                    → copilot-scheduler (+ its jobs)  │
//!                      │ /api/notifications/*, notification routes, Shuffle   │
//!                      │ integrations, dispatch log, channel catalog          │
//!                      │                    → copilot-notifications ───────────► webhook, Teams,
//!                      │ (every module emits in-process: DispatchingSink)     │   Resend, Shuffle
//!                      │ /api/soc_management/* (but GET /report),             │
//!                      │ /api/customer_portal/sla/*                           │
//!                      │                    → copilot-soc-management          │
//!                      │ /api/agent_data_store/*, the incidents' MinIO routes │
//!                      │                    → copilot-objectstore ────────────────► MinIO :9000
//!                      │ /api/siem/dashboards, /event_sources, /events        │
//!                      │                    → copilot-siem ───────────────────────► Wazuh indexer
//!                      │ /api/threat_intel/*                                  │
//!                      │                    → copilot-threat-intel ───────────► SOCFortress, VirusTotal,
//!                      │                                                      │   api.first.org
//!                      │ /api/vulnerabilities/*, /api/sca/*,                  │
//!                      │ /api/syscollector/* → copilot-agent-reports          │
//!                      │ /api/monitoring_alert/*                              │
//!                      │                    → copilot-monitoring-alerts ──────► Graylog, Event Shipper
//!                      │ /api/copilot_searches/* → copilot-searches ──────────► GitHub, Wazuh, Graylog
//! Talon (MCP tools) ──►│ /api/talon/*       → copilot-talon ───────────────────► Talon :3100
//!                      │ /_copilot/health                                     │
//!                      │ anything else      → copilot-gateway ─────────────────► Python backend
//!                      └──────────────────────────────────────────────────────┘
//! ```

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use copilot_agent_reports::AgentReportsState;
use copilot_agents::AgentsState;
use copilot_auth::{Fernet, JwtCodec};
use copilot_connectors::{ConnectorsState, Verifiers};
use copilot_core::config::CopilotConfig;
use copilot_core::notify::SharedNotificationSink;
use copilot_db::Db;
use copilot_db::audit::DbAuditSink;
use copilot_db::connectors::ConnectorCache;
use copilot_db::schema::{self, TableRequirement};
use copilot_gateway::LegacyProxy;
use copilot_grafana::{GrafanaClient, GrafanaState};
use copilot_graylog::{GraylogClient, GraylogState};
use copilot_identity::{IdentityState, SsoClient, TwoFactorLimiter};
use copilot_influxdb::{InfluxClient, InfluxState};
use copilot_ingest::IngestState;
use copilot_notifications::{Dispatcher, DispatchingSink, NotificationsState};
use copilot_objectstore::{DataStoreState, ObjectStore};
use copilot_platform::PlatformState;
use copilot_platform::version::VersionChecker;
use copilot_portainer::{PortainerClient, PortainerState};
use copilot_scheduler::{OptIn, Scheduler, SchedulerState};
use copilot_talon::{TalonConnector, TalonState};
use copilot_velociraptor::VelociraptorClient;
use copilot_waf::{WafClient, WafEnv, WafState};
use copilot_wazuh::WazuhState;
use copilot_web::middleware::{compression, cors, log_handled_errors, security_headers};
use copilot_web::{ApiError, AppContext, AppDeps};
use copilot_webauthn::RelyingParty;

/// Route prefixes this build answers itself. Everything else is proxied.
/// A method prefix (`GET /api/customers`) means only that method is ported;
/// other methods on those paths go to Python.
pub const PORTED_PREFIXES: &[&str] = &[
    "/api/ai_analyst",
    "/api/talon",
    // The whole portal module (copilot-customer-portal): AI reports, settings
    // and branding, the Overview and dashboard counters, agents, `/me`; the
    // SLA page (below) is copilot-soc-management's.
    "/api/customer_portal",
    "GET /api/customers",
    "GET /api/healthcheck",
    "/api/version",
    "/api/audit",
    "/api/auth/token",
    "GET /api/auth/refresh",
    "/api/auth/2fa",
    "/api/auth/register",
    "POST /api/auth/login",
    "/api/auth/users",
    "/api/auth/reset-password",
    "DELETE /api/auth/delete",
    "GET /api/auth/me/customers",
    "/api/auth/sso",
    "/api/auth/passkey",
    "/api/auth/security",
    // /api/incidents/db_operations but POST /case-report-template/default-template
    // (the templates are files on the Python host), which falls through to the
    // legacy backend; POST /case/notification is copilot-shuffle's. The MinIO routes
    // (case files, report templates, DELETE /case/{id}) are copilot-objectstore's,
    // the Wazuh-indexer reads (/available-source, /available-indices, /mappings)
    // copilot-ingest's.
    "/api/incidents/db_operations",
    // The template CRUD; the library and /suggest stay in Python.
    "/api/incidents/case_templates",
    "/api/incidents/tag_access",
    // /api/incidents/alerts: the Velociraptor Sigma exclusion rules (CRUD and
    // toggle, copilot-incidents), and alert creation and ingest (copilot-ingest):
    // the indexer and Graylog-event alerts, /create/threshold, the Sigma ingest,
    // the exclusion draft and dry-run.
    "/api/incidents/alerts",
    // The CSV case exports; the DOCX and PDF reports stay in Python.
    "POST /api/incidents/report/generate-report-csv",
    // The report list, the visibility switch, download and delete (GET "",
    // PATCH /{id}/visibility, GET /{id}/download, DELETE /{id}); generation
    // (the PDF renderer) stays in Python.
    "GET /api/incidents/customer_reports",
    "PATCH /api/incidents/customer_reports",
    "DELETE /api/incidents/customer_reports",
    "GET /api/scheduler",
    "POST /api/scheduler/jobs/run",
    "POST /api/scheduler/start",
    "POST /api/scheduler/pause",
    "/api/notifications",
    "/api/notification_channels",
    "/api/internal_notification_routes",
    "/api/customers/{customer_code}/notification_routes",
    "/api/customers/{customer_code}/notification_dispatch_log",
    "/api/customers/{customer_code}/shuffle_integrations",
    // The connector list, rows, updates and verification; a connector whose
    // tool has no Rust verifier is updated and verified by Python, and the YAML
    // upload (a file on the Python host) stays there.
    "GET /api/connectors",
    "PUT /api/connectors",
    "POST /api/connectors/verify",
    // The Wazuh indexer: every route of its three routers.
    "/api/alerts",
    "/api/wazuh_indexer",
    "/api/snapshots",
    // The Wazuh manager: rules and rule files (the upload included), groups,
    // the six MITRE listings and the restart; /rule/disabled|disable|enable
    // (no `disabledrule` table), /rule/exclude, the Atomic Red Team routes and
    // the two MITRE alert searches stay in Python.
    "/api/wazuh_manager/rules",
    "/api/wazuh_manager/groups",
    "GET /api/wazuh_manager/mitre/groups",
    "GET /api/wazuh_manager/mitre/mitigations",
    "GET /api/wazuh_manager/mitre/references",
    "GET /api/wazuh_manager/mitre/software",
    "GET /api/wazuh_manager/mitre/tactics",
    "GET /api/wazuh_manager/mitre/techniques",
    "POST /api/wazuh_manager/management/restart",
    // The Graylog connector (copilot-graylog); `POST /api/graylog/invoke`,
    // the active-response webhook, is copilot-response's (below).
    "GET /api/graylog/indices",
    "GET /api/graylog/inputs",
    "/api/graylog/event",
    "GET /api/graylog/url_whitelist",
    "DELETE /api/graylog/index",
    "POST /api/graylog/input",
    "POST /api/graylog/stream",
    "GET /api/graylog/messages",
    "GET /api/graylog/metrics",
    "GET /api/graylog/event_notifications",
    "GET /api/graylog/streams",
    "GET /api/graylog/pipeline",
    "POST /api/graylog/receiver",
    // The InfluxDB connector (copilot-influxdb): alerts and metrics.
    "GET /api/influxdb",
    // The Grafana connector (copilot-grafana): the reporting reads and iframe
    // links, adding a user to an org. `POST /api/reporting/generate-report`
    // (Playwright) stays in Python.
    "GET /api/reporting",
    "POST /api/reporting/generate_iframe_links",
    "POST /api/user/user/organization/add",
    // Dashboard provisioning (copilot-grafana-dashboards, the templates
    // compiled in from backend/); its customer-provisioning twin
    // `POST /api/customer_provisioning/provision/dashboards` is below.
    "POST /api/grafana/dashboards",
    // The Portainer connector (copilot-portainer) but
    // `POST /api/portainer/create-wazuh-customer-stack` (Wazuh, provisioning).
    "GET /api/portainer",
    "POST /api/portainer/start-wazuh-customer-stack",
    "POST /api/portainer/stop-wazuh-customer-stack",
    "POST /api/portainer/update-customer-stack-id",
    "DELETE /api/portainer/delete-wazuh-customer-stack",
    // SOC Management but GET /report (the PDF operations report: matplotlib
    // charts and wkhtmltopdf), which falls through to the legacy backend.
    "/api/soc_management",
    "/api/customer_portal/sla",
    // The customer WAF (copilot-waf).
    "/api/customer_waf",
    // The monitoring-alert catalog (copilot-monitoring-alerts; the two WAF
    // alerts through copilot-waf).
    "/api/monitoring_alert",
    // Stack provisioning (copilot-provisioning): the content packs and the
    // InfluxDB checks, and network-connector decommissioning; the Fortinet /
    // SonicWall / SentinelOne provisioning is copilot-integration-provisioning's.
    "GET /api/stack_provisioning/graylog/available/content_packs",
    "POST /api/stack_provisioning/graylog/provision/content_pack",
    "POST /api/stack_provisioning/graylog/provision/fortinet",
    "POST /api/stack_provisioning/graylog/provision/sonicwall",
    "POST /api/stack_provisioning/graylog/provision/sentinelone",
    "/api/stack_provisioning/influxdb",
    "/api/stack_decommissioning",
    // Customer provisioning (copilot-provisioning; `POST /provision/dashboards`
    // is copilot-grafana-dashboards') but `POST /provision` and
    // `POST /provision/wazuh_worker` (Grafana dashboards and the Portainer
    // stack in one request), which fall through.
    "/api/customer_provisioning",
    // The agents router (copilot-agents, on copilot-velociraptor's client).
    "/api/agents",
    // The Velociraptor connector (copilot-velociraptor), its MinIO collections
    // (`POST /api/artifacts/collect`, `…/collect/file/agent/{agent_id}`) included.
    "/api/artifacts",
    "/api/flows",
    // The MinIO data store (copilot-objectstore): the upload and the agents'
    // Velociraptor artifact files.
    "/api/agent_data_store",
    // The integrations core (copilot-integrations): the generic integrations
    // system (its 14 routes; the delete of a deployed AWS instance is handed to
    // Python, as is every integration's provisioning), the alert creation
    // settings (mounted under /api/api/v1) and the network connectors.
    "/api/integrations/available_integrations",
    "/api/integrations/customer_integrations",
    "/api/integrations/customer_integrations_meta",
    "/api/integrations/create_integration",
    "/api/integrations/create_integration_meta",
    "/api/integrations/update_integration",
    "/api/integrations/delete_integration",
    "/api/integrations/integration_customer",
    "/api/integrations/meta_auto",
    "/api/integrations/update_meta_auto",
    "/api/api/v1/alert_settings",
    "/api/network_connectors",
    // The integrations' provisioning (copilot-integration-provisioning; the
    // scheduler jobs handed to Python) but CrowdStrike, Defender for Endpoint
    // and Bitdefender (collector files on the Python host), Office365 and AWS.
    "POST /api/huntress/provision",
    "POST /api/darktrace/provision",
    "POST /api/duo/provision",
    "POST /api/cato/provision",
    "POST /api/carbonblack/provision",
    "POST /api/mimecast/provision",
    "POST /api/sap_siem/provision",
    "POST /api/socfortress_mdr/provision",
    // SIEM (copilot-siem): dashboards (built-in and custom templates, panel
    // data), event sources and the event search.
    "/api/siem/dashboards",
    "/api/siem/event_sources",
    "/api/siem/events",
    // Threat intel (copilot-threat-intel): EPSS, SOCFortress intel and AI,
    // the process-name analysis, VirusTotal.
    "/api/threat_intel",
    // The response routes (copilot-response): the Wazuh active response and
    // its Graylog webhook.
    "/api/active_response",
    "POST /api/graylog/invoke",
    // Sysmon configs but `POST /upload` (ElementTree's XML validation).
    "GET /api/sysmon_config",
    "POST /api/sysmon_config/deploy",
    // CoPilot Actions: the inventory and the invoke.
    "/api/copilot_action",
    // The Shuffle connector (copilot-shuffle), and its case notification.
    "/api/workflows",
    "/api/shuffle",
    "POST /api/incidents/db_operations/case/notification",
    // The agents' reports (copilot-agent-reports): vulnerabilities, SCA and
    // the syscollector packages.
    "/api/vulnerabilities",
    "/api/sca",
    "/api/syscollector",
    // The OpenCTI and Cortex connectors (copilot-intel-connectors).
    "/api/opencti",
    "/api/analyzers",
    // The SOCFortress UBA connector (copilot-uba).
    "/api/uba",
    // The Detections Catalog and CoPilot Searches (copilot-searches): every
    // route of the module.
    "/api/copilot_searches",
    // The integration modules (copilot-integration-modules): the Huntress,
    // Mimecast, Duo, Cato and SAP SIEM collections and the SAP SIEM analyses,
    // and of /api/mimecast exactly these two routes (`/provision` and the
    // `/invoke/scheduler/*` routes, which add APScheduler jobs, are not
    // these).
    "/api/integrations/modules",
    "POST /api/mimecast/invoke",
    "POST /api/mimecast/ttp/urls",
    // The licence (copilot-license) and the error log (copilot-status).
    "/api/license",
    "/api/logs",
    // The sidebar's status panel (copilot-status).
    "/api/status",
    // This process's request timing, runtime lag and query metrics
    // (copilot-status).
    "/api/performance",
    // Microsoft Patch Tuesday (copilot-patch-tuesday): MSRC, EPSS and KEV.
    "/api/patch-tuesday",
    // CoPilot MCP (copilot-mcp): the servers, their questions and the query.
    "/api/copilot_mcp",
    // The Sublime connector (copilot-sublime): the alert webhook and the
    // stored alerts.
    "/api/sublime",
];

/// While the Python backend can still write `connectors`, its cache
/// invalidations cannot reach this process; cap how stale a row may get.
pub const CONNECTOR_TTL_WITH_LEGACY: Duration = Duration::from_secs(60);

/// Every column this build reads or writes.
pub fn schema_requirements() -> Vec<TableRequirement> {
    let mut all = schema::CORE_REQUIREMENTS.to_vec();
    all.extend_from_slice(copilot_db::ai_analyst::REQUIREMENTS);
    all.extend_from_slice(copilot_db::customer_portal::REQUIREMENTS);
    all.extend_from_slice(copilot_db::customers::REQUIREMENTS);
    all.extend_from_slice(copilot_db::agents::REQUIREMENTS);
    all.extend_from_slice(copilot_db::totp::REQUIREMENTS);
    all.extend_from_slice(copilot_db::users::REQUIREMENTS);
    all.extend_from_slice(copilot_db::sso::REQUIREMENTS);
    all.extend_from_slice(copilot_db::passkeys::REQUIREMENTS);
    all.extend_from_slice(copilot_db::security::REQUIREMENTS);
    all.extend_from_slice(copilot_db::branding::REQUIREMENTS);
    all.extend_from_slice(copilot_customer_portal::REQUIREMENTS);
    all.extend_from_slice(copilot_incidents::REQUIREMENTS);
    all.extend_from_slice(copilot_ingest::REQUIREMENTS);
    all.extend_from_slice(copilot_sla::REQUIREMENTS);
    all.extend_from_slice(copilot_soc_management::REQUIREMENTS);
    all.extend_from_slice(copilot_notifications::db::REQUIREMENTS);
    all.extend_from_slice(copilot_connectors::REQUIREMENTS);
    all.extend_from_slice(copilot_wazuh::REQUIREMENTS);
    all.extend_from_slice(copilot_portainer::REQUIREMENTS);
    all.extend_from_slice(copilot_waf::REQUIREMENTS);
    all.extend_from_slice(copilot_provisioning::REQUIREMENTS);
    all.extend_from_slice(copilot_integration_provisioning::REQUIREMENTS);
    all.extend_from_slice(copilot_agents::REQUIREMENTS);
    all.extend_from_slice(copilot_velociraptor::REQUIREMENTS);
    all.extend_from_slice(copilot_objectstore::REQUIREMENTS);
    all.extend_from_slice(copilot_incidents::datastore::REQUIREMENTS);
    all.extend_from_slice(copilot_integrations::REQUIREMENTS);
    all.extend_from_slice(copilot_siem::REQUIREMENTS);
    all.extend_from_slice(copilot_threat_intel::REQUIREMENTS);
    all.extend_from_slice(copilot_searches::REQUIREMENTS);
    all.extend(copilot_agent_reports::requirements());
    all.extend_from_slice(copilot_uba::REQUIREMENTS);
    all.extend_from_slice(copilot_integration_modules::REQUIREMENTS);
    all.extend_from_slice(copilot_license::REQUIREMENTS);
    all.extend_from_slice(copilot_status::REQUIREMENTS);
    all.extend_from_slice(copilot_sublime::REQUIREMENTS);
    all.push(TableRequirement {
        table: "audit_log",
        columns: &[
            "id",
            "timestamp",
            "actor_user_id",
            "actor_username",
            "customer_code",
            "action",
            "entity_type",
            "entity_id",
            "result",
            "old_value",
            "new_value",
            "source_ip",
            "details",
        ],
    });
    all.push(TableRequirement {
        table: "scheduled_job_metadata",
        columns: &[
            "id",
            "job_id",
            "last_success",
            "time_interval",
            "extra_data",
            "enabled",
            "job_description",
        ],
    });
    // `apscheduler_jobs` is APScheduler's own table, created by the Python
    // scheduler at its first start rather than by Alembic: the Scheduler
    // routes read it when it exists and let Python answer until then.
    all
}

/// The assembled application.
pub struct App {
    /// Shared dependencies.
    pub ctx: AppContext,
    /// Talon connector (also used by the palace jobs).
    pub talon: TalonConnector,
    /// GitHub release lookup for `/api/version/check`.
    pub version: VersionChecker,
    /// Login and 2FA state (the TOTP key, the brute-force counter).
    pub identity: IdentityState,
    /// Notification dispatch (routes and the in-process sink).
    pub dispatcher: Dispatcher,
    /// Legacy backend, if configured.
    pub legacy: Option<LegacyProxy>,
    /// The scheduled jobs this build can take over from APScheduler.
    pub scheduler: Scheduler,
    /// The connectors this build verifies itself (`/api/connectors`).
    pub verifiers: Verifiers,
    /// The Wazuh indexer and manager clients.
    pub wazuh: WazuhState,
    /// Alert creation and ingest (`/api/incidents/alerts`).
    pub ingest: IngestState,
    /// The Graylog client (`/api/graylog`, and later ports' provisioning).
    pub graylog: GraylogClient,
    /// The InfluxDB client (`/api/influxdb`, and the checks provisioning).
    pub influxdb: InfluxClient,
    /// The Grafana client (`/api/reporting`, `/api/user`, and provisioning).
    pub grafana: GrafanaClient,
    /// The Portainer client (`/api/portainer`, and provisioning).
    pub portainer: PortainerClient,
    /// The customer WAF module (`/api/customer_waf`, the WAF alerts).
    pub waf: WafState,
    /// `requests` for the Wazuh worker and HAProxy provisioning services.
    pub worker_http: copilot_provisioning::customer::decommission::WorkerHttp,
    /// The agents routes' clients (`/api/agents`, `agent_sync`).
    pub agents: AgentsState,
    /// The MinIO object store (`/api/agent_data_store`, the incidents'
    /// files).
    pub objectstore: ObjectStore,
    /// The threat-intel routes' clients (`/api/threat_intel`).
    pub threat_intel: copilot_threat_intel::ThreatIntelState,
    /// The response routes (`/api/active_response`, the Graylog webhook,
    /// `/api/sysmon_config`).
    pub response: copilot_response::ResponseState,
    /// The Shuffle connector's client (its routes, the case notification
    /// and its verification).
    pub shuffle: copilot_shuffle::ShuffleClient,
    /// The agents' report routers (`/api/vulnerabilities`, `/api/sca`,
    /// `/api/syscollector`).
    pub agent_reports: AgentReportsState,
    /// The OpenCTI and Cortex connectors (`/api/opencti`, `/api/analyzers`).
    pub intel: copilot_intel_connectors::IntelState,
    /// The Detections Catalog (`/api/copilot_searches`) and its caches.
    pub searches: copilot_searches::SearchesState,
    /// The Customer Portal routes and their branding cache.
    pub portal: copilot_customer_portal::PortalState,
    /// The integration modules (`/api/integrations/modules/*`, the two
    /// Mimecast routes) and their collection jobs.
    pub modules: copilot_integration_modules::ModulesState,
    /// The licence server (`/api/license`).
    pub license: copilot_license::LicenseClient,
    /// The sidebar's status panel (`/api/status/sidebar`) and its process
    /// state.
    pub sidebar: copilot_status::sidebar::SidebarState,
    /// Microsoft Patch Tuesday (`/api/patch-tuesday`).
    pub patch_tuesday: copilot_patch_tuesday::PatchTuesdayState,
    /// CoPilot MCP (`/api/copilot_mcp`).
    pub mcp: copilot_mcp::McpState,
    /// The Sublime connector (`/api/sublime`).
    pub sublime: copilot_sublime::SublimeState,
}

impl App {
    /// Build the dependencies from configuration and a pool.
    pub fn new(cfg: &CopilotConfig, db: Db) -> anyhow::Result<Self> {
        let legacy = cfg
            .legacy_url
            .clone()
            .map(LegacyProxy::new)
            .transpose()
            .context("building the legacy backend client")?;
        let ttl = if legacy.is_some() {
            cfg.connector_cache_ttl.min(CONNECTOR_TTL_WITH_LEGACY)
        } else {
            cfg.connector_cache_ttl
        };
        let connectors =
            ConnectorCache::new(db.clone(), ttl).with_check_interval(cfg.connector_cache_check);
        // Notifications are dispatched in-process, whatever else is ported.
        let dispatcher = Dispatcher::new(db.clone(), connectors.clone(), cfg.notifications.clone())
            .context("building the notification clients")?;
        let notifications: SharedNotificationSink = Arc::new(DispatchingSink::new(
            dispatcher.clone(),
            JwtCodec::new(&cfg.jwt_secret),
        ));
        // Verified unless explicitly disabled: the request carries Talon's
        // API key (Python used verify=False).
        let verify_tls = std::env::var("TALON_VERIFY_TLS")
            .map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(true);
        let talon = TalonConnector::new(connectors.clone(), verify_tls)
            .context("building the Talon client")?;
        let version = VersionChecker::new(cfg.version_check_url.clone())
            .context("building the release-check client")?;
        let fernet = Fernet::for_totp(cfg.totp_encryption_key.as_ref(), &cfg.jwt_secret).map_err(
            |e| {
                anyhow::anyhow!(
                    "TOTP_ENCRYPTION_KEY is malformed. Expected a 32-byte url-safe base64 key \
                     (typically 44 characters ending with '='). Generate a valid one with:\n  \
                     python -c \"from cryptography.fernet import Fernet; \
                     print(Fernet.generate_key().decode())\"\nThen paste the value into your \
                     .env without surrounding quotes or trailing whitespace. (underlying error: {e})"
                )
            },
        )?;
        let ctx = AppContext::new(AppDeps {
            db: db.clone(),
            jwt: JwtCodec::new(&cfg.jwt_secret),
            connectors,
            audit: Arc::new(DbAuditSink::new(db)),
            notifications,
            notification_defaults: cfg.notifications.clone(),
            http: reqwest::Client::new(),
            log_handled_errors: true,
        });
        let wazuh =
            WazuhState::new(ctx.clone(), legacy.clone()).context("building the Wazuh clients")?;
        let ingest = IngestState::new(
            ctx.clone(),
            wazuh.es.clone(),
            talon.clone(),
            cfg.ingest.clone(),
            legacy.clone(),
        )
        .context("building the ingest clients")?;
        let agents = AgentsState {
            ctx: ctx.clone(),
            wazuh: wazuh.clone(),
            velociraptor: VelociraptorClient::new(ctx.connectors.clone()),
            epss: copilot_agents::services::epss::EpssClient::new()
                .context("building the EPSS client")?,
        };
        let modules = copilot_integration_modules::ModulesState::new(
            ctx.clone(),
            cfg.integration_modules_url.clone(),
        );
        let scheduler = Scheduler::new(
            ctx.db.clone(),
            OptIn::parse(cfg.rust_jobs.as_deref(), cfg.palace_jobs),
            scheduled_jobs(&ctx, &talon, &wazuh, &ingest, &agents, &modules, cfg),
        );
        let graylog =
            GraylogClient::new(ctx.connectors.clone()).context("building the Graylog client")?;
        let influxdb =
            InfluxClient::new(ctx.connectors.clone()).context("building the InfluxDB client")?;
        let grafana =
            GrafanaClient::new(ctx.connectors.clone()).context("building the Grafana client")?;
        let portainer = PortainerClient::new(ctx.connectors.clone())
            .context("building the Portainer client")?;
        let prov = &cfg.provisioning;
        let waf = WafState {
            ctx: ctx.clone(),
            client: WafClient::new(prov.waf_token_encryption_key.clone()),
            graylog: graylog.clone(),
            env: Arc::new(WafEnv {
                token_key: prov.waf_token_encryption_key.clone(),
                syslog_port_range: prov.waf_syslog_port_range.clone(),
                syslog_default_host: prov.waf_syslog_default_host.clone(),
                alert_forwarding_ip: prov.alert_forwarding_ip.clone(),
                graylog_api_header_value: prov.graylog_api_header_value.clone(),
            }),
        };
        let threat_intel = copilot_threat_intel::ThreatIntelState::new(
            ctx.clone(),
            ingest.clone(),
            cfg.copilot_api_key.clone(),
            legacy.clone(),
        )
        .context("building the threat-intel clients")?;
        let objectstore = ObjectStore::from_env(&cfg.minio)
            .map_err(|e| anyhow::anyhow!("MinIO settings: {e}"))?;
        let response = copilot_response::ResponseState {
            ctx: ctx.clone(),
            wazuh: wazuh.clone(),
            store: objectstore.clone(),
            worker: copilot_response::sysmon::worker::WorkerHttp::new()
                .context("building the provisioning-worker client")?,
            action: copilot_response::copilot_action::client::ActionHttp::new(
                cfg.response.copilot_action_url.clone(),
            )
            .context("building the CoPilot Action client")?,
            velociraptor: agents.velociraptor.clone(),
            env: Arc::new(copilot_response::ResponseEnv::from_config(
                &cfg.ingest,
                &cfg.response,
            )),
            legacy: legacy.clone(),
        };
        let shuffle = copilot_shuffle::ShuffleClient::new(ctx.connectors.clone())
            .context("building the Shuffle client")?;
        let agent_reports = AgentReportsState {
            ctx: ctx.clone(),
            wazuh: wazuh.clone(),
            store: objectstore.clone(),
            epss: agents.epss.clone(),
            sca_repo: copilot_agent_reports::sca::policies::ScaRepo::from_env()
                .context("building the CoPilot-SCA client")?,
        };
        let intel = copilot_intel_connectors::IntelState::new(ctx.clone())
            .context("building the Cortex client")?;
        let searches = copilot_searches::SearchesState::new(
            &cfg.catalog,
            ctx.clone(),
            wazuh.clone(),
            graylog.clone(),
            objectstore.clone(),
            legacy.clone(),
        )
        .context("building the catalog clients")?;
        let portal = copilot_customer_portal::PortalState::new(
            ctx.clone(),
            cfg.branding_cache_ttl,
            cfg.branding_cache_check,
        );
        let license = copilot_license::LicenseClient::new(
            copilot_license::client::license_url_from_env(),
            cfg.copilot_api_key.clone(),
        )
        .context("building the licence-server client")?;
        // This process's instrumentation (`/api/performance`): the settings
        // are read once, by the first App of the process.
        copilot_status::performance::init(copilot_status::performance::PerfConfig::from_env(
            &cfg.perf,
        ))
        .install_pool(ctx.db.pool().clone());
        let sidebar = copilot_status::sidebar::SidebarState {
            ctx: ctx.clone(),
            wazuh: wazuh.clone(),
            influx: influxdb.clone(),
            store: objectstore.clone(),
            searches: searches.clone(),
            env: Arc::new(copilot_status::sidebar::SidebarEnv::new(
                cfg.environment.clone(),
                cfg.sidebar_refresh.as_deref(),
                cfg.catalog.refresh_enabled(),
                cfg.version_check_url.clone(),
            )),
            cache: Arc::default(),
        };
        let patch_tuesday =
            copilot_patch_tuesday::PatchTuesdayState::new(ctx.clone(), legacy.clone());
        let mcp = copilot_mcp::McpState::new(ctx.clone(), threat_intel.clone(), legacy.clone());
        let sublime = copilot_sublime::SublimeState::new(
            ctx.clone(),
            copilot_sublime::SublimeClient::new(ctx.connectors.clone())
                .context("building the Sublime client")?,
            legacy.clone(),
        );
        let sso_secret = cfg.sso_state_secret.as_ref().unwrap_or(&cfg.jwt_secret);
        let sso = SsoClient::new(sso_secret, cfg.sso_idp_url.clone())
            .context("building the SSO client")?;
        let webauthn = &cfg.webauthn;
        let relying_party = RelyingParty::from_env(
            webauthn.origins.as_deref(),
            webauthn.origin.as_deref(),
            webauthn.rp_id.as_deref(),
            webauthn.rp_name.as_deref(),
        );
        let identity = IdentityState {
            ctx: ctx.clone(),
            fernet: Arc::new(fernet),
            limiter: Arc::new(TwoFactorLimiter::default()),
            token_ttl_minutes: cfg.access_token_expire_minutes,
            relying_party: Arc::new(relying_party),
            sso: Arc::new(sso),
            smtp: Arc::new(cfg.smtp.clone()),
        };
        Ok(Self {
            ctx,
            talon,
            version,
            identity,
            dispatcher,
            legacy,
            scheduler,
            verifiers: Verifiers::new(
                copilot_wazuh::verify::verifiers(&wazuh)
                    .into_iter()
                    .chain(copilot_velociraptor::verify::verifiers(
                        agents.velociraptor.timeouts(),
                    ))
                    .chain(copilot_shuffle::verifiers(&shuffle))
                    .chain(copilot_intel_connectors::verify::verifiers())
                    .chain(copilot_uba::verifiers())
                    .chain(copilot_sublime::verifiers(&sublime.client)),
            ),
            wazuh,
            ingest,
            graylog,
            influxdb,
            grafana,
            portainer,
            waf,
            worker_http: copilot_provisioning::customer::decommission::worker_http()
                .context("building the provisioning-worker client")?,
            agents,
            objectstore,
            threat_intel,
            response,
            shuffle,
            agent_reports,
            intel,
            searches,
            portal,
            modules,
            license,
            sidebar,
            patch_tuesday,
            mcp,
            sublime,
        })
    }

    /// One Wazuh router, with the encoded-slash hand-off to Python.
    fn wazuh_routes(&self, build: fn(WazuhState) -> Router) -> Router {
        build(self.wazuh.clone()).layer(axum::middleware::from_fn_with_state(
            self.wazuh.legacy.clone(),
            copilot_wazuh::decoded_slash_to_legacy,
        ))
    }

    /// The Velociraptor routes' state (the agents routes' client).
    fn shuffle_state(&self) -> copilot_shuffle::ShuffleState {
        copilot_shuffle::ShuffleState {
            ctx: self.ctx.clone(),
            client: self.shuffle.clone(),
        }
    }

    fn velociraptor_state(&self) -> copilot_velociraptor::VelociraptorState {
        copilot_velociraptor::VelociraptorState {
            ctx: self.ctx.clone(),
            client: self.agents.velociraptor.clone(),
            store: self.objectstore.clone(),
        }
    }

    /// The full router: ported modules, health, and the legacy fallback.
    pub fn router(&self, max_body_bytes: usize) -> Router {
        let state = TalonState {
            ctx: self.ctx.clone(),
            talon: self.talon.clone(),
        };
        let platform = PlatformState {
            ctx: self.ctx.clone(),
            version: self.version.clone(),
        };
        let ported = Router::new()
            .nest("/api/ai_analyst", copilot_ai_analyst::router(state.clone()))
            .nest("/api/talon", copilot_talon::router(state.clone()))
            // Every portal route but `/sla/*` (copilot-soc-management's,
            // merged below with full paths); an encoded `/` is Python's.
            .nest(
                "/api/customer_portal",
                copilot_customer_portal::router(state, self.portal.clone()).layer(
                    from_fn_with_state(
                        self.wazuh.legacy.clone(),
                        copilot_wazuh::decoded_slash_to_legacy,
                    ),
                ),
            )
            .nest(
                "/api/customers",
                copilot_customers::router(self.ctx.clone()),
            )
            .nest(
                "/api/healthcheck",
                copilot_healthchecks::router(self.ctx.clone()),
            )
            .nest(
                "/api/version",
                copilot_platform::version_router(platform.clone()),
            )
            .nest("/api/audit", copilot_platform::audit_router(platform))
            .nest("/api/auth", copilot_identity::router(self.identity.clone()))
            // Only the routes ported so far; every other path and method of
            // the module falls through to the legacy backend.
            .nest(
                "/api/incidents/db_operations",
                copilot_incidents::db_operations(self.ctx.clone()),
            )
            .nest(
                "/api/incidents/case_templates",
                copilot_incidents::case_templates(self.ctx.clone()),
            )
            .nest(
                "/api/incidents/tag_access",
                copilot_incidents::tag_access(self.ctx.clone()),
            )
            .nest(
                "/api/incidents/alerts",
                copilot_incidents::alerts(self.ctx.clone()),
            )
            .nest(
                "/api/incidents/report",
                copilot_incidents::report(self.ctx.clone()),
            )
            .nest(
                "/api/incidents/customer_reports",
                copilot_incidents::customer_reports(self.ctx.clone()),
            )
            .nest(
                "/api/scheduler",
                copilot_scheduler::router(SchedulerState {
                    ctx: self.ctx.clone(),
                    scheduler: self.scheduler.clone(),
                    legacy: self.legacy.clone(),
                }),
            )
            // Full paths beside the two nested incidents routers: alert
            // creation and ingest, and the indexer reads of /db_operations.
            .merge(copilot_ingest::router(self.ingest.clone()))
            // Full paths: the module spans `/api/customers/{code}/…`,
            // `/api/notifications`, `/api/notification_channels` and
            // `/api/internal_notification_routes`.
            .merge(copilot_notifications::router(NotificationsState {
                ctx: self.ctx.clone(),
                dispatcher: self.dispatcher.clone(),
            }))
            .nest(
                "/api/alerts",
                self.wazuh_routes(copilot_wazuh::indexer::routes::alerts_router),
            )
            .nest(
                "/api/wazuh_indexer",
                self.wazuh_routes(copilot_wazuh::indexer::routes::monitoring_router),
            )
            .nest(
                "/api/snapshots",
                self.wazuh_routes(copilot_wazuh::indexer::routes::snapshots_router),
            )
            .nest(
                "/api/wazuh_manager",
                self.wazuh_routes(copilot_wazuh::manager::routes::router),
            )
            .nest(
                "/api/connectors",
                copilot_connectors::router(ConnectorsState {
                    ctx: self.ctx.clone(),
                    verifiers: self.verifiers.clone(),
                    legacy: self.legacy.clone(),
                }),
            )
            // Only the Graylog connector's routes; `POST /invoke` (active
            // response) falls through to the legacy backend.
            .nest(
                "/api/graylog",
                copilot_graylog::router(GraylogState {
                    ctx: self.ctx.clone(),
                    client: self.graylog.clone(),
                }),
            )
            .nest(
                "/api/influxdb",
                copilot_influxdb::router(InfluxState {
                    ctx: self.ctx.clone(),
                    client: self.influxdb.clone(),
                }),
            )
            // Full paths: `/api/reporting/*` but `POST /generate-report`, and
            // `/api/user/user/organization/add`.
            .merge(copilot_grafana::router(GrafanaState {
                ctx: self.ctx.clone(),
                client: self.grafana.clone(),
            }))
            // All but `POST /create-wazuh-customer-stack`, which falls through.
            .nest(
                "/api/portainer",
                copilot_portainer::router(PortainerState {
                    ctx: self.ctx.clone(),
                    client: self.portainer.clone(),
                }),
            )
            // `/api/soc_management/*` but `GET /report`; the portal's SLA page
            // with full paths beside the other `/api/customer_portal` routes.
            .nest(
                "/api/soc_management",
                copilot_soc_management::router(self.ctx.clone()),
            )
            .merge(copilot_soc_management::portal_router(self.ctx.clone()))
            .nest("/api/customer_waf", copilot_waf::router(self.waf.clone()))
            .nest(
                "/api/monitoring_alert",
                copilot_monitoring_alerts::router(
                    copilot_monitoring_alerts::MonitoringAlertState {
                        ctx: self.ctx.clone(),
                        graylog: self.graylog.clone(),
                        waf: self.waf.clone(),
                    },
                ),
            )
            .merge(copilot_provisioning::router(
                copilot_provisioning::StackState {
                    ctx: self.ctx.clone(),
                    graylog: self.graylog.clone(),
                    influx: self.influxdb.clone(),
                    grafana: self.grafana.clone(),
                },
            ))
            // Full paths: `POST /api/stack_provisioning/graylog/provision/
            // {fortinet,sonicwall,sentinelone}` and `POST /api/<integration>/provision`.
            .merge(copilot_integration_provisioning::router(
                copilot_integration_provisioning::ProvisioningState {
                    ctx: self.ctx.clone(),
                    graylog: self.graylog.clone(),
                    grafana: self.grafana.clone(),
                    wazuh: self.wazuh.clone(),
                    legacy: self.legacy.clone(),
                },
            ))
            // Full paths: `POST /api/grafana/dashboards` and
            // `POST /api/customer_provisioning/provision/dashboards` (beside
            // the customer router's `GET` of that path).
            .merge(copilot_grafana_dashboards::router(
                copilot_grafana_dashboards::DashboardsState {
                    ctx: self.ctx.clone(),
                    grafana: self.grafana.clone(),
                },
            ))
            .merge(copilot_provisioning::customer::routes::router(
                copilot_provisioning::customer::decommission::Tools {
                    ctx: self.ctx.clone(),
                    wazuh: self.wazuh.clone(),
                    graylog: self.graylog.clone(),
                    grafana: self.grafana.clone(),
                    portainer: self.portainer.clone(),
                    http: self.worker_http.clone(),
                },
            ))
            .nest(
                "/api/agents",
                copilot_agents::router(self.agents.clone()).layer(from_fn_with_state(
                    self.wazuh.legacy.clone(),
                    copilot_wazuh::decoded_slash_to_legacy,
                )),
            )
            .nest(
                "/api/artifacts",
                copilot_velociraptor::artifacts_router(self.velociraptor_state()).layer(
                    from_fn_with_state(
                        self.wazuh.legacy.clone(),
                        copilot_wazuh::decoded_slash_to_legacy,
                    ),
                ),
            )
            .nest(
                "/api/flows",
                copilot_velociraptor::flows_router(self.velociraptor_state()).layer(
                    from_fn_with_state(
                        self.wazuh.legacy.clone(),
                        copilot_wazuh::decoded_slash_to_legacy,
                    ),
                ),
            )
            .nest(
                "/api/vulnerabilities",
                copilot_agent_reports::vulnerabilities::router(self.agent_reports.clone()).layer(
                    from_fn_with_state(
                        self.wazuh.legacy.clone(),
                        copilot_wazuh::decoded_slash_to_legacy,
                    ),
                ),
            )
            .nest(
                "/api/sca",
                copilot_agent_reports::sca::router(self.agent_reports.clone()).layer(
                    from_fn_with_state(
                        self.wazuh.legacy.clone(),
                        copilot_wazuh::decoded_slash_to_legacy,
                    ),
                ),
            )
            .nest(
                "/api/syscollector",
                copilot_agent_reports::syscollector::router(self.agent_reports.clone()).layer(
                    from_fn_with_state(
                        self.wazuh.legacy.clone(),
                        copilot_wazuh::decoded_slash_to_legacy,
                    ),
                ),
            )
            .nest(
                "/api/agent_data_store",
                copilot_objectstore::router(DataStoreState {
                    ctx: self.ctx.clone(),
                    store: self.objectstore.clone(),
                    legacy: self.legacy.clone(),
                }),
            )
            // Full paths beside the nested incidents routers (methods merge
            // on a shared path: DELETE /case/{case_id} joins its GET).
            .merge(copilot_incidents::datastore::router(
                copilot_incidents::datastore::DatastoreState {
                    ctx: self.ctx.clone(),
                    store: self.objectstore.clone(),
                    legacy: self.legacy.clone(),
                },
            ))
            // Full paths: `/api/integrations/*` (only this router's routes),
            // `/api/api/v1/alert_settings/*` and `/api/network_connectors/*`.
            .merge(copilot_integrations::router(
                copilot_integrations::IntegrationsState {
                    ctx: self.ctx.clone(),
                    graylog: self.graylog.clone(),
                    grafana: self.grafana.clone(),
                    wazuh: self.wazuh.clone(),
                    legacy: self.legacy.clone(),
                },
            ))
            // Full paths: `/api/siem/dashboards`, `/event_sources`, `/events`.
            .merge(copilot_siem::router(copilot_siem::SiemState {
                ctx: self.ctx.clone(),
                es: self.wazuh.es.clone(),
                legacy: self.legacy.clone(),
            }))
            // Full paths: `/api/threat_intel/*`.
            .merge(copilot_threat_intel::router(self.threat_intel.clone()))
            // Full paths: `/api/copilot_searches/*`, dispatched on the decoded
            // path as Starlette routes it.
            .merge(copilot_searches::router(self.searches.clone()))
            .nest(
                "/api/active_response",
                copilot_response::active_response_router(self.response.clone()).layer(
                    from_fn_with_state(
                        self.wazuh.legacy.clone(),
                        copilot_wazuh::decoded_slash_to_legacy,
                    ),
                ),
            )
            // Full path beside the nested Graylog connector.
            .merge(copilot_response::graylog_router(self.response.clone()))
            // `POST /upload` (ElementTree's XML validation) falls through.
            .nest(
                "/api/sysmon_config",
                copilot_response::sysmon_router(self.response.clone()).layer(from_fn_with_state(
                    self.wazuh.legacy.clone(),
                    copilot_wazuh::decoded_slash_to_legacy,
                )),
            )
            .nest(
                "/api/copilot_action",
                copilot_response::copilot_action_router(self.response.clone()).layer(
                    from_fn_with_state(
                        self.wazuh.legacy.clone(),
                        copilot_wazuh::decoded_slash_to_legacy,
                    ),
                ),
            )
            // The Shuffle connector, by full path: `/api/workflows`,
            // `/api/shuffle/*` and the case notification beside the nested
            // `/api/incidents/db_operations`.
            .merge(copilot_shuffle::router(self.shuffle_state()))
            .merge(
                copilot_shuffle::organizations_router(self.shuffle_state()).layer(
                    from_fn_with_state(
                        self.wazuh.legacy.clone(),
                        copilot_wazuh::decoded_slash_to_legacy,
                    ),
                ),
            )
            .merge(copilot_shuffle::case_notification_router(
                self.shuffle_state(),
            ))
            // Full paths: `/api/opencti/*` and `/api/analyzers*`.
            .merge(
                copilot_intel_connectors::router(self.intel.clone()).layer(from_fn_with_state(
                    self.wazuh.legacy.clone(),
                    copilot_wazuh::decoded_slash_to_legacy,
                )),
            )
            .nest(
                "/api/uba",
                copilot_uba::router(copilot_uba::UbaState::new(
                    self.ctx.clone(),
                    self.graylog.clone(),
                    self.wazuh.clone(),
                ))
                .layer(from_fn_with_state(
                    self.wazuh.legacy.clone(),
                    copilot_wazuh::decoded_slash_to_legacy,
                )),
            )
            // Full paths: `/api/integrations/modules/*` beside
            // copilot-integrations' routes, and `POST /api/mimecast/invoke`,
            // `/ttp/urls`.
            .merge(copilot_integration_modules::router(self.modules.clone()))
            .nest(
                "/api/license",
                copilot_license::router(copilot_license::LicenseState {
                    ctx: self.ctx.clone(),
                    client: self.license.clone(),
                })
                .layer(from_fn_with_state(
                    self.wazuh.legacy.clone(),
                    copilot_wazuh::decoded_slash_to_legacy,
                )),
            )
            .nest(
                "/api/status",
                copilot_status::sidebar::router(self.sidebar.clone()),
            )
            .nest(
                "/api/performance",
                copilot_status::performance::router(self.ctx.clone()).layer(from_fn_with_state(
                    self.wazuh.legacy.clone(),
                    copilot_wazuh::decoded_slash_to_legacy,
                )),
            )
            .nest(
                "/api/logs",
                copilot_status::logs::router(self.ctx.clone()).layer(from_fn_with_state(
                    self.wazuh.legacy.clone(),
                    copilot_wazuh::decoded_slash_to_legacy,
                )),
            )
            // Full paths: `/api/patch-tuesday*`.
            .merge(copilot_patch_tuesday::router(self.patch_tuesday.clone()))
            // Full paths: `/api/copilot_mcp/*`.
            .merge(copilot_mcp::router(self.mcp.clone()))
            // Full paths: `/api/sublime/*`.
            .merge(copilot_sublime::router(self.sublime.clone()))
            .layer(from_fn_with_state(self.ctx.clone(), log_handled_errors))
            .layer(from_fn(security_headers))
            .layer(compression())
            .layer(cors())
            .layer(DefaultBodyLimit::max(max_body_bytes));
        let health = Router::new()
            .route("/_copilot/health", get(health))
            .with_state(HealthState {
                ctx: self.ctx.clone(),
                legacy: self.legacy.is_some(),
            });
        let app = Router::new().merge(ported).merge(health);
        let app = match &self.legacy {
            // Unported paths *and* methods go to Python, which answers its
            // own 404/405 when it does not know them either.
            Some(proxy) => {
                let fallback = Router::new()
                    .fallback(copilot_gateway::proxy_handler)
                    .with_state(proxy.clone());
                // Static paths still served by Python under a prefix whose
                // `/{id}` route would otherwise capture them.
                let mut app = app;
                for path in copilot_incidents::routes::case_templates::LEGACY_PATHS {
                    let proxy = proxy.clone();
                    app = app.route(
                        &format!("/api/incidents/case_templates{path}"),
                        axum::routing::any(
                            move |req: Request| async move { proxy.forward(req).await },
                        ),
                    );
                }
                app.method_not_allowed_fallback({
                    let proxy = proxy.clone();
                    move |req: Request| async move { proxy.forward(req).await }
                })
                .fallback_service(fallback)
            }
            None => {
                // Without Python nothing serves these; keep `/{template_id}`
                // from answering them.
                let mut app = app;
                for path in copilot_incidents::routes::case_templates::LEGACY_PATHS {
                    app = app.route(
                        &format!("/api/incidents/case_templates{path}"),
                        axum::routing::any(|| async { ApiError::RouteNotFound }),
                    );
                }
                app.method_not_allowed_fallback(|| async { ApiError::MethodNotAllowed })
                    .fallback(root_or_404)
            }
        };
        // Last, so it wraps every route and the fallback (the proxy to
        // Python included) after routing: the request timer of
        // `/api/performance`, `X-Process-Time-Ms` and `X-Request-Id`.
        app.layer(from_fn(copilot_status::performance::middleware::timing))
    }
}

/// Every job this build can take over from APScheduler (`handover.py`'s
/// `RUST_CAPABLE_JOBS`): the palace drainer and sweeper, `prune_audit_log`,
/// `notify_sla_transitions`, `invoke_snapshot_schedules`,
/// `resize_wazuh_index_fields`, `invoke_alert_creation_collect`, `agent_sync`,
/// and the integrations' collection jobs (`copilot_integration_modules::jobs`).
pub fn scheduled_jobs(
    ctx: &AppContext,
    talon: &TalonConnector,
    wazuh: &WazuhState,
    ingest: &IngestState,
    agents: &AgentsState,
    modules: &copilot_integration_modules::ModulesState,
    cfg: &CopilotConfig,
) -> Vec<copilot_scheduler::JobSpec> {
    let mut jobs = copilot_ai_analyst::palace_jobs::job_specs(ctx, talon);
    jobs.push(copilot_scheduler::jobs::prune_audit_log_spec(
        ctx.db.clone(),
        cfg.audit_log_retention_days.clone(),
    ));
    jobs.push(copilot_soc_management::notifier_job_spec(ctx));
    jobs.extend(copilot_wazuh::jobs::job_specs(wazuh));
    jobs.push(copilot_ingest::job_spec(ingest));
    jobs.extend(copilot_agents::jobs::job_specs(agents));
    jobs.extend(copilot_integration_modules::jobs::job_specs(modules));
    jobs
}

/// Without a legacy backend: the Python root greeting, else FastAPI's 404.
async fn root_or_404(req: Request) -> Response {
    if req.uri().path() == "/" && req.method() == http::Method::GET {
        return axum::Json(json!({"message": "CoPilot - We Made It!"})).into_response();
    }
    ApiError::RouteNotFound.into_response()
}

#[derive(Clone)]
struct HealthState {
    ctx: AppContext,
    legacy: bool,
}

/// Unauthenticated liveness + dependency summary (no secrets).
async fn health(State(s): State<HealthState>) -> Response {
    let database = match tokio::time::timeout(Duration::from_secs(3), s.ctx.db.ping()).await {
        Ok(Ok(())) => "ok",
        Ok(Err(_)) | Err(_) => "unreachable",
    };
    let status = if database == "ok" {
        http::StatusCode::OK
    } else {
        http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        axum::Json(json!({
            "status": if database == "ok" { "ok" } else { "degraded" },
            "service": "copilot",
            "version": env!("CARGO_PKG_VERSION"),
            "database": database,
            "legacy_backend": if s.legacy { "configured" } else { "none" },
            "ported": PORTED_PREFIXES,
        })),
    )
        .into_response()
}
