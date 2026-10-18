//! The catalogs the startup seeds, as data: `app/db/db_populate.py`'s lists,
//! `create_buckets()`'s bucket names, `initialize_job_metadata`'s known jobs
//! and the two system users of `app/auth/services/universal.py`. Every list
//! is pinned to Python's own by `startup_vectors.json`
//! (`scripts/gen-startup-vectors.py`).

use copilot_core::env::EnvFile;

/// What a connector authenticates with (`load_connector_data`'s
/// `accepts_key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepts {
    /// `host_only`.
    HostOnly,
    /// `api_key`.
    ApiKey,
    /// `username_password`.
    UsernamePassword,
    /// `file`.
    File,
}

/// One entry of `get_connectors_list()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorSpec {
    /// `connector_name`.
    pub name: &'static str,
    /// `connector_type` (a version, in practice).
    pub kind: &'static str,
    /// How it authenticates.
    pub accepts: Accepts,
    /// `connector_description`.
    pub description: &'static str,
    /// The variable holding `connector_extra_data`, when it takes one.
    pub extra_data_key: Option<&'static str>,
}

/// The connectors `add_connectors` keeps in the table, in its order (which
/// is also the order of their ids on a new database: Python code refers to
/// connectors by id).
pub const CONNECTORS: &[ConnectorSpec] = &[
    ConnectorSpec {
        name: "Wazuh-Indexer",
        kind: "4.4.1",
        accepts: Accepts::UsernamePassword,
        description: "Connection to Wazuh-Indexer.",
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "Wazuh-Manager",
        kind: "4.4.1",
        accepts: Accepts::UsernamePassword,
        description: "Connection to Wazuh-Manager. Default is wazuh-wui:wazuh-wui",
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "Graylog",
        kind: "5.0.7",
        accepts: Accepts::UsernamePassword,
        description: "Connection to Graylog.",
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "Shuffle",
        kind: "1.1.0",
        accepts: Accepts::ApiKey,
        description: "Connection to Shuffle.",
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "Velociraptor",
        kind: "0.6.8",
        accepts: Accepts::File,
        description: "Connection to Velociraptor. Make sure you have generated the api file first.",
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "Sublime",
        kind: "3",
        accepts: Accepts::ApiKey,
        description: "Connection to Sublime.",
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "InfluxDB",
        kind: "3",
        accepts: Accepts::ApiKey,
        description: "Connection to InfluxDB.",
        extra_data_key: Some("INFLUXDB_ORG_AND_BUCKET"),
    },
    ConnectorSpec {
        name: "Grafana",
        kind: "3",
        accepts: Accepts::UsernamePassword,
        description: "Connection to Grafana.",
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "Wazuh Worker Provisioning",
        kind: "3",
        accepts: Accepts::HostOnly,
        description: concat!(
            "Connection to Wazuh Worker Provisioning. Make sure you have deployed the Wazuh ",
            "Worker Provisioning Application provided by SOCFortress: ",
            "https://github.com/socfortress/Customer-Provisioning-Worker",
        ),
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "Event Shipper",
        kind: "3",
        accepts: Accepts::HostOnly,
        description: concat!(
            "Connection to Graylog GELF Input to receive events from integrations. Make sure ",
            "you have created a GELF Input in Graylog.",
        ),
        extra_data_key: Some("GELF_INPUT_PORT"),
    },
    ConnectorSpec {
        name: "HAProxy Provisioning",
        kind: "3",
        accepts: Accepts::HostOnly,
        description: concat!(
            "Connection to HAProxy Provisioning. Make sure you have deployed the HAProxy ",
            "Provisioning Application provided by SOCFortress: ",
            "https://github.com/socfortress/Customer-Provisioning-Worker",
        ),
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "VirusTotal",
        kind: "3",
        accepts: Accepts::ApiKey,
        description: "Connection to VirusTotal. Make sure you have created an API key.",
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "Portainer",
        kind: "3",
        accepts: Accepts::UsernamePassword,
        description: "Connection to Portainer.",
        extra_data_key: Some("PORTAINER_ENDPOINT_ID"),
    },
    ConnectorSpec {
        name: "Graylog-Network",
        kind: "5.0.7",
        accepts: Accepts::UsernamePassword,
        description: concat!(
            "Connection to Graylog. If you only have one Graylog instance, set this to the ",
            "same as Graylog.",
        ),
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "Resend",
        kind: "1",
        accepts: Accepts::ApiKey,
        description: concat!(
            "Connection to Resend for transactional email notifications. Requires an API key ",
            "and a verified sending domain. The default From address is read from ",
            "RESEND_FROM_ADDRESS and can be overridden per notification route.",
        ),
        extra_data_key: Some("RESEND_FROM_ADDRESS"),
    },
    ConnectorSpec {
        name: "Talon",
        kind: "3",
        accepts: Accepts::ApiKey,
        description: concat!(
            "Talon is an automated AI SOC analyst built by SOCfortress for the CoPilot ",
            "stack. It runs as a background service alongside CoPilot — pulling raw events ",
            "from your Wazuh/OpenSearch SIEM, enriching them with threat intelligence, ",
            "correlating across your environment, and writing structured investigation ",
            "reports with severity assessments and recommended actions directly back into ",
            "CoPilot.",
        ),
        extra_data_key: None,
    },
    ConnectorSpec {
        name: "OpenCTI",
        kind: "7",
        accepts: Accepts::ApiKey,
        description: concat!(
            "Connection to OpenCTI's GraphQL API for threat intelligence lookups — IOC ",
            "enrichment, indicators, reports and threat entities. Set the URL to the ",
            "platform address (e.g. http://opencti:8080) and the API key to an OpenCTI ",
            "user's API token. Optionally set the public URL analysts open OpenCTI at (e.g. ",
            "https://cti.example.com) when it differs from the address CoPilot calls.",
        ),
        extra_data_key: Some("OPENCTI_PUBLIC_URL"),
    },
    ConnectorSpec {
        name: "SOCFortress UBA",
        kind: "1",
        accepts: Accepts::ApiKey,
        description: concat!(
            "Connection to SOCFortress UBA (user behavior analytics): entities ranked by ",
            "risk, their signals and alerts, suppressions and verdicts. Set the URL to the ",
            "UBA API (e.g. http://172.17.0.1:8010) and the API key to one created with ",
            "`uba-admin api-keys create --name copilot --scope write`.",
        ),
        extra_data_key: None,
    },
];

/// The connectors `delete_connectors` removes (`delete_connectors_list()`).
pub const DELETED_CONNECTORS: &[&str] = &[
    "DFIR-IRIS",
    "AskSocfortress",
    "SocfortressThreatIntel",
    "Cortex",
];

/// A `connectors` row as `load_connector_data` builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRow {
    /// `connector_name`.
    pub name: &'static str,
    /// `connector_type`.
    pub kind: &'static str,
    /// `connector_url`: `<PREFIX>_URL`, or `""` (the column is `NOT NULL`).
    pub url: String,
    /// `<PREFIX>_USERNAME`.
    pub username: Option<String>,
    /// `<PREFIX>_PASSWORD`.
    pub password: Option<String>,
    /// `<PREFIX>_API_KEY`.
    pub api_key: Option<String>,
    /// `connector_description`.
    pub description: &'static str,
    /// `<PREFIX>_SUPPORTS`, else `Not specified.`.
    pub supports: String,
    /// `bool(os.getenv("<PREFIX>_VERIFIED", False))`: any non-empty text,
    /// `false` included.
    pub verified: bool,
    /// `connector_accepts_host_only`.
    pub accepts_host_only: bool,
    /// `connector_accepts_api_key`.
    pub accepts_api_key: bool,
    /// `connector_accepts_username_password`.
    pub accepts_username_password: bool,
    /// `connector_accepts_file`.
    pub accepts_file: bool,
    /// `connector_accepts_extra_data`.
    pub accepts_extra_data: bool,
    /// The extra-data variable's value.
    pub extra_data: Option<String>,
}

impl ConnectorSpec {
    /// The variables' prefix: the name upper-cased, `-` and ` ` made `_`.
    pub fn env_prefix(&self) -> String {
        self.name.to_uppercase().replace(['-', ' '], "_")
    }

    /// `load_connector_data(...)`, reading the variables as `os.getenv`
    /// does (an empty value is a value).
    pub fn row(&self, env: &EnvFile) -> ConnectorRow {
        let prefix = self.env_prefix();
        let var = |suffix: &str| env.get_raw(&format!("{prefix}_{suffix}"));
        ConnectorRow {
            name: self.name,
            kind: self.kind,
            url: var("URL").unwrap_or_default(),
            username: var("USERNAME"),
            password: var("PASSWORD"),
            api_key: var("API_KEY"),
            description: self.description,
            supports: var("SUPPORTS").unwrap_or_else(|| "Not specified.".to_string()),
            verified: var("VERIFIED").is_some_and(|v| !v.is_empty()),
            accepts_host_only: self.accepts == Accepts::HostOnly,
            accepts_api_key: self.accepts == Accepts::ApiKey,
            accepts_username_password: self.accepts == Accepts::UsernamePassword,
            accepts_file: self.accepts == Accepts::File,
            accepts_extra_data: self.extra_data_key.is_some(),
            extra_data: self.extra_data_key.and_then(|k| env.get_raw(k)),
        }
    }
}

/// `ROLES`: the five roles with their fixed ids (`RoleEnum`).
pub const ROLES: &[(i64, &str, &str)] = &[
    (1, "admin", "Administrator"),
    (2, "analyst", "SOC Analyst"),
    (3, "scheduler", "Scheduler for automated tasks"),
    (
        4,
        "customer_user",
        "Customer user with limited access to their own data",
    ),
    (
        5,
        "responder",
        "SOC Analyst who may also run response actions on their assigned customers",
    ),
];

/// The text stored when an integration has no deployment instructions.
pub const NO_INSTRUCTIONS: &str = "No deployment instructions available.";

/// `get_available_integrations_list()`: name and description (the
/// instructions are [`crate::markdown`]'s).
pub const INTEGRATIONS: &[(&str, &str)] = &[
    ("Office365", "Integrate Office365 with SOCFortress."),
    ("Mimecast", "Integrate Mimecast with SOCFortress."),
    ("SAP SIEM", "Integrate SAP SIEM with SOCFortress."),
    ("Huntress", "Integrate Huntress with SOCFortress."),
    ("CarbonBlack", "Integrate CarbonBlack with SOCFortress."),
    ("Crowdstrike", "Integrate Crowdstrike with SOCFortress."),
    ("DUO", "Integrate DUO with SOCFortress."),
    ("Darktrace", "Integrate Darktrace with SOCFortress."),
    ("BitDefender", "Integrate BitDefender with SOCFortress."),
    ("CATO", "Integrate CATO NETWORKS with SOCFortress."),
    (
        "DefenderForEndpoint",
        "Integrate DefenderForEndpoint with SOCFortress.",
    ),
    (
        "SOCFortress MDR",
        "Forward alerts to the SOCFortress MDR server for this customer.",
    ),
    ("AWS", "Integrate AWS with SOCFortress."),
];

/// `get_available_integrations_auth_keys_list()`'s `(integration, key)`
/// pairs, in its order.
pub const INTEGRATION_AUTH_KEYS: &[(&str, &str)] = &[
    ("Office365", "TENANT_ID"),
    ("Office365", "CLIENT_ID"),
    ("Office365", "CLIENT_SECRET"),
    ("Office365", "API_TYPE"),
    ("Mimecast", "APP_ID"),
    ("Mimecast", "APP_KEY"),
    ("Mimecast", "EMAIL_ADDRESS"),
    ("Mimecast", "ACCESS_KEY"),
    ("Mimecast", "SECRET_KEY"),
    ("SAP SIEM", "API_KEY"),
    ("SAP SIEM", "SECRET_KEY"),
    ("SAP SIEM", "USER_KEY"),
    ("SAP SIEM", "API_DOMAIN"),
    ("Huntress", "API_KEY"),
    ("Huntress", "API_SECRET"),
    ("CarbonBlack", "API_KEY"),
    ("CarbonBlack", "API_URL"),
    ("CarbonBlack", "API_ID"),
    ("CarbonBlack", "ORGANIZATION_KEY"),
    ("Crowdstrike", "CLIENT_ID"),
    ("Crowdstrike", "CLIENT_SECRET"),
    ("Crowdstrike", "BASE_URL"),
    ("Crowdstrike", "SYSLOG_PORT"),
    ("DUO", "API_HOSTNAME"),
    ("DUO", "INTEGRATION_KEY"),
    ("DUO", "SECRET_KEY"),
    ("Darktrace", "PUBLIC_TOKEN"),
    ("Darktrace", "PRIVATE_TOKEN"),
    ("Darktrace", "HOST"),
    ("Darktrace", "PORT"),
    ("BitDefender", "BASIC_AUTH_USERNAME"),
    ("BitDefender", "BASIC_AUTH_PASSWORD"),
    ("BitDefender", "WEBSERVER_HOSTNAME"),
    ("BitDefender", "WEBSERVER_PORT"),
    ("BitDefender", "GRAYLOG_PORT"),
    ("BitDefender", "API_KEY"),
    ("CATO", "API_KEY"),
    ("CATO", "ACCOUNT_ID"),
    ("CATO", "EVENT_TYPES"),
    ("CATO", "EVENT_SUB_TYPES"),
    ("DefenderForEndpoint", "TENANT_ID"),
    ("DefenderForEndpoint", "CLIENT_ID"),
    ("DefenderForEndpoint", "CLIENT_SECRET"),
    ("DefenderForEndpoint", "SYSLOG_PORT"),
    ("SOCFortress MDR", "COLLECTOR_UUID"),
    ("AWS", "ACCESS_KEY_ID"),
    ("AWS", "SECRET_ACCESS_KEY"),
    ("AWS", "AWS_ACCOUNT_ID"),
    ("AWS", "AWS_ACCOUNT_ALIAS"),
    ("AWS", "AWS_ORGANIZATION_ID"),
    ("AWS", "BUCKET_NAME"),
    ("AWS", "SERVICES"),
    ("AWS", "ONLY_LOGS_AFTER"),
];

/// `get_available_network_connectors_list()`: name and description.
pub const NETWORK_CONNECTORS: &[(&str, &str)] = &[
    ("Fortinet", "Integrate Fortinet with SOCFortress."),
    ("Sonicwall", "Integrate Sonicwall with SOCFortress."),
    ("Sentinelone", "Integrate Sentinelone with SOCFortress."),
];

/// `get_available_network_connectors_auth_keys_list()`'s pairs, in its order.
pub const NETWORK_CONNECTOR_AUTH_KEYS: &[(&str, &str)] = &[
    ("Fortinet", "SYSLOG_PORT"),
    ("Sonicwall", "SYSLOG_PORT"),
    ("Sonicwall", "TLS_CERT_FILE"),
    ("Sonicwall", "TLS_KEY_FILE"),
    ("Sentinelone", "SYSLOG_PORT"),
    ("Sentinelone", "TLS_CERT_FILE"),
    ("Sentinelone", "TLS_KEY_FILE"),
];

/// `create_buckets()`: the MinIO buckets, in its order.
pub const BUCKETS: &[&str] = &[
    "copilot-cases",
    "copilot-case-report-templates",
    "sysmon-configs",
    "velociraptor-artifacts",
    "incident-management-reports",
];

/// One of `initialize_job_metadata`'s known jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownJob {
    /// `job_id` (the function's name).
    pub job_id: &'static str,
    /// `time_interval`, minutes: reset at every start.
    pub time_interval: i64,
    /// `job_description`.
    pub description: &'static str,
}

/// `initialize_job_metadata`'s known jobs, in its order.
pub const KNOWN_JOBS: &[KnownJob] = &[
    KnownJob {
        job_id: "agent_sync",
        time_interval: 15,
        description: "Synchronizes agents with the Wazuh Manager and Velociraptor server.",
    },
    KnownJob {
        job_id: "resize_wazuh_index_fields",
        time_interval: 1,
        description: "Resizes the Wazuh index fields.",
    },
    KnownJob {
        job_id: "invoke_alert_creation_collect",
        time_interval: 5,
        description: "Invokes alert creation collection.",
    },
    KnownJob {
        job_id: "invoke_snapshot_schedules",
        time_interval: 15,
        description: "Invokes Index snapshot schedules execution.",
    },
    KnownJob {
        job_id: "invoke_palace_lesson_drainer",
        time_interval: 2,
        description: "Drains pending AI analyst palace lessons into MemPalace via NanoClaw /palace/lesson.",
    },
    KnownJob {
        job_id: "invoke_palace_lesson_sweeper",
        time_interval: 60,
        description: "Forgets expired one-off AI analyst palace lessons via NanoClaw /palace/forget.",
    },
    KnownJob {
        job_id: "refresh_wazuh_rules_cache",
        time_interval: 30,
        description: "Refreshes the in-memory Wazuh ruleset cache so catalog and sidebar requests never load it.",
    },
    KnownJob {
        job_id: "refresh_catalog_caches",
        time_interval: 15,
        description: "Refreshes the Detections Catalog GitHub-backed caches (CoPilot Searches rules, MITRE matrix) off the request path.",
    },
    KnownJob {
        job_id: "refresh_sidebar_health",
        time_interval: 6,
        description: "Refreshes the sidebar InfluxDB health indicator so the sidebar never runs the Flux query itself.",
    },
    KnownJob {
        job_id: "refresh_sidebar_indicators",
        time_interval: 4,
        description: "Assembles the deployment-wide sidebar indicators so /status/sidebar reads them from memory.",
    },
    KnownJob {
        job_id: "notify_sla_transitions",
        time_interval: 2,
        description: "Notifies internal routes when an alert's or case's SLA turns at risk or breaches, once per clock.",
    },
    KnownJob {
        job_id: "prune_audit_log",
        time_interval: 1440,
        description: "Prunes audit_log entries older than the configured retention window (AUDIT_LOG_RETENTION_DAYS).",
    },
];

/// A user the startup makes sure of (`create_admin_user`,
/// `create_scheduler_user`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemUser {
    /// `username`.
    pub username: &'static str,
    /// `email`.
    pub email: &'static str,
    /// `role_id`.
    pub role_id: i64,
    /// The length `Password.generate` is asked for.
    pub password_length: usize,
}

/// The admin user (its password is logged once, when it is created).
pub const ADMIN_USER: SystemUser = SystemUser {
    username: "admin",
    email: "admin@admin.com",
    role_id: 1,
    password_length: 24,
};

/// The scheduler user, removed again when the process stops.
pub const SCHEDULER_USER: SystemUser = SystemUser {
    username: "scheduler",
    email: "scheduler@scheduler.com",
    role_id: 3,
    password_length: 12,
};
