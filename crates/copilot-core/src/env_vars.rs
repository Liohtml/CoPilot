//! Every environment variable this build knows: the ones it reads, and the
//! others a CoPilot `.env` holds (the Python backend's, the other Compose
//! services', Compose's own, obsolete ones).
//!
//! `copilot doctor` lists the variables of the environment and of `.env`
//! that are not in this table — a typo, or a variable of another release —
//! and the test-only ones that are set ([`report`]). `scripts/check-compose.py`
//! parses this file: it checks that every variable the sources read is here,
//! that `.env.example` documents every [`Kind::Read`] and [`Kind::Seed`]
//! variable and none of the [`Kind::Test`] ones, and that the Compose files
//! pass the Rust service only variables it reads. Keep one entry per line, as
//! `("NAME", Kind),`.

use std::collections::BTreeSet;

/// What a variable is to this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Read by this build (at start, per request or by a job).
    Read,
    /// Read by the startup tasks when they seed the `connectors` table
    /// (`add_connectors`, as `app/db/db_populate.py`): only a connector that
    /// has no row yet takes these; later changes are made on the Connectors
    /// page. Built from [`CONNECTOR_SEED_PREFIXES`] and [`SEED_SUFFIXES`],
    /// plus [`SEED_EXTRA`].
    Seed,
    /// Read by this build, but set only by the test and parity harnesses (a
    /// stand-in's address, a debugging switch): never set in production, and
    /// left out of `.env.example`.
    Test,
    /// Read only by the Python backend (the Compose `legacy` profile and the
    /// staged-rollout overlay).
    Legacy,
    /// Another Compose service's (`copilot-mcp`, the frontends, the
    /// inspector runner) or Compose's own; this build ignores it.
    Compose,
    /// Read by no CoPilot service any more; found in older `.env` files.
    Obsolete,
    /// The operating system's, the container runtime's or the image's
    /// (`PATH`, `HOME`, the proxies, …); never reported.
    System,
}

impl Kind {
    /// One word for `copilot doctor`.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Read => "read",
            Kind::Seed => "seed",
            Kind::Test => "test-only",
            Kind::Legacy => "legacy",
            Kind::Compose => "compose",
            Kind::Obsolete => "obsolete",
            Kind::System => "system",
        }
    }
}

use Kind::{Compose, Legacy, Obsolete, Read, System, Test};

/// The table (connector seeds aside: [`kind`] builds those).
pub const KNOWN: &[(&str, Kind)] = &[
    // --- the process -----------------------------------------------------
    ("COPILOT_ROOT", Read),
    ("COPILOT_BIND", Read),
    ("SERVER_IP", Read),
    ("COPILOT_PORT", Read),
    ("COPILOT_LEGACY_URL", Read),
    ("COPILOT_MAX_BODY_BYTES", Read),
    ("COPILOT_LOG_FORMAT", Read),
    ("LOG_LEVEL", Read),
    ("RUST_LOG", Read),
    ("ENVIRONMENT", Read),
    // --- schema and startup tasks (phase 5) -------------------------------
    ("COPILOT_RUN_MIGRATIONS", Read),
    ("COPILOT_STARTUP_TASKS", Read),
    ("MYSQL_ROOT_PASSWORD", Read),
    // --- MySQL ------------------------------------------------------------
    ("MYSQL_URL", Read),
    ("MYSQL_USER", Read),
    ("MYSQL_PASSWORD", Read),
    ("MYSQL_DATABASE", Read),
    ("COPILOT_DATABASE_URL", Read),
    ("DB_POOL_SIZE", Read),
    ("DB_MAX_OVERFLOW", Read),
    ("DB_POOL_TIMEOUT", Read),
    ("DB_POOL_RECYCLE", Read),
    // --- secrets ------------------------------------------------------------
    ("JWT_SECRET", Read),
    ("ACCESS_TOKEN_EXPIRE_MINUTES", Read),
    ("TOTP_ENCRYPTION_KEY", Read),
    ("SSO_STATE_SECRET", Read),
    ("WAF_TOKEN_ENCRYPTION_KEY", Read),
    ("COPILOT_API_KEY", Read),
    // --- passkeys -----------------------------------------------------------
    ("WEBAUTHN_ORIGINS", Read),
    ("WEBAUTHN_ORIGIN", Read),
    ("WEBAUTHN_RP_ID", Read),
    ("WEBAUTHN_RP_NAME", Read),
    // --- webhooks and forwarding -------------------------------------------
    ("GRAYLOG_API_HEADER_VALUE", Read),
    ("VELOCIRAPTOR_API_HEADER_VALUE", Read),
    ("GRAFANA_API_HEADER_VALUE", Read),
    ("ALERT_FORWARDING_IP", Read),
    ("WAF_SYSLOG_PORT_RANGE", Read),
    ("WAF_SYSLOG_DEFAULT_HOST", Read),
    // --- notifications ------------------------------------------------------
    ("COPILOT_URL", Read),
    ("DEFAULT_ALERT_SEVERITY", Read),
    ("SMTP_HOST", Read),
    ("SMTP_PORT", Read),
    ("SMTP_USERNAME", Read),
    ("SMTP_PASSWORD", Read),
    ("SMTP_FROM", Read),
    ("SMTP_USE_TLS", Read),
    // --- caches -------------------------------------------------------------
    ("CONNECTOR_CACHE_TTL_SECONDS", Read),
    ("CONNECTOR_CACHE_CHECK_SECONDS", Read),
    ("BRANDING_CACHE_TTL_SECONDS", Read),
    ("BRANDING_CACHE_CHECK_SECONDS", Read),
    ("COPILOT_CATALOG_REFRESH", Read),
    ("COPILOT_SIDEBAR_REFRESH", Read),
    ("GITHUB_TOKEN", Read),
    // --- scheduler ----------------------------------------------------------
    ("COPILOT_SCHEDULER_OWNER", Read),
    ("COPILOT_RS_JOBS", Read),
    ("COPILOT_RS_PALACE_JOBS", Read),
    ("AUDIT_LOG_RETENTION_DAYS", Read),
    // --- MinIO --------------------------------------------------------------
    ("MINIO_URL", Read),
    ("MINIO_ROOT_USER", Read),
    ("MINIO_ROOT_PASSWORD", Read),
    ("MINIO_SECURE", Read),
    ("SSL_CERT_FILE", Read),
    // --- connectors ---------------------------------------------------------
    ("TALON_VERIFY_TLS", Read),
    ("INFLUXDB_VERIFY_SSL", Read),
    ("VELOCIRAPTOR_QUERY_TIMEOUT", Read),
    ("VELOCIRAPTOR_FLOW_TIMEOUT", Read),
    ("VELOCIRAPTOR_MAX_CONCURRENT_FLOW_WAITS", Read),
    ("VELOCIRAPTOR_LINUX_QUARANTINE_ARTIFACT", Read),
    ("VELOCIRAPTOR_WINDOWS_QUARANTINE_ARTIFACT", Read),
    ("VELOCIRAPTOR_API_FILE", Read),
    ("AWS_ENDPOINT_URL", Read),
    ("AWS_ENDPOINT_URL_STS", Read),
    ("AWS_ENDPOINT_URL_S3", Read),
    // --- alert ingest -------------------------------------------------------
    ("MDR_ENABLED", Read),
    ("MDR_SERVER_URL", Read),
    ("MDR_COLLECTOR_UUID", Read),
    ("THRESHOLD_SOURCE_INDEX_MAPPING", Read),
    ("THRESHOLD_SOURCE_INDEX_FALLBACK_ENABLED", Read),
    // --- file analysis ------------------------------------------------------
    ("INSPECTOR_URL", Read),
    ("INSPECTOR_HTTP_TIMEOUT", Read),
    ("FILE_ANALYSIS_MINIO_BUCKET", Read),
    ("FILE_ANALYSIS_MAX_FLOW_FILES", Read),
    ("FILE_ANALYSIS_MINIO_RETRIES", Read),
    ("FILE_ANALYSIS_MINIO_BACKOFF", Read),
    ("FILE_ANALYSIS_COLLECT_TIMEOUT", Read),
    ("FILE_ANALYSIS_ENUM_TIMEOUT", Read),
    ("FILE_ANALYSIS_MAX_CONCURRENT_JOBS", Read),
    ("VELOCIRAPTOR_API_CONFIG", Read),
    ("SANDBOX_BACKEND", Read),
    ("CAPE_API_URL", Read),
    ("CAPE_API_TOKEN", Read),
    ("CAPE_TASK_TIMEOUT", Read),
    ("CAPE_POLL_INTERVAL", Read),
    ("CAPE_POLL_TIMEOUT", Read),
    ("CAPE_HTTP_TIMEOUT", Read),
    ("CAPE_PACKAGE", Read),
    ("ENRICHMENT_SUBMIT_FILES", Read),
    ("ENRICHMENT_VT_MALICIOUS_THRESHOLD", Read),
    ("ENRICHMENT_VT_MAX_WAIT", Read),
    ("ENRICHMENT_VT_POLL", Read),
    ("ENRICHMENT_VT_DEEP", Read),
    ("ENRICHMENT_VT_MAX_UPLOAD_MB", Read),
    // --- paths (set by the image or by Compose) ------------------------------
    ("COPILOT_BACKEND_DATA_DIR", Read),
    ("COPILOT_SCOUTSUITE_DIR", Read),
    ("COPILOT_MIMECAST_DIR", Read),
    ("COPILOT_WKHTMLTOPDF", Read),
    ("COPILOT_CHROMIUM", Read),
    ("COPILOT_REPORT_FONT_DIR", Read),
    ("PLAYWRIGHT_BROWSERS_PATH", Read),
    // --- this process's instrumentation (/api/performance) ------------------
    ("PERF_MONITOR_ENABLED", Read),
    ("PERF_LAG_SAMPLE_INTERVAL", Read),
    ("PERF_LAG_STALL_THRESHOLD_MS", Read),
    ("PERF_SLOW_REQUEST_MS", Read),
    ("PERF_RECENT_REQUESTS", Read),
    ("PERF_RECENT_STALLS", Read),
    ("PERF_LAG_SAMPLES", Read),
    ("PERF_DURATION_SAMPLES", Read),
    ("PERF_MAX_ENDPOINTS", Read),
    ("DB_SLOW_QUERY_MS", Read),
    ("DB_QUERY_SAMPLES", Read),
    ("DB_MAX_STATEMENTS", Read),
    // --- test and parity harnesses only -------------------------------------
    ("COPILOT_TEST_DATABASE_URL", Test),
    ("COPILOT_MINIO_ENDPOINT", Test),
    ("COPILOT_GITHUB_API_URL", Test),
    ("COPILOT_GITHUB_RAW_URL", Test),
    ("COPILOT_MITRE_STIX_URL", Test),
    ("COPILOT_INTEGRATION_MODULES_URL", Test),
    ("COPILOT_AWS_PROFILE_CHECK_SECONDS", Test),
    ("COPILOT_BITDEFENDER_URL", Test),
    ("COPILOT_PROVISION_WORKER_PORT", Test),
    ("COPILOT_GITHUB_AUDIT_API_URL", Test),
    ("COPILOT_NUCLEI_MODULE_URL", Test),
    ("COPILOT_VERSION_CHECK_URL", Test),
    ("COPILOT_SSO_IDP_URL", Test),
    ("COPILOT_EPSS_URL", Test),
    ("COPILOT_LICENSE_URL", Test),
    ("COPILOT_SOCFORTRESS_INTEL_URL", Test),
    ("COPILOT_SOCFORTRESS_AI_URL", Test),
    ("COPILOT_SOCFORTRESS_MCP_URL", Test),
    ("COPILOT_VIRUSTOTAL_URL", Test),
    ("COPILOT_CISA_KEV_URL", Test),
    ("COPILOT_MSRC_CVRF_URL", Test),
    ("COPILOT_SCA_REPO_URL", Test),
    ("COPILOT_MCP_LOCAL_URL", Test),
    ("COPILOT_ACTION_URL", Test),
    ("COPILOT_CHART_DUMP", Test),
    // --- the Python backend only (legacy profile) ----------------------------
    ("COPILOT_PY_SCHEDULER", Legacy),
    ("PERF_LOG_ENABLED", Legacy),
    ("PERF_LOG_DIR", Legacy),
    ("PERF_LOG_SNAPSHOT_INTERVAL", Legacy),
    ("PERF_LOG_RETENTION", Legacy),
    ("PERF_SESSION_LABEL", Legacy),
    ("CANCEL_ON_DISCONNECT", Legacy),
    ("CANCEL_ON_DISCONNECT_EXCLUDE", Legacy),
    ("INTEGRITY_ENFORCE", Legacy),
    ("CRYPTOLENS_AUTH", Legacy),
    ("FILE_ANALYSIS_SCRATCH", Legacy),
    ("FLASK_DEBUG", Legacy),
    ("SECRET_KEY", Legacy),
    ("SQLALCHEMY_DATABASE_URI", Legacy),
    // --- other Compose services, and Compose itself -------------------------
    ("SERVER_HOST", Compose),
    ("TLS_CERT_PATH", Compose),
    ("TLS_KEY_PATH", Compose),
    ("COMPOSE_PROFILES", Compose),
    ("COMPOSE_PROJECT_NAME", Compose),
    ("COMPOSE_FILE", Compose),
    ("INSPECTOR_MODE", Compose),
    ("FILE_ANALYSIS_DEV_MODE", Compose),
    ("OPENAI_API_KEY", Compose),
    ("OPENAI_MODEL", Compose),
    ("MCP_SERVER_ENABLED", Compose),
    ("OPENSEARCH_URL", Compose),
    ("OPENSEARCH_USERNAME", Compose),
    ("OPENSEARCH_PASSWORD", Compose),
    ("OPENSEARCH_SSL_VERIFY", Compose),
    ("OPENSEARCH_SSL_SHOW_WARN", Compose),
    ("MCP_OPENSEARCH_AUTH_TOKEN", Compose),
    ("MYSQL_ENABLED", Compose),
    ("MYSQL_HOST", Compose),
    ("MYSQL_PORT", Compose),
    ("MCP_MYSQL_AUTH_TOKEN", Compose),
    ("MCP_MYSQL_SERVER_ENABLED", Compose),
    ("WAZUH_PROD_URL", Compose),
    ("WAZUH_PROD_USERNAME", Compose),
    ("WAZUH_PROD_PASSWORD", Compose),
    ("WAZUH_PROD_SSL_VERIFY", Compose),
    ("WAZUH_PROD_TIMEOUT", Compose),
    ("MCP_WAZUH_AUTH_TOKEN", Compose),
    ("MCP_WAZUH_SERVER_ENABLED", Compose),
    ("VELOCIRAPTOR_SSL_VERIFY", Compose),
    ("VELOCIRAPTOR_TIMEOUT", Compose),
    ("MCP_VELOCIRAPTOR_AUTH_TOKEN", Compose),
    ("MCP_VELOCIRAPTOR_SERVER_ENABLED", Compose),
    ("MCP_VELOCIRAPTOR_HOST", Compose),
    ("MCP_VELOCIRAPTOR_PORT", Compose),
    // --- no CoPilot service reads these any more ------------------------------
    ("SHUFFLER_API_KEY", Obsolete),
    ("SHUFFLE_WORKFLOW_ID", Obsolete),
    ("ALERT_CREATION_PROVISIONING_URL", Obsolete),
    ("VELOCIRAPTOR_API_KEY_PATH", Obsolete),
    ("GZIP_MINIMUM_SIZE", Obsolete),
    ("ASKSOCFORTRESS_URL", Obsolete),
    ("ASKSOCFORTRESS_API_KEY", Obsolete),
    ("SOCFORTRESSTHREATINTEL_URL", Obsolete),
    ("SOCFORTRESSTHREATINTEL_API_KEY", Obsolete),
    ("CORTEX_URL", Obsolete),
    ("CORTEX_API_KEY", Obsolete),
    // --- the system's, the runtime's, the image's ---------------------------
    ("PATH", System),
    ("HOME", System),
    ("HOSTNAME", System),
    ("USER", System),
    ("LOGNAME", System),
    ("SHELL", System),
    ("PWD", System),
    ("OLDPWD", System),
    ("SHLVL", System),
    ("TERM", System),
    ("LANG", System),
    ("LANGUAGE", System),
    ("LC_ALL", System),
    ("TZ", System),
    ("TMPDIR", System),
    ("TMP", System),
    ("TEMP", System),
    ("XDG_CACHE_HOME", System),
    ("SSL_CERT_DIR", System),
    ("HTTP_PROXY", System),
    ("HTTPS_PROXY", System),
    ("NO_PROXY", System),
    ("ALL_PROXY", System),
    ("http_proxy", System),
    ("https_proxy", System),
    ("no_proxy", System),
    ("all_proxy", System),
];

/// The connectors whose rows the startup tasks seed from the environment,
/// as `db_populate.py`'s `get_connectors_list()` names them, turned into
/// variable prefixes (`connector_name.upper()`, `-` and ` ` to `_`).
pub const CONNECTOR_SEED_PREFIXES: &[&str] = &[
    "WAZUH_INDEXER",
    "WAZUH_MANAGER",
    "GRAYLOG",
    "SHUFFLE",
    "VELOCIRAPTOR",
    "SUBLIME",
    "INFLUXDB",
    "GRAFANA",
    "WAZUH_WORKER_PROVISIONING",
    "EVENT_SHIPPER",
    "HAPROXY_PROVISIONING",
    "VIRUSTOTAL",
    "PORTAINER",
    "GRAYLOG_NETWORK",
    "RESEND",
    "TALON",
    "OPENCTI",
    "SOCFORTRESS_UBA",
];

/// What `load_connector_data` reads after a connector's prefix.
pub const SEED_SUFFIXES: &[&str] = &[
    "_URL",
    "_USERNAME",
    "_PASSWORD",
    "_API_KEY",
    "_SUPPORTS",
    "_VERIFIED",
];

/// The connectors' `extra_data_key`s.
pub const SEED_EXTRA: &[&str] = &[
    "INFLUXDB_ORG_AND_BUCKET",
    "GELF_INPUT_PORT",
    "PORTAINER_ENDPOINT_ID",
    "RESEND_FROM_ADDRESS",
    "OPENCTI_PUBLIC_URL",
];

/// What `name` is, if this build knows it.
pub fn kind(name: &str) -> Option<Kind> {
    if let Some((_, k)) = KNOWN.iter().find(|(n, _)| *n == name) {
        return Some(*k);
    }
    if SEED_EXTRA.contains(&name) {
        return Some(Kind::Seed);
    }
    let seeded = CONNECTOR_SEED_PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| SEED_SUFFIXES.contains(&rest))
    });
    seeded.then_some(Kind::Seed)
}

/// The first `_`-separated word of every known variable but the system's:
/// a process variable is CoPilot's when it starts with one of these.
fn families() -> BTreeSet<&'static str> {
    KNOWN
        .iter()
        .filter(|(_, k)| *k != Kind::System)
        .map(|(n, _)| *n)
        .chain(CONNECTOR_SEED_PREFIXES.iter().copied())
        .chain(SEED_EXTRA.iter().copied())
        .filter_map(|n| n.split_once('_').map(|(head, _)| head))
        .collect()
}

/// What `copilot doctor` says about the environment.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Set, and not in the table: a typo, or another release's variable.
    pub unknown: Vec<String>,
    /// Set, and read by no CoPilot service any more.
    pub obsolete: Vec<String>,
    /// Set, and meant for the test harnesses only.
    pub test_only: Vec<String>,
}

/// Classify the variables set in `.env` (`file_keys`: every one is
/// CoPilot's) and in the process environment (`process_keys`: only those
/// that share their first word with a known variable are, so a shell's own
/// variables are not reported).
pub fn report<'a>(
    file_keys: impl IntoIterator<Item = &'a str>,
    process_keys: impl IntoIterator<Item = &'a str>,
) -> Report {
    let families = families();
    let ours = |name: &str| {
        name.split_once('_')
            .is_some_and(|(head, _)| families.contains(head))
    };
    let names: BTreeSet<&str> = file_keys
        .into_iter()
        .chain(process_keys.into_iter().filter(|n| ours(n)))
        .collect();
    let mut out = Report::default();
    for name in names {
        match kind(name) {
            None => out.unknown.push(name.to_string()),
            Some(Kind::Obsolete) => out.obsolete.push(name.to_string()),
            Some(Kind::Test) => out.test_only.push(name.to_string()),
            Some(_) => {}
        }
    }
    out
}

impl Report {
    /// One line per finding, `ok` when there is none.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.unknown.is_empty() {
            lines.push(format!(
                "unknown {} — not read by this build (a typo, or another release's variable?)",
                self.unknown.join(", ")
            ));
        }
        if !self.obsolete.is_empty() {
            lines.push(format!(
                "obsolete {} — no CoPilot service reads it any more",
                self.obsolete.join(", ")
            ));
        }
        if !self.test_only.is_empty() {
            lines.push(format!(
                "test-only {} — a test harness's stand-in; never set it in production",
                self.test_only.join(", ")
            ));
        }
        if lines.is_empty() {
            lines.push("ok (every variable set is known)".to_string());
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_no_duplicates_and_well_formed_names() {
        let mut seen = BTreeSet::new();
        for (name, _) in KNOWN {
            assert!(seen.insert(*name), "{name} listed twice");
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{name}"
            );
            // A seed is built, never listed: a listed one would shadow the rule.
            let seed = CONNECTOR_SEED_PREFIXES.iter().any(|p| {
                name.strip_prefix(p)
                    .is_some_and(|rest| SEED_SUFFIXES.contains(&rest))
            });
            assert!(!seed, "{name} is a connector seed");
        }
        for extra in SEED_EXTRA {
            assert!(!seen.contains(extra), "{extra}");
        }
    }

    #[test]
    fn seeds_follow_db_populate() {
        assert_eq!(kind("WAZUH_INDEXER_URL"), Some(Kind::Seed));
        assert_eq!(kind("SOCFORTRESS_UBA_API_KEY"), Some(Kind::Seed));
        assert_eq!(kind("GRAYLOG_NETWORK_PASSWORD"), Some(Kind::Seed));
        assert_eq!(kind("INFLUXDB_ORG_AND_BUCKET"), Some(Kind::Seed));
        assert_eq!(kind("TALON_VERIFIED"), Some(Kind::Seed));
        // Listed variables win over the rule.
        assert_eq!(kind("TALON_VERIFY_TLS"), Some(Kind::Read));
        assert_eq!(kind("SHUFFLER_API_KEY"), Some(Kind::Obsolete));
        assert_eq!(kind("WAZUH_INDEXER_URLL"), None);
    }

    #[test]
    fn report_sorts_findings_and_ignores_the_shell() {
        let r = report(
            [
                "JWT_SECRET",
                "JWT_SECRT",
                "SHUFFLER_API_KEY",
                "MY_OWN_THING",
            ],
            [
                "PATH",
                "SSH_AUTH_SOCK",
                "COPILOT_SHEDULER_OWNER",
                "COPILOT_LICENSE_URL",
                "MYSQL_URL",
                "LOG_FORMAT",
            ],
        );
        assert_eq!(
            r.unknown,
            [
                "COPILOT_SHEDULER_OWNER",
                "JWT_SECRT",
                "LOG_FORMAT",
                "MY_OWN_THING"
            ]
        );
        assert_eq!(r.obsolete, ["SHUFFLER_API_KEY"]);
        assert_eq!(r.test_only, ["COPILOT_LICENSE_URL"]);
        assert_eq!(r.lines().len(), 3);
        assert_eq!(
            report(["JWT_SECRET"], ["HOME", "TERM"]).lines(),
            ["ok (every variable set is known)"]
        );
    }
}
