//! The dashboard templates and the dashboard enums of
//! `app/connectors/grafana/schema/dashboards.py`.
//!
//! **One source, compiled in.** Python reads
//! `backend/app/connectors/grafana/dashboards/<folder>/<file>.json` from disk
//! on every call; the Rust image carries no `backend/`, so `build.rs` embeds
//! that very tree at build time ([`FILES`], an `include_str!` per file, with
//! `cargo:rerun-if-changed` on each) — there is no copy under `crates/`, and
//! `crates/copilot/Dockerfile` copies the directory into the build context.
//! A template edited on disk therefore reaches Python at once and Rust at its
//! next build. When phase 5 retires the Python backend the directory moves
//! under this crate.
//!
//! The enums are [`DashboardClass`] tables, member by member in declaration
//! order; `valid_dashboards` ([`valid`]) is their concatenation in
//! `provision_dashboards`' order, keyed by member name (a dict: a name that
//! came twice would keep its first place and its last value).

include!(concat!(env!("OUT_DIR"), "/templates.rs"));

/// One enum member: its name and its `(folder, file)` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dashboard {
    /// The member name (`WAZUH_SUMMARY`), what requests name.
    pub name: &'static str,
    /// The folder under `dashboards/`.
    pub folder: &'static str,
    /// The file in that folder.
    pub file: &'static str,
}

impl Dashboard {
    const fn new(name: &'static str, folder: &'static str, file: &'static str) -> Self {
        Self { name, folder, file }
    }

    /// The template's text (`get_dashboard_path(value)` read), if embedded.
    pub fn template(&self) -> Option<&'static str> {
        template(self.folder, self.file)
    }
}

/// One dashboard enum class.
#[derive(Debug)]
pub struct DashboardClass {
    /// The class name.
    pub name: &'static str,
    /// Its members in declaration order (`list(Enum)`; no class has aliases).
    pub members: &'static [Dashboard],
}

impl DashboardClass {
    /// `[dashboard.name for dashboard in Class]`.
    pub fn names(&self) -> Vec<String> {
        self.members.iter().map(|d| d.name.to_string()).collect()
    }
}

/// The embedded text of `dashboards/<folder>/<file>`.
pub fn template(folder: &str, file: &str) -> Option<&'static str> {
    let path = format!("{folder}/{file}");
    FILES
        .iter()
        .find(|(rel, _)| *rel == path)
        .map(|(_, text)| *text)
}

/// `valid_dashboards`: every member of [`CLASSES`], keyed by name, in the
/// dict's order.
pub fn valid() -> Vec<Dashboard> {
    let mut out: Vec<Dashboard> = Vec::new();
    for class in CLASSES {
        for member in class.members {
            match out.iter_mut().find(|d| d.name == member.name) {
                Some(slot) => *slot = *member,
                None => out.push(*member),
            }
        }
    }
    out
}

/// `valid_dashboards[name]`.
pub fn find(name: &str) -> Option<Dashboard> {
    valid().into_iter().find(|d| d.name == name)
}

/// `WazuhDashboard`.
pub static WAZUH: DashboardClass = DashboardClass {
    name: "WazuhDashboard",
    members: &[
        Dashboard::new("WAZUH_SUMMARY", "Wazuh", "summary.json"),
        Dashboard::new(
            "EDR_WINDOWS_EVENT_LOGS",
            "Wazuh",
            "edr_windows_event_logs.json",
        ),
        Dashboard::new("EDR_USERS_AND_GROUPS", "Wazuh", "edr_users_and_groups.json"),
        Dashboard::new(
            "EDR_SYSTEM_SECURITY_AUDIT",
            "Wazuh",
            "edr_system_security_audit.json",
        ),
        Dashboard::new("EDR_SYSTEM_PROCESSES", "Wazuh", "edr_system_processes.json"),
        Dashboard::new(
            "EDR_PROCESS_INJECTION",
            "Wazuh",
            "edr_process_injection.json",
        ),
        Dashboard::new("EDR_OPEN_AUDIT", "Wazuh", "edr_open_audit.json"),
        Dashboard::new("EDR_NETWORK_SCAN", "Wazuh", "edr_network_scan.json"),
        Dashboard::new(
            "EDR_NETWORK_CONNECTIONS",
            "Wazuh",
            "edr_network_connections.json",
        ),
        Dashboard::new("EDR_MITRE", "Wazuh", "edr_mitre.json"),
        Dashboard::new("EDR_FIM", "Wazuh", "edr_fim.json"),
        Dashboard::new(
            "EDR_DOCKER_MONITORING",
            "Wazuh",
            "edr_docker_monitoring.json",
        ),
        Dashboard::new("EDR_DNS_REQUESTS", "Wazuh", "edr_dns_requests.json"),
        Dashboard::new("EDR_DLL_SIDE_LOADING", "Wazuh", "edr_dll_side_loading.json"),
        Dashboard::new("EDR_COMPLIANCE", "Wazuh", "edr_compliance.json"),
        Dashboard::new("EDR_AV_MALWARE_IOC", "Wazuh", "edr_av_malware_ioc.json"),
        Dashboard::new("EDR_AGENT_INVENTORY", "Wazuh", "edr_agent_inventory.json"),
        Dashboard::new("EDR_AD_INVENTORY", "Wazuh", "edr_ad_inventory.json"),
    ],
};

/// `Office365Dashboard`.
pub static OFFICE365: DashboardClass = DashboardClass {
    name: "Office365Dashboard",
    members: &[
        Dashboard::new("ACTIVE_DIRECTORY", "Office365", "active_directory.json"),
        Dashboard::new("APPLICATIONS", "Office365", "applications.json"),
        Dashboard::new("COMPLIANCE_CENTER", "Office365", "compliance_center.json"),
        Dashboard::new(
            "DEFENDER_FOR_IDENTITIY",
            "Office365",
            "defender_for_identity.json",
        ),
        Dashboard::new("DLP", "Office365", "dlp.json"),
        Dashboard::new("ENDPOINT", "Office365", "endpoint.json"),
        Dashboard::new("EXCHANGE", "Office365", "exchange.json"),
        Dashboard::new("FORMS", "Office365", "forms.json"),
        Dashboard::new("MITRE", "Office365", "mitre.json"),
        Dashboard::new("ONEDRIVE", "Office365", "onedrive.json"),
        Dashboard::new("POWERBI", "Office365", "powerbi.json"),
        Dashboard::new("SHAREPOINT", "Office365", "sharepoint.json"),
        Dashboard::new("OFFICE365_SUMMARY", "Office365", "summary.json"),
        Dashboard::new("TEAMS", "Office365", "teams.json"),
        Dashboard::new(
            "THREAT_INTELLIGENCE",
            "Office365",
            "threat_intelligence.json",
        ),
    ],
};

/// `MimecastDashboard`.
pub static MIMECAST: DashboardClass = DashboardClass {
    name: "MimecastDashboard",
    members: &[Dashboard::new(
        "MIMECAST_SUMMARY",
        "Mimecast",
        "summary.json",
    )],
};

/// `SapSiemDashboard`.
pub static SAP_SIEM: DashboardClass = DashboardClass {
    name: "SapSiemDashboard",
    members: &[Dashboard::new("USERS_AUTH", "SapSiem", "users_auth.json")],
};

/// `HuntressDashboard`.
pub static HUNTRESS: DashboardClass = DashboardClass {
    name: "HuntressDashboard",
    members: &[Dashboard::new(
        "HUNTRESS_SUMMARY",
        "Huntress",
        "summary.json",
    )],
};

/// `CarbonBlackDashboard`.
pub static CARBON_BLACK: DashboardClass = DashboardClass {
    name: "CarbonBlackDashboard",
    members: &[Dashboard::new(
        "CARBONBLACK_SUMMARY",
        "CarbonBlack",
        "summary.json",
    )],
};

/// `FortinetDashboard`.
pub static FORTINET: DashboardClass = DashboardClass {
    name: "FortinetDashboard",
    members: &[
        Dashboard::new(
            "FORTINET_SYSTEM_LOGS",
            "Fortinet",
            "fortinet_system_logs.json",
        ),
        Dashboard::new(
            "FORTINET_UTM_ANOMALIES",
            "Fortinet",
            "fortinet_utm_anomalies.json",
        ),
        Dashboard::new(
            "FORTINET_UTM_APP_CONTROL",
            "Fortinet",
            "fortinet_utm_app_control.json",
        ),
        Dashboard::new("FOTINET_UTM_DLP", "Fortinet", "fortinet_utm_dlp.json"),
        Dashboard::new("FORTINET_UTM_DNS", "Fortinet", "fortinet_utm_dns.json"),
        Dashboard::new("FORTINET_UTM_IPS", "Fortinet", "fortinet_utm_ips.json"),
        Dashboard::new("FORTINET_UTM_SSL", "Fortinet", "fortinet_utm_ssl.json"),
        Dashboard::new(
            "FORTINET_UTM_SUMMARY",
            "Fortinet",
            "fortinet_utm_summary.json",
        ),
        Dashboard::new("FORTINET_UTM_VIRUS", "Fortinet", "fortinet_utm_virus.json"),
        Dashboard::new(
            "FORTINET_UTM_WEBFILTER",
            "Fortinet",
            "fortinet_utm_webfilter.json",
        ),
        Dashboard::new("FORTINET_VPN", "Fortinet", "fortinet_vpn.json"),
    ],
};

/// `CrowdstrikeDashboard`.
pub static CROWDSTRIKE: DashboardClass = DashboardClass {
    name: "CrowdstrikeDashboard",
    members: &[Dashboard::new(
        "CROWDSTRIKE_SUMMARY",
        "Crowdstrike",
        "summary.json",
    )],
};

/// `DuoDashboard`.
pub static DUO: DashboardClass = DashboardClass {
    name: "DuoDashboard",
    members: &[Dashboard::new("DUO_AUTH", "Duo", "duo_auth.json")],
};

/// `DarktraceDashboard`.
pub static DARKTRACE: DashboardClass = DashboardClass {
    name: "DarktraceDashboard",
    members: &[Dashboard::new(
        "DARKTRACE_SUMMARY",
        "Darktrace",
        "summary.json",
    )],
};

/// `BitdefenderDashboard`.
pub static BITDEFENDER: DashboardClass = DashboardClass {
    name: "BitdefenderDashboard",
    members: &[Dashboard::new(
        "BITDEFENDER_SUMMARY",
        "Bitdefender",
        "summary.json",
    )],
};

/// `CatoDashboard`.
pub static CATO: DashboardClass = DashboardClass {
    name: "CatoDashboard",
    members: &[Dashboard::new("CATO_SUMMARY", "Cato", "summary.json")],
};

/// `DefenderForEndpointDashboard`.
pub static DEFENDER_FOR_ENDPOINT: DashboardClass = DashboardClass {
    name: "DefenderForEndpointDashboard",
    members: &[Dashboard::new(
        "DEFENDERFORENDPOINT_SUMMARY",
        "DefenderForEndpoint",
        "summary.json",
    )],
};

/// `SonicwallDashboard`.
pub static SONICWALL: DashboardClass = DashboardClass {
    name: "SonicwallDashboard",
    members: &[
        Dashboard::new("SONICWALL_SUMMARY", "Sonicwall", "sonicwall_summary.json"),
        Dashboard::new("SONICWALL_VPN", "Sonicwall", "sonicwall_vpn.json"),
        Dashboard::new(
            "SONICWALL_APP_CONTROL",
            "Sonicwall",
            "sonicwall_app_control.json",
        ),
        Dashboard::new("SONICWALL_SD_WAN", "Sonicwall", "sonicwall_sdwan.json"),
        Dashboard::new("SONICWALL_IPS", "Sonicwall", "sonicwall_ips.json"),
    ],
};

/// `SentinelOneDashboard`.
pub static SENTINELONE: DashboardClass = DashboardClass {
    name: "SentinelOneDashboard",
    members: &[
        Dashboard::new(
            "SENTINELONE_EPP_ADMINISTRATIVE",
            "Sentinelone",
            "sentinelone_epp_administrative.json",
        ),
        Dashboard::new(
            "SENTINELONE_EPP_MITIGATION",
            "Sentinelone",
            "sentinelone_epp_mitigation.json",
        ),
        Dashboard::new(
            "SENTINELONE_EPP_RANGER",
            "Sentinelone",
            "sentinelone_epp_ranger.json",
        ),
        Dashboard::new(
            "SENTINELONE_EPP_WHITELISTBLACKLIST",
            "Sentinelone",
            "sentinelone_epp_whitelistblacklist.json",
        ),
        Dashboard::new(
            "SENTINELONE_EPP_MALWARE",
            "Sentinelone",
            "sentinelone_epp_malware.json",
        ),
        Dashboard::new(
            "SENTINELONE_EPP_OPERATIONS",
            "Sentinelone",
            "sentinelone_epp_operations.json",
        ),
        Dashboard::new(
            "SENTINELONE_EPP_SUMMARY",
            "Sentinelone",
            "sentinelone_epp_summary.json",
        ),
    ],
};

/// The classes in the order `provision_dashboards` concatenates them.
pub static CLASSES: &[&DashboardClass] = &[
    &WAZUH,
    &OFFICE365,
    &MIMECAST,
    &SAP_SIEM,
    &HUNTRESS,
    &CARBON_BLACK,
    &FORTINET,
    &CROWDSTRIKE,
    &DUO,
    &DARKTRACE,
    &BITDEFENDER,
    &CATO,
    &DEFENDER_FOR_ENDPOINT,
    &SONICWALL,
    &SENTINELONE,
];
