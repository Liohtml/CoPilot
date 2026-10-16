//! The public endpoints the Python services call, as module constants there.
//! Each can be pointed at a stand-in for the parity harness — never in
//! production — as `COPILOT_EPSS_URL` and `COPILOT_VERSION_CHECK_URL` are.

/// The upstream URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Urls {
    /// `https://api.first.org/data/v1/epss` (`COPILOT_EPSS_URL`).
    pub epss: String,
    /// `https://intel.socfortress.co/search` (`COPILOT_SOCFORTRESS_INTEL_URL`).
    pub intel: String,
    /// `https://ai.socfortress.co`, before `/analyze-alert` and
    /// `/wazuh-exclusion-rule` (`COPILOT_SOCFORTRESS_AI_URL`).
    pub ai: String,
    /// `https://mcp.socfortress.co/query`, the cloud MCP services' base
    /// (`COPILOT_SOCFORTRESS_MCP_URL`).
    pub mcp: String,
    /// `https://license.socfortress.co/`, before the endpoint
    /// (`COPILOT_LICENSE_URL`).
    pub license: String,
    /// `https://www.virustotal.com/api/v3`, before `/files` and `/analyses`
    /// (`COPILOT_VIRUSTOTAL_URL`).
    pub virustotal: String,
}

impl Default for Urls {
    fn default() -> Self {
        Self {
            epss: "https://api.first.org/data/v1/epss".into(),
            intel: "https://intel.socfortress.co/search".into(),
            ai: "https://ai.socfortress.co".into(),
            mcp: "https://mcp.socfortress.co/query".into(),
            license: "https://license.socfortress.co/".into(),
            virustotal: "https://www.virustotal.com/api/v3".into(),
        }
    }
}

impl Urls {
    /// The defaults, each replaced by its variable when that is set.
    pub fn from_env() -> Self {
        let over = |name: &str, default: String| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or(default)
        };
        let d = Self::default();
        Self {
            epss: over("COPILOT_EPSS_URL", d.epss),
            intel: over("COPILOT_SOCFORTRESS_INTEL_URL", d.intel),
            ai: over("COPILOT_SOCFORTRESS_AI_URL", d.ai),
            mcp: over("COPILOT_SOCFORTRESS_MCP_URL", d.mcp),
            license: over("COPILOT_LICENSE_URL", d.license),
            virustotal: over("COPILOT_VIRUSTOTAL_URL", d.virustotal),
        }
    }
}
