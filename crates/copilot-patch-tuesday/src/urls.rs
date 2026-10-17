//! The three public feeds, Python's module constants (`MSRC_CVRF_BASE`,
//! `EPSS_BASE`, `CISA_KEV_JSON`). Each can be pointed at a stand-in for the
//! parity harness — never in production — as `COPILOT_EPSS_URL` already is
//! for the threat-intel routes (the same variable names the same feed).

/// The upstream URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Urls {
    /// `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf`, before `/{cycle}`
    /// (`COPILOT_MSRC_CVRF_URL`).
    pub msrc: String,
    /// `https://api.first.org/data/v1/epss` (`COPILOT_EPSS_URL`).
    pub epss: String,
    /// CISA's `known_exploited_vulnerabilities.json` (`COPILOT_CISA_KEV_URL`).
    pub kev: String,
}

impl Default for Urls {
    fn default() -> Self {
        Self {
            msrc: "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf".into(),
            epss: "https://api.first.org/data/v1/epss".into(),
            kev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                .into(),
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
            msrc: over("COPILOT_MSRC_CVRF_URL", d.msrc),
            epss: over("COPILOT_EPSS_URL", d.epss),
            kev: over("COPILOT_CISA_KEV_URL", d.kev),
        }
    }
}
