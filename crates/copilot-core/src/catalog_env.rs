//! The settings the Detections Catalog reads from the environment
//! (`copilot-searches`), raw as `os.getenv` returns them.

use crate::config::Secret;
use crate::env::EnvFile;

/// Raw catalog settings (`None` = unset).
#[derive(Debug, Clone, Default)]
pub struct CatalogEnv {
    /// `GITHUB_TOKEN`: the bearer token of the GitHub calls when a custom
    /// repository has none of its own (unset or empty = no
    /// `Authorization`).
    pub github_token: Option<Secret>,
    /// `COPILOT_CATALOG_REFRESH`: whether this process refreshes its catalog
    /// caches itself (warm-up and the two loops); on unless `0`, `false`,
    /// `no` or `off`.
    pub refresh: Option<String>,
    /// `COPILOT_GITHUB_API_URL` — tests only: GitHub's API base instead of
    /// `https://api.github.com`.
    pub github_api_url: Option<String>,
    /// `COPILOT_GITHUB_RAW_URL` — tests only: the raw files' base instead of
    /// `https://raw.githubusercontent.com`.
    pub github_raw_url: Option<String>,
    /// `COPILOT_MITRE_STIX_URL` — tests only: the ATT&CK bundle's URL.
    pub mitre_stix_url: Option<String>,
}

impl CatalogEnv {
    /// Read the values the way `os.getenv` would see them.
    pub fn from_env(env: &EnvFile) -> Self {
        let url = |key: &str| {
            env.get(key)
                .map(|v| v.trim().trim_end_matches('/').to_string())
                .filter(|v| !v.is_empty())
        };
        Self {
            github_token: env.get_raw("GITHUB_TOKEN").map(Secret::new),
            refresh: env.get_raw("COPILOT_CATALOG_REFRESH"),
            github_api_url: url("COPILOT_GITHUB_API_URL"),
            github_raw_url: url("COPILOT_GITHUB_RAW_URL"),
            mitre_stix_url: env
                .get("COPILOT_MITRE_STIX_URL")
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
        }
    }

    /// `COPILOT_CATALOG_REFRESH` read as a switch (on unless `0`, `false`,
    /// `no` or `off`, any case).
    pub fn refresh_enabled(&self) -> bool {
        self.refresh.as_deref().is_none_or(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_catalog_settings() {
        let env = EnvFile::isolated(
            "GITHUB_TOKEN=tok\nCOPILOT_CATALOG_REFRESH= Off \nCOPILOT_GITHUB_API_URL=http://x/\n",
        );
        let c = CatalogEnv::from_env(&env);
        assert_eq!(c.github_token.as_ref().map(Secret::expose), Some("tok"));
        assert!(!c.refresh_enabled());
        assert_eq!(c.github_api_url.as_deref(), Some("http://x"));
        assert_eq!(c.github_raw_url, None);
        assert!(CatalogEnv::from_env(&EnvFile::isolated("")).refresh_enabled());
        let on = CatalogEnv::from_env(&EnvFile::isolated("COPILOT_CATALOG_REFRESH=yes\n"));
        assert!(on.refresh_enabled());
    }
}
