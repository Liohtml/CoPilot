//! The upstream overrides of the security assessments (`copilot-assessments`:
//! the GitHub organization audit and the Nuclei web scans). Both are for the
//! e2e and parity harnesses only; production leaves them unset and reaches
//! the URLs the Python services hard-code.

use crate::env::EnvFile;

/// The two test-only overrides (`None` = unset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssessmentsEnv {
    /// `COPILOT_GITHUB_AUDIT_API_URL` — tests only: the GitHub API base the
    /// audit calls instead of `https://api.github.com`.
    pub github_api_url: Option<String>,
    /// `COPILOT_NUCLEI_MODULE_URL` — tests only: every request to
    /// `http://copilot-nuclei-module/…` goes to `{url}/{host}{path}`.
    pub nuclei_module_url: Option<String>,
}

impl AssessmentsEnv {
    /// Read both, trimmed, without a trailing `/`.
    pub fn from_env(env: &EnvFile) -> Self {
        let url = |key: &str| {
            env.get(key)
                .map(|v| v.trim().trim_end_matches('/').to_string())
                .filter(|v| !v.is_empty())
        };
        Self {
            github_api_url: url("COPILOT_GITHUB_AUDIT_API_URL"),
            nuclei_module_url: url("COPILOT_NUCLEI_MODULE_URL"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_overrides() {
        let env = EnvFile::isolated(
            "COPILOT_GITHUB_AUDIT_API_URL= http://127.0.0.1:1/ \nCOPILOT_NUCLEI_MODULE_URL=\n",
        );
        let a = AssessmentsEnv::from_env(&env);
        assert_eq!(a.github_api_url.as_deref(), Some("http://127.0.0.1:1"));
        assert_eq!(a.nuclei_module_url, None);
        assert_eq!(
            AssessmentsEnv::from_env(&EnvFile::isolated("")),
            AssessmentsEnv::default()
        );
    }
}
