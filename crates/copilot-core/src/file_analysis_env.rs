//! The settings File Analysis reads from the environment
//! (`copilot-file-analysis`), raw as `os.getenv` returns them: the Python
//! modules read them at import or per call with their own defaults, so an
//! unset value and an empty one are kept apart and nothing is parsed here.

use crate::config::Secret;
use crate::env::EnvFile;

/// Every variable `app/file_analysis/` reads, in the order the modules read
/// them, and the test-only overrides of the Rust service.
pub const KEYS: &[&str] = &[
    "INSPECTOR_URL",
    "INSPECTOR_HTTP_TIMEOUT",
    "SANDBOX_BACKEND",
    "CAPE_API_URL",
    "CAPE_PACKAGE",
    "CAPE_TASK_TIMEOUT",
    "CAPE_POLL_INTERVAL",
    "CAPE_POLL_TIMEOUT",
    "CAPE_HTTP_TIMEOUT",
    "ENRICHMENT_VT_MALICIOUS_THRESHOLD",
    "ENRICHMENT_SUBMIT_FILES",
    "ENRICHMENT_VT_MAX_WAIT",
    "ENRICHMENT_VT_POLL",
    "ENRICHMENT_VT_MAX_UPLOAD_MB",
    "ENRICHMENT_VT_DEEP",
    "FILE_ANALYSIS_MINIO_BUCKET",
    "FILE_ANALYSIS_MINIO_RETRIES",
    "FILE_ANALYSIS_MINIO_BACKOFF",
    "FILE_ANALYSIS_MAX_FLOW_FILES",
    "FILE_ANALYSIS_COLLECT_TIMEOUT",
    "FILE_ANALYSIS_ENUM_TIMEOUT",
    "VELOCIRAPTOR_API_CONFIG",
    "FILE_ANALYSIS_MAX_CONCURRENT_JOBS",
    "COPILOT_WKHTMLTOPDF",
];

/// Raw File Analysis settings (`None` = unset; an empty value is a value).
#[derive(Debug, Clone, Default)]
pub struct FileAnalysisEnv {
    /// `(name, value)` of every [`KEYS`] entry that is set.
    pub values: Vec<(String, String)>,
    /// `CAPE_API_TOKEN` (kept apart: it is a secret).
    pub cape_api_token: Option<Secret>,
}

impl FileAnalysisEnv {
    /// Read the values the way `os.getenv` would see them.
    pub fn from_env(env: &EnvFile) -> Self {
        Self {
            values: KEYS
                .iter()
                .filter_map(|k| env.get_raw(k).map(|v| ((*k).to_string(), v)))
                .collect(),
            cape_api_token: env.get_raw("CAPE_API_TOKEN").map(Secret::new),
        }
    }

    /// `os.getenv(key)`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// `os.getenv(key, default)`.
    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get(key).unwrap_or(default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_raw() {
        let e = FileAnalysisEnv::from_env(&EnvFile::isolated(
            "INSPECTOR_URL=\nSANDBOX_BACKEND=Remote\nCAPE_API_TOKEN=t\n",
        ));
        assert_eq!(e.get("INSPECTOR_URL"), Some(""));
        assert_eq!(e.get_or("SANDBOX_BACKEND", "none"), "Remote");
        assert_eq!(e.get_or("CAPE_PACKAGE", "x"), "x");
        assert_eq!(e.cape_api_token.as_ref().map(Secret::expose), Some("t"));
    }
}
