//! The settings the response routes and the Shuffle connector read from the
//! environment (`copilot-response`, `copilot-shuffle`), raw as `os.getenv`
//! returns them: the Python routes read them on every call, so an unset value
//! and an empty one are kept apart and nothing is parsed at startup.

use crate::config::Secret;
use crate::env::EnvFile;

/// Raw response settings (`None` = unset; an empty value is still a value).
#[derive(Debug, Clone, Default)]
pub struct ResponseEnv {
    /// `COPILOT_API_KEY`: the license key the CoPilot Action inventory is
    /// asked with (unset or empty = the routes answer 500).
    pub copilot_api_key: Option<Secret>,
    /// `COPILOT_ACTION_URL` — tests only: the CoPilot Action inventory's
    /// base URL instead of `https://copilot-action.socfortress.co`.
    pub copilot_action_url: Option<String>,
    /// `COPILOT_PROVISION_WORKER_PORT` — tests only: the port of the Wazuh
    /// master's provisioning worker instead of `5003` (the Sysmon deploy).
    pub provision_worker_port: Option<String>,
}

impl ResponseEnv {
    /// Read the values the way `os.getenv` would see them.
    pub fn from_env(env: &EnvFile) -> Self {
        Self {
            copilot_api_key: env.get_raw("COPILOT_API_KEY").map(Secret::new),
            copilot_action_url: env
                .get("COPILOT_ACTION_URL")
                .map(|v| v.trim().trim_end_matches('/').to_string())
                .filter(|v| !v.is_empty()),
            provision_worker_port: env
                .get("COPILOT_PROVISION_WORKER_PORT")
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
        }
    }
}
