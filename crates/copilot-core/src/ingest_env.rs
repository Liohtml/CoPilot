//! The settings the alert ingest reads from the environment
//! (`copilot-ingest`), raw as `os.getenv` returns them: the Python helpers
//! interpret them on every call, so an unset value and an empty one are kept
//! apart and nothing is parsed at startup.

use crate::env::EnvFile;

/// Raw ingest settings (`None` = unset; an empty value is still a value).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestEnv {
    /// `GRAYLOG_API_HEADER_VALUE`: the `graylog` header the threshold
    /// webhook must carry (unset or empty = the route is closed).
    pub graylog_api_header_value: Option<String>,
    /// `VELOCIRAPTOR_API_HEADER_VALUE`: the `velociraptor` header of the
    /// Sigma webhook (unset or empty = the route is closed).
    pub velociraptor_api_header_value: Option<String>,
    /// `MDR_ENABLED` (`true`/`1`/`yes`, any case, enables MDR forwarding).
    pub mdr_enabled: Option<String>,
    /// `MDR_SERVER_URL`.
    pub mdr_server_url: Option<String>,
    /// `MDR_COLLECTOR_UUID` (single-tenant fallback).
    pub mdr_collector_uuid: Option<String>,
    /// `THRESHOLD_SOURCE_INDEX_MAPPING` (JSON object).
    pub threshold_source_index_mapping: Option<String>,
    /// `THRESHOLD_SOURCE_INDEX_FALLBACK_ENABLED` (default `true`).
    pub threshold_source_index_fallback_enabled: Option<String>,
}

impl IngestEnv {
    /// Read the values the way `os.getenv` would see them.
    pub fn from_env(env: &EnvFile) -> Self {
        Self {
            graylog_api_header_value: env.get_raw("GRAYLOG_API_HEADER_VALUE"),
            velociraptor_api_header_value: env.get_raw("VELOCIRAPTOR_API_HEADER_VALUE"),
            mdr_enabled: env.get_raw("MDR_ENABLED"),
            mdr_server_url: env.get_raw("MDR_SERVER_URL"),
            mdr_collector_uuid: env.get_raw("MDR_COLLECTOR_UUID"),
            threshold_source_index_mapping: env.get_raw("THRESHOLD_SOURCE_INDEX_MAPPING"),
            threshold_source_index_fallback_enabled: env
                .get_raw("THRESHOLD_SOURCE_INDEX_FALLBACK_ENABLED"),
        }
    }
}
