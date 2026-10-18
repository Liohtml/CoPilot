//! `get_function_by_name` — the jobs a scheduler can schedule, by the key a
//! job id or a function name is looked up under.
//!
//! Python's map, in its order ([`FUNCTIONS`], pinned with the callables'
//! names and the `ValueError` text by `scheduler_vectors.json`,
//! `scripts/gen-scheduler-vectors.py`). The key is what `schedule_enabled_jobs`
//! and `POST /add` look a job up by; the name is `job.name`, which APScheduler
//! takes from the callable (`get_callable_name`) and `POST /jobs/run` looks the
//! function up by again — only CarbonBlack's differ.

/// One entry of `get_function_by_name`'s map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Function {
    /// The key (a job id; the function name for every job but CarbonBlack).
    pub key: &'static str,
    /// The callable's name (`job.name`).
    pub name: &'static str,
}

/// `get_function_by_name`'s map, in its order.
pub const FUNCTIONS: &[Function] = &[
    Function {
        key: "agent_sync",
        name: "agent_sync",
    },
    Function {
        key: "prune_audit_log",
        name: "prune_audit_log",
    },
    Function {
        key: "resize_wazuh_index_fields",
        name: "resize_wazuh_index_fields",
    },
    Function {
        key: "invoke_alert_creation_collect",
        name: "invoke_alert_creation_collect",
    },
    Function {
        key: "invoke_snapshot_schedules",
        name: "invoke_snapshot_schedules",
    },
    Function {
        key: "invoke_mimecast_integration",
        name: "invoke_mimecast_integration",
    },
    Function {
        key: "invoke_mimecast_integration_ttp",
        name: "invoke_mimecast_integration_ttp",
    },
    Function {
        key: "invoke_sap_siem_integration_collection",
        name: "invoke_sap_siem_integration_collection",
    },
    Function {
        key: "invoke_sap_siem_integration_suspicious_logins_analysis",
        name: "invoke_sap_siem_integration_suspicious_logins_analysis",
    },
    Function {
        key: "invoke_sap_siem_integration_multiple_logins_same_ip_analysis",
        name: "invoke_sap_siem_integration_multiple_logins_same_ip_analysis",
    },
    Function {
        key: "invoke_sap_siem_integration_successful_user_login_with_different_ip",
        name: "invoke_sap_siem_integration_successful_user_login_with_different_ip",
    },
    Function {
        key: "invoke_sap_siem_integration_same_user_failed_login_from_different_ip",
        name: "invoke_sap_siem_integration_same_user_failed_login_from_different_ip",
    },
    Function {
        key: "invoke_sap_siem_integration_same_user_failed_login_from_different_geo_location",
        name: "invoke_sap_siem_integration_same_user_failed_login_from_different_geo_location",
    },
    Function {
        key: "invoke_sap_siem_integration_same_user_successful_login_from_different_geo_location",
        name: "invoke_sap_siem_integration_same_user_successful_login_from_different_geo_location",
    },
    Function {
        key: "invoke_sap_siem_integration_brute_force_failed_logins",
        name: "invoke_sap_siem_integration_brute_force_failed_logins",
    },
    Function {
        key: "invoke_sap_siem_integration_brute_force_failed_logins_same_ip",
        name: "invoke_sap_siem_integration_brute_force_failed_logins_same_ip",
    },
    Function {
        key: "invoke_sap_siem_integration_successful_login_after_multiple_failed_logins",
        name: "invoke_sap_siem_integration_successful_login_after_multiple_failed_logins",
    },
    Function {
        key: "invoke_huntress_integration_collect",
        name: "invoke_huntress_integration_collect",
    },
    Function {
        key: "invoke_cato_integration_collect",
        name: "invoke_cato_integration_collect",
    },
    Function {
        key: "invoke_duo_integration_collect",
        name: "invoke_duo_integration_collect",
    },
    Function {
        key: "invoke_darktrace_integration_collect",
        name: "invoke_darktrace_integration_collect",
    },
    Function {
        key: "invoke_carbonblack_integration_collection",
        name: "invoke_carbonblack_integration_collect",
    },
    Function {
        key: "invoke_palace_lesson_drainer",
        name: "invoke_palace_lesson_drainer",
    },
    Function {
        key: "invoke_palace_lesson_sweeper",
        name: "invoke_palace_lesson_sweeper",
    },
    Function {
        key: "refresh_wazuh_rules_cache",
        name: "refresh_wazuh_rules_cache",
    },
    Function {
        key: "refresh_catalog_caches",
        name: "refresh_catalog_caches",
    },
    Function {
        key: "refresh_sidebar_health",
        name: "refresh_sidebar_health",
    },
    Function {
        key: "refresh_sidebar_indicators",
        name: "refresh_sidebar_indicators",
    },
    Function {
        key: "notify_sla_transitions",
        name: "notify_sla_transitions",
    },
];

/// `get_function_by_name(key)`.
pub fn by_key(key: &str) -> Option<&'static Function> {
    FUNCTIONS.iter().find(|f| f.key == key)
}

/// The entry whose callable is named `name` (the run route's lookup, made to
/// work for CarbonBlack: see [`run_key`]).
pub fn by_name(name: &str) -> Option<&'static Function> {
    FUNCTIONS.iter().find(|f| f.name == name)
}

/// The function a manual run executes for a job whose callable is `name`.
///
/// `run_job_manually` calls `get_function_by_name(job.name)`: the key equal to
/// the callable's name, which for every job but CarbonBlack is its own. The
/// CarbonBlack job's callable is `invoke_carbonblack_integration_collect`, which
/// is no key, so Python's manual run of that job always fails with the
/// `ValueError` (a §4 row: Python fails, Rust works) — here the callable's
/// name finds its entry.
pub fn run_key(name: &str) -> Option<&'static str> {
    by_key(name).or_else(|| by_name(name)).map(|f| f.key)
}

/// The `ValueError` `get_function_by_name` raises for an unknown name.
pub fn unknown_function(name: &str) -> String {
    format!(
        "Scheduled job '{name}' has no entry in get_function_by_name's function_map. Add it \
         there as well as in initialize_job_metadata's known_jobs."
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use serde_json::Value;

    fn doc() -> Value {
        serde_json::from_str(include_str!("scheduler_vectors.json")).unwrap()
    }

    #[test]
    fn the_table_is_python_s() {
        let d = doc();
        let python: Vec<(String, String)> = d["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["key"].as_str().unwrap().to_string(),
                    f["name"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let ours: Vec<(String, String)> = FUNCTIONS
            .iter()
            .map(|f| (f.key.to_string(), f.name.to_string()))
            .collect();
        assert_eq!(python, ours);
        // Every function is guarded by its own key (the hand-over rule).
        for f in d["functions"].as_array().unwrap() {
            assert_eq!(f["guard"], f["key"], "{f}");
        }
        assert_eq!(
            unknown_function("{name}"),
            d["unknown_function"].as_str().unwrap()
        );
    }

    #[test]
    fn a_manual_run_resolves_carbonblack_by_its_callable() {
        assert_eq!(
            run_key("invoke_carbonblack_integration_collect"),
            Some("invoke_carbonblack_integration_collection")
        );
        assert_eq!(run_key("agent_sync"), Some("agent_sync"));
        assert_eq!(run_key("nope"), None);
        assert!(by_key("invoke_carbonblack_integration_collect").is_none());
    }
}
