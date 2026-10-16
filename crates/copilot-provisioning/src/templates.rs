//! The provisioning templates, compiled in.
//!
//! Python reads `app/stack_provisioning/{graylog,influxdb}/templates/*.json`
//! from disk on every call. The Rust image carries no `backend/`, so the
//! files are copied under `crates/copilot-provisioning/templates/` and
//! embedded; the test below fails when a copy differs from the backend's.
//! Only the templates a ported route can load are here (the
//! `SENTINELONE_INPUT_SYSLOG_TLS` content pack belongs to the SentinelOne
//! provisioning, which stays in Python).

use copilot_auth::pyvalue::{PyValue, loads};

/// `AvailableContentPacks` member name → content pack JSON.
pub const GRAYLOG: &[(&str, &str)] = &[
    (
        "SOCFORTRESS_WAZUH_CONTENT_PACK",
        include_str!("../templates/graylog/SOCFORTRESS_WAZUH_CONTENT_PACK.json"),
    ),
    (
        "SOCFORTRESS_FORTINET_INPUT_SYSLOG_TCP",
        include_str!("../templates/graylog/SOCFORTRESS_FORTINET_INPUT_SYSLOG_TCP.json"),
    ),
    (
        "SOCFORTRESS_FORTINET_INPUT_SYSLOG_UDP",
        include_str!("../templates/graylog/SOCFORTRESS_FORTINET_INPUT_SYSLOG_UDP.json"),
    ),
    (
        "SOCFORTRESS_FORTINET_PROCESSING_PIPELINE",
        include_str!("../templates/graylog/SOCFORTRESS_FORTINET_PROCESSING_PIPELINE.json"),
    ),
    (
        "SOCFORTRESS_FORTINET_STREAM",
        include_str!("../templates/graylog/SOCFORTRESS_FORTINET_STREAM.json"),
    ),
    (
        "SOCFORTRESS_CROWDSTRIKE_INPUT_TCP",
        include_str!("../templates/graylog/SOCFORTRESS_CROWDSTRIKE_INPUT_TCP.json"),
    ),
    (
        "SOCFORTRESS_CROWDSTRIKE_STREAM",
        include_str!("../templates/graylog/SOCFORTRESS_CROWDSTRIKE_STREAM.json"),
    ),
    (
        "SOCFORTRESS_CROWDSTRIKE_PROCESSING_PIPELINE",
        include_str!("../templates/graylog/SOCFORTRESS_CROWDSTRIKE_PROCESSING_PIPELINE.json"),
    ),
    (
        "SOCFORTRESS_BITDEFENDER_INPUT_TCP",
        include_str!("../templates/graylog/SOCFORTRESS_BITDEFENDER_INPUT_TCP.json"),
    ),
    (
        "SOCFORTRESS_BITDEFENDER_STREAM",
        include_str!("../templates/graylog/SOCFORTRESS_BITDEFENDER_STREAM.json"),
    ),
    (
        "SOCFORTRESS_DEFENDER_FOR_ENDPOINT_INPUT_TCP",
        include_str!("../templates/graylog/SOCFORTRESS_DEFENDER_FOR_ENDPOINT_INPUT_TCP.json"),
    ),
    (
        "SOCFORTRESS_DEFENDER_FOR_ENDPOINT_STREAM",
        include_str!("../templates/graylog/SOCFORTRESS_DEFENDER_FOR_ENDPOINT_STREAM.json"),
    ),
    (
        "SOCFORTRESS_SONICWALL_INPUT_SYSLOG_TLS",
        include_str!("../templates/graylog/SOCFORTRESS_SONICWALL_INPUT_SYSLOG_TLS.json"),
    ),
    (
        "SOCFORTRESS_SONICWALL_STREAM",
        include_str!("../templates/graylog/SOCFORTRESS_SONICWALL_STREAM.json"),
    ),
    (
        "SOCFORTRESS_SONICWALL_PROCESSING_PIPELINE",
        include_str!("../templates/graylog/SOCFORTRESS_SONICWALL_PROCESSING_PIPELINE.json"),
    ),
];

/// `AvailableInfluxDBChecks` member name → check JSON (placeholders intact).
pub const INFLUXDB: &[(&str, &str)] = &[
    (
        "SOCFORTRESS_INFLUXDB_CPU_CHECK",
        include_str!("../templates/influxdb/SOCFORTRESS_INFLUXDB_CPU_CHECK.json"),
    ),
    (
        "SOCFORTRESS_INFLUXDB_MEMORY_CHECK",
        include_str!("../templates/influxdb/SOCFORTRESS_INFLUXDB_MEMORY_CHECK.json"),
    ),
    (
        "SOCFORTRESS_INFLUXDB_DISK_CHECK",
        include_str!("../templates/influxdb/SOCFORTRESS_INFLUXDB_DISK_CHECK.json"),
    ),
    (
        "SOCFORTRESS_INFLUXDB_CRITICAL_SERVICES_CHECK",
        include_str!("../templates/influxdb/SOCFORTRESS_INFLUXDB_CRITICAL_SERVICES_CHECK.json"),
    ),
];

fn load(set: &[(&str, &str)], name: &str) -> Option<PyValue> {
    set.iter()
        .find(|(n, _)| *n == name)
        .and_then(|(_, text)| loads(text).ok())
}

/// `load_content_pack_json(f"{name}.json")`.
pub fn content_pack(name: &str) -> Option<PyValue> {
    load(GRAYLOG, name)
}

/// `load_raw_check_template(name)`.
pub fn check(name: &str) -> Option<PyValue> {
    load(INFLUXDB, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend's files, by the same names.
    const BACKEND_GRAYLOG: &[&str] = &[
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_WAZUH_CONTENT_PACK.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_FORTINET_INPUT_SYSLOG_TCP.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_FORTINET_INPUT_SYSLOG_UDP.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_FORTINET_PROCESSING_PIPELINE.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_FORTINET_STREAM.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_CROWDSTRIKE_INPUT_TCP.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_CROWDSTRIKE_STREAM.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_CROWDSTRIKE_PROCESSING_PIPELINE.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_BITDEFENDER_INPUT_TCP.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_BITDEFENDER_STREAM.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_DEFENDER_FOR_ENDPOINT_INPUT_TCP.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_DEFENDER_FOR_ENDPOINT_STREAM.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_SONICWALL_INPUT_SYSLOG_TLS.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_SONICWALL_STREAM.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/graylog/templates/SOCFORTRESS_SONICWALL_PROCESSING_PIPELINE.json"
        ),
    ];

    const BACKEND_INFLUXDB: &[&str] = &[
        include_str!(
            "../../../backend/app/stack_provisioning/influxdb/templates/SOCFORTRESS_INFLUXDB_CPU_CHECK.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/influxdb/templates/SOCFORTRESS_INFLUXDB_MEMORY_CHECK.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/influxdb/templates/SOCFORTRESS_INFLUXDB_DISK_CHECK.json"
        ),
        include_str!(
            "../../../backend/app/stack_provisioning/influxdb/templates/SOCFORTRESS_INFLUXDB_CRITICAL_SERVICES_CHECK.json"
        ),
    ];

    #[test]
    fn copies_match_the_backend_templates() {
        assert_eq!(GRAYLOG.len(), BACKEND_GRAYLOG.len());
        for ((name, ours), theirs) in GRAYLOG.iter().zip(BACKEND_GRAYLOG) {
            assert!(ours == theirs, "{name} differs from the backend's template");
        }
        assert_eq!(INFLUXDB.len(), BACKEND_INFLUXDB.len());
        for ((name, ours), theirs) in INFLUXDB.iter().zip(BACKEND_INFLUXDB) {
            assert!(ours == theirs, "{name} differs from the backend's template");
        }
    }

    #[test]
    fn every_template_parses() {
        for (name, _) in GRAYLOG {
            let pack = content_pack(name).unwrap();
            assert!(
                pack.get("id").is_some() && pack.get("rev").is_some(),
                "{name}"
            );
        }
        for (name, _) in INFLUXDB {
            assert!(matches!(
                check(name).unwrap().get("name"),
                Some(PyValue::Str(_))
            ));
        }
    }
}
