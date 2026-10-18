//! The connector verifications the Python backend still answered, each as
//! its `verify_<tool>_connection(connector_name)` does it, registered with
//! `copilot_connectors::Verifiers` under the names `get_connector_service`
//! maps to it:
//!
//! | Connector | Python | Here |
//! |---|---|---|
//! | `Graylog`, `Graylog-Network` | `verify_graylog_credentials` | [`graylog`] |
//! | `InfluxDB` | `verify_influxdb_credentials` | [`influxdb`] |
//! | `Grafana` | `verify_grafana_credentials` | [`grafana`] |
//! | `Wazuh Worker Provisioning` | `verify_wazuh_worker_provisioning_healtcheck` | [`healthchecks`] |
//! | `HAProxy Provisioning` | `verify_haproxy_provisioning_healtcheck` | [`healthchecks`] |
//! | `Alert Creation Provisioning` | `verify_alert_creation_provisioning_healtcheck` | [`healthchecks`] |
//! | `VirusTotal` | `verify_virustotal_healtcheck` | [`healthchecks`] |
//! | `Talon` | `verify_talon_credentials` | [`healthchecks`] |
//! | `Event Shipper` | `verify_event_shipper_healtcheck` | [`event_shipper`] |
//! | `Portainer` | `verify_portainer_credentials` | [`portainer`] |
//! | `Resend` | `verify_resend_credentials` | [`resend`] |
//!
//! Each reads its row through the connector cache as
//! `get_connector_info_from_db` does, sends what the Python library sends
//! (`requests` through `copilot_upstream::http::PyHttp`, httpx 0.28 through
//! `copilot_threat_intel::httpx`, aiohttp for InfluxDB through
//! `copilot-influxdb`, niquests for Grafana through `copilot-grafana`, the
//! GELF frame through `copilot_graylog::gelf`) and answers Python's
//! `{connectionSuccessful, message}` texts. Where Python raises out of the
//! verifier (a missing row read before its `None` check, a URL the Grafana
//! client refuses, an `AttributeError` on an odd answer) the outcome is
//! `None`: `verify_connector_by_id`'s `except` → the route's 404. The
//! `connector_verified` write and the cache invalidation are the routes'
//! (`copilot-connectors`), as in Python. No per-process state.

#![warn(missing_docs)]

use std::sync::Arc;

use copilot_connectors::schema::VerifyConnectorResponse;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_grafana::GrafanaClient;
use copilot_influxdb::InfluxClient;

pub mod event_shipper;
pub mod grafana;
pub mod graylog;
pub mod healthchecks;
pub mod influxdb;
pub mod portainer;
pub mod resend;

/// `{"connectionSuccessful": successful, "message": message}`.
pub(crate) fn outcome(successful: bool, message: impl Into<String>) -> VerifyOutcome {
    Some(VerifyConnectorResponse {
        connection_successful: successful,
        message: message.into(),
    })
}

/// The clients the verifiers reach their tools with.
#[derive(Debug, Clone)]
pub struct Tools {
    /// Grafana (`grafana_client` over niquests).
    pub grafana: GrafanaClient,
    /// InfluxDB (`influxdb_client`'s aiohttp client).
    pub influxdb: InfluxClient,
}

/// The verifiers this crate provides, for the binary's registry.
pub fn verifiers(tools: &Tools) -> Vec<(String, Arc<dyn ConnectorVerifier>)> {
    let mut out: Vec<(String, Arc<dyn ConnectorVerifier>)> = vec![
        ("Graylog".into(), Arc::new(graylog::GraylogVerifier)),
        ("Graylog-Network".into(), Arc::new(graylog::GraylogVerifier)),
        (
            "InfluxDB".into(),
            Arc::new(influxdb::InfluxDbVerifier(tools.influxdb.clone())),
        ),
        (
            "Grafana".into(),
            Arc::new(grafana::GrafanaVerifier(tools.grafana.clone())),
        ),
        (
            "Event Shipper".into(),
            Arc::new(event_shipper::EventShipperVerifier),
        ),
        ("Portainer".into(), Arc::new(portainer::PortainerVerifier)),
        ("Resend".into(), Arc::new(resend::ResendVerifier)),
    ];
    for kind in healthchecks::Healthcheck::ALL {
        out.push((
            kind.connector().to_string(),
            Arc::new(healthchecks::HealthcheckVerifier(kind)),
        ));
    }
    out
}
