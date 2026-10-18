//! `verify_event_shipper_connection(name)`: a TCP connection to the GELF
//! input (`asyncio.open_connection(url, extra_data)`), closed again, then
//! the test message `EventShipperPayload(message="Healthcheck successful",
//! integration="event_shipper", customer_code="n/a")` shipped as
//! `send_json_test_message_to_event_shipper` ships it
//! (`copilot_graylog::gelf::ship`). Any failure is the one message.

use async_trait::async_trait;

use copilot_auth::pyvalue::PyValue;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_graylog::gelf;

use crate::outcome;

/// The Event Shipper verifier.
#[derive(Debug, Clone, Copy)]
pub struct EventShipperVerifier;

/// `EventShipperPayload(...).to_dict()`: the declared fields, then the
/// extra `message`.
pub fn healthcheck_payload() -> PyValue {
    PyValue::Dict(vec![
        ("integration".into(), PyValue::Str("event_shipper".into())),
        ("customer_code".into(), PyValue::Str("n/a".into())),
        (
            "message".into(),
            PyValue::Str("Healthcheck successful".into()),
        ),
    ])
}

#[async_trait]
impl ConnectorVerifier for EventShipperVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        let Some(row) = connectors.get(name).await.ok()? else {
            tracing::error!("No attributes found for event shipper connector");
            return None;
        };
        let url = row.connector_url.clone();
        tracing::info!("Verifying the event shipper connection to {url}");
        let failed = |e: String| {
            tracing::error!("Connection to {url} failed with error: {e}");
            outcome(false, format!("Connection to {url} failed"))
        };
        // `open_connection(host, None)` connects to port 0.
        let port = match row.connector_extra_data.as_deref() {
            Some(p) => gelf::resolve_port(&url, p),
            None => Some(0),
        };
        let Some(port) = port else {
            return failed("the port cannot be resolved".into());
        };
        match tokio::net::TcpStream::connect((url.as_str(), port)).await {
            Ok(stream) => drop(stream),
            Err(e) => return failed(e.to_string()),
        }
        match gelf::ship(connectors, &healthcheck_payload()).await {
            Ok(()) => outcome(true, "Event shipper healthcheck successful"),
            Err(e) => failed(e.display()),
        }
    }
}
