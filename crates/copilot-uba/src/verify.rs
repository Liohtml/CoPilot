//! `verify_uba_connection` — registered with `copilot_connectors::Verifiers`
//! under `SOCFortress UBA`: `GET /v1/status` with the stored key (10 s). A
//! UBA failure is `connectionSuccessful: false` with its detail; what
//! `uba_request` does not catch, and an answer the message cannot be built
//! from, is the exception `verify_connector_by_id` turns into its `None`.

use std::sync::Arc;

use async_trait::async_trait;
use copilot_auth::pyvalue::PyValue;
use copilot_connectors::schema::VerifyConnectorResponse;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::py;

use crate::client::{CONNECTOR, Call, UbaClient, UbaError};

fn outcome(successful: bool, message: String) -> VerifyOutcome {
    Some(VerifyConnectorResponse {
        connection_successful: successful,
        message,
    })
}

/// `{"connectionSuccessful": True, "message": …}` from `/v1/status`, or the
/// exception Python raises building it.
fn success_message(body: &PyValue) -> Option<String> {
    let tenants = py::get(body, "tenants")
        .ok()?
        .cloned()
        .unwrap_or_else(|| PyValue::List(Vec::new()));
    let mut names = Vec::new();
    for t in py::iterate(&tenants).ok()? {
        // `', '.join(...)` takes strings only.
        match py::get(&t, "tenant").ok()? {
            Some(PyValue::Str(s)) => names.push(s.clone()),
            _ => return None,
        }
    }
    let version = py::get(body, "version")
        .ok()?
        .map_or_else(String::new, PyValue::py_str);
    let tenants = if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    };
    Some(format!(
        "Connected to SOCFortress UBA {version}; tenants: {tenants}"
    ))
}

/// The UBA verifier.
#[derive(Debug, Clone)]
pub struct UbaVerifier;

#[async_trait]
impl ConnectorVerifier for UbaVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        let row = match connectors.get(name).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                tracing::error!("No {name} connector found in the database");
                return None;
            }
            Err(_) => return None,
        };
        let client = UbaClient::new(connectors.clone());
        match client
            .request_with(Some(&row), Call::get("/v1/status").timeout(10.0))
            .await
        {
            Ok(body) => outcome(true, success_message(&body)?),
            Err(UbaError::Request { detail, .. }) => outcome(false, detail),
            Err(UbaError::Py(_)) => None,
        }
    }
}

/// The verifiers this crate provides, for the binary's registry.
pub fn verifiers() -> Vec<(String, Arc<dyn ConnectorVerifier>)> {
    vec![(CONNECTOR.to_string(), Arc::new(UbaVerifier) as _)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn messages_like_python() {
        let msg = |s: &str| success_message(&loads(s).unwrap());
        assert_eq!(
            msg(r#"{"version": "1.4.6", "tenants": [{"tenant": "a"}, {"tenant": "b"}]}"#)
                .as_deref(),
            Some("Connected to SOCFortress UBA 1.4.6; tenants: a, b")
        );
        assert_eq!(
            msg(r#"{"tenants": []}"#).as_deref(),
            Some("Connected to SOCFortress UBA ; tenants: none")
        );
        assert_eq!(msg(r#"{"version": 1, "tenants": [{"x": 1}]}"#), None);
        assert_eq!(msg("[]"), None);
    }
}
