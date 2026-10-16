//! `verify_velociraptor_connection` — registered with
//! `copilot_connectors::Verifiers` under `Velociraptor`.
//!
//! The check Python makes: the api config file can be opened, it loads, and
//! `SELECT * FROM info()` answers (`VQLCollectorArgs(max_wait=60,
//! Query=[VQLRequest(Name="ClientQuery", …)])`, no org, the query deadline).
//! The two failure messages are Python's: a file that cannot be opened is
//! `Failed to get connector_api_key from the database: …`, anything after it
//! `Failed to verify connection to Velociraptor: …` with `str()` of the
//! exception (for a gRPC failure, grpc's `_MultiThreadedRendezvous` text).

use std::time::Duration;

use async_trait::async_trait;

use copilot_auth::pyvalue::PyValue;
use copilot_connectors::schema::VerifyConnectorResponse;
use copilot_connectors::{ConnectorVerifier, VerifyOutcome};
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::py::PyExc;

use crate::client::{CONNECTOR, QUERY_METHOD, Timeouts, json_loads};
use crate::config::{ApiConfig, read_text};
use crate::grpc::{self, CallError};
use crate::proto::{VqlCollectorArgs, VqlRequest, VqlResponse};

fn outcome(successful: bool, message: String) -> VerifyOutcome {
    Some(VerifyConnectorResponse {
        connection_successful: successful,
        message,
    })
}

/// The verifier.
#[derive(Debug, Clone)]
pub struct VelociraptorVerifier {
    timeouts: Timeouts,
}

impl VelociraptorVerifier {
    /// With the environment's query deadline.
    pub fn new(timeouts: Timeouts) -> Self {
        Self { timeouts }
    }
}

/// `r = r + json.loads(chunk)`.
fn concat(r: &mut Vec<PyValue>, value: PyValue) -> Result<(), PyExc> {
    match value {
        PyValue::List(items) => {
            r.extend(items);
            Ok(())
        }
        other => Err(PyExc::TypeError(format!(
            "can only concatenate list (not \"{}\") to list",
            copilot_upstream::py::type_name(&other)
        ))),
    }
}

/// `_verify_velociraptor_credentials_sync(attributes)`.
pub async fn verify_credentials(api_key: Option<&str>, timeouts: Timeouts) -> (bool, String) {
    let Some(path) = api_key else {
        return (
            false,
            "Failed to get connector_api_key from the database: expected str, bytes or \
             os.PathLike object, not NoneType"
                .into(),
        );
    };
    let owned = path.to_string();
    let opened = tokio::task::spawn_blocking(move || read_text(&owned).map(|_| ())).await;
    // `with open(connector_api_key, "r") as f: f.read()`, outside the inner try.
    match opened {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!("Failed to get connector_api_key from the database: {e}");
            return (
                false,
                format!("Failed to get connector_api_key from the database: {e}"),
            );
        }
        Err(e) => return failed(&e.to_string()),
    }
    let owned = path.to_string();
    let cfg = match tokio::task::spawn_blocking(move || ApiConfig::load(Some(&owned))).await {
        Ok(Ok(cfg)) => cfg,
        Ok(Err(e)) => return failed(&e.text()),
        Err(e) => return failed(&e.to_string()),
    };
    let request = VqlCollectorArgs {
        max_wait: 60,
        query: vec![VqlRequest {
            name: "ClientQuery".into(),
            vql: "SELECT * FROM info()".into(),
        }],
        ..Default::default()
    };
    let mut r = Vec::new();
    let result: Result<(), CallError<Option<PyExc>>> = grpc::server_streaming(
        &cfg,
        QUERY_METHOD,
        request.encode(),
        Duration::from_secs(timeouts.query),
        |message| {
            let response = VqlResponse::decode(&message).map_err(|_| None)?;
            if !response.response.is_empty() {
                let value = json_loads(&response.response).map_err(Some)?;
                concat(&mut r, value).map_err(Some)?;
            }
            Ok(())
        },
    )
    .await;
    match result {
        Ok(()) => (true, "Connection to Velociraptor successful".into()),
        Err(CallError::Rpc(e)) => failed(&e.rendezvous_str()),
        Err(CallError::Handler(Some(e))) => failed(&e.text()),
        Err(CallError::Handler(None)) => failed(
            &grpc::RpcError::local(grpc::Code::Internal, "Exception deserializing response!")
                .rendezvous_str(),
        ),
    }
}

fn failed(e: &str) -> (bool, String) {
    tracing::error!("Failed to verify connection to Velociraptor: {e}");
    (
        false,
        format!("Failed to verify connection to Velociraptor: {e}"),
    )
}

#[async_trait]
impl ConnectorVerifier for VelociraptorVerifier {
    async fn verify(&self, connectors: &ConnectorCache, name: &str) -> VerifyOutcome {
        tracing::info!("Verifying the Velociraptor connection for connector: {name}");
        let row = connectors.get(name).await.ok().flatten();
        let Some(row) = row else {
            tracing::error!("No Velociraptor connector found in the database");
            return None;
        };
        let (ok, message) =
            verify_credentials(row.connector_api_key.as_deref(), self.timeouts).await;
        outcome(ok, message)
    }
}

/// The verifier this crate provides, for the binary's registry.
pub fn verifiers(timeouts: Timeouts) -> Vec<(String, std::sync::Arc<dyn ConnectorVerifier>)> {
    vec![(
        CONNECTOR.to_string(),
        std::sync::Arc::new(VelociraptorVerifier::new(timeouts)) as _,
    )]
}
