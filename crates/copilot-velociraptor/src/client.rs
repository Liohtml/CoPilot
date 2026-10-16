//! `app/connectors/velociraptor/utils/universal.py`: `UniversalService`, the
//! VQL client every Velociraptor feature goes through.
//!
//! A [`Service`] is `UniversalService.create("Velociraptor")`: the connector
//! row read through the process's connector cache, its `api.config.yaml`
//! loaded. [`Service::execute_query`] sends `VQLCollectorArgs(max_wait=1,
//! org_id=…, Query=[VQLRequest(Name="VQLRequest", VQL=…)])` and folds the
//! streamed `Response` chunks with Python's `results += json.loads(chunk)`;
//! its failures are Python's `HTTPException`s: 504 on an expired deadline
//! (naming the knob that raises it), 403 for Velociraptor's "Permission
//! denied" (naming the grant), 500 `Failed to execute query: …` otherwise.
//!
//! Deadlines and the flow-wait allowance come from the environment, as in
//! Python: `VELOCIRAPTOR_QUERY_TIMEOUT` (30 s), `VELOCIRAPTOR_FLOW_TIMEOUT`
//! (300 s) for waiting on a collection, and at most
//! `VELOCIRAPTOR_MAX_CONCURRENT_FLOW_WAITS` (20) such waits at once.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use copilot_auth::pyvalue::{PyValue, loads};
use copilot_db::connectors::ConnectorCache;
use copilot_upstream::py::{PyExc, PyResult, getitem, type_name};

use crate::config::ApiConfig;
use crate::grpc::{self, CallError, Code};
use crate::proto::{VqlCollectorArgs, VqlRequest, VqlResponse};
use crate::validation::{
    validate_artifact_name, validate_client_id, validate_flow_id, validate_org_id,
};

/// The connector row.
pub const CONNECTOR: &str = "Velociraptor";
/// The one method CoPilot calls.
pub const QUERY_METHOD: &str = "/proto.API/Query";
/// `org_id="root"`, the default of every `UniversalService` method.
pub const ROOT: Option<&str> = Some("root");

/// `int(raw)` as CPython reads an integer setting (whitespace, `+`/`-`,
/// single underscores between digits).
pub fn py_int(raw: &str) -> Option<i64> {
    let s = raw.trim();
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.chars().all(|c| c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    let n: i64 = digits.replace('_', "").parse().ok()?;
    Some(if neg { -n } else { n })
}

/// `_positive_int_from_env(name, default)`.
pub fn positive_int_from_env(name: &str, default: u64) -> u64 {
    let raw = std::env::var(name).unwrap_or_else(|_| default.to_string());
    match py_int(&raw) {
        None => {
            tracing::warn!("{name}={raw:?} is not an integer; falling back to {default}");
            default
        }
        Some(n) if n <= 0 => {
            tracing::warn!("{name}={n} is not a positive integer; falling back to {default}");
            default
        }
        Some(n) => n.unsigned_abs(),
    }
}

/// The deadlines, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// `QUERY_TIMEOUT_SECONDS`.
    pub query: u64,
    /// `FLOW_TIMEOUT_SECONDS`.
    pub flow: u64,
}

impl Timeouts {
    /// From `VELOCIRAPTOR_QUERY_TIMEOUT` / `VELOCIRAPTOR_FLOW_TIMEOUT`.
    pub fn from_env() -> Self {
        Self {
            query: positive_int_from_env("VELOCIRAPTOR_QUERY_TIMEOUT", 30),
            flow: positive_int_from_env("VELOCIRAPTOR_FLOW_TIMEOUT", 300),
        }
    }
}

/// The process-wide client (one per process, as Python's module state).
#[derive(Debug, Clone)]
pub struct VelociraptorClient {
    connectors: ConnectorCache,
    timeouts: Timeouts,
    flow_waits: Arc<Semaphore>,
}

impl VelociraptorClient {
    /// Build with the environment's deadlines and flow-wait allowance.
    pub fn new(connectors: ConnectorCache) -> Self {
        let waits = positive_int_from_env("VELOCIRAPTOR_MAX_CONCURRENT_FLOW_WAITS", 20);
        Self::with(connectors, Timeouts::from_env(), waits)
    }

    /// Build with explicit settings (tests).
    pub fn with(connectors: ConnectorCache, timeouts: Timeouts, flow_waits: u64) -> Self {
        Self {
            connectors,
            timeouts,
            flow_waits: Arc::new(Semaphore::new(
                usize::try_from(flow_waits).unwrap_or(usize::MAX >> 4),
            )),
        }
    }

    /// The connector cache.
    pub fn connectors(&self) -> &ConnectorCache {
        &self.connectors
    }

    /// The deadlines.
    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// `await UniversalService.create("Velociraptor")`.
    pub async fn service(&self) -> PyResult<Service> {
        let row = self
            .connectors
            .get(CONNECTOR)
            .await
            .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
        let Some(row) = row else {
            tracing::error!("No Velociraptor connector found in the database");
            // `self.config` stays None: `None["ca_certificate"]`.
            return Err(PyExc::TypeError(
                "'NoneType' object is not subscriptable".into(),
            ));
        };
        let path = row.connector_api_key.clone();
        let cfg = tokio::task::spawn_blocking(move || ApiConfig::load(path.as_deref()))
            .await
            .map_err(|e| PyExc::Other("RuntimeError", e.to_string()))??;
        Ok(Service {
            cfg,
            timeouts: self.timeouts,
            flow_waits: Arc::clone(&self.flow_waits),
        })
    }
}

/// One `UniversalService` instance.
#[derive(Debug, Clone)]
pub struct Service {
    cfg: ApiConfig,
    timeouts: Timeouts,
    flow_waits: Arc<Semaphore>,
}

/// `results += value` for a Python list.
pub fn extend(results: &mut Vec<PyValue>, value: PyValue) -> PyResult<()> {
    match value {
        PyValue::List(items) => results.extend(items),
        PyValue::Dict(items) => results.extend(items.into_iter().map(|(k, _)| PyValue::Str(k))),
        PyValue::Str(s) => results.extend(s.chars().map(|c| PyValue::Str(c.to_string()))),
        other => {
            return Err(PyExc::TypeError(format!(
                "'{}' object is not iterable",
                type_name(&other)
            )));
        }
    }
    Ok(())
}

/// `json.loads(text)` with CPython's error texts.
pub fn json_loads(text: &str) -> PyResult<PyValue> {
    loads(text).map_err(|_| {
        PyExc::JsonDecode(
            copilot_upstream::json::decode_error(text)
                .unwrap_or_else(|| "Expecting value: line 1 column 1 (char 0)".into()),
        )
    })
}

impl Service {
    /// A service over a config (tests, the verifier).
    pub fn from_config(cfg: ApiConfig, timeouts: Timeouts) -> Self {
        Self {
            cfg,
            timeouts,
            flow_waits: Arc::new(Semaphore::new(20)),
        }
    }

    /// The loaded config.
    pub fn config(&self) -> &ApiConfig {
        &self.cfg
    }

    /// `create_vql_request(vql, org_id)`: `org_id or "root"`, validated.
    pub fn create_vql_request(vql: &str, org_id: Option<&str>) -> PyResult<VqlCollectorArgs> {
        let org_id = match org_id {
            Some(o) if !o.is_empty() => o,
            _ => "root",
        };
        validate_org_id(Some(org_id))?;
        Ok(VqlCollectorArgs {
            max_wait: 1,
            org_id: org_id.to_string(),
            query: vec![VqlRequest {
                name: "VQLRequest".into(),
                vql: vql.to_string(),
            }],
            ..Default::default()
        })
    }

    /// `execute_query(vql, org_id, timeout)`: the `results` of its success
    /// dict (`success` is always `True` when it returns). `org_id` is the
    /// Python argument: `None` is `None` (pass [`ROOT`] for the default), and
    /// reads as `'None'` in the 403's text, as in Python.
    pub async fn execute_query(
        &self,
        vql: &str,
        org_id: Option<&str>,
        timeout: Option<u64>,
    ) -> PyResult<Vec<PyValue>> {
        let timeout = timeout.unwrap_or(self.timeouts.query);
        tracing::info!("Executing query: {vql} (timeout {timeout}s)");
        let request = Self::create_vql_request(vql, org_id)?;
        let org = org_id.unwrap_or("None").to_string();
        let mut results = Vec::new();
        let outcome = grpc::server_streaming(
            &self.cfg,
            QUERY_METHOD,
            request.encode(),
            Duration::from_secs(timeout),
            |message| {
                let response = VqlResponse::decode(&message).map_err(|_| {
                    PyExc::Other("RpcError", "Exception deserializing response!".into())
                })?;
                if !response.response.is_empty() {
                    extend(&mut results, json_loads(&response.response)?)?;
                } else if !response.log.is_empty() {
                    tracing::info!("Log: {}", response.log);
                }
                Ok(())
            },
        )
        .await;
        match outcome {
            Ok(()) => Ok(results),
            Err(CallError::Handler(PyExc::Other("RpcError", details))) => {
                Err(self.rpc_failure(Code::Internal, &details, timeout, &org))
            }
            Err(CallError::Handler(e)) => {
                tracing::error!("Failed to execute query: {}", e.text());
                Err(PyExc::http(
                    500,
                    format!("Failed to execute query: {}", e.text()),
                ))
            }
            Err(CallError::Rpc(e)) => Err(self.rpc_failure(e.code, &e.details, timeout, &org)),
        }
    }

    /// The `except grpc.RpcError` branch of `execute_query`.
    fn rpc_failure(&self, code: Code, details: &str, timeout: u64, org_id: &str) -> PyExc {
        if code == Code::DeadlineExceeded {
            let env_var = if timeout == self.timeouts.flow {
                "VELOCIRAPTOR_FLOW_TIMEOUT"
            } else {
                "VELOCIRAPTOR_QUERY_TIMEOUT"
            };
            tracing::error!("Failed to execute query: deadline of {timeout}s exceeded.");
            return PyExc::http(
                504,
                format!(
                    "Velociraptor did not respond within {timeout}s. The collection may still be \
                     running on the server -- check the flow there before re-running it. Raise \
                     {env_var} (seconds) if collections on this deployment legitimately take longer."
                ),
            );
        }
        tracing::error!("Failed to execute query: {}: {details}", code.name());
        if details.to_lowercase().contains("permission denied") {
            return PyExc::http(
                403,
                format!(
                    "Velociraptor denied the query for org '{org_id}': {details}. The Velociraptor \
                     API user CoPilot authenticates as needs a role in each org, not just root. \
                     Grant it on the Velociraptor server with: SELECT user_grant(user='<copilot \
                     api user>', roles='administrator', orgs=['{org_id}']) FROM scope()"
                ),
            );
        }
        PyExc::http(500, format!("Failed to execute query: {details}"))
    }

    /// `watch_flow_completion(flow_id, org_id, timeout)` from the flow-wait
    /// allowance; the deadline starts once a permit is held.
    pub async fn watch_flow_completion(
        &self,
        flow_id: &str,
        org_id: Option<&str>,
        timeout: Option<u64>,
    ) -> PyResult<Vec<PyValue>> {
        let _permit = self
            .flow_waits
            .acquire()
            .await
            .map_err(|e| PyExc::Other("RuntimeError", e.to_string()))?;
        validate_flow_id(Some(flow_id))?;
        let vql = format!(
            "SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId='{flow_id}' LIMIT 1"
        );
        let timeout = timeout.unwrap_or(self.timeouts.flow);
        tracing::info!("Watching flow {flow_id} for completion (timeout {timeout}s)");
        self.execute_query(&vql, org_id, Some(timeout)).await
    }

    /// `read_collection_results(client_id, flow_id, org_id, artifact)`.
    pub async fn read_collection_results(
        &self,
        client_id: Option<&str>,
        flow_id: Option<&str>,
        org_id: Option<&str>,
        artifact: Option<&str>,
    ) -> PyResult<Vec<PyValue>> {
        let client_id = validate_client_id(client_id)?;
        let flow_id = validate_flow_id(flow_id)?;
        let artifact = validate_artifact_name(artifact)?;
        let vql = format!(
            "SELECT * FROM source(client_id='{client_id}', flow_id='{flow_id}', artifact='{artifact}')"
        );
        self.execute_query(&vql, org_id, None).await
    }

    /// `_get_server_version(vql)`: `results[0]["version"]["version"]`, an
    /// empty answer being the 500 `Failed to get server version: list index
    /// out of range`.
    pub async fn get_server_version(&self, vql: &str) -> PyResult<PyValue> {
        let results = self.execute_query(vql, ROOT, None).await?;
        let first = results.first().ok_or_else(|| {
            PyExc::http(500, "Failed to get server version: list index out of range")
        })?;
        let version = getitem(first, "version")?;
        Ok(getitem(version, "version")?.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_settings_read_like_int() {
        assert_eq!(py_int(" 30 "), Some(30));
        assert_eq!(py_int("1_000"), Some(1000));
        assert_eq!(py_int("+5"), Some(5));
        assert_eq!(py_int("-5"), Some(-5));
        assert_eq!(py_int("1__0"), None);
        assert_eq!(py_int("_1"), None);
        assert_eq!(py_int("3.5"), None);
        assert_eq!(py_int(""), None);
    }

    #[test]
    fn requests_coalesce_and_validate_the_org() {
        let r = Service::create_vql_request("SELECT 1", None).unwrap();
        assert_eq!(r.org_id, "root");
        assert_eq!(r.max_wait, 1);
        assert_eq!(r.query[0].name, "VQLRequest");
        assert_eq!(
            Service::create_vql_request("x", Some("")).unwrap().org_id,
            "root"
        );
        assert_eq!(
            Service::create_vql_request("x", Some("O'1")).unwrap_err(),
            PyExc::http(400, "Invalid Velociraptor org id")
        );
    }

    #[test]
    fn results_extend_as_a_python_list_does() {
        let mut r = Vec::new();
        extend(&mut r, loads(r#"[{"a": 1}]"#).unwrap()).unwrap();
        extend(&mut r, loads(r#"{"k": 1}"#).unwrap()).unwrap();
        extend(&mut r, loads(r#""ab""#).unwrap()).unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(
            extend(&mut r, loads("5").unwrap()).unwrap_err().text(),
            "'int' object is not iterable"
        );
        assert_eq!(
            extend(&mut r, loads("null").unwrap()).unwrap_err().text(),
            "'NoneType' object is not iterable"
        );
        assert_eq!(
            json_loads("[1,").unwrap_err().text(),
            "Expecting value: line 1 column 4 (char 3)"
        );
    }
}
