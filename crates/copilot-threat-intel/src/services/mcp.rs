//! The cloud half of `app/integrations/copilot_mcp/`: `query_mcp` for the
//! `cyber-news` server, which `POST /threat_intel/process_name` calls.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, construct_star};
use copilot_upstream::py::{PyExc, PyResult};
use http::Method;

use crate::ThreatIntelState;
use crate::httpx::{self, Request};
use crate::license;
use crate::py::{dict, s};
use crate::schema::MCP_RESPONSE;

/// The server the process-name route asks (`MCPServerType.CYBER_NEWS`).
pub const SERVER: &str = "cyber-news";
/// Its endpoint under the cloud base.
pub const ENDPOINT: &str = "cyber_news";

/// `query_mcp(MCPQueryRequest(mcp_server="cyber-news", input=…))`: the
/// licence (`SOCFORTRESS AI`) and its key, then `execute_query`.
pub async fn query(st: &ThreatIntelState, input: &str) -> PyResult<PyValue> {
    tracing::info!("Processing MCP query for server: {SERVER}");
    let checked = async {
        license::is_feature_enabled(st, "SOCFORTRESS AI").await?;
        let key = license::license_key(st).await?;
        if key.is_empty() {
            return Err(PyExc::http(
                404,
                "No license found. A license must be created first.",
            ));
        }
        Ok(key)
    }
    .await;
    let key = match checked {
        Ok(k) => k,
        Err(e @ PyExc::Http(..)) => return Err(e),
        Err(e) => {
            return Err(PyExc::http(
                500,
                format!("License validation failed: {}", e.display()),
            ));
        }
    };
    Ok(execute_query(st, input, &key).await)
}

fn failed(message: String) -> PyValue {
    // `MCPQueryResponse(message=…, success=False, result=None,
    // structured_result=None, execution_time=0.0)`.
    dict(vec![
        ("message", s(message)),
        ("success", PyValue::Bool(false)),
        ("result", PyValue::None),
        ("structured_result", PyValue::None),
        ("execution_time", PyValue::Float(0.0)),
    ])
}

/// `MCPService.execute_query(data, license_key)`: every failure becomes an
/// answer (`Error: …` for a `ValueError`, `HTTP error when querying …` for
/// an httpx error, `Unexpected error: …` for the rest).
async fn execute_query(st: &ThreatIntelState, input: &str, key: &str) -> PyValue {
    let body = dict(vec![
        ("input", s(input)),
        ("mcp_server", s(SERVER)),
        ("verbose", PyValue::Bool(true)),
    ]);
    let sent = httpx::send(
        Request::new(Method::POST, format!("{}/{ENDPOINT}", st.urls.mcp))
            .header("Content-Type", Some("application/json"))
            .header("x-api-key", Some(key))
            .json(body)
            .timeout(Duration::from_secs(300)),
    )
    .await;
    let outcome = match sent {
        Err(e) if e.is_http_error() => {
            return failed(format!("HTTP error when querying {SERVER}: {}", e.message));
        }
        Err(e) if e.class == "UnicodeEncodeError" => {
            return failed(format!("Error: {}", e.message));
        }
        Err(e) => return failed(format!("Unexpected error: {}", e.message)),
        Ok(response) => match response.raise_for_status() {
            Err(e) => return failed(format!("HTTP error when querying {SERVER}: {}", e.message)),
            Ok(()) => response.json().and_then(|answer| {
                construct_star(
                    &MCP_RESPONSE,
                    "app.integrations.copilot_mcp.schema.copilot_mcp.MCPQueryResponse",
                    &answer,
                )
            }),
        },
    };
    match outcome {
        Ok(v) => v,
        Err(e) if e.is_value_error() => failed(format!("Error: {}", e.text())),
        Err(e) => failed(format!("Unexpected error: {}", e.text())),
    }
}

/// The route's answer model over what [`query`] returned.
pub fn respond(answer: &PyValue) -> PyResult<PyValue> {
    construct(&MCP_RESPONSE, answer)
}
