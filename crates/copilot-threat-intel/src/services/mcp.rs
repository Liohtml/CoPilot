//! `MCPService.execute_query` of `app/integrations/copilot_mcp/` (shared with
//! `copilot-mcp`, which answers `/api/copilot_mcp`) and `query_mcp` for the
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
    let key = cloud_license_key(st).await?;
    let body = dict(vec![
        ("input", s(input)),
        ("mcp_server", s(SERVER)),
        ("verbose", PyValue::Bool(true)),
    ]);
    let url = format!("{}/{ENDPOINT}", st.urls.mcp);
    Ok(execute_query(&url, SERVER, body, Some(&key)).await)
}

/// What `query_mcp` checks before it asks a cloud server: the licence's
/// `SOCFORTRESS AI` feature and its key. An `HTTPException` passes through;
/// anything else is the route's 500 `License validation failed: …`.
pub async fn cloud_license_key(st: &ThreatIntelState) -> PyResult<String> {
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
    match checked {
        Ok(k) => Ok(k),
        Err(e @ PyExc::Http(..)) => Err(e),
        Err(e) => Err(PyExc::http(
            500,
            format!("License validation failed: {}", e.display()),
        )),
    }
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

/// `MCPService.execute_query(data, license_key)` for the server named
/// `server` at `url`, `body` being `data.model_dump()`: every failure becomes
/// an answer (`Error: …` for a `ValueError`, `HTTP error when querying …`
/// for an httpx error, `Unexpected error: …` for the rest). `x-api-key` is
/// sent when there is a key (a cloud server's).
pub async fn execute_query(url: &str, server: &str, body: PyValue, key: Option<&str>) -> PyValue {
    let mut req = Request::new(Method::POST, url).header("Content-Type", Some("application/json"));
    if let Some(key) = key.filter(|k| !k.is_empty()) {
        req = req.header("x-api-key", Some(key));
    }
    let sent = httpx::send(req.json(body).timeout(Duration::from_secs(300))).await;
    let outcome = match sent {
        Err(e) if e.is_http_error() => {
            return failed(format!("HTTP error when querying {server}: {}", e.message));
        }
        Err(e) if e.class == "UnicodeEncodeError" => {
            return failed(format!("Error: {}", e.message));
        }
        Err(e) => return failed(format!("Unexpected error: {}", e.message)),
        Ok(response) => match response.raise_for_status() {
            Err(e) => return failed(format!("HTTP error when querying {server}: {}", e.message)),
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
