//! `/api/copilot_mcp` — port of `routes/copilot_mcp.py`: five routes, every
//! one `require_any_scope("admin", "analyst")`. The servers and their
//! questions are deployment-wide; the query reaches the local `copilot-mcp`
//! container (the four local servers) or SOCFortress's cloud (the four cloud
//! servers, behind the `SOCFORTRESS AI` licence feature). No route is
//! tenant-scoped, as in Python: a query names no customer.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::services::mcp;
use copilot_upstream::py::PyExc;
use copilot_upstream::respond::{body_model, model_response};
use copilot_web::validate::{Validator, loc};
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, Authorized, JsonBody, QueryPairs, WithJson,
};
use http::StatusCode;
use serde_json::Value;

use crate::McpState;
use crate::schema::{self, MCP_QUERY_REQUEST, SERVER_ENUM, SERVERS, Server};

type Reader = Authorized<AdminOrAnalyst>;

/// The five routes (full paths), behind the encoded-slash hand-off.
pub fn router(state: McpState) -> Router {
    let p = |s: &str| format!("/api/copilot_mcp{s}");
    let legacy = state.legacy.clone();
    Router::new()
        .route(&p("/servers"), get(servers))
        .route(&p("/servers/{mcp_server}"), get(server))
        .route(&p("/example-questions"), get(example_questions))
        .route(&p("/categories"), get(categories))
        .route(&p("/query"), post(query))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            legacy,
            copilot_wazuh::decoded_slash_to_legacy,
        ))
}

fn ok(dump: &PyValue) -> Response {
    model_response(dump)
}

fn s(v: impl Into<String>) -> PyValue {
    PyValue::Str(v.into())
}

fn dict(pairs: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn int(n: usize) -> PyValue {
    PyValue::Int(n.to_string())
}

fn strings(items: &[&str]) -> PyValue {
    PyValue::List(items.iter().map(|c| s(*c)).collect())
}

/// An `MCPServerType` parameter: the server, or Pydantic's `missing` /
/// `enum` error.
fn enum_param(v: &mut Validator, location: &str, raw: Option<&str>) -> Option<Server> {
    let name = "mcp_server";
    let Some(raw) = raw else {
        v.missing(loc(location, name));
        return None;
    };
    let found = Server::from_value(raw);
    if found.is_none() {
        v.push(
            "enum",
            loc(location, name),
            format!("Input should be {}", SERVER_ENUM.expected()),
        );
    }
    found
}

async fn servers(_: Reader) -> ApiResult {
    tracing::info!("Fetching available MCP servers");
    let list: Vec<PyValue> = SERVERS.iter().map(schema::ServerInfo::dump).collect();
    tracing::info!("Found {} available MCP servers", list.len());
    let total = int(list.len());
    Ok(ok(&dict(vec![
        ("servers", PyValue::List(list)),
        ("total_servers", total),
        ("message", s("Successfully retrieved available MCP servers")),
        ("success", PyValue::Bool(true)),
    ])))
}

async fn server(_: Reader, Path(raw): Path<String>) -> ApiResult {
    let mut v = Validator::new();
    let server = enum_param(&mut v, "path", Some(&raw));
    v.finish()?;
    let Some(server) = server else {
        return Err(ApiError::internal("unreachable: validated"));
    };
    let value = server.value();
    tracing::info!("Fetching details for MCP server: {value}");
    let Some(info) = schema::server_info(server) else {
        return Ok(ok(&dict(vec![
            ("server", s(value)),
            (
                "message",
                s(format!("Server information not found for {value}")),
            ),
            ("success", PyValue::Bool(false)),
        ])));
    };
    let categories = schema::categories(server);
    Ok(ok(&dict(vec![
        ("server", info.dump()),
        ("available_categories", strings(&categories)),
        (
            "total_example_questions",
            int(schema::questions(server).len()),
        ),
        (
            "message",
            s(format!("Successfully retrieved details for {value}")),
        ),
        ("success", PyValue::Bool(true)),
    ])))
}

async fn example_questions(_: Reader, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let server = enum_param(&mut v, "query", q.get("mcp_server"));
    let category = q.get("category").map(str::to_string);
    v.finish()?;
    let Some(server) = server else {
        return Err(ApiError::internal("unreachable: validated"));
    };
    let value = server.value();
    tracing::info!("Fetching example questions for MCP server: {value}");
    let questions: Vec<PyValue> = schema::questions(server)
        .iter()
        // `if category:`: an empty one is no filter.
        .filter(|qn| {
            category
                .as_deref()
                .is_none_or(|c| c.is_empty() || qn.category == c)
        })
        .map(schema::Question::dump)
        .collect();
    let total = int(questions.len());
    Ok(ok(&dict(vec![
        ("mcp_server", s(value)),
        ("questions", PyValue::List(questions)),
        ("total_questions", total),
        (
            "message",
            s(format!(
                "Successfully retrieved example questions for {value}"
            )),
        ),
        ("success", PyValue::Bool(true)),
    ])))
}

async fn categories(_: Reader, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let server = enum_param(&mut v, "query", q.get("mcp_server"));
    v.finish()?;
    let Some(server) = server else {
        return Err(ApiError::internal("unreachable: validated"));
    };
    let value = server.value();
    tracing::info!("Fetching question categories for MCP server: {value}");
    let categories = schema::categories(server);
    Ok(ok(&dict(vec![
        ("mcp_server", s(value)),
        ("categories", strings(&categories)),
        ("total_categories", int(categories.len())),
        (
            "message",
            s(format!("Successfully retrieved categories for {value}")),
        ),
        ("success", PyValue::Bool(true)),
    ])))
}

/// `MCPQueryRequest.validate_mcp_server` (`mode="before"`): a string that is
/// no `MCPServerType` value is an `HTTPException` that ends the validation,
/// whatever the other fields hold.
pub(crate) fn invalid_server(body: &JsonBody) -> Option<ApiError> {
    let JsonBody::Value(Value::Object(fields)) = body else {
        return None;
    };
    let Some(Value::String(raw)) = fields.get("mcp_server") else {
        return None;
    };
    if Server::from_value(raw).is_some() {
        return None;
    }
    Some(ApiError::http(
        StatusCode::BAD_REQUEST,
        format!(
            "Invalid MCP server type: '{raw}'. Must be one of: {}",
            SERVER_ENUM.values.join(", ")
        ),
    ))
}

async fn query(State(st): State<McpState>, WithJson(_auth, body): WithJson<Reader>) -> ApiResult {
    if let Some(e) = invalid_server(&body) {
        return Err(e);
    }
    let request = body_model(&body, &MCP_QUERY_REQUEST)?;
    let value = request
        .get("mcp_server")
        .and_then(PyValue::as_str)
        .unwrap_or_default()
        .to_string();
    let Some(server) = Server::from_value(&value) else {
        return Err(ApiError::internal("unreachable: validated"));
    };
    tracing::info!("Processing MCP query for server: {value}");
    let (cloud, endpoint) = server.config();
    let key = if cloud {
        let key = mcp::cloud_license_key(&st.threat_intel)
            .await
            .map_err(PyExc::unhandled)?;
        tracing::info!("Retrieved license key for cloud service {value}");
        Some(key)
    } else {
        None
    };
    let base = if cloud {
        &st.threat_intel.urls.mcp
    } else {
        &st.local_base
    };
    let url = format!("{base}/{endpoint}");
    tracing::info!(
        "Sending MCP query to {value} ({}) at {url}",
        if cloud { "cloud" } else { "local" }
    );
    let answer = mcp::execute_query(&url, &value, request, key.as_deref()).await;
    Ok(ok(&mcp::respond(&answer).map_err(PyExc::unhandled)?))
}
