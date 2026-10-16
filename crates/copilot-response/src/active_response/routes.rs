//! `/api/active_response` — port of
//! `app/active_response/routes/active_response.py` — and the Graylog
//! webhook `POST /api/graylog/invoke` (`routes/graylog.py`).
//!
//! **Tenancy** (`invoke`): the targets are in the body. A caller without
//! deployment-wide access must name them (`agents_list` absent, empty or
//! `["*"]` — which the model turns into `[]` — is the 403: Wazuh would run
//! the command on *every* agent) and own each one
//! (`enforce_agent_access`, fail-closed), checked before anything is sent.
//!
//! **The webhook** has no token: it is Graylog's HTTP notification,
//! authenticated by its `graylog` header against
//! `GRAYLOG_API_HEADER_VALUE` — fail closed without one (GHSA-x8gc-f8p4-frc2)
//! — before the body is validated. It answers success whatever Wazuh says.

use axum::Router;
use axum::extract::{FromRef, Path, State};
use axum::routing::{get, post};
use http::HeaderMap;
use serde_json::Value;

use copilot_agents::db::{Cond, Tenancy, first};
use copilot_auth::AccessScope;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::respond::model_response;
use copilot_web::form::latin1;
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, JsonBody, WithJson,
};

use crate::ResponseState;
use crate::active_response::schema::{self, SUPPORTED, SUPPORTED_ITEMS, item, read_invoke};
use crate::active_response::services;

type Soc = Authorized<AdminOrAnalyst>;

/// `scripts/windows/windows_firewall.md`, the one script the describe route
/// can read (a copy of the backend's file, pinned by a test).
pub const WINDOWS_FIREWALL_MD: &str = include_str!("../../templates/windows_firewall.md");

/// The router to nest at `/api/active_response`.
pub fn router(state: ResponseState) -> Router {
    Router::new()
        .route("/describe/{active_response_name}", get(describe))
        .route("/supported", get(supported))
        .route("/supported/{agent_id}", get(supported_for_agent))
        .route("/invoke", post(invoke))
        .with_state(state)
}

/// The webhook, with its full path (beside the nested Graylog connector).
pub fn graylog_router(state: ResponseState) -> Router {
    Router::new()
        .route("/api/graylog/invoke", post(graylog_invoke))
        .with_state(state)
}

impl FromRef<ResponseState> for AppContext {
    fn from_ref(s: &ResponseState) -> AppContext {
        s.ctx.clone()
    }
}

fn supported_response(items: Vec<PyValue>) -> PyValue {
    PyValue::Dict(vec![
        ("supported_active_responses".into(), PyValue::List(items)),
        ("success".into(), PyValue::Bool(true)),
        (
            "message".into(),
            PyValue::Str("Supported Active Responses retrieved successfully".into()),
        ),
    ])
}

/// `GET /describe/{name}`: the name must be a member (case-insensitively);
/// the file is then read as `scripts/{first part, lowered}/{name}.md`, so
/// only the exact lower-case spelling finds it — any other is Python's
/// `FileNotFoundError`, a bare 500.
async fn describe(_auth: Soc, Path(name): Path<String>) -> ApiResult {
    let upper = name.to_uppercase();
    let Some((_, description)) = SUPPORTED.iter().find(|(n, _)| *n == upper) else {
        return Err(ApiError::not_found("Active Response not found"));
    };
    let directory = name.split('_').next().unwrap_or_default().to_lowercase();
    let file = format!("scripts/{directory}/{name}.md");
    tracing::info!("Reading markdown file: {file}");
    if file != "scripts/windows/windows_firewall.md" {
        return Err(ApiError::internal(format!(
            "[Errno 2] No such file or directory: '{file}'"
        )));
    }
    let details = PyValue::Dict(vec![
        ("name".into(), PyValue::Str(name.clone())),
        ("description".into(), PyValue::Str((*description).into())),
        (
            "markdown_content".into(),
            PyValue::Str(WINDOWS_FIREWALL_MD.into()),
        ),
    ]);
    Ok(model_response(&PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(true)),
        (
            "message".into(),
            PyValue::Str("Active Response details retrieved successfully".into()),
        ),
        ("active_response".into(), details),
    ])))
}

async fn supported(_auth: Soc) -> ApiResult {
    Ok(model_response(&supported_response(SUPPORTED_ITEMS.clone())))
}

/// `GET /supported/{agent_id}`: `get_agent` (the agents route, called
/// directly: its own 404 is swallowed into its 500), then the responses of
/// the agent's OS family.
async fn supported_for_agent(
    auth: Soc,
    State(st): State<ResponseState>,
    Path(agent_id): Path<String>,
) -> ApiResult {
    tracing::info!("Fetching agent with agent_id: {agent_id}");
    let failed =
        || ApiError::server_error(format!("Failed to fetch agent: {agent_id}. Does it exist?"));
    let scope = auth.access(&st.ctx).await.map_err(|_| failed())?;
    let tenancy = Tenancy::of(&scope.resolve_effective(None));
    let agent = first(&st.ctx.db, &[Cond::AgentId(&agent_id)], &tenancy)
        .await
        .map_err(|_| failed())?
        .ok_or_else(failed)?;
    let os = agent.os.clone();
    if os.is_empty() {
        return Err(ApiError::not_found("Agent not found"));
    }
    let family = if os.contains("Windows") {
        tracing::info!("Agent OS is Windows");
        "WINDOWS"
    } else {
        tracing::info!("Agent OS is Linux");
        "LINUX"
    };
    let items = SUPPORTED
        .iter()
        .filter(|(name, _)| name.contains(family))
        .map(|(name, description)| item(name, description))
        .collect();
    Ok(model_response(&supported_response(items)))
}

/// `"*" in get_user_accessible_customers(user)`.
fn deployment_wide(scope: &AccessScope) -> bool {
    match scope {
        AccessScope::All => true,
        AccessScope::Customers(codes) => codes.iter().any(|c| c == "*"),
    }
}

async fn invoke(State(st): State<ResponseState>, WithJson(auth, body): WithJson<Soc>) -> ApiResult {
    let req = read_invoke(&body)?;
    tracing::info!("Invoking Wazuh Active Response...");
    let scope = auth.access(&st.ctx).await?;
    if !deployment_wide(scope) {
        let targets = req.agents_list.clone().unwrap_or_default();
        if targets.is_empty() {
            return Err(ApiError::forbidden(
                "agents_list is required: a deployment-wide active response is limited to \
                 unscoped users",
            ));
        }
        for agent_id in &targets {
            let owner = copilot_db::agents::customer_code_for_agent(&st.ctx.db, agent_id).await?;
            auth.enforce_owned(&st.ctx, owner.as_deref(), &format!("agent {agent_id}"))
                .await?;
        }
    }
    let response = services::invoke(&st.wazuh, &req).await?;
    if response.is_null() {
        return Err(ApiError::http(
            http::StatusCode::SERVICE_UNAVAILABLE,
            "Wazuh Manager connector is not configured",
        ));
    }
    let truthy = |v: Option<&Value>| v.is_some_and(copilot_wazuh::pyops::truthy);
    if !truthy(response.get("success")) {
        tracing::error!(
            "Request failed: {}",
            response
                .get("message")
                .map(copilot_wazuh::pyops::py_str)
                .unwrap_or_else(|| "None".into())
        );
        let detail = [response.get("error_detail"), response.get("message")]
            .into_iter()
            .find(|v| truthy(*v))
            .flatten()
            .map(copilot_wazuh::pyops::py_str)
            .unwrap_or_else(|| "Wazuh rejected the Active Response request".into());
        return Err(ApiError::http(
            http::StatusCode::BAD_GATEWAY,
            format!("Wazuh Active Response failed: {detail}"),
        ));
    }
    Ok(invoked())
}

fn invoked() -> axum::response::Response {
    model_response(&PyValue::Dict(vec![
        ("success".into(), PyValue::Bool(true)),
        (
            "message".into(),
            PyValue::Str("Wazuh Active Response invoked successfully".into()),
        ),
    ]))
}

/// `verify_graylog_header`.
fn check_graylog_header(headers: &HeaderMap, expected: Option<&str>) -> Result<(), ApiError> {
    let Some(expected) = expected.filter(|e| !e.is_empty()) else {
        tracing::error!(
            "GRAYLOG_API_HEADER_VALUE is not configured; denying Graylog webhook request"
        );
        return Err(ApiError::forbidden(
            "Graylog header authentication is not configured",
        ));
    };
    let sent = headers.get("graylog").map(|v| latin1(v.as_bytes()));
    if sent.as_deref() != Some(expected) {
        tracing::error!("Invalid or missing Graylog header");
        return Err(ApiError::forbidden("Invalid or missing Graylog header"));
    }
    Ok(())
}

async fn graylog_invoke(
    State(st): State<ResponseState>,
    headers: HeaderMap,
    body: JsonBody,
) -> ApiResult {
    check_graylog_header(&headers, st.env.graylog_api_header_value.as_deref())?;
    let fields = schema::read_notification(&body)?;
    tracing::info!("Invoking Wazuh Active Response...");
    services::invoke_from_graylog(&st.wazuh, &fields).await?;
    Ok(invoked())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_compiled_markdown_is_the_backend_file() {
        let backend = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../backend/app/active_response/scripts/windows/windows_firewall.md"
        );
        let on_disk = std::fs::read_to_string(backend).expect("backend file");
        assert_eq!(
            on_disk, WINDOWS_FIREWALL_MD,
            "templates/windows_firewall.md differs from the backend's: copy it again"
        );
    }
}
