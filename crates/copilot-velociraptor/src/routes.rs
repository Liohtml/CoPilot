//! `/api/artifacts` and `/api/flows` — port of
//! `app/connectors/velociraptor/routes/{artifacts,flows}.py`.
//!
//! Every route but the artifact listings names an endpoint, by hostname or
//! by Velociraptor client id; its tenant is checked first, as in Python
//! (`verify_hostname_access`, `enforce_hostname_access`,
//! `enforce_owned_object_access`: fail-closed). The response routes
//! (`/command`, `/quarantine`) admit `admin` and `responder` and are audited.
//!
//! Still Python: `POST /api/artifacts/collect` and `POST
//! /api/artifacts/collect/file/agent/{agent_id}` store the collection in
//! MinIO. No route here matches them (`/collect` is only a `GET`), so the
//! binary forwards both.

use axum::Router;
use axum::extract::{FromRef, Path, State};
use axum::routing::{get, post};
use serde_json::{Map, Value};

use copilot_auth::pyvalue::PyValue;
use copilot_core::audit::AuditRecord;
use copilot_upstream::respond::model_response;
use copilot_web::validate::{Loc, LocPart, StrRules, Validator};
use copilot_web::{
    AdminOrAnalyst, ApiError, ApiResult, AppContext, Authorized, CurrentUser, JsonBody, ScopeSet,
    WithJson,
};

use crate::VelociraptorClient;
use crate::agents::{self, AgentRow};
use crate::schema::{
    ACTIONS, COMMAND_ARTIFACTS, QUARANTINE_ARTIFACTS, QuarantineBody, RunCommandBody,
};
use crate::services::{artifacts, flows};

/// `require_any_scope("admin", "responder")`.
#[derive(Debug)]
pub struct AdminOrResponder;
impl ScopeSet for AdminOrResponder {
    const SCOPES: &'static [&'static str] = &["admin", "responder"];
}

type Soc = Authorized<AdminOrAnalyst>;

/// What the Velociraptor routes need.
#[derive(Debug, Clone)]
pub struct VelociraptorState {
    /// The shared context.
    pub ctx: AppContext,
    /// The gRPC client.
    pub client: VelociraptorClient,
}

impl FromRef<VelociraptorState> for AppContext {
    fn from_ref(s: &VelociraptorState) -> AppContext {
        s.ctx.clone()
    }
}

/// The router to nest at `/api/artifacts`.
pub fn artifacts_router(state: VelociraptorState) -> Router {
    Router::new()
        .route("/", get(list))
        .route("/{os_prefix}", get(for_os_prefix))
        .route("/artifact/{artifact_name}", get(by_name))
        .route(
            "/artifact/{artifact_name}/parameters/{parameter_prefix}",
            get(parameters),
        )
        .route("/hostname/{hostname}", get(for_hostname))
        .route("/command", post(command))
        .route("/quarantine", post(quarantine))
        .with_state(state)
}

/// The router to nest at `/api/flows`.
pub fn flows_router(state: VelociraptorState) -> Router {
    Router::new()
        .route("/{hostname}", get(flows_for_hostname))
        .route("/retrieve", post(retrieve))
        .with_state(state)
}

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(name.into()));
    l
}

/// `verify_hostname_access` / `enforce_hostname_access`: the first agent
/// with the hostname decides (none: denied to a scoped caller). Returns
/// that agent.
async fn enforce_host(
    st: &VelociraptorState,
    auth: &CurrentUser,
    hostname: &str,
) -> Result<Option<AgentRow>, ApiError> {
    let agent = agents::by_hostname(&st.ctx.db, hostname).await?;
    auth.enforce_owned(
        &st.ctx,
        agent.as_ref().and_then(|a| a.customer_code.as_deref()),
        &format!("host {hostname}"),
    )
    .await?;
    Ok(agent)
}

fn host_not_found(hostname: &str) -> ApiError {
    ApiError::not_found(format!("Agent with hostname {hostname} not found"))
}

// --- artifacts ------------------------------------------------------------------

async fn list(_auth: Soc, State(st): State<VelociraptorState>) -> ApiResult {
    tracing::info!("Fetching all artifacts");
    let all = artifacts::get_artifacts(&st.client).await?;
    Ok(model_response(&artifacts::artifacts_response(
        "All artifacts retrieved".into(),
        all,
    )))
}

/// `get_all_artifacts_for_os_prefix(prefix)`: the artifacts named
/// `<prefix>…` or `Custom.<prefix>…`.
async fn artifacts_with_prefix(
    st: &VelociraptorState,
    prefix: &str,
) -> Result<Vec<PyValue>, ApiError> {
    let custom = format!("Custom.{prefix}");
    Ok(artifacts::get_artifacts(&st.client)
        .await?
        .into_iter()
        .filter(|a| {
            copilot_upstream::model::field(a, "name")
                .as_str()
                .is_some_and(|n| n.starts_with(prefix) || n.starts_with(&custom))
        })
        .collect())
}

async fn for_os_prefix(
    _auth: Soc,
    State(st): State<VelociraptorState>,
    Path(os_prefix): Path<String>,
) -> ApiResult {
    let prefix = artifacts::verify_os_prefix(&os_prefix)?;
    tracing::info!("Fetching all artifacts for OS prefix {prefix}");
    let found = artifacts_with_prefix(&st, prefix).await?;
    Ok(model_response(&artifacts::artifacts_response(
        format!("All artifacts for OS prefix {prefix} retrieved"),
        found,
    )))
}

async fn by_name(
    _auth: Soc,
    State(st): State<VelociraptorState>,
    Path(artifact_name): Path<String>,
) -> ApiResult {
    tracing::info!("Fetching artifact by name: {artifact_name}");
    let (message, found) = artifacts::get_artifact_by_name(&st.client, &artifact_name).await?;
    Ok(model_response(&artifacts::artifacts_response(
        message, found,
    )))
}

async fn parameters(
    _auth: Soc,
    State(st): State<VelociraptorState>,
    Path((artifact_name, parameter_prefix)): Path<(String, String)>,
) -> ApiResult {
    let dump =
        artifacts::parameters_by_prefix(&st.client, &artifact_name, &parameter_prefix).await?;
    Ok(model_response(&dump))
}

/// `get_all_artifacts_for_hostname(hostname)`: the artifacts of the host's
/// OS (its prefix without the dot: the route function is called directly,
/// its `Depends` not applied).
async fn host_artifacts(
    st: &VelociraptorState,
    hostname: &str,
    agent: Option<&AgentRow>,
) -> Result<Vec<PyValue>, ApiError> {
    tracing::info!("Fetching all artifacts for hostname {hostname}");
    let agent = agent.ok_or_else(|| host_not_found(hostname))?;
    let os = agent.os.to_lowercase();
    let prefix = artifacts::os_prefix_of(&os).ok_or_else(|| {
        ApiError::not_found(format!(
            "OS prefix of {os} for hostname {hostname} not found"
        ))
    })?;
    artifacts_with_prefix(st, prefix).await
}

async fn for_hostname(
    auth: Soc,
    State(st): State<VelociraptorState>,
    Path(hostname): Path<String>,
) -> ApiResult {
    let agent = enforce_host(&st, &auth, &hostname).await?;
    let found = host_artifacts(&st, &hostname, agent.as_ref()).await?;
    Ok(model_response(&artifacts::artifacts_response(
        format!("All available artifacts that can be ran for hostname {hostname} retrieved"),
        found,
    )))
}

fn artifact_names(found: &[PyValue]) -> Vec<String> {
    found
        .iter()
        .filter_map(|a| {
            copilot_upstream::model::field(a, "name")
                .as_str()
                .map(str::to_string)
        })
        .collect()
}

/// `get_velociraptor_id` then `get_velociraptor_org` of the host.
fn host_ids(
    hostname: &str,
    agent: Option<&AgentRow>,
) -> Result<(Option<String>, String), ApiError> {
    let agent = agent.ok_or_else(|| host_not_found(hostname))?;
    if agent.velociraptor_id.as_deref() == Some("n/a") {
        return Err(ApiError::not_found(format!(
            "Velociraptor ID for hostname {hostname} is not available"
        )));
    }
    let org = agent.velociraptor_org.clone().ok_or_else(|| {
        ApiError::not_found(format!(
            "Velociraptor ORG for hostname {hostname} is not available"
        ))
    })?;
    Ok((agent.velociraptor_id.clone(), org))
}

/// A field `Enum = Field(None)`: absent is `None`, anything sent is checked.
fn enum_or_none(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    allowed: &[&str],
) -> Option<String> {
    obj.get(name)
        .and_then(|value| v.check_enum(&child(at, name), value, allowed))
}

async fn command(
    State(st): State<VelociraptorState>,
    WithJson(auth, body): WithJson<Authorized<AdminOrResponder>>,
) -> ApiResult {
    let mut body = body.model(|v, obj, at| RunCommandBody {
        hostname: v.req_str(obj, at, "hostname", StrRules::default()),
        velociraptor_id: v.opt_str(obj, at, "velociraptor_id", StrRules::default()),
        velociraptor_org: v.opt_str(obj, at, "velociraptor_org", StrRules::default()),
        command: v.opt_str(obj, at, "command", StrRules::default()),
        artifact_name: enum_or_none(v, obj, at, "artifact_name", COMMAND_ARTIFACTS),
    })?;
    tracing::info!("Received request to run command {}", body.py_str());
    let agent = enforce_host(&st, &auth, &body.hostname).await?;
    let found = host_artifacts(&st, &body.hostname, agent.as_ref()).await?;
    let Some(artifact) = body.artifact_name.clone() else {
        // `run_command_body.artifact_name.value` of `None`.
        return Err(ApiError::internal(
            "'NoneType' object has no attribute 'value'",
        ));
    };
    if !artifact_names(&found).contains(&artifact) {
        return Err(ApiError::bad_request(format!(
            "Artifact name {artifact} does not apply for hostname {} or does not exist",
            body.hostname
        )));
    }
    let (velociraptor_id, org) = host_ids(&body.hostname, agent.as_ref())?;
    body.velociraptor_id = velociraptor_id;
    body.velociraptor_org = Some(org);
    st.ctx.audit.record(
        AuditRecord::new("response.command_execute")
            .actor(Some(auth.id), Some(&auth.username))
            .entity("agent", &body.hostname)
            // The artifact and host only; the command itself is not stored.
            .values(
                None,
                Some(serde_json::json!({
                    "artifact_name": artifact,
                    "velociraptor_id": body.velociraptor_id,
                })),
            )
            .source_ip(auth.source_ip.clone()),
    );
    let dump = artifacts::run_remote_command(&st.client, &body).await?;
    Ok(model_response(&dump))
}

async fn quarantine(
    State(st): State<VelociraptorState>,
    WithJson(auth, body): WithJson<Authorized<AdminOrResponder>>,
) -> ApiResult {
    let mut body = body.model(|v, obj, at| QuarantineBody {
        hostname: v.req_str(obj, at, "hostname", StrRules::default()),
        velociraptor_id: v.opt_str(obj, at, "velociraptor_id", StrRules::default()),
        velociraptor_org: v.opt_str(obj, at, "velociraptor_org", StrRules::default()),
        action: v.req_enum(obj, at, "action", ACTIONS),
        artifact_name: enum_or_none(v, obj, at, "artifact_name", QUARANTINE_ARTIFACTS),
    })?;
    tracing::info!("Received request to quarantine host {}", body.hostname);
    let agent = enforce_host(&st, &auth, &body.hostname).await?;
    let found = host_artifacts(&st, &body.hostname, agent.as_ref()).await?;
    let effective = artifacts::resolve_quarantine_artifact(body.artifact_name.as_deref());
    if !artifact_names(&found).contains(&effective) {
        return Err(ApiError::bad_request(format!(
            "Artifact name {effective} does not apply for hostname {} or does not exist",
            body.hostname
        )));
    }
    body.artifact_name = Some(effective);
    let (velociraptor_id, org) = host_ids(&body.hostname, agent.as_ref())?;
    body.velociraptor_id = velociraptor_id;
    body.velociraptor_org = Some(org);
    let dump = artifacts::quarantine_host(&st.client, &body).await?;
    // `update_agent_quarantine_status`: the response is always a success.
    let agent = agents::by_hostname(&st.ctx.db, &body.hostname)
        .await?
        .ok_or_else(|| host_not_found(&body.hostname))?;
    agents::set_quarantined(&st.ctx.db, agent.id, body.action == "quarantine").await?;
    tracing::info!(
        "Agent quarantine status for hostname {} updated to {}",
        body.hostname,
        if body.action == "quarantine" {
            "True"
        } else {
            "False"
        }
    );
    let artifact = artifacts::resolve_quarantine_artifact(body.artifact_name.as_deref());
    st.ctx.audit.record(
        AuditRecord::new("response.quarantine")
            .actor(Some(auth.id), Some(&auth.username))
            .entity("agent", &body.hostname)
            .values(
                None,
                Some(serde_json::json!({
                    "action": body.action,
                    "artifact_name": artifact,
                    "velociraptor_id": body.velociraptor_id,
                })),
            )
            .source_ip(auth.source_ip.clone()),
    );
    Ok(model_response(&dump))
}

// --- flows ----------------------------------------------------------------------

async fn flows_for_hostname(
    auth: Soc,
    State(st): State<VelociraptorState>,
    Path(hostname): Path<String>,
) -> ApiResult {
    let agent = enforce_host(&st, &auth, &hostname).await?;
    tracing::info!("Fetching all flows for hostname {hostname}");
    let (velociraptor_id, org) = host_ids(&hostname, agent.as_ref())?;
    let dump = flows::get_flows(&st.client, velociraptor_id.as_deref(), Some(&org)).await?;
    Ok(model_response(&dump))
}

/// `RetrieveFlowRequest.validate_session_id` (`mode="before"`) on the raw
/// body: `"session_id" in values and values["session_id"] == ""`.
fn retrieve_precheck(body: &JsonBody) -> Result<(), ApiError> {
    let crash = |e: &str| Err(ApiError::internal(e.to_string()));
    match body {
        JsonBody::Value(Value::Object(m)) => match m.get("session_id") {
            Some(Value::String(s)) if s.is_empty() => Err(ApiError::bad_request(
                "The session_id cannot be an empty string",
            )),
            _ => Ok(()),
        },
        JsonBody::Value(Value::Array(items)) => {
            if items.iter().any(|i| i.as_str() == Some("session_id")) {
                crash("list indices must be integers or slices, not str")
            } else {
                Ok(())
            }
        }
        JsonBody::Value(Value::String(s)) => {
            if s.contains("session_id") {
                crash("string indices must be integers, not 'str'")
            } else {
                Ok(())
            }
        }
        JsonBody::Value(Value::Number(_) | Value::Bool(_)) => {
            crash("argument of type is not iterable")
        }
        JsonBody::NotJson => crash("a bytes-like object is required, not 'str'"),
        JsonBody::Value(Value::Null) | JsonBody::Missing => Ok(()),
    }
}

async fn retrieve(
    State(st): State<VelociraptorState>,
    WithJson(auth, body): WithJson<Soc>,
) -> ApiResult {
    retrieve_precheck(&body)?;
    let (client_id, session_id) = body.model(|v, obj, at| {
        (
            v.req_str(obj, at, "client_id", StrRules::default()),
            v.req_str(obj, at, "session_id", StrRules::default()),
        )
    })?;
    tracing::info!("Fetching flow for flow_id {session_id}");
    let agent = agents::by_client_id(&st.ctx.db, &client_id).await?;
    auth.enforce_owned(
        &st.ctx,
        agent.as_ref().and_then(|a| a.customer_code.as_deref()),
        &format!("client {client_id}"),
    )
    .await?;
    let agent = agent.ok_or_else(|| {
        ApiError::not_found(format!("Agent with client id {client_id} not found"))
    })?;
    let org = agent.velociraptor_org.ok_or_else(|| {
        ApiError::not_found(format!(
            "Velociraptor ORG for hostname {client_id} is not available"
        ))
    })?;
    let dump = flows::get_flow(&st.client, &client_id, &session_id, Some(&org)).await?;
    Ok(model_response(&dump))
}
