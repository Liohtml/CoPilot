//! `app/connectors/velociraptor/services/artifacts.py` (what the ported
//! routes call): the artifact definitions, one artifact and its parameters,
//! a remote command and a quarantine.
//!
//! The artifact collections that store their files in MinIO
//! (`run_artifact_collection`, `run_file_collection`) are
//! [`super::collections`].

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model;
use copilot_upstream::py::{PyExc, PyResult, getitem};

use crate::client::{ROOT, Service, VelociraptorClient};
use crate::schema::{
    ARTIFACTS, ARTIFACTS_QUALNAME, QUARANTINE_RESPONSE, QuarantineBody, RUN_COMMAND_RESPONSE,
    RunCommandBody,
};
use crate::validation::{validate_artifact_name, validate_client_id, validate_org_id};

/// `DEFAULT_LINUX_QUARANTINE_ARTIFACT`.
pub const DEFAULT_LINUX_QUARANTINE_ARTIFACT: &str = "Linux.Remediation.Quarantine";
/// `DEFAULT_WINDOWS_QUARANTINE_ARTIFACT`.
pub const DEFAULT_WINDOWS_QUARANTINE_ARTIFACT: &str = "Windows.Remediation.Quarantine";

/// `resolve_quarantine_artifact(name)` (#913): a built-in quarantine
/// artifact replaced by `VELOCIRAPTOR_{LINUX,WINDOWS}_QUARANTINE_ARTIFACT`
/// when set; anything else unchanged (`None` is `"None"`, `str(None)`).
pub fn resolve_quarantine_artifact(name: Option<&str>) -> String {
    let name = name.unwrap_or("None");
    let configured = |var: &str, default: &str| {
        std::env::var(var)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| default.to_string())
    };
    match name {
        DEFAULT_LINUX_QUARANTINE_ARTIFACT => configured(
            "VELOCIRAPTOR_LINUX_QUARANTINE_ARTIFACT",
            DEFAULT_LINUX_QUARANTINE_ARTIFACT,
        ),
        DEFAULT_WINDOWS_QUARANTINE_ARTIFACT => configured(
            "VELOCIRAPTOR_WINDOWS_QUARANTINE_ARTIFACT",
            DEFAULT_WINDOWS_QUARANTINE_ARTIFACT,
        ),
        other => other.to_string(),
    }
}

/// `OSPrefixModel(os_name=…).get_os_prefix()`: the first keyword the name
/// contains, in the mapping's order.
pub fn os_prefix_of(os_name: &str) -> Option<&'static str> {
    let lower = os_name.to_lowercase();
    [
        ("windows", "Windows"),
        ("linux", "Linux"),
        ("mac", "MacOS"),
        ("ubuntu", "Linux"),
    ]
    .into_iter()
    .find(|(keyword, _)| lower.contains(keyword))
    .map(|(_, prefix)| prefix)
}

/// `verify_os_prefix_exists(os_prefix)`: `OSPrefixEnum`'s value.
pub fn verify_os_prefix(os_prefix: &str) -> PyResult<&'static str> {
    match os_prefix.to_lowercase().as_str() {
        "linux" => Ok("Linux."),
        "windows" => Ok("Windows."),
        "macos" => Ok("MacOS."),
        _ => Err(PyExc::http(
            400,
            format!("OS prefix {os_prefix} does not exist."),
        )),
    }
}

/// `[Artifacts(**row) for row in rows]`.
fn artifacts_of(rows: &[PyValue]) -> PyResult<Vec<PyValue>> {
    rows.iter()
        .map(|row| model::construct_star(&ARTIFACTS, ARTIFACTS_QUALNAME, row))
        .collect()
}

/// `get_artifacts()`: every artifact definition.
pub async fn get_artifacts(client: &VelociraptorClient) -> PyResult<Vec<PyValue>> {
    tracing::info!("Fetching artifacts from Velociraptor");
    let service = client.service().await?;
    let rows = service
        .execute_query(
            "SELECT name,description,parameters FROM artifact_definitions()",
            ROOT,
            None,
        )
        .await?;
    artifacts_of(&rows).map_err(|e| {
        tracing::error!("Failed to get all artifacts: {}", e.display());
        PyExc::http(500, format!("Failed to get all artifacts: {}", e.display()))
    })
}

/// `ArtifactsResponse(...)`'s dump.
pub fn artifacts_response(message: String, artifacts: Vec<PyValue>) -> PyValue {
    PyValue::Dict(vec![
        ("message".into(), PyValue::Str(message)),
        ("artifacts".into(), PyValue::List(artifacts)),
        ("success".into(), PyValue::Bool(true)),
    ])
}

/// `get_artifact_by_name(name)`: the message and the artifacts.
pub async fn get_artifact_by_name(
    client: &VelociraptorClient,
    name: &str,
) -> PyResult<(String, Vec<PyValue>)> {
    tracing::info!("Fetching artifact '{name}' from Velociraptor");
    validate_artifact_name(Some(name))?;
    let service = client.service().await?;
    let vql = format!(
        "SELECT name,description,parameters FROM artifact_definitions() WHERE name = '{name}'"
    );
    let rows = service.execute_query(&vql, ROOT, None).await?;
    if rows.is_empty() {
        return Ok((format!("Artifact '{name}' not found"), Vec::new()));
    }
    match artifacts_of(&rows) {
        Ok(artifacts) => Ok((
            format!("Artifact '{name}' retrieved successfully"),
            artifacts,
        )),
        Err(e) => {
            tracing::error!("Failed to get artifact '{name}': {}", e.display());
            Err(PyExc::http(
                500,
                format!("Failed to get artifact '{name}': {}", e.display()),
            ))
        }
    }
}

/// `get_artifact_parameters_by_prefix_service(name, prefix)`: the
/// `ArtifactParametersResponse` dump.
pub async fn parameters_by_prefix(
    client: &VelociraptorClient,
    name: &str,
    prefix: &str,
) -> PyResult<PyValue> {
    tracing::info!("Fetching parameters with prefix '{prefix}' from artifact '{name}'");
    let response = |success: bool, message: String, matching: Vec<PyValue>| {
        let total = matching.len();
        PyValue::Dict(vec![
            ("success".into(), PyValue::Bool(success)),
            ("message".into(), PyValue::Str(message)),
            ("artifact_name".into(), PyValue::Str(name.into())),
            ("parameter_prefix".into(), PyValue::Str(prefix.into())),
            ("matching_parameters".into(), PyValue::List(matching)),
            ("total_matches".into(), PyValue::Int(total.to_string())),
        ])
    };
    let (_, artifacts) = get_artifact_by_name(client, name).await.map_err(|e| {
        let text = format!(
            "Failed to get parameters with prefix '{prefix}' from artifact '{name}': {}",
            e.display()
        );
        tracing::error!("{text}");
        PyExc::http(500, text)
    })?;
    let Some(artifact) = artifacts.first() else {
        return Ok(response(
            false,
            format!("Artifact '{name}' not found"),
            Vec::new(),
        ));
    };
    let mut matching: Vec<PyValue> = match model::field(artifact, "parameters") {
        PyValue::List(params) => params
            .iter()
            .filter(|p| {
                model::field(p, "name")
                    .as_str()
                    .is_some_and(|n| n.starts_with(prefix))
            })
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    matching.sort_by(|a, b| {
        let key = |p: &PyValue| {
            model::field(p, "name")
                .as_str()
                .unwrap_or_default()
                .to_string()
        };
        key(a).cmp(&key(b))
    });
    let message = match matching.len() {
        0 => format!("No parameters found matching prefix '{prefix}' in artifact '{name}'"),
        1 => format!("Found 1 parameter matching prefix '{prefix}' in artifact '{name}'"),
        n => format!("Found {n} parameters matching prefix '{prefix}' in artifact '{name}'"),
    };
    tracing::info!("{message}");
    Ok(response(true, message, matching))
}

/// The flow a `collect_client()` started: `rows[0][key]["flow_id"]`.
fn flow_id_of(rows: &[PyValue], key: &str) -> PyResult<PyValue> {
    let first = rows
        .first()
        .ok_or_else(|| PyExc::IndexError("list index out of range".into()))?;
    Ok(getitem(getitem(first, key)?, "flow_id")?.clone())
}

/// Wait for the flow, then read its results (`watch_flow_completion_async`,
/// `read_collection_results_async`).
async fn finish_flow(
    service: &Service,
    flow_id: &PyValue,
    client_id: Option<&str>,
    org: Option<&str>,
    artifact: Option<&str>,
) -> PyResult<Vec<PyValue>> {
    tracing::info!("Extracted flow_id: {}", flow_id.py_str());
    let Some(flow) = flow_id.as_str() else {
        return Err(PyExc::http(400, "Invalid Velociraptor flow id"));
    };
    service.watch_flow_completion(flow, org, None).await?;
    service
        .read_collection_results(client_id, Some(flow), org, artifact)
        .await
}

/// `BaseResponse(success=results["success"], message=…, results=…)`.
fn base_response(m: &'static model::Model, rows: Vec<PyValue>) -> PyResult<PyValue> {
    model::construct(
        m,
        &model::kwargs(vec![
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("Successfully executed query".into()),
            ),
            ("results", PyValue::List(rows)),
        ]),
    )
}

/// `run_remote_command(body)`: the `RunCommandResponse` dump.
pub async fn run_remote_command(
    client: &VelociraptorClient,
    body: &RunCommandBody,
) -> PyResult<PyValue> {
    let service = client.service().await?;
    let wrap = |e: PyExc| {
        let text = format!(
            "Failed to run artifact collection on {}: {}",
            body.py_str(),
            e.display()
        );
        tracing::error!("{text}");
        PyExc::http(500, text)
    };
    let run = async {
        let org = validate_org_id(body.velociraptor_org.as_deref())?;
        let client_id = validate_client_id(body.velociraptor_id.as_deref())?;
        let artifact = body.artifact_name.as_deref().unwrap_or("None");
        let command = body.command.as_deref().unwrap_or("None");
        tracing::info!("Running remote command on {}", body.py_str());
        let vql = format!(
            "SELECT collect_client(org_id='{org}', client_id='{client_id}', urgent=true, \
             artifacts=['{artifact}'], env=dict(Command='{command}')) FROM scope()"
        );
        let rows = service.execute_query(&vql, Some(org), None).await?;
        // `get_artifact_key(run_command_body)`.
        let key = if body.command.is_some() {
            format!(
                "collect_client(org_id='{org}', client_id='{client_id}', urgent=true, \
                 artifacts=['{artifact}'], env=dict(Command='{command}'))"
            )
        } else {
            format!(
                "collect_client(org_id='{org}', client_id='{client_id}', artifacts=['{artifact}'])"
            )
        };
        let flow_id = flow_id_of(&rows, &key)?;
        let results = finish_flow(
            &service,
            &flow_id,
            Some(client_id),
            Some(org),
            body.artifact_name.as_deref(),
        )
        .await?;
        base_response(&RUN_COMMAND_RESPONSE, results)
    };
    run.await.map_err(wrap)
}

/// `quarantine_host(body)`: the `QuarantineResponse` dump. `body` holds the
/// artifact the route resolved; it is resolved once more, as in Python.
pub async fn quarantine_host(
    client: &VelociraptorClient,
    body: &QuarantineBody,
) -> PyResult<PyValue> {
    let service = client.service().await?;
    let body = QuarantineBody {
        artifact_name: Some(resolve_quarantine_artifact(body.artifact_name.as_deref())),
        ..body.clone()
    };
    let wrap = |e: PyExc| {
        let text = format!(
            "Failed to run artifact collection on {}: {}",
            body.py_str(),
            e.display()
        );
        tracing::error!("{text}");
        PyExc::http(500, text)
    };
    let run = async {
        let org = validate_org_id(body.velociraptor_org.as_deref())?;
        let client_id = validate_client_id(body.velociraptor_id.as_deref())?;
        let artifact = validate_artifact_name(body.artifact_name.as_deref())?;
        let spec = if body.action == "quarantine" {
            format!("spec=dict(`{artifact}`=dict()))")
        } else {
            format!("spec=dict(`{artifact}`=dict(`RemovePolicy`=\"Y\")))")
        };
        let call = format!(
            "collect_client(org_id=\"{org}\", client_id=\"{client_id}\", artifacts=[\"{artifact}\"], {spec}"
        );
        let rows = service
            .execute_query(&format!("SELECT {call} FROM scope()"), Some(org), None)
            .await?;
        // `get_artifact_key(quarantine_body)`: the same call.
        let flow_id = flow_id_of(&rows, &call)?;
        let results = finish_flow(
            &service,
            &flow_id,
            Some(client_id),
            Some(org),
            Some(artifact),
        )
        .await?;
        base_response(&QUARANTINE_RESPONSE, results)
    };
    run.await.map_err(wrap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_names_map_to_prefixes() {
        assert_eq!(os_prefix_of("ubuntu 22.04"), Some("Linux"));
        assert_eq!(os_prefix_of("Microsoft Windows 11"), Some("Windows"));
        assert_eq!(os_prefix_of("macOS"), Some("MacOS"));
        assert_eq!(os_prefix_of("Debian"), None);
        assert_eq!(verify_os_prefix("MacOS"), Ok("MacOS."));
        assert_eq!(
            verify_os_prefix("solaris"),
            Err(PyExc::http(400, "OS prefix solaris does not exist."))
        );
        assert_eq!(resolve_quarantine_artifact(None), "None");
        assert_eq!(resolve_quarantine_artifact(Some("Custom.X")), "Custom.X");
    }
}
