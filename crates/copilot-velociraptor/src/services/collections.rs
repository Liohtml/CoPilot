//! The collections that store their result in MinIO —
//! `run_artifact_collection`, `run_file_collection` and
//! `fetch_file_from_filestore` of `services/artifacts.py`: start the flow,
//! wait for it, read its rows, then pull the flow's download pack out of the
//! Velociraptor filestore 1 MiB at a time (`base64encode(read_file(…))`),
//! upload it to `velociraptor-artifacts` and record it in `agent_datastore`.
//!
//! Python writes the pack to a temporary file in its working directory before
//! the upload; here the bytes stay in memory (a RUST_MIGRATION.md §4 row).

use chrono::NaiveDateTime;

use copilot_auth::pybase64::a2b_base64;
use copilot_auth::pyvalue::PyValue;
use copilot_db::{Db, DbError};
use copilot_objectstore::ObjectStore;
use copilot_objectstore::ops::upload_agent_artifact_file;
use copilot_upstream::model;
use copilot_upstream::py::{PyExc, PyResult};

use crate::VelociraptorClient;
use crate::agents;
use crate::client::Service;
use crate::schema::{COLLECT_ARTIFACT_RESPONSE, CollectArtifactBody, ParamValue};
use crate::validation::{
    validate_artifact_name, validate_client_id, validate_flow_id, validate_org_id,
};

/// The file-collection artifact.
pub const FILE_COLLECTOR: &str = "Generic.Collectors.File";

/// `fetch_file_from_filestore`'s chunk size.
const CHUNK: usize = 1024 * 1024;

/// `CollectFileBody` as `collect_file_by_agent_id` builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectFileBody {
    /// `hostname`.
    pub hostname: String,
    /// `velociraptor_id`.
    pub velociraptor_id: String,
    /// `velociraptor_org`.
    pub velociraptor_org: String,
    /// `file` (already formatted for the OS).
    pub file: String,
    /// `root_disk`.
    pub root_disk: String,
}

/// `format_file_path_for_os(file_path, os_prefix)`: `Glob\n<path>\n`, the
/// backslashes doubled on Windows. `None` is the `AttributeError` of
/// `None.lower()`.
pub fn format_file_path_for_os(file_path: &str, os_prefix: Option<&str>) -> PyResult<String> {
    let Some(prefix) = os_prefix else {
        return Err(PyExc::AttributeError(
            "'NoneType' object has no attribute 'lower'".into(),
        ));
    };
    tracing::info!("Formatting file path '{file_path}' for OS prefix '{prefix}'");
    let lower = prefix.to_lowercase();
    if lower == "windows" || lower == "windows." {
        return Ok(format!("Glob\n{}\n", file_path.replace('\\', "\\\\")));
    }
    Ok(format!("Glob\n{file_path}\n"))
}

/// `collect_client(...)`'s VQL for an artifact and its parameters.
pub fn artifact_query(
    org: &str,
    client_id: &str,
    artifact: &str,
    body: &CollectArtifactBody,
) -> String {
    let head = format!(
        "SELECT collect_client(org_id='{org}', client_id='{client_id}', artifacts=['{artifact}']"
    );
    let Some(parameters) = body.parameters.as_ref().filter(|p| !p.is_empty()) else {
        return format!("{head}) FROM scope()");
    };
    if let Some((_, ParamValue::Pairs(pairs))) = parameters.iter().find(|(k, _)| k == "env") {
        // `env_dict[item.key] = item.value`: a repeated key keeps its first
        // place and its last value.
        let mut env: Vec<(&str, &str)> = Vec::new();
        for (k, v) in pairs {
            match env.iter_mut().find(|(key, _)| key == k) {
                Some(slot) => slot.1 = v,
                None => env.push((k, v)),
            }
        }
        let parts: Vec<String> = env
            .iter()
            .map(|(k, v)| format!("`{k}`='{}'", v.replace('\'', "\\'")))
            .collect();
        return format!("{head}, env=dict({})) FROM scope()", parts.join(", "));
    }
    let mut query = head;
    for (k, v) in parameters {
        if let ParamValue::Str(v) = v {
            query.push_str(&format!(", `{k}`='{v}'"));
        }
    }
    query.push_str(") FROM scope()");
    query
}

/// The flow a `collect_client()` started: the first value of the first row
/// that is a dict holding `flow_id`.
fn flow_of(rows: &[PyValue]) -> PyResult<PyValue> {
    let Some(first) = rows.first() else {
        tracing::error!("No results returned from query execution");
        return Err(PyExc::http(
            500,
            "Query execution did not return any results",
        ));
    };
    let PyValue::Dict(items) = first else {
        return Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'items'",
            copilot_upstream::py::type_name(first)
        )));
    };
    let flow = items.iter().find_map(|(_, v)| match v {
        PyValue::Dict(inner) => inner
            .iter()
            .find(|(k, _)| k == "flow_id")
            .map(|(_, f)| f.clone()),
        _ => None,
    });
    match flow {
        Some(f) if f.truthy() => Ok(f),
        _ => {
            tracing::error!("Could not find flow_id in results: {}", first.py_repr());
            Err(PyExc::http(500, "Failed to extract flow ID from results"))
        }
    }
}

/// A flow id the validators accept (anything else is their 400).
fn flow_text(flow: &PyValue) -> PyResult<&str> {
    validate_flow_id(flow.as_str())
}

/// `{**dict}` of `fetch_file_from_filestore`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub struct FileData {
    /// The dict as Python returns it (`file_info`).
    pub dump: PyValue,
    /// `bucket_name` … `file_hash` of a successful upload.
    pub stored: Option<copilot_objectstore::ops::Uploaded>,
}

/// `fetch_file_from_filestore(client_id, flow_id, org_id, agent_id)`.
pub async fn fetch_file_from_filestore(
    client: &VelociraptorClient,
    store: &ObjectStore,
    client_id: Option<&str>,
    flow_id: &PyValue,
    org_id: Option<&str>,
    agent_id: &str,
) -> PyResult<FileData> {
    let client_id = validate_client_id(client_id)?;
    let flow_id = flow_text(flow_id)?;
    let service = client.service().await?;
    let run = async {
        tracing::info!("Fetching hostname for client {client_id}");
        let info = service
            .execute_query(
                &format!(
                    "SELECT os_info.hostname AS Hostname FROM clients(client_id='{client_id}')"
                ),
                org_id,
                None,
            )
            .await?;
        let hostname = match info.first() {
            Some(row) => match copilot_upstream::py::get(row, "Hostname")? {
                Some(h) => h.py_str(),
                None => client_id.to_string(),
            },
            None => {
                tracing::warn!("Could not fetch hostname, using client_id: {client_id}");
                client_id.to_string()
            }
        };
        tracing::info!("Creating flow download for client {client_id}, flow {flow_id}");
        let name = format!("{hostname}-{client_id}-{flow_id}");
        let zip = format!("{name}.zip");
        service
            .execute_query(
                &format!(
                    "SELECT create_flow_download(client_id='{client_id}', flow_id='{flow_id}', \
                     wait=true, format='json', expand_sparse=false, name='{name}') FROM scope()"
                ),
                org_id,
                None,
            )
            .await?;
        tracing::info!("Flow download created successfully");
        let vfs_path = format!("downloads/{client_id}/{flow_id}/{zip}");
        let data = read_pack(&service, &vfs_path, org_id).await?;
        if data.is_empty() {
            tracing::warn!("No file data found at path: {vfs_path}");
            return Ok(FileData {
                dump: PyValue::Dict(vec![
                    ("success".into(), PyValue::Bool(false)),
                    (
                        "message".into(),
                        PyValue::Str(format!("No file found at path: {vfs_path}")),
                    ),
                    ("file_path".into(), PyValue::None),
                    ("file_size".into(), PyValue::Int("0".into())),
                ]),
                stored: None,
            });
        }
        tracing::info!("Successfully fetched file of size {} bytes", data.len());
        let up = upload_agent_artifact_file(store, agent_id, flow_id, &data, &zip).await?;
        Ok(FileData {
            dump: PyValue::Dict(vec![
                ("success".into(), PyValue::Bool(true)),
                (
                    "message".into(),
                    PyValue::Str(
                        "Successfully fetched file from Velociraptor and uploaded to MinIO".into(),
                    ),
                ),
                ("bucket_name".into(), PyValue::Str(up.bucket_name.clone())),
                ("object_key".into(), PyValue::Str(up.object_key.clone())),
                ("file_name".into(), PyValue::Str(up.file_name.clone())),
                ("file_size".into(), PyValue::Int(up.file_size.to_string())),
                ("file_hash".into(), PyValue::Str(up.file_hash.clone())),
            ]),
            stored: Some(up),
        })
    };
    run.await.map_err(|e| match e {
        e @ PyExc::Http(..) => {
            tracing::error!("HTTPException while fetching file: {}", e.text());
            e
        }
        other => {
            tracing::error!("Failed to fetch file from filestore: {}", other.text());
            PyExc::http(
                500,
                format!("Failed to fetch file from filestore: {}", other.text()),
            )
        }
    })
}

/// The download pack, chunk by chunk, until a short or empty one (a chunk
/// that does not decode ends it, as Python's `except` does).
async fn read_pack(service: &Service, vfs_path: &str, org_id: Option<&str>) -> PyResult<Vec<u8>> {
    let mut data = Vec::new();
    loop {
        let rows = service
            .execute_query(
                &format!(
                    "SELECT base64encode(string=read_file(accessor='fs', filename='/{vfs_path}', \
                     offset={}, length={CHUNK})) AS Data FROM scope()",
                    data.len()
                ),
                org_id,
                None,
            )
            .await?;
        let Some(first) = rows.first() else {
            break;
        };
        let chunk = copilot_upstream::py::get(first, "Data")?
            .cloned()
            .unwrap_or(PyValue::None);
        if !chunk.truthy() {
            break;
        }
        // `base64.b64decode(data)`: ASCII text only, CPython's lenient rules.
        let decoded = match &chunk {
            PyValue::Str(s) if s.is_ascii() => a2b_base64(s.as_bytes()).ok(),
            _ => None,
        };
        let Some(decoded) = decoded else {
            tracing::error!("Failed to decode chunk");
            break;
        };
        if decoded.is_empty() {
            break;
        }
        let n = decoded.len();
        data.extend_from_slice(&decoded);
        if n < CHUNK {
            break;
        }
    }
    Ok(data)
}

/// The `AgentDataStore` row of an uploaded collection.
pub async fn insert_datastore_row(
    db: &Db,
    agent_id: &str,
    client_id: &str,
    artifact: &str,
    flow_id: &str,
    up: &copilot_objectstore::ops::Uploaded,
    collection_time: NaiveDateTime,
) -> Result<i64, DbError> {
    let res = sqlx::query(
        "INSERT INTO agent_datastore (agent_id, velociraptor_id, artifact_name, flow_id, \
         collection_time, bucket_name, object_key, file_name, content_type, file_size, file_hash, \
         uploaded_by, notes, status, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
         ?, ?)",
    )
    .bind(agent_id)
    .bind(client_id)
    .bind(artifact)
    .bind(flow_id)
    .bind(collection_time)
    .bind(&up.bucket_name)
    .bind(&up.object_key)
    .bind(&up.file_name)
    .bind("application/zip")
    .bind(up.file_size)
    .bind(&up.file_hash)
    .bind(None::<i32>)
    .bind(None::<String>)
    .bind("completed")
    .bind(None::<String>)
    .execute(db.pool())
    .await?;
    Ok(i64::try_from(res.last_insert_id()).unwrap_or_default())
}

/// `CollectArtifactResponse(...)`.
fn response(message: PyValue, results: PyValue, file: Option<&FileData>) -> PyResult<PyValue> {
    let file_info = match file {
        Some(f) if f.stored.is_some() => f.dump.clone(),
        _ => PyValue::None,
    };
    model::construct(
        &COLLECT_ARTIFACT_RESPONSE,
        &model::kwargs(vec![
            ("success", PyValue::Bool(true)),
            ("message", message),
            ("results", results),
            ("file_info", file_info),
        ]),
    )
}

/// `run_artifact_collection(body)`: the `CollectArtifactResponse` dump.
/// What the file upload raises is only logged, as in Python.
pub async fn run_artifact_collection(
    client: &VelociraptorClient,
    store: &ObjectStore,
    db: &Db,
    body: &CollectArtifactBody,
) -> PyResult<PyValue> {
    let org = validate_org_id(body.velociraptor_org.as_deref())?;
    let client_id = validate_client_id(body.velociraptor_id.as_deref())?;
    let artifact = validate_artifact_name(body.artifact_name.as_deref())?;
    let service = client.service().await?;
    let run = async {
        let agent = agents::collect_agent_by_client_id(db, client_id)
            .await
            .map_err(|e| PyExc::Other("Exception", e.to_string()))?
            .ok_or_else(|| {
                PyExc::http(
                    404,
                    format!("Agent with velociraptor_id {client_id} not found"),
                )
            })?;
        let query = artifact_query(org, client_id, artifact, body);
        tracing::info!("Running artifact collection with query: {query}");
        let rows = service.execute_query(&query, Some(org), None).await?;
        let flow = flow_of(&rows)?;
        tracing::info!("Extracted flow_id: {}", flow.py_str());
        let flow_id = flow_text(&flow)?;
        service
            .watch_flow_completion(flow_id, Some(org), None)
            .await?;
        let store_only = body.data_store_only == Some(true);
        let results = if store_only {
            None
        } else {
            Some(
                service
                    .read_collection_results(
                        Some(client_id),
                        Some(flow_id),
                        Some(org),
                        Some(artifact),
                    )
                    .await?,
            )
        };
        tracing::info!("Fetching collected file from filestore and uploading to MinIO");
        let file = match fetch_file_from_filestore(
            client,
            store,
            Some(client_id),
            &flow,
            Some(org),
            &agent.agent_id,
        )
        .await
        {
            Ok(file) => {
                if let Some(up) = &file.stored {
                    let saved = insert_datastore_row(
                        db,
                        &agent.agent_id,
                        client_id,
                        artifact,
                        flow_id,
                        up,
                        copilot_core::time::now_utc_micros(),
                    )
                    .await;
                    match saved {
                        Ok(id) => {
                            tracing::info!("Saved artifact metadata to database with ID {id}")
                        }
                        Err(e) => tracing::warn!(
                            "Failed to upload file to MinIO, but artifact collection succeeded: {e}"
                        ),
                    }
                }
                Some(file)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to upload file to MinIO, but artifact collection succeeded: {}",
                    e.display()
                );
                None
            }
        };
        if store_only {
            return response(
                PyValue::Str(
                    "Artifact collected and stored successfully. Results not retrieved.".into(),
                ),
                PyValue::None,
                file.as_ref(),
            );
        }
        response(
            PyValue::Str("Successfully executed query".into()),
            PyValue::List(results.unwrap_or_default()),
            file.as_ref(),
        )
    };
    run.await.map_err(|e| match e {
        e @ PyExc::Http(..) => {
            tracing::error!(
                "HTTPException while running artifact collection on {}: {}",
                body.py_str(),
                e.text()
            );
            e
        }
        other => {
            let text = format!(
                "Failed to run artifact collection on {}: {}",
                body.py_str(),
                other.text()
            );
            tracing::error!("{text}");
            PyExc::http(500, text)
        }
    })
}

/// `run_file_collection(body)`: the `CollectArtifactResponse` dump. Here
/// the upload's failures are the request's.
pub async fn run_file_collection(
    client: &VelociraptorClient,
    store: &ObjectStore,
    db: &Db,
    body: &CollectFileBody,
) -> PyResult<PyValue> {
    let org = validate_org_id(Some(&body.velociraptor_org))?;
    let client_id = validate_client_id(Some(&body.velociraptor_id))?;
    let artifact = validate_artifact_name(Some(FILE_COLLECTOR))?;
    let service = client.service().await?;
    let run = async {
        let agent = agents::collect_agent_by_client_id(db, client_id)
            .await
            .map_err(|e| PyExc::Other("Exception", e.to_string()))?
            .ok_or_else(|| {
                PyExc::http(
                    404,
                    format!("Agent with velociraptor_id {client_id} not found"),
                )
            })?;
        let query = format!(
            "SELECT collect_client(org_id='{org}', client_id='{client_id}', \
             artifacts=['{artifact}'], spec=dict(`{artifact}`=dict(`collectionSpec`='{}', \
             `Root`='{}'))) FROM scope()",
            body.file, body.root_disk
        );
        tracing::info!("Query: {query}");
        let rows = service.execute_query(&query, Some(org), None).await?;
        let flow = flow_of(&rows)?;
        tracing::info!("Extracted flow_id: {}", flow.py_str());
        let flow_id = flow_text(&flow)?;
        service
            .watch_flow_completion(flow_id, Some(org), None)
            .await?;
        let results = service
            .read_collection_results(Some(client_id), Some(flow_id), Some(org), Some(artifact))
            .await?;
        tracing::info!("Successfully read collection results");
        let file = fetch_file_from_filestore(
            client,
            store,
            Some(client_id),
            &flow,
            Some(org),
            &agent.agent_id,
        )
        .await?;
        if let Some(up) = &file.stored {
            let id = insert_datastore_row(
                db,
                &agent.agent_id,
                client_id,
                artifact,
                flow_id,
                up,
                copilot_core::time::now_utc_micros(),
            )
            .await
            .map_err(|e| PyExc::Other("Exception", e.to_string()))?;
            tracing::info!("Saved artifact metadata to database with ID {id}");
        }
        response(
            PyValue::Str("Successfully executed query".into()),
            PyValue::List(results),
            Some(&file),
        )
    };
    run.await.map_err(|e| match e {
        e @ PyExc::Http(..) => {
            tracing::error!(
                "HTTPException while running artifact collection: {}",
                e.text()
            );
            e
        }
        other => {
            tracing::error!("Failed to run artifact collection: {}", other.text());
            PyExc::http(
                500,
                format!("Failed to run artifact collection: {}", other.text()),
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(parameters: Option<Vec<(String, ParamValue)>>) -> CollectArtifactBody {
        CollectArtifactBody {
            hostname: "h".into(),
            velociraptor_id: Some("C.1".into()),
            velociraptor_org: Some("root".into()),
            artifact_name: Some("Windows.X".into()),
            parameters,
            data_store_only: Some(false),
        }
    }

    #[test]
    fn queries_are_pythons() {
        assert_eq!(
            artifact_query("root", "C.1", "Windows.X", &body(None)),
            "SELECT collect_client(org_id='root', client_id='C.1', artifacts=['Windows.X']) FROM scope()"
        );
        let env = body(Some(vec![(
            "env".into(),
            ParamValue::Pairs(vec![
                ("A".into(), "it's".into()),
                ("B".into(), "1".into()),
                ("A".into(), "2".into()),
            ]),
        )]));
        assert_eq!(
            artifact_query("root", "C.1", "Windows.X", &env),
            "SELECT collect_client(org_id='root', client_id='C.1', artifacts=['Windows.X'], \
             env=dict(`A`='2', `B`='1')) FROM scope()"
        );
        let direct = body(Some(vec![
            ("X".into(), ParamValue::Str("y".into())),
            ("L".into(), ParamValue::Pairs(vec![])),
        ]));
        assert_eq!(
            artifact_query("root", "C.1", "Windows.X", &direct),
            "SELECT collect_client(org_id='root', client_id='C.1', artifacts=['Windows.X'], `X`='y') FROM scope()"
        );
        assert_eq!(
            env.py_str(),
            "hostname='h' velociraptor_id='C.1' velociraptor_org='root' artifact_name='Windows.X' \
             parameters={'env': [ParameterKeyValue(key='A', value=\"it's\"), \
             ParameterKeyValue(key='B', value='1'), ParameterKeyValue(key='A', value='2')]} \
             data_store_only=False"
        );
    }

    #[test]
    fn file_paths_are_formatted_per_os() {
        assert_eq!(
            format_file_path_for_os("Users\\A\\x.txt", Some("Windows")).unwrap(),
            "Glob\nUsers\\\\A\\\\x.txt\n"
        );
        assert_eq!(
            format_file_path_for_os("/tmp/x", Some("Linux")).unwrap(),
            "Glob\n/tmp/x\n"
        );
        assert!(format_file_path_for_os("/tmp/x", None).is_err());
    }

    #[test]
    fn the_flow_is_the_first_dict_naming_one() {
        let rows = vec![PyValue::Dict(vec![
            ("x".into(), PyValue::Int("1".into())),
            (
                "collect_client(...)".into(),
                PyValue::Dict(vec![("flow_id".into(), PyValue::Str("F.ABC".into()))]),
            ),
        ])];
        assert_eq!(flow_of(&rows).unwrap(), PyValue::Str("F.ABC".into()));
        assert_eq!(
            flow_of(&[]).unwrap_err(),
            PyExc::http(500, "Query execution did not return any results")
        );
        assert_eq!(
            flow_of(&[PyValue::Dict(vec![])]).unwrap_err(),
            PyExc::http(500, "Failed to extract flow ID from results")
        );
    }
}
