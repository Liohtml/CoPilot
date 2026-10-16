//! `run_artifact_collection` (`app/connectors/velociraptor/services/
//! artifacts.py`) as the CoPilot Action invoke calls it, with
//! `fetch_file_from_filestore` and `upload_agent_artifact_file`: one
//! collection with an `env` dict, the wait for its flow, its results, then
//! its download pack copied into MinIO (`velociraptor-artifacts`) and an
//! `agent_datastore` row — that last part best-effort, as in Python.
//!
//! The VQL is Python's, character for character; every query goes through
//! `copilot-velociraptor`'s client. What fails is what Python raises: the
//! identifier validators' 400s before anything is sent, an `HTTPException`
//! passed through, anything else the 500 `Failed to run artifact collection
//! on {str(body)}: {e}`.

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_db::Db;
use copilot_objectstore::ObjectStore;
use copilot_objectstore::ops;
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::{PyExc, type_name};
use copilot_velociraptor::validation::{
    validate_artifact_name, validate_client_id, validate_flow_id, validate_org_id,
};
use copilot_velociraptor::{Service, VelociraptorClient};

use crate::copilot_action::schema::COLLECT_ARTIFACT_RESPONSE;

/// The bucket of the collections.
pub const ARTIFACTS_BUCKET: &str = ops::ARTIFACTS_BUCKET;
/// `chunk_size`.
const CHUNK: usize = 1024 * 1024;

/// `CollectArtifactBody` as the invoke builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectBody {
    /// `hostname`.
    pub hostname: String,
    /// `velociraptor_id`.
    pub velociraptor_id: Option<String>,
    /// `velociraptor_org`.
    pub velociraptor_org: Option<String>,
    /// `artifact_name`.
    pub artifact_name: String,
    /// `parameters["env"]`: `ParameterKeyValue`s in order.
    pub env: Vec<(String, String)>,
}

fn opt_repr(v: Option<&str>) -> String {
    v.map_or_else(|| "None".to_string(), str_repr)
}

impl CollectBody {
    /// `str(body)`: Pydantic's `field=repr(value)` pairs.
    pub fn py_str(&self) -> String {
        let env: Vec<String> = self
            .env
            .iter()
            .map(|(k, v)| {
                format!(
                    "ParameterKeyValue(key={}, value={})",
                    str_repr(k),
                    str_repr(v)
                )
            })
            .collect();
        format!(
            "hostname={} velociraptor_id={} velociraptor_org={} artifact_name={} \
             parameters={{'env': [{}]}} data_store_only=False",
            str_repr(&self.hostname),
            opt_repr(self.velociraptor_id.as_deref()),
            opt_repr(self.velociraptor_org.as_deref()),
            str_repr(&self.artifact_name),
            env.join(", ")
        )
    }

    /// The `env=dict(…)` query (`env_dict[item.key] = item.value`: the
    /// first position of a key, its last value; `'` escaped as `\'`).
    fn query(&self, org: &str, client_id: &str) -> String {
        let mut env: Vec<(String, String)> = Vec::new();
        for (k, v) in &self.env {
            match env.iter_mut().find(|(ek, _)| ek == k) {
                Some(slot) => slot.1 = v.clone(),
                None => env.push((k.clone(), v.clone())),
            }
        }
        let parts: Vec<String> = env
            .iter()
            .map(|(k, v)| format!("`{k}`='{}'", v.replace('\'', "\\'")))
            .collect();
        format!(
            "SELECT collect_client(org_id='{org}', client_id='{client_id}', artifacts=['{}'], \
             env=dict({})) FROM scope()",
            self.artifact_name,
            parts.join(", ")
        )
    }
}

/// `select(Agents).where(Agents.velociraptor_id == id)`, `.first()`'s
/// `agent_id`.
async fn agent_id_for(db: &Db, velociraptor_id: &str) -> Result<Option<String>, PyExc> {
    copilot_agents::db::first(
        db,
        &[copilot_agents::db::Cond::VelociraptorId(velociraptor_id)],
        &copilot_agents::db::Tenancy::All,
    )
    .await
    .map(|a| a.map(|a| a.agent_id))
    .map_err(|e| PyExc::Other("OperationalError", e.to_string()))
}

/// `value.items()` of the first result: the first dict holding `flow_id`.
fn flow_id_of(rows: &[PyValue]) -> Result<PyValue, PyExc> {
    let first = rows
        .first()
        .ok_or_else(|| PyExc::http(500, "Query execution did not return any results"))?;
    let PyValue::Dict(items) = first else {
        return Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'items'",
            type_name(first)
        )));
    };
    for (_, value) in items {
        if let PyValue::Dict(inner) = value {
            if let Some((_, id)) = inner.iter().find(|(k, _)| k == "flow_id") {
                return Ok(id.clone());
            }
        }
    }
    Ok(PyValue::None)
}

/// `run_artifact_collection(body, session)`: the `CollectArtifactResponse`
/// dump.
pub async fn run_artifact_collection(
    client: &VelociraptorClient,
    db: &Db,
    store: &ObjectStore,
    body: &CollectBody,
) -> Result<PyValue, PyExc> {
    let org = validate_org_id(body.velociraptor_org.as_deref())?.to_string();
    let client_id = validate_client_id(body.velociraptor_id.as_deref())?.to_string();
    validate_artifact_name(Some(&body.artifact_name))?;
    let service = client.service().await?;
    let wrap = |e: PyExc| match e {
        e @ PyExc::Http(..) => e,
        e => {
            let text = format!(
                "Failed to run artifact collection on {}: {}",
                body.py_str(),
                e.display()
            );
            tracing::error!("{text}");
            PyExc::http(500, text)
        }
    };
    let run = async {
        let agent_id = agent_id_for(db, &client_id).await?.ok_or_else(|| {
            PyExc::http(
                404,
                format!("Agent with velociraptor_id {client_id} not found"),
            )
        })?;
        let query = body.query(&org, &client_id);
        tracing::info!("Running artifact collection with query: {query}");
        let rows = service.execute_query(&query, Some(&org), None).await?;
        let flow_id = flow_id_of(&rows)?;
        if !flow_id.truthy() {
            return Err(PyExc::http(500, "Failed to extract flow ID from results"));
        }
        let PyValue::Str(flow_id) = flow_id else {
            // `validate_flow_id` of something that is not a `str`.
            return Err(PyExc::http(400, "Invalid Velociraptor flow id"));
        };
        service
            .watch_flow_completion(&flow_id, Some(&org), None)
            .await?;
        let results = service
            .read_collection_results(
                Some(&client_id),
                Some(&flow_id),
                Some(&org),
                Some(&body.artifact_name),
            )
            .await?;
        let file = FileRef {
            client_id: &client_id,
            flow_id: &flow_id,
            org: &org,
            agent_id: &agent_id,
        };
        // `file_data = await fetch_file_from_filestore(…)`, then the row: a
        // failure of either is logged, and `file_info` is whatever
        // `file_data` holds by then.
        let file_info = match fetch_file_from_filestore(client, store, &file).await {
            Ok(Some((info, uploaded))) => {
                if let Err(e) = save_row(db, &file, &body.artifact_name, &uploaded).await {
                    tracing::warn!(
                        "Failed to upload file to MinIO, but artifact collection succeeded: {}",
                        e.display()
                    );
                }
                Some(info)
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    "Failed to upload file to MinIO, but artifact collection succeeded: {}",
                    e.display()
                );
                None
            }
        };
        construct(
            &COLLECT_ARTIFACT_RESPONSE,
            &kwargs(vec![
                ("success", PyValue::Bool(true)),
                (
                    "message",
                    PyValue::Str("Successfully executed query".into()),
                ),
                ("results", PyValue::List(results)),
                ("file_info", file_info.unwrap_or(PyValue::None)),
            ]),
        )
    };
    run.await.map_err(wrap)
}

struct FileRef<'a> {
    client_id: &'a str,
    flow_id: &'a str,
    org: &'a str,
    agent_id: &'a str,
}

/// `results[0].get(key)` on a query's answer: `Ok(None)` without a row,
/// `Ok(Some(None))` for a row without the key.
fn first_get(rows: &[PyValue], key: &str) -> Result<Option<Option<PyValue>>, PyExc> {
    match rows.first() {
        None => Ok(None),
        Some(PyValue::Dict(items)) => Ok(Some(
            items.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()),
        )),
        Some(other) => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'get'",
            type_name(other)
        ))),
    }
}

/// `fetch_file_from_filestore(...)`: `Ok(Some((file_data, upload)))` when a
/// file was stored, `Ok(None)` for the `success: False` answer of an empty
/// pack; `Err` is what it raises (the caller swallows it).
async fn fetch_file_from_filestore(
    client: &VelociraptorClient,
    store: &ObjectStore,
    f: &FileRef<'_>,
) -> Result<Option<(PyValue, ops::Uploaded)>, PyExc> {
    validate_client_id(Some(f.client_id))?;
    validate_flow_id(Some(f.flow_id))?;
    let service: Service = client.service().await?;
    let (client_id, flow_id, org) = (f.client_id, f.flow_id, f.org);
    let fetched = async {
        tracing::info!("Fetching hostname for client {client_id}");
        let info = service
            .execute_query(
                &format!(
                    "SELECT os_info.hostname AS Hostname FROM clients(client_id='{client_id}')"
                ),
                Some(org),
                None,
            )
            .await?;
        // `results[0].get("Hostname", client_id)`, formatted by an f-string.
        let hostname = match first_get(&info, "Hostname")? {
            None | Some(None) => client_id.to_string(),
            Some(Some(PyValue::Str(s))) => s,
            Some(Some(other)) => other.py_str(),
        };
        let name = format!("{hostname}-{client_id}-{flow_id}");
        let zip = format!("{name}.zip");
        service
            .execute_query(
                &format!(
                    "SELECT create_flow_download(client_id='{client_id}', flow_id='{flow_id}', \
                     wait=true, format='json', expand_sparse=false, name='{name}') FROM scope()"
                ),
                Some(org),
                None,
            )
            .await?;
        let vfs_path = format!("downloads/{client_id}/{flow_id}/{zip}");
        // `open(os.path.join(os.getcwd(), zip_filename), "wb")`: a name with a
        // directory in it (or a NUL) cannot be opened there.
        if zip.contains('/') || zip.contains('\0') {
            return Err(PyExc::Other(
                "FileNotFoundError",
                format!("[Errno 2] No such file or directory: {}", str_repr(&zip)),
            ));
        }
        let mut data: Vec<u8> = Vec::new();
        loop {
            let rows = service
                .execute_query(
                    &format!(
                        "SELECT base64encode(string=read_file(accessor='fs', filename='/{vfs_path}', \
                         offset={}, length={CHUNK})) AS Data FROM scope()",
                        data.len()
                    ),
                    Some(org),
                    None,
                )
                .await?;
            let chunk = match first_get(&rows, "Data")? {
                None | Some(None) => break,
                Some(Some(v)) if !v.truthy() => break,
                // `base64.b64decode` of an ASCII `str`; anything else is its
                // error, caught by the loop.
                Some(Some(PyValue::Str(s))) if s.is_ascii() => s,
                Some(Some(_)) => break,
            };
            let Ok(decoded) = copilot_auth::pybase64::a2b_base64(chunk.as_bytes()) else {
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
        if data.is_empty() {
            tracing::warn!("No file data found at path: {vfs_path}");
            return Ok(None);
        }
        let object_key = format!("{}/{flow_id}/{zip}", f.agent_id);
        let uploaded = ops::upload_file_to_datastore(
            store,
            &zip,
            Some("application/zip"),
            &data,
            ARTIFACTS_BUCKET,
            &object_key,
        )
        .await?;
        Ok(Some(uploaded))
    };
    let uploaded = fetched.await.map_err(|e| match e {
        e @ PyExc::Http(..) => e,
        e => PyExc::http(
            500,
            format!("Failed to fetch file from filestore: {}", e.display()),
        ),
    })?;
    Ok(uploaded.map(|u| {
        let info = PyValue::Dict(vec![
            ("success".into(), PyValue::Bool(true)),
            (
                "message".into(),
                PyValue::Str(
                    "Successfully fetched file from Velociraptor and uploaded to MinIO".into(),
                ),
            ),
            ("bucket_name".into(), PyValue::Str(u.bucket_name.clone())),
            ("object_key".into(), PyValue::Str(u.object_key.clone())),
            ("file_name".into(), PyValue::Str(u.file_name.clone())),
            ("file_size".into(), PyValue::Int(u.file_size.to_string())),
            ("file_hash".into(), PyValue::Str(u.file_hash.clone())),
        ]);
        (info, u)
    }))
}

/// The `AgentDataStore` row of a stored file, committed.
async fn save_row(
    db: &Db,
    f: &FileRef<'_>,
    artifact_name: &str,
    u: &ops::Uploaded,
) -> Result<(), PyExc> {
    sqlx::query(
        "INSERT INTO agent_datastore (notes, error_message, agent_id, velociraptor_id, \
         artifact_name, flow_id, collection_time, bucket_name, object_key, file_name, \
         content_type, file_size, file_hash, uploaded_by, status) VALUES (NULL, NULL, ?, ?, ?, \
         ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'completed')",
    )
    .bind(f.agent_id)
    .bind(f.client_id)
    .bind(artifact_name)
    .bind(f.flow_id)
    .bind(chrono::Utc::now().naive_utc())
    .bind(&u.bucket_name)
    .bind(&u.object_key)
    .bind(&u.file_name)
    .bind("application/zip")
    .bind(u.file_size)
    .bind(&u.file_hash)
    .execute(db.pool())
    .await
    .map(|_| ())
    .map_err(|e| PyExc::Other("IntegrityError", e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_reads_like_pydantic() {
        let body = CollectBody {
            hostname: "WIN-1".into(),
            velociraptor_id: Some("C.1a".into()),
            velociraptor_org: None,
            artifact_name: "Windows.Execute.RemotePowerShellScript".into(),
            env: vec![
                ("ScriptURL".into(), "https://x/a.ps1".into()),
                ("Arg1".into(), "it's".into()),
                ("Arg1".into(), "again".into()),
            ],
        };
        assert_eq!(
            body.py_str(),
            "hostname='WIN-1' velociraptor_id='C.1a' velociraptor_org=None \
             artifact_name='Windows.Execute.RemotePowerShellScript' parameters={'env': \
             [ParameterKeyValue(key='ScriptURL', value='https://x/a.ps1'), \
             ParameterKeyValue(key='Arg1', value=\"it's\"), ParameterKeyValue(key='Arg1', \
             value='again')]} data_store_only=False"
        );
        assert_eq!(
            body.query("root", "C.1a"),
            "SELECT collect_client(org_id='root', client_id='C.1a', \
             artifacts=['Windows.Execute.RemotePowerShellScript'], \
             env=dict(`ScriptURL`='https://x/a.ps1', `Arg1`='again')) FROM scope()"
        );
    }
}
