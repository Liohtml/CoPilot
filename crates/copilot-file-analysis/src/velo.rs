//! `services/velociraptor_fetch.py`: collecting a file from an endpoint
//! through the Velociraptor connector (`copilot-velociraptor`'s
//! `UniversalService` port — the same gRPC request, deadlines and failure
//! texts) and reading its bytes back.
//!
//! The VQL is Python's, character for character: the OS from `clients()`,
//! the OS's `*.Search.FileFinder` (`Upload_File=Y` to collect, `N` to only
//! list matches), `uploads(client_id, flow_id)` polled every 3 s until the
//! collection's file appears, then `read_file(filename, accessor)` for each
//! candidate path (`file_store`, …, `vfs_path`, … × `fs`, `collector`) of
//! every upload row (up to `FILE_ANALYSIS_MAX_FLOW_FILES`), the file name
//! from `upload_name`, …, `client_path`. The bytes stay in memory: Python's
//! scratch file (written, read back and deleted) is not reproduced, nor the
//! scratch files of the rows after the first, which Python leaves behind.
//!
//! One difference by design (§4): a client id that is not a Velociraptor id
//! (`copilot_velociraptor::validation::validate_client_id`) and a hostname
//! holding a quote are refused before any VQL is built — Python interpolated
//! them into the query unescaped.

use std::time::{Duration, Instant};

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::py::{PyExc, PyResult};
use copilot_velociraptor::client::{ROOT, Service};
use copilot_velociraptor::config::ApiConfig;
use num_traits::ToPrimitive as _;
use sha2::{Digest, Sha256};

use crate::FileAnalysisState;
use crate::py::{self, dict, empty_dict, get, int_setting, int_value, is_dict, or, str_of};

/// A collected file.
#[derive(Debug, Clone)]
pub struct LocalFile {
    /// The bytes.
    pub data: Vec<u8>,
    /// Their SHA-256 (hex).
    pub sha256: String,
    /// `_upload_name(row)`.
    pub original_filename: String,
}

/// `VelociraptorFetchError(text)`.
fn fetch_error(text: impl Into<String>) -> PyExc {
    PyExc::Other("VelociraptorFetchError", text.into())
}

/// `_local_api_config()`: the first of `VELOCIRAPTOR_API_CONFIG`, the
/// backend's `data/api.config.yaml` and `./data/api.config.yaml` that is a
/// file.
fn local_api_config(st: &FileAnalysisState) -> Option<String> {
    let mut candidates = vec![st.settings.velociraptor_api_config.clone()];
    candidates.push(
        st.backend_data_dir
            .join("api.config.yaml")
            .to_string_lossy()
            .into_owned(),
    );
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(
            cwd.join("data")
                .join("api.config.yaml")
                .to_string_lossy()
                .into_owned(),
        );
    }
    candidates
        .into_iter()
        .find(|c| !c.is_empty() && std::path::Path::new(c).is_file())
}

/// `_service()`: the connector's service, else the local config's.
async fn service(st: &FileAnalysisState) -> PyResult<Service> {
    match st.velociraptor.service().await {
        Ok(svc) => Ok(svc),
        Err(e) => {
            let Some(local) = local_api_config(st) else {
                return Err(fetch_error(format!(
                    "could not connect to Velociraptor connector: {}",
                    e.display()
                )));
            };
            let path = local.clone();
            match tokio::task::spawn_blocking(move || ApiConfig::load(Some(&path))).await {
                Ok(Ok(cfg)) => {
                    tracing::warn!(
                        "Velociraptor connector config unusable ({}); using local config {local}",
                        e.display()
                    );
                    Ok(Service::from_config(cfg, st.velociraptor.timeouts()))
                }
                Ok(Err(e2)) => Err(fetch_error(format!(
                    "Velociraptor connect failed (connector + local fallback {local}): {}",
                    e2.display()
                ))),
                Err(e2) => Err(fetch_error(e2.to_string())),
            }
        }
    }
}

async fn query(svc: &Service, vql: &str) -> PyResult<Vec<PyValue>> {
    svc.execute_query(vql, ROOT, None).await
}

/// `str.replace("'", "''")` of a value that should be a `str`.
fn quote_escape(value: &PyValue) -> PyResult<String> {
    match value {
        PyValue::Str(s) => Ok(s.replace('\'', "''")),
        other => Err(PyExc::AttributeError(format!(
            "'{}' object has no attribute 'replace'",
            copilot_upstream::py::type_name(other)
        ))),
    }
}

/// `resolve_client_id(hostname)`: the most recently seen client of that
/// host (`None` when the query fails or finds none).
pub async fn resolve_client_id(st: &FileAnalysisState, hostname: &str) -> PyResult<PyValue> {
    let svc = service(st).await?;
    copilot_velociraptor::validation::validate_hostname(Some(hostname))?;
    let vql = format!(
        "SELECT client_id, last_seen_at FROM clients(search='host:{hostname}') ORDER BY last_seen_at DESC"
    );
    let rows = match query(&svc, &vql).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("resolve_client_id failed for {hostname:?}: {}", e.text());
            return Ok(PyValue::None);
        }
    };
    match rows.first() {
        Some(row) => Ok(copilot_upstream::py::getitem(row, "client_id")?.clone()),
        None => Ok(PyValue::None),
    }
}

/// `_ONLINE_WINDOW_US`.
const ONLINE_WINDOW_US: f64 = 15.0 * 60.0 * 1_000_000.0;

/// `is_online(last_seen_us)`.
pub fn is_online(last_seen_us: i128) -> bool {
    if last_seen_us == 0 {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    (now * 1_000_000.0 - last_seen_us as f64) < ONLINE_WINDOW_US
}

/// `bare_client_id(velociraptor_id)`.
pub fn bare_client_id(velociraptor_id: &str) -> &str {
    velociraptor_id.split('-').next().unwrap_or(velociraptor_id)
}

/// `live_last_seen_map()`: `client_id → last_seen_at` for the `str` ids.
pub async fn live_last_seen_map(st: &FileAnalysisState) -> PyResult<Vec<(String, i128)>> {
    let svc = service(st).await?;
    let rows = match query(&svc, "SELECT client_id, last_seen_at FROM clients()").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("live_last_seen_map failed: {}", e.text());
            return Ok(Vec::new());
        }
    };
    let mut out: Vec<(String, i128)> = Vec::new();
    for r in rows {
        let id = get(&r, "client_id")?;
        if !id.truthy() {
            continue;
        }
        let seen = int_value(&or(get(&r, "last_seen_at")?, py::int(0)))?;
        let seen = seen.to_i128().unwrap_or(i128::MAX);
        if let PyValue::Str(id) = id {
            match out.iter_mut().find(|(k, _)| *k == id) {
                Some(slot) => slot.1 = seen,
                None => out.push((id, seen)),
            }
        }
    }
    Ok(out)
}

/// `_client_os(svc, client_id)`.
async fn client_os(svc: &Service, client_id: &PyValue) -> PyResult<String> {
    let safe = quote_escape(client_id)?;
    let vql = format!("SELECT os_info.system AS os FROM clients() WHERE client_id='{safe}'");
    let rows = match query(svc, &vql).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("_client_os failed for {}: {}", str_of(client_id), e.text());
            return Ok(String::new());
        }
    };
    match rows.first() {
        None => Ok(String::new()),
        Some(row) => py::lower_of(&get(row, "os")?),
    }
}

/// `_finder_artifact(os_name)`.
pub fn finder_artifact(os_name: &str) -> &'static str {
    match os_name {
        "windows" => "Windows.Search.FileFinder",
        "darwin" => "MacOS.Search.FileFinder",
        _ => "Linux.Search.FileFinder",
    }
}

/// `_finder_vql(client_id, os_name, target_path, upload)`.
pub fn finder_vql(client_id: &str, os_name: &str, target_path: &str, upload: bool) -> String {
    let artifact = finder_artifact(os_name);
    let up = if upload { "Y" } else { "N" };
    let env = if os_name == "windows" {
        let glob = target_path.replace('`', "");
        format!(
            "dict(SearchFilesGlobTable=`Glob\n{glob}\n`, Upload_File='{up}', Calculate_Hash='Y')"
        )
    } else {
        let safe = target_path.replace('\'', "''");
        format!("dict(SearchFilesGlob='{safe}', Upload_File='{up}', Calculate_Hash='Y')")
    };
    format!(
        "SELECT collect_client(client_id='{client_id}', artifacts=['{artifact}'], env={env}) AS Flow FROM scope()"
    )
}

/// `_extract_flow_id(rows)`.
fn extract_flow_id(rows: &[PyValue]) -> PyResult<PyValue> {
    for row in rows {
        let flow = get(row, "Flow")?;
        if is_dict(&flow) {
            return Ok(or(
                get_or_empty(&flow, "flow_id")?,
                get_or_empty(&flow, "FlowId")?,
            ));
        }
        if let PyValue::Str(s) = &flow {
            if s.starts_with("F.") {
                return Ok(flow);
            }
        }
    }
    Ok(py::s(""))
}

fn get_or_empty(v: &PyValue, key: &str) -> PyResult<PyValue> {
    py::get_or(v, key, py::s(""))
}

/// `rows[:cap]` with Python's negative-index rule.
fn py_head<T: Clone>(items: &[T], cap: i64) -> Vec<T> {
    let len = i64::try_from(items.len()).unwrap_or(i64::MAX);
    let end = if cap < 0 {
        (len + cap).max(0)
    } else {
        cap.min(len)
    };
    items[..usize::try_from(end).unwrap_or(0)].to_vec()
}

/// `_wait_for_flow(svc, client_id, flow_id, timeout)`.
async fn wait_for_flow(
    svc: &Service,
    client_id: &PyValue,
    flow_id: &str,
    timeout: i64,
) -> PyResult<()> {
    let safe = quote_escape(client_id)?;
    let deadline = Instant::now() + Duration::from_secs(u64::try_from(timeout).unwrap_or(0));
    let vql = format!("SELECT * FROM uploads(client_id='{safe}', flow_id='{flow_id}')");
    while Instant::now() < deadline {
        match query(svc, &vql).await {
            Ok(rows) if !rows.is_empty() => {
                tracing::info!("[velo] flow {flow_id} has {} upload(s); ready", rows.len());
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("[velo] upload poll error ({flow_id}): {}", e.text()),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    tracing::warn!("[velo] flow {flow_id} produced no upload within {timeout}s");
    Ok(())
}

const PATH_COLUMNS: &[&str] = &[
    "file_store",
    "_FileStore",
    "FileStore",
    "vfs_path",
    "_Path",
    "Path",
    "OSPath",
];
const READ_ACCESSORS: &[&str] = &["fs", "collector"];
const NAME_COLUMNS: &[&str] = &[
    "upload_name",
    "Name",
    "client_path",
    "vfs_path",
    "_Components",
];

/// `_upload_name(row)`.
fn upload_name(row: &PyValue) -> PyResult<String> {
    for key in NAME_COLUMNS {
        let mut val = get(row, key)?;
        if let PyValue::List(items) = &val {
            if let Some(last) = items.last() {
                val = last.clone();
            }
        }
        if let PyValue::Str(text) = &val {
            if !text.is_empty() {
                let normalised = text.replace('\\', "/");
                let base = py::basename(normalised.trim_end_matches('/'));
                if !base.is_empty() {
                    return Ok(base.to_string());
                }
            }
        }
    }
    Ok("sample".into())
}

/// `_candidate_paths(row)`.
fn candidate_paths(row: &PyValue) -> PyResult<Vec<String>> {
    let mut paths = Vec::new();
    for key in PATH_COLUMNS {
        match get(row, key)? {
            PyValue::List(items) if !items.is_empty() => paths.push(str_of(&items[0])),
            PyValue::Str(text) if !text.is_empty() => paths.push(text),
            _ => {}
        }
    }
    Ok(paths)
}

/// `bytes(data)` for what `read_file` returned (a `str` is encoded as
/// latin-1 with `?` for what does not fit).
fn data_bytes(data: &PyValue) -> PyResult<Vec<u8>> {
    match data {
        PyValue::Str(text) => Ok(py::latin1_replace(text)),
        PyValue::Bool(b) => Ok(vec![0; usize::from(*b)]),
        PyValue::Int(i) => {
            let n: i64 = i.parse().map_err(|_| {
                PyExc::Other(
                    "OverflowError",
                    "cannot fit 'int' into an index-sized integer".into(),
                )
            })?;
            if n < 0 {
                return Err(PyExc::ValueError("negative count".into()));
            }
            let n = usize::try_from(n).unwrap_or(usize::MAX);
            if n > 512 * 1024 * 1024 {
                return Err(PyExc::Other("MemoryError", String::new()));
            }
            Ok(vec![0; n])
        }
        PyValue::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let n = match item {
                    PyValue::Int(i) => i.parse::<i64>().ok(),
                    PyValue::Bool(b) => Some(i64::from(*b)),
                    _ => {
                        return Err(PyExc::TypeError(format!(
                            "'{}' object cannot be interpreted as an integer",
                            copilot_upstream::py::type_name(item)
                        )));
                    }
                };
                match n.and_then(|n| u8::try_from(n).ok()) {
                    Some(b) => out.push(b),
                    None => return Err(PyExc::ValueError("bytes must be in range(0, 256)".into())),
                }
            }
            Ok(out)
        }
        PyValue::Dict(items) => {
            let keys = PyValue::List(items.iter().map(|(k, _)| py::s(k.clone())).collect());
            data_bytes(&keys)
        }
        other => Err(PyExc::TypeError(format!(
            "cannot convert '{}' object to bytes",
            copilot_upstream::py::type_name(other)
        ))),
    }
}

/// `_download_one(svc, row, flow_id)`.
async fn download_one(svc: &Service, row: &PyValue) -> PyResult<Option<LocalFile>> {
    let name = upload_name(row)?;
    let mut data = PyValue::None;
    for path in candidate_paths(row)? {
        let safe = path.replace('\'', "''");
        for accessor in READ_ACCESSORS {
            let vql = format!(
                "SELECT read_file(filename='{safe}', accessor='{accessor}') AS Data FROM scope()"
            );
            match query(svc, &vql).await {
                Ok(out) => {
                    if let Some(first) = out.first() {
                        match get(first, "Data") {
                            Ok(d) if d.truthy() => {
                                data = d;
                                break;
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!(
                                "[velo] read_file({accessor}, {path}) failed: {}",
                                e.text()
                            ),
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("[velo] read_file({accessor}, {path}) failed: {}", e.text())
                }
            }
        }
        if data.truthy() {
            break;
        }
    }
    if !data.truthy() {
        tracing::warn!("[velo] no bytes for upload '{name}'");
        return Ok(None);
    }
    let raw = data_bytes(&data)?;
    let sha256 = hex::encode(Sha256::digest(&raw));
    Ok(Some(LocalFile {
        data: raw,
        sha256,
        original_filename: name,
    }))
}

/// `fetch_from_flow(client_id, flow_id)`: every upload of the flow (up to
/// the cap), each read back.
async fn fetch_from_flow(
    st: &FileAnalysisState,
    client_id: &PyValue,
    flow_id: &str,
) -> PyResult<Vec<LocalFile>> {
    let cap = int_setting(&st.settings.max_flow_files)?;
    let svc = service(st).await?;
    let vql = format!(
        "SELECT * FROM uploads(client_id='{}', flow_id='{flow_id}')",
        str_of(client_id)
    );
    let rows = query(&svc, &vql)
        .await
        .map_err(|e| fetch_error(format!("failed to read flow uploads: {}", e.display())))?;
    tracing::info!(
        "[velo] uploads() returned {} row(s) for flow {flow_id}",
        rows.len()
    );
    let mut results = Vec::new();
    for row in py_head(&rows, cap) {
        if let Some(local) = download_one(&svc, &row).await? {
            results.push(local);
        }
    }
    if i64::try_from(rows.len()).unwrap_or(i64::MAX) > cap {
        tracing::warn!(
            "flow {flow_id} had {} uploads; truncated to {cap}",
            rows.len()
        );
    }
    Ok(results)
}

/// `collect_and_fetch(client_id, target_path, customer_code)`: `None` when
/// the file is gone.
pub async fn collect_and_fetch(
    st: &FileAnalysisState,
    client_id: &PyValue,
    target_path: &str,
) -> PyResult<Option<LocalFile>> {
    let svc = service(st).await?;
    let os_name = client_os(&svc, client_id).await?;
    let id = str_of(client_id);
    copilot_velociraptor::validation::validate_client_id(Some(&id))?;
    let vql = finder_vql(&id, &os_name, target_path, true);
    tracing::info!("[velo] collecting {target_path:?} from {id} (os={os_name})");
    let rows = query(&svc, &vql)
        .await
        .map_err(|e| fetch_error(format!("collect_client failed: {}", e.display())))?;
    let flow_id = extract_flow_id(&rows)?;
    if !flow_id.truthy() {
        return Err(fetch_error("collect_client returned no flow id"));
    }
    let flow_id = str_of(&flow_id);
    let timeout = int_setting(&st.settings.collect_timeout)?;
    wait_for_flow(&svc, client_id, &flow_id, timeout).await?;
    let mut files = fetch_from_flow(st, client_id, &flow_id).await?;
    if files.is_empty() {
        tracing::info!(
            "collect_and_fetch: no file recovered for {target_path} (deleted or not found)"
        );
        return Ok(None);
    }
    Ok(Some(files.remove(0)))
}

/// `_match_from_source_row(row)`.
fn match_from_source_row(row: &PyValue) -> PyResult<Option<PyValue>> {
    let path = or(
        or(
            or(get(row, "OSPath")?, get(row, "_FullPath")?),
            get(row, "FullPath")?,
        ),
        get(row, "Path")?,
    );
    let PyValue::Str(path) = path else {
        return Ok(None);
    };
    if path.is_empty() {
        return Ok(None);
    }
    let hashes = or(get(row, "Hash")?, empty_dict());
    let sha256 = if is_dict(&hashes) {
        get(&hashes, "SHA256")?
    } else {
        PyValue::None
    };
    let normalised = path.replace('\\', "/");
    let base = py::basename(normalised.trim_end_matches('/'));
    let name = if base.is_empty() {
        path.clone()
    } else {
        base.to_string()
    };
    let size = int_value(&or(get(row, "Size")?, py::int(0)))?;
    Ok(Some(dict(vec![
        ("path", py::s(path)),
        ("name", py::s(name)),
        ("size", PyValue::Int(size.to_string())),
        ("sha256", or(sha256, py::s(""))),
    ])))
}

/// `enumerate_matches(client_id, target_path)`.
pub async fn enumerate_matches(
    st: &FileAnalysisState,
    client_id: &str,
    target_path: &str,
) -> PyResult<Vec<PyValue>> {
    let svc = service(st).await?;
    let id = py::s(client_id);
    let os_name = client_os(&svc, &id).await?;
    copilot_velociraptor::validation::validate_client_id(Some(client_id))?;
    let vql = finder_vql(client_id, &os_name, target_path, false);
    tracing::info!("[velo] enumerating {target_path:?} on {client_id} (os={os_name})");
    let rows = query(&svc, &vql)
        .await
        .map_err(|e| fetch_error(format!("enumerate collect_client failed: {}", e.display())))?;
    let flow_id = extract_flow_id(&rows)?;
    if !flow_id.truthy() {
        return Err(fetch_error("enumerate returned no flow id"));
    }
    let flow_id = str_of(&flow_id);
    let cap = int_setting(&st.settings.max_flow_files)?;
    let timeout = int_setting(&st.settings.enum_timeout)?;
    let safe = client_id.replace('\'', "''");
    let artifact = finder_artifact(&os_name);
    let vql = format!(
        "SELECT * FROM source(client_id='{safe}', flow_id='{flow_id}', artifact='{artifact}')"
    );
    let deadline = Instant::now() + Duration::from_secs(u64::try_from(timeout).unwrap_or(0));
    let mut rows = Vec::new();
    while Instant::now() < deadline {
        match query(&svc, &vql).await {
            Ok(found) if !found.is_empty() => {
                rows = found;
                break;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("[velo] source poll error ({flow_id}): {}", e.text()),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let mut matches = Vec::new();
    for r in &rows {
        if let Some(m) = match_from_source_row(r)? {
            matches.push(m);
        }
    }
    tracing::info!(
        "[velo] enumerate matched {} file(s) for {target_path:?}",
        matches.len()
    );
    Ok(py_head(&matches, cap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn vql_is_pythons() {
        assert_eq!(
            finder_vql("C.1", "linux", "/tmp/o'k", true),
            "SELECT collect_client(client_id='C.1', artifacts=['Linux.Search.FileFinder'], \
             env=dict(SearchFilesGlob='/tmp/o''k', Upload_File='Y', Calculate_Hash='Y')) AS Flow FROM scope()"
        );
        assert_eq!(
            finder_vql("C.1", "windows", "C:\\a`b", false),
            "SELECT collect_client(client_id='C.1', artifacts=['Windows.Search.FileFinder'], \
             env=dict(SearchFilesGlobTable=`Glob\nC:\\ab\n`, Upload_File='N', Calculate_Hash='Y')) AS Flow FROM scope()"
        );
        assert_eq!(finder_artifact("darwin"), "MacOS.Search.FileFinder");
        assert_eq!(bare_client_id("C.475d-OL680"), "C.475d");
    }

    #[test]
    fn upload_rows_read_like_python() {
        let row =
            loads(r#"{"vfs_path": "/clients/C.1/x", "client_path": "C:\\Users\\a\\evil.ps1"}"#)
                .unwrap();
        assert_eq!(upload_name(&row).unwrap(), "evil.ps1");
        assert_eq!(candidate_paths(&row).unwrap(), ["/clients/C.1/x"]);
        assert_eq!(upload_name(&loads("{}").unwrap()).unwrap(), "sample");
        assert_eq!(data_bytes(&py::s("aé€")).unwrap(), b"a\xe9?");
        assert_eq!(py_head(&[1, 2, 3], -1), vec![1, 2]);
        assert_eq!(py_head(&[1, 2, 3], 5), vec![1, 2, 3]);
    }
}
