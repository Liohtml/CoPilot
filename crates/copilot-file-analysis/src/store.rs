//! `services/state_store.py`: File Analysis keeps everything in MinIO —
//! bucket `FILE_ANALYSIS_MINIO_BUCKET` (`file-analysis`), created on first
//! use — under the keys Python writes, as the JSON it writes
//! (`json.dumps(obj, ensure_ascii=False)`), so a job either backend wrote is
//! the other's to read:
//!
//! - `jobs/{job_id}.json` — the job
//! - `{customer_code}/{sha256}/result.json` — the merged result (the cache)
//! - `{customer_code}/{sha256}/summary.json` — its history row
//! - `{customer_code}/{sha256}/previews/{name}` — the PNG previews
//!
//! Every operation is miniopy-async's (`copilot-objectstore`, a fresh client
//! each time as `create_session()` gives one) inside `_retry`: a transient
//! connection failure is retried `FILE_ANALYSIS_MINIO_RETRIES` times with
//! `FILE_ANALYSIS_MINIO_BACKOFF · 2^attempt` seconds between, an S3 error
//! never. "The bucket exists" is remembered per process, as Python's
//! `_bucket_ready` is (a bucket deleted behind a running process is not
//! re-created by either).

use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use copilot_auth::pyvalue::{PyValue, loads};
use copilot_objectstore::client::SESSION_AS_OFFSET_RANGE;
use copilot_objectstore::{Minio, MinioError};
use copilot_upstream::json::{Dumps, py_dumps_allow_nan};
use copilot_upstream::py::{PyExc, PyResult};
use futures::StreamExt as _;

use crate::FileAnalysisState;
use crate::py::{self, dict, get, get_or, str_of};

/// `ENGINE_VERSION`: a cached result of another engine is analysed again.
pub const ENGINE_VERSION: i64 = 15;

const HISTORY_SCAN_CAP: usize = 250;
const HISTORY_CONCURRENCY: usize = 24;

/// The aiohttp errors `_TRANSIENT_ERRORS` catches, by the class names
/// `copilot-objectstore` gives them.
fn transient(e: &MinioError) -> bool {
    matches!(
        e,
        MinioError::Py(PyExc::Other(
            "ClientError"
                | "ClientConnectorError"
                | "ClientConnectorDNSError"
                | "ClientConnectorCertificateError"
                | "ClientOSError"
                | "ServerDisconnectedError"
                | "SocketTimeoutError"
                | "ClientPayloadError",
            _
        ))
    )
}

fn exc(e: MinioError) -> PyExc {
    e.into_py()
}

/// `_retry(what, op)`: `None` when `FILE_ANALYSIS_MINIO_RETRIES` is not
/// positive (the loop never runs, as in Python).
async fn retry<T, F, Fut>(
    st: &FileAnalysisState,
    what: &str,
    op: F,
) -> Result<Option<T>, MinioError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, MinioError>>,
{
    let attempts = st.settings.minio_retries;
    let mut attempt: i64 = 0;
    while attempt < attempts {
        match op().await {
            Ok(v) => return Ok(Some(v)),
            Err(e) if transient(&e) => {
                if attempt + 1 >= attempts {
                    tracing::error!(
                        "MinIO {what} failed after {attempts} attempts: {}",
                        e.clone().into_py().text()
                    );
                    return Err(e);
                }
                let delay =
                    st.settings.minio_backoff * 2f64.powi(i32::try_from(attempt).unwrap_or(30));
                tracing::warn!(
                    "MinIO {what} transient error (attempt {}/{attempts}): {}; retrying in {delay:.1}s",
                    attempt + 1,
                    e.clone().into_py().text()
                );
                tokio::time::sleep(Duration::from_secs_f64(delay.max(0.0))).await;
            }
            Err(e) => return Err(e),
        }
        attempt += 1;
    }
    Ok(None)
}

fn session(st: &FileAnalysisState) -> Result<Minio, MinioError> {
    st.objects.session().map_err(MinioError::Py)
}

/// `ensure_bucket()`.
pub async fn ensure_bucket(st: &FileAnalysisState) -> PyResult<()> {
    if st.bucket_ready.load(Ordering::SeqCst) {
        return Ok(());
    }
    let bucket = st.settings.bucket.clone();
    retry(st, "ensure_bucket", || {
        let bucket = bucket.clone();
        async move {
            let client = session(st)?;
            if !client.bucket_exists(&bucket).await? {
                client.make_bucket(&bucket).await?;
                tracing::info!("Created MinIO bucket {bucket}");
            }
            Ok(())
        }
    })
    .await
    .map_err(exc)?;
    st.bucket_ready.store(true, Ordering::SeqCst);
    Ok(())
}

/// `json.dumps(obj, ensure_ascii=False).encode()`.
pub fn dumps(obj: &PyValue) -> Vec<u8> {
    py_dumps_allow_nan(
        obj,
        Dumps {
            ensure_ascii: false,
            compact: false,
        },
    )
    .into_bytes()
}

async fn put(st: &FileAnalysisState, key: &str, data: Vec<u8>, content_type: &str) -> PyResult<()> {
    ensure_bucket(st).await?;
    let bucket = st.settings.bucket.clone();
    retry(st, &format!("put {key}"), || {
        let (bucket, data) = (bucket.clone(), data.clone());
        async move {
            let client = session(st)?;
            client
                .fput_object(&bucket, key, &data, Some(content_type))
                .await
        }
    })
    .await
    .map_err(exc)?;
    Ok(())
}

/// `put_json(key, obj)`.
pub async fn put_json(st: &FileAnalysisState, key: &str, obj: &PyValue) -> PyResult<()> {
    put(st, key, dumps(obj), "application/json").await
}

/// `get_bytes(key)` / `get_json`'s read: `stat_object`, then `get_object`
/// (with the session as its offset); `None` for any failure.
async fn read(st: &FileAnalysisState, key: &str) -> PyResult<Option<Bytes>> {
    ensure_bucket(st).await?;
    let bucket = st.settings.bucket.clone();
    let got = retry(st, &format!("get {key}"), || {
        let bucket = bucket.clone();
        async move {
            let client = session(st)?;
            client.stat_object(&bucket, key).await?;
            client
                .get_object(&bucket, key, Some(SESSION_AS_OFFSET_RANGE))
                .await
        }
    })
    .await;
    Ok(got.ok().flatten())
}

/// `json.loads(data.decode("utf-8"))`, raising what Python raises.
fn decode(data: &[u8]) -> PyResult<PyValue> {
    let text = copilot_objectstore::error::utf8(data)?;
    loads(&text).map_err(|_| {
        PyExc::JsonDecode(
            copilot_upstream::json::decode_error(&text)
                .unwrap_or_else(|| "Expecting value: line 1 column 1 (char 0)".into()),
        )
    })
}

/// `get_json(key)`.
pub async fn get_json(st: &FileAnalysisState, key: &str) -> PyResult<Option<PyValue>> {
    match read(st, key).await? {
        None => Ok(None),
        Some(data) => decode(&data).map(Some),
    }
}

/// `put_bytes(key, data, content_type)`.
pub async fn put_bytes(
    st: &FileAnalysisState,
    key: &str,
    data: Vec<u8>,
    content_type: &str,
) -> PyResult<()> {
    put(st, key, data, content_type).await
}

/// `get_bytes(key)`.
pub async fn get_bytes(st: &FileAnalysisState, key: &str) -> PyResult<Option<Bytes>> {
    read(st, key).await
}

/// `list_prefix(prefix)`: `[]` on any failure.
pub async fn list_prefix(st: &FileAnalysisState, prefix: &str) -> PyResult<Vec<String>> {
    ensure_bucket(st).await?;
    let bucket = st.settings.bucket.clone();
    let listed = retry(st, &format!("list_prefix {prefix}"), || {
        let bucket = bucket.clone();
        async move {
            let client = session(st)?;
            let objects = client.list_objects(&bucket, Some(prefix), true).await?;
            Ok(objects
                .into_iter()
                .map(|o| o.object_name)
                .filter(|n| !n.is_empty())
                .collect::<Vec<_>>())
        }
    })
    .await;
    Ok(listed.ok().flatten().unwrap_or_default())
}

/// `_job_key(job_id)`.
pub fn job_key(job_id: &str) -> String {
    format!("jobs/{job_id}.json")
}

fn result_key(customer_code: &str, sha256: &str) -> String {
    format!("{customer_code}/{sha256}/result.json")
}

fn summary_key(customer_code: &str, sha256: &str) -> String {
    format!("{customer_code}/{sha256}/summary.json")
}

fn preview_key(customer_code: &str, sha256: &str, name: &str) -> String {
    format!("{customer_code}/{sha256}/previews/{name}")
}

/// `_history_item(result)`.
pub fn history_item(result: &PyValue) -> PyResult<PyValue> {
    let job = py::or(get(result, "job")?, py::empty_dict());
    let insp = py::or(get(result, "inspector")?, py::empty_dict());
    let rep = py::or(get(result, "reputation")?, py::empty_dict());
    let found = get(&rep, "found")?.truthy();
    let filename = py::or(
        py::or(get(&job, "filename")?, get(&insp, "filename")?),
        py::s(""),
    );
    let sha256 = py::or(
        py::or(get(&job, "sha256")?, get(&insp, "sha256")?),
        py::s(""),
    );
    Ok(dict(vec![
        ("job_id", get_or(&job, "job_id", py::s(""))?),
        ("filename", filename),
        ("sha256", sha256),
        ("verdict", get(&job, "verdict")?),
        ("source", get_or(&job, "source", py::s(""))?),
        ("status", get_or(&job, "status", py::s(""))?),
        (
            "hardened",
            PyValue::Bool(get_or(&job, "hardened", PyValue::Bool(true))?.truthy()),
        ),
        ("created_at", get_or(&job, "created_at", py::s(""))?),
        ("updated_at", get_or(&job, "updated_at", py::s(""))?),
        (
            "vt_malicious",
            if found {
                get(&rep, "malicious")?
            } else {
                PyValue::None
            },
        ),
        (
            "vt_total",
            if found {
                get(&rep, "total")?
            } else {
                PyValue::None
            },
        ),
    ]))
}

/// `save_job(job)`.
pub async fn save_job(st: &FileAnalysisState, job: &PyValue) -> PyResult<()> {
    let id = copilot_upstream::py::getitem(job, "job_id")?;
    put_json(st, &job_key(&str_of(id)), job).await
}

/// `load_job(job_id)`.
pub async fn load_job(st: &FileAnalysisState, job_id: &str) -> PyResult<Option<PyValue>> {
    get_json(st, &job_key(job_id)).await
}

/// `save_result(customer_code, sha256, result)`: the result, then its
/// history row (whose failure is only logged).
pub async fn save_result(
    st: &FileAnalysisState,
    customer_code: &str,
    sha256: &str,
    result: &PyValue,
) -> PyResult<()> {
    put_json(st, &result_key(customer_code, sha256), result).await?;
    let summary = history_item(result);
    let written = match summary {
        Ok(item) => put_json(st, &summary_key(customer_code, sha256), &item).await,
        Err(e) => Err(e),
    };
    if let Err(e) = written {
        tracing::warn!(
            "summary write failed for {}: {}",
            sha256.chars().take(12).collect::<String>(),
            e.text()
        );
    }
    Ok(())
}

/// `delete_analysis(customer_code, sha256, job_id)`: the number of keys
/// removed (a missing object counts, as MinIO answers its delete).
pub async fn delete_analysis(
    st: &FileAnalysisState,
    customer_code: &str,
    sha256: &str,
    job_id: Option<&str>,
) -> PyResult<i64> {
    let mut keys = vec![
        result_key(customer_code, sha256),
        summary_key(customer_code, sha256),
    ];
    keys.extend(list_prefix(st, &format!("{customer_code}/{sha256}/previews/")).await?);
    if let Some(id) = job_id.filter(|j| !j.is_empty()) {
        keys.push(job_key(id));
    }
    let bucket = st.settings.bucket.clone();
    let removed = retry(
        st,
        &format!(
            "delete_analysis {}",
            sha256.chars().take(12).collect::<String>()
        ),
        || {
            let (bucket, keys) = (bucket.clone(), keys.clone());
            async move {
                let client = session(st)?;
                let mut removed = 0i64;
                for key in &keys {
                    if client.remove_object(&bucket, key).await.is_ok() {
                        removed += 1;
                    }
                }
                Ok(removed)
            }
        },
    )
    .await
    .map_err(exc)?;
    Ok(removed.unwrap_or(0))
}

/// `load_result(customer_code, sha256)`.
pub async fn load_result(
    st: &FileAnalysisState,
    customer_code: &str,
    sha256: &str,
) -> PyResult<Option<PyValue>> {
    get_json(st, &result_key(customer_code, sha256)).await
}

/// `find_cached_job_id(customer_code, sha256)`: a complete result of this
/// engine's version.
pub async fn find_cached_job_id(
    st: &FileAnalysisState,
    customer_code: &str,
    sha256: &str,
) -> PyResult<Option<PyValue>> {
    let Some(result) = load_result(st, customer_code, sha256).await? else {
        return Ok(None);
    };
    if !result.truthy() {
        return Ok(None);
    }
    let inspector = get_or(&result, "inspector", py::empty_dict())?;
    if get(&inspector, "analysis_incomplete")?.truthy() {
        return Ok(None);
    }
    if !copilot_upstream::py::py_eq(&get(&result, "engine_version")?, &py::int(ENGINE_VERSION)) {
        return Ok(None);
    }
    let job = get_or(&result, "job", py::empty_dict())?;
    let id = get(&job, "job_id")?;
    if id.truthy() {
        return Ok(Some(id));
    }
    Ok(None)
}

/// `_read_json_batch(keys)`: one client, every key read without `stat`, 24
/// at a time; a missing or unreadable object is `None`.
async fn read_json_batch(
    st: &FileAnalysisState,
    keys: &[String],
) -> PyResult<Vec<Option<PyValue>>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    ensure_bucket(st).await?;
    let client = std::sync::Arc::new(session(st).map_err(exc)?);
    let bucket: std::sync::Arc<str> = st.settings.bucket.as_str().into();
    let results: Vec<Option<PyValue>> = futures::stream::iter(keys.to_vec())
        .map(move |key: String| {
            let client = client.clone();
            let bucket = bucket.clone();
            async move {
                let data = client
                    .get_object(&bucket, &key, Some(SESSION_AS_OFFSET_RANGE))
                    .await
                    .ok()?;
                decode(&data).ok()
            }
        })
        .buffered(HISTORY_CONCURRENCY)
        .collect()
        .await;
    Ok(results)
}

/// `list_history(customer_code, limit)`: newest first. Summaries are read
/// in listing order (Python's `set` gives the strings' hash order; equal
/// `created_at` values come back in that order, §4).
pub async fn list_history(
    st: &FileAnalysisState,
    customer_code: &str,
    limit: i64,
) -> PyResult<Vec<PyValue>> {
    let names = list_prefix(st, &format!("{customer_code}/")).await?;
    let mut have_summary: Vec<String> = Vec::new();
    let mut result_shas: Vec<String> = Vec::new();
    for name in &names {
        let parts: Vec<&str> = name.split('/').collect();
        if parts.len() < 3 {
            continue;
        }
        let sha = parts[1].to_string();
        if name.ends_with("/summary.json") {
            if !have_summary.contains(&sha) {
                have_summary.push(sha);
            }
        } else if name.ends_with("/result.json") && !result_shas.contains(&sha) {
            result_shas.push(sha);
        }
    }
    let mut fast: Vec<(String, String, bool)> = have_summary
        .iter()
        .map(|sha| (sha.clone(), summary_key(customer_code, sha), true))
        .collect();
    for sha in &result_shas {
        if !have_summary.contains(sha) {
            fast.push((sha.clone(), result_key(customer_code, sha), false));
        }
    }
    fast.truncate(HISTORY_SCAN_CAP);
    let keys: Vec<String> = fast.iter().map(|(_, k, _)| k.clone()).collect();
    let blobs = read_json_batch(st, &keys).await?;

    let mut items: Vec<PyValue> = Vec::new();
    let mut backfill: Vec<(String, PyValue)> = Vec::new();
    for ((sha, _, is_summary), blob) in fast.into_iter().zip(blobs) {
        let Some(blob) = blob.filter(PyValue::truthy) else {
            continue;
        };
        if is_summary {
            items.push(blob);
        } else {
            let item = history_item(&blob)?;
            backfill.push((sha, item.clone()));
            items.push(item);
        }
    }
    for (sha, item) in &backfill {
        let _ = put_json(st, &summary_key(customer_code, sha), item).await;
    }
    let mut keyed = Vec::with_capacity(items.len());
    for item in items {
        let created = py::or(get(&item, "created_at")?, py::s(""));
        keyed.push((created, item));
    }
    sort_desc(&mut keyed)?;
    let len = i64::try_from(keyed.len()).unwrap_or(i64::MAX);
    let end = if limit < 0 {
        (len + limit).max(0)
    } else {
        limit.min(len)
    };
    Ok(keyed
        .into_iter()
        .take(usize::try_from(end).unwrap_or(0))
        .map(|(_, item)| item)
        .collect())
}

/// `items.sort(key=..., reverse=True)` on `created_at` strings (a mix of
/// types is Python's `TypeError`).
fn sort_desc(items: &mut [(PyValue, PyValue)]) -> PyResult<()> {
    let mut bad = None;
    for (key, _) in items.iter() {
        if !matches!(key, PyValue::Str(_)) {
            bad = Some(copilot_upstream::py::type_name(key));
        }
    }
    if let (Some(kind), true) = (bad, items.len() > 1) {
        return Err(PyExc::TypeError(format!(
            "'<' not supported between instances of '{kind}' and 'str'"
        )));
    }
    items.sort_by(|a, b| match (&b.0, &a.0) {
        (PyValue::Str(x), PyValue::Str(y)) => x.cmp(y),
        _ => std::cmp::Ordering::Equal,
    });
    Ok(())
}

/// `save_preview(customer_code, sha256, name, data)`.
pub async fn save_preview(
    st: &FileAnalysisState,
    customer_code: &str,
    sha256: &str,
    name: &str,
    data: Vec<u8>,
) -> PyResult<()> {
    put_bytes(
        st,
        &preview_key(customer_code, sha256, name),
        data,
        "image/png",
    )
    .await
}

/// `load_preview(customer_code, sha256, name)`.
pub async fn load_preview(
    st: &FileAnalysisState,
    customer_code: &str,
    sha256: &str,
    name: &str,
) -> PyResult<Option<Bytes>> {
    get_bytes(st, &preview_key(customer_code, sha256, name)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_rows_project_like_python() {
        let result = loads(
            r#"{"job": {"job_id": "j", "sha256": "", "verdict": "clean", "source": "upload",
                "status": "done", "hardened": 0, "created_at": "c", "updated_at": "u"},
                "inspector": {"sha256": "abc", "filename": "x.ps1"},
                "reputation": {"found": true, "malicious": 2, "total": 70}}"#,
        )
        .unwrap();
        let item = history_item(&result).unwrap();
        assert_eq!(
            String::from_utf8(dumps(&item)).unwrap(),
            r#"{"job_id": "j", "filename": "x.ps1", "sha256": "abc", "verdict": "clean", "source": "upload", "status": "done", "hardened": false, "created_at": "c", "updated_at": "u", "vt_malicious": 2, "vt_total": 70}"#
        );
    }
}
