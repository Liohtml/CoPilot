//! `app/data_store/data_store_operations.py`: the operations the routes call,
//! line by line — which client each one opens, which calls it makes in which
//! order, and what it raises or swallows.
//!
//! Each function opens its own client (`create_session()` → a fresh region
//! cache), so every operation starts with the bucket's `GET ?location=`, as
//! in Python. Errors are the [`PyExc`] Python would hold at that point; the
//! routes decide what reaches the caller.

use bytes::Bytes;
use sha2::{Digest, Sha256};

use copilot_upstream::py::PyExc;

use crate::client::{Minio, SESSION_AS_OFFSET_RANGE};
use crate::error::MinioError;
use crate::store::ObjectStore;

/// `copilot-cases`.
pub const CASES_BUCKET: &str = "copilot-cases";
/// `copilot-case-report-templates`.
pub const REPORT_TEMPLATES_BUCKET: &str = "copilot-case-report-templates";
/// `velociraptor-artifacts`.
pub const ARTIFACTS_BUCKET: &str = "velociraptor-artifacts";

fn py(e: MinioError) -> PyExc {
    e.into_py()
}

/// `create_bucket_if_not_exists`: `bucket_exists`, then `make_bucket`.
pub async fn create_bucket_if_not_exists(store: &ObjectStore, bucket: &str) -> Result<(), PyExc> {
    let client = store.session()?;
    if !client.bucket_exists(bucket).await.map_err(py)? {
        client.make_bucket(bucket).await.map_err(py)?;
        tracing::info!("Created bucket {bucket}");
    } else {
        tracing::info!("Bucket {bucket} already exists");
    }
    Ok(())
}

/// `upload_case_data_store`: `fput_object` to `copilot-cases` as
/// `{case_id}/{file_name}` (no bucket check).
pub async fn upload_case_data_store(
    store: &ObjectStore,
    case_id: i64,
    file_name: &str,
    content_type: Option<&str>,
    data: &[u8],
) -> Result<(), PyExc> {
    let client = store.session()?;
    tracing::info!("Uploading file {file_name} to bucket {CASES_BUCKET}");
    client
        .fput_object(
            CASES_BUCKET,
            &format!("{case_id}/{file_name}"),
            data,
            content_type,
        )
        .await
        .map_err(py)
}

/// `upload_case_report_template_data_store`: `fput_object` to
/// `copilot-case-report-templates` under the file name.
pub async fn upload_case_report_template_data_store(
    store: &ObjectStore,
    file_name: &str,
    content_type: Option<&str>,
    data: &[u8],
) -> Result<(), PyExc> {
    let client = store.session()?;
    tracing::info!("Uploading file {file_name} to bucket {REPORT_TEMPLATES_BUCKET}");
    client
        .fput_object(REPORT_TEMPLATES_BUCKET, file_name, data, content_type)
        .await
        .map_err(py)
}

/// `download_data_store`: `stat_object`, then `get_object` (with the
/// session-as-offset `Range`). On any failure the bucket is listed
/// (recursively, every page — for the log) and the answer is the 404
/// `File {object} not found in bucket {bucket}`; a failure of that listing
/// is what escapes instead.
pub async fn download_data_store(
    store: &ObjectStore,
    bucket: &str,
    object: &str,
) -> Result<Bytes, PyExc> {
    let client = store.session()?;
    tracing::info!("Downloading file {object} from bucket {bucket}");
    let attempt = async {
        client.stat_object(bucket, object).await?;
        client
            .get_object(bucket, object, Some(SESSION_AS_OFFSET_RANGE))
            .await
    };
    match attempt.await {
        Ok(data) => {
            tracing::info!("Downloaded file {object} from bucket {bucket} and returning data");
            Ok(data)
        }
        Err(e) => {
            tracing::info!("Error: {}", e.clone().into_py().text());
            let names = list_names(&client, bucket, None, true).await?;
            tracing::info!("Objects in bucket {bucket}: {names:?}");
            Err(PyExc::http(
                404,
                format!("File {object} not found in bucket {bucket}"),
            ))
        }
    }
}

async fn list_names(
    client: &Minio,
    bucket: &str,
    prefix: Option<&str>,
    recursive: bool,
) -> Result<Vec<String>, PyExc> {
    Ok(client
        .list_objects(bucket, prefix, recursive)
        .await
        .map_err(py)?
        .into_iter()
        .map(|o| o.object_name)
        .collect())
}

/// `list_case_report_template_data_store_files`: the names in the bucket's
/// top level (objects, then common prefixes, page by page).
pub async fn list_case_report_template_data_store_files(
    store: &ObjectStore,
    bucket: &str,
) -> Result<Vec<String>, PyExc> {
    let client = store.session()?;
    tracing::info!("Listing objects in bucket {bucket}");
    list_names(&client, bucket, None, false).await
}

/// What `upload_file_to_datastore` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    /// `bucket_name`.
    pub bucket_name: String,
    /// `object_key`.
    pub object_key: String,
    /// `file_name`.
    pub file_name: String,
    /// `file_size`.
    pub file_size: i64,
    /// `file_hash` (SHA-256).
    pub file_hash: String,
    /// `content_type` (`application/octet-stream` when the part had none).
    pub content_type: String,
}

/// `upload_file_to_datastore`: the bucket created if missing (its own
/// client), then `fput_object`.
pub async fn upload_file_to_datastore(
    store: &ObjectStore,
    file_name: &str,
    content_type: Option<&str>,
    data: &[u8],
    bucket: &str,
    object: &str,
) -> Result<Uploaded, PyExc> {
    let client = store.session()?;
    create_bucket_if_not_exists(store, bucket).await?;
    tracing::info!("Uploading file {file_name} to bucket {bucket} as {object}");
    let file_hash = hex::encode(Sha256::digest(data));
    let content_type = content_type
        .filter(|c| !c.is_empty())
        .unwrap_or("application/octet-stream")
        .to_string();
    client
        .fput_object(bucket, object, data, Some(&content_type))
        .await
        .map_err(py)?;
    Ok(Uploaded {
        bucket_name: bucket.to_string(),
        object_key: object.to_string(),
        file_name: file_name.to_string(),
        file_size: i64::try_from(data.len()).unwrap_or(i64::MAX),
        file_hash,
        content_type,
    })
}

/// What `store_file_in_minio` reports on success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// `bucket_name`.
    pub bucket_name: String,
    /// `object_key`.
    pub object_key: String,
    /// `file_size`.
    pub file_size: i64,
    /// `file_hash` (SHA-256).
    pub file_hash: String,
    /// `content_type`.
    pub content_type: String,
}

/// `store_file_in_minio(file_content, bucket_name, object_key,
/// content_type)` — how the agents' CSV reports reach MinIO: a client, the
/// bucket created if missing (its own client; a failure there escapes, it is
/// outside the `try`), then `fput_object`. `Ok(Err(str(e)))` is the
/// `{"success": False, "error": …}` answer of a failed upload.
pub async fn store_file_in_minio(
    store: &ObjectStore,
    data: &[u8],
    bucket: &str,
    object: &str,
    content_type: &str,
) -> Result<Result<Stored, String>, PyExc> {
    let client = store.session()?;
    create_bucket_if_not_exists(store, bucket).await?;
    tracing::info!("Storing file to bucket {bucket} as {object}");
    let file_hash = hex::encode(Sha256::digest(data));
    let file_size = i64::try_from(data.len()).unwrap_or(i64::MAX);
    match client
        .fput_object(bucket, object, data, Some(content_type))
        .await
    {
        Ok(()) => {
            tracing::info!("Successfully stored file ({file_size} bytes) to {bucket}/{object}");
            Ok(Ok(Stored {
                bucket_name: bucket.to_string(),
                object_key: object.to_string(),
                file_size,
                file_hash,
                content_type: content_type.to_string(),
            }))
        }
        Err(e) => {
            let text = e.into_py().text();
            tracing::error!("Error storing file in MinIO: {text}");
            Ok(Err(text))
        }
    }
}

/// `delete_file`: `stat_object`, then `remove_object`; any failure is the
/// 404 `File {object} not found in bucket {bucket}` (only the client's own
/// construction escapes as it is).
pub async fn delete_file(store: &ObjectStore, bucket: &str, object: &str) -> Result<(), PyExc> {
    let client = store.session()?;
    let attempt = async {
        client.stat_object(bucket, object).await?;
        client.remove_object(bucket, object).await
    };
    match attempt.await {
        Ok(()) => {
            tracing::info!("Deleted file {object} from bucket {bucket}");
            Ok(())
        }
        Err(e) => {
            tracing::info!("Error: {}", e.into_py().text());
            Err(PyExc::http(
                404,
                format!("File {object} not found in bucket {bucket}"),
            ))
        }
    }
}

/// What the argument checks raise for a report row without a bucket
/// (`re.match(…, None)`) or without a key (`check_non_empty_string(None)`).
fn none_value(what: &str) -> MinioError {
    MinioError::Py(PyExc::TypeError(if what == "bucket" {
        "expected string or bytes-like object, got 'NoneType'".into()
    } else {
        String::new()
    }))
}

/// `retrieve_file_from_minio`: `Ok(Ok(bytes))`, `Ok(Err(str(e)))` for the
/// `{"success": False, "error": …}` answer, `Err` for what escapes (the
/// client's construction).
pub async fn retrieve_file_from_minio(
    store: &ObjectStore,
    bucket: Option<&str>,
    object: Option<&str>,
) -> Result<Result<Bytes, String>, PyExc> {
    let client = store.session()?;
    let attempt = async {
        let bucket = bucket.ok_or_else(|| none_value("bucket"))?;
        let object = object.ok_or_else(|| none_value("object"))?;
        client.stat_object(bucket, object).await?;
        client
            .get_object(bucket, object, Some(SESSION_AS_OFFSET_RANGE))
            .await
    };
    Ok(attempt.await.map_err(|e| {
        let text = e.into_py().text();
        tracing::error!("Error retrieving file from MinIO: {text}");
        text
    }))
}

/// `delete_file_from_minio`: `Ok(Err(str(e)))` when it failed (the caller
/// logs it and carries on), `Err` for the client's construction.
pub async fn delete_file_from_minio(
    store: &ObjectStore,
    bucket: Option<&str>,
    object: Option<&str>,
) -> Result<Result<(), String>, PyExc> {
    let client = store.session()?;
    let attempt = async {
        let bucket = bucket.ok_or_else(|| none_value("bucket"))?;
        let object = object.ok_or_else(|| none_value("object"))?;
        client.stat_object(bucket, object).await?;
        client.remove_object(bucket, object).await
    };
    Ok(attempt.await.map_err(|e| {
        let text = e.into_py().text();
        tracing::error!("Error deleting file from MinIO: {text}");
        text
    }))
}
