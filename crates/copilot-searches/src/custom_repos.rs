//! `services/custom_repos.py`: the per-tenant custom-repo pointers in MinIO
//! (bucket `copilot-searches`, `custom-repos/<customer_code>.json`), read and
//! written through `copilot-objectstore` as `miniopy-async` does — a client
//! per call, the download's `Range` naming the aiohttp session.

use copilot_auth::pyvalue::{PyValue, loads_bytes};
use copilot_objectstore::client::SESSION_AS_OFFSET_RANGE;
use copilot_objectstore::{Minio, ObjectStore};
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::py::{PyExc, PyResult};

/// `BUCKET`.
pub const BUCKET: &str = "copilot-searches";
/// `PREFIX`.
pub const PREFIX: &str = "custom-repos/";

/// One pointer (`_normalize`'s dict).
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// `customer_code`.
    pub customer_code: String,
    /// `repo`.
    pub repo: String,
    /// `branch`.
    pub branch: String,
    /// `token` (`cfg.get("token") or None`: any truthy JSON value).
    pub token: Option<PyValue>,
    /// `enabled`.
    pub enabled: bool,
}

impl Record {
    /// The token as the headers use it (`f"Bearer {tok}"`).
    pub fn token_text(&self) -> Option<String> {
        self.token.as_ref().map(PyValue::py_str)
    }

    /// `json.dumps(record)`.
    pub fn dumps(&self) -> String {
        let value = PyValue::Dict(vec![
            (
                "customer_code".into(),
                PyValue::Str(self.customer_code.clone()),
            ),
            ("repo".into(), PyValue::Str(self.repo.clone())),
            ("branch".into(), PyValue::Str(self.branch.clone())),
            ("token".into(), self.token.clone().unwrap_or(PyValue::None)),
            ("enabled".into(), PyValue::Bool(self.enabled)),
        ]);
        py_dumps(&value, Dumps::DEFAULT).unwrap_or_default()
    }
}

fn py_strip(t: &str) -> String {
    t.trim_matches(copilot_jinja::unicode::is_space).to_string()
}

fn attr_error(v: &PyValue, attr: &str) -> PyExc {
    PyExc::AttributeError(format!(
        "'{}' object has no attribute '{attr}'",
        copilot_upstream::py::type_name(v)
    ))
}

/// `(value or default).strip()`.
fn or_strip(v: Option<&PyValue>, default: &str) -> PyResult<String> {
    match v {
        Some(v) if v.truthy() => match v {
            PyValue::Str(t) => Ok(py_strip(t)),
            other => Err(attr_error(other, "strip")),
        },
        _ => Ok(py_strip(default)),
    }
}

/// `_normalize(cfg, customer_code)`.
pub fn normalize(cfg: &PyValue, customer_code: &str) -> PyResult<Record> {
    let get = |k: &str| copilot_upstream::py::get(cfg, k);
    let repo = or_strip(get("repo")?, "")?;
    let branch = or_strip(get("branch")?, "main")?;
    let branch = if branch.is_empty() {
        "main".to_string()
    } else {
        branch
    };
    let token = get("token")?.filter(|t| t.truthy()).cloned();
    let enabled = match get("enabled")? {
        None => true,
        Some(v) => v.truthy(),
    };
    Ok(Record {
        customer_code: customer_code.to_string(),
        repo,
        branch,
        token,
        enabled,
    })
}

fn object_name(customer_code: &str) -> String {
    format!("{PREFIX}{customer_code}.json")
}

fn minio_exc(e: copilot_objectstore::MinioError) -> PyExc {
    e.into_py()
}

fn session(store: &ObjectStore) -> PyResult<Minio> {
    store.session()
}

/// `set_custom_repo(customer_code, cfg)`.
pub async fn set(store: &ObjectStore, customer_code: &str, cfg: &PyValue) -> PyResult<Record> {
    let record = normalize(cfg, customer_code)?;
    let body = record.dumps().into_bytes();
    let client = session(store)?;
    if !client.bucket_exists(BUCKET).await.map_err(minio_exc)? {
        client.make_bucket(BUCKET).await.map_err(minio_exc)?;
        tracing::info!("[custom-repos] created MinIO bucket {BUCKET}");
    }
    client
        .fput_object(
            BUCKET,
            &object_name(customer_code),
            &body,
            Some("application/json"),
        )
        .await
        .map_err(minio_exc)?;
    tracing::info!(
        "[custom-repos] saved pointer for {customer_code}: {}@{}",
        record.repo,
        record.branch
    );
    Ok(record)
}

/// `json.loads(data)` then `_normalize`; `Ok(None)` where Python catches a
/// `ValueError` / `TypeError`.
fn parse(data: &[u8], customer_code: &str) -> PyResult<Option<Record>> {
    let Ok(cfg) = loads_bytes(data) else {
        return Ok(None);
    };
    match normalize(&cfg, customer_code) {
        Ok(r) => Ok(Some(r)),
        Err(e @ PyExc::AttributeError(_)) => Err(e),
        Err(_) => Ok(None),
    }
}

/// `get_custom_repo(customer_code)`.
pub async fn get(store: &ObjectStore, customer_code: &str) -> PyResult<Option<Record>> {
    let client = session(store)?;
    if !client.bucket_exists(BUCKET).await.map_err(minio_exc)? {
        return Ok(None);
    }
    let name = object_name(customer_code);
    if client.stat_object(BUCKET, &name).await.is_err() {
        return Ok(None);
    }
    let data = client
        .get_object(BUCKET, &name, Some(SESSION_AS_OFFSET_RANGE))
        .await
        .map_err(minio_exc)?;
    parse(&data, customer_code)
}

/// `list_custom_repos()`.
pub async fn list(store: &ObjectStore) -> PyResult<Vec<Record>> {
    let client = session(store)?;
    if !client.bucket_exists(BUCKET).await.map_err(minio_exc)? {
        return Ok(Vec::new());
    }
    let objects = client
        .list_objects(BUCKET, Some(PREFIX), true)
        .await
        .map_err(minio_exc)?;
    let mut out = Vec::new();
    for obj in objects {
        let name = obj.object_name;
        if !name.ends_with(".json") {
            continue;
        }
        let code: String = {
            let chars: Vec<char> = name.chars().collect();
            let start = PREFIX.chars().count().min(chars.len());
            let end = chars.len().saturating_sub(".json".len()).max(start);
            chars[start..end].iter().collect()
        };
        let read = client
            .get_object(BUCKET, &name, Some(SESSION_AS_OFFSET_RANGE))
            .await
            .map_err(minio_exc)
            .and_then(|data| {
                loads_bytes(&data)
                    .map_err(|_| PyExc::ValueError("invalid JSON".into()))
                    .and_then(|cfg| normalize(&cfg, &code))
            });
        match read {
            Ok(r) => out.push(r),
            Err(e) => tracing::warn!("[custom-repos] skipping unreadable {name}: {}", e.text()),
        }
    }
    Ok(out)
}

/// `delete_custom_repo(customer_code)`.
pub async fn delete(store: &ObjectStore, customer_code: &str) -> PyResult<()> {
    let client = session(store)?;
    if !client.bucket_exists(BUCKET).await.map_err(minio_exc)? {
        return Ok(());
    }
    match client
        .remove_object(BUCKET, &object_name(customer_code))
        .await
    {
        Ok(()) => tracing::info!("[custom-repos] deleted pointer for {customer_code}"),
        Err(e) => tracing::warn!(
            "[custom-repos] delete failed for {customer_code}: {}",
            e.into_py().text()
        ),
    }
    Ok(())
}

/// `redact(record)`, with the last refresh's outcome for the repo's owner.
pub fn redact(record: &Record) -> Vec<(&'static str, PyValue)> {
    vec![
        ("customer_code", PyValue::Str(record.customer_code.clone())),
        ("repo", PyValue::Str(record.repo.clone())),
        ("branch", PyValue::Str(record.branch.clone())),
        ("enabled", PyValue::Bool(record.enabled)),
        ("has_token", PyValue::Bool(record.token.is_some())),
    ]
}
