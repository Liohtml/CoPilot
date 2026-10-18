//! # copilot-file-analysis — `/api/file-analysis`
//!
//! Port of `app/file_analysis/` (the CoPilot side of File Analysis; the
//! inspector-runner sidecar and the CAPE box stay the services they are):
//!
//! - [`routes`] — the 12 routes: the Velociraptor agents and file listing,
//!   `/submit` (collect from an endpoint), `/upload`, a job, its result, the
//!   raw CAPE report, the PDF report, a preview, the delete, the history and
//!   the cache lookup by SHA-256
//! - [`orchestrator`] — the pipeline each job runs on a task of its own:
//!   fetch, Tier 1 (the inspector), the interim save, the VirusTotal hash
//!   lookup, Tier 2 (CAPE, when `SANDBOX_BACKEND=remote`), the final save,
//!   and the detached VirusTotal upload
//! - [`store`] — MinIO as the only store (`state_store.py`'s keys and JSON)
//! - [`inspector`], [`cape`], [`reputation`], [`velo`] — the upstreams, as
//!   httpx and pyvelociraptor reach them
//! - [`verdict`] — the cross-tier verdict (pure)
//! - [`report`] — the PDF report (`report_pdf.py`, Jinja2 through
//!   `copilot-jinja`, wkhtmltopdf as pdfkit runs it)
//! - [`schema`] — the Pydantic models
//!
//! State this process keeps on its own: the "bucket exists" flag (as
//! Python's `_bucket_ready`) and the jobs in flight. Both backends read and
//! write the same objects, so a job either one started is the other's to
//! show; a job in flight when its process stops is lost, in both.

#![warn(missing_docs)]

pub mod cape;
pub mod inspector;
pub mod mimetypes;
pub mod orchestrator;
mod pdf;
pub mod py;
pub mod report;
pub mod reputation;
pub mod routes;
pub mod schema;
mod starlette;
pub mod store;
pub mod velo;
pub mod verdict;
pub mod zip;

#[cfg(test)]
mod vectors_tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use axum::extract::FromRef;
use copilot_core::file_analysis_env::FileAnalysisEnv;
use copilot_gateway::LegacyProxy;
use copilot_objectstore::ObjectStore;
use copilot_threat_intel::ThreatIntelState;
use copilot_velociraptor::VelociraptorClient;
use copilot_web::AppContext;
use tokio::sync::Semaphore;

pub use routes::router;

/// What the module reads from the environment, parsed as the Python modules
/// parse it (`int(os.getenv(name, default))`; a value Python could not parse
/// stops its import — here the default is kept and the value logged).
#[derive(Debug, Clone)]
pub struct Settings {
    /// `INSPECTOR_URL`.
    pub inspector_url: String,
    /// `INSPECTOR_HTTP_TIMEOUT` (seconds).
    pub inspector_timeout: u64,
    /// `SANDBOX_BACKEND`, lower-cased.
    pub sandbox_backend: String,
    /// `CAPE_API_URL` without its trailing `/`.
    pub cape_api_url: String,
    /// `CAPE_API_TOKEN`.
    pub cape_api_token: String,
    /// `CAPE_PACKAGE`, stripped.
    pub cape_package: String,
    /// `CAPE_TASK_TIMEOUT`, as the text sent.
    pub cape_task_timeout: String,
    /// `CAPE_POLL_INTERVAL` (seconds).
    pub cape_poll_interval: u64,
    /// `CAPE_POLL_TIMEOUT` (seconds).
    pub cape_poll_timeout: i64,
    /// `CAPE_HTTP_TIMEOUT` (seconds).
    pub cape_http_timeout: u64,
    /// `ENRICHMENT_VT_MALICIOUS_THRESHOLD`.
    pub vt_threshold: i64,
    /// `ENRICHMENT_VT_MAX_WAIT` (seconds).
    pub vt_max_wait: i64,
    /// `ENRICHMENT_VT_POLL` (seconds).
    pub vt_poll: i64,
    /// `ENRICHMENT_VT_MAX_UPLOAD_MB`.
    pub vt_max_upload_mb: i64,
    /// `ENRICHMENT_VT_DEEP`.
    pub vt_deep: bool,
    /// `FILE_ANALYSIS_MINIO_BUCKET`.
    pub bucket: String,
    /// `FILE_ANALYSIS_MINIO_RETRIES`.
    pub minio_retries: i64,
    /// `FILE_ANALYSIS_MINIO_BACKOFF` (seconds).
    pub minio_backoff: f64,
    /// `FILE_ANALYSIS_MAX_FLOW_FILES`, read per call as Python reads it.
    pub max_flow_files: String,
    /// `FILE_ANALYSIS_COLLECT_TIMEOUT`, read per call.
    pub collect_timeout: String,
    /// `FILE_ANALYSIS_ENUM_TIMEOUT`, read per call.
    pub enum_timeout: String,
    /// `VELOCIRAPTOR_API_CONFIG` (the fallback config).
    pub velociraptor_api_config: String,
    /// `FILE_ANALYSIS_MAX_CONCURRENT_JOBS`: jobs running at once (Python
    /// bounds nothing; §4).
    pub max_jobs: usize,
    /// `COPILOT_WKHTMLTOPDF` — tests only: the wkhtmltopdf binary instead of
    /// pdfkit's search of `/usr/bin` and `/usr/local/bin`.
    pub wkhtmltopdf: Option<String>,
}

fn int_or(env: &FileAnalysisEnv, key: &str, default: i64) -> i64 {
    let raw = env.get_or(key, "");
    if env.get(key).is_none() {
        return default;
    }
    match py::int_setting(raw) {
        Ok(n) => n,
        Err(_) => {
            tracing::warn!("{key}={raw:?} is not an integer; using {default}");
            default
        }
    }
}

impl Settings {
    /// From the raw environment.
    pub fn from_env(env: &FileAnalysisEnv, cape_api_token: Option<&str>) -> Self {
        let backoff = match env.get("FILE_ANALYSIS_MINIO_BACKOFF") {
            None => 0.5,
            Some(raw) => py::float_str(raw).unwrap_or_else(|_| {
                tracing::warn!("FILE_ANALYSIS_MINIO_BACKOFF={raw:?} is not a number; using 0.5");
                0.5
            }),
        };
        Self {
            inspector_url: env
                .get_or("INSPECTOR_URL", "http://inspector-runner:9000")
                .to_string(),
            inspector_timeout: u64::try_from(int_or(env, "INSPECTOR_HTTP_TIMEOUT", 240))
                .unwrap_or(0),
            sandbox_backend: py::lower(env.get_or("SANDBOX_BACKEND", "none")),
            cape_api_url: env
                .get_or("CAPE_API_URL", "http://cape-host:8000/apiv2")
                .trim_end_matches('/')
                .to_string(),
            cape_api_token: cape_api_token.unwrap_or_default().to_string(),
            cape_package: py::strip(env.get_or("CAPE_PACKAGE", "")).to_string(),
            cape_task_timeout: env.get_or("CAPE_TASK_TIMEOUT", "120").to_string(),
            cape_poll_interval: u64::try_from(int_or(env, "CAPE_POLL_INTERVAL", 15)).unwrap_or(0),
            cape_poll_timeout: int_or(env, "CAPE_POLL_TIMEOUT", 1800),
            cape_http_timeout: u64::try_from(int_or(env, "CAPE_HTTP_TIMEOUT", 60)).unwrap_or(0),
            vt_threshold: int_or(env, "ENRICHMENT_VT_MALICIOUS_THRESHOLD", 5),
            vt_max_wait: int_or(env, "ENRICHMENT_VT_MAX_WAIT", 300),
            vt_poll: int_or(env, "ENRICHMENT_VT_POLL", 10),
            vt_max_upload_mb: int_or(env, "ENRICHMENT_VT_MAX_UPLOAD_MB", 32),
            vt_deep: py::lower(env.get_or("ENRICHMENT_VT_DEEP", "true")) == "true",
            bucket: env
                .get_or("FILE_ANALYSIS_MINIO_BUCKET", "file-analysis")
                .to_string(),
            minio_retries: int_or(env, "FILE_ANALYSIS_MINIO_RETRIES", 4),
            minio_backoff: backoff,
            max_flow_files: env.get_or("FILE_ANALYSIS_MAX_FLOW_FILES", "25").to_string(),
            collect_timeout: env
                .get_or("FILE_ANALYSIS_COLLECT_TIMEOUT", "180")
                .to_string(),
            enum_timeout: env.get_or("FILE_ANALYSIS_ENUM_TIMEOUT", "90").to_string(),
            velociraptor_api_config: env.get_or("VELOCIRAPTOR_API_CONFIG", "").to_string(),
            max_jobs: usize::try_from(int_or(env, "FILE_ANALYSIS_MAX_CONCURRENT_JOBS", 8).max(1))
                .unwrap_or(8),
            wkhtmltopdf: env
                .get("COPILOT_WKHTMLTOPDF")
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string),
        }
    }
}

/// State of the File Analysis routes and jobs.
#[derive(Clone)]
pub struct FileAnalysisState {
    /// Shared dependencies (database, connector cache, auth).
    pub ctx: AppContext,
    /// MinIO.
    pub objects: ObjectStore,
    /// The Velociraptor client.
    pub velociraptor: VelociraptorClient,
    /// The threat-intel state (VirusTotal's base URL and client).
    pub threat_intel: ThreatIntelState,
    /// The settings.
    pub settings: Arc<Settings>,
    /// `_bucket_ready`.
    pub bucket_ready: Arc<AtomicBool>,
    /// The bound on jobs running at once.
    pub jobs: Arc<Semaphore>,
    /// The bound on detached VirusTotal uploads running at once.
    pub uploads: Arc<Semaphore>,
    /// The Python backend's data directory (the Velociraptor fallback
    /// config).
    pub backend_data_dir: PathBuf,
    /// The Python backend, for a path with an encoded `/`.
    pub legacy: Option<LegacyProxy>,
}

impl std::fmt::Debug for FileAnalysisState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileAnalysisState")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl FileAnalysisState {
    /// The state, with the settings read from the environment.
    pub fn new(
        ctx: AppContext,
        objects: ObjectStore,
        velociraptor: VelociraptorClient,
        threat_intel: ThreatIntelState,
        env: &FileAnalysisEnv,
        backend_data_dir: PathBuf,
        legacy: Option<LegacyProxy>,
    ) -> Self {
        let settings = Settings::from_env(
            env,
            env.cape_api_token
                .as_ref()
                .map(copilot_core::config::Secret::expose),
        );
        let max_jobs = settings.max_jobs;
        Self {
            ctx,
            objects,
            velociraptor,
            threat_intel,
            settings: Arc::new(settings),
            bucket_ready: Arc::new(AtomicBool::new(false)),
            jobs: Arc::new(Semaphore::new(max_jobs)),
            uploads: Arc::new(Semaphore::new(max_jobs)),
            backend_data_dir,
            legacy,
        }
    }
}

impl FromRef<FileAnalysisState> for AppContext {
    fn from_ref(s: &FileAnalysisState) -> AppContext {
        s.ctx.clone()
    }
}

/// The `agents` columns the routes read.
pub const REQUIREMENTS: &[copilot_db::schema::TableRequirement] =
    &[copilot_db::schema::TableRequirement {
        table: "agents",
        columns: &["id", "hostname", "os", "velociraptor_id", "customer_code"],
    }];
