//! `services/orchestrator.py`: the pipeline a job runs, in Python's order.
//!
//! 1. the sample: the upload's bytes, or a Velociraptor collection
//!    (`source=host_path`: the client id, or the host's, then
//!    `collect_and_fetch`);
//! 2. Tier 1, always: `running` saved, the inspector called, its previews
//!    stored;
//! 3. the VirusTotal hash lookup (`reputation_mode` `off` | `lookup` |
//!    `upload`), before any detonation;
//! 4. the interim result (Tier 1 and reputation) and the job saved;
//! 5. Tier 2 when a sandbox is available, `dynamic` was asked for and the
//!    file is worth detonating;
//! 6. the final verdict and result, the job `done`;
//! 7. for `upload` mode with VirusTotal not knowing the file, the upload
//!    and scan on a task of their own, patching the stored result.
//!
//! A failure anywhere in 1–7 is the job `failed` with the exception's text,
//! as Python's `except Exception`. Each job runs on a `tokio::spawn`ed task,
//! at most `FILE_ANALYSIS_MAX_CONCURRENT_JOBS` at once (Python's
//! `BackgroundTasks` bound nothing, §4); the detached uploads share their own
//! bound. Jobs in flight when the process stops are lost, as in Python.

use bytes::Bytes;
use chrono::Utc;
use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::field;
use copilot_upstream::py::{PyExc, PyResult};

use crate::cape::Cape;
use crate::py::{self, dict, get, get_or, or, str_of};
use crate::schema::ANALYSIS_JOB;
use crate::{FileAnalysisState, Settings, inspector, reputation, store, velo, verdict};

/// `_ESCALATION_FLAGS`.
const ESCALATION_FLAGS: &[&str] = &[
    "encoded_powershell",
    "auto_execute_javascript",
    "launch_action",
    "autoopen_macro",
    "lnk_suspicious_args",
    "html_smuggling",
    "deobfuscation_incomplete",
    "analysis_incomplete",
];
/// `_ESCALATION_TYPES`.
const ESCALATION_TYPES: &[&str] = &[
    "pe", "elf", "script", "office", "pdf", "lnk", "archive", "html",
];
/// `_INERT_FILETYPES`.
const INERT_FILETYPES: &[&str] = &["text"];

/// `datetime.now(timezone.utc).isoformat()`.
pub fn now() -> String {
    let t = Utc::now();
    if t.timestamp_subsec_micros() == 0 {
        t.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        t.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
    }
}

/// `uuid.uuid4().hex`.
pub fn new_job_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// `AnalysisJob` as the orchestrator mutates it.
#[derive(Debug, Clone)]
pub struct Job {
    /// `job_id`.
    pub job_id: String,
    /// `sha256` (the inspector's value is assigned as it comes).
    pub sha256: PyValue,
    /// `filename`.
    pub filename: String,
    /// `customer_code`.
    pub customer_code: String,
    /// `source`.
    pub source: String,
    /// `status`.
    pub status: String,
    /// `static_status`.
    pub static_status: String,
    /// `dynamic_status`.
    pub dynamic_status: Option<String>,
    /// `sandbox_enabled`.
    pub sandbox_enabled: bool,
    /// `hardened`.
    pub hardened: bool,
    /// `verdict`.
    pub verdict: Option<String>,
    /// `created_at`.
    pub created_at: String,
    /// `updated_at`.
    pub updated_at: String,
    /// `error`.
    pub error: Option<String>,
}

fn opt_text(v: Option<&String>) -> PyValue {
    v.map_or(PyValue::None, |s| py::s(s.clone()))
}

impl Job {
    /// `AnalysisJob(**job_dict)`.
    pub fn validate(stored: &PyValue) -> PyResult<Self> {
        let dump = copilot_upstream::model::construct_star(
            &ANALYSIS_JOB,
            "app.file_analysis.schema.analysis.AnalysisJob",
            stored,
        )?;
        let text = |k: &str| field(&dump, k).as_str().unwrap_or_default().to_string();
        let opt = |k: &str| field(&dump, k).as_str().map(str::to_string);
        Ok(Self {
            job_id: text("job_id"),
            sha256: field(&dump, "sha256").clone(),
            filename: text("filename"),
            customer_code: text("customer_code"),
            source: text("source"),
            status: text("status"),
            static_status: text("static_status"),
            dynamic_status: opt("dynamic_status"),
            sandbox_enabled: field(&dump, "sandbox_enabled").truthy(),
            hardened: field(&dump, "hardened").truthy(),
            verdict: opt("verdict"),
            created_at: text("created_at"),
            updated_at: text("updated_at"),
            error: opt("error"),
        })
    }

    /// `job.model_dump(mode="json")`.
    pub fn dump(&self) -> PyValue {
        dict(vec![
            ("job_id", py::s(self.job_id.clone())),
            ("sha256", self.sha256.clone()),
            ("filename", py::s(self.filename.clone())),
            ("customer_code", py::s(self.customer_code.clone())),
            ("source", py::s(self.source.clone())),
            ("status", py::s(self.status.clone())),
            ("static_status", py::s(self.static_status.clone())),
            ("dynamic_status", opt_text(self.dynamic_status.as_ref())),
            ("sandbox_enabled", PyValue::Bool(self.sandbox_enabled)),
            ("hardened", PyValue::Bool(self.hardened)),
            ("verdict", opt_text(self.verdict.as_ref())),
            ("created_at", py::s(self.created_at.clone())),
            ("updated_at", py::s(self.updated_at.clone())),
            ("error", opt_text(self.error.as_ref())),
        ])
    }

    fn sha(&self) -> String {
        str_of(&self.sha256)
    }
}

/// `_save(job)`.
async fn save(st: &FileAnalysisState, job: &mut Job) -> PyResult<()> {
    job.updated_at = now();
    store::save_job(st, &job.dump()).await
}

/// `create_and_dispatch(...)`: `(job_id, needs_run)`; a complete cached
/// result of the same file answers with its job.
pub async fn create_and_dispatch(
    st: &FileAnalysisState,
    source: &str,
    customer_code: &str,
    filename: &str,
    sha256: &str,
) -> PyResult<(PyValue, bool)> {
    if !sha256.is_empty() {
        if let Some(cached) = store::find_cached_job_id(st, customer_code, sha256).await? {
            tracing::info!(
                "cache hit (complete) for {} ({customer_code}) -> job {}",
                sha256.chars().take(12).collect::<String>(),
                str_of(&cached)
            );
            return Ok((cached, false));
        }
    }
    let mut job = Job {
        job_id: new_job_id(),
        sha256: py::s(sha256),
        filename: filename.to_string(),
        customer_code: customer_code.to_string(),
        source: source.to_string(),
        status: "queued".into(),
        static_status: "queued".into(),
        dynamic_status: None,
        sandbox_enabled: false,
        hardened: true,
        verdict: None,
        created_at: now(),
        updated_at: String::new(),
        error: None,
    };
    save(st, &mut job).await?;
    Ok((py::s(job.job_id), true))
}

/// What `/submit` hands the job (`refs`).
#[derive(Debug, Clone, Default)]
pub struct Refs {
    /// `client_id`.
    pub client_id: Option<String>,
    /// `target_path`.
    pub target_path: Option<String>,
    /// `hostname`.
    pub hostname: Option<String>,
    /// For a caller without deployment-wide access, the client a hostname
    /// resolves to must be one of the job's customer's agents (§4).
    pub owner_check: bool,
}

/// The arguments of `run`.
#[derive(Debug, Clone)]
pub struct RunArgs {
    /// The upload's bytes (`None` for a collection).
    pub sample: Option<Bytes>,
    /// `tiers`.
    pub tiers: Vec<String>,
    /// `refs`.
    pub refs: Refs,
    /// `reputation_mode`.
    pub reputation_mode: String,
}

/// Start `run` on a task of its own (FastAPI's `background.add_task`).
pub fn spawn(st: &FileAnalysisState, job_id: String, args: RunArgs) {
    let st = st.clone();
    tokio::spawn(async move {
        let permit = st.jobs.clone().acquire_owned().await;
        run(&st, &job_id, args).await;
        drop(permit);
    });
}

/// `run(job_id, ...)`.
pub async fn run(st: &FileAnalysisState, job_id: &str, args: RunArgs) {
    let stored = match store::load_job(st, job_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            tracing::error!("run: job {job_id} not found");
            return;
        }
        Err(e) => {
            tracing::error!("run: job {job_id} could not be read: {}", e.display());
            return;
        }
    };
    let mut job = match Job::validate(&stored) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("run: job {job_id} is not an AnalysisJob: {}", e.display());
            return;
        }
    };
    if let Err(e) = pipeline(st, &mut job, args).await {
        tracing::error!("orchestrator run failed for {job_id}: {}", e.display());
        job.status = "failed".into();
        job.error = Some(e.display());
        if let Err(e) = save(st, &mut job).await {
            tracing::error!(
                "orchestrator could not save failed job {job_id}: {}",
                e.display()
            );
        }
    }
}

/// The owner of a Velociraptor client id: every `agents` row naming it
/// (bare or with its org suffix) must be the customer's.
pub async fn client_owned_by(st: &FileAnalysisState, client_id: &str, customer: &str) -> bool {
    let escaped = client_id
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let rows: Result<Vec<Option<String>>, sqlx::Error> = sqlx::query_scalar(
        "SELECT agents.customer_code FROM agents WHERE agents.velociraptor_id = ? \
         OR agents.velociraptor_id LIKE ?",
    )
    .persistent(false)
    .bind(client_id)
    .bind(format!("{escaped}-%"))
    .fetch_all(st.ctx.db.pool())
    .await;
    match rows {
        Ok(rows) => !rows.is_empty() && rows.iter().all(|c| c.as_deref() == Some(customer)),
        Err(e) => {
            tracing::error!("client owner lookup failed: {e}");
            false
        }
    }
}

/// `_resolve_sample(job, refs)`: the collected bytes, or `None` (any
/// failure).
async fn resolve_sample(st: &FileAnalysisState, job: &mut Job, refs: &Refs) -> Option<Vec<u8>> {
    let outcome: PyResult<Option<Vec<u8>>> = async {
        if job.source != "host_path" {
            return Ok(None);
        }
        let mut client_id = refs.client_id.clone().map_or(PyValue::None, PyValue::Str);
        if !client_id.truthy() {
            if let Some(host) = refs.hostname.as_ref().filter(|h| !h.is_empty()) {
                client_id = velo::resolve_client_id(st, host).await?;
                if refs.owner_check
                    && client_id.truthy()
                    && !client_owned_by(st, &str_of(&client_id), &job.customer_code).await
                {
                    tracing::error!(
                        "host_path: {host} resolved to a client outside customer {}",
                        job.customer_code
                    );
                    return Ok(None);
                }
            }
        }
        if !client_id.truthy() {
            tracing::error!("host_path: could not resolve an agent from refs={refs:?}");
            return Ok(None);
        }
        let target = refs.target_path.clone().unwrap_or_default();
        let Some(local) = velo::collect_and_fetch(st, &client_id, &target).await? else {
            return Ok(None);
        };
        job.sha256 = py::s(local.sha256);
        job.filename = local.original_filename;
        Ok(Some(local.data))
    }
    .await;
    outcome.unwrap_or_else(|e| {
        tracing::error!("sample resolve failed: {}", e.display());
        None
    })
}

/// The configured Tier 2 backend (`get_backend()`): `None` is
/// `NullBackend`.
pub fn backend(settings: &Settings) -> Option<Cape> {
    match settings.sandbox_backend.as_str() {
        "none" => None,
        "remote" => Some(Cape::new(settings)),
        "local_vm" => {
            if virtualization_available() {
                Some(Cape::new(settings))
            } else {
                tracing::error!(
                    "SANDBOX_BACKEND=local_vm but no hypervisor detected (/dev/kvm absent). \
                     Detonation is VM-based; falling back to 'none'. Use 'remote' or install KVM."
                );
                None
            }
        }
        other => {
            tracing::error!("Unknown SANDBOX_BACKEND={other:?}; defaulting to 'none'.");
            None
        }
    }
}

/// `shutil.which(name)` is set.
fn on_path(name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            let p = dir.join(name);
            p.metadata()
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

/// `_virtualization_available()`.
fn virtualization_available() -> bool {
    std::path::Path::new("/dev/kvm").exists() || on_path("kvm-ok") || on_path("virsh")
}

/// `_should_escalate(inspector, source)`.
pub(crate) fn should_escalate(inspector: &PyValue) -> PyResult<bool> {
    let filetype = get_or(inspector, "filetype", py::s(""))?;
    if py::in_str_set(&filetype, ESCALATION_TYPES)? {
        return Ok(true);
    }
    let flags = get_or(inspector, "flags", py::empty_list())?;
    let mut hit = false;
    for flag in py::iter(&flags)? {
        if py::in_str_set(&flag, ESCALATION_FLAGS)? {
            hit = true;
        }
    }
    if hit {
        return Ok(true);
    }
    Ok(!py::in_str_set(&filetype, INERT_FILETYPES)?)
}

/// `_detonate(sample_bytes, inspector, job)`: the summary, or `None`.
async fn detonate(
    st: &FileAnalysisState,
    sample: &[u8],
    inspector: &PyValue,
    job: &Job,
) -> Option<PyValue> {
    let cape = backend(&st.settings)?;
    let outcome: Result<PyValue, String> = async {
        let existing = cape
            .find_by_sha256(&job.sha())
            .await
            .map_err(|e| e.text())?;
        let filename = if !job.filename.is_empty() {
            py::s(job.filename.clone())
        } else {
            or(
                get(inspector, "filename").map_err(|e| e.display())?,
                job.sha256.clone(),
            )
        };
        let PyValue::Str(filename) = filename else {
            return Err(format!(
                "'{}' object has no attribute 'translate'",
                copilot_upstream::py::type_name(&filename)
            ));
        };
        let reference = match existing.filter(|e| !e.is_empty()) {
            Some(r) => r,
            None => cape
                .submit(
                    &st.settings,
                    sample,
                    &filename,
                    &st.settings.cape_package,
                    &job.customer_code,
                    &job.source,
                )
                .await
                .map_err(|e| e.text())?,
        };
        cape.wait_for_report(&reference)
            .await
            .map_err(|e| e.text())?;
        let report = cape.get_report(&reference).await.map_err(|e| e.text())?;
        crate::cape::summarize(&report).map_err(|e| e.display())
    }
    .await;
    match outcome {
        Ok(summary) => Some(summary),
        Err(e) => {
            tracing::error!(
                "detonation failed for {}: {e}",
                job.sha().chars().take(12).collect::<String>()
            );
            None
        }
    }
}

/// `_sandbox_available()`.
async fn sandbox_available(settings: &Settings) -> bool {
    match backend(settings) {
        None => false,
        Some(cape) => cape.available().await,
    }
}

/// `Verdict(value)`.
fn verdict_of(value: &PyValue) -> PyResult<String> {
    match value.as_str() {
        Some(v @ (verdict::CLEAN | verdict::SUSPICIOUS | verdict::MALICIOUS)) => Ok(v.to_string()),
        _ => Err(PyExc::ValueError(format!(
            "{} is not a valid Verdict",
            value.py_repr()
        ))),
    }
}

async fn pipeline(st: &FileAnalysisState, job: &mut Job, args: RunArgs) -> PyResult<()> {
    let settings = st.settings.clone();
    // 1. The sample.
    let sample: Vec<u8> = match args.sample {
        Some(b) => b.to_vec(),
        None => match resolve_sample(st, job, &args.refs).await {
            Some(b) => b,
            None => {
                job.status = "failed".into();
                job.static_status = "failed".into();
                job.error = Some("sample could not be retrieved (file gone?)".into());
                save(st, job).await?;
                return Ok(());
            }
        },
    };

    // 2. Tier 1.
    job.status = "running".into();
    job.static_status = "running".into();
    save(st, job).await?;
    let inspector_job = dict(vec![
        ("sha256", job.sha256.clone()),
        ("filename", py::s(job.filename.clone())),
        ("customer_code", py::s(job.customer_code.clone())),
        ("context", py::empty_dict()),
    ]);
    let (inspector, previews) =
        inspector::inspect_with_retry(&settings, &sample, &inspector_job).await?;
    job.sha256 = get_or(&inspector, "sha256", job.sha256.clone())?;
    job.hardened = get_or(&inspector, "hardened", PyValue::Bool(true))?.truthy();
    let static_hint = get_or(&inspector, "verdict_hint", py::s("clean"))?;
    let mut preview_names = Vec::new();
    for (name, data) in previews {
        store::save_preview(st, &job.customer_code, &job.sha(), &name, data).await?;
        preview_names.push(py::s(name));
    }

    // 3. The VirusTotal hash lookup.
    let mut reputation = if args.reputation_mode == "off" {
        Some(reputation::skipped())
    } else {
        reputation::lookup_only(&settings, &st.threat_intel, &job.sha()).await
    };
    let submit_pending = args.reputation_mode == "upload"
        && reputation
            .as_ref()
            .is_some_and(|r| !field(r, "found").truthy())
        && !sample.is_empty();
    if submit_pending {
        reputation = Some(reputation::pending(&job.sha()));
    }
    let reputation_value = reputation.clone().unwrap_or(PyValue::None);

    // 4. The interim result.
    job.sandbox_enabled = sandbox_available(&settings).await;
    job.static_status = "done".into();
    let static_verdict = verdict_of(&static_hint)?;
    job.verdict = Some(static_verdict.clone());
    let interim = dict(vec![
        ("job", job.dump()),
        ("inspector", inspector.clone()),
        ("sandbox", PyValue::None),
        ("reputation", reputation_value.clone()),
        ("preview_urls", PyValue::List(preview_names.clone())),
        ("engine_version", py::int(store::ENGINE_VERSION)),
    ]);
    store::save_result(st, &job.customer_code, &job.sha(), &interim).await?;
    save(st, job).await?;

    // 5. Tier 2.
    let mut sandbox_summary: Option<PyValue> = None;
    if job.sandbox_enabled
        && args.tiers.iter().any(|t| t == "dynamic")
        && should_escalate(&inspector)?
    {
        job.dynamic_status = Some("running".into());
        save(st, job).await?;
        sandbox_summary = detonate(st, &sample, &inspector, job).await;
        job.dynamic_status = Some(
            if sandbox_summary.is_some() {
                "done"
            } else {
                "failed"
            }
            .into(),
        );
    }

    // 6. The final verdict.
    let verdict_reason = verdict::explain_verdict(
        &static_verdict,
        sandbox_summary.as_ref(),
        reputation.as_ref(),
        Some(&inspector),
    )?;
    let merged = verdict::merge_all(
        &static_verdict,
        sandbox_summary.as_ref(),
        reputation.as_ref(),
        settings.vt_threshold,
    )?;
    job.verdict = Some(verdict_of(&py::s(merged))?);
    job.status = "done".into();
    let result = dict(vec![
        ("job", job.dump()),
        ("inspector", inspector.clone()),
        ("sandbox", sandbox_summary.clone().unwrap_or(PyValue::None)),
        ("reputation", reputation_value),
        ("preview_urls", PyValue::List(preview_names)),
        ("engine_version", py::int(store::ENGINE_VERSION)),
        ("verdict_reason", py::s(verdict_reason)),
    ]);
    store::save_result(st, &job.customer_code, &job.sha(), &result).await?;
    save(st, job).await?;

    // 7. The detached upload.
    if submit_pending {
        let st = st.clone();
        let (job_id, customer, sha, filename) = (
            job.job_id.clone(),
            job.customer_code.clone(),
            job.sha(),
            job.filename.clone(),
        );
        tokio::spawn(async move {
            let permit = st.uploads.clone().acquire_owned().await;
            submit_and_patch(
                &st,
                &job_id,
                &customer,
                &sha,
                &sample,
                &filename,
                &static_verdict,
            )
            .await;
            drop(permit);
        });
    }
    Ok(())
}

/// `_submit_and_patch(...)`: upload, wait, then patch the stored result and
/// job (every failure only logged).
async fn submit_and_patch(
    st: &FileAnalysisState,
    _job_id: &str,
    customer_code: &str,
    sha256: &str,
    sample: &[u8],
    filename: &str,
    static_verdict: &str,
) {
    let outcome: PyResult<()> = async {
        let Some(rep) =
            reputation::submit_and_wait(&st.settings, &st.threat_intel, sha256, sample, filename)
                .await
        else {
            return Ok(());
        };
        let Some(result) = store::load_result(st, customer_code, sha256).await? else {
            return Ok(());
        };
        if !result.truthy() {
            return Ok(());
        }
        let PyValue::Dict(mut pairs) = result else {
            return Err(PyExc::TypeError(
                "'list' object does not support item assignment".into(),
            ));
        };
        set(&mut pairs, "reputation", rep.clone());
        let current = PyValue::Dict(pairs.clone());
        let sandbox = get(&current, "sandbox")?;
        let inspector = get(&current, "inspector")?;
        let reason = verdict::explain_verdict(
            static_verdict,
            Some(&sandbox).filter(|s| !matches!(s, PyValue::None)),
            Some(&rep),
            Some(&inspector).filter(|s| !matches!(s, PyValue::None)),
        )?;
        set(&mut pairs, "verdict_reason", py::s(reason));
        let job = or(get_or(&current, "job", py::empty_dict())?, py::empty_dict());
        let PyValue::Dict(mut job_pairs) = job else {
            return Err(PyExc::TypeError(
                "object does not support item assignment".into(),
            ));
        };
        let merged = verdict::merge_all(
            static_verdict,
            Some(&sandbox).filter(|s| !matches!(s, PyValue::None)),
            Some(&rep),
            st.settings.vt_threshold,
        )?;
        set(&mut job_pairs, "verdict", py::s(merged));
        set(&mut job_pairs, "updated_at", py::s(now()));
        let job = PyValue::Dict(job_pairs);
        set(&mut pairs, "job", job.clone());
        store::save_result(st, customer_code, sha256, &PyValue::Dict(pairs)).await?;
        store::save_job(st, &job).await?;
        tracing::info!(
            "[reputation] patched VirusTotal result for {} (found={})",
            sha256.chars().take(12).collect::<String>(),
            str_of(field(&rep, "found"))
        );
        Ok(())
    }
    .await;
    if let Err(e) = outcome {
        tracing::warn!(
            "detached VT submit failed for {}: {}",
            sha256.chars().take(12).collect::<String>(),
            e.display()
        );
    }
}

/// `d[key] = value` (an existing key keeps its place).
fn set(pairs: &mut Vec<(String, PyValue)>, key: &str, value: PyValue) {
    match pairs.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => pairs.push((key.to_string(), value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn escalation_follows_python() {
        let t = |s: &str| should_escalate(&loads(s).unwrap());
        assert!(t(r#"{"filetype": "pe"}"#).unwrap());
        assert!(!t(r#"{"filetype": "text"}"#).unwrap());
        assert!(t(r#"{"filetype": "text", "flags": ["html_smuggling"]}"#).unwrap());
        assert!(t(r#"{"filetype": "image"}"#).unwrap());
        assert!(t(r#"{"filetype": [1]}"#).is_err());
        assert!(t(r#"{"filetype": "text", "flags": 5}"#).is_err());
        assert_eq!(
            verdict_of(&py::s("CLEAN")).unwrap_err().text(),
            "'CLEAN' is not a valid Verdict"
        );
        assert_eq!(
            verdict_of(&py::int(5)).unwrap_err().text(),
            "5 is not a valid Verdict"
        );
    }

    #[test]
    fn timestamps_are_isoformat() {
        let t = now();
        assert!(t.ends_with("+00:00"), "{t}");
        assert_eq!(new_job_id().len(), 32);
    }
}
