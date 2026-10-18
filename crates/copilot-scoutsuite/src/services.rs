//! `app/integrations/scoutsuite/services/scoutsuite.py` and the routes'
//! file work.
//!
//! **A scan** is `run_command`: `scout` with the route's arguments
//! (`construct_{aws,azure,gcp}_command`, the credentials as arguments, as
//! Python passes them), stdout and stderr piped, stdin inherited, in the
//! working directory, with this process's environment; a non-zero exit is
//! logged with its stderr. It starts once the answer is built (FastAPI runs
//! a background task after sending the answer) and nothing waits for it.
//! Python's child also holds the `.env` file's values (`load_dotenv` puts
//! them into `os.environ`); this process does not hand `.env` to children
//! (`copilot_core::env`'s rule) — under Compose `env_file` puts them into
//! both processes' environment (a §4 row).
//!
//! **The GCP key** is written as the route writes it: a fresh private
//! directory (`tempfile.mkdtemp(prefix="scoutsuite-gcp-cred-")`: the first
//! usable of `TMPDIR`, `TEMP`, `TMP`, `/tmp`, `/var/tmp`, `/usr/tmp` and the
//! working directory, eight random characters, mode `0700`), the file
//! `gcp-service-account.json` under its real path, removed with the
//! directory when the scan ends, however it ends.
//!
//! **The reports** are the `.html` entries of `scoutsuite-report/` in the
//! order the directory lists them (`os.listdir`), and a delete removes the
//! report and its two `scoutsuite-results/` scripts that exist (a directory
//! of that name, or a file that cannot be removed, is the bare 500 of
//! `os.remove`'s `OSError`).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;

use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_patch_tuesday::services::{LoadsError, json_loads_bytes};
use copilot_upstream::model::construct_star;
use copilot_upstream::py::PyExc;

use crate::ScoutState;
use crate::schema::{GCP_JSON, GCP_JSON_QUALNAME};

/// The credential file's name.
pub const GCP_KEY_FILE: &str = "gcp-service-account.json";
/// `mkdtemp`'s prefix.
pub const GCP_KEY_PREFIX: &str = "scoutsuite-gcp-cred-";

fn text(v: &PyValue, key: &str) -> String {
    match v.get(key) {
        Some(PyValue::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

/// `construct_aws_command(request)` (without the program).
pub fn aws_command(request: &PyValue) -> Vec<String> {
    vec![
        "aws".into(),
        "--access-key-id".into(),
        text(request, "access_key_id"),
        "--secret-access-key".into(),
        text(request, "secret_access_key"),
        "--report-name".into(),
        text(request, "report_name"),
        "--force".into(),
        "--no-browser".into(),
    ]
}

/// `construct_azure_command(request)` (without the program).
pub fn azure_command(request: &PyValue) -> Vec<String> {
    vec![
        "azure".into(),
        "--user-account".into(),
        "--tenant".into(),
        text(request, "tenant_id"),
        "--username".into(),
        text(request, "username"),
        "--password".into(),
        text(request, "password"),
        "--report-name".into(),
        text(request, "report_name"),
        "--force".into(),
        "--no-browser".into(),
    ]
}

/// `construct_gcp_command(request)` (without the program).
pub fn gcp_command(report_name: &str, file_path: &str) -> Vec<String> {
    vec![
        "gcp".into(),
        "--service-account".into(),
        file_path.into(),
        "--all-projects".into(),
        "--report-name".into(),
        report_name.into(),
        "--force".into(),
        "--no-browser".into(),
    ]
}

/// `run_command(command)`.
pub async fn run(program: &str, args: &[String], dir: &Path) {
    let child = tokio::process::Command::new(program)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let output = match child {
        Ok(child) => child.wait_with_output().await,
        Err(e) => Err(e),
    };
    match output {
        Ok(out) if out.status.success() => {
            tracing::info!("ScoutSuite report generated successfully");
        }
        Ok(out) => tracing::error!(
            "ScoutSuite report generation failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
        // Python's background task raises (`FileNotFoundError` for a
        // missing `scout`): the answer was already sent.
        Err(e) => tracing::error!("ScoutSuite report generation could not start: {e}"),
    }
}

/// The background task: the scan, then (GCP) the credential's directory
/// removed whatever happened.
pub fn spawn_scan(state: &ScoutState, cloud: &str, args: Vec<String>, cleanup: Option<PathBuf>) {
    tracing::info!("Generating {cloud} ScoutSuite report in the background");
    let program = state.program.to_string();
    let dir = state.dir.as_ref().clone();
    tokio::spawn(async move {
        run(&program, &args, &dir).await;
        if let Some(cred_dir) = cleanup {
            // `shutil.rmtree(cred_dir, ignore_errors=True)`.
            let _ = tokio::fs::remove_dir_all(&cred_dir).await;
            tracing::info!("Deleted GCP credentials temp directory");
        }
    });
}

/// `read_json_file(contents)` then `validate_json_data(data)`: `None`, or
/// what the route answers (the two 400s, or `json.loads`' `UnicodeDecodeError`
/// for the `ValueError` handler).
pub fn check_upload(contents: &[u8]) -> Result<(), PyExc> {
    let data = match json_loads_bytes(contents) {
        Ok(data) => data,
        Err(LoadsError::Json(e)) => {
            return Err(PyExc::http(400, format!("Invalid JSON file - {e}")));
        }
        Err(LoadsError::Unicode(e)) => return Err(PyExc::ValueError(e)),
    };
    construct_star(&GCP_JSON, GCP_JSON_QUALNAME, &data).map_err(|e| {
        PyExc::http(
            400,
            format!(
                "JSON file does not have the correct format and fields - {}",
                e.text()
            ),
        )
    })?;
    Ok(())
}

/// `str(OSError)` for a path: `[Errno N] strerror: 'path'`.
pub fn os_error(e: &std::io::Error, path: &Path) -> String {
    let strerror = e.to_string();
    let strerror = strerror
        .rsplit_once(" (os error ")
        .map_or(strerror.as_str(), |(s, _)| s)
        .to_string();
    match e.raw_os_error() {
        Some(n) => format!(
            "[Errno {n}] {strerror}: {}",
            str_repr(&path.to_string_lossy())
        ),
        None => strerror,
    }
}

/// `tempfile.gettempdir()`: the first candidate a file can be created in,
/// looked up once per process as Python caches it.
fn gettempdir() -> Option<&'static PathBuf> {
    static TEMPDIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    TEMPDIR
        .get_or_init(|| {
            let mut candidates: Vec<PathBuf> = ["TMPDIR", "TEMP", "TMP"]
                .iter()
                .filter_map(std::env::var_os)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .collect();
            candidates.extend(["/tmp", "/var/tmp", "/usr/tmp"].map(PathBuf::from));
            if let Ok(cwd) = std::env::current_dir() {
                candidates.push(cwd);
            }
            candidates.into_iter().find_map(|dir| {
                let dir = std::path::absolute(&dir).unwrap_or(dir);
                let probe = dir.join(random_name());
                let created = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&probe)
                    .is_ok();
                if created {
                    let _ = std::fs::remove_file(&probe);
                    Some(dir)
                } else {
                    None
                }
            })
        })
        .as_ref()
}

/// `_RandomNameSequence`: eight characters of `[a-z0-9_]`.
fn random_name() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    bytes[..8]
        .iter()
        .map(|b| char::from(CHARS[usize::from(*b) % CHARS.len()]))
        .collect()
}

/// `tempfile.mkdtemp(prefix=…)`: a new directory, mode `0700`.
pub fn mkdtemp(prefix: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let Some(base) = gettempdir() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No usable temporary directory found",
        ));
    };
    let mut last = None;
    for _ in 0..10_000 {
        let dir = base.join(format!("{prefix}{}", random_name()));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("No usable temporary file name found")))
}

/// `save_file_to_directory(contents, directory, "gcp-service-account.json")`:
/// the file under the directory's real path, or the 400 naming the
/// `OSError`.
pub fn save_credentials(contents: &[u8], directory: &Path) -> Result<PathBuf, PyExc> {
    let failed = |e: &std::io::Error, path: &Path| PyExc::http(400, os_error(e, path));
    std::fs::create_dir_all(directory).map_err(|e| failed(&e, directory))?;
    let base = std::fs::canonicalize(directory).map_err(|e| failed(&e, directory))?;
    let path = base.join(GCP_KEY_FILE);
    std::fs::write(&path, contents).map_err(|e| failed(&e, &path))?;
    Ok(path)
}

/// The `.html` entries of `scoutsuite-report/`, in the directory's order;
/// the 404 when it does not exist.
pub fn available_reports(state: &ScoutState) -> Result<Vec<String>, PyExc> {
    let dir = state.report_dir();
    tracing::info!("Checking directory: {}", dir.display());
    if !dir.exists() {
        return Err(PyExc::http(404, "Directory does not exist"));
    }
    let entries =
        std::fs::read_dir(&dir).map_err(|e| PyExc::Other("OSError", os_error(&e, &dir)))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| PyExc::Other("OSError", os_error(&e, &dir)))?;
        let name = entry.file_name();
        let lossy = name.to_string_lossy();
        if !lossy.ends_with(".html") {
            continue;
        }
        // A name that is not UTF-8 is a surrogate-escaped `str` in Python,
        // which the JSON answer cannot encode (a bare 500).
        let Some(name) = name.to_str() else {
            return Err(PyExc::Other(
                "UnicodeEncodeError",
                format!("'utf-8' codec can't encode a surrogate in {lossy:?}"),
            ));
        };
        out.push(name.to_string());
    }
    Ok(out)
}

/// `os.path.splitext(name)[0]`: the name without its last extension (a dot
/// that only leading dots precede is no extension).
pub fn splitext_base(name: &str) -> &str {
    let sep = name.rfind('/').map_or(0, |i| i + 1);
    match name.rfind('.') {
        Some(dot) if dot > sep && name[sep..dot].chars().any(|c| c != '.') => &name[..dot],
        _ => name,
    }
}

/// `delete_report(report_name)`: the report, then its exceptions and its
/// results script, each removed when it exists.
pub fn delete_report(state: &ScoutState, report_name: &str) -> Result<(), PyExc> {
    let base = splitext_base(report_name);
    let reports = state.report_dir();
    let results = reports.join("scoutsuite-results");
    for path in [
        reports.join(report_name),
        results.join(format!("scoutsuite_exceptions_{base}.js")),
        results.join(format!("scoutsuite_results_{base}.js")),
    ] {
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| PyExc::Other("OSError", os_error(&e, &path)))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_errors_read_like_python() {
        let e = std::io::Error::from_raw_os_error(21);
        assert_eq!(
            os_error(&e, Path::new("scoutsuite-report/x.html")),
            "[Errno 21] Is a directory: 'scoutsuite-report/x.html'"
        );
    }

    #[test]
    fn temporary_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = mkdtemp(GCP_KEY_PREFIX).unwrap();
        let name = dir.file_name().unwrap().to_str().unwrap().to_string();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let path = save_credentials(b"{}", &dir).unwrap();
        let written = std::fs::read(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(name.starts_with(GCP_KEY_PREFIX));
        let random = &name[GCP_KEY_PREFIX.len()..];
        assert_eq!(random.len(), 8);
        assert!(
            random
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        );
        assert_eq!(mode, 0o700);
        assert_eq!(written, b"{}");
        assert!(path.ends_with(GCP_KEY_FILE));
    }
}
