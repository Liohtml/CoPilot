//! `invoke_mimecast` past the region discovery: what
//! `app/integrations/mimecast/services/mimecast.py` does once
//! `get_base_url` answered, had the region's `api` been the string Mimecast
//! sent (it is a Pydantic `HttpUrl`, and `base_url + auth_keys.URI` is the
//! `TypeError` every Python run ends in — RUST_MIGRATION.md §4, "Python
//! fails, Rust works").
//!
//! 1. `get_checkpoint_filename` / `get_log_file_path` (the files of
//!    [`super::files`]);
//! 2. `get_mta_siem_logs`: the page token read from the checkpoint, the
//!    request signed (`HMAC-SHA1` over `date:req_id:URI:APP_KEY` with the
//!    base64-decoded secret — a bad secret is `b64decode`'s `ValueError`,
//!    outside the `try`), then `requests.post(url=base_url + URI,
//!    headers=…, data=json.dumps(body), timeout=60)` — any failure the 400
//!    `Unable to retrieve MTA SIEM logs from Mimecast integration.`;
//! 3. `process_response`: an `application/json` answer means no more logs;
//!    an `application/octet-stream` one names its file
//!    (`Content-Disposition`'s `="…"`), carries the next token
//!    (`mc-siem-token`, written to the checkpoint) and is written by
//!    `write_log_file` — a `.zip` extracted into a directory of that name
//!    (any failure the 400 `Unable to extract zip file.`), anything else
//!    the `TypeError` of writing bytes to a text file (the empty file
//!    stays, as in Python); a missing header is its `KeyError`;
//! 4. the log directory walked as `os.listdir` lists it: every file of each
//!    sub-directory read line by line (`convert_to_json`), each line one
//!    event through the Event Shipper, the file deleted; a plain file in
//!    the directory is Python's crash (the `else` branch calls
//!    `process_log_file` without its customer code);
//! 5. `delete_log_directory` (its `OSError` the 400 naming `strerror`).

use std::path::Path;

use base64::Engine as _;
use copilot_auth::pyvalue::{PyValue, str_repr};
use copilot_upstream::http::{PyHttp, PyRequest, PyResponse};
use copilot_upstream::json::{Dumps, py_dumps};
use copilot_upstream::model::field;
use copilot_upstream::py::PyExc;
use hmac::{Hmac, Mac};
use http::Method;
use sha1::Sha1;

use super::files::{self, CustomerFiles};
use super::zip;
use crate::ModulesState;
use crate::error::{Fail, FailResult};

const SIEM_LOGS_FAILED: &str = "Unable to retrieve MTA SIEM logs from Mimecast integration.";
const ZIP_FAILED: &str = "Unable to extract zip file.";

/// `run_blocking(requests.post, …, timeout=DEFAULT_HTTP_TIMEOUT)`: 60 s,
/// TLS verified, requests' headers in their order.
pub fn requests_client() -> Result<PyHttp, PyExc> {
    let timeout = std::time::Duration::from_secs(60);
    PyHttp::new(timeout, true)
        .and_then(|c| c.with_exact_headers(timeout, true))
        .map_err(|e| PyExc::Other("RuntimeError", e.to_string()))
}

/// `hmac.new(b64decode(secret), text.encode(), sha1).digest()`, base64.
pub fn signature(secret: &[u8], text: &str) -> String {
    // HMAC takes a key of any length: this never fails.
    let Ok(mut mac) = <Hmac<Sha1> as Mac>::new_from_slice(secret) else {
        return String::new();
    };
    mac.update(text.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// A header of a `requests` answer: `http.client`'s latin-1 text, several
/// of the same name joined with `, ` (urllib3's `HTTPHeaderDict`).
pub fn header(resp: &PyResponse, name: &str) -> Option<String> {
    let values: Vec<String> = resp
        .headers
        .get_all(name)
        .iter()
        .map(|v| v.as_bytes().iter().map(|&b| char::from(b)).collect())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

/// `resp_headers[name]`: the `KeyError` of `CaseInsensitiveDict`.
fn required_header(resp: &PyResponse, name: &str) -> FailResult<String> {
    header(resp, name).ok_or_else(|| Fail::Py(PyExc::KeyError(str_repr(&name.to_lowercase()))))
}

/// `get_mta_siem_logs(checkpoint, base_url, keys)`.
async fn mta_siem_logs(
    files: &CustomerFiles,
    base_url: &str,
    keys: &PyValue,
) -> FailResult<PyResponse> {
    let text = |k: &str| field(keys, k).as_str().unwrap_or_default().to_string();
    let token = files::read_text(&files.checkpoint)?;
    let body = PyValue::Dict(vec![(
        "data".into(),
        PyValue::List(vec![PyValue::Dict(vec![
            ("type".into(), PyValue::Str("MTA".into())),
            ("compress".into(), PyValue::Bool(true)),
            ("token".into(), PyValue::Str(token)),
        ])]),
    )]);
    let request_id = uuid::Uuid::new_v4().to_string();
    let request_date = super::hdr_date();
    let uri = text("URI");
    let unsigned = format!("{request_date}:{request_id}:{uri}:{}", text("APP_KEY"));
    let secret = super::b64decode(&text("SECRET_KEY"))?;
    let sig = signature(&secret, &unsigned);
    let data =
        py_dumps(&body, Dumps::DEFAULT).map_err(|e| Fail::Py(PyExc::ValueError(format!("{e}"))))?;
    let req = PyRequest::new(Method::POST, format!("{base_url}{uri}"))
        .header("Authorization", format!("MC {}:{sig}", text("ACCESS_KEY")))
        .header("x-mc-app-id", text("APP_ID"))
        .header("x-mc-date", request_date)
        .header("x-mc-req-id", request_id)
        .header("Content-Type", "application/json")
        .data(data);
    let failed = |e: PyExc| {
        tracing::error!(target: "copilot::integration_modules",
            "Unable to retrieve MTA SIEM logs from Mimecast integration. Exception: {}", e.display());
        Fail::Py(PyExc::http(400, SIEM_LOGS_FAILED))
    };
    let client = requests_client().map_err(failed)?;
    client.send(req).await.map_err(failed)
}

/// `write_log_file(filename, body)`.
fn write_log_file(path: &Path, body: &[u8]) -> FailResult<()> {
    if path.display().to_string().contains(".zip") {
        zip::extract_all(body, path).map_err(|e| {
            tracing::error!(target: "copilot::integration_modules",
                "Unable to extract zip file. Exception: {e}");
            Fail::Py(PyExc::http(400, ZIP_FAILED))
        })
    } else {
        // `aiofiles.open(filename, "w")` creates the file; writing `bytes`
        // to it is the `TypeError`.
        std::fs::write(path, b"").map_err(|e| files::os_error(&e, path))?;
        Err(Fail::other(
            "TypeError",
            "write() argument must be str, not bytes",
        ))
    }
}

/// `process_response(response, checkpoint, log_dir)`.
fn process_response(resp: &PyResponse, files: &CustomerFiles) -> FailResult<()> {
    let content_type = required_header(resp, "Content-Type")?;
    if content_type == "application/json" {
        tracing::info!(target: "copilot::integration_modules", "No more logs available");
        return Ok(());
    }
    if content_type != "application/octet-stream" {
        return Ok(());
    }
    let disposition = required_header(resp, "Content-Disposition")?;
    let mut parts = disposition.split("=\"");
    parts.next();
    let Some(quoted) = parts.next() else {
        return Err(Fail::Py(PyExc::IndexError(
            "list index out of range".into(),
        )));
    };
    // `[:-1]`: the closing quote (or whatever ends the text).
    let mut name: Vec<char> = quoted.chars().collect();
    name.pop();
    let name: String = name.into_iter().collect();
    let token = required_header(resp, "mc-siem-token")?;
    files::write_text(&files.checkpoint, &token)?;
    if name.contains(['/', '\0']) {
        // `os.path.join` would leave the customer's directory (§4).
        tracing::error!(target: "copilot::integration_modules",
            "Refusing the Mimecast log file name {name:?}");
        return Err(Fail::Py(PyExc::http(400, ZIP_FAILED)));
    }
    write_log_file(&files.log_dir.join(&name), &resp.body)
}

/// `process_log_file`: every line one event, then the file deleted.
async fn process_log_file(st: &ModulesState, path: &Path, code: &str) -> FailResult<()> {
    std::fs::metadata(path).map_err(|e| files::os_error(&e, path))?;
    if path.is_dir() {
        return Err(Fail::other(
            "IsADirectoryError",
            format!(
                "[Errno 21] Is a directory: {}",
                str_repr(&path.display().to_string())
            ),
        ));
    }
    let (lines, failure) = files::read_lines(path)?;
    for line in lines {
        let fields = files::convert_to_json(&line)
            .into_iter()
            .map(|(k, v)| (k, PyValue::Str(v)))
            .collect();
        let message = files::event_payload(code, fields)?;
        copilot_graylog::gelf::ship(&st.ctx.connectors, &message).await?;
    }
    if let Some(failure) = failure {
        return Err(failure);
    }
    match std::fs::remove_file(path) {
        Ok(()) => tracing::info!(target: "copilot::integration_modules",
            "Successfully deleted the file: {}", path.display()),
        Err(e) => tracing::error!(target: "copilot::integration_modules",
            "Error: {}. File: {}", files::strerror(&e), path.display()),
    }
    Ok(())
}

fn entries(dir: &Path) -> FailResult<Vec<String>> {
    let read = std::fs::read_dir(dir).map_err(|e| files::os_error(&e, dir))?;
    let mut out = Vec::new();
    for entry in read {
        let entry = entry.map_err(|e| files::os_error(&e, dir))?;
        out.push(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(out)
}

/// `invoke_mimecast` after the discovery answered with `base_url`.
pub async fn collect(
    st: &ModulesState,
    code: &str,
    keys: &PyValue,
    base_url: &str,
) -> FailResult<()> {
    let files = files::customer_files(&st.mimecast_dir, code)?;
    files.prepare()?;
    let resp = mta_siem_logs(&files, base_url, keys).await?;
    process_response(&resp, &files)?;
    let mut second_name_bound = false;
    for name in entries(&files.log_dir)? {
        let path = files.log_dir.join(&name);
        if path.is_dir() {
            for inner in entries(&path)? {
                second_name_bound = true;
                process_log_file(st, &path.join(&inner), code).await?;
            }
            tracing::info!(target: "copilot::integration_modules",
                "Log file path: {}", files.log_dir.display());
        } else {
            // `process_log_file(filename, filename2, log_file_path)`.
            return Err(if second_name_bound {
                Fail::other(
                    "TypeError",
                    "process_log_file() missing 1 required positional argument: 'customer_code'",
                )
            } else {
                Fail::other(
                    "UnboundLocalError",
                    "cannot access local variable 'filename2' where it is not associated with a \
                     value",
                )
            });
        }
    }
    if let Err(e) = std::fs::remove_dir_all(&files.log_dir) {
        return Err(Fail::Py(PyExc::http(
            400,
            format!(
                "Error: {}. Directory: {}",
                files::strerror(&e),
                files.log_dir.display()
            ),
        )));
    }
    tracing::info!(target: "copilot::integration_modules",
        "Successfully deleted the directory: {}", files.log_dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signature_is_python_s_hmac_sha1() {
        // hmac.new(b"secret-a", b"x", hashlib.sha1).digest(), base64.
        assert_eq!(signature(b"secret-a", "x"), "z0clzRbQp9Ysl9vnixto+XLAJeU=");
    }
}
