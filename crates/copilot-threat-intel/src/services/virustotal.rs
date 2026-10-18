//! VirusTotal: the IoC lookup of `app/threat_intel/services/socfortress.py`
//! (`invoke_virustotal_api`) and the file analysis of
//! `services/virustotal_file.py` (submit, analysis status, file report,
//! submit-and-wait).

use std::sync::LazyLock;
use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::{PyExc, PyResult, get, getitem, type_name};
use http::Method;
use regex::Regex;

use crate::ThreatIntelState;
use crate::httpx::{self, FileField, HttpxError, Request, Response};
use crate::py::contains;
use crate::schema::{
    ANALYSIS_DATA, ANALYSIS_RESPONSE, REPORT_DATA, REPORT_RESPONSE, SUBMISSION_RESPONSE,
    VT_RESPONSE, cut_repr, model_repr,
};

/// Python's `$` is the end or just before a final newline; `\s` of a `str`
/// pattern is `str.isspace()` (Unicode White_Space and the C0 separators).
static PATTERNS: LazyLock<Option<[Regex; 4]>> = LazyLock::new(|| {
    Some([
        Regex::new(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\n?\z").ok()?,
        Regex::new(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\n?\z").ok()?,
        Regex::new(r"^[a-fA-F0-9]{32}\n?\z|^[a-fA-F0-9]{40}\n?\z|^[a-fA-F0-9]{64}\n?\z").ok()?,
        Regex::new(r"^(?:https?|ftp)://[^\s\x1c-\x1f/$.?#].[^\s\x1c-\x1f]*\n?\z").ok()?,
    ])
});

fn matches(which: usize, s: &str) -> bool {
    PATTERNS.as_ref().is_some_and(|p| p[which].is_match(s))
}

/// `determine_ioc_type(ioc_value)`: the endpoint, or its 400.
pub fn determine_ioc_type(ioc: &str) -> PyResult<String> {
    if matches(0, ioc) {
        Ok(format!("/ip_addresses/{ioc}"))
    } else if matches(1, ioc) {
        Ok(format!("/domains/{ioc}"))
    } else if matches(2, ioc) {
        Ok(format!("/files/{ioc}"))
    } else if matches(3, ioc) {
        Err(PyExc::http(400, "URL scanning is currently not supported."))
    } else {
        Err(PyExc::http(
            400,
            "Invalid IOC value provided. Only IP addresses, domains, URLs, and hashes are \
             supported.",
        ))
    }
}

/// `invoke_virustotal_api(url, api_key, request)`: `GET
/// {connector_url}{endpoint}` with `x-apikey`; an error status, an answer
/// that is not JSON or not `VirusTotalResponse` is raised as it is.
pub async fn lookup(url: &str, api_key: Option<&str>, ioc: &str) -> PyResult<PyValue> {
    let endpoint = determine_ioc_type(ioc)?;
    let response = httpx::send(
        Request::new(Method::GET, format!("{url}{endpoint}")).header("x-apikey", api_key),
    )
    .await
    .map_err(HttpxError::into_py)?;
    response.raise_for_status().map_err(HttpxError::into_py)?;
    let data = response.json()?;
    // `VirusTotalResponse.parse_obj(…)`.
    copilot_upstream::model::validate(&VT_RESPONSE, &data).map_err(|e| match e {
        copilot_upstream::model::Invalid::Errors(errors) => PyExc::Validation(
            copilot_upstream::model::format_validation_error(VT_RESPONSE.name, &errors),
        ),
        copilot_upstream::model::Invalid::Abort(s, d) => PyExc::Http(s, d),
    })
}

/// The `UploadFile` a file route received.
#[derive(Debug, Clone)]
pub struct Upload {
    /// `file.filename`.
    pub filename: String,
    /// `file.content_type`.
    pub content_type: Option<String>,
    /// `await file.read()`.
    pub content: Vec<u8>,
}

/// `str(value)` of an error message picked out of an answer.
fn text_of(v: &PyValue) -> String {
    v.py_str()
}

/// `submit_file_to_virustotal(api_key, file, request)`.
pub async fn submit(
    st: &ThreatIntelState,
    api_key: &str,
    file: &Upload,
    password: Option<&str>,
) -> PyResult<PyValue> {
    tracing::info!(
        "Submitting file {} to VirusTotal (size: {} bytes)",
        file.filename,
        file.content.len()
    );
    let data = match password.filter(|p| !p.is_empty()) {
        Some(p) => vec![("password".to_string(), p.to_string())],
        None => Vec::new(),
    };
    let sent = httpx::send(
        Request::new(Method::POST, format!("{}/files", st.urls.virustotal))
            .header("accept", Some("application/json"))
            .header("x-apikey", Some(api_key))
            .multipart(
                data,
                vec![FileField {
                    name: "file".into(),
                    filename: Some(file.filename.clone()),
                    content_type: "application/octet-stream".into(),
                    content: file.content.clone(),
                }],
            )
            .timeout(Duration::from_secs(300)),
    )
    .await;
    let response = match sent {
        Ok(r) => r,
        Err(e) if e.is_request_error() => {
            return Err(PyExc::http(
                500,
                format!("Network error occurred: {}", e.message),
            ));
        }
        Err(e) => {
            return Err(PyExc::http(
                500,
                format!("Unexpected error occurred: {}", e.message),
            ));
        }
    };
    if response.raise_for_status().is_err() {
        return Err(submission_failed(&response)?);
    }
    let accepted = (|| -> PyResult<PyValue> {
        let body = response.json()?;
        let data = getitem(&body, "data")?.clone();
        construct(
            &SUBMISSION_RESPONSE,
            &kwargs(vec![
                ("data", data),
                ("success", PyValue::Bool(true)),
                (
                    "message",
                    PyValue::Str(format!(
                        "File {} submitted successfully for analysis",
                        file.filename
                    )),
                ),
            ]),
        )
    })();
    accepted.map_err(|e| PyExc::http(500, format!("Unexpected error occurred: {}", e.text())))
}

/// The `except httpx.HTTPStatusError` block of the submission: its
/// `HTTPException`, or (`Err`) the exception the block itself raises.
fn submission_failed(response: &Response) -> PyResult<PyExc> {
    let text = response.text();
    let message = match response.json() {
        Err(_) => PyValue::Str(text.clone()),
        Ok(body) => {
            let error = get(&body, "error")?
                .cloned()
                .unwrap_or(PyValue::Dict(Vec::new()));
            get(&error, "message")?
                .cloned()
                .unwrap_or_else(|| PyValue::Str(text.clone()))
        }
    };
    Ok(match response.status {
        400 => {
            if contains(&message, "Invalid zip file")? {
                PyExc::http(
                    400,
                    "File format not supported or corrupted. VirusTotal accepts executables, \
                     documents, archives, and other common file types.",
                )
            } else if contains(&message, "File too large")? {
                PyExc::http(
                    413,
                    "File too large. Maximum file size is 32MB for free API keys, 650MB for \
                     premium.",
                )
            } else {
                let PyValue::Str(m) = &message else {
                    return Err(PyExc::AttributeError(format!(
                        "'{}' object has no attribute 'lower'",
                        type_name(&message)
                    )));
                };
                if copilot_jinja::unicode::lower(m).contains("missing") {
                    PyExc::http(
                        400,
                        "File upload failed. Please ensure the file is properly formatted and try \
                         again.",
                    )
                } else {
                    PyExc::http(400, format!("Bad request: {m}"))
                }
            }
        }
        429 => PyExc::http(429, "Rate limit exceeded. Please try again later."),
        413 => PyExc::http(
            413,
            "File too large. Maximum file size is 32MB for free API keys.",
        ),
        status => PyExc::http(
            status,
            format!("Failed to submit file: {}", text_of(&message)),
        ),
    })
}

/// `get_file_analysis_status` / `get_file_report`: `GET {vt}/{kind}/{id}`
/// (30 s); an error status is the upstream status with the answer's text,
/// a transport failure the 500 `Network error occurred`, anything else
/// raised as it is.
async fn fetch(
    st: &ThreatIntelState,
    api_key: &str,
    path: String,
    failed: impl Fn(&Response) -> PyExc,
) -> PyResult<PyValue> {
    let sent = httpx::send(
        Request::new(Method::GET, format!("{}{path}", st.urls.virustotal))
            .header("x-apikey", Some(api_key))
            .timeout(Duration::from_secs(30)),
    )
    .await;
    let response = match sent {
        Ok(r) => r,
        Err(e) if e.is_request_error() => {
            return Err(PyExc::http(
                500,
                format!("Network error occurred: {}", e.message),
            ));
        }
        Err(e) => return Err(e.into_py()),
    };
    if response.raise_for_status().is_err() {
        return Err(failed(&response));
    }
    let body = response.json()?;
    Ok(getitem(&body, "data")?.clone())
}

/// `get_file_analysis_status(api_key, analysis_id)`.
pub async fn analysis_status(
    st: &ThreatIntelState,
    api_key: &str,
    analysis_id: &str,
) -> PyResult<PyValue> {
    tracing::info!("Checking analysis status for ID: {analysis_id}");
    let data = fetch(st, api_key, format!("/analyses/{analysis_id}"), |r| {
        PyExc::http(
            r.status,
            format!("Failed to get analysis status: {}", r.text()),
        )
    })
    .await?;
    construct(
        &ANALYSIS_RESPONSE,
        &kwargs(vec![
            ("data", data),
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("Analysis status retrieved successfully".into()),
            ),
        ]),
    )
}

/// `get_file_report(api_key, file_id)`.
pub async fn file_report(st: &ThreatIntelState, api_key: &str, file_id: &str) -> PyResult<PyValue> {
    tracing::info!("Getting file report for ID: {file_id}");
    let data = fetch(st, api_key, format!("/files/{file_id}"), |r| {
        if r.status == 404 {
            PyExc::http(404, "File not found or not yet analyzed")
        } else {
            PyExc::http(r.status, format!("Failed to get file report: {}", r.text()))
        }
    })
    .await?;
    construct(
        &REPORT_RESPONSE,
        &kwargs(vec![
            ("data", data),
            ("success", PyValue::Bool(true)),
            (
                "message",
                PyValue::Str("File report retrieved successfully".into()),
            ),
        ]),
    )
}

/// `submit_and_wait_for_analysis(...)`: the submission, then the status
/// every `poll_interval` seconds until `max_wait_time`. A completed analysis
/// is answered as `FileReportResponse(data=<FileAnalysisData>)`, which
/// Pydantic refuses (a model of another class): the `ValidationError`
/// Python raises there; past the wait, the 408.
pub async fn submit_and_wait(
    st: &ThreatIntelState,
    api_key: &str,
    file: &Upload,
    password: Option<&str>,
    max_wait_time: i64,
    poll_interval: i64,
) -> PyResult<PyValue> {
    let submission = submit(st, api_key, file, password).await?;
    let analysis_id = getitem(getitem(&submission, "data")?, "id")?.py_str();
    tracing::info!("File submitted, analysis ID: {analysis_id}. Waiting for completion...");
    let mut waited = 0;
    while waited < max_wait_time {
        let status = analysis_status(st, api_key, &analysis_id).await?;
        let data = getitem(&status, "data")?;
        let state = getitem(getitem(data, "attributes")?, "status")?;
        if state.as_str() == Some("completed") {
            let repr = model_repr(&ANALYSIS_DATA, data);
            return Err(PyExc::Validation(format!(
                "1 validation error for FileReportResponse\ndata\n  Input should be a valid \
                 dictionary or instance of {} [type=model_type, input_value={}, \
                 input_type={}]\n    For further information visit \
                 https://errors.pydantic.dev/{}/v/model_type",
                REPORT_DATA.name,
                cut_repr(&repr),
                ANALYSIS_DATA.name,
                copilot_upstream::model::PYDANTIC_VERSION
            )));
        }
        tracing::info!(
            "Analysis status: {}. Waiting {poll_interval} seconds...",
            state.py_str()
        );
        tokio::time::sleep(Duration::from_secs(
            u64::try_from(poll_interval).unwrap_or(0),
        ))
        .await;
        waited += poll_interval;
    }
    Err(PyExc::http(
        408,
        format!(
            "Analysis did not complete within {max_wait_time} seconds. You can check the status \
             later using analysis ID: {analysis_id}"
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_types_follow_pythons_patterns() {
        assert_eq!(
            determine_ioc_type("1.2.3.4").unwrap(),
            "/ip_addresses/1.2.3.4"
        );
        assert_eq!(
            determine_ioc_type("1.2.3.4\n").unwrap(),
            "/ip_addresses/1.2.3.4\n"
        );
        assert_eq!(determine_ioc_type("evil.co").unwrap(), "/domains/evil.co");
        assert_eq!(
            determine_ioc_type(&"a".repeat(32)).unwrap(),
            format!("/files/{}", "a".repeat(32))
        );
        let status = |s: &str| match determine_ioc_type(s) {
            Err(PyExc::Http(400, d)) => d,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            status("http://x.y/z"),
            "URL scanning is currently not supported."
        );
        assert_eq!(
            status("ftp://a b"),
            "URL scanning is currently not supported."
        );
        assert_eq!(
            status("http://\u{1c}b"),
            "Invalid IOC value provided. Only IP addresses, domains, URLs, and hashes are supported."
        );
        assert_eq!(
            determine_ioc_type("EVIL.CO\n").unwrap(),
            "/domains/EVIL.CO\n"
        );
        assert_eq!(
            status("1.2.3.4\n\n"),
            "Invalid IOC value provided. Only IP addresses, domains, URLs, and hashes are supported."
        );
    }
}
