//! `services/inspector_client.py`: Tier 1 is one multipart `POST
//! {INSPECTOR_URL}/inspect` to the inspector-runner sidecar — `data={"job":
//! json.dumps(job)}` then `files={"sample": ("sample", bytes)}`, httpx's
//! encoder, `INSPECTOR_HTTP_TIMEOUT` — and the orchestrator's
//! `_inspect_with_retry` around it (a 429 is "busy": up to five tries, `2 **
//! attempt` seconds apart).
//!
//! An httpx failure, an error status or an answer that is not JSON is the
//! fail-closed result (`analysis_incomplete`, `verdict_hint: suspicious`, the
//! exception's text as `error`); what Python lets escape (an invalid URL,
//! `.pop` on an answer that is not a dict, a preview that is not base64)
//! fails the job with its text.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::httpx::{self, FileField, Request};
use copilot_upstream::json::{Dumps, py_dumps_allow_nan};
use copilot_upstream::py::{PyExc, PyResult, type_name};
use http::Method;

use crate::Settings;
use crate::py::{self, dict, get_or};

/// The inspector's answer: its result (without `previews_b64`) and the
/// decoded previews, in the answer's order.
pub type Inspected = (PyValue, Vec<(String, Vec<u8>)>);

enum Outcome {
    Done(Inspected),
    Busy,
}

/// `base64.b64decode(value)` of a `json.loads` value.
fn b64decode(value: &PyValue) -> PyResult<Vec<u8>> {
    match value {
        PyValue::Str(text) => {
            if !text.is_ascii() {
                return Err(PyExc::ValueError(
                    "string argument should contain only ASCII characters".into(),
                ));
            }
            copilot_auth::pybase64::a2b_base64(text.as_bytes())
                .map_err(|e| PyExc::Other("Error", e.to_string()))
        }
        other => Err(PyExc::TypeError(format!(
            "argument should be a bytes-like object or ASCII string, not '{}'",
            type_name(other)
        ))),
    }
}

fn attr_error(value: &PyValue, attr: &str) -> PyExc {
    PyExc::AttributeError(format!(
        "'{}' object has no attribute '{attr}'",
        type_name(value)
    ))
}

/// `inspect(sample_bytes, job)`.
async fn inspect(settings: &Settings, sample: &[u8], job: &PyValue) -> PyResult<Outcome> {
    let request = Request::new(Method::POST, format!("{}/inspect", settings.inspector_url))
        .timeout(Duration::from_secs(settings.inspector_timeout))
        .multipart(
            vec![("job".to_string(), py_dumps_allow_nan(job, Dumps::DEFAULT))],
            vec![FileField {
                name: "sample".into(),
                filename: Some("sample".into()),
                content_type: crate::mimetypes::httpx_content_type("sample"),
                content: sample.to_vec(),
            }],
        );
    let failed = |error: String| -> PyResult<Outcome> {
        tracing::error!("inspector call failed: {error}");
        Ok(Outcome::Done((
            dict(vec![
                ("sha256", get_or(job, "sha256", py::s(""))?),
                ("filename", get_or(job, "filename", py::s(""))?),
                ("customer_code", get_or(job, "customer_code", py::s(""))?),
                ("filetype", py::s("unknown")),
                ("analysis_incomplete", PyValue::Bool(true)),
                ("flags", PyValue::List(vec![py::s("analysis_incomplete")])),
                ("verdict_hint", py::s("suspicious")),
                ("error", py::s(error)),
            ]),
            Vec::new(),
        )))
    };
    let resp = match httpx::send(request).await {
        Ok(r) => r,
        Err(e) if e.is_http_error() => return failed(e.message),
        Err(e) => return Err(e.into_py()),
    };
    if resp.status == 429 {
        return Ok(Outcome::Busy);
    }
    if let Err(e) = resp.raise_for_status() {
        return failed(e.message);
    }
    let payload = match resp.json() {
        Ok(p) => p,
        Err(e) => return failed(e.text()),
    };
    let PyValue::Dict(mut pairs) = payload else {
        // `payload.pop("previews_b64", {})`: a list's `pop` takes one argument.
        if let PyValue::List(_) = payload {
            return Err(PyExc::TypeError(
                "pop expected at most 1 argument, got 2".into(),
            ));
        }
        return Err(attr_error(&payload, "pop"));
    };
    let previews_b64 = match pairs.iter().position(|(k, _)| k == "previews_b64") {
        Some(i) => pairs.remove(i).1,
        None => py::empty_dict(),
    };
    let previews_b64 = py::or(previews_b64, py::empty_dict());
    let PyValue::Dict(entries) = &previews_b64 else {
        return Err(attr_error(&previews_b64, "items"));
    };
    let mut previews = Vec::with_capacity(entries.len());
    for (name, b64) in entries {
        previews.push((name.clone(), b64decode(b64)?));
    }
    Ok(Outcome::Done((PyValue::Dict(pairs), previews)))
}

/// The orchestrator's `_inspect_with_retry(sample_bytes, inspector_job)`.
pub async fn inspect_with_retry(
    settings: &Settings,
    sample: &[u8],
    job: &PyValue,
) -> PyResult<Inspected> {
    for attempt in 0..5u32 {
        match inspect(settings, sample, job).await? {
            Outcome::Done(done) => return Ok(done),
            Outcome::Busy => tokio::time::sleep(Duration::from_secs(1 << attempt)).await,
        }
    }
    let PyValue::Dict(mut pairs) = job.clone() else {
        return Err(PyExc::TypeError(
            "'NoneType' object is not a mapping".into(),
        ));
    };
    for (k, v) in [
        ("filetype", py::s("unknown")),
        ("analysis_incomplete", PyValue::Bool(true)),
        ("flags", PyValue::List(vec![py::s("analysis_incomplete")])),
        ("verdict_hint", py::s("suspicious")),
    ] {
        match pairs.iter_mut().find(|(key, _)| key == k) {
            Some(slot) => slot.1 = v,
            None => pairs.push((k.to_string(), v)),
        }
    }
    Ok((PyValue::Dict(pairs), Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previews_decode_like_b64decode() {
        assert_eq!(b64decode(&py::s("aGk=")).unwrap(), b"hi");
        assert_eq!(
            b64decode(&py::s("aGk")).unwrap_err().text(),
            "Incorrect padding"
        );
        assert_eq!(
            b64decode(&py::int(5)).unwrap_err().text(),
            "argument should be a bytes-like object or ASCII string, not 'int'"
        );
        assert_eq!(
            b64decode(&py::s("é")).unwrap_err().text(),
            "string argument should contain only ASCII characters"
        );
    }
}
