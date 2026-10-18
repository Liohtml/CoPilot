//! `services/sandbox/cape.py`: the CAPEv2 REST client (`CapeBackend`) and
//! `summarize(report)`.
//!
//! Every call is `_request`: a fresh httpx client (`CAPE_HTTP_TIMEOUT`), the
//! `Authorization: Token …` header when a token is set, three attempts with
//! `asyncio.sleep(2 ** attempt)` after each transport failure or 5xx — the
//! last one too — then `TransportError("CAPE request failed after 3
//! retries: …")`; a 401 is `NotEnabled` at once. `summarize` reads the
//! report with Python's operations on its JSON (`crate::py`), so an odd
//! report fails where Python's fails (the detonation then counts as failed).

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::httpx::{self, FileField, HttpxError, Request, Response};
use copilot_upstream::py::{PyExc, PyResult, type_name};
use http::Method;

use crate::Settings;
use crate::py::{
    self, dict, empty_dict, empty_list, float_of, get, get_or, int_value, is_dict, isdigit, or,
    str_of,
};
use crate::verdict;

/// A CAPE failure as the orchestrator and the routes see it.
#[derive(Debug, Clone, PartialEq)]
pub enum CapeError {
    /// `NotEnabled` (a 401, or a disabled backend).
    NotEnabled(String),
    /// An httpx `HTTPError` (the retries' final `TransportError`).
    Http(HttpxError),
    /// Anything else (`RuntimeError`, `TimeoutError`, a JSON or `.get`
    /// failure on the answer, httpx's `InvalidURL`).
    Other(PyExc),
}

impl CapeError {
    /// `str(exc)`.
    pub fn text(&self) -> String {
        match self {
            CapeError::NotEnabled(m) => m.clone(),
            CapeError::Http(e) => e.message.clone(),
            CapeError::Other(e) => e.display(),
        }
    }
}

impl From<PyExc> for CapeError {
    fn from(e: PyExc) -> Self {
        CapeError::Other(e)
    }
}

/// `CapeBackend()`: the URL and token as its constructor reads them.
#[derive(Debug, Clone)]
pub struct Cape {
    base_url: String,
    token: String,
    http_timeout: Duration,
    poll_interval: u64,
    poll_timeout: i64,
}

const RETRIES: u32 = 3;

/// `_handle the request` after its answer: `NotEnabled` for a 401, a
/// retryable `HTTPStatusError("server error")` for a 5xx.
enum Attempt {
    Done(Response),
    Retry(String),
}

impl Cape {
    /// `CapeBackend()` with the process's settings.
    pub fn new(settings: &Settings) -> Self {
        Self {
            base_url: settings.cape_api_url.clone(),
            token: settings.cape_api_token.clone(),
            http_timeout: Duration::from_secs(settings.cape_http_timeout),
            poll_interval: settings.cape_poll_interval,
            poll_timeout: settings.cape_poll_timeout,
        }
    }

    fn request(&self, method: Method, path: &str) -> Request {
        let mut req =
            Request::new(method, format!("{}{path}", self.base_url)).timeout(self.http_timeout);
        if !self.token.is_empty() {
            req = req.header("Authorization", Some(&format!("Token {}", self.token)));
        }
        req
    }

    async fn attempt(&self, req: Request) -> Result<Attempt, CapeError> {
        match httpx::send(req).await {
            Ok(resp) if resp.status == 401 => Err(CapeError::NotEnabled(
                "CAPE returned 401 — check CAPE_API_TOKEN (token_auth_enabled=yes in api.conf)"
                    .into(),
            )),
            Ok(resp) if resp.status >= 500 => Ok(Attempt::Retry("server error".into())),
            Ok(resp) => Ok(Attempt::Done(resp)),
            // `httpx.TransportError`: every `RequestError` but a decoding one.
            Err(e) if e.is_request_error() && e.class != "DecodingError" => {
                Ok(Attempt::Retry(e.message))
            }
            Err(e) if e.is_request_error() => Err(CapeError::Http(e)),
            Err(e) => Err(CapeError::Other(e.into_py())),
        }
    }

    /// `_request(method, path, **kw)`.
    async fn send(&self, build: impl Fn() -> Request) -> Result<Response, CapeError> {
        let mut last = String::new();
        for attempt in 0..RETRIES {
            match self.attempt(build()).await? {
                Attempt::Done(resp) => return Ok(resp),
                Attempt::Retry(message) => {
                    last = message;
                    tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                }
            }
        }
        Err(CapeError::Http(HttpxError {
            class: "TransportError",
            message: format!("CAPE request failed after {RETRIES} retries: {last}"),
        }))
    }

    /// `available()`: `GET /cuckoo/status/` answered 200 (any failure is
    /// `False`).
    pub async fn available(&self) -> bool {
        match self
            .send(|| self.request(Method::GET, "/cuckoo/status/"))
            .await
        {
            Ok(resp) => resp.status == 200,
            Err(e) => {
                tracing::warn!("CAPE availability check failed: {}", e.text());
                false
            }
        }
    }

    /// `find_by_sha256(sha256)`: the id of a `reported` prior task.
    pub async fn find_by_sha256(&self, sha256: &str) -> Result<Option<String>, CapeError> {
        let resp = match self
            .send(|| self.request(Method::GET, &format!("/tasks/search/sha256/{sha256}/")))
            .await
        {
            Ok(r) => r,
            Err(CapeError::Http(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        if resp.status != 200 {
            return Ok(None);
        }
        let body = resp.json()?;
        let data = get_or(&body, "data", empty_list())?;
        if let PyValue::List(tasks) = &data {
            for task in tasks {
                if is_dict(task) && get(task, "status")?.as_str() == Some("reported") {
                    let id = or(or(get(task, "id")?, get(task, "task_id")?), py::s(""));
                    return Ok(Some(str_of(&id)));
                }
            }
        }
        Ok(None)
    }

    /// `submit(sample, filename, package, customer_code, source_flow)`.
    pub async fn submit(
        &self,
        settings: &Settings,
        sample: &[u8],
        filename: &str,
        package: &str,
        customer_code: &str,
        source_flow: &str,
    ) -> Result<String, CapeError> {
        let custom = format!("{customer_code}|{source_flow}");
        let filename = if filename.is_empty() {
            "sample"
        } else {
            filename
        };
        let file = FileField {
            name: "file".into(),
            filename: Some(filename.to_string()),
            content_type: crate::mimetypes::httpx_content_type(filename),
            content: sample.to_vec(),
        };
        let data = vec![
            ("package".to_string(), package.to_string()),
            ("custom".to_string(), custom),
            ("timeout".to_string(), settings.cape_task_timeout.clone()),
        ];
        let resp = self
            .send(|| {
                self.request(Method::POST, "/tasks/create/file/")
                    .multipart(data.clone(), vec![file.clone()])
            })
            .await?;
        let payload = resp.json()?;
        let data = get_or(&payload, "data", empty_dict())?;
        let ids = get_or(&data, "task_ids", PyValue::List(vec![PyValue::None]))?;
        let first = index0(&ids)?;
        let mut task_id = first;
        if !task_id.truthy() {
            task_id = get(&payload, "task_id")?;
        }
        if !task_id.truthy() {
            task_id = get(&get_or(&payload, "data", empty_dict())?, "task_id")?;
        }
        if !task_id.truthy() {
            return Err(CapeError::Other(PyExc::Other(
                "RuntimeError",
                format!("CAPE submit returned no task id: {}", payload.py_repr()),
            )));
        }
        Ok(str_of(&task_id))
    }

    /// `wait_for_report(job_ref)`: poll `/tasks/view/<id>/` until
    /// `reported`.
    pub async fn wait_for_report(&self, job_ref: &str) -> Result<(), CapeError> {
        let mut waited: i64 = 0;
        while waited < self.poll_timeout {
            let resp = self
                .send(|| self.request(Method::GET, &format!("/tasks/view/{job_ref}/")))
                .await?;
            let body = resp.json()?;
            let status = get_or(&get_or(&body, "data", empty_dict())?, "status", py::s(""))?;
            if status.as_str() == Some("reported") {
                return Ok(());
            }
            if let Some(s @ ("failed_analysis" | "failed_processing")) = status.as_str() {
                return Err(CapeError::Other(PyExc::Other(
                    "RuntimeError",
                    format!("CAPE task {job_ref} failed: {s}"),
                )));
            }
            tokio::time::sleep(Duration::from_secs(self.poll_interval)).await;
            waited += i64::try_from(self.poll_interval).unwrap_or(i64::MAX);
        }
        Err(CapeError::Other(PyExc::Other(
            "TimeoutError",
            format!(
                "CAPE task {job_ref} not reported within {}s",
                self.poll_timeout
            ),
        )))
    }

    /// `get_report(job_ref)`: the report's JSON, whatever the status.
    pub async fn get_report(&self, job_ref: &str) -> Result<PyValue, CapeError> {
        let resp = self
            .send(|| self.request(Method::GET, &format!("/tasks/get/report/{job_ref}/json/")))
            .await?;
        Ok(resp.json()?)
    }

    /// `get_screenshots(job_ref, limit=24)`: the zip's images in name
    /// order; any failure is no screenshot.
    pub async fn get_screenshots(&self, job_ref: &str, limit: usize) -> Vec<Vec<u8>> {
        let resp = match self
            .send(|| self.request(Method::GET, &format!("/tasks/get/screenshot/{job_ref}/")))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "CAPE screenshot fetch failed for task {job_ref}: {}",
                    e.text()
                );
                return Vec::new();
            }
        };
        let content_type = resp
            .headers
            .get(http::header::CONTENT_TYPE)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .unwrap_or_default();
        if resp.status != 200 || !content_type.contains("zip") {
            return Vec::new();
        }
        let shots = (|| -> Result<Vec<Vec<u8>>, crate::zip::BadZip> {
            let archive = crate::zip::Archive::open(&resp.content)?;
            let mut names = archive.names();
            names.sort();
            let mut shots = Vec::new();
            for name in names {
                let lowered = py::lower(&name);
                if lowered.ends_with(".jpg")
                    || lowered.ends_with(".jpeg")
                    || lowered.ends_with(".png")
                {
                    shots.push(archive.read(&name)?);
                    if shots.len() >= limit {
                        break;
                    }
                }
            }
            Ok(shots)
        })();
        shots.unwrap_or_else(|e| {
            tracing::warn!("CAPE screenshot fetch failed for task {job_ref}: {}", e.0);
            Vec::new()
        })
    }
}

/// `value[0]`.
fn index0(value: &PyValue) -> PyResult<PyValue> {
    match value {
        PyValue::List(items) => items
            .first()
            .cloned()
            .ok_or_else(|| PyExc::IndexError("list index out of range".into())),
        PyValue::Str(text) => text
            .chars()
            .next()
            .map(|c| PyValue::Str(c.to_string()))
            .ok_or_else(|| PyExc::IndexError("string index out of range".into())),
        // JSON keys are strings: `d[0]` never finds one.
        PyValue::Dict(_) => Err(PyExc::KeyError("0".into())),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        ))),
    }
}

// --- summarize -------------------------------------------------------------------------------

fn as_list(value: PyValue) -> Vec<PyValue> {
    match value {
        PyValue::None => Vec::new(),
        PyValue::List(items) => items,
        other => vec![other],
    }
}

fn looks_like_ip(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| isdigit(p))
}

fn add_c2(ips: &mut Vec<PyValue>, domains: &mut Vec<PyValue>, endpoint: &PyValue) {
    let PyValue::Str(text) = endpoint else {
        return;
    };
    if text.is_empty() {
        return;
    }
    let after = text.rsplit("://").next().unwrap_or(text);
    let host = after.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    if looks_like_ip(host) {
        ips.push(py::s(host));
    } else {
        domains.push(py::s(host));
    }
}

fn dedup(items: Vec<PyValue>) -> Vec<PyValue> {
    let mut out: Vec<PyValue> = Vec::new();
    for item in items {
        if item.truthy() && !py::list_contains(&out, &item) {
            out.push(item);
        }
    }
    out
}

/// `get(key, []) or []` iterated.
fn items(value: &PyValue, key: &str) -> PyResult<Vec<PyValue>> {
    py::iter(&or(get_or(value, key, empty_list())?, empty_list()))
}

/// `summarize(report).to_dict()`.
pub fn summarize(report: &PyValue) -> PyResult<PyValue> {
    let info = or(get_or(report, "info", empty_dict())?, empty_dict());
    let task_id = get(&info, "id")?;
    let score_default = get_or(&info, "score", py::int(0))?;
    let raw_score = or(get_or(report, "malscore", score_default)?, py::int(0));
    let malscore = match float_of(&raw_score) {
        Ok(f) => f,
        Err(PyExc::TypeError(_) | PyExc::ValueError(_)) => 0.0,
        Err(e) => return Err(e),
    };

    let mut family = py::s("");
    let mut c2_ips = Vec::new();
    let mut c2_domains = Vec::new();
    let cape = or(get_or(report, "CAPE", empty_dict())?, empty_dict());
    let configs = if is_dict(&cape) {
        get_or(&cape, "configs", empty_list())?
    } else {
        empty_list()
    };
    for cfg in py::iter(&or(configs, empty_list()))? {
        let PyValue::Dict(pairs) = &cfg else {
            continue;
        };
        for (fam, details) in pairs {
            if !family.truthy() {
                family = py::s(fam.clone());
            }
            if is_dict(details) {
                for key in ["c2", "address", "cncs", "cnc", "c2_list"] {
                    for endpoint in as_list(get(details, key)?) {
                        add_c2(&mut c2_ips, &mut c2_domains, &endpoint);
                    }
                }
            }
        }
    }
    if !family.truthy() {
        let malfamily = get_or(report, "malfamily", py::s(""))?;
        family = if malfamily.truthy() {
            malfamily
        } else {
            let package = get_or(&info, "package", py::s(""))?;
            if package.truthy() { py::s("") } else { package }
        };
    }

    let mut signatures = Vec::new();
    for sig in items(report, "signatures")? {
        let name = get_or(&sig, "name", py::s(""))?;
        let description = get_or(&sig, "description", py::s(""))?;
        let severity = get_or(&sig, "severity", py::int(0))?;
        let noise = verdict::is_noise(&name)?;
        let low = if verdict::is_noise(&name)? {
            false
        } else {
            verdict::is_low_confidence(&name)?
        };
        let source = or(
            or(
                get_or(&sig, "ttp", empty_list())?,
                get_or(&sig, "mitre", empty_list())?,
            ),
            empty_list(),
        );
        let mut mitre = Vec::new();
        for t in py::iter(&source)? {
            if is_dict(&t) {
                mitre.push(get_or(&t, "attack_id", t.clone())?);
            } else {
                mitre.push(t);
            }
        }
        signatures.push(dict(vec![
            ("name", name),
            ("description", description),
            ("severity", severity),
            ("noise", PyValue::Bool(noise)),
            ("low_confidence", PyValue::Bool(low)),
            ("mitre", PyValue::List(mitre)),
        ]));
    }

    let duration = PyValue::Int(int_value(&or(get(&info, "duration")?, py::int(0)))?.to_string());
    let package = or(get(&info, "package")?, py::s(""));
    let mut machine_text = py::s("");
    let machine = or(get(&info, "machine")?, empty_dict());
    if is_dict(&machine) {
        let name = or(
            or(get(&machine, "name")?, get(&machine, "label")?),
            py::s(""),
        );
        let platform = or(get(&machine, "platform")?, py::s(""));
        machine_text = if platform.truthy() {
            py::s(format!("{} ({})", str_of(&name), str_of(&platform)))
        } else {
            name
        };
    }

    let network = or(get_or(report, "network", empty_dict())?, empty_dict());
    let mut hosts = Vec::new();
    for host in items(&network, "hosts")? {
        let ip = if is_dict(&host) {
            get(&host, "ip")?
        } else {
            host
        };
        if ip.truthy() {
            hosts.push(ip);
        }
    }
    let mut domains = Vec::new();
    for dom in items(&network, "domains")? {
        let domain = if is_dict(&dom) {
            get(&dom, "domain")?
        } else {
            dom
        };
        if domain.truthy() {
            domains.push(domain);
        }
    }
    let mut dns = Vec::new();
    for q in items(&network, "dns")? {
        if !is_dict(&q) {
            continue;
        }
        let mut answers = Vec::new();
        for a in items(&q, "answers")? {
            if is_dict(&a) {
                answers.push(get_or(&a, "data", a.clone())?);
            } else {
                answers.push(a);
            }
        }
        dns.push(dict(vec![
            ("request", get_or(&q, "request", py::s(""))?),
            ("type", get_or(&q, "type", py::s(""))?),
            ("answers", PyValue::List(answers)),
        ]));
    }
    let mut http_rows = Vec::new();
    for h in items(&network, "http")? {
        if is_dict(&h) {
            let path = get_or(&h, "path", py::s(""))?;
            http_rows.push(dict(vec![
                ("method", get_or(&h, "method", py::s(""))?),
                ("host", get_or(&h, "host", py::s(""))?),
                ("uri", get_or(&h, "uri", path)?),
            ]));
        }
    }
    let mut connections = Vec::new();
    for proto in ["tcp", "udp"] {
        for c in items(&network, proto)? {
            if is_dict(&c) && get(&c, "dst")?.truthy() {
                connections.push(dict(vec![
                    ("proto", py::s(proto)),
                    ("dst", get(&c, "dst")?),
                    ("dport", get(&c, "dport")?),
                ]));
            }
        }
    }

    let behavior = or(get_or(report, "behavior", empty_dict())?, empty_dict());
    let mut processes = Vec::new();
    for proc in items(&behavior, "processes")? {
        if !is_dict(&proc) {
            continue;
        }
        let environ = get(&proc, "environ")?;
        let environ = if is_dict(&environ) {
            environ
        } else {
            empty_dict()
        };
        let pid = match get(&proc, "process_id")? {
            PyValue::None => get(&proc, "pid")?,
            v => v,
        };
        let ppid = match get(&proc, "parent_id")? {
            PyValue::None => get(&proc, "ppid")?,
            v => v,
        };
        let name = or(
            or(get(&proc, "process_name")?, get(&proc, "name")?),
            py::s(""),
        );
        let command_line = or_else_get(get(&proc, "command_line")?, &environ, "CommandLine")?;
        processes.push(dict(vec![
            ("name", name),
            ("pid", pid),
            ("ppid", ppid),
            ("command_line", command_line),
        ]));
    }

    const BEHAV_CAP: usize = 2000;
    const BEHAV_MAP: &[(&str, &str)] = &[
        ("files", "files"),
        ("read_files", "read_files"),
        ("write_files", "write_files"),
        ("delete_files", "delete_files"),
        ("registry_keys", "keys"),
        ("read_keys", "read_keys"),
        ("write_keys", "write_keys"),
        ("delete_keys", "delete_keys"),
        ("mutexes", "mutexes"),
        ("executed_commands", "executed_commands"),
        ("created_services", "created_services"),
        ("started_services", "started_services"),
        ("resolved_apis", "resolved_apis"),
    ];
    let behav_summary = or(get_or(&behavior, "summary", empty_dict())?, empty_dict());
    let mut behavior_out: Vec<(String, PyValue)> = Vec::new();
    for (out_key, src_key) in BEHAV_MAP {
        let vals = or(get(&behav_summary, src_key)?, empty_list());
        if vals.truthy() {
            let rendered: Vec<PyValue> = py::iter(&vals)?
                .iter()
                .map(|v| py::s(str_of(v)))
                .take(BEHAV_CAP)
                .collect();
            behavior_out.push(((*out_key).to_string(), PyValue::List(rendered)));
        }
    }
    let mut enhanced = Vec::new();
    let raw_enhanced = or(get_or(&behavior, "enhanced", empty_list())?, empty_list());
    for ev in py::iter(&py::head(&raw_enhanced, BEHAV_CAP)?)? {
        if is_dict(&ev) {
            enhanced.push(dict(vec![
                ("event", get_or(&ev, "event", py::s(""))?),
                ("object", get_or(&ev, "object", py::s(""))?),
                ("data", get_or(&ev, "data", empty_dict())?),
            ]));
        }
    }

    let mut dead_hosts = Vec::new();
    for dh in items(&network, "dead_hosts")? {
        match &dh {
            PyValue::List(parts) if !parts.is_empty() => {
                dead_hosts.push(py::s(if parts.len() > 1 {
                    format!("{}:{}", str_of(&parts[0]), str_of(&parts[1]))
                } else {
                    str_of(&parts[0])
                }));
            }
            other if other.truthy() => dead_hosts.push(py::s(str_of(other))),
            _ => {}
        }
    }

    let mut ttps = Vec::new();
    for t in items(report, "ttps")? {
        if is_dict(&t) {
            let tid = or(or(get(&t, "ttp")?, get(&t, "id")?), py::s(""));
            if tid.truthy() {
                let signature = or(or(get(&t, "signature")?, get(&t, "name")?), py::s(""));
                ttps.push(dict(vec![("id", tid), ("signature", signature)]));
            }
        }
    }

    let mut payloads = Vec::new();
    for p in items(&cape, "payloads")? {
        if is_dict(&p) {
            let kind = or(get(&p, "cape_type")?, get_or(&p, "type", py::s(""))?);
            payloads.push(dict(vec![
                ("name", get_or(&p, "name", py::s(""))?),
                ("sha256", get_or(&p, "sha256", py::s(""))?),
                ("type", kind),
            ]));
        }
    }

    let mut dropped = Vec::new();
    for d in items(report, "dropped")? {
        dropped.push(dict(vec![
            ("sha256", get_or(&d, "sha256", py::s(""))?),
            ("name", get_or(&d, "name", py::s(""))?),
            ("type", get_or(&d, "type", py::s(""))?),
        ]));
    }
    let mut screenshots = Vec::new();
    for shot in items(report, "screenshots")? {
        if is_dict(&shot) {
            screenshots.push(get_or(&shot, "path", shot.clone())?);
        } else {
            screenshots.push(shot);
        }
    }
    let debug = or(get_or(report, "debug", empty_dict())?, empty_dict());
    let errors: Vec<PyValue> = items(&debug, "errors")?
        .iter()
        .filter(|e| e.truthy())
        .map(|e| py::s(str_of(e)))
        .take(20)
        .collect();

    let build = |verdict_text: &str,
                 c2_ips: Vec<PyValue>,
                 c2_domains: Vec<PyValue>,
                 hosts: Vec<PyValue>,
                 domains: Vec<PyValue>| {
        dict(vec![
            ("task_id", task_id.clone()),
            ("malscore", PyValue::Float(malscore)),
            ("family", family.clone()),
            ("signatures", PyValue::List(signatures.clone())),
            ("c2_ips", PyValue::List(c2_ips)),
            ("c2_domains", PyValue::List(c2_domains)),
            ("dropped", PyValue::List(dropped.clone())),
            ("screenshots", PyValue::List(screenshots.clone())),
            ("duration", duration.clone()),
            ("machine", machine_text.clone()),
            ("package", package.clone()),
            ("verdict", py::s(verdict_text)),
            ("processes", PyValue::List(processes.clone())),
            ("hosts", PyValue::List(hosts)),
            ("domains", PyValue::List(domains)),
            ("dns", PyValue::List(dns.clone())),
            ("http", PyValue::List(http_rows.clone())),
            ("connections", PyValue::List(connections.clone())),
            ("ttps", PyValue::List(ttps.clone())),
            ("payloads", PyValue::List(payloads.clone())),
            ("errors", PyValue::List(errors.clone())),
            ("behavior", PyValue::Dict(behavior_out.clone())),
            ("enhanced", PyValue::List(enhanced.clone())),
            ("dead_hosts", PyValue::List(dead_hosts.clone())),
        ])
    };
    let before = build(
        "",
        c2_ips.clone(),
        c2_domains.clone(),
        hosts.clone(),
        domains.clone(),
    );
    let verdict_text = verdict::dynamic_verdict_from_report(&before)?;
    Ok(build(
        verdict_text,
        dedup(c2_ips),
        dedup(c2_domains),
        dedup(hosts),
        dedup(domains),
    ))
}

/// `a or environ.get(key, "")`.
fn or_else_get(a: PyValue, environ: &PyValue, key: &str) -> PyResult<PyValue> {
    if a.truthy() {
        Ok(a)
    } else {
        get_or(environ, key, py::s(""))
    }
}

/// `str(x)` for the screenshot task id the routes pass on.
pub fn task_ref(task_id: &PyValue) -> String {
    str_of(task_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_auth::pyvalue::loads;

    #[test]
    fn summarize_reads_the_recorded_shape() {
        let report = loads(
            r#"{"info": {"id": 42}, "malscore": 9.4,
            "CAPE": {"configs": [{"RedLine": {"c2": ["45.10.20.30:443", "evil.example.com"]}}]},
            "signatures": [{"name": "Process injection", "severity": 3, "ttp": [{"attack_id": "T1055"}]},
                           {"name": "Registry Run key persistence", "ttp": [{"attack_id": "T1547.001"}]}],
            "network": {"hosts": [{"ip": "45.10.20.30"}], "domains": [{"domain": "evil.example.com"}]},
            "dropped": [{"sha256": "aa", "name": "svchost.exe"}]}"#,
        )
        .unwrap();
        let s = summarize(&report).unwrap();
        assert_eq!(s.get("task_id"), Some(&py::int(42)));
        assert_eq!(s.get("family"), Some(&py::s("RedLine")));
        assert_eq!(
            s.get("c2_ips"),
            Some(&PyValue::List(vec![py::s("45.10.20.30")]))
        );
        assert_eq!(s.get("verdict"), Some(&py::s("malicious")));
        assert_eq!(
            summarize(&loads("[]").unwrap()).unwrap_err().text(),
            "'list' object has no attribute 'get'"
        );
    }
}
