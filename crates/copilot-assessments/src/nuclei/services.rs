//! `app/integrations/nuclei/services/nuclei.py`.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::httpx::{self, Request, Response};
use copilot_upstream::model::{Model, construct_star, kwargs};
use copilot_upstream::py::{PyExc, PyResult};
use http::Method;

use super::schema::{DELETE_RESPONSE, MODULE, REPORT_RESPONSE, REPORTS_RESPONSE, SCAN_RESPONSE};

/// The container's base URL the Python service hard-codes.
pub const MODULE_URL: &str = "http://copilot-nuclei-module";

/// The scan's `timeout=120`.
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(120);

/// Where the module is reached: its own URLs, or — tests only,
/// `COPILOT_NUCLEI_MODULE_URL` — `{base}/{host}{path}` of the URL httpx
/// would send (as the parity harness redirects Python's client).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Upstream {
    base: Option<String>,
}

impl Upstream {
    /// `base`: the test-only override.
    pub fn new(base: Option<String>) -> Self {
        Self { base }
    }

    /// The URL a request to `url` goes to.
    pub fn url(&self, url: &str) -> String {
        match &self.base {
            None => url.to_string(),
            Some(base) => {
                let rendered =
                    httpx::parse_url(url).map_or_else(|_| url.to_string(), |u| u.render());
                let rest = rendered
                    .split_once("://")
                    .map_or(rendered.as_str(), |(_, r)| r);
                format!("{base}/{rest}")
            }
        }
    }

    async fn send(&self, req: Request) -> PyResult<Response> {
        httpx::send(req).await.map_err(httpx::HttpxError::into_py)
    }

    async fn get(&self, path: &str) -> PyResult<Response> {
        let url = self.url(&format!("{MODULE_URL}{path}"));
        self.send(Request::new(Method::GET, url)).await
    }
}

fn model(m: &'static Model, response: &Response) -> PyResult<PyValue> {
    let body = response.json()?;
    construct_star(m, &format!("{MODULE}.{}", m.name), &body)
}

fn raise_for_status(response: &Response) -> PyResult<()> {
    response
        .raise_for_status()
        .map_err(httpx::HttpxError::into_py)
}

/// `get_nuclei_reports_available`.
pub async fn reports_available(up: &Upstream) -> PyResult<PyValue> {
    let response = up.get("/all_reports").await?;
    if response.status == 404 {
        return Err(PyExc::http(404, "Nuclei reports not found"));
    }
    raise_for_status(&response)?;
    model(&REPORTS_RESPONSE, &response)
}

/// `get_nuclei_report(host, report)`.
pub async fn report(up: &Upstream, host: &str, report: &str) -> PyResult<PyValue> {
    let response = up.get(&format!("/report/{host}/{report}")).await?;
    if response.status == 404 {
        return Err(PyExc::http(404, "Nuclei report not found"));
    }
    raise_for_status(&response)?;
    model(&REPORT_RESPONSE, &response)
}

/// `delete_nuclei_report(host)` (no `raise_for_status()`).
pub async fn delete_report(up: &Upstream, host: &str) -> PyResult<PyValue> {
    let url = up.url(&format!("{MODULE_URL}/report/{host}"));
    let response = up.send(Request::new(Method::DELETE, url)).await?;
    if response.status == 404 {
        return Err(PyExc::http(404, "Nuclei report not found"));
    }
    model(&DELETE_RESPONSE, &response)
}

/// `post_to_copilot_nuclei_module(data)`: `json=data.model_dump()`.
pub async fn scan(up: &Upstream, host: &str) -> PyResult<PyValue> {
    let url = up.url(&format!("{MODULE_URL}/scan"));
    let response = up
        .send(
            Request::new(Method::POST, url)
                .json(kwargs(vec![("host", PyValue::Str(host.to_string()))]))
                .timeout(SCAN_TIMEOUT),
        )
        .await?;
    model(&SCAN_RESPONSE, &response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_override_keeps_what_httpx_would_send() {
        let up = Upstream::new(Some("http://127.0.0.1:6240".into()));
        assert_eq!(
            up.url("http://copilot-nuclei-module/report/a b/x/../index.md"),
            "http://127.0.0.1:6240/copilot-nuclei-module/report/a%20b/index.md"
        );
        assert_eq!(
            Upstream::default().url("http://copilot-nuclei-module/scan"),
            "http://copilot-nuclei-module/scan"
        );
    }
}
