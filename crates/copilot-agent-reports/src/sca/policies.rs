//! The CoPilot-SCA repository: `fetch_sca_policies_index`,
//! `fetch_sca_policy_metadata` and `fetch_sca_policy_content` — one
//! `httpx.AsyncClient(timeout=15.0)` GET per file, the raw GitHub URLs, the
//! texts each `except` wraps.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{self, kwargs};
use copilot_upstream::py::{self, PyExc, PyResult};

use crate::httpx::HttpxClient;
use crate::pyfmt::{dict, s};

use super::schema::{POLICIES_INDEX, POLICY_ITEM};

/// `COPILOT_SCA_RAW_BASE`.
pub const RAW_BASE: &str =
    "https://raw.githubusercontent.com/socfortress/CoPilot-SCA/refs/heads/main";

/// The variable that points the repository at a stand-in (the parity
/// harness only; never set in production).
pub const REPO_URL_ENV: &str = "COPILOT_SCA_REPO_URL";

const POLICY_QUALNAME: &str = "app.agents.sca.schema.sca.ScaPolicyItem";

/// The repository client.
#[derive(Debug, Clone)]
pub struct ScaRepo {
    base: String,
    http: HttpxClient,
}

impl ScaRepo {
    /// `COPILOT_SCA_RAW_BASE` (or [`REPO_URL_ENV`]), 15 s timeouts.
    pub fn from_env() -> Result<Self, reqwest::Error> {
        let base = std::env::var(REPO_URL_ENV)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| RAW_BASE.to_string());
        Self::new(base)
    }

    /// A client for `base`.
    pub fn new(base: impl Into<String>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            base: base.into().trim_end_matches('/').to_string(),
            http: HttpxClient::new(Duration::from_secs(15))?,
        })
    }

    /// `fetch_sca_policies_index()`: the `ScaPoliciesIndexResponse` dump, or
    /// the `HTTPException` (GitHub's own status for an error answer, else
    /// 502).
    pub async fn index(&self) -> PyResult<PyValue> {
        let url = format!("{}/index.json", self.base);
        let failed = |text: String| {
            tracing::error!("Error fetching SCA policies index: {text}");
            PyExc::http(502, format!("Failed to fetch SCA policies index: {text}"))
        };
        let resp = self.http.get(&url).await.map_err(failed)?;
        if let Err(text) = resp.raise_for_status() {
            tracing::error!("HTTP error fetching SCA policies index: {text}");
            return Err(PyExc::http(
                resp.status,
                format!("Failed to fetch SCA policies index from GitHub: {text}"),
            ));
        }
        let parse = || -> PyResult<PyValue> {
            let data = resp.json()?;
            let listed = py::get(&data, "policies")?
                .cloned()
                .unwrap_or(PyValue::List(Vec::new()));
            let policies = py::iterate(&listed)?
                .iter()
                .map(|p| model::construct_star(&POLICY_ITEM, POLICY_QUALNAME, p))
                .collect::<PyResult<Vec<_>>>()?;
            let version = py::get(&data, "version")?
                .cloned()
                .unwrap_or_else(|| s("unknown"));
            let last_updated = py::get(&data, "last_updated")?
                .cloned()
                .unwrap_or_else(|| s("unknown"));
            let n = policies.len();
            model::construct(
                &POLICIES_INDEX,
                &kwargs(vec![
                    ("version", version),
                    ("last_updated", last_updated),
                    ("policies", PyValue::List(policies)),
                    ("success", PyValue::Bool(true)),
                    (
                        "message",
                        s(format!("Successfully fetched {n} available SCA policies")),
                    ),
                ]),
            )
        };
        parse().map_err(|e| failed(e.display()))
    }

    /// `fetch_sca_policy_metadata(policy_id)`.
    pub async fn metadata(&self, policy_id: &str) -> PyResult<PyValue> {
        let index = self.index().await?;
        let Some(policy) = find(&index, policy_id) else {
            return Err(PyExc::http(
                404,
                format!("SCA policy '{policy_id}' not found"),
            ));
        };
        Ok(dict(vec![
            ("policy", policy),
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(format!("Successfully fetched SCA policy '{policy_id}'")),
            ),
        ]))
    }

    /// `fetch_sca_policy_content(policy_id)`.
    pub async fn content(&self, policy_id: &str) -> PyResult<PyValue> {
        let index = self.index().await?;
        let Some(policy) = find(&index, policy_id) else {
            return Err(PyExc::http(
                404,
                format!("SCA policy '{policy_id}' not found in the CoPilot-SCA repository index"),
            ));
        };
        let text_of = |k: &str| py::py_str(model::field(&policy, k));
        let file = text_of("file");
        let url = format!("{}/{file}", self.base);
        let resp = self.http.get(&url).await.map_err(|text| {
            tracing::error!("Error fetching SCA policy content for {policy_id}: {text}");
            PyExc::http(502, format!("Failed to fetch SCA policy content: {text}"))
        })?;
        if let Err(text) = resp.raise_for_status() {
            tracing::error!("HTTP error fetching SCA policy content for {policy_id}: {text}");
            return Err(PyExc::http(
                resp.status,
                format!("Failed to fetch SCA policy file from GitHub: {text}"),
            ));
        }
        Ok(dict(vec![
            ("policy_id", s(text_of("id"))),
            ("file_path", s(file)),
            ("content", s(resp.text())),
            ("success", PyValue::Bool(true)),
            (
                "message",
                s(format!("Successfully fetched policy '{}'", text_of("name"))),
            ),
        ]))
    }
}

/// The policies of an index dump.
pub fn policies(index: &PyValue) -> Vec<PyValue> {
    match model::field(index, "policies") {
        PyValue::List(items) => items.clone(),
        _ => Vec::new(),
    }
}

/// `next((p for p in index.policies if p.id == policy_id), None)`.
fn find(index: &PyValue, policy_id: &str) -> Option<PyValue> {
    policies(index)
        .into_iter()
        .find(|p| model::field(p, "id").as_str() == Some(policy_id))
}
