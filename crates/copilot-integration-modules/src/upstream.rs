//! The fixed upstream URLs of the Python services and the one httpx call
//! they all make (`async with httpx.AsyncClient() as client:
//! client.post(url, json=…, timeout=…)`), through
//! `copilot_threat_intel::httpx`: httpx 0.28's request bytes and exception
//! texts.

use std::time::Duration;

use copilot_auth::pyvalue::PyValue;
use copilot_threat_intel::httpx::{self, HttpxError, Request, Response};
use http::Method;

/// `app/integrations/modules/services/huntress.py:MODULE_URL`.
pub const HUNTRESS_URL: &str = "http://copilot-huntress-module/collect";
/// The Mimecast module's collection.
pub const MIMECAST_MODULE_URL: &str = "http://copilot-mimecast-module/collect";
/// The Duo module's collection.
pub const DUO_URL: &str = "http://copilot-duo-module/auth";
/// The Cato module's collection.
pub const CATO_URL: &str = "http://copilot-cato-module/collect";
/// The CarbonBlack module's collection.
pub const CARBONBLACK_URL: &str = "http://copilot-carbonblack-module/collect";
/// The Darktrace module's collection.
pub const DARKTRACE_URL: &str = "http://copilot-darktrace-module/all_logs";
/// The SAP SIEM module's routes (`/collect`, the analyses).
pub const SAP_URL: &str = "http://copilot-sap-module/sap-siem";
/// Mimecast's region discovery (`get_base_url`).
pub const MIMECAST_DISCOVER_URL: &str =
    "https://api.mimecast.com/api/login/discover-authentication";

/// The module posts' `timeout=120`.
pub const MODULE_TIMEOUT: Duration = Duration::from_secs(120);

/// Where requests to the fixed URLs go.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Upstream {
    base: Option<String>,
}

impl Upstream {
    /// `base`: `COPILOT_INTEGRATION_MODULES_URL` (tests only), else
    /// Python's URLs as they are.
    pub fn new(base: Option<String>) -> Self {
        Self {
            base: base
                .map(|b| b.trim().trim_end_matches('/').to_string())
                .filter(|b| !b.is_empty()),
        }
    }

    /// The URL a request to `url` is sent to: `url` itself, or
    /// `{base}/{host}{path}` under the override.
    pub fn url(&self, url: &str) -> String {
        match &self.base {
            None => url.to_string(),
            Some(base) => {
                let rest = url.split_once("://").map_or(url, |(_, r)| r);
                format!("{base}/{rest}")
            }
        }
    }

    /// `client.post(url, json=body, headers=headers, timeout=timeout)`.
    pub async fn post_json(
        &self,
        url: &str,
        body: PyValue,
        headers: &[(&str, String)],
        timeout: Duration,
    ) -> Result<Response, HttpxError> {
        let mut req = Request::new(Method::POST, self.url(url))
            .json(body)
            .timeout(timeout);
        for (name, value) in headers {
            req = req.header(name, Some(value));
        }
        httpx::send(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_override_keeps_host_and_path() {
        let up = Upstream::new(Some("http://127.0.0.1:6610/".into()));
        assert_eq!(
            up.url(HUNTRESS_URL),
            "http://127.0.0.1:6610/copilot-huntress-module/collect"
        );
        assert_eq!(
            up.url(MIMECAST_DISCOVER_URL),
            "http://127.0.0.1:6610/api.mimecast.com/api/login/discover-authentication"
        );
        assert_eq!(Upstream::new(None).url(DUO_URL), DUO_URL);
        assert_eq!(Upstream::new(Some(" ".into())).url(DUO_URL), DUO_URL);
    }
}
