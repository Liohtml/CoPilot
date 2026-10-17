//! The GitHub REST API as `GitHubAuditService._request` reaches it: one
//! `httpx.AsyncClient(timeout=30.0)` per audit (its connection pool), every
//! request a GET of `f"{GITHUB_API_BASE}{endpoint}"` with the three headers
//! the service sets, through `copilot_threat_intel::httpx` (httpx 0.28's
//! URL handling, default headers and their order, TLS verified, no
//! redirects followed).
//!
//! `params=` is what httpx 0.28 makes of it: `URL(url, params=params)`
//! *replaces* the URL's own query (a `?` in an organization or repository
//! name cuts the path there and the rest is dropped), so the query is built
//! here and the URL handed over without `params`.
//!
//! `_request` swallows everything: a 200 is its JSON (a body that is not
//! JSON is the `except`'s `(None, 500)`), a 404 `(None, 404)`, any other
//! status `(None, status)`, any exception `(None, 500)`.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use copilot_threat_intel::httpx::{self, Client, Request};
use copilot_upstream::http::urlencode;
use http::Method;

use super::audit::{Fetch, Transport};

/// `GITHUB_API_BASE`.
pub const GITHUB_API_BASE: &str = "https://api.github.com";

/// The audit client's `timeout=30.0`.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// One audit's client.
pub struct GithubHttp {
    client: Client,
    base: String,
    authorization: String,
}

impl GithubHttp {
    /// `GitHubAuditService(token, …).__aenter__()`; `base` is
    /// `GITHUB_API_BASE` (or the parity harness's stand-in).
    pub fn new(base: &str, token: &str) -> Result<Self, httpx::HttpxError> {
        Ok(Self {
            client: Client::new(TIMEOUT)?,
            base: base.to_string(),
            authorization: format!("Bearer {token}"),
        })
    }

    async fn fetch(&self, endpoint: String, params: Vec<(String, String)>) -> Fetch {
        let url = with_params(&format!("{}{endpoint}", self.base), &params);
        let req = Request::new(Method::GET, url)
            .timeout(TIMEOUT)
            .header("Authorization", Some(&self.authorization))
            .header("Accept", Some("application/vnd.github+json"))
            .header("X-GitHub-Api-Version", Some("2022-11-28"));
        match httpx::send_on(&self.client, req).await {
            Ok(resp) if resp.status == 200 => match resp.json() {
                Ok(value) => (Some(value), 200),
                Err(_) => (None, 500),
            },
            Ok(resp) => {
                if resp.status != 404 {
                    tracing::warn!(
                        status = resp.status,
                        "GitHub API error: {}",
                        resp.text().chars().take(200).collect::<String>()
                    );
                }
                (None, resp.status)
            }
            Err(e) => {
                tracing::error!("GitHub API request failed: {}", e.message);
                (None, 500)
            }
        }
    }
}

impl Transport for GithubHttp {
    fn get(
        &self,
        endpoint: String,
        params: Vec<(String, String)>,
    ) -> Pin<Box<dyn Future<Output = Fetch> + Send + '_>> {
        Box::pin(self.fetch(endpoint, params))
    }
}

/// `URL(url, params=params)`: with params, the URL's own query (from its
/// first `?` to its fragment) is replaced by `urlencode(params)`.
pub fn with_params(url: &str, params: &[(String, String)]) -> String {
    if params.is_empty() {
        return url.to_string();
    }
    // The query starts at the first `?` before any `#` (after the scheme
    // and authority, which hold neither here).
    let (before_fragment, fragment) = match url.find('#') {
        Some(i) => (&url[..i], Some(&url[i..])),
        None => (url, None),
    };
    let path = match before_fragment.find('?') {
        Some(i) => &before_fragment[..i],
        None => before_fragment,
    };
    format!(
        "{path}?{}{}",
        urlencode(params),
        fragment.unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn params_replace_the_query_like_httpx() {
        let params = p(&[("per_page", "100"), ("page", "1")]);
        assert_eq!(
            with_params("https://api.github.com/orgs/acme/repos", &params),
            "https://api.github.com/orgs/acme/repos?per_page=100&page=1"
        );
        assert_eq!(
            with_params("https://api.github.com/orgs/a?b/repos", &params),
            "https://api.github.com/orgs/a?per_page=100&page=1"
        );
        assert_eq!(
            with_params("https://api.github.com/orgs/a#b?c/repos", &params),
            "https://api.github.com/orgs/a?per_page=100&page=1#b?c/repos"
        );
        assert_eq!(
            with_params("https://api.github.com/orgs/a b", &[]),
            "https://api.github.com/orgs/a b"
        );
    }
}
