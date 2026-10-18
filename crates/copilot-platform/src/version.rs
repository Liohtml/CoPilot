//! `GET /api/version/check` — port of `app/version/`.
//!
//! Compares the running release ([`CURRENT_VERSION`], the Python constant —
//! a test keeps them equal) with GitHub's latest release. Any failure to
//! fetch or read the release is "Unable to check for updates"; a tag that is
//! not a PEP 440 version is "Error checking version". Like the Python
//! service, a release without a `name` (GitHub sends `null`) counts as a
//! failed fetch.

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use copilot_web::ApiError;

use crate::pep440::Version;

/// The CoPilot release this deployment runs (`version.py:CURRENT_VERSION`).
pub const CURRENT_VERSION: &str = "0.1.98";

/// `VERSION_CHECK_URL`.
pub const DEFAULT_VERSION_CHECK_URL: &str =
    "https://api.github.com/repos/socfortress/CoPilot/releases/latest";

/// httpx's `timeout=5.0`.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// `VersionCheckResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionCheckResponse {
    /// Whether the check could be made.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
    /// The running release.
    pub current_version: String,
    /// GitHub's latest tag, without its `v`.
    pub latest_version: Option<String>,
    /// `current < latest`.
    pub is_outdated: bool,
    /// The release page.
    pub release_url: Option<String>,
    /// The release notes.
    pub release_notes: Option<String>,
    /// When it was published.
    pub published_at: Option<String>,
}

/// What `get_latest_version` keeps of a release.
#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    /// `tag_name.lstrip("v")`.
    pub tag_name: String,
    /// `html_url` (default `""`).
    pub html_url: Value,
    /// `published_at` (default `""`).
    pub published_at: Value,
    /// `body` (default `""`).
    pub body: Value,
}

/// `str.lstrip("v")`.
fn lstrip_v(s: &str) -> String {
    s.trim_start_matches('v').to_string()
}

impl Release {
    /// Read GitHub's JSON as `get_latest_version` does: `tag_name` and `name`
    /// must be strings when present (`.lstrip` on anything else raises).
    pub fn from_json(data: &Value) -> Option<Self> {
        let obj = data.as_object()?;
        let text = |key: &str| match obj.get(key) {
            None => Some(String::new()),
            Some(Value::String(s)) => Some(lstrip_v(s)),
            Some(_) => None,
        };
        let tag_name = text("tag_name")?;
        text("name")?;
        let or_empty = |key: &str| {
            obj.get(key)
                .cloned()
                .unwrap_or_else(|| Value::String(String::new()))
        };
        Some(Self {
            tag_name,
            html_url: or_empty("html_url"),
            published_at: or_empty("published_at"),
            body: or_empty("body"),
        })
    }
}

/// An `Optional[str]` response field: a non-string is Pydantic's
/// `ValidationError` on the response model — a bare 500.
fn opt_str(field: &str, v: &Value) -> Result<Option<String>, ApiError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        other => Err(ApiError::internal(format!(
            "VersionCheckResponse.{field}: not a string: {other}"
        ))),
    }
}

/// `check_version_outdated`, given the fetched release.
pub fn compare(current: &str, release: Option<&Release>) -> Result<VersionCheckResponse, ApiError> {
    let Some(release) = release else {
        return Ok(VersionCheckResponse {
            success: false,
            message: "Unable to check for updates".into(),
            current_version: current.into(),
            latest_version: None,
            is_outdated: false,
            release_url: None,
            release_notes: None,
            published_at: None,
        });
    };
    let latest = release.tag_name.clone();
    let release_url = opt_str("release_url", &release.html_url)?;
    match (Version::parse(current), Version::parse(&latest)) {
        (Some(c), Some(l)) => {
            let is_outdated = c < l;
            Ok(VersionCheckResponse {
                success: true,
                message: if is_outdated {
                    format!("New version v{latest} available!")
                } else {
                    "You're up to date".into()
                },
                current_version: current.into(),
                latest_version: Some(latest),
                is_outdated,
                release_url,
                release_notes: opt_str("release_notes", &release.body)?,
                published_at: opt_str("published_at", &release.published_at)?,
            })
        }
        _ => {
            tracing::error!(latest = %latest, "error comparing versions");
            Ok(VersionCheckResponse {
                success: false,
                message: "Error checking version".into(),
                current_version: current.into(),
                latest_version: Some(latest),
                is_outdated: false,
                release_url,
                release_notes: None,
                published_at: None,
            })
        }
    }
}

/// Fetches GitHub's latest release.
#[derive(Debug, Clone)]
pub struct VersionChecker {
    url: String,
    http: reqwest::Client,
}

impl VersionChecker {
    /// A checker for `url` (`None` = GitHub). GitHub refuses requests without
    /// a `User-Agent`, which httpx always sends; so does this client.
    pub fn new(url: Option<String>) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(CHECK_TIMEOUT)
            .user_agent(concat!("copilot/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            url: url.unwrap_or_else(|| DEFAULT_VERSION_CHECK_URL.to_string()),
            http,
        })
    }

    /// `get_latest_version`: `None` on any failure (logged).
    pub async fn latest(&self) -> Option<Release> {
        let resp = match self.http.get(&self.url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(err = %e, "failed to fetch latest version");
                return None;
            }
        };
        if resp.status() != reqwest::StatusCode::OK {
            return None;
        }
        match resp.json::<Value>().await {
            Ok(data) => Release::from_json(&data),
            Err(e) => {
                tracing::warn!(err = %e, "failed to read latest version");
                None
            }
        }
    }

    /// `check_version_outdated`.
    pub async fn check(&self) -> Result<VersionCheckResponse, ApiError> {
        compare(CURRENT_VERSION, self.latest().await.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn current_version_matches_the_python_backend() {
        let py = include_str!("../../../backend/app/version/services/version.py");
        let line = py
            .lines()
            .find(|l| l.starts_with("CURRENT_VERSION = "))
            .unwrap();
        assert_eq!(line, format!("CURRENT_VERSION = \"{CURRENT_VERSION}\""));
    }

    #[test]
    fn release_json_is_read_like_python() {
        let r = Release::from_json(&json!({"tag_name": "vv0.1.99", "name": "v0.1.99",
            "html_url": "https://x", "body": null}))
        .unwrap();
        assert_eq!(r.tag_name, "0.1.99");
        assert_eq!(r.body, Value::Null);
        assert_eq!(r.published_at, json!(""));
        assert!(Release::from_json(&json!({"tag_name": "v1", "name": null})).is_none());
        assert!(Release::from_json(&json!({"tag_name": 1})).is_none());
        assert!(Release::from_json(&json!([])).is_none());
        assert_eq!(Release::from_json(&json!({})).unwrap().tag_name, "");
    }

    #[test]
    fn compare_outcomes() {
        let rel = |tag: &str| Release {
            tag_name: tag.into(),
            html_url: json!("https://example.com/r"),
            published_at: json!("2026-01-01T00:00:00Z"),
            body: json!("notes"),
        };
        let r = compare("0.1.98", Some(&rel("0.1.99"))).unwrap();
        assert!(r.is_outdated);
        assert_eq!(r.message, "New version v0.1.99 available!");
        let r = compare("0.1.98", Some(&rel("0.1.98.0"))).unwrap();
        assert!(!r.is_outdated);
        assert_eq!(r.message, "You're up to date");
        let r = compare("0.1.98", Some(&rel("latest"))).unwrap();
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"success": false, "message": "Error checking version", "current_version": "0.1.98",
                   "latest_version": "latest", "is_outdated": false,
                   "release_url": "https://example.com/r", "release_notes": null, "published_at": null})
        );
        let r = compare("0.1.98", None).unwrap();
        assert_eq!(r.message, "Unable to check for updates");
        assert!(
            compare(
                "0.1.98",
                Some(&Release {
                    body: json!(5),
                    ..rel("0.2")
                })
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn fetches_with_a_user_agent_and_degrades_on_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/latest"))
            .and(header_exists("user-agent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tag_name": "v0.2.0", "name": "v0.2.0", "html_url": "https://example.com/r",
                "published_at": "2026-10-01T00:00:00Z", "body": "notes"})))
            .mount(&server)
            .await;
        let checker = VersionChecker::new(Some(format!("{}/latest", server.uri()))).unwrap();
        let r = checker.check().await.unwrap();
        assert!(r.success && r.is_outdated, "{r:?}");
        assert_eq!(r.latest_version.as_deref(), Some("0.2.0"));

        let missing = VersionChecker::new(Some(format!("{}/missing", server.uri()))).unwrap();
        let r = missing.check().await.unwrap();
        assert_eq!(r.message, "Unable to check for updates");
        assert_eq!(r.current_version, CURRENT_VERSION);
    }
}
