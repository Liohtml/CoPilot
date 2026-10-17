//! `app/status/schema/context.py`: one indicator and the sidebar answer.

use serde::Serialize;

/// `SidebarHealthIndicator`, in its field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Indicator {
    /// `id`: `connectors`, `scheduler`, `wazuh_catalog`, …
    pub id: &'static str,
    /// `ok`, `warning` or `error`.
    pub status: &'static str,
    /// `label`.
    pub label: &'static str,
    /// `detail`.
    pub detail: Option<String>,
    /// `count`.
    pub count: Option<i64>,
    /// `category`: `triage`, `ai`, `operations`, `infrastructure`, `platform`.
    pub category: Option<&'static str>,
}

impl Indicator {
    /// An indicator with every field set (as every builder sets them).
    pub fn new(
        id: &'static str,
        status: &'static str,
        label: &'static str,
        detail: impl Into<String>,
        count: i64,
        category: &'static str,
    ) -> Self {
        Self {
            id,
            status,
            label,
            detail: Some(detail.into()),
            count: Some(count),
            category: Some(category),
        }
    }
}

/// `SidebarContextResponse`, in its field order.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SidebarResponse {
    /// Always `true`.
    pub success: bool,
    /// `Sidebar context loaded`.
    pub message: &'static str,
    /// The running release.
    pub current_version: String,
    /// GitHub's latest tag (without its `v`).
    pub latest_version: Option<String>,
    /// `current < latest`.
    pub is_outdated: bool,
    /// The release page.
    pub release_url: Option<String>,
    /// `ENVIRONMENT` (default `PRODUCTION`).
    pub environment: String,
    /// The per-user indicators, then the shared ones the caller may see.
    pub indicators: Vec<Indicator>,
}
