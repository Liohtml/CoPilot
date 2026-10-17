//! `_ProvisioningRollback` (Office 365 and AWS): every externally visible
//! step registers its undo; on a failure they run newest-first, one failing
//! undo never stops the rest, and the ones that failed are reported.

use copilot_integration_provisioning::grafana::{ES_CONNECTION_ERROR, ES_TRANSPORT_ERROR};
use copilot_upstream::py::PyExc;

use crate::Tools;

/// What one step created.
#[derive(Debug, Clone)]
pub enum Undo {
    /// An Office 365 tenant's `<api_auth>` block
    /// (`decommission_office365_tenant`).
    Office365Tenant(String),
    /// `delete_index_by_id(index_id)`.
    IndexSet(String),
    /// `delete_stream(stream_id)`.
    Stream(String),
    /// `delete_grafana_datasource(organization_id, datasource_uid)`.
    Datasource {
        /// The organization.
        org: String,
        /// The datasource's uid.
        uid: String,
    },
    /// `delete_folder(organization_id, folder_id)`.
    Folder {
        /// The organization.
        org: String,
        /// The folder's id.
        folder: String,
    },
}

/// How a failed undo is described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// `f"{description} ({exc})"` (Office 365).
    Str,
    /// `f"{description} ({getattr(exc, 'detail', None) or exc})"` (AWS).
    Detail,
}

/// The registered steps.
#[derive(Debug, Default)]
pub struct Rollback {
    steps: Vec<(String, Undo)>,
}

impl Rollback {
    /// `rollback.add(description, undo)`.
    pub fn add(&mut self, description: impl Into<String>, undo: Undo) {
        self.steps.push((description.into(), undo));
    }

    /// `rollback.run()`: the descriptions that could not be undone.
    pub async fn run(&self, tools: Tools<'_>, style: Style) -> Vec<String> {
        let mut failures = Vec::new();
        for (description, undo) in self.steps.iter().rev() {
            tracing::info!("Rolling back: {description}");
            if let Err(e) = undo_one(tools, undo).await {
                tracing::error!("Could not roll back {description}: {}", e.display());
                let shown = match (style, &e) {
                    (Style::Detail, PyExc::Http(_, detail)) if !detail.is_empty() => detail.clone(),
                    _ => e.display(),
                };
                failures.push(format!("{description} ({shown})"));
            }
        }
        failures
    }
}

async fn undo_one(tools: Tools<'_>, undo: &Undo) -> Result<(), PyExc> {
    use copilot_integrations::integrations::cleanup;
    match undo {
        Undo::Office365Tenant(tenant) => {
            copilot_integrations::office365::decommission_tenant(tools.wazuh, tenant).await
        }
        Undo::IndexSet(id) => cleanup::delete_index(tools.graylog, id).await,
        Undo::Stream(id) => cleanup::delete_stream(tools.graylog, id).await,
        Undo::Datasource { org, uid } => cleanup::delete_datasource(tools.grafana, org, uid).await,
        Undo::Folder { org, folder } => cleanup::delete_folder(tools.grafana, org, folder).await,
    }
}

/// `getattr(exc, "detail", None) or str(exc)`.
pub fn detail_or_str(e: &PyExc) -> String {
    match e {
        PyExc::Http(_, detail) if !detail.is_empty() => detail.clone(),
        other => other.display(),
    }
}

/// `getattr(exc, "status_code", 500)`, for the status of the `HTTPException`
/// a failed deployment raises: an `HTTPException`'s, a `grafana_client`
/// exception's (`GrafanaException.status_code`: the HTTP status, 400 and 401
/// for the two fixed classes) and an elasticsearch-py `TransportError`'s; 500
/// for anything without one.
///
/// `None` is an elasticsearch-py `ConnectionError`'s `"N/A"`: Python's
/// handler writes the `log_entries` row, then `JSONResponse` fails comparing
/// the status with 200 and uvicorn answers its bare 500 ([`NOT_AN_HTTP_STATUS`]).
/// A `GrafanaTimeoutError`'s `0` is answered 500 here: uvicorn starts that
/// response, fails to look its status line up and closes the connection
/// without an answer (RUST_MIGRATION.md §4).
pub fn status_of(e: &PyExc) -> Option<u16> {
    fn leading_number(text: &str) -> Option<u16> {
        let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    }
    let status = match e {
        PyExc::Http(status, _) => Some(*status),
        PyExc::Other("GrafanaServerError", text) => {
            text.strip_prefix("Server Error ").and_then(leading_number)
        }
        PyExc::Other("GrafanaClientError", text) => {
            text.strip_prefix("Client Error ").and_then(leading_number)
        }
        PyExc::Other("GrafanaBadInputError", _) => Some(400),
        PyExc::Other("GrafanaUnauthorizedError", _) => Some(401),
        PyExc::Other(class, text) if *class == ES_TRANSPORT_ERROR => text
            .split_once('(')
            .and_then(|(_, rest)| leading_number(rest)),
        PyExc::Other(class, _) if *class == ES_CONNECTION_ERROR => return None,
        _ => Some(500),
    };
    Some(status.filter(|s| (100..600).contains(s)).unwrap_or(500))
}

/// The class of the exception a failed deployment ends in when its status is
/// no HTTP status ([`status_of`]'s `None`): its text is the `detail`, written
/// to `log_entries` before the bare 500 ([`failure_response`]).
pub const NOT_AN_HTTP_STATUS: &str = "HTTPException(status_code='N/A')";

/// The `HTTPException` a failed deployment raises: `status_of(exc)` with the
/// rolled-back message.
pub fn failure(exc: &PyExc, message: String) -> PyExc {
    match status_of(exc) {
        Some(status) => PyExc::http(status, message),
        None => PyExc::Other(NOT_AN_HTTP_STATUS, message),
    }
}

/// What a failed deployment answers: the `HTTPException` envelope, or for a
/// status that is none, the `log_entries` row and uvicorn's bare 500.
pub fn failure_response(e: PyExc) -> axum::response::Response {
    use axum::response::IntoResponse;
    match e {
        PyExc::Other(class, message) if class == NOT_AN_HTTP_STATUS => {
            let mut resp = copilot_web::ApiError::internal(format!(
                "JSONResponse(status_code='N/A'): {message}"
            ))
            .into_response();
            resp.extensions_mut()
                .insert(copilot_web::error::LoggedError { message });
            resp
        }
        other => other.unhandled().into_response(),
    }
}
