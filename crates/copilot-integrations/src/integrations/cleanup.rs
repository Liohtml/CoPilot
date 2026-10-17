//! `_cleanup_integration_infrastructure`: what a deployed integration's
//! metadata recorded in Graylog and Grafana, removed resource by resource —
//! a failure is a warning for the caller, never the request's failure.
//!
//! The Graylog stream goes with every instance; the index set, the Grafana
//! folder and the datasource only with the customer's last instance of a
//! multi-instance integration (`stream_only` otherwise: every Office365
//! tenant writes into the one `office365-<code>` index set).

use copilot_grafana::GrafanaClient;
use copilot_graylog::GraylogClient;
use copilot_upstream::model::{Field, Model, Ty, construct_star, field};
use copilot_upstream::py::{PyExc, PyResult, iterate};

/// The metadata fields the cleanup reads (an integration's or a network
/// connector's row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resources {
    /// `graylog_stream_id`.
    pub stream_id: String,
    /// `graylog_index_id`.
    pub index_id: String,
    /// `grafana_org_id`.
    pub org_id: String,
    /// `grafana_dashboard_folder_id`.
    pub folder_id: String,
    /// `grafana_datasource_uid`.
    pub datasource_uid: Option<String>,
}

/// `app/connectors/grafana/schema/folders.py:Folder`.
static FOLDER: Model = Model::new(
    "Folder",
    &[
        Field::req("id", Ty::Int),
        Field::req("uid", Ty::Str),
        Field::req("title", Ty::Str),
    ],
);

/// `delete_stream(stream_id)`.
pub async fn delete_stream(graylog: &GraylogClient, id: &str) -> PyResult<()> {
    let reply = graylog.delete(&format!("/api/streams/{id}"), &[]).await?;
    if reply.success {
        Ok(())
    } else {
        Err(PyExc::http(500, format!("Failed to delete stream {id}")))
    }
}

/// `delete_index_by_id(index_id)` (a failed answer is not looked at).
pub async fn delete_index(graylog: &GraylogClient, id: &str) -> PyResult<()> {
    graylog
        .delete(&format!("/api/system/indices/index_sets/{id}"), &[])
        .await?;
    Ok(())
}

/// `app/connectors/grafana/services/folders.py:delete_folder`: the folder
/// matched by its numeric id *or* its uid.
pub async fn delete_folder(grafana: &GrafanaClient, org: &str, folder: &str) -> PyResult<()> {
    let attempt = async {
        let api = grafana.create(copilot_grafana::client::CONNECTOR).await?;
        grafana.switch_organization(&api, org).await?;
        let all = grafana.get_all_folders(&api).await?;
        let mut folders = Vec::new();
        for item in iterate(&all)? {
            folders.push(construct_star(
                &FOLDER,
                "app.connectors.grafana.schema.folders.Folder",
                &item,
            )?);
        }
        let uid = folders.iter().find_map(|f| {
            let id = field(f, "id").py_str();
            let uid = field(f, "uid").py_str();
            (id == folder || uid == folder).then_some(uid)
        });
        let Some(uid) = uid.filter(|u| !u.is_empty()) else {
            return Err(PyExc::http(
                404,
                format!("Folder with ID {folder} not found"),
            ));
        };
        grafana.delete_folder(&api, &uid).await?;
        Ok(())
    }
    .await;
    match attempt {
        Ok(()) => Ok(()),
        Err(e @ PyExc::Http(..)) => Err(e),
        Err(e) => Err(PyExc::http(
            500,
            format!("Error deleting dashboard folder: {}", e.text()),
        )),
    }
}

/// `customer_provisioning/services/grafana.py:delete_grafana_datasource`.
pub async fn delete_datasource(grafana: &GrafanaClient, org: &str, uid: &str) -> PyResult<()> {
    let api = grafana.create(copilot_grafana::client::CONNECTOR).await?;
    grafana.switch_organization(&api, org).await?;
    grafana.delete_datasource_by_uid(&api, uid).await?;
    Ok(())
}

fn warn(warnings: &mut Vec<String>, what: &str, name: &str, code: &str, e: &PyExc) {
    tracing::warn!(
        "Failed to delete {what} for {name} / {code}: {}",
        e.display()
    );
    warnings.push(format!(
        "Could not delete {what}: {}. Remove it manually if it still exists.",
        e.display()
    ));
}

/// `_cleanup_integration_infrastructure(meta, code, name, warnings,
/// stream_only)`.
pub async fn cleanup(
    graylog: &GraylogClient,
    grafana: &GrafanaClient,
    meta: &Resources,
    code: &str,
    name: &str,
    warnings: &mut Vec<String>,
    stream_only: bool,
) {
    if !meta.stream_id.is_empty() {
        let what = format!("Graylog stream {}", meta.stream_id);
        if let Err(e) = delete_stream(graylog, &meta.stream_id).await {
            warn(warnings, &what, name, code, &e);
        }
    }
    if stream_only {
        tracing::info!(
            "Other instances of {name} are still deployed for {code}; keeping the shared index \
             set, Grafana folder and datasource."
        );
        return;
    }
    if !meta.index_id.is_empty() {
        let what = format!("Graylog index {}", meta.index_id);
        if let Err(e) = delete_index(graylog, &meta.index_id).await {
            warn(warnings, &what, name, code, &e);
        }
    }
    if !meta.org_id.is_empty() && !meta.folder_id.is_empty() {
        let what = format!("Grafana dashboard folder {}", meta.folder_id);
        if let Err(e) = delete_folder(grafana, &meta.org_id, &meta.folder_id).await {
            warn(warnings, &what, name, code, &e);
        }
    }
    match meta.datasource_uid.as_deref() {
        Some(uid) if !meta.org_id.is_empty() && !uid.is_empty() => {
            let what = format!("Grafana datasource {uid}");
            if let Err(e) = delete_datasource(grafana, &meta.org_id, uid).await {
                warn(warnings, &what, name, code, &e);
            }
        }
        _ => {}
    }
}
