//! What a provisioning run created, undone when the run fails.
//!
//! Python's stack, integration, collector and customer provisioning stop at
//! the first failure and leave whatever they had created: Graylog content
//! packs and their installations, index sets, streams, Grafana
//! organizations, datasources and folders, Wazuh groups, the meta rows. A
//! retry then meets those objects (an index prefix Graylog refuses, a pack
//! that "already exists", a meta row that makes the run a 400). Here every
//! externally visible step a run *creates* registers its undo, and a failure
//! unwinds them newest-first, as `copilot-waf`'s forwarding and Python's own
//! `provision_office365` (`_ProvisioningRollback`) do: an object the run
//! *found* and reused is never registered, one failing undo is logged and
//! the rest still run, and the run answers what it answered without the
//! rollback (RUST_MIGRATION.md §4).

use std::path::PathBuf;

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_grafana::GrafanaClient;
use copilot_graylog::GraylogClient;
use copilot_upstream::py::{PyExc, PyResult, getitem};
use copilot_wazuh::WazuhState;
use copilot_wazuh::manager::client as manager;
use http::Method;

/// One object a run created.
#[derive(Debug, Clone)]
pub enum Undo {
    /// A content pack this run inserted, installed or not: its
    /// installation removed (when installed), then the pack.
    ContentPack {
        /// The Graylog connector.
        connector: &'static str,
        /// The pack's id.
        id: String,
        /// Whether the run installed it too.
        installed: bool,
    },
    /// `DELETE /api/system/indices/index_sets/{id}`.
    IndexSet {
        /// The Graylog connector.
        connector: &'static str,
        /// The index set's id.
        id: String,
    },
    /// `DELETE /api/streams/{id}` (a stream the run created itself, or one
    /// a pack it installed created: removed before that pack's index set,
    /// which Graylog keeps while a stream is assigned to it).
    Stream {
        /// The Graylog connector.
        connector: &'static str,
        /// The stream's id.
        id: String,
    },
    /// `DELETE /api/system/pipelines/rule/{id}`.
    PipelineRule {
        /// The Graylog connector.
        connector: &'static str,
        /// The rule's id.
        id: String,
    },
    /// A Grafana organization: `DELETE /orgs/{id}`.
    GrafanaOrganization {
        /// The organization's id.
        id: String,
    },
    /// A Grafana datasource: `DELETE /datasources/uid/{uid}` in `org`.
    Datasource {
        /// The organization.
        org: String,
        /// The datasource's uid.
        uid: String,
    },
    /// A Grafana folder (and the dashboards in it): `DELETE /folders/{uid}`
    /// in `org`.
    Folder {
        /// The organization.
        org: String,
        /// The folder's uid.
        uid: String,
    },
    /// A Wazuh group: `DELETE /groups?groups_list={name}`.
    WazuhGroup(String),
    /// A row: `DELETE FROM {table} WHERE id = ?`.
    Row {
        /// The table.
        table: &'static str,
        /// The row's id.
        id: i64,
    },
    /// Rows whose `deployed` this run set: back to `0`.
    Deployed {
        /// The table.
        table: &'static str,
        /// The rows' ids.
        ids: Vec<i64>,
    },
    /// A file the run wrote (`created`: it did not exist before).
    File(PathBuf),
    /// A directory the run created (removed when empty).
    Directory(PathBuf),
}

/// What the undos reach.
#[derive(Debug, Clone, Copy)]
pub struct UndoTools<'a> {
    /// The database.
    pub db: &'a Db,
    /// Graylog.
    pub graylog: &'a GraylogClient,
    /// Grafana.
    pub grafana: &'a GrafanaClient,
    /// The Wazuh manager (the customer provisioning's groups).
    pub wazuh: Option<&'a WazuhState>,
}

/// The registered undos, oldest first.
#[derive(Debug, Default)]
pub struct Rollback {
    steps: Vec<(String, Undo)>,
}

impl Rollback {
    /// A step that created something.
    pub fn add(&mut self, description: impl Into<String>, undo: Undo) {
        self.steps.push((description.into(), undo));
    }

    /// The content pack `id` this run inserted is installed too.
    pub fn set_installed(&mut self, pack: &str) {
        for (_, undo) in self.steps.iter_mut().rev() {
            if let Undo::ContentPack { id, installed, .. } = undo {
                if id == pack {
                    *installed = true;
                    return;
                }
            }
        }
    }

    /// The index set `id` is kept whatever happens: a stream the run did
    /// not create was moved onto it, and deleting it would leave that
    /// stream on a missing index set.
    pub fn keep_index_set(&mut self, index_set: &str) {
        self.steps
            .retain(|(_, undo)| !matches!(undo, Undo::IndexSet { id, .. } if id == index_set));
    }

    /// Whether anything was registered.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// The registered steps' descriptions, oldest first.
    pub fn descriptions(&self) -> Vec<&str> {
        self.steps.iter().map(|(d, _)| d.as_str()).collect()
    }

    /// Undo every step, newest first; a failing undo is logged and the rest
    /// still run. The descriptions that could not be undone.
    pub async fn run(&self, tools: UndoTools<'_>) -> Vec<String> {
        let mut failed = Vec::new();
        for (description, undo) in self.steps.iter().rev() {
            tracing::info!("Rolling back: {description}");
            if let Err(e) = undo_one(tools, undo).await {
                tracing::error!("Could not roll back {description}: {}", e.display());
                failed.push(format!("{description} ({})", e.display()));
            }
        }
        failed
    }
}

fn ok_reply(success: bool, what: &str) -> PyResult<()> {
    if success {
        Ok(())
    } else {
        Err(PyExc::http(500, format!("Failed to delete {what}")))
    }
}

async fn undo_one(tools: UndoTools<'_>, undo: &Undo) -> PyResult<()> {
    let gl = tools.graylog;
    match undo {
        Undo::ContentPack {
            connector,
            id,
            installed,
        } => {
            // The installation first (it removes what it created); the pack is
            // deleted whatever the uninstall gave, the first failure reported.
            let uninstalled = if *installed {
                uninstall(gl, connector, id).await
            } else {
                Ok(())
            };
            let reply = gl
                .delete_on(connector, &format!("/api/system/content_packs/{id}"), &[])
                .await?;
            uninstalled?;
            ok_reply(reply.success, &format!("content pack {id}"))
        }
        Undo::IndexSet { connector, id } => {
            let reply = gl
                .delete_on(
                    connector,
                    &format!("/api/system/indices/index_sets/{id}"),
                    &[],
                )
                .await?;
            ok_reply(reply.success, &format!("index set {id}"))
        }
        Undo::Stream { connector, id } => {
            let reply = gl
                .delete_on(connector, &format!("/api/streams/{id}"), &[])
                .await?;
            ok_reply(reply.success, &format!("stream {id}"))
        }
        Undo::PipelineRule { connector, id } => {
            let reply = gl
                .delete_on(connector, &format!("/api/system/pipelines/rule/{id}"), &[])
                .await?;
            ok_reply(reply.success, &format!("pipeline rule {id}"))
        }
        Undo::GrafanaOrganization { id } => {
            let api = tools
                .grafana
                .create(copilot_grafana::client::CONNECTOR)
                .await?;
            tools
                .grafana
                .call(
                    &api,
                    Method::DELETE,
                    &format!("/orgs/{id}"),
                    None,
                    Vec::new(),
                )
                .await?;
            Ok(())
        }
        Undo::Datasource { org, uid } => {
            let api = tools
                .grafana
                .create(copilot_grafana::client::CONNECTOR)
                .await?;
            tools.grafana.switch_organization(&api, org).await?;
            tools.grafana.delete_datasource_by_uid(&api, uid).await?;
            Ok(())
        }
        Undo::Folder { org, uid } => {
            let api = tools
                .grafana
                .create(copilot_grafana::client::CONNECTOR)
                .await?;
            tools.grafana.switch_organization(&api, org).await?;
            tools.grafana.delete_folder(&api, uid).await?;
            Ok(())
        }
        Undo::WazuhGroup(name) => {
            let Some(wazuh) = tools.wazuh else {
                return Err(PyExc::Other("RuntimeError", "no Wazuh manager".into()));
            };
            let params = [("groups_list".to_string(), manager::Param::Str(name.clone()))];
            let answer = manager::send_delete(wazuh, "/groups", Some(&params))
                .await
                .map_err(|e| PyExc::Other("Exception", format!("{e:?}")))?;
            if answer.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
                return Err(PyExc::http(
                    500,
                    format!("Failed to delete Wazuh group {name}"),
                ));
            }
            Ok(())
        }
        Undo::Row { table, id } => {
            sqlx::query(&format!("DELETE FROM {table} WHERE id = ?"))
                .bind(id)
                .execute(tools.db.pool())
                .await
                .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
            Ok(())
        }
        Undo::Deployed { table, ids } => {
            for id in ids {
                sqlx::query(&format!("UPDATE {table} SET deployed = 0 WHERE id = ?"))
                    .bind(id)
                    .execute(tools.db.pool())
                    .await
                    .map_err(|e| PyExc::Other("OperationalError", e.to_string()))?;
            }
            Ok(())
        }
        Undo::File(path) => std::fs::remove_file(path)
            .map_err(|e| PyExc::Other("OSError", format!("{e}: {}", path.display()))),
        Undo::Directory(path) => std::fs::remove_dir(path)
            .map_err(|e| PyExc::Other("OSError", format!("{e}: {}", path.display()))),
    }
}

/// Remove every installation of the content pack `id`.
async fn uninstall(gl: &GraylogClient, connector: &str, id: &str) -> PyResult<()> {
    let reply = gl
        .get_on(
            connector,
            &format!("/api/system/content_packs/{id}/installations"),
            &[],
        )
        .await?;
    if let PyValue::List(items) = getitem(&reply.data, "installations")? {
        for installation in items {
            let installation_id = getitem(installation, "_id")?.py_str();
            let reply = gl
                .delete_on(
                    connector,
                    &format!("/api/system/content_packs/{id}/installations/{installation_id}"),
                    &[],
                )
                .await?;
            ok_reply(reply.success, &format!("installation {installation_id}"))?;
        }
    }
    Ok(())
}

/// The text of an id Graylog or Grafana answered (`str()` of the value).
pub fn id_text(v: &PyValue) -> Option<String> {
    match v {
        PyValue::None => None,
        PyValue::Str(s) if s.is_empty() => None,
        other => Some(other.py_str()),
    }
}
