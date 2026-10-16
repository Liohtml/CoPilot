//! Graylog stack provisioning — port of
//! `app/stack_provisioning/graylog/services/{provision,utils,decommission}.py`
//! and of the Graylog connector services they call
//! (`content_packs.py`, `management.get_system_info`, `pipelines.py`).
//!
//! Each `try`/`except` is kept where Python has it, which decides the text a
//! failure carries: `get_content_packs` turns everything (the GET's own
//! `HTTPException` included, as `"{status}: {detail}"`) into
//! `500 Failed to collect content packs: …`; `insert_content_pack` re-raises
//! an `HTTPException` as `500 Failed to insert content pack: …` unless it is
//! Graylog's "already found" for a `PROCESSING_PIPELINE` pack;
//! `install_content_pack` wraps every failure as `500 Failed to install
//! content pack: …`; the version check, the pipeline-rule read and create and
//! the decommissioning steps let theirs through.

use copilot_auth::pyvalue::PyValue;
use copilot_db::{Db, DbError};
use copilot_grafana::GrafanaClient;
use copilot_graylog::GraylogClient;
use copilot_graylog::client::{DEFAULT_CONNECTOR, create_entity_body};
use copilot_platform::pep440::Version;
use copilot_upstream::model::{construct, construct_star, field, kwargs};
use copilot_upstream::py::{PyExc, PyResult, getitem, type_name};

use crate::schema::{CONTENT_PACK_LIST, GRAYLOG_SERVER_INFO};
use crate::templates;

/// The Graylog version the content packs need (`system_version_check`).
pub const COMPATIBLE_VERSION: &str = "5.0.13+083613e";
/// The pipeline rule `check_pipeline_rules` makes sure exists.
pub const ETW_RULE_TITLE: &str = "Set Syslog Level to ALERT for ETW Registry";
/// `install_content_pack`'s comment.
pub const INSTALL_COMMENT: &str = "Installed by SOCFortress CoPilot";

fn st(s: &str) -> PyValue {
    PyValue::Str(s.to_string())
}

/// `get_system_info().version`.
async fn graylog_version(c: &GraylogClient) -> PyResult<String> {
    let reply = c.get("/api/system", &[]).await?;
    let info = construct_star(
        &GRAYLOG_SERVER_INFO,
        "app.connectors.graylog.schema.management.GraylogServerInfo",
        &reply.data,
    )?;
    Ok(field(&info, "version").py_str())
}

/// `system_version_check(compatible_version)`.
pub async fn system_version_check(c: &GraylogClient) -> PyResult<()> {
    let system = graylog_version(c).await?;
    let invalid = |v: &str| {
        PyExc::http(
            400,
            format!(
                "Invalid version format: Invalid version: {}",
                PyValue::Str(v.to_string()).py_repr()
            ),
        )
    };
    let parsed = Version::parse(&system).ok_or_else(|| invalid(&system))?;
    let compatible =
        Version::parse(COMPATIBLE_VERSION).ok_or_else(|| invalid(COMPATIBLE_VERSION))?;
    if parsed >= compatible {
        Ok(())
    } else {
        Err(PyExc::http(
            400,
            format!("Graylog version {system} is not compatible with the content pack"),
        ))
    }
}

/// `get_content_packs()`: each pack's `name`.
async fn content_pack_names(c: &GraylogClient) -> PyResult<Vec<String>> {
    let wrap = |e: PyExc| match e {
        PyExc::KeyError(k) => PyExc::http(500, format!("Failed to collect content packs key: {k}")),
        other => PyExc::http(
            500,
            format!("Failed to collect content packs: {}", other.display()),
        ),
    };
    let reply = c
        .get("/api/system/content_packs", &[])
        .await
        .map_err(wrap)?;
    let list = construct(&CONTENT_PACK_LIST, &reply.data).map_err(wrap)?;
    let PyValue::List(packs) = field(&list, "content_packs") else {
        return Ok(Vec::new());
    };
    Ok(packs.iter().map(|p| field(p, "name").py_str()).collect())
}

/// `does_content_pack_exist(name)`: `True` for an installed
/// `PROCESSING_PIPELINE` pack, 400 for any other installed one.
pub async fn does_content_pack_exist(c: &GraylogClient, name: &str) -> PyResult<bool> {
    for pack in content_pack_names(c).await? {
        if pack == name {
            if pack.contains("PROCESSING_PIPELINE") {
                return Ok(true);
            }
            return Err(PyExc::http(
                400,
                format!("Content pack {name} already exists"),
            ));
        }
    }
    Ok(false)
}

/// `insert_content_pack(content_pack)`.
async fn insert_content_pack(c: &GraylogClient, pack: &PyValue) -> PyResult<bool> {
    match c
        .post("/api/system/content_packs", Some(pack.clone()))
        .await
    {
        Ok(_) => Ok(true),
        Err(PyExc::Http(status, detail)) => {
            let pipeline = getitem(pack, "name")?
                .py_str()
                .contains("PROCESSING_PIPELINE");
            if detail.contains("Content pack") && detail.contains("already found") && pipeline {
                Ok(false)
            } else {
                Err(PyExc::http(
                    500,
                    format!(
                        "Failed to insert content pack: {}",
                        PyExc::http_str(status, &detail)
                    ),
                ))
            }
        }
        Err(PyExc::KeyError(k)) => Err(PyExc::http(
            500,
            format!("Failed to insert content pack key: {k}"),
        )),
        Err(other) => Err(PyExc::http(
            500,
            format!("Failed to insert content pack: {}", other.display()),
        )),
    }
}

/// `install_content_pack(id, revision)`: `send_post_request_create_entity`
/// on the f-string path of whatever the template carries.
async fn install_content_pack(c: &GraylogClient, id: &PyValue, rev: &PyValue) -> PyResult<()> {
    let endpoint = format!(
        "/api/system/content_packs/{}/{}/installations",
        id.py_str(),
        rev.py_str()
    );
    let entity = kwargs(vec![("comment", st(INSTALL_COMMENT))]);
    let major = c.major_version(DEFAULT_CONNECTOR).await;
    let body = create_entity_body(major, entity, None);
    match c.post(&endpoint, Some(body)).await {
        Ok(_) => Ok(()),
        Err(PyExc::KeyError(k)) => Err(PyExc::http(
            500,
            format!("Failed to install content pack key: {k}"),
        )),
        Err(other) => Err(PyExc::http(
            500,
            format!("Failed to install content pack: {}", other.display()),
        )),
    }
}

/// `provision_content_pack(request)`: insert, then install.
pub async fn provision_content_pack(c: &GraylogClient, name: &str) -> PyResult<()> {
    let pack = templates::content_pack(name)
        .ok_or_else(|| PyExc::http(404, "Content pack JSON file not found"))?;
    insert_content_pack(c, &pack).await?;
    let id = pack.get("id").cloned().unwrap_or(PyValue::None);
    let rev = pack.get("rev").cloned().unwrap_or(PyValue::None);
    install_content_pack(c, &id, &rev).await
}

/// The ETW rule's source, as `create_etw_rule` writes it.
pub fn etw_rule_source() -> String {
    format!(
        "rule \"{ETW_RULE_TITLE}\"\nwhen\n  has_field(\"syscheck_path\") &&\n  \
         starts_with(to_string($message.syscheck_path), \
         \"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\WMI\\\\Autologger\\\\EventLog\")\n\
         then\n  set_field(\"syslog_level\", \"ALERT\");\nend"
    )
}

/// `check_pipeline_rules()`: create the ETW rule when no rule has its title.
pub async fn check_pipeline_rules(c: &GraylogClient) -> PyResult<()> {
    let rules = copilot_graylog::services::pipeline_rules(c).await?;
    let exists = match field(&rules, "pipeline_rules") {
        PyValue::List(items) => items
            .iter()
            .any(|r| field(r, "title") == &st(ETW_RULE_TITLE)),
        _ => false,
    };
    if !exists {
        let data = kwargs(vec![
            ("title", st(ETW_RULE_TITLE)),
            ("description", st(ETW_RULE_TITLE)),
            ("source", PyValue::Str(etw_rule_source())),
        ]);
        c.post("/api/system/pipelines/rule", Some(data)).await?;
    }
    Ok(())
}

// --- network connectors ------------------------------------------------------

/// `customer_network_connectors_meta`'s columns.
pub const META_COLUMNS: &[&str] = &[
    "id",
    "customer_code",
    "network_connector_name",
    "graylog_input_id",
    "graylog_index_id",
    "graylog_stream_id",
    "graylog_pipeline_id",
    "graylog_content_pack_input_id",
    "graylog_content_pack_stream_id",
    "grafana_org_id",
    "grafana_dashboard_folder_id",
    "grafana_datasource_uid",
];

/// One `customer_network_connectors_meta` row (what decommissioning reads).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct NetworkConnectorMeta {
    /// `id`.
    pub id: i32,
    /// `customer_code`.
    pub customer_code: String,
    /// `network_connector_name`.
    pub network_connector_name: String,
    /// `graylog_content_pack_input_id`.
    pub graylog_content_pack_input_id: String,
    /// `graylog_content_pack_stream_id`.
    pub graylog_content_pack_stream_id: String,
    /// `grafana_org_id`.
    pub grafana_org_id: String,
    /// `grafana_dashboard_folder_id`.
    pub grafana_dashboard_folder_id: String,
    /// `grafana_datasource_uid`.
    pub grafana_datasource_uid: String,
}

fn db(e: impl Into<DbError>) -> PyExc {
    PyExc::Other("OperationalError", e.into().to_string())
}

/// `get_network_connectors_meta_by_customer_code_and_connector_name`: the
/// first row in the table's order.
pub async fn find_meta(
    pool: &Db,
    code: &str,
    name: &str,
) -> PyResult<Option<NetworkConnectorMeta>> {
    let rows: Vec<NetworkConnectorMeta> = sqlx::query_as(
        "SELECT id, customer_code, network_connector_name, graylog_content_pack_input_id, \
         graylog_content_pack_stream_id, grafana_org_id, grafana_dashboard_folder_id, \
         grafana_datasource_uid FROM customer_network_connectors_meta WHERE customer_code = ? \
         AND network_connector_name = ?",
    )
    .bind(code)
    .bind(name)
    .fetch_all(pool.pool())
    .await
    .map_err(db)?;
    Ok(rows.into_iter().next())
}

/// `x[0]` of a JSON value.
fn first(value: &PyValue) -> PyResult<&PyValue> {
    match value {
        PyValue::List(items) => items
            .first()
            .ok_or_else(|| PyExc::IndexError("list index out of range".into())),
        PyValue::Dict(_) => Err(PyExc::KeyError("0".into())),
        PyValue::Str(_) => Err(PyExc::IndexError("string index out of range".into())),
        other => Err(PyExc::TypeError(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        ))),
    }
}

/// `uninstall_content_pack(id)` then `delete_content_pack(id)`.
async fn uninstall_and_delete(c: &GraylogClient, id: &str) -> PyResult<()> {
    let reply = c
        .get(
            &format!("/api/system/content_packs/{id}/installations"),
            &[],
        )
        .await?;
    let installation = first(getitem(&reply.data, "installations")?)?;
    let installation_id = getitem(installation, "_id")?.py_str();
    c.delete(
        &format!("/api/system/content_packs/{id}/installations/{installation_id}"),
        &[],
    )
    .await?;
    c.delete(&format!("/api/system/content_packs/{id}"), &[])
        .await?;
    Ok(())
}

/// `decommission_network_connector(meta, session)`: the response dump.
pub async fn decommission_network_connector(
    pool: &Db,
    graylog: &GraylogClient,
    grafana: &GrafanaClient,
    meta: &NetworkConnectorMeta,
) -> PyResult<PyValue> {
    uninstall_and_delete(graylog, &meta.graylog_content_pack_input_id).await?;
    uninstall_and_delete(graylog, &meta.graylog_content_pack_stream_id).await?;
    // `delete_grafana_dashboard_folder`, then `delete_grafana_datasource`:
    // each builds its client and switches the user's organization first.
    let api = grafana.create(copilot_grafana::client::CONNECTOR).await?;
    grafana
        .switch_organization(&api, &meta.grafana_org_id)
        .await?;
    grafana
        .delete_folder(&api, &meta.grafana_dashboard_folder_id)
        .await?;
    let api = grafana.create(copilot_grafana::client::CONNECTOR).await?;
    grafana
        .switch_organization(&api, &meta.grafana_org_id)
        .await?;
    grafana
        .delete_datasource_by_uid(&api, &meta.grafana_datasource_uid)
        .await?;
    sqlx::query("DELETE FROM customer_network_connectors_meta WHERE id = ?")
        .bind(meta.id)
        .execute(pool.pool())
        .await
        .map_err(db)?;
    // `set_deployed_flag(..., flag=False)`: the first matching row, which
    // must exist (`None.deployed` is an `AttributeError`).
    let ids: Vec<(i32,)> = sqlx::query_as(
        "SELECT id FROM customer_network_connectors WHERE customer_code = ? AND \
         network_connector_service_name = ?",
    )
    .bind(&meta.customer_code)
    .bind(&meta.network_connector_name)
    .fetch_all(pool.pool())
    .await
    .map_err(db)?;
    let Some((id,)) = ids.into_iter().next() else {
        return Err(PyExc::AttributeError(
            "'NoneType' object has no attribute 'deployed'".into(),
        ));
    };
    sqlx::query("UPDATE customer_network_connectors SET deployed = 0 WHERE id = ?")
        .bind(id)
        .execute(pool.pool())
        .await
        .map_err(db)?;
    Ok(kwargs(vec![
        (
            "message",
            PyValue::Str(format!(
                "Network connector {} has been decommissioned. However, the indices still \
                 remain. If you want to remove the index set, do so within Graylog.",
                meta.network_connector_name
            )),
        ),
        ("success", PyValue::Bool(true)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_etw_rule_is_python_s() {
        let source = etw_rule_source();
        assert!(
            source.starts_with(
                "rule \"Set Syslog Level to ALERT for ETW Registry\"\nwhen\n  has_field"
            )
        );
        assert!(source.contains(
            r#"(to_string($message.syscheck_path), "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EventLog")"#
        ));
        assert!(source.ends_with("\nthen\n  set_field(\"syslog_level\", \"ALERT\");\nend"));
    }
}
