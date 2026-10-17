//! The statements of the provisioning flows: the customer's meta row (its
//! Grafana organization), connector id 1, the network connector's
//! `customer_network_connectors_meta` row and `deployed` flag.

use copilot_auth::pyvalue::PyValue;
use copilot_db::Db;
use copilot_db::connectors::ConnectorRow;
use copilot_upstream::py::{PyExc, PyResult};

fn db(e: impl std::fmt::Display) -> PyExc {
    PyExc::Other("OperationalError", e.to_string())
}

/// `get_customer_meta_attribute(code, "customer_meta_grafana_org_id")`:
/// the first meta row's organization, `None` without one.
pub async fn grafana_org_attribute(pool: &Db, code: &str) -> PyResult<Option<String>> {
    Ok(copilot_db::customers::find_customer_meta(pool, code)
        .await
        .map_err(db)?
        .map(|m| m.customer_meta_grafana_org_id))
}

/// `(await get_customer_meta(code, session)).customer_meta
/// .customer_meta_grafana_org_id`: the 404 without a meta row.
pub async fn grafana_org_id(pool: &Db, code: &str) -> PyResult<String> {
    grafana_org_attribute(pool, code).await?.ok_or_else(|| {
        PyExc::http(
            404,
            format!("Customer meta with customer_code {code} not found"),
        )
    })
}

/// `get_connector_attribute(connector_id=…, …)`'s row.
pub async fn connector_by_id(pool: &Db, id: i64) -> PyResult<Option<ConnectorRow>> {
    copilot_db::connectors::find_by_id(pool, id)
        .await
        .map_err(db)
}

/// A `str` column's value as SQLAlchemy binds it (`None` is `NULL`).
pub fn text(v: &PyValue) -> Option<String> {
    match v {
        PyValue::None => None,
        other => Some(other.py_str()),
    }
}

/// One `CustomerNetworkConnectorsMeta(...)` before its insert.
#[derive(Debug, Clone)]
pub struct NetworkMeta {
    /// `customer_code`.
    pub customer_code: String,
    /// `network_connector_name`.
    pub network_connector_name: &'static str,
    /// `graylog_stream_id`.
    pub graylog_stream_id: PyValue,
    /// `graylog_input_id`.
    pub graylog_input_id: PyValue,
    /// `graylog_pipeline_id`.
    pub graylog_pipeline_id: PyValue,
    /// `graylog_content_pack_input_id`.
    pub graylog_content_pack_input_id: PyValue,
    /// `graylog_content_pack_stream_id`.
    pub graylog_content_pack_stream_id: PyValue,
    /// `grafana_org_id`.
    pub grafana_org_id: Option<String>,
    /// `graylog_index_id`.
    pub graylog_index_id: PyValue,
    /// `grafana_dashboard_folder_id`.
    pub grafana_dashboard_folder_id: PyValue,
    /// `grafana_datasource_uid`.
    pub grafana_datasource_uid: PyValue,
}

/// `insert_into_customer_network_connectors_meta_table`: add, commit. A
/// `NULL` in a `NOT NULL` column is MySQL's refusal (the `IntegrityError`).
pub async fn insert_network_meta(pool: &Db, meta: &NetworkMeta) -> PyResult<()> {
    sqlx::query(
        "INSERT INTO customer_network_connectors_meta (customer_code, network_connector_name, \
         graylog_input_id, graylog_index_id, graylog_stream_id, graylog_pipeline_id, \
         graylog_content_pack_input_id, graylog_content_pack_stream_id, grafana_org_id, \
         grafana_dashboard_folder_id, grafana_datasource_uid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, \
         ?, ?, ?)",
    )
    .bind(&meta.customer_code)
    .bind(meta.network_connector_name)
    .bind(text(&meta.graylog_input_id))
    .bind(text(&meta.graylog_index_id))
    .bind(text(&meta.graylog_stream_id))
    .bind(text(&meta.graylog_pipeline_id))
    .bind(text(&meta.graylog_content_pack_input_id))
    .bind(text(&meta.graylog_content_pack_stream_id))
    .bind(meta.grafana_org_id.as_deref())
    .bind(text(&meta.grafana_dashboard_folder_id))
    .bind(text(&meta.grafana_datasource_uid))
    .persistent(false)
    .execute(pool.pool())
    .await
    .map_err(|e| PyExc::Other("IntegrityError", e.to_string()))?;
    Ok(())
}

/// `set_deployed_flag(code, service_name, True)`: the first matching
/// `customer_network_connectors` row (`None.deployed` without one).
pub async fn set_network_deployed(pool: &Db, code: &str, service_name: &str) -> PyResult<()> {
    let ids: Vec<(i32,)> = sqlx::query_as(
        "SELECT id FROM customer_network_connectors WHERE customer_code = ? AND \
         network_connector_service_name = ?",
    )
    .bind(code)
    .bind(service_name)
    .persistent(false)
    .fetch_all(pool.pool())
    .await
    .map_err(db)?;
    let Some((id,)) = ids.into_iter().next() else {
        return Err(PyExc::AttributeError(
            "'NoneType' object has no attribute 'deployed'".into(),
        ));
    };
    sqlx::query("UPDATE customer_network_connectors SET deployed = 1 WHERE id = ?")
        .bind(id)
        .execute(pool.pool())
        .await
        .map_err(db)?;
    Ok(())
}
