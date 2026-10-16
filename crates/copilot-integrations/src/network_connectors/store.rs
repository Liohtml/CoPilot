//! The statements of `app/network_connectors/routes.py`, in SQLAlchemy's
//! shapes.

use copilot_db::Db;
use sqlx::Row;
use sqlx::mysql::MySqlRow;

use crate::sql::{opt_bool, opt_int, opt_text, text};

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

/// One catalog entry with its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    /// `id`.
    pub id: i64,
    /// `network_connector_name`.
    pub name: String,
    /// `description`.
    pub description: String,
    /// `network_connector_details`.
    pub details: String,
    /// The key names, in row order.
    pub keys: Vec<String>,
}

const CATALOG: &str = "SELECT available_network_connectors.id, \
     available_network_connectors.network_connector_name, available_network_connectors.description, \
     available_network_connectors.network_connector_details, available_network_connectors_keys_1.id \
     AS id_1, available_network_connectors_keys_1.network_connector_id, \
     available_network_connectors_keys_1.network_connector_name AS network_connector_name_1, \
     available_network_connectors_keys_1.auth_key_name \nFROM available_network_connectors LEFT \
     OUTER JOIN available_network_connectors_keys AS available_network_connectors_keys_1 ON \
     available_network_connectors.id = available_network_connectors_keys_1.network_connector_id";

fn catalog_rows(rows: Vec<MySqlRow>) -> Result<Vec<Catalog>, sqlx::Error> {
    let mut out: Vec<Catalog> = Vec::new();
    for row in rows {
        let id = i64::from(row.try_get::<i32, _>(0)?);
        let pos = match out.iter().position(|c| c.id == id) {
            Some(p) => p,
            None => {
                out.push(Catalog {
                    id,
                    name: row.try_get(1)?,
                    description: row.try_get(2)?,
                    details: row.try_get(3)?,
                    keys: Vec::new(),
                });
                out.len() - 1
            }
        };
        if let (Some(_), Some(k)) = (
            row.try_get::<Option<i32>, _>(4)?,
            row.try_get::<Option<String>, _>(7)?,
        ) {
            out[pos].keys.push(k);
        }
    }
    Ok(out)
}

/// `fetch_available_network_connectors`.
pub async fn catalog(db: &Db) -> Result<Vec<Catalog>, sqlx::Error> {
    catalog_rows(sqlx::query(CATALOG).fetch_all(db.pool()).await?)
}

/// `fetch_available_network_connector_by_id`.
pub async fn catalog_by_id(db: &Db, id: i64) -> Result<Option<Catalog>, sqlx::Error> {
    let sql = format!("{CATALOG} \nWHERE available_network_connectors.id = ?");
    let rows = sqlx::query(&sql).bind(id).fetch_all(db.pool()).await?;
    Ok(catalog_rows(rows)?.into_iter().next())
}

/// The first catalog row named `name`: its id and stored name.
pub async fn catalog_first_by_name(
    db: &Db,
    name: &str,
) -> Result<Option<(i64, String)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT available_network_connectors.id, available_network_connectors.network_connector_name, \
         available_network_connectors.description, \
         available_network_connectors.network_connector_details \nFROM available_network_connectors \
         \nWHERE available_network_connectors.network_connector_name = ?",
    )
    .bind(name)
    .fetch_all(db.pool())
    .await?;
    match rows.first() {
        Some(r) => Ok(Some((i64::from(r.try_get::<i32, _>(0)?), r.try_get(1)?))),
        None => Ok(None),
    }
}

/// `network_connectors_services`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Service {
    pub id: i64,
    pub service_name: String,
    pub auth_type: String,
}

/// `network_connectors_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Key {
    pub id: i64,
    pub subscription_id: Option<i64>,
    pub auth_key_name: String,
    pub auth_value: String,
}

/// `network_connectors_subscriptions` with its service and keys.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Subscription {
    pub id: i64,
    pub customer_id: Option<i64>,
    pub service_id: i64,
    pub service: Option<Service>,
    pub keys: Vec<Key>,
}

/// One `customer_network_connectors` row with its subscriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct CustomerConnector {
    pub id: i64,
    pub customer_code: String,
    pub customer_name: String,
    pub service_id: i64,
    pub service_name: String,
    pub deployed: Option<bool>,
    pub subscriptions: Vec<Subscription>,
}

/// The customer connectors (all, or one customer's) with their
/// subscriptions (joined), services (joined) and keys (sub-query loaded).
pub async fn customer_connectors(
    db: &Db,
    code: Option<&str>,
) -> Result<Vec<CustomerConnector>, sqlx::Error> {
    let filter = if code.is_some() {
        " \nWHERE customer_network_connectors.customer_code = ?"
    } else {
        ""
    };
    let main = format!(
        "SELECT customer_network_connectors.id, customer_network_connectors.customer_code, \
         customer_network_connectors.customer_name, \
         customer_network_connectors.network_connector_service_id, \
         customer_network_connectors.network_connector_service_name, \
         customer_network_connectors.deployed, network_connectors_services_1.id AS id_1, \
         network_connectors_services_1.service_name, network_connectors_services_1.auth_type, \
         network_connectors_subscriptions_1.id AS id_2, \
         network_connectors_subscriptions_1.customer_id, \
         network_connectors_subscriptions_1.network_connectors_service_id \nFROM \
         customer_network_connectors LEFT OUTER JOIN network_connectors_subscriptions AS \
         network_connectors_subscriptions_1 ON customer_network_connectors.id = \
         network_connectors_subscriptions_1.customer_id LEFT OUTER JOIN network_connectors_services \
         AS network_connectors_services_1 ON network_connectors_services_1.id = \
         network_connectors_subscriptions_1.network_connectors_service_id{filter}"
    );
    let mut q = sqlx::query(&main);
    if let Some(c) = code {
        q = q.bind(c);
    }
    let rows = q.fetch_all(db.pool()).await?;
    let mut out: Vec<CustomerConnector> = Vec::new();
    for row in &rows {
        let id = i64::from(row.try_get::<i32, _>(0)?);
        let pos = match out.iter().position(|c| c.id == id) {
            Some(p) => p,
            None => {
                out.push(CustomerConnector {
                    id,
                    customer_code: text(row, "customer_code")?,
                    customer_name: text(row, "customer_name")?,
                    service_id: i64::from(row.try_get::<i32, _>(3)?),
                    service_name: text(row, "network_connector_service_name")?,
                    deployed: opt_bool(row, "deployed")?,
                    subscriptions: Vec::new(),
                });
                out.len() - 1
            }
        };
        let Some(sub_id) = row.try_get::<Option<i32>, _>(9)? else {
            continue;
        };
        let sub_id = i64::from(sub_id);
        if out[pos].subscriptions.iter().any(|s| s.id == sub_id) {
            continue;
        }
        let service = match row.try_get::<Option<i32>, _>(6)? {
            Some(sid) => Some(Service {
                id: i64::from(sid),
                service_name: row.try_get(7)?,
                auth_type: row.try_get(8)?,
            }),
            None => None,
        };
        out[pos].subscriptions.push(Subscription {
            id: sub_id,
            customer_id: row.try_get::<Option<i32>, _>(10)?.map(i64::from),
            service_id: i64::from(row.try_get::<i32, _>(11)?),
            service,
            keys: Vec::new(),
        });
    }
    if out.is_empty() {
        return Ok(out);
    }
    let sub = format!(
        "SELECT network_connectors_keys.id AS network_connectors_keys_id, \
         network_connectors_keys.subscription_id AS network_connectors_keys_subscription_id, \
         network_connectors_keys.auth_key_name AS network_connectors_keys_auth_key_name, \
         network_connectors_keys.auth_value AS network_connectors_keys_auth_value, \
         network_connectors_subscriptions_1.id AS network_connectors_subscriptions_1_id \nFROM \
         (SELECT customer_network_connectors.id AS customer_network_connectors_id \nFROM \
         customer_network_connectors{filter}) AS anon_1 INNER JOIN \
         network_connectors_subscriptions AS network_connectors_subscriptions_1 ON \
         anon_1.customer_network_connectors_id = network_connectors_subscriptions_1.customer_id \
         INNER JOIN network_connectors_keys ON network_connectors_subscriptions_1.id = \
         network_connectors_keys.subscription_id"
    );
    let mut q = sqlx::query(&sub);
    if let Some(c) = code {
        q = q.bind(c);
    }
    for row in q.fetch_all(db.pool()).await? {
        let parent = i64::from(row.try_get::<i32, _>(4)?);
        let key = Key {
            id: i64::from(row.try_get::<i32, _>(0)?),
            subscription_id: row.try_get::<Option<i32>, _>(1)?.map(i64::from),
            auth_key_name: row.try_get(2)?,
            auth_value: row.try_get(3)?,
        };
        for c in &mut out {
            for s in &mut c.subscriptions {
                if s.id == parent {
                    s.keys.push(key.clone());
                }
            }
        }
    }
    Ok(out)
}

/// Whether the customer already has this connector.
pub async fn exists(db: &Db, code: &str, name: &str) -> Result<bool, sqlx::Error> {
    Ok(!sqlx::query(
        "SELECT customer_network_connectors.id \nFROM customer_network_connectors INNER JOIN \
         network_connectors_subscriptions ON customer_network_connectors.id = \
         network_connectors_subscriptions.customer_id INNER JOIN network_connectors_services ON \
         network_connectors_services.id = \
         network_connectors_subscriptions.network_connectors_service_id \nWHERE \
         customer_network_connectors.customer_code = ? AND \
         network_connectors_services.service_name = ?",
    )
    .bind(code)
    .bind(name)
    .fetch_all(db.pool())
    .await?
    .is_empty())
}

/// `get_customer_and_service_ids`.
pub async fn customer_and_service_ids(
    db: &Db,
    code: &str,
    name: &str,
) -> Result<Vec<(i64, i64)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT customer_network_connectors.id, network_connectors_services.id AS id_1 \nFROM \
         customer_network_connectors INNER JOIN network_connectors_subscriptions ON \
         customer_network_connectors.id = network_connectors_subscriptions.customer_id INNER \
         JOIN network_connectors_services ON \
         network_connectors_subscriptions.network_connectors_service_id = \
         network_connectors_services.id \nWHERE customer_network_connectors.customer_code = ? \
         AND network_connectors_services.service_name = ?",
    )
    .bind(code)
    .bind(name)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|r| {
            Ok((
                i64::from(r.try_get::<i32, _>(0)?),
                i64::from(r.try_get::<i32, _>(1)?),
            ))
        })
        .collect()
}

/// `get_subscription_ids`.
pub async fn subscription_ids(
    db: &Db,
    customer_id: i64,
    service_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT network_connectors_subscriptions.id \nFROM network_connectors_subscriptions \
         \nWHERE network_connectors_subscriptions.customer_id = ? AND \
         network_connectors_subscriptions.network_connectors_service_id = ?",
    )
    .bind(customer_id)
    .bind(service_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|r| Ok(i64::from(r.try_get::<i32, _>(0)?)))
        .collect()
}

/// One `customer_network_connectors_meta` row (the schema's fields).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Meta {
    pub id: i64,
    pub customer_code: String,
    pub network_connector_name: String,
    pub graylog_input_id: Option<String>,
    pub graylog_index_id: String,
    pub graylog_stream_id: String,
    pub grafana_org_id: String,
    pub grafana_dashboard_folder_id: String,
}

/// Every metadata row, or one customer's (or the first of a connector).
pub async fn metas(
    db: &Db,
    code: Option<&str>,
    name: Option<&str>,
) -> Result<Vec<Meta>, sqlx::Error> {
    let mut sql = crate::integrations::store::NETWORK_META_SELECT.to_string();
    if code.is_some() {
        sql.push_str(" \nWHERE customer_network_connectors_meta.customer_code = ?");
        if name.is_some() {
            sql.push_str(" AND customer_network_connectors_meta.network_connector_name = ?");
        }
    }
    let mut q = sqlx::query(&sql);
    if let Some(c) = code {
        q = q.bind(c);
        if let Some(n) = name {
            q = q.bind(n);
        }
    }
    let rows = q.fetch_all(db.pool()).await?;
    rows.iter()
        .map(|r| {
            Ok(Meta {
                id: opt_int(r, "id")?.unwrap_or_default(),
                customer_code: text(r, "customer_code")?,
                network_connector_name: text(r, "network_connector_name")?,
                graylog_input_id: opt_text(r, "graylog_input_id")?,
                graylog_index_id: text(r, "graylog_index_id")?,
                graylog_stream_id: text(r, "graylog_stream_id")?,
                grafana_org_id: text(r, "grafana_org_id")?,
                grafana_dashboard_folder_id: text(r, "grafana_dashboard_folder_id")?,
            })
        })
        .collect()
}
