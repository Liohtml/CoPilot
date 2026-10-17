//! The statements of `app/integrations/routes.py`, its AWS lookups
//! (`aws/services/account_lookup.py`) and the Office365 tenant read
//! (`office365/services/decommission.py`), in SQLAlchemy's shapes.

use copilot_db::Db;
use sqlx::Row;
use sqlx::mysql::MySqlRow;

use crate::sql::{Clause, bind_clause, opt_bool, opt_int, opt_text, text};

/// `customer_integrations_meta`'s columns.
pub const META_COLUMNS: &[&str] = &[
    "id",
    "customer_code",
    "integration_name",
    "instance_name",
    "graylog_input_id",
    "graylog_index_id",
    "graylog_stream_id",
    "grafana_org_id",
    "grafana_dashboard_folder_id",
    "grafana_datasource_uid",
];

/// One catalog entry with its auth keys (`AvailableIntegrations`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    /// `id`.
    pub id: i64,
    /// `integration_name`.
    pub name: String,
    /// `description`.
    pub description: String,
    /// `integration_details`.
    pub details: String,
    /// The auth key names, in row order.
    pub keys: Vec<String>,
}

const CATALOG: &str = "SELECT available_integrations.id, available_integrations.integration_name, \
     available_integrations.description, available_integrations.integration_details, \
     available_integrations_auth_keys_1.id AS id_1, available_integrations_auth_keys_1.integration_id, \
     available_integrations_auth_keys_1.integration_name AS integration_name_1, \
     available_integrations_auth_keys_1.auth_key_name \nFROM available_integrations LEFT OUTER JOIN \
     available_integrations_auth_keys AS available_integrations_auth_keys_1 ON \
     available_integrations.id = available_integrations_auth_keys_1.integration_id";

fn catalog_rows(rows: Vec<MySqlRow>) -> Result<Vec<Catalog>, sqlx::Error> {
    let mut out: Vec<Catalog> = Vec::new();
    for row in rows {
        let id = i64::from(row.try_get::<i32, _>(0)?);
        let key: Option<String> = row.try_get(7)?;
        let key_id: Option<i32> = row.try_get(4)?;
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
        if let (Some(_), Some(k)) = (key_id, key) {
            out[pos].keys.push(k);
        }
    }
    Ok(out)
}

/// `fetch_available_integrations`.
pub async fn catalog(db: &Db) -> Result<Vec<Catalog>, sqlx::Error> {
    catalog_rows(sqlx::query(CATALOG).fetch_all(db.pool()).await?)
}

/// `fetch_available_integration_by_id`.
pub async fn catalog_by_id(db: &Db, id: i64) -> Result<Option<Catalog>, sqlx::Error> {
    let sql = format!("{CATALOG} \nWHERE available_integrations.id = ?");
    let rows = sqlx::query(&sql).bind(id).fetch_all(db.pool()).await?;
    Ok(catalog_rows(rows)?.into_iter().next())
}

/// `select(AvailableIntegrations).where(integration_name == name)` →
/// `first()`: the id and the stored name.
pub async fn catalog_first_by_name(
    db: &Db,
    name: &str,
) -> Result<Option<(i64, String)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT available_integrations.id, available_integrations.integration_name, \
         available_integrations.description, available_integrations.integration_details \nFROM \
         available_integrations \nWHERE available_integrations.integration_name = ?",
    )
    .bind(name)
    .fetch_all(db.pool())
    .await?;
    match rows.first() {
        Some(r) => Ok(Some((i64::from(r.try_get::<i32, _>(0)?), r.try_get(1)?))),
        None => Ok(None),
    }
}

/// `validate_customer_code`: a `customers` row with this code.
pub async fn customer_exists(db: &Db, code: &str) -> Result<bool, sqlx::Error> {
    Ok(!sqlx::query(
        "SELECT customers.id, customers.customer_code \nFROM customers \nWHERE \
         customers.customer_code = ?",
    )
    .bind(code)
    .fetch_all(db.pool())
    .await?
    .is_empty())
}

/// `validate_customer_meta`: a `customersmeta` row with this code.
pub async fn customer_meta_exists(db: &Db, code: &str) -> Result<bool, sqlx::Error> {
    Ok(!sqlx::query(
        "SELECT customersmeta.id, customersmeta.customer_code \nFROM customersmeta \nWHERE \
         customersmeta.customer_code = ?",
    )
    .bind(code)
    .fetch_all(db.pool())
    .await?
    .is_empty())
}

/// `integration_services` (eager-loaded on a subscription).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// `id`.
    pub id: i64,
    /// `service_name`.
    pub service_name: String,
    /// `auth_type`.
    pub auth_type: String,
}

/// `integration_auth_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKey {
    /// `id`.
    pub id: i64,
    /// `subscription_id`.
    pub subscription_id: Option<i64>,
    /// `auth_key_name`.
    pub auth_key_name: String,
    /// `auth_value`.
    pub auth_value: String,
}

/// `integration_subscriptions` with its service and keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// `id`.
    pub id: i64,
    /// `customer_id`.
    pub customer_id: Option<i64>,
    /// `integration_service_id`.
    pub service_id: Option<i64>,
    /// The joined service.
    pub service: Option<Service>,
    /// The sub-query loaded keys.
    pub keys: Vec<AuthKey>,
}

/// One `customer_integrations` row with its subscriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerIntegration {
    /// `id`.
    pub id: i64,
    /// `customer_code`.
    pub customer_code: String,
    /// `customer_name`.
    pub customer_name: String,
    /// `integration_service_id` (the catalog id it was created with).
    pub integration_service_id: i64,
    /// `integration_service_name`.
    pub integration_service_name: String,
    /// `instance_name`.
    pub instance_name: Option<String>,
    /// `deployed`.
    pub deployed: Option<bool>,
    /// The joined subscriptions, in row order.
    pub subscriptions: Vec<Subscription>,
}

impl CustomerIntegration {
    /// `get_subscription_id`: the subscription of `service` holding a key
    /// named `key`.
    pub fn subscription_with_key(&self, service: &str, key: &str) -> Option<i64> {
        self.subscriptions
            .iter()
            .filter(|s| {
                s.service
                    .as_ref()
                    .is_some_and(|v| v.service_name == service)
            })
            .find(|s| s.keys.iter().any(|k| k.auth_key_name == key))
            .map(|s| s.id)
    }

    /// Whether a subscription of this service exists.
    pub fn has_service(&self, service: &str) -> bool {
        self.subscriptions.iter().any(|s| {
            s.service
                .as_ref()
                .is_some_and(|v| v.service_name == service)
        })
    }
}

/// The customer integrations (all, or one customer's) with
/// `joinedload(subscriptions).joinedload(service)` and
/// `joinedload(subscriptions).subqueryload(auth_keys)`.
pub async fn customer_integrations(
    db: &Db,
    code: Option<&str>,
) -> Result<Vec<CustomerIntegration>, sqlx::Error> {
    let filter = if code.is_some() {
        " \nWHERE customer_integrations.customer_code = ?"
    } else {
        ""
    };
    let main = format!(
        "SELECT customer_integrations.id, customer_integrations.customer_code, \
         customer_integrations.customer_name, customer_integrations.integration_service_id, \
         customer_integrations.integration_service_name, customer_integrations.instance_name, \
         customer_integrations.deployed, integration_services_1.id AS id_1, \
         integration_services_1.service_name, integration_services_1.auth_type, \
         integration_subscriptions_1.id AS id_2, integration_subscriptions_1.customer_id, \
         integration_subscriptions_1.integration_service_id AS integration_service_id_1 \nFROM \
         customer_integrations LEFT OUTER JOIN integration_subscriptions AS \
         integration_subscriptions_1 ON customer_integrations.id = \
         integration_subscriptions_1.customer_id LEFT OUTER JOIN integration_services AS \
         integration_services_1 ON integration_services_1.id = \
         integration_subscriptions_1.integration_service_id{filter}"
    );
    let mut q = sqlx::query(&main);
    if let Some(c) = code {
        q = q.bind(c);
    }
    let rows = q.fetch_all(db.pool()).await?;
    let mut out: Vec<CustomerIntegration> = Vec::new();
    for row in &rows {
        let id = i64::from(row.try_get::<i32, _>(0)?);
        let pos = match out.iter().position(|c| c.id == id) {
            Some(p) => p,
            None => {
                out.push(CustomerIntegration {
                    id,
                    customer_code: text(row, "customer_code")?,
                    customer_name: text(row, "customer_name")?,
                    integration_service_id: i64::from(row.try_get::<i32, _>(3)?),
                    integration_service_name: text(row, "integration_service_name")?,
                    instance_name: opt_text(row, "instance_name")?,
                    deployed: opt_bool(row, "deployed")?,
                    subscriptions: Vec::new(),
                });
                out.len() - 1
            }
        };
        let Some(sub_id) = row.try_get::<Option<i32>, _>(10)? else {
            continue;
        };
        let sub_id = i64::from(sub_id);
        if out[pos].subscriptions.iter().any(|s| s.id == sub_id) {
            continue;
        }
        let service = match row.try_get::<Option<i32>, _>(7)? {
            Some(sid) => Some(Service {
                id: i64::from(sid),
                service_name: row.try_get(8)?,
                auth_type: row.try_get(9)?,
            }),
            None => None,
        };
        out[pos].subscriptions.push(Subscription {
            id: sub_id,
            customer_id: row.try_get::<Option<i32>, _>(11)?.map(i64::from),
            service_id: row.try_get::<Option<i32>, _>(12)?.map(i64::from),
            service,
            keys: Vec::new(),
        });
    }
    if out.is_empty() {
        return Ok(out);
    }
    let sub = format!(
        "SELECT integration_auth_keys.id AS integration_auth_keys_id, \
         integration_auth_keys.subscription_id AS integration_auth_keys_subscription_id, \
         integration_auth_keys.auth_key_name AS integration_auth_keys_auth_key_name, \
         integration_auth_keys.auth_value AS integration_auth_keys_auth_value, \
         integration_subscriptions_1.id AS integration_subscriptions_1_id \nFROM (SELECT \
         customer_integrations.id AS customer_integrations_id \nFROM customer_integrations{filter}) \
         AS anon_1 INNER JOIN integration_subscriptions AS integration_subscriptions_1 ON \
         anon_1.customer_integrations_id = integration_subscriptions_1.customer_id INNER JOIN \
         integration_auth_keys ON integration_subscriptions_1.id = \
         integration_auth_keys.subscription_id"
    );
    let mut q = sqlx::query(&sub);
    if let Some(c) = code {
        q = q.bind(c);
    }
    for row in q.fetch_all(db.pool()).await? {
        let parent = i64::from(row.try_get::<i32, _>(4)?);
        let key = AuthKey {
            id: i64::from(row.try_get::<i32, _>(0)?),
            subscription_id: row.try_get::<Option<i32>, _>(1)?.map(i64::from),
            auth_key_name: row.try_get(2)?,
            auth_value: row.try_get(3)?,
        };
        for ci in &mut out {
            for s in &mut ci.subscriptions {
                if s.id == parent {
                    s.keys.push(key.clone());
                }
            }
        }
    }
    Ok(out)
}

const JOIN: &str = "FROM customer_integrations INNER JOIN integration_subscriptions ON \
     customer_integrations.id = integration_subscriptions.customer_id INNER JOIN \
     integration_services ON integration_subscriptions.integration_service_id = \
     integration_services.id";

/// `check_existing_customer_integration`'s rows: the instance name of every
/// row of this integration the customer has.
pub async fn existing_instances(
    db: &Db,
    code: &str,
    name: &str,
) -> Result<Vec<Option<String>>, sqlx::Error> {
    // `.join(CustomerIntegrations.integration_subscriptions)
    //  .join(IntegrationSubscription.integration_service)`.
    let rows = sqlx::query(
        "SELECT customer_integrations.id, customer_integrations.instance_name \nFROM \
         customer_integrations INNER JOIN integration_subscriptions ON customer_integrations.id = \
         integration_subscriptions.customer_id INNER JOIN integration_services ON \
         integration_services.id = integration_subscriptions.integration_service_id \nWHERE \
         customer_integrations.customer_code = ? AND integration_services.service_name = ?",
    )
    .bind(code)
    .bind(name)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(|r| opt_text(r, "instance_name")).collect()
}

/// `resolve_integration_instance`'s `SELECT DISTINCT instance_name`.
pub async fn distinct_instances(
    db: &Db,
    code: &str,
    name: &str,
) -> Result<Vec<Option<String>>, sqlx::Error> {
    let sql = format!(
        "SELECT DISTINCT customer_integrations.instance_name \n{JOIN} \nWHERE \
         customer_integrations.customer_code = ? AND integration_services.service_name = ?"
    );
    let rows = sqlx::query(&sql)
        .bind(code)
        .bind(name)
        .fetch_all(db.pool())
        .await?;
    rows.iter()
        .map(|r| r.try_get::<Option<String>, _>(0))
        .collect()
}

/// `count_other_integration_instances`.
pub async fn count_other_instances(
    db: &Db,
    code: &str,
    name: &str,
    differs: &Clause,
) -> Result<usize, sqlx::Error> {
    let sql = format!(
        "SELECT DISTINCT customer_integrations.id \n{JOIN} \nWHERE \
         customer_integrations.customer_code = ? AND integration_services.service_name = ? AND {}",
        differs.0
    );
    let q = sqlx::query(&sql).bind(code).bind(name);
    Ok(bind_clause(q, differs).fetch_all(db.pool()).await?.len())
}

/// `get_customer_and_service_ids(..., match_instance=True)`.
pub async fn customer_and_service_ids(
    db: &Db,
    code: &str,
    name: &str,
    matches: &Clause,
) -> Result<Vec<(i64, i64)>, sqlx::Error> {
    let sql = format!(
        "SELECT customer_integrations.id, integration_services.id AS id_1 \n{JOIN} \nWHERE \
         customer_integrations.customer_code = ? AND integration_services.service_name = ? AND {}",
        matches.0
    );
    let q = sqlx::query(&sql).bind(code).bind(name);
    let rows = bind_clause(q, matches).fetch_all(db.pool()).await?;
    rows.iter()
        .map(|r| {
            Ok((
                i64::from(r.try_get::<i32, _>(0)?),
                i64::from(r.try_get::<i32, _>(1)?),
            ))
        })
        .collect()
}

/// `select(CustomerIntegrations.deployed).where(id == …)` → `scalar()`.
pub async fn deployed(db: &Db, id: i64) -> Result<Option<bool>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT customer_integrations.deployed \nFROM customer_integrations \nWHERE \
         customer_integrations.id = ?",
    )
    .bind(id)
    .fetch_all(db.pool())
    .await?;
    match rows.first() {
        Some(r) => opt_bool(r, "deployed"),
        None => Ok(None),
    }
}

/// `get_subscription_ids`.
pub async fn subscription_ids(
    db: &Db,
    customer_id: i64,
    service_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT integration_subscriptions.id \nFROM integration_subscriptions \nWHERE \
         integration_subscriptions.customer_id = ? AND \
         integration_subscriptions.integration_service_id = ?",
    )
    .bind(customer_id)
    .bind(service_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|r| Ok(i64::from(r.try_get::<i32, _>(0)?)))
        .collect()
}

/// `get_office365_tenant_id`, or `get_tenant_id(..., match_instance=True)`
/// (the same filters; Python selects the value or the row): the first
/// `TENANT_ID` of the instance.
pub async fn tenant_id(
    db: &Db,
    code: &str,
    service: &str,
    matches: &Clause,
    whole_row: bool,
) -> Result<Option<String>, sqlx::Error> {
    let columns = if whole_row {
        "integration_auth_keys.id, integration_auth_keys.subscription_id, \
         integration_auth_keys.auth_key_name, integration_auth_keys.auth_value"
    } else {
        "integration_auth_keys.auth_value"
    };
    let sql = format!(
        "SELECT {columns} \nFROM integration_auth_keys INNER JOIN integration_subscriptions ON \
         integration_auth_keys.subscription_id = integration_subscriptions.id INNER JOIN \
         customer_integrations ON integration_subscriptions.customer_id = customer_integrations.id \
         INNER JOIN integration_services ON integration_subscriptions.integration_service_id = \
         integration_services.id \nWHERE customer_integrations.customer_code = ? AND \
         integration_services.service_name = ? AND integration_auth_keys.auth_key_name = ? AND {}",
        matches.0
    );
    let q = sqlx::query(&sql).bind(code).bind(service).bind("TENANT_ID");
    let rows = bind_clause(q, matches).fetch_all(db.pool()).await?;
    match rows.first() {
        Some(r) => Ok(Some(text(r, "auth_value")?)),
        None => Ok(None),
    }
}

/// `get_customer_by_auth_key`'s rows: `(customer_code, customer_name)` of
/// every match, in row order.
pub async fn customers_by_auth_key(
    db: &Db,
    integration: &str,
    key: &str,
    value: &str,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT customer_integrations.customer_code, customer_integrations.customer_name \nFROM \
         customer_integrations INNER JOIN integration_subscriptions ON customer_integrations.id = \
         integration_subscriptions.customer_id INNER JOIN integration_services ON \
         integration_subscriptions.integration_service_id = integration_services.id INNER JOIN \
         integration_auth_keys ON integration_subscriptions.id = \
         integration_auth_keys.subscription_id \nWHERE integration_services.service_name = ? AND \
         integration_auth_keys.auth_key_name = ? AND integration_auth_keys.auth_value = ?",
    )
    .bind(integration)
    .bind(key)
    .bind(value)
    .fetch_all(db.pool())
    .await?;
    rows.iter()
        .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
        .collect()
}

/// One `customer_integrations_meta` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// `id`.
    pub id: i64,
    /// `customer_code`.
    pub customer_code: String,
    /// `integration_name`.
    pub integration_name: String,
    /// `instance_name`.
    pub instance_name: Option<String>,
    /// `graylog_input_id`.
    pub graylog_input_id: Option<String>,
    /// `graylog_index_id`.
    pub graylog_index_id: String,
    /// `graylog_stream_id`.
    pub graylog_stream_id: String,
    /// `grafana_org_id`.
    pub grafana_org_id: String,
    /// `grafana_dashboard_folder_id`.
    pub grafana_dashboard_folder_id: String,
    /// `grafana_datasource_uid`.
    pub grafana_datasource_uid: Option<String>,
}

const META_SELECT: &str = "SELECT customer_integrations_meta.id, \
     customer_integrations_meta.customer_code, customer_integrations_meta.integration_name, \
     customer_integrations_meta.instance_name, customer_integrations_meta.graylog_input_id, \
     customer_integrations_meta.graylog_index_id, customer_integrations_meta.graylog_stream_id, \
     customer_integrations_meta.grafana_org_id, \
     customer_integrations_meta.grafana_dashboard_folder_id, \
     customer_integrations_meta.grafana_datasource_uid \nFROM customer_integrations_meta";

fn meta_row(r: &MySqlRow) -> Result<Meta, sqlx::Error> {
    Ok(Meta {
        id: opt_int(r, "id")?.unwrap_or_default(),
        customer_code: text(r, "customer_code")?,
        integration_name: text(r, "integration_name")?,
        instance_name: opt_text(r, "instance_name")?,
        graylog_input_id: opt_text(r, "graylog_input_id")?,
        graylog_index_id: text(r, "graylog_index_id")?,
        graylog_stream_id: text(r, "graylog_stream_id")?,
        grafana_org_id: text(r, "grafana_org_id")?,
        grafana_dashboard_folder_id: text(r, "grafana_dashboard_folder_id")?,
        grafana_datasource_uid: opt_text(r, "grafana_datasource_uid")?,
    })
}

/// Every metadata row, or one customer's.
pub async fn metas(db: &Db, code: Option<&str>) -> Result<Vec<Meta>, sqlx::Error> {
    let rows = match code {
        Some(c) => {
            let sql = format!("{META_SELECT} \nWHERE customer_integrations_meta.customer_code = ?");
            sqlx::query(&sql).bind(c).fetch_all(db.pool()).await?
        }
        None => sqlx::query(META_SELECT).fetch_all(db.pool()).await?,
    };
    rows.iter().map(meta_row).collect()
}

/// The first metadata row of `(code, integration)`, narrowed to an instance
/// when `instance` is given.
pub async fn meta_first(
    db: &Db,
    code: &str,
    integration: &str,
    instance: Option<&Clause>,
) -> Result<Option<Meta>, sqlx::Error> {
    let narrow = instance.map_or(String::new(), |c| format!(" AND {}", c.0));
    let sql = format!(
        "{META_SELECT} \nWHERE customer_integrations_meta.customer_code = ? AND \
         customer_integrations_meta.integration_name = ?{narrow}"
    );
    let mut q = sqlx::query(&sql).bind(code).bind(integration);
    if let Some(c) = instance {
        q = bind_clause(q, c);
    }
    let rows = q.fetch_all(db.pool()).await?;
    rows.first().map(meta_row).transpose()
}

/// Every metadata row of a customer's integration (`.scalars().all()`), in
/// the plan's order.
pub async fn integration_metas(
    db: &Db,
    code: &str,
    integration: &str,
    instance: Option<&Clause>,
) -> Result<Vec<Meta>, sqlx::Error> {
    let narrow = instance.map_or(String::new(), |c| format!(" AND {}", c.0));
    let sql = format!(
        "{META_SELECT} \nWHERE customer_integrations_meta.customer_code = ? AND \
         customer_integrations_meta.integration_name = ?{narrow}"
    );
    let mut q = sqlx::query(&sql)
        .bind(code)
        .bind(integration)
        .persistent(false);
    if let Some(c) = instance {
        q = bind_clause(q, c);
    }
    let rows = q.fetch_all(db.pool()).await?;
    rows.iter().map(meta_row).collect()
}

/// One `customer_network_connectors_meta` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkMeta {
    /// `id`.
    pub id: i64,
    /// `customer_code`.
    pub customer_code: String,
    /// `network_connector_name`.
    pub network_connector_name: String,
    /// `graylog_input_id`.
    pub graylog_input_id: Option<String>,
    /// `graylog_index_id`.
    pub graylog_index_id: String,
    /// `graylog_stream_id`.
    pub graylog_stream_id: String,
    /// `graylog_pipeline_id`.
    pub graylog_pipeline_id: String,
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

/// `customer_network_connectors_meta`'s columns.
pub const NETWORK_META_SELECT: &str = "SELECT customer_network_connectors_meta.id, \
     customer_network_connectors_meta.customer_code, \
     customer_network_connectors_meta.network_connector_name, \
     customer_network_connectors_meta.graylog_input_id, \
     customer_network_connectors_meta.graylog_index_id, \
     customer_network_connectors_meta.graylog_stream_id, \
     customer_network_connectors_meta.graylog_pipeline_id, \
     customer_network_connectors_meta.graylog_content_pack_input_id, \
     customer_network_connectors_meta.graylog_content_pack_stream_id, \
     customer_network_connectors_meta.grafana_org_id, \
     customer_network_connectors_meta.grafana_dashboard_folder_id, \
     customer_network_connectors_meta.grafana_datasource_uid \nFROM \
     customer_network_connectors_meta";

/// A network connector's metadata row.
pub fn network_meta_row(r: &MySqlRow) -> Result<NetworkMeta, sqlx::Error> {
    Ok(NetworkMeta {
        id: opt_int(r, "id")?.unwrap_or_default(),
        customer_code: text(r, "customer_code")?,
        network_connector_name: text(r, "network_connector_name")?,
        graylog_input_id: opt_text(r, "graylog_input_id")?,
        graylog_index_id: text(r, "graylog_index_id")?,
        graylog_stream_id: text(r, "graylog_stream_id")?,
        graylog_pipeline_id: text(r, "graylog_pipeline_id")?,
        graylog_content_pack_input_id: text(r, "graylog_content_pack_input_id")?,
        graylog_content_pack_stream_id: text(r, "graylog_content_pack_stream_id")?,
        grafana_org_id: text(r, "grafana_org_id")?,
        grafana_dashboard_folder_id: text(r, "grafana_dashboard_folder_id")?,
        grafana_datasource_uid: text(r, "grafana_datasource_uid")?,
    })
}

/// The first network-connector metadata row of `(code, name)`.
pub async fn network_meta_first(
    db: &Db,
    code: &str,
    name: &str,
) -> Result<Option<NetworkMeta>, sqlx::Error> {
    let sql = format!(
        "{NETWORK_META_SELECT} \nWHERE customer_network_connectors_meta.customer_code = ? AND \
         customer_network_connectors_meta.network_connector_name = ?"
    );
    let rows = sqlx::query(&sql)
        .bind(code)
        .bind(name)
        .fetch_all(db.pool())
        .await?;
    rows.first().map(network_meta_row).transpose()
}

/// `AwsInstanceRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsInstance {
    /// `customer_code`.
    pub customer_code: String,
    /// `instance_name`.
    pub instance_name: Option<String>,
    /// The stripped `AWS_ACCOUNT_ID` (`None` when blank).
    pub account_id: Option<String>,
    /// The stripped `BUCKET_NAME` (`None` when blank).
    pub bucket_name: Option<String>,
}

/// `list_aws_instances`: every AWS instance, in first-seen order.
pub async fn aws_instances(db: &Db) -> Result<Vec<AwsInstance>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT customer_integrations.id, customer_integrations.customer_code, \
         customer_integrations.instance_name, integration_auth_keys.auth_key_name, \
         integration_auth_keys.auth_value \nFROM customer_integrations INNER JOIN \
         integration_subscriptions ON customer_integrations.id = \
         integration_subscriptions.customer_id INNER JOIN integration_services ON \
         integration_subscriptions.integration_service_id = integration_services.id INNER JOIN \
         integration_auth_keys ON integration_auth_keys.subscription_id = \
         integration_subscriptions.id \nWHERE integration_services.service_name = ? AND \
         integration_auth_keys.auth_key_name IN (?, ?)",
    )
    .bind(super::AWS)
    .bind("AWS_ACCOUNT_ID")
    .bind("BUCKET_NAME")
    .fetch_all(db.pool())
    .await?;
    let mut ids: Vec<i64> = Vec::new();
    let mut out: Vec<AwsInstance> = Vec::new();
    for r in &rows {
        let id = i64::from(r.try_get::<i32, _>(0)?);
        let pos = match ids.iter().position(|i| *i == id) {
            Some(p) => p,
            None => {
                ids.push(id);
                out.push(AwsInstance {
                    customer_code: r.try_get(1)?,
                    instance_name: r.try_get(2)?,
                    account_id: None,
                    bucket_name: None,
                });
                out.len() - 1
            }
        };
        let name: String = r.try_get(3)?;
        let value: String = r.try_get(4)?;
        let value = copilot_web::form::py_strip(&value);
        let value = (!value.is_empty()).then(|| value.to_string());
        if name == "AWS_ACCOUNT_ID" {
            out[pos].account_id = value;
        } else {
            out[pos].bucket_name = value;
        }
    }
    Ok(out)
}
