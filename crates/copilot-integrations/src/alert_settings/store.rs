//! `custom_alert_creation_settings` with `joinedload(event_orders)
//! .joinedload(event_configs)`, and the writes of the routes.

use copilot_db::Db;
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, Row, Transaction};

use crate::sql::{opt_int, opt_text, text};

/// `custom_alert_creation_settings`' columns.
pub const SETTINGS_COLUMNS: &[&str] = &[
    "id",
    "customer_code",
    "customer_name",
    "excluded_wazuh_rules",
    "excluded_suricata_rules",
    "timefield",
    "office365_organization_id",
    "iris_customer_id",
    "iris_customer_name",
    "iris_index",
    "grafana_url",
    "misp_url",
    "opencti_url",
    "custom_message",
    "shuffle_endpoint",
    "nvd_url",
];

/// One event config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventConfig {
    /// `id`.
    pub id: i64,
    /// `event_id`.
    pub event_id: String,
    /// `field`.
    pub field: String,
    /// `value`.
    pub value: String,
}

/// One event order with its configs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventOrder {
    /// `id`.
    pub id: i64,
    /// `order_label`.
    pub order_label: String,
    /// The configs, in row order.
    pub configs: Vec<EventConfig>,
}

/// One settings row with its orders.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Settings {
    pub id: i64,
    pub customer_code: String,
    pub customer_name: String,
    pub excluded_wazuh_rules: Option<String>,
    pub excluded_suricata_rules: Option<String>,
    pub timefield: Option<String>,
    pub office365_organization_id: Option<String>,
    pub iris_customer_id: Option<i64>,
    pub iris_customer_name: Option<String>,
    pub iris_index: Option<String>,
    pub grafana_url: Option<String>,
    pub misp_url: Option<String>,
    pub opencti_url: Option<String>,
    pub custom_message: Option<String>,
    pub shuffle_endpoint: Option<String>,
    pub nvd_url: Option<String>,
    /// The orders, in row order.
    pub orders: Vec<EventOrder>,
}

fn columns(prefix: &str) -> String {
    SETTINGS_COLUMNS
        .iter()
        .map(|c| format!("{prefix}.{c}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn settings_row(r: &MySqlRow) -> Result<Settings, sqlx::Error> {
    Ok(Settings {
        id: i64::from(r.try_get::<i32, _>(0)?),
        customer_code: text(r, "customer_code")?,
        customer_name: text(r, "customer_name")?,
        excluded_wazuh_rules: opt_text(r, "excluded_wazuh_rules")?,
        excluded_suricata_rules: opt_text(r, "excluded_suricata_rules")?,
        timefield: opt_text(r, "timefield")?,
        office365_organization_id: opt_text(r, "office365_organization_id")?,
        iris_customer_id: opt_int(r, "iris_customer_id")?,
        iris_customer_name: opt_text(r, "iris_customer_name")?,
        iris_index: opt_text(r, "iris_index")?,
        grafana_url: opt_text(r, "grafana_url")?,
        misp_url: opt_text(r, "misp_url")?,
        opencti_url: opt_text(r, "opencti_url")?,
        custom_message: opt_text(r, "custom_message")?,
        shuffle_endpoint: opt_text(r, "shuffle_endpoint")?,
        nvd_url: opt_text(r, "nvd_url")?,
        orders: Vec::new(),
    })
}

/// Where a joined load is keyed.
#[derive(Debug, Clone, Copy)]
pub enum By<'a> {
    /// `customer_name = ?`.
    Name(&'a str),
    /// `customer_code = ?`.
    Code(&'a str),
    /// `id = ?` (a refresh).
    Id(i64),
}

/// `select(AlertCreationSettings).options(joinedload(...)).where(...)` →
/// `scalars().first()`: the first row's settings, with every order and
/// config the rows carried for it, in row order.
pub async fn load(db: &Db, by: By<'_>) -> Result<Option<Settings>, sqlx::Error> {
    let filter = match by {
        By::Name(_) => "custom_alert_creation_settings.customer_name = ?",
        By::Code(_) => "custom_alert_creation_settings.customer_code = ?",
        By::Id(_) => "custom_alert_creation_settings.id = ?",
    };
    let sql = format!(
        "SELECT {}, custom_alert_creation_event_config_1.id AS id_1, \
         custom_alert_creation_event_config_1.event_order_id, \
         custom_alert_creation_event_config_1.event_id, custom_alert_creation_event_config_1.field, \
         custom_alert_creation_event_config_1.value, custom_alert_creation_event_order_1.id AS \
         id_2, custom_alert_creation_event_order_1.alert_creation_settings_id, \
         custom_alert_creation_event_order_1.order_label \nFROM custom_alert_creation_settings \
         LEFT OUTER JOIN custom_alert_creation_event_order AS custom_alert_creation_event_order_1 \
         ON custom_alert_creation_settings.id = \
         custom_alert_creation_event_order_1.alert_creation_settings_id LEFT OUTER JOIN \
         custom_alert_creation_event_config AS custom_alert_creation_event_config_1 ON \
         custom_alert_creation_event_order_1.id = custom_alert_creation_event_config_1.event_order_id \
         \nWHERE {filter}",
        columns("custom_alert_creation_settings")
    );
    let q = sqlx::query(&sql);
    let q = match by {
        By::Name(n) => q.bind(n),
        By::Code(c) => q.bind(c),
        By::Id(i) => q.bind(i),
    };
    let rows = q.fetch_all(db.pool()).await?;
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let mut settings = settings_row(first)?;
    for r in &rows {
        if i64::from(r.try_get::<i32, _>(0)?) != settings.id {
            continue;
        }
        let Some(order_id) = r.try_get::<Option<i32>, _>("id_2")? else {
            continue;
        };
        let order_id = i64::from(order_id);
        let pos = match settings.orders.iter().position(|o| o.id == order_id) {
            Some(p) => p,
            None => {
                settings.orders.push(EventOrder {
                    id: order_id,
                    order_label: text(r, "order_label")?,
                    configs: Vec::new(),
                });
                settings.orders.len() - 1
            }
        };
        if let Some(cid) = r.try_get::<Option<i32>, _>("id_1")? {
            let cid = i64::from(cid);
            if !settings.orders[pos].configs.iter().any(|c| c.id == cid) {
                settings.orders[pos].configs.push(EventConfig {
                    id: cid,
                    event_id: text(r, "event_id")?,
                    field: text(r, "field")?,
                    value: text(r, "value")?,
                });
            }
        }
    }
    Ok(Some(settings))
}

/// `verify_customer_name_access`'s lookup: the first row's code.
pub async fn code_of_name(db: &Db, name: &str) -> Result<Option<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT custom_alert_creation_settings.customer_code \nFROM \
         custom_alert_creation_settings \nWHERE custom_alert_creation_settings.customer_name = ?",
    )
    .bind(name)
    .fetch_all(db.pool())
    .await?;
    rows.first().map(|r| r.try_get::<String, _>(0)).transpose()
}

/// Whether the customer has settings (`/create`'s check).
pub async fn exists_for_code(db: &Db, code: &str) -> Result<bool, sqlx::Error> {
    let sql = format!(
        "SELECT {} \nFROM custom_alert_creation_settings \nWHERE \
         custom_alert_creation_settings.customer_code = ?",
        columns("custom_alert_creation_settings")
    );
    Ok(!sqlx::query(&sql)
        .bind(code)
        .fetch_all(db.pool())
        .await?
        .is_empty())
}

/// Insert one order; its id.
pub async fn insert_order(
    tx: &mut Transaction<'_, MySql>,
    settings_id: i64,
    label: &str,
) -> Result<i64, sqlx::Error> {
    let id = sqlx::query(
        "INSERT INTO custom_alert_creation_event_order (alert_creation_settings_id, order_label) \
         VALUES (?, ?)",
    )
    .bind(settings_id)
    .bind(label)
    .execute(&mut **tx)
    .await?
    .last_insert_id();
    i64::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

/// Insert one config.
pub async fn insert_config(
    tx: &mut Transaction<'_, MySql>,
    order_id: i64,
    config: (&str, &str, &str),
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO custom_alert_creation_event_config (event_order_id, event_id, field, value) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(order_id)
    .bind(config.0)
    .bind(config.1)
    .bind(config.2)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
