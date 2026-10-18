//! The module's tables — `customer_notification_route`,
//! `notification_dispatch_log`, `customer_shuffle_integration`,
//! `notification_template` — plus the few reads of other tables the
//! dispatcher needs (alerts and cases for a manual send, the newest AI
//! report of an alert).
//!
//! List queries select SQLAlchemy's column list in SQLAlchemy's order and
//! keep its `ORDER BY`: MySQL's filesort then breaks same-second ties the
//! same way for both backends.

use chrono::NaiveDateTime;
use sqlx::{FromRow, MySql, QueryBuilder};

use copilot_db::schema::TableRequirement;
use copilot_db::{Db, DbError};

/// Every column this module reads or writes.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customer_notification_route",
        columns: &[
            "id",
            "customer_code",
            "scope",
            "recipient_mode",
            "notify_on_self_assign",
            "name",
            "trigger",
            "channel",
            "destination",
            "min_severity",
            "format_template",
            "enabled",
            "last_dispatched_at",
            "dispatch_count",
            "created_by",
            "template_id",
            "config",
            "shuffle_integration_id",
            "created_at",
            "updated_at",
        ],
    },
    TableRequirement {
        table: "notification_dispatch_log",
        columns: &[
            "id",
            "customer_code",
            "alert_id",
            "entity_type",
            "entity_id",
            "dedupe_key",
            "route_id",
            "trigger",
            "dispatched_at",
            "status",
            "error_message",
            "latency_ms",
            "payload_preview",
            "triggered_by",
            "trigger_source",
            "provider_reference",
        ],
    },
    TableRequirement {
        table: "customer_shuffle_integration",
        columns: &[
            "id",
            "customer_code",
            "shuffle_org_id",
            "display_name",
            "enabled",
            "last_used_at",
            "created_by",
            "created_at",
            "updated_at",
        ],
    },
    TableRequirement {
        table: "notification_template",
        columns: &[
            "id",
            "name",
            "description",
            "trigger",
            "format",
            "subject_template",
            "body_template",
            "customer_code",
            "is_default",
            "created_by",
            "created_at",
            "updated_at",
        ],
    },
    TableRequirement {
        table: "incident_management_alert",
        columns: &["id", "alert_name", "customer_code", "severity"],
    },
    TableRequirement {
        table: "incident_management_case",
        columns: &["id", "case_name", "customer_code"],
    },
];

// ---------------------------------------------------------------------------
// customer_notification_route
// ---------------------------------------------------------------------------

/// A `customer_notification_route` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct RouteRow {
    /// Primary key.
    pub id: i32,
    /// Tenant; `NULL` for an internal route.
    pub customer_code: Option<String>,
    /// `customer` | `internal`.
    pub scope: String,
    /// `static` | `assignee`.
    pub recipient_mode: String,
    /// Notify an assignee who assigned themselves.
    pub notify_on_self_assign: bool,
    /// Label.
    pub name: String,
    /// The trigger it fires on (legacy `severity_critical_or_high` possible).
    pub trigger: String,
    /// Channel key.
    pub channel: String,
    /// Shuffle's destination hint (`""` when unused).
    pub destination: Option<String>,
    /// Lowest severity that fires.
    pub min_severity: String,
    /// Inline Jinja body.
    pub format_template: Option<String>,
    /// Switched on.
    pub enabled: bool,
    /// Last successful dispatch.
    pub last_dispatched_at: Option<NaiveDateTime>,
    /// Successful dispatches.
    pub dispatch_count: i32,
    /// Creator's username.
    pub created_by: Option<String>,
    /// Named template.
    pub template_id: Option<i32>,
    /// Channel settings, JSON text.
    pub config: Option<String>,
    /// Shuffle integration (FK).
    pub shuffle_integration_id: Option<i32>,
    /// Created (naive UTC).
    pub created_at: NaiveDateTime,
    /// Last edit.
    pub updated_at: Option<NaiveDateTime>,
}

const ROUTE_COLUMNS: &str = "customer_notification_route.id, \
     customer_notification_route.customer_code, customer_notification_route.scope, \
     customer_notification_route.recipient_mode, \
     customer_notification_route.notify_on_self_assign, customer_notification_route.name, \
     customer_notification_route.`trigger`, customer_notification_route.channel, \
     customer_notification_route.destination, customer_notification_route.min_severity, \
     customer_notification_route.format_template, customer_notification_route.enabled, \
     customer_notification_route.last_dispatched_at, customer_notification_route.dispatch_count, \
     customer_notification_route.created_by, customer_notification_route.template_id, \
     customer_notification_route.config, customer_notification_route.shuffle_integration_id, \
     customer_notification_route.created_at, customer_notification_route.updated_at";

/// A customer's routes, newest first (`list_routes`).
pub async fn routes_of_customer(db: &Db, customer_code: &str) -> Result<Vec<RouteRow>, DbError> {
    Ok(sqlx::query_as::<_, RouteRow>(&format!(
        "SELECT {ROUTE_COLUMNS} FROM customer_notification_route \
         WHERE customer_notification_route.customer_code = ? \
         ORDER BY customer_notification_route.created_at DESC"
    ))
    .bind(customer_code)
    .fetch_all(db.pool())
    .await?)
}

/// Every internal route, newest first (`list_internal_routes`).
pub async fn internal_routes(db: &Db) -> Result<Vec<RouteRow>, DbError> {
    Ok(sqlx::query_as::<_, RouteRow>(&format!(
        "SELECT {ROUTE_COLUMNS} FROM customer_notification_route \
         WHERE customer_notification_route.scope = ? \
         ORDER BY customer_notification_route.created_at DESC"
    ))
    .bind("internal")
    .fetch_all(db.pool())
    .await?)
}

/// `get_route`: a route by id within one customer.
pub async fn route_of_customer(
    db: &Db,
    id: i64,
    customer_code: &str,
) -> Result<Option<RouteRow>, DbError> {
    Ok(sqlx::query_as::<_, RouteRow>(&format!(
        "SELECT {ROUTE_COLUMNS} FROM customer_notification_route \
         WHERE customer_notification_route.id = ? \
         AND customer_notification_route.customer_code = ?"
    ))
    .bind(id)
    .bind(customer_code)
    .fetch_optional(db.pool())
    .await?)
}

/// `get_internal_route`: a route by id among the internal ones.
pub async fn internal_route(db: &Db, id: i64) -> Result<Option<RouteRow>, DbError> {
    Ok(sqlx::query_as::<_, RouteRow>(&format!(
        "SELECT {ROUTE_COLUMNS} FROM customer_notification_route \
         WHERE customer_notification_route.id = ? AND customer_notification_route.scope = ?"
    ))
    .bind(id)
    .bind("internal")
    .fetch_optional(db.pool())
    .await?)
}

/// A route by id, any scope (manual send).
pub async fn route(db: &Db, id: i64) -> Result<Option<RouteRow>, DbError> {
    Ok(sqlx::query_as::<_, RouteRow>(&format!(
        "SELECT {ROUTE_COLUMNS} FROM customer_notification_route \
         WHERE customer_notification_route.id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}

/// Which pool of routes an event resolves against (`routes_for_event`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePool<'a> {
    /// Internal routes only.
    Internal,
    /// The customer's routes only (`customer_code` may be `None`: no rows).
    Customer(Option<&'a str>),
    /// Both.
    Both(Option<&'a str>),
}

/// `routes_for_event`: the candidate routes, newest first.
pub async fn routes_for_pool(db: &Db, pool: RoutePool<'_>) -> Result<Vec<RouteRow>, DbError> {
    let mut qb: QueryBuilder<'_, MySql> = QueryBuilder::new(format!(
        "SELECT {ROUTE_COLUMNS} FROM customer_notification_route WHERE "
    ));
    let push_customer = |qb: &mut QueryBuilder<'_, MySql>, code: Option<&str>| {
        qb.push("customer_notification_route.scope = ");
        qb.push_bind("customer".to_string());
        match code {
            Some(c) => {
                qb.push(" AND customer_notification_route.customer_code = ");
                qb.push_bind(c.to_string());
            }
            None => {
                qb.push(" AND customer_notification_route.customer_code IS NULL");
            }
        }
    };
    match pool {
        RoutePool::Internal => {
            qb.push("customer_notification_route.scope = ");
            qb.push_bind("internal".to_string());
        }
        RoutePool::Customer(code) => push_customer(&mut qb, code),
        RoutePool::Both(code) => {
            qb.push("customer_notification_route.scope = ");
            qb.push_bind("internal".to_string());
            qb.push(" OR ");
            push_customer(&mut qb, code);
        }
    }
    qb.push(" ORDER BY customer_notification_route.created_at DESC");
    Ok(qb.build_query_as::<RouteRow>().fetch_all(db.pool()).await?)
}

/// Routes using a named template (no `ORDER BY`, like
/// `_attached_route_conflicts`).
pub async fn routes_with_template(db: &Db, template_id: i64) -> Result<Vec<RouteRow>, DbError> {
    Ok(sqlx::query_as::<_, RouteRow>(&format!(
        "SELECT {ROUTE_COLUMNS} FROM customer_notification_route \
         WHERE customer_notification_route.template_id = ?"
    ))
    .bind(template_id)
    .fetch_all(db.pool())
    .await?)
}

/// Routes pointing at a Shuffle integration (no `ORDER BY`).
pub async fn routes_with_integration(
    db: &Db,
    integration_id: i64,
) -> Result<Vec<RouteRow>, DbError> {
    Ok(sqlx::query_as::<_, RouteRow>(&format!(
        "SELECT {ROUTE_COLUMNS} FROM customer_notification_route \
         WHERE customer_notification_route.shuffle_integration_id = ?"
    ))
    .bind(integration_id)
    .fetch_all(db.pool())
    .await?)
}

/// A route to insert.
#[derive(Debug, Clone)]
pub struct NewRoute {
    /// Tenant (`None` for internal).
    pub customer_code: Option<String>,
    /// Scope.
    pub scope: String,
    /// Recipient mode.
    pub recipient_mode: String,
    /// Self-assignment flag.
    pub notify_on_self_assign: bool,
    /// Label.
    pub name: String,
    /// Trigger.
    pub trigger: String,
    /// Channel.
    pub channel: String,
    /// Destination (`""` when none).
    pub destination: String,
    /// Severity floor.
    pub min_severity: String,
    /// Inline template.
    pub format_template: Option<String>,
    /// Named template.
    pub template_id: Option<i64>,
    /// Enabled.
    pub enabled: bool,
    /// Creator.
    pub created_by: Option<String>,
    /// Shuffle integration.
    pub shuffle_integration_id: Option<i64>,
    /// `json.dumps(config)`.
    pub config: String,
    /// `datetime.utcnow()` as stored.
    pub created_at: NaiveDateTime,
}

/// Insert a route; returns its id.
pub async fn insert_route(db: &Db, r: &NewRoute) -> Result<i64, DbError> {
    let done = sqlx::query(
        "INSERT INTO customer_notification_route (customer_code, scope, recipient_mode, \
         notify_on_self_assign, name, `trigger`, channel, destination, min_severity, \
         format_template, enabled, last_dispatched_at, dispatch_count, created_by, template_id, \
         config, shuffle_integration_id, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(&r.customer_code)
    .bind(&r.scope)
    .bind(&r.recipient_mode)
    .bind(r.notify_on_self_assign)
    .bind(&r.name)
    .bind(&r.trigger)
    .bind(&r.channel)
    .bind(&r.destination)
    .bind(&r.min_severity)
    .bind(&r.format_template)
    .bind(r.enabled)
    .bind(&r.created_by)
    .bind(r.template_id)
    .bind(&r.config)
    .bind(r.shuffle_integration_id)
    .bind(r.created_at)
    .execute(db.pool())
    .await?;
    Ok(i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX))
}

/// A value for an `UPDATE … SET` list.
#[derive(Debug, Clone, PartialEq)]
pub enum SetValue {
    /// `NULL`.
    Null,
    /// A string.
    Str(String),
    /// An integer.
    Int(i64),
    /// A boolean.
    Bool(bool),
    /// A timestamp.
    Time(NaiveDateTime),
}

/// `UPDATE <table> SET <col = value, …> WHERE id = ?` — the columns a
/// PATCH changed (as SQLAlchemy's unit of work writes them).
pub async fn update_columns(
    db: &Db,
    table: &str,
    id: i64,
    sets: &[(&str, SetValue)],
) -> Result<(), DbError> {
    if sets.is_empty() {
        return Ok(());
    }
    let mut qb: QueryBuilder<'_, MySql> = QueryBuilder::new(format!("UPDATE {table} SET "));
    for (i, (col, value)) in sets.iter().enumerate() {
        if i > 0 {
            qb.push(", ");
        }
        qb.push(format!("`{col}` = "));
        match value {
            SetValue::Null => {
                qb.push("NULL");
            }
            SetValue::Str(s) => {
                qb.push_bind(s.clone());
            }
            SetValue::Int(n) => {
                qb.push_bind(*n);
            }
            SetValue::Bool(b) => {
                qb.push_bind(*b);
            }
            SetValue::Time(t) => {
                qb.push_bind(*t);
            }
        }
    }
    qb.push(" WHERE id = ");
    qb.push_bind(id);
    qb.build().execute(db.pool()).await?;
    Ok(())
}

/// Delete one row of `table` by id.
pub async fn delete_by_id(db: &Db, table: &str, id: i64) -> Result<(), DbError> {
    sqlx::query(&format!("DELETE FROM {table} WHERE id = ?"))
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// The denormalized counters after a successful dispatch.
pub async fn bump_dispatch_count(
    db: &Db,
    route_id: i64,
    now: NaiveDateTime,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE customer_notification_route SET dispatch_count = \
         (customer_notification_route.dispatch_count + ?), last_dispatched_at = ? \
         WHERE customer_notification_route.id = ?",
    )
    .bind(1)
    .bind(now)
    .bind(route_id)
    .execute(db.pool())
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// customer_shuffle_integration
// ---------------------------------------------------------------------------

/// A `customer_shuffle_integration` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct IntegrationRow {
    /// Primary key.
    pub id: i32,
    /// Tenant (FK).
    pub customer_code: String,
    /// Shuffle Org-Id.
    pub shuffle_org_id: String,
    /// Label.
    pub display_name: String,
    /// Switched on.
    pub enabled: bool,
    /// Last successful dispatch through it.
    pub last_used_at: Option<NaiveDateTime>,
    /// Creator.
    pub created_by: Option<String>,
    /// Created.
    pub created_at: NaiveDateTime,
    /// Last edit.
    pub updated_at: Option<NaiveDateTime>,
}

const INTEGRATION_COLUMNS: &str = "customer_shuffle_integration.id, \
     customer_shuffle_integration.customer_code, customer_shuffle_integration.shuffle_org_id, \
     customer_shuffle_integration.display_name, customer_shuffle_integration.enabled, \
     customer_shuffle_integration.last_used_at, customer_shuffle_integration.created_by, \
     customer_shuffle_integration.created_at, customer_shuffle_integration.updated_at";

/// A customer's integrations, newest first.
pub async fn integrations_of_customer(
    db: &Db,
    customer_code: &str,
) -> Result<Vec<IntegrationRow>, DbError> {
    Ok(sqlx::query_as::<_, IntegrationRow>(&format!(
        "SELECT {INTEGRATION_COLUMNS} FROM customer_shuffle_integration \
         WHERE customer_shuffle_integration.customer_code = ? \
         ORDER BY customer_shuffle_integration.created_at DESC"
    ))
    .bind(customer_code)
    .fetch_all(db.pool())
    .await?)
}

/// `_ensure_integration_belongs_to_customer`'s lookup.
pub async fn integration_of_customer(
    db: &Db,
    id: i64,
    customer_code: &str,
) -> Result<Option<IntegrationRow>, DbError> {
    Ok(sqlx::query_as::<_, IntegrationRow>(&format!(
        "SELECT {INTEGRATION_COLUMNS} FROM customer_shuffle_integration \
         WHERE customer_shuffle_integration.id = ? \
         AND customer_shuffle_integration.customer_code = ?"
    ))
    .bind(id)
    .bind(customer_code)
    .fetch_optional(db.pool())
    .await?)
}

/// An integration by id (`session.get`).
pub async fn integration(db: &Db, id: i64) -> Result<Option<IntegrationRow>, DbError> {
    Ok(sqlx::query_as::<_, IntegrationRow>(&format!(
        "SELECT {INTEGRATION_COLUMNS} FROM customer_shuffle_integration \
         WHERE customer_shuffle_integration.id = ?"
    ))
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}

/// Insert an integration; returns its id.
pub async fn insert_integration(
    db: &Db,
    customer_code: &str,
    display_name: &str,
    shuffle_org_id: &str,
    enabled: bool,
    created_by: Option<&str>,
    now: NaiveDateTime,
) -> Result<i64, DbError> {
    let done = sqlx::query(
        "INSERT INTO customer_shuffle_integration (customer_code, shuffle_org_id, display_name, \
         enabled, last_used_at, created_by, created_at, updated_at) \
         VALUES (?, ?, ?, ?, NULL, ?, ?, NULL)",
    )
    .bind(customer_code)
    .bind(shuffle_org_id)
    .bind(display_name)
    .bind(enabled)
    .bind(created_by)
    .bind(now)
    .execute(db.pool())
    .await?;
    Ok(i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX))
}

/// Shuffle's `after_send`: stamp `last_used_at`.
pub async fn touch_integration(db: &Db, id: i64, now: NaiveDateTime) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE customer_shuffle_integration SET last_used_at = ? \
         WHERE customer_shuffle_integration.id = ?",
    )
    .bind(now)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// notification_dispatch_log
// ---------------------------------------------------------------------------

/// A `notification_dispatch_log` row.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct LogRow {
    /// Primary key.
    pub id: i32,
    /// Tenant (`""` for an internal event without one).
    pub customer_code: String,
    /// The alert, for alert-shaped events.
    pub alert_id: Option<i32>,
    /// `alert` | `case` | `case_task`.
    pub entity_type: String,
    /// The entity.
    pub entity_id: i32,
    /// Idempotency key.
    pub dedupe_key: String,
    /// The route.
    pub route_id: i32,
    /// Trigger.
    pub trigger: String,
    /// When.
    pub dispatched_at: NaiveDateTime,
    /// `sent` | `failed` | `skipped`.
    pub status: String,
    /// Why not sent (and template errors).
    pub error_message: Option<String>,
    /// Provider round-trip.
    pub latency_ms: Option<i32>,
    /// First 500 characters of the body.
    pub payload_preview: Option<String>,
    /// Who caused it.
    pub triggered_by: Option<String>,
    /// `automatic` | `manual` | `test`.
    pub trigger_source: String,
    /// Vendor id of the delivery.
    pub provider_reference: Option<String>,
}

const LOG_COLUMNS: &str = "notification_dispatch_log.id, notification_dispatch_log.customer_code, \
     notification_dispatch_log.alert_id, notification_dispatch_log.entity_type, \
     notification_dispatch_log.entity_id, notification_dispatch_log.dedupe_key, \
     notification_dispatch_log.route_id, notification_dispatch_log.`trigger`, \
     notification_dispatch_log.dispatched_at, notification_dispatch_log.status, \
     notification_dispatch_log.error_message, notification_dispatch_log.latency_ms, \
     notification_dispatch_log.payload_preview, notification_dispatch_log.triggered_by, \
     notification_dispatch_log.trigger_source, notification_dispatch_log.provider_reference";

/// A customer's newest log rows (`list_dispatch_log`).
pub async fn log_of_customer(
    db: &Db,
    customer_code: &str,
    limit: i64,
) -> Result<Vec<LogRow>, DbError> {
    Ok(sqlx::query_as::<_, LogRow>(&format!(
        "SELECT {LOG_COLUMNS} FROM notification_dispatch_log \
         WHERE notification_dispatch_log.customer_code = ? \
         ORDER BY notification_dispatch_log.dispatched_at DESC LIMIT ?"
    ))
    .bind(customer_code)
    .bind(limit)
    .fetch_all(db.pool())
    .await?)
}

/// The log row of one `(route, dedupe_key)`.
pub async fn log_entry(
    db: &Db,
    route_id: i64,
    dedupe_key: &str,
) -> Result<Option<LogRow>, DbError> {
    Ok(sqlx::query_as::<_, LogRow>(&format!(
        "SELECT {LOG_COLUMNS} FROM notification_dispatch_log \
         WHERE notification_dispatch_log.route_id = ? \
         AND notification_dispatch_log.dedupe_key = ?"
    ))
    .bind(route_id)
    .bind(dedupe_key)
    .fetch_optional(db.pool())
    .await?)
}

/// A log row to insert.
#[derive(Debug, Clone)]
pub struct NewLog<'a> {
    /// Tenant.
    pub customer_code: &'a str,
    /// Alert id for alert events.
    pub alert_id: Option<i64>,
    /// Entity type.
    pub entity_type: &'a str,
    /// Entity id.
    pub entity_id: i64,
    /// Idempotency key.
    pub dedupe_key: &'a str,
    /// Route.
    pub route_id: i64,
    /// Trigger.
    pub trigger: &'a str,
    /// When.
    pub dispatched_at: NaiveDateTime,
    /// Status.
    pub status: &'a str,
    /// Error text.
    pub error_message: Option<&'a str>,
    /// Latency.
    pub latency_ms: Option<i64>,
    /// Body preview.
    pub payload_preview: Option<&'a str>,
    /// Who.
    pub triggered_by: Option<&'a str>,
    /// How.
    pub trigger_source: &'a str,
    /// Vendor id.
    pub provider_reference: Option<&'a str>,
}

/// Insert a log row. An integrity error — a duplicate `(route_id,
/// dedupe_key)` when a concurrent dispatch won — is reported as `Ok(false)`.
pub async fn insert_log(db: &Db, l: &NewLog<'_>) -> Result<bool, DbError> {
    let res = sqlx::query(
        "INSERT INTO notification_dispatch_log (customer_code, alert_id, entity_type, entity_id, \
         dedupe_key, route_id, `trigger`, dispatched_at, status, error_message, latency_ms, \
         payload_preview, triggered_by, trigger_source, provider_reference) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(l.customer_code)
    .bind(l.alert_id)
    .bind(l.entity_type)
    .bind(l.entity_id)
    .bind(l.dedupe_key)
    .bind(l.route_id)
    .bind(l.trigger)
    .bind(l.dispatched_at)
    .bind(l.status)
    .bind(l.error_message)
    .bind(l.latency_ms)
    .bind(l.payload_preview)
    .bind(l.triggered_by)
    .bind(l.trigger_source)
    .bind(l.provider_reference)
    .execute(db.pool())
    .await;
    match res {
        Ok(_) => Ok(true),
        // SQLAlchemy's `IntegrityError` is every SQLSTATE 23000: the
        // duplicate key of a lost race, but also a customer code that names
        // no customer (the column's foreign key). Python reads all of them
        // as "already done".
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23000") => Ok(false),
        Err(e) => Err(DbError::from(e)),
    }
}

/// Overwrite a failed/skipped log row with a new outcome.
#[allow(clippy::too_many_arguments)]
pub async fn overwrite_log(
    db: &Db,
    id: i64,
    status: &str,
    error_message: Option<&str>,
    latency_ms: Option<i64>,
    payload_preview: Option<&str>,
    provider_reference: Option<&str>,
    now: NaiveDateTime,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE notification_dispatch_log SET dispatched_at = ?, status = ?, error_message = ?, \
         latency_ms = ?, payload_preview = ?, provider_reference = ? WHERE id = ?",
    )
    .bind(now)
    .bind(status)
    .bind(error_message)
    .bind(latency_ms)
    .bind(payload_preview)
    .bind(provider_reference)
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// `sends_in_last_hour`: a route's `sent` rows since `since`.
pub async fn sends_since(db: &Db, route_id: i64, since: NaiveDateTime) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT count(*) AS count_1 FROM notification_dispatch_log \
         WHERE notification_dispatch_log.route_id = ? AND notification_dispatch_log.status = ? \
         AND notification_dispatch_log.dispatched_at >= ?",
    )
    .bind(route_id)
    .bind("sent")
    .bind(since)
    .fetch_one(db.pool())
    .await?)
}

/// `sends_this_month`: `sent` rows through Resend routes since `since`,
/// optionally for one customer's routes.
pub async fn resend_sends_since(
    db: &Db,
    since: NaiveDateTime,
    customer_code: Option<&str>,
) -> Result<i64, DbError> {
    let mut qb: QueryBuilder<'_, MySql> = QueryBuilder::new(
        "SELECT count(*) AS count_1 FROM notification_dispatch_log \
         INNER JOIN customer_notification_route \
         ON customer_notification_route.id = notification_dispatch_log.route_id \
         WHERE customer_notification_route.channel = ",
    );
    qb.push_bind("resend");
    qb.push(" AND notification_dispatch_log.status = ");
    qb.push_bind("sent");
    qb.push(" AND notification_dispatch_log.dispatched_at >= ");
    qb.push_bind(since);
    if let Some(code) = customer_code {
        qb.push(" AND customer_notification_route.customer_code = ");
        qb.push_bind(code.to_string());
    }
    Ok(qb.build_query_scalar::<i64>().fetch_one(db.pool()).await?)
}

// ---------------------------------------------------------------------------
// notification_template
// ---------------------------------------------------------------------------

pub use copilot_db::security::TemplateRow;

const TEMPLATE_COLUMNS: &str = "notification_template.id, notification_template.name, \
     notification_template.description, notification_template.`trigger`, \
     notification_template.format, notification_template.subject_template, \
     notification_template.body_template, notification_template.customer_code, \
     notification_template.is_default, notification_template.created_by, \
     notification_template.created_at, notification_template.updated_at";

/// How `list_templates` narrows by customer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateScope {
    /// Every template.
    All,
    /// This customer's plus the shared ones.
    Customer(String),
    /// These customers' plus the shared ones (an empty list: shared only).
    Customers(Vec<String>),
}

/// `list_templates`.
pub async fn list_templates(
    db: &Db,
    scope: &TemplateScope,
    trigger: Option<&str>,
) -> Result<Vec<TemplateRow>, DbError> {
    let mut qb: QueryBuilder<'_, MySql> = QueryBuilder::new(format!(
        "SELECT {TEMPLATE_COLUMNS} FROM notification_template"
    ));
    let mut where_started = false;
    let mut clause = |qb: &mut QueryBuilder<'_, MySql>| {
        qb.push(if where_started { " AND " } else { " WHERE " });
        where_started = true;
    };
    match scope {
        TemplateScope::All => {}
        TemplateScope::Customer(code) => {
            clause(&mut qb);
            qb.push("(notification_template.customer_code = ");
            qb.push_bind(code.clone());
            qb.push(" OR notification_template.customer_code IS NULL)");
        }
        TemplateScope::Customers(codes) => {
            clause(&mut qb);
            if codes.is_empty() {
                // SQLAlchemy's empty IN: never true.
                qb.push(
                    "(notification_template.customer_code IN (NULL) AND (1 != 1) \
                         OR notification_template.customer_code IS NULL)",
                );
            } else {
                qb.push("(notification_template.customer_code IN (");
                let mut sep = qb.separated(", ");
                for c in codes {
                    sep.push_bind(c.clone());
                }
                qb.push(") OR notification_template.customer_code IS NULL)");
            }
        }
    }
    if let Some(t) = trigger {
        clause(&mut qb);
        qb.push("(notification_template.`trigger` = ");
        qb.push_bind(t.to_string());
        qb.push(" OR notification_template.`trigger` IS NULL)");
    }
    qb.push(" ORDER BY notification_template.created_at DESC");
    Ok(qb
        .build_query_as::<TemplateRow>()
        .fetch_all(db.pool())
        .await?)
}

/// A template by id.
pub async fn template(db: &Db, id: i64) -> Result<Option<TemplateRow>, DbError> {
    copilot_db::security::template(db, id).await
}

/// A template to insert.
#[derive(Debug, Clone)]
pub struct NewTemplate {
    /// Name (stripped).
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Trigger scope.
    pub trigger: Option<String>,
    /// Format.
    pub format: String,
    /// Subject.
    pub subject_template: Option<String>,
    /// Body.
    pub body_template: String,
    /// Customer scope.
    pub customer_code: Option<String>,
    /// Creator.
    pub created_by: Option<String>,
    /// Created.
    pub created_at: NaiveDateTime,
}

/// Insert a (never built-in) template; returns its id.
pub async fn insert_template(db: &Db, t: &NewTemplate) -> Result<i64, DbError> {
    let done = sqlx::query(
        "INSERT INTO notification_template (name, description, `trigger`, format, \
         subject_template, body_template, customer_code, is_default, created_by, created_at, \
         updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL)",
    )
    .bind(&t.name)
    .bind(&t.description)
    .bind(&t.trigger)
    .bind(&t.format)
    .bind(&t.subject_template)
    .bind(&t.body_template)
    .bind(&t.customer_code)
    .bind(&t.created_by)
    .bind(t.created_at)
    .execute(db.pool())
    .await?;
    Ok(i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX))
}

/// Detach a template from its routes and delete it, in one transaction.
/// Returns how many routes were detached.
pub async fn delete_template(db: &Db, id: i64) -> Result<u64, DbError> {
    let mut tx = db.pool().begin().await?;
    let detached = sqlx::query(
        "UPDATE customer_notification_route SET template_id = ? \
         WHERE customer_notification_route.template_id = ?",
    )
    .bind(Option::<i64>::None)
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    sqlx::query("DELETE FROM notification_template WHERE notification_template.id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(detached)
}

// ---------------------------------------------------------------------------
// Other modules' rows
// ---------------------------------------------------------------------------

/// The alert fields a manual send needs.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AlertRow {
    /// Primary key.
    pub id: i32,
    /// Title.
    pub alert_name: String,
    /// Tenant (string, no FK).
    pub customer_code: String,
    /// Stored severity (`NULL` = the source gave none).
    pub severity: Option<String>,
}

/// An alert by id.
pub async fn alert(db: &Db, id: i64) -> Result<Option<AlertRow>, DbError> {
    Ok(sqlx::query_as::<_, AlertRow>(
        "SELECT id, alert_name, customer_code, severity FROM incident_management_alert \
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}

/// The case fields a manual send needs.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CaseRow {
    /// Primary key.
    pub id: i32,
    /// Title.
    pub case_name: String,
    /// Tenant.
    pub customer_code: Option<String>,
}

/// A case by id.
pub async fn case(db: &Db, id: i64) -> Result<Option<CaseRow>, DbError> {
    Ok(sqlx::query_as::<_, CaseRow>(
        "SELECT id, case_name, customer_code FROM incident_management_case WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.pool())
    .await?)
}

/// The newest AI report of an alert (`created_at`, then `id`, descending).
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct LatestReport {
    /// Primary key.
    pub id: i32,
    /// Severity assessment.
    pub severity_assessment: Option<String>,
    /// Summary.
    pub summary: Option<String>,
    /// Markdown body.
    pub report_markdown: Option<String>,
    /// Recommended actions.
    pub recommended_actions: Option<String>,
    /// Created.
    pub created_at: NaiveDateTime,
}

/// `load_ai_report_context`'s report query.
pub async fn latest_report(db: &Db, alert_id: i64) -> Result<Option<LatestReport>, DbError> {
    Ok(sqlx::query_as::<_, LatestReport>(
        "SELECT id, severity_assessment, summary, report_markdown, recommended_actions, \
         created_at FROM ai_analyst_report WHERE alert_id = ? \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(alert_id)
    .fetch_optional(db.pool())
    .await?)
}
