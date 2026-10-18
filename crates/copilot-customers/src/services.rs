//! Lookups behind the customer routes, with the Python 404 texts.

use copilot_auth::AccessScope;
use copilot_auth::pyvalue::PyValue;
use copilot_db::customers::{self as db, CustomerListFilter, CustomerRow, ListedCustomer};
use copilot_db::{Db, DbError};
use copilot_license::services::{CmpOp, py_compare};
use copilot_license::{LicenseClient, SeatAllowance};
use copilot_upstream::py::{PyExc, int_of};
use copilot_web::{ApiError, AppContext};
use sqlx::FromRow;

use crate::schema::{CustomerMetaOut, CustomerMetaRequest, CustomerRequest};

/// `get_customers`: what the caller may see, narrowed by `?search=` and
/// capped by `?limit=` (`filter_query_by_customer_access`).
pub async fn list(
    ctx: &AppContext,
    access: &AccessScope,
    search: Option<&str>,
    limit: Option<i64>,
) -> Result<Vec<ListedCustomer>, ApiError> {
    let codes = match access {
        AccessScope::All => None,
        // `.where(False)`: nothing to read.
        AccessScope::Customers(codes) if codes.is_empty() => return Ok(Vec::new()),
        AccessScope::Customers(codes) => Some(codes.as_slice()),
    };
    let filter = CustomerListFilter {
        search,
        limit,
        codes,
    };
    Ok(db::list_customers(&ctx.db, &filter).await?)
}

/// The customer, or `404 Customer with customer_code … not found`.
pub async fn customer_or_404(ctx: &AppContext, code: &str) -> Result<CustomerRow, ApiError> {
    db::find_customer(&ctx.db, code)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Customer with customer_code {code} not found")))
}

// --- writes ---------------------------------------------------------------

/// `mssp_license_check`'s refusal when no tier allows another customer.
pub const LICENSE_LIMIT_MESSAGE: &str = "You have reached the maximum number of customers \
     allowed for your license type. Please upgrade your license to provision more customers.";

/// `mssp_license_check(session)`: the first customer is free; then the
/// numeric "MSSP Seats" allowance (or "MSSP Unlimited") read fresh from the
/// licence server, else the legacy ladder of boolean tiers through
/// `is_feature_enabled` (its cache and its own refusals: a 400 is the next
/// tier, anything else is raised).
pub async fn mssp_license_check(db: &Db, license: &LicenseClient) -> Result<(), ApiError> {
    let provisioned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM customers")
        .fetch_one(db.pool())
        .await
        .map_err(DbError::from)?;
    tracing::info!("Provisioned customers: {provisioned}");
    if provisioned == 0 {
        return Ok(());
    }
    match copilot_license::get_license_seat_allowance(db, license).await? {
        Some(SeatAllowance::Unlimited) => return Ok(()),
        Some(SeatAllowance::Seats(seats)) => {
            let count = PyValue::Int(provisioned.to_string());
            if py_compare(&count, CmpOp::Lt, &seats)? {
                return Ok(());
            }
            return Err(ApiError::bad_request(format!(
                "You have reached your licensed customer limit ({provisioned}/{} seats). Please \
                 purchase additional MSSP seats to provision more customers.",
                int_of(&seats)?
            )));
        }
        None => {}
    }
    for (feature, limit) in [
        ("MSSP Unlimited", None),
        ("MSSP 10", Some(10)),
        ("MSSP 5", Some(5)),
    ] {
        if limit.is_some_and(|l| provisioned >= l) {
            continue;
        }
        match copilot_license::is_feature_enabled_with(
            db,
            license,
            feature,
            Some(LICENSE_LIMIT_MESSAGE),
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(PyExc::Http(400, _)) => {}
            Err(e) => return Err(e.unhandled()),
        }
    }
    Err(ApiError::bad_request(LICENSE_LIMIT_MESSAGE))
}

/// A `customers` row with its id, as the write routes load it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct StoredCustomer {
    /// Primary key.
    pub id: i32,
    /// Tenant key, as stored.
    pub customer_code: String,
    /// Display name.
    pub customer_name: String,
    /// Contact last name.
    pub contact_last_name: Option<String>,
    /// Contact first name.
    pub contact_first_name: Option<String>,
    /// Parent customer.
    pub parent_customer_code: Option<String>,
    /// Phone.
    pub phone: Option<String>,
    /// Address line 1.
    pub address_line1: Option<String>,
    /// Address line 2.
    pub address_line2: Option<String>,
    /// City.
    pub city: Option<String>,
    /// State.
    pub state: Option<String>,
    /// Postal code.
    pub postal_code: Option<String>,
    /// Country.
    pub country: Option<String>,
    /// Customer type.
    pub customer_type: Option<String>,
    /// Logo file name.
    pub logo_file: Option<String>,
}

impl StoredCustomer {
    fn value(&self, column: &str) -> Option<&str> {
        match column {
            "customer_code" => Some(&self.customer_code),
            "customer_name" => Some(&self.customer_name),
            "contact_last_name" => self.contact_last_name.as_deref(),
            "contact_first_name" => self.contact_first_name.as_deref(),
            "parent_customer_code" => self.parent_customer_code.as_deref(),
            "phone" => self.phone.as_deref(),
            "address_line1" => self.address_line1.as_deref(),
            "address_line2" => self.address_line2.as_deref(),
            "city" => self.city.as_deref(),
            "state" => self.state.as_deref(),
            "postal_code" => self.postal_code.as_deref(),
            "country" => self.country.as_deref(),
            "customer_type" => self.customer_type.as_deref(),
            _ => self.logo_file.as_deref(),
        }
    }
}

/// `select(Customers).filter(Customers.customer_code == code)` then
/// `.first()` (MySQL's collation compares the code).
pub async fn stored_customer(db: &Db, code: &str) -> Result<Option<StoredCustomer>, DbError> {
    Ok(sqlx::query_as::<_, StoredCustomer>(
        "SELECT customers.id, customers.customer_code, customers.customer_name, \
         customers.contact_last_name, customers.contact_first_name, \
         customers.parent_customer_code, customers.phone, customers.address_line1, \
         customers.address_line2, customers.city, customers.state, customers.postal_code, \
         customers.country, customers.customer_type, customers.logo_file \
         FROM customers WHERE customers.customer_code = ?",
    )
    .bind(code)
    .fetch_optional(db.pool())
    .await?)
}

fn not_found(code: &str) -> ApiError {
    ApiError::not_found(format!("Customer with customer_code {code} not found"))
}

/// `create_customer`: the licence check, `verify_unique_customer_code`, the
/// row. `created_at` is the time of creation (Python's model default is
/// evaluated once, at import).
pub async fn create_customer(
    db: &Db,
    license: &LicenseClient,
    req: &CustomerRequest,
) -> Result<(), ApiError> {
    mssp_license_check(db, license).await?;
    if stored_customer(db, &req.customer_code).await?.is_some() {
        return Err(ApiError::bad_request(
            "Customer with this customer_code already exists",
        ));
    }
    tracing::info!(customer_code = %req.customer_code, "creating new customer");
    let mut q = sqlx::query(
        "INSERT INTO customers (customer_code, customer_name, contact_last_name, \
         contact_first_name, parent_customer_code, phone, address_line1, address_line2, city, \
         state, postal_code, country, customer_type, logo_file, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (_, value) in req.columns() {
        q = q.bind(value);
    }
    q.bind(copilot_core::time::now_utc_micros())
        .execute(db.pool())
        .await
        .map_err(DbError::from)?;
    Ok(())
}

/// `update_customer`: the row found by its code (404), every field of the
/// body set on it, and an `UPDATE` of the columns whose value changed (none:
/// no statement), as the ORM flushes it.
pub async fn update_customer(db: &Db, code: &str, req: &CustomerRequest) -> Result<(), ApiError> {
    let existing = stored_customer(db, code)
        .await?
        .ok_or_else(|| not_found(code))?;
    let changed: Vec<(&str, Option<&str>)> = req
        .columns()
        .into_iter()
        .filter(|(column, value)| existing.value(column) != *value)
        .collect();
    if changed.is_empty() {
        return Ok(());
    }
    let sets: Vec<String> = changed.iter().map(|(c, _)| format!("{c}=?")).collect();
    let sql = format!(
        "UPDATE customers SET {} WHERE customers.id = ?",
        sets.join(", ")
    );
    let mut q = sqlx::query(&sql);
    for (_, value) in &changed {
        q = q.bind(*value);
    }
    q.bind(existing.id)
        .execute(db.pool())
        .await
        .map_err(DbError::from)?;
    Ok(())
}

/// pymysql's `IntegrityError` codes (`pymysql.err._map_error`).
const INTEGRITY_ERRORS: &[u16] = &[
    1022, 1048, 1062, 1169, 1215, 1216, 1217, 1451, 1452, 1557, 4025,
];

/// `str(e.orig)` of a pymysql error: `(code, 'message')`.
fn pymysql_text(code: u16, message: &str) -> String {
    format!("({code}, {})", copilot_auth::pyvalue::str_repr(message))
}

/// `delete_customer`: the row found by its code (404), then the ORM's
/// flush — the customer's agents and its meta row loaded, their
/// `customer_code` set to `NULL` (the relationships have no delete cascade),
/// the row deleted — in one transaction, rolled back on failure. A foreign
/// key of `user_customer_access` is the users' 400, any other integrity
/// error the dependencies' 400, anything else the 500 with its text.
pub async fn delete_customer(db: &Db, code: &str) -> Result<String, ApiError> {
    let existing = stored_customer(db, code)
        .await?
        .ok_or_else(|| not_found(code))?;
    let outcome = delete_flush(db, &existing).await;
    match outcome {
        Ok(()) => {
            tracing::info!("Successfully deleted customer with customer_code: {code}");
            Ok(format!("Customer '{code}' deleted successfully"))
        }
        Err(e) => {
            let Some(dbe) = e.as_database_error() else {
                return Err(ApiError::http(
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An error occurred while deleting the customer: {e}"),
                ));
            };
            let number = dbe
                .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .map(sqlx::mysql::MySqlDatabaseError::number)
                .unwrap_or_default();
            let text = pymysql_text(number, dbe.message());
            if INTEGRITY_ERRORS.contains(&number) {
                if text.contains("user_customer_access") && text.contains("FOREIGN KEY") {
                    tracing::error!(
                        "Cannot delete customer {code}: users are still assigned to this customer"
                    );
                    return Err(ApiError::bad_request(format!(
                        "Cannot delete customer '{code}'. There are still users assigned to \
                         this customer. Please remove all user assignments before deleting the \
                         customer."
                    )));
                }
                tracing::error!("Integrity error deleting customer {code}: {text}");
                return Err(ApiError::bad_request(
                    "Cannot delete customer due to existing dependencies. Please ensure all \
                     related data is removed first.",
                ));
            }
            Err(ApiError::http(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("An error occurred while deleting the customer: {text}"),
            ))
        }
    }
}

async fn delete_flush(db: &Db, existing: &StoredCustomer) -> Result<(), sqlx::Error> {
    let mut tx = db.pool().begin().await?;
    let mut agents: Vec<i32> =
        sqlx::query_scalar("SELECT agents.id FROM agents WHERE ? = agents.customer_code")
            .bind(&existing.customer_code)
            .fetch_all(&mut *tx)
            .await?;
    let meta: Option<i32> = sqlx::query_scalar(
        "SELECT customersmeta.id FROM customersmeta WHERE ? = customersmeta.customer_code",
    )
    .bind(&existing.customer_code)
    .fetch_optional(&mut *tx)
    .await?;
    agents.sort_unstable();
    for id in agents {
        sqlx::query("UPDATE agents SET customer_code=? WHERE agents.id = ?")
            .bind(None::<String>)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(id) = meta {
        sqlx::query("UPDATE customersmeta SET customer_code=? WHERE customersmeta.id = ?")
            .bind(None::<String>)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM customers WHERE customers.id = ?")
        .bind(existing.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

/// A `customersmeta` row with its id.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct StoredMeta {
    /// Primary key.
    pub id: i32,
    /// Graylog index set.
    pub customer_meta_graylog_index: String,
    /// Graylog stream.
    pub customer_meta_graylog_stream: String,
    /// Grafana organisation.
    pub customer_meta_grafana_org_id: String,
    /// Wazuh group.
    pub customer_meta_wazuh_group: String,
    /// Index retention.
    pub customer_meta_index_retention: Option<String>,
    /// Wazuh registration port.
    pub customer_meta_wazuh_registration_port: Option<String>,
    /// Wazuh log ingestion port.
    pub customer_meta_wazuh_log_ingestion_port: Option<String>,
    /// Wazuh API port.
    pub customer_meta_wazuh_api_port: Option<String>,
    /// Wazuh auth password.
    pub customer_meta_wazuh_auth_password: Option<String>,
    /// Portainer stack.
    pub customer_meta_portainer_stack_id: Option<i32>,
}

impl StoredMeta {
    fn string(&self, column: &str) -> Option<&str> {
        match column {
            "customer_meta_graylog_index" => Some(&self.customer_meta_graylog_index),
            "customer_meta_graylog_stream" => Some(&self.customer_meta_graylog_stream),
            "customer_meta_grafana_org_id" => Some(&self.customer_meta_grafana_org_id),
            "customer_meta_wazuh_group" => Some(&self.customer_meta_wazuh_group),
            "customer_meta_index_retention" => self.customer_meta_index_retention.as_deref(),
            "customer_meta_wazuh_registration_port" => {
                self.customer_meta_wazuh_registration_port.as_deref()
            }
            "customer_meta_wazuh_log_ingestion_port" => {
                self.customer_meta_wazuh_log_ingestion_port.as_deref()
            }
            "customer_meta_wazuh_api_port" => self.customer_meta_wazuh_api_port.as_deref(),
            _ => self.customer_meta_wazuh_auth_password.as_deref(),
        }
    }
}

impl From<StoredMeta> for CustomerMetaOut {
    fn from(r: StoredMeta) -> Self {
        Self {
            customer_meta_graylog_index: r.customer_meta_graylog_index,
            customer_meta_graylog_stream: r.customer_meta_graylog_stream,
            customer_meta_grafana_org_id: r.customer_meta_grafana_org_id,
            customer_meta_wazuh_group: r.customer_meta_wazuh_group,
            customer_meta_index_retention: r.customer_meta_index_retention,
            customer_meta_wazuh_registration_port: r.customer_meta_wazuh_registration_port,
            customer_meta_wazuh_log_ingestion_port: r.customer_meta_wazuh_log_ingestion_port,
            customer_meta_wazuh_api_port: r.customer_meta_wazuh_api_port,
            customer_meta_wazuh_auth_password: r.customer_meta_wazuh_auth_password,
            customer_meta_portainer_stack_id: r.customer_meta_portainer_stack_id.map(i64::from),
        }
    }
}

/// `select(CustomersMeta).filter(CustomersMeta.customer_code == code)` then
/// `.first()`.
pub async fn stored_meta(db: &Db, code: &str) -> Result<Option<StoredMeta>, DbError> {
    Ok(sqlx::query_as::<_, StoredMeta>(
        "SELECT customersmeta.id, customersmeta.customer_meta_graylog_index, \
         customersmeta.customer_meta_graylog_stream, customersmeta.customer_meta_grafana_org_id, \
         customersmeta.customer_meta_wazuh_group, customersmeta.customer_meta_index_retention, \
         customersmeta.customer_meta_wazuh_registration_port, \
         customersmeta.customer_meta_wazuh_log_ingestion_port, \
         customersmeta.customer_meta_wazuh_api_port, \
         customersmeta.customer_meta_wazuh_auth_password, \
         customersmeta.customer_meta_portainer_stack_id \
         FROM customersmeta WHERE customersmeta.customer_code = ?",
    )
    .bind(code)
    .fetch_optional(db.pool())
    .await?)
}

fn meta_not_found(code: &str) -> ApiError {
    ApiError::not_found(format!("Customer meta with customer_code {code} not found"))
}

/// `add_customer_meta`: the customer found by its code (404), then a new
/// meta row with the body's fields and the customer's stored code and name.
pub async fn add_customer_meta(
    db: &Db,
    code: &str,
    req: &CustomerMetaRequest,
) -> Result<(), ApiError> {
    let existing = stored_customer(db, code)
        .await?
        .ok_or_else(|| not_found(code))?;
    let mut q = sqlx::query(
        "INSERT INTO customersmeta (customer_code, customer_name, customer_meta_graylog_index, \
         customer_meta_graylog_stream, customer_meta_grafana_org_id, customer_meta_wazuh_group, \
         customer_meta_index_retention, customer_meta_wazuh_registration_port, \
         customer_meta_wazuh_log_ingestion_port, customer_meta_wazuh_api_port, \
         customer_meta_wazuh_auth_password, customer_meta_iris_customer_id, \
         customer_meta_office365_organization_id, customer_meta_portainer_stack_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&existing.customer_code)
    .bind(&existing.customer_name);
    for (_, value) in &req.strings {
        q = q.bind(value);
    }
    q.bind(None::<i32>)
        .bind(None::<String>)
        .bind(req.stack_id())
        .execute(db.pool())
        .await
        .map_err(DbError::from)?;
    Ok(())
}

/// `update_customer_meta`: the first meta row of the code (404), the fields
/// the body set (`exclude_unset`), an `UPDATE` of the columns that changed.
pub async fn update_customer_meta(
    db: &Db,
    code: &str,
    req: &CustomerMetaRequest,
) -> Result<(), ApiError> {
    let existing = stored_meta(db, code)
        .await?
        .ok_or_else(|| meta_not_found(code))?;
    let mut sets = Vec::new();
    let mut strings = Vec::new();
    for (column, value) in &req.strings {
        if existing.string(column) != Some(value.as_str()) {
            sets.push(format!("{column}=?"));
            strings.push(value.as_str());
        }
    }
    let stack = req
        .portainer_stack_id
        .filter(|v| *v != existing.customer_meta_portainer_stack_id.map(i64::from));
    if stack.is_some() {
        sets.push("customer_meta_portainer_stack_id=?".into());
    }
    if sets.is_empty() {
        return Ok(());
    }
    let sql = format!(
        "UPDATE customersmeta SET {} WHERE customersmeta.id = ?",
        sets.join(", ")
    );
    let mut q = sqlx::query(&sql);
    for value in strings {
        q = q.bind(value);
    }
    if let Some(v) = stack {
        q = q.bind(v);
    }
    q.bind(existing.id)
        .execute(db.pool())
        .await
        .map_err(DbError::from)?;
    Ok(())
}

/// `delete_customer_meta`: the first meta row of the code (404), deleted;
/// the answer shows it as it was.
pub async fn delete_customer_meta(db: &Db, code: &str) -> Result<CustomerMetaOut, ApiError> {
    let existing = stored_meta(db, code)
        .await?
        .ok_or_else(|| meta_not_found(code))?;
    let id = existing.id;
    sqlx::query("DELETE FROM customersmeta WHERE customersmeta.id = ?")
        .bind(id)
        .execute(db.pool())
        .await
        .map_err(DbError::from)?;
    Ok(existing.into())
}
