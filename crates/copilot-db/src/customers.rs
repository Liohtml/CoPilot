//! `customers` and `customersmeta` reads (`app/customers/routes/customers.py`).
//!
//! The Python routes query without `ORDER BY`; these queries keep the same
//! shape (filters in the same order, no ordering added), so MySQL picks the
//! same plan and returns rows in the same order — primary-key order for a full
//! scan, `customer_code` index order for an `IN` list.

use sqlx::{FromRow, MySql, QueryBuilder};

use crate::schema::TableRequirement;
use crate::{Db, DbError};

/// Columns this module needs.
pub const REQUIREMENTS: &[TableRequirement] = &[
    TableRequirement {
        table: "customers",
        columns: &[
            "id",
            "customer_code",
            "parent_customer_code",
            "customer_name",
            "contact_last_name",
            "contact_first_name",
            "phone",
            "address_line1",
            "address_line2",
            "city",
            "state",
            "postal_code",
            "country",
            "customer_type",
            "logo_file",
        ],
    },
    TableRequirement {
        table: "customersmeta",
        columns: &[
            "customer_code",
            "customer_meta_graylog_index",
            "customer_meta_graylog_stream",
            "customer_meta_grafana_org_id",
            "customer_meta_wazuh_group",
            "customer_meta_index_retention",
            "customer_meta_wazuh_registration_port",
            "customer_meta_wazuh_log_ingestion_port",
            "customer_meta_wazuh_api_port",
            "customer_meta_wazuh_auth_password",
            "customer_meta_portainer_stack_id",
        ],
    },
];

/// One `customers` row, as `CustomerOut` reads it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CustomerRow {
    /// Tenant key.
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

const CUSTOMER_COLS: &str = "customers.customer_code, customers.customer_name, \
     customers.contact_last_name, customers.contact_first_name, customers.parent_customer_code, \
     customers.phone, customers.address_line1, customers.address_line2, customers.city, \
     customers.state, customers.postal_code, customers.country, customers.customer_type, \
     customers.logo_file";

/// A `customers` row with whether a `customersmeta` row exists for it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ListedCustomer {
    /// The customer.
    #[sqlx(flatten)]
    pub customer: CustomerRow,
    /// `EXISTS (customersmeta …)` (MySQL answers 0/1 as a `BIGINT`).
    pub is_provisioned: i64,
}

/// What `GET /customers` narrows by.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CustomerListFilter<'a> {
    /// `?search=`: case-insensitive substring of code or name (`ilike`; `%`
    /// and `_` keep their `LIKE` meaning, as in Python).
    pub search: Option<&'a str>,
    /// `?limit=`.
    pub limit: Option<i64>,
    /// Customer scope; `None` = every customer. Never empty (callers return
    /// an empty list themselves).
    pub codes: Option<&'a [String]>,
}

/// `GET /customers`: rows with `is_provisioned`, in MySQL's order.
pub async fn list_customers(
    db: &Db,
    filter: &CustomerListFilter<'_>,
) -> Result<Vec<ListedCustomer>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {CUSTOMER_COLS}, EXISTS (SELECT customersmeta.customer_code FROM customersmeta \
         WHERE customersmeta.customer_code = customers.customer_code) AS is_provisioned \
         FROM customers"
    ));
    let mut first = true;
    let mut and = |qb: &mut QueryBuilder<'_, MySql>| {
        qb.push(if first { " WHERE " } else { " AND " });
        first = false;
    };
    if let Some(term) = filter.search.filter(|s| !s.is_empty()) {
        let like = format!("%{term}%");
        and(&mut qb);
        qb.push("(lower(customers.customer_code) LIKE lower(")
            .push_bind(like.clone())
            .push(") OR lower(customers.customer_name) LIKE lower(")
            .push_bind(like)
            .push("))");
    }
    if let Some(codes) = filter.codes {
        and(&mut qb);
        qb.push("customers.customer_code IN (");
        let mut sep = qb.separated(", ");
        for c in codes {
            sep.push_bind(c.clone());
        }
        qb.push(")");
    }
    if let Some(limit) = filter.limit {
        qb.push(" LIMIT ").push_bind(limit);
    }
    Ok(qb
        .build_query_as::<ListedCustomer>()
        .fetch_all(db.pool())
        .await?)
}

/// The first customer with this code (`.scalars().first()`).
pub async fn find_customer(db: &Db, code: &str) -> Result<Option<CustomerRow>, DbError> {
    Ok(sqlx::query_as::<_, CustomerRow>(&format!(
        "SELECT {CUSTOMER_COLS} FROM customers WHERE customers.customer_code = ? LIMIT 1"
    ))
    .bind(code)
    .fetch_optional(db.pool())
    .await?)
}

/// One `customersmeta` row, as `CustomerMetaOut` reads it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CustomerMetaRow {
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

/// The first meta row for this code.
pub async fn find_customer_meta(db: &Db, code: &str) -> Result<Option<CustomerMetaRow>, DbError> {
    Ok(sqlx::query_as::<_, CustomerMetaRow>(
        "SELECT customer_meta_graylog_index, customer_meta_graylog_stream, \
         customer_meta_grafana_org_id, customer_meta_wazuh_group, customer_meta_index_retention, \
         customer_meta_wazuh_registration_port, customer_meta_wazuh_log_ingestion_port, \
         customer_meta_wazuh_api_port, customer_meta_wazuh_auth_password, \
         customer_meta_portainer_stack_id FROM customersmeta WHERE customer_code = ? LIMIT 1",
    )
    .bind(code)
    .fetch_optional(db.pool())
    .await?)
}
