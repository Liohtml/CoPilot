//! Case listings and counts — `list_cases_for_user`,
//! `case_status_counts_for_user`, `list_cases_by_*`, `get_case_filter_options`.
//!
//! Cases are scoped by customer only (no tag RBAC), through
//! `filter_query_by_customer_access`: deployment-wide callers get no filter,
//! a scoped caller `customer_code IN (…)`, and a scope that resolves to
//! nothing `WHERE false`. `incident_management_case.customer_code` is
//! nullable; a case without one is visible to admins only.

use sqlx::{MySql, QueryBuilder};

use copilot_auth::AccessScope;
use copilot_db::{Db, DbError};

use crate::lists::StatusCounts;
use crate::store::{self, CASE_COLS, CaseRow, push_list};

fn push_scope<'a>(qb: &mut QueryBuilder<'a, MySql>, scope: &'a AccessScope) {
    match scope {
        AccessScope::All => {}
        AccessScope::Customers(codes) if codes.is_empty() => {
            qb.push(" AND false");
        }
        AccessScope::Customers(codes) => {
            qb.push(" AND c.customer_code IN (");
            push_list(qb, codes.iter().map(String::as_str));
            qb.push(")");
        }
    }
}

fn push_case_page(qb: &mut QueryBuilder<'_, MySql>, order: &str, page: i64, page_size: i64) {
    let dir = if order == "asc" { "ASC" } else { "DESC" };
    qb.push(format!(" ORDER BY c.id {dir} LIMIT "));
    qb.push_bind(page_size);
    qb.push(" OFFSET ");
    qb.push_bind((page - 1).saturating_mul(page_size));
}

/// `list_cases_for_user` (`scope` = `resolve_effective_customers`).
pub async fn list_for_user(
    db: &Db,
    scope: &AccessScope,
    page: i64,
    page_size: i64,
    order: &str,
) -> Result<Vec<CaseRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {CASE_COLS} FROM incident_management_case c WHERE 1=1"
    ));
    push_scope(&mut qb, scope);
    push_case_page(&mut qb, order, page, page_size);
    store::fetch_cases(&mut qb, db).await
}

/// `case_status_counts_for_user`.
pub async fn status_counts(db: &Db, scope: &AccessScope) -> Result<StatusCounts, DbError> {
    if matches!(scope, AccessScope::Customers(c) if c.is_empty()) {
        return Ok(StatusCounts::default());
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT c.case_status, count(c.id) FROM incident_management_case c WHERE 1=1",
    );
    push_scope(&mut qb, scope);
    qb.push(" GROUP BY c.case_status");
    Ok(StatusCounts::from_rows(
        &store::status_rows(&mut qb, db).await?,
    ))
}

/// `list_cases_by_status`.
pub async fn list_by_status(
    db: &Db,
    status: &str,
    page: i64,
    page_size: i64,
    order: &str,
) -> Result<Vec<CaseRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {CASE_COLS} FROM incident_management_case c WHERE c.case_status = "
    ));
    qb.push_bind(status);
    push_case_page(&mut qb, order, page, page_size);
    store::fetch_cases(&mut qb, db).await
}

/// `list_cases_by_name` (`LIKE %name%`).
pub async fn list_by_name(
    db: &Db,
    name: &str,
    page: i64,
    page_size: i64,
    order: &str,
) -> Result<Vec<CaseRow>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {CASE_COLS} FROM incident_management_case c WHERE c.case_name LIKE "
    ));
    qb.push_bind(format!("%{name}%"));
    push_case_page(&mut qb, order, page, page_size);
    store::fetch_cases(&mut qb, db).await
}

/// `list_cases_by_assigned_to` (no `ORDER BY`, as in Python).
pub async fn list_by_assigned_to(db: &Db, assigned_to: &str) -> Result<Vec<CaseRow>, DbError> {
    let sql = format!("SELECT {CASE_COLS} FROM incident_management_case c WHERE c.assigned_to = ?");
    Ok(sqlx::query_as::<_, CaseRow>(&sql)
        .bind(assigned_to)
        .fetch_all(db.pool())
        .await?)
}

/// `list_cases_by_customer_code` (no `ORDER BY`).
pub async fn list_by_customer(db: &Db, code: &str) -> Result<Vec<CaseRow>, DbError> {
    let sql =
        format!("SELECT {CASE_COLS} FROM incident_management_case c WHERE c.customer_code = ?");
    Ok(sqlx::query_as::<_, CaseRow>(&sql)
        .bind(code)
        .fetch_all(db.pool())
        .await?)
}

/// `list_cases_by_asset_name` without `customer_codes` (the admin branch of
/// `/case/asset/{name}`): each case once, newest first.
pub async fn list_by_asset_name(db: &Db, asset_name: &str) -> Result<Vec<CaseRow>, DbError> {
    let sql = format!(
        "SELECT {CASE_COLS} FROM incident_management_case c WHERE c.id IN \
         (SELECT l.case_id FROM incident_management_casealertlink l \
         JOIN incident_management_alert a ON a.id = l.alert_id \
         JOIN incident_management_asset s ON s.alert_linked = a.id WHERE s.asset_name = ?) \
         ORDER BY c.id DESC"
    );
    Ok(sqlx::query_as::<_, CaseRow>(&sql)
        .bind(asset_name)
        .fetch_all(db.pool())
        .await?)
}

/// `get_case_filter_options`: distinct statuses and assignees (empty values
/// dropped), within `get_user_accessible_customers`.
pub async fn filter_options(
    db: &Db,
    scope: &AccessScope,
) -> Result<(Vec<String>, Vec<String>), DbError> {
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT DISTINCT c.case_status FROM incident_management_case c WHERE 1=1",
    );
    push_scope(&mut qb, scope);
    qb.push(" ORDER BY c.case_status");
    let statuses: Vec<Option<String>> = qb.build_query_scalar().fetch_all(db.pool()).await?;
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT DISTINCT c.assigned_to FROM incident_management_case c WHERE 1=1",
    );
    push_scope(&mut qb, scope);
    qb.push(" AND c.assigned_to IS NOT NULL ORDER BY c.assigned_to");
    let assigned: Vec<Option<String>> = qb.build_query_scalar().fetch_all(db.pool()).await?;
    let keep = |v: Vec<Option<String>>| v.into_iter().flatten().filter(|s| !s.is_empty()).collect();
    Ok((keep(statuses), keep(assigned)))
}
