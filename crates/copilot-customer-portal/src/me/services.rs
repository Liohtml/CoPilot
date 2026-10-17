//! Port of `app/customer_portal/services/me.py`.

use std::collections::HashMap;

use sqlx::{MySql, QueryBuilder};

use copilot_core::Role;
use copilot_db::{Db, DbError};
use copilot_incidents::store;
use copilot_jinja::unicode::casefold;
use copilot_web::form::py_strip;
use copilot_web::{ApiError, AppContext, CurrentUser};

use super::schema::{PortalCustomer, PortalMeResponse};

/// `portal_customers`: the user's customers (the wildcard never expanded),
/// each with its name (`strip()`ped; the code when there is none — a code
/// without a `customers` row is still listed), sorted by
/// `(name.casefold(), code)`.
pub async fn portal_customers(db: &Db, codes: &[String]) -> Result<Vec<PortalCustomer>, DbError> {
    let codes: Vec<&String> = codes.iter().filter(|c| c.as_str() != "*").collect();
    if codes.is_empty() {
        return Ok(Vec::new());
    }
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT customers.customer_code, customers.customer_name FROM customers \
         WHERE customers.customer_code IN (",
    );
    store::push_list(&mut qb, codes.iter().map(|c| c.as_str()));
    qb.push(")");
    // `{code: name for code, name in result.all()}`: a later row wins.
    let mut names: HashMap<String, String> = HashMap::new();
    for (code, name) in qb
        .build_query_as::<(String, String)>()
        .fetch_all(db.pool())
        .await?
    {
        names.insert(code, name);
    }
    let mut customers: Vec<PortalCustomer> = codes
        .into_iter()
        .map(|code| {
            let name = names.get(code).map(|n| py_strip(n)).unwrap_or_default();
            PortalCustomer {
                customer_code: code.clone(),
                customer_name: if name.is_empty() {
                    code.clone()
                } else {
                    name.to_string()
                },
            }
        })
        .collect();
    sort_customers(&mut customers);
    Ok(customers)
}

/// `sorted(customers, key=lambda c: (c.customer_name.casefold(), c.customer_code))`
/// (stable, code point order).
pub fn sort_customers(customers: &mut [PortalCustomer]) {
    customers.sort_by(|a, b| {
        (casefold(&a.customer_name), &a.customer_code)
            .cmp(&(casefold(&b.customer_name), &b.customer_code))
    });
}

/// `get_portal_profile`. A role id `RoleEnum` does not know is Python's
/// `ValueError` (the route's 500).
pub async fn profile(ctx: &AppContext, user: &CurrentUser) -> Result<PortalMeResponse, ApiError> {
    let role = user
        .role_id
        .and_then(Role::from_id)
        .ok_or_else(|| ApiError::internal(format!("{:?} is not a valid RoleEnum", user.role_id)))?;
    let codes = user.access(ctx).await?.to_python_list();
    Ok(PortalMeResponse {
        success: true,
        message: "Profile retrieved successfully".into(),
        username: user.username.clone(),
        role: role.name().into(),
        customers: portal_customers(&ctx.db, &codes).await?,
    })
}
