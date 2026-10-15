//! Lookups behind the customer routes, with the Python 404 texts.

use copilot_auth::AccessScope;
use copilot_db::customers::{self as db, CustomerListFilter, CustomerRow, ListedCustomer};
use copilot_web::{ApiError, AppContext};

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
