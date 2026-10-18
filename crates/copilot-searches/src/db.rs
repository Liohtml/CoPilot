//! The one table the catalog reads: a customer's Graylog stream for the
//! backtest (`get_customer_stream`).

use copilot_web::AppContext;

/// `select(CustomersMeta).where(customer_code == …)` → `.scalars().first()`
/// → `customer_meta_graylog_stream` (`None` without a row).
pub async fn customer_stream(
    ctx: &AppContext,
    customer_code: &str,
) -> Result<Option<String>, String> {
    let rows: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT customer_meta_graylog_stream FROM customersmeta WHERE customer_code = ?",
    )
    .persistent(false)
    .bind(customer_code)
    .fetch_all(ctx.db.pool())
    .await
    .map_err(|e| e.to_string())?;
    Ok(rows.into_iter().next().and_then(|(s,)| s))
}
