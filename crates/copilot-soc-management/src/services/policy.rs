//! Reading the SLA policy — port of the reads of
//! `soc_management/services/policy.py` (the writes are `copilot_sla::policy`,
//! shared with the incidents recorder).

use copilot_sla::policy::{effective_matrix, load_rows};
use copilot_web::{ApiError, AppContext};
use sqlx::MySqlConnection;

use crate::schema::policy::PolicyMatrix;
use crate::services::{internal, sla_error};

/// `get_matrix(session, customer_code)` on a connection (inside a write's
/// transaction, it sees the rows just written).
pub async fn get_matrix_on(
    conn: &mut MySqlConnection,
    customer_code: Option<&str>,
) -> Result<PolicyMatrix, copilot_sla::SlaError> {
    let codes: Vec<&str> = customer_code
        .into_iter()
        .filter(|c| !c.is_empty())
        .collect();
    let rows = load_rows(conn, &codes).await?;
    Ok(PolicyMatrix::new(
        customer_code.map(str::to_string),
        &effective_matrix(customer_code, &rows),
    ))
}

/// `get_matrix(session, customer_code)`: every cell of a scope as it
/// resolves, each labelled with where its value comes from.
pub async fn get_matrix(
    ctx: &AppContext,
    customer_code: Option<&str>,
) -> Result<PolicyMatrix, ApiError> {
    let mut conn = ctx.db.pool().acquire().await.map_err(internal)?;
    get_matrix_on(&mut conn, customer_code)
        .await
        .map_err(sla_error)
}
