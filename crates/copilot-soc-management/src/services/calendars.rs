//! Reading business-hours calendars — port of the reads of
//! `soc_management/services/calendars.py` (the writes are
//! `copilot_sla::calendar`).

use copilot_auth::AccessScope;
use copilot_sla::calendar::{customers_with_calendar, load_book};
use copilot_web::{ApiError, AppContext, CurrentUser};

use crate::schema::calendar::{CalendarOut, CalendarResponse};
use crate::services::{internal, sla_error};

/// `get_calendar(session, customer_code)`: the calendar a scope runs on,
/// labelled with where it comes from.
pub async fn get_calendar(
    ctx: &AppContext,
    customer_code: Option<&str>,
) -> Result<CalendarOut, ApiError> {
    let mut conn = ctx.db.pool().acquire().await.map_err(internal)?;
    let code = customer_code.filter(|c| !c.is_empty());
    let book = load_book(&mut conn, &code.into_iter().collect::<Vec<_>>())
        .await
        .map_err(sla_error)?;
    let calendar = book.for_customer(customer_code);
    let source = match code {
        Some(c) => book.source(Some(c)),
        None if book.global.is_some() => "global",
        None => "default",
    };
    Ok(CalendarOut::new(
        customer_code.map(str::to_string),
        source,
        calendar,
    ))
}

/// `_calendar_response(session, user, customer_code, message, retargeted)`.
pub async fn calendar_response(
    ctx: &AppContext,
    user: &CurrentUser,
    customer_code: Option<&str>,
    message: String,
    retargeted: i64,
) -> Result<CalendarResponse, ApiError> {
    let codes = match user.access(ctx).await? {
        AccessScope::All => None,
        AccessScope::Customers(codes) => Some(codes.clone()),
    };
    let calendar = get_calendar(ctx, customer_code).await?;
    let mut conn = ctx.db.pool().acquire().await.map_err(internal)?;
    let with_calendar = customers_with_calendar(&mut conn, codes.as_deref())
        .await
        .map_err(internal)?;
    Ok(CalendarResponse {
        success: true,
        message,
        calendar,
        customers_with_calendar: with_calendar,
        retargeted,
    })
}
