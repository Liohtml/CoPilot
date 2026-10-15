//! `/api/incidents/report` — port of the CSV case exports of
//! `app/incidents/routes/incident_report.py` (admin/analyst).
//!
//! One row per case and linked alert, in the order the ORM loads them (the
//! case query has no `ORDER BY` and keeps SQLAlchemy's shape; links by alert
//! id; an alert's assets, tags and comments as `selectinload` returns them),
//! written like `csv.DictWriter` (`excel` dialect, `\n` line ends: a field is
//! quoted when it holds `,`, `"`, `\r` or `\n`, quotes doubled, `None` empty).
//!
//! Still Python: `/generate-report-docx` and `/generate-report-pdf` (the
//! template comes from MinIO, the document is rendered by docxtpl or
//! wkhtmltopdf).
//!
//! Difference by design: `POST /generate-report-csv` exports the caller's
//! customers' cases only. Python exported every tenant's cases to any
//! analyst; the per-customer export already checked the customer.

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::post;
use chrono::{NaiveDate, NaiveDateTime};
use http::header::{CONTENT_DISPOSITION, CONTENT_TYPE, HeaderValue};
use serde_json::Value;
use sqlx::{MySql, QueryBuilder};

use copilot_auth::AccessScope;
use copilot_web::validate::{IntRules, Validator, loc};
use copilot_web::{AdminOrAnalyst, ApiError, AppContext, Authorized, QueryPairs};

use crate::store::{self, CASE_COLS, CaseRow, Include};

type Soc = Authorized<AdminOrAnalyst>;

/// `FIELDNAMES`.
pub const FIELDNAMES: [&str; 20] = [
    "Case ID",
    "Case Name",
    "Case Description",
    "Case Creation Time",
    "Case Status",
    "Case Closed Time",
    "Case Assigned To",
    "Case Customer Code",
    "Alert ID",
    "Alert Name",
    "Alert Description",
    "Alert Status",
    "Alert Creation Time",
    "Alert Time Closed",
    "Alert Source",
    "Alert Assigned To",
    "Assets",
    "Tags",
    "Comments",
    "Customer Code",
];

/// The router, to be nested at `/api/incidents/report`.
pub fn report(ctx: AppContext) -> Router {
    Router::new()
        .route("/generate-report-csv", post(export_all))
        .route(
            "/generate-report-csv/{customer_code}",
            post(export_customer),
        )
        .with_state(ctx)
}

/// One field as `csv.writer` (`QUOTE_MINIMAL`) writes it.
pub fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// `writer.writeheader()` + `writer.writerows(rows)`.
pub fn csv_document(rows: &[[String; 20]]) -> String {
    let mut out = String::new();
    let mut line = |fields: &mut dyn Iterator<Item = String>| {
        let joined: Vec<String> = fields.collect();
        out.push_str(&joined.join(","));
        out.push('\n');
    };
    line(&mut FIELDNAMES.iter().map(|f| csv_field(f)));
    for row in rows {
        line(&mut row.iter().map(|f| csv_field(f)));
    }
    out
}

fn stamp(t: NaiveDateTime) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// `year` / `month` (`ge`/`le` bounds), then the pair rule (400).
fn period(q: &QueryPairs) -> Result<Option<(i32, u32)>, ApiError> {
    let mut v = Validator::new();
    let mut read = |name: &str, ge: i64, le: i64| {
        q.get(name).and_then(|raw| {
            v.check_int(
                &loc("query", name),
                &Value::String(raw.into()),
                IntRules {
                    ge: Some(ge),
                    le: Some(le),
                },
            )
        })
    };
    let year = read("year", 2000, 2100);
    let month = read("month", 1, 12);
    let had_year = q.get("year").is_some();
    let had_month = q.get("month").is_some();
    v.finish()?;
    if had_year != had_month {
        return Err(ApiError::bad_request(
            "Both year and month must be provided together",
        ));
    }
    Ok(match (year, month) {
        (Some(y), Some(m)) => Some((y as i32, m as u32)),
        _ => None,
    })
}

/// `_build_month_range`: the first second of the month to its last.
fn month_range(year: i32, month: u32) -> Option<(NaiveDateTime, NaiveDateTime)> {
    let start = NaiveDate::from_ymd_opt(year, month, 1)?;
    let next = if month == 12 {
        NaiveDate::from_ymd_opt(year + 1, 1, 1)?
    } else {
        NaiveDate::from_ymd_opt(year, month + 1, 1)?
    };
    let last = next.pred_opt()?;
    Some((start.and_hms_opt(0, 0, 0)?, last.and_hms_opt(23, 59, 59)?))
}

/// `fetch_cases_with_related_data` / `fetch_cases_by_customer`, flattened to
/// `serialize_case_alert_to_row` rows.
async fn rows(
    ctx: &AppContext,
    customer: Option<&str>,
    scope: Option<&AccessScope>,
    period: Option<(i32, u32)>,
) -> Result<Vec<[String; 20]>, ApiError> {
    // SQLAlchemy's statement (no ORDER BY): the same query, the same scan.
    let mut qb = QueryBuilder::<MySql>::new(format!(
        "SELECT {CASE_COLS} FROM incident_management_case c"
    ));
    let mut first = true;
    let mut and = |qb: &mut QueryBuilder<'_, MySql>| {
        qb.push(if first { " WHERE " } else { " AND " });
        first = false;
    };
    if let Some(code) = customer {
        and(&mut qb);
        qb.push("c.customer_code = ").push_bind(code.to_string());
    }
    if let Some((year, month)) = period {
        let (start, end) =
            month_range(year, month).ok_or_else(|| ApiError::internal("invalid month"))?;
        and(&mut qb);
        qb.push("c.case_creation_time >= ")
            .push_bind(start)
            .push(" AND c.case_creation_time <= ")
            .push_bind(end);
    }
    if let Some(AccessScope::Customers(codes)) = scope {
        and(&mut qb);
        if codes.is_empty() {
            qb.push("1 = 0");
        } else {
            qb.push("c.customer_code IN (");
            store::push_list(&mut qb, codes.iter().cloned());
            qb.push(")");
        }
    }
    let mut cases: Vec<CaseRow> = store::fetch_cases(&mut qb, &ctx.db).await?;
    if let Some(scope @ AccessScope::Customers(_)) = scope {
        // The collation compares case-insensitively; tenancy is exact.
        cases.retain(|c| {
            c.customer_code
                .as_deref()
                .is_some_and(|code| scope.can_access(code))
        });
    }
    let case_ids: Vec<i32> = cases.iter().map(|c| c.id).collect();
    let (links, _) = store::case_children(&ctx.db, &case_ids).await?;
    let alert_ids: Vec<i32> = links.values().flatten().copied().collect();
    let alerts = store::alerts_by_ids(&ctx.db, &alert_ids).await?;
    let children = store::alert_children(&ctx.db, &alert_ids, Include::BASIC).await?;
    let mut out = Vec::new();
    for case in &cases {
        for alert_id in links.get(&case.id).into_iter().flatten() {
            let Some(alert) = alerts.iter().find(|a| a.id == *alert_id) else {
                continue;
            };
            let joined = |parts: Vec<&str>| parts.join(";");
            let assets = joined(
                children
                    .assets
                    .get(alert_id)
                    .into_iter()
                    .flatten()
                    .map(|a| a.asset_name.as_str())
                    .collect(),
            );
            let tags = joined(
                children
                    .tags
                    .get(alert_id)
                    .into_iter()
                    .flatten()
                    .map(|t| t.tag.as_str())
                    .collect(),
            );
            let comments = joined(
                children
                    .comments
                    .get(alert_id)
                    .into_iter()
                    .flatten()
                    .map(|c| c.comment.as_str())
                    .collect(),
            );
            out.push([
                case.id.to_string(),
                case.case_name.clone(),
                case.case_description.clone(),
                stamp(case.case_creation_time),
                case.case_status.clone(),
                case.case_closed_time.map(stamp).unwrap_or_default(),
                case.assigned_to.clone().unwrap_or_default(),
                case.customer_code.clone().unwrap_or_default(),
                alert.id.to_string(),
                alert.alert_name.clone(),
                alert.alert_description.clone(),
                alert.status.clone(),
                stamp(alert.alert_creation_time),
                alert.time_closed.map(stamp).unwrap_or_default(),
                alert.source.clone(),
                alert.assigned_to.clone().unwrap_or_default(),
                assets,
                tags,
                comments,
                alert.customer_code.clone(),
            ]);
        }
    }
    Ok(out)
}

/// `StreamingResponse(csv, media_type="text/csv")` with the attachment name
/// (Starlette encodes header values as Latin-1).
fn csv_response(body: String, filename: &str) -> Result<Response, ApiError> {
    let latin1: Option<Vec<u8>> = filename
        .chars()
        .map(|c| u8::try_from(u32::from(c)).ok())
        .collect();
    let disposition = latin1
        .map(|name| [b"attachment; filename=".as_slice(), &name].concat())
        .and_then(|bytes| HeaderValue::from_bytes(&bytes).ok())
        .ok_or_else(|| ApiError::internal("filename is not a Latin-1 header value"))?;
    Response::builder()
        .status(200)
        .header(CONTENT_TYPE, "text/csv; charset=utf-8")
        .header(CONTENT_DISPOSITION, disposition)
        .body(Body::from(body))
        .map_err(ApiError::internal)
}

fn file_name(customer: Option<&str>, period: Option<(i32, u32)>) -> String {
    let customer = customer.map(|c| format!("_{c}")).unwrap_or_default();
    let month = period
        .map(|(y, m)| format!("_{y}-{m:02}"))
        .unwrap_or_default();
    let now = chrono::Local::now().format("%Y%m%d_%H%M%S");
    format!("cases_export{customer}{month}_{now}.csv")
}

/// `POST /generate-report-csv?year=&month=`.
async fn export_all(
    auth: Soc,
    State(ctx): State<AppContext>,
    q: QueryPairs,
) -> Result<Response, ApiError> {
    let period = period(&q)?;
    let scope = auth.access(&ctx).await?;
    let rows = rows(&ctx, None, Some(scope), period).await?;
    csv_response(csv_document(&rows), &file_name(None, period))
}

/// `POST /generate-report-csv/{customer_code}?year=&month=`.
async fn export_customer(
    auth: Soc,
    State(ctx): State<AppContext>,
    Path(code): Path<String>,
    q: QueryPairs,
) -> Result<Response, ApiError> {
    auth.enforce_customer(&ctx, &code).await?;
    let period = period(&q)?;
    // `get_customer`: SQL equality (the collation's), 404 when missing.
    let found: Option<i32> = sqlx::query_scalar("SELECT 1 FROM customers WHERE customer_code = ?")
        .bind(&code)
        .fetch_optional(ctx.db.pool())
        .await
        .map_err(ApiError::internal)?;
    if found.is_none() {
        return Err(ApiError::not_found(format!(
            "Customer with customer_code {code} not found"
        )));
    }
    let rows = rows(&ctx, Some(&code), None, period).await?;
    csv_response(csv_document(&rows), &file_name(Some(&code), period))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_quoted_like_python_csv() {
        // csv.writer(out, lineterminator="\n") on Python 3.11.
        let row: [String; 20] = std::array::from_fn(|i| match i {
            0 => "a,b".into(),
            1 => "q\"x".into(),
            2 => "l\nf".into(),
            3 => "c\rr".into(),
            4 => " sp ".into(),
            5 => String::new(),
            6 => "x\u{0}y".into(),
            7 => "\u{2028}".into(),
            _ => "z".into(),
        });
        let doc = csv_document(&[row]);
        let line = doc.lines().nth(1).map(str::to_string).unwrap_or_default();
        assert!(doc.starts_with("Case ID,Case Name,Case Description,"));
        assert!(doc.contains("\"a,b\",\"q\"\"x\",\"l\nf\",\"c\rr\", sp ,,x\u{0}y,\u{2028},z"));
        assert!(line.starts_with("\"a,b\""));
        assert!(doc.ends_with("z\n"));
    }

    #[test]
    fn month_ranges() {
        let (s, e) = month_range(2024, 2).unwrap();
        assert_eq!(s.to_string(), "2024-02-01 00:00:00");
        assert_eq!(e.to_string(), "2024-02-29 23:59:59");
        let (_, e) = month_range(2026, 12).unwrap();
        assert_eq!(e.to_string(), "2026-12-31 23:59:59");
    }
}
